/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2020 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <algorithm>

#include <rex/filesystem.h>
#include <rex/filesystem/device.h>
#include <rex/filesystem/entry.h>
#include <rex/string.h>

namespace rex::filesystem {

Entry::Entry(Device* device, Entry* parent, const std::string_view path)
    : device_(device),
      parent_(parent),
      path_(path),
      attributes_(0),
      size_(0),
      allocation_size_(0),
      create_timestamp_(0),
      access_timestamp_(0),
      write_timestamp_(0) {
  assert_not_null(device);
  absolute_path_ = rex::string::utf8_join_guest_paths(device->mount_path(), path);
  name_ = rex::string::utf8_find_name_from_guest_path(path);
}

Entry::~Entry() = default;

void Entry::Dump(rex::string::StringBuffer* string_buffer, int indent) {
  for (int i = 0; i < indent; ++i) {
    string_buffer->Append(' ');
  }
  string_buffer->Append(name());
  string_buffer->Append('\n');
  for (auto& child : children_) {
    child->Dump(string_buffer, indent + 2);
  }
}

bool Entry::is_read_only() const {
  return device_->is_read_only();
}

Entry* Entry::GetChild(const std::string_view name) {
  auto global_lock = global_critical_region_.Acquire();
  // The size test is exact, not just a hint: the fold is ASCII-only, so any two
  // names it calls equal hold the same bytes per codepoint. It skips the UTF-8
  // decode for nearly every child, and a game directory can hold thousands.
  auto it = std::find_if(children_.cbegin(), children_.cend(), [&](const auto& child) {
    return child->name().size() == name.size() && rex::string::utf8_equal_case(child->name(), name);
  });
  if (it == children_.cend()) {
    return nullptr;
  }
  return (*it).get();
}

Entry* Entry::ResolvePath(const std::string_view path) {
  // Walk the path, one separator at a time.
  Entry* entry = this;
  for (auto& part : rex::string::utf8_split_path(path)) {
    entry = entry->GetChild(part);
    if (!entry) {
      // Not found.
      return nullptr;
    }
  }
  return entry;
}

Entry* Entry::IterateChildren(const rex::filesystem::WildcardEngine& engine,
                              size_t* current_index) {
  auto global_lock = global_critical_region_.Acquire();
  while (*current_index < children_.size()) {
    auto& child = children_[*current_index];
    *current_index = *current_index + 1;
    if (engine.Match(child->name())) {
      return child.get();
    }
  }
  return nullptr;
}

Entry* Entry::CreateEntry(const std::string_view name, uint32_t attributes) {
  auto global_lock = global_critical_region_.Acquire();
  if (is_read_only()) {
    return nullptr;
  }
  if (GetChild(name)) {
    // Already exists.
    return nullptr;
  }
  auto entry = CreateEntryInternal(name, attributes);
  if (!entry) {
    return nullptr;
  }
  children_.push_back(std::move(entry));
  // TODO(benvanik): resort? would break iteration?
  Touch();
  return children_.back().get();
}

bool Entry::Delete(Entry* entry) {
  auto global_lock = global_critical_region_.Acquire();
    if (!entry) {
        return false;
    }
  if (is_read_only()) {
    return false;
  }
  if (entry->parent() != this) {
    return false;
  }
    // (Hunt v1.4.6, A2-R4-03.) The open-handle count used to be consulted
    // only by the delete-on-close path (ReleaseOpenHandle): deleting an
    // entry with live handles freed the Entry object out from under the
    // File/XFile objects pointing at it (XFile::~XFile dereferences the
    // entry after destroying the file), a use-after-free. Refuse the
    // delete while any handle is open -- BEFORE DeleteEntryInternal, so a
    // refused delete removes neither the entry nor the host file. Every
    // caller already handles a false return: kSuperscede fails with
    // ACCESS_DENIED, kOverwrite/kOverwriteIf fall back to Truncate, the
    // stale-entry invalidation keeps the entry (its next open then fails
    // honestly on the missing host file), and DeletePath reports failure
    // to DeleteFileA/RemoveDirectoryA. The delete-on-close path is
    // unaffected: ReleaseOpenHandle only calls Delete() at count zero.
    if (entry->open_handle_count() > 0) {
        return false;
    }
  if (!DeleteEntryInternal(entry)) {
    return false;
  }
  for (auto it = children_.begin(); it != children_.end(); ++it) {
    if (it->get() == entry) {
      children_.erase(it);
      break;
    }
  }
  Touch();
  return true;
}

bool Entry::Delete() {
  // (Hunt v1.4.6, A2-R3-04.) Device-root entries have no parent: the old
  // assert_not_null(parent_) is a no-op in Release, so NtCreateFile with
  // supersede/overwrite on "d:" / "game:" dereferenced a null parent and
  // crashed the host. (The R4-D1 fix only normalized the disposition for
  // xbmovie:.) A parentless entry cannot be deleted: report failure and
  // let the caller answer ACCESS_DENIED instead of crashing.
  if (!parent_) {
    return false;
  }
  return parent_->Delete(this);
}

void Entry::AddOpenHandle() {
  auto global_lock = global_critical_region_.Acquire();
  ++open_handle_count_;
}

bool Entry::ReleaseOpenHandle() {
  auto global_lock = global_critical_region_.Acquire();
  if (open_handle_count_ > 0) {
    --open_handle_count_;
  }
  if (open_handle_count_ == 0 && delete_on_close_) {
    // (Hunt v1.4.6, A2-R3-09.) Last handle closed on a file the game
    // marked delete-on-close: honor the flag now. Delete() re-acquires
    // the global lock (it is recursive) and destroys this entry, so
    // nothing of `this` is touched after this call returns.
    return Delete();
  }
  return false;
}

X_STATUS Entry::Rename(const std::filesystem::path& file_path) {
  // Store the string so split path string_views remain valid.
  const std::string path_str = rex::path_to_utf8(file_path);
  std::vector<std::string_view> path_parts = rex::string::utf8_split_path(path_str);
  if (!path_parts.empty()) {
    // Drop root path (for example, "game:").
    path_parts.erase(path_parts.begin());
  }

    // (Hunt v1.4.6, A2-R4-07.) The rename path never goes through the VFS
    // canonicalization that resolves ".." on reads
    // (utf8_canonicalize_guest_path), and HostPathEntry joins the parts
    // verbatim onto the device root -- so a target like
    // "game:..\..\evil.dat" renamed the file above the device root.
    // Reject ".." components outright instead of canonicalizing: a rename
    // target is a single destination name, never a path that needs to
    // climb, so no legitimate rename trips this. Both callers inherit the
    // fix (NtSetInformationFile rename and CRT MoveFileA); MoveFileA stays
    // consistent because its exists-check uses the canonicalized path and
    // a ".." destination now fails the rename either way.
    for (const auto& part : path_parts) {
        if (part == "..") {
            return X_STATUS_INVALID_PARAMETER;
        }
    }

  X_STATUS status = RenameEntryInternal(path_parts);
  if (status != X_STATUS_SUCCESS) {
    return status;
  }

  const std::string guest_path = rex::string::utf8_join_guest_paths(path_parts);
  absolute_path_ = rex::string::utf8_join_guest_paths(device_->mount_path(), guest_path);
  path_ = guest_path;
  name_ = rex::path_to_utf8(file_path.filename());
  return X_STATUS_SUCCESS;
}

void Entry::Touch() {
  // TODO(benvanik): update timestamps.
}

}  // namespace rex::filesystem
