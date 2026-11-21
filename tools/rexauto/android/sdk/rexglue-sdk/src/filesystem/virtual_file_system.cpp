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

#include <rex/filesystem/vfs.h>
#include <rex/logging.h>
#include <rex/string.h>

#include <rex/filesystem/devices/host_path_entry.h>

REXCVAR_DEFINE_BOOL(allow_game_relative_writes, false, "Filesystem",
                    "Not useful to non-developers. Allows code to write to paths "
                    "relative to game://. Used for "
                    "generating test data to compare with original hardware.");

namespace rex::filesystem {

VirtualFileSystem::VirtualFileSystem() {}

VirtualFileSystem::~VirtualFileSystem() {
  // Delete all devices.
  // This will explode if anyone is still using data from them.
  devices_.clear();
  symlinks_.clear();
}

bool VirtualFileSystem::RegisterDevice(std::unique_ptr<Device> device) {
  auto global_lock = global_critical_region_.Acquire();
  devices_.emplace_back(std::move(device));
  return true;
}

bool VirtualFileSystem::UnregisterDevice(const std::string_view path) {
  auto global_lock = global_critical_region_.Acquire();
  for (auto it = devices_.begin(); it != devices_.end(); ++it) {
    if ((*it)->mount_path() == path) {
      REXFS_DEBUG("Unregistered device: {}", (*it)->mount_path());
      devices_.erase(it);
      return true;
    }
  }
  return false;
}

bool VirtualFileSystem::RegisterSymbolicLink(const std::string_view path,
                                             const std::string_view target) {
  auto global_lock = global_critical_region_.Acquire();
  // (Hunt v1.4.6, A2-R6-06.) A link whose target starts with its own path
  // re-resolves to itself on the first iteration (target + remainder
  // still starts with path), so it can only ever cycle. Reject it here,
  // at the one choke point every registration passes through -- including
  // the guest-facing ObCreateSymbolicLink export, which returns
  // UNSUCCESSFUL on false.
  if (rex::string::utf8_starts_with_case(target, path)) {
    REXFS_WARN("Refusing self-referential symbolic link: {} => {}", path, target);
    return false;
  }
  // (Hunt v1.4.6, A2-R2-08.) insert() keeps the old target when the key
  // already exists while this function still returns true, so a
  // re-registration silently changed nothing. Overwrite instead: the
  // caller (and the log line below) is told the new target took effect.
  symlinks_.insert_or_assign(std::string(path), std::string(target));
  REXFS_DEBUG("Registered symbolic link: {} => {}", path, target);

  return true;
}

bool VirtualFileSystem::UnregisterSymbolicLink(const std::string_view path) {
  auto global_lock = global_critical_region_.Acquire();
  auto it = std::find_if(symlinks_.cbegin(), symlinks_.cend(), [&](const auto& s) {
    return rex::string::utf8_equal_case(path, s.first);
  });
  if (it == symlinks_.end()) {
    return false;
  }
  REXFS_DEBUG("Unregistered symbolic link: {} => {}", it->first, it->second);

  symlinks_.erase(it);
  return true;
}

bool VirtualFileSystem::FindSymbolicLink(const std::string_view path, std::string& target) {
  // (Hunt v1.4.6, A2-R2-03.) This is the only symlinks_ access that ran
  // without the VFS lock: Register/Unregister take it, and the callers
  // (NtOpenSymbolicLinkObject, ContentManager) run on guest threads, so a
  // concurrent insert during this find_if was UB on the unordered_map.
  // Same lock as its sisters (recursive: safe even if a caller holds it).
  auto global_lock = global_critical_region_.Acquire();
  // (Hunt v1.4.6, A2-R3-11.) Overlapping prefixes used to resolve by
  // unordered_map order: find_if takes the FIRST prefix match, so if two
  // registered links ever overlap (e.g. "game:" and "game:\dlc") which
  // target won was hash order, not the longest match. Scan the whole map
  // and keep the longest matching prefix.
  auto best = symlinks_.cend();
  for (auto it = symlinks_.cbegin(); it != symlinks_.cend(); ++it) {
    if (rex::string::utf8_starts_with_case(path, it->first) &&
        (best == symlinks_.cend() || it->first.size() > best->first.size())) {
      best = it;
    }
  }
  if (best == symlinks_.cend()) {
    return false;
  }
  target = best->second;
  return true;
}

bool VirtualFileSystem::ResolveSymbolicLink(const std::string_view path, std::string& result) {
  result = path;
  bool was_resolved = false;
  // (Hunt v1.4.6, A2-R6-06.) This used to be an unbounded while (true):
  // a guest-registered cycle (a -> b, b -> a, via ObCreateSymbolicLink)
  // looped forever AND grew `result` without bound, all while holding
  // the global VFS lock (ResolvePath acquires it before calling here),
  // so every other VFS operation on every thread stalled too. Bound the
  // chain to 16 hops and refuse to revisit a prefix already resolved in
  // this chain: a cycle is now a failed resolution (caller falls back to
  // the unresolved path) instead of a hang. 16 is far above any chain
  // the runtime registers (game:/d:/xbmovie: resolve in one hop).
  static constexpr size_t kMaxSymbolicLinkResolutions = 16;
  std::string resolved_prefixes[kMaxSymbolicLinkResolutions];
  size_t resolutions = 0;
  while (true) {
    // (Hunt v1.4.6, A2-R3-11.) Same longest-prefix rule as
    // FindSymbolicLink above: the old find_if took the first prefix match
    // in unordered_map order, so overlapping links resolved arbitrarily.
    auto it = symlinks_.cend();
    for (auto candidate = symlinks_.cbegin(); candidate != symlinks_.cend(); ++candidate) {
      if (rex::string::utf8_starts_with_case(result, candidate->first) &&
          (it == symlinks_.cend() || candidate->first.size() > it->first.size())) {
        it = candidate;
      }
    }
    if (it == symlinks_.cend()) {
      break;
    }
    if (resolutions >= kMaxSymbolicLinkResolutions) {
      REXFS_WARN("ResolveSymbolicLink: chain too deep for '{}' (>{} hops), refusing", path,
                 kMaxSymbolicLinkResolutions);
      result = std::string(path);
      return false;
    }
    for (size_t i = 0; i < resolutions; ++i) {
      if (rex::string::utf8_equal_case(resolved_prefixes[i], (*it).first)) {
        REXFS_WARN("ResolveSymbolicLink: cycle at '{}' while resolving '{}', refusing", (*it).first,
                   path);
        result = std::string(path);
        return false;
      }
    }
    resolved_prefixes[resolutions++] = (*it).first;
    // Found symlink!
    auto target_path = (*it).second;
    auto relative_path = result.substr((*it).first.size());
    result = target_path + relative_path;
    was_resolved = true;
  }
  return was_resolved;
}

Entry* VirtualFileSystem::ResolvePath(const std::string_view path) {
  auto global_lock = global_critical_region_.Acquire();

  // Resolve relative paths
  auto normalized_path(rex::string::utf8_canonicalize_guest_path(path));

  // Resolve symlinks.
  std::string resolved_path;
  bool had_symlink = ResolveSymbolicLink(normalized_path, resolved_path);
  if (had_symlink) {
    normalized_path = resolved_path;
  }

  // Find the device.
  auto it = std::find_if(devices_.cbegin(), devices_.cend(), [&](const auto& d) {
    return rex::string::utf8_starts_with_case(normalized_path, d->mount_path());
  });
  if (it == devices_.cend()) {
    REXFS_WARN("VFS: '{}' -> [no device]", path);
    // Supress logging the error for ShaderDumpxe:\CompareBackEnds as this is
    // not an actual problem nor something we care about.
    if (path != "ShaderDumpxe:\\CompareBackEnds") {
      REXFS_ERROR("ResolvePath({}) failed - device not found", path);
    }
    return nullptr;
  }

  const auto& device = *it;
  auto relative_path = normalized_path.substr(device->mount_path().size());
  auto* entry = device->ResolvePath(relative_path);

  if (entry) {
    if (had_symlink) {
      REXFS_TRACE("VFS resolved '{}' via symlink '{}' on device '{}' -> '{}'", path,
                  normalized_path, device->mount_path(), entry->absolute_path());
    } else {
      REXFS_TRACE("VFS resolved '{}' on device '{}' -> '{}'", path, device->mount_path(),
                  entry->absolute_path());
    }
  } else {
    if (had_symlink) {
      REXFS_DEBUG("VFS: entry not found for '{}' (via symlink '{}') on device '{}'", path,
                  normalized_path, device->mount_path());
    } else {
      REXFS_DEBUG("VFS: entry not found for '{}' on device '{}'", path, device->mount_path());
    }
  }

  return entry;
}

Entry* VirtualFileSystem::CreatePath(const std::string_view path, uint32_t attributes) {
  // Create all required directories recursively.
  auto path_parts = rex::string::utf8_split_path(path);
  if (path_parts.empty()) {
    return nullptr;
  }
  auto partial_path = std::string(path_parts[0]);
  auto partial_entry = ResolvePath(partial_path);
  if (!partial_entry) {
    return nullptr;
  }
  auto parent_entry = partial_entry;
  for (size_t i = 1; i < path_parts.size() - 1; ++i) {
    partial_path = rex::string::utf8_join_guest_paths(partial_path, path_parts[i]);
    auto child_entry = ResolvePath(partial_path);
    if (!child_entry) {
      child_entry = parent_entry->CreateEntry(path_parts[i], kFileAttributeDirectory);
    }
    if (!child_entry) {
      return nullptr;
    }
    parent_entry = child_entry;
  }
  return parent_entry->CreateEntry(path_parts[path_parts.size() - 1], attributes);
}

bool VirtualFileSystem::DeletePath(const std::string_view path) {
  auto entry = ResolvePath(path);
  if (!entry) {
    return false;
  }
  auto parent = entry->parent();
  if (!parent) {
    // Can't delete root.
    return false;
  }
  return parent->Delete(entry);
}

X_STATUS VirtualFileSystem::OpenFile(Entry* root_entry, const std::string_view path,
                                     FileDisposition creation_disposition, uint32_t desired_access,
                                     bool is_directory, bool is_non_directory, File** out_file,
                                     FileAction* out_action) {
  // TODO(gibbed): should 'is_directory' remain as a bool or should it be
  // flipped to a generic FileAttributeFlags?

  // Cleanup access.
  if (desired_access & FileAccess::kGenericRead) {
    desired_access |= FileAccess::kFileReadData;
  }
  if (desired_access & FileAccess::kGenericWrite) {
    desired_access |= FileAccess::kFileWriteData;
  }
  if (desired_access & FileAccess::kGenericAll) {
    desired_access |= FileAccess::kFileReadData | FileAccess::kFileWriteData;
  }

  // Lookup host device/parent path.
  // If no device or parent, fail.
  Entry* parent_entry = nullptr;
  Entry* entry = nullptr;

  auto base_path = rex::string::utf8_find_base_guest_path(path);
  if (!base_path.empty()) {
    parent_entry = !root_entry ? ResolvePath(base_path) : root_entry->ResolvePath(base_path);
    if (!parent_entry) {
      *out_action = FileAction::kDoesNotExist;
      return X_STATUS_NO_SUCH_FILE;
    }

    auto file_name = rex::string::utf8_find_name_from_guest_path(path);
    entry = parent_entry->GetChild(file_name);
  } else {
    entry = !root_entry ? ResolvePath(path) : root_entry->GetChild(path);
  }

  if (entry) {
    if (entry->attributes() & kFileAttributeDirectory && is_non_directory) {
      // (Hunt v1.4.6, A2-R3-05.) Every exit must write *out_action:
      // NtCreateFile copies it into the caller's IO_STATUS_BLOCK even on
      // failure, and an unwritten value there is uninitialized stack.
      *out_action = FileAction::kDoesNotExist;
      return X_STATUS_FILE_IS_A_DIRECTORY;
    }

    // If the cached entry does not exist on host anymore, invalidate it.
    if (parent_entry) {
      const auto* host_path_entry = dynamic_cast<const HostPathEntry*>(parent_entry);
      if (host_path_entry) {
        std::error_code ec;
        const auto file_path = host_path_entry->host_path() / rex::to_path(entry->name());
        if (!std::filesystem::exists(file_path, ec)) {
          // (Hunt v1.4.6, A2-R4-03.) The old code nulled the entry
          // unconditionally after Delete(), but Delete() now refuses
          // while handles are open -- so a refused delete would keep
          // going with entry == nullptr and create a second entry for
          // the same name. Only drop the cached entry when the delete
          // actually happened; otherwise keep it and let the open below
          // fail honestly on the missing host file (the live handles
          // keep working on the entry they hold).
          if (entry->Delete()) {
            entry = nullptr;
          }
        }
      }
    }
  }

  // Check if exists (if we need it to), or that it doesn't (if it shouldn't).
  switch (creation_disposition) {
    case FileDisposition::kOpen:
    case FileDisposition::kOverwrite:
      // Must exist.
      if (!entry) {
        *out_action = FileAction::kDoesNotExist;
        return X_STATUS_NO_SUCH_FILE;
      }
      break;
    case FileDisposition::kCreate:
      // Must not exist.
      if (entry) {
        *out_action = FileAction::kExists;
        return X_STATUS_OBJECT_NAME_COLLISION;
      }
      break;
    default:
      // Either way, ok.
      break;
  }

  // Verify permissions.
  bool wants_write =
      desired_access & FileAccess::kFileWriteData || desired_access & FileAccess::kFileAppendData;
  if (wants_write &&
      ((parent_entry && parent_entry->is_read_only()) || (entry && entry->is_read_only()))) {
    // Match Xenia behavior: downgrade to read access instead of failing.
    REXFS_WARN("Attempted to open read-only file/dir for write: {}", path);
    desired_access = FileAccess::kGenericRead | FileAccess::kFileReadData;
  }

  bool created = false;
  if (!entry) {
    // Remember that we are creating this new, instead of replacing.
    created = true;
    *out_action = FileAction::kCreated;
  } else {
    // May need to delete, if it exists.
    switch (creation_disposition) {
      case FileDisposition::kCreate:
        // Shouldn't be possible to hit this.
        assert_always();
        // (Hunt v1.4.6, A2-R3-05.) See the FILE_IS_A_DIRECTORY exit
        // above: the action must be written on failure paths too.
        *out_action = FileAction::kDoesNotExist;
        return X_STATUS_ACCESS_DENIED;
      case FileDisposition::kSuperscede:
        // Replace (by delete + recreate).
        if (!entry->Delete()) {
          *out_action = FileAction::kDoesNotExist;
          return X_STATUS_ACCESS_DENIED;
        }
        entry = nullptr;
        *out_action = FileAction::kSuperseded;
        break;
      case FileDisposition::kOpen:
      case FileDisposition::kOpenIf:
        // Normal open.
        *out_action = FileAction::kOpened;
        break;
      case FileDisposition::kOverwrite:
      case FileDisposition::kOverwriteIf:
        // Overwrite by delete + recreate, or truncate if delete fails
        // (host file may be briefly locked by cloud sync, AV, etc.).
        if (entry->Delete()) {
          entry = nullptr;
        } else if (!entry->Truncate()) {
          *out_action = FileAction::kDoesNotExist;
          return X_STATUS_ACCESS_DENIED;
        }
        *out_action = FileAction::kOverwritten;
        break;
      default:
        // (Hunt v1.4.6, A2-R4-06.) Backstop: NtCreateFile now rejects a
        // disposition outside 0-5 before calling here, so this is
        // unreachable from the guest. If a future caller ever passes
        // one, the file is opened as-is -- but the action is still
        // written, so the iosb never carries a stale value again.
        *out_action = FileAction::kOpened;
        break;
    }
  }
  if (!entry) {
    // Create if needed (either new or as a replacement).
    entry = CreatePath(path, !is_directory ? kFileAttributeNormal : kFileAttributeDirectory);
    if (!entry) {
      *out_action = FileAction::kDoesNotExist;
      return X_STATUS_ACCESS_DENIED;
    }
  }

  // Open.
  auto result = entry->Open(desired_access, out_file);
  if (XFAILED(result)) {
    *out_action = FileAction::kDoesNotExist;
  }
  return result;
}

}  // namespace rex::filesystem
