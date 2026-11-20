/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2022 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <rex/filesystem/vfs.h>
#include <rex/logging.h>
#include <rex/math.h>
#include <rex/memory.h>
#include <rex/stream.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xevent.h>
#include <rex/system/xfile.h>
#include <rex/thread/mutex.h>

#include <span>

namespace rex::system {

XFile::XFile(KernelState* kernel_state, rex::filesystem::File* file, bool synchronous)
    : XObject(kernel_state, kObjectType), file_(file), is_synchronous_(synchronous) {
  async_event_ = rex::thread::Event::CreateAutoResetEvent(false);
  assert_not_null(async_event_);
  // (Hunt v1.4.6, A2-R3-09.) Track the open handle on the entry so a
  // delete-on-close flag can be honored when the LAST handle closes.
  if (file_ && file_->entry()) {
    file_->entry()->AddOpenHandle();
  }
}

XFile::XFile() : XObject(kObjectType) {
  async_event_ = rex::thread::Event::CreateAutoResetEvent(false);
  assert_not_null(async_event_);
}

XFile::~XFile() {
  // TODO(benvanik): signal that the file is closing?
  async_event_->Set();
  // (Hunt v1.4.6, A2-R6-10.) file_ is null for a default-constructed
  // XFile whose Restore failed to re-open the file; Restore now returns
  // nullptr in that case, but never let the destructor dereference a
  // null file_ if one ever slips through.
  if (file_) {
    // (Hunt v1.4.6, A2-R3-09.) Honor delete-on-close: when the last open
    // handle to a flagged entry closes, the entry is deleted. Capture the
    // entry BEFORE Destroy() (the File owns no entry reference past its
    // own destruction) and release the handle AFTER it, so the count
    // this handle contributed is dropped first; ReleaseOpenHandle does
    // the delete itself, under the VFS lock, only at count zero.
    auto* entry = file_->entry();
    file_->Destroy();
    file_ = nullptr;
    if (entry) {
      entry->ReleaseOpenHandle();
    }
  }
}

uint64_t XFile::position() const {
  std::lock_guard<std::mutex> lock(file_lock_);
  return position_;
}

void XFile::set_position(uint64_t value) {
  std::lock_guard<std::mutex> lock(file_lock_);
  position_ = value;
}

X_STATUS XFile::QueryDirectory(X_FILE_DIRECTORY_INFORMATION* out_info, size_t length,
                               const std::string_view file_name, bool restart) {
  std::lock_guard<std::mutex> lock(file_lock_);
  assert_not_null(out_info);

  rex::filesystem::Entry* entry = nullptr;

  if (!file_name.empty()) {
    // Only queries in the current directory are supported for now.
    assert_true(rex::string::utf8_find_any_of(file_name, "\\") == std::string_view::npos);

    find_engine_.SetRule(file_name);

    // Always restart the search?
    find_index_ = 0;
    entry = file_->entry()->IterateChildren(find_engine_, &find_index_);
    if (!entry) {
      return X_STATUS_NO_SUCH_FILE;
    }
  } else {
    if (restart) {
      find_index_ = 0;
    }

    entry = file_->entry()->IterateChildren(find_engine_, &find_index_);
    if (!entry) {
      return X_STATUS_NO_MORE_FILES;
    }
  }

  auto end = reinterpret_cast<uint8_t*>(out_info) + length;
  const auto& entry_name = entry->name();
  if (reinterpret_cast<uint8_t*>(&out_info->file_name[0]) + entry_name.size() > end) {
    assert_always("Buffer overflow?");
    // (Hunt v1.4.6, A2-R3-14.) A buffer that fits the fixed header but not
    // the name is a length problem, not a missing file: the caller must
    // retry with a bigger buffer, not stop the enumeration as if the
    // directory had no such file.
    return X_STATUS_BUFFER_OVERFLOW;
  }

  out_info->next_entry_offset = 0;
  out_info->file_index = static_cast<uint32_t>(find_index_);
  out_info->creation_time = entry->create_timestamp();
  out_info->last_access_time = entry->access_timestamp();
  out_info->last_write_time = entry->write_timestamp();
  out_info->change_time = entry->write_timestamp();
  out_info->end_of_file = entry->size();
  out_info->allocation_size = entry->allocation_size();
  out_info->attributes = entry->attributes();
  out_info->file_name_length = static_cast<uint32_t>(entry_name.size());
  std::memcpy(out_info->file_name, entry_name.data(), entry_name.size());

  return X_STATUS_SUCCESS;
}

X_STATUS XFile::Read(uint32_t buffer_guest_address, uint32_t buffer_length, uint64_t byte_offset,
                     uint32_t* out_bytes_read, uint32_t apc_context, bool notify_completion) {
  std::lock_guard<std::mutex> lock(file_lock_);
  return ReadInternal(buffer_guest_address, buffer_length, byte_offset, out_bytes_read, apc_context,
                      notify_completion);
}

X_STATUS XFile::ReadInternal(uint32_t buffer_guest_address, uint32_t buffer_length,
                             uint64_t byte_offset, uint32_t* out_bytes_read, uint32_t apc_context,
                             bool notify_completion) {
  // (Audit D, ronda 5, R5-D3.) -1 is "current position". -2 is also a
  // position-relative marker, not an absolute offset: XFile::ReadScatter
  // forwards it verbatim (it only skips the read_total accumulation for -1
  // and -2), so without this mapping a scatter with byte_offset -2 would
  // land here as the literal offset 0xFFFFFFFFFFFFFFFE and position_ would
  // jump there (subsequent -1 reads would log that absurd offset). -2 has
  // no "append" meaning on reads (it only means append on writes), so
  // treating it as the current position completes what ReadScatter started.
  if (byte_offset == uint64_t(-1) || byte_offset == uint64_t(-2)) {
    // Read from current position.
    byte_offset = position_;
  }

  size_t bytes_read = 0;
  X_STATUS result = X_STATUS_SUCCESS;
  // Zero length means success for a valid file object according to Windows
  // tests.
  if (buffer_length) {
    if (UINT32_MAX - buffer_guest_address < buffer_length) {
      result = X_STATUS_ACCESS_VIOLATION;
    } else {
      // Games often read directly to texture/vertex buffer memory - in this
      // case, invalidation notifications must be sent. However, having any
      // memory callbacks in the range will result in STATUS_ACCESS_VIOLATION at
      // least on Windows, without anything being read or any callbacks being
      // triggered. So for physical memory, host protection must be bypassed,
      // and invalidation callbacks must be triggered manually (it's also wrong
      // to trigger invalidation callbacks before reading in this case, because
      // during the read, the guest may still access the data around the buffer
      // that is located in the same host pages as the buffer's start and end,
      // on the GPU - and that must not trigger a race condition).
      uint32_t buffer_guest_high_address = buffer_guest_address + buffer_length - 1;
      rex::memory::BaseHeap* buffer_start_heap = memory()->LookupHeap(buffer_guest_address);
      const rex::memory::BaseHeap* buffer_end_heap =
          memory()->LookupHeap(buffer_guest_high_address);
      if (!buffer_start_heap || !buffer_end_heap ||
          (buffer_start_heap->heap_type() == memory::HeapType::kGuestPhysical) !=
              (buffer_end_heap->heap_type() == memory::HeapType::kGuestPhysical) ||
          (buffer_start_heap->heap_type() == memory::HeapType::kGuestPhysical &&
           buffer_start_heap != buffer_end_heap)) {
        result = X_STATUS_ACCESS_VIOLATION;
      } else {
        rex::memory::PhysicalHeap* buffer_physical_heap =
            buffer_start_heap->heap_type() == memory::HeapType::kGuestPhysical
                ? static_cast<rex::memory::PhysicalHeap*>(buffer_start_heap)
                : nullptr;
        if (buffer_physical_heap && buffer_physical_heap->QueryRangeAccess(
                                        buffer_guest_address, buffer_guest_high_address) !=
                                        memory::PageAccess::kReadWrite) {
          result = X_STATUS_ACCESS_VIOLATION;
        } else {
          result = file_->ReadSync(
              std::span<uint8_t>(
                  buffer_physical_heap
                      ? memory()->TranslatePhysical(
                            buffer_physical_heap->GetPhysicalAddress(buffer_guest_address))
                      : memory()->TranslateVirtual(buffer_guest_address),
                  buffer_length),
              size_t(byte_offset), &bytes_read);
          if (XSUCCEEDED(result)) {
            if (buffer_physical_heap) {
              buffer_physical_heap->TriggerCallbacks(
                  rex::thread::global_critical_region::AcquireDirect(), buffer_guest_address,
                  buffer_length, true, true);
            }

            // (Audit D, ronda 5, R5-D2.) The position must track the offset
            // actually read, including an explicit 0: the old
            // `if (byte_offset)` guard left position_ stale after an
            // explicit-offset-0 read, so a later position-relative (-1) read
            // resumed at the pre-read position instead of after the bytes
            // just read. -1 was already mapped to position_ above, so an
            // unconditional assignment is safe here.
            position_ = byte_offset;
            position_ += bytes_read;
          }
        }
      }
    }
  }

  if (out_bytes_read) {
    *out_bytes_read = uint32_t(bytes_read);
  }

  if (notify_completion) {
    XIOCompletion::IONotification notify;
    notify.apc_context = apc_context;
    notify.num_bytes = uint32_t(bytes_read);
    notify.status = result;

    NotifyIOCompletionPorts(notify);

    async_event_->Set();
  }

  return result;
}

X_STATUS XFile::ReadScatter(uint32_t segments_guest_address, uint32_t length, uint64_t byte_offset,
                            uint32_t* out_bytes_read, uint32_t apc_context) {
  std::lock_guard<std::mutex> lock(file_lock_);
  X_STATUS result = X_STATUS_SUCCESS;

  // TODO: not sure if this is meant to change depending on buffer address?
  // (only game seen using this always seems to use 4096-byte buffers)
  uint32_t page_size = 4096;

  // (Hunt v1.4.6, A2-R2-09.) Validate the guest segment array BEFORE
  // dereferencing it: TranslateVirtual is unchecked pointer arithmetic
  // (virtual_membase_ + guest_address, xmemory.h), so an array placed at
  // the top of guest memory would read past the host mapping as segments
  // advances. Same wrap + heap check R5-D4 added for the data buffers
  // (ReadInternal/Write): the array spans ceil(length / 4096) 4-byte
  // entries, and both ends must land in heaps of the same kind (and in
  // the same heap when physical). (length / page_size + remainder
  // avoids overflowing length + 4095 for a huge length.)
  if (length) {
    uint32_t segment_count = length / page_size + (length % page_size != 0 ? 1 : 0);
    uint32_t array_bytes = segment_count * 4u;  // one uint32_t per segment
    if (UINT32_MAX - segments_guest_address < array_bytes) {
      result = X_STATUS_ACCESS_VIOLATION;
    } else {
      uint32_t array_high_address = segments_guest_address + array_bytes - 1;
      rex::memory::BaseHeap* array_start_heap = memory()->LookupHeap(segments_guest_address);
      const rex::memory::BaseHeap* array_end_heap = memory()->LookupHeap(array_high_address);
      if (!array_start_heap || !array_end_heap ||
          (array_start_heap->heap_type() == memory::HeapType::kGuestPhysical) !=
              (array_end_heap->heap_type() == memory::HeapType::kGuestPhysical) ||
          (array_start_heap->heap_type() == memory::HeapType::kGuestPhysical &&
           array_start_heap != array_end_heap)) {
        result = X_STATUS_ACCESS_VIOLATION;
      }
    }
  }

  // segments points to an array of buffer pointers of type
  // "FILE_SEGMENT_ELEMENT", but they can just be treated as normal pointers
  rex::be<uint32_t>* segments =
      reinterpret_cast<rex::be<uint32_t>*>(memory()->TranslateVirtual(segments_guest_address));

  uint32_t read_total = 0;
  uint32_t read_remain = length;
  while (read_remain && result == X_STATUS_SUCCESS) {
    uint32_t read_length = read_remain;
    uint32_t read_buffer = *segments;
    if (read_length > page_size) {
      read_length = page_size;
      segments++;
    }

    uint32_t bytes_read = 0;
    // (Hunt v1.4.6, A2-R6-02.) byte_offset -1 / -2 are the
    // position-relative markers (ReadInternal maps them to position_);
    // ANY other value, including an explicit 0, is an absolute offset.
    // The old `byte_offset ? ... : -1` treated an explicit 0 as "current
    // position", so a scatter at the start of the file read from wherever
    // the cursor happened to be (typically EOF). Only NtReadFileScatter
    // calls this, and it passes -1 when the guest gave no offset pointer,
    // so 0 here always means "offset 0".
    result = ReadInternal(
        read_buffer, read_length,
        (byte_offset == uint64_t(-1) || byte_offset == uint64_t(-2))
            ? byte_offset
            : byte_offset + read_total,
        &bytes_read, apc_context, false);

    if (result != X_STATUS_SUCCESS) {
      break;
    }

    read_total += bytes_read;
    // (Hunt v1.4.6, A2-R6-02.) Discount what was actually READ, not what
    // was asked for: the old `read_remain -= read_length` ended the
    // scatter early with SUCCESS and a short buffer whenever a segment
    // read short (EOF / truncated hole), and with SUCCESS + 0 bytes it
    // never advanced read_total at all while still consuming read_remain.
    read_remain -= bytes_read;
    if (bytes_read < read_length) {
      // A short read means the source ran out at this offset: stop here
      // instead of filling later segments from further offsets (or, with
      // a 0-byte short read, looping forever on read_remain -= 0). A
      // partial segment is still honest SUCCESS with the real count; a
      // 0-byte segment is END_OF_FILE, so the caller terminates instead
      // of retrying the same offset.
      if (bytes_read == 0) {
        result = X_STATUS_END_OF_FILE;
      }
      break;
    }
  }

  if (out_bytes_read) {
    *out_bytes_read = uint32_t(read_total);
  }

  XIOCompletion::IONotification notify;
  notify.apc_context = apc_context;
  notify.num_bytes = uint32_t(read_total);
  notify.status = result;

  NotifyIOCompletionPorts(notify);

  async_event_->Set();

  return result;
}

X_STATUS XFile::Write(uint32_t buffer_guest_address, uint32_t buffer_length, uint64_t byte_offset,
                      uint32_t* out_bytes_written, uint32_t apc_context) {
  std::lock_guard<std::mutex> lock(file_lock_);
  if (byte_offset == uint64_t(-1)) {
    // Write from current position.
    byte_offset = position_;
  }

  size_t bytes_written = 0;
  // (Audit D, ronda 5, R5-D4.) ReadInternal rejects a wrapping guest buffer
  // (UINT32_MAX - address < length -> ACCESS_VIOLATION) before calling
  // TranslateVirtual, which is unchecked pointer arithmetic
  // (virtual_membase_ + guest_address). Write had no such check: a guest
  // address + length wrapping past 4 GiB made TranslateVirtual point at
  // host memory outside the guest mapping, and WriteSync would then read it
  // (for the xbmovie probe: the first 16 bytes land in the phone log).
  // Same check, same status code as the read path.
  // (Hunt v1.4.6, A2-R3-01.) The wrap check was only half the read-path
  // validation: ReadInternal ALSO rejects a buffer outside any heap, a
  // buffer spanning heaps of different kinds (or two physical heaps), and
  // a physical range without kReadWrite access -- Write did none of that,
  // so a write buffer in an unmapped hole handed WriteSync a bogus host
  // pointer (host SIGSEGV, or host-memory bytes written to disk / the
  // phone log). Mirror the full ReadInternal validation here, including
  // the physical-heap TranslatePhysical path. A zero-length write keeps
  // the old path: like ReadInternal's `if (buffer_length)` guard, there
  // is no buffer to validate and no bytes for WriteSync to read.
  X_STATUS result;
  if (buffer_length == 0) {
    result = file_->WriteSync(
        std::span<const uint8_t>(memory()->TranslateVirtual(buffer_guest_address), buffer_length),
        size_t(byte_offset), &bytes_written);
  } else if (UINT32_MAX - buffer_guest_address < buffer_length) {
    result = X_STATUS_ACCESS_VIOLATION;
  } else {
    uint32_t buffer_guest_high_address = buffer_guest_address + buffer_length - 1;
    rex::memory::BaseHeap* buffer_start_heap = memory()->LookupHeap(buffer_guest_address);
    const rex::memory::BaseHeap* buffer_end_heap =
        memory()->LookupHeap(buffer_guest_high_address);
    if (!buffer_start_heap || !buffer_end_heap ||
     
  if (XSUCCEEDED(result)) {
    // (Hunt v1.4.6, A2-R2-02.) Mirror ReadInternal (R5-D2): position_ must
    // track the offset actually written, including an explicit one: the
    // old `position_ += bytes_written` left position_ at
    // `old_position + written` after an explicit-offset write, so a later
    // position-relative (-1) write landed at the wrong offset (hole or
    // overwrite). -1 was already mapped to position_ above. -2 is NOT
    // mapped here: on writes it means append (H-01, still open), and
    // WriteSync may succeed while ignoring the offset, so assigning
    // position_ = -2 would poison it for a later -1 read/write.
    // (Round 2 second sweep, LOW-1.)
    if (byte_offset != uint64_t(-2)) {
      position_ = byte_offset;
    }
    position_ += bytes_written;
  }

  XIOCompletion::IONotification notify;
  notify.apc_context = apc_context;
  notify.num_bytes = uint32_t(bytes_written);
  notify.status = result;

  NotifyIOCompletionPorts(notify);

  if (out_bytes_written) {
    *out_bytes_written = uint32_t(bytes_written);
  }

  async_event_->Set();
  return result;
}

X_STATUS XFile::SetLength(size_t length) {
  std::lock_guard<std::mutex> lock(file_lock_);
  return file_->SetLength(length);
}

X_STATUS XFile::Rename(const std::filesystem::path& file_path) {
  std::lock_guard<std::mutex> lock(file_lock_);
  return entry()->Rename(file_path);
}

void XFile::RegisterIOCompletionPort(uint32_t key, object_ref<XIOCompletion> port) {
  std::lock_guard<std::mutex> lock(completion_port_lock_);

  completion_ports_.push_back({key, port});
}

void XFile::RemoveIOCompletionPort(uint32_t key) {
  std::lock_guard<std::mutex> lock(completion_port_lock_);

  for (auto it = completion_ports_.begin(); it != completion_ports_.end(); it++) {
    if (it->first == key) {
      completion_ports_.erase(it);
      break;
    }
  }
}

bool XFile::Save(stream::ByteStream* stream) {
  REXSYS_DEBUG("XFile {:08X} ({})", handle(), file_->entry()->absolute_path().c_str());

  if (!SaveObject(stream)) {
    return false;
  }

  stream->Write(file_->entry()->absolute_path());
  stream->Write<uint64_t>(position_);
  stream->Write(file_access());
  stream->Write<bool>((file_->entry()->attributes() & rex::filesystem::kFileAttributeDirectory) !=
                      0);
  stream->Write<bool>(is_synchronous_);

  return true;
}

object_ref<XFile> XFile::Restore(KernelState* kernel_state, stream::ByteStream* stream) {
  auto file = new XFile();
  file->kernel_state_ = kernel_state;
  if (!file->RestoreObject(stream)) {
    delete file;
    return nullptr;
  }

  auto abs_path = stream->Read<std::string>();
  uint64_t position = stream->Read<uint64_t>();
  auto access = stream->Read<uint32_t>();
  auto is_directory = stream->Read<bool>();
  auto is_synchronous = stream->Read<bool>();

  REXSYS_DEBUG("XFile {:08X} ({})", file->handle(), abs_path);

  rex::filesystem::File* vfs_file = nullptr;
  rex::filesystem::FileAction action;
  auto res = kernel_state->file_system()->OpenFile(nullptr, abs_path,
                                                   rex::filesystem::FileDisposition::kOpen, access,
                                                   is_directory, false, &vfs_file, &action);
  if (XFAILED(res)) {
    REXSYS_ERROR("Failed to open XFile: error {:08X}", res);
    // (Hunt v1.4.6, A2-R6-10.) Do NOT return the half-built object: its
    // file_ is still nullptr, and the first use -- or its own destructor
    // -- dereferences it. Same delete-and-nullptr pattern as the
    // RestoreObject failure above and every other Restore in this tree.
    delete file;
    return nullptr;
  }

  file->file_ = vfs_file;
  file->position_ = position;
  file->is_synchronous_ = is_synchronous;
  // (Hunt v1.4.6, A2-R3-09.) The default ctor above had no file to count;
  // this is where the restored handle starts existing.
  if (vfs_file && vfs_file->entry()) {
    vfs_file->entry()->AddOpenHandle();
  }

  return object_ref<XFile>(file);
}

void XFile::NotifyIOCompletionPorts(XIOCompletion::IONotification& notification) {
  std::lock_guard<std::mutex> lock(completion_port_lock_);

  for (auto port : completion_ports_) {
    notification.key_context = port.first;
    port.second->QueueNotification(notification);
  }
}

}  // namespace rex::system
