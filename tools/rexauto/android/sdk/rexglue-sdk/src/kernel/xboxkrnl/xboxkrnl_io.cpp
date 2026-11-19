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

// Disable warnings about unused parameters for kernel functions
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include <rex/filesystem/device.h>
#include <rex/filesystem/devices/xbmovie_device.h>
#include <rex/filesystem/devices/xbmovie_file.h>
#include <rex/kernel/xboxkrnl/private.h>
#include <rex/logging.h>
#include <rex/memory.h>
#include <rex/hook.h>
#include <rex/thread.h>
#include <rex/types.h>
#include <rex/system/info/file.h>
#include <rex/system/kernel_state.h>
#include <rex/system/util/string_utils.h>
#include <rex/system/xevent.h>
#include <rex/system/xfile.h>
#include <rex/system/xiocompletion.h>
#include <rex/system/xsymboliclink.h>
#include <rex/system/xthread.h>
#include <rex/system/xtypes.h>
#include <rex/thread/mutex.h>

namespace rex::kernel::xboxkrnl {
using namespace rex::system;

struct CreateOptions {
  // https://processhacker.sourceforge.io/doc/ntioapi_8h.html
  static const uint32_t FILE_DIRECTORY_FILE = 0x00000001;
  // Optimization - files access will be sequential, not random.
  static const uint32_t FILE_SEQUENTIAL_ONLY = 0x00000004;
  static const uint32_t FILE_SYNCHRONOUS_IO_ALERT = 0x00000010;
  static const uint32_t FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
  static const uint32_t FILE_NON_DIRECTORY_FILE = 0x00000040;
  // Optimization - file access will be random, not sequential.
  static const uint32_t FILE_RANDOM_ACCESS = 0x00000800;
};

static bool IsValidPath(const std::string_view s, bool is_pattern) {
  // TODO(gibbed): validate path components individually
  bool got_asterisk = false;
  for (const auto& c : s) {
    if (c <= 31 || c >= 127) {
      return false;
    }
    if (got_asterisk) {
      // * must be followed by a . (*.)
      //
      // 4D530819 has a bug in its game code where it attempts to
      // FindFirstFile() with filters of "Game:\\*_X3.rkv", "Game:\\m*_X3.rkv",
      // and "Game:\\w*_X3.rkv" and will infinite loop if the path filter is
      // allowed.
      if (c != '.') {
        return false;
      }
      got_asterisk = false;
    }
    switch (c) {
      case '"':
      // case '*':
      case '+':
      case ',':
      // case ':':
      // case ';':
      case '<':
      // case '=':
      case '>':
      // case '?':
      case '|': {
        return false;
      }
      case '*': {
        // Pattern-specific (for NtQueryDirectoryFile)
        if (!is_pattern) {
          return false;
        }
        got_asterisk = true;
        break;
      }
      case '?': {
        // Pattern-specific (for NtQueryDirectoryFile)
        if (!is_pattern) {
          return false;
        }
        break;
      }
      default: {
        break;
      }
    }
  }
  return true;
}

u32 NtCreateFile_entry(mapped_u32 handle_out, u32 desired_access,
                       ppc_ptr_t<X_OBJECT_ATTRIBUTES> object_attrs,
                       ppc_ptr_t<X_IO_STATUS_BLOCK> io_status_block, mapped_u64 allocation_size_ptr,
                       u32 file_attributes, u32 share_access, u32 creation_disposition,
                       u32 create_options) {
  // note used. maybe later
  // uint64_t allocation_size = 0;  // is this correct???
  // if (allocation_size_ptr) {
  //  allocation_size = *allocation_size_ptr;
  //}

  if (!object_attrs) {
    // ..? Some games do this. This parameter is not optional.
    return X_STATUS_INVALID_PARAMETER;
  }
  assert_not_null(handle_out);

  auto object_name = REX_KERNEL_MEMORY()->TranslateVirtual<X_ANSI_STRING*>(object_attrs->name_ptr);

  rex::filesystem::Entry* root_entry = nullptr;

  // Compute path, possibly attrs relative.
  auto target_path = util::TranslateAnsiPath(REX_KERNEL_MEMORY(), object_name);

  // (Audit C, ronda 2; restricted by audit D, ronda 3, D-X-C-1.) Xbox 360
  // device paths use the NT `\??\` (DosDevices) prefix -- the game opens
  // `\??\xbmovie:` for video playback. TranslateAnsiPath only trims, so
  // the prefix used to reach IsValidPath() verbatim, where '?' is rejected
  // outright and the open failed with OBJECT_NAME_INVALID (0xC0000033)
  // before the VFS was ever consulted -- silently, with no log line.
  // Strip the prefix ONLY for the xbmovie probe device, and ONLY while
  // the `xbmovie_probe` cvar is on: the game binary contains no other
  // `\??\` path (verified by strings on default.pe, ASCII + UTF-16LE/BE:
  // the single occurrence is `\??\xbmovie:`), so every other `\??\...`
  // path keeps exactly today's behaviour (rejected with 0xC0000033), and
  // with the cvar off even `\??\xbmovie:` fails exactly as it does today.
  // The unconditional strip this replaces changed behaviour with the cvar
  // off (a `\??\d:\...` that always failed before could suddenly resolve);
  // restricting it removes that without touching any path that works today.
  if (REXCVAR_GET(xbmovie_probe) &&
      rex::string::utf8_starts_with(target_path, "\\??\\") &&
      rex::string::utf8_starts_with(target_path.substr(4), "xbmovie:")) {
    target_path = target_path.substr(4);
  }

  REXKRNL_IMPORT_TRACE(
      "NtCreateFile", "path={} access={:#x} attrs={:#x} share={:#x} disp={:#x} options={:#x}",
      target_path, (uint32_t)desired_access, (uint32_t)file_attributes, (uint32_t)share_access,
      (uint32_t)creation_disposition, (uint32_t)create_options);

  // Enforce that the path is ASCII.
  if (!IsValidPath(target_path, false)) {
    // (Audit C, ronda 2.) This early return used to be silent: a game
    // asking for `\??\xbmovie:` died here with no log line at all, so the
    // phone log could never show the video open being attempted. Log it
    // at WARN -- invalid NtCreateFile paths are error paths, not hot paths.
    REXKRNL_WARN("NtCreateFile: rejecting invalid path '{}'", target_path);
    return X_STATUS_OBJECT_NAME_INVALID;
  }

  if (object_attrs->root_directory != 0xFFFFFFFD &&  // ObDosDevices
      object_attrs->root_directory != 0) {
    auto root_file = REX_KERNEL_OBJECTS()->LookupObject<XFile>(object_attrs->root_directory);
    assert_not_null(root_file);
    assert_true(root_file->type() == XObject::Type::File);

    root_entry = root_file->entry();
  }

  // (Audit D, ronda 4, R4-D1.) A device node cannot be created or
  // overwritten: VirtualFileSystem::OpenFile answers kCreate on an existing
  // entry with OBJECT_NAME_COLLISION, and kSuperscede/kOverwrite/
  // kOverwriteIf call entry->Delete() -- on the parentless root entry of a
  // device that dereferences a null parent (Entry::Delete() asserts the
  // parent, which is a no-op in Release) and crashes the process. The
  // movie component's disposition is unknown and invisible in the phone
  // log (the disp is only in a NOISY_TRACE), so normalize any
  // create/overwrite disposition on the probe device node to kOpen while
  // the probe cvar is on: on real hardware a create on a device would
  // fail and the component would skip the movie, exactly the outcome EOF
  // already gives it, while here the open succeeds and the probe can log
  // the protocol. Only the `xbmovie:` node is affected, only with the
  // cvar on; every other path keeps today's behaviour.
  if (REXCVAR_GET(xbmovie_probe) &&
      rex::string::utf8_starts_with(target_path, "xbmovie:") &&
      (creation_disposition ==
           static_cast<uint32_t>(rex::filesystem::FileDisposition::kCreate) ||
       creation_disposition ==
           static_cast<uint32_t>(rex::filesystem::FileDisposition::kSuperscede) ||
       creation_disposition ==
           static_cast<uint32_t>(rex::filesystem::FileDisposition::kOverwrite) ||
       creation_disposition ==
           static_cast<uint32_t>(rex::filesystem::FileDisposition::kOverwriteIf))) {
    REXKRNL_WARN(
        "NtCreateFile: xbmovie device open with disposition {:#x} normalized to open",
        creation_disposition);
    creation_disposition =
        static_cast<uint32_t>(rex::filesystem::FileDisposition::kOpen);
  }

  // Attempt open (or create).
  rex::filesystem::File* vfs_file;
  rex::filesystem::FileAction file_action;
  X_STATUS result = REX_KERNEL_FS()->OpenFile(
      root_entry, target_path, rex::filesystem::FileDisposition((uint32_t)creation_disposition),
      desired_access, (create_options & CreateOptions::FILE_DIRECTORY_FILE) != 0,
      (create_options & CreateOptions::FILE_NON_DIRECTORY_FILE) != 0, &vfs_file, &file_action);
  object_ref<XFile> file = nullptr;

  X_HANDLE handle = X_INVALID_HANDLE_VALUE;
  if (XSUCCEEDED(result)) {
    // If true, desired_access SYNCHRONIZE flag must be set.
    bool synchronous = (create_options & CreateOptions::FILE_SYNCHRONOUS_IO_ALERT) ||
                       (create_options & CreateOptions::FILE_SYNCHRONOUS_IO_NONALERT);
    file = object_ref<XFile>(new XFile(REX_KERNEL_STATE(), vfs_file, synchronous));

    // Handle ref is incremented, so return that.
    handle = file->handle();
  }

  if (io_status_block) {
    io_status_block->status = result;
    io_status_block->information = (uint32_t)file_action;
  }

  *handle_out = handle;
  if (XFAILED(result)) {
    REXKRNL_IMPORT_FAIL("NtCreateFile", "path='{}' -> {:#x}", target_path, result);
  } else {
    REXKRNL_IMPORT_RESULT("NtCreateFile", "{:#x} handle={:#x}", result, handle);
  }
  return result;
}

u32 NtOpenFile_entry(mapped_u32 handle_out, u32 desired_access,
                     ppc_ptr_t<X_OBJECT_ATTRIBUTES> object_attributes,
                     ppc_ptr_t<X_IO_STATUS_BLOCK> io_status_block, u32 open_options) {
  return NtCreateFile_entry(handle_out, desired_access, object_attributes, io_status_block, nullptr,
                            0, 0, static_cast<uint32_t>(rex::filesystem::FileDisposition::kOpen),
                            open_options);
}

u32 NtReadFile_entry(u32 file_handle, u32 event_handle, mapped_void apc_routine_ptr,
                     mapped_void apc_context, ppc_ptr_t<X_IO_STATUS_BLOCK> io_status_block,
                     mapped_void buffer, u32 buffer_length, mapped_u64 byte_offset_ptr) {
  uint64_t byte_offset = byte_offset_ptr ? static_cast<uint64_t>(*byte_offset_ptr) : 0;
  const bool apc_requested = (static_cast<uint32_t>(apc_routine_ptr) & ~1u) != 0;
  REXKRNL_IMPORT_TRACE(
      "NtReadFile",
      "handle={:#x} event={:#x} apc={:#x} apc_ctx={:#x} iosb={:#x} buf={:#x} len={:#x} offset={}",
      (uint32_t)file_handle, (uint32_t)event_handle, apc_routine_ptr.guest_address(),
      apc_context.guest_address(), io_status_block.guest_address(), buffer.guest_address(),
      (uint32_t)buffer_length, byte_offset_ptr ? (int64_t)byte_offset : -1);
  X_STATUS result = X_STATUS_SUCCESS;
  bool apc_queued = false;

  bool signal_event = false;
  auto ev = REX_KERNEL_OBJECTS()->LookupObject<XEvent>(event_handle);
  if (event_handle && !ev) {
    result = X_STATUS_INVALID_HANDLE;
  }

  auto file = REX_KERNEL_OBJECTS()->LookupObject<XFile>(file_handle);
  if (!file) {
    result = X_STATUS_INVALID_HANDLE;
  }

  if (XSUCCEEDED(result)) {
    if (true || file->is_synchronous()) {
      // Synchronous.
      uint32_t bytes_read = 0;
      result = file->Read(buffer.guest_address(), buffer_length,
                          byte_offset_ptr ? static_cast<uint64_t>(*byte_offset_ptr) : -1,
                          &bytes_read, apc_context.guest_address());
      if (io_status_block) {
        io_status_block->status = result;
        io_status_block->information = bytes_read;
      }

      // Queue the APC callback. It must be delivered via the APC mechanism even
      // though were are completing immediately.
      // Low bit probably means do not queue to IO ports.
      // (Audit D, ronda 7, R7-D1.) The completion APC is queued for ANY final
      // status, not only SUCCESS: the io_status_block carries the status, and
      // the caller learns the outcome from it when the APC runs. The old
      // `result == X_STATUS_SUCCESS` gate suppressed the APC on every failing
      // read -- including the xbmovie probe's END_OF_FILE since R6-D1, whose
      // EVERY read fails by design -- so a caller that waits for its APC
      // (instead of the event or the completion port, both of which still
      // fire) never wakes up: it hangs instead of ending the movie, which is
      // strictly worse than the pre-R6-D1 SUCCESS + 0 behaviour. The two
      // sibling paths already queue unconditionally (NtReadFileScatter and
      // NtWriteFile in this file only check for a context), and
      // IoCompleteRequest schedules the APC independent of the final status,
      // so this aligns NtReadFile with both. No other behaviour changes:
      // the iosb is already written above with the real status, and the
      // PENDING rewrite below still applies to async handles.
      if ((uint32_t)apc_routine_ptr & ~1) {
        if (apc_context) {
          auto thread = XThread::GetCurrentThread();
          uint32_t apc_routine = static_cast<uint32_t>(apc_routine_ptr) & ~1u;
          uint32_t apc_ctx = apc_context.guest_address();
          uint32_t apc_arg1 = io_status_block.guest_address();
          REXKRNL_IMPORT_TRACE("NtReadFile",
                               "queue_apc thid={} normal={:#x} ctx={:#x} arg1={:#x} arg2=0",
                               thread ? thread->thread_id() : 0, apc_routine, apc_ctx, apc_arg1);
          thread->EnqueueApc(apc_routine, apc_ctx, apc_arg1, 0);
          apc_queued = true;
        } else {
          REXKRNL_IMPORT_TRACE("NtReadFile",
                               "skip_apc_queue (no apc_context, status={:#x})", result);
        }
      }

      if (!file->is_synchronous() && result != X_STATUS_END_OF_FILE) {
        result = X_STATUS_PENDING;
      }

      // Mark that we should signal the event now. We do this after
      // we have written the info out.
      signal_event = true;
    } else {
      // TODO(benvanik): async.

      // X_STATUS_PENDING if not returning immediately.
      // XFile is waitable and signalled after each async req completes.
      // reset the input event (->Reset())
      /*xeNtReadFileState* call_state = new xeNtReadFileState();
      XAsyncRequest* request = new XAsyncRequest(
      state, file,
      (XAsyncRequest::CompletionCallback)xeNtReadFileCompleted,
      call_state);*/
      // result = file->Read(buffer.guest_address(), buffer_length, byte_offset,
      //                     request);
      if (io_status_block) {
        io_status_block->status = X_STATUS_PENDING;
        io_status_block->information = 0;
      }

      result = X_STATUS_PENDING;
    }
  }

  if (XFAILED(result) && io_status_block) {
    io_status_block->status = result;
    io_status_block->information = 0;
  }

  // (Hunt v1.4.6, A2-R6-12.) EOF backoff, lock-free: XFile::Read has
  // returned by now, so no XFile lock is held (the old C-04 sleep ran
  // inside ReadSync, under file_lock_). Only files that override
  // EofBackoffMs() (the xbmovie probe) ever sleep here; every other file
  // returns 0. The iosb already carries the real EOF status above.
  if (file && result == X_STATUS_END_OF_FILE) {
    uint32_t backoff_ms = file->file() ? file->file()->EofBackoffMs() : 0;
    if (backoff_ms > 0) {
      rex::thread::Sleep(std::chrono::milliseconds(backoff_ms));
    }
  }

  if (ev && signal_event) {
    ev->Set(0, false);
  }

  // Log detailed completion info for debugging async IO issues
  if (file) {
    REXKRNL_IMPORT_RESULT(
        "NtReadFile",
        "{:#x} (sync={}, iosb_status={:#x}, iosb_info={}, ev_signaled={}, apc_requested={}, "
        "apc_queued={})",
        result, file->is_synchronous(),
        io_status_block ? (uint32_t)io_status_block->status : 0xDEAD,
        io_status_block ? (uint32_t)io_status_block->information : 0, ev && signal_event,
        apc_requested, apc_queued);
  } else {
    REXKRNL_IMPORT_RESULT("NtReadFile", "{:#x} (apc_requested={}, apc_queued={})", result,
                          apc_requested, apc_queued);
  }
  return result;
}

u32 NtReadFileScatter_entry(u32 file_handle, u32 event_handle, mapped_void apc_routine_ptr,
                            mapped_void apc_context, ppc_ptr_t<X_IO_STATUS_BLOCK> io_status_block,
                            mapped_u32 segment_array, u32 length, mapped_u64 byte_offset_ptr) {
  X_STATUS result = X_STATUS_SUCCESS;

  bool signal_event = false;
  auto ev = REX_KERNEL_OBJECTS()->LookupObject<XEvent>(event_handle);
  if (event_handle && !ev) {
    result = X_STATUS_INVALID_HANDLE;
  }

  auto file = REX_KERNEL_OBJECTS()->LookupObject<XFile>(file_handle);
  if (!file) {
    result = X_STATUS_INVALID_HANDLE;
  }

  if (XSUCCEEDED(result)) {
    if (true || file->is_synchronous()) {
      // Synchronous.
      uint32_t bytes_read = 0;
      result = file->ReadScatter(segment_array.guest_address(), length,
                                 byte_offset_ptr ? static_cast<uint64_t>(*byte_offset_ptr) : -1,
                                 &bytes_read, apc_context.guest_address());
      if (io_status_block) {
        io_status_block->status = result;
        io_status_block->information = bytes_read;
      }

      // Queue the APC callback. It must be delivered via the APC mechanism even
      // though were are completing immediately.
      // Low bit probably means do not queue to IO ports.
      if ((uint32_t)apc_routine_ptr & ~1) {
        if (apc_context) {
          auto thread = XThread::GetCurrentThread();
          thread->EnqueueApc(static_cast<uint32_t>(apc_routine_ptr) & ~1u,
                             apc_context.guest_address(), io_status_block.guest_address(), 0);
        }
      }

      // (Hunt v1.4.6, A2-R6-08.) Same EOF exemption as NtReadFile above:
      // END_OF_FILE is terminal -- no more data is coming -- so an async
      // handle must see EOF, not PENDING (a caller that reads PENDING as
      // "data is on its way" retries the read forever).
      if (!file->is_synchronous() && result != X_STATUS_END_OF_FILE) {
        result = X_STATUS_PENDING;
      }

      // Mark that we should signal the event now. We do this after
      // we have written the info out.
      signal_event = true;
    } else {
      // TODO(benvanik): async.

      // TODO: On Windows it might be worth trying to use Win32 ReadFileScatter
      // here instead of handling it ourselves

      // X_STATUS_PENDING if not returning immediately.
      // XFile is waitable and signalled after each async req completes.
      // reset the input event (->Reset())
      /*xeNtReadFileState* call_state = new xeNtReadFileState();
      XAsyncRequest* request = new XAsyncRequest(
      state, file,
      (XAsyncRequest::CompletionCallback)xeNtReadFileCompleted,
      call_state);*/
      // result = file->Read(buffer.guest_address(), buffer_length, byte_offset,
      //                     request);
      if (io_status_block) {
        io_status_block->status = X_STATUS_PENDING;
        io_status_block->information = 0;
      }

      result = X_STATUS_PENDING;
    }
  }

  if (XFAILED(result) && io_status_block) {
    io_status_block->status = result;
    io_status_block->information = 0;
  }

  // (Hunt v1.4.6, A2-R6-12.) EOF backoff, lock-free -- same as NtReadFile
  // above: XFile::ReadScatter has returned, so no XFile lock is held.
  if (file && result == X_STATUS_END_OF_FILE) {
    uint32_t backoff_ms = file->file() ? file->file()->EofBackoffMs() : 0;
    if (backoff_ms > 0) {
      rex::thread::Sleep(std::chrono::milliseconds(backoff_ms));
    }
  }

  if (ev && signal_event) {
    ev->Set(0, false);
  }

  return result;
}

u32 NtWriteFile_entry(u32 file_handle, u32 event_handle, u32 apc_routine, mapped_void apc_context,
                      ppc_ptr_t<X_IO_STATUS_BLOCK> io_status_block, mapped_void buffer,
                      u32 buffer_length, mapped_u64 byte_offset_ptr) {
  X_STATUS result = X_STATUS_SUCCESS;

  // Grab event to signal.
  bool signal_event = false;
  auto ev = REX_KERNEL_OBJECTS()->LookupObject<XEvent>(event_handle);
  if (event_handle && !ev) {
    result = X_STATUS_INVALID_HANDLE;
  }

  // Grab file.
  auto file = REX_KERNEL_OBJECTS()->LookupObject<XFile>(file_handle);
  if (!file) {
    result = X_STATUS_INVALID_HANDLE;
  }

  // Execute write.
  if (XSUCCEEDED(result)) {
    // TODO(benvanik): async path.
    if (true || file->is_synchronous()) {
      // Synchronous request.
      uint32_t bytes_written = 0;
      result = file->Write(buffer.guest_address(), buffer_length,
                           byte_offset_ptr ? static_cast<uint64_t>(*byte_offset_ptr) : -1,
                           &bytes_written, apc_context.guest_address());

      if (io_status_block) {
        io_status_block->status = result;
        io_status_block->information = static_cast<uint32_t>(bytes_written);
      }

      // Queue the APC callback. It must be delivered via the APC mechanism even
      // though were are completing immediately.
      // Low bit probably means do not queue to IO ports.
      if ((uint32_t)apc_routine & ~1) {
        if (apc_context) {
          auto thread = XThread::GetCurrentThread();
          thread->EnqueueApc(static_cast<uint32_t>(apc_routine) & ~1u, apc_context.guest_address(),
                             io_status_block.guest_address(), 0);
        }
      }

      if (!file->is_synchronous()) {
        result = X_STATUS_PENDING;
      }

      // Mark that we should signal the event now. We do this after
      // we have written the info out.
      signal_event = true;
    } else {
      // X_STATUS_PENDING if not returning immediately.
      result = X_STATUS_PENDING;

      if (io_status_block) {
        io_status_block->status = X_STATUS_PENDING;
        io_status_block->information = 0;
      }
    }
  }

  if (XFAILED(result) && io_status_block) {
    io_status_block->status = result;
    io_status_block->information = 0;
  }

  if (ev && signal_event) {
    ev->Set(0, false);
  }

  return result;
}

u32 NtCreateIoCompletion_entry(mapped_u32 out_handle, u32 desired_access,
                               mapped_void object_attribs, u32 num_concurrent_threads) {
  auto completion = new XIOCompletion(REX_KERNEL_STATE());
  if (out_handle) {
    *out_handle = completion->handle();
  }

  return X_STATUS_SUCCESS;
}

u32 NtSetIoCompletion_entry(u32 handle, u32 key_context, u32 apc_context, u32 completion_status,
                            u32 num_bytes) {
  auto port = REX_KERNEL_OBJECTS()->LookupObject<XIOCompletion>(handle);
  if (!port) {
    return X_STATUS_INVALID_HANDLE;
  }

  XIOCompletion::IONotification notification;
  notification.key_context = key_context;
  notification.apc_context = apc_context;
  notification.num_bytes = num_bytes;
  notification.status = completion_status;

  port->QueueNotification(notification);
  return X_STATUS_SUCCESS;
}

// Dequeues a packet from the completion port.
u32 NtRemoveIoCompletion_entry(u32 handle, mapped_u32 key_context, mapped_u32 apc_context,
                               ppc_ptr_t<X_IO_STATUS_BLOCK> io_status_block, mapped_u64 timeout) {
  X_STATUS status = X_STATUS_SUCCESS;
  // uint32_t info = 0;

  auto port = REX_KERNEL_OBJECTS()->LookupObject<XIOCompletion>(handle);
  if (!port) {
    status = X_STATUS_INVALID_HANDLE;
  }

  uint64_t timeout_ticks = timeout ? static_cast<uint32_t>(*timeout)
                                   : static_cast<uint64_t>(std::numeric_limits<int64_t>::min());
  XIOCompletion::IONotification notification;
  if (port->WaitForNotification(timeout_ticks, &notification)) {
    if (key_context) {
      *key_context = notification.key_context;
    }
    if (apc_context) {
      *apc_context = notification.apc_context;
    }

    if (io_status_block) {
      io_status_block->status = notification.status;
      io_status_block->information = notification.num_bytes;
    }
  } else {
    status = X_STATUS_TIMEOUT;
  }

  return status;
}

u32 NtQueryFullAttributesFile_entry(ppc_ptr_t<X_OBJECT_ATTRIBUTES> obj_attribs,
                                    ppc_ptr_t<X_FILE_NETWORK_OPEN_INFORMATION> file_info) {
  auto object_name = REX_KERNEL_MEMORY()->TranslateVirtual<X_ANSI_STRING*>(obj_attribs->name_ptr);
  auto path_str = util::TranslateAnsiPath(REX_KERNEL_MEMORY(), object_name);
  REXKRNL_IMPORT_TRACE("NtQueryFullAttributesFile", "path={}", path_str);

  object_ref<XFile> root_file;
  if (obj_attribs->root_directory != 0xFFFFFFFD &&  // ObDosDevices
      obj_attribs->root_directory != 0) {
    root_file = REX_KERNEL_OBJECTS()->LookupObject<XFile>(obj_attribs->root_directory);
    assert_not_null(root_file);
    assert_true(root_file->type() == XObject::Type::File);
    assert_always();
  }

  auto target_path = util::TranslateAnsiPath(REX_KERNEL_MEMORY(), object_name);

  // (Audit C, ronda 2; restricted by audit D, ronda 3, D-X-C-1.) Same
  // restricted `\??\` strip as NtCreateFile above: only `\??\xbmovie:`
  // and only while the `xbmovie_probe` cvar is on. Every other `\??\...`
  // path keeps today's behaviour (rejected with 0xC0000033 below).
  if (REXCVAR_GET(xbmovie_probe) &&
      rex::string::utf8_starts_with(target_path, "\\??\\") &&
      rex::string::utf8_starts_with(target_path.substr(4), "xbmovie:")) {
    target_path = target_path.substr(4);
  }

  // Enforce that the path is ASCII.
  if (!IsValidPath(target_path, false)) {
    return X_STATUS_OBJECT_NAME_INVALID;
  }

  // Resolve the file using the virtual file system.
  auto entry = REX_KERNEL_FS()->ResolvePath(target_path);
  if (entry) {
    // Found.
    file_info->creation_time = entry->create_timestamp();
    file_info->last_access_time = entry->access_timestamp();
    file_info->last_write_time = entry->write_timestamp();
    file_info->change_time = entry->write_timestamp();
    file_info->allocation_size = entry->allocation_size();
    file_info->end_of_file = entry->size();
    file_info->attributes = entry->attributes();

    REXKRNL_IMPORT_RESULT("NtQueryFullAttributesFile", "0x0 size={}", (uint64_t)entry->size());
    return X_STATUS_SUCCESS;
  }

  REXKRNL_IMPORT_RESULT("NtQueryFullAttributesFile", "X_STATUS_NO_SUCH_FILE");
  return X_STATUS_NO_SUCH_FILE;
}

u32 NtQueryDirectoryFile_entry(u32 file_handle, u32 event_handle, u32 apc_routine,
                               mapped_void apc_context,
                               ppc_ptr_t<X_IO_STATUS_BLOCK> io_status_block,
                               ppc_ptr_t<X_FILE_DIRECTORY_INFORMATION> file_info_ptr, u32 length,
                               ppc_ptr_t<X_ANSI_STRING> file_name, u32 restart_scan) {
  if (length < 72) {
    return X_STATUS_INFO_LENGTH_MISMATCH;
  }

  X_STATUS result = X_STATUS_UNSUCCESSFUL;
  uint32_t info = 0;

  auto file = REX_KERNEL_OBJECTS()->LookupObject<XFile>(file_handle);
  auto name = util::TranslateAnsiPath(REX_KERNEL_MEMORY(), file_name);

  // Enforce that the path is ASCII.
  if (!IsValidPath(name, true)) {
    return X_STATUS_INVALID_PARAMETER;
  }

  if (file) {
    // X_FILE_DIRECTORY_INFORMATION dir_info = {0};
    result = file->QueryDirectory(file_info_ptr, length, name, restart_scan != 0);
    if (XSUCCEEDED(result)) {
      info = length;
    }
  } else {
    result = X_STATUS_NO_SUCH_FILE;
  }

  if (XFAILED(result)) {
    info = 0;
  }

  if (io_status_block) {
    io_status_block->status = result;
    io_status_block->information = info;
  }

  return result;
}

u32 NtFlushBuffersFile_entry(u32 file_handle, ppc_ptr_t<X_IO_STATUS_BLOCK> io_status_block_ptr) {
  auto result = X_STATUS_SUCCESS;

  if (io_status_block_ptr) {
    io_status_block_ptr->status = result;
    io_status_block_ptr->information = 0;
  }

  return result;
}

// https://docs.microsoft.com/en-us/windows/win32/devnotes/ntopensymboliclinkobject
u32 NtOpenSymbolicLinkObject_entry(mapped_u32 handle_out,
                                   ppc_ptr_t<X_OBJECT_ATTRIBUTES> object_attrs) {
  if (!object_attrs) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // (Audit A3, ronda 6, R6-06.) assert_not_null is a no-op in Release;
  // a NULL handle_out used to write the handle to guest address 0.
  if (!handle_out) {
    return X_STATUS_INVALID_PARAMETER;
  }

  assert_true(object_attrs->attributes == 64);  // case insensitive

  auto object_name = REX_KERNEL_MEMORY()->TranslateVirtual<X_ANSI_STRING*>(object_attrs->name_ptr);

  auto target_path = util::TranslateAnsiPath(REX_KERNEL_MEMORY(), object_name);

  // (Audit D, ronda 4, R4-D3: C-8, same restricted pattern as D-X-C-1.)
  // NtOpenSymbolicLinkObject used to validate the path BEFORE stripping
  // the `\??\` prefix, so opening the `xbmovie:` link with the prefix
  // always died with OBJECT_NAME_INVALID here. Strip the prefix FIRST,
  // but only for `xbmovie:` and only while the probe cvar is on; every
  // other `\??\...` path is validated exactly as before.
  if (REXCVAR_GET(xbmovie_probe) &&
      rex::string::utf8_starts_with(target_path, "\\??\\") &&
      rex::string::utf8_starts_with(target_path.substr(4), "xbmovie:")) {
    target_path = target_path.substr(4);  // Strip the full qualifier
  }

  // Enforce that the path is ASCII.
  if (!IsValidPath(target_path, false)) {
    return X_STATUS_OBJECT_NAME_INVALID;
  }

  if (object_attrs->root_directory != 0) {
    assert_always();
  }

  std::string link_path;
  if (!REX_KERNEL_FS()->FindSymbolicLink(target_path, link_path)) {
    return X_STATUS_NO_SUCH_FILE;
  }

  object_ref<XSymbolicLink> symlink(new XSymbolicLink(REX_KERNEL_STATE()));
  symlink->Initialize(target_path, link_path);

  *handle_out = symlink->handle();

  return X_STATUS_SUCCESS;
}

// https://docs.microsoft.com/en-us/windows/win32/devnotes/ntquerysymboliclinkobject
u32 NtQuerySymbolicLinkObject_entry(u32 handle, ppc_ptr_t<X_ANSI_STRING> target) {
  auto symlink = REX_KERNEL_OBJECTS()->LookupObject<XSymbolicLink>(handle);
  if (!symlink) {
    return X_STATUS_NO_SUCH_FILE;
  }
  auto length = std::min(static_cast<size_t>(target->maximum_length), symlink->target().size());
  if (length > 0) {
    auto target_buf = REX_KERNEL_MEMORY()->TranslateVirtual(target->pointer);
    std::memcpy(target_buf, symlink->target().c_str(), length);
  }
  target->length = static_cast<uint16_t>(length);
  return X_STATUS_SUCCESS;
}

u32 FscGetCacheElementCount_entry(u32 r3) {
  return 0;
}

u32 FscSetCacheElementCount_entry(u32 unk_0, u32 unk_1) {
  // unk_0 = 0
  // unk_1 looks like a count? in what units? 256 is a common value
  return X_STATUS_SUCCESS;
}

u32 NtDeviceIoControlFile_entry(u32 handle, u32 event_handle, u32 apc_routine, u32 apc_context,
                                u32 io_status_block, u32 io_control_code, mapped_void input_buffer,
                                u32 input_buffer_len, mapped_void output_buffer,
                                u32 output_buffer_len) {
  // Called by XMountUtilityDrive cache-mounting code
  // (checks if the returned values look valid, values below seem to pass the
  // checks)
  const uint32_t cache_size = 0xFF000;

  const uint32_t X_IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x70000;
  const uint32_t X_IOCTL_DISK_GET_PARTITION_INFO = 0x74004;

  // (Audit A-5.) Complete the call on every exit below (R7-D3): write the
  // caller's IO_STATUS_BLOCK, signal its event and queue its APC. The disk
  // branches used to return bare, so a caller waiting on any of the three
  // would hang (or read a STALE iosb status left over from a previous call
  // and believe the IOCTL succeeded). `information` is the bytes written
  // to the output buffer on success, 0 on error. Defined before the
  // xbmovie branch so that branch uses it too instead of duplicating the
  // completion by hand.
  auto complete_io = [&](X_STATUS status, uint32_t information) {
    if (io_status_block) {
      auto* iosb = REX_KERNEL_MEMORY()->TranslateVirtual<X_IO_STATUS_BLOCK*>(io_status_block);
      if (iosb) {
        iosb->status = status;
        iosb->information = information;
      }
    }
    if (event_handle) {
      auto ev = REX_KERNEL_OBJECTS()->LookupObject<XEvent>(event_handle);
      if (ev) {
        ev->Set(0, false);
      }
    }
    if ((apc_routine & ~1u) && apc_context) {
      auto thread = XThread::GetCurrentThread();
      if (thread) {
        thread->EnqueueApc(apc_routine & ~1u, apc_context, io_status_block, 0);
      }
    }
  };

  // (Audit C, ronda 2.) Probe for the xbmovie video device. This function
  // only knows the two disk IOCTLs above; any other code falls through to
  // REXKRNL_DEBUG (invisible at log_level=info) + assert_always (a no-op
  // in Release) + INVALID_PARAMETER. If the handle belongs to the
  // XbMovieDevice, log the IOCTL at WARN instead -- the code and the
  // buffer lengths ARE the protocol, and the phone log is the only place
  // that can reveal them -- and answer NOT_IMPLEMENTED so the caller can
  // distinguish "unknown IOCTL on the video device" from "bad handle".
  // Handles for any other device take the historical path unchanged.
  // (Hunt v1.4.6, A2-R6-01.) NOT_IMPLEMENTED forever was a trap, not a
  // probe: a component that retries its start IOCTL until it succeeds
  // spins with no sleep, no counter and no exit -- and every iteration
  // used to emit an unthrottled WARN with a disk flush, so the log itself
  // stole the guest thread. Now the streak is counted per handle with
  // exponential backoff (1-8 ms, taken here -- this function holds no
  // XFile lock), the log is throttled to the first 8 + every 16, and
  // after 64 consecutive NOT_IMPLEMENTED answers to the SAME code the
  // probe answers X_STATUS_END_OF_FILE instead: the probe's established
  // "movie ended" signal (same as its reads), which lets a retrying
  // component terminate and move on instead of spinning forever. The
  // first 64 answers are still honest NOT_IMPLEMENTED, so a component
  // that falls back to another method after a few failures never sees
  // the terminal status. The call is still completed on every exit
  // (iosb + event + APC, R7-D3) via complete_io above.
  {
    auto xbmovie_file = REX_KERNEL_OBJECTS()->LookupObject<XFile>(handle);
    if (xbmovie_file && xbmovie_file->device() &&
        xbmovie_file->device()->name() == "XbMovieDevice") {
      auto* movie = xbmovie_file->file()
                        ? static_cast<rex::filesystem::XbMovieFile*>(xbmovie_file->file())
                        : nullptr;
      bool terminate = false;
      uint32_t backoff_ms = 0;
      uint32_t streak = 0;
      if (movie) {
        terminate = movie->RecordUnimplementedIoctl(io_control_code);
        backoff_ms = movie->IoctlBackoffMs();
        streak = movie->ConsecutiveIoctlCount();
      }
      if (streak <= 8 || streak % 16 == 0 || terminate) {
        REXKRNL_WARN(
            "NtDeviceIoControlFile(xbmovie): ioctl={:#x} in_len={} out_len={} streak={}{}",
            io_control_code, input_buffer_len, output_buffer_len, streak,
            terminate ? " -> END_OF_FILE (start retry limit reached, movie ended)" : "");
      }
      X_STATUS status = terminate ? X_STATUS_END_OF_FILE : X_STATUS_NOT_IMPLEMENTED;
      if (backoff_ms > 0 && !terminate) {
        rex::thread::Sleep(std::chrono::milliseconds(backoff_ms));
      }
      complete_io(status, 0);
      return status;
    }
  }

  uint32_t bytes_written = 0;
  if (io_control_code == X_IOCTL_DISK_GET_DRIVE_GEOMETRY) {
    if (output_buffer_len < 0x8) {
      assert_always();
      complete_io(X_STATUS_BUFFER_TOO_SMALL, 0);
      return X_STATUS_BUFFER_TOO_SMALL;
    }
    memory::store_and_swap<uint32_t>(output_buffer, cache_size / 512);
    memory::store_and_swap<uint32_t>(output_buffer + 4, 512);
    bytes_written = 0x8;
  } else if (io_control_code == X_IOCTL_DISK_GET_PARTITION_INFO) {
    if (output_buffer_len < 0x10) {
      assert_always();
      complete_io(X_STATUS_BUFFER_TOO_SMALL, 0);
      return X_STATUS_BUFFER_TOO_SMALL;
    }
    memory::store_and_swap<uint64_t>(output_buffer, 0);
    memory::store_and_swap<uint64_t>(output_buffer + 8, cache_size);
    bytes_written = 0x10;
  } else {
    REXKRNL_DEBUG("NtDeviceIoControlFile(0x{:X}) - unhandled IOCTL!", uint32_t(io_control_code));
    assert_always();
    complete_io(X_STATUS_INVALID_PARAMETER, 0);
    return X_STATUS_INVALID_PARAMETER;
  }

  complete_io(X_STATUS_SUCCESS, bytes_written);
  return X_STATUS_SUCCESS;
}

u32 IoCreateDevice_entry(u32 device_struct, u32 r4, u32 r5, u32 r6, u32 r7, mapped_u32 out_struct) {
  // (Audit A3, ronda 6, R6-06.) A NULL out_struct used to write the
  // device pointer to guest address 0, after leaking two heap allocs.
  if (!out_struct) {
    return X_STATUS_INVALID_PARAMETER;
  }

  // Called from XMountUtilityDrive XAM-task code
  // That code tries writing things to a pointer at out_struct+0x18
  // We'll alloc some scratch space for it so it doesn't cause any exceptions

  // 0x24 is guessed size from accesses to out_struct - likely incorrect
  auto out_guest = REX_KERNEL_MEMORY()->SystemHeapAlloc(0x24);

  auto out = REX_KERNEL_MEMORY()->TranslateVirtual<uint8_t*>(out_guest);
  memset(out, 0, 0x24);

  // XMountUtilityDrive writes some kind of header here
  // 0x1000 bytes should be enough to store it
  auto out_guest2 = REX_KERNEL_MEMORY()->SystemHeapAlloc(0x1000);
  memory::store_and_swap(out + 0x18, out_guest2);

  *out_struct = out_guest;
  return X_STATUS_SUCCESS;
}

u32 IoDismountVolumeByFileHandle_entry(u32 handle) {
  REXKRNL_WARN("IoDismountVolumeByFileHandle({:#x}) - stub", (uint32_t)handle);
  // (Audit A3, ronda 6, R6-05.) Was SUCCESS without dismounting anything.
  return X_STATUS_NOT_IMPLEMENTED;
}

u32 IoDismountVolumeByName_entry(ppc_ptr_t<X_ANSI_STRING> name) {
  REXKRNL_WARN("IoDismountVolumeByName - stub");
  // (Audit A3, ronda 6, R6-05.) Was SUCCESS without dismounting anything.
  return X_STATUS_NOT_IMPLEMENTED;
}

u32 IoSynchronousDeviceIoControlRequest_entry(u32 ioctl, mapped_void device_object,
                                              mapped_void input_buffer, u32 input_length,
                                              mapped_void output_buffer, u32 output_length,
                                              mapped_u32 returned_length, u32 unk) {
  REXKRNL_WARN("IoSynchronousDeviceIoControlRequest({:#x}) - stub", (uint32_t)ioctl);
  // (Audit A3, ronda 6, R6-05.) Was SUCCESS without running the IOCTL or
  // writing the out-params: callers believed the request ran and read
  // output that was never produced. Fail honestly, and zero the byte
  // count so a caller that ignores the status does not read a stale length.
  if (returned_length) {
    *returned_length = 0;
  }
  return X_STATUS_NOT_IMPLEMENTED;
}

u32 StfsCreateDevice_entry(mapped_void device_object, u32 flags, mapped_u32 out_device) {
  REXKRNL_WARN("StfsCreateDevice - stub");
  // (Audit A3, ronda 6, R6-05.) Was SUCCESS without creating the device
  // or writing *out_device (the write was commented out): callers used
  // an uninitialized device pointer. Write NULL and fail honestly.
  if (out_device) {
    *out_device = 0;
  }
  return X_STATUS_NOT_IMPLEMENTED;
}

u32 StfsControlDevice_entry(mapped_void device_object, u32 ioctl, mapped_void input_buffer,
                            u32 input_length, mapped_void output_buffer, u32 output_length) {
  REXKRNL_WARN("StfsControlDevice({:#x}) - stub", (uint32_t)ioctl);
  // (Audit A3, ronda 6, R6-05.) Was SUCCESS without running the IOCTL.
  return X_STATUS_NOT_IMPLEMENTED;
}

}  // namespace rex::kernel::xboxkrnl

REX_EXPORT(__imp__NtCreateFile, rex::kernel::xboxkrnl::NtCreateFile_entry)
REX_EXPORT(__imp__NtOpenFile, rex::kernel::xboxkrnl::NtOpenFile_entry)
REX_EXPORT(__imp__NtReadFile, rex::kernel::xboxkrnl::NtReadFile_entry)
REX_EXPORT(__imp__NtReadFileScatter, rex::kernel::xboxkrnl::NtReadFileScatter_entry)
REX_EXPORT(__imp__NtWriteFile, rex::kernel::xboxkrnl::NtWriteFile_entry)
REX_EXPORT(__imp__NtCreateIoCompletion, rex::kernel::xboxkrnl::NtCreateIoCompletion_entry)
REX_EXPORT(__imp__NtSetIoCompletion, rex::kernel::xboxkrnl::NtSetIoCompletion_entry)
REX_EXPORT(__imp__NtRemoveIoCompletion, rex::kernel::xboxkrnl::NtRemoveIoCompletion_entry)
REX_EXPORT(__imp__NtQueryFullAttributesFile, rex::kernel::xboxkrnl::NtQueryFullAttributesFile_entry)
REX_EXPORT(__imp__NtQueryDirectoryFile, rex::kernel::xboxkrnl::NtQueryDirectoryFile_entry)
REX_EXPORT(__imp__NtFlushBuffersFile, rex::kernel::xboxkrnl::NtFlushBuffersFile_entry)
REX_EXPORT(__imp__NtOpenSymbolicLinkObject, rex::kernel::xboxkrnl::NtOpenSymbolicLinkObject_entry)
REX_EXPORT(__imp__NtQuerySymbolicLinkObject, rex::kernel::xboxkrnl::NtQuerySymbolicLinkObject_entry)
REX_EXPORT(__imp__FscGetCacheElementCount, rex::kernel::xboxkrnl::FscGetCacheElementCount_entry)
REX_EXPORT(__imp__FscSetCacheElementCount, rex::kernel::xboxkrnl::FscSetCacheElementCount_entry)
REX_EXPORT(__imp__NtDeviceIoControlFile, rex::kernel::xboxkrnl::NtDeviceIoControlFile_entry)
REX_EXPORT(__imp__IoCreateDevice, rex::kernel::xboxkrnl::IoCreateDevice_entry)
REX_EXPORT(__imp__IoDismountVolumeByFileHandle,
           rex::kernel::xboxkrnl::IoDismountVolumeByFileHandle_entry)
REX_EXPORT(__imp__IoDismountVolumeByName, rex::kernel::xboxkrnl::IoDismountVolumeByName_entry)
REX_EXPORT(__imp__IoSynchronousDeviceIoControlRequest,
           rex::kernel::xboxkrnl::IoSynchronousDeviceIoControlRequest_entry)
REX_EXPORT(__imp__StfsCreateDevice, rex::kernel::xboxkrnl::StfsCreateDevice_entry)
REX_EXPORT(__imp__StfsControlDevice, rex::kernel::xboxkrnl::StfsControlDevice_entry)

// (Audit A-6.) Stub return values: a bare REX_STUB leaves r3 = arg0
// (a guest pointer, 0x82...), which as NTSTATUS has the high bit set
// (failure) and as a pointer is a bogus address. NTSTATUS routines
// return X_STATUS_NOT_IMPLEMENTED (honest failure, no lie-success);
// pointer routines return 0 (NULL). VOID routines keep the bare stub:
// their r3 is ignored by the caller. Left pending (signature not
// verified): IoInvalidDeviceRequest, IoAcquireCancelSpinLock,
// IoReleaseCancelSpinLock, SataCdRomRecordReset.
REX_EXPORT_STUB(__imp__IoAcquireDeviceObjectLock);
REX_EXPORT_STUB_RETURN(__imp__IoAllocateIrp, 0);
REX_EXPORT_STUB_RETURN(__imp__IoBuildAsynchronousFsdRequest, 0);
REX_EXPORT_STUB_RETURN(__imp__IoBuildDeviceIoControlRequest, 0);
REX_EXPORT_STUB_RETURN(__imp__IoBuildSynchronousFsdRequest, 0);
REX_EXPORT_STUB_RETURN(__imp__IoCallDriver, X_STATUS_NOT_IMPLEMENTED);
REX_EXPORT_STUB_RETURN(__imp__IoCheckShareAccess, X_STATUS_NOT_IMPLEMENTED);
REX_EXPORT_STUB(__imp__IoCompleteRequest);
REX_EXPORT_STUB_RETURN(__imp__IoCreateFile, X_STATUS_NOT_IMPLEMENTED);
REX_EXPORT_STUB(__imp__IoDeleteDevice);
REX_EXPORT_STUB_RETURN(__imp__IoDismountVolume, X_STATUS_NOT_IMPLEMENTED);
REX_EXPORT_STUB(__imp__IoFreeIrp);
REX_EXPORT_STUB(__imp__IoInitializeIrp);
REX_EXPORT_STUB(__imp__IoInvalidDeviceRequest);
REX_EXPORT_STUB(__imp__IoQueueThreadIrp);
REX_EXPORT_STUB(__imp__IoReleaseDeviceObjectLock);
REX_EXPORT_STUB(__imp__IoRemoveShareAccess);
REX_EXPORT_STUB(__imp__IoSetIoCompletion);
REX_EXPORT_STUB(__imp__IoSetShareAccess);
REX_EXPORT_STUB(__imp__IoStartNextPacket);
REX_EXPORT_STUB(__imp__IoStartNextPacketByKey);
REX_EXPORT_STUB(__imp__IoStartPacket);
REX_EXPORT_STUB_RETURN(__imp__IoSynchronousFsdRequest, X_STATUS_NOT_IMPLEMENTED);
REX_EXPORT_STUB_RETURN(__imp__NtDeleteFile, X_STATUS_NOT_IMPLEMENTED);
REX_EXPORT_STUB_RETURN(__imp__NtSetSystemTime, X_STATUS_NOT_IMPLEMENTED);
REX_EXPORT_STUB_RETURN(__imp__NtWriteFileGather, X_STATUS_NOT_IMPLEMENTED);
REX_EXPORT_STUB(__imp__IoAcquireCancelSpinLock);
REX_EXPORT_STUB(__imp__IoReleaseCancelSpinLock);
REX_EXPORT_STUB_RETURN(__imp__NtCancelIoFile, X_STATUS_NOT_IMPLEMENTED);
REX_EXPORT_STUB_RETURN(__imp__NtCancelIoFileEx, X_STATUS_NOT_IMPLEMENTED);
REX_EXPORT_STUB_RETURN(__imp__SvodCreateDevice, X_STATUS_NOT_IMPLEMENTED);

REX_EXPORT_STUB(__imp__SataCdRomRecordReset);
