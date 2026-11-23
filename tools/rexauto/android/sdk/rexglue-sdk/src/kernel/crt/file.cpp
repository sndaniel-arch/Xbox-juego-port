/**
 * @file        kernel/crt/file.cpp
 *
 * @brief       rexcrt File I/O hooks -- Win32-style CRT wrappers backed by VFS.
 *              Generic implementations with no game-specific logic.
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 * @license     BSD 3-Clause License
 */

#include <cstring>
#include <memory>
#include <span>

#include <rex/filesystem.h>
#include <rex/filesystem/device.h>
#include <rex/filesystem/entry.h>
#include <rex/filesystem/vfs.h>
#include <rex/logging.h>
#include <rex/memory.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/string.h>
#include <rex/system/kernel_state.h>
#include <rex/system/thread_state.h>
#include <rex/system/xfile.h>
#include <rex/system/xtypes.h>

using rex::X_STATUS;

namespace rex::kernel::crt {

// (Hunt v1.4.6, ronda 7, A3-R7-07.) TranslateVirtual never validates
// and never returns null, so a guest pointer + length that runs past
// the end of the mapping SIGSEGVs the host on the memcpy/read/write.
// Same heap validation as A3-R4-09 (see xam_net.cpp for the full
// comment), copied here because this file had no range helper at all:
// reject a range that wraps past 4 GiB, starts or ends outside any
// heap, or spans heaps of different kinds (or two physical heaps);
// inside a single heap, require the pages to be accessible (read/write
// for a destination, readable for a source).
static bool GuestRangeAccessible(uint32_t guest_address, size_t length, bool writable) {
  if (!length) {
    return true;
  }
  if (length > UINT32_MAX - guest_address) {
    return false;
  }
  uint32_t high_address = guest_address + static_cast<uint32_t>(length) - 1;
  rex::memory::BaseHeap* start_heap = REX_KERNEL_MEMORY()->LookupHeap(guest_address);
  rex::memory::BaseHeap* end_heap = REX_KERNEL_MEMORY()->LookupHeap(high_address);
  if (!start_heap || !end_heap) {
    return false;
  }
  bool start_physical =
      start_heap->heap_type() == rex::memory::HeapType::kGuestPhysical;
  bool end_physical =
      end_heap->heap_type() == rex::memory::HeapType::kGuestPhysical;
  if (start_physical != end_physical || (start_physical && start_heap != end_heap)) {
    return false;
  }
  if (start_heap == end_heap) {
    auto access = start_heap->QueryRangeAccess(guest_address, high_address);
    if (start_physical) {
      return access == rex::memory::PageAccess::kReadWrite;
    }
    return writable ? access == rex::memory::PageAccess::kReadWrite
                    : access != rex::memory::PageAccess::kNoAccess;
  }
  // (Hunt v1.4.6, ronda 8, A3-R8-13.) The range straddles a heap
  // boundary -- legitimate allocations never do (each allocation
  // lives in a single heap) -- and the old code returned true here
  // without checking anything, so a buffer whose first page is
  // uncommitted or NoAccess sailed through every GuestRange* check.
  // Validate both ends instead: the tail of the start heap and the
  // head of the end heap, with the same read/write rule as above.
  // (A range spanning more than two heaps still has only its two
  // ends checked; no legitimate range spans even one boundary.)
  auto range_ok = [&](rex::memory::PageAccess access) {
    if (start_physical) {
      return access == rex::memory::PageAccess::kReadWrite;
}
      return writable ? access == rex::memory::PageAccess::kReadWrite
                        : access != rex::memory::PageAccess::kNoAccess;
  };
  uint32_t start_heap_end = start_heap->heap_base() + start_heap->heap_size() - 1;
  return range_ok(start_heap->QueryRangeAccess(guest_address, start_heap_end)) &&
           range_ok(end_heap->QueryRangeAccess(end_heap->heap_base(), high_address));
}

static bool GuestRangeReadable(uint32_t guest_address, size_t length) {
  return GuestRangeAccessible(guest_address, length, false);
}

static bool GuestRangeWritable(uint32_t guest_address, size_t length) {
  return GuestRangeAccessible(guest_address, length, true);
}


constexpr uint32_t kCreateNew = 1;
constexpr uint32_t kCreateAlways = 2;
constexpr uint32_t kOpenExisting = 3;
constexpr uint32_t kOpenAlways = 4;
constexpr uint32_t kTruncateExisting = 5;

constexpr uint32_t kFileBegin = 0;
constexpr uint32_t kFileCurrent = 1;
constexpr uint32_t kFileEnd = 2;

constexpr uint32_t kInvalidHandleValue = 0xFFFFFFFF;

static rex::filesystem::FileDisposition MapDisposition(uint32_t win32_disp) {
  using FD = rex::filesystem::FileDisposition;
  switch (win32_disp) {
    case kCreateNew:
      return FD::kCreate;
    case kCreateAlways:
      return FD::kOverwriteIf;
    case kOpenExisting:
      return FD::kOpen;
    case kOpenAlways:
      return FD::kOpenIf;
    case kTruncateExisting:
      return FD::kOverwrite;
    default:
      return FD::kOpen;
  }
}

// (Hunt v1.4.6, A2-R4-14.) Compute a seek target without wrapping: a
// negative result used to wrap to ~2^64 (uint64 + negative int64) and get
// stored as the file position, poisoning every later read/write.
// Returns false when the seek would land before the start of the file,
// past the end of the 64-bit range, or for an unknown move method --
// the caller then fails the seek instead of storing the position.
static bool ComputeSeekPosition(rex::system::XFile* file, int64_t distance, uint32_t method,
                                uint64_t* out_position) {
  uint64_t base = 0;
  switch (method) {
    case kFileBegin:
      break;
    case kFileCurrent:
      base = file->position();
      break;
    case kFileEnd:
      base = file->entry()->size();
      break;
    default:
      return false;
  }
  if (distance >= 0) {
    if (static_cast<uint64_t>(distance) > ~uint64_t(0) - base) {
      return false;
    }
    *out_position = base + static_cast<uint64_t>(distance);
  } else {
    // distance == INT64_MIN: -distance overflows int64, and its magnitude
    // (2^63) exceeds any real file position, so it can only fail.
    if (distance == INT64_MIN || static_cast<uint64_t>(-distance) > base) {
      return false;
    }
    *out_position = base - static_cast<uint64_t>(-distance);
  }
  return true;
}

u32 CreateFileA_entry(mapped_string lpFileName, u32 dwDesiredAccess, u32 dwShareMode,
                      mapped_void lpSecurityAttributes, u32 dwCreationDisposition,
                      u32 dwFlagsAndAttributes, u32 hTemplateFile) {
  // (Hunt v1.4.6, A2-R4-13.) A guest NULL filename arrives as a null
  // const char* here, and building a string_view from it below is UB
  // (strlen on NULL) before any path handling runs. Fail honestly.
  if (!lpFileName) {
    return kInvalidHandleValue;
  }
  const char* path = static_cast<const char*>(lpFileName);
  auto* ks = REX_KERNEL_STATE();
  auto disposition = MapDisposition(static_cast<uint32_t>(dwCreationDisposition));

  rex::filesystem::File* vfs_file = nullptr;
  rex::filesystem::FileAction action;
  X_STATUS status = ks->file_system()->OpenFile(nullptr, path, disposition,
                                                static_cast<uint32_t>(dwDesiredAccess), false, true,
                                                &vfs_file, &action);

  if (XFAILED(status) || !vfs_file) {
    REXKRNL_NOISY_DEBUG("rexcrt_CreateFileA: FAILED path='{}' status={:#x}", path, status);
    return kInvalidHandleValue;
  }

  auto* xfile = new rex::system::XFile(ks, vfs_file, true);
  auto handle = xfile->handle();
  REXKRNL_NOISY_DEBUG("rexcrt_CreateFileA: '{}' -> handle={:#x}", path, handle);
  return handle;
}

u32 ReadFile_entry(u32 hFile, mapped_void lpBuffer, u32 nNumberOfBytesToRead,
                   mapped_u32 lpNumberOfBytesRead, mapped_void lpOverlapped) {
  // (Hunt v1.4.6, ronda 8, A3-R8-08.) lpNumberOfBytesRead is written
  // on both paths below (0 on invalid handle, the count otherwise);
  // validate it up front instead of writing through a wild pointer.
  // (NULL stays allowed: no count out.)
  if (lpNumberOfBytesRead &&
        !GuestRangeWritable(lpNumberOfBytesRead.guest_address(), sizeof(uint32_t)) {
    return 0;
  }
      auto file = REX_KERNEL_OBJECTS()->LookupObject<rex::system::XFile>(static_cast<uint32_t>(hFile));
  if (!file) {
    REXKRNL_WARN("rexcrt_ReadFile: invalid handle {:#x}", static_cast<uint32_t>(hFile));
    if (lpNumberOfBytesRead)
      *lpNumberOfBytesRead = 0;
    return 0;
  }

  // (Hunt v1.4.6, ronda 7, A3-R7-07.) The OVERLAPPED is read (ov[2]/ov[3])
  // and written (ov[0]/ov[1]) -- 16 bytes -- with only a NULL-check.
  // (The data buffer itself is validated inside XFile::Read.)
  if (lpOverlapped && !GuestRangeWritable(lpOverlapped.guest_address(), 16)) {
    return 0;
  }

  uint64_t offset = static_cast<uint64_t>(-1);
  if (lpOverlapped) {
    auto* ov = reinterpret_cast<rex::be<uint32_t>*>(
        static_cast<uint8_t*>(static_cast<void*>(lpOverlapped)));
    offset =
        (static_cast<uint64_t>(static_cast<uint32_t>(ov[3])) << 32) | static_cast<uint32_t>(ov[2]);
  }

  uint32_t bytes_read = 0;
  X_STATUS status = file->Read(lpBuffer.guest_address(),
                               static_cast<uint32_t>(nNumberOfBytesToRead), offset, &bytes_read, 0);

  if (lpOverlapped) {
    auto* ov = reinterpret_cast<rex::be<uint32_t>*>(
        static_cast<uint8_t*>(static_cast<void*>(lpOverlapped)));
    ov[0] = 0;
    ov[1] = bytes_read;
  } else if (lpNumberOfBytesRead) {
    *lpNumberOfBytesRead = bytes_read;
  }

  return XSUCCEEDED(status) ? 1u : 0u;
}

u32 WriteFile_entry(u32 hFile, mapped_void lpBuffer, u32 nNumberOfBytesToWrite,
                    mapped_u32 lpNumberOfBytesWritten, mapped_void lpOverlapped) {
  // (Hunt v1.4.6, ronda 8, A3-R8-08.) See ReadFile above.
  if (lpNumberOfBytesWritten &&
        !GuestRangeWritable(lpNumberOfBytesWritten.guest_address(), sizeof(uint32_t))) {
        return 0;
  }
  auto file = REX_KERNEL_OBJECTS()->LookupObject<rex::system::XFile>(static_cast<uint32_t>(hFile));
  if (!file) {
    if (lpNumberOfBytesWritten)
      *lpNumberOfBytesWritten = 0;
    return 0;
  }

  // (Hunt v1.4.6, ronda 7, A3-R7-07.) Same 16-byte OVERLAPPED as
  // ReadFile above, with only a NULL-check. (The data buffer itself
  // is validated inside XFile::Write.)
  if (lpOverlapped && !GuestRangeWritable(lpOverlapped.guest_address(), 16)) {
    return 0;
  }

  uint64_t offset = static_cast<uint64_t>(-1);
  if (lpOverlapped) {
    auto* ov = reinterpret_cast<rex::be<uint32_t>*>(
        static_cast<uint8_t*>(static_cast<void*>(lpOverlapped)));
    offset =
        (static_cast<uint64_t>(static_cast<uint32_t>(ov[3])) << 32) | static_cast<uint32_t>(ov[2]);
  }

  uint32_t bytes_written = 0;
  X_STATUS status =
      file->Write(lpBuffer.guest_address(), static_cast<uint32_t>(nNumberOfBytesToWrite), offset,
                  &bytes_written, 0);

  if (lpOverlapped) {
    auto* ov = reinterpret_cast<rex::be<uint32_t>*>(
        static_cast<uint8_t*>(static_cast<void*>(lpOverlapped)));
    ov[0] = 0;
    ov[1] = bytes_written;
  } else if (lpNumberOfBytesWritten) {
    *lpNumberOfBytesWritten = bytes_written;
  }

  return XSUCCEEDED(status) ? 1u : 0u;
}

u32 SetFilePointer_entry(u32 hFile, u32 lDistanceToMove, mapped_u32 lpDistanceToMoveHigh,
                         u32 dwMoveMethod) {
  auto file = REX_KERNEL_OBJECTS()->LookupObject<rex::system::XFile>(static_cast<uint32_t>(hFile));
  if (!file)
    return kInvalidHandleValue;

  int64_t distance = static_cast<int32_t>(static_cast<uint32_t>(lDistanceToMove));
  if (lpDistanceToMoveHigh) {
    distance |=
        static_cast<int64_t>(static_cast<int32_t>(static_cast<uint32_t>(*lpDistanceToMoveHigh)))
        << 32;
  }

  uint64_t new_pos = 0;
  // (Hunt v1.4.6, A2-R4-14.) A negative result used to wrap to ~2^64 and
  // get stored as the position; fail the seek instead, like Win32.
  if (!ComputeSeekPosition(file.get(), distance, static_cast<uint32_t>(dwMoveMethod), &new_pos)) {
    return kInvalidHandleValue;
  }

  file->set_position(new_pos);
  if (lpDistanceToMoveHigh)
    *lpDistanceToMoveHigh = static_cast<uint32_t>(new_pos >> 32);
  return static_cast<uint32_t>(new_pos & 0xFFFFFFFF);
}

u32 GetFileSize_entry(u32 hFile, mapped_u32 lpFileSizeHigh) {
  auto file = REX_KERNEL_OBJECTS()->LookupObject<rex::system::XFile>(static_cast<uint32_t>(hFile));
  if (!file)
    return kInvalidHandleValue;

  uint64_t size = file->entry()->size();
  if (lpFileSizeHigh)
    *lpFileSizeHigh = static_cast<uint32_t>(size >> 32);
  return static_cast<uint32_t>(size & 0xFFFFFFFF);
}

u32 GetFileSizeEx_entry(u32 hFile, mapped_void lpFileSize) {
  auto file = REX_KERNEL_OBJECTS()->LookupObject<rex::system::XFile>(static_cast<uint32_t>(hFile));
  if (!file)
    return 0;

  // (Hunt v1.4.6, ronda 7, A3-R7-07.) The 8-byte out-param (high/low
  // dwords) is written with only a NULL-check.
  if (lpFileSize && !GuestRangeWritable(lpFileSize.guest_address(), 8)) {
    return 0;
  }

  uint64_t size = file->entry()->size();
  if (lpFileSize) {
    auto* out =
        reinterpret_cast<rex::be<uint32_t>*>(static_cast<uint8_t*>(static_cast<void*>(lpFileSize)));
    out[0] = static_cast<uint32_t>(size >> 32);
    out[1] = static_cast<uint32_t>(size & 0xFFFFFFFF);
  }
  return 1;
}

u32 SetEndOfFile_entry(u32 hFile) {
  auto file = REX_KERNEL_OBJECTS()->LookupObject<rex::system::XFile>(static_cast<uint32_t>(hFile));
  if (!file)
    return 0;
  X_STATUS status = file->SetLength(file->position());
  return XSUCCEEDED(status) ? 1u : 0u;
}

u32 FlushFileBuffers_entry(u32 hFile) {
  // (Second sweep, V-A2-01.) This used to ignore the handle entirely and
  // return success -- the CRT twin of A2-R4-19's NtFlushBuffersFile.
  // Validate the handle and flush for real.
  auto file = REX_KERNEL_OBJECTS()->LookupObject<rex::system::XFile>(static_cast<uint32_t>(hFile));
  if (!file) {
    return 0;
  }
  file->Flush();
  return 1;
}

u32 DeleteFileA_entry(mapped_string lpFileName) {
  // (Hunt v1.4.6, A2-R4-13.) NULL filename: string_view(nullptr) is UB.
  if (!lpFileName) {
    return 0;
  }
  const char* path = static_cast<const char*>(lpFileName);
  bool ok = REX_KERNEL_FS()->DeletePath(path);
  if (!ok)
    REXKRNL_NOISY_DEBUG("rexcrt_DeleteFileA: FAILED '{}'", path);
  return ok ? 1u : 0u;
}

u32 CloseHandle_entry(u32 hObject) {
  uint32_t h = static_cast<uint32_t>(hObject);
  if (h == kInvalidHandleValue || h == 0)
    return 0;
  auto status = REX_KERNEL_OBJECTS()->ReleaseHandle(h);
  if (XFAILED(status)) {
    REXKRNL_WARN("rexcrt_CloseHandle: unknown handle {:#x}", h);
    return 0;
  }
  return 1;
}

static bool FillFindData(mapped_void lpFindFileData, rex::filesystem::Entry* entry) {
  // (Hunt v1.4.6, A2-R4-13.) A NULL lpFindFileData used to be memset
  // through unchecked (host SIGSEGV); a NULL entry is the same hole.
  // Callers fail the find instead.
  if (!lpFindFileData || !entry) {
    return false;
  }
  auto* buf = static_cast<uint8_t*>(static_cast<void*>(lpFindFileData));
  std::memset(buf, 0, 0x140);

  auto* fields = reinterpret_cast<be<uint32_t>*>(buf);
  fields[0] = entry->attributes();  // 0x00 dwFileAttributes
  fields[1] =
      static_cast<uint32_t>(entry->create_timestamp() & 0xFFFFFFFF);   // 0x04 ftCreationTime.Low
  fields[2] = static_cast<uint32_t>(entry->create_timestamp() >> 32);  // 0x08 ftCreationTime.High
  fields[3] =
      static_cast<uint32_t>(entry->access_timestamp() & 0xFFFFFFFF);   // 0x0C ftLastAccessTime.Low
  fields[4] = static_cast<uint32_t>(entry->access_timestamp() >> 32);  // 0x10 ftLastAccessTime.High
  fields[5] =
      static_cast<uint32_t>(entry->write_timestamp() & 0xFFFFFFFF);   // 0x14 ftLastWriteTime.Low
  fields[6] = static_cast<uint32_t>(entry->write_timestamp() >> 32);  // 0x18 ftLastWriteTime.High
  fields[7] = static_cast<uint32_t>(entry->size() >> 32);             // 0x1C nFileSizeHigh
  fields[8] = static_cast<uint32_t>(entry->size() & 0xFFFFFFFF);      // 0x20 nFileSizeLow
  // 0x24 dwReserved0, 0x28 dwReserved1 already zero

  // 0x2C cFileName[260]
  const auto& name = entry->name();
  rex::string::copy_truncating(reinterpret_cast<char*>(buf + 0x2C), name, 260);
  // 0x130 cAlternateFileName[14] already zero
  return true;
}

u32 FindFirstFileA_entry(mapped_string lpFileName, mapped_void lpFindFileData) {
  // (Hunt v1.4.6, A2-R4-13.) NULL filename (string_view(nullptr) is UB)
  // or NULL out-buffer (FillFindData would memset through it).
  if (!lpFileName || !lpFindFileData) {
    return kInvalidHandleValue;
  }
  const char* path = static_cast<const char*>(lpFileName);
  auto dir = rex::string::utf8_find_base_guest_path(path);
  auto pattern = rex::string::utf8_find_name_from_guest_path(path);

  auto* ks = REX_KERNEL_STATE();
  rex::filesystem::File* vfs_file = nullptr;
  rex::filesystem::FileAction action;
  X_STATUS status = ks->file_system()->OpenFile(
      nullptr, dir, rex::filesystem::FileDisposition::kOpen, 0, true, false, &vfs_file, &action);
  if (XFAILED(status) || !vfs_file) {
    REXKRNL_DEBUG("rexcrt_FindFirstFileA: dir not found '{}'", dir);
    return kInvalidHandleValue;
  }

  auto* xfile = new rex::system::XFile(ks, vfs_file, true);
  xfile->SetFindPattern(pattern);

  auto* entry = xfile->FindNext();
  if (!entry) {
    REXKRNL_DEBUG("rexcrt_FindFirstFileA: no matches for '{}' in '{}'", pattern, dir);
    REX_KERNEL_OBJECTS()->ReleaseHandle(xfile->handle());
    return kInvalidHandleValue;
  }

  if (!FillFindData(lpFindFileData, entry)) {
    REX_KERNEL_OBJECTS()->ReleaseHandle(xfile->handle());
    return kInvalidHandleValue;
  }
  REXKRNL_TRACE("rexcrt_FindFirstFileA: '{}' first match='{}' handle={:#x}", path, entry->name(),
                xfile->handle());
  return xfile->handle();
}

u32 FindNextFileA_entry(u32 hFindFile, mapped_void lpFindFileData) {
  auto file =
      REX_KERNEL_OBJECTS()->LookupObject<rex::system::XFile>(static_cast<uint32_t>(hFindFile));
  if (!file)
    return 0;

  auto* entry = file->FindNext();
  if (!entry)
    return 0;

  // (Hunt v1.4.6, A2-R4-13.) FillFindData now reports a NULL out-buffer
  // instead of memsetting through it.
  if (!FillFindData(lpFindFileData, entry)) {
    return 0;
  }
  return 1;
}

u32 FindClose_entry(u32 hFindFile) {
  return CloseHandle_entry(hFindFile);
}

u32 CreateDirectoryA_entry(mapped_string lpPathName, mapped_void lpSecurityAttributes) {
  // (Hunt v1.4.6, A2-R4-13.) NULL path: string_view(nullptr) is UB.
  if (!lpPathName) {
    return 0;
  }
  const char* path = static_cast<const char*>(lpPathName);
  auto* entry = REX_KERNEL_FS()->CreatePath(path, rex::filesystem::kFileAttributeDirectory);
  return entry ? 1u : 0u;
}

u32 MoveFileA_entry(mapped_string lpExistingFileName, mapped_string lpNewFileName) {
  // (Hunt v1.4.6, A2-R4-13.) NULL path on either side: string_view
  // (nullptr) is UB.
  if (!lpExistingFileName || !lpNewFileName) {
    return 0;
  }
  const char* src = static_cast<const char*>(lpExistingFileName);
  const char* dst = static_cast<const char*>(lpNewFileName);

  auto* fs = REX_KERNEL_FS();
  auto* src_entry = fs->ResolvePath(src);
  if (!src_entry) {
    REXKRNL_DEBUG("rexcrt_MoveFileA: source not found '{}'", src);
    return 0;
  }
  // Win32 MoveFileA fails if the destination already exists; callers wanting
  // overwrite semantics use MoveFileExA with MOVEFILE_REPLACE_EXISTING.
  if (fs->ResolvePath(dst)) {
    REXKRNL_DEBUG("rexcrt_MoveFileA: destination exists '{}'", dst);
    return 0;
  }

  X_STATUS rename_status = src_entry->Rename(rex::to_path(dst));
  if (rename_status != X_STATUS_SUCCESS) {
    REXKRNL_DEBUG("rexcrt_MoveFileA: rename failed '{}' -> '{}': {:#x}", src, dst, rename_status);
    return 0;
  }
  REXKRNL_TRACE("rexcrt_MoveFileA: '{}' -> '{}'", src, dst);
  return 1;
}

u32 SetFileAttributesA_entry(mapped_string lpFileName, u32 dwFileAttributes) {
  (void)lpFileName;
  (void)dwFileAttributes;
  return 1;
}

u32 GetFileAttributesA_entry(mapped_string lpFileName) {
  // (Hunt v1.4.6, A2-R4-13.) NULL filename: string_view(nullptr) is UB.
  if (!lpFileName) {
    return kInvalidHandleValue;  // INVALID_FILE_ATTRIBUTES
  }
  const char* path = static_cast<const char*>(lpFileName);
  auto* entry = REX_KERNEL_FS()->ResolvePath(path);
  if (!entry) {
    REXKRNL_DEBUG("rexcrt_GetFileAttributesA: not found '{}'", path);
    return kInvalidHandleValue;  // INVALID_FILE_ATTRIBUTES
  }
  REXKRNL_TRACE("rexcrt_GetFileAttributesA: '{}' -> attrs={:#x}", path, entry->attributes());
  return entry->attributes();
}

u32 GetFileAttributesExA_entry(u32 fInfoLevelId, mapped_string lpFileName,
                               mapped_void lpFileInformation) {
  // (Hunt v1.4.6, A2-R4-13.) NULL filename (string_view(nullptr) is UB)
  // or NULL out-buffer (the buf[] writes below would dereference it).
  if (!lpFileName || !lpFileInformation) {
    return 0;
  }
  const char* path = static_cast<const char*>(lpFileName);
  auto* entry = REX_KERNEL_FS()->ResolvePath(path);
  if (!entry) {
    REXKRNL_DEBUG("rexcrt_GetFileAttributesExA: not found '{}'", path);
    return 0;
  }

  // Fill WIN32_FILE_ATTRIBUTE_DATA (GetFileExInfoStandard = 0)
  auto* buf =
      reinterpret_cast<be<uint32_t>*>(static_cast<uint8_t*>(static_cast<void*>(lpFileInformation)));
  buf[0] = entry->attributes();                                            // dwFileAttributes
  buf[1] = static_cast<uint32_t>(entry->create_timestamp() & 0xFFFFFFFF);  // ftCreationTime.Low
  buf[2] = static_cast<uint32_t>(entry->create_timestamp() >> 32);         // ftCreationTime.High
  buf[3] = static_cast<uint32_t>(entry->access_timestamp() & 0xFFFFFFFF);  // ftLastAccessTime.Low
  buf[4] = static_cast<uint32_t>(entry->access_timestamp() >> 32);         // ftLastAccessTime.High
  buf[5] = static_cast<uint32_t>(entry->write_timestamp() & 0xFFFFFFFF);   // ftLastWriteTime.Low
  buf[6] = static_cast<uint32_t>(entry->write_timestamp() >> 32);          // ftLastWriteTime.High
  buf[7] = static_cast<uint32_t>(entry->size() >> 32);                     // nFileSizeHigh
  buf[8] = static_cast<uint32_t>(entry->size() & 0xFFFFFFFF);              // nFileSizeLow
  return 1;
}

u32 SetFilePointerEx_entry(u32 hFile, u32 distHigh, u32 distLow, mapped_void lpNewFilePointer,
                           u32 dwMoveMethod) {
  auto file = REX_KERNEL_OBJECTS()->LookupObject<rex::system::XFile>(static_cast<uint32_t>(hFile));
  if (!file)
    return 0;

  int64_t distance =
      static_cast<int64_t>((static_cast<uint64_t>(static_cast<uint32_t>(distHigh)) << 32) |
                           static_cast<uint32_t>(distLow));

  uint64_t new_pos = 0;
  // (Hunt v1.4.6, A2-R4-14.) Same wrapping negative seek as
  // SetFilePointer above: fail it instead of storing ~2^64.
  if (!ComputeSeekPosition(file.get(), distance, static_cast<uint32_t>(dwMoveMethod), &new_pos)) {
    return 0;
  }

  // (Hunt v1.4.6, ronda 7, A3-R7-07.) As GetFileSizeEx above: the
  // 8-byte out-param is written with only a NULL-check. Validate it
  // before the seek takes effect, so a bad pointer fails without
  // moving the file position.
  if (lpNewFilePointer && !GuestRangeWritable(lpNewFilePointer.guest_address(), 8)) {
    return 0;
  }

  file->set_position(new_pos);

  if (lpNewFilePointer) {
    auto* out = reinterpret_cast<be<uint32_t>*>(
        static_cast<uint8_t*>(static_cast<void*>(lpNewFilePointer)));
    out[0] = static_cast<uint32_t>(new_pos & 0xFFFFFFFF);  // LowPart
    out[1] = static_cast<uint32_t>(new_pos >> 32);         // HighPart
  }
  return 1;
}

u32 SetFileTime_entry(u32 hFile, mapped_void lpCreationTime, mapped_void lpLastAccessTime,
                      mapped_void lpLastWriteTime) {
  // VFS doesn't support modifying timestamps; report success.
  (void)hFile;
  (void)lpCreationTime;
  (void)lpLastAccessTime;
  (void)lpLastWriteTime;
  return 1;
}

u32 CompareFileTime_entry(mapped_void lpFileTime1, mapped_void lpFileTime2) {
  // (Hunt v1.4.6, A2-R4-13.) A NULL FILETIME used to be dereferenced
  // below. Win32 CompareFileTime has no error return (its values are
  // -1/0/1), so a NULL input is answered as "earlier" (-1) rather than
  // crashing; the choice is documented because it is arbitrary.
  if (!lpFileTime1 || !lpFileTime2) {
    return static_cast<uint32_t>(-1);
  }
  auto* ft1 =
      reinterpret_cast<be<uint32_t>*>(static_cast<uint8_t*>(static_cast<void*>(lpFileTime1)));
  auto* ft2 =
      reinterpret_cast<be<uint32_t>*>(static_cast<uint8_t*>(static_cast<void*>(lpFileTime2)));
  // FILETIME: { dwLowDateTime, dwHighDateTime }
  uint64_t t1 =
      (static_cast<uint64_t>(static_cast<uint32_t>(ft1[1])) << 32) | static_cast<uint32_t>(ft1[0]);
  uint64_t t2 =
      (static_cast<uint64_t>(static_cast<uint32_t>(ft2[1])) << 32) | static_cast<uint32_t>(ft2[0]);
  if (t1 < t2)
    return static_cast<uint32_t>(-1);
  if (t1 > t2)
    return 1u;
  return 0u;
}

u32 CopyFileA_entry(mapped_string lpExistingFileName, mapped_string lpNewFileName,
                    u32 bFailIfExists) {
  // (Hunt v1.4.6, A2-R4-13.) NULL filename on either side:
  // string_view(nullptr) is UB.
  if (!lpExistingFileName || !lpNewFileName) {
    return 0;
  }
  const char* src = static_cast<const char*>(lpExistingFileName);
  const char* dst = static_cast<const char*>(lpNewFileName);

  auto* ks = REX_KERNEL_STATE();

  // (Hunt v1.4.6, A2-R4-03.) Copying a file onto itself used to open the
  // destination with kOverwriteIf, which deleted the entry the just-opened
  // source File points at -- a use-after-free. Win32 CopyFile fails when
  // source and destination are the same file, so fail here instead.
  // ResolvePath canonicalizes, so case/.. variants of the same path are
  // caught too; a not-yet-existing destination resolves to null and is
  // unaffected.
  auto* src_entry = REX_KERNEL_FS()->ResolvePath(src);
  if (src_entry && src_entry == REX_KERNEL_FS()->ResolvePath(dst)) {
    REXKRNL_DEBUG("rexcrt_CopyFileA: source and destination are the same file '{}'", src);
    return 0;
  }

  // Open source for reading
  rex::filesystem::File* src_file = nullptr;
  rex::filesystem::FileAction action;
  X_STATUS status = ks->file_system()->OpenFile(
      nullptr, src, rex::filesystem::FileDisposition::kOpen,
      rex::filesystem::FileAccess::kFileReadData, false, true, &src_file, &action);
  if (XFAILED(status) || !src_file) {
    REXKRNL_DEBUG("rexcrt_CopyFileA: failed to open source '{}'", src);
    return 0;
  }

  // Open/create destination
  auto disp = static_cast<uint32_t>(bFailIfExists) ? rex::filesystem::FileDisposition::kCreate
                                                   : rex::filesystem::FileDisposition::kOverwriteIf;
  rex::filesystem::File* dst_file = nullptr;
  status =
      ks->file_system()->OpenFile(nullptr, dst, disp, rex::filesystem::FileAccess::kFileWriteData,
                                  false, true, &dst_file, &action);
  if (XFAILED(status) || !dst_file) {
    src_file->Destroy();
    REXKRNL_DEBUG("rexcrt_CopyFileA: failed to open dest '{}'", dst);
    return 0;
  }

  // Copy data in 64KB chunks
  constexpr size_t kBufSize = 65536;
  auto buf = std::make_unique<uint8_t[]>(kBufSize);
  uint64_t offset = 0;
  bool ok = true;
  // The source size is the contract: the copy is complete only when every
  // byte of it has been read. (Hunt v1.4.6, A2-R4-05.) A read error used
  // to break out of this loop with ok still true, so a truncated
  // destination was reported as a successful copy -- the same hole the
  // ExtractEntry fix closed in content_manager.cpp.
  const uint64_t src_size = src_file->entry() ? src_file->entry()->size() : 0;
  const bool have_src_size = src_file->entry() != nullptr;
  for (;;) {
    size_t bytes_read = 0;
    status = src_file->ReadSync(std::span<uint8_t>(buf.get(), kBufSize), offset, &bytes_read);
    if (XFAILED(status)) {
      // END_OF_FILE is the clean end of the copy, but only when the
      // source is fully consumed; EOF early (or any other failure) means
      // the source is short and the destination is truncated.
      if (status != X_STATUS_END_OF_FILE || (have_src_size && offset != src_size)) {
        ok = false;
      }
      break;
    }
    if (bytes_read == 0) {
      // SUCCESS with 0 bytes before the source is exhausted is a short
      // read, not a clean EOF.
      if (!have_src_size || offset != src_size) {
        ok = false;
      }
      break;
    }

    size_t bytes_written = 0;
    status = dst_file->WriteSync(std::span<const uint8_t>(buf.get(), bytes_read), offset,
                                 &bytes_written);
    if (XFAILED(status) || bytes_written != bytes_read) {
      ok = false;
      break;
    }
    offset += bytes_read;
  }

  dst_file->Destroy();
  src_file->Destroy();
  REXKRNL_TRACE("rexcrt_CopyFileA: '{}' -> '{}' {}", src, dst, ok ? "OK" : "FAILED");
  return ok ? 1u : 0u;
}

u32 RemoveDirectoryA_entry(mapped_string lpPathName) {
  // (Hunt v1.4.6, A2-R4-13.) NULL path: string_view(nullptr) is UB.
  if (!lpPathName) {
    return 0;
  }
  const char* path = static_cast<const char*>(lpPathName);
  bool ok = REX_KERNEL_FS()->DeletePath(path);
  if (!ok)
    REXKRNL_DEBUG("rexcrt_RemoveDirectoryA: FAILED '{}'", path);
  return ok ? 1u : 0u;
}

u32 GetFileType_entry(u32 hFile) {
  auto file = REX_KERNEL_OBJECTS()->LookupObject<rex::system::XFile>(static_cast<uint32_t>(hFile));
  if (!file)
    return 0;  // FILE_TYPE_UNKNOWN
  return 1;    // FILE_TYPE_DISK
}

u32 GetDiskFreeSpaceExA_entry(mapped_string lpDirectoryName,
                              mapped_void lpFreeBytesAvailableToCaller,
                              mapped_void lpTotalNumberOfBytes,
                              mapped_void lpTotalNumberOfFreeBytes) {
  // (Second sweep, V-A2-03.) Same NULL-filename class as A2-R4-13, on a
  // site the audit missed: string_view(nullptr) is UB.
  if (!lpDirectoryName) {
    return 0;
  }
  const char* path = static_cast<const char*>(lpDirectoryName);
  auto* entry = REX_KERNEL_FS()->ResolvePath(path);
  if (!entry) {
    REXKRNL_DEBUG("rexcrt_GetDiskFreeSpaceExA: path not found '{}'", path);
    return 0;
  }

  auto* dev = entry->device();
  uint64_t bytes_per_au =
      static_cast<uint64_t>(dev->sectors_per_allocation_unit()) * dev->bytes_per_sector();
  uint64_t total_bytes = static_cast<uint64_t>(dev->total_allocation_units()) * bytes_per_au;
  uint64_t free_bytes = static_cast<uint64_t>(dev->available_allocation_units()) * bytes_per_au;

  if (lpFreeBytesAvailableToCaller) {
    auto* out = reinterpret_cast<be<uint32_t>*>(
        static_cast<uint8_t*>(static_cast<void*>(lpFreeBytesAvailableToCaller)));
    out[0] = static_cast<uint32_t>(free_bytes & 0xFFFFFFFF);
    out[1] = static_cast<uint32_t>(free_bytes >> 32);
  }
  if (lpTotalNumberOfBytes) {
    auto* out = reinterpret_cast<be<uint32_t>*>(
        static_cast<uint8_t*>(static_cast<void*>(lpTotalNumberOfBytes)));
    out[0] = static_cast<uint32_t>(total_bytes & 0xFFFFFFFF);
    out[1] = static_cast<uint32_t>(total_bytes >> 32);
  }
  if (lpTotalNumberOfFreeBytes) {
    auto* out = reinterpret_cast<be<uint32_t>*>(
        static_cast<uint8_t*>(static_cast<void*>(lpTotalNumberOfFreeBytes)));
    out[0] = static_cast<uint32_t>(free_bytes & 0xFFFFFFFF);
    out[1] = static_cast<uint32_t>(free_bytes >> 32);
  }

  REXKRNL_TRACE("rexcrt_GetDiskFreeSpaceExA: '{}' total={}MB free={}MB", path,
                total_bytes / (1024 * 1024), free_bytes / (1024 * 1024));
  return 1;
}

}  // namespace rex::kernel::crt

REX_HOOK(rexcrt_CreateFileA, rex::kernel::crt::CreateFileA_entry)
REX_HOOK(rexcrt_ReadFile, rex::kernel::crt::ReadFile_entry)
REX_HOOK(rexcrt_WriteFile, rex::kernel::crt::WriteFile_entry)
REX_HOOK(rexcrt_SetFilePointer, rex::kernel::crt::SetFilePointer_entry)
REX_HOOK(rexcrt_GetFileSize, rex::kernel::crt::GetFileSize_entry)
REX_HOOK(rexcrt_GetFileSizeEx, rex::kernel::crt::GetFileSizeEx_entry)
REX_HOOK(rexcrt_SetEndOfFile, rex::kernel::crt::SetEndOfFile_entry)
REX_HOOK(rexcrt_FlushFileBuffers, rex::kernel::crt::FlushFileBuffers_entry)
REX_HOOK(rexcrt_DeleteFileA, rex::kernel::crt::DeleteFileA_entry)
REX_HOOK(rexcrt_CloseHandle, rex::kernel::crt::CloseHandle_entry)
REX_HOOK(rexcrt_FindFirstFileA, rex::kernel::crt::FindFirstFileA_entry)
REX_HOOK(rexcrt_FindNextFileA, rex::kernel::crt::FindNextFileA_entry)
REX_HOOK(rexcrt_FindClose, rex::kernel::crt::FindClose_entry)
REX_HOOK(rexcrt_CreateDirectoryA, rex::kernel::crt::CreateDirectoryA_entry)
REX_HOOK(rexcrt_MoveFileA, rex::kernel::crt::MoveFileA_entry)
REX_HOOK(rexcrt_SetFileAttributesA, rex::kernel::crt::SetFileAttributesA_entry)
REX_HOOK(rexcrt_GetFileAttributesA, rex::kernel::crt::GetFileAttributesA_entry)
REX_HOOK(rexcrt_GetFileAttributesExA, rex::kernel::crt::GetFileAttributesExA_entry)
REX_HOOK(rexcrt_SetFilePointerEx, rex::kernel::crt::SetFilePointerEx_entry)
REX_HOOK(rexcrt_SetFileTime, rex::kernel::crt::SetFileTime_entry)
REX_HOOK(rexcrt_CompareFileTime, rex::kernel::crt::CompareFileTime_entry)
REX_HOOK(rexcrt_CopyFileA, rex::kernel::crt::CopyFileA_entry)
REX_HOOK(rexcrt_RemoveDirectoryA, rex::kernel::crt::RemoveDirectoryA_entry)
REX_HOOK(rexcrt_GetFileType, rex::kernel::crt::GetFileType_entry)

// XAM exports -- same implementations, for games that import file I/O from xam.xex
REX_EXPORT(__imp__CreateFileA, rex::kernel::crt::CreateFileA_entry)
REX_EXPORT(__imp__ReadFile, rex::kernel::crt::ReadFile_entry)
REX_EXPORT(__imp__WriteFile, rex::kernel::crt::WriteFile_entry)
REX_EXPORT(__imp__SetFilePointer, rex::kernel::crt::SetFilePointer_entry)
REX_EXPORT(__imp__GetFileSize, rex::kernel::crt::GetFileSize_entry)
REX_EXPORT(__imp__GetFileSizeEx, rex::kernel::crt::GetFileSizeEx_entry)
REX_EXPORT(__imp__SetEndOfFile, rex::kernel::crt::SetEndOfFile_entry)
REX_EXPORT(__imp__FlushFileBuffers, rex::kernel::crt::FlushFileBuffers_entry)
REX_EXPORT(__imp__DeleteFileA, rex::kernel::crt::DeleteFileA_entry)
REX_EXPORT(__imp__CloseHandle, rex::kernel::crt::CloseHandle_entry)
REX_EXPORT(__imp__FindFirstFileA, rex::kernel::crt::FindFirstFileA_entry)
REX_EXPORT(__imp__FindNextFileA, rex::kernel::crt::FindNextFileA_entry)
REX_EXPORT(__imp__CreateDirectoryA, rex::kernel::crt::CreateDirectoryA_entry)
REX_EXPORT(__imp__MoveFileA, rex::kernel::crt::MoveFileA_entry)
REX_EXPORT(__imp__SetFileAttributesA, rex::kernel::crt::SetFileAttributesA_entry)
REX_EXPORT(__imp__GetFileAttributesA, rex::kernel::crt::GetFileAttributesA_entry)
REX_EXPORT(__imp__GetFileAttributesExA, rex::kernel::crt::GetFileAttributesExA_entry)
REX_EXPORT(__imp__SetFilePointerEx, rex::kernel::crt::SetFilePointerEx_entry)
REX_EXPORT(__imp__SetFileTime, rex::kernel::crt::SetFileTime_entry)
REX_EXPORT(__imp__CompareFileTime, rex::kernel::crt::CompareFileTime_entry)
REX_EXPORT(__imp__CopyFileA, rex::kernel::crt::CopyFileA_entry)
REX_EXPORT(__imp__GetDiskFreeSpaceExA, rex::kernel::crt::GetDiskFreeSpaceExA_entry)
