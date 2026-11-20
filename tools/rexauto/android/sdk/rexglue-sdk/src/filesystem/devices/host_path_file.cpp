/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2013 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <rex/filesystem/devices/host_path_entry.h>
#include <rex/filesystem/devices/host_path_file.h>

namespace rex::filesystem {

HostPathFile::HostPathFile(uint32_t file_access, HostPathEntry* entry,
                           std::unique_ptr<rex::filesystem::FileHandle> file_handle)
    : File(file_access, entry), file_handle_(std::move(file_handle)) {}

HostPathFile::~HostPathFile() = default;

void HostPathFile::Destroy() {
  delete this;
}

X_STATUS HostPathFile::ReadSync(std::span<uint8_t> buffer, size_t byte_offset,
                                size_t* out_bytes_read) {
  if (!(file_access_ & (FileAccess::kGenericRead | FileAccess::kFileReadData))) {
    // (Hunt v1.4.6, A2-R2-05.) Denied paths must still write the count
    // (0, null-guarded), per the file.h contract (R6-09).
    if (out_bytes_read) {
      *out_bytes_read = 0;
    }
    return X_STATUS_ACCESS_DENIED;
  }

  // (Hunt v1.4.6, A2-R6-03/A2-R6-09.) A 0-byte read at/past EOF is EOF,
  // not SUCCESS + 0: pread() returns 0 at EOF and PosixFileHandle::Read
  // reports it as success, so the old code returned SUCCESS + 0 and any
  // status-driven reader looped on the same offset forever. A 0-length
  // buffer is still SUCCESS (nothing was asked for). The count goes
  // through a local so a null out_bytes_read is safe.
  size_t bytes_read = 0;
  if (file_handle_->Read(byte_offset, buffer.data(), buffer.size(), &bytes_read)) {
    if (out_bytes_read) {
      *out_bytes_read = bytes_read;
    }
    if (bytes_read == 0 && !buffer.empty()) {
      return X_STATUS_END_OF_FILE;
    }
    return X_STATUS_SUCCESS;
  } else {
    // (Hunt v1.4.6, A2-R3-02.) A failed pread is a real I/O error, not
    // end-of-file -- the read-side mirror of A2-R2-06, which fixed the
    // same mis-mapping for writes. PosixFileHandle::Read already wrote
    // the partial count into bytes_read before returning false, so keep
    // it (a mid-file disk error must not look like a clean EOF with 0
    // bytes, hiding bytes already copied into the guest buffer).
    if (out_bytes_read) {
      *out_bytes_read = bytes_read;
    }
    return X_STATUS_UNSUCCESSFUL;
  }
}

X_STATUS HostPathFile::WriteSync(std::span<const uint8_t> buffer, size_t byte_offset,
                                 size_t* out_bytes_written) {
  if (!(file_access_ &
        (FileAccess::kGenericWrite | FileAccess::kFileWriteData | FileAccess::kFileAppendData))) {
    // (Hunt v1.4.6, A2-R2-05.) Denied paths must still write the count
    // (0, null-guarded), per the file.h contract (R6-09).
    if (out_bytes_written) {
      *out_bytes_written = 0;
    }
    return X_STATUS_ACCESS_DENIED;
  }

  // (Hunt v1.4.6, A2-R6-09.) Same null-guard as ReadSync above.
  size_t bytes_written = 0;
  if (file_handle_->Write(byte_offset, buffer.data(), buffer.size(), &bytes_written)) {
    if (out_bytes_written) {
      *out_bytes_written = bytes_written;
    }
    return X_STATUS_SUCCESS;
  } else {
    if (out_bytes_written) {
      *out_bytes_written = 0;
    }
    // (Hunt v1.4.6, A2-R2-06.) A failed pwrite is a real I/O error
    // (EIO, ENOSPC, EFBIG, EBADF -- EINTR is retried and a 0-progress
    // write reports success with a partial count, so reaching here
    // always means an error), not end-of-file: EOF is not a write
    // status, and a guest treating EOF-on-write as "done" would stop
    // writing silently on a full disk instead of seeing the error.
    return X_STATUS_UNSUCCESSFUL;
  }
}

X_STATUS HostPathFile::SetLength(size_t length) {
  if (!(file_access_ & (FileAccess::kGenericWrite | FileAccess::kFileWriteData))) {
    return X_STATUS_ACCESS_DENIED;
  }

  if (file_handle_->SetLength(length)) {
    return X_STATUS_SUCCESS;
  } else {
    // (Hunt v1.4.6, A2-R2-06.) Same as WriteSync above: a failed
    // truncate is an I/O error, not end-of-file.
    return X_STATUS_UNSUCCESSFUL;
  }
}

}  // namespace rex::filesystem
