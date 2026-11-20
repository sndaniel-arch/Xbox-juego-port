/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2021 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <rex/filesystem/devices/null_entry.h>
#include <rex/filesystem/devices/null_file.h>

namespace rex::filesystem {

NullFile::NullFile(uint32_t file_access, NullEntry* entry) : File(file_access, entry) {}

NullFile::~NullFile() = default;

void NullFile::Destroy() {
  delete this;
}

X_STATUS NullFile::ReadSync(std::span<uint8_t> buffer, size_t byte_offset, size_t* out_bytes_read) {
  if (!(file_access_ & FileAccess::kFileReadData)) {
    // (Hunt v1.4.6, A2-R2-05.) Denied paths must still write the count
    // (0, null-guarded), per the file.h contract (R6-09).
    if (out_bytes_read) {
      *out_bytes_read = 0;
    }
    return X_STATUS_ACCESS_DENIED;
  }

  // (Hunt v1.4.6, A2-R6-04/A2-R6-09.) The null device has no bytes to
  // give: END_OF_FILE, not SUCCESS + 0 -- the same terminal signal every
  // other "nothing to read" device returns, so a status-driven reader
  // terminates instead of spinning. The count is written (0, guarded
  // against a null pointer) so no caller ever sees a stale value.
  if (out_bytes_read) {
    *out_bytes_read = 0;
  }
  return X_STATUS_END_OF_FILE;
}

X_STATUS NullFile::WriteSync(std::span<const uint8_t> buffer, size_t byte_offset,
                             size_t* out_bytes_written) {
  if (!(file_access_ & (FileAccess::kFileWriteData | FileAccess::kFileAppendData))) {
    // (Hunt v1.4.6, A2-R2-05.) Denied paths must still write the count
    // (0, null-guarded), per the file.h contract (R6-09).
    if (out_bytes_written) {
      *out_bytes_written = 0;
    }
    return X_STATUS_ACCESS_DENIED;
  }

  // (Hunt v1.4.6, A2-R6-04/A2-R6-09, fixed A2-R3-03.) Writes to the null
  // device are discarded by design (it exists to make cache/raw-partition
  // IO "succeed"), so SUCCESS stays -- but the count must be the full
  // buffer size, not 0: the old SUCCESS + 0 made any guest "write until
  // complete" loop spin forever, never making progress and never seeing
  // an error. Same "accepted and dropped" semantics as
  // XbMovieFile::WriteSync, which reports buffer.size().
  if (out_bytes_written) {
    *out_bytes_written = buffer.size();
  }
  return X_STATUS_SUCCESS;
}

X_STATUS NullFile::SetLength(size_t length) {
  if (!(file_access_ & FileAccess::kFileWriteData)) {
    return X_STATUS_ACCESS_DENIED;
  }

  return X_STATUS_SUCCESS;
}

}  // namespace rex::filesystem
