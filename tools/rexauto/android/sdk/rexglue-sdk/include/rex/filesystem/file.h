/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2015 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#pragma once

#include <cstdint>
#include <span>

#include <rex/system/xtypes.h>

namespace rex::filesystem {

class Entry;

class File {
 public:
  File(uint32_t file_access, Entry* entry) : file_access_(file_access), entry_(entry) {}
  virtual ~File() = default;

  virtual void Destroy() = 0;

  // (Hunt v1.4.6, A2-R6-09.) The out_bytes_read / out_bytes_written
  // pointers MAY be null: every implementation must guard the write
  // (write 0 when non-null) instead of dereferencing unconditionally.
  virtual X_STATUS ReadSync(std::span<uint8_t> buffer, size_t byte_offset,
                            size_t* out_bytes_read) = 0;
  virtual X_STATUS WriteSync(std::span<const uint8_t> buffer, size_t byte_offset,
                             size_t* out_bytes_written) = 0;

  // (Hunt v1.4.6, A2-R6-12.) Milliseconds the NtReadFile /
  // NtReadFileScatter caller should sleep after this file returns
  // X_STATUS_END_OF_FILE, to back off a guest thread looping on EOF
  // reads. Default 0 (no backoff). The sleep runs in the Nt* caller,
  // AFTER XFile::Read returns, so it never holds XFile::file_lock_.
  // Only files whose reads can legitimately return EOF forever (the
  // xbmovie probe) override this.
  virtual uint32_t EofBackoffMs() const { return 0; }

  // TODO: Parameters
  virtual X_STATUS ReadAsync(std::span<uint8_t> buffer, size_t byte_offset,
                             size_t* out_bytes_read) {
    (void)buffer;
    (void)byte_offset;
    (void)out_bytes_read;

    return X_STATUS_NOT_IMPLEMENTED;
  }

  // TODO: Parameters
  virtual X_STATUS WriteAsync(std::span<const uint8_t> buffer, size_t byte_offset,
                              size_t* out_bytes_written) {
    (void)buffer;
    (void)byte_offset;
    (void)out_bytes_written;

    return X_STATUS_NOT_IMPLEMENTED;
  }

  virtual X_STATUS SetLength(size_t length) {
    (void)length;
    return X_STATUS_NOT_IMPLEMENTED;
  }

  // rex::filesystem::FileAccess
  uint32_t file_access() const { return file_access_; }
  const Entry* entry() const { return entry_; }
  Entry* entry() { return entry_; }

 protected:
  // rex::filesystem::FileAccess
  uint32_t file_access_ = 0;
  Entry* entry_ = nullptr;
};

}  // namespace rex::filesystem
