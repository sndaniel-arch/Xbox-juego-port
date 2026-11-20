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

#include <rex/filesystem/devices/disc_image_entry.h>
#include <rex/filesystem/devices/disc_image_file.h>

#include <algorithm>

namespace rex::filesystem {

DiscImageFile::DiscImageFile(uint32_t file_access, DiscImageEntry* entry)
    : File(file_access, entry), entry_(entry) {}

DiscImageFile::~DiscImageFile() = default;

void DiscImageFile::Destroy() {
  delete this;
}

X_STATUS DiscImageFile::ReadSync(std::span<uint8_t> buffer, size_t byte_offset,
                                 size_t* out_bytes_read) {
  if (byte_offset >= entry_->size()) {
    // (Hunt v1.4.6, A2-R6-09.) The EOF branch never wrote the count.
    if (out_bytes_read) {
      *out_bytes_read = 0;
    }
    return X_STATUS_END_OF_FILE;
  }
  size_t real_offset = entry_->data_offset() + byte_offset;
  size_t real_length = std::min(buffer.size(), entry_->data_size() - byte_offset);
// (Hunt v1.4.6, A2-R2-07.) Defense in depth for the ReadEntry check in
    // disc_image_device.cpp: a data range that runs past the mapped image
    // must fail, not memcpy out of bounds. Unreachable for entries built
    // by ReadEntry (it rejects them at mount), but ReadSync is the last
    // place the memcpy can still be stopped.
    if (real_offset > entry_->mmap()->size() ||
        real_length > entry_->mmap()->size() - real_offset) {
        if (out_bytes_read) {
            *out_bytes_read = 0;
        }
        return X_STATUS_UNSUCCESSFUL;
    }
    std::memcpy(buffer.data(), entry_->mmap()->data() + real_offset, real_length);
  // (Hunt v1.4.6, A2-R6-09.) Null-guarded write of the count.
  if (out_bytes_read) {
    *out_bytes_read = real_length;
  }
  return X_STATUS_SUCCESS;
}

}  // namespace rex::filesystem
