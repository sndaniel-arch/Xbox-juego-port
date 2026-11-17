/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2014 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <rex/filesystem/devices/stfs_container_entry.h>
#include <rex/filesystem/devices/stfs_container_file.h>

#include <algorithm>
#include <cmath>

#include <rex/math.h>

namespace rex::filesystem {

StfsContainerFile::StfsContainerFile(uint32_t file_access, StfsContainerEntry* entry)
    : File(file_access, entry), entry_(entry) {}

StfsContainerFile::~StfsContainerFile() = default;

void StfsContainerFile::Destroy() {
  delete this;
}

X_STATUS StfsContainerFile::ReadSync(std::span<uint8_t> buffer, size_t byte_offset,
                                     size_t* out_bytes_read) {
  if (byte_offset >= entry_->size()) {
    return X_STATUS_END_OF_FILE;
  }

  size_t src_offset = 0;
  uint8_t* p = buffer.data();
  size_t remaining_length = std::min(buffer.size(), entry_->size() - byte_offset);

  *out_bytes_read = 0;
  for (size_t i = 0; i < entry_->block_list().size(); i++) {
    auto& record = entry_->block_list()[i];
    if (src_offset + record.length <= byte_offset) {
      // Doesn't begin in this region. Skip it.
      src_offset += record.length;
      continue;
    }

    size_t read_offset = (byte_offset > src_offset) ? byte_offset - src_offset : 0;
    size_t read_length = std::min(record.length - read_offset, remaining_length);

    auto files = entry_->files();
    auto file_it = files->find(record.file);
    if (file_it == files->end()) {
      // Corrupt block list (SVOD file index outside the container's data
      // files): fail instead of throwing std::out_of_range, which has no
      // catch on the read path and would terminate the process.
      return X_STATUS_UNSUCCESSFUL;
    }
    auto& file = file_it->second;
    // Positional read: works identically for a whole host file and for a
    // slice of a larger file (fd-backed container inside an APK), and needs
    // no seek, so concurrent reads from several game threads are safe in
    // fd mode. Short reads keep the historical behaviour (count what was
    // actually read).
    auto num_read = file->ReadAtPartial(record.offset + read_offset, p, read_length);

    *out_bytes_read += num_read;
    p += num_read;
    src_offset += record.length;
    remaining_length -= num_read;
    if (num_read < read_length) {
      // F-round2 (F5): a short read means the backing bytes are gone
      // (truncated/corrupt package: only the tail of this record exists).
      // Continuing into the next record would copy ITS bytes at the wrong
      // buffer offset and still return SUCCESS -- the next record's data
      // lands read_length-num_read bytes too early and the caller never
      // learns the file is short. ExtractEntry (content_manager.cpp) only
      // fails on bytes_read == 0, so a mid-file short read used to install
      // a silently shifted DLC file AND write the .header for it. Stop
      // here: the caller sees fewer bytes than requested and fails/retries
      // loudly instead (ExtractEntry re-reads at the gap and gets 0).
      break;
    }
    if (remaining_length == 0) {
      break;
    }
  }

  return X_STATUS_SUCCESS;
}

}  // namespace rex::filesystem
