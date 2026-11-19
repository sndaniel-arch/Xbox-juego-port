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
    // (Hunt v1.4.6, A2-R6-05/A2-R6-09.) The EOF branch never wrote the
    // count; a null out_bytes_read is safe here too.
    if (out_bytes_read) {
      *out_bytes_read = 0;
    }
    return X_STATUS_END_OF_FILE;
  }

  size_t src_offset = 0;
  uint8_t* p = buffer.data();
  size_t remaining_length = std::min(buffer.size(), entry_->size() - byte_offset);

  // (Hunt v1.4.6, A2-R6-09.) Accumulate locally and write back once, so
  // a null out_bytes_read never dereferences.
  size_t bytes_read = 0;
  bool hit_gap = false;
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
      if (out_bytes_read) {
        *out_bytes_read = bytes_read;
      }
      return X_STATUS_UNSUCCESSFUL;
    }
    auto& file = file_it->second;
    // Positional read: works identically for a whole host file and for a
    // slice of a larger file (fd-backed container inside an APK), and needs
    // no seek, so concurrent reads from several game threads are safe in
    // fd mode. Short reads keep the historical behaviour (count what was
    // actually read).
    auto num_read = file->ReadAtPartial(record.offset + read_offset, p, read_length);

    bytes_read += num_read;
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
      // (Hunt v1.4.6, A2-R6-05.) Remember the gap: the return below turns
      // a 0-byte read at the gap into END_OF_FILE. Without it, a
      // sequential reader that retries the same offset got SUCCESS + 0
      // forever (position_ only advances by the bytes actually read, so
      // the retry lands on the same hole) -- the same spin class as C-04.
      hit_gap = true;
      break;
    }
    if (remaining_length == 0) {
      break;
    }
  }

  if (out_bytes_read) {
    *out_bytes_read = bytes_read;
  }
  // (Hunt v1.4.6, A2-R6-05.) The hole does not refill: a read that got
  // nothing -- first read straight into the gap, or a retry at the same
  // offset after a partial read -- is EOF, not SUCCESS + 0. A partial
  // read still returns SUCCESS with the real count the first time; the
  // retry at the advanced offset then hits the gap with 0 bytes and gets
  // EOF. A 0-length buffer is SUCCESS (nothing was asked for), as before.
  if (bytes_read == 0 && hit_gap && !buffer.empty()) {
    return X_STATUS_END_OF_FILE;
  }
  return X_STATUS_SUCCESS;
}

}  // namespace rex::filesystem
