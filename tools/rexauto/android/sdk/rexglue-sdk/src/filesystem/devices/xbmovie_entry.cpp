/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2021 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 * @modified    Aurora, 2026-11-14 - XbMovie video-playback device (audit C,
 *              ronda 2). PROBE ONLY, see xbmovie_device.h. Template:
 *              NullEntry.
 */

#include <rex/filesystem/devices/xbmovie_entry.h>
#include <rex/filesystem/devices/xbmovie_file.h>

#include <rex/filesystem.h>
#include <rex/filesystem/device.h>
#include <rex/logging.h>
#include <rex/math.h>
#include <rex/memory/mapped_memory.h>
#include <rex/string.h>

namespace rex::filesystem {

XbMovieEntry::XbMovieEntry(Device* device, Entry* parent, std::string path)
    : Entry(device, parent, path) {}

XbMovieEntry::~XbMovieEntry() = default;

XbMovieEntry* XbMovieEntry::Create(Device* device, Entry* parent, const std::string& path) {
  auto entry = new XbMovieEntry(device, parent, path);

  entry->create_timestamp_ = 0;
  entry->access_timestamp_ = 0;
  entry->write_timestamp_ = 0;

  entry->attributes_ = kFileAttributeDevice;

  entry->size_ = 0;
  entry->allocation_size_ = 0;
  return entry;
}

X_STATUS XbMovieEntry::Open(uint32_t desired_access, File** out_file) {
  if (is_read_only() &&
      (desired_access & (FileAccess::kFileWriteData | FileAccess::kFileAppendData))) {
    REXFS_ERROR("Attempting to open file for write access on read-only device");
    return X_STATUS_ACCESS_DENIED;
  }

  // The open itself is the first protocol fact: log it at WARN so it is
  // visible with the default log_level=info (NtCreateFile success is
  // NOISY/TRACE and would not be).
  REXFS_WARN("XbMovieDevice: opened (access={:#x})", desired_access);
  *out_file = new XbMovieFile(desired_access, this);
  return X_STATUS_SUCCESS;
}

}  // namespace rex::filesystem
