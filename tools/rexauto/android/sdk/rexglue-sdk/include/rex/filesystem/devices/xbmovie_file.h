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
 *              ronda 2). PROBE ONLY, see xbmovie_device.h.
 */

#pragma once

#include <span>
#include <string>

#include <rex/filesystem.h>
#include <rex/filesystem/file.h>

namespace rex::filesystem {

class XbMovieEntry;

class XbMovieFile : public File {
 public:
  XbMovieFile(uint32_t file_access, XbMovieEntry* entry);
  ~XbMovieFile() override;

  void Destroy() override;

  X_STATUS ReadSync(std::span<uint8_t> buffer, size_t byte_offset, size_t* out_bytes_read) override;
  X_STATUS WriteSync(std::span<const uint8_t> buffer, size_t byte_offset,
                     size_t* out_bytes_written) override;
  X_STATUS SetLength(size_t length) override;

 private:
  // The probe logs only the first few reads/writes in full; after that it
  // counts, logging the running total every kProbeLogEveryN so a game
  // spinning on EOF reads stays visible in the log instead of going silent
  // after the first 8 (audit D, ronda 3, D-X-C-2).
  //
  // (Audit D, ronda 5, R5-D5.) The counters live in xbmovie_file.cpp as
  // process-wide statics, NOT as members: every open creates a new
  // XbMovieFile (XbMovieEntry::Open), so per-instance counters reset on
  // every re-open and the #1-#8 detail lines repeat while the 1024-totals
  // never grow. Shared counters keep one running total per process, which
  // is what the X-2a/X-2b phone discriminators read.
  static constexpr uint32_t kProbeLogFirstN = 8;
  static constexpr uint32_t kProbeLogEveryN = 1024;
};

}  // namespace rex::filesystem
