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
 *              ronda 2). PROBE ONLY: opening the device succeeds and reads
 *              return EOF; no video is decoded or shown yet. The real
 *              xbmovie wire protocol (how the game tells the driver which
 *              .wmv to play, and how frames/completion are signalled) is
 *              UNKNOWN -- it cannot be determined from the code in this repo
 *              (see REPORT-C-video.md, C-1/C-2). This device exists so the
 *              phone log can reveal the protocol: every open/read/write/
 *              ioctl on it is logged, behind the `xbmovie_probe` cvar
 *              (default false: behaviour identical to today).
 */

#pragma once

#include <string>

#include <rex/cvar.h>
#include <rex/filesystem/device.h>

// Declared at global scope, like every other REXCVAR_DECLARE in the SDK
// (rex/filesystem/vfs.h, rex/graphics/flags.h, rex/filesystem/flags.h):
// the matching REXCVAR_DEFINE_BOOL in xbmovie_device.cpp is at global scope,
// and the cvar is read from namespace rex (runtime.cpp) and
// rex::kernel::xboxkrnl (xboxkrnl_io.cpp), where an unqualified REXCVAR_GET
// only finds global-scope names. Declaring it inside rex::filesystem made
// runtime.cpp:418 fail with "use of undeclared identifier
// 'FLAGS_xbmovie_probe_storage_'" (run #4) and would have left the declared
// rex::filesystem:: accessor without a definition at link.
REXCVAR_DECLARE(bool, xbmovie_probe);
REXCVAR_DECLARE(int32_t, xbmovie_probe_eof_sleep_ms);

namespace rex::filesystem {

class XbMovieEntry;

class XbMovieDevice : public Device {
 public:
  explicit XbMovieDevice(const std::string& mount_path);
  ~XbMovieDevice() override;

  bool Initialize() override;
  void Dump(string::StringBuffer* string_buffer) override;
  Entry* ResolvePath(const std::string_view path) override;

  bool is_read_only() const override { return false; }

  const std::string& name() const override { return name_; }
  uint32_t attributes() const override { return 0; }
  uint32_t component_name_max_length() const override { return 40; }

  uint32_t total_allocation_units() const override { return 0x10; }
  uint32_t available_allocation_units() const override { return 0x10; }

  // Same harmless placeholders as NullDevice (see null_device.h): the
  // volume geometry of a device node is meaningless, but returning 0
  // risks a divide-by-zero in a guest NtQueryVolumeInformationFile path.
  uint32_t sectors_per_allocation_unit() const override { return 0x80; }
  uint32_t bytes_per_sector() const override { return 0x200; }

 private:
  std::string name_;
  std::unique_ptr<Entry> root_entry_;
};

}  // namespace rex::filesystem
