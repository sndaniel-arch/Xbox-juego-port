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
 *              ronda 2). PROBE ONLY: the device answers opens and returns
 *              EOF on reads. It decodes nothing and shows nothing yet --
 *              the xbmovie wire protocol is unknown (see REPORT-C-video.md,
 *              C-1/C-2). Every access is logged so the phone log reveals
 *              what COL_FullscreenMoviePlayerComponent actually does with
 *              the handle (open/read/write/ioctl/close order, sizes,
 *              first bytes of writes). Template: NullDevice.
 */

#include <rex/filesystem/devices/xbmovie_entry.h>

#include <rex/filesystem.h>
#include <rex/filesystem/devices/xbmovie_device.h>
#include <rex/logging.h>
#include <rex/math.h>
#include <rex/string.h>

REXCVAR_DEFINE_BOOL(xbmovie_probe, false, "Filesystem",
                    "Register the \\Device\\XbMovie probe device and the "
                    "xbmovie: symbolic link (open succeeds, reads return "
                    "EOF, every access is logged). OFF by default: with it "
                    "off, video opens fail exactly as they do today.");

namespace rex::filesystem {

XbMovieDevice::XbMovieDevice(const std::string& mount_path)
    : Device(mount_path), name_("XbMovieDevice") {}

XbMovieDevice::~XbMovieDevice() = default;

bool XbMovieDevice::Initialize() {
  auto root_entry = new XbMovieEntry(this, nullptr, "");
  // NOTE: kFileAttributeDevice, NOT Directory (unlike NullDevice's root):
  // the game opens the device node itself, and VFS::OpenFile rejects a
  // directory entry when the open asks for FILE_NON_DIRECTORY_FILE. A
  // device node is not a directory either way.
  root_entry->attributes_ = kFileAttributeDevice;
  root_entry_ = std::unique_ptr<Entry>(root_entry);
  return true;
}

void XbMovieDevice::Dump(string::StringBuffer* string_buffer) {
  auto global_lock = global_critical_region_.Acquire();
  root_entry_->Dump(string_buffer, 0);
}

Entry* XbMovieDevice::ResolvePath(const std::string_view path) {
  REXFS_DEBUG("XbMovieDevice::ResolvePath({})", path);

  if (path.empty()) {
    return root_entry_.get();
  }

  // Single-node device: there are no children. Anything else is not found,
  // exactly like NullDevice returns nullptr for unknown children.
  return nullptr;
}

}  // namespace rex::filesystem
