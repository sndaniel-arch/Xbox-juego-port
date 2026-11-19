/**
 ******************************************************************************
 * ReXGlue : Xbox 360 recompilation runtime                                 *
 ******************************************************************************
 * Copyright 2026 Tom Clay. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include <rex/filesystem/stfs_asset.h>

#include <cerrno>
#include <cstring>
#include <mutex>
#include <utility>

#if defined(__ANDROID__) || defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#endif

#include <rex/logging.h>

namespace rex::filesystem {
namespace {

std::mutex g_stfs_asset_mutex;
StfsAssetSource g_stfs_asset_source;
// (Hunt v1.4.6, A2-R6-07.) Set by every SetStfsAssetSource call, success
// or failure; read by Runtime::SetupVfs (see StfsAssetSourceAttempted).
bool g_stfs_asset_attempted = false;

void CloseSourceFd(StfsAssetSource& source) {
  if (source.fd >= 0) {
#if defined(__ANDROID__) || defined(__linux__) || defined(__APPLE__)
    ::close(source.fd);
#endif
    source.fd = -1;
  }
}

}  // namespace

bool SetStfsAssetSource(int fd, uint64_t base_offset, uint64_t length) {
  {
    std::lock_guard<std::mutex> lock(g_stfs_asset_mutex);
    g_stfs_asset_attempted = true;
  }
  // The app passes the raw AssetManager.openFd() fd; dup() it so the app
  // can close its own copy (and its AssetFileDescriptor) immediately.
  int owned_fd = -1;
  if (fd >= 0) {
#if defined(__ANDROID__) || defined(__linux__) || defined(__APPLE__)
    owned_fd = ::dup(fd);
#else
    owned_fd = fd;
#endif
  }
  if (owned_fd < 0) {
    // (Hunt v1.4.6, A2-R6-07.) This used to fail silently (void return,
    // no log): the old source stayed in place, android_main logged
    // success anyway, and SetupVfs "succeeded" with no game mounted.
    // Report it with the errno and return false so the caller aborts the
    // launch instead of logging success; the previous source is left
    // untouched, so a failed re-delivery never clobbers a good one.
    if (fd < 0) {
      REXFS_ERROR("SetStfsAssetSource: invalid fd {}", fd);
    } else {
      REXFS_ERROR("SetStfsAssetSource: cannot store fd {} (dup failed: {})", fd,
                  std::strerror(errno));
    }
    return false;
  }
  std::lock_guard<std::mutex> lock(g_stfs_asset_mutex);
  CloseSourceFd(g_stfs_asset_source);
  g_stfs_asset_source = StfsAssetSource{owned_fd, base_offset, length};
  return true;
}

bool HasStfsAssetSource() {
  std::lock_guard<std::mutex> lock(g_stfs_asset_mutex);
  return g_stfs_asset_source.valid();
}

bool StfsAssetSourceAttempted() {
  std::lock_guard<std::mutex> lock(g_stfs_asset_mutex);
  return g_stfs_asset_attempted;
}

StfsAssetSource TakeStfsAssetSource() {
  std::lock_guard<std::mutex> lock(g_stfs_asset_mutex);
  StfsAssetSource source = g_stfs_asset_source;
  g_stfs_asset_source = StfsAssetSource{};
  return source;
}

}  // namespace rex::filesystem
