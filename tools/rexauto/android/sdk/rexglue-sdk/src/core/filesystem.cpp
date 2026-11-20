/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2020 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <algorithm>

#include <rex/filesystem.h>

namespace rex {
namespace filesystem {

bool CreateParentFolder(const std::filesystem::path& path) {
  if (path.has_parent_path()) {
    std::error_code ec_r316_1;
    auto parent_path = path.parent_path();
    if (!std::filesystem::exists(parent_path, ec_r316_1)) {
      std::error_code ec;
      return std::filesystem::create_directories(parent_path, ec);
    }
  }
  return true;
}

}  // namespace filesystem
}  // namespace rex
