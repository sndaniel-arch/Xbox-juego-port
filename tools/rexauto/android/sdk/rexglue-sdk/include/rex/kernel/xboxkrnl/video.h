/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2022 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#pragma once

#include <rex/system/xtypes.h>
#include <rex/system/xvideo.h>

namespace rex::runtime {
class ExportResolver;
}

namespace rex::system {
class KernelState;
}

namespace rex::kernel::xboxkrnl {

void VdQueryVideoMode(system::X_VIDEO_MODE* video_mode);

// (Hunt v1.4.6, ronda 11, A3-R11-11.) The guest entry point was
// defined and exported in xboxkrnl_video.cpp but declared nowhere,
// so XGetVideoMode (xam_video.cpp) could not route through it and
// duplicated its 48-byte validation locally instead (R10-13). The
// entry validates the guest pointer and forwards to the host-pointer
// overload above, which graphics code also calls with stack
// addresses -- so the entry, not the overload, is the validation
// point for guest input.
void VdQueryVideoMode_entry(ppc_ptr_t<system::X_VIDEO_MODE> video_mode);

// Register video variable exports (VdGlobalDevice, VdHSIOCalibrationLock, etc.)
// Must be called during kernel initialization before XEX modules are loaded.
void RegisterVideoExports(rex::runtime::ExportResolver* export_resolver,
                          system::KernelState* kernel_state);

}  // namespace rex::kernel::xboxkrnl
