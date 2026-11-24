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

#include <rex/kernel/xam/private.h>
#include <rex/kernel/xboxkrnl/video.h>
#include <rex/logging.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xtypes.h>

namespace rex {
namespace kernel {
namespace xam {
using namespace rex::system;

// (Hunt v1.4.6, ronda 11, A3-R11-11.) The GuestRange* helpers lived
// here only for XGetVideoMode's local validation; the function now
// routes through VdQueryVideoMode_entry (video.h), so they are gone
// -- a file-scope static with no callers is -Wunused-function dead
// code (A3-R10-11).

void XGetVideoMode_entry(ppc_ptr_t<X_VIDEO_MODE> video_mode) {
  // TODO(benvanik): actually check to see if these are the same.
  // (Hunt v1.4.6, ronda 11, A3-R11-11.) This used to validate the
  // 48-byte struct locally and forward the guest pointer into
  // VdQueryVideoMode's host-pointer overload, duplicating the
  // VdQueryVideoMode_entry guard in xboxkrnl_video.cpp (R10-13).
  // The entry is now declared in video.h: route through it, so the
  // validation lives in exactly one place. Behavior is identical:
  // the entry validates 48 bytes writable and returns silently on
  // an invalid pointer, as the local check did.
  xboxkrnl::VdQueryVideoMode_entry(video_mode);
}

u32 XGetVideoCapabilities_entry() {
  return 0;
}

}  // namespace xam
}  // namespace kernel
}  // namespace rex

REX_EXPORT(__imp__XGetVideoMode, rex::kernel::xam::XGetVideoMode_entry)
REX_EXPORT(__imp__XGetVideoCapabilities, rex::kernel::xam::XGetVideoCapabilities_entry)

REX_EXPORT_STUB(__imp__XGetVideoFlags);
REX_EXPORT_STUB(__imp__XGetVideoStandard);
REX_EXPORT_STUB(__imp__XamLoadExtraAVCodecs2);
REX_EXPORT_STUB(__imp__XamUnloadExtraAVCodecs2);
