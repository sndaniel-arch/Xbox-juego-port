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

#include <rex/logging.h>
#include <rex/hook.h>
#include <rex/runtime.h>
#include <rex/system/flags.h>
#include <rex/system/kernel_state.h>

namespace rex {
namespace kernel {
namespace xam {

extern std::atomic<int> xam_dialogs_shown_;

static bool GuestRangeAccessible(uint32_t guest_address, size_t length, bool writable) {
  if (!length) {
    return true;
  }
  if (length > UINT32_MAX - guest_address) {
    return false;
  }
  uint32_t high_address = guest_address + static_cast<uint32_t>(length) - 1;
  rex::memory::BaseHeap* start_heap = REX_KERNEL_MEMORY()->LookupHeap(guest_address);
  rex::memory::BaseHeap* end_heap = REX_KERNEL_MEMORY()->LookupHeap(high_address);
  if (!start_heap || !end_heap) {
    return false;
  }
  bool start_physical =
      start_heap->heap_type() == rex::memory::HeapType::kGuestPhysical;
  bool end_physical = end_heap->heap_type() == rex::memory::HeapType::kGuestPhysical;
  if (start_physical != end_physical || (start_physical && start_heap != end_heap)) {
    return false;
  }
  if (start_heap == end_heap) {
    auto access = start_heap->QueryRangeAccess(guest_address, high_address);
    if (start_physical) {
      return access == rex::memory::PageAccess::kReadWrite;
    }
    return writable ? access == rex::memory::PageAccess::kReadWrite
                    : access != rex::memory::PageAccess::kNoAccess;
  }
  // (Hunt v1.4.6, ronda 8, A3-R8-13.) The range straddles a heap
  // boundary -- legitimate allocations never do (each allocation
  // lives in a single heap) -- and the old code returned true here
  // without checking anything, so a buffer whose first page is
  // uncommitted or NoAccess sailed through every GuestRange* check.
  // Validate both ends instead: the tail of the start heap and the
  // head of the end heap, with the same read/write rule as above.
  // (Hunt v1.4.6, ronda 9, A3-R9-10.) A range spanning more than
  // two heaps is rejected outright below: the middle heap would
  // otherwise go unchecked, and no legitimate range spans even
  // one boundary (see the R8-13 comment above).
  auto range_ok = [&](rex::memory::PageAccess access) {
    if (start_physical) {
      return access == rex::memory::PageAccess::kReadWrite;
    }
    return writable ? access == rex::memory::PageAccess::kReadWrite
                    : access != rex::memory::PageAccess::kNoAccess;
  };
  uint32_t start_heap_end = start_heap->heap_base() + start_heap->heap_size() - 1;
  // (Hunt v1.4.6, ronda 9, A3-R9-10.) The heap right after the start
  // heap must be the end heap: anything else means the range spans
  // three or more heaps (or a gap in the heap map) and the middle heap
  // would go unchecked. Reject outright instead of validating only
  // the two ends.
  if (REX_KERNEL_MEMORY()->LookupHeap(start_heap_end + 1) != end_heap) {
    return false;
  }
  return range_ok(start_heap->QueryRangeAccess(guest_address, start_heap_end)) &&
         range_ok(end_heap->QueryRangeAccess(end_heap->heap_base(), high_address));
}

static bool GuestRangeReadable(uint32_t guest_address, size_t length) {
  return GuestRangeAccessible(guest_address, length, false);
}

static bool GuestRangeWritable(uint32_t guest_address, size_t length) {
  return GuestRangeAccessible(guest_address, length, true);
}

struct X_NUI_DEVICE_STATUS {
  rex::be<uint32_t> unk0;
  rex::be<uint32_t> unk1;
  rex::be<uint32_t> unk2;
  rex::be<uint32_t> status;
  rex::be<uint32_t> unk4;
  rex::be<uint32_t> unk5;
};
static_assert(sizeof(X_NUI_DEVICE_STATUS) == 24, "Size matters");

void XamNuiGetDeviceStatus_entry(ppc_ptr_t<X_NUI_DEVICE_STATUS> status_ptr) {
  // (Hunt v1.4.6, ronda 10, A3-R10-13.) Zero() is null-safe, so this
  // entry *looked* guarded -- but status_ptr->status derefs
  // unconditionally right after it: NULL is a host null deref and a
  // wild non-null pointer gets a 24-byte write with no validation.
  // This entry returns void, so an invalid pointer just returns.
  if (!status_ptr ||
      !GuestRangeWritable(status_ptr.guest_address(), sizeof(X_NUI_DEVICE_STATUS))) {
    return;
  }
  status_ptr.Zero();
  status_ptr->status = 0;  // Not connected.
}

u32 XamShowNuiTroubleshooterUI_entry(u32 unk1, u32 unk2, u32 unk3) {
  // unk1 is 0xFF - possibly user index?
  // unk2, unk3 appear to always be zero.

  if (REXCVAR_GET(headless)) {
    return 0;
  }
  // TODO(tomc): Implement imgui stuff
  // const Runtime* emulator = REX_KERNEL_STATE()->emulator();
  // ui::Window* display_window = emulator->display_window();
  // ui::ImGuiDrawer* imgui_drawer = emulator->imgui_drawer();
  // if (display_window && imgui_drawer) {
  //  rex::thread::Fence fence;
  //  if (display_window->app_context().CallInUIThreadSynchronous([&]() {
  //        rex::ui::ImGuiDialog::ShowMessageBox(
  //            imgui_drawer, "NUI Troubleshooter",
  //            "The game has indicated there is a problem with NUI (Kinect).")
  //            ->Then(&fence);
  //      })) {
  //    ++xam_dialogs_shown_;
  //    fence.Wait();
  //    --xam_dialogs_shown_;
  //  }
  //}

  return 0;
}

}  // namespace xam
}  // namespace kernel
}  // namespace rex

REX_EXPORT(__imp__XamNuiGetDeviceStatus, rex::kernel::xam::XamNuiGetDeviceStatus_entry)
REX_EXPORT(__imp__XamShowNuiTroubleshooterUI, rex::kernel::xam::XamShowNuiTroubleshooterUI_entry)

REX_EXPORT_STUB(__imp__XamEnableNatalPlayback);
REX_EXPORT_STUB(__imp__XamEnableNuiAutomation);
REX_EXPORT_STUB(__imp__XamKinectGetHardwareType);
REX_EXPORT_STUB(__imp__XamNatalDeviceAudioCalibrate);
REX_EXPORT_STUB(__imp__XamNuiCameraAdjustTilt);
REX_EXPORT_STUB(__imp__XamNuiCameraElevationAutoTilt);
REX_EXPORT_STUB(__imp__XamNuiCameraElevationGetAngle);
REX_EXPORT_STUB(__imp__XamNuiCameraElevationReverseAutoTilt);
REX_EXPORT_STUB(__imp__XamNuiCameraElevationSetAngle);
REX_EXPORT_STUB(__imp__XamNuiCameraElevationSetCallback);
REX_EXPORT_STUB(__imp__XamNuiCameraElevationStopMovement);
REX_EXPORT_STUB(__imp__XamNuiCameraGetTiltControllerType);
REX_EXPORT_STUB(__imp__XamNuiCameraRememberFloor);
REX_EXPORT_STUB(__imp__XamNuiCameraSetFlags);
REX_EXPORT_STUB(__imp__XamNuiCameraTiltGetStatus);
REX_EXPORT_STUB(__imp__XamNuiCameraTiltReportStatus);
REX_EXPORT_STUB(__imp__XamNuiCameraTiltSetCallback);
REX_EXPORT_STUB(__imp__XamNuiEnableChatMic);
REX_EXPORT_STUB(__imp__XamNuiGetCameraIntrinsics);
REX_EXPORT_STUB(__imp__XamNuiGetDepthCalibration);
REX_EXPORT_STUB(__imp__XamNuiGetDeviceSerialNumber);
REX_EXPORT_STUB(__imp__XamNuiGetFanRate);
REX_EXPORT_STUB(__imp__XamNuiGetLoadedDepthCalibration);
REX_EXPORT_STUB(__imp__XamNuiGetSupportString);
REX_EXPORT_STUB(__imp__XamNuiGetSystemGestureControl);
REX_EXPORT_STUB(__imp__XamNuiGetTrueColorInfo);
REX_EXPORT_STUB(__imp__XamNuiHudEnableInputFilter);
REX_EXPORT_STUB(__imp__XamNuiHudGetEngagedEnrollmentIndex);
REX_EXPORT_STUB(__imp__XamNuiHudGetEngagedTrackingID);
REX_EXPORT_STUB(__imp__XamNuiHudGetInitializeFlags);
REX_EXPORT_STUB(__imp__XamNuiHudGetVersions);
REX_EXPORT_STUB(__imp__XamNuiHudInterpretFrame);
REX_EXPORT_STUB(__imp__XamNuiHudIsEnabled);
REX_EXPORT_STUB(__imp__XamNuiHudSetEngagedTrackingID);
REX_EXPORT_STUB(__imp__XamNuiIdentityAbort);
REX_EXPORT_STUB(__imp__XamNuiIdentityEnrollForSignIn);
REX_EXPORT_STUB(__imp__XamNuiIdentityGetColorTexture);
REX_EXPORT_STUB(__imp__XamNuiIdentityGetEnrollmentInfo);
REX_EXPORT_STUB(__imp__XamNuiIdentityGetQualityFlags);
REX_EXPORT_STUB(__imp__XamNuiIdentityGetQualityFlagsMessage);
REX_EXPORT_STUB(__imp__XamNuiIdentityGetSessionId);
REX_EXPORT_STUB(__imp__XamNuiIdentityIdentifyWithBiometric);
REX_EXPORT_STUB(__imp__XamNuiIdentityUnenroll);
REX_EXPORT_STUB(__imp__XamNuiIsChatMicEnabled);
REX_EXPORT_STUB(__imp__XamNuiIsDeviceReady);
REX_EXPORT_STUB(__imp__XamNuiNatalCameraUpdateComplete);
REX_EXPORT_STUB(__imp__XamNuiNatalCameraUpdateStarting);
REX_EXPORT_STUB(__imp__XamNuiPlayerEngagementUpdate);
REX_EXPORT_STUB(__imp__XamNuiSetForceDeviceOff);
REX_EXPORT_STUB(__imp__XamNuiSkeletonGetBestSkeletonIndex);
REX_EXPORT_STUB(__imp__XamNuiSkeletonScoreUpdate);
REX_EXPORT_STUB(__imp__XamNuiStoreDepthCalibration);
