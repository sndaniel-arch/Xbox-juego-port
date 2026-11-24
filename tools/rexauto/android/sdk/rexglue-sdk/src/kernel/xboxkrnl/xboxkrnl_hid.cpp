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

// Disable warnings about unused parameters for kernel functions
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include <rex/kernel/xboxkrnl/private.h>
#include <rex/logging.h>
#include <rex/memory.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xtypes.h>

namespace rex::kernel::xboxkrnl {

// (Hunt v1.4.6, caza ronda 13.) This file had no range helper:
// TranslateVirtual never validates and never returns null, so a
// guest pointer + length that runs past the end of the mapping
// SIGSEGVs the host on the read/write. Same heap validation as
// A3-R4-09 (see xam_net.cpp for the full comment): reject a range
// that wraps past 4 GiB, starts or ends outside any heap, or spans
// heaps of different kinds (or two physical heaps); inside a single
// heap, require the pages to be accessible (read/write for a
// destination, readable for a source); across a heap boundary
// validate both ends (A3-R8-13); a range spanning more than two
// heaps is rejected outright (A3-R9-10).
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
  auto range_ok = [&](rex::memory::PageAccess access) {
    if (start_physical) {
      return access == rex::memory::PageAccess::kReadWrite;
    }
    return writable ? access == rex::memory::PageAccess::kReadWrite
                    : access != rex::memory::PageAccess::kNoAccess;
  };
  uint32_t start_heap_end = start_heap->heap_base() + start_heap->heap_size() - 1;
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

u32 HidReadKeys_entry(u32 unk1, u32 unk2, u32 unk3) {
  /* TODO(gibbed):
   * Games check for the following errors:
   *   0xC000009D - translated to 0x48F  - ERROR_DEVICE_NOT_CONNECTED
   *   0x103      - translated to 0x10D2 - ERROR_EMPTY
   * Other errors appear to be ignored?
   *
   * unk1 is 0
   * unk2 is a pointer to &unk3[2], possibly a 6-byte buffer
   * unk3 is a pointer to a 20-byte buffer
   */
  return 0xC000009D;
}

u32 HidGetCapabilities_entry(u32 unk1, u32 caps_ptr) {
  // HidGetCapabilities - ordinal 0x01EA
  // Returns capabilities for HID device (keyboard/mouse)
  // Not supported in rexglue - return unsuccessful
  return X_STATUS_UNSUCCESSFUL;
}

u32 HidGetLastInputTime_entry(mapped_u32 time_ptr) {
  // HidGetLastInputTime - ordinal 0x01F1
  // Returns the last time any HID input was received
  // (Hunt v1.4.6, caza ronda 13, A3-R13-05.) The 4-byte out-param
  // was written with only the NULL check above: a wild non-NULL
  // pointer SIGSEGVd the host. Validate the range first; NULL
  // stays allowed, as before.
  if (time_ptr && !GuestRangeWritable(time_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  if (time_ptr) {
    *time_ptr = 0;
  }
  return X_STATUS_SUCCESS;
}

u32 HidReadMouseChanges_entry(u32 unk1, u32 unk2) {
  // HidReadMouseChanges - ordinal 0x0273
  // Reads mouse input changes - not supported in rexglue
  return X_STATUS_UNSUCCESSFUL;
}

}  // namespace rex::kernel::xboxkrnl

REX_EXPORT(__imp__HidReadKeys, rex::kernel::xboxkrnl::HidReadKeys_entry)
REX_EXPORT(__imp__HidGetCapabilities, rex::kernel::xboxkrnl::HidGetCapabilities_entry)
REX_EXPORT(__imp__HidGetLastInputTime, rex::kernel::xboxkrnl::HidGetLastInputTime_entry)
REX_EXPORT(__imp__HidReadMouseChanges, rex::kernel::xboxkrnl::HidReadMouseChanges_entry)

// XInputd stubs
REX_EXPORT_STUB(__imp__XInputdGetCapabilities);
REX_EXPORT_STUB(__imp__XInputdReadState);
REX_EXPORT_STUB(__imp__XInputdWriteState);
REX_EXPORT_STUB(__imp__XInputdNotify);
REX_EXPORT_STUB(__imp__XInputdRawState);
REX_EXPORT_STUB(__imp__XInputdGetDeviceStats);
REX_EXPORT_STUB(__imp__XInputdResetDevice);
REX_EXPORT_STUB(__imp__XInputdSetRingOfLight);
REX_EXPORT_STUB(__imp__XInputdSetRFPowerMode);
REX_EXPORT_STUB(__imp__XInputdSetRadioFrequency);
REX_EXPORT_STUB(__imp__XInputdPassThroughRFCommand);
REX_EXPORT_STUB(__imp__XInputdPowerDownDevice);
REX_EXPORT_STUB(__imp__XInputdReadTextKeystroke);
REX_EXPORT_STUB(__imp__XInputdSendStayAliveRequest);
REX_EXPORT_STUB(__imp__XInputdFFGetDeviceInfo);
REX_EXPORT_STUB(__imp__XInputdFFSetEffect);
REX_EXPORT_STUB(__imp__XInputdFFUpdateEffect);
REX_EXPORT_STUB(__imp__XInputdFFEffectOperation);
REX_EXPORT_STUB(__imp__XInputdFFDeviceControl);
REX_EXPORT_STUB(__imp__XInputdFFSetDeviceGain);
REX_EXPORT_STUB(__imp__XInputdFFCancelIo);
REX_EXPORT_STUB(__imp__XInputdFFSetRumble);
REX_EXPORT_STUB(__imp__XInputdGetLastTextInputTime);
REX_EXPORT_STUB(__imp__XInputdSetTextMessengerIndicator);
REX_EXPORT_STUB(__imp__XInputdSetTextDeviceKeyLocks);
REX_EXPORT_STUB(__imp__XInputdGetTextDeviceKeyLocks);
REX_EXPORT_STUB(__imp__XInputdControl);
REX_EXPORT_STUB(__imp__XInputdSetWifiChannel);
REX_EXPORT_STUB(__imp__XInputdGetDevicePid);
REX_EXPORT_STUB(__imp__XInputdGetFailedConnectionOrBind);
REX_EXPORT_STUB(__imp__XInputdSetFailedConnectionOrBindCallback);
REX_EXPORT_STUB(__imp__XInputdSetMinMaxAuthDelay);

// Drv stubs
REX_EXPORT_STUB(__imp__DrvSetSysReqCallback);
REX_EXPORT_STUB(__imp__DrvSetUserBindingCallback);
REX_EXPORT_STUB(__imp__DrvSetContentStorageCallback);
REX_EXPORT_STUB(__imp__DrvSetAutobind);
REX_EXPORT_STUB(__imp__DrvGetContentStorageNotification);
REX_EXPORT_STUB(__imp__DrvXenonButtonPressed);
REX_EXPORT_STUB(__imp__DrvBindToUser);
REX_EXPORT_STUB(__imp__DrvSetDeviceConfigChangeCallback);
REX_EXPORT_STUB(__imp__DrvDeviceConfigChange);
REX_EXPORT_STUB(__imp__DrvSetMicArrayStartCallback);
REX_EXPORT_STUB(__imp__DrvSetAudioLatencyCallback);
