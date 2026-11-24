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

#include <rex/kernel/xam/private.h>
#include <rex/logging.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xtypes.h>

namespace rex {
namespace kernel {
namespace xam {

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
u32 XamVoiceIsActiveProcess_entry() {
  // Returning 0 here will short-circuit a bunch of voice stuff.
  return 0;
}

u32 XamVoiceCreate_entry(u32 unk1,  // 0
                         u32 unk2,  // 0xF
                         mapped_u32 out_voice_ptr) {
  // (Hunt v1.4.6, ronda 10, A3-R10-12.) Zero() is null-safe, so a
  // NULL pointer was harmless -- but a wild non-null pointer got a
  // 4-byte memset with no validation. Validate the range first when
  // the pointer is non-null; the ACCESS_DENIED answer is unchanged.
  if (out_voice_ptr &&
      !GuestRangeWritable(out_voice_ptr.guest_address(), sizeof(uint32_t))) {
    return X_E_INVALIDARG;
  }
  // Null out the ptr.
  out_voice_ptr.Zero();
  return X_ERROR_ACCESS_DENIED;
}

u32 XamVoiceClose_entry(mapped_void voice_ptr) {
  return 0;
}

u32 XamVoiceHeadsetPresent_entry(mapped_void voice_ptr) {
  return 0;
}

}  // namespace xam
}  // namespace kernel
}  // namespace rex

REX_EXPORT(__imp__XamVoiceIsActiveProcess, rex::kernel::xam::XamVoiceIsActiveProcess_entry)
REX_EXPORT(__imp__XamVoiceCreate, rex::kernel::xam::XamVoiceCreate_entry)
REX_EXPORT(__imp__XamVoiceClose, rex::kernel::xam::XamVoiceClose_entry)
REX_EXPORT(__imp__XamVoiceHeadsetPresent, rex::kernel::xam::XamVoiceHeadsetPresent_entry)

REX_EXPORT_STUB(__imp__XamMuteSound);
REX_EXPORT_STUB(__imp__XamVoiceDisableMicArray);
REX_EXPORT_STUB(__imp__XamVoiceGetBatteryStatus);
REX_EXPORT_STUB(__imp__XamVoiceGetDirectionalData);
REX_EXPORT_STUB(__imp__XamVoiceGetMicArrayAudio);
REX_EXPORT_STUB(__imp__XamVoiceGetMicArrayAudioEx);
REX_EXPORT_STUB(__imp__XamVoiceGetMicArrayFilenameDesc);
REX_EXPORT_STUB(__imp__XamVoiceGetMicArrayStatus);
REX_EXPORT_STUB(__imp__XamVoiceGetMicArrayUnderrunStatus);
REX_EXPORT_STUB(__imp__XamVoiceMuteMicArray);
REX_EXPORT_STUB(__imp__XamVoiceRecordUserPrivileges);
REX_EXPORT_STUB(__imp__XamVoiceSetAudioCaptureRoutine);
REX_EXPORT_STUB(__imp__XamVoiceSetMicArrayBeamAngle);
REX_EXPORT_STUB(__imp__XamVoiceSetMicArrayIdleUsers);
REX_EXPORT_STUB(__imp__XamVoiceSubmitPacket);
