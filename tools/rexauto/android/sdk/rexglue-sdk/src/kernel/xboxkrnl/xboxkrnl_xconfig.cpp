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

#include <rex/cvar.h>
#include <rex/kernel/xboxkrnl/private.h>
#include <rex/logging.h>
#include <rex/memory.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/system/flags.h>
#include <rex/system/kernel_state.h>
#include <rex/system/user_module.h>
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

X_STATUS xeExGetXConfigSetting(uint16_t category, uint16_t setting, void* buffer,
                               uint16_t buffer_size, uint16_t* required_size) {
  uint16_t setting_size = 0;
  alignas(uint32_t) uint8_t value[4];

  // TODO(benvanik): have real structs here that just get copied from.
  // https://free60project.github.io/wiki/XConfig.html
  // https://github.com/oukiar/freestyledash/blob/master/Freestyle/Tools/Generic/ExConfig.h
  switch (category) {
    case 0x0002:
      // XCONFIG_SECURED_CATEGORY
      switch (setting) {
        case 0x0002:  // XCONFIG_SECURED_AV_REGION
          setting_size = 4;
          memory::store_and_swap<uint32_t>(value, 0x00001000);  // USA/Canada
          break;
        default:
          REXKRNL_WARN("Unimplemented XConfig SECURED setting 0x{:04X}", setting);
          return X_STATUS_INVALID_PARAMETER_2;
      }
      break;
    case 0x0003:
      // XCONFIG_USER_CATEGORY
      switch (setting) {
        case 0x0001:  // XCONFIG_USER_TIME_ZONE_BIAS
        case 0x0002:  // XCONFIG_USER_TIME_ZONE_STD_NAME
        case 0x0003:  // XCONFIG_USER_TIME_ZONE_DLT_NAME
        case 0x0004:  // XCONFIG_USER_TIME_ZONE_STD_DATE
        case 0x0005:  // XCONFIG_USER_TIME_ZONE_DLT_DATE
        case 0x0006:  // XCONFIG_USER_TIME_ZONE_STD_BIAS
        case 0x0007:  // XCONFIG_USER_TIME_ZONE_DLT_BIAS
          setting_size = 4;
          // TODO(benvanik): get this value.
          memory::store_and_swap<uint32_t>(value, 0);
          break;
        case 0x0009:  // XCONFIG_USER_LANGUAGE
          setting_size = 4;
          memory::store_and_swap<uint32_t>(value, REXCVAR_GET(user_language));
          break;
        case 0x000A:  // XCONFIG_USER_VIDEO_FLAGS
          setting_size = 4;
          memory::store_and_swap<uint32_t>(value, 0x00040000);
          break;
        case 0x000B:  // XCONFIG_USER_AUDIO_FLAGS
          setting_size = 4;
          memory::store_and_swap<uint32_t>(value, 0x00010001);
          break;
        case 0x000C:  // XCONFIG_USER_RETAIL_FLAGS
          setting_size = 4;
          memory::store_and_swap<uint32_t>(value, 0x40);
          break;
        case 0x000E:  // XCONFIG_USER_COUNTRY
          setting_size = 1;
          value[0] = static_cast<uint8_t>(REXCVAR_GET(user_country));
          break;
        case 0x0019:  // XCONFIG_USER_PC_FLAGS
          setting_size = 1;
          // XBLAllowed | XBLMembershipCreationAllowed
          value[0] = 0x03;
          break;
        default:
          REXKRNL_WARN("Unimplemented XConfig USER setting 0x{:04X}", setting);
          return X_STATUS_INVALID_PARAMETER_2;
      }
      break;
    default:
      REXKRNL_WARN("Unimplemented XConfig category 0x{:04X}", category);
      return X_STATUS_INVALID_PARAMETER_1;
  }

  if (buffer) {
    if (buffer_size < setting_size) {
      return X_STATUS_BUFFER_TOO_SMALL;
    }
    std::memcpy(buffer, value, setting_size);
  } else {
    if (buffer_size) {
      return X_STATUS_INVALID_PARAMETER_3;
    }
  }

  if (required_size) {
    *required_size = setting_size;
  }

  return X_STATUS_SUCCESS;
}

u32 ExGetXConfigSetting_entry(u16 category, u16 setting, mapped_void buffer_ptr, u16 buffer_size,
                              mapped_u16 required_size_ptr) {
  // (Hunt v1.4.6, caza ronda 13, A3-R13-03.) buffer_ptr is passed
  // through to xeExGetXConfigSetting, which memcpys up to 4 bytes
  // into it (every setting writes 1 or 4 bytes), and
  // required_size_ptr is written 2 bytes below -- both with only
  // the NULL checks inside the callee. A wild non-NULL pointer
  // SIGSEGVd the host on the copy. Validate both ranges first
  // (4 bytes covers every setting size); a NULL buffer stays
  // allowed, as before (the callee answers INVALID_PARAMETER_3
  // when buffer_size is nonzero).
  if ((buffer_ptr &&
       !GuestRangeWritable(buffer_ptr.guest_address(), sizeof(uint32_t))) ||
      (required_size_ptr &&
       !GuestRangeWritable(required_size_ptr.guest_address(), sizeof(uint16_t)))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  uint16_t required_size = 0;
  X_STATUS result =
      xeExGetXConfigSetting(category, setting, buffer_ptr, buffer_size, &required_size);

  if (required_size_ptr) {
    *required_size_ptr = required_size;
  }

  return result;
}

}  // namespace rex::kernel::xboxkrnl

REX_EXPORT(__imp__ExGetXConfigSetting, rex::kernel::xboxkrnl::ExGetXConfigSetting_entry)
REX_EXPORT_STUB(__imp__ExSetXConfigSetting);
