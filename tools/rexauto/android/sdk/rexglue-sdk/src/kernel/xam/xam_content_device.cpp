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
#include <rex/logging.h>
#include <rex/math.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xam/content_device.h>
#include <rex/system/xenumerator.h>
#include <rex/system/xtypes.h>

namespace rex {
namespace kernel {
namespace xam {
using namespace rex::system;
using namespace rex::system::xam;

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

// TODO(gibbed): real information.
//
// Until we expose real information about a HDD device, we
// claim there is 3GB free on a 4GB dummy HDD.
//
// There is a possibility that certain games are bugged in that
// they incorrectly only look at the lower 32-bits of free_bytes,
// when it is a 64-bit value. Which means any size above ~4GB
// will not be recognized properly.
#define ONE_GB (1024ull * 1024ull * 1024ull)

static const DummyDeviceInfo dummy_hdd_device_info_ = {
    DummyDeviceId::HDD, DeviceType::HDD,
    20ull * ONE_GB,  // 20GB
    3ull * ONE_GB,   // 3GB, so it looks a little used.
    u"Dummy HDD",
};
static const DummyDeviceInfo dummy_odd_device_info_ = {
    DummyDeviceId::ODD, DeviceType::ODD,
    7ull * ONE_GB,  // 7GB (rough maximum)
    0ull * ONE_GB,  // read-only FS, so no free space
    u"Dummy ODD",
};
static const DummyDeviceInfo* dummy_device_infos_[] = {
    &dummy_hdd_device_info_,
    &dummy_odd_device_info_,
};
#undef ONE_GB

const DummyDeviceInfo* GetDummyDeviceInfo(uint32_t device_id) {
  const auto& begin = std::begin(dummy_device_infos_);
  const auto& end = std::end(dummy_device_infos_);
  auto it = std::find_if(begin, end, [device_id](const auto& item) {
    return static_cast<uint32_t>(item->device_id) == device_id;
  });
  return it == end ? nullptr : *it;
}

u32 XamContentGetDeviceName_entry(u32 device_id, mapped_wstring name_buffer, u32 name_capacity) {
  auto device_info = GetDummyDeviceInfo(device_id);
  if (device_info == nullptr) {
    return X_ERROR_DEVICE_NOT_CONNECTED;
  }
  // (Hunt v1.4.6, ronda 10, A3-R10-12.) Same out-param cluster:
  // name_buffer was written below with no check at all (not even a
  // NULL check). Validate the destination range first -- name_capacity
  // is in UTF-16 code units, so the range is capacity * 2 bytes.
  if (!name_buffer ||
      !GuestRangeWritable(name_buffer.guest_address(),
                          static_cast<size_t>(name_capacity) * sizeof(char16_t))) {
    return X_E_INVALIDARG;
  }
  auto name = std::u16string(device_info->name);
  if (name_capacity < name.size() + 1) {
    return X_ERROR_INSUFFICIENT_BUFFER;
  }
  rex::string::copy_and_swap_truncating(name_buffer, name, name_capacity);
  return X_ERROR_SUCCESS;
}

u32 XamContentGetDeviceState_entry(u32 device_id, mapped_void overlapped_ptr) {
  auto device_info = GetDummyDeviceInfo(device_id);
  if (device_info == nullptr) {
    if (overlapped_ptr) {
      REX_KERNEL_STATE()->CompleteOverlappedImmediateEx(
          overlapped_ptr.guest_address(), X_ERROR_FUNCTION_FAILED, X_ERROR_DEVICE_NOT_CONNECTED, 0);
      return X_ERROR_IO_PENDING;
    } else {
      return X_ERROR_DEVICE_NOT_CONNECTED;
    }
  }
  if (overlapped_ptr) {
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped_ptr.guest_address(),
                                                    X_ERROR_SUCCESS);
    return X_ERROR_IO_PENDING;
  } else {
    return X_ERROR_SUCCESS;
  }
}

typedef struct {
  rex::be<uint32_t> device_id;
  rex::be<uint32_t> device_type;
  rex::be<uint64_t> total_bytes;
  rex::be<uint64_t> free_bytes;
  union {
    rex::be<uint16_t> name[28];
    char16_t name_chars[28];
  };
} X_CONTENT_DEVICE_DATA;
static_assert_size(X_CONTENT_DEVICE_DATA, 0x50);

u32 XamContentGetDeviceData_entry(u32 device_id, ppc_ptr_t<X_CONTENT_DEVICE_DATA> device_data) {
  REXKRNL_INFO("XamContentGetDeviceData(device_id={:#X})", device_id);
  auto device_info = GetDummyDeviceInfo(device_id);
  if (device_info == nullptr) {
    REXKRNL_WARN("XamContentGetDeviceData: device {} not found", device_id);
    return X_ERROR_DEVICE_NOT_CONNECTED;
  }
  // (Hunt v1.4.6, ronda 10, A3-R10-13.) Zero() is null-safe, so this
  // entry *looked* guarded -- but the whole 0x50-byte
  // X_CONTENT_DEVICE_DATA struct is written below with no NULL check
  // at all. Validate the full struct range first.
  if (!device_data ||
      !GuestRangeWritable(device_data.guest_address(), sizeof(X_CONTENT_DEVICE_DATA))) {
    return X_E_INVALIDARG;
  }
  device_data.Zero();
  device_data->device_id = static_cast<uint32_t>(device_info->device_id);
  device_data->device_type = static_cast<uint32_t>(device_info->device_type);
  device_data->total_bytes = device_info->total_bytes;
  device_data->free_bytes = device_info->free_bytes;
  rex::string::copy_and_swap_truncating(device_data->name_chars, device_info->name,
                                        rex::countof(device_data->name_chars));
  REXKRNL_INFO("XamContentGetDeviceData: success, device_id={:#X} type={:#X} total={} free={}",
               uint32_t(device_info->device_id), uint32_t(device_info->device_type),
               uint64_t(device_info->total_bytes), uint64_t(device_info->free_bytes));
  return X_ERROR_SUCCESS;
}

u32 XamContentCreateDeviceEnumerator_entry(u32 content_type, u32 content_flags, u32 max_count,
                                           mapped_u32 buffer_size_ptr, mapped_u32 handle_out) {
  // (Audit A3, ronda 6, R6-06.) assert_not_null is a no-op in Release;
  // a NULL handle_out used to write the handle to guest address 0.
  // Same guard as XamContentCreateEnumerator / Aggregate.
  if (!handle_out) {
    return X_E_INVALIDARG;
  }

  // (Hunt v1.4.6, ronda 10, A3-R10-12.) Both out-params are written
  // below with only the NULL checks above: validate both 4-byte
  // ranges first.
  if ((buffer_size_ptr &&
       !GuestRangeWritable(buffer_size_ptr.guest_address(), sizeof(uint32_t))) ||
      !GuestRangeWritable(handle_out.guest_address(), sizeof(uint32_t))) {
    return X_E_INVALIDARG;
  }

  if (buffer_size_ptr) {
    // (Hunt v1.4.6, ronda 10, A3-R10-12.) The multiplication used
    // to wrap in u32 for huge counts: compute it in 64 bits (R7-03
    // pattern, as XamContentCreateEnumerator does) and reject a
    // total that does not fit the u32 out-param. Mostly benign in
    // practice -- WriteItems truncates per R4-03.
    const uint64_t total_size =
        static_cast<uint64_t>(sizeof(X_CONTENT_DEVICE_DATA)) * max_count;
    if (total_size > UINT32_MAX) {
      return X_E_INVALIDARG;
    }
    *buffer_size_ptr = static_cast<uint32_t>(total_size);
  }

  auto e = make_object<XStaticEnumerator<X_CONTENT_DEVICE_DATA>>(REX_KERNEL_STATE(), max_count);
  auto result = e->Initialize(0xFE, 0xFE, 0x2000A, 0x20009, 0);
  if (XFAILED(result)) {
    return result;
  }

  for (const auto& device_info : dummy_device_infos_) {
    // Copy our dummy device into the enumerator
    auto device_data = e->AppendItem();
    assert_not_null(device_data);
    if (device_data) {
      device_data->device_id = static_cast<uint32_t>(device_info->device_id);
      device_data->device_type = static_cast<uint32_t>(device_info->device_type);
      device_data->total_bytes = device_info->total_bytes;
      device_data->free_bytes = device_info->free_bytes;
      rex::string::copy_and_swap_truncating(device_data->name_chars, device_info->name,
                                            rex::countof(device_data->name_chars));
    }
  }

  *handle_out = e->handle();
  return X_ERROR_SUCCESS;
}

}  // namespace xam
}  // namespace kernel
}  // namespace rex

// fix me later
namespace rex {
namespace system {
namespace xam {

const DummyDeviceInfo* GetDummyDeviceInfo(uint32_t device_id) {
  return rex::kernel::xam::GetDummyDeviceInfo(device_id);
}

}  // namespace xam
}  // namespace system
}  // namespace rex

REX_EXPORT(__imp__XamContentGetDeviceName, rex::kernel::xam::XamContentGetDeviceName_entry)
REX_EXPORT(__imp__XamContentGetDeviceState, rex::kernel::xam::XamContentGetDeviceState_entry)
REX_EXPORT(__imp__XamContentGetDeviceData, rex::kernel::xam::XamContentGetDeviceData_entry)
REX_EXPORT(__imp__XamContentCreateDeviceEnumerator,
           rex::kernel::xam::XamContentCreateDeviceEnumerator_entry)

REX_EXPORT_STUB(__imp__XamContentAddCacheDevice);
REX_EXPORT_STUB(__imp__XamContentDeviceCheckUpdates);
REX_EXPORT_STUB(__imp__XamContentGetDefaultDevice);
REX_EXPORT_STUB(__imp__XamContentGetDeviceSerialNumber);
REX_EXPORT_STUB(__imp__XamContentGetDeviceVolumePath);
REX_EXPORT_STUB(__imp__XamContentGetLocalizedDeviceData);
REX_EXPORT_STUB(__imp__XamContentRemoveCacheDevice);
