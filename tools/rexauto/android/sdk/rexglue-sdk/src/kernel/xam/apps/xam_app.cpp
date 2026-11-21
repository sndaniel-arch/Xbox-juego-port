/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2021 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <rex/kernel/xam/apps/app.h>
#include <rex/logging.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xenumerator.h>
#include <rex/thread.h>

namespace rex {
namespace kernel {
namespace xam {
using namespace rex::system;
using namespace rex::system::xam;
namespace apps {
using namespace rex::system;

// (Hunt v1.4.6, ronda 4, A3-R4-07.) TranslateVirtual never validates
// and never returns null, so a guest pointer + length that runs past
// the end of the mapping SIGSEGVs the host on the memset/memcpy. Same
// heap validation as A2-R3-01 (see xam_user.cpp for the full comment).
static bool GuestRangeAccessible(rex::memory::Memory* memory, uint32_t guest_address,
                                 size_t length, bool writable) {
  if (!length) {
    return true;
  }
  if (length > UINT32_MAX - guest_address) {
    return false;
  }
  uint32_t high_address = guest_address + static_cast<uint32_t>(length) - 1;
  rex::memory::BaseHeap* start_heap = memory->LookupHeap(guest_address);
  const rex::memory::BaseHeap* end_heap = memory->LookupHeap(high_address);
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
  return true;
}

XamApp::XamApp(KernelState* kernel_state) : App(kernel_state, 0xFE) {}

X_HRESULT XamApp::DispatchMessageSync(uint32_t message, uint32_t buffer_ptr,
                                      uint32_t buffer_length) {
  // NOTE: buffer_length may be zero or valid.
  auto buffer = memory_->TranslateVirtual(buffer_ptr);
  switch (message) {
    case 0x0002000E: {
      struct message_data {
        rex::be<uint32_t> user_index;
        rex::be<uint32_t> unk_04;
        rex::be<uint32_t> extra_ptr;
        rex::be<uint32_t> buffer_ptr;
        rex::be<uint32_t> buffer_size;
        rex::be<uint32_t> unk_14;
        rex::be<uint32_t> length_ptr;
        rex::be<uint32_t> unk_1C;
      }* data = reinterpret_cast<message_data*>(buffer);
      // (Hunt v1.4.6, ronda 4, A3-R4-07.) The message struct itself is
      // read from the guest buffer before anything else: validate its
      // 32 bytes first. The old code then read extra->handle BEFORE the
      // (dead) !extra check — TranslateVirtual never returns null — and
      // memsets buffer_size bytes from an unvalidated pointer. Validate
      // the extra struct and the destination range before touching
      // either, and pass buffer_size to WriteItems so the enumerator
      // truncates to what fits (A3-R4-03).
      if (!GuestRangeAccessible(memory_, buffer_ptr, sizeof(message_data), false)) {
        return X_E_INVALIDARG;
      }
      REXKRNL_DEBUG(
          "XamAppEnumerateContentAggregate({}, {:08X}, {:08X}, {:08X}, {}, "
          "{:08X}, {:08X}, {:08X})",
          (uint32_t)data->user_index, (uint32_t)data->unk_04, (uint32_t)data->extra_ptr,
          (uint32_t)data->buffer_ptr, (uint32_t)data->buffer_size, (uint32_t)data->unk_14,
          (uint32_t)data->length_ptr, (uint32_t)data->unk_1C);
      if (!GuestRangeAccessible(memory_, static_cast<uint32_t>(data->extra_ptr),
                                sizeof(X_KENUMERATOR_CONTENT_AGGREGATE), false)) {
        return X_E_INVALIDARG;
      }
      auto extra = memory_->TranslateVirtual<X_KENUMERATOR_CONTENT_AGGREGATE*>(data->extra_ptr);
      auto e = kernel_state_->object_table()->LookupObject<XEnumerator>(extra->handle);
      if (!e) {
        return X_E_INVALIDARG;
      }
      assert_true(extra->magic == kXObjSignature);
      auto buffer = memory_->TranslateVirtual(data->buffer_ptr);
      if (data->buffer_size &&
          !GuestRangeAccessible(memory_, static_cast<uint32_t>(data->buffer_ptr),
                                static_cast<uint32_t>(data->buffer_size), true)) {
        return X_E_INVALIDARG;
      }
      if (data->buffer_size) {
        std::memset(buffer, 0, data->buffer_size);
      }
      uint32_t item_count = 0;
      auto result = e->WriteItems(data->buffer_ptr, buffer, &item_count, data->buffer_size);

      if (result == X_ERROR_SUCCESS && item_count >= 1) {
        if (data->length_ptr) {
          if (!GuestRangeAccessible(memory_, static_cast<uint32_t>(data->length_ptr),
                                    sizeof(uint32_t), true)) {
            return X_E_INVALIDARG;
          }
          auto length_ptr = memory_->TranslateVirtual<be<uint32_t>*>(data->length_ptr);
          *length_ptr = 1;
        }
        return X_E_SUCCESS;
      }
      return X_E_NO_MORE_FILES;
    }
    case 0x00020021: {
      struct message_data {
        char unk_00[64];
        rex::be<uint32_t> unk_40;  // KeGetCurrentProcessType() < 1 ? 1 : 0
        rex::be<uint32_t> unk_44;  // ? output_ptr ?
        rex::be<uint32_t> unk_48;  // ? overlapped_ptr ?
      }* data = reinterpret_cast<message_data*>(buffer);
      assert_true(buffer_length == sizeof(message_data));
      // (Audit A3, ronda 6, R6-06, sweep.) unk_44 is a guest pointer
      // field; a zero value used to write to guest address 0.
      if (data->unk_44) {
        auto unk = memory_->TranslateVirtual<rex::be<uint32_t>*>(data->unk_44);
        *unk = 0;
      }
      REXKRNL_DEBUG("XamApp(0x00020021)('{}', {:08X}, {:08X}, {:08X})", data->unk_00,
                    (uint32_t)data->unk_40, (uint32_t)data->unk_44, (uint32_t)data->unk_48);
      return X_E_SUCCESS;
    }
    case 0x00021012: {
      REXKRNL_DEBUG("XamApp(0x00021012)");
      return X_E_SUCCESS;
    }
    case 0x00022005: {
      struct message_data {
        rex::be<uint32_t> unk_00;  // ? output_ptr ?
        rex::be<uint32_t> unk_04;  // ? value/jump to? ?
      }* data = reinterpret_cast<message_data*>(buffer);
      assert_true(buffer_length == sizeof(message_data));
      auto unk = memory_->TranslateVirtual<rex::be<uint32_t>*>(data->unk_00);
      auto adr = *unk;
      REXKRNL_DEBUG("XamApp(0x00022005)(%.8X, %.8X)", (uint32_t)data->unk_00,
                    (uint32_t)data->unk_04);
      return X_E_SUCCESS;
    }
  }
  REXKRNL_ERROR(
      "Unimplemented XAM message app={:08X}, msg={:08X}, arg1={:08X}, "
      "arg2={:08X}",
      app_id(), message, buffer_ptr, buffer_length);
  return X_E_FAIL;
}

}  // namespace apps
}  // namespace xam
}  // namespace kernel
}  // namespace rex
