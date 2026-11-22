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

#include <rex/cvar.h>
#include <rex/kernel/xam/private.h>
#include <rex/logging.h>
#include <rex/math.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/string.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xam/content_device.h>
#include <rex/system/xenumerator.h>
#include <rex/system/xtypes.h>

REXCVAR_DEFINE_UINT32(license_mask, 0, "Kernel", "Set license mask for activated content");

namespace rex {
namespace kernel {
namespace xam {
using namespace rex::system;
using namespace rex::system::xam;

// (Hunt v1.4.6, ronda 7, A3-R7-03.) TranslateVirtual never validates
// and never returns null, so a guest pointer + length that runs past
// the end of the mapping SIGSEGVs the host on the memcpy/read/write.
// Same heap validation as A3-R4-09 (see xam_net.cpp for the full
// comment), copied here because this file had no range helper at all:
// reject a range that wraps past 4 GiB, starts or ends outside any
// heap, or spans heaps of different kinds (or two physical heaps);
// inside a single heap, require the pages to be accessible (read/write
// for a destination, readable for a source).
static bool GuestRangeAccessible(uint32_t guest_address, size_t length, bool writable) {
  if (!length) {
    return true;
  }
  if (length > UINT32_MAX - guest_address) {
    return false;
  }
  uint32_t high_address = guest_address + static_cast<uint32_t>(length) - 1;
  rex::memory::BaseHeap* start_heap = REX_KERNEL_MEMORY()->LookupHeap(guest_address);
  const rex::memory::BaseHeap* end_heap = REX_KERNEL_MEMORY()->LookupHeap(high_address);
  if (!start_heap || !end_heap) {
    return false;
  }
  bool start_physical =
      start_heap->heap_type() == rex::memory::HeapType::kGuestPhysical;
  bool end_physical =
      end_heap->heap_type() == rex::memory::HeapType::kGuestPhysical;
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

static bool GuestRangeReadable(uint32_t guest_address, size_t length) {
  return GuestRangeAccessible(guest_address, length, false);
}

static bool GuestRangeWritable(uint32_t guest_address, size_t length) {
  return GuestRangeAccessible(guest_address, length, true);
}


u32 XamContentGetLicenseMask_entry(mapped_u32 mask_ptr, mapped_void overlapped_ptr) {
  // (Audit A3, ronda 6, R6-06.) A NULL mask_ptr used to write the mask
  // to guest address 0.
  if (!mask_ptr) {
    return X_E_INVALIDARG;
  }
  // (Hunt v1.4.6, ronda 7, A3-R7-03.) Same class, same file: the
  // 4-byte mask out-param had only the NULL-check above.
  if (!GuestRangeWritable(mask_ptr.guest_address(), sizeof(uint32_t))) {
    return X_E_INVALIDARG;
  }

  // Each bit in the mask represents a granted license. Available licenses
  // seems to vary from game to game, but most appear to use bit 0 to indicate
  // if the game is purchased or not.
  *mask_ptr = REXCVAR_GET(license_mask);

  if (overlapped_ptr) {
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped_ptr.guest_address(),
                                                    X_ERROR_SUCCESS);
    return X_ERROR_IO_PENDING;
  } else {
    return X_ERROR_SUCCESS;
  }
}

u32 XamContentResolve_entry(u32 user_index, mapped_void content_data_ptr, mapped_void buffer_ptr,
                            u32 buffer_size, u32 unk1, u32 unk2, u32 unk3) {
  // (Hunt v1.4.6, ronda 7, A3-R7-03.) content_data_ptr is read as a
  // 0x134-byte XCONTENT_DATA below. (buffer_ptr is never dereferenced
  // here -- the resolve itself is unimplemented -- so there is no
  // range to validate for it.)
  if (!content_data_ptr ||
      !GuestRangeReadable(content_data_ptr.guest_address(), sizeof(XCONTENT_DATA))) {
    return X_E_INVALIDARG;
  }
  auto content_data = content_data_ptr.as<XCONTENT_DATA*>();

  // Result of buffer_ptr is sent to RtlInitAnsiString.
  // buffer_size is usually 260 (max path).
  // Games expect zero if resolve was successful.
  assert_always();
  REXKRNL_WARN("XamContentResolve unimplemented!");
  return X_ERROR_NOT_FOUND;
}

// https://github.com/MrColdbird/gameservice/blob/master/ContentManager.cpp
// https://github.com/LestaD/SourceEngine2007/blob/master/se2007/engine/xboxsystem.cpp#L499
u32 XamContentCreateEnumerator_entry(u32 user_index, u32 device_id, u32 content_type,
                                     u32 content_flags, u32 items_per_enumerate,
                                     mapped_u32 buffer_size_ptr, mapped_u32 handle_out) {
  assert_not_null(handle_out);

  // (Hunt v1.4.6, ronda 7, A3-R7-03.) handle_out is written on every
  // exit and buffer_size_ptr on the early ones: validate both 4-byte
  // ranges before anything writes through them.
  if (buffer_size_ptr &&
      !GuestRangeWritable(buffer_size_ptr.guest_address(), sizeof(uint32_t))) {
    return X_E_INVALIDARG;
  }
  if (!handle_out || !GuestRangeWritable(handle_out.guest_address(), sizeof(uint32_t))) {
    return X_E_INVALIDARG;
  }

  auto device_info = device_id == 0 ? nullptr : GetDummyDeviceInfo(device_id);
  if ((device_id && device_info == nullptr) || !handle_out) {
    if (buffer_size_ptr) {
      *buffer_size_ptr = 0;
    }
    return X_E_INVALIDARG;
  }

  if (buffer_size_ptr) {
    // (Hunt v1.4.6, ronda 7, A3-R7-03.) The multiplication used to
    // wrap in u32 (0x134 * ~14M items already turns over): compute it
    // in 64 bits; a total that does not fit the u32 out-param cannot
    // be reported, so reject the call.
    const uint64_t total_size =
        static_cast<uint64_t>(sizeof(XCONTENT_DATA)) * items_per_enumerate;
    if (total_size > UINT32_MAX) {
      return X_E_INVALIDARG;
    }
    *buffer_size_ptr = static_cast<uint32_t>(total_size);
  }

  uint64_t xuid = REX_KERNEL_STATE()->user_profile()->xuid();

  auto e = make_object<XStaticEnumerator<XCONTENT_DATA>>(REX_KERNEL_STATE(), items_per_enumerate);
  auto result = e->Initialize(0xFF, 0xFE, 0x20005, 0x20007, 0);
  if (XFAILED(result)) {
    return result;
  }

  if (!device_info || device_info->device_id == DummyDeviceId::HDD) {
    // Enumerate user-specific content
    auto content_datas = REX_KERNEL_STATE()->content_manager()->ListContent(
        static_cast<uint32_t>(DummyDeviceId::HDD), xuid, XContentType(uint32_t(content_type)));
    for (const auto& content_data : content_datas) {
      auto item = e->AppendItem();
      if (item) {
        *item = content_data;
      }
    }

    // Also enumerate common content (xuid=0)
    if (xuid != 0) {
      auto common_datas = REX_KERNEL_STATE()->content_manager()->ListContent(
          static_cast<uint32_t>(DummyDeviceId::HDD), 0, XContentType(uint32_t(content_type)));
      for (const auto& content_data : common_datas) {
        auto item = e->AppendItem();
        if (item) {
          *item = content_data;
        }
      }
    }
  }

  if (!device_info || device_info->device_id == DummyDeviceId::ODD) {
    // TODO(gibbed): disc drive content
  }

  REXKRNL_DEBUG("XamContentCreateEnumerator: added {} items to enumerator", e->item_count());

  *handle_out = e->handle();
  return X_ERROR_SUCCESS;
}

enum class kDispositionState : uint32_t { Unknown = 0, Create = 1, Open = 2 };

u32 xeXamContentCreate(u32 user_index, mapped_string root_name, mapped_void content_data_ptr,
                       u32 content_data_size, u32 flags, mapped_u32 disposition_ptr,
                       mapped_u32 license_mask_ptr, u32 cache_size, u64 content_size,
                       mapped_void overlapped_ptr) {
  uint64_t xuid = REX_KERNEL_STATE()->user_profile()->xuid();

  // (Hunt v1.4.6, ronda 7, A3-R7-03.) content_data_ptr is read as
  // either a 0x134-byte XCONTENT_DATA or a 0x148-byte
  // XCONTENT_AGGREGATE_DATA, and the deferred lambda below writes the
  // disposition/license out-params: validate all of them up front
  // (the lambda may run later, on the overlapped completion path).
  // content_data_size only ever arrives as one of the two sizes
  // above, so validating exactly that many bytes is exact; any other
  // size is rejected here instead of in the else branch below.
  if (!content_data_ptr ||
      !GuestRangeReadable(content_data_ptr.guest_address(), content_data_size)) {
    return X_ERROR_INVALID_PARAMETER;
  }
  if (disposition_ptr &&
      !GuestRangeWritable(disposition_ptr.guest_address(), sizeof(uint32_t))) {
    return X_ERROR_INVALID_PARAMETER;
  }
  if (license_mask_ptr &&
      !GuestRangeWritable(license_mask_ptr.guest_address(), sizeof(uint32_t))) {
    return X_ERROR_INVALID_PARAMETER;
  }

  XCONTENT_AGGREGATE_DATA content_data;
  if (content_data_size == sizeof(XCONTENT_DATA)) {
    content_data = *content_data_ptr.as<XCONTENT_DATA*>();
  } else if (content_data_size == sizeof(XCONTENT_AGGREGATE_DATA)) {
    content_data = *content_data_ptr.as<XCONTENT_AGGREGATE_DATA*>();
  } else {
    assert_always();
    return X_ERROR_INVALID_PARAMETER;
  }

  if (content_data.content_type == XContentType::kMarketplaceContent) {
    xuid = 0;
  }

  auto content_manager = REX_KERNEL_STATE()->content_manager();

  if (overlapped_ptr && disposition_ptr) {
    *disposition_ptr = 0;
  }

  auto run = [content_manager, xuid, root_name = root_name.value(), flags, content_data,
              disposition_ptr,
              license_mask_ptr](uint32_t& extended_error, uint32_t& length) -> X_RESULT {
    X_RESULT result = X_ERROR_INVALID_PARAMETER;
    kDispositionState disposition = kDispositionState::Unknown;
    switch (flags & 0xF) {
      case 1:  // CREATE_NEW
               // Fail if exists.
        if (content_manager->ContentExists(xuid, content_data)) {
          result = X_ERROR_ALREADY_EXISTS;
        } else {
          disposition = kDispositionState::Create;
        }
        break;
      case 2:  // CREATE_ALWAYS
               // Overwrite existing, if any.
        // Close any existing mount under this root name first.
        // Games may reuse the same root without explicitly closing.
        content_manager->CloseContent(root_name);
        if (content_manager->ContentExists(xuid, content_data)) {
          content_manager->DeleteContent(xuid, content_data);
        }
        // Check filesystem state after deletion attempt to decide
        // whether to create fresh or open existing.
        if (content_manager->ContentExists(xuid, content_data)) {
          disposition = kDispositionState::Open;
        } else {
          disposition = kDispositionState::Create;
        }
        break;
      case 3:  // OPEN_EXISTING
               // Open only if exists.
        if (!content_manager->ContentExists(xuid, content_data)) {
          result = X_ERROR_PATH_NOT_FOUND;
        } else {
          disposition = kDispositionState::Open;
        }
        break;
      case 4:  // OPEN_ALWAYS
               // Create if needed.
        if (!content_manager->ContentExists(xuid, content_data)) {
          disposition = kDispositionState::Create;
        } else {
          disposition = kDispositionState::Open;
        }
        break;
      case 5:  // TRUNCATE_EXISTING
               // Fail if doesn't exist, if does exist delete and recreate.
        if (!content_manager->ContentExists(xuid, content_data)) {
          result = X_ERROR_PATH_NOT_FOUND;
        } else {
          content_manager->CloseContent(root_name);
          content_manager->DeleteContent(xuid, content_data);
          if (content_manager->ContentExists(xuid, content_data)) {
            disposition = kDispositionState::Open;
          } else {
            disposition = kDispositionState::Create;
          }
        }
        break;
      default:
        assert_unhandled_case(flags & 0xF);
        break;
    }

    uint32_t content_license = 0;
    if (disposition == kDispositionState::Create) {
      result = content_manager->CreateContent(root_name, xuid, content_data);
      if (XSUCCEEDED(result)) {
        content_manager->WriteContentHeaderFile(xuid, content_data);
      }
    } else if (disposition == kDispositionState::Open) {
      result = content_manager->OpenContent(root_name, xuid, content_data, content_license);
    }

    if (license_mask_ptr && XSUCCEEDED(result)) {
      *license_mask_ptr = content_license;
    }

    if (disposition_ptr) {
      *disposition_ptr = static_cast<uint32_t>(disposition);
    }

    extended_error = X_HRESULT_FROM_WIN32(result);
    length = static_cast<uint32_t>(disposition);
    return result;
  };

  if (!overlapped_ptr) {
    uint32_t extended_error, length;
    auto result = run(extended_error, length);
    REXKRNL_INFO("XamContentCreateEx: sync result={:#X}", uint32_t(result));
    return result;
  } else {
    REXKRNL_INFO("XamContentCreateEx: async (overlapped={:#X})", overlapped_ptr.guest_address());
    REX_KERNEL_STATE()->CompleteOverlappedDeferredEx(run, overlapped_ptr.guest_address());
    return X_ERROR_IO_PENDING;
  }
}

u32 XamContentCreateEx_entry(u32 user_index, mapped_string root_name, mapped_void content_data_ptr,
                             u32 flags, mapped_u32 disposition_ptr, mapped_u32 license_mask_ptr,
                             u32 cache_size, u64 content_size, mapped_void overlapped_ptr) {
  REXKRNL_INFO("XamContentCreateEx(user={}, root='{}', flags={:#X}, size={})",
               user_index, root_name ? std::string(root_name) : std::string("(null)"),
               flags, content_size);
  return xeXamContentCreate(user_index, root_name, content_data_ptr, sizeof(XCONTENT_DATA), flags,
                            disposition_ptr, license_mask_ptr, cache_size, content_size,
                            overlapped_ptr);
}

u32 XamContentCreate_entry(u32 user_index, mapped_string root_name, mapped_void content_data_ptr,
                           u32 flags, mapped_u32 disposition_ptr, mapped_u32 license_mask_ptr,
                           mapped_void overlapped_ptr) {
  return xeXamContentCreate(user_index, root_name, content_data_ptr, sizeof(XCONTENT_DATA), flags,
                            disposition_ptr, license_mask_ptr, 0, 0, overlapped_ptr);
}

u32 XamContentCreateInternal_entry(mapped_string root_name, mapped_void content_data_ptr, u32 flags,
                                   mapped_u32 disposition_ptr, mapped_u32 license_mask_ptr,
                                   u32 cache_size, u64 content_size, mapped_void overlapped_ptr) {
  return xeXamContentCreate(0xFE, root_name, content_data_ptr, sizeof(XCONTENT_AGGREGATE_DATA),
                            flags, disposition_ptr, license_mask_ptr, cache_size, content_size,
                            overlapped_ptr);
}

u32 XamContentOpenFile_entry(u32 user_index, mapped_string root_name, mapped_string path, u32 flags,
                             mapped_u32 disposition_ptr, mapped_u32 license_mask_ptr,
                             mapped_void overlapped_ptr) {
  // TODO(gibbed): arguments assumed based on XamContentCreate.
  return X_ERROR_FILE_NOT_FOUND;
}

u32 XamContentFlush_entry(mapped_string root_name, mapped_void overlapped_ptr) {
  X_RESULT result = X_ERROR_SUCCESS;
  if (overlapped_ptr) {
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped_ptr.guest_address(), result);
    return X_ERROR_IO_PENDING;
  } else {
    return result;
  }
}

u32 XamContentClose_entry(mapped_string root_name, mapped_void overlapped_ptr) {
  // Closes a previously opened root from XamContentCreate*.
  auto result = REX_KERNEL_STATE()->content_manager()->CloseContent(root_name.value());

  if (overlapped_ptr) {
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped_ptr.guest_address(), result);
    return X_ERROR_IO_PENDING;
  } else {
    return result;
  }
}

u32 XamContentGetCreator_entry(u32 user_index, mapped_void content_data_ptr,
                               mapped_u32 is_creator_ptr, mapped_u64 creator_xuid_ptr,
                               mapped_void overlapped_ptr) {
  // (Audit A3, ronda 6, R6-06.) A NULL is_creator_ptr used to write to
  // guest address 0. (creator_xuid_ptr is already guarded below.)
  if (!is_creator_ptr) {
    return X_E_INVALIDARG;
  }

  // (Hunt v1.4.6, ronda 7, A3-R7-03.) content_data_ptr is read as a
  // 0x134-byte XCONTENT_DATA below; is_creator_ptr (4 bytes) and
  // creator_xuid_ptr (8 bytes, when present) are written.
  if (!content_data_ptr ||
      !GuestRangeReadable(content_data_ptr.guest_address(), sizeof(XCONTENT_DATA)) ||
      !GuestRangeWritable(is_creator_ptr.guest_address(), sizeof(uint32_t)) ||
      (creator_xuid_ptr &&
       !GuestRangeWritable(creator_xuid_ptr.guest_address(), sizeof(uint64_t)))) {
    return X_E_INVALIDARG;
  }

  auto result = X_ERROR_SUCCESS;

  uint64_t xuid = REX_KERNEL_STATE()->user_profile()->xuid();
  XCONTENT_AGGREGATE_DATA content_data = *content_data_ptr.as<XCONTENT_DATA*>();

  bool content_exists = REX_KERNEL_STATE()->content_manager()->ContentExists(xuid, content_data);

  if (content_exists) {
    if (content_data.content_type == XContentType::kSavedGame) {
      // User always creates saves.
      *is_creator_ptr = 1;
      if (creator_xuid_ptr) {
        *creator_xuid_ptr = xuid;
      }
    } else {
      *is_creator_ptr = 0;
      if (creator_xuid_ptr) {
        *creator_xuid_ptr = 0;
      }
    }
  } else {
    result = X_ERROR_PATH_NOT_FOUND;
  }

  if (overlapped_ptr) {
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped_ptr.guest_address(), result);
    return X_ERROR_IO_PENDING;
  } else {
    return result;
  }
}

u32 XamContentGetThumbnail_entry(u32 user_index, mapped_void content_data_ptr,
                                 mapped_void buffer_ptr, mapped_u32 buffer_size_ptr,
                                 mapped_void overlapped_ptr) {
  // (Audit A3, ronda 6, R6-06.) assert_not_null is a no-op in Release;
  // a NULL buffer_size_ptr used to read/write guest address 0.
  if (!buffer_size_ptr) {
    return X_E_INVALIDARG;
  }

  // (Hunt v1.4.6, ronda 7, A3-R7-03.) buffer_size_ptr is read and
  // written (4 bytes) and content_data_ptr is read as a 0x134-byte
  // XCONTENT_DATA: validate both before the first dereference.
  if (!content_data_ptr ||
      !GuestRangeReadable(content_data_ptr.guest_address(), sizeof(XCONTENT_DATA)) ||
      !GuestRangeWritable(buffer_size_ptr.guest_address(), sizeof(uint32_t))) {
    return X_E_INVALIDARG;
  }

  uint32_t buffer_size = *buffer_size_ptr;
  uint64_t xuid = REX_KERNEL_STATE()->user_profile()->xuid();
  XCONTENT_AGGREGATE_DATA content_data = *content_data_ptr.as<XCONTENT_DATA*>();

  // Get thumbnail (if it exists).
  std::vector<uint8_t> buffer;
  auto result =
      REX_KERNEL_STATE()->content_manager()->GetContentThumbnail(xuid, content_data, &buffer);

  *buffer_size_ptr = uint32_t(buffer.size());

  if (XSUCCEEDED(result)) {
    // Write data, if we were given a pointer.
    // This may have just been a size query.
    if (buffer_ptr) {
      if (buffer_size < buffer.size()) {
        // Dest buffer too small.
        result = X_ERROR_INSUFFICIENT_BUFFER;
      } else if (!GuestRangeWritable(buffer_ptr.guest_address(), buffer.size())) {
        // (Hunt v1.4.6, ronda 7, A3-R7-03.) Validate the destination
        // against the bytes actually copied (buffer.size()), not the
        // guest-provided buffer_size. The error still flows through
        // the overlapped completion below, like the other failures.
        result = X_E_INVALIDARG;
      } else {
        // Copy data.
        std::memcpy((uint8_t*)buffer_ptr, buffer.data(), buffer.size());
      }
    }
  }

  if (overlapped_ptr) {
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped_ptr.guest_address(), result);
    return X_ERROR_IO_PENDING;
  } else {
    return result;
  }
}

u32 XamContentSetThumbnail_entry(u32 user_index, mapped_void content_data_ptr,
                                 mapped_void buffer_ptr, u32 buffer_size,
                                 mapped_void overlapped_ptr) {
  // (Hunt v1.4.6, ronda 7, A3-R7-03.) content_data_ptr is read as a
  // 0x134-byte XCONTENT_DATA, and the vector below reads buffer_size
  // bytes (a guest u32) from buffer_ptr: validate both ranges first,
  // so a ~4 GiB size is rejected instead of trying to reserve 4 GiB.
  if (!content_data_ptr ||
      !GuestRangeReadable(content_data_ptr.guest_address(), sizeof(XCONTENT_DATA)) ||
      (buffer_ptr && !GuestRangeReadable(buffer_ptr.guest_address(), buffer_size)) ||
      (!buffer_ptr && buffer_size)) {
    return X_E_INVALIDARG;
  }
  uint64_t xuid = REX_KERNEL_STATE()->user_profile()->xuid();
  XCONTENT_AGGREGATE_DATA content_data = *content_data_ptr.as<XCONTENT_DATA*>();

  // Buffer is PNG data.
  auto buffer = std::vector<uint8_t>((uint8_t*)buffer_ptr, (uint8_t*)buffer_ptr + buffer_size);
  auto result = REX_KERNEL_STATE()->content_manager()->SetContentThumbnail(xuid, content_data,
                                                                           std::move(buffer));

  if (overlapped_ptr) {
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped_ptr.guest_address(), result);
    return X_ERROR_IO_PENDING;
  } else {
    return result;
  }
}

u32 XamContentDelete_entry(u32 user_index, mapped_void content_data_ptr,
                           mapped_void overlapped_ptr) {
  // (Hunt v1.4.6, ronda 7, A3-R7-03.) content_data_ptr is read as a
  // 0x134-byte XCONTENT_DATA below.
  if (!content_data_ptr ||
      !GuestRangeReadable(content_data_ptr.guest_address(), sizeof(XCONTENT_DATA))) {
    return X_E_INVALIDARG;
  }
  uint64_t xuid = REX_KERNEL_STATE()->user_profile()->xuid();
  XCONTENT_AGGREGATE_DATA content_data = *content_data_ptr.as<XCONTENT_DATA*>();

  auto result = REX_KERNEL_STATE()->content_manager()->DeleteContent(xuid, content_data);

  if (overlapped_ptr) {
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped_ptr.guest_address(), result);
    return X_ERROR_IO_PENDING;
  } else {
    return result;
  }
}

u32 XamContentDeleteInternal_entry(mapped_void content_data_ptr, mapped_void overlapped_ptr) {
  // INFO: Analysis of xam.xex shows that "internal" functions are wrappers with
  // 0xFE as user_index
  // (Hunt v1.4.6, ronda 7, A3-R7-03.) content_data_ptr is read as a
  // 0x148-byte XCONTENT_AGGREGATE_DATA below.
  if (!content_data_ptr ||
      !GuestRangeReadable(content_data_ptr.guest_address(),
                          sizeof(XCONTENT_AGGREGATE_DATA))) {
    return X_E_INVALIDARG;
  }
  uint64_t xuid = REX_KERNEL_STATE()->user_profile()->xuid();
  XCONTENT_AGGREGATE_DATA content_data = *content_data_ptr.as<XCONTENT_AGGREGATE_DATA*>();

  auto result = REX_KERNEL_STATE()->content_manager()->DeleteContent(xuid, content_data);

  if (overlapped_ptr) {
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped_ptr.guest_address(), result);
    return X_ERROR_IO_PENDING;
  } else {
    return result;
  }
}

}  // namespace xam
}  // namespace kernel
}  // namespace rex

REX_EXPORT(__imp__XamContentGetLicenseMask, rex::kernel::xam::XamContentGetLicenseMask_entry)
REX_EXPORT(__imp__XamContentResolve, rex::kernel::xam::XamContentResolve_entry)
REX_EXPORT(__imp__XamContentCreateEnumerator, rex::kernel::xam::XamContentCreateEnumerator_entry)
REX_EXPORT(__imp__XamContentCreateEx, rex::kernel::xam::XamContentCreateEx_entry)
REX_EXPORT(__imp__XamContentCreate, rex::kernel::xam::XamContentCreate_entry)
REX_EXPORT(__imp__XamContentCreateInternal, rex::kernel::xam::XamContentCreateInternal_entry)
REX_EXPORT(__imp__XamContentOpenFile, rex::kernel::xam::XamContentOpenFile_entry)
REX_EXPORT(__imp__XamContentFlush, rex::kernel::xam::XamContentFlush_entry)
REX_EXPORT(__imp__XamContentClose, rex::kernel::xam::XamContentClose_entry)
REX_EXPORT(__imp__XamContentGetCreator, rex::kernel::xam::XamContentGetCreator_entry)
REX_EXPORT(__imp__XamContentGetThumbnail, rex::kernel::xam::XamContentGetThumbnail_entry)
REX_EXPORT(__imp__XamContentSetThumbnail, rex::kernel::xam::XamContentSetThumbnail_entry)
REX_EXPORT(__imp__XamContentDelete, rex::kernel::xam::XamContentDelete_entry)
REX_EXPORT(__imp__XamContentDeleteInternal, rex::kernel::xam::XamContentDeleteInternal_entry)

REX_EXPORT_STUB(__imp__XamContentClosePackageFile);
REX_EXPORT_STUB(__imp__XamContentCopyInternal);
REX_EXPORT_STUB(__imp__XamContentCreateAndMountPackage);
REX_EXPORT_STUB(__imp__XamContentCreateEnumeratorInternal);
REX_EXPORT_STUB(__imp__XamContentDismountAndClosePackage);
REX_EXPORT_STUB(__imp__XamContentDuplicateFileHandle);
REX_EXPORT_STUB(__imp__XamContentExistsOnDeviceInternal);
REX_EXPORT_STUB(__imp__XamContentFlushPackage);
REX_EXPORT_STUB(__imp__XamContentGetAttributes);
REX_EXPORT_STUB(__imp__XamContentGetAttributesInternal);
REX_EXPORT_STUB(__imp__XamContentGetHeaderInternal);
REX_EXPORT_STUB(__imp__XamContentGetLocalizedString);
REX_EXPORT_STUB(__imp__XamContentGetMetaDataInternal);
REX_EXPORT_STUB(__imp__XamContentGetMountedPackageByRootName);
REX_EXPORT_STUB(__imp__XamContentGetOnlineCreator);
REX_EXPORT_STUB(__imp__XamContentInstall);
REX_EXPORT_STUB(__imp__XamContentInstallInternal);
REX_EXPORT_STUB(__imp__XamContentIsGameInstalledToHDD);
REX_EXPORT_STUB(__imp__XamContentLaunchImage);
REX_EXPORT_STUB(__imp__XamContentLaunchImageFromFileInternal);
REX_EXPORT_STUB(__imp__XamContentLaunchImageInternal);
REX_EXPORT_STUB(__imp__XamContentLaunchImageInternalEx);
REX_EXPORT_STUB(__imp__XamContentLockUnlockPackageHeaders);
REX_EXPORT_STUB(__imp__XamContentMountInstalledGame);
REX_EXPORT_STUB(__imp__XamContentMountPackage);
REX_EXPORT_STUB(__imp__XamContentMoveInternal);
REX_EXPORT_STUB(__imp__XamContentOpenFileInternal);
REX_EXPORT_STUB(__imp__XamContentOpenPackageFile);
REX_EXPORT_STUB(__imp__XamContentQueryLicenseInternal);
REX_EXPORT_STUB(__imp__XamContentRegisterChangeCallback);
REX_EXPORT_STUB(__imp__XamContentResolveInternal);
REX_EXPORT_STUB(__imp__XamContentSetAttributes);
REX_EXPORT_STUB(__imp__XamContentSetMediaMetaDataInternal);
REX_EXPORT_STUB(__imp__XamContentSetThumbnailInternal);
REX_EXPORT_STUB(__imp__XamContentWritePackageHeader);
