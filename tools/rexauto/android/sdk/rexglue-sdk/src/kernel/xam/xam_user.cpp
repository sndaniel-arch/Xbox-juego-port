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

#include <cstring>

#include <rex/cvar.h>
#include <rex/kernel/xam/private.h>
#include <rex/logging.h>
#include <rex/math.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/string.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xam/user_profile.h>
#include <rex/system/xenumerator.h>
#include <rex/system/xio.h>
#include <rex/system/xthread.h>
#include <rex/system/xtypes.h>

REXCVAR_DEFINE_UINT32(user_language, 1, "Kernel", "User's language ID");

namespace rex {
namespace kernel {
namespace xam {
using namespace rex::system;
using namespace rex::system::xam;

// (Hunt v1.4.6, ronda 4, A3-R4-01.) TranslateVirtual never validates and
// never returns null, so a guest pointer + length that runs past the end
// of the mapping SIGSEGVs the host on the memcpy/memset. Mirror the
// XFile::ReadInternal/Write validation (A2-R3-01): reject a range that
// wraps past 4 GiB, starts or ends outside any heap, or spans heaps of
// different kinds (or two physical heaps). When the range lies inside a
// single heap, additionally require the pages to be accessible — the
// MmIsAddressValid precedent (xboxkrnl_memory.cpp) — readable for a
// source, read/write for a destination (and always read/write for a
// physical heap, as XFile does). A range spanning two virtual heaps can
// only be checked at heap granularity; that is the same limit XFile has.
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

i32 XamUserGetXUID_entry(u32 user_index, u32 type_mask, mapped_u64 xuid_ptr) {
  assert_true(type_mask == 1 || type_mask == 2 || type_mask == 3 || type_mask == 4 ||
              type_mask == 7);
  if (!xuid_ptr) {
    return X_E_INVALIDARG;
  }
  // (Hunt v1.4.6, ronda 7, A3-R7-08.) The 8-byte xuid out-param is
  // written at the end with only a NULL-check.
  if (!GuestRangeWritable(xuid_ptr.guest_address(), sizeof(uint64_t))) {
    return X_E_INVALIDARG;
  }
  uint32_t result = X_E_NO_SUCH_USER;
  uint64_t xuid = 0;
  if (user_index < 4) {
    if (user_index == 0) {
      const auto& user_profile = REX_KERNEL_STATE()->user_profile();
      auto type = user_profile->type() & type_mask;
      if (type & (2 | 4)) {
        // maybe online profile?
        xuid = user_profile->xuid();
        result = X_E_SUCCESS;
      } else if (type & 1) {
        // maybe offline profile?
        xuid = user_profile->xuid();
        result = X_E_SUCCESS;
      }
    }
  } else {
    result = X_E_INVALIDARG;
  }
  *xuid_ptr = xuid;
  return result;
}

u32 XamUserGetSigninState_entry(u32 user_index) {
  uint32_t signin_state = 0;
  if (user_index < 4) {
    if (user_index == 0) {
      const auto& user_profile = REX_KERNEL_STATE()->user_profile();
      signin_state = user_profile->signin_state();
    }
  }
  return signin_state;
}

typedef struct {
  rex::be<uint64_t> xuid;
  rex::be<uint32_t> unk08;  // maybe zero?
  rex::be<uint32_t> signin_state;
  rex::be<uint32_t> unk10;  // ?
  rex::be<uint32_t> unk14;  // ?
  char name[16];
} X_USER_SIGNIN_INFO;
static_assert_size(X_USER_SIGNIN_INFO, 40);

i32 XamUserGetSigninInfo_entry(u32 user_index, u32 flags, ppc_ptr_t<X_USER_SIGNIN_INFO> info) {
  if (!info) {
    return X_E_INVALIDARG;
  }

  // (Hunt v1.4.6, ronda 7, A3-R7-08.) The 40-byte struct is memsets
  // and filled with only a NULL-check.
  if (!GuestRangeWritable(info.guest_address(), sizeof(X_USER_SIGNIN_INFO))) {
    return X_E_INVALIDARG;
  }

  std::memset(info, 0, sizeof(X_USER_SIGNIN_INFO));
  if (user_index) {
    return X_E_NO_SUCH_USER;
  }

  const auto& user_profile = REX_KERNEL_STATE()->user_profile();
  info->xuid = user_profile->xuid();
  info->signin_state = user_profile->signin_state();
  rex::string::copy_truncating(info->name, user_profile->name(), rex::countof(info->name));
  return X_E_SUCCESS;
}

u32 XamUserGetName_entry(u32 user_index, mapped_string buffer, u32 buffer_len) {
  if (user_index >= 4) {
    return X_E_INVALIDARG;
  }

  if (user_index) {
    return X_E_NO_SUCH_USER;
  }

  // (Hunt v1.4.6, ronda 4, A3-R4-14.) Same guard as the sister
  // XamUserGetGamerTag below: a NULL buffer used to write the name to
  // guest address 0.
  if (!buffer) {
    return X_E_INVALIDARG;
  }

  // (Hunt v1.4.6, ronda 10, A3-R10-12.) The name buffer (up to 16
  // bytes, the count copy_truncating writes) had only the NULL check
  // above: validate the range first.
  if (!GuestRangeWritable(buffer.guest_address(), std::min(buffer_len, uint32_t(16)))) {
    return X_E_INVALIDARG;
  }
  const auto& user_profile = REX_KERNEL_STATE()->user_profile();
  const auto& user_name = user_profile->name();
  rex::string::copy_truncating(buffer, user_name, std::min(buffer_len, uint32_t(16)));
  return X_E_SUCCESS;
}

u32 XamUserGetGamerTag_entry(u32 user_index, mapped_wstring buffer, u32 buffer_len) {
  if (user_index >= 4) {
    return X_E_INVALIDARG;
  }

  if (user_index) {
    return X_E_NO_SUCH_USER;
  }

  if (!buffer || buffer_len < 16) {
    return X_E_INVALIDARG;
  }

  // (Hunt v1.4.6, ronda 10, A3-R10-12.) The gamertag buffer (up to
  // 16 UTF-16 code units = 32 bytes) had only the NULL / length
  // checks above: validate the range first.
  if (!GuestRangeWritable(buffer.guest_address(),
                          static_cast<size_t>(std::min(buffer_len, uint32_t(16))) *
                              sizeof(char16_t))) {
    return X_E_INVALIDARG;
  }
  const auto& user_profile = REX_KERNEL_STATE()->user_profile();
  auto user_name = rex::string::to_utf16(user_profile->name());
  rex::string::copy_and_swap_truncating(buffer, user_name, std::min(buffer_len, uint32_t(16)));
  return X_E_SUCCESS;
}

typedef struct {
  rex::be<uint32_t> setting_count;
  rex::be<uint32_t> settings_ptr;
} X_USER_READ_PROFILE_SETTINGS;
static_assert_size(X_USER_READ_PROFILE_SETTINGS, 8);

// https://github.com/oukiar/freestyledash/blob/master/Freestyle/Tools/Generic/xboxtools.cpp
uint32_t XamUserReadProfileSettingsEx(uint32_t title_id, uint32_t user_index, uint32_t xuid_count,
                                      be<uint64_t>* xuids, uint32_t setting_count,
                                      be<uint32_t>* setting_ids, uint32_t unk,
                                      be<uint32_t>* buffer_size_ptr, uint8_t* buffer,
                                      XAM_OVERLAPPED* overlapped) {
  // (Hunt v1.4.6, ronda 3, A3-R3-22.) xuids and setting_ids were the
  // two pointers in this function without a guard (buffer_size_ptr
  // and buffer both have one below): xuid_count > 0 with NULL xuids
  // dereferenced xuids[0] at the assert below, and setting_ids[i] is
  // read in three loops. The assert_not_null on xuids is a no-op in
  // Release.
  if ((xuid_count && !xuids) || !setting_ids) {
    return X_ERROR_INVALID_PARAMETER;
  }
  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-13.)
  // Direct sibling of FE-08 (WriteProfileSettings, same file): R3-22
  // above only NULL-checked the three guest arrays this function reads
  // and writes, but none of their ranges was validated. The pointers
  // arrive here already translated to host pointers, so recover the
  // guest address with HostToGuestVirtual (same call this function
  // already uses for the output header below). Only xuids[0] is ever
  // read (the count is clamped to 1 just below), so 8 bytes is what
  // this guard covers; the setting_ids array and the out-params are
  // covered by the guards after the count cap below.
  if (xuid_count && xuids &&
      !GuestRangeReadable(REX_KERNEL_MEMORY()->HostToGuestVirtual(xuids),
                          sizeof(uint64_t))) {
    return X_ERROR_INVALID_PARAMETER;
  }
  if (!xuid_count) {
    assert_null(xuids);
  } else {
    assert_true(xuid_count == 1);
    assert_not_null(xuids);
    // TODO(gibbed): allow proper lookup of arbitrary XUIDs
    const auto& user_profile = REX_KERNEL_STATE()->user_profile();
    assert_true(static_cast<uint64_t>(xuids[0]) == user_profile->xuid());
    // TODO(gibbed): we assert here, but in case a title passes xuid_count > 1
    // until it's implemented for release builds...
    xuid_count = 1;
  }
  assert_zero(unk);  // probably flags

  // must have at least 1 to 32 settings
  if (setting_count < 1 || setting_count > 32) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-13.)
  // The setting_ids array (setting_count * 4 bytes) is read in three
  // loops below. The cap above bounds it to 128 bytes, so the size
  // cannot overflow; validate the whole array before the first loop.
  if (!GuestRangeReadable(REX_KERNEL_MEMORY()->HostToGuestVirtual(setting_ids),
                          static_cast<size_t>(setting_count) * sizeof(uint32_t))) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // buffer size pointer must be valid
  if (!buffer_size_ptr) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-13.)
  // *buffer_size_ptr is read just below and written back on the
  // insufficient-buffer path: validate the 4 bytes readable AND
  // writable before touching it.
  if (!GuestRangeReadable(REX_KERNEL_MEMORY()->HostToGuestVirtual(buffer_size_ptr),
                          sizeof(uint32_t)) ||
      !GuestRangeWritable(REX_KERNEL_MEMORY()->HostToGuestVirtual(buffer_size_ptr),
                          sizeof(uint32_t))) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // if buffer size is non-zero, buffer pointer must be valid
  auto buffer_size = static_cast<uint32_t>(*buffer_size_ptr);
  if (buffer_size && !buffer) {
    return X_ERROR_INVALID_PARAMETER;
  }

  uint32_t needed_header_size = 0;
  uint32_t needed_data_size = 0;
  for (uint32_t i = 0; i < setting_count; ++i) {
    needed_header_size += sizeof(X_USER_PROFILE_SETTING);
    UserProfile::Setting::Key setting_key;
    setting_key.value = static_cast<uint32_t>(setting_ids[i]);
    switch (static_cast<UserProfile::Setting::Type>(setting_key.type)) {
      case UserProfile::Setting::Type::WSTRING:
      case UserProfile::Setting::Type::BINARY:
        // (Hunt v1.4.6, ronda 4, A3-R4-02.) Count the STORED value, not
        // the 12-bit `size` field of the requested key: Append writes
        // the stored value in full, so counting only the key size made
        // the first (size-query) call report a buffer too small for the
        // second (fill) call, which then wrote past it. Unknown
        // settings keep the old key-size count (Append writes nothing
        // for them).
        if (auto* stored_setting =
                REX_KERNEL_STATE()->user_profile()->GetSetting(static_cast<uint32_t>(setting_ids[i]))) {
          needed_data_size += static_cast<uint32_t>(stored_setting->DataSize());
        } else {
          needed_data_size += setting_key.size;
        }
        break;
      default:
        break;
    }
  }
  if (xuids) {
    needed_header_size *= xuid_count;
    needed_data_size *= xuid_count;
  }
  needed_header_size += sizeof(X_USER_READ_PROFILE_SETTINGS);

  uint32_t needed_size = needed_header_size + needed_data_size;
  if (!buffer || buffer_size < needed_size) {
    if (!buffer_size) {
      *buffer_size_ptr = needed_size;
    }
    return X_ERROR_INSUFFICIENT_BUFFER;
  }

  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-13.)
  // The fill below writes the header + settings into `buffer`
  // (buffer_size bytes; the size check above guarantees
  // buffer_size >= needed_size). Validate the whole destination range
  // first -- placed here, after the insufficient-buffer early return,
  // so the size-query path (buffer NULL or too small, buffer never
  // touched) keeps returning X_ERROR_INSUFFICIENT_BUFFER unchanged.
  if (!GuestRangeWritable(REX_KERNEL_MEMORY()->HostToGuestVirtual(buffer), buffer_size)) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // Title ID = 0 means us.
  // 0xfffe07d1 = profile?

  if (!xuids && user_index) {
    // Only support user 0.
    if (overlapped) {
      REX_KERNEL_STATE()->CompleteOverlappedImmediate(
          REX_KERNEL_MEMORY()->HostToGuestVirtual(overlapped), X_ERROR_NO_SUCH_USER);
      return X_ERROR_IO_PENDING;
    }
    return X_ERROR_NO_SUCH_USER;
  }

  const auto& user_profile = REX_KERNEL_STATE()->user_profile();

  // First call asks for size (fill buffer_size_ptr).
  // Second call asks for buffer contents with that size.

  // TODO(gibbed): setting validity checking without needing a user profile
  // object.
  bool any_missing = false;
  for (uint32_t i = 0; i < setting_count; ++i) {
    auto setting_id = static_cast<uint32_t>(setting_ids[i]);
    auto setting = user_profile->GetSetting(setting_id);
    if (!setting) {
      any_missing = true;
      REXKRNL_ERROR(
          "xeXamUserReadProfileSettingsEx requested unimplemented setting "
          "{:08X}",
          setting_id);
    }
  }
  if (any_missing) {
    // TODO(benvanik): don't fail? most games don't even check!
    if (overlapped) {
      REX_KERNEL_STATE()->CompleteOverlappedImmediate(
          REX_KERNEL_MEMORY()->HostToGuestVirtual(overlapped), X_ERROR_INVALID_PARAMETER);
      return X_ERROR_IO_PENDING;
    }
    return X_ERROR_INVALID_PARAMETER;
  }

  auto out_header = reinterpret_cast<X_USER_READ_PROFILE_SETTINGS*>(buffer);
  auto out_setting = reinterpret_cast<X_USER_PROFILE_SETTING*>(&out_header[1]);
  out_header->setting_count = static_cast<uint32_t>(setting_count);
  out_header->settings_ptr = REX_KERNEL_MEMORY()->HostToGuestVirtual(out_setting);

  UserProfile::SettingByteStream out_stream(REX_KERNEL_MEMORY()->HostToGuestVirtual(buffer), buffer,
                                            buffer_size, needed_header_size);
  for (uint32_t n = 0; n < setting_count; ++n) {
    uint32_t setting_id = setting_ids[n];
    auto setting = user_profile->GetSetting(setting_id);

    std::memset(out_setting, 0, sizeof(X_USER_PROFILE_SETTING));
    out_setting->from = !setting || !setting->is_set ? 0 : setting->is_title_specific() ? 2 : 1;
    if (xuids) {
      out_setting->xuid = user_profile->xuid();
    } else {
      out_setting->user_index = static_cast<uint32_t>(user_index);
    }
    out_setting->setting_id = setting_id;

    if (setting && setting->is_set) {
      setting->Append(&out_setting->data, &out_stream);
    }
    ++out_setting;
  }

  if (overlapped) {
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(
        REX_KERNEL_MEMORY()->HostToGuestVirtual(overlapped), X_ERROR_SUCCESS);
    return X_ERROR_IO_PENDING;
  }
  return X_ERROR_SUCCESS;
}

u32 XamUserReadProfileSettings_entry(u32 title_id, u32 user_index, u32 xuid_count, mapped_u64 xuids,
                                     u32 setting_count, mapped_u32 setting_ids,
                                     mapped_u32 buffer_size_ptr, mapped_void buffer_ptr,
                                     ppc_ptr_t<XAM_OVERLAPPED> overlapped) {
  return XamUserReadProfileSettingsEx(title_id, user_index, xuid_count, xuids, setting_count,
                                      setting_ids, 0, buffer_size_ptr, buffer_ptr, overlapped);
}

u32 XamUserReadProfileSettingsEx_entry(u32 title_id, u32 user_index, u32 xuid_count,
                                       mapped_u64 xuids, u32 setting_count, mapped_u32 setting_ids,
                                       mapped_u32 buffer_size_ptr, u32 unk_2,
                                       mapped_void buffer_ptr,
                                       ppc_ptr_t<XAM_OVERLAPPED> overlapped) {
  return XamUserReadProfileSettingsEx(title_id, user_index, xuid_count, xuids, setting_count,
                                      setting_ids, unk_2, buffer_size_ptr, buffer_ptr, overlapped);
}

u32 XamUserWriteProfileSettings_entry(u32 title_id, u32 user_index, u32 setting_count,
                                      ppc_ptr_t<X_USER_PROFILE_SETTING> settings,
                                      ppc_ptr_t<XAM_OVERLAPPED> overlapped) {
  if (!settings) {
    return X_ERROR_INVALID_PARAMETER;
  }
  // (Verificacion profunda, FE-08.) setting_count is guest-controlled
  // (u32) and had no upper bound, while the sister read
  // XamUserReadProfileSettingsEx caps it at 1..32 in this same file
  // (:232). Apply the same cap here: the game passes only a few
  // settings.
  if (setting_count < 1 || setting_count > 32) {
    return X_ERROR_INVALID_PARAMETER;
  }

  if (user_index) {
    // Only support user 0.
    if (overlapped) {
      REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped.guest_address(),
                                                      X_ERROR_NO_SUCH_USER);
      return X_ERROR_IO_PENDING;
    }
    return X_ERROR_NO_SUCH_USER;
  }

  // Update and save settings.
  const auto& user_profile = REX_KERNEL_STATE()->user_profile();

  // (Verificacion profunda, FE-08.) Validate the whole settings array
  // (setting_count * 40 bytes; X_USER_PROFILE_SETTING is 40 bytes per
  // static_assert_size in user_profile.h) before the loop reads
  // settings[n]: a short array crossing the end of the mapping used to
  // SIGSEGV the host. setting_count <= 32 here, so the size cannot
  // overflow. Checked here, after the user_index early return, so the
  // NO_SUCH_USER path is unchanged.
  if (!GuestRangeReadable(settings.guest_address(),
                          setting_count * sizeof(X_USER_PROFILE_SETTING))) {
    return X_ERROR_INVALID_PARAMETER;
  }

  for (uint32_t n = 0; n < setting_count; ++n) {
    const X_USER_PROFILE_SETTING& setting = settings[n];

    auto setting_type = static_cast<UserProfile::Setting::Type>(setting.data.type);
    if (setting_type == UserProfile::Setting::Type::UNSET) {
      continue;
    }

    REXKRNL_DEBUG(
        "XamUserWriteProfileSettings: setting index [{}]:"
        " from={} setting_id={:08X} data.type={}",
        n, (uint32_t)setting.from, (uint32_t)setting.setting_id, setting.data.type);

    switch (setting_type) {
      case UserProfile::Setting::Type::CONTENT:
      case UserProfile::Setting::Type::BINARY: {
        // (Hunt v1.4.6, ronda 4, A3-R4-01.) binary.size is guest
        // controlled (u32, up to 4 GiB): the old code resized a vector
        // to it and memcpy'd from an unvalidated guest pointer — a
        // SIGSEGV past the end of the mapping, or bad_alloc/terminate
        // on the resize. The setting-id `size` field is 12 bits, so no
        // legitimate binary setting is larger than 4095 bytes; reject
        // anything bigger, and validate the source range before the
        // copy. The ptr == 0 branch only zero-fills, so it needs the
        // cap but no range check. A bad setting is skipped (logged)
        // rather than failing the whole save.
        size_t binary_size = setting.data.binary.size;
        if (binary_size > 4095) {
          REXKRNL_ERROR(
              "XamUserWriteProfileSettings: binary setting {:08X} size {} exceeds the "
              "12-bit setting size field (4095); skipping",
              (uint32_t)setting.setting_id, binary_size);
          break;
        }
        uint32_t binary_ptr_guest = static_cast<uint32_t>(setting.data.binary.ptr);
        if (setting.data.binary.ptr &&
            !GuestRangeReadable(binary_ptr_guest, binary_size)) {
          REXKRNL_ERROR(
              "XamUserWriteProfileSettings: binary setting {:08X} source range {:08X}+{} "
              "is outside readable guest memory; skipping",
              (uint32_t)setting.setting_id, binary_ptr_guest, binary_size);
          break;
        }
        uint8_t* binary_ptr = REX_KERNEL_MEMORY()->TranslateVirtual(binary_ptr_guest);
        std::vector<uint8_t> bytes;
        if (setting.data.binary.ptr) {
          // Copy provided data
          bytes.resize(binary_size);
          std::memcpy(bytes.data(), binary_ptr, binary_size);
        } else {
          // Data pointer was NULL, so just fill with zeroes
          bytes.resize(binary_size, 0);
        }
        user_profile->AddSetting(
            std::make_unique<xam::UserProfile::BinarySetting>(setting.setting_id, bytes));
      } break;
      case UserProfile::Setting::Type::WSTRING:
      case UserProfile::Setting::Type::DOUBLE:
      case UserProfile::Setting::Type::FLOAT:
      case UserProfile::Setting::Type::INT32:
      case UserProfile::Setting::Type::INT64:
      case UserProfile::Setting::Type::DATETIME:
      default: {
        REXKRNL_ERROR("XamUserWriteProfileSettings: Unimplemented data type {}", setting_type);
      } break;
    };
  }

  if (overlapped) {
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped.guest_address(), X_ERROR_SUCCESS);
    return X_ERROR_IO_PENDING;
  }
  return X_ERROR_SUCCESS;
}

u32 XamUserCheckPrivilege_entry(u32 user_index, u32 mask, mapped_u32 out_value) {
  // (Audit A3, ronda 6, R6-06.) A NULL out_value used to write 0 to
  // guest address 0.
  if (!out_value) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, ronda 10, A3-R10-12.) *out_value is written below
  // with only the NULL check above: validate the 4-byte range first.
  if (!GuestRangeWritable(out_value.guest_address(), sizeof(uint32_t))) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // checking all users?
  if (user_index != 0xFF) {
    if (user_index >= 4) {
      return X_ERROR_INVALID_PARAMETER;
    }

    if (user_index) {
      return X_ERROR_NO_SUCH_USER;
    }
  }

  // If we deny everything, games should hopefully not try to do stuff.
  *out_value = 0;
  return X_ERROR_SUCCESS;
}

u32 XamUserContentRestrictionGetFlags_entry(u32 user_index, mapped_u32 out_flags) {
  // (Audit A3, ronda 6, R6-06.) A NULL out_flags used to write 0 to
  // guest address 0.
  if (!out_flags) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, ronda 10, A3-R10-12.) Same 4-byte out-param class
  // as CheckPrivilege above.
  if (!GuestRangeWritable(out_flags.guest_address(), sizeof(uint32_t))) {
    return X_ERROR_INVALID_PARAMETER;
  }

  if (user_index) {
    return X_ERROR_NO_SUCH_USER;
  }

  // No restrictions?
  *out_flags = 0;
  return X_ERROR_SUCCESS;
}

u32 XamUserContentRestrictionGetRating_entry(u32 user_index, u32 unk1, mapped_u32 out_unk2,
                                             mapped_u32 out_unk3) {
  // (Audit A3, ronda 6, R6-06.) NULL out params used to write to
  // guest address 0.
  if (!out_unk2 || !out_unk3) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, ronda 10, A3-R10-12.) Both out-params are written
  // below with only the NULL checks above: validate both 4-byte
  // ranges first.
  if (!GuestRangeWritable(out_unk2.guest_address(), sizeof(uint32_t)) ||
      !GuestRangeWritable(out_unk3.guest_address(), sizeof(uint32_t))) {
    return X_ERROR_INVALID_PARAMETER;
  }

  if (user_index) {
    return X_ERROR_NO_SUCH_USER;
  }

  // Some games have special case paths for 3F that differ from the failure
  // path, so my guess is that's 'don't care'.
  *out_unk2 = 0x3F;
  *out_unk3 = 0;
  return X_ERROR_SUCCESS;
}

u32 XamUserContentRestrictionCheckAccess_entry(u32 user_index, u32 unk1, u32 unk2, u32 unk3,
                                               u32 unk4, mapped_u32 out_unk5, u32 overlapped_ptr) {
  // (Audit A3, ronda 6, R6-06.) A NULL out_unk5 used to write 1 to
  // guest address 0.
  if (!out_unk5) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, ronda 10, A3-R10-12.) The old code wrote *out_unk5
  // = 1 here, before any validation at all. The range is validated
  // first now; the write itself is unchanged.
  if (!GuestRangeWritable(out_unk5.guest_address(), sizeof(uint32_t))) {
    return X_ERROR_INVALID_PARAMETER;
  }

  *out_unk5 = 1;

  if (overlapped_ptr) {
    // TODO(benvanik): does this need the access arg on it?
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped_ptr, X_ERROR_SUCCESS);
  }

  return X_ERROR_SUCCESS;
}

u32 XamUserIsOnlineEnabled_entry(u32 user_index) {
  return 1;
}

u32 XamUserGetMembershipTier_entry(u32 user_index) {
  if (user_index >= 4) {
    return X_ERROR_INVALID_PARAMETER;
  }
  if (user_index) {
    return X_ERROR_NO_SUCH_USER;
  }
  return 6 /* 6 appears to be Gold */;
}

u32 XamUserAreUsersFriends_entry(u32 user_index, u32 unk1, u32 unk2, mapped_u32 out_value,
                                 u32 overlapped_ptr) {
  // (Hunt v1.4.6, ronda 10, A3-R10-12.) *out_value is written below
  // (even on failure paths, with 0) with only a NULL check: validate
  // the 4-byte range first. A NULL out_value stays allowed here --
  // the overlapped path below is the alternative.
  if (out_value && !GuestRangeWritable(out_value.guest_address(), sizeof(uint32_t))) {
    return X_ERROR_INVALID_PARAMETER;
  }
  uint32_t are_friends = 0;
  X_RESULT result;

  if (user_index >= 4) {
    result = X_ERROR_INVALID_PARAMETER;
  } else {
    if (user_index == 0) {
      const auto& user_profile = REX_KERNEL_STATE()->user_profile();
      if (user_profile->signin_state() == 0) {
        result = X_ERROR_NOT_LOGGED_ON;
      } else {
        // No friends!
        are_friends = 0;
        result = X_ERROR_SUCCESS;
      }
    } else {
      // Only support user 0.
      result = X_ERROR_NO_SUCH_USER;  // if user is local -> X_ERROR_NOT_LOGGED_ON
    }
  }

  if (out_value) {
    assert_true(!overlapped_ptr);
    *out_value = result == X_ERROR_SUCCESS ? are_friends : 0;
    return result;
  } else if (overlapped_ptr) {
    assert_true(!out_value);
    REX_KERNEL_STATE()->CompleteOverlappedImmediateEx(
        overlapped_ptr, result == X_ERROR_SUCCESS ? X_ERROR_SUCCESS : X_ERROR_FUNCTION_FAILED,
        X_HRESULT_FROM_WIN32(result), result == X_ERROR_SUCCESS ? are_friends : 0);
    return X_ERROR_IO_PENDING;
  } else {
    assert_always();
    return X_ERROR_INVALID_PARAMETER;
  }
}

u32 XamShowSigninUI_entry(u32 unk, u32 unk_mask) {
  // Mask values vary. Probably matching user types? Local/remote?

  // To fix game modes that display a 4 profile signin UI (even if playing
  // alone):
  // XN_SYS_SIGNINCHANGED
  REX_KERNEL_STATE()->BroadcastNotification(0x0000000A, 1);
  // Games seem to sit and loop until we trigger this notification:
  // XN_SYS_UI (off)
  REX_KERNEL_STATE()->BroadcastNotification(0x00000009, 0);
  return X_ERROR_SUCCESS;
}

// TODO(gibbed): probably a FILETIME/LARGE_INTEGER, unknown currently
struct X_ACHIEVEMENT_UNLOCK_TIME {
  rex::be<uint32_t> unk_0;
  rex::be<uint32_t> unk_4;
};

struct X_ACHIEVEMENT_DETAILS {
  rex::be<uint32_t> id;
  rex::be<uint32_t> label_ptr;
  rex::be<uint32_t> description_ptr;
  rex::be<uint32_t> unachieved_ptr;
  rex::be<uint32_t> image_id;
  rex::be<uint32_t> gamerscore;
  X_ACHIEVEMENT_UNLOCK_TIME unlock_time;
  rex::be<uint32_t> flags;

  static const size_t kStringBufferSize = 464;
};
static_assert_size(X_ACHIEVEMENT_DETAILS, 36);

class XStaticAchievementEnumerator : public XEnumerator {
 public:
  struct AchievementDetails {
    uint32_t id;
    std::u16string label;
    std::u16string description;
    std::u16string unachieved;
    uint32_t image_id;
    uint32_t gamerscore;
    struct {
      uint32_t unk_0;
      uint32_t unk_4;
    } unlock_time;
    uint32_t flags;
  };

  XStaticAchievementEnumerator(KernelState* kernel_state, size_t items_per_enumerate,
                               uint32_t flags)
      : XEnumerator(kernel_state, items_per_enumerate,
                    sizeof(X_ACHIEVEMENT_DETAILS) +
                        (!!(flags & 7) ? X_ACHIEVEMENT_DETAILS::kStringBufferSize : 0)),
        flags_(flags) {}

  void AppendItem(AchievementDetails item) { items_.push_back(std::move(item)); }

  uint32_t WriteItems(uint32_t buffer_ptr, uint8_t* buffer_data, uint32_t* written_count,
                      size_t buffer_size) override {
    // (Hunt v1.4.6, ronda 4, A3-R4-03.) Truncate the item count to what
    // fits in the buffer the game actually passed. The layout is kept
    // exactly as before — the details array holds items_per_enumerate()
    // entries and the string area starts after it — so a count that fits
    // writes byte-identical output; only an over-large count is cut.
    // With strings, one item costs sizeof(details) in the details array
    // plus kStringBufferSize in the string area; without them, only the
    // details array matters.
    size_t remaining = items_.size() - current_item_;
    size_t count = std::min(remaining, items_per_enumerate());
    if (!count) {
      return X_ERROR_NO_MORE_FILES;
    }
    if (flags_ & 7) {
      size_t details_size = items_per_enumerate() * sizeof(X_ACHIEVEMENT_DETAILS);
      if (buffer_size < details_size) {
        return X_ERROR_INSUFFICIENT_BUFFER;
      }
      size_t string_capacity =
          (buffer_size - details_size) / X_ACHIEVEMENT_DETAILS::kStringBufferSize;
      count = std::min(count, string_capacity);
    } else {
      count = std::min(count, buffer_size / sizeof(X_ACHIEVEMENT_DETAILS));
    }
    if (!count) {
      return X_ERROR_INSUFFICIENT_BUFFER;
    }

    size_t size = count * item_size();

    auto details = reinterpret_cast<X_ACHIEVEMENT_DETAILS*>(buffer_data);
    size_t string_offset = items_per_enumerate() * sizeof(X_ACHIEVEMENT_DETAILS);
    auto string_buffer =
        StringBuffer{buffer_ptr + static_cast<uint32_t>(string_offset), &buffer_data[string_offset],
                     count * X_ACHIEVEMENT_DETAILS::kStringBufferSize};
    for (size_t i = 0, o = current_item_; i < count; ++i, ++current_item_) {
      const auto& item = items_[current_item_];
      details[i].id = item.id;
      details[i].label_ptr = !!(flags_ & 1) ? AppendString(string_buffer, item.label) : 0;
      details[i].description_ptr =
          !!(flags_ & 2) ? AppendString(string_buffer, item.description) : 0;
      details[i].unachieved_ptr = !!(flags_ & 4) ? AppendString(string_buffer, item.unachieved) : 0;
      details[i].image_id = item.image_id;
      details[i].gamerscore = item.gamerscore;
      details[i].unlock_time.unk_0 = item.unlock_time.unk_0;
      details[i].unlock_time.unk_4 = item.unlock_time.unk_4;
      details[i].flags = item.flags;
    }

    if (written_count) {
      *written_count = static_cast<uint32_t>(count);
    }

    return X_ERROR_SUCCESS;
  }

 private:
  struct StringBuffer {
    uint32_t ptr;
    uint8_t* data;
    size_t remaining_bytes;
  };

  uint32_t AppendString(StringBuffer& sb, const std::u16string_view string) {
    size_t count = string.length() + 1;
    size_t size = count * sizeof(char16_t);
    if (size > sb.remaining_bytes) {
      assert_always();
      return 0;
    }
    auto ptr = sb.ptr;
    rex::string::copy_and_swap_truncating(reinterpret_cast<char16_t*>(sb.data), string, count);
    sb.ptr += static_cast<uint32_t>(size);
    sb.data += size;
    sb.remaining_bytes -= size;
    return ptr;
  }

 private:
  uint32_t flags_;
  std::vector<AchievementDetails> items_;
  size_t current_item_ = 0;
};

u32 XamUserCreateAchievementEnumerator_entry(u32 title_id, u32 user_index, u32 xuid, u32 flags,
                                             u32 offset, u32 count, mapped_u32 buffer_size_ptr,
                                             mapped_u32 handle_ptr) {
  if (!count || !buffer_size_ptr || !handle_ptr) {
    return X_ERROR_INVALID_PARAMETER;
  }

  if (user_index >= 4) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, ronda 10, A3-R10-12.) Both out-params are written
  // below with only the NULL checks above: validate both 4-byte
  // ranges first.
  if (!GuestRangeWritable(buffer_size_ptr.guest_address(), sizeof(uint32_t)) ||
      !GuestRangeWritable(handle_ptr.guest_address(), sizeof(uint32_t))) {
    return X_ERROR_INVALID_PARAMETER;
  }

  size_t entry_size = sizeof(X_ACHIEVEMENT_DETAILS);
  if (flags & 7) {
    entry_size += X_ACHIEVEMENT_DETAILS::kStringBufferSize;
  }

  if (buffer_size_ptr) {
    // (Hunt v1.4.6, ronda 10, A3-R10-12.) The multiplication used
    // to wrap in u32 for huge counts: compute it in 64 bits (R7-03
    // pattern, as XamContentCreateEnumerator does) and reject a
    // total that does not fit the u32 out-param. Mostly benign in
    // practice -- WriteItems truncates per R4-03 -- but the
    // out-param itself must never carry a wrapped size.
    const uint64_t total_size = static_cast<uint64_t>(entry_size) * count;
    if (total_size > UINT32_MAX) {
      return X_ERROR_INVALID_PARAMETER;
    }
    *buffer_size_ptr = static_cast<uint32_t>(total_size);
  }

  auto e = object_ref<XStaticAchievementEnumerator>(
      new XStaticAchievementEnumerator(REX_KERNEL_STATE(), count, flags));
  auto result = e->Initialize(user_index, 0xFB, 0xB000A, 0xB000B, 0);
  if (XFAILED(result)) {
    return result;
  }

  // ACHIEVED | ACHIEVED_ONLINE flags the game checks to consider an achievement earned.
  constexpr uint32_t kAchievedFlags = 0x00030000;

  auto fill_unlock = [](XStaticAchievementEnumerator::AchievementDetails& item, uint32_t id,
                        const rex::system::KernelState* ks) {
    uint64_t ft = ks->GetAchievementUnlockTime(id);
    if (ft) {
      item.flags |= kAchievedFlags;
      item.unlock_time.unk_0 = static_cast<uint32_t>(ft & 0xFFFF'FFFF);
      item.unlock_time.unk_4 = static_cast<uint32_t>(ft >> 32);
    }
  };

  const auto* ks = REX_KERNEL_STATE();

  // Prefer the runtime store (populated from TOML or XDBF at boot) so that
  // dev-edited labels/descriptions are visible to the game's own queries.
  const auto store = ks->loaded_achievements();
  if (!store.empty()) {
    for (const auto& info : store) {
      auto item = XStaticAchievementEnumerator::AchievementDetails{
          info.id,
          rex::string::to_utf16(info.label),
          rex::string::to_utf16(info.description),
          rex::string::to_utf16(info.unachieved_description),
          info.image_id,
          info.gamerscore,
          {0, 0},
          info.flags};
      fill_unlock(item, info.id, ks);
      e->AppendItem(item);
    }
  } else {
    const util::XdbfGameData db = ks->title_xdbf();
    if (db.is_valid()) {
      const XLanguage language =
          db.GetExistingLanguage(static_cast<XLanguage>(REXCVAR_GET(user_language)));
      for (const util::XdbfAchievementTableEntry& entry : db.GetAchievements()) {
        auto item = XStaticAchievementEnumerator::AchievementDetails{
            entry.id,
            rex::string::to_utf16(db.GetStringTableEntry(language, entry.label_id)),
            rex::string::to_utf16(db.GetStringTableEntry(language, entry.description_id)),
            rex::string::to_utf16(db.GetStringTableEntry(language, entry.unachieved_id)),
            entry.image_id,
            entry.gamerscore,
            {0, 0},
            entry.flags};
        fill_unlock(item, entry.id, ks);
        e->AppendItem(item);
      }
    }
  }

  *handle_ptr = e->handle();
  return X_ERROR_SUCCESS;
}

u32 XamParseGamerTileKey_entry(mapped_u32 key_ptr, mapped_u32 out1_ptr, mapped_u32 out2_ptr,
                               mapped_u32 out3_ptr) {
  // (Audit A3, ronda 6, R6-06.) NULL out params used to write the
  // placeholder key parts to guest address 0.
  if (!out1_ptr || !out2_ptr || !out3_ptr) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, ronda 10, A3-R10-12.) All three out-params are
  // written below with only the NULL checks above: validate all
  // three 4-byte ranges first.
  if (!GuestRangeWritable(out1_ptr.guest_address(), sizeof(uint32_t)) ||
      !GuestRangeWritable(out2_ptr.guest_address(), sizeof(uint32_t)) ||
      !GuestRangeWritable(out3_ptr.guest_address(), sizeof(uint32_t))) {
    return X_ERROR_INVALID_PARAMETER;
  }

  *out1_ptr = 0xC0DE0001;
  *out2_ptr = 0xC0DE0002;
  *out3_ptr = 0xC0DE0003;
  return X_ERROR_SUCCESS;
}

u32 XamReadTileToTexture_entry(u32 unknown, u32 title_id, u64 tile_id, u32 user_index,
                               mapped_void buffer_ptr, u32 stride, u32 height, u32 overlapped_ptr) {
  // TODO(gibbed): unknown=0,2,3,9
  if (!tile_id) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, ronda 4, A3-R4-08.) stride * height are both guest
  // controlled: the old code memsets that many bytes from an unchecked
  // guest pointer, past the end of the mapping. Validate the whole
  // destination range before touching it.
  if (!buffer_ptr) {
    return X_ERROR_INVALID_PARAMETER;
  }
  size_t size = size_t(stride) * size_t(height);
  if (!GuestRangeWritable(buffer_ptr.guest_address(), size)) {
    return X_ERROR_INVALID_PARAMETER;
  }
  std::memset(buffer_ptr, 0xFF, size);

  if (overlapped_ptr) {
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped_ptr, X_ERROR_SUCCESS);
    return X_ERROR_IO_PENDING;
  }
  return X_ERROR_SUCCESS;
}

u32 XamWriteGamerTile_entry(u32 arg1, u32 arg2, u32 arg3, u32 arg4, u32 arg5, u32 overlapped_ptr) {
  if (overlapped_ptr) {
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped_ptr, X_ERROR_SUCCESS);
    return X_ERROR_IO_PENDING;
  }
  return X_ERROR_SUCCESS;
}

u32 XamSessionCreateHandle_entry(mapped_u32 handle_ptr) {
  // (Audit A3, ronda 6, R6-06.) A NULL handle_ptr used to write the
  // placeholder handle to guest address 0.
  if (!handle_ptr) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, ronda 10, A3-R10-12.) *handle_ptr is written below
  // with only the NULL check above: validate the 4-byte range first.
  if (!GuestRangeWritable(handle_ptr.guest_address(), sizeof(uint32_t))) {
    return X_ERROR_INVALID_PARAMETER;
  }

  *handle_ptr = 0xCAFEDEAD;
  return X_ERROR_SUCCESS;
}

u32 XamSessionRefObjByHandle_entry(u32 handle, mapped_u32 obj_ptr) {
  // (Audit A3, ronda 6, R6-06.) A NULL obj_ptr used to write the
  // placeholder object pointer to guest address 0.
  if (!obj_ptr) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, ronda 10, A3-R10-12.) *obj_ptr is written below
  // with only the NULL check above: validate the 4-byte range first.
  if (!GuestRangeWritable(obj_ptr.guest_address(), sizeof(uint32_t))) {
    return X_ERROR_INVALID_PARAMETER;
  }

  assert_true(handle == 0xCAFEDEAD);
  // TODO(PermaNull): Implement this properly,
  // For the time being returning 0xDEADF00D will prevent crashing.
  *obj_ptr = 0xDEADF00D;
  return X_ERROR_SUCCESS;
}

}  // namespace xam
}  // namespace kernel
}  // namespace rex

REX_EXPORT(__imp__XamUserGetXUID, rex::kernel::xam::XamUserGetXUID_entry)
REX_EXPORT(__imp__XamUserGetSigninState, rex::kernel::xam::XamUserGetSigninState_entry)
REX_EXPORT(__imp__XamUserGetSigninInfo, rex::kernel::xam::XamUserGetSigninInfo_entry)
REX_EXPORT(__imp__XamUserGetName, rex::kernel::xam::XamUserGetName_entry)
REX_EXPORT(__imp__XamUserGetGamerTag, rex::kernel::xam::XamUserGetGamerTag_entry)
REX_EXPORT(__imp__XamUserReadProfileSettings, rex::kernel::xam::XamUserReadProfileSettings_entry)
REX_EXPORT(__imp__XamUserReadProfileSettingsEx,
           rex::kernel::xam::XamUserReadProfileSettingsEx_entry)
REX_EXPORT(__imp__XamUserWriteProfileSettings, rex::kernel::xam::XamUserWriteProfileSettings_entry)
REX_EXPORT(__imp__XamUserCheckPrivilege, rex::kernel::xam::XamUserCheckPrivilege_entry)
REX_EXPORT(__imp__XamUserContentRestrictionGetFlags,
           rex::kernel::xam::XamUserContentRestrictionGetFlags_entry)
REX_EXPORT(__imp__XamUserContentRestrictionGetRating,
           rex::kernel::xam::XamUserContentRestrictionGetRating_entry)
REX_EXPORT(__imp__XamUserContentRestrictionCheckAccess,
           rex::kernel::xam::XamUserContentRestrictionCheckAccess_entry)
REX_EXPORT(__imp__XamUserIsOnlineEnabled, rex::kernel::xam::XamUserIsOnlineEnabled_entry)
REX_EXPORT(__imp__XamUserGetMembershipTier, rex::kernel::xam::XamUserGetMembershipTier_entry)
REX_EXPORT(__imp__XamUserAreUsersFriends, rex::kernel::xam::XamUserAreUsersFriends_entry)
REX_EXPORT(__imp__XamShowSigninUI, rex::kernel::xam::XamShowSigninUI_entry)
REX_EXPORT(__imp__XamUserCreateAchievementEnumerator,
           rex::kernel::xam::XamUserCreateAchievementEnumerator_entry)
REX_EXPORT(__imp__XamParseGamerTileKey, rex::kernel::xam::XamParseGamerTileKey_entry)
REX_EXPORT(__imp__XamReadTileToTexture, rex::kernel::xam::XamReadTileToTexture_entry)
REX_EXPORT(__imp__XamWriteGamerTile, rex::kernel::xam::XamWriteGamerTile_entry)
REX_EXPORT(__imp__XamSessionCreateHandle, rex::kernel::xam::XamSessionCreateHandle_entry)
REX_EXPORT(__imp__XamSessionRefObjByHandle, rex::kernel::xam::XamSessionRefObjByHandle_entry)

REX_EXPORT_STUB(__imp__XamUserAddRecentPlayer);
REX_EXPORT_STUB(__imp__XamUserAllowedToPostToSocialNetwork);
REX_EXPORT_STUB(__imp__XamUserCreateAvatarAssetEnumerator);
REX_EXPORT_STUB(__imp__XamUserCreatePlayerEnumerator);
REX_EXPORT_STUB(__imp__XamUserCreateStatsEnumerator);
REX_EXPORT_STUB(__imp__XamUserCreateTitlesPlayedEnumerator);
REX_EXPORT_STUB(__imp__XamUserFlushLogonQueue);
REX_EXPORT_STUB(__imp__XamUserGetAge);
REX_EXPORT_STUB(__imp__XamUserGetAgeGroup);
REX_EXPORT_STUB(__imp__XamUserGetCachedUserFlags);
REX_EXPORT_STUB(__imp__XamUserGetDeviceId);
REX_EXPORT_STUB(__imp__XamUserGetIndexFromXUID);
REX_EXPORT_STUB(__imp__XamUserGetMembershipTierFromXUID);
REX_EXPORT_STUB(__imp__XamUserGetOnlineCountryFromXUID);
REX_EXPORT_STUB(__imp__XamUserGetOnlineLanguageFromXUID);
REX_EXPORT_STUB(__imp__XamUserGetOnlineXUIDFromOfflineXUID);
REX_EXPORT_STUB(__imp__XamUserGetReportingInfo);
REX_EXPORT_STUB(__imp__XamUserGetRequestedUserIndexMask);
REX_EXPORT_STUB(__imp__XamUserGetSubscriptionType);
REX_EXPORT_STUB(__imp__XamUserGetUserFlags);
REX_EXPORT_STUB(__imp__XamUserGetUserFlagsFromXUID);
REX_EXPORT_STUB(__imp__XamUserGetUserIndexMask);
REX_EXPORT_STUB(__imp__XamUserGetUserTenure);
REX_EXPORT_STUB(__imp__XamUserGetUsersMissingAvatars);
REX_EXPORT_STUB(__imp__XamUserGetXUIDForTFA);
REX_EXPORT_STUB(__imp__XamUserInvalidateProfileSetting);
REX_EXPORT_STUB_RETURN(__imp__XamUserIsGuest, 0);
REX_EXPORT_STUB_RETURN(__imp__XamUserIsLogonPreviewModeEnabled, 0);
REX_EXPORT_STUB_RETURN(__imp__XamUserIsParentalControlled, 0);
REX_EXPORT_STUB_RETURN(__imp__XamUserIsPartial, 0);
REX_EXPORT_STUB_RETURN(__imp__XamUserIsPartialProfile, 0);
REX_EXPORT_STUB_RETURN(__imp__XamUserIsUnsafeProgrammingAllowed, 0);
REX_EXPORT_STUB(__imp__XamUserLockLogonPreviewMode);
REX_EXPORT_STUB(__imp__XamUserLogon);
REX_EXPORT_STUB(__imp__XamUserLogonEx);
REX_EXPORT_STUB(__imp__XamUserLookupDevice);
REX_EXPORT_STUB(__imp__XamUserNuiBind);
REX_EXPORT_STUB(__imp__XamUserNuiEnableBiometric);
REX_EXPORT_STUB(__imp__XamUserNuiGetEnrollmentIndex);
REX_EXPORT_STUB(__imp__XamUserNuiGetUserIndex);
REX_EXPORT_STUB(__imp__XamUserNuiGetUserIndexForBind);
REX_EXPORT_STUB(__imp__XamUserNuiGetUserIndexForSignin);
REX_EXPORT_STUB(__imp__XamUserNuiIsBiometricEnabled);
REX_EXPORT_STUB(__imp__XamUserNuiUnbind);
REX_EXPORT_STUB(__imp__XamUserOverrideBindingCallbacks);
REX_EXPORT_STUB(__imp__XamUserOverrideDeviceBindings);
REX_EXPORT_STUB(__imp__XamUserOverrideGlobalState);
REX_EXPORT_STUB(__imp__XamUserOverrideUserInfo);
REX_EXPORT_STUB(__imp__XamUserPrefetchProfileSettings);
REX_EXPORT_STUB(__imp__XamUserProfileSync);
REX_EXPORT_STUB(__imp__XamUserReadUserPreference);
REX_EXPORT_STUB(__imp__XamUserResetSubscriptionType);
REX_EXPORT_STUB(__imp__XamUserUnlockLogonPreviewMode);
REX_EXPORT_STUB(__imp__XamUserUpdateRecentPlayer);
REX_EXPORT_STUB(__imp__XamUserValidateAvatarManifest);
REX_EXPORT_STUB(__imp__XamUserWriteUserPreference);
REX_EXPORT_STUB(__imp__XamVerifyPasscode);
