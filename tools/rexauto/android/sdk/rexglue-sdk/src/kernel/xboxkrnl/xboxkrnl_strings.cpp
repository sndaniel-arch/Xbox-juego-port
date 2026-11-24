/**
 * @file        kernel/xboxkrnl/xboxkrnl_strings.cpp
 * @brief       Xbox kernel string function exports
 *
 * @copyright   Copyright 2022 Ben Vanik. All rights reserved. (Xenia Project)
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#pragma GCC diagnostic ignored "-Wunused-parameter"

#include <algorithm>
#include <cctype>
#include <cstring>

#include <rex/logging.h>
#include <rex/memory/utils.h>
#include <rex/hook.h>
#include <rex/system/flags.h>
#include <rex/system/format.h>
#include <rex/system/kernel_state.h>

using namespace rex::system::format;
using rex::memory::GuestPtr;

// (Hunt v1.4.6, ronda 12, A3-R12-24.) This file had no range helper:
// every hook below read its format string through GuestPtr -- pure
// base + guest_address arithmetic with no validation -- and
// StringFormatData::get() scans it to NUL with no cap, so a wild
// format pointer SIGSEGVd the host. Same heap validation as A3-R4-07
// (xam_app.cpp): reject a range that wraps past 4 GiB, starts or
// ends outside any heap, or spans heaps of different kinds (or two
// physical heaps); inside a single heap require the pages to be
// accessible; across a heap boundary validate both ends (A3-R8-13);
// a range spanning more than two heaps is rejected outright (A3-R9-10).
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

// (Hunt v1.4.6, ronda 12, A3-R12-24.) Bounded format-string
// pre-scan: format_core re-reads the format from the raw GuestPtr,
// so unlike the R10-03 ReadGuestCString pattern (which returns the
// truncated copy and is safe to truncate), a format with no NUL
// within the cap MUST fail here -- otherwise format_core would scan
// past the validated pages. Read page by page (each chunk validated
// readable first), stop at the first NUL; false on an invalid range
// or on no NUL within 4096 units. A successful pre-scan proves
// every byte format_core can read (up to that NUL) lies in pages
// validated readable.
constexpr size_t kMaxGuestFormatChars = 4096;

static bool ReadGuestFormatString(uint32_t guest_address) {
  size_t remaining = kMaxGuestFormatChars;
  uint32_t address = guest_address;
  while (remaining > 0) {
    size_t page_bytes = 0x1000 - (address & 0xFFF);
    size_t chunk = remaining < page_bytes ? remaining : page_bytes;
    if (!GuestRangeReadable(address, chunk)) {
      return false;
    }
    const char* host_ptr = REX_KERNEL_MEMORY()->TranslateVirtual<const char*>(address);
    for (size_t i = 0; i < chunk; ++i) {
      if (!host_ptr[i]) {
        return true;
      }
    }
    address += static_cast<uint32_t>(chunk);
    remaining -= chunk;
  }
  return false;
}

static bool ReadGuestFormatWString(uint32_t guest_address) {
  size_t remaining = kMaxGuestFormatChars;
  uint32_t address = guest_address;
  while (remaining > 0) {
    size_t page_units = (0x1000 - (address & 0xFFF)) / sizeof(char16_t);
    size_t chunk = remaining < page_units ? remaining : page_units;
    if (!chunk || !GuestRangeReadable(address, chunk * sizeof(char16_t))) {
      return false;
    }
    const char16_t* host_ptr = REX_KERNEL_MEMORY()->TranslateVirtual<const char16_t*>(address);
    for (size_t i = 0; i < chunk; ++i) {
      if (!host_ptr[i]) {
        return true;
      }
    }
    address += static_cast<uint32_t>(chunk * sizeof(char16_t));
    remaining -= chunk;
  }
  return false;
}

//=============================================================================
// DbgPrint / XamDbgPrint
//=============================================================================

REX_HOOK_RAW(__imp__DbgPrint) {
  uint32_t format_ptr = ctx.r3.u32;
  if (!format_ptr) {
    ctx.r3.u64 = 0;
    return;
  }
  // (Hunt v1.4.6, ronda 12, A3-R12-24.) The format string was scanned
  // to NUL with no validation (GuestPtr is bare arithmetic): a wild
  // pointer SIGSEGVd the host. Pre-scan it bounded first.
  if (!ReadGuestFormatString(format_ptr)) {
    ctx.r3.u64 = 0;
    return;
  }
  auto format = GuestPtr<const u8*>(base, format_ptr);

  StackArgList args(ctx, base, 1);
  StringFormatData data(format);

  int32_t count = format_core(base, data, args, false);
  if (count > 0) {
    auto str = data.str();
    // Trim trailing whitespace
    while (!str.empty() && std::isspace(static_cast<unsigned char>(str.back()))) {
      str.pop_back();
    }
    REXKRNL_INFO("DbgPrint: {}", str);
  }

  ctx.r3.u64 = 0;  // NTSTATUS success
}

REX_HOOK_RAW(__imp__XamDbgPrint) {
  uint32_t format_ptr = ctx.r3.u32;
  if (!format_ptr) {
    ctx.r3.u64 = 0;
    return;
  }
  // (Hunt v1.4.6, ronda 12, A3-R12-24.) Same unbounded format scan
  // as DbgPrint above: pre-scan it bounded first.
  if (!ReadGuestFormatString(format_ptr)) {
    ctx.r3.u64 = 0;
    return;
  }
  auto format = GuestPtr<const u8*>(base, format_ptr);

  StackArgList args(ctx, base, 1);
  StringFormatData data(format);

  int32_t count = format_core(base, data, args, false);
  if (count > 0) {
    auto str = data.str();
    while (!str.empty() && std::isspace(static_cast<unsigned char>(str.back()))) {
      str.pop_back();
    }
    REXKRNL_INFO("XamDbgPrint: {}", str);
  }

  ctx.r3.u64 = 0;
}

//=============================================================================
// sprintf / _snprintf (narrow, stack varargs)
//=============================================================================

REX_HOOK_RAW(__imp__sprintf) {
  uint32_t buffer_ptr = ctx.r3.u32;
  uint32_t format_ptr = ctx.r4.u32;

  if (buffer_ptr == 0 || format_ptr == 0) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  // (Hunt v1.4.6, ronda 12, A3-R12-24.) The format string was scanned
  // to NUL with no validation (GuestPtr is bare arithmetic): a wild
  // pointer SIGSEGVd the host. Pre-scan it bounded first.
  if (!ReadGuestFormatString(format_ptr)) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  auto buffer = GuestPtr<u8*>(base, buffer_ptr);
  auto format = GuestPtr<const u8*>(base, format_ptr);

  StackArgList args(ctx, base, 2);
  StringFormatData data(format);

  int32_t count = format_core(base, data, args, false);
  // (Hunt v1.4.6, ronda 12, A3-R12-25.) The formatted result (count
  // bytes plus NUL, or 1 byte on a format error) was memcpy'd into
  // the guest buffer with no validation: a wild buffer pointer
  // SIGSEGVd the host. Validate the bytes actually written first.
  uint64_t write_size = count <= 0 ? 1 : uint64_t(count) + 1;
  if (!GuestRangeWritable(buffer_ptr, static_cast<size_t>(write_size))) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }
  if (count <= 0) {
    buffer[0] = '\0';
  } else {
    std::memcpy(buffer, data.str().c_str(), count);
    buffer[count] = '\0';
  }
  ctx.r3.u64 = count;
}

REX_HOOK_RAW(__imp___snprintf) {
  uint32_t buffer_ptr = ctx.r3.u32;
  int32_t buffer_count = static_cast<int32_t>(ctx.r4.u32);
  uint32_t format_ptr = ctx.r5.u32;

  if (buffer_ptr == 0 || buffer_count <= 0 || format_ptr == 0) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  // (Hunt v1.4.6, ronda 12, A3-R12-24.) Bounded format pre-scan, as
  // in sprintf above.
  if (!ReadGuestFormatString(format_ptr)) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }
  // (Hunt v1.4.6, ronda 12, A3-R12-25.) Every branch below writes at
  // most buffer_count bytes (count bytes, count + NUL, or buffer_count
  // on truncation): validate the whole buffer first.
  if (!GuestRangeWritable(buffer_ptr, static_cast<size_t>(buffer_count))) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  auto buffer = GuestPtr<u8*>(base, buffer_ptr);
  auto format = GuestPtr<const u8*>(base, format_ptr);

  StackArgList args(ctx, base, 3);
  StringFormatData data(format);

  int32_t count = format_core(base, data, args, false);
  if (count < 0) {
    if (buffer_count > 0) {
      buffer[0] = '\0';
    }
  } else if (count <= buffer_count) {
    std::memcpy(buffer, data.str().c_str(), count);
    if (count < buffer_count) {
      buffer[count] = '\0';
    }
  } else {
    std::memcpy(buffer, data.str().c_str(), buffer_count);
    count = -1;
  }
  ctx.r3.u64 = count;
}

//=============================================================================
// swprintf / _snwprintf (wide, stack varargs)
//=============================================================================

REX_HOOK_RAW(__imp__swprintf) {
  uint32_t buffer_ptr = ctx.r3.u32;
  uint32_t format_ptr = ctx.r4.u32;

  if (buffer_ptr == 0 || format_ptr == 0) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  // (Hunt v1.4.6, ronda 12, A3-R12-24.) Bounded wide-format
  // pre-scan, as in sprintf above (wide variant).
  if (!ReadGuestFormatWString(format_ptr)) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  auto buffer = GuestPtr<u16*>(base, buffer_ptr);
  auto format = GuestPtr<const u16*>(base, format_ptr);

  StackArgList args(ctx, base, 2);
  WideStringFormatData data(format);

  int32_t count = format_core(base, data, args, true);
  // (Hunt v1.4.6, ronda 12, A3-R12-25.) The formatted result (count
  // u16 units plus NUL, or 1 unit on a format error) was written into
  // the guest buffer with no validation. Validate first.
  uint64_t write_size = count <= 0 ? 1 : uint64_t(count) + 1;
  if (!GuestRangeWritable(buffer_ptr, static_cast<size_t>(write_size * sizeof(uint16_t)))) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }
  if (count <= 0) {
    buffer[0] = '\0';
  } else {
    rex::memory::copy_and_swap(buffer, reinterpret_cast<const uint16_t*>(data.wstr().c_str()),
                               count);
    buffer[count] = '\0';
  }
  ctx.r3.u64 = count;
}

REX_HOOK_RAW(__imp___snwprintf) {
  uint32_t buffer_ptr = ctx.r3.u32;
  int32_t buffer_count = static_cast<int32_t>(ctx.r4.u32);
  uint32_t format_ptr = ctx.r5.u32;

  if (buffer_ptr == 0 || buffer_count <= 0 || format_ptr == 0) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  // (Hunt v1.4.6, ronda 12, A3-R12-24.) Bounded wide-format
  // pre-scan, as in swprintf above.
  if (!ReadGuestFormatWString(format_ptr)) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }
  // (Hunt v1.4.6, ronda 12, A3-R12-25.) Every branch below writes at
  // most buffer_count u16 units: validate the whole buffer first.
  if (!GuestRangeWritable(buffer_ptr,
                         static_cast<size_t>(buffer_count) * sizeof(uint16_t))) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  auto buffer = GuestPtr<u16*>(base, buffer_ptr);
  auto format = GuestPtr<const u16*>(base, format_ptr);

  StackArgList args(ctx, base, 3);
  WideStringFormatData data(format);

  int32_t count = format_core(base, data, args, true);
  if (count < 0) {
    if (buffer_count > 0) {
      buffer[0] = '\0';
    }
  } else if (count <= buffer_count) {
    rex::memory::copy_and_swap(buffer, reinterpret_cast<const uint16_t*>(data.wstr().c_str()),
                               count);
    if (count < buffer_count) {
      buffer[count] = '\0';
    }
  } else {
    rex::memory::copy_and_swap(buffer, reinterpret_cast<const uint16_t*>(data.wstr().c_str()),
                               buffer_count);
    count = -1;
  }
  ctx.r3.u64 = count;
}

//=============================================================================
// vsprintf / _vsnprintf (narrow, va_list from memory)
//=============================================================================

REX_HOOK_RAW(__imp__vsprintf) {
  uint32_t buffer_ptr = ctx.r3.u32;
  uint32_t format_ptr = ctx.r4.u32;
  uint32_t arg_ptr = ctx.r5.u32;

  if (buffer_ptr == 0 || format_ptr == 0) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  // (Hunt v1.4.6, ronda 12, A3-R12-24.) Bounded format pre-scan, as
  // in sprintf above. (The va_list itself is A3-R12-26: ArrayArgList
  // reads it through GuestPtr with no validation -- no bounded fix
  // exists without threading Memory through format_core.)
  if (!ReadGuestFormatString(format_ptr)) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  auto buffer = GuestPtr<u8*>(base, buffer_ptr);
  auto format = GuestPtr<const u8*>(base, format_ptr);

  ArrayArgList args(base, arg_ptr);
  StringFormatData data(format);

  int32_t count = format_core(base, data, args, false);
  // (Hunt v1.4.6, ronda 12, A3-R12-25.) Output-buffer validation,
  // as in sprintf above.
  uint64_t write_size = count <= 0 ? 1 : uint64_t(count) + 1;
  if (!GuestRangeWritable(buffer_ptr, static_cast<size_t>(write_size))) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }
  if (count <= 0) {
    buffer[0] = '\0';
  } else {
    std::memcpy(buffer, data.str().c_str(), count);
    buffer[count] = '\0';
  }
  ctx.r3.u64 = count;
}

REX_HOOK_RAW(__imp___vsnprintf) {
  uint32_t buffer_ptr = ctx.r3.u32;
  int32_t buffer_count = static_cast<int32_t>(ctx.r4.u32);
  uint32_t format_ptr = ctx.r5.u32;
  uint32_t arg_ptr = ctx.r6.u32;

  if (buffer_ptr == 0 || buffer_count <= 0 || format_ptr == 0) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  // (Hunt v1.4.6, ronda 12, A3-R12-24.) Bounded format pre-scan, as
  // in sprintf above. (The va_list itself is A3-R12-26, see
  // vsprintf.)
  if (!ReadGuestFormatString(format_ptr)) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }
  // (Hunt v1.4.6, ronda 12, A3-R12-25.) Every branch below writes at
  // most buffer_count bytes: validate the whole buffer first.
  if (!GuestRangeWritable(buffer_ptr, static_cast<size_t>(buffer_count))) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  auto buffer = GuestPtr<u8*>(base, buffer_ptr);
  auto format = GuestPtr<const u8*>(base, format_ptr);

  ArrayArgList args(base, arg_ptr);
  StringFormatData data(format);

  int32_t count = format_core(base, data, args, false);
  if (count < 0) {
    if (buffer_count > 0) {
      buffer[0] = '\0';
    }
  } else if (count <= buffer_count) {
    std::memcpy(buffer, data.str().c_str(), count);
    if (count < buffer_count) {
      buffer[count] = '\0';
    }
  } else {
    std::memcpy(buffer, data.str().c_str(), buffer_count);
  }
  ctx.r3.u64 = count;
}

//=============================================================================
// vswprintf / _vsnwprintf / _vscwprintf (wide, va_list from memory)
//=============================================================================

REX_HOOK_RAW(__imp__vswprintf) {
  uint32_t buffer_ptr = ctx.r3.u32;
  uint32_t format_ptr = ctx.r4.u32;
  uint32_t arg_ptr = ctx.r5.u32;

  if (buffer_ptr == 0 || format_ptr == 0) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  // (Hunt v1.4.6, ronda 12, A3-R12-24.) Bounded wide-format
  // pre-scan, as in swprintf above. (The va_list itself is A3-R12-26,
  // see vsprintf.)
  if (!ReadGuestFormatWString(format_ptr)) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  auto buffer = GuestPtr<u16*>(base, buffer_ptr);
  auto format = GuestPtr<const u16*>(base, format_ptr);

  ArrayArgList args(base, arg_ptr);
  WideStringFormatData data(format);

  int32_t count = format_core(base, data, args, true);
  // (Hunt v1.4.6, ronda 12, A3-R12-25.) Output-buffer validation,
  // as in swprintf above.
  uint64_t write_size = count <= 0 ? 1 : uint64_t(count) + 1;
  if (!GuestRangeWritable(buffer_ptr, static_cast<size_t>(write_size * sizeof(uint16_t)))) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }
  if (count <= 0) {
    buffer[0] = '\0';
  } else {
    rex::memory::copy_and_swap(buffer, reinterpret_cast<const uint16_t*>(data.wstr().c_str()),
                               count);
    buffer[count] = '\0';
  }
  ctx.r3.u64 = count;
}

REX_HOOK_RAW(__imp___vsnwprintf) {
  uint32_t buffer_ptr = ctx.r3.u32;
  int32_t buffer_count = static_cast<int32_t>(ctx.r4.u32);
  uint32_t format_ptr = ctx.r5.u32;
  uint32_t arg_ptr = ctx.r6.u32;

  if (buffer_ptr == 0 || buffer_count <= 0 || format_ptr == 0) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  // (Hunt v1.4.6, ronda 12, A3-R12-24.) Bounded wide-format
  // pre-scan, as in swprintf above. (The va_list itself is A3-R12-26,
  // see vsprintf.)
  if (!ReadGuestFormatWString(format_ptr)) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }
  // (Hunt v1.4.6, ronda 12, A3-R12-25.) Every branch below writes at
  // most buffer_count u16 units: validate the whole buffer first.
  if (!GuestRangeWritable(buffer_ptr,
                         static_cast<size_t>(buffer_count) * sizeof(uint16_t))) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  auto buffer = GuestPtr<u16*>(base, buffer_ptr);
  auto format = GuestPtr<const u16*>(base, format_ptr);

  ArrayArgList args(base, arg_ptr);
  WideStringFormatData data(format);

  int32_t count = format_core(base, data, args, true);
  if (count < 0) {
    if (buffer_count > 0) {
      buffer[0] = '\0';
    }
  } else if (count <= buffer_count) {
    rex::memory::copy_and_swap(buffer, reinterpret_cast<const uint16_t*>(data.wstr().c_str()),
                               count);
    if (count < buffer_count) {
      buffer[count] = '\0';
    }
  } else {
    rex::memory::copy_and_swap(buffer, reinterpret_cast<const uint16_t*>(data.wstr().c_str()),
                               buffer_count);
  }
  ctx.r3.u64 = count;
}

REX_HOOK_RAW(__imp___vscwprintf) {
  uint32_t format_ptr = ctx.r3.u32;
  uint32_t arg_ptr = ctx.r4.u32;

  if (format_ptr == 0) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  // (Hunt v1.4.6, ronda 12, A3-R12-24.) Bounded wide-format
  // pre-scan, as in swprintf above. (The va_list itself is A3-R12-26,
  // see vsprintf.)
  if (!ReadGuestFormatWString(format_ptr)) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  auto format = GuestPtr<const u16*>(base, format_ptr);

  ArrayArgList args(base, arg_ptr);
  WideCountFormatData data(format);

  int32_t count = format_core(base, data, args, true);
  assert_true(count < 0 || data.count() == count);
  ctx.r3.u64 = count;
}

//=============================================================================
// Export stubs
//=============================================================================

REX_EXPORT_STUB(__imp___scprintf);
REX_EXPORT_STUB(__imp___scwprintf);
REX_EXPORT_STUB(__imp___vscprintf);
