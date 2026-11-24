/**
 * @file        kernel/xam/xam_debug.cpp
 * @brief       XAM debug export implementations
 *
 * @copyright   Copyright 2022 Ben Vanik. All rights reserved. (Xenia Project)
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <string>

#include <rex/logging.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/system/kernel_state.h>

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

// (Hunt v1.4.6, ronda 10, A3-R10-03.) Bounded guest C-string read:
// MappedPtr<char>::value() builds a string_view straight off the
// host pointer -- a strlen to NUL with no cap -- so a guest debug
// string with no NUL in its page ran the host scan into unmapped
// memory. Read page by page (each chunk validated readable first,
// like the R6-05 ReadGuestU16String reader in xam_ui.cpp), stop at
// the first NUL, truncate at 4096 chars if there is none. Returns
// false on an invalid range.
constexpr size_t kMaxGuestPathChars = 4096;

static bool ReadGuestCString(uint32_t guest_address, std::string* out) {
  out->clear();
  size_t remaining = kMaxGuestPathChars;
  uint32_t address = guest_address;
  while (remaining > 0) {
    size_t page_bytes = 0x1000 - (address & 0xFFF);
    size_t chunk = remaining < page_bytes ? remaining : page_bytes;
    if (!GuestRangeReadable(address, chunk)) {
      return false;
    }
    const char* host_ptr = REX_KERNEL_MEMORY()->TranslateVirtual<const char*>(address);
    for (size_t i = 0; i < chunk; ++i) {
      char c = host_ptr[i];
      if (!c) {
        return true;
      }
      out->push_back(c);
    }
    address += static_cast<uint32_t>(chunk);
    remaining -= chunk;
  }
  return true;
}

// (Hunt v1.4.6, ronda 10, A3-R10-03.) Bounded guest UTF-16 read:
// MappedPtr<char16_t>::value() is a NUL scan with no cap, and the
// raw view is NOT byte-swapped (guest UTF-16 is big-endian -- the
// old code below compared the swapped units against 0x80, so ASCII
// debug strings logged as '?'). Same 4096 code-unit cap and
// page-at-a-time validation as the R6-05 reader in xam_ui.cpp,
// copied here; returns false on an invalid range, and on success
// *out holds the string in host byte order, truncated at the cap.
constexpr size_t kMaxGuestUiStringCodeUnits = 4096;

static bool ReadGuestU16String(uint32_t guest_address, std::u16string* out) {
  out->clear();
  if ((guest_address & 1) != 0) {
    return false;
  }
  size_t remaining = kMaxGuestUiStringCodeUnits;
  uint32_t address = guest_address;
  while (remaining > 0) {
    size_t page_units = (0x1000 - (address & 0xFFF)) / sizeof(uint16_t);
    size_t chunk_units = remaining < page_units ? remaining : page_units;
    if (!GuestRangeReadable(address, chunk_units * sizeof(uint16_t))) {
      return false;
    }
    const uint16_t* host_ptr =
        REX_KERNEL_MEMORY()->TranslateVirtual<const uint16_t*>(address);
    for (size_t i = 0; i < chunk_units; ++i) {
      uint16_t c = rex::memory::load_and_swap<uint16_t>(host_ptr + i);
      if (!c) {
        return true;
      }
      out->push_back(static_cast<wchar_t>(c));
    }
    address += static_cast<uint32_t>(chunk_units * sizeof(uint16_t));
    remaining -= chunk_units;
  }
  return true;
}

// OutputDebugStringA - ANSI debug string output
void OutputDebugStringA_entry(mapped_string string) {
  if (string) {
    // (Hunt v1.4.6, ronda 10, A3-R10-03.) Bounded read: the old
    // string.value() scanned for NUL with no cap.
    std::string bounded;
    if (!ReadGuestCString(string.guest_address(), &bounded)) {
      return;
    }
    REXKRNL_INFO("OutputDebugStringA: {}", bounded);
  }
}

// OutputDebugStringW - Unicode debug string output
void OutputDebugStringW_entry(mapped_wstring string) {
  if (string) {
    // (Hunt v1.4.6, ronda 10, A3-R10-03.) Bounded read, as above
    // (and now byte-swapped, so ASCII actually logs as ASCII).
    std::u16string bounded;
    if (!ReadGuestU16String(string.guest_address(), &bounded)) {
      return;
    }
    // Convert char16_t to UTF-8 for logging (simple ASCII fallback)
    std::u16string_view sv = bounded;
    std::string utf8;
    utf8.reserve(sv.size());
    for (char16_t c : sv) {
      if (c < 0x80) {
        utf8.push_back(static_cast<char>(c));
      } else {
        utf8.push_back('?');  // Non-ASCII fallback
      }
    }
    REXKRNL_INFO("OutputDebugStringW: {}", utf8);
  }
}

// RtlOutputDebugString - Same as OutputDebugStringA
void RtlOutputDebugString_entry(mapped_string string) {
  if (string) {
    // (Hunt v1.4.6, ronda 10, A3-R10-03.) Bounded read, as
    // OutputDebugStringA above.
    std::string bounded;
    if (!ReadGuestCString(string.guest_address(), &bounded)) {
      return;
    }
    REXKRNL_INFO("RtlOutputDebugString: {}", bounded);
  }
}

// RtlDebugTrace - Debug trace output
void RtlDebugTrace_entry(mapped_string string) {
  if (string) {
    // (Hunt v1.4.6, ronda 10, A3-R10-03.) Bounded read, as
    // OutputDebugStringA above.
    std::string bounded;
    if (!ReadGuestCString(string.guest_address(), &bounded)) {
      return;
    }
    REXKRNL_INFO("RtlDebugTrace: {}", bounded);
  }
}

}  // namespace xam
}  // namespace kernel
}  // namespace rex

// Hook registrations
REX_EXPORT(__imp__OutputDebugStringA, rex::kernel::xam::OutputDebugStringA_entry)
REX_EXPORT(__imp__OutputDebugStringW, rex::kernel::xam::OutputDebugStringW_entry)
REX_EXPORT(__imp__RtlOutputDebugString, rex::kernel::xam::RtlOutputDebugString_entry)
REX_EXPORT(__imp__RtlDebugTrace, rex::kernel::xam::RtlDebugTrace_entry)
