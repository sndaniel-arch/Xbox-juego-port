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

#include <algorithm>
#include <string>

#include <rex/chrono/chrono_steady_cast.h>
#include <rex/kernel/xboxkrnl/private.h>
#include <rex/kernel/xboxkrnl/rtl.h>
#include <rex/kernel/xboxkrnl/threading.h>
#include <rex/logging.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/string.h>
#include <rex/system/kernel_state.h>
#include <rex/system/user_module.h>
#include <rex/system/util/string_utils.h>
#include <rex/system/xevent.h>
#include <rex/system/xthread.h>
#include <rex/thread.h>
#include <rex/thread/atomic.h>

namespace rex::kernel::xboxkrnl {
using namespace rex::system;

// (Hunt v1.4.6, ronda 12, A3-R12-06.) This file had no range helper:
// every entry below dereferenced its guest pointers with at most a
// NULL check, and TranslateVirtual never validates or returns null,
// so a wild pointer SIGSEGVd the host. Same heap validation as
// A3-R4-07 (xam_app.cpp): reject a range that wraps past 4 GiB,
// starts or ends outside any heap, or spans heaps of different kinds
// (or two physical heaps); inside a single heap require the pages to
// be accessible; across a heap boundary validate both ends (A3-R8-13);
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

// (Hunt v1.4.6, ronda 12, A3-R12-06.) Bounded guest string reads,
// the R10-03 pattern from crt/file.cpp: MappedPtr<char>::value() /
// MappedPtr<char16_t>::value() build a string_view straight off the
// host pointer -- a strlen to NUL with no cap -- so a guest string
// with no NUL in its page ran the host scan into unmapped memory.
// Read page by page (each chunk validated readable first), stop at
// the first NUL, truncate at 4096 units if there is none. Returns
// false on an invalid range. Callers pass a null guest address as
// "empty" (the MappedPtr null convention); that case is handled by
// the caller, not here.
constexpr size_t kMaxGuestStringChars = 4096;

static bool ReadGuestCString(uint32_t guest_address, std::string* out) {
  out->clear();
  size_t remaining = kMaxGuestStringChars;
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

static bool ReadGuestWString(uint32_t guest_address, std::u16string* out) {
  out->clear();
  size_t remaining = kMaxGuestStringChars;
  uint32_t address = guest_address;
  while (remaining > 0) {
    size_t page_units = (0x1000 - (address & 0xFFF)) / sizeof(char16_t);
    size_t chunk = remaining < page_units ? remaining : page_units;
    if (!chunk || !GuestRangeReadable(address, chunk * sizeof(char16_t))) {
      return false;
    }
    const char16_t* host_ptr = REX_KERNEL_MEMORY()->TranslateVirtual<const char16_t*>(address);
    for (size_t i = 0; i < chunk; ++i) {
      char16_t c = host_ptr[i];
      if (!c) {
        return true;
      }
      out->push_back(c);
    }
    address += static_cast<uint32_t>(chunk * sizeof(char16_t));
    remaining -= chunk;
  }
  return true;
}

// (Hunt v1.4.6, ronda 12, A3-R12-15.) An X_UNICODE_STRING guest
// struct plus the bytes it points at: the 8-byte header first, then
// length bytes at pointer. A NULL pointer or zero length means
// "empty", which TranslateUnicodeString already tolerates.
static bool GuestUnicodeStringReadable(uint32_t guest_address) {
  if (!guest_address) {
    return true;
  }
  if (!GuestRangeReadable(guest_address, sizeof(X_UNICODE_STRING))) {
    return false;
  }
  auto* unicode = REX_KERNEL_MEMORY()->TranslateVirtual<const X_UNICODE_STRING*>(guest_address);
  uint32_t length = unicode->length;
  if (!length) {
    return true;
  }
  uint32_t pointer = unicode->pointer;
  if (!pointer) {
    return false;
  }
  return GuestRangeReadable(pointer, length);
}

// https://msdn.microsoft.com/en-us/library/ff561778
u32 RtlCompareMemory_entry(mapped_void source1, mapped_void source2, u32 length) {
  // (Hunt v1.4.6, ronda 12, A3-R12-06.) Both buffers were read
  // length bytes with no validation at all: a wild pointer SIGSEGVd
  // the host. Validate both ranges first; 0 is the honest "no bytes
  // match" answer for an invalid range (same as the sibling below).
  if (!GuestRangeReadable(source1.guest_address(), length) ||
      !GuestRangeReadable(source2.guest_address(), length)) {
    return 0;
  }
  uint8_t* p1 = source1;
  uint8_t* p2 = source2;

  // Note that the return value is the number of bytes that match, so it's best
  // we just do this ourselves vs. using memcmp.
  // On Windows we could use the builtin function.

  uint32_t c = 0;
  for (uint32_t n = 0; n < length; n++, p1++, p2++) {
    if (*p1 == *p2) {
      c++;
    }
  }

  return c;
}

// https://msdn.microsoft.com/en-us/library/ff552123
u32 RtlCompareMemoryUlong_entry(mapped_void source, u32 length, u32 pattern) {
  // Return 0 if source/length not aligned
  if (source.guest_address() % 4 || length % 4) {
    return 0;
  }

  // (Hunt v1.4.6, ronda 12, A3-R12-07.) The buffer was read length
  // bytes (as_array, no validation) below: a wild pointer SIGSEGVd
  // the host. Validate the whole range first.
  if (!GuestRangeReadable(source.guest_address(), length)) {
    return 0;
  }

  uint32_t n = 0;
  for (uint32_t i = 0; i < (length / 4); i++) {
    // FIXME: This assumes as_array returns rex::be
    uint32_t val = source.as_array<uint32_t>()[i];
    if (val == pattern) {
      n++;
    }
  }

  return n;
}

// https://msdn.microsoft.com/en-us/library/ff552263
void RtlFillMemoryUlong_entry(mapped_void destination, u32 length, u32 pattern) {
  // (Audit A3, ronda 6, R6-06, sweep.) A NULL destination used to fill
  // guest address 0 with the pattern, `length` dwords long.
  if (!destination) {
    return;
  }

  // NOTE: length must be % 4, so we can work on uint32s.
  uint32_t count = length >> 2;

  // (Hunt v1.4.6, ronda 12, A3-R12-08.) The destination was written
  // count dwords with only the null check above: a wild non-null
  // pointer SIGSEGVd the host. Validate the bytes actually written
  // (count * 4 == length with the low 2 bits cleared) first.
  if (!GuestRangeWritable(destination.guest_address(), count * sizeof(uint32_t))) {
    return;
  }

  uint32_t* p = destination.as<uint32_t*>();
  uint32_t swapped_pattern = rex::byte_swap(pattern);
  for (uint32_t n = 0; n < count; n++, p++) {
    *p = swapped_pattern;
  }
}

u32 RtlUpperChar_entry(u32 in) {
  char c = in & 0xFF;
  if (c >= 'a' && c <= 'z') {
    return c ^ 0x20;
  }

  return c;
}

u32 RtlLowerChar_entry(u32 in) {
  char c = in & 0xFF;
  if (c >= 'A' && c <= 'Z') {
    return c ^ 0x20;
  }

  return c;
}

u32 RtlCompareString_entry(mapped_string string_1, mapped_string string_2, u32 case_insensitive) {
  // (Hunt v1.4.6, ronda 12, A3-R12-09.) strcmp / compare_case scan
  // both strings to NUL with no cap (MappedPtr<char>::value() class,
  // R10-03): a guest string with no NUL in its page ran the host scan
  // into unmapped memory. Read both bounded first; a null string
  // stays empty, matching the MappedPtr null convention.
  std::string str_1;
  std::string str_2;
  if ((string_1 && !ReadGuestCString(string_1.guest_address(), &str_1)) ||
      (string_2 && !ReadGuestCString(string_2.guest_address(), &str_2))) {
    return 0;
  }
  int ret = case_insensitive ? rex::string::compare_case(str_1.c_str(), str_2.c_str())
                             : std::strcmp(str_1.c_str(), str_2.c_str());

  return ret;
}

u32 RtlCompareStringN_entry(mapped_string string_1, u32 string_1_len, mapped_string string_2,
                            u32 string_2_len, u32 case_insensitive) {
  // (Hunt v1.4.6, ronda 12, A3-R12-10.) The 0xFFFF paths called
  // strlen() on the raw guest pointers -- an unbounded scan (R10-03
  // class) -- and strncmp then read the raw pointers anyway, with
  // len computed from the RAW lengths instead of len1/len2 (so a
  // 0xFFFF length compared 0xFFFF bytes). Read both strings bounded
  // first and compare the copies; a null string stays empty.
  std::string str_1;
  std::string str_2;
  if ((string_1 && !ReadGuestCString(string_1.guest_address(), &str_1)) ||
      (string_2 && !ReadGuestCString(string_2.guest_address(), &str_2))) {
    return 0;
  }
  uint32_t len1 = string_1_len;
  uint32_t len2 = string_2_len;

  if (string_1_len == 0xFFFF) {
    len1 = uint32_t(str_1.size());
  }
  if (string_2_len == 0xFFFF) {
    len2 = uint32_t(str_2.size());
  }
  auto len = std::min(len1, len2);

  int ret = case_insensitive ? rex::string::compare_case_n(str_1.c_str(), str_2.c_str(), len)
                             : std::strncmp(str_1.c_str(), str_2.c_str(), len);

  return ret;
}

// https://msdn.microsoft.com/en-us/library/ff561918
void RtlInitAnsiString_entry(ppc_ptr_t<X_ANSI_STRING> destination, mapped_string source) {
  // (Hunt v1.4.6, ronda 12, A3-R12-11.) destination was written (8
  // bytes: length / maximum_length / pointer) with no check at all,
  // and strlen(source) scanned the guest string to NUL with no cap
  // (R10-03 class). Validate the struct writable first, then read the
  // source bounded. The old IMPORT_TRACE line above also scanned
  // source.value(); it now logs the bounded copy instead (the trace
  // is log_noisy-gated and was not evaluated by default, but the
  // scan was still latent in the line).
  if (!destination ||
      !GuestRangeWritable(destination.guest_address(), sizeof(X_ANSI_STRING))) {
    return;
  }
  std::string source_str;
  if (source && !ReadGuestCString(source.guest_address(), &source_str)) {
    return;
  }
  REXKRNL_IMPORT_TRACE("RtlInitAnsiString", "str={}", source ? source_str : "(null)");
  if (source) {
    uint16_t length = (uint16_t)source_str.size();
    destination->length = length;
    destination->maximum_length = length + 1;
  } else {
    destination->reset();
  }

  destination->pointer = source.guest_address();
}

// https://msdn.microsoft.com/en-us/library/ff561899
void RtlFreeAnsiString_entry(ppc_ptr_t<X_ANSI_STRING> string) {
  // (Hunt v1.4.6, ronda 12, A3-R12-13.) string was dereferenced with
  // no check at all (R10-13 class): a null or wild pointer SIGSEGVd
  // the host on the pointer read and the 8-byte reset() write.
  // Validate the struct writable first; the free itself stays the
  // A3-R10-04 residue (no ownership check exists for SystemHeapFree).
  if (!string || !GuestRangeWritable(string.guest_address(), sizeof(X_ANSI_STRING))) {
    return;
  }
  if (string->pointer) {
    REX_KERNEL_MEMORY()->SystemHeapFree(string->pointer);
  }

  string->reset();
}

// https://msdn.microsoft.com/en-us/library/ff561934
void RtlInitUnicodeString_entry(ppc_ptr_t<X_UNICODE_STRING> destination, mapped_wstring source) {
  // (Hunt v1.4.6, ronda 12, A3-R12-12.) destination was written (8
  // bytes) with no check at all, and source.value().size() scanned
  // the wide guest string to NUL with no cap (R10-03 class, wide
  // variant). Validate the struct writable first, then read the
  // source bounded.
  if (!destination ||
      !GuestRangeWritable(destination.guest_address(), sizeof(X_UNICODE_STRING))) {
    return;
  }
  std::u16string source_str;
  if (source && !ReadGuestWString(source.guest_address(), &source_str)) {
    return;
  }
  if (source) {
    destination->length = (uint16_t)source_str.size() * 2;
    destination->maximum_length = (uint16_t)(source_str.size() + 1) * 2;
    destination->pointer = source.guest_address();
  } else {
    destination->reset();
  }
}

// https://msdn.microsoft.com/en-us/library/ff561903
void RtlFreeUnicodeString_entry(ppc_ptr_t<X_UNICODE_STRING> string) {
  // (Hunt v1.4.6, ronda 12, A3-R12-13.) Same unvalidated deref as
  // RtlFreeAnsiString above: validate the struct writable first.
  if (!string || !GuestRangeWritable(string.guest_address(), sizeof(X_UNICODE_STRING))) {
    return;
  }
  if (string->pointer) {
    REX_KERNEL_MEMORY()->SystemHeapFree(string->pointer);
  }

  string->reset();
}

void RtlCopyString_entry(ppc_ptr_t<X_ANSI_STRING> destination, ppc_ptr_t<X_ANSI_STRING> source) {
  // (Hunt v1.4.6, ronda 12, A3-R12-14.) Both structs were read with
  // no check, and the memcpy copied length bytes between two
  // TranslateVirtual pointers -- guest-controlled addresses and a
  // guest-controlled length, no validation anywhere. Validate the
  // destination struct writable and the source struct readable first,
  // then both buffers for the bytes actually copied.
  if (!destination ||
      !GuestRangeWritable(destination.guest_address(), sizeof(X_ANSI_STRING))) {
    return;
  }
  if (!source) {
    destination->length = 0;
    return;
  }
  if (!GuestRangeReadable(source.guest_address(), sizeof(X_ANSI_STRING))) {
    return;
  }

  auto length = std::min(destination->maximum_length, source->length);
  if (length > 0) {
    if (!GuestRangeWritable(destination->pointer, length) ||
        !GuestRangeReadable(source->pointer, length)) {
      return;
    }
    auto dst_buf = REX_KERNEL_MEMORY()->TranslateVirtual(destination->pointer);
    auto src_buf = REX_KERNEL_MEMORY()->TranslateVirtual(source->pointer);
    std::memcpy(dst_buf, src_buf, length);
  }
  destination->length = length;
}

void RtlCopyUnicodeString_entry(ppc_ptr_t<X_UNICODE_STRING> destination,
                                ppc_ptr_t<X_UNICODE_STRING> source) {
  // (Hunt v1.4.6, ronda 12, A3-R12-14.) Same unvalidated struct
  // reads and guest-controlled memcpy as RtlCopyString above.
  // Validate both structs, then both buffers.
  // (Hunt v1.4.6, caza ronda 13, A3-R13-04.) The byte count was
  // length * 2: wrong. UNICODE_STRING Length/MaximumLength are in
  // BYTES (MS Learn _UNICODE_STRING; Wine RtlCopyUnicodeString
  // copies min(src->Length, dst->MaximumLength) bytes, no * 2),
  // and this file's own RtlInitUnicodeString sets length =
  // u16-count * 2. The * 2 copied length bytes past the end of
  // both strings on every call. Copy length bytes.
  if (!destination ||
      !GuestRangeWritable(destination.guest_address(), sizeof(X_UNICODE_STRING))) {
    return;
  }
  if (!source) {
    destination->length = 0;
    return;
  }
  if (!GuestRangeReadable(source.guest_address(), sizeof(X_UNICODE_STRING))) {
    return;
  }

  auto length = std::min(destination->maximum_length, source->length);
  if (length > 0) {
    if (!GuestRangeWritable(destination->pointer, length) ||
        !GuestRangeReadable(source->pointer, length)) {
      return;
    }
    auto dst_buf = REX_KERNEL_MEMORY()->TranslateVirtual(destination->pointer);
    auto src_buf = REX_KERNEL_MEMORY()->TranslateVirtual(source->pointer);
    std::memcpy(dst_buf, src_buf, length);
  }
  destination->length = length;
}

// https://msdn.microsoft.com/en-us/library/ff562969
u32 RtlUnicodeStringToAnsiString_entry(ppc_ptr_t<X_ANSI_STRING> destination_ptr,
                                       ppc_ptr_t<X_UNICODE_STRING> source_ptr, u32 alloc_dest) {
  // NTSTATUS
  // _Inout_  PANSI_STRING DestinationString,
  // _In_     PCUNICODE_STRING SourceString,
  // _In_     BOOLEAN AllocateDestinationString

  // (Hunt v1.4.6, ronda 12, A3-R12-15.) destination_ptr was
  // dereferenced with no check at all, TranslateUnicodeString read
  // length bytes off source_ptr->pointer with no validation, and the
  // non-alloc path computed buffer_capacity - 1 with no guard: a
  // maximum_length of 0 underflowed to 0xFFFFFFFF and memcpy copied
  // ~4 GiB. Validate both structs and the source bytes first; reject
  // a zero-capacity destination (BUFFER_OVERFLOW, the existing
  // failure value for this path) instead of underflowing; validate
  // the destination buffer for the bytes actually written; and never
  // memcpy into a failed alloc (SystemHeapAlloc returns 0).
  if (!destination_ptr ||
      !GuestRangeWritable(destination_ptr.guest_address(), sizeof(X_ANSI_STRING)) ||
      !GuestUnicodeStringReadable(source_ptr.guest_address())) {
    return X_STATUS_INVALID_PARAMETER;
  }
  std::u16string unicode_str = util::TranslateUnicodeString(REX_KERNEL_MEMORY(), source_ptr);
  std::string ansi_str = rex::string::to_utf8(unicode_str);
  if (ansi_str.size() > 0xFFFF - 1) {
    return X_STATUS_INVALID_PARAMETER_2;
  }

  X_STATUS result = X_STATUS_SUCCESS;
  if (alloc_dest) {
    uint32_t buffer_ptr = REX_KERNEL_MEMORY()->SystemHeapAlloc(uint32_t(ansi_str.size() + 1));
    if (!buffer_ptr) {
      return X_STATUS_NO_MEMORY;
    }

    memcpy(REX_KERNEL_MEMORY()->TranslateVirtual(buffer_ptr), ansi_str.data(), ansi_str.size() + 1);
    destination_ptr->length = static_cast<uint16_t>(ansi_str.size());
    destination_ptr->maximum_length = static_cast<uint16_t>(ansi_str.size() + 1);
    destination_ptr->pointer = static_cast<uint32_t>(buffer_ptr);
  } else {
    uint32_t buffer_capacity = destination_ptr->maximum_length;
    if (buffer_capacity == 0) {
      return X_STATUS_BUFFER_OVERFLOW;
    }
    if (!GuestRangeWritable(destination_ptr->pointer, buffer_capacity)) {
      return X_STATUS_BUFFER_OVERFLOW;
    }
    auto buffer_ptr = REX_KERNEL_MEMORY()->TranslateVirtual(destination_ptr->pointer);
    if (buffer_capacity < ansi_str.size() + 1) {
      // Too large - we just write what we can.
      result = X_STATUS_BUFFER_OVERFLOW;
      memcpy(buffer_ptr, ansi_str.data(), buffer_capacity - 1);
    } else {
      memcpy(buffer_ptr, ansi_str.data(), ansi_str.size() + 1);
    }
    buffer_ptr[buffer_capacity - 1] = 0;  // \0
  }
  return result;
}

// https://msdn.microsoft.com/en-us/library/ff553113
u32 RtlMultiByteToUnicodeN_entry(mapped_u16 destination_ptr, u32 destination_len,
                                 mapped_u32 written_ptr, ppc_ptr_t<uint8_t> source_ptr,
                                 u32 source_len) {
  uint32_t copy_len = destination_len >> 1;
  copy_len = copy_len < source_len ? copy_len : source_len;

  // (Hunt v1.4.6, ronda 12, A3-R12-16.) The element-wise copy below
  // read/wrote copy_len entries with no validation of either buffer,
  // and *written_ptr was written with only a non-zero check (R10-09
  // class). Validate both buffers and the out-param first.
  if (!GuestRangeWritable(destination_ptr.guest_address(), copy_len * sizeof(uint16_t)) ||
      !GuestRangeReadable(source_ptr.guest_address(), copy_len) ||
      (written_ptr && !GuestRangeWritable(written_ptr.guest_address(), sizeof(uint32_t)))) {
    return 0;
  }

  // TODO(benvanik): maybe use MultiByteToUnicode on Win32? would require
  // swapping.

  for (uint32_t i = 0; i < copy_len; i++) {
    destination_ptr[i] = source_ptr[i];
  }

  if (written_ptr.guest_address() != 0) {
    *written_ptr = copy_len << 1;
  }

  return 0;
}

// https://msdn.microsoft.com/en-us/library/ff553261
u32 RtlUnicodeToMultiByteN_entry(ppc_ptr_t<uint8_t> destination_ptr, u32 destination_len,
                                 mapped_u32 written_ptr, mapped_u16 source_ptr, u32 source_len) {
  uint32_t copy_len = source_len >> 1;
  copy_len = copy_len < destination_len ? copy_len : destination_len;

  // (Hunt v1.4.6, ronda 12, A3-R12-16.) Same unvalidated buffers and
  // out-param as RtlMultiByteToUnicodeN above (mirrored directions).
  // Validate both buffers and the out-param first.
  if (!GuestRangeWritable(destination_ptr.guest_address(), copy_len) ||
      !GuestRangeReadable(source_ptr.guest_address(), copy_len * sizeof(uint16_t)) ||
      (written_ptr && !GuestRangeWritable(written_ptr.guest_address(), sizeof(uint32_t)))) {
    return 0;
  }

  // TODO(benvanik): maybe use UnicodeToMultiByte on Win32?
  for (uint32_t i = 0; i < copy_len; i++) {
    uint16_t c = source_ptr[i];
    destination_ptr[i] = c < 256 ? (uint8_t)c : '?';
  }

  if (written_ptr.guest_address() != 0) {
    *written_ptr = copy_len;
  }
  return 0;
}

// https://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Executable%20Images/RtlImageNtHeader.html
u32 RtlImageNtHeader_entry(mapped_void module) {
  if (!module) {
    return 0;
  }

  // (Hunt v1.4.6, ronda 12, A3-R12-17.) module was only null-checked:
  // dos_lfanew is a guest-controlled offset, so &dos_header[lfanew]
  // read an arbitrary guest address with no validation at all. Read
  // the DOS header from a validated 0x40-byte range first, then
  // validate the 4 NT-magic bytes at the guest-controlled offset
  // (64-bit math: a negative or overflowing offset is rejected).
  if (!GuestRangeReadable(module.guest_address(), 0x40)) {
    return 0;
  }

  // Little-endian! no swapping!

  auto dos_header = module.as<const uint8_t*>();
  auto dos_magic = *reinterpret_cast<const uint16_t*>(&dos_header[0x00]);
  if (dos_magic != 0x5A4D) {  // 'MZ'
    return 0;
  }
  auto dos_lfanew = *reinterpret_cast<const int32_t*>(&dos_header[0x3C]);
  if (dos_lfanew < 0) {
    return 0;
  }
  uint64_t nt_header_address = uint64_t(module.guest_address()) + uint64_t(dos_lfanew);
  if (nt_header_address > UINT32_MAX ||
      !GuestRangeReadable(static_cast<uint32_t>(nt_header_address), sizeof(uint32_t))) {
    return 0;
  }

  auto nt_header = &dos_header[dos_lfanew];
  auto nt_magic = *reinterpret_cast<const uint32_t*>(&nt_header[0x00]);
  if (nt_magic != 0x4550) {  // 'PE'
    return 0;
  }
  return REX_KERNEL_MEMORY()->HostToGuestVirtual(nt_header);
}

u32 RtlImageXexHeaderField_entry(ppc_ptr_t<xex2_header> xex_header, u32 field_dword) {
  // (Hunt v1.4.6, ronda 12, A3-R12-18.) xex_header was dereferenced
  // with no check at all, and GetOptHeader walks header->headers[i]
  // for a guest-controlled header_count (8 bytes per entry): a wild
  // pointer, or a huge count, read past the header into unmapped
  // memory. Validate the 0x18-byte fixed prefix first, read the
  // count, then validate the whole table (64-bit math).
  if (!xex_header ||
      !GuestRangeReadable(xex_header.guest_address(), offsetof(xex2_header, headers))) {
    return 0;
  }
  uint32_t field_value = 0;
  uint32_t field = field_dword;  // VS acts weird going from u32 -> enum

  uint64_t header_bytes = uint64_t(offsetof(xex2_header, headers)) +
                          uint64_t(xex_header->header_count) * sizeof(xex2_opt_header);
  if (header_bytes > UINT32_MAX ||
      !GuestRangeReadable(xex_header.guest_address(), static_cast<size_t>(header_bytes))) {
    return 0;
  }

  UserModule::GetOptHeader(REX_KERNEL_MEMORY(), xex_header, xex2_header_keys(field), &field_value);

  return field_value;
}

// Unfortunately the Windows RTL_CRITICAL_SECTION object is bigger than the one
// on the 360 (32b vs. 28b). This means that we can't do in-place splatting of
// the critical sections. Also, the 360 never calls RtlDeleteCriticalSection
// so we can't clean up the native handles.
//
// Because of this, we reimplement it poorly. Hooray.
// We have 28b to work with so we need to be careful. We map our struct directly
// into guest memory, as it should be opaque and so long as our size is right
// the user code will never know.
//
// Ref:
// https://web.archive.org/web/20161214022602/https://msdn.microsoft.com/en-us/magazine/cc164040.aspx
// Ref:
// https://github.com/reactos/reactos/blob/master/sdk/lib/rtl/critical.c

// This structure tries to match the one on the 360 as best I can figure out.
// Unfortunately some games have the critical sections pre-initialized in
// their embedded data and InitializeCriticalSection will never be called.
#pragma pack(push, 1)
struct X_RTL_CRITICAL_SECTION {
  X_DISPATCH_HEADER header;
  int32_t lock_count;                // 0x10 -1 -> 0 on first lock
  rex::be<int32_t> recursion_count;  // 0x14  0 -> 1 on first lock
  rex::be<uint32_t> owning_thread;   // 0x18 PKTHREAD 0 unless locked
};
#pragma pack(pop)
static_assert_size(X_RTL_CRITICAL_SECTION, 28);

void xeRtlInitializeCriticalSection(X_RTL_CRITICAL_SECTION* cs, uint32_t cs_ptr) {
  cs->header.type = 1;      // EventSynchronizationObject (auto reset)
  cs->header.absolute = 0;  // spin count div 256
  cs->header.signal_state = 0;
  cs->lock_count = -1;
  cs->recursion_count = 0;
  cs->owning_thread = 0;
}

void RtlInitializeCriticalSection_entry(ppc_ptr_t<X_RTL_CRITICAL_SECTION> cs) {
  // (Hunt v1.4.6, ronda 12, A3-R12-19.) cs was written (28 bytes)
  // with no check at all (R10-13 class). Validate it first.
  if (!cs || !GuestRangeWritable(cs.guest_address(), sizeof(X_RTL_CRITICAL_SECTION))) {
    return;
  }
  REXKRNL_IMPORT_TRACE("RtlInitializeCriticalSection", "cs={:#x}", cs.guest_address());
  xeRtlInitializeCriticalSection(cs, cs.guest_address());
}

X_STATUS xeRtlInitializeCriticalSectionAndSpinCount(X_RTL_CRITICAL_SECTION* cs, uint32_t cs_ptr,
                                                    uint32_t spin_count) {
  // Spin count is rounded up to 256 intervals then packed in.
  // uint32_t spin_count_div_256 = (uint32_t)floor(spin_count / 256.0f + 0.5f);
  uint32_t spin_count_div_256 = (spin_count + 255) >> 8;
  if (spin_count_div_256 > 255) {
    spin_count_div_256 = 255;
  }

  cs->header.type = 1;  // EventSynchronizationObject (auto reset)
  cs->header.absolute = spin_count_div_256;
  cs->header.signal_state = 0;
  cs->lock_count = -1;
  cs->recursion_count = 0;
  cs->owning_thread = 0;

  return X_STATUS_SUCCESS;
}

u32 RtlInitializeCriticalSectionAndSpinCount_entry(ppc_ptr_t<X_RTL_CRITICAL_SECTION> cs,
                                                   u32 spin_count) {
  // (Hunt v1.4.6, ronda 12, A3-R12-19.) Same unvalidated 28-byte
  // struct write as RtlInitializeCriticalSection above.
  if (!cs || !GuestRangeWritable(cs.guest_address(), sizeof(X_RTL_CRITICAL_SECTION))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  return xeRtlInitializeCriticalSectionAndSpinCount(cs, cs.guest_address(), spin_count);
}

void RtlEnterCriticalSection_entry(ppc_ptr_t<X_RTL_CRITICAL_SECTION> cs) {
  // (Hunt v1.4.6, ronda 12, A3-R12-19.) cs was read/written (28
  // bytes, on the hottest lock path in the game) with no check at
  // all. Validate it first; the current thread is also null-checked
  // (R3-08 precedent: GetCurrentThread is only an assert away from
  // null on a non-kernel thread).
  if (!cs || !GuestRangeWritable(cs.guest_address(), sizeof(X_RTL_CRITICAL_SECTION))) {
    return;
  }
  auto* current_thread = XThread::GetCurrentThread();
  if (!current_thread) {
    return;
  }
  uint32_t cur_thread = current_thread->guest_object();
  uint32_t spin_count = cs->header.absolute * 256;

  if (cs->owning_thread == cur_thread) {
    // We already own the lock.
    rex::thread::atomic_inc(&cs->lock_count);
    cs->recursion_count++;
    return;
  }

  // Spin loop
  while (spin_count--) {
    if (rex::thread::atomic_cas(-1, 0, &cs->lock_count)) {
      // Acquired.
      cs->owning_thread = cur_thread;
      cs->recursion_count = 1;
      return;
    }
  }

  if (rex::thread::atomic_inc(&cs->lock_count) != 0) {
    // Create a full waiter.
    xeKeWaitForSingleObject(reinterpret_cast<void*>(cs.host_address()), 8, 0, 0, nullptr);
  }

  assert_true(cs->owning_thread == 0);
  cs->owning_thread = cur_thread;
  cs->recursion_count = 1;
}

u32 RtlTryEnterCriticalSection_entry(ppc_ptr_t<X_RTL_CRITICAL_SECTION> cs) {
  // (Hunt v1.4.6, ronda 12, A3-R12-19.) Same unvalidated 28-byte
  // struct access as RtlEnterCriticalSection above.
  if (!cs || !GuestRangeWritable(cs.guest_address(), sizeof(X_RTL_CRITICAL_SECTION))) {
    return 0;
  }
  auto* current_thread = XThread::GetCurrentThread();
  if (!current_thread) {
    return 0;
  }
  uint32_t thread = current_thread->guest_object();

  if (rex::thread::atomic_cas(-1, 0, &cs->lock_count)) {
    // Able to steal the lock right away.
    cs->owning_thread = thread;
    cs->recursion_count = 1;
    return 1;
  } else if (cs->owning_thread == thread) {
    // Already own the lock.
    rex::thread::atomic_inc(&cs->lock_count);
    ++cs->recursion_count;
    return 1;
  }

  // Failed to acquire lock.
  return 0;
}

void RtlLeaveCriticalSection_entry(ppc_ptr_t<X_RTL_CRITICAL_SECTION> cs) {
  // (Hunt v1.4.6, ronda 12, A3-R12-19.) Same unvalidated 28-byte
  // struct access as RtlEnterCriticalSection above.
  if (!cs || !GuestRangeWritable(cs.guest_address(), sizeof(X_RTL_CRITICAL_SECTION))) {
    return;
  }
  auto* current_thread = XThread::GetCurrentThread();
  if (!current_thread) {
    return;
  }
  assert_true(cs->owning_thread == current_thread->guest_object());

  // Drop recursion count - if it isn't zero we still have the lock.
  assert_true(cs->recursion_count > 0);
  if (--cs->recursion_count != 0) {
    assert_true(cs->recursion_count >= 0);

    rex::thread::atomic_dec(&cs->lock_count);
    return;
  }

  // Not owned - unlock!
  cs->owning_thread = 0;
  if (rex::thread::atomic_dec(&cs->lock_count) != -1) {
    // There were waiters - wake one of them.
    xeKeSetEvent(reinterpret_cast<X_KEVENT*>(cs.host_address()), 1, 0);
  }
}

struct X_TIME_FIELDS {
  rex::be<uint16_t> year;
  rex::be<uint16_t> month;
  rex::be<uint16_t> day;
  rex::be<uint16_t> hour;
  rex::be<uint16_t> minute;
  rex::be<uint16_t> second;
  rex::be<uint16_t> milliseconds;
  rex::be<uint16_t> weekday;
};
static_assert_size(X_TIME_FIELDS, 16);

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltimetotimefields
void RtlTimeToTimeFields_entry(mapped_u64 time_ptr, ppc_ptr_t<X_TIME_FIELDS> time_fields_ptr) {
  // (Hunt v1.4.6, ronda 12, A3-R12-20.) Neither pointer was checked
  // at all: time_ptr.value() read 8 bytes and the 16-byte
  // X_TIME_FIELDS struct was written through a wild pointer (R10-13
  // class). Validate both first.
  if (!time_ptr || !time_fields_ptr ||
      !GuestRangeReadable(time_ptr.guest_address(), sizeof(uint64_t)) ||
      !GuestRangeWritable(time_fields_ptr.guest_address(), sizeof(X_TIME_FIELDS))) {
    return;
  }
  // Use host clock because we don't want scaling to be applied, just conversion
  using rex::chrono::WinSystemClock;
  auto tp = WinSystemClock::to_sys(WinSystemClock::from_file_time(time_ptr.value()));
  auto dp = std::chrono::floor<std::chrono::days>(tp);
  auto year_month_day = std::chrono::year_month_day{dp};
  auto weekday = std::chrono::weekday{dp};
  auto time = std::chrono::hh_mm_ss{std::chrono::floor<std::chrono::milliseconds>(tp - dp)};
  time_fields_ptr->year = static_cast<int>(year_month_day.year());
  time_fields_ptr->month = static_cast<unsigned>(year_month_day.month());
  time_fields_ptr->day = static_cast<unsigned>(year_month_day.day());
  time_fields_ptr->weekday = weekday.c_encoding();
  time_fields_ptr->hour = time.hours().count();
  time_fields_ptr->minute = time.minutes().count();
  time_fields_ptr->second = static_cast<uint16_t>(time.seconds().count());
  time_fields_ptr->milliseconds = static_cast<uint16_t>(time.subseconds().count());
}

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltimefieldstotime
u32 RtlTimeFieldsToTime_entry(ppc_ptr_t<X_TIME_FIELDS> time_fields_ptr, mapped_u64 time_ptr) {
  // (Audit A3, ronda 6, R6-06, sweep.) Both pointers are dereferenced
  // below; a NULL one used to read/write guest address 0.
  if (!time_fields_ptr || !time_ptr) {
    return 0;
  }
  // (Hunt v1.4.6, ronda 12, A3-R12-21.) The R6-06 sweep fixed only
  // the NULL case: a wild non-null pointer still SIGSEGVd the host
  // on the struct read / 8-byte write below (R10-09 class).
  if (!GuestRangeReadable(time_fields_ptr.guest_address(), sizeof(X_TIME_FIELDS)) ||
      !GuestRangeWritable(time_ptr.guest_address(), sizeof(uint64_t))) {
    return 0;
  }

  using rex::chrono::WinSystemClock;
  if (time_fields_ptr->year < 1601 || time_fields_ptr->month < 1 || time_fields_ptr->month > 12 ||
      time_fields_ptr->day < 1 || time_fields_ptr->day > 31 || time_fields_ptr->hour > 23 ||
      time_fields_ptr->minute > 59 || time_fields_ptr->second > 59 ||
      time_fields_ptr->milliseconds > 999) {
    return 0;
  }
  auto year = std::chrono::year{time_fields_ptr->year};
  auto month = std::chrono::month{time_fields_ptr->month};
  auto day = std::chrono::day{time_fields_ptr->day};
  auto year_month_day = std::chrono::year_month_day{year, month, day};
  if (!year_month_day.ok()) {
    return 0;
  }
  auto dp = static_cast<std::chrono::sys_days>(year_month_day);
  std::chrono::system_clock::time_point time = dp;
  time += std::chrono::hours{time_fields_ptr->hour};
  time += std::chrono::minutes{time_fields_ptr->minute};
  time += std::chrono::seconds{time_fields_ptr->second};
  time += std::chrono::milliseconds{time_fields_ptr->milliseconds};
  *time_ptr = WinSystemClock::to_file_time(WinSystemClock::from_sys(time));
  return 1;
}

static uint32_t crc32_table[256] = {
    0x00000000u, 0x77073096u, 0xEE0E612Cu, 0x990951BAu, 0x076DC419u, 0x706AF48Fu, 0xE963A535u,
    0x9E6495A3u, 0x0EDB8832u, 0x79DCB8A4u, 0xE0D5E91Eu, 0x97D2D988u, 0x09B64C2Bu, 0x7EB17CBDu,
    0xE7B82D07u, 0x90BF1D91u, 0x1DB71064u, 0x6AB020F2u, 0xF3B97148u, 0x84BE41DEu, 0x1ADAD47Du,
    0x6DDDE4EBu, 0xF4D4B551u, 0x83D385C7u, 0x136C9856u, 0x646BA8C0u, 0xFD62F97Au, 0x8A65C9ECu,
    0x14015C4Fu, 0x63066CD9u, 0xFA0F3D63u, 0x8D080DF5u, 0x3B6E20C8u, 0x4C69105Eu, 0xD56041E4u,
    0xA2677172u, 0x3C03E4D1u, 0x4B04D447u, 0xD20D85FDu, 0xA50AB56Bu, 0x35B5A8FAu, 0x42B2986Cu,
    0xDBBBC9D6u, 0xACBCF940u, 0x32D86CE3u, 0x45DF5C75u, 0xDCD60DCFu, 0xABD13D59u, 0x26D930ACu,
    0x51DE003Au, 0xC8D75180u, 0xBFD06116u, 0x21B4F4B5u, 0x56B3C423u, 0xCFBA9599u, 0xB8BDA50Fu,
    0x2802B89Eu, 0x5F058808u, 0xC60CD9B2u, 0xB10BE924u, 0x2F6F7C87u, 0x58684C11u, 0xC1611DABu,
    0xB6662D3Du, 0x76DC4190u, 0x01DB7106u, 0x98D220BCu, 0xEFD5102Au, 0x71B18589u, 0x06B6B51Fu,
    0x9FBFE4A5u, 0xE8B8D433u, 0x7807C9A2u, 0x0F00F934u, 0x9609A88Eu, 0xE10E9818u, 0x7F6A0DBBu,
    0x086D3D2Du, 0x91646C97u, 0xE6635C01u, 0x6B6B51F4u, 0x1C6C6162u, 0x856530D8u, 0xF262004Eu,
    0x6C0695EDu, 0x1B01A57Bu, 0x8208F4C1u, 0xF50FC457u, 0x65B0D9C6u, 0x12B7E950u, 0x8BBEB8EAu,
    0xFCB9887Cu, 0x62DD1DDFu, 0x15DA2D49u, 0x8CD37CF3u, 0xFBD44C65u, 0x4DB26158u, 0x3AB551CEu,
    0xA3BC0074u, 0xD4BB30E2u, 0x4ADFA541u, 0x3DD895D7u, 0xA4D1C46Du, 0xD3D6F4FBu, 0x4369E96Au,
    0x346ED9FCu, 0xAD678846u, 0xDA60B8D0u, 0x44042D73u, 0x33031DE5u, 0xAA0A4C5Fu, 0xDD0D7CC9u,
    0x5005713Cu, 0x270241AAu, 0xBE0B1010u, 0xC90C2086u, 0x5768B525u, 0x206F85B3u, 0xB966D409u,
    0xCE61E49Fu, 0x5EDEF90Eu, 0x29D9C998u, 0xB0D09822u, 0xC7D7A8B4u, 0x59B33D17u, 0x2EB40D81u,
    0xB7BD5C3Bu, 0xC0BA6CADu, 0xEDB88320u, 0x9ABFB3B6u, 0x03B6E20Cu, 0x74B1D29Au, 0xEAD54739u,
    0x9DD277AFu, 0x04DB2615u, 0x73DC1683u, 0xE3630B12u, 0x94643B84u, 0x0D6D6A3Eu, 0x7A6A5AA8u,
    0xE40ECF0Bu, 0x9309FF9Du, 0x0A00AE27u, 0x7D079EB1u, 0xF00F9344u, 0x8708A3D2u, 0x1E01F268u,
    0x6906C2FEu, 0xF762575Du, 0x806567CBu, 0x196C3671u, 0x6E6B06E7u, 0xFED41B76u, 0x89D32BE0u,
    0x10DA7A5Au, 0x67DD4ACCu, 0xF9B9DF6Fu, 0x8EBEEFF9u, 0x17B7BE43u, 0x60B08ED5u, 0xD6D6A3E8u,
    0xA1D1937Eu, 0x38D8C2C4u, 0x4FDFF252u, 0xD1BB67F1u, 0xA6BC5767u, 0x3FB506DDu, 0x48B2364Bu,
    0xD80D2BDAu, 0xAF0A1B4Cu, 0x36034AF6u, 0x41047A60u, 0xDF60EFC3u, 0xA867DF55u, 0x316E8EEFu,
    0x4669BE79u, 0xCB61B38Cu, 0xBC66831Au, 0x256FD2A0u, 0x5268E236u, 0xCC0C7795u, 0xBB0B4703u,
    0x220216B9u, 0x5505262Fu, 0xC5BA3BBEu, 0xB2BD0B28u, 0x2BB45A92u, 0x5CB36A04u, 0xC2D7FFA7u,
    0xB5D0CF31u, 0x2CD99E8Bu, 0x5BDEAE1Du, 0x9B64C2B0u, 0xEC63F226u, 0x756AA39Cu, 0x026D930Au,
    0x9C0906A9u, 0xEB0E363Fu, 0x72076785u, 0x05005713u, 0x95BF4A82u, 0xE2B87A14u, 0x7BB12BAEu,
    0x0CB61B38u, 0x92D28E9Bu, 0xE5D5BE0Du, 0x7CDCEFB7u, 0x0BDBDF21u, 0x86D3D2D4u, 0xF1D4E242u,
    0x68DDB3F8u, 0x1FDA836Eu, 0x81BE16CDu, 0xF6B9265Bu, 0x6FB077E1u, 0x18B74777u, 0x88085AE6u,
    0xFF0F6A70u, 0x66063BCAu, 0x11010B5Cu, 0x8F659EFFu, 0xF862AE69u, 0x616BFFD3u, 0x166CCF45u,
    0xA00AE278u, 0xD70DD2EEu, 0x4E048354u, 0x3903B3C2u, 0xA7672661u, 0xD06016F7u, 0x4969474Du,
    0x3E6E77DBu, 0xAED16A4Au, 0xD9D65ADCu, 0x40DF0B66u, 0x37D83BF0u, 0xA9BCAE53u, 0xDEBB9EC5u,
    0x47B2CF7Fu, 0x30B5FFE9u, 0xBDBDF21Cu, 0xCABAC28Au, 0x53B39330u, 0x24B4A3A6u, 0xBAD03605u,
    0xCDD70693u, 0x54DE5729u, 0x23D967BFu, 0xB3667A2Eu, 0xC4614AB8u, 0x5D681B02u, 0x2A6F2B94u,
    0xB40BBE37u, 0xC30C8EA1u, 0x5A05DF1Bu, 0x2D02EF8Du,
};

u32 RtlComputeCrc32_entry(u32 seed, mapped_void buffer, u32 length) {
  if (!length) {
    return seed;
  }
  // (Hunt v1.4.6, ronda 12, A3-R12-22.) buffer[i] was read length
  // bytes with no validation at all: a wild pointer SIGSEGVd the
  // host. Validate the whole range first; the seed is the honest
  // answer for an invalid range (same as the empty-buffer path).
  if (!GuestRangeReadable(buffer.guest_address(), length)) {
    return seed;
  }
  uint32_t hash = ~seed;
  for (uint32_t i = 0; i < length; ++i) {
    hash = crc32_table[buffer[i] ^ (hash & 0xFF)] ^ (hash >> 8);
  }
  return ~hash;
}

void RtlCaptureContext_entry() {
  // TODO(tomc): do we even need this?
  REXKRNL_WARN("[STUB] RtlCaptureContext called - not implemented");
}

void RtlUnwind_entry() {
  // TODO(tomc): do we even need this?
  REXKRNL_WARN("[STUB] RtlUnwind called - not implemented");
}

void __C_specific_handler_entry() {
  // TODO(tomc): do we even need this?
  REXKRNL_WARN("[STUB] __C_specific_handler called - not implemented");
}

REX_EXPORT_STUB(__imp__RtlAnsiStringToUnicodeString);
REX_EXPORT_STUB(__imp__RtlAppendStringToString);
REX_EXPORT_STUB(__imp__RtlAppendUnicodeStringToString);
REX_EXPORT_STUB(__imp__RtlAppendUnicodeToString);
REX_EXPORT_STUB(__imp__RtlCompareUnicodeString);
REX_EXPORT_STUB(__imp__RtlCompareUnicodeStringN);
REX_EXPORT_STUB(__imp__RtlCompareUtf8ToUnicode);
REX_EXPORT_STUB(__imp__RtlCreateUnicodeString);
REX_EXPORT_STUB(__imp__RtlDowncaseUnicodeChar);
REX_EXPORT_STUB(__imp__RtlGetCallersAddress);
REX_EXPORT_STUB(__imp__RtlGetStackLimits);
REX_EXPORT_STUB(__imp__RtlLookupFunctionEntry);
REX_EXPORT_STUB(__imp__RtlMultiByteToUnicodeSize);
REX_EXPORT_STUB(__imp__RtlUnicodeToMultiByteSize);
REX_EXPORT_STUB(__imp__RtlUnicodeToUtf8);
REX_EXPORT_STUB(__imp__RtlUnicodeToUtf8Size);
REX_EXPORT_STUB(__imp__RtlUnwind2);
REX_EXPORT_STUB(__imp__RtlUpcaseUnicodeChar);
REX_EXPORT_STUB(__imp__RtlVirtualUnwind);
REX_EXPORT_STUB(__imp__RtlImageDirectoryEntryToData);
REX_EXPORT_STUB(__imp__RtlCaptureStackBackTrace);
REX_EXPORT_STUB(__imp__RtlSetVectoredExceptionHandler);
REX_EXPORT_STUB(__imp__RtlClearVectoredExceptionHandler);

}  // namespace rex::kernel::xboxkrnl

REX_EXPORT(__imp__RtlCompareMemory, rex::kernel::xboxkrnl::RtlCompareMemory_entry)
REX_EXPORT(__imp__RtlCompareMemoryUlong, rex::kernel::xboxkrnl::RtlCompareMemoryUlong_entry)
REX_EXPORT(__imp__RtlFillMemoryUlong, rex::kernel::xboxkrnl::RtlFillMemoryUlong_entry)
REX_EXPORT(__imp__RtlUpperChar, rex::kernel::xboxkrnl::RtlUpperChar_entry)
REX_EXPORT(__imp__RtlLowerChar, rex::kernel::xboxkrnl::RtlLowerChar_entry)
REX_EXPORT(__imp__RtlCompareString, rex::kernel::xboxkrnl::RtlCompareString_entry)
REX_EXPORT(__imp__RtlCompareStringN, rex::kernel::xboxkrnl::RtlCompareStringN_entry)
REX_EXPORT(__imp__RtlInitAnsiString, rex::kernel::xboxkrnl::RtlInitAnsiString_entry)
REX_EXPORT(__imp__RtlFreeAnsiString, rex::kernel::xboxkrnl::RtlFreeAnsiString_entry)
REX_EXPORT(__imp__RtlInitUnicodeString, rex::kernel::xboxkrnl::RtlInitUnicodeString_entry)
REX_EXPORT(__imp__RtlFreeUnicodeString, rex::kernel::xboxkrnl::RtlFreeUnicodeString_entry)
REX_EXPORT(__imp__RtlCopyString, rex::kernel::xboxkrnl::RtlCopyString_entry)
REX_EXPORT(__imp__RtlCopyUnicodeString, rex::kernel::xboxkrnl::RtlCopyUnicodeString_entry)
REX_EXPORT(__imp__RtlUnicodeStringToAnsiString,
           rex::kernel::xboxkrnl::RtlUnicodeStringToAnsiString_entry)
REX_EXPORT(__imp__RtlMultiByteToUnicodeN, rex::kernel::xboxkrnl::RtlMultiByteToUnicodeN_entry)
REX_EXPORT(__imp__RtlUnicodeToMultiByteN, rex::kernel::xboxkrnl::RtlUnicodeToMultiByteN_entry)
REX_EXPORT(__imp__RtlImageNtHeader, rex::kernel::xboxkrnl::RtlImageNtHeader_entry)
REX_EXPORT(__imp__RtlImageXexHeaderField, rex::kernel::xboxkrnl::RtlImageXexHeaderField_entry)
REX_EXPORT(__imp__RtlInitializeCriticalSection,
           rex::kernel::xboxkrnl::RtlInitializeCriticalSection_entry)
REX_EXPORT(__imp__RtlInitializeCriticalSectionAndSpinCount,
           rex::kernel::xboxkrnl::RtlInitializeCriticalSectionAndSpinCount_entry)
REX_EXPORT(__imp__RtlEnterCriticalSection, rex::kernel::xboxkrnl::RtlEnterCriticalSection_entry)
REX_EXPORT(__imp__RtlTryEnterCriticalSection,
           rex::kernel::xboxkrnl::RtlTryEnterCriticalSection_entry)
REX_EXPORT(__imp__RtlLeaveCriticalSection, rex::kernel::xboxkrnl::RtlLeaveCriticalSection_entry)
REX_EXPORT(__imp__RtlTimeToTimeFields, rex::kernel::xboxkrnl::RtlTimeToTimeFields_entry)
REX_EXPORT(__imp__RtlTimeFieldsToTime, rex::kernel::xboxkrnl::RtlTimeFieldsToTime_entry)
REX_EXPORT(__imp__RtlComputeCrc32, rex::kernel::xboxkrnl::RtlComputeCrc32_entry)
REX_EXPORT(__imp__RtlCaptureContext, rex::kernel::xboxkrnl::RtlCaptureContext_entry)
REX_EXPORT(__imp__RtlUnwind, rex::kernel::xboxkrnl::RtlUnwind_entry)
REX_EXPORT(__imp____C_specific_handler, rex::kernel::xboxkrnl::__C_specific_handler_entry)
