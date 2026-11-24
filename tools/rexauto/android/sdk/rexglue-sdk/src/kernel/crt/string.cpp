/**
 * @file        kernel/crt/string.cpp
 *
 * @brief       Native string operation hooks -- replaces recompiled PPC
 *              implementations of strncmp, strchr, lstrlenA, etc.
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 * @license     BSD 3-Clause License
 */
#include <algorithm>
#include <cstring>

#include <rex/platform.h>

#if !REX_PLATFORM_WIN32
#include <strings.h>
#endif

#include <rex/hook.h>
#include <rex/memory.h>
#include <rex/string.h>
#include <rex/system/kernel_state.h>

namespace rex::kernel::crt {

// (Hunt v1.4.6, caza ronda 13, A3-R13-08; stageado ronda 14,
// A3-R14-01.) This file had no range helper: the marshaller
// (rex/ppc/function.h) translates raw pointer arguments with
// GuestPtr -- pure base + guest_address arithmetic, no validation
// -- so these native functions only ever see host pointers, and
// every scan here ran to NUL with no cap: a wild or unterminated
// guest string SIGSEGVs the host on the read, and the unbounded
// writers (strcpy/strcat/wcscpy) corrupt host memory past the
// mapping. Same heap validation as A3-R4-09 (see xam_net.cpp for
// the full comment): reject a range that wraps past 4 GiB, starts
// or ends outside any heap, or spans heaps of different kinds (or
// two physical heaps); inside a single heap, require the pages to
// be accessible (read/write for a destination, readable for a
// source); across a heap boundary validate both ends (A3-R8-13); a
// range spanning more than two heaps is rejected outright (A3-R9-10).
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

// (Hunt v1.4.6, caza ronda 14, A3-R14-01.) The marshaller hands
// these natives host pointers, so recover the guest address to
// validate first; a host pointer outside the mapping recovers to a
// guest address outside every heap and is rejected. A host NULL
// recovers to guest 0, which the null page covers (RW by default,
// NoAccess with protect_zero): the measure below then reads at most
// the mapped null page and fails safe either way.
static uint32_t HostToGuestAddress(const void* host_ptr) {
  return REX_KERNEL_MEMORY()->HostToGuestVirtual(host_ptr);
}

// No guest string these hooks can legitimately see is anywhere near
// this long (paths and names are hundreds of bytes at most); the cap
// only bounds the scan work for a wild or unterminated pointer, and
// the page-by-page validation stops the scan at the first unreadable
// page long before the cap in practice.
constexpr size_t kMaxGuestStringUnits = 0x100000;  // 1 Mi units (1 MiB narrow, 2 MiB wide)

// Bounded guest C-string measure: scan page by page, validating each
// chunk readable before touching it (like the R6-05 reader in
// xam_ui.cpp and ReadGuestCString in xboxkrnl_debug.cpp). On success
// *out_len is the length excluding the NUL and *out_terminated says
// whether a NUL was found within cap units. Returns false when a
// page is unreadable before the scan completes -- the caller must
// NOT touch the string. A string with no NUL within cap is NOT an
// error here: out_terminated is false and out_len is cap, so
// callers with an explicit bound (strncmp/strncpy) can still use the
// first cap units, which are all validated.
struct CStringMeasure {
  bool ok = false;
  size_t length = 0;
  bool terminated = false;
};

static CStringMeasure MeasureCString(const char* host_ptr, size_t cap) {
  CStringMeasure result;
  if (!host_ptr || cap == 0) {
    return result;
  }
  uint32_t address = HostToGuestAddress(host_ptr);
  size_t length = 0;
  while (length < cap) {
    size_t page_bytes = 0x1000 - (address & 0xFFF);
    size_t chunk = std::min(cap - length, page_bytes);
    if (!GuestRangeReadable(address, chunk)) {
      return result;
    }
    const char* chunk_ptr = REX_KERNEL_MEMORY()->TranslateVirtual<const char*>(address);
    for (size_t i = 0; i < chunk; ++i) {
      if (!chunk_ptr[i]) {
        result.ok = true;
        result.length = length + i;
        result.terminated = true;
        return result;
      }
    }
    length += chunk;
    address += static_cast<uint32_t>(chunk);
  }
  result.ok = true;
  result.length = cap;
  result.terminated = false;
  return result;
}

// Wide twin of MeasureCString, in int16_t units. A wide string that
// starts at an odd guest address is already pathological (wchar_t is
// 2-byte aligned by ABI); if such a string runs into a page boundary
// with one byte left (no full unit fits in the page) the measure
// fails safe rather than reading across into an unvalidated page.
static CStringMeasure MeasureWString(const int16_t* host_ptr, size_t cap) {
  CStringMeasure result;
  if (!host_ptr || cap == 0) {
    return result;
  }
  uint32_t address = HostToGuestAddress(host_ptr);
  size_t length = 0;
  while (length < cap) {
    size_t page_units = (0x1000 - (address & 0xFFF)) / sizeof(int16_t);
    size_t chunk = std::min(cap - length, page_units);
    if (chunk == 0 || !GuestRangeReadable(address, chunk * sizeof(int16_t))) {
      return result;
    }
    const int16_t* chunk_ptr =
        REX_KERNEL_MEMORY()->TranslateVirtual<const int16_t*>(address);
    for (size_t i = 0; i < chunk; ++i) {
      if (!chunk_ptr[i]) {
        result.ok = true;
        result.length = length + i;
        result.terminated = true;
        return result;
      }
    }
    length += chunk;
    address += static_cast<uint32_t>(chunk * sizeof(int16_t));
  }
  result.ok = true;
  result.length = cap;
  result.terminated = false;
  return result;
}

// Failure values on an unreadable/unterminated operand, per family
// (the guest is already in undefined-behavior territory; the only
// hard requirement is no host crash and no guest-memory write):
// comparisons fail closed (an unreadable operand cannot be proven
// equal), finders report not-found, lengths report 0, copiers leave
// the destination untouched, the _s family reports EINVAL.
static int CompareFailed() { return 1; }

// ---------------------------------------------------------------------------
// C string operations
// ---------------------------------------------------------------------------

static int native_strncmp(const char* s1, const char* s2, size_t n) {
  if (n == 0) {
    return 0;
  }
  auto m1 = MeasureCString(s1, n);
  auto m2 = MeasureCString(s2, n);
  if (!m1.ok || !m2.ok) {
    return CompareFailed();
  }
  return std::strncmp(s1, s2, n);
}

static char* native_strncpy(char* dst, const char* src, size_t n) {
  if (n == 0) {
    return dst;
  }
  // dst is bounded by n, so it can be validated up front; src is
  // measured bounded by n (early stop on NUL is fine -- strncpy
  // reads at most n bytes and stops at the first NUL).
  if (!GuestRangeWritable(HostToGuestAddress(dst), n)) {
    return dst;
  }
  auto m = MeasureCString(src, n);
  if (!m.ok) {
    return dst;
  }
  return std::strncpy(dst, src, n);
}

static char* native_strchr(const char* s, int c) {
  auto m = MeasureCString(s, kMaxGuestStringUnits);
  if (!m.ok || !m.terminated) {
    return nullptr;
  }
  return const_cast<char*>(std::strchr(s, c));
}

static char* native_strstr(const char* haystack, const char* needle) {
  auto m_needle = MeasureCString(needle, kMaxGuestStringUnits);
  if (!m_needle.ok || !m_needle.terminated) {
    return nullptr;
  }
  if (m_needle.length == 0) {
    // Empty needle: libc returns haystack without reading it.
    return const_cast<char*>(haystack);
  }
  auto m_hay = MeasureCString(haystack, kMaxGuestStringUnits);
  if (!m_hay.ok || !m_hay.terminated) {
    return nullptr;
  }
  return const_cast<char*>(std::strstr(haystack, needle));
}

static char* native_strrchr(const char* s, int c) {
  auto m = MeasureCString(s, kMaxGuestStringUnits);
  if (!m.ok || !m.terminated) {
    return nullptr;
  }
  return const_cast<char*>(std::strrchr(s, c));
}

static char* native_strtok(char* s, const char* delim) {
  // Non-reentrant per guest libc contract; concurrent guest threads will trample.
  static char* context = nullptr;
#if REX_PLATFORM_WIN32
  return strtok_s(s, delim, &context);
#else
  auto m_delim = MeasureCString(delim, kMaxGuestStringUnits);
  if (!m_delim.ok || !m_delim.terminated) {
    return nullptr;
  }
  char* str = s ? s : context;
  if (!str) {
    return nullptr;
  }
  auto m = MeasureCString(str, kMaxGuestStringUnits);
  if (!m.ok || !m.terminated) {
    return nullptr;
  }
  // strtok_r writes NULs into the string (at delimiters and at the
  // end of the token), all within [str, str + length].
  if (!GuestRangeWritable(HostToGuestAddress(str), m.length + 1)) {
    return nullptr;
  }
  return strtok_r(s, delim, &context);
#endif
}

static int native_stricmp(const char* s1, const char* s2) {
#if REX_PLATFORM_WIN32
  return _stricmp(s1, s2);
#else
  auto m1 = MeasureCString(s1, kMaxGuestStringUnits);
  auto m2 = MeasureCString(s2, kMaxGuestStringUnits);
  if (!m1.ok || !m1.terminated || !m2.ok || !m2.terminated) {
    return CompareFailed();
  }
  return strcasecmp(s1, s2);
#endif
}

static int native_strcpy_s(char* dst, size_t dstsz, const char* src) {
#if REX_PLATFORM_WIN32
  return strcpy_s(dst, dstsz, src);
#else
  if (!dst || !src || dstsz == 0)
    return 22;  // EINVAL
  // Only the first min(dstsz, cap) bytes matter: if there is no NUL
  // in there the source cannot fit, which is ERANGE either way.
  size_t cap = std::min(dstsz, kMaxGuestStringUnits);
  auto m = MeasureCString(src, cap);
  if (!m.ok) {
    return 22;  // EINVAL: source unreadable, touch nothing
  }
  if (!m.terminated) {
    // No NUL within dstsz bytes (or within the cap, which only
    // matters for a >1 MiB source): the source does not fit.
    if (!GuestRangeWritable(HostToGuestAddress(dst), 1)) {
      return 22;  // EINVAL
    }
    dst[0] = '\0';
    return 34;  // ERANGE
  }
  if (m.length + 1 > dstsz) {
    if (!GuestRangeWritable(HostToGuestAddress(dst), 1)) {
      return 22;  // EINVAL
    }
    dst[0] = '\0';
    return 34;  // ERANGE
  }
  if (!GuestRangeWritable(HostToGuestAddress(dst), m.length + 1)) {
    return 22;  // EINVAL
  }
  std::memcpy(dst, src, m.length + 1);
  return 0;
#endif
}

// ---------------------------------------------------------------------------
// Win32 string functions (lstr*)
// ---------------------------------------------------------------------------

static int native_lstrlenA(const char* s) {
  if (!s) {
    return 0;
  }
  auto m = MeasureCString(s, kMaxGuestStringUnits);
  if (!m.ok || !m.terminated) {
    return 0;
  }
  return static_cast<int>(m.length);
}

static char* native_lstrcpyA(char* dst, const char* src) {
  // Unbounded by guest contract.
#if REX_PLATFORM_WIN32
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
  auto m = MeasureCString(src, kMaxGuestStringUnits);
  if (!m.ok || !m.terminated) {
    return dst;
  }
  if (!GuestRangeWritable(HostToGuestAddress(dst), m.length + 1)) {
    return dst;
  }
  return std::strcpy(dst, src);
}

static char* native_lstrcpynA(char* dst, const char* src, int maxlen) {
  if (maxlen <= 0)
    return dst;
#if REX_PLATFORM_WIN32
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
  // dst is bounded by maxlen, so it can be validated up front; src
  // is measured bounded by maxlen - 1 (strncpy reads at most that
  // many bytes).
  if (!GuestRangeWritable(HostToGuestAddress(dst), static_cast<size_t>(maxlen))) {
    return dst;
  }
  auto m = MeasureCString(src, static_cast<size_t>(maxlen) - 1);
  if (!m.ok) {
    return dst;
  }
  std::strncpy(dst, src, static_cast<size_t>(maxlen) - 1);
  dst[maxlen - 1] = '\0';
  return dst;
}

static char* native_lstrcatA(char* dst, const char* src) {
  // Unbounded by guest contract.
#if REX_PLATFORM_WIN32
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
  auto m_dst = MeasureCString(dst, kMaxGuestStringUnits);
  auto m_src = MeasureCString(src, kMaxGuestStringUnits);
  if (!m_dst.ok || !m_dst.terminated || !m_src.ok || !m_src.terminated) {
    return dst;
  }
  if (!GuestRangeWritable(HostToGuestAddress(dst), m_dst.length + m_src.length + 1)) {
    return dst;
  }
  return std::strcat(dst, src);
}

static int native_lstrcmpiA(const char* s1, const char* s2) {
#if REX_PLATFORM_WIN32
  return _stricmp(s1, s2);
#else
  auto m1 = MeasureCString(s1, kMaxGuestStringUnits);
  auto m2 = MeasureCString(s2, kMaxGuestStringUnits);
  if (!m1.ok || !m1.terminated || !m2.ok || !m2.terminated) {
    return CompareFailed();
  }
  return strcasecmp(s1, s2);
#endif
}

// ---------------------------------------------------------------------------
// C UTF-16 Widestring functions (int16_t*)
// ---------------------------------------------------------------------------

static uint32_t native_wcslen(const int16_t* str) {
  if (!str) {
    return 0;
  }
  auto m = MeasureWString(str, kMaxGuestStringUnits);
  if (!m.ok || !m.terminated) {
    return 0;
  }
  return static_cast<uint32_t>(m.length);
}

static uint32_t native_wcscmp(const int16_t* lhs, const int16_t* rhs) {
  auto m1 = MeasureWString(lhs, kMaxGuestStringUnits);
  auto m2 = MeasureWString(rhs, kMaxGuestStringUnits);
  if (!m1.ok || !m1.terminated || !m2.ok || !m2.terminated) {
    return CompareFailed();
  }
  while (*lhs && (*lhs == *rhs)) {
    lhs++;
    rhs++;
  }
  return (int)(*lhs) - (int)(*rhs);
}

static uint32_t native_wcsncmp(const int16_t* lhs, const int16_t* rhs, int count) {
  if (count <= 0) {
    return 0;
  }
  auto m1 = MeasureWString(lhs, static_cast<size_t>(count));
  auto m2 = MeasureWString(rhs, static_cast<size_t>(count));
  if (!m1.ok || !m2.ok) {
    return CompareFailed();
  }
  for (; count > 0; count--, lhs++, rhs++) {
    if (*lhs != *rhs)
      return (int)(*lhs) - (int)(*rhs);

    if (*lhs == L'\0')
      return 0;
  }

  return 0;
}

static uint32_t native_wcscoll(const int16_t* lhs, const int16_t* rhs) {
  if (lhs && rhs)
    return native_wcscmp(lhs, rhs);
  return 22;  // EINVAL
}

static int16_t* native_wcschr(const int16_t* str, int16_t ch) {
  auto m = MeasureWString(str, kMaxGuestStringUnits);
  if (!m.ok || !m.terminated) {
    return 0;
  }
  while (*str && *str != ch)
    str++;

  return (*str == ch) ? (int16_t*)str : 0;
}

static int16_t* native_wcsrchr(const int16_t* str, int16_t ch) {
  auto m = MeasureWString(str, kMaxGuestStringUnits);
  if (!m.ok || !m.terminated) {
    return 0;
  }
  const int16_t* res = 0;

  for (; *str; str++)
    if (*str == ch)
      res = str;

  return (int16_t*)(ch ? res : str);
}

static int16_t* native_wcscpy(const int16_t* src, int16_t* dst) {
  auto m = MeasureWString(src, kMaxGuestStringUnits);
  if (!m.ok || !m.terminated) {
    return dst;
  }
  if (!GuestRangeWritable(HostToGuestAddress(dst), (m.length + 1) * sizeof(int16_t))) {
    return dst;
  }
  int16_t* d = dst;

  while ((*d++ = *src++))
    ;

  return dst;
}

static int16_t* native_wcsncpy(int16_t* dest, const int16_t* src, int count) {
  if (count <= 0) {
    return dest;
  }
  // (Hunt v1.4.6, caza ronda 14, A3-R14-02.) The old two-loop form
  // ran away: when the source had no NUL within the first `count`
  // units -- the normal truncate case -- the first loop consumed
  // `count` and left it at -1, and the second `while (count--)`
  // then zero-filled ~2^32 units (~8 GiB) past dest before the host
  // SIGSEGVd. Rewritten as one bounded loop with the exact wcsncpy
  // semantics: copy up to count units, stop at the NUL, zero-fill
  // only the remainder up to count.
  if (!GuestRangeWritable(HostToGuestAddress(dest), static_cast<size_t>(count) * sizeof(int16_t))) {
    return dest;
  }
  auto m = MeasureWString(src, static_cast<size_t>(count));
  if (!m.ok) {
    return dest;
  }
  size_t i = 0;
  size_t n = static_cast<size_t>(count);
  for (; i < n && src[i] != 0; ++i) {
    dest[i] = src[i];
  }
  for (; i < n; ++i) {
    dest[i] = 0;
  }
  return dest;
}

static uint32_t native_wcsncpy_s(int16_t* dst, size_t dstsz, const int16_t* src, size_t count) {
  if (!dst || !src || dstsz == 0)
    return 22;  // EINVAL

  // Measure bounded by what the copy can ever touch: min(count,
  // dstsz) units. If the source has no NUL in there it is longer
  // than the copy window, which is ERANGE either way.
  size_t cap = std::min(count, dstsz);
  cap = std::min(cap, kMaxGuestStringUnits);
  auto m = MeasureWString(src, cap);
  if (!m.ok) {
    return 22;  // EINVAL: source unreadable, touch nothing
  }
  // The old loop copied min(count, dstsz - 1, strlen(src)) units and
  // reported ERANGE when it stopped early with source left over.
  // m.length is the measured length, or cap when unterminated (so
  // the source is at least cap units long).
  size_t copied = std::min({count, dstsz - 1, m.length});
  if (!GuestRangeWritable(HostToGuestAddress(dst), dstsz * sizeof(int16_t))) {
    return 22;  // EINVAL
  }
  for (size_t i = 0; i < copied; ++i) {
    dst[i] = src[i];
  }
  dst[copied] = 0;
  // ERANGE iff the copy stopped early (copied < count) while the
  // source continues: unterminated within the window, or terminated
  // past the copied prefix.
  if (copied < count && (!m.terminated || copied < m.length)) {
    return 34;  // ERANGE
  }

  return 0;
}

static int16_t* native_wcsstr(const int16_t* dest, const int16_t* src) {
  auto m_src = MeasureWString(src, kMaxGuestStringUnits);
  if (!m_src.ok || !m_src.terminated) {
    return 0;
  }
  if (m_src.length == 0) {
    // Empty needle: return dest without reading it.
    return (int16_t*)dest;
  }
  auto m_dest = MeasureWString(dest, kMaxGuestStringUnits);
  if (!m_dest.ok || !m_dest.terminated) {
    return 0;
  }
  if (!*src)
    return (int16_t*)dest;

  for (; *dest; dest++) {
    const int16_t* d = dest;
    const int16_t* s = src;

    while (*d && *s && *d == *s) {
      d++;
      s++;
    }

    if (!*s)
      return (int16_t*)dest;
  }

  return 0;
}

}  // namespace rex::kernel::crt

REX_HOOK(rexcrt_strncmp, rex::kernel::crt::native_strncmp)
REX_HOOK(rexcrt_strncpy, rex::kernel::crt::native_strncpy)
REX_HOOK(rexcrt_strchr, rex::kernel::crt::native_strchr)
REX_HOOK(rexcrt_strstr, rex::kernel::crt::native_strstr)
REX_HOOK(rexcrt_strrchr, rex::kernel::crt::native_strrchr)
REX_HOOK(rexcrt_strtok, rex::kernel::crt::native_strtok)
REX_HOOK(rexcrt__stricmp, rex::kernel::crt::native_stricmp)
REX_HOOK(rexcrt_strcpy_s, rex::kernel::crt::native_strcpy_s)
REX_HOOK(rexcrt_lstrlenA, rex::kernel::crt::native_lstrlenA)
REX_HOOK(rexcrt_lstrcpyA, rex::kernel::crt::native_lstrcpyA)
REX_HOOK(rexcrt_lstrcpynA, rex::kernel::crt::native_lstrcpynA)
REX_HOOK(rexcrt_lstrcatA, rex::kernel::crt::native_lstrcatA)
REX_HOOK(rexcrt_lstrcmpiA, rex::kernel::crt::native_lstrcmpiA)
REX_HOOK(rexcrt_wcslen, rex::kernel::crt::native_wcslen)
REX_HOOK(rexcrt_wcscmp, rex::kernel::crt::native_wcscmp)
REX_HOOK(rexcrt_wcsncmp, rex::kernel::crt::native_wcsncmp)
REX_HOOK(rexcrt_wcscoll, rex::kernel::crt::native_wcscoll)
REX_HOOK(rexcrt_wcschr, rex::kernel::crt::native_wcschr)
REX_HOOK(rexcrt_wcsrchr, rex::kernel::crt::native_wcsrchr)
REX_HOOK(rexcrt_wcscpy, rex::kernel::crt::native_wcscpy)
REX_HOOK(rexcrt_wcsncpy, rex::kernel::crt::native_wcsncpy)
REX_HOOK(rexcrt_wcsncpy_s, rex::kernel::crt::native_wcsncpy_s)
REX_HOOK(rexcrt_wcsstr, rex::kernel::crt::native_wcsstr)
