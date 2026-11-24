/**
 * @file        kernel/crt/memory.cpp
 *
 * @brief       Native memory operation hooks -- replaces recompiled PPC
 *              implementations of memcpy, memmove, memset, etc.
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 * @license     BSD 3-Clause License
 */
#include <cstring>

#include <rex/hook.h>
#include <rex/memory.h>
#include <rex/system/kernel_state.h>

namespace rex::kernel::crt {

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

// (Hunt v1.4.6, caza ronda 13, A3-R13-07.) The marshaller
// (rex/ppc/function.h) translates raw pointer arguments with
// GuestPtr -- pure base + guest_address arithmetic, no validation
// -- so these native functions only ever see host pointers.
// Recover the guest address to validate the range first; a host
// pointer outside the mapping recovers to a guest address outside
// every heap and is rejected. On an invalid range the operation
// is skipped and the function's honest failure value is returned
// (dst unchanged for the copy/set family, nullptr for memchr, 22
// EINVAL for the _s family): the alternative was a host SIGSEGV
// (read) or host memory corruption (write) past the mapping.
static uint32_t HostToGuestAddress(const void* host_ptr) {
  return REX_KERNEL_MEMORY()->HostToGuestVirtual(host_ptr);
}

// ---------------------------------------------------------------------------
// Standard memory operations
// ---------------------------------------------------------------------------

static void* native_memcpy(void* dst, const void* src, size_t n) {
  if (!GuestRangeWritable(HostToGuestAddress(dst), n) ||
      !GuestRangeReadable(HostToGuestAddress(src), n)) {
    return dst;
  }
  return std::memcpy(dst, src, n);
}

static void* native_memmove(void* dst, const void* src, size_t n) {
  if (!GuestRangeWritable(HostToGuestAddress(dst), n) ||
      !GuestRangeReadable(HostToGuestAddress(src), n)) {
    return dst;
  }
  return std::memmove(dst, src, n);
}

static void* native_memset(void* dst, int val, size_t n) {
  if (!GuestRangeWritable(HostToGuestAddress(dst), n)) {
    return dst;
  }
  return std::memset(dst, val, n);
}

static void* native_memchr(const void* ptr, int val, size_t n) {
  if (!GuestRangeReadable(HostToGuestAddress(ptr), n)) {
    return nullptr;
  }
  return const_cast<void*>(std::memchr(ptr, val, n));
}

// ---------------------------------------------------------------------------
// Xbox/VMX-optimized variants (same semantics, native speed)
// ---------------------------------------------------------------------------

static void* native_XMemCpy(void* dst, const void* src, size_t n) {
  if (!GuestRangeWritable(HostToGuestAddress(dst), n) ||
      !GuestRangeReadable(HostToGuestAddress(src), n)) {
    return dst;
  }
  return std::memcpy(dst, src, n);
}

static void* native_XMemSet(void* dst, int val, size_t n) {
  if (!GuestRangeWritable(HostToGuestAddress(dst), n)) {
    return dst;
  }
  return std::memset(dst, val, n);
}

static void* native_XMemSet128(void* dst, int val, size_t n) {
  if (!GuestRangeWritable(HostToGuestAddress(dst), n)) {
    return dst;
  }
  return std::memset(dst, val, n);
}

static void* native_memset_vmx(void* dst, int val, size_t n) {
  if (!GuestRangeWritable(HostToGuestAddress(dst), n)) {
    return dst;
  }
  return std::memset(dst, val, n);
}

// ---------------------------------------------------------------------------
// Secure variants (return errno_t)
// ---------------------------------------------------------------------------

static int native_memcpy_s(void* dst, size_t dstsz, const void* src, size_t count) {
  if (!dst || !src || count > dstsz)
    return 22;  // EINVAL
  if (!GuestRangeWritable(HostToGuestAddress(dst), count) ||
      !GuestRangeReadable(HostToGuestAddress(src), count)) {
    return 22;  // EINVAL
  }
  std::memcpy(dst, src, count);
  return 0;
}

static int native_memmove_s(void* dst, size_t dstsz, const void* src, size_t count) {
  if (!dst || !src || count > dstsz)
    return 22;  // EINVAL
  if (!GuestRangeWritable(HostToGuestAddress(dst), count) ||
      !GuestRangeReadable(HostToGuestAddress(src), count)) {
    return 22;  // EINVAL
  }
  std::memmove(dst, src, count);
  return 0;
}

}  // namespace rex::kernel::crt

REX_HOOK(rexcrt_memcpy, rex::kernel::crt::native_memcpy)
REX_HOOK(rexcrt_memmove, rex::kernel::crt::native_memmove)
REX_HOOK(rexcrt_memset, rex::kernel::crt::native_memset)
REX_HOOK(rexcrt_memchr, rex::kernel::crt::native_memchr)
REX_HOOK(rexcrt_XMemCpy, rex::kernel::crt::native_XMemCpy)
REX_HOOK(rexcrt_XMemSet, rex::kernel::crt::native_XMemSet)
REX_HOOK(rexcrt_XMemSet128, rex::kernel::crt::native_XMemSet128)
REX_HOOK(rexcrt_memset_vmx, rex::kernel::crt::native_memset_vmx)
REX_HOOK(rexcrt_memcpy_s, rex::kernel::crt::native_memcpy_s)
REX_HOOK(rexcrt_memmove_s, rex::kernel::crt::native_memmove_s)
