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

#include <rex/dbg.h>
#include <rex/kernel/xboxkrnl/private.h>
#include <rex/logging.h>
#include <rex/memory.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xexception.h>
#include <rex/system/xthread.h>
#include <rex/system/xtypes.h>

namespace rex::kernel::xboxkrnl {
using namespace rex::system;

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

// (Hunt v1.4.6, caza ronda 13, A3-R13-02.) Bounded guest
// C-string read: MappedPtr<char>::value() builds a string_view
// straight off the host pointer -- a strlen to NUL with no cap.
// Read page by page (each chunk validated readable first, like the
// R6-05 ReadGuestU16String reader in xam_ui.cpp), stop at the first
// NUL, truncate at 4096 chars if there is none. Returns false on an
// invalid range.
constexpr size_t kMaxGuestDebugStringChars = 4096;

static bool ReadGuestCString(uint32_t guest_address, std::string* out) {
  out->clear();
  size_t remaining = kMaxGuestDebugStringChars;
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

void DbgBreakPoint_entry() {
  rex::debug::Break();
}

// https://msdn.microsoft.com/en-us/library/xcb2z8hs.aspx
typedef struct {
  rex::be<uint32_t> type;
  rex::be<uint32_t> name_ptr;
  rex::be<uint32_t> thread_id;
  rex::be<uint32_t> flags;
} X_THREADNAME_INFO;
static_assert_size(X_THREADNAME_INFO, 0x10);

void HandleSetThreadName(ppc_ptr_t<X_EXCEPTION_RECORD> record) {
  // SetThreadName. FFS.
  // https://msdn.microsoft.com/en-us/library/xcb2z8hs.aspx

  // TODO(benvanik): check record->number_parameters to make sure it's a
  // correct size.
  auto thread_info = reinterpret_cast<X_THREADNAME_INFO*>(&record->exception_information[0]);

  assert_true(thread_info->type == 0x1000);

  if (!thread_info->name_ptr) {
    REXKRNL_DEBUG("SetThreadName called with null name_ptr");
    return;
  }

  // 4D5307D6 (and its demo) has a bug where it ends up passing freed memory for
  // the name, so at the point of SetThreadName it's filled with junk.

  // TODO(gibbed): cvar for thread name encoding for conversion, some games use
  // SJIS and there's no way to automatically know this.
  // (Hunt v1.4.6, caza ronda 13, A3-R13-02.) Bounded read: the
  // old std::string(TranslateVirtual(name_ptr)) scanned for NUL
  // with no cap -- the comment below even notes games pass freed
  // memory here. A name with no NUL in its page ran the host scan
  // into unmapped memory.
  std::string name;
  if (!ReadGuestCString(static_cast<uint32_t>(thread_info->name_ptr), &name)) {
    return;
  }
  std::replace_if(name.begin(), name.end(), [](auto c) { return c < 32 || c > 127; }, '?');

  object_ref<XThread> thread;
  if (thread_info->thread_id == -1) {
    // Current thread.
    thread = retain_object(XThread::GetCurrentThread());
  } else {
    // Lookup thread by ID.
    thread = REX_KERNEL_STATE()->GetThreadByID(thread_info->thread_id);
  }

  if (thread) {
    REXKRNL_DEBUG("SetThreadName({}, {})", thread->thread_id(), name);
    thread->set_name(name);
  }

  // TODO(benvanik): unwinding required here?
}

typedef struct {
  rex::be<int32_t> mdisp;
  rex::be<int32_t> pdisp;
  rex::be<int32_t> vdisp;
} x_PMD;

typedef struct {
  rex::be<uint32_t> properties;
  rex::be<uint32_t> type_ptr;
  x_PMD this_displacement;
  rex::be<int32_t> size_or_offset;
  rex::be<uint32_t> copy_function_ptr;
} x_s__CatchableType;

typedef struct {
  rex::be<int32_t> number_catchable_types;
  rex::be<uint32_t> catchable_type_ptrs[1];
} x_s__CatchableTypeArray;

typedef struct {
  rex::be<uint32_t> attributes;
  rex::be<uint32_t> unwind_ptr;
  rex::be<uint32_t> forward_compat_ptr;
  rex::be<uint32_t> catchable_type_array_ptr;
} x_s__ThrowInfo;

void HandleCppException(ppc_ptr_t<X_EXCEPTION_RECORD> record) {
  // C++ exception.
  // https://blogs.msdn.com/b/oldnewthing/archive/2010/07/30/10044061.aspx
  // http://www.drdobbs.com/visual-c-exception-handling-instrumentat/184416600
  // http://www.openrce.org/articles/full_view/21

  assert_true(record->number_parameters == 3);
  assert_true(record->exception_information[0] == 0x19930520);

  auto thrown_ptr = record->exception_information[1];
  auto throw_info_ptr = record->exception_information[2];
  // (Hunt v1.4.6, caza ronda 13, A3-R13-02.) thrown_ptr and
  // throw_info_ptr come straight out of the guest record; both were
  // translated and dereferenced below with no check (thrown is read
  // for the vftable pointer, throw_info for the catchable-type
  // array). Validate both ranges first. The catchable-type array
  // pointer itself is never dereferenced here, so it needs no check.
  if (!GuestRangeReadable(static_cast<uint32_t>(thrown_ptr), sizeof(uint32_t)) ||
      !GuestRangeReadable(static_cast<uint32_t>(throw_info_ptr), sizeof(x_s__ThrowInfo))) {
    return;
  }
  auto thrown = REX_KERNEL_MEMORY()->TranslateVirtual(thrown_ptr);
  auto vftable_ptr = *reinterpret_cast<rex::be<uint32_t>*>(thrown);

  auto throw_info = REX_KERNEL_MEMORY()->TranslateVirtual<x_s__ThrowInfo*>(throw_info_ptr);
  auto catchable_types = REX_KERNEL_MEMORY()->TranslateVirtual<x_s__CatchableTypeArray*>(
      throw_info->catchable_type_array_ptr);

  rex::debug::Break();
}

void RtlRaiseException_entry(ppc_ptr_t<X_EXCEPTION_RECORD> record) {
  // (Hunt v1.4.6, caza ronda 13, A3-R13-02.) record is a
  // guest-controlled pointer (this export takes it straight from
  // the caller) and was dereferenced below with no check at all:
  // record->code, the 0x50-byte record in both handlers, and the
  // thread-name string it points at. Validate the whole record
  // first; void entry, so an invalid record just returns.
  if (!record ||
      !GuestRangeReadable(record.guest_address(), sizeof(X_EXCEPTION_RECORD))) {
    return;
  }
  switch (record->code) {
    case 0x406D1388: {
      HandleSetThreadName(record);
      return;
    }
    case 0xE06D7363: {
      HandleCppException(record);
      return;
    }
  }

  // TODO(benvanik): unwinding.
  // This is going to suck.
  rex::debug::Break();
}

void KeBugCheckEx_entry(u32 code, u32 param1, u32 param2, u32 param3, u32 param4) {
  REXKRNL_DEBUG("*** STOP: 0x{:08X} (0x{:08X}, 0x{:08X}, 0x{:08X}, 0x{:08X})", code, param1, param2,
                param3, param4);
  fflush(stdout);
  rex::debug::Break();
  assert_always();
}

void KeBugCheck_entry(u32 code) {
  KeBugCheckEx_entry(code, 0, 0, 0, 0);
}

}  // namespace rex::kernel::xboxkrnl

REX_EXPORT(__imp__DbgBreakPoint, rex::kernel::xboxkrnl::DbgBreakPoint_entry)
REX_EXPORT(__imp__RtlRaiseException, rex::kernel::xboxkrnl::RtlRaiseException_entry)
REX_EXPORT(__imp__KeBugCheckEx, rex::kernel::xboxkrnl::KeBugCheckEx_entry)
REX_EXPORT(__imp__KeBugCheck, rex::kernel::xboxkrnl::KeBugCheck_entry)

REX_EXPORT_STUB(__imp__DbgBreakPointWithStatus);
REX_EXPORT_STUB(__imp__DbgPrompt);
REX_EXPORT_STUB(__imp__DbgLoadImageSymbols);
REX_EXPORT_STUB(__imp__DbgUnLoadImageSymbols);
REX_EXPORT_STUB(__imp__DmPrintData);

REX_EXPORT_STUB(__imp__DumpGetRawDumpInfo);
REX_EXPORT_STUB(__imp__DumpRegisterDedicatedDataBlock);
REX_EXPORT_STUB(__imp__DumpSetCollectionFacility);
REX_EXPORT_STUB(__imp__DumpUpdateDumpSettings);
REX_EXPORT_STUB(__imp__DumpWriteDump);
REX_EXPORT_STUB(__imp__DumpXitThread);
REX_EXPORT_STUB(__imp__RtlAssert);
REX_EXPORT_STUB(__imp__RtlRaiseStatus);
REX_EXPORT_STUB(__imp__RtlRip);
