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
#include <atomic>
#include <chrono>
#include <memory>
#include <vector>

#include <rex/chrono/clock.h>
#include <rex/dbg.h>
#include <rex/kernel/xboxkrnl/private.h>
#include <rex/kernel/xboxkrnl/threading.h>
#include <rex/logging.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/system/kernel_state.h>
#include <rex/system/function_dispatcher.h>
#include <rex/system/thread_state.h>
#include <rex/system/user_module.h>
#include <rex/system/util/string_utils.h>
#include <rex/system/xevent.h>
#include <rex/system/xmutant.h>
#include <rex/system/xsemaphore.h>
#include <rex/system/xthread.h>
#include <rex/system/xtimer.h>
#include <rex/system/xtypes.h>
#include <rex/thread/atomic.h>
#include <rex/thread/mutex.h>

namespace rex::kernel::xboxkrnl {
using namespace rex::system;
using rex::runtime::current_ppc_context;

// (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-12.)
// TranslateVirtual never validates and never returns null, so a guest
// pointer + length that runs past the end of the mapping SIGSEGVs the
// host on the read. Same heap validation as A2-R3-01 (see xam_user.cpp
// for the full comment), copied here because the wait-multiple entries
// below read a guest handle array: reject a range that wraps past
// 4 GiB, starts or ends outside any heap, or spans heaps of different
// kinds (or two physical heaps); inside a single heap, require the
// pages to be accessible (readable for a source).
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

// (Hunt v1.4.6, ronda 8, A3-R8-03.) An X_ANSI_STRING guest struct
// plus the bytes it points at, and the X_OBJECT_ATTRIBUTES struct
// that carries it: the 16-byte struct first, then the name string.
// A NULL pointer means "no name", which LookupNamedObject already
// tolerates (it returns nullptr for a NULL attributes pointer).
static bool GuestAnsiStringReadable(uint32_t guest_address) {
  if (!guest_address) {
    return true;
  }
  if (!GuestRangeReadable(guest_address, sizeof(X_ANSI_STRING))) {
    return false;
  }
  auto* ansi = REX_KERNEL_MEMORY()->TranslateVirtual<const X_ANSI_STRING*>(guest_address);
  uint32_t length = ansi->length;
  if (!length) {
    return true;
  }
  uint32_t pointer = ansi->pointer;
  if (!pointer) {
    return false;
  }
  return GuestRangeReadable(pointer, length);
}

static bool GuestObjectAttributesReadable(uint32_t guest_address) {
  if (!guest_address) {
    return true;
  }
  if (!GuestRangeReadable(guest_address, sizeof(X_OBJECT_ATTRIBUTES))) {
    return false;
  }
  auto* attrs =
      REX_KERNEL_MEMORY()->TranslateVirtual<const X_OBJECT_ATTRIBUTES*>(guest_address);
  return GuestAnsiStringReadable(attrs->name_ptr);
}

// r13 + 0x100: pointer to thread local state
// Thread local state:
//   0x058: kernel time
//   0x14C: thread id
//   0x150: if >0 then error states don't get set
//   0x160: last error

// GetCurrentThreadId:
// lwz       r11, 0x100(r13)
// lwz       r3, 0x14C(r11)

// RtlGetLastError:
// lwz r11, 0x150(r13)
// if (r11 == 0) {
//   lwz r11, 0x100(r13)
//   stw r3, 0x160(r11)
// }

// RtlSetLastError:
// lwz r11, 0x150(r13)
// if (r11 == 0) {
//   lwz r11, 0x100(r13)
//   stw r3, 0x160(r11)
// }

// RtlSetLastNTError:
// r3 = RtlNtStatusToDosError(r3)
// lwz r11, 0x150(r13)
// if (r11 == 0) {
//   lwz r11, 0x100(r13)
//   stw r3, 0x160(r11)
// }

template <typename T>
object_ref<T> LookupNamedObject(KernelState* kernel_state, uint32_t obj_attributes_ptr) {
  // If the name exists and its type matches, we can return that (ref+1)
  // with a success of NAME_EXISTS.
  // If the name exists and its type doesn't match, we do NAME_COLLISION.
  // Otherwise, we add like normal.
  if (!obj_attributes_ptr) {
    return nullptr;
  }
  // (Hunt v1.4.6, ronda 8, A3-R8-03.) The attributes struct and its
  // name string are guest memory; the old code read both with only
  // the assert_true above, a no-op in Release. The NtCreate*
  // entries below reject an invalid pointer up front; this check is
  // defense in depth for future callers (nullptr here means "no
  // named object", as before).
  if (!GuestObjectAttributesReadable(obj_attributes_ptr)) {
    return nullptr;
  }
  auto obj_attributes =
      kernel_state->memory()->TranslateVirtual<X_OBJECT_ATTRIBUTES*>(obj_attributes_ptr);
  assert_true(obj_attributes->name_ptr != 0);
  auto name = util::TranslateAnsiStringAddress(kernel_state->memory(), obj_attributes->name_ptr);
  if (!name.empty()) {
    X_HANDLE handle = X_INVALID_HANDLE_VALUE;
    X_RESULT result = kernel_state->object_table()->GetObjectByName(name, &handle);
    if (XSUCCEEDED(result)) {
      // Found something! It's been retained, so return.
      auto obj = kernel_state->object_table()->LookupObject<T>(handle);
      if (obj) {
        // The caller will do as it likes.
        obj->ReleaseHandle();
        return obj;
      }
    }
  }
  return nullptr;
}

u32 ExCreateThread_entry(mapped_u32 handle_ptr, u32 stack_size, mapped_u32 thread_id_ptr,
                         u32 xapi_thread_startup, mapped_void start_address,
                         mapped_void start_context, u32 creation_flags) {
  REXKRNL_IMPORT_TRACE(
      "ExCreateThread", "stack={:#x} xapi_startup={:#x} start={:#x} context={:#x} flags={:#x}",
      (uint32_t)stack_size, (uint32_t)xapi_thread_startup, start_address.guest_address(),
      start_context.guest_address(), (uint32_t)creation_flags);
  // (Hunt v1.4.6, ronda 8, A3-R8-03.) Both out-params are written
  // on success (NULL stays allowed for either).
  if ((handle_ptr && !GuestRangeWritable(handle_ptr.guest_address(), sizeof(uint32_t))) ||
      (thread_id_ptr && !GuestRangeWritable(thread_id_ptr.guest_address(), sizeof(uint32_t)))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // http://jafile.com/uploads/scoop/main.cpp.txt
  // DWORD
  // LPHANDLE Handle,
  // DWORD    StackSize,
  // LPDWORD  ThreadId,
  // LPVOID   XapiThreadStartup, ?? often 0
  // LPVOID   StartAddress,
  // LPVOID   StartContext,
  // DWORD    CreationFlags // 0x80?

  // Determine target process based on creation flags.
  uint32_t guest_process = REX_KERNEL_STATE()->GetTitleProcess();
  if (creation_flags & 2) {
    REXKRNL_WARN("[ExCreateThread] Guest is creating a system thread!");
    guest_process = REX_KERNEL_STATE()->GetSystemProcess();
  }

  // Inherit default stack size
  uint32_t actual_stack_size = stack_size;

  if (actual_stack_size == 0) {
    actual_stack_size = REX_KERNEL_STATE()->GetExecutableModule()->stack_size();
  }

  // Stack must be aligned to 16kb pages
  actual_stack_size = std::max((uint32_t)0x4000, ((actual_stack_size + 0xFFF) & 0xFFFFF000));

  auto thread = object_ref<XThread>(new XThread(
      REX_KERNEL_STATE(), actual_stack_size, xapi_thread_startup, start_address.guest_address(),
      start_context.guest_address(), creation_flags, true, false, guest_process));

  X_STATUS result = thread->Create();
  if (XFAILED(result)) {
    // Failed!
    REXKRNL_ERROR("Thread creation failed: {:08X}", result);
    return result;
  }

  if (XSUCCEEDED(result)) {
    if (handle_ptr) {
      if (creation_flags & 0x80) {
        *handle_ptr = thread->guest_object();
      } else {
        *handle_ptr = thread->handle();
      }
    }
    if (thread_id_ptr) {
      *thread_id_ptr = thread->thread_id();
    }
  }
  REXKRNL_IMPORT_RESULT("ExCreateThread", "{:#x} handle={:#x} tid={}", result,
                        handle_ptr ? (uint32_t)*handle_ptr : 0,
                        thread_id_ptr ? (uint32_t)*thread_id_ptr : 0);
  return result;
}

u32 ExTerminateThread_entry(u32 exit_code) {
  XThread* thread = XThread::GetCurrentThread();

  // (Hunt v1.4.6, ronda 3, A3-R3-20.) GetCurrentThread() is null when
  // called from a host thread with no guest TLS (xthread.cpp); the
  // old code dereferenced it unconditionally. Guest code always runs
  // on a guest thread, so this is defence-in-depth only.
  if (!thread) {
    return X_STATUS_INVALID_HANDLE;
  }
  // NOTE: this kills us right now. We won't return from it.
  return thread->Exit(exit_code);
}

u32 NtResumeThread_entry(u32 handle, mapped_u32 suspend_count_ptr) {
  // (Hunt v1.4.6, ronda 9, A3-R9-02.) suspend_count_ptr is a 4-byte
  // out-param written below even on the invalid-handle path; a wild
  // pointer SIGSEGVs the host on a call that was going to fail
  // anyway. Fail fast, NULL stays allowed (same contract as
  // NtReleaseSemaphore, R8-03).
  if (suspend_count_ptr &&
      !GuestRangeWritable(suspend_count_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  X_RESULT result = X_STATUS_INVALID_HANDLE;
  uint32_t suspend_count = 0;

  auto thread = REX_KERNEL_OBJECTS()->LookupObject<XThread>(handle);
  if (thread) {
    REXKRNL_TRACE("[NtResumeThread] handle={:08X} thread={}", uint32_t(handle), thread->name());
    result = thread->Resume(&suspend_count);
  } else {
    REXKRNL_WARN("[NtResumeThread] handle={:08X} NOT FOUND", uint32_t(handle));
  }
  if (suspend_count_ptr) {
    *suspend_count_ptr = suspend_count;
  }

  REXKRNL_TRACE("[NtResumeThread] -> {:#x} suspend_count={}", result, suspend_count);
  return result;
}

u32 KeResumeThread_entry(mapped_void thread_ptr) {
  X_STATUS result = X_STATUS_SUCCESS;
  // (Hunt v1.4.6, ronda 9, A3-R9-04.) GetNativeObject reads the
  // dispatch header of a wild pointer with no range check (see NOTES:
  // validating inside GetNativeObject itself is unsafe because
  // HostToGuestVirtual only corrects the vE0000000 host offset, so
  // the entries validate instead, as ObOpenObjectByPointer already
  // does in R8-02). The KTHREAD is a kernel struct (0xAB0 B,
  // allocated by XThread::Create via CreateNative); Resume() touches
  // fields past the header, so validate the whole struct. NULL keeps
  // the existing INVALID_HANDLE path below.
  if (thread_ptr && !GuestRangeWritable(thread_ptr.guest_address(), sizeof(X_KTHREAD))) {
    return X_STATUS_INVALID_HANDLE;
  }
  auto thread = XObject::GetNativeObject<XThread>(REX_KERNEL_STATE(), thread_ptr);
  if (thread) {
    REXKRNL_TRACE("[KeResumeThread] ptr={:08X} thread={}", thread_ptr.guest_address(),
                  thread->name());
    result = thread->Resume();
  } else {
    REXKRNL_WARN("[KeResumeThread] ptr={:08X} NOT FOUND", thread_ptr.guest_address());
    result = X_STATUS_INVALID_HANDLE;
  }

  REXKRNL_TRACE("[KeResumeThread] -> {:#x}", result);
  return result;
}

u32 NtSuspendThread_entry(u32 handle, mapped_u32 suspend_count_ptr) {
  // (Hunt v1.4.6, ronda 9, A3-R9-02.) As in NtResumeThread_entry
  // above: 4-byte out-param, written even on the invalid-handle path.
  if (suspend_count_ptr &&
      !GuestRangeWritable(suspend_count_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  X_RESULT result = X_STATUS_SUCCESS;
  uint32_t suspend_count = 0;

  auto thread = REX_KERNEL_OBJECTS()->LookupObject<XThread>(handle);
  if (thread) {
    if (thread->type() != XObject::Type::Thread) {
      return X_STATUS_OBJECT_TYPE_MISMATCH;
    }

    auto guest_thread = thread->guest_object<X_KTHREAD>();
    if (guest_thread->terminated) {
      return X_STATUS_THREAD_IS_TERMINATING;
    }

    REXKRNL_TRACE("[NtSuspendThread] handle={:08X} thread={}", uint32_t(handle), thread->name());
#if REX_PLATFORM_LINUX || REX_PLATFORM_MAC
    auto* current_thread = XThread::GetCurrentThread();
    bool is_self_suspend = current_thread && current_thread == thread.get();
    if (is_self_suspend) {
      REXKRNL_TRACE("[NtSuspendThread] self-suspend for thread={:08X}", uint32_t(handle));
      suspend_count = thread->SelfSuspend();
      result = X_STATUS_SUCCESS;
    } else {
      result = thread->Suspend(&suspend_count);
    }
#else
    result = thread->Suspend(&suspend_count);
#endif
  } else {
    REXKRNL_WARN("[NtSuspendThread] handle={:08X} NOT FOUND", uint32_t(handle));
    result = X_STATUS_INVALID_HANDLE;
  }

  if (suspend_count_ptr) {
    *suspend_count_ptr = suspend_count;
  }

  REXKRNL_TRACE("[NtSuspendThread] -> {:#x} suspend_count={}", result, suspend_count);
  return result;
}

namespace {

void UpdateGuestStackPointers(X_KTHREAD* kthread, X_KPCR* pcr, PPCContext* ctx, uint32_t sp,
                              uint32_t stack_alloc_base, uint32_t stack_base,
                              uint32_t stack_limit) {
  kthread->stack_alloc_base = stack_alloc_base;
  kthread->stack_base = stack_base;
  kthread->stack_limit = stack_limit;
  pcr->stack_base_ptr = stack_base;
  pcr->stack_end_ptr = stack_limit;
  ctx->r1.u64 = sp;
}

}  // namespace

void KeSetCurrentStackPointers_entry(mapped_void stack_ptr, ppc_ptr_t<X_KTHREAD> thread,
                                     mapped_void stack_alloc_base, mapped_void stack_base,
                                     mapped_void stack_limit) {
  auto current_thread = XThread::GetCurrentThread();
  // (Hunt v1.4.6, ronda 3, A3-R3-08/A3-R3-20.) UpdateGuestStackPointers
  // writes through thread, and thread_state() is read off
  // current_thread -- both were dereferenced unconditionally.
  if (!thread || !current_thread) {
    return;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-09.) UpdateGuestStackPointers writes
  // the stack fields of the KTHREAD below; validate the whole struct
  // first (see A3-R9-04 for why the whole KTHREAD, not just the
  // header).
  if (!GuestRangeWritable(thread.guest_address(), sizeof(X_KTHREAD))) {
    return;
  }
  auto context = current_thread->thread_state()->context();
  uint32_t pcr_address = static_cast<uint32_t>(context->r13.u64);
  // (Hunt v1.4.6, ronda 9, A3-R9-09.) UpdateGuestStackPointers also
  // writes the PCR's stack pointers; r13 is guest-controlled, so the
  // PCR address is validated the same way xeKfRaiseIrql validates it.
  if (!GuestRangeWritable(pcr_address, sizeof(X_KPCR))) {
    return;
  }
  auto pcr = REX_KERNEL_MEMORY()->TranslateVirtual<X_KPCR*>(pcr_address);

  UpdateGuestStackPointers(thread, pcr, context, stack_ptr.guest_address(),
                           stack_alloc_base.value(), stack_base.value(), stack_limit.value());
}

u32 KeSetAffinityThread_entry(mapped_void thread_ptr, u32 affinity,
                              mapped_u32 previous_affinity_ptr) {
  // (Hunt v1.4.6, ronda 9, A3-R9-02.) previous_affinity_ptr is a
  // 4-byte out-param (see the write below); fail fast before any
  // other validation, NULL stays allowed (R8-03 contract).
  if (previous_affinity_ptr &&
      !GuestRangeWritable(previous_affinity_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-04.) As in KeResumeThread_entry
  // above: validate the whole KTHREAD before GetNativeObject reads
  // its header.
  if (thread_ptr && !GuestRangeWritable(thread_ptr.guest_address(), sizeof(X_KTHREAD))) {
    return X_STATUS_INVALID_HANDLE;
  }
  REXKRNL_IMPORT_TRACE("KeSetAffinityThread", "thread={:#x} affinity={:#x}",
                       thread_ptr.guest_address(), (uint32_t)affinity);
  // The Xbox 360, according to disassembly of KeSetAffinityThread, unlike
  // Windows NT, stores the previous affinity via the pointer provided as an
  // argument, not in the return value - the return value is used for the
  // result.
  if (!affinity) {
    return X_STATUS_INVALID_PARAMETER;
  }
  auto thread = XObject::GetNativeObject<XThread>(REX_KERNEL_STATE(), thread_ptr);
  if (!thread) {
    REXKRNL_IMPORT_WARN("KeSetAffinityThread", "invalid thread handle ptr={:#x}",
                        thread_ptr.guest_address());
    return X_STATUS_INVALID_HANDLE;
  }
  if (previous_affinity_ptr) {
    *previous_affinity_ptr = uint32_t(1) << thread->active_cpu();
  }
  thread->SetAffinity(affinity);
  REXKRNL_IMPORT_RESULT("KeSetAffinityThread", "0x0");
  return X_STATUS_SUCCESS;
}

u32 KeQueryBasePriorityThread_entry(mapped_void thread_ptr) {
  REXKRNL_IMPORT_TRACE("KeQueryBasePriorityThread", "thread={:#x}", thread_ptr.guest_address());
  int32_t priority = 0;

  // (Hunt v1.4.6, ronda 9, A3-R9-04.) As in KeResumeThread_entry
  // above: validate the whole KTHREAD before GetNativeObject reads
  // its header. The failure value is the same 0 the not-found path
  // below returns.
  if (thread_ptr && !GuestRangeWritable(thread_ptr.guest_address(), sizeof(X_KTHREAD))) {
    REXKRNL_IMPORT_RESULT("KeQueryBasePriorityThread", "{}", priority);
    return priority;
  }
  auto thread = XObject::GetNativeObject<XThread>(REX_KERNEL_STATE(), thread_ptr);
  if (thread) {
    priority = thread->QueryPriority();
  }

  REXKRNL_IMPORT_RESULT("KeQueryBasePriorityThread", "{}", priority);
  return priority;
}

u32 KeSetBasePriorityThread_entry(mapped_void thread_ptr, u32 increment) {
  REXKRNL_IMPORT_TRACE("KeSetBasePriorityThread", "thread={:#x} increment={}",
                       thread_ptr.guest_address(), (int32_t)increment);
  int32_t prev_priority = 0;
  // (Hunt v1.4.6, ronda 9, A3-R9-04.) As in KeResumeThread_entry
  // above: validate the whole KTHREAD before GetNativeObject reads
  // its header. The failure value is the same 0 the not-found path
  // below returns.
  if (thread_ptr && !GuestRangeWritable(thread_ptr.guest_address(), sizeof(X_KTHREAD))) {
    REXKRNL_IMPORT_RESULT("KeSetBasePriorityThread", "prev_priority={}", prev_priority);
    return prev_priority;
  }
  auto thread = XObject::GetNativeObject<XThread>(REX_KERNEL_STATE(), thread_ptr);

  if (thread) {
    prev_priority = thread->QueryPriority();
    thread->SetPriority(increment);
  }
  REXKRNL_IMPORT_RESULT("KeSetBasePriorityThread", "prev_priority={}", prev_priority);

  return prev_priority;
}

u32 KeSetDisableBoostThread_entry(ppc_ptr_t<X_KTHREAD> thread_ptr, u32 disabled) {
  // (Hunt v1.4.6, ronda 3, A3-R3-08.) thread_ptr->boost_disabled was
  // exchanged through the raw pointer with no check.
  if (!thread_ptr) {
    return 0;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-04.) No GetNativeObject here, but
  // the same wild-pointer hole: boost_disabled sits at offset 0xBB
  // in the KTHREAD, so a header-only check would not cover the
  // atomic exchange. Validate the whole KTHREAD (0xAB0 B).
  if (!GuestRangeWritable(thread_ptr.guest_address(), sizeof(X_KTHREAD))) {
    return 0;
  }
  auto old_boost_disabled = reinterpret_cast<std::atomic_uint8_t*>(&thread_ptr->boost_disabled)
                                ->exchange(static_cast<uint8_t>(disabled));
  return old_boost_disabled;
}

u32 KeGetCurrentProcessType_entry() {
  auto current_thread = XThread::GetCurrentThread();
  // (Hunt v1.4.6, ronda 3, A3-R3-20.) See ExTerminateThread above.
  if (!current_thread) {
    return 0;
  }
  auto context = current_thread->thread_state()->context();
  uint32_t pcr_address = static_cast<uint32_t>(context->r13.u64);
  // (Hunt v1.4.6, ronda 9, A3-R9-09.) r13 is guest-controlled; the
  // PCR is dereferenced below, so validate it the same way
  // xeKfRaiseIrql does.
  if (!GuestRangeWritable(pcr_address, sizeof(X_KPCR))) {
    return 0;
  }
  auto pcr = REX_KERNEL_MEMORY()->TranslateVirtual<X_KPCR*>(pcr_address);

  if (pcr->prcb_data.dpc_active) {
    return pcr->processtype_value_in_dpc;
  }

  // (Hunt v1.4.6, ronda 9, A3-R9-09.) current_thread is a second
  // guest-controlled pointer: it is stored in the PCR by the kernel,
  // but the guest can rewrite its own PCR. Validate the KTHREAD
  // before dereferencing its process_type.
  uint32_t current_thread_ptr = pcr->prcb_data.current_thread;
  if (!GuestRangeReadable(current_thread_ptr, sizeof(X_KTHREAD))) {
    return 0;
  }
  auto thread = REX_KERNEL_MEMORY()->TranslateVirtual<X_KTHREAD*>(current_thread_ptr);
  return thread->process_type;
}

void KeSetCurrentProcessType_entry(u32 type) {
  // One of X_PROCTYPE_?
  assert_true(type <= 2);
  // (Hunt v1.4.6, ronda 20, A3-R20-01.) The assert above is a no-op in
  // Release, and both stores below truncate: set_process_type writes
  // uint8_t(value) into title_process.process_type, and the PCR write
  // stores static_cast<uint8_t>(type) into processtype_value_in_dpc.
  // A guest passing 3+ would silently poison the process type later
  // read back by KeGetCurrentProcessType during a DPC. The contract
  // is 0 = IDLE, 1 = USER, 2 = SYSTEM (kernel_state.h:102-104); same
  // INVALID_PARAMETER class as A3-R19-04 (wait_type), but this entry
  // is void, so reject by returning early, as KeInitializeTimerEx
  // does (A3-R9-03).
  if (type > 2) {
    return;
  }

  REX_KERNEL_STATE()->set_process_type(type);

  auto current_thread = XThread::GetCurrentThread();
  // (Hunt v1.4.6, ronda 3, A3-R3-20.) See ExTerminateThread above;
  // the process type above is already set, so just skip the PCR write.
  if (!current_thread) {
    return;
  }
  auto context = current_thread->thread_state()->context();
  uint32_t pcr_address = static_cast<uint32_t>(context->r13.u64);
  // (Hunt v1.4.6, ronda 9, A3-R9-09.) r13 is guest-controlled; the
  // PCR is dereferenced below, so validate it the same way
  // xeKfRaiseIrql does. The process type in the kernel state above
  // is already set, matching the existing early return for a null
  // current thread, so only the PCR write is skipped.
  if (!GuestRangeWritable(pcr_address, sizeof(X_KPCR))) {
    return;
  }
  auto pcr = REX_KERNEL_MEMORY()->TranslateVirtual<X_KPCR*>(pcr_address);

  if (pcr->prcb_data.dpc_active) {
    pcr->processtype_value_in_dpc = static_cast<uint8_t>(type);
  }
}

u32 KeQueryPerformanceFrequency_entry() {
  uint64_t result = chrono::Clock::guest_tick_frequency();
  return static_cast<uint32_t>(result);
}

u32 KeDelayExecutionThread_entry(u32 processor_mode, u32 alertable, mapped_u64 interval_ptr) {
  XThread* thread = XThread::GetCurrentThread();

  // (Hunt v1.4.6, ronda 3, A3-R3-08/A3-R3-20.) *interval_ptr was
  // dereferenced unconditionally, and thread is null on a host thread
  // with no guest TLS.
  if (!interval_ptr) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-02.) interval_ptr is an 8-byte
  // in-param read by Delay() below; NULL is already rejected above,
  // so a non-NULL pointer must name a readable range.
  if (!GuestRangeReadable(interval_ptr.guest_address(), sizeof(uint64_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  if (!thread) {
    return X_STATUS_INVALID_HANDLE;
  }
  if (alertable) {
    thread->DeliverAPCs();
  }

  X_STATUS result = thread->Delay(processor_mode, alertable, *interval_ptr);

  if (alertable && result == X_STATUS_USER_APC) {
    thread->DeliverAPCs();
  }

  return result;
}

u32 NtYieldExecution_entry() {
  rex::thread::MaybeYield();
  return X_STATUS_SUCCESS;
}

void KeQuerySystemTime_entry(mapped_u64 time_ptr) {
  uint64_t time = chrono::Clock::QueryGuestSystemTime();
  // (Hunt v1.4.6, ronda 9, A3-R9-02.) time_ptr is an 8-byte out-param
  // written below; NULL stays allowed (no time out), as before.
  if (time_ptr && !GuestRangeWritable(time_ptr.guest_address(), sizeof(uint64_t))) {
    return;
  }
  if (time_ptr) {
    *time_ptr = time;
  }
}

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryinterrupttime
uint64_t KeQueryInterruptTime_entry() {
  // (Audit A3, ronda 6, R6-03.) Was a bare stub: the 64-bit interrupt
  // time came back as whatever the caller left in r3. Interrupt time is
  // monotonic time since the system started, in 100ns units — the guest
  // uptime clock already tracks exactly that (scaled like the rest of
  // guest time). First uint64_t-returning export in the tree; the
  // marshaling writes 64-bit returns to r3 (see HostToGuestFunction).
  return static_cast<uint64_t>(chrono::Clock::QueryGuestUptimeMillis()) * 10000u;
}

// https://msdn.microsoft.com/en-us/library/ms686801
u32 KeTlsAlloc_entry() {
  uint32_t slot = REX_KERNEL_STATE()->AllocateTLS(current_ppc_context());
  if (slot != X_TLS_OUT_OF_INDEXES) {
    // (Hunt v1.4.6, ronda 3, A3-R3-20.) See ExTerminateThread above.
    if (auto* thread = XThread::GetCurrentThread()) {
      thread->SetTLSValue(slot, 0);
    }
  }
  REXKRNL_IMPORT_RESULT("KeTlsAlloc", "slot={}", slot);
  return slot;
}

// https://msdn.microsoft.com/en-us/library/ms686804
u32 KeTlsFree_entry(u32 tls_index) {
  REXKRNL_IMPORT_TRACE("KeTlsFree", "slot={}", (uint32_t)tls_index);
  if (tls_index == X_TLS_OUT_OF_INDEXES) {
    REXKRNL_IMPORT_RESULT("KeTlsFree", "0 (invalid)");
    return 0;
  }

  REX_KERNEL_STATE()->FreeTLS(current_ppc_context(), tls_index);
  REXKRNL_IMPORT_RESULT("KeTlsFree", "1");
  return 1;
}

// https://msdn.microsoft.com/en-us/library/ms686812
u32 KeTlsGetValue_entry(u32 tls_index) {
  // xboxkrnl doesn't actually have an error branch - it always succeeds, even
  // if it overflows the TLS.
  uint32_t value = 0;
  // (Hunt v1.4.6, ronda 3, A3-R3-20.) See ExTerminateThread above.
  auto* thread = XThread::GetCurrentThread();
  if (thread && thread->GetTLSValue(tls_index, &value)) {
    return value;
  }

  return 0;
}

// https://msdn.microsoft.com/en-us/library/ms686818
u32 KeTlsSetValue_entry(u32 tls_index, u32 tls_value) {
  REXKRNL_IMPORT_TRACE("KeTlsSetValue", "slot={} value={:#x}", (uint32_t)tls_index,
                       (uint32_t)tls_value);
  // xboxkrnl doesn't actually have an error branch - it always succeeds, even
  // if it overflows the TLS.
  // (Hunt v1.4.6, ronda 3, A3-R3-20.) See ExTerminateThread above.
  auto* thread = XThread::GetCurrentThread();
  if (thread && thread->SetTLSValue(tls_index, tls_value)) {
    REXKRNL_IMPORT_RESULT("KeTlsSetValue", "1");
    return 1;
  }

  REXKRNL_IMPORT_RESULT("KeTlsSetValue", "0");
  return 0;
}

void KeInitializeMutant_entry(ppc_ptr_t<X_DISPATCH_HEADER> mutant_ptr, u32 initial_owner) {
  // (Hunt v1.4.6, ronda 4, A3-R4-05.) Was a bare stub: the guest's
  // mutant header was never initialized and no XMutant was ever
  // created for it, so any later wait/release on that address read an
  // uninitialized header. Mirrors KeInitializeEvent above; there is no
  // X_KMUTANT struct in this tree, so the parameter is the dispatch
  // header the KMUTANT starts with (DISP_TYPE_MUTANT = 2, verified
  // against the Windows DDK KMUTANT layout: Header.Type = 0x02,
  // SignalState 0 = not signaled / 1 = signaled). SignalState follows
  // the ReactOS KeInitializeMutant convention: InitialOwner ? 0 : 1.
  if (!mutant_ptr) {
    return;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-03.) The writes below span the
  // 16-byte dispatch header (Zero + type + signal_state); the sibling
  // KeInitializeSemaphore already validates its struct (R8-03).
  if (!GuestRangeWritable(mutant_ptr.guest_address(), sizeof(X_DISPATCH_HEADER))) {
    return;
  }
  mutant_ptr.Zero();
  mutant_ptr->type = 2;  // MutantObject
  mutant_ptr->signal_state = initial_owner ? 0 : 1;
  auto mutant = XObject::GetNativeObject<XMutant>(REX_KERNEL_STATE(), mutant_ptr, 2);
  if (!mutant) {
    assert_always();
    return;
  }
}

void KeInitializeEvent_entry(ppc_ptr_t<X_KEVENT> event_ptr, u32 event_type, u32 initial_state) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) Zero() is null-safe, the header
  // writes below are not.
  if (!event_ptr) {
    return;
  }
  // (Hunt v1.4.6, ronda 20, A3-R20-02.) event_type has only two values
  // (0 = NotificationEvent, 1 = SynchronizationEvent); the header.type
  // write below truncates the u32 to a u8, and GetNativeObject is then
  // called with the raw value as as_type. With event_type == 2 the
  // header is stamped MutantObject, GetNativeObject builds an XMutant,
  // and the XEvent type check (A3-R4-11) rejects it -- so the entry
  // returns having created a permanently dead event: no primitive, no
  // stashed handle, and every later Set/Pulse/Reset/Wait on that
  // address fails the same way (5 stamps a SemaphoreObject with the
  // same result). Reject up front, mirroring KeInitializeTimerEx
  // (A3-R9-03); the struct is left untouched, as if never initialized.
  if (event_type > 1) {
    return;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-03.) The writes below span the whole
  // X_KEVENT (16 B: the dispatch header); same shape as
  // KeInitializeSemaphore (R8-03).
  if (!GuestRangeWritable(event_ptr.guest_address(), sizeof(X_KEVENT))) {
    return;
  }
  event_ptr.Zero();
  event_ptr->header.type = event_type;
  event_ptr->header.signal_state = (uint32_t)initial_state;
  auto ev = XObject::GetNativeObject<XEvent>(REX_KERNEL_STATE(), event_ptr, event_type);
  if (!ev) {
    assert_always();
    return;
  }
}

uint32_t xeKeSetEvent(X_KEVENT* event_ptr, uint32_t increment, uint32_t wait) {
  auto ev = XObject::GetNativeObject<XEvent>(REX_KERNEL_STATE(), event_ptr);
  if (!ev) {
    assert_always();
    return 0;
  }

  return ev->Set(increment, !!wait);
}

u32 KeSetEvent_entry(ppc_ptr_t<X_KEVENT> event_ptr, u32 increment, u32 wait) {
  // (Hunt v1.4.6, ronda 9, A3-R9-04.) xeKeSetEvent below hands the
  // pointer straight to GetNativeObject, which reads the dispatch
  // header (and StashHandle writes it on first use). Validate the
  // whole X_KEVENT here, where the guest address is known; the other
  // xeKeSetEvent caller (ExReleaseReadWriteLock) passes a member of
  // an ERWLOCK validated whole by A3-R9-08.
  if (event_ptr && !GuestRangeWritable(event_ptr.guest_address(), sizeof(X_KEVENT))) {
    return 0;
  }
  return xeKeSetEvent(event_ptr, increment, wait);
}

u32 KePulseEvent_entry(ppc_ptr_t<X_KEVENT> event_ptr, u32 increment, u32 wait) {
  // (Hunt v1.4.6, ronda 9, A3-R9-04.) As in KeSetEvent_entry above.
  if (event_ptr && !GuestRangeWritable(event_ptr.guest_address(), sizeof(X_KEVENT))) {
    return 0;
  }
  auto ev = XObject::GetNativeObject<XEvent>(REX_KERNEL_STATE(), event_ptr);
  if (!ev) {
    assert_always();
    return 0;
  }

  return ev->Pulse(increment, !!wait);
}

u32 KeResetEvent_entry(ppc_ptr_t<X_KEVENT> event_ptr) {
  // (Hunt v1.4.6, ronda 9, A3-R9-04.) As in KeSetEvent_entry above.
  if (event_ptr && !GuestRangeWritable(event_ptr.guest_address(), sizeof(X_KEVENT))) {
    return 0;
  }
  auto ev = XObject::GetNativeObject<XEvent>(REX_KERNEL_STATE(), event_ptr);
  if (!ev) {
    assert_always();
    return 0;
  }

  return ev->Reset();
}

u32 NtCreateEvent_entry(mapped_u32 handle_ptr, ppc_ptr_t<X_OBJECT_ATTRIBUTES> obj_attributes_ptr,
                        u32 event_type, u32 initial_state) {
  // (Hunt v1.4.6, ronda 8, A3-R8-03.) handle_ptr is written on
  // every success path below (NULL stays allowed: no handle out);
  // obj_attributes is read by LookupNamedObject and SetAttributes.
  if (handle_ptr && !GuestRangeWritable(handle_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  if (!GuestObjectAttributesReadable(obj_attributes_ptr.guest_address())) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // Check for an existing timer with the same name.
  auto existing_object =
      LookupNamedObject<XEvent>(REX_KERNEL_STATE(), obj_attributes_ptr.guest_address());
  if (existing_object) {
    if (existing_object->type() == XObject::Type::Event) {
      if (handle_ptr) {
        existing_object->RetainHandle();
        *handle_ptr = existing_object->handle();
      }
      return X_STATUS_OBJECT_NAME_EXISTS;
    } else {
      return X_STATUS_INVALID_HANDLE;
    }
  }

  auto ev = object_ref<XEvent>(new XEvent(REX_KERNEL_STATE()));
  ev->Initialize(!event_type, !!initial_state);

  // obj_attributes may have a name inside of it, if != NULL.
  if (obj_attributes_ptr) {
    ev->SetAttributes(obj_attributes_ptr.guest_address());
  }

  if (handle_ptr) {
    *handle_ptr = ev->handle();
  }
  return X_STATUS_SUCCESS;
}

uint32_t xeNtSetEvent(uint32_t handle, rex::be<uint32_t>* previous_state_ptr) {
  X_STATUS result = X_STATUS_SUCCESS;

  auto ev = REX_KERNEL_OBJECTS()->LookupObject<XEvent>(handle);
  if (ev) {
    int32_t was_signalled = ev->Set(0, false);
    if (previous_state_ptr) {
      *previous_state_ptr = static_cast<uint32_t>(was_signalled);
    }
  } else {
    result = X_STATUS_INVALID_HANDLE;
  }

  return result;
}

u32 NtSetEvent_entry(u32 handle, mapped_u32 previous_state_ptr) {
  // (Hunt v1.4.6, ronda 9, A3-R9-02.) previous_state_ptr is a 4-byte
  // out-param written by xeNtSetEvent below when the handle is valid.
  // Validated here, where the guest address is still known (the
  // callee only sees the translated host pointer); NULL stays
  // allowed (R8-03 contract).
  if (previous_state_ptr &&
      !GuestRangeWritable(previous_state_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  return xeNtSetEvent(handle, previous_state_ptr);
}

u32 NtPulseEvent_entry(u32 handle, mapped_u32 previous_state_ptr) {
  // (Hunt v1.4.6, ronda 9, A3-R9-02.) As in NtSetEvent_entry above:
  // 4-byte out-param, written below when the handle is valid.
  if (previous_state_ptr &&
      !GuestRangeWritable(previous_state_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  X_STATUS result = X_STATUS_SUCCESS;

  auto ev = REX_KERNEL_OBJECTS()->LookupObject<XEvent>(handle);
  if (ev) {
    int32_t was_signalled = ev->Pulse(0, false);
    if (previous_state_ptr) {
      *previous_state_ptr = static_cast<uint32_t>(was_signalled);
    }
  } else {
    result = X_STATUS_INVALID_HANDLE;
  }

  return result;
}

uint32_t xeNtClearEvent(uint32_t handle) {
  X_STATUS result = X_STATUS_SUCCESS;

  auto ev = REX_KERNEL_OBJECTS()->LookupObject<XEvent>(handle);
  if (ev) {
    ev->Reset();
  } else {
    result = X_STATUS_INVALID_HANDLE;
  }

  return result;
}

u32 NtClearEvent_entry(u32 handle) {
  return xeNtClearEvent(handle);
}

// https://msdn.microsoft.com/en-us/library/windows/hardware/ff552150(v=vs.85).aspx
void KeInitializeSemaphore_entry(ppc_ptr_t<X_KSEMAPHORE> semaphore_ptr, u32 count, u32 limit) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) The header/limit writes below
  // dereference semaphore_ptr with no check.
  if (!semaphore_ptr) {
    return;
  }
  // (Hunt v1.4.6, ronda 20, A3-R20-03.) Semaphore::Create
  // (threading_posix.cpp) refuses initial_count < 0, initial_count >
  // maximum_count and maximum_count <= 0 (signed ints), so
  // InitializeNative leaves semaphore_ null and GetNativeObject still
  // hands out the wrapper (A3-R8-09): waits fail via the null handle
  // and releases are no-ops -- a permanently dead semaphore.
  // NtCreateSemaphore already rejects this through Initialize's false
  // return (A3-R4-04 class); this void entry cannot report failure,
  // so refuse the values here instead, mirroring KeInitializeTimerEx
  // (A3-R9-03). The signed casts mirror Create's condition exactly: a
  // u32 count/limit with bit 31 set converts to a negative int.
  if (static_cast<int32_t>(limit) <= 0 || static_cast<int32_t>(count) < 0 ||
      static_cast<int32_t>(count) > static_cast<int32_t>(limit)) {
    return;
  }
  // (Hunt v1.4.6, ronda 8, A3-R8-03.) The three writes below span
  // sizeof(X_KSEMAPHORE) (20 B: header type/signal_state at +0/+4
  // and limit at +0x10), not just the 12 bytes written.
  if (!GuestRangeWritable(semaphore_ptr.guest_address(), sizeof(X_KSEMAPHORE))) {
    return;
  }
  semaphore_ptr->header.type = 5;  // SemaphoreObject
  semaphore_ptr->header.signal_state = (uint32_t)count;
  semaphore_ptr->limit = (uint32_t)limit;

  auto sem = XObject::GetNativeObject<XSemaphore>(REX_KERNEL_STATE(), semaphore_ptr,
                                                  5 /* SemaphoreObject */);
  if (!sem) {
    assert_always();
    return;
  }
}

uint32_t xeKeReleaseSemaphore(X_KSEMAPHORE* semaphore_ptr, uint32_t increment, uint32_t adjustment,
                              uint32_t wait) {
  auto sem = XObject::GetNativeObject<XSemaphore>(REX_KERNEL_STATE(), semaphore_ptr);
  if (!sem) {
    assert_always();
    return 0;
  }

  // TODO(benvanik): increment thread priority?
  // TODO(benvanik): wait?

  int32_t previous_count = 0;
  [[maybe_unused]] bool success =
      sem->ReleaseSemaphore(static_cast<int32_t>(adjustment), &previous_count);
  return static_cast<uint32_t>(previous_count);
}

u32 KeReleaseSemaphore_entry(ppc_ptr_t<X_KSEMAPHORE> semaphore_ptr, u32 increment, u32 adjustment,
                             u32 wait) {
  // (Hunt v1.4.6, ronda 9, A3-R9-04.) xeKeReleaseSemaphore below hands
  // the pointer straight to GetNativeObject; validate the whole
  // X_KSEMAPHORE here, where the guest address is known. The other
  // xeKeReleaseSemaphore caller (ExReleaseReadWriteLock) passes a
  // member of an ERWLOCK validated whole by A3-R9-08.
  if (semaphore_ptr &&
      !GuestRangeWritable(semaphore_ptr.guest_address(), sizeof(X_KSEMAPHORE))) {
    return 0;
  }
  return xeKeReleaseSemaphore(semaphore_ptr, increment, adjustment, wait);
}

u32 NtCreateSemaphore_entry(mapped_u32 handle_ptr, mapped_void obj_attributes_ptr, u32 count,
                            u32 limit) {
  // (Hunt v1.4.6, ronda 8, A3-R8-03.) See NtCreateEvent above.
  if (handle_ptr && !GuestRangeWritable(handle_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  if (!GuestObjectAttributesReadable(obj_attributes_ptr.guest_address())) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // Check for an existing semaphore with the same name.
  auto existing_object =
      LookupNamedObject<XSemaphore>(REX_KERNEL_STATE(), obj_attributes_ptr.guest_address());
  if (existing_object) {
    if (existing_object->type() == XObject::Type::Semaphore) {
      if (handle_ptr) {
        existing_object->RetainHandle();
        *handle_ptr = existing_object->handle();
      }
      return X_STATUS_OBJECT_NAME_EXISTS;
    } else {
      return X_STATUS_INVALID_HANDLE;
    }
  }

  auto sem = object_ref<XSemaphore>(new XSemaphore(REX_KERNEL_STATE()));
  if (!sem->Initialize((int32_t)count, (int32_t)limit)) {
    if (handle_ptr) {
      *handle_ptr = 0;
    }
    sem->ReleaseHandle();
    return X_STATUS_INVALID_PARAMETER;
  }

  // obj_attributes may have a name inside of it, if != NULL.
  if (obj_attributes_ptr) {
    sem->SetAttributes(obj_attributes_ptr.guest_address());
  }

  if (handle_ptr) {
    *handle_ptr = sem->handle();
  }

  return X_STATUS_SUCCESS;
}

u32 NtReleaseSemaphore_entry(u32 sem_handle, u32 release_count, mapped_u32 previous_count_ptr) {
  // (Hunt v1.4.6, ronda 8, A3-R8-03.) previous_count_ptr is written
  // on every path below, including the invalid-handle path (which
  // used to write 0 through a wild pointer before failing). Fail
  // fast: no release happens on an invalid out-pointer.
  if (previous_count_ptr &&
      !GuestRangeWritable(previous_count_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  X_STATUS result = X_STATUS_SUCCESS;
  int32_t previous_count = 0;

  auto sem = REX_KERNEL_OBJECTS()->LookupObject<XSemaphore>(sem_handle);
  if (sem) {
    bool success = sem->ReleaseSemaphore(static_cast<int32_t>(release_count), &previous_count);
    if (!success) {
      result = X_STATUS_SEMAPHORE_LIMIT_EXCEEDED;
    }
  } else {
    result = X_STATUS_INVALID_HANDLE;
  }
  if (previous_count_ptr) {
    *previous_count_ptr = (uint32_t)previous_count;
  }

  return result;
}

u32 NtCreateMutant_entry(mapped_u32 handle_out, ppc_ptr_t<X_OBJECT_ATTRIBUTES> obj_attributes,
                         u32 initial_owner) {
  // (Hunt v1.4.6, ronda 8, A3-R8-03.) See NtCreateEvent above.
  if (handle_out && !GuestRangeWritable(handle_out.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  if (!GuestObjectAttributesReadable(obj_attributes.guest_address())) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // Check for an existing timer with the same name.
  auto existing_object =
      LookupNamedObject<XMutant>(REX_KERNEL_STATE(), obj_attributes.guest_address());
  if (existing_object) {
    if (existing_object->type() == XObject::Type::Mutant) {
      if (handle_out) {
        existing_object->RetainHandle();
        *handle_out = existing_object->handle();
      }
      return X_STATUS_OBJECT_NAME_EXISTS;
    } else {
      return X_STATUS_INVALID_HANDLE;
    }
  }

  auto mutant = object_ref<XMutant>(new XMutant(REX_KERNEL_STATE()));
  mutant->Initialize(initial_owner ? true : false);

  // obj_attributes may have a name inside of it, if != NULL.
  if (obj_attributes) {
    mutant->SetAttributes(obj_attributes.guest_address());
  }

  if (handle_out) {
    *handle_out = mutant->handle();
  }

  return X_STATUS_SUCCESS;
}

u32 NtReleaseMutant_entry(u32 mutant_handle, u32 unknown) {
  // This doesn't seem to be supported.
  // int32_t previous_count_ptr = SHIM_GET_ARG_32(2);

  // Whatever arg 1 is all games seem to set it to 0, so whether it's
  // abandon or wait we just say false. Which is good, cause they are
  // both ignored.
  assert_zero(unknown);
  uint32_t priority_increment = 0;
  bool abandon = false;
  bool wait = false;

  X_STATUS result = X_STATUS_SUCCESS;

  auto mutant = REX_KERNEL_OBJECTS()->LookupObject<XMutant>(mutant_handle);
  if (mutant) {
    result = mutant->ReleaseMutant(priority_increment, abandon, wait);
  } else {
    result = X_STATUS_INVALID_HANDLE;
  }

  return result;
}

u32 NtCreateTimer_entry(mapped_u32 handle_ptr, mapped_void obj_attributes_ptr, u32 timer_type) {
  // timer_type = NotificationTimer (0) or SynchronizationTimer (1)
  // (Hunt v1.4.6, ronda 4, A3-R4-04.) Anything else used to leave the
  // timer primitive null (XTimer::Initialize only handles 0/1), and
  // NtSetTimerEx/NtCancelTimer then dereferenced it. Reject up front;
  // assert_true alone is a no-op in Release.
  if (timer_type > 1) {
    return X_STATUS_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, ronda 8, A3-R8-03.) See NtCreateEvent above.
  if (handle_ptr && !GuestRangeWritable(handle_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  if (!GuestObjectAttributesReadable(obj_attributes_ptr.guest_address())) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // Check for an existing timer with the same name.
  auto existing_object =
      LookupNamedObject<XTimer>(REX_KERNEL_STATE(), obj_attributes_ptr.guest_address());
  if (existing_object) {
    if (existing_object->type() == XObject::Type::Timer) {
      if (handle_ptr) {
        existing_object->RetainHandle();
        *handle_ptr = existing_object->handle();
      }
      return X_STATUS_OBJECT_NAME_EXISTS;
    } else {
      return X_STATUS_INVALID_HANDLE;
    }
  }

  auto timer = object_ref<XTimer>(new XTimer(REX_KERNEL_STATE()));
  // (Hunt v1.4.6, ronda 4, A3-R4-04.) Initialize reports failure
  // instead of leaving timer_ null; drop the half-created object
  // (mirrors NtCreateSemaphore) rather than handing out a handle to
  // a timer that can never fire.
  if (!timer->Initialize(timer_type)) {
    timer->ReleaseHandle();
    return X_STATUS_INVALID_PARAMETER;
  }

  // obj_attributes may have a name inside of it, if != NULL.
  if (obj_attributes_ptr) {
    timer->SetAttributes(obj_attributes_ptr.guest_address());
  }

  if (handle_ptr) {
    *handle_ptr = timer->handle();
  }

  return X_STATUS_SUCCESS;
}

void KeInitializeTimerEx_entry(ppc_ptr_t<X_KTIMER> timer_ptr, u32 timer_type, u32 proc_type) {
  assert_true(timer_type == 0 || timer_type == 1);
  assert_true(proc_type < 3);
  // (Hunt v1.4.6, ronda 9, A3-R9-03.) The asserts above are no-ops in
  // Release: a timer_type >= 2 used to write header.type = type + 8
  // (an object type that does not exist) and a proc_type >= 3 was
  // truncated into the header. Reject with the same criterion
  // NtCreateTimer_entry already enforces for timer_type (> 1), plus
  // the proc_type < 3 bound the assert states.
  if (timer_type > 1 || proc_type >= 3) {
    return;
  }
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) Every write below dereferences
  // timer_ptr with no check.
  if (!timer_ptr) {
    return;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-03.) The writes below span the whole
  // X_KTIMER (0x28 B: header + due_time + period).
  if (!GuestRangeWritable(timer_ptr.guest_address(), sizeof(X_KTIMER))) {
    return;
  }
  // Other fields are unmodified; they must carry through multiple calls.
  timer_ptr->header.process_type = static_cast<uint8_t>(proc_type & 0xFF);
  timer_ptr->header.inserted = 0;
  timer_ptr->header.type = static_cast<uint8_t>(timer_type + 8);
  timer_ptr->header.signal_state = 0;
  // Initialize wait list to point to itself (empty list).
  uint32_t wait_list_addr =
      timer_ptr.guest_address() + offsetof(X_DISPATCH_HEADER, wait_list_flink);
  timer_ptr->header.wait_list_flink = wait_list_addr;
  timer_ptr->header.wait_list_blink = wait_list_addr;
  timer_ptr->due_time = 0;
  timer_ptr->period = 0;
}

u32 NtSetTimerEx_entry(u32 timer_handle, mapped_u64 due_time_ptr,
                       mapped_void routine_ptr /*PTIMERAPCROUTINE*/, u32 unk_one,
                       mapped_void routine_arg, u32 resume, u32 period_ms, u32 unk_zero) {
  assert_true(unk_one == 1);
  assert_true(unk_zero == 0);

  // (Hunt v1.4.6, ronda 3, A3-R3-08.) due_time_ptr was dereferenced
  // before the timer handle was even looked up.
  if (!due_time_ptr) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-02.) due_time_ptr is an 8-byte
  // in-param read below; NULL is already rejected above, so a
  // non-NULL pointer must name a readable range.
  if (!GuestRangeReadable(due_time_ptr.guest_address(), sizeof(uint64_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  uint64_t due_time = *due_time_ptr;

  X_STATUS result = X_STATUS_SUCCESS;

  auto timer = REX_KERNEL_OBJECTS()->LookupObject<XTimer>(timer_handle);
  if (timer) {
    result = timer->SetTimer(due_time, period_ms, routine_ptr.guest_address(),
                             routine_arg.guest_address(), resume ? true : false);
  } else {
    result = X_STATUS_INVALID_HANDLE;
  }

  return result;
}

u32 NtCancelTimer_entry(u32 timer_handle, mapped_u32 current_state_ptr) {
  // (Hunt v1.4.6, ronda 9, A3-R9-02.) current_state_ptr is a 4-byte
  // out-param written below even on the invalid-handle path; fail
  // fast, NULL stays allowed (same contract as NtReleaseSemaphore,
  // R8-03).
  if (current_state_ptr &&
      !GuestRangeWritable(current_state_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  X_STATUS result = X_STATUS_SUCCESS;

  auto timer = REX_KERNEL_OBJECTS()->LookupObject<XTimer>(timer_handle);
  if (timer) {
    result = timer->Cancel();
  } else {
    result = X_STATUS_INVALID_HANDLE;
  }
  if (current_state_ptr) {
    *current_state_ptr = 0;
  }

  return result;
}

uint32_t xeKeWaitForSingleObject(void* object_ptr, uint32_t wait_reason, uint32_t processor_mode,
                                 uint32_t alertable, uint64_t* timeout_ptr) {
  auto object = XObject::GetNativeObject<XObject>(REX_KERNEL_STATE(), object_ptr);

  if (!object) {
    // The only kind-of failure code (though this should never happen)
    assert_always();
    return X_STATUS_ABANDONED_WAIT_0;
  }

  X_STATUS result = object->Wait(wait_reason, processor_mode, alertable, timeout_ptr);

  if (alertable && result == X_STATUS_USER_APC) {
    // (Hunt v1.4.6, ronda 3, A3-R3-20.) GetCurrentThread() is null
    // on a host thread with no guest TLS; DeliverAPCs only when there is one.
    if (auto* current_thread = XThread::GetCurrentThread()) current_thread->DeliverAPCs();
  }

  return result;
}

u32 KeWaitForSingleObject_entry(mapped_void object_ptr, u32 wait_reason, u32 processor_mode,
                                u32 alertable, mapped_u64 timeout_ptr) {
  // (Hunt v1.4.6, ronda 9, A3-R9-01.) timeout_ptr is dereferenced
  // below with only a NULL check; a wild pointer SIGSEGVs the host
  // on the read. NULL stays allowed (infinite wait), as before.
  if (timeout_ptr && !GuestRangeReadable(timeout_ptr.guest_address(), sizeof(uint64_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-04.) object_ptr names an object of
  // unknown type; xeKeWaitForSingleObject below hands it straight to
  // GetNativeObject, which reads the dispatch header (and StashHandle
  // writes it on first use). Validate at least the header here.
  if (object_ptr && !GuestRangeWritable(object_ptr.guest_address(), sizeof(X_DISPATCH_HEADER))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  uint64_t timeout = timeout_ptr ? static_cast<uint64_t>(*timeout_ptr) : 0u;
  // REXKRNL_IMPORT_TRACE("KeWaitForSingleObject", "obj={:#x} reason={} mode={} alertable={}
  // timeout={}",
  // object_ptr.guest_address(), (uint32_t)wait_reason,
  //(uint32_t)processor_mode, (uint32_t)alertable,
  // timeout_ptr ? (int64_t)timeout : -1);
  auto result = xeKeWaitForSingleObject(object_ptr, wait_reason, processor_mode, alertable,
                                        timeout_ptr ? &timeout : nullptr);
  // REXKRNL_IMPORT_RESULT("KeWaitForSingleObject", "{:#x}", result);
  return result;
}

u32 NtWaitForSingleObjectEx_entry(u32 object_handle, u32 wait_mode, u32 alertable,
                                  mapped_u64 timeout_ptr) {
  // (Hunt v1.4.6, ronda 9, A3-R9-01.) As in KeWaitForSingleObject_entry
  // above: fail fast on a wild timeout pointer, before the handle
  // lookup (same fail-fast contract as NtReleaseSemaphore, R8-03).
  if (timeout_ptr && !GuestRangeReadable(timeout_ptr.guest_address(), sizeof(uint64_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  X_STATUS result = X_STATUS_SUCCESS;

  auto object = REX_KERNEL_OBJECTS()->LookupObject<XObject>(object_handle);
  if (object) {
    uint64_t timeout = timeout_ptr ? static_cast<uint64_t>(*timeout_ptr) : 0u;
    result = object->Wait(3, wait_mode, alertable, timeout_ptr ? &timeout : nullptr);
    if (alertable && result == X_STATUS_USER_APC) {
      // (Hunt v1.4.6, ronda 3, A3-R3-20.) GetCurrentThread() is null
      // on a host thread with no guest TLS; DeliverAPCs only when there is one.
      if (auto* current_thread = XThread::GetCurrentThread()) current_thread->DeliverAPCs();
    }
  } else {
    result = X_STATUS_INVALID_HANDLE;
  }

  return result;
}

u32 KeWaitForMultipleObjects_entry(u32 count, mapped_u32 objects_ptr, u32 wait_type,
                                   u32 wait_reason, u32 processor_mode, u32 alertable,
                                   mapped_u64 timeout_ptr, mapped_void wait_block_array_ptr) {
  assert_true(wait_type <= 1);
  // (Hunt v1.4.6, ronda 19, A3-R19-04.) The assert above is a no-op in
  // Release, and WaitMultiple treats any nonzero wait_type as WaitAny:
  // a guest passing 2+ silently got WaitAny instead of an error. The
  // contract is 0 = WaitAll, 1 = WaitAny (same bound the assert
  // states, same INVALID_PARAMETER the count > 64 check returns).
  if (wait_type > 1) {
    return X_STATUS_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, ronda 3, A3-R3-13.) objects_ptr was dereferenced
  // with no null check, and count was uncapped: a guest array
  // repeating one valid handle grew the host vector without limit.
  // 64 is MAXIMUM_WAIT_OBJECTS on Xbox, the same cap the WSA wrapper
  // in xam_net.cpp already enforces.
  if (!objects_ptr) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // (Hunt v1.4.6, ronda 20, A3-R20-07.) count == 0 used to fall
  // through to WaitMultiple with an empty vector: WaitAll returns
  // instant SUCCESS on zero handles (vacuous truth), while WaitAny
  // sleeps on the shared multi-wait channel until a deadline that
  // never comes with an infinite timeout -- an effective hang, since
  // no handle can ever signal it. ReactOS NtWaitForMultipleObjects
  // rejects it the same way (0 == ObjectCount ->
  // STATUS_INVALID_PARAMETER). Same bound as the count > 64 check
  // next to it.
  if (!count) {
    return X_STATUS_INVALID_PARAMETER;
  }
  if (count > 64) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-12.)
  // Same shape as FE-04 (WSASendTo): the count is capped at 64 above,
  // but the objects array itself (count * 4 bytes) was never
  // range-validated -- the loop below reads objects_ptr[n] for
  // n < count. An array crossing the end of the mapping SIGSEGVs the
  // host on that read. The cap above bounds the validated length to
  // 256 bytes, so it cannot overflow. Validated here, in the entry
  // that still knows the guest address: xeNtWaitForMultipleObjectsEx
  // below only receives the translated host pointer.
  if (count && !GuestRangeReadable(objects_ptr.guest_address(),
                                   static_cast<size_t>(count) * sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  std::vector<object_ref<XObject>> objects;
  for (uint32_t n = 0; n < count; n++) {
    // (Hunt v1.4.6, ronda 9, A3-R9-04.) Each element is a guest object
    // pointer read from the array validated above; GetNativeObject
    // reads its dispatch header, so validate the header per element.
    if (!GuestRangeWritable(objects_ptr[n], sizeof(X_DISPATCH_HEADER))) {
      return X_STATUS_INVALID_PARAMETER;
    }
    auto object_ptr = REX_KERNEL_MEMORY()->TranslateVirtual(objects_ptr[n]);
    auto object_ref = XObject::GetNativeObject<XObject>(REX_KERNEL_STATE(), object_ptr);
    if (!object_ref) {
      return X_STATUS_INVALID_PARAMETER;
    }

    objects.push_back(std::move(object_ref));
  }

  // (Hunt v1.4.6, ronda 9, A3-R9-01.) As in KeWaitForSingleObject_entry
  // above: the timeout is read below with only a NULL check.
  if (timeout_ptr && !GuestRangeReadable(timeout_ptr.guest_address(), sizeof(uint64_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  uint64_t timeout = timeout_ptr ? static_cast<uint64_t>(*timeout_ptr) : 0u;
  X_STATUS result = XObject::WaitMultiple(
      uint32_t(objects.size()), reinterpret_cast<XObject**>(objects.data()), wait_type, wait_reason,
      processor_mode, alertable, timeout_ptr ? &timeout : nullptr);
  if (alertable && result == X_STATUS_USER_APC) {
    // (Hunt v1.4.6, ronda 3, A3-R3-20.) GetCurrentThread() is null
    // on a host thread with no guest TLS; DeliverAPCs only when there is one.
    if (auto* current_thread = XThread::GetCurrentThread()) current_thread->DeliverAPCs();
  }
  return result;
}

uint32_t xeNtWaitForMultipleObjectsEx(uint32_t count, rex::be<uint32_t>* handles,
                                      uint32_t wait_type, uint32_t wait_mode, uint32_t alertable,
                                      uint64_t* timeout_ptr) {
  assert_true(wait_type <= 1);
  // (Hunt v1.4.6, ronda 19, A3-R19-04.) The assert above is a no-op in
  // Release, and WaitMultiple treats any nonzero wait_type as WaitAny:
  // a guest passing 2+ silently got WaitAny instead of an error. The
  // contract is 0 = WaitAll, 1 = WaitAny (same bound the assert
  // states, same INVALID_PARAMETER the count > 64 check returns).
  if (wait_type > 1) {
    return X_STATUS_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, ronda 3, A3-R3-13.) As in
  // KeWaitForMultipleObjects_entry above: handles was unchecked and
  // count uncapped. This is also the callee of
  // NetDll_WSAWaitForMultipleEvents (which caps at 64 already) and
  // NtWaitForMultipleObjectsEx.
  if (!handles) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // (Hunt v1.4.6, ronda 20, A3-R20-07.) As in
  // KeWaitForMultipleObjects_entry above: count == 0 must not reach
  // WaitMultiple. This is also the choke point for
  // NtWaitForMultipleObjectsEx_entry and for
  // NetDll_WSAWaitForMultipleEvents (which maps the failure through
  // RtlNtStatusToDosError to ERROR_INVALID_PARAMETER, the correct
  // Winsock answer for 0 events).
  if (!count) {
    return X_STATUS_INVALID_PARAMETER;
  }
  if (count > 64) {
    return X_STATUS_INVALID_PARAMETER;
  }
  std::vector<object_ref<XObject>> objects;
  for (uint32_t n = 0; n < count; n++) {
    uint32_t object_handle = handles[n];
    auto object = REX_KERNEL_OBJECTS()->LookupObject<XObject>(object_handle);
    if (!object) {
      return X_STATUS_INVALID_PARAMETER;
    }
    objects.push_back(std::move(object));
  }

  auto result = XObject::WaitMultiple(count, reinterpret_cast<XObject**>(objects.data()), wait_type,
                                      6, wait_mode, alertable, timeout_ptr);
  if (alertable && result == X_STATUS_USER_APC) {
    // (Hunt v1.4.6, ronda 3, A3-R3-20.) GetCurrentThread() is null
    // on a host thread with no guest TLS; DeliverAPCs only when there is one.
    if (auto* current_thread = XThread::GetCurrentThread()) current_thread->DeliverAPCs();
  }
  return result;
}

u32 NtWaitForMultipleObjectsEx_entry(u32 count, mapped_u32 handles, u32 wait_type, u32 wait_mode,
                                     u32 alertable, mapped_u64 timeout_ptr) {
  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-12.)
  // Same as KeWaitForMultipleObjects_entry above and the WSA wrapper in
  // xam_net.cpp: the count is capped at 64 inside
  // xeNtWaitForMultipleObjectsEx, but the handles array itself was never
  // range-validated. Validate it here, where the guest address is still
  // known, before the callee reads handles[n]. count == 0 with a NULL
  // handles is already rejected inside the callee; a NULL handles with
  // count > 0 fails the range check below (guest address 0 is not a
  // readable range).
  if (count && !GuestRangeReadable(handles.guest_address(),
                                   static_cast<size_t>(count) * sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-01.) As in KeWaitForSingleObject_entry
  // above: the timeout is read below with only a NULL check.
  if (timeout_ptr && !GuestRangeReadable(timeout_ptr.guest_address(), sizeof(uint64_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  uint64_t timeout = timeout_ptr ? static_cast<uint64_t>(*timeout_ptr) : 0u;
  return xeNtWaitForMultipleObjectsEx(count, handles, wait_type, wait_mode, alertable,
                                      timeout_ptr ? &timeout : nullptr);
}

u32 NtSignalAndWaitForSingleObjectEx_entry(u32 signal_handle, u32 wait_handle, u32 alertable,
                                           u32 r6, mapped_u64 timeout_ptr) {
  // (Hunt v1.4.6, ronda 9, A3-R9-01.) As in KeWaitForSingleObject_entry
  // above: fail fast on a wild timeout pointer, before the handle
  // lookups (same fail-fast contract as NtReleaseSemaphore, R8-03).
  if (timeout_ptr && !GuestRangeReadable(timeout_ptr.guest_address(), sizeof(uint64_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  X_STATUS result = X_STATUS_SUCCESS;

  auto signal_object = REX_KERNEL_OBJECTS()->LookupObject<XObject>(signal_handle);
  auto wait_object = REX_KERNEL_OBJECTS()->LookupObject<XObject>(wait_handle);
  if (signal_object && wait_object) {
    uint64_t timeout = timeout_ptr ? static_cast<uint64_t>(*timeout_ptr) : 0u;
    result = XObject::SignalAndWait(signal_object.get(), wait_object.get(), 3, 1, alertable,
                                    timeout_ptr ? &timeout : nullptr);
  } else {
    result = X_STATUS_INVALID_HANDLE;
  }

  if (alertable && result == X_STATUS_USER_APC) {
    // (Hunt v1.4.6, ronda 3, A3-R3-20.) GetCurrentThread() is null
    // on a host thread with no guest TLS; DeliverAPCs only when there is one.
    if (auto* current_thread = XThread::GetCurrentThread()) current_thread->DeliverAPCs();
  }

  return result;
}

// Guest-memory IRQL helpers - read/write current_irql directly from PCR.
// Take PPCContext* explicitly so they work from any thread (including host threads
// during InitializeGuestObject, dispatch thread creation, etc.).
// (Hunt v1.4.6, ronda 9, A3-R9-09.) r13 is a guest-controlled GPR, and
// the PCR it names is dereferenced below with no check. The PCR is
// allocated by XThread::Create in the system heap (0x2D8 B, committed
// read/write, v00000000), so a real PCR always passes
// GuestRangeWritable(sizeof(X_KPCR)); anything else is not a PCR and
// the write is skipped instead of SIGSEGVing the host. Validating
// here (rather than caching the host PCR pointer in ThreadState) is
// the smaller change: the PCR host pointer already lives in the
// per-thread ThreadState, but every site below re-derives it from
// r13, and the cached pointer would still have to be plumbed through
// the PPCContext* callers that have no ThreadState (host threads).
// Raise returns IRQL_PASSIVE (0) when there is no PCR to read an old
// IRQL from; the spinlock itself still works, only the IRQL
// bookkeeping is skipped.
static unsigned char xeKfRaiseIrql(PPCContext* ctx, unsigned char new_irql) {
  auto* mem = rex::system::kernel_state()->memory();
  uint32_t pcr_address = static_cast<uint32_t>(ctx->r13.u64);
  if (!GuestRangeWritable(pcr_address, sizeof(X_KPCR))) {
    return 0;
  }
  auto pcr = mem->TranslateVirtual<X_KPCR*>(pcr_address);
  uint8_t old_irql = pcr->current_irql;
  pcr->current_irql = new_irql;
  return old_irql;
}

static void xeKfLowerIrql(PPCContext* ctx, unsigned char new_irql) {
  auto* mem = rex::system::kernel_state()->memory();
  uint32_t pcr_address = static_cast<uint32_t>(ctx->r13.u64);
  if (!GuestRangeWritable(pcr_address, sizeof(X_KPCR))) {
    return;
  }
  auto pcr = mem->TranslateVirtual<X_KPCR*>(pcr_address);
  pcr->current_irql = new_irql;
}

// Guest-memory spinlock helpers - store PCR address as owner (matching xenia).
// PPCContext* provides r13 (PCR address) without needing XThread::GetCurrentThread().
uint32_t xeKeKfAcquireSpinLock(PPCContext* ctx, X_KSPINLOCK* lock, bool change_irql) {
  uint32_t old_irql = change_irql ? xeKfRaiseIrql(ctx, IRQL_DISPATCH) : 0;
  uint32_t pcr_addr = static_cast<uint32_t>(ctx->r13.u64);
  const uint32_t self = rex::byte_swap(pcr_addr);
  assert_true(lock->prcb_of_owner.value != self);  // self-deadlock detection
  while (!rex::thread::atomic_cas(0u, self, &lock->prcb_of_owner.value)) {
    rex::thread::MaybeYield();
  }
  return old_irql;
}

void xeKeKfReleaseSpinLock(PPCContext* ctx, X_KSPINLOCK* lock, uint32_t old_irql,
                           bool change_irql) {
  assert_true(lock->prcb_of_owner == static_cast<uint32_t>(ctx->r13.u64));
  rex::thread::atomic_store_release(0u, &lock->prcb_of_owner.value);
  if (change_irql && old_irql < IRQL_DISPATCH) {
    xeKfLowerIrql(ctx, static_cast<unsigned char>(old_irql));
  }
}

// Guest-memory APC helpers
void xeKeInitializeApc(XAPC* apc, uint32_t thread_ptr, uint32_t kernel_routine,
                       uint32_t rundown_routine, uint32_t normal_routine, uint32_t apc_mode,
                       uint32_t normal_context) {
  apc->thread_ptr = thread_ptr;
  apc->kernel_routine = kernel_routine;
  apc->rundown_routine = rundown_routine;
  apc->normal_routine = normal_routine;
  apc->type = 18;  // ApcObject
  if (normal_routine) {
    apc->apc_mode = apc_mode;
    apc->normal_context = normal_context;
  } else {
    apc->apc_mode = 0;
    apc->normal_context = 0;
  }
  apc->enqueued = 0;
}

uint32_t xeKeInsertQueueApc(XAPC* apc, uint32_t arg1, uint32_t arg2, uint32_t priority_increment,
                            PPCContext* ctx) {
  uint32_t thread_guest_pointer = apc->thread_ptr;
  if (!thread_guest_pointer) {
    return 0;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-05.) thread_guest_pointer is
  // guest-controlled (it is read out of the APC struct itself); the
  // spinlock below writes target_thread->apc_lock and the list insert
  // writes its apc_lists, so the whole KTHREAD must be writable, not
  // just readable. A system-heap APC (NtQueueApcThread) always names
  // a real KTHREAD, so this passes for it.
  if (!GuestRangeWritable(thread_guest_pointer, sizeof(X_KTHREAD))) {
    return 0;
  }
  // (Hunt v1.4.6, ronda 19, A3-R19-03.) apc_mode indexes
  // X_KTHREAD::apc_lists[2] below (0 = kernel, 1 = user); it comes
  // straight from the guest's KeInitializeApc ProcessorMode argument
  // (u32, truncated to the u8 field in xeKeInitializeApc) with no
  // bound check anywhere. A mode >= 2 indexes past the array and
  // InsertTail writes list pointers over the KTHREAD fields that
  // follow it (process pointer at +0x84, apc_lock at +0x8C) -- guest
  // memory corruption from a single guest-controlled byte. Reject it
  // here, the choke point every insert path shares (KeInsertQueueApc,
  // NtQueueApcThread and XThread::EnqueueApc all pass mode 0/1).
  if (apc->apc_mode > 1) {
    return 0;
  }
  auto* mem = rex::system::kernel_state()->memory();
  auto target_thread = mem->TranslateVirtual<X_KTHREAD*>(thread_guest_pointer);
  auto old_irql = xeKeKfAcquireSpinLock(ctx, &target_thread->apc_lock);
  uint32_t result;
  if (!target_thread->may_queue_apcs || apc->enqueued) {
    result = 0;
  } else {
    apc->arg1 = arg1;
    apc->arg2 = arg2;

    auto& which_list = target_thread->apc_lists[apc->apc_mode];

    if (apc->normal_routine) {
      which_list.InsertTail(apc, mem);
    } else {
      // Kernel-mode APCs without normal_routine go before those with one.
      XAPC* insertion_pos = nullptr;
      for (auto&& sub_apc : which_list.IterateForward(mem)) {
        insertion_pos = &sub_apc;
        if (sub_apc.normal_routine) {
          break;
        }
      }
      if (!insertion_pos) {
        which_list.InsertHead(apc, mem);
      } else {
        util::XeInsertHeadList(insertion_pos->list_entry.blink_ptr, &apc->list_entry, mem);
      }
    }

    apc->enqueued = 1;
    result = 1;
  }
  xeKeKfReleaseSpinLock(ctx, &target_thread->apc_lock, old_irql);
  return result;
}

u32 KfAcquireSpinLock_entry(mapped_u32 lock_ptr) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) host_address() is null for
  // guest 0; xeKeKfAcquireSpinLock dereferences lock->prcb_of_owner.
  if (!lock_ptr) {
    return 0;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-06.) The CAS below writes
  // prcb_of_owner through host_address(); validate the 4-byte
  // X_KSPINLOCK first.
  if (!GuestRangeWritable(lock_ptr.guest_address(), sizeof(X_KSPINLOCK))) {
    return 0;
  }
  auto lock = reinterpret_cast<X_KSPINLOCK*>(lock_ptr.host_address());
  return xeKeKfAcquireSpinLock(current_ppc_context(), lock);
}

void KfReleaseSpinLock_entry(mapped_u32 lock_ptr, u32 old_irql) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) As above.
  if (!lock_ptr) {
    return;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-06.) As in KfAcquireSpinLock_entry
  // above: the release stores 0 to prcb_of_owner.
  if (!GuestRangeWritable(lock_ptr.guest_address(), sizeof(X_KSPINLOCK))) {
    return;
  }
  auto lock = reinterpret_cast<X_KSPINLOCK*>(lock_ptr.host_address());
  xeKeKfReleaseSpinLock(current_ppc_context(), lock, old_irql);
}

void KeAcquireSpinLockAtRaisedIrql_entry(mapped_u32 lock_ptr) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) As above.
  if (!lock_ptr) {
    return;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-06.) As in KfAcquireSpinLock_entry
  // above.
  if (!GuestRangeWritable(lock_ptr.guest_address(), sizeof(X_KSPINLOCK))) {
    return;
  }
  auto lock = reinterpret_cast<X_KSPINLOCK*>(lock_ptr.host_address());
  xeKeKfAcquireSpinLock(current_ppc_context(), lock, false);
}

u32 KeTryToAcquireSpinLockAtRaisedIrql_entry(mapped_u32 lock_ptr) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) As above.
  if (!lock_ptr) {
    return 0;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-06.) As in KfAcquireSpinLock_entry
  // above: the atomic_cas below writes prcb_of_owner.
  if (!GuestRangeWritable(lock_ptr.guest_address(), sizeof(X_KSPINLOCK))) {
    return 0;
  }
  auto lock = reinterpret_cast<X_KSPINLOCK*>(lock_ptr.host_address());
  auto* ctx = current_ppc_context();
  uint32_t pcr_addr = static_cast<uint32_t>(ctx->r13.u64);
  if (!rex::thread::atomic_cas(0u, rex::byte_swap(pcr_addr), &lock->prcb_of_owner.value)) {
    return 0;
  }
  return 1;
}

void KeReleaseSpinLockFromRaisedIrql_entry(mapped_u32 lock_ptr) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) As KfAcquireSpinLock above.
  if (!lock_ptr) {
    return;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-06.) As in KfReleaseSpinLock_entry
  // above.
  if (!GuestRangeWritable(lock_ptr.guest_address(), sizeof(X_KSPINLOCK))) {
    return;
  }
  auto lock = reinterpret_cast<X_KSPINLOCK*>(lock_ptr.host_address());
  xeKeKfReleaseSpinLock(current_ppc_context(), lock, 0, false);
}

void KeEnterCriticalRegion_entry() {
  // (Hunt v1.4.6, ronda 3, A3-R3-20.) See ExTerminateThread above.
  if (auto* thread = XThread::GetCurrentThread()) {
    thread->EnterCriticalRegion();
  }
}

void KeLeaveCriticalRegion_entry() {
  // (Hunt v1.4.6, ronda 3, A3-R3-20.) See ExTerminateThread above.
  if (auto* thread = XThread::GetCurrentThread()) {
    thread->LeaveCriticalRegion();
  }
}

u32 KeRaiseIrqlToDpcLevel_entry() {
  return xeKfRaiseIrql(current_ppc_context(), IRQL_DISPATCH);
}

void KfLowerIrql_entry(u32 old_value) {
  xeKfLowerIrql(current_ppc_context(),
                static_cast<unsigned char>(static_cast<uint32_t>(old_value)));
}

u32 KfRaiseIrql_entry(u32 new_irql) {
  return xeKfRaiseIrql(current_ppc_context(),
                       static_cast<unsigned char>(static_cast<uint32_t>(new_irql)));
}

void NtQueueApcThread_entry(u32 thread_handle, mapped_void apc_routine,
                            mapped_void apc_routine_context, mapped_void arg1, mapped_void arg2) {
  auto mem = REX_KERNEL_MEMORY();
  auto thread = REX_KERNEL_OBJECTS()->LookupObject<XThread>(thread_handle);

  if (!thread) {
    REXKRNL_ERROR("NtQueueApcThread: Incorrect thread handle! Might cause crash");
    return;
  }

  if (!apc_routine) {
    REXKRNL_ERROR("NtQueueApcThread: Incorrect apc routine! Might cause crash");
    return;
  }

  uint32_t apc_ptr = mem->SystemHeapAlloc(XAPC::kSize);
  if (!apc_ptr) {
    return;
  }
  XAPC* apc = mem->TranslateVirtual<XAPC*>(apc_ptr);
  xeKeInitializeApc(apc, thread->guest_object(), XAPC::kDummyKernelRoutine, 0,
                    apc_routine.guest_address(), 1 /* user apc mode */,
                    apc_routine_context.guest_address());

  if (!xeKeInsertQueueApc(apc, arg1.guest_address(), arg2.guest_address(), 0,
                          current_ppc_context())) {
    mem->SystemHeapFree(apc_ptr);
    return;
  }
  // Match Edge/Canary behavior: callback is only a wakeup hint.
  // APC delivery happens via alertable wait handling.
  thread->thread()->QueueUserCallback([]() {});
}

void KeInitializeApc_entry(ppc_ptr_t<XAPC> apc, mapped_void thread_ptr, mapped_void kernel_routine,
                           mapped_void rundown_routine, mapped_void normal_routine,
                           u32 processor_mode, mapped_void normal_context) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) xeKeInitializeApc writes
  // apc->thread_ptr through apc.host_address(), null for guest 0.
  if (!apc) {
    return;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-05.) xeKeInitializeApc writes the
  // whole 40-byte XAPC below.
  if (!GuestRangeWritable(apc.guest_address(), sizeof(XAPC))) {
    return;
  }
  xeKeInitializeApc(apc.host_address(), thread_ptr.guest_address(), kernel_routine.guest_address(),
                    rundown_routine.guest_address(), normal_routine.guest_address(), processor_mode,
                    normal_context.guest_address());
}

u32 KeInsertQueueApc_entry(ppc_ptr_t<XAPC> apc, mapped_void arg1, mapped_void arg2,
                           u32 priority_increment) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) xeKeInsertQueueApc reads
  // apc->thread_ptr; a NULL apc used to crash the host there.
  if (!apc) {
    return 0;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-05.) xeKeInsertQueueApc writes
  // apc->arg1/arg2/enqueued below, and validates the thread pointer
  // itself; the APC struct must be writable first.
  if (!GuestRangeWritable(apc.guest_address(), sizeof(XAPC))) {
    return 0;
  }
  return xeKeInsertQueueApc(apc.host_address(), arg1.guest_address(), arg2.guest_address(),
                            priority_increment, current_ppc_context());
}

u32 KeRemoveQueueApc_entry(ppc_ptr_t<XAPC> apc) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) apc->thread_ptr is read first
  // thing below.
  if (!apc) {
    return 0;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-05.) apc->thread_ptr is read below
  // and apc->enqueued is written; validate the APC struct first.
  if (!GuestRangeWritable(apc.guest_address(), sizeof(XAPC))) {
    return 0;
  }
  uint32_t thread_guest_pointer = apc->thread_ptr;
  if (!thread_guest_pointer) {
    return 0;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-05.) As in xeKeInsertQueueApc
  // above: the spinlock below writes target_thread->apc_lock, so the
  // whole KTHREAD must be writable before translating.
  if (!GuestRangeWritable(thread_guest_pointer, sizeof(X_KTHREAD))) {
    return 0;
  }
  auto* ctx = current_ppc_context();
  auto mem = REX_KERNEL_MEMORY();
  auto target_thread = mem->TranslateVirtual<X_KTHREAD*>(thread_guest_pointer);
  auto old_irql = xeKeKfAcquireSpinLock(ctx, &target_thread->apc_lock);

  bool result = false;
  if (apc->enqueued) {
    apc->enqueued = 0;
    util::XeRemoveEntryList(&apc->list_entry, mem);
    result = true;
  }

  xeKeKfReleaseSpinLock(ctx, &target_thread->apc_lock, old_irql);
  return result ? 1 : 0;
}

u32 KiApcNormalRoutineNop_entry(u32 unk0 /* output? */, u32 unk1 /* 0x13 */) {
  return 0;
}

void KeInitializeDpc_entry(ppc_ptr_t<XDPC> dpc, mapped_void routine, mapped_void context) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) XDPC::Initialize writes
  // through `this`; a NULL dpc used to crash the host.
  if (!dpc) {
    return;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-05.) XDPC::Initialize writes
  // type/routine/context below (sizeof(XDPC) = 28 B).
  if (!GuestRangeWritable(dpc.guest_address(), sizeof(XDPC))) {
    return;
  }
  dpc->Initialize(routine.guest_address(), context.guest_address());
}

// (Hunt v1.4.6, ronda 18, A3-R18-03 + F41.) KeInsertQueueDpc used to only
// append to dpc_list(); nothing ever drained it — KeRetireDpcList is a plain
// stub and the assert_always("DPC does not dispatch yet; going to hang!")
// compiled out in Release — so every DPC-driven signal was lost since the
// initial commit. CrownPark's ReXGlue fork fixed the identical bug the same
// way, matching xenia-canary: run the DPC inline under DPC impersonation
// (IRQL_DISPATCH + dpc_active, depth-guarded). The drain here is iterative, not
// recursive: KeInsertQueueDpc enqueues, then drains the whole list while it
// is the outermost drain on this thread (thread_local flag). A DPC routine
// that queues another DPC only appends; the outer loop picks it up, so no
// DPC is ever lost and the stack cannot grow. The global lock is released
// before any guest code runs (same rule as DeliverAPCs, which releases the
// APC spinlock first). KeRetireDpcList stays a stub: with inline draining
// the list is empty whenever it could run.
static void DrainDpcList() {
  // Only the outermost drain on this thread runs the loop; a nested
  // KeInsertQueueDpc (called from inside a DPC routine) only enqueues and
  // returns, and the outer loop picks the new entry up.
  static thread_local bool draining = false;
  if (draining) {
    return;
  }
  XThread* thread = XThread::GetCurrentThread();
  if (!thread) {
    // Host thread with no guest TLS (see ExTerminateThread, R3-20): no
    // ThreadState to execute with. The DPC stays queued; the next insert
    // from a guest thread drains it.
    return;
  }
  auto* thread_state = thread->thread_state();
  auto* dispatcher = REX_KERNEL_STATE()->function_dispatcher();
  if (!thread_state || !dispatcher) {
    return;
  }
  draining = true;
  auto* mem = rex::system::kernel_state()->memory();
  auto* dpc_list = REX_KERNEL_STATE()->dpc_list();
  while (true) {
    uint32_t list_entry_ptr = 0;
    {
      // Take one DPC under the lock, then release the lock before running
      // guest code. HasPending + Shift share one acquisition so the list
      // cannot empty between the check and the take.
      auto global_lock = rex::thread::global_critical_region::AcquireDirect();
      if (dpc_list->HasPending()) {
        list_entry_ptr = dpc_list->Shift();
      }
    }
    if (!list_entry_ptr) {
      break;
    }
    // XDPC::list_entry sits at +4, so the struct starts 4 bytes earlier.
    uint32_t dpc_ptr = list_entry_ptr - 4;
    if (!GuestRangeWritable(dpc_ptr, sizeof(XDPC))) {
      REXKRNL_ERROR("[DPC] Dropping queued DPC at {:08X}: not a writable XDPC",
                    dpc_ptr);
      continue;
    }
    XDPC* dpc = mem->TranslateVirtual<XDPC*>(dpc_ptr);
    // Copy the fields out before executing: the routine may mutate the DPC.
    uint32_t routine = uint32_t(dpc->routine);
    uint32_t deferred_context = uint32_t(dpc->context);
    uint32_t arg1 = uint32_t(dpc->arg1);
    uint32_t arg2 = uint32_t(dpc->arg2);
    if (!routine || !dispatcher->GetFunction(routine)) {
      REXKRNL_ERROR(
          "[DPC] Dropping queued DPC at {:08X}: routine {:08X} not found",
          dpc_ptr, routine);
      continue;
    }
    // DPC routine signature: (Dpc, DeferredContext, SystemArgument1,
    // SystemArgument2). Same call shape as DeliverAPCs uses for APCs.
    uint64_t dpc_args[] = {dpc_ptr, deferred_context, arg1, arg2};
    // (Hunt v1.4.6, ronda 19, A3-R19-01.) The R18 drain only raised
    // IRQL: it never set PRCB dpc_active, so KeGetCurrentProcessType
    // (which branches on dpc_active) returned the thread's normal
    // process type instead of processtype_value_in_dpc for the whole
    // DPC routine, and any guest code reading the PRCB saw "not in a
    // DPC". Impersonate properly with the existing (previously dead)
    // Begin/EndDPCImpersonation pair, which sets IRQL_DISPATCH and
    // dpc_active=1 and restores both afterwards -- including restoring
    // an old IRQL above DISPATCH, which the manual raise/lower above
    // silently lost.
    auto dpc_scope = REX_KERNEL_STATE()->BeginDPCImpersonation();
    dispatcher->ExecuteTrap(thread_state, routine, dpc_args, 4);
    REX_KERNEL_STATE()->EndDPCImpersonation(dpc_scope);
  }
  draining = false;
}

u32 KeInsertQueueDpc_entry(ppc_ptr_t<XDPC> dpc, u32 arg1, u32 arg2) {

  // (Hunt v1.4.6, ronda 3, A3-R3-07.) dpc->arg1/arg2 are written
  // below; a NULL dpc used to crash the host there.
  if (!dpc) {
    return 0;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-05.) dpc->arg1/arg2 are written
  // below; validate the XDPC first.
  if (!GuestRangeWritable(dpc.guest_address(), sizeof(XDPC))) {
    return 0;
  }
  uint32_t list_entry_ptr = dpc.guest_address() + 4;

  {
    // Lock dispatcher.
    auto global_lock = rex::thread::global_critical_region::AcquireDirect();
    auto dpc_list = REX_KERNEL_STATE()->dpc_list();

    // If already in a queue, abort.
    if (dpc_list->IsQueued(list_entry_ptr)) {
      return 0;
    }

    // Prep DPC.
    dpc->arg1 = (uint32_t)arg1;
    dpc->arg2 = (uint32_t)arg2;

    dpc_list->Insert(list_entry_ptr);
  }

  // (Hunt v1.4.6, ronda 18, A3-R18-03.) The DPC is drained inline now
  // (DrainDpcList above); the lock is released first so guest code never
  // runs under it.
  DrainDpcList();

  return 1;
}

u32 KeRemoveQueueDpc_entry(ppc_ptr_t<XDPC> dpc) {
  // (Hunt v1.4.6, ronda 4, A3-R4-20.) Same null-guard as its sister
  // KeInsertQueueDpc (R3-07): a null DPC used to compute a list entry
  // at guest address 4 and walk the queue with it.
  if (!dpc) {
    return 0;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-05.) This entry only derives the
  // list-entry address from the DPC, but a wild pointer names no
  // DPC at all; validate the struct for symmetry with its sisters.
  if (!GuestRangeWritable(dpc.guest_address(), sizeof(XDPC))) {
    return 0;
  }
  bool result = false;

  uint32_t list_entry_ptr = dpc.guest_address() + 4;

  auto global_lock = rex::thread::global_critical_region::AcquireDirect();
  auto dpc_list = REX_KERNEL_STATE()->dpc_list();
  if (dpc_list->IsQueued(list_entry_ptr)) {
    dpc_list->Remove(list_entry_ptr);
    result = true;
  }

  return result ? 1 : 0;
}

// https://github.com/Cxbx-Reloaded/Cxbx-Reloaded/blob/51e4dfcaacfdbd1a9692272931a436371492f72d/import/OpenXDK/include/xboxkrnl/xboxkrnl.h#L1372
struct X_ERWLOCK {
  be<int32_t> lock_count;              // 0x0
  be<uint32_t> writers_waiting_count;  // 0x4
  be<uint32_t> readers_waiting_count;  // 0x8
  be<uint32_t> readers_entry_count;    // 0xC
  X_KEVENT writer_event;               // 0x10
  X_KSEMAPHORE reader_semaphore;       // 0x20
  X_KSPINLOCK spin_lock;               // 0x34
};
static_assert_size(X_ERWLOCK, 0x38);

void ExInitializeReadWriteLock_entry(ppc_ptr_t<X_ERWLOCK> lock_ptr) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) Every write below dereferences
  // lock_ptr with no check.
  if (!lock_ptr) {
    return;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-08.) The writes below span the whole
  // 0x38-byte X_ERWLOCK; validate it first. (This also covers the
  // writer_event / reader_semaphore members passed to the KeInitialize
  // entries below.)
  if (!GuestRangeWritable(lock_ptr.guest_address(), sizeof(X_ERWLOCK))) {
    return;
  }
  lock_ptr->lock_count = -1;
  lock_ptr->writers_waiting_count = 0;
  lock_ptr->readers_waiting_count = 0;
  lock_ptr->readers_entry_count = 0;
  // Create GuestPointers to struct members with correct guest addresses
  ppc_ptr_t<X_KEVENT> event_ptr(&lock_ptr->writer_event,
                                lock_ptr.guest_address() + offsetof(X_ERWLOCK, writer_event));
  ppc_ptr_t<X_KSEMAPHORE> sem_ptr(&lock_ptr->reader_semaphore,
                                  lock_ptr.guest_address() + offsetof(X_ERWLOCK, reader_semaphore));
  KeInitializeEvent_entry(event_ptr, 1, 0);
  KeInitializeSemaphore_entry(sem_ptr, 0, 0x7FFFFFFF);
  lock_ptr->spin_lock.prcb_of_owner = 0;
}

void ExAcquireReadWriteLockExclusive_entry(ppc_ptr_t<X_ERWLOCK> lock_ptr) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) &lock_ptr->spin_lock is taken
  // first thing below.
  if (!lock_ptr) {
    return;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-08.) The spinlock and counter
  // accesses below span the whole 0x38-byte X_ERWLOCK; validate it
  // first. (This also covers the &writer_event passed to
  // xeKeWaitForSingleObject below.)
  if (!GuestRangeWritable(lock_ptr.guest_address(), sizeof(X_ERWLOCK))) {
    return;
  }
  auto* ctx = current_ppc_context();
  auto old_irql = xeKeKfAcquireSpinLock(ctx, &lock_ptr->spin_lock);

  int32_t lock_count = ++lock_ptr->lock_count;
  if (!lock_count) {
    xeKeKfReleaseSpinLock(ctx, &lock_ptr->spin_lock, old_irql);
    return;
  }

  lock_ptr->writers_waiting_count++;

  xeKeKfReleaseSpinLock(ctx, &lock_ptr->spin_lock, old_irql);
  xeKeWaitForSingleObject(&lock_ptr->writer_event, 7, 0, 0, nullptr);
}

u32 ExTryToAcquireReadWriteLockExclusive_entry(ppc_ptr_t<X_ERWLOCK> lock_ptr) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) As above; 0 = not acquired.
  if (!lock_ptr) {
    return 0;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-08.) As in
  // ExAcquireReadWriteLockExclusive_entry above.
  if (!GuestRangeWritable(lock_ptr.guest_address(), sizeof(X_ERWLOCK))) {
    return 0;
  }
  auto* ctx = current_ppc_context();
  auto old_irql = xeKeKfAcquireSpinLock(ctx, &lock_ptr->spin_lock);

  uint32_t result;
  if (lock_ptr->lock_count < 0) {
    lock_ptr->lock_count = 0;
    result = 1;
  } else {
    result = 0;
  }

  xeKeKfReleaseSpinLock(ctx, &lock_ptr->spin_lock, old_irql);
  return result;
}

void ExAcquireReadWriteLockShared_entry(ppc_ptr_t<X_ERWLOCK> lock_ptr) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) As above.
  if (!lock_ptr) {
    return;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-08.) As in
  // ExAcquireReadWriteLockExclusive_entry above. (This also covers
  // the &reader_semaphore passed to xeKeWaitForSingleObject below.)
  if (!GuestRangeWritable(lock_ptr.guest_address(), sizeof(X_ERWLOCK))) {
    return;
  }
  auto* ctx = current_ppc_context();
  auto old_irql = xeKeKfAcquireSpinLock(ctx, &lock_ptr->spin_lock);

  int32_t lock_count = ++lock_ptr->lock_count;
  if (!lock_count || (lock_ptr->readers_entry_count && !lock_ptr->writers_waiting_count)) {
    lock_ptr->readers_entry_count++;
    xeKeKfReleaseSpinLock(ctx, &lock_ptr->spin_lock, old_irql);
    return;
  }

  lock_ptr->readers_waiting_count++;

  xeKeKfReleaseSpinLock(ctx, &lock_ptr->spin_lock, old_irql);
  xeKeWaitForSingleObject(&lock_ptr->reader_semaphore, 7, 0, 0, nullptr);
}

u32 ExTryToAcquireReadWriteLockShared_entry(ppc_ptr_t<X_ERWLOCK> lock_ptr) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) As above; 0 = not acquired.
  if (!lock_ptr) {
    return 0;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-08.) As in
  // ExAcquireReadWriteLockExclusive_entry above.
  if (!GuestRangeWritable(lock_ptr.guest_address(), sizeof(X_ERWLOCK))) {
    return 0;
  }
  auto* ctx = current_ppc_context();
  auto old_irql = xeKeKfAcquireSpinLock(ctx, &lock_ptr->spin_lock);

  uint32_t result;
  if (lock_ptr->lock_count < 0 ||
      (lock_ptr->readers_entry_count && !lock_ptr->writers_waiting_count)) {
    lock_ptr->lock_count++;
    lock_ptr->readers_entry_count++;
    result = 1;
  } else {
    result = 0;
  }

  xeKeKfReleaseSpinLock(ctx, &lock_ptr->spin_lock, old_irql);
  return result;
}

void ExReleaseReadWriteLock_entry(ppc_ptr_t<X_ERWLOCK> lock_ptr) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) As above.
  if (!lock_ptr) {
    return;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-08.) As in
  // ExAcquireReadWriteLockExclusive_entry above. (This also covers
  // the &reader_semaphore / &writer_event passed to
  // xeKeReleaseSemaphore / xeKeSetEvent below.)
  if (!GuestRangeWritable(lock_ptr.guest_address(), sizeof(X_ERWLOCK))) {
    return;
  }
  auto* ctx = current_ppc_context();
  auto old_irql = xeKeKfAcquireSpinLock(ctx, &lock_ptr->spin_lock);

  int32_t lock_count = --lock_ptr->lock_count;

  if (lock_count < 0) {
    lock_ptr->readers_entry_count = 0;
    xeKeKfReleaseSpinLock(ctx, &lock_ptr->spin_lock, old_irql);
    return;
  }

  if (!lock_ptr->readers_entry_count) {
    auto readers_waiting_count = lock_ptr->readers_waiting_count;
    if (readers_waiting_count) {
      lock_ptr->readers_waiting_count = 0;
      lock_ptr->readers_entry_count = readers_waiting_count;
      xeKeKfReleaseSpinLock(ctx, &lock_ptr->spin_lock, old_irql);
      xeKeReleaseSemaphore(&lock_ptr->reader_semaphore, 1, readers_waiting_count, 0);
      return;
    }
    // (Hunt v1.4.6, ronda 19, A3-R19-02.) No readers entered and none
    // waiting: the lock is free for a waiting writer. The old code
    // fell through to --readers_entry_count below, which underflows a
    // zero be<uint32_t> to 0xFFFFFFFF and returns WITHOUT setting
    // writer_event -- so an exclusive waiter slept forever on a lock
    // whose owner had already released it, and the lock stayed wedged
    // (readers_entry_count poisoned) for every later acquire. Wake the
    // writer here instead.
    if (lock_ptr->writers_waiting_count) {
      lock_ptr->writers_waiting_count--;
      xeKeKfReleaseSpinLock(ctx, &lock_ptr->spin_lock, old_irql);
      xeKeSetEvent(&lock_ptr->writer_event, 1, 0);
      return;
    }
    // No waiters at all: unreachable for a consistent lock (an
    // exclusive owner releasing with no waiter already returned via
    // the lock_count < 0 branch above), but never fall through to
    // --readers_entry_count: it would underflow the zero count.
    xeKeKfReleaseSpinLock(ctx, &lock_ptr->spin_lock, old_irql);
    return;
  }

  auto readers_entry_count = --lock_ptr->readers_entry_count;
  if (readers_entry_count) {
    xeKeKfReleaseSpinLock(ctx, &lock_ptr->spin_lock, old_irql);
    return;
  }

  lock_ptr->writers_waiting_count--;
  xeKeKfReleaseSpinLock(ctx, &lock_ptr->spin_lock, old_irql);
  xeKeSetEvent(&lock_ptr->writer_event, 1, 0);
}

// NOTE: This function is very commonly inlined, and probably won't be called!
u32 InterlockedPushEntrySList_entry(ppc_ptr_t<X_SLIST_HEADER> plist_ptr,
                                    ppc_ptr_t<X_SINGLE_LIST_ENTRY> entry) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) The only guards were
  // assert_not_null, no-ops in Release; *plist_ptr and entry->next
  // were dereferenced below.
  if (!plist_ptr || !entry) {
    return 0;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-07.) The CAS below writes the
  // 8-byte header and entry->next is written in the loop; validate
  // both structs first.
  if (!GuestRangeWritable(plist_ptr.guest_address(), sizeof(X_SLIST_HEADER)) ||
      !GuestRangeWritable(entry.guest_address(), sizeof(X_SINGLE_LIST_ENTRY))) {
    return 0;
  }

  alignas(8) X_SLIST_HEADER old_hdr = *plist_ptr;
  alignas(8) X_SLIST_HEADER new_hdr = {};
  uint32_t old_head = 0;
  do {
    old_hdr = *plist_ptr;
    new_hdr.depth = old_hdr.depth + 1;
    new_hdr.sequence = old_hdr.sequence + 1;

    old_head = old_hdr.next.next;
    entry->next = old_hdr.next.next;
    new_hdr.next.next = entry.guest_address();
  } while (!rex::thread::atomic_cas(*(uint64_t*)(&old_hdr), *(uint64_t*)(&new_hdr),
                                    reinterpret_cast<uint64_t*>(plist_ptr.host_address())));

  return old_head;
}

u32 InterlockedPopEntrySList_entry(ppc_ptr_t<X_SLIST_HEADER> plist_ptr) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) As above.
  if (!plist_ptr) {
    return 0;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-07.) The CAS below writes the
  // 8-byte header; validate it first.
  if (!GuestRangeWritable(plist_ptr.guest_address(), sizeof(X_SLIST_HEADER))) {
    return 0;
  }

  uint32_t popped = 0;
  alignas(8) X_SLIST_HEADER old_hdr = {0};
  alignas(8) X_SLIST_HEADER new_hdr = {0};
  do {
    old_hdr = *plist_ptr;
    auto next = REX_KERNEL_MEMORY()->TranslateVirtual<X_SINGLE_LIST_ENTRY*>(old_hdr.next.next);
    if (!old_hdr.next.next) {
      return 0;
    }
    // (Hunt v1.4.6, ronda 9, A3-R9-07.) `next` is a guest pointer
    // read out of the list itself; validate it before reading
    // next->next below.
    if (!GuestRangeReadable(old_hdr.next.next, sizeof(X_SINGLE_LIST_ENTRY))) {
      return 0;
    }
    popped = old_hdr.next.next;

    new_hdr.depth = old_hdr.depth - 1;
    new_hdr.next.next = next->next;
    new_hdr.sequence = old_hdr.sequence;
  } while (!rex::thread::atomic_cas(*(uint64_t*)(&old_hdr), *(uint64_t*)(&new_hdr),
                                    reinterpret_cast<uint64_t*>(plist_ptr.host_address())));

  return popped;
}

u32 InterlockedFlushSList_entry(ppc_ptr_t<X_SLIST_HEADER> plist_ptr) {
  // (Hunt v1.4.6, ronda 3, A3-R3-07.) As above.
  if (!plist_ptr) {
    return 0;
  }
  // (Hunt v1.4.6, ronda 9, A3-R9-07.) The CAS below writes the
  // 8-byte header; validate it first.
  if (!GuestRangeWritable(plist_ptr.guest_address(), sizeof(X_SLIST_HEADER))) {
    return 0;
  }

  alignas(8) X_SLIST_HEADER old_hdr = *plist_ptr;
  alignas(8) X_SLIST_HEADER new_hdr = {0};
  uint32_t first = 0;
  do {
    old_hdr = *plist_ptr;
    first = old_hdr.next.next;
    new_hdr.next.next = 0;
    new_hdr.depth = 0;
    new_hdr.sequence = 0;
  } while (!rex::thread::atomic_cas(*(uint64_t*)(&old_hdr), *(uint64_t*)(&new_hdr),
                                    reinterpret_cast<uint64_t*>(plist_ptr.host_address())));

  return first;
}

REX_EXPORT_STUB(__imp__KeInsertByKeyDeviceQueue);
REX_EXPORT_STUB(__imp__KeInsertDeviceQueue);
REX_EXPORT_STUB(__imp__KeInsertHeadQueue);
REX_EXPORT_STUB(__imp__KeInsertQueue);
// (Audit A3, ronda 6, R6-03.) Was a bare stub: r3 came back as the
// first argument. 0 is the honest value (FALSE / previous count 0).
REX_EXPORT_STUB_RETURN(__imp__KeReleaseMutant, 0);
REX_EXPORT_STUB(__imp__KeRemoveByKeyDeviceQueue);
REX_EXPORT_STUB(__imp__KeRemoveDeviceQueue);
REX_EXPORT_STUB(__imp__KeRemoveEntryDeviceQueue);
REX_EXPORT_STUB(__imp__KeRemoveQueue);
REX_EXPORT_STUB(__imp__KeSetEventBoostPriority);
REX_EXPORT_STUB(__imp__KiApcNormalRoutineNop_);

u32 KeSuspendThread_entry(mapped_void kthread_ptr) {
  // (Hunt v1.4.6, ronda 9, A3-R9-04.) As in KeResumeThread_entry
  // above: validate the whole KTHREAD before GetNativeObject reads
  // its header. The failure value is the same 0 the not-found path
  // below returns.
  if (kthread_ptr && !GuestRangeWritable(kthread_ptr.guest_address(), sizeof(X_KTHREAD))) {
    return 0;
  }
  auto thread = XObject::GetNativeObject<XThread>(REX_KERNEL_STATE(), kthread_ptr);
  uint32_t old_suspend_count = 0;

  if (thread) {
    old_suspend_count = thread->suspend_count();
    uint32_t discarded = 0;
    thread->Suspend(&discarded);
  }

  return old_suspend_count;
}

}  // namespace rex::kernel::xboxkrnl

REX_EXPORT(__imp__ExCreateThread, rex::kernel::xboxkrnl::ExCreateThread_entry)
REX_EXPORT(__imp__ExTerminateThread, rex::kernel::xboxkrnl::ExTerminateThread_entry)
REX_EXPORT(__imp__NtResumeThread, rex::kernel::xboxkrnl::NtResumeThread_entry)
REX_EXPORT(__imp__KeResumeThread, rex::kernel::xboxkrnl::KeResumeThread_entry)
REX_EXPORT(__imp__NtSuspendThread, rex::kernel::xboxkrnl::NtSuspendThread_entry)
REX_EXPORT(__imp__KeSuspendThread, rex::kernel::xboxkrnl::KeSuspendThread_entry)
REX_EXPORT(__imp__KeSetCurrentStackPointers, rex::kernel::xboxkrnl::KeSetCurrentStackPointers_entry)
REX_EXPORT(__imp__KeSetAffinityThread, rex::kernel::xboxkrnl::KeSetAffinityThread_entry)
REX_EXPORT(__imp__KeQueryBasePriorityThread, rex::kernel::xboxkrnl::KeQueryBasePriorityThread_entry)
REX_EXPORT(__imp__KeSetBasePriorityThread, rex::kernel::xboxkrnl::KeSetBasePriorityThread_entry)
REX_EXPORT(__imp__KeSetDisableBoostThread, rex::kernel::xboxkrnl::KeSetDisableBoostThread_entry)
REX_EXPORT(__imp__KeGetCurrentProcessType, rex::kernel::xboxkrnl::KeGetCurrentProcessType_entry)
REX_EXPORT(__imp__KeSetCurrentProcessType, rex::kernel::xboxkrnl::KeSetCurrentProcessType_entry)
REX_EXPORT(__imp__KeQueryPerformanceFrequency,
           rex::kernel::xboxkrnl::KeQueryPerformanceFrequency_entry)
REX_EXPORT(__imp__KeDelayExecutionThread, rex::kernel::xboxkrnl::KeDelayExecutionThread_entry)
REX_EXPORT(__imp__NtYieldExecution, rex::kernel::xboxkrnl::NtYieldExecution_entry)
REX_EXPORT(__imp__KeQuerySystemTime, rex::kernel::xboxkrnl::KeQuerySystemTime_entry)
REX_EXPORT(__imp__KeTlsAlloc, rex::kernel::xboxkrnl::KeTlsAlloc_entry)
REX_EXPORT(__imp__KeTlsFree, rex::kernel::xboxkrnl::KeTlsFree_entry)
REX_EXPORT(__imp__KeTlsGetValue, rex::kernel::xboxkrnl::KeTlsGetValue_entry)
REX_EXPORT(__imp__KeTlsSetValue, rex::kernel::xboxkrnl::KeTlsSetValue_entry)
REX_EXPORT(__imp__KeInitializeEvent, rex::kernel::xboxkrnl::KeInitializeEvent_entry)
REX_EXPORT(__imp__KeInitializeMutant, rex::kernel::xboxkrnl::KeInitializeMutant_entry)
REX_EXPORT(__imp__KeSetEvent, rex::kernel::xboxkrnl::KeSetEvent_entry)
REX_EXPORT(__imp__KePulseEvent, rex::kernel::xboxkrnl::KePulseEvent_entry)
REX_EXPORT(__imp__KeResetEvent, rex::kernel::xboxkrnl::KeResetEvent_entry)
REX_EXPORT(__imp__NtCreateEvent, rex::kernel::xboxkrnl::NtCreateEvent_entry)
REX_EXPORT(__imp__NtSetEvent, rex::kernel::xboxkrnl::NtSetEvent_entry)
REX_EXPORT(__imp__NtPulseEvent, rex::kernel::xboxkrnl::NtPulseEvent_entry)
REX_EXPORT(__imp__NtClearEvent, rex::kernel::xboxkrnl::NtClearEvent_entry)
REX_EXPORT(__imp__KeInitializeSemaphore, rex::kernel::xboxkrnl::KeInitializeSemaphore_entry)
REX_EXPORT(__imp__KeReleaseSemaphore, rex::kernel::xboxkrnl::KeReleaseSemaphore_entry)
REX_EXPORT(__imp__NtCreateSemaphore, rex::kernel::xboxkrnl::NtCreateSemaphore_entry)
REX_EXPORT(__imp__NtReleaseSemaphore, rex::kernel::xboxkrnl::NtReleaseSemaphore_entry)
REX_EXPORT(__imp__NtCreateMutant, rex::kernel::xboxkrnl::NtCreateMutant_entry)
REX_EXPORT(__imp__NtReleaseMutant, rex::kernel::xboxkrnl::NtReleaseMutant_entry)
REX_EXPORT(__imp__NtCreateTimer, rex::kernel::xboxkrnl::NtCreateTimer_entry)
REX_EXPORT(__imp__NtSetTimerEx, rex::kernel::xboxkrnl::NtSetTimerEx_entry)
REX_EXPORT(__imp__NtCancelTimer, rex::kernel::xboxkrnl::NtCancelTimer_entry)
REX_EXPORT(__imp__KeInitializeTimerEx, rex::kernel::xboxkrnl::KeInitializeTimerEx_entry)
REX_EXPORT(__imp__KeWaitForSingleObject, rex::kernel::xboxkrnl::KeWaitForSingleObject_entry)
REX_EXPORT(__imp__NtWaitForSingleObjectEx, rex::kernel::xboxkrnl::NtWaitForSingleObjectEx_entry)
REX_EXPORT(__imp__KeWaitForMultipleObjects, rex::kernel::xboxkrnl::KeWaitForMultipleObjects_entry)
REX_EXPORT(__imp__NtWaitForMultipleObjectsEx,
           rex::kernel::xboxkrnl::NtWaitForMultipleObjectsEx_entry)
REX_EXPORT(__imp__NtSignalAndWaitForSingleObjectEx,
           rex::kernel::xboxkrnl::NtSignalAndWaitForSingleObjectEx_entry)
REX_EXPORT(__imp__KfAcquireSpinLock, rex::kernel::xboxkrnl::KfAcquireSpinLock_entry)
REX_EXPORT(__imp__KfReleaseSpinLock, rex::kernel::xboxkrnl::KfReleaseSpinLock_entry)
REX_EXPORT(__imp__KeAcquireSpinLockAtRaisedIrql,
           rex::kernel::xboxkrnl::KeAcquireSpinLockAtRaisedIrql_entry)
REX_EXPORT(__imp__KeTryToAcquireSpinLockAtRaisedIrql,
           rex::kernel::xboxkrnl::KeTryToAcquireSpinLockAtRaisedIrql_entry)
REX_EXPORT(__imp__KeReleaseSpinLockFromRaisedIrql,
           rex::kernel::xboxkrnl::KeReleaseSpinLockFromRaisedIrql_entry)
REX_EXPORT(__imp__KeEnterCriticalRegion, rex::kernel::xboxkrnl::KeEnterCriticalRegion_entry)
REX_EXPORT(__imp__KeLeaveCriticalRegion, rex::kernel::xboxkrnl::KeLeaveCriticalRegion_entry)
REX_EXPORT(__imp__KeRaiseIrqlToDpcLevel, rex::kernel::xboxkrnl::KeRaiseIrqlToDpcLevel_entry)
REX_EXPORT(__imp__KfLowerIrql, rex::kernel::xboxkrnl::KfLowerIrql_entry)
REX_EXPORT(__imp__NtQueueApcThread, rex::kernel::xboxkrnl::NtQueueApcThread_entry)
REX_EXPORT(__imp__KeInitializeApc, rex::kernel::xboxkrnl::KeInitializeApc_entry)
REX_EXPORT(__imp__KeInsertQueueApc, rex::kernel::xboxkrnl::KeInsertQueueApc_entry)
REX_EXPORT(__imp__KeRemoveQueueApc, rex::kernel::xboxkrnl::KeRemoveQueueApc_entry)
REX_EXPORT(__imp__KiApcNormalRoutineNop, rex::kernel::xboxkrnl::KiApcNormalRoutineNop_entry)
REX_EXPORT(__imp__KeInitializeDpc, rex::kernel::xboxkrnl::KeInitializeDpc_entry)
REX_EXPORT(__imp__KeInsertQueueDpc, rex::kernel::xboxkrnl::KeInsertQueueDpc_entry)
REX_EXPORT(__imp__KeRemoveQueueDpc, rex::kernel::xboxkrnl::KeRemoveQueueDpc_entry)
REX_EXPORT(__imp__ExInitializeReadWriteLock, rex::kernel::xboxkrnl::ExInitializeReadWriteLock_entry)
REX_EXPORT(__imp__ExAcquireReadWriteLockExclusive,
           rex::kernel::xboxkrnl::ExAcquireReadWriteLockExclusive_entry)
REX_EXPORT(__imp__ExTryToAcquireReadWriteLockExclusive,
           rex::kernel::xboxkrnl::ExTryToAcquireReadWriteLockExclusive_entry)
REX_EXPORT(__imp__ExAcquireReadWriteLockShared,
           rex::kernel::xboxkrnl::ExAcquireReadWriteLockShared_entry)
REX_EXPORT(__imp__ExTryToAcquireReadWriteLockShared,
           rex::kernel::xboxkrnl::ExTryToAcquireReadWriteLockShared_entry)
REX_EXPORT(__imp__ExReleaseReadWriteLock, rex::kernel::xboxkrnl::ExReleaseReadWriteLock_entry)
REX_EXPORT(__imp__InterlockedPushEntrySList, rex::kernel::xboxkrnl::InterlockedPushEntrySList_entry)
REX_EXPORT(__imp__InterlockedPopEntrySList, rex::kernel::xboxkrnl::InterlockedPopEntrySList_entry)
REX_EXPORT(__imp__InterlockedFlushSList, rex::kernel::xboxkrnl::InterlockedFlushSList_entry)

REX_EXPORT_STUB(__imp__KeAlertResumeThread);
REX_EXPORT_STUB(__imp__KeAlertThread);
REX_EXPORT_STUB(__imp__KeBoostPriorityThread);
// (Audit A3, ronda 6, R6-03.) Was a bare stub: r3 came back as the
// first argument. 0 is the honest value (FALSE / previous count 0).
REX_EXPORT_STUB_RETURN(__imp__KeCancelTimer, 0);
REX_EXPORT_STUB(__imp__KeConnectInterrupt);
REX_EXPORT_STUB(__imp__KeContextFromKframes);
REX_EXPORT_STUB(__imp__KeContextToKframes);
REX_EXPORT_STUB(__imp__KeDisconnectInterrupt);
REX_EXPORT_STUB(__imp__KeFlushCacheRange);
REX_EXPORT_STUB(__imp__KeFlushCurrentEntireTb);
REX_EXPORT_STUB(__imp__KeFlushEntireTb);
REX_EXPORT_STUB(__imp__KeFlushMultipleTb);
REX_EXPORT_STUB(__imp__KeFlushUserModeCurrentTb);
REX_EXPORT_STUB(__imp__KeFlushUserModeTb);
REX_EXPORT_STUB(__imp__KeInitializeDeviceQueue);
REX_EXPORT_STUB(__imp__KeInitializeInterrupt);
// REX_EXPORT_STUB(__imp__KeInitializeMutant); -- implemented above
REX_EXPORT_STUB(__imp__KeInitializeQueue);
// REX_EXPORT_STUB(__imp__KeInitializeTimerEx); -- implemented below
REX_EXPORT_STUB(__imp__KeIpiGenericCall);
REX_EXPORT_STUB(__imp__KeQueryBackgroundProcessors);
REX_EXPORT(__imp__KeQueryInterruptTime, rex::kernel::xboxkrnl::KeQueryInterruptTime_entry)
REX_EXPORT_STUB(__imp__KeRegisterDriverNotification);
REX_EXPORT_STUB(__imp__KeRestoreFloatingPointState);
REX_EXPORT_STUB(__imp__KeRestoreVectorUnitState);
REX_EXPORT_STUB(__imp__KeRetireDpcList);
REX_EXPORT_STUB(__imp__KeRundownQueue);
REX_EXPORT_STUB(__imp__KeSaveFloatingPointState);
REX_EXPORT_STUB(__imp__KeSaveVectorUnitState);
REX_EXPORT_STUB(__imp__KeSetBackgroundProcessors);
REX_EXPORT_STUB(__imp__KeSetPriorityClassThread);
REX_EXPORT_STUB(__imp__KeSetPriorityThread);
// (Audit A3, ronda 6, R6-03.) Was a bare stub: r3 came back as the
// first argument. 0 is the honest value (FALSE / previous count 0).
REX_EXPORT_STUB_RETURN(__imp__KeSetTimer, 0);
// (Audit A3, ronda 6, R6-03.) Was a bare stub: r3 came back as the
// first argument. 0 is the honest value (FALSE / previous count 0).
REX_EXPORT_STUB_RETURN(__imp__KeSetTimerEx, 0);
REX_EXPORT_STUB(__imp__KeStallExecutionProcessor);
REX_EXPORT_STUB(__imp__KeSweepDcacheRange);
REX_EXPORT_STUB(__imp__KeSweepIcacheRange);
// (Audit A3, ronda 6, R6-03.) Was a bare stub: r3 came back as the
// first argument. 0 is the honest value (FALSE / previous count 0).
REX_EXPORT_STUB_RETURN(__imp__KeTestAlertThread, 0);
REX_EXPORT(__imp__KfRaiseIrql, rex::kernel::xboxkrnl::KfRaiseIrql_entry)
