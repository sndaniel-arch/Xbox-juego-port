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

#include <rex/kernel/xam/module.h>
#include <rex/kernel/xam/private.h>
#include <rex/logging.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/string.h>
#include <rex/system/kernel_state.h>
#include <rex/system/function_dispatcher.h>
#include <rex/system/user_module.h>
#include <rex/system/xthread.h>
#include <rex/system/xtypes.h>

#if REX_PLATFORM_WIN32
#include <rex/platform.h>
#endif

#include <fmt/format.h>

namespace rex {
namespace kernel {
namespace xam {
using namespace rex::system;
using namespace rex::system::xam;

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

struct XTASK_MESSAGE {
  be<uint32_t> unknown_00;
  be<uint32_t> unknown_04;
  be<uint32_t> unknown_08;
  be<uint32_t> callback_arg_ptr;
  be<uint32_t> event_handle;
  be<uint32_t> unknown_14;
  be<uint32_t> task_handle;
};
static_assert_size(XTASK_MESSAGE, 0x1C);

u32 XamTaskSchedule_entry(mapped_void callback, ppc_ptr_t<XTASK_MESSAGE> message,
                          mapped_u32 unknown, mapped_u32 handle_ptr) {
  // (Audit A3, ronda 6, R6-06.) A NULL handle_ptr used to write the
  // dummy handle to guest address 0.
  if (!handle_ptr) {
    return X_STATUS_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, ronda 10, A3-R10-12.) *handle_ptr is written below
  // with only the NULL check above: validate the 4-byte range first.
  if (!GuestRangeWritable(handle_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, ronda 10, A3-R10-15.) GetExecutableModule() can
  // return nullptr; the old code derefed it below with only an
  // assert (a no-op in Release). Check before the handle is handed
  // out, so a failure here does not leave a dummy handle behind.
  auto module = REX_KERNEL_STATE()->GetExecutableModule();
  if (!module) {
    return X_STATUS_INVALID_PARAMETER;
  }

  // TODO(gibbed): figure out what this is for
  *handle_ptr = 12345;

  uint32_t stack_size = module->stack_size();

  // Stack must be aligned to 16kb pages
  stack_size = std::max((uint32_t)0x4000, ((stack_size + 0xFFF) & 0xFFFFF000));

  auto thread =
      object_ref<XThread>(new XThread(REX_KERNEL_STATE(), stack_size, 0, callback.guest_address(),
                                      message.guest_address(), 0, true));

  X_STATUS result = thread->Create();

  if (XFAILED(result)) {
    // Failed!
    REXKRNL_ERROR("XAM task creation failed: {:08X}", result);
    return result;
  }

  REXKRNL_DEBUG("XAM task ({:08X}) scheduled asynchronously", callback.guest_address());

  return X_STATUS_SUCCESS;
}

u32 XamTaskShouldExit_entry(u32 r3) {
  return 0;
}

u32 XamTaskCloseHandle_entry(u32 handle) {
  REXKRNL_DEBUG("XamTaskCloseHandle({:#x}) - stub", (uint32_t)handle);
  return X_STATUS_SUCCESS;
}

}  // namespace xam
}  // namespace kernel
}  // namespace rex

REX_EXPORT(__imp__XamTaskSchedule, rex::kernel::xam::XamTaskSchedule_entry)
REX_EXPORT(__imp__XamTaskShouldExit, rex::kernel::xam::XamTaskShouldExit_entry)
REX_EXPORT(__imp__XamTaskCloseHandle, rex::kernel::xam::XamTaskCloseHandle_entry)

REX_EXPORT_STUB(__imp__XamTaskCancel);
REX_EXPORT_STUB(__imp__XamTaskCancelWaitAndCloseWaitTask);
REX_EXPORT_STUB(__imp__XamTaskCreateQueue);
REX_EXPORT_STUB(__imp__XamTaskCreateQueueEx);
REX_EXPORT_STUB(__imp__XamTaskGetAttributes);
REX_EXPORT_STUB(__imp__XamTaskGetCompletionStatus);
REX_EXPORT_STUB(__imp__XamTaskGetCurrentTask);
REX_EXPORT_STUB(__imp__XamTaskGetStatus);
REX_EXPORT_STUB(__imp__XamTaskModify);
REX_EXPORT_STUB(__imp__XamTaskQueryProperty);
REX_EXPORT_STUB(__imp__XamTaskReschedule);
REX_EXPORT_STUB(__imp__XamTaskSetCancelSubTasks);
REX_EXPORT_STUB(__imp__XamTaskWaitOnCompletion);
