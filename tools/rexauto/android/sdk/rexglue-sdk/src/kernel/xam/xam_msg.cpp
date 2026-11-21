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

#include <rex/kernel/xam/private.h>
#include <rex/kernel/xboxkrnl/error.h>
#include <rex/logging.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xevent.h>
#include <rex/system/xio.h>
#include <rex/system/xthread.h>
#include <rex/system/xtypes.h>

namespace rex {
namespace kernel {
namespace xam {
using namespace rex::system;
using namespace rex::system::xam;

u32 XMsgInProcessCall_entry(u32 app, u32 message, u32 arg1, u32 arg2) {
  auto result = REX_KERNEL_STATE()->app_manager()->DispatchMessageSync(app, message, arg1, arg2);
  if (result == X_ERROR_NOT_FOUND) {
    REXKRNL_ERROR("XMsgInProcessCall: app {:08X} undefined", app);
  }
  return result;
}

u32 XMsgSystemProcessCall_entry(u32 app, u32 message, u32 buffer, u32 buffer_length) {
  auto result =
      REX_KERNEL_STATE()->app_manager()->DispatchMessageAsync(app, message, buffer, buffer_length);
  if (result == X_ERROR_NOT_FOUND) {
    REXKRNL_ERROR("XMsgSystemProcessCall: app {:08X} undefined", app);
  }
  return result;
}

struct XMSGSTARTIOREQUEST_UNKNOWNARG {
  be<uint32_t> unk_0;
  be<uint32_t> unk_1;
};

X_HRESULT xeXMsgStartIORequestEx(uint32_t app, uint32_t message, uint32_t overlapped_ptr,
                                 uint32_t buffer_ptr, uint32_t buffer_length,
                                 XMSGSTARTIOREQUEST_UNKNOWNARG* unknown) {
  auto result = REX_KERNEL_STATE()->app_manager()->DispatchMessageAsync(app, message, buffer_ptr,
                                                                        buffer_length);
  if (result == X_E_NOTFOUND) {
    REXKRNL_ERROR("XMsgStartIORequestEx: app {:08X} undefined", app);
    result = X_E_INVALIDARG;
    XThread::SetLastError(X_ERROR_NOT_FOUND);
  }
  if (overlapped_ptr) {
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped_ptr, result);
    result = X_ERROR_IO_PENDING;
  }
  if (result == X_ERROR_SUCCESS || result == X_ERROR_IO_PENDING) {
    XThread::SetLastError(0);
  }
  return result;
}

u32 XMsgStartIORequestEx_entry(u32 app, u32 message, ppc_ptr_t<XAM_OVERLAPPED> overlapped_ptr,
                               u32 buffer_ptr, u32 buffer_length,
                               ppc_ptr_t<XMSGSTARTIOREQUEST_UNKNOWNARG> unknown_ptr) {
  return xeXMsgStartIORequestEx(app, message, overlapped_ptr.guest_address(), buffer_ptr,
                                buffer_length, unknown_ptr);
}

u32 XMsgStartIORequest_entry(u32 app, u32 message, ppc_ptr_t<XAM_OVERLAPPED> overlapped_ptr,
                             u32 buffer_ptr, u32 buffer_length) {
  return xeXMsgStartIORequestEx(app, message, overlapped_ptr.guest_address(), buffer_ptr,
                                buffer_length, nullptr);
}

u32 XMsgCancelIORequest_entry(ppc_ptr_t<XAM_OVERLAPPED> overlapped_ptr, u32 wait) {
  // (Hunt v1.4.6, ronda 3, A3-R3-10.) XOverlappedGetEvent reads p[3]
  // of the struct unconditionally; a NULL overlapped pointer SIGSEGVd
  // the host before anything else ran.
  if (!overlapped_ptr) {
    return X_ERROR_INVALID_PARAMETER;
  }
  X_HANDLE event_handle = XOverlappedGetEvent(overlapped_ptr);
  if (event_handle && wait) {
    auto ev = REX_KERNEL_OBJECTS()->LookupObject<XEvent>(event_handle);
    if (ev) {
      // (Ronda 4, R4-C1.) Non-alertable on purpose: the result of this wait
      // is discarded, so an APC wake-up buys nothing here -- it would only
      // end the wait early, before the event is signaled. The alertable
      // path slices every wait into 1 ms cond_timedwait slices
      // (threading_posix.cpp: kAlertablePollSlice), so the old infinite
      // alertable wait burned ~1000 futex waits/s for as long as the event
      // stayed unsignaled. The non-alertable path blocks on the same
      // condvar until the event is signaled. Caveat, stated plainly: an
      // APC queued to this guest thread during the wait now runs at the
      // next alertable point instead of during this wait; this is a cancel
      // path, not a completion pump, and the wait's own result is ignored
      // either way.
      ev->Wait(0, 0, false, nullptr);
    }
  }

  return 0;
}

u32 XMsgCompleteIORequest_entry(ppc_ptr_t<XAM_OVERLAPPED> overlapped_ptr, u32 result,
                                u32 extended_error, u32 length) {
  // (Hunt v1.4.6, ronda 4, A3-R4-19.) Same guard as its sisters R3-10
  // (XMsgCancelIORequest, XamGetOverlappedResult): a null overlapped
  // used to complete the overlapped at guest address 0.
  if (!overlapped_ptr) {
    return X_ERROR_INVALID_PARAMETER;
  }
  REX_KERNEL_STATE()->CompleteOverlappedImmediateEx(overlapped_ptr.guest_address(), result,
                                                    extended_error, length);
  return X_ERROR_SUCCESS;
}

u32 XamGetOverlappedResult_entry(ppc_ptr_t<XAM_OVERLAPPED> overlapped_ptr, mapped_u32 length_ptr,
                                 u32 unknown) {
  // (Hunt v1.4.6, ronda 3, A3-R3-10.) overlapped_ptr->result is read
  // first thing below; a NULL overlapped pointer SIGSEGVd the host.
  // (length_ptr in this same function is already guarded.)
  if (!overlapped_ptr) {
    return X_ERROR_INVALID_PARAMETER;
  }
  uint32_t result;
  if (overlapped_ptr->result != X_ERROR_IO_PENDING) {
    result = overlapped_ptr->result;
  } else if (!overlapped_ptr->event) {
    result = X_ERROR_IO_INCOMPLETE;
  } else {
    auto ev = REX_KERNEL_OBJECTS()->LookupObject<XEvent>(overlapped_ptr->event);
    // (Hunt v1.4.6, ronda 2, A3-R2-02.) LookupObject returns nullptr
    // for an invalid/closed handle; there was no check at all here,
    // so ev->Wait on null used to SIGSEGV the host.
    if (!ev) {
      return X_ERROR_INVALID_HANDLE;
    }
    result = ev->Wait(3, 1, 0, nullptr);
    if (XSUCCEEDED(result)) {
      result = overlapped_ptr->result;
    } else {
      result = xboxkrnl::xeRtlNtStatusToDosError(result);
    }
  }
  if (XSUCCEEDED(result) && length_ptr) {
    *length_ptr = overlapped_ptr->length;
  }
  return result;
}

}  // namespace xam
}  // namespace kernel
}  // namespace rex

REX_EXPORT(__imp__XMsgInProcessCall, rex::kernel::xam::XMsgInProcessCall_entry)
REX_EXPORT(__imp__XMsgSystemProcessCall, rex::kernel::xam::XMsgSystemProcessCall_entry)
REX_EXPORT(__imp__XMsgStartIORequestEx, rex::kernel::xam::XMsgStartIORequestEx_entry)
REX_EXPORT(__imp__XMsgStartIORequest, rex::kernel::xam::XMsgStartIORequest_entry)
REX_EXPORT(__imp__XMsgCancelIORequest, rex::kernel::xam::XMsgCancelIORequest_entry)
REX_EXPORT(__imp__XMsgCompleteIORequest, rex::kernel::xam::XMsgCompleteIORequest_entry)
REX_EXPORT(__imp__XamGetOverlappedResult, rex::kernel::xam::XamGetOverlappedResult_entry)

// (Audit run #16, A-6.) These three return an error, never success and never
// IO_PENDING: a bare REX_STUB leaves r3 = the app id (< 0x80000000), which
// XSUCCEEDED reads as success, and the caller would then read an overlapped
// that was never filled. X_ERROR_NOT_FOUND (xtypes.h) is the honest answer:
// no message queue exists for them. 0 would be the same success lie; an
// IO_PENDING that never completes would hang whoever waits on it.
// XMsgCancelIORequest / XMsgCompleteIORequest above are implemented, not
// touched.
REX_EXPORT_STUB_RETURN(__imp__XMsgAcquireAsyncMessageFromOverlapped, X_ERROR_NOT_FOUND);
REX_EXPORT_STUB_RETURN(__imp__XMsgProcessRequest, X_ERROR_NOT_FOUND);
REX_EXPORT_STUB_RETURN(__imp__XMsgReleaseAsyncMessageToOverlapped, X_ERROR_NOT_FOUND);
