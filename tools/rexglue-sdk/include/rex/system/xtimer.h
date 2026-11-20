#pragma once
/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2013 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <rex/system/xobject.h>
#include <rex/system/xtypes.h>
#include <rex/thread.h>

namespace rex::system {

struct XDPC;

struct X_KTIMER {
  X_DISPATCH_HEADER header;         // 0x0
  rex::be<uint64_t> due_time;       // 0x10
  X_LIST_ENTRY table_bucket_entry;  // 0x18
  TypedGuestPointer<XDPC> dpc;      // 0x20
  rex::be<uint32_t> period;         // 0x24
};
static_assert_size(X_KTIMER, 0x28);

class XThread;

class XTimer : public XObject {
 public:
  static const XObject::Type kObjectType = XObject::Type::Timer;

  explicit XTimer(KernelState* kernel_state);
  ~XTimer() override;

  // Returns false for a timer_type outside {0, 1}; the timer is left
  // without a host primitive and must not be used. (Hunt v1.4.6, ronda 4,
  // A3-R4-04.) Initialize used to be void and left timer_ null on a bad
  // type, and NtCreateTimer returned SUCCESS anyway; NtSetTimerEx /
  // NtCancelTimer then dereferenced the null timer_.
  bool Initialize(uint32_t timer_type);

  X_STATUS SetTimer(int64_t due_time, uint32_t period_ms, uint32_t routine, uint32_t routine_arg,
                    bool resume);
  X_STATUS Cancel();

 protected:
  rex::thread::WaitHandle* GetWaitHandle() override { return timer_.get(); }

 private:
  std::unique_ptr<rex::thread::Timer> timer_;

  XThread* callback_thread_ = nullptr;
  uint32_t callback_routine_ = 0;
  uint32_t callback_routine_arg_ = 0;
};

}  // namespace rex::system
