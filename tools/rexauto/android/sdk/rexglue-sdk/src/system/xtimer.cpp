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

#include <limits>

#include <rex/chrono/chrono.h>
#include <rex/chrono/clock.h>
#include <rex/logging.h>
#include <rex/system/xthread.h>
#include <rex/system/xtimer.h>

namespace rex::system {

XTimer::XTimer(KernelState* kernel_state) : XObject(kernel_state, kObjectType) {}

XTimer::~XTimer() = default;

bool XTimer::Initialize(uint32_t timer_type) {
  assert_false(timer_);
  switch (timer_type) {
    case 0:  // NotificationTimer
      timer_ = rex::thread::Timer::CreateManualResetTimer();
      break;
    case 1:  // SynchronizationTimer
      timer_ = rex::thread::Timer::CreateSynchronizationTimer();
      break;
    default:
      // (Hunt v1.4.6, ronda 4, A3-R4-04.) Unknown type: no host
      // primitive exists for this timer. Report it instead of leaving
      // timer_ null for SetTimer/Cancel to dereference.
      assert_always();
      return false;
  }
  if (!timer_) {
    return false;
  }
  return true;
}

X_STATUS XTimer::SetTimer(int64_t due_time, uint32_t period_ms, uint32_t routine,
                          uint32_t routine_arg, bool resume) {
  using rex::chrono::WinSystemClock;
  using rex::chrono::XSystemClock;
  // (Hunt v1.4.6, ronda 4, A3-R4-04.) Defense in depth for a timer
  // whose Initialize failed: no primitive, nothing to arm.
  if (!timer_) {
    return X_STATUS_UNSUCCESSFUL;
  }
  // Caller is checking for STATUS_TIMER_RESUME_IGNORED.
  if (resume) {
    return X_STATUS_TIMER_RESUME_IGNORED;
  }

  period_ms = chrono::Clock::ScaleGuestDurationMillis(period_ms);
  WinSystemClock::time_point due_tp;
  if (due_time < 0) {
    // Any timer implementation uses absolute times eventually, convert as early
    // as possible for increased accuracy
    // (Hunt v1.4.6, ronda 18, A3-R18-02.) -due_time is signed overflow (UB)
    // when due_time == INT64_MIN (the infinite-wait sentinel a guest may
    // pass; same class as A3-R15-03/A3-R17-02/A3-R18-01). Clamp it to the
    // longest representable duration instead.
    int64_t relative_ticks =
        due_time == std::numeric_limits<int64_t>::min()
            ? std::numeric_limits<int64_t>::max()
            : -due_time;
    auto after = rex::chrono::hundrednanoseconds(relative_ticks);
    due_tp = std::chrono::clock_cast<WinSystemClock>(XSystemClock::now() + after);
  } else {
    due_tp = std::chrono::clock_cast<WinSystemClock>(XSystemClock::from_file_time(due_time));
  }

  // Stash routine for callback.
  callback_thread_ = XThread::GetCurrentThread();
  callback_routine_ = routine;
  callback_routine_arg_ = routine_arg;

  // This callback will only be issued when the timer is fired.
  std::function<void()> callback = nullptr;
  if (callback_routine_) {
    callback = [this]() {
      // Queue APC to call back routine with (arg, low, high).
      // It'll be executed on the thread that requested the timer.
      uint64_t time = rex::chrono::Clock::QueryGuestSystemTime();
      uint32_t time_low = static_cast<uint32_t>(time);
      uint32_t time_high = static_cast<uint32_t>(time >> 32);
      REXSYS_DEBUG("XTimer enqueuing timer callback to {:08X}({:08X}, {:08X}, {:08X})",
                   callback_routine_, callback_routine_arg_, time_low, time_high);
      // (Hunt v1.4.6, ronda 4, A3-R4-13.) GetCurrentThread() is null
      // when SetTimer runs on a host thread with no guest TLS; the
      // callback then has nowhere to deliver the APC to. Skip it
      // instead of dereferencing the null thread. (The captured `this`
      // is safe: destroying the host timer cancels pending callbacks —
      // PosixCondition's destructor Disarms the wait item and blocks
      // until a running callback finishes — so the callback cannot
      // fire after this XTimer is gone.)
      if (callback_thread_) {
        callback_thread_->EnqueueApc(callback_routine_, callback_routine_arg_, time_low, time_high);
      }
    };
  }

  bool result;
  if (!period_ms) {
    result = timer_->SetOnceAt(due_tp, std::move(callback));
  } else {
    result =
        timer_->SetRepeatingAt(due_tp, std::chrono::milliseconds(period_ms), std::move(callback));
  }

  return result ? X_STATUS_SUCCESS : X_STATUS_UNSUCCESSFUL;
}

X_STATUS XTimer::Cancel() {
  // (Hunt v1.4.6, ronda 4, A3-R4-04.) See SetTimer above.
  if (!timer_) {
    return X_STATUS_UNSUCCESSFUL;
  }
  return timer_->Cancel() ? X_STATUS_SUCCESS : X_STATUS_UNSUCCESSFUL;
}

}  // namespace rex::system
