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

#include <rex/assert.h>
#include <rex/audio/audio_driver.h>
#include <rex/audio/audio_system.h>
#include <rex/audio/flags.h>
#include <rex/audio/xma/decoder.h>
#include <rex/dbg.h>
#include <rex/logging.h>
#include <rex/math.h>
#include <rex/memory/ring_buffer.h>
#include <rex/stream.h>
#include <rex/string/buffer.h>
#include <rex/system/thread_state.h>
#include <rex/thread.h>
#include <rex/cvar.h>

REXCVAR_DEFINE_INT32(
    audio_maxqframes, 8, "Audio",
    "Max buffered audio frames (range 4-64). Lower reduces latency but may cause stuttering.");

// As with normal Microsoft, there are like twelve different ways to access
// the audio APIs. Early games use XMA*() methods almost exclusively to touch
// decoders. Later games use XAudio*() and direct memory writes to the XMA
// structures (as opposed to the XMA* calls), meaning that we have to support
// both.
//
// For ease of implementation, most audio related processing is handled in
// AudioSystem, and the functions here call off to it.
// The XMA*() functions just manipulate the audio system in the guest context
// and let the normal AudioSystem handling take it, to prevent duplicate
// implementations. They can be found in xboxkrnl_audio_xma.cc

namespace rex::audio {

namespace {
constexpr std::chrono::milliseconds kWorkerShutdownTimeout{500};
// (Hunt v1.4.6 ronda 3, A4-R3-02.) Bound for the pause fence wait: long
// enough for a worker parked inside a guest callback / FFmpeg decode to
// reach its park point (the audio WaitAny cycle is 500 ms), short enough
// that the Android UI thread never hangs on pause. On timeout Pause()
// logs and returns with paused_ still set; the worker parks when it can
// and Resume() unparks it.
constexpr std::chrono::milliseconds kPauseFenceTimeout{1000};
}  // namespace

AudioSystem::AudioSystem(runtime::FunctionDispatcher* function_dispatcher)
    : memory_(function_dispatcher->memory()),
      function_dispatcher_(function_dispatcher),
      worker_running_(false) {
  std::memset(clients_, 0, sizeof(clients_));

  queued_frames_ = std::min(
      static_cast<uint32_t>(kMaximumQueuedFrames),
      std::max(static_cast<uint32_t>(REXCVAR_GET(audio_maxqframes)), static_cast<uint32_t>(4)));

  for (size_t i = 0; i < kMaximumClientCount; ++i) {
    client_semaphores_[i] = rex::thread::Semaphore::Create(0, queued_frames_);
    assert_not_null(client_semaphores_[i]);
    wait_handles_[i] = client_semaphores_[i].get();
  }
  shutdown_event_ = rex::thread::Event::CreateAutoResetEvent(false);
  assert_not_null(shutdown_event_);
  wait_handles_[kMaximumClientCount] = shutdown_event_.get();

  xma_decoder_ = std::make_unique<rex::audio::XmaDecoder>(function_dispatcher_);

  resume_event_ = rex::thread::Event::CreateAutoResetEvent(false);
  assert_not_null(resume_event_);
}

AudioSystem::~AudioSystem() {
  if (xma_decoder_) {
    xma_decoder_->Shutdown();
  }
}

X_STATUS AudioSystem::Setup(system::KernelState* kernel_state) {
  X_STATUS result = xma_decoder_->Setup(kernel_state);
  if (result) {
    return result;
  }

  worker_running_ = true;
  worker_thread_ = system::object_ref<system::XHostThread>(
      new system::XHostThread(kernel_state, 128 * 1024, 0, [this]() {
        WorkerThreadMain();
        return 0;
      }));

  worker_thread_->set_name("Audio Worker");
  worker_thread_->Create();

  return X_STATUS_SUCCESS;
}

void AudioSystem::WorkerThreadMain() {
  // Initialize driver and ringbuffer.
  Initialize();

  // Main run loop.
  uint32_t diag_pump_count = 0;
  while (worker_running_) {
    // These handles signify the number of submitted samples. Once we reach
    // 64 samples, we wait until our audio backend releases a semaphore
    // (signaling a sample has finished playing)
    // Non-alertable on purpose (hunt round 2, auditor H): the alertable
    // path slices every wait into 1 ms pthread_cond_timedwait slices
    // (threading_posix.cpp: kAlertablePollSlice), so this 500 ms wait cost
    // ~500 futex waits per cycle -- ~1000 futex/s forever, even idle -- and
    // this host worker thread NEVER receives a user APC. (Caza ronda 5,
    // auditor C, R5-C3): the producer list this comment used to give --
    // "only NtQueueApcThread and TerminateTitle" -- was incomplete. The
    // full set of QueueUserCallback producers is: NtQueueApcThread
    // (xboxkrnl_threading.cpp), KernelState::TerminateTitle
    // (kernel_state.cpp), XThread::UnlockApc and XThread::EnqueueApc
    // (xthread.cpp -- reached from NtReadFile/NtReadFileScatter/
    // NtWriteFile, KernelState::CompleteOverlappedEx and XTimer). Every
    // one of them queues on an XThread guest object -- the APC is delivered
    // through that guest thread's own host thread. This Audio Worker is a
    // bare XHostThread created directly in AudioSystem::Initialize, with no
    // XThread wrapper and no guest handle that could ever name it, so no
    // producer can target it. The blocking path waits the full 500 ms on
    // one condvar wait: ~2 futex/s idle. Semaphore/shutdown wake-ups are
    // unaffected (same condvar, same handles); worst case an APC that could
    // never arrive here would wait up to the 500 ms timeout.
    auto result = rex::thread::WaitAny(wait_handles_, rex::countof(wait_handles_), false,
                                       std::chrono::milliseconds(500));
    if (result.first == rex::thread::WaitResult::kFailed) {
      REXAPU_WARN("AudioWorker: WaitAny failed");
      continue;
    }

    if (result.first == rex::thread::WaitResult::kTimeout) {
      if (diag_pump_count < 5) {
        REXAPU_NOISY_DEBUG("AudioWorker: WaitAny timed out (no semaphore signals)");
      }
    }

    if (result.first == thread::WaitResult::kSuccess && result.second == kMaximumClientCount) {
      // Shutdown event signaled.
      if (paused_) {
        pause_fence_.Signal();
        thread::Wait(resume_event_.get(), false);
      }

      continue;
    }

    if (result.first == rex::thread::WaitResult::kSuccess) {
      auto index = result.second;

      auto global_lock = global_critical_region_.Acquire();
      uint32_t client_callback = clients_[index].callback;
      uint32_t client_callback_arg = clients_[index].wrapped_callback_arg;
      global_lock.unlock();

      if (client_callback) {
        if (diag_pump_count < 10) {
          REXAPU_DEBUG("AudioWorker: dispatching callback {:08X} with arg {:08X} for client {}",
                       client_callback, client_callback_arg, index);
        }
        SCOPE_profile_cpu_i("apu", "rex::audio::AudioSystem->client_callback");
        uint64_t args[] = {client_callback_arg};
        function_dispatcher_->Execute(worker_thread_->thread_state(), client_callback, args,
                                      rex::countof(args));
        if (diag_pump_count < 10) {
          REXAPU_DEBUG("AudioWorker: callback returned for client {}", index);
        }
        diag_pump_count++;
      } else {
        REXAPU_DEBUG("AudioWorker: semaphore signaled for client {} but callback is 0", index);
      }
    }

    if (!worker_running_) {
      break;
    }

    // (Audit run #16, M-9.) No extra sleep when idle: the WaitAny above
    // already waits up to 500 ms and wakes immediately on a semaphore, so
    // the old Sleep(500) here only added up to 500 ms of wake latency on
    // the idle -> active transition (the first audio after silence) while
    // saving one condvar wait per second. The loop now re-waits at once.
  }
  worker_running_ = false;

  // TODO(benvanik): call module API to kill?
}

int AudioSystem::FindFreeClient() {
  for (size_t i = 0; i < kMaximumClientCount; i++) {
    auto& client = clients_[i];
    if (!client.in_use) {
      return i;
    }
  }

  return -1;
}

void AudioSystem::Initialize() {}

void AudioSystem::Shutdown() {
  if (!worker_running_) {
    return;
  }

  // Shut down XMA decoder first - its worker can stall in FFmpeg
  if (xma_decoder_) {
    xma_decoder_->Shutdown();
  }

  worker_running_ = false;
  // (Hunt v1.4.6 ronda 2, A4-R2-03.) Resume a paused worker before waiting
  // for it: Pause() parks the worker in Wait(resume_event_) (see the
  // shutdown-event branch of WorkerThreadMain), so it never observes the
  // shutdown event and the 500 ms wait below always expires into the
  // Terminate(0) last resort on a normal pause-then-teardown path. Same
  // pattern as XmaDecoder::Shutdown, which already does
  // `if (paused_) Resume();` before waiting for its worker. Resume() also
  // calls xma_decoder_->Resume(), which is a no-op here: the decoder was
  // just shut down above and its own paused_ is already false.
  if (paused_) {
    Resume();
  }
  shutdown_event_->Set();
  if (worker_thread_) {
    // The worker may be stuck inside a guest callback that is itself blocked on
    // guest objects (e.g. KeWaitForMultipleObjects), so terminating is the last
    // resort. Give it a chance to unwind first: TerminateThread abandons any
    // lock the thread holds, including the CRT heap lock.
    rex::thread::Thread* host_thread = worker_thread_->thread();
    bool exited = host_thread && rex::thread::Wait(host_thread, false, kWorkerShutdownTimeout) ==
                                     rex::thread::WaitResult::kSuccess;
    if (!exited) {
      // (Audit run #16, M-9.) Terminate(0) stays, deliberately: the orderly
      // path above (shutdown_event_ + a bounded 500 ms wait) already runs
      // first, and this only fires when the worker is stuck inside a guest
      // callback blocked on guest objects -- in that case there is no
      // orderly way out, and removing the Terminate would turn a bounded
      // forced kill into a shutdown hang (or a reset() of a still-running
      // thread). Pending a real fix for stuck guest callbacks, not for
      // this round. The 500 ms idle sleep in WorkerThreadMain was the
      // part that could go: it only added wake latency.
      REXAPU_WARN("Audio worker did not exit within {} ms; terminating",
                  kWorkerShutdownTimeout.count());
      worker_thread_->Terminate(0);
    }
    worker_thread_.reset();
  }

  // Destroy all active client drivers (closes SDL audio devices, stopping
  // callback threads) before the semaphores they reference are destroyed.
  for (size_t i = 0; i < kMaximumClientCount; i++) {
    if (clients_[i].in_use) {
      DestroyDriver(clients_[i].driver);
      if (clients_[i].wrapped_callback_arg) {
        memory()->SystemHeapFree(clients_[i].wrapped_callback_arg);
      }
      clients_[i] = {nullptr, 0, 0, 0, false};
    }
  }
}

X_STATUS AudioSystem::RegisterClient(uint32_t callback, uint32_t callback_arg, size_t* out_index) {
  REXAPU_DEBUG("AudioSystem::RegisterClient: callback={:08X} callback_arg={:08X}", callback,
               callback_arg);
  auto global_lock = global_critical_region_.Acquire();

  auto index = FindFreeClient();
  // (Run #16, C-01.) With all 8 clients busy FindFreeClient returns -1;
  // assert_true is a no-op in Release, so the code below would index
  // clients_[-1] - out of bounds. Fail cleanly instead: the caller
  // (xboxkrnl_audio.cpp) propagates the failure to the guest, which can
  // retry or take the no-audio path.
  if (index < 0) {
    REXAPU_WARN("AudioSystem::RegisterClient: all {} clients busy",
                kMaximumClientCount);
    return X_STATUS_INSUFFICIENT_RESOURCES;
  }
  REXAPU_DEBUG("AudioSystem::RegisterClient: using client index={} queued_frames={}", index,
               queued_frames_);

  auto client_semaphore = client_semaphores_[index].get();
  auto ret = client_semaphore->Release(queued_frames_, nullptr);
  assert_true(ret);

  AudioDriver* driver;
  auto result = CreateDriver(index, client_semaphore, &driver);
  if (XFAILED(result)) {
    return result;
  }
  assert_not_null(driver);

  uint32_t ptr = memory()->SystemHeapAlloc(0x4);
  memory::store_and_swap<uint32_t>(memory()->TranslateVirtual(ptr), callback_arg);

  clients_[index] = {driver, callback, callback_arg, ptr, true};

  if (out_index) {
    *out_index = index;
  }

  return X_STATUS_SUCCESS;
}

void AudioSystem::SubmitFrame(size_t index, uint32_t samples_ptr) {
  SCOPE_profile_cpu_f("apu");

  static uint32_t submit_count = 0;
  if (submit_count < 10) {
    REXAPU_DEBUG("AudioSystem::SubmitFrame called: index={} samples_ptr={:08X}", index,
                 samples_ptr);
    submit_count++;
  }

  auto global_lock = global_critical_region_.Acquire();
  // (Run #16, C-01.) The asserts are no-ops in Release; an out-of-range
  // or free client index would dereference garbage. Validate and drop
  // the frame instead.
  if (index >= kMaximumClientCount || !clients_[index].in_use ||
      clients_[index].driver == NULL) {
    REXAPU_WARN("AudioSystem::SubmitFrame: invalid client index={}", index);
    return;
  }
  (clients_[index].driver)->SubmitFrame(samples_ptr);
}

void AudioSystem::UnregisterClient(size_t index) {
  SCOPE_profile_cpu_f("apu");

  auto global_lock = global_critical_region_.Acquire();
  // (Run #16, C-01.) Same as SubmitFrame: the assert is a no-op in
  // Release, so validate before touching the client.
  if (index >= kMaximumClientCount || !clients_[index].in_use) {
    REXAPU_WARN("AudioSystem::UnregisterClient: invalid client index={}",
                index);
    return;
  }
  DestroyDriver(clients_[index].driver);
  memory()->SystemHeapFree(clients_[index].wrapped_callback_arg);
  clients_[index] = {nullptr, 0, 0, 0, false};

  // Drain the semaphore of its count.
  auto client_semaphore = client_semaphores_[index].get();
  rex::thread::WaitResult wait_result;
  do {
    wait_result = rex::thread::Wait(client_semaphore, false, std::chrono::milliseconds(0));
  } while (wait_result == rex::thread::WaitResult::kSuccess);
  assert_true(wait_result == rex::thread::WaitResult::kTimeout);
}

bool AudioSystem::Save(stream::ByteStream* stream) {
  // (Hunt v1.4.6 ronda 3, A4-R3-07.) Save read clients_ with no lock while
  // a guest thread could be inside SubmitFrame/RegisterClient on the same
  // array; take the global critical region like every other clients_
  // accessor. Recursive mutex, so the lock also covers Restore's
  // UnregisterClient/CreateDriver calls below.
  auto global_lock = global_critical_region_.Acquire();
  stream->Write(kAudioSaveSignature);

  // Count the number of used clients first.
  // Any gaps should be handled gracefully.
  uint32_t used_clients = 0;
  for (size_t i = 0; i < kMaximumClientCount; i++) {
    if (clients_[i].in_use) {
      used_clients++;
    }
  }

  stream->Write(used_clients);
  for (uint32_t i = 0; i < kMaximumClientCount; i++) {
    auto& client = clients_[i];
    if (!client.in_use) {
      continue;
    }

    stream->Write(i);
    stream->Write(client.callback);
    stream->Write(client.callback_arg);
    stream->Write(client.wrapped_callback_arg);
  }

  return true;
}

bool AudioSystem::Restore(stream::ByteStream* stream) {
  // (Hunt v1.4.6 ronda 3, A4-R3-07.) The old Restore ran with no lock, no
  // duplicate-id check and no rollback: a guest thread in SubmitFrame
  // could read clients_[] while Restore freed the driver under it; a
  // stream listing the same id twice unregistered + recreated the client
  // a second time; and a CreateDriver failure mid-stream left clients
  // 0..k-1 restored with no way back. Fixed in three phases, all under
  // the global critical region (recursive, so UnregisterClient below
  // re-acquiring it is safe):
  //  1. parse + validate the whole stream into a scratch list first
  //     (range + duplicate-id checks) without touching clients_;
  //  2. create every new driver into scratch — CreateDriver touches no
  //     clients_ state, so a failure here destroys only the scratch
  //     drivers and leaves the live system exactly as it was;
  //  3. commit: unregister each old client, install its new driver and
  //     fill its semaphore. The commit does no fallible work, so it
  //     cannot fail halfway. Clients live before Restore but absent
  //     from the stream are cleared last, as before.
  auto global_lock = global_critical_region_.Acquire();

  if (stream->Read<uint32_t>() != kAudioSaveSignature) {
    REXAPU_ERROR("AudioSystem::Restore - Invalid magic value!");
    return false;
  }

  uint32_t num_clients = stream->Read<uint32_t>();
  // (Hunt v1.4.6, A4-R6-03.) Same class as C-01: the stream is untrusted
  // (a corrupt/truncated save), and assert_true is a no-op in Release.
  // Bound the count and every id before indexing clients_ /
  // client_semaphores_ below; a bad save fails instead of indexing OOB.
  if (num_clients > kMaximumClientCount) {
    REXAPU_ERROR("AudioSystem::Restore - num_clients {} exceeds maximum {}",
                 num_clients, kMaximumClientCount);
    return false;
  }

  struct RestoredClient {
    uint32_t id;
    uint32_t callback;
    uint32_t callback_arg;
    uint32_t wrapped_callback_arg;
  };
  RestoredClient entries[kMaximumClientCount];
  bool seen[kMaximumClientCount] = {};
  for (uint32_t i = 0; i < num_clients; i++) {
    auto id = stream->Read<uint32_t>();
    if (id >= kMaximumClientCount) {
      REXAPU_ERROR("AudioSystem::Restore - client id {} out of range", id);
      return false;
    }
    if (seen[id]) {
      REXAPU_ERROR("AudioSystem::Restore - duplicate client id {}", id);
      return false;
    }
    seen[id] = true;
    entries[i] = {id, stream->Read<uint32_t>(), stream->Read<uint32_t>(),
                  stream->Read<uint32_t>()};
  }

  // Phase 2: build all replacement drivers before mutating anything.
  AudioDriver* new_drivers[kMaximumClientCount] = {};
  for (uint32_t i = 0; i < num_clients; i++) {
    auto id = entries[i].id;
    auto client_semaphore = client_semaphores_[id].get();
    AudioDriver* driver = nullptr;
    auto status = CreateDriver(id, client_semaphore, &driver);
    if (XFAILED(status)) {
      REXAPU_ERROR(
          "AudioSystem::Restore - Call to CreateDriver failed with status "
          "{:08X}",
          status);
      for (uint32_t j = 0; j < i; j++) {
        DestroyDriver(new_drivers[j]);
      }
      return false;
    }
    assert_not_null(driver);
    new_drivers[i] = driver;
  }

  // Phase 3: commit. No fallible work below this point.
  bool restored[kMaximumClientCount] = {};
  for (uint32_t i = 0; i < num_clients; i++) {
    const auto& entry = entries[i];
    auto& client = clients_[entry.id];

    // Reset the semaphore and recreate the driver ourselves.
    if (client.driver) {
      UnregisterClient(entry.id);
    }

    client.callback = entry.callback;
    client.callback_arg = entry.callback_arg;
    client.wrapped_callback_arg = entry.wrapped_callback_arg;

    auto client_semaphore = client_semaphores_[entry.id].get();
    // CreateDriver only stores the semaphore pointer — see
    // SDLAudioSystem::CreateDriver — so releasing after creation instead of
    // before changes nothing on success, and on failure above no permits
    // are left behind for a client that does not exist.
    auto ret = client_semaphore->Release(queued_frames_, nullptr);
    assert_true(ret);
    client.driver = new_drivers[i];
    client.in_use = true;
    restored[entry.id] = true;
  }

  // Clear clients that were live before Restore but are absent from the
  // stream: their guest state is gone, so keeping them would leave stale
  // drivers and callbacks behind. UnregisterClient destroys the driver,
  // frees the wrapped arg and drains the semaphore.
  for (size_t i = 0; i < kMaximumClientCount; i++) {
    if (clients_[i].in_use && !restored[i]) {
      UnregisterClient(i);
    }
  }

  return true;
}

void AudioSystem::Pause() {
  if (paused_) {
    return;
  }
  // (Hunt v1.4.6 ronda 3, A4-R3-01.) No worker exists yet between the
  // audio-system assignment in Runtime::Setup and the end of Setup()
  // (which creates the worker thread): the old code set paused_ and then
  // waited on pause_fence_ forever, because nothing could ever signal it.
  // A pause before the worker exists is a no-op — do NOT set paused_
  // either, or the worker would start life believing it is parked while
  // its loop only checks paused_ on the shutdown-event branch.
  if (!worker_thread_ || !worker_running_) {
    return;
  }
  paused_ = true;

  // Kind of a hack, but it works.
  shutdown_event_->Set();
  if (!pause_fence_.WaitFor(kPauseFenceTimeout)) {
    // (A4-R3-02.) The worker is stuck inside a guest callback and has
    // not parked yet. Do NOT clear paused_: the worker checks it on the
    // shutdown-event branch, parks when it can, and Resume() (which sets
    // resume_event_, an auto-reset event the worker consumes on arrival)
    // unparks it. The UI thread returns instead of hanging.
    REXAPU_WARN("AudioSystem::Pause: worker did not park within {} ms; continuing paused",
                kPauseFenceTimeout.count());
  }

  xma_decoder_->Pause();
}

void AudioSystem::Resume() {
  if (!paused_) {
    return;
  }
  paused_ = false;

  resume_event_->Set();

  xma_decoder_->Resume();
}

}  // namespace rex::audio
