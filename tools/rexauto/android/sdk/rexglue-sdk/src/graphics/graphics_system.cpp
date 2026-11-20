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

#include <rex/graphics/graphics_system.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_set>
#include <utility>

#include <rex/cvar.h>
#include <rex/graphics/command_processor.h>
#include <rex/graphics/flags.h>
#include <rex/kernel/xboxkrnl/video.h>
#include <rex/logging.h>
#include <rex/stream.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xthread.h>
#include <rex/thread/big_core_affinity.h>
#include <rex/ui/graphics_provider.h>
#include <rex/ui/window.h>
#include <rex/ui/windowed_app_context.h>

REXCVAR_DEFINE_STRING(swap_post_effect, "none", "GPU", "Swap post effect: none, fxaa, fxaa_extreme")
    .allowed({"none", "fxaa", "fxaa_extreme"})
    .lifecycle(rex::cvar::Lifecycle::kRequiresRestart);

REXCVAR_DEFINE_BOOL(store_shaders, true, "GPU",
                    "Store shaders persistently and load them when loading games to avoid "
                    "runtime spikes and freezes when playing the game not for the first time.");

namespace {

rex::graphics::CommandProcessor::SwapPostEffect ParseSwapPostEffect(
    const std::string& effect_name) {
  std::string lowered = effect_name;
  std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) {
    c = static_cast<unsigned char>(std::tolower(c));
    return c == '-' ? '_' : char(c);
  });
  if (lowered == "fxaa") {
    return rex::graphics::CommandProcessor::SwapPostEffect::kFxaa;
  }
  if (lowered == "fxaa_extreme" || lowered == "extreme") {
    return rex::graphics::CommandProcessor::SwapPostEffect::kFxaaExtreme;
  }
  return rex::graphics::CommandProcessor::SwapPostEffect::kNone;
}
}  // namespace

namespace rex::graphics {

// Nvidia Optimus/AMD PowerXpress support.
// These exports force the process to trigger the discrete GPU in multi-GPU
// systems.
// https://developer.download.nvidia.com/devzone/devcenter/gamegraphics/files/OptimusRenderingPolicies.pdf
// https://stackoverflow.com/questions/17458803/amd-equivalent-to-nvoptimusenablement
#if REX_PLATFORM_WIN32
extern "C" {
__declspec(dllexport) uint32_t NvOptimusEnablement = 0x00000001;
__declspec(dllexport) uint32_t AmdPowerXpressRequestHighPerformance = 1;
}  // extern "C"
#endif  // REX_PLATFORM_WIN32

GraphicsSystem::GraphicsSystem() : vsync_worker_running_(false) {}

GraphicsSystem::~GraphicsSystem() = default;

X_STATUS GraphicsSystem::SetupPresentation(ui::WindowedAppContext* app_context) {
  if (presenter_) {
    return X_STATUS_SUCCESS;
  }

  if (!provider_) {
    CreateProvider(true);
    if (!provider_) {
      REXGPU_ERROR("Unable to create graphics provider");
      return X_STATUS_UNSUCCESSFUL;
    }
    provider_supports_presentation_ = true;
  } else if (!provider_supports_presentation_) {
    // A prior SetupGuestGpu built a headless provider; backends like Vulkan
    // need swapchain support baked in at provider creation time.
    REXGPU_ERROR("SetupPresentation called after headless SetupGuestGpu; call order is reversed");
    return X_STATUS_UNSUCCESSFUL;
  }

  app_context_ = app_context;
  auto loss_cb = [this](bool is_responsible, bool statically_from_ui_thread) {
    OnHostGpuLossFromAnyThread(is_responsible);
  };
  if (app_context_) {
    // Presenter creation must happen on the UI thread.
    app_context_->CallInUIThreadSynchronous(
        [this, loss_cb]() { presenter_ = provider_->CreatePresenter(loss_cb); });
  } else {
    // Offscreen path (e.g. capturing guest output without a window).
    presenter_ = provider_->CreatePresenter(loss_cb);
  }

  if (!presenter_) {
    REXGPU_ERROR("Unable to create presenter");
    return X_STATUS_UNSUCCESSFUL;
  }
  return X_STATUS_SUCCESS;
}

X_STATUS GraphicsSystem::SetupGuestGpu(runtime::FunctionDispatcher* function_dispatcher,
                                       system::KernelState* kernel_state) {
  memory_ = function_dispatcher->memory();
  function_dispatcher_ = function_dispatcher;
  kernel_state_ = kernel_state;

  // Headless path: no one set up presentation, so build a no-presentation
  // provider just for the command processor.
  if (!provider_) {
    CreateProvider(false);
    provider_supports_presentation_ = false;
  }

  // Create command processor. This will spin up a thread to process all
  // incoming ringbuffer packets.
  command_processor_ = CreateCommandProcessor();
  if (!command_processor_->Initialize()) {
    REXGPU_ERROR("Unable to initialize command processor");
    return X_STATUS_UNSUCCESSFUL;
  }
  command_processor_->SetDesiredSwapPostEffect(ParseSwapPostEffect(REXCVAR_GET(swap_post_effect)));

  // Register GPU MMIO handlers
  // GPU registers are at 0x7FC80000-0x7FCFFFFF
  memory_->AddVirtualMappedRange(0x7FC80000,  // base address
                                 0xFFFF0000,  // mask
                                 0x0000FFFF,  // size (64KB)
                                 this,        // context (GraphicsSystem*)
                                 reinterpret_cast<runtime::MMIOReadCallback>(ReadRegisterThunk),
                                 reinterpret_cast<runtime::MMIOWriteCallback>(WriteRegisterThunk));

  // Guest vblank timer based on the configured guest video mode.
  vsync_worker_running_ = true;
  vsync_worker_thread_ = system::object_ref<system::XHostThread>(
      new system::XHostThread(kernel_state_, 128 * 1024, 0, [this]() {
        system::X_VIDEO_MODE video_mode;
        kernel::xboxkrnl::VdQueryVideoMode(&video_mode);
        double refresh_rate_hz = std::max(1.0, double(float(video_mode.refresh_rate)));
        // REX_FPS_CAP=<hz>: run the guest vblank at a lower rate than the video
        // mode reports. Titles pace themselves on vblank, so this is a real
        // frame-rate cap that also halves GPU work -- the difference between
        // a phone throttling after five minutes and holding a steady 30.
        // Kept for the periodic re-read below: the env var does not change
        // at runtime, so it is read once.
        double fps_cap_hz = 0.0;
        if (const char* cap = std::getenv("REX_FPS_CAP")) {
          double cap_hz = std::atof(cap);
          if (cap_hz >= 10.0 && cap_hz < refresh_rate_hz) {
            REXLOG_INFO("vblank rate capped at {} Hz (REX_FPS_CAP)", cap_hz);
            refresh_rate_hz = cap_hz;
            fps_cap_hz = cap_hz;
          }
        }
        uint64_t guest_tick_frequency = chrono::Clock::guest_tick_frequency();
        uint64_t vsync_interval_ticks =
            std::max(uint64_t(1), uint64_t(double(guest_tick_frequency) / refresh_rate_hz));
        uint64_t no_vsync_interval_ticks = std::max(uint64_t(1), guest_tick_frequency / 1000);
        uint64_t last_frame_time = chrono::Clock::QueryGuestTickCount();
        uint64_t last_mode_check_time = last_frame_time;
        while (vsync_worker_running_) {
          uint64_t current_time = chrono::Clock::QueryGuestTickCount();
          // (Audit run #16, M-10.) The video mode was read once when this
          // thread started; a mode change afterwards never reached the
          // vblank rate. Cvars are mutable at runtime (settings overlay /
          // console), and the guest may ask for another mode later, so
          // re-read once per guest-second and rebuild the interval when
          // the effective rate moved.
          //
          // (Hunt v1.4.6, R-C-11.) The guest interrupt handler itself
          // stays synchronous (MarkVblank -> DispatchInterruptCallback ->
          // ExecuteInterrupt, which has no timeout): making it async is
          // pending -- the command processor blocks waiting for interrupt
          // code to run, so an async handler needs an ordering analysis
          // first. What this batch does bound the damage instead:
          // (a) while paused (A4-R6-01: app backgrounded, command
          // processor suspended) no vblank is dispatched at all and the
          // backlog is dropped, not banked for resume; (b) if the
          // handler was starved for any other reason, at most 2 stale
          // vblanks fire per iteration and the rest are dropped instead
          // of a burst that re-enters the guest N times in a row.
          if (guest_tick_frequency > 0 &&
              current_time - last_mode_check_time >= guest_tick_frequency) {
            last_mode_check_time = current_time;
            system::X_VIDEO_MODE current_mode;
            kernel::xboxkrnl::VdQueryVideoMode(&current_mode);
            double new_rate_hz = std::max(1.0, double(float(current_mode.refresh_rate)));
            if (fps_cap_hz > 0.0 && fps_cap_hz < new_rate_hz) {
              new_rate_hz = fps_cap_hz;
            }
            if (new_rate_hz != refresh_rate_hz) {
              REXLOG_INFO("vblank rate changed: {} Hz -> {} Hz (video mode {}x{})",
                          refresh_rate_hz, new_rate_hz,
                          uint32_t(current_mode.display_width),
                          uint32_t(current_mode.display_height));
              refresh_rate_hz = new_rate_hz;
              vsync_interval_ticks = std::max(
                  uint64_t(1), uint64_t(double(guest_tick_frequency) / refresh_rate_hz));
            }
          }
          uint64_t interval_ticks =
              REXCVAR_GET(vsync) ? vsync_interval_ticks : no_vsync_interval_ticks;
          if (paused_) {
            // Paused: drop the backlog (see comment above) instead of
            // firing it as a burst on resume.
            last_frame_time = current_time;
          } else {
            // Cap the catch-up burst at 2 stale vblanks per iteration.
            uint64_t missed = (current_time - last_frame_time) / interval_ticks;
            if (missed > 2) {
              last_frame_time = current_time - 2 * interval_ticks;
            }
            while (current_time - last_frame_time >= interval_ticks) {
              MarkVblank();
              last_frame_time += interval_ticks;
            }
          }
          // When time scalar > 1 (fast-forward), yield instead of sleeping
          // to allow vblanks to fire as fast as the guest clock advances.
          if (chrono::Clock::guest_time_scalar() > 1.0) {
            rex::thread::MaybeYield();
          } else {
            rex::thread::Sleep(std::chrono::milliseconds(1));
          }
        }
        return 0;
      }));
  // TODO: set_can_debugger_suspend not yet ported
  // vsync_worker_thread_->set_can_debugger_suspend(true);
  vsync_worker_thread_->set_name("GPU VSync");
  vsync_worker_thread_->Create();

  return X_STATUS_SUCCESS;
}

void GraphicsSystem::Shutdown() {
  // (Hunt v1.4.6 round 2, A1-R2-03.) Stop the vblank worker BEFORE
  // destroying the command processor: MarkVblank() runs on that thread
  // and reads/uses command_processor_, so resetting the unique_ptr first
  // raced with the worker and could use-after-free the processor. No
  // shutdown path pauses first -- Runtime::Shutdown runs from ~Runtime
  // and the Setup failure paths with no Pause() in between, and the
  // Android destroy path hard-exits without reaching Shutdown at all --
  // so Pause() cannot be relied on to close this window; only stopping
  // and joining the thread does.
  if (vsync_worker_thread_) {
    vsync_worker_running_ = false;
    vsync_worker_thread_->Wait(0, 0, 0, nullptr);
    vsync_worker_thread_.reset();
  }

  if (command_processor_) {
    command_processor_->Shutdown();
    command_processor_.reset();
  }

  if (presenter_) {
    if (app_context_) {
      app_context_->CallInUIThreadSynchronous([this]() { presenter_.reset(); });
    }
    // If there's no app context (thus the presenter is owned by the thread that
    // initialized the GraphicsSystem) or can't be queueing UI thread calls
    // anymore, shutdown anyway.
    presenter_.reset();
  }

  provider_.reset();
}

void GraphicsSystem::OnHostGpuLossFromAnyThread([[maybe_unused]] bool is_responsible) {
  // TODO(Triang3l): Somehow gain exclusive ownership of the Provider (may be
  // used by the command processor, the presenter, and possibly anything else,
  // it's considered free-threaded, except for lifetime management which will be
  // involved in this case) and reset it so a new host GPU API device is
  // created. Then ask the command processor to reset itself in its thread, and
  // ask the UI thread to reset the Presenter (the UI thread manages its
  // lifetime - but if there's no WindowedAppContext, either don't reset it as
  // in this case there's no user who needs uninterrupted gameplay, or somehow
  // protect it with a mutex so any thread can be considered a UI thread and
  // reset).
  if (host_gpu_loss_reported_.test_and_set(std::memory_order_relaxed)) {
    return;
  }
  rex::FatalError("Graphics device lost (probably due to an internal error)");
}

uint32_t GraphicsSystem::ReadRegisterThunk(void* ppc_context, GraphicsSystem* gs, uint32_t addr) {
  return gs->ReadRegister(addr);
}

void GraphicsSystem::WriteRegisterThunk(void* ppc_context, GraphicsSystem* gs, uint32_t addr,
                                        uint32_t value) {
  gs->WriteRegister(addr, value);
}

uint32_t GraphicsSystem::ReadRegister(uint32_t addr) {
  uint32_t r = (addr & 0xFFFF) / 4;

  switch (r) {
    case 0x0F00:  // RB_EDRAM_TIMING
      return 0x08100748;
    case 0x0F01:  // RB_BC_CONTROL
      return 0x0000200E;
    case 0x194C: {  // R500_D1MODE_V_COUNTER
      system::X_VIDEO_MODE video_mode;
      kernel::xboxkrnl::VdQueryVideoMode(&video_mode);
      return std::min(uint32_t(video_mode.display_height), uint32_t(0x0FFF));
    }
    case 0x1951:    // interrupt status
      return 1;     // vblank
    case 0x1961: {  // AVIVO_D1MODE_VIEWPORT_SIZE
      // Maximum [width(0x0FFF), height(0x0FFF)].
      system::X_VIDEO_MODE video_mode;
      kernel::xboxkrnl::VdQueryVideoMode(&video_mode);
      uint32_t viewport_width = std::min(uint32_t(video_mode.display_width), uint32_t(0x0FFF));
      uint32_t viewport_height = std::min(uint32_t(video_mode.display_height), uint32_t(0x0FFF));
      return (viewport_width << 16) | viewport_height;
    }
    default:
      if (!register_file_.GetRegisterInfo(r)) {
        REXGPU_DEBUG("GPU: Read from unknown register ({:04X})", r);
      }
  }

  assert_true(r < RegisterFile::kRegisterCount);
  return register_file_.values[r];
}

void GraphicsSystem::WriteRegister(uint32_t addr, uint32_t value) {
  uint32_t r = (addr & 0xFFFF) / 4;

  switch (r) {
    case 0x01C5:  // CP_RB_WPTR
      // (Hunt v1.4.6 round 3, A1-R3-05.) command_processor_ is null after
      // Shutdown() (and before SetupGuestGpu finishes); a register write
      // racing teardown must be dropped, not dereferenced.
      if (command_processor_) {
        command_processor_->UpdateWritePointer(value);
      }
      break;
    case 0x1844:  // AVIVO_D1GRPH_PRIMARY_SURFACE_ADDRESS
      break;
    default: {
      // (Audit run #16, M-6.) A WARN here flushed to disk on EVERY unknown
      // write, in the guest thread (flush_level = warn). Log each distinct
      // register once; later writes to it cost only a set lookup, and the
      // log call happens outside the lock so a flush never blocks another
      // guest thread. The set is capped so a guest spraying the register
      // space cannot grow it without bound. (ReadRegister already logs
      // unknown reads at DEBUG, which is dropped at the Release default
      // level; a throttled WARN keeps the signal visible in the phone log.)
      static std::mutex unknown_register_warn_mutex;
      static std::unordered_set<uint32_t> unknown_registers_warned;
      static std::atomic<bool> unknown_register_warn_cap_logged{false};
      constexpr uint32_t kMaxUnknownRegistersWarned = 256;
      bool warn_now = false;
      bool warn_cap_now = false;
      {
        std::lock_guard<std::mutex> lock(unknown_register_warn_mutex);
        if (unknown_registers_warned.count(r) == 0) {
          if (unknown_registers_warned.size() < kMaxUnknownRegistersWarned) {
            unknown_registers_warned.insert(r);
            warn_now = true;
          } else if (!unknown_register_warn_cap_logged.exchange(true)) {
            warn_cap_now = true;
          }
        }
      }
      if (warn_now) {
        REXGPU_WARN("Unknown GPU register {:04X} write: {:08X}", r, value);
      } else if (warn_cap_now) {
        REXGPU_WARN("Unknown GPU register writes: stopped logging new registers "
                    "after {} distinct ones",
                    kMaxUnknownRegistersWarned);
      }
      break;
    }
  }

  assert_true(r < RegisterFile::kRegisterCount);
  register_file_.values[r] = value;
}

void GraphicsSystem::InitializeRingBuffer(uint32_t ptr, uint32_t size_log2) {
  // (Hunt v1.4.6 round 3, A1-R3-05.) See WriteRegister above.
  if (!command_processor_) {
    return;
  }
  command_processor_->InitializeRingBuffer(ptr, size_log2);
}

void GraphicsSystem::EnableReadPointerWriteBack(uint32_t ptr, uint32_t block_size_log2) {
  // (Hunt v1.4.6 round 3, A1-R3-05.) See WriteRegister above.
  if (!command_processor_) {
    return;
  }
  command_processor_->EnableReadPointerWriteBack(ptr, block_size_log2);
}

void GraphicsSystem::SetInterruptCallback(uint32_t callback, uint32_t user_data) {
  interrupt_callback_ = callback;
  interrupt_callback_data_ = user_data;
  REXGPU_INFO("SetInterruptCallback({:08X}, {:08X})", callback, user_data);
}

void GraphicsSystem::DispatchInterruptCallback(uint32_t source, uint32_t cpu) {
  if (!interrupt_callback_) {
    return;
  }

  auto thread = system::XThread::GetCurrentThread();
  assert_not_null(thread);

  // Pick a CPU, if needed. We're going to guess 2. Because.
  if (cpu == 0xFFFFFFFF) {
    cpu = 2;
  }
  thread->SetActiveCpu(cpu);

  // REXGPU_INFO("Dispatching GPU interrupt at {:08X} w/ mode {} on cpu {}",
  //          interrupt_callback_, source, cpu);

  uint64_t args[] = {source, interrupt_callback_data_};
  function_dispatcher_->ExecuteInterrupt(thread->thread_state(), interrupt_callback_, args,
                                         rex::countof(args));
}

void GraphicsSystem::MarkVblank() {
  // TODO: Enable profiling once ported
  // SCOPE_profile_cpu_f("gpu");

  // Increment vblank counter (so the game sees us making progress).
  if (command_processor_) {
    command_processor_->increment_counter();
  }

  // TODO(benvanik): we shouldn't need to do the dispatch here, but there's
  //     something wrong and the CP will block waiting for code that
  //     needs to be run in the interrupt.
  DispatchInterruptCallback(0, 2);
}

void GraphicsSystem::ClearCaches() {
  // (Hunt v1.4.6 round 3, A1-R3-05.) See WriteRegister above.
  if (!command_processor_) {
    return;
  }
  command_processor_->CallInThread([&]() { command_processor_->ClearCaches(); });
}

void GraphicsSystem::InvalidateGpuMemory() {
  // (Hunt v1.4.6 round 3, A1-R3-05.) See WriteRegister above.
  if (!command_processor_) {
    return;
  }
  command_processor_->CallInThread([&]() { command_processor_->InvalidateGpuMemory(); });
}

void GraphicsSystem::pin_command_processor_thread(uint64_t mask) {
  // Runs inside the GPU plugin, where CommandProcessor::CallInThread is
  // visible: the app must never call it directly (consumers never link
  // librexgpu-xenos.so — run #13 link failure).
  if (command_processor_) {
    command_processor_->CallInThread([mask]() {
      rex::big_core::PinCurrentThreadToBigCores(mask, "GPU Commands");
    });
  }
}

void GraphicsSystem::InitializeShaderStorage(const std::filesystem::path& cache_root,
                                             uint32_t title_id, bool blocking) {
  // (Hunt v1.4.6 round 3, A1-R3-05, 10th site found in the same sweep.)
  // Same null dereference class as the 9 listed sites: every path below
  // touches command_processor_.
  if (!command_processor_) {
    return;
  }
  if (!REXCVAR_GET(store_shaders)) {
    return;
  }
  if (blocking) {
    if (command_processor_->is_paused()) {
      // Safe to run on any thread while the command processor is paused, no
      // race condition.
      command_processor_->InitializeShaderStorage(cache_root, title_id, true);
    } else {
      rex::thread::Fence fence;
      command_processor_->CallInThread([this, cache_root, title_id, &fence]() {
        command_processor_->InitializeShaderStorage(cache_root, title_id, true);
        fence.Signal();
      });
      fence.Wait();
    }
  } else {
    command_processor_->CallInThread([this, cache_root, title_id]() {
      command_processor_->InitializeShaderStorage(cache_root, title_id, false);
    });
  }
}

void GraphicsSystem::Pause() {
  // (Hunt v1.4.6 ronda 3, A4-R3-01.) command_processor_ is only created in
  // SetupGuestGpu (graphics_system.cpp:137), long after Runtime::Setup
  // assigns the graphics system — the old code dereferenced it with no
  // null check, a native crash on the UI thread for a pause during load.
  // No CP yet: record the pause (the vblank worker, created with the CP,
  // reads paused_) and return; Resume() clears it again. The CP itself
  // starts unpaused, which is harmless this early: no guest commands have
  // been submitted yet, and the vblank worker drops its backlog while
  // paused_ is set.
  if (!command_processor_) {
    paused_ = true;
    return;
  }
  paused_ = true;
  command_processor_->Pause();
}

void GraphicsSystem::Resume() {
  // (Hunt v1.4.6 ronda 3, A4-R3-08 — VERIFIED real, fixed.) The old order
  // cleared paused_ BEFORE resuming the CP, so the 1 ms vblank worker
  // could fire MarkVblank() -> DispatchInterruptCallback() -> guest
  // interrupt code while the CP worker was still suspended. Mirror
  // Pause() (which sets paused_ first, then suspends): resume the CP
  // first, then clear paused_, so no vblank dispatches until the CP runs
  // again. No CP yet (pause during load): just clear the flag.
  if (command_processor_) {
    command_processor_->Resume();
  }
  paused_ = false;
}

bool GraphicsSystem::Save(::rex::stream::ByteStream* stream) {
  stream->Write<uint32_t>(interrupt_callback_);
  stream->Write<uint32_t>(interrupt_callback_data_);
  // (Hunt v1.4.6 round 3, A1-R3-05.) No CP means no GPU state to save.
  if (!command_processor_) {
    return false;
  }
  return command_processor_->Save(stream);
}

bool GraphicsSystem::Restore(::rex::stream::ByteStream* stream) {
  interrupt_callback_ = stream->Read<uint32_t>();
  interrupt_callback_data_ = stream->Read<uint32_t>();
  // (Hunt v1.4.6 round 3, A1-R3-05.) No CP means no GPU state to restore.
  if (!command_processor_) {
    return false;
  }
  return command_processor_->Restore(stream);
}

}  // namespace rex::graphics
