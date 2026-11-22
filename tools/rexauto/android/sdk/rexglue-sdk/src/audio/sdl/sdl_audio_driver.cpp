/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2020 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <algorithm>
#include <array>
#include <cstring>

#include <rex/assert.h>
#include <rex/audio/conversion.h>
#include <rex/audio/downmix.h>
#include <rex/audio/flags.h>
#include <rex/audio/sdl/sdl_audio_driver.h>
#include <rex/cvar.h>
#include <rex/dbg.h>
#include <rex/logging.h>
#include <rex/perf/counter.h>
#include <SDL3/SDL.h>

REXCVAR_DEFINE_BOOL(audio_mute, false, "Audio", "Mute audio output");

namespace {

// (Ronda 5, C-R5-09.) Hard cap for frames_queued_. The guest is paced by
// the client semaphore (AudioSystem::queued_frames_, at most
// kMaximumQueuedFrames = 64 permits: one permit per submitted frame,
// released by the SDL callback per consumed frame), so on the paced path
// the queue can never hold more than 64 -- the cap only bites if the
// guest submits outside the pacing, or the SDL callback stalls (device
// switch, pause without drain). Dropping the OLDEST frame keeps latency
// low and the semaphore accounting self-consistent: a dropped frame never
// gets its permit released, so the guest throttles itself instead of
// growing the queue at ~1.1 MiB/s forever. Same bound for the retained
// spare pool: a frame is 1536 floats = 6 KiB, so 64 spares is 384 KiB.
constexpr size_t kMaxQueuedFrames = 64;
constexpr size_t kMaxRetainedUnusedFrames = 64;

}  // namespace

namespace rex::audio::sdl {

SDLAudioDriver::SDLAudioDriver(memory::Memory* memory, rex::thread::Semaphore* semaphore)
    : AudioDriver(memory), semaphore_(semaphore) {}

SDLAudioDriver::~SDLAudioDriver() {
  assert_true(frames_queued_.empty());
  assert_true(frames_unused_.empty());
}

bool SDLAudioDriver::Initialize() {
  // Set audio category for proper OS audio handling
  SDL_SetHint(SDL_HINT_AUDIO_CATEGORY, "playback");

  // Set app name for audio device identification
  SDL_SetAppMetadataProperty(SDL_PROP_APP_METADATA_NAME_STRING, "rexglue");

  if (!SDL_InitSubSystem(SDL_INIT_AUDIO)) {
    REXAPU_ERROR("SDL_InitSubSystem(SDL_INIT_AUDIO) failed: {}", SDL_GetError());
    return false;
  }
  sdl_initialized_ = true;

  SDL_AudioSpec desired_spec = {};
  SDL_AudioSpec obtained_spec = {};
  desired_spec.freq = frame_frequency_;
  desired_spec.format = SDL_AUDIO_F32LE;
  desired_spec.channels = frame_channels_;
  sdl_device_channels_ = frame_channels_;
  sdl_stream_ = SDL_OpenAudioDeviceStream(SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK, &desired_spec,
                                          SDLCallback, this);
  if (!sdl_stream_) {
    REXAPU_ERROR("SDL_OpenAudioDeviceStream() failed: {}", SDL_GetError());
    return false;
  }

  SDL_AudioDeviceID sdl_device = SDL_GetAudioStreamDevice(sdl_stream_);
  if (!sdl_device) {
    REXAPU_ERROR("SDL_GetAudioStreamDevice() failed: {}", SDL_GetError());
    return false;
  }

  if (!SDL_GetAudioDeviceFormat(sdl_device, &obtained_spec, NULL)) {
    REXAPU_WARN("SDL_GetAudioDeviceFormat() failed: {}", SDL_GetError());
    obtained_spec = desired_spec;
  }

  // A 1-channel device gets the stereo fold too, then SDL collapses to mono.
  // Handing it a 6ch stream instead would use SDL's own downmix.
  if (obtained_spec.channels <= 2) {
    SDL_DestroyAudioStream(sdl_stream_);
    sdl_stream_ = nullptr;
    desired_spec.channels = 2;
    sdl_device_channels_ = 2;
    sdl_stream_ = SDL_OpenAudioDeviceStream(SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK, &desired_spec,
                                            SDLCallback, this);
    if (!sdl_stream_) {
      REXAPU_ERROR("SDL_OpenAudioDeviceStream() stereo fallback failed: {}", SDL_GetError());
      return false;
    }
    sdl_device = SDL_GetAudioStreamDevice(sdl_stream_);
    if (!sdl_device) {
      REXAPU_ERROR("SDL_GetAudioStreamDevice() failed after stereo fallback: {}", SDL_GetError());
      return false;
    }
  }

  // The endpoint layout decides which mix the callback runs, and it is the
  // first thing worth knowing when a report says the balance is wrong on one
  // speaker setup and right on another.
  const char* device_name = SDL_GetAudioDeviceName(sdl_device);
  REXAPU_INFO("audio endpoint '{}': {} ch, {} Hz, format 0x{:04X}; submitting {} ch",
              device_name ? device_name : "?", obtained_spec.channels, obtained_spec.freq,
              static_cast<uint32_t>(obtained_spec.format), static_cast<int>(sdl_device_channels_));

  if (!SDL_ResumeAudioDevice(sdl_device)) {
    REXAPU_ERROR("SDL_ResumeAudioDevice() failed: {}", SDL_GetError());
    return false;
  }

  return true;
}

void SDLAudioDriver::SubmitFrame(uint32_t frame_ptr) {
  // (Hunt v1.4.6 ronda 4, A4-R4-08.) The frame is guest memory:
  // TranslateVirtual never returns null, so an invalid samples_ptr used
  // to memcpy from unmapped host memory (SIGSEGV in the audio thread).
  // Validate the whole frame against the guest heap first, same shape as
  // the XFile read/write guards (A2-R3-01): both ends in one heap, and
  // the range readable. frame_samples_ is a compile-time constant, so the
  // end computation cannot overflow past the guard below.
  const uint32_t frame_bytes = frame_samples_ * sizeof(float);
  if (frame_ptr == 0 || frame_ptr > UINT32_MAX - frame_bytes) {
    REXAPU_WARN("SDLAudioDriver::SubmitFrame: invalid frame_ptr={:08X}", frame_ptr);
    return;
  }
  const uint32_t frame_end = frame_ptr + frame_bytes - 1;
  auto* start_heap = memory_->LookupHeap(frame_ptr);
  auto* end_heap = memory_->LookupHeap(frame_end);
  if (!start_heap || !end_heap || start_heap != end_heap ||
      start_heap->QueryRangeAccess(frame_ptr, frame_end) ==
          rex::memory::PageAccess::kNoAccess) {
    REXAPU_WARN("SDLAudioDriver::SubmitFrame: frame {:08X}-{:08X} not readable", frame_ptr,
                frame_end);
    return;
  }
  const auto input_frame = memory_->TranslateVirtual<float*>(frame_ptr);
  float* output_frame;
  {
    std::unique_lock<std::mutex> guard(frames_mutex_);
    if (frames_unused_.empty()) {
      output_frame = new float[frame_samples_];
    } else {
      output_frame = frames_unused_.top();
      frames_unused_.pop();
    }
  }

  std::memcpy(output_frame, input_frame, frame_samples_ * sizeof(float));

  static uint32_t sdl_submit_count = 0;
  if (sdl_submit_count < 10) {
    REXAPU_DEBUG("SDLAudioDriver::SubmitFrame: frame_ptr={:08X} queued_count={}", frame_ptr,
                 frames_queued_.size() + 1);
    sdl_submit_count++;
  }

  {
    std::unique_lock<std::mutex> guard(frames_mutex_);
    // (Ronda 5, C-R5-09.) Hard cap: drop the oldest queued frame(s)
    // instead of growing without bound. The cap is enforced here, at the
    // push -- the single linearization point -- so concurrent submits
    // cannot race past it. The dropped buffer is recycled into the spare
    // pool (or freed if that is full, see below): the new frame's buffer
    // was already filled above, so this only discards stale audio. The
    // semaphore permit for the dropped frame is never released, which is
    // what throttles the guest back into the paced path.
    static uint32_t dropped_frame_count = 0;
    while (frames_queued_.size() >= kMaxQueuedFrames) {
      float* stale_frame = frames_queued_.front();
      frames_queued_.pop();
      if (frames_unused_.size() < kMaxRetainedUnusedFrames) {
        frames_unused_.push(stale_frame);
      } else {
        delete[] stale_frame;
      }
      ++dropped_frame_count;
      if (dropped_frame_count < 8 || (dropped_frame_count % 1024) == 0) {
        REXAPU_WARN("SDLAudioDriver::SubmitFrame: audio frame queue full ({} frames) - "
                    "dropping oldest frame #{} (SDL callback stalled or guest submitting "
                    "outside the semaphore pacing)",
                    kMaxQueuedFrames, dropped_frame_count);
      }
    }
    frames_queued_.push(output_frame);
    PROFILE_BUFFER_QUEUE_DEPTH(static_cast<int64_t>(frames_queued_.size()));
  }
}

void SDLAudioDriver::Shutdown() {
  if (sdl_stream_) {
    SDL_DestroyAudioStream(sdl_stream_);
    sdl_stream_ = nullptr;
  }
  if (sdl_initialized_) {
    SDL_QuitSubSystem(SDL_INIT_AUDIO);
    sdl_initialized_ = false;
  }
  std::unique_lock<std::mutex> guard(frames_mutex_);
  while (!frames_unused_.empty()) {
    delete[] frames_unused_.top();
    frames_unused_.pop();
  }
  while (!frames_queued_.empty()) {
    delete[] frames_queued_.front();
    frames_queued_.pop();
  }
}

void SDLAudioDriver::SDLCallback(void* userdata, SDL_AudioStream* stream, int additional_amount,
                                 [[maybe_unused]] int total_amount) {
  SCOPE_profile_cpu_f("apu");
  if (!userdata || !stream) {
    REXAPU_ERROR("SDLAudioDriver::SDLCallback called with nullptr.");
    return;
  }
  const auto driver = static_cast<SDLAudioDriver*>(userdata);
  const int sample_count =
      static_cast<int>(channel_samples_ * std::max<uint8_t>(driver->sdl_device_channels_, 1));
  const int len = static_cast<int>(sizeof(float) * sample_count);
  // (Ronda 5, C-R5-09.) Return a consumed buffer to the spare pool, but
  // never retain more than kMaxRetainedUnusedFrames: after a stall the
  // pool used to keep every buffer the burst allocated, forever (384 KiB
  // at the cap instead of unbounded).
  auto return_unused_frame = [&](float* frame) {
    std::unique_lock<std::mutex> guard(driver->frames_mutex_);
    if (driver->frames_unused_.size() < kMaxRetainedUnusedFrames) {
      driver->frames_unused_.push(frame);
    } else {
      delete[] frame;
    }
  };
  float* data = SDL_stack_alloc(float, sample_count);
  if (!data) {
    REXAPU_ERROR("SDLAudioDriver::SDLCallback failed to allocate {} samples", sample_count);
    return;
  }
  // Snapshot once. A change mid-callback would split the frame across two mixes.
  const StereoFold fold = GetStereoFold();
  const SurroundMix mix = GetSurroundMix();
  const float gain = GetOutputGain();
  // (Hunt v1.4.6 ronda 3, A4-R3-15.) The old loop held frames_mutex_ for
  // the whole drain, including the conversion and SDL_PutAudioStreamData
  // calls, so after a stall (focus-loss pause, underrun) additional_amount
  // is many frames deep and SubmitFrame + Shutdown block on the SDL audio
  // thread for the entire drain. Now the lock is only held to pop one
  // frame (and to return its buffer afterwards); conversion and the
  // stream put run outside it. SubmitFrame can queue while the callback
  // drains, and Shutdown only waits for one frame's worth of work.
  // Note: Shutdown destroys the SDL stream before taking frames_mutex_,
  // so no new callback can start once Shutdown runs; a buffer popped
  // just before that is returned to frames_unused_ under the lock by the
  // in-flight callback, which Shutdown then frees with the rest.
  while (additional_amount > 0) {
    static uint32_t sdl_callback_count = 0;
    float* buffer = nullptr;
    {
      std::unique_lock<std::mutex> guard(driver->frames_mutex_);
      if (!driver->frames_queued_.empty()) {
        buffer = driver->frames_queued_.front();
        driver->frames_queued_.pop();
      }
    }
    if (!buffer) {
      if (sdl_callback_count < 10) {
        REXAPU_DEBUG("SDLCallback: no frames queued (silence)");
        sdl_callback_count++;
      }
      std::memset(data, 0, len);
      if (!SDL_PutAudioStreamData(stream, data, len)) {
        REXAPU_ERROR("SDL_PutAudioStreamData() failed while filling silence: {}", SDL_GetError());
        break;
      }
      additional_amount -= len;
      continue;
    }
    if (REXCVAR_GET(audio_mute)) {
      std::memset(data, 0, len);
    } else {
      switch (driver->sdl_device_channels_) {
        case 2:
          conversion::sequential_6_BE_to_interleaved_2_LE(data, buffer, channel_samples_, fold,
                                                          gain);
          break;
        case 6:
          conversion::sequential_6_BE_to_interleaved_6_LE(data, buffer, channel_samples_, mix,
                                                          gain);
          break;
        default:
          assert_unhandled_case(driver->sdl_device_channels_);
          break;
      }
    }
    if (!SDL_PutAudioStreamData(stream, data, len)) {
      REXAPU_ERROR("SDL_PutAudioStreamData() failed: {}", SDL_GetError());
      return_unused_frame(buffer);
      break;
    }
    return_unused_frame(buffer);

    auto ret = driver->semaphore_->Release(1, nullptr);
    assert_true(ret);
    additional_amount -= len;
  }
  SDL_stack_free(data);
}

}  // namespace rex::audio::sdl
