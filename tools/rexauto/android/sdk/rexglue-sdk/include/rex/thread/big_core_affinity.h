/**
 * @file        thread/big_core_affinity.h
 * @brief       Shared big-core pinning helper (run #11, F1).
 *
 * The guest main thread is the CPU bottleneck (96% of a core in the v1.3
 * phone profile), so it belongs on the fastest cluster. The cluster layout
 * is read from the device at startup - nothing is assumed about the SoC
 * (the G99 is 2x Cortex-A76 + 6x Cortex-A55, but another phone may differ).
 *
 * This header exists so the detection logic lives in exactly one place:
 * the guest main thread (ui/rex_app.cpp, in libmain.so), the pipeline
 * creation threads (graphics/vulkan/pipeline_cache.cpp, in
 * librexgpu-xenos.so) and the command processor worker (pinned from
 * rex_app.cpp via CommandProcessor::CallInThread) all reuse it instead of
 * duplicating the sysfs parsing.
 *
 * Two module-boundary facts shape the API:
 * - The cvar override (pin_big_cores_mask, defined once in rex_app.cpp)
 *   CANNOT be read from the GPU plugin: rexcore is an OBJECT library, so
 *   each .so has its own cvar registry copy and a flag registered in
 *   libmain.so is invisible in librexgpu-xenos.so. Plugin threads therefore
 *   resolve the mask with REXCVAR_QUERY (0 when unregistered in their
 *   module) and fall back to the detector, which reads the same sysfs and
 *   returns the same mask on a given device. Only the manual override is
 *   main-thread-only; the auto-detected mask is identical everywhere.
 *   The command processor worker is the exception: rex_app.cpp resolves
 *   the effective mask (override included) and passes it by value through
 *   CallInThread, so the override reaches it.
 * - Verification reads the affinity back with Thread::affinity_mask()
 *   (sched_getaffinity on the thread). set_affinity_mask() itself cannot
 *   be trusted to report failure: on error it runs assert_always(), which
 *   is rex_assert(false), a no-op under NDEBUG (see rex/assert.h). A
 *   failed set leaves the old mask in place, so a read-back mismatch is
 *   the signal. threading_posix.cpp is NOT touched; the fix is verifying
 *   in the caller, as diagnosed in run #11 F1.
 */
#pragma once

#include <cstdint>

#include <rex/cvar.h>
#include <rex/logging.h>
#include <rex/platform.h>
#include <rex/thread.h>

#if REX_PLATFORM_ANDROID
#include <sched.h>

#include <fstream>
#include <string>

#include <fmt/format.h>
#endif  // REX_PLATFORM_ANDROID

namespace rex {
namespace big_core {

#if REX_PLATFORM_ANDROID
namespace detail {

// Parses a non-negative decimal integer at text[pos..]; advances pos past
// the digits. No exceptions.
inline bool ParseCpuNumber(const std::string& text, size_t* pos_inout, int* value_out) {
  size_t pos = *pos_inout;
  if (pos >= text.size() || text[pos] < '0' || text[pos] > '9') {
    return false;
  }
  int value = 0;
  while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
    value = value * 10 + (text[pos] - '0');
    ++pos;
  }
  *pos_inout = pos;
  *value_out = value;
  return true;
}

inline bool ReadSysInt(const std::string& path, int* value_out) {
  std::ifstream file(path);
  if (!file.is_open()) {
    return false;
  }
  int value = 0;
  file >> value;
  if (file.fail() || value <= 0) {
    return false;
  }
  *value_out = value;
  return true;
}

// /sys/devices/system/cpu/online looks like "0-7", "0-3,5-7" or "0".
inline uint64_t ReadOnlineCpuMask() {
  std::ifstream file("/sys/devices/system/cpu/online");
  if (!file.is_open()) {
    return 0;
  }
  std::string text;
  std::getline(file, text);
  uint64_t mask = 0;
  size_t pos = 0;
  while (pos < text.size()) {
    int first = 0;
    int last = 0;
    if (!ParseCpuNumber(text, &pos, &first)) {
      return 0;
    }
    last = first;
    if (pos < text.size() && text[pos] == '-') {
      ++pos;
      if (!ParseCpuNumber(text, &pos, &last)) {
        return 0;
      }
    }
    if (first > last || last >= 64) {
      return 0;
    }
    for (int cpu = first; cpu <= last; ++cpu) {
      mask |= uint64_t(1) << cpu;
    }
    if (pos < text.size() && text[pos] == ',') {
      ++pos;
      continue;
    }
    break;
  }
  return mask;
}

// The detector proper. Every 0 return logs its own reason (WARN: the
// original code failed silently here, which is what F1 is about). Runs
// once per process: the cluster layout does not change at runtime.
inline uint64_t DetectBigCoreMaskUncached() {
  const uint64_t online_mask = ReadOnlineCpuMask();
  if (!online_mask) {
    REXLOG_WARN(
        "Big-core pin: cannot read /sys/devices/system/cpu/online: not pinning");
    return 0;
  }
  // Pick the ranking metric once, from the first online CPU: cpu_capacity
  // when the kernel exposes it, otherwise the max frequency. Never mix the
  // two - they are on unrelated scales.
  int first_cpu = 0;
  while (first_cpu < 64 && !(online_mask & (uint64_t(1) << first_cpu))) {
    ++first_cpu;
  }
  const bool use_capacity =
      std::ifstream(fmt::format("/sys/devices/system/cpu/cpu{}/cpu_capacity", first_cpu))
          .good();
  const char* metric_file = use_capacity ? "cpu_capacity" : "cpufreq/cpuinfo_max_freq";
  int best_metric = 0;
  uint64_t best_mask = 0;
  for (int cpu = 0; cpu < 64; ++cpu) {
    if (!(online_mask & (uint64_t(1) << cpu))) {
      continue;
    }
    int metric = 0;
    if (!ReadSysInt(fmt::format("/sys/devices/system/cpu/cpu{}/{}", cpu, metric_file),
                    &metric)) {
      REXLOG_WARN(
          "Big-core pin: cannot read {} for cpu {} (online mask 0x{:X}): cannot rank every "
          "core, not pinning",
          metric_file, cpu, online_mask);
      return 0;  // Cannot rank every core: do not pin.
    }
    if (metric > best_metric) {
      best_metric = metric;
      best_mask = uint64_t(1) << cpu;
    } else if (metric == best_metric) {
      best_mask |= uint64_t(1) << cpu;
    }
  }
  if (!best_mask || best_mask == online_mask) {
    REXLOG_WARN("Big-core pin: device looks homogeneous (online mask 0x{:X}, best mask "
                "0x{:X}): pinning buys nothing, not pinning",
                online_mask, best_mask);
    return 0;  // Homogeneous device: pinning buys nothing.
  }
  // Never pin outside the CPUs this process is actually allowed to run on
  // (cpuset restrictions would make sched_setaffinity fail).
  cpu_set_t allowed;
  CPU_ZERO(&allowed);
  if (sched_getaffinity(0, sizeof(allowed), &allowed) == 0) {
    uint64_t allowed_mask = 0;
    for (int cpu = 0; cpu < 64; ++cpu) {
      if (CPU_ISSET(cpu, &allowed)) {
        allowed_mask |= uint64_t(1) << cpu;
      }
    }
    best_mask &= allowed_mask;
    if (!best_mask) {
      REXLOG_WARN("Big-core pin: big cores (mask 0x{:X}) are outside the process cpuset "
                  "(allowed 0x{:X}): not pinning",
                  best_mask, allowed_mask);
      return 0;
    }
  }
  return best_mask;
}

inline uint64_t DetectBigCoreMask() {
  static const uint64_t cached_mask = DetectBigCoreMaskUncached();
  return cached_mask;
}

}  // namespace detail

// Resolves the mask to pin with: an explicit mask wins; otherwise the
// pin_big_cores_mask cvar (REXCVAR_QUERY: 0 when the flag is not
// registered in this module - see the header comment); otherwise the
// sysfs detector. Returns 0 when nothing should be pinned.
inline uint64_t ResolveBigCoreMask(uint64_t forced_mask) {
  if (forced_mask != 0) {
    return forced_mask;
  }
  const uint64_t cvar_mask = cvar::Query<uint64_t>("pin_big_cores_mask");
  if (cvar_mask != 0) {
    return cvar_mask;
  }
  return detail::DetectBigCoreMask();
}

// Pins `thread` to `mask` and verifies the result by reading the affinity
// back. Logs every outcome. Returns true only when the read-back mask
// equals the requested one. A 0 mask means "leave alone" and logs why at
// WARN level (the detector already logged the specific reason).
inline bool PinThreadToBigCores(thread::Thread* thread, uint64_t mask, const char* label) {
  if (!thread) {
    REXLOG_WARN("Big-core pin: {}: no thread object, not pinning", label);
    return false;
  }
  if (mask == 0) {
    REXLOG_WARN("Big-core pin: {}: no usable big-core mask, leaving the thread unpinned",
                label);
    return false;
  }
  thread->set_affinity_mask(mask);
  // set_affinity_mask() cannot report failure (assert_always() is a no-op
  // in Release), so verify by reading the affinity back.
  const uint64_t actual_mask = thread->affinity_mask();
  if (actual_mask == mask) {
    REXLOG_INFO("Pinning {} to big cores (affinity mask 0x{:X}); verified affinity mask "
                "0x{:X}",
                label, mask, actual_mask);
    return true;
  }
  REXLOG_WARN("Big-core pin: {}: requested affinity mask 0x{:X} but the thread reads back "
              "0x{:X} (set_affinity_mask failed silently or the cpuset overrode it)",
              label, mask, actual_mask);
  return false;
}

// Same, for the calling thread.
inline bool PinCurrentThreadToBigCores(uint64_t mask, const char* label) {
  return PinThreadToBigCores(thread::Thread::GetCurrentThread(), mask, label);
}

#else  // !REX_PLATFORM_ANDROID

// No big.LITTLE pinning off Android.
inline uint64_t ResolveBigCoreMask(uint64_t /*forced_mask*/) { return 0; }

inline bool PinThreadToBigCores(thread::Thread* /*thread*/, uint64_t /*mask*/,
                                const char* /*label*/) {
  return false;
}

inline bool PinCurrentThreadToBigCores(uint64_t /*mask*/, const char* /*label*/) {
  return false;
}

#endif  // REX_PLATFORM_ANDROID

}  // namespace big_core
}  // namespace rex
