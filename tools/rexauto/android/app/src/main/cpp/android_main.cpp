/**
 * rexauto Android port - native entry point (generic, title-agnostic).
 *
 * Derived from deivid22srk/hells-gate-recomp-android (android_main.cpp) and
 * generalised: the project identifier arrives from CMake (REX_APP_NAME), the
 * game data root and the graphics settings are written by the Java launcher
 * (SetupActivity) into the app's external files dir:
 *
 *   <external>/game_root.txt   absolute path of the folder holding default.xex
 *   <external>/settings.txt    one "key=value" per line -> passed as --key=value
 *                              cvars (resolution_scale, vsync, present_effect...)
 *
 * SDL3's SDL_main.h maps main() to SDL_main; org.libsdl.app.SDLActivity calls
 * SDL_RunApp on a dedicated thread which lands here.
 */

#include <SDL3/SDL_main.h>
#include <SDL3/SDL_system.h>
#include <SDL3/SDL_hints.h>

#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <unwind.h>
#include <sys/syscall.h>
#include <pthread.h>

#include <algorithm>
#include <cctype>
#include <atomic>
#include <chrono>
#include <map>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <sys/resource.h>
#include <jni.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <fmt/format.h>

#include "android_gamepad.h"
#include "stfs_asset.h"
#if REX_HAVE_ADRENOTOOLS
#include <adrenotools/driver.h>
#endif
#include <rex/cvar.h>
#include <rex/filesystem.h>
#include <rex/filesystem/stfs_asset.h>
#include <rex/logging.h>
#include <rex/main_android.h>
#include <rex/memory.h>
#include <rex/platform.h>
#include <rex/thread.h>
#include <rex/ui/windowed_app.h>
#include <rex/ui/windowed_app_context_sdl.h>

#if REX_PLATFORM_ANDROID

#ifndef REX_APP_NAME
#error "REX_APP_NAME must be defined by the build (the rexglue project name)"
#endif

namespace {

constexpr char kAppIdentifier[] = REX_APP_NAME;
constexpr char kConfigFileName[] = "game_root.txt";
constexpr char kSettingsFileName[] = "settings.txt";
// <internal files>/gpu_driver/<name>/  + driver.txt naming the .so (written by
// the launcher after importing a Turnip/Adreno or PanVK/Mali driver zip).
// Internal storage, not external: dlopen() refuses libraries on
// world-writable paths.
constexpr char kDriverDirName[] = "gpu_driver";
constexpr char kDriverConfigName[] = "driver.txt";

#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, REX_APP_NAME, __VA_ARGS__)
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, REX_APP_NAME, __VA_ARGS__)

std::string ReadTrimmedFile(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return {};
  std::string line;
  std::getline(in, line);
  while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
  return line;
}

// settings.txt -> ["--key=value", ...]. Blank lines and '#' comments ignored.
std::vector<std::string> ReadSettingsArgs(const std::string& path) {
  std::vector<std::string> out;
  std::ifstream in(path, std::ios::binary);
  if (!in) return out;
  std::string line;
  while (std::getline(in, line)) {
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
    if (line.empty() || line[0] == '#') continue;
    const auto eq = line.find('=');
    if (eq == std::string::npos || eq == 0) continue;
    if (line.rfind("env.", 0) == 0) {
      // env.NAME=value -> setenv(NAME, value); consumed by getenv() readers
      // such as the tolerant dispatcher (REX_HEAL_DISCOVER).
      setenv(line.substr(4, eq - 4).c_str(), line.substr(eq + 1).c_str(), 1);
      continue;
    }
    out.emplace_back("--" + line);
  }
  return out;
}

// (Audit run #16, J-18.) The user's orientation choice lives in the
// launcher's SharedPreferences ("graphics" prefs, key "orientation":
// "landscape" | "portrait" | "auto", GraphicsSettings.java) -- the same
// file MainActivity.applyOrientation() reads, with the same mapping:
// landscape -> fixed landscape, portrait -> portrait, auto -> no hint
// (SDL's empty hint + resizable window resolves to FULL_USER, i.e. follow
// the device rotation, exactly what "auto" means). The old code hardcoded
// "LandscapeLeft" here, so a user who chose portrait or auto still got a
// landscape request from SDL on every window (re)creation -- the Java side
// overrode it in setOrientationBis, but only after SDL had already asked.
// Reading the prefs XML directly is the only channel available to native
// code: orientation is exported neither to settings.txt nor to any
// cvar/env. Any failure (no file yet, unparsable, unknown value) falls
// back to "LandscapeLeft", i.e. today's behavior. SharedPreferences
// writes atomically (temp file + rename), so a concurrent Java write can
// only show the old or the new value, never a torn one.
std::string ReadOrientationHint(const std::string& internal_dir) {
  std::string base = internal_dir;
  while (!base.empty() && base.back() == '/') base.pop_back();
  const size_t slash = base.find_last_of('/');
  if (slash == std::string::npos) return "LandscapeLeft";
  // SDL_GetAndroidInternalStoragePath() is <app>/files; shared_prefs is
  // its sibling.
  const std::string prefs_path = base.substr(0, slash) + "/shared_prefs/graphics.xml";
  std::ifstream in(prefs_path, std::ios::binary);
  if (!in) return "LandscapeLeft";
  std::string line;
  while (std::getline(in, line)) {
    // SharedPreferences XML, one entry per line:
    // <string name="orientation">portrait</string>
    const size_t key_pos = line.find("name=\"orientation\"");
    if (key_pos == std::string::npos) continue;
    const size_t value_begin = line.find('>', key_pos);
    if (value_begin == std::string::npos) break;
    const size_t value_end = line.find('<', value_begin + 1);
    if (value_end == std::string::npos) break;
    const std::string value = line.substr(value_begin + 1, value_end - value_begin - 1);
    if (value == "portrait") return "Portrait";
    if (value == "auto") return "";
    return "LandscapeLeft";
  }
  return "LandscapeLeft";
}

std::string QueryNativeLibraryDir() {
  Dl_info info{};
  if (dladdr(reinterpret_cast<void*>(&QueryNativeLibraryDir), &info) && info.dli_fname) {
    std::string path(info.dli_fname);
    const size_t slash = path.find_last_of('/');
    if (slash != std::string::npos) return path.substr(0, slash);
  }
  return {};
}

JavaVM* QueryJavaVm() {
  auto* env = static_cast<JNIEnv*>(SDL_GetAndroidJNIEnv());
  if (env) {
    JavaVM* vm = nullptr;
    if (env->GetJavaVM(&vm) == JNI_OK && vm) return vm;
  }
  return nullptr;
}

// --- crash reporter ---------------------------------------------------------
// Android throws a native crash away (a tombstone the user cannot reach without
// adb). This writes <logs>/crash.txt from the signal handler with the
// async-signal-safe subset: signal, fault address, pc, the symbol (sub_XXXXXXXX
// = the guest function) and module offset of every frame. SetupActivity shows
// the file on the next launch. The SDK's own handlers run first (write-watch,
// SEH regions) and chain here only for genuinely unhandled faults.
char g_crash_path[512];

void CrashWrite(int fd, const char* s) {
  size_t n = 0;
  while (s[n]) ++n;
  while (n) {
    ssize_t w = write(fd, s, n);
    if (w <= 0) return;
    s += w;
    n -= static_cast<size_t>(w);
  }
}

void CrashHex(int fd, uint64_t v) {
  char buf[17];
  int i = 16; buf[i] = 0;
  do { int d = int(v & 15); buf[--i] = char(d < 10 ? '0' + d : 'a' + d - 10); v >>= 4; } while (v);
  CrashWrite(fd, buf + i);
}

void CrashAddr(int fd, uintptr_t pc) {
  CrashWrite(fd, "0x");
  CrashHex(fd, pc);
  Dl_info di{};
  if (dladdr(reinterpret_cast<void*>(pc), &di) && di.dli_fname) {
    const char* base = di.dli_fname;
    for (const char* q = base; *q; ++q) if (*q == '/') base = q + 1;
    CrashWrite(fd, "  ");
    CrashWrite(fd, base);
    CrashWrite(fd, "+0x");
    CrashHex(fd, pc - reinterpret_cast<uintptr_t>(di.dli_fbase));
    if (di.dli_sname) {
      CrashWrite(fd, "  ");
      CrashWrite(fd, di.dli_sname);
      CrashWrite(fd, "+0x");
      CrashHex(fd, pc - reinterpret_cast<uintptr_t>(di.dli_saddr));
    }
  }
}

struct CrashTrace { int fd; int n; };

_Unwind_Reason_Code CrashUnwind(struct _Unwind_Context* c, void* arg) {
  auto* t = static_cast<CrashTrace*>(arg);
  uintptr_t pc = _Unwind_GetIP(c);
  if (pc && t->n < 48) {
    CrashWrite(t->fd, "  #");
    char idx[4] = {char('0' + t->n / 10), char('0' + t->n % 10), ' ', 0};
    CrashWrite(t->fd, idx);
    CrashAddr(t->fd, pc);
    CrashWrite(t->fd, "\n");
  }
  ++t->n;
  return t->n >= 48 ? _URC_END_OF_STACK : _URC_NO_REASON;
}

void CrashHandler(int sig, siginfo_t* info, void* uctx) {
  static volatile sig_atomic_t entered = 0;
  if (!entered) {
    entered = 1;
    int fd = open(g_crash_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd >= 0) {
      CrashWrite(fd, REX_APP_NAME " native crash\nsignal: ");
      const char* name = sig == SIGSEGV ? "SIGSEGV (access violation)" :
                         sig == SIGBUS ? "SIGBUS (misaligned/bad mapping)" :
                         sig == SIGILL ? "SIGILL (illegal instruction / trap)" :
                         sig == SIGFPE ? "SIGFPE (arithmetic)" :
                         sig == SIGABRT ? "SIGABRT (abort / assertion / uncaught exception)" :
                         sig == SIGTRAP ? "SIGTRAP (breakpoint)" : "unknown";
      CrashWrite(fd, name);
      CrashWrite(fd, "\nfault address: 0x");
      CrashHex(fd, reinterpret_cast<uintptr_t>(info ? info->si_addr : nullptr));
      auto* uc = static_cast<ucontext_t*>(uctx);
      if (uc) {
        CrashWrite(fd, "\npc: ");
        CrashAddr(fd, static_cast<uintptr_t>(uc->uc_mcontext.pc));
        CrashWrite(fd, "\nlr: ");
        CrashAddr(fd, static_cast<uintptr_t>(uc->uc_mcontext.regs[30]));
        CrashWrite(fd, "\nsp: 0x");
        CrashHex(fd, uc->uc_mcontext.sp);
        CrashWrite(fd, "\nx0-x7:");
        for (int i = 0; i < 8; ++i) { CrashWrite(fd, " 0x"); CrashHex(fd, uc->uc_mcontext.regs[i]); }
        CrashWrite(fd, "\nx19-x21:");
        for (int i = 19; i < 22; ++i) { CrashWrite(fd, " 0x"); CrashHex(fd, uc->uc_mcontext.regs[i]); }
      }
      CrashWrite(fd, "\nbacktrace (pc  module+offset  symbol+offset; sub_XXXXXXXX = guest function):\n");
      CrashTrace t{fd, 0};
      _Unwind_Backtrace(CrashUnwind, &t);
      CrashWrite(fd, "\n");
      close(fd);
    }
  }
  signal(sig, SIG_DFL);
  raise(sig);
}

void InstallCrashReporter(const std::string& log_dir) {
  std::string path = log_dir + "/crash.txt";
  if (path.size() >= sizeof(g_crash_path)) return;
  std::memcpy(g_crash_path, path.c_str(), path.size() + 1);
  // Run on an alternate stack so a stack overflow is reported too.
  static std::vector<char> alt_stack(1 << 17);
  stack_t ss{};
  ss.ss_sp = alt_stack.data();
  ss.ss_size = alt_stack.size();
  sigaltstack(&ss, nullptr);
  struct sigaction sa{};
  sa.sa_sigaction = CrashHandler;
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
  sigemptyset(&sa.sa_mask);
  for (int sig : {SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT, SIGTRAP}) sigaction(sig, &sa, nullptr);
  std::set_terminate([] {
    // Uncaught C++ exception (REX_UNIMPLEMENTED, bad_alloc...): name it, then
    // fall into the SIGABRT path above for the backtrace.
    if (auto ex = std::current_exception()) {
      try { std::rethrow_exception(ex); }
      catch (const std::exception& e) {
        __android_log_print(ANDROID_LOG_ERROR, REX_APP_NAME, "uncaught exception: %s", e.what());
        // (Audit run #16, M-11.) O_APPEND, not O_TRUNC: std::abort() below
        // raises SIGABRT, and CrashHandler appends the backtrace to this
        // same file -- with O_TRUNC here AND there, the handler wiped the
        // exception message, the one line that names the failure. crash.txt
        // is removed at every fresh launch, so appends never mix runs.
        int fd = open(g_crash_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (fd >= 0) { CrashWrite(fd, "uncaught exception: "); CrashWrite(fd, e.what()); CrashWrite(fd, "\n"); close(fd); }
      } catch (...) {}
    }
    std::abort();
  });
}

// --- built-in sampling profiler ---------------------------------------------
// Every 5 ms each thread of the process gets SIGPROF; the handler records its
// pc into a lock-free open-addressing table. Every 20 s a report is written to
// <logs>/profile.txt: per-thread CPU%, per-core clock (throttling), and the
// top sampled host functions resolved through dladdr (sub_XXXXXXXX = guest
// function, librexruntime/librexgpu = runtime). Claimed to cost well under 1%
// CPU, but the v1.4.1 profile on this phone shows the sampler thread itself
// at 33.7% of one core. Disabled by setting REX_PROFILE=0 in the environment
// before prof::Start runs; settings.txt is read after Start, so an env line
// there is too late.
namespace prof {
constexpr size_t kSlots = 1 << 16;  // power of two
struct Slot { std::atomic<uintptr_t> pc; std::atomic<uint32_t> n; };
Slot g_table[kSlots];
std::atomic<uint64_t> g_total{0}, g_dropped{0};
std::string g_path;

void OnSigprof(int, siginfo_t*, void* uctx) {
  auto* uc = static_cast<ucontext_t*>(uctx);
  uintptr_t pc = uc ? static_cast<uintptr_t>(uc->uc_mcontext.pc) : 0;
  if (!pc) return;
  g_total.fetch_add(1, std::memory_order_relaxed);
  size_t h = (pc >> 2) * 0x9E3779B97F4A7C15ull >> 48;
  for (int probe = 0; probe < 32; ++probe) {
    Slot& sl = g_table[(h + probe) & (kSlots - 1)];
    uintptr_t cur = sl.pc.load(std::memory_order_relaxed);
    if (cur == pc) { sl.n.fetch_add(1, std::memory_order_relaxed); return; }
    if (cur == 0) {
      uintptr_t expect = 0;
      if (sl.pc.compare_exchange_strong(expect, pc, std::memory_order_relaxed)) {
        sl.n.fetch_add(1, std::memory_order_relaxed);
        return;
      }
      if (expect == pc) { sl.n.fetch_add(1, std::memory_order_relaxed); return; }
    }
  }
  g_dropped.fetch_add(1, std::memory_order_relaxed);
}

struct ThreadCpu { std::string name; uint64_t ticks; };

std::map<int, ThreadCpu> SampleThreads() {
  std::map<int, ThreadCpu> out;
  std::error_code ec;
  for (auto& e : std::filesystem::directory_iterator("/proc/self/task", ec)) {
    int tid = std::atoi(e.path().filename().c_str());
    if (tid <= 0) continue;
    std::ifstream st(e.path() / "stat");
    std::string line;
    if (!std::getline(st, line)) continue;
    auto rp = line.rfind(')');
    auto lp = line.find('(');
    if (rp == std::string::npos || lp == std::string::npos) continue;
    std::string name = line.substr(lp + 1, rp - lp - 1);
    // fields after ')': state(3) ... utime(14) stime(15)
    std::istringstream rest(line.substr(rp + 2));
    std::string tok; uint64_t ut = 0, stm = 0;
    for (int i = 3; i <= 15 && rest >> tok; ++i) {
      if (i == 14) ut = std::strtoull(tok.c_str(), nullptr, 10);
      if (i == 15) stm = std::strtoull(tok.c_str(), nullptr, 10);
    }
    out[tid] = {name, ut + stm};
  }
  return out;
}

std::string CpuFreqs() {
  std::string s;
  for (int c = 0; c < 16; ++c) {
    std::ifstream f("/sys/devices/system/cpu/cpu" + std::to_string(c) + "/cpufreq/scaling_cur_freq");
    long khz = 0;
    if (!(f >> khz)) break;
    if (!s.empty()) s += " ";
    s += std::to_string(khz / 1000);
  }
  return s.empty() ? "n/a" : s + " MHz";
}

void Dump(const std::map<int, ThreadCpu>& prev, const std::map<int, ThreadCpu>& cur,
          double interval_s, uint64_t total_before) {
  std::ofstream out(g_path, std::ios::trunc);
  if (!out) return;
  const long hz = sysconf(_SC_CLK_TCK);
  out << REX_APP_NAME << " profile (last " << int(interval_s) << " s window; rewritten every 20 s)\n";
  out << "cpu clocks: " << CpuFreqs() << "\n";
  out << "samples: " << (g_total.load() - total_before) << " in window, dropped " << g_dropped.load() << "\n\n";

  out << "threads (CPU% of one core):\n";
  std::vector<std::pair<double, std::string>> th;
  for (auto& [tid, c] : cur) {
    auto it = prev.find(tid);
    uint64_t d = it == prev.end() ? c.ticks : c.ticks - it->second.ticks;
    double pct = hz > 0 && interval_s > 0 ? 100.0 * double(d) / double(hz) / interval_s : 0;
    if (pct >= 0.5) th.push_back({pct, c.name});
  }
  std::sort(th.rbegin(), th.rend());
  for (auto& [pct, name] : th) out << fmt::format("  {:6.1f}%  {}\n", pct, name);

  // Aggregate samples by symbol (or module+page when unsymbolised).
  std::unordered_map<std::string, uint64_t> by_sym;
  std::unordered_map<std::string, uint64_t> by_mod;
  uint64_t seen = 0;
  for (size_t i = 0; i < kSlots; ++i) {
    uintptr_t pc = g_table[i].pc.load(std::memory_order_relaxed);
    uint32_t n = g_table[i].n.exchange(0, std::memory_order_relaxed);
    if (!pc || !n) continue;
    seen += n;
    Dl_info di{};
    std::string mod = "?", sym;
    if (dladdr(reinterpret_cast<void*>(pc), &di)) {
      if (di.dli_fname) { mod = di.dli_fname; auto sl = mod.find_last_of('/'); if (sl != std::string::npos) mod = mod.substr(sl + 1); }
      if (di.dli_sname) sym = di.dli_sname;
      else sym = fmt::format("{}+0x{:x}", mod, (pc - reinterpret_cast<uintptr_t>(di.dli_fbase)) & ~uintptr_t(0xfff));
    } else {
      sym = fmt::format("0x{:x}", pc);
    }
    by_sym[sym] += n;
    by_mod[mod] += n;
  }
  out << "\nby module:\n";
  std::vector<std::pair<uint64_t, std::string>> mods(by_mod.size());
  std::transform(by_mod.begin(), by_mod.end(), mods.begin(), [](auto& kv) { return std::make_pair(kv.second, kv.first); });
  std::sort(mods.rbegin(), mods.rend());
  for (auto& [n, m] : mods) out << fmt::format("  {:5.1f}%  {}\n", seen ? 100.0 * n / seen : 0.0, m);

  out << "\ntop functions (sub_XXXXXXXX = game code; __imp__ prefix is the same function):\n";
  std::vector<std::pair<uint64_t, std::string>> syms(by_sym.size());
  std::transform(by_sym.begin(), by_sym.end(), syms.begin(), [](auto& kv) { return std::make_pair(kv.second, kv.first); });
  std::sort(syms.rbegin(), syms.rend());
  size_t k = 0;
  for (auto& [n, sname] : syms) {
    if (++k > 60) break;
    out << fmt::format("  {:5.1f}%  {}\n", seen ? 100.0 * n / seen : 0.0, sname);
  }
}

void Start(const std::string& log_dir) {
  if (const char* e = std::getenv("REX_PROFILE"); e && e[0] == '0') return;
  g_path = log_dir + "/profile.txt";
  struct sigaction sa{};
  sa.sa_sigaction = OnSigprof;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGPROF, &sa, nullptr);
  std::thread([] {
    pthread_setname_np(pthread_self(), "rex-profiler");
    const pid_t pid = getpid();
    const pid_t self = gettid();
    auto prev = SampleThreads();
    auto t_prev = std::chrono::steady_clock::now();
    uint64_t total_before = 0;
    int ticks = 0;
    std::vector<int> tids;
    for (;;) {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
      if ((ticks++ % 200) == 0) {  // refresh the thread list once a second
        tids.clear();
        std::error_code ec;
        for (auto& e : std::filesystem::directory_iterator("/proc/self/task", ec)) {
          int tid = std::atoi(e.path().filename().c_str());
          if (tid > 0 && tid != self) tids.push_back(tid);
        }
      }
      for (int tid : tids) {
        // Only threads that are actually running burn CPU; skip sleepers so the
        // profile is "where CPU time goes", not "where threads wait".
        char path[64];
        std::snprintf(path, sizeof(path), "/proc/self/task/%d/stat", tid);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        char buf[256];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) continue;
        buf[n] = 0;
        const char* rp = std::strrchr(buf, ')');
        if (!rp || rp[1] != ' ') continue;
        if (rp[2] != 'R') continue;
        syscall(SYS_tgkill, pid, tid, SIGPROF);
      }
      if (ticks % 4000 == 0) {  // 20 s
        auto cur = SampleThreads();
        auto now = std::chrono::steady_clock::now();
        double dt = std::chrono::duration<double>(now - t_prev).count();
        Dump(prev, cur, dt, total_before);
        prev = std::move(cur);
        t_prev = now;
        total_before = g_total.load();
      }
    }
  }).detach();
  ALOGI("profiler on: %s", g_path.c_str());
}
}  // namespace prof

std::string ResolveLogDir(const std::string& external_dir) {
  const std::string dir = external_dir + "/logs";
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  return dir;
}

// Load a user-supplied Vulkan driver (Turnip / newer Adreno blob, or PanVK
// for Mali) through libadrenotools and publish the handle for the SDK's
// DynamicLibrary (see the android-custom-vulkan SDK patch). Silent no-op when
// nothing is configured. PanVK loads through the SAME adrenotools CUSTOM path
// as Turnip: the hook only redirects the dlopen of the driver by name and
// never checks which GPU the library targets (the panvk-kbase releases ship
// a dedicated ...-adrenotools.zip for exactly this use).
void LoadCustomVulkanDriver(const std::string& internal_dir, const std::string& lib_dir) {
#if REX_HAVE_ADRENOTOOLS
  const std::string cfg = internal_dir + "/" + kDriverDirName + "/" + kDriverConfigName;
  const std::string spec = ReadTrimmedFile(cfg);  // "<subdir>/<libvulkan_freedreno.so>"
  if (spec.empty()) return;
  const auto slash = spec.rfind('/');
  const std::string dir = internal_dir + "/" + kDriverDirName + "/" +
                          (slash == std::string::npos ? "" : spec.substr(0, slash)) + "/";
  const std::string so = slash == std::string::npos ? spec : spec.substr(slash + 1);
  std::error_code ec;
  if (!std::filesystem::is_regular_file(dir + so, ec)) {
    ALOGE("custom GPU driver configured but %s%s is missing - using the system driver", dir.c_str(), so.c_str());
    return;
  }
  const std::string tmp = internal_dir + "/" + kDriverDirName + "/tmp";
  std::filesystem::create_directories(tmp, ec);
  void* handle = adrenotools_open_libvulkan(RTLD_NOW, ADRENOTOOLS_DRIVER_CUSTOM, tmp.c_str(),
                                            lib_dir.c_str(), dir.c_str(), so.c_str(), nullptr, nullptr);
  if (!handle) {
    ALOGE("adrenotools_open_libvulkan(%s%s) failed - using the system driver", dir.c_str(), so.c_str());
    return;
  }
  setenv("REX_VULKAN_HANDLE", std::to_string(reinterpret_cast<uintptr_t>(handle)).c_str(), 1);
  // (Ronda 5, auditor E — R5-E3.) Publish the requested .so name so the
  // Vulkan layer can check that the driver that actually loaded is the
  // one requested: adrenotools loads the custom .so lazily, and if it
  // fails the hook silently falls back to the system driver (only a LOGI
  // in hook_impl.cpp) while this function has already logged "custom
  // Vulkan driver loaded". vulkan_device.cpp compares the reported
  // driverID against the ID expected from this name and logs loudly on
  // mismatch; unknown names just keep the driverID log line.
  setenv("REX_CUSTOM_DRIVER_SO", so.c_str(), 1);
  // (Ronda 3, auditor E — E-R3-5.) PanVK (Mesa, Mali) env knobs, set for
  // ANY custom driver, not only when the .so name contains "panfrost":
  // the old test missed PanVK packs whose library is named differently
  // (the GameHub zip names it libvulkan_freedreno.so) and is
  // case-sensitive (libvulkan_PanFrost.so missed it too). Both variables
  // are PanVK-specific, so a Turnip driver simply ignores them.
  // They must be set HERE, before the driver is first used: settings.txt
  // is only read later (ReadSettingsArgs runs after this call). NOTE
  // (ronda 6, R6-E4): that does NOT mean an env.PANVK_* line in
  // settings.txt arrives too late — the old comment claimed it did, but
  // Mesa only reads these variables later, at physical-device init
  // (PAN_I_WANT_A_BROKEN_VULKAN_DRIVER) and device creation
  // (PANVK_BC_AFRC), both after settings.txt is parsed and before any
  // Vulkan call. So a user CAN override them from settings.txt (its
  // setenv uses overwrite=1); these setenvs here are the defaults, not
  // the only way in.
  // PANVK_BC_AFRC=0: exact BC decode. The kbase default is lossy (RGBA8 BC
  // shadows use AFRC; RC3 notes: PANVK_BC_AFRC=0 restores exact output) and
  // this game ships DXT/BC textures everywhere.
  // PAN_I_WANT_A_BROKEN_VULKAN_DRIVER=1: PROVISIONAL (auditoría PanVK ronda
  // 2, sin verificar). Upstream Mesa refuses to load the non-conformant
  // PanVK driver unless it is set; whether the kbase build keeps that guard
  // is unverified — setting it is harmless if the build ignores it. If the
  // driver loads without it, delete this line.
  setenv("PANVK_BC_AFRC", "0", 1);
  setenv("PAN_I_WANT_A_BROKEN_VULKAN_DRIVER", "1", 1);
  // (Ronda 7, auditor E — R7-E1.) Case-insensitive, como el chequeo
  // R6-E1 de vulkan_device.cpp: el pack PanVK real es
  // libvulkan_PanFrost.so (P/F mayúsculas) y un libvulkan_panvk.so
  // también es PanVK, así que el find("panfrost") case-sensitive de
  // antes nunca imprimía esta línea para ninguno de los dos nombres,
  // aunque los defaults PANVK_* de arriba SÍ se fijaban para ellos
  // (incondicionales desde E-R3-5). Solo log: sin cambio de conducta.
  std::string lower_so = so;
  std::transform(lower_so.begin(), lower_so.end(), lower_so.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  if (lower_so.find("panfrost") != std::string::npos ||
      lower_so.find("panvk") != std::string::npos) {
    ALOGI("PanVK driver: exact BC decode (PANVK_BC_AFRC=0)");
  }
  ALOGI("custom Vulkan driver requested: %s%s (the Vulkan layer verifies the active driverID against this .so)", dir.c_str(), so.c_str());
#else
  (void)internal_dir; (void)lib_dir;
#endif
}

// (Ronda 6, auditor E — R6-E2.) Clean startup failure report: when
// OnInitialize() returns false (most often the Vulkan provider: no
// instance, no physical device, no supported logical device) the process
// exits with EXIT_FAILURE WITHOUT a signal, so no crash.txt is written
// and no frames.ok exists — the launcher's driver-crash guard (which
// needs crash.txt) stays silent and the game just vanishes back to the
// launcher with the reason buried in childoflight.log only. Write a
// short report into the same crash.txt the signal handler uses, so the
// next launch shows it (driver guard when a custom driver is selected,
// generic crash report otherwise). The first line says plainly that this
// is a clean startup failure, not a native crash, so it cannot be mistaken
// for a signal backtrace.
// (Ronda 8, auditor E — R8-E1.) R6-E2 solo cubria el fallo de
// OnInitialize(): los otros dos fallos limpios de arranque de esta
// funcion — SDLWindowedAppContext::Initialize() y !creator —
// devolvian EXIT_FAILURE sin informe y sin guard, con el mismo
// sintoma (el juego desaparece de vuelta al launcher). Ambos ocurren
// DESPUES de resolver log_dir e instalar el crash reporter, asi que
// el mismo fichero sirve. El motivo y el detalle viajan como
// parametros porque el parrafo del proveedor Vulkan solo aplica al
// caso OnInitialize; los otros dos apuntan a la linea REXLOG_ERROR
// que ya se escribio justo antes.
// (Ronda 9, auditor E — R9-E3.) El cuarto fallo limpio,
// SDL_InitSubSystem (antes de log_dir), queda cubierto en
// RunAndroidApp con el fallback del external dir; ver alli.
void WriteStartupFailureReport(const std::string& log_dir, const char* reason,
                               const char* detail) {
  const std::string path = log_dir + "/crash.txt";
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) return;
  out << "Child of Light failed to start: " << reason
      << " (clean startup failure, NOT a native crash).\n"
      << detail << "\n";
  if (const char* so = std::getenv("REX_CUSTOM_DRIVER_SO")) {
    out << "Custom GPU driver requested: " << so << "\n";
  } else {
    out << "Custom GPU driver requested: (none - system driver)\n";
  }
  out << "If a custom driver was selected, try the system driver; otherwise "
         "see childoflight.log.\n";
}

int RunAndroidApp() {
  // Foreground apps may lower their own nice value down to -10 without any
  // permission; the guest threads inherit it. Ignored (EACCES) if refused.
  setpriority(PRIO_PROCESS, 0, -10);
  const std::string lib_dir = QueryNativeLibraryDir();
  JavaVM* java_vm = QueryJavaVm();
  if (lib_dir.empty()) ALOGE("nativeLibraryDir unresolved - GPU plugin loading will fail");

  // Landscape lock (v1.3, bugs A/B): SDL's Android video driver calls Java
  // SDLActivity.setOrientation(1280, 720, resizable=true, hint="") when the
  // window is created, and with an empty hint + resizable window that
  // resolves to SCREEN_ORIENTATION_FULL_USER — which follows the user's
  // rotation lock instead of forcing landscape, so the first surface is
  // born vertical and the title renders letterboxed into a short band.
  // The orientations hint below makes SDL request the orientation the user
  // chose in the graphics settings instead (landscape by default), on
  // every window (re)creation (incl. each SDL_SetWindowFullscreen).
  // MainActivity.setOrientationBis applies the same choice on the Java
  // side as a second layer.
  // (Audit run #16, J-18.) The hint itself is set after
  // SDL_GetAndroidInternalStoragePath(), below: it reads the user's
  // setting from the "graphics" SharedPreferences (ReadOrientationHint),
  // which needs the internal dir. The hint only matters before the window
  // is created (SDLWindowedAppContext::Initialize), so setting it there
  // is still in time.

  // (Ronda 9, auditor E — R9-E3.) El fallback del external dir vive
  // aquí arriba, antes de SDL_InitSubSystem: el cuarto fallo limpio de
  // arranque (este) ocurre antes de que exista log_dir, y R8 lo dejó
  // sin cubrir porque "el log dir necesita SDL_GetAndroidExternalStoragePath".
  // Pero ResolveLogDir solo necesita el external dir, y este fallback es la
  // ruta estándar que getExternalFilesDir devuelve (la misma que lee el
  // guard Java, LogsDialog logsDir) — así que el informe puede escribirse
  // sin llamar a SDL en absoluto.
  const std::string fallback_external_dir =
      std::string("/storage/emulated/0/Android/data/com.rexauto.port.") +
      kAppIdentifier + "/files";
  if (!SDL_InitSubSystem(SDL_INIT_VIDEO)) {
    ALOGE("SDL_InitSubSystem(SDL_INIT_VIDEO) failed: %s", SDL_GetError());
    WriteStartupFailureReport(
        ResolveLogDir(fallback_external_dir),
        "SDL_InitSubSystem(SDL_INIT_VIDEO) failed",
        "The SDL video subsystem could not start (see the ALOGE line in "
        "logcat just above; it carries SDL_GetError()). No Vulkan driver "
        "was attempted yet.");
    return EXIT_FAILURE;
  }
  const char* external_c = SDL_GetAndroidExternalStoragePath();
  std::string external_dir = external_c ? external_c : "";
  if (external_dir.empty()) {
    external_dir = fallback_external_dir;
  }

  const std::string game_root = ReadTrimmedFile(external_dir + "/" + kConfigFileName);
  const char* internal_c = SDL_GetAndroidInternalStoragePath();
  // (Audit run #16, J-18.) Orientation hint from the user's graphics
  // setting (ReadOrientationHint above): landscape by default (the v1.3
  // fix -- an empty hint lets the first surface be born vertical), the
  // user's portrait/auto choice otherwise. Empty means "auto": leave the
  // hint unset so SDL falls back to FULL_USER, matching the Java side.
  {
    const std::string orientations_hint = ReadOrientationHint(internal_c ? internal_c : "");
    if (!orientations_hint.empty()) {
      SDL_SetHint(SDL_HINT_ORIENTATIONS, orientations_hint.c_str());
    }
  }
  // (Ronda 6, auditor E — R6-E3.) Resolve the log dir, wipe the stale
  // markers and install the crash reporter BEFORE loading the custom
  // driver: the old order did it after LoadCustomVulkanDriver, so a crash
  // inside adrenotools_open_libvulkan / the driver dlopen left no
  // crash.txt — and worse, the previous run's frames.ok was still on disk
  // (it was only removed below), so even with a crash report the Java
  // guard's !hasFramesOk() check would have stayed silent. Installing
  // first shrinks the unreported window to the SDL video init above
  // (which loads no Vulkan; since R9-E3 it is covered too, via the
  // hardcoded fallback external dir — SDL_GetAndroidExternalStoragePath is
  // not needed to resolve the log dir).
  std::error_code ec;
  std::filesystem::create_directories(external_dir + "/data", ec);
  const std::string log_dir = ResolveLogDir(external_dir);
  // A previous crash.txt is consumed by the launcher; a fresh launch means the
  // user has seen it (or chose to play again) -- start clean.
  std::filesystem::remove(log_dir + "/crash.txt", ec);
  // (Ronda 4, auditor E — R4-E1.) 300-frame boot guard, launcher half:
  // delete the previous run's marker next to crash.txt (same "start
  // clean" rule: the Java guard reads both files before SDL starts, so a
  // stale marker must not survive into this launch), and publish this
  // run's marker path for the presenter (src/ui/presenter.cpp writes
  // <logs>/frames.ok when presented_frame_count_ reaches 300 in
  // PaintAndPresent — ronda 5, R5-E2 moved the write there from
  // RefreshGuestOutput, so the marker means 300 PRESENTED frames, not
  // 300 refreshes; the old text naming guest_frame_count_ was stale
  // after that move — ronda 6, R6-A1). Publishing it unconditionally
  // costs one setenv and keeps the presenter side free of Android paths;
  // on the system driver the file is written and ignored (the guard only
  // consults it when a custom driver is selected). If the run crashes
  // before 300 presents, no marker exists and the guard offers "Volver
  // al sistema"; if it presented 300 frames, the crash was not a
  // driver-boot failure and the guard stays silent.
  std::filesystem::remove(log_dir + "/frames.ok", ec);
  setenv("REX_FRAMES_OK_PATH", (log_dir + "/frames.ok").c_str(), 1);
  InstallCrashReporter(log_dir);
  LoadCustomVulkanDriver(internal_c ? internal_c : "", lib_dir);
  // The built-in sampler costs a third of a core on this phone (rex-profiler
  // 33.7% in the v1.4.1 profile) for diagnostics we already have, so it is
  // off in this build. Must be set here: prof::Start reads the variable and
  // settings.txt is only read afterwards, so an env line there is too late.
  // To re-enable profiling, remove this line.
  setenv("REX_PROFILE", "0", 1);
  prof::Start(log_dir);

  rex::SetAndroidApplicationContext(java_vm, SDL_GetAndroidActivity(), lib_dir.c_str());
  rex::thread::AndroidInitialize();
  rex::memory::AndroidInitialize();
  rex::filesystem::AndroidInitialize();

  // The port's src/<name>_app.h carries rexauto's desktop "portable paths"
  // hook (game in <exe>/assets, saves in <exe>/userdata). On Android the exe
  // folder is the read-only nativeLibraryDir, so keep the explicit roots below
  // authoritative: the hook honours these two env toggles.
  setenv("REX_NO_PORTABLE_USERDATA", "1", 1);
  unsetenv("REX_PORTABLE_ONLY");

  std::vector<std::string> args;
  args.emplace_back(kAppIdentifier);
  if (!game_root.empty()) {
    if (game_root.starts_with("asset:")) {
      // Full build (Fase 5, v1.4): the game lives inside the APK as an
      // uncompressed asset, not in a host directory. Do NOT pass the marker
      // as --game_data_root: ReXApp::ConstructRuntime rejects any non-empty
      // root that is not a directory. Instead, bridge the fd triple that
      // PortApp handed over at startup (StfsAsset.setAssetFd JNI, stored by
      // stfs_asset_jni.cpp) into the SDK, so Runtime::SetupVfs mounts the
      // STFS container from the APK. The SDK setter dup()s the fd, so the
      // JNI-side copy stays open for the process as documented.
      // The game root is decided by the game_root.txt marker alone: an
      // extracted directory root keeps the historical host-path mount even
      // if an asset fd was also handed over.
      int asset_fd = -1;
      std::int64_t asset_offset = 0, asset_length = 0;
      if (rexport::StfsAssetFd(&asset_fd, &asset_offset, &asset_length)) {
        rex::filesystem::SetStfsAssetSource(asset_fd, uint64_t(asset_offset),
                                            uint64_t(asset_length));
        ALOGI("game root is %s - STFS asset fd=%d offset=%lld length=%lld",
              game_root.c_str(), asset_fd, static_cast<long long>(asset_offset),
              static_cast<long long>(asset_length));
      } else {
        // No triple was handed over: SetupVfs falls back to the (empty)
        // host root and ConstructRuntime fails with "--game_data_root was
        // not provided". Say why here, where the cause is visible.
        ALOGE("game root is %s but no STFS asset fd was handed over "
              "(PortApp/StfsAsset failed?) - the game cannot start",
              game_root.c_str());
      }
    } else {
      args.emplace_back(fmt::format("--game_data_root={}", game_root));
    }
  } else {
    ALOGE("no game_root.txt under %s - re-run setup", external_dir.c_str());
  }
  args.emplace_back(fmt::format("--user_data_root={}", external_dir + "/data"));
  args.emplace_back(fmt::format("--log_file={}/{}.log", log_dir, kAppIdentifier));
  // Mobile defaults (see hells-gate-recomp-android docs/android_performance):
  // no per-frame full re-upload of guest memory pages; the write-watch keeps
  // coherency. Everything below can be overridden by settings.txt.
  args.emplace_back("--clear_memory_page_state=false");
  args.emplace_back("--fullscreen=true");
  // GPU emulation plugin. On Windows the rexauto SDK auto-discovers
  // rexgpu-*.dll beside the exe; on Android there is no such scan, and without
  // it the kernel logs "no GPU emulation loaded (gpu_plugin not set)" and the
  // title renders nothing. librexgpu-xenos.so ships in the APK; the SDK
  // resolves "xenos" against nativeLibraryDir (SetAndroidApplicationContext).
  args.emplace_back("--gpu_plugin=xenos");
  // Mobile pacing defaults (all overridable from settings.txt): the guest
  // thread scheduler must not try to pin threads to the 360's 6 hardware
  // threads (we have big.LITTLE and want the kernel to migrate freely), and
  // the vsync worker should sleep, not spin.
  args.emplace_back("--ignore_thread_affinities=true");
  args.emplace_back("--ignore_thread_priorities=true");
  args.emplace_back("--log_flush_interval=5");  // batch log writes
  // Present frames that used placeholder pipelines instead of dropping them:
  // the skip (default true) drops EVERY frame that still has an uncompiled
  // shader, so during shader warm-up whole frames vanish instead of showing
  // a placeholder for a frame or two. Presenting the placeholder can flash
  // while the cache warms up, but it stops the frame drops. Overridable
  // from settings.txt.
  args.emplace_back("--vulkan_async_skip_incomplete_frames=false");
  // (Audit run #16, M-8.) Two pipeline-creation workers: with one, every
  // new-zone shader compiles serially while the game shows placeholders
  // (the long black/placeholder phase in cold starts). The cvar defaults
  // to -1 (6 threads on this phone: logical_processor_count * 3/4) and is
  // set nowhere else; the old value 1 was a deliberate guard ("several
  // workers saturate mobile drivers, up to crash/OOM"), so this raises it
  // by one worker only -- each worker is pinned to the big cores (2x A76
  // here) and compiles one pipeline at a time, so memory stays bounded by
  // two in-flight pipelines. If the phone shows driver crashes or OOM
  // during shader warm-up, set vulkan_pipeline_creation_threads=1 in
  // settings.txt (it overrides this arg). Phone verification required:
  // CI cannot tell whether 2 workers is safe on this driver.
  args.emplace_back("--vulkan_pipeline_creation_threads=2");
  for (auto& a : ReadSettingsArgs(external_dir + "/" + kSettingsFileName)) {
    ALOGI("setting: %s", a.c_str());
    args.emplace_back(std::move(a));
  }

  std::vector<char*> argv_ptrs;
  argv_ptrs.reserve(args.size());
  for (auto& arg : args) argv_ptrs.push_back(arg.data());

  auto remaining = rex::cvar::Init(static_cast<int>(argv_ptrs.size()), argv_ptrs.data());
  (void)remaining;
  rex::cvar::ApplyEnvironment();
  rex::InitLoggingEarly();

  REXLOG_INFO("android_main: app={} external_dir={} game_root={}", kAppIdentifier,
              external_dir, game_root);

  int result;
  {
    rex::ui::SDLWindowedAppContext app_context;
    if (!app_context.Initialize()) {
      REXLOG_ERROR("SDLWindowedAppContext::Initialize failed: {}", SDL_GetError());
      WriteStartupFailureReport(
          log_dir, "SDLWindowedAppContext::Initialize() failed",
          "The SDL window could not be created (see the REXLOG_ERROR line in "
          "childoflight.log just above; it carries SDL_GetError()).");
      return EXIT_FAILURE;
    }
    const auto creator = rex::ui::WindowedApp::GetCreator(kAppIdentifier);
    if (!creator) {
      REXLOG_ERROR("app '{}' is not registered - recompiled code built for another name",
                   kAppIdentifier);
      WriteStartupFailureReport(
          log_dir, "no WindowedApp creator is registered for this app name",
          "The recompiled code was built for another app name (see the "
          "REXLOG_ERROR line in childoflight.log just above); check the "
          "-PrexName passed to Gradle.");
      return EXIT_FAILURE;
    }
    std::unique_ptr<rex::ui::WindowedApp> app = creator(app_context);
    if (app->OnInitialize()) {
      rexport::gamepad::EnsureVirtualPadAttached();
      result = app_context.RunMainMessageLoop();
    } else {
      REXLOG_ERROR("OnInitialize failed - see earlier errors");
      WriteStartupFailureReport(
          log_dir, "OnInitialize() returned false",
          "Most often this is the Vulkan provider: no instance, no physical "
          "device, or no supported logical device (see the REXLOG_ERROR lines "
          "in childoflight.log just above \"OnInitialize failed\").");
      result = EXIT_FAILURE;
    }
    app->InvokeOnDestroy();
  }
  REXLOG_INFO("android_main: exiting with code {}", result);
  return result;
}

}  // namespace

int main(int argc, char* argv[]) {
  (void)argc;
  (void)argv;
  return RunAndroidApp();
}

#endif  // REX_PLATFORM_ANDROID
