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
#include <charconv>
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
#include <rex/audio/downmix.h>
#include <rex/cvar.h>
#include <rex/filesystem.h>
#include <rex/filesystem/stfs_asset.h>
#include <rex/logging.h>
#include <rex/main_android.h>
#include <rex/memory.h>
#include <rex/platform.h>
#include <rex/runtime.h>
#include <rex/thread.h>
#include <rex/ui/flags.h>
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
#define ALOGW(...) __android_log_print(ANDROID_LOG_WARN, REX_APP_NAME, __VA_ARGS__)
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
// (Hunt v1.4.6 ronda 17, A4-R17-03.) env_count (when non-null) receives the
// number of env.* lines consumed here: they never reach argv, so without
// it the "N lines applied" log below undercounted every boot (the default
// file always carries env.REX_HEAL_DISCOVER=1). A malformed line (no '=',
// empty key) used to be skipped silently -- warn in logcat, so a typo'd
// hand-added line is visible instead of looking applied.
// (Hunt v1.4.6 ronda 23, A4-R23-02.) env_set (when non-null) receives
// every validated env.* line as (NAME, value), in file order, so the
// post-hoc checks can warn about env values that map to a cvar: an
// env.REX_* line reaches the cvar through ApplyEnvironment, which --
// like the CLI path -- never validates constraints, and neither
// LogUnknownSettingsCvars nor LogSuspiciousSettingsValues ever sees it
// (both only iterate the --key=value lines). Lines skipped as malformed
// (empty env name) are not collected: they never ran setenv.
std::vector<std::string> ReadSettingsArgs(
    const std::string& path, int* env_count,
    std::vector<std::pair<std::string, std::string>>* env_set) {
  std::vector<std::string> out;
  if (env_count) *env_count = 0;
  std::ifstream in(path, std::ios::binary);
  if (!in) return out;
  std::string line;
  bool first_line = true;
  while (std::getline(in, line)) {
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) line.pop_back();
    // (Hunt v1.4.6 ronda 19, A4-R19-02.) A UTF-8 BOM (EF BB BF) at the
    // start of the file -- what Windows editors write when a hand-edited
    // settings.txt is saved as UTF-8 -- used to become part of the first
    // line's key ("--\xEF\xBB\xBFgpu_plugin=xenos"), an unknown option
    // CLI11 stashed and ignored, so the first line silently never
    // applied. Strip it once, on the first line only: a BOM is a file
    // header, never line content. Verified against the real
    // ReadSettingsArgs: the BOM'd first line reached argv with the BOM
    // bytes in the key.
    if (first_line) {
      first_line = false;
      if (line.rfind("\xEF\xBB\xBF", 0) == 0) line.erase(0, 3);
    }
    // (Hunt v1.4.6 ronda 19, A4-R19-01.) Leading blanks are not part of
    // the key: " resolution_scale=2" used to reach CLI11 as
    // "-- resolution_scale=2", an unknown option that was silently
    // ignored, and "  # comment" was warned about as malformed instead
    // of skipped as a comment. A "--" prefix is not part of the key
    // either: the file format is "key=value" (this function adds the
    // "--"), so "--gpu_plugin=xenos" used to arrive as
    // "----gpu_plugin=xenos" and was silently ignored too.
    const size_t first = line.find_first_not_of(" \t");
    if (first == std::string::npos) continue;
    if (first > 0) line.erase(0, first);
    if (line.rfind("--", 0) == 0) line.erase(0, 2);
    // (Hunt v1.4.6 ronda 22, A4-R22-03.) A blank after the dashes
    // ("-- gpu_plugin=xenos") left the key with a leading blank:
    // the leading-blank strip above ran BEFORE the "--" strip, so
    // "-- gpu_plugin" reached CLI11 as "-- gpu_plugin=xenos", an
    // unknown option that was dropped and only warned about as a
    // (confusingly named) unknown cvar. Strip blanks again after the
    // dashes; a line that is only "--" plus blanks is silently skipped,
    // as before (the loop-top trim already leaves "--" -> ""), and
    // "-- # comment" now reads as the comment it is.
    const size_t after_dashes = line.find_first_not_of(" \t");
    if (after_dashes != std::string::npos && after_dashes > 0) line.erase(0, after_dashes);
    if (line.empty() || line[0] == '#') continue;
    const auto eq = line.find('=');
    if (eq == std::string::npos || eq == 0) {
      ALOGW("settings.txt: ignoring malformed line '%s' (expected key=value)", line.c_str());
      continue;
    }
    // (Hunt v1.4.6 ronda 19, A4-R19-01.) Blanks around the key are not
    // part of it: "resolution_scale =2" used to reach CLI11 as
    // "--resolution_scale =2", an unknown option that was silently
    // ignored (and " env.FOO=1" setenv'd " FOO"). The key is empty
    // after the trim only for the "--=value" spelling, whose "--" strip
    // above leaves an empty key; plain "=value" is already rejected by
    // the check above.
    std::string key = line.substr(0, eq);
    while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();
    if (key.empty()) {
      ALOGW("settings.txt: ignoring malformed line '%s' (expected key=value)", line.c_str());
      continue;
    }
    // The value, normalised once and shared by the env.* branch below
    // and the cvar branch after it, so both read the same value.
    // Leading blanks are not part of it: "gpu_plugin= xenos" used to
    // store " xenos" (the plugin lookup failed: black screen), and
    // "vulkan_async_skip_incomplete_frames= true" was applied as false
    // by CLI11 (verified against the vendored CLI11: to_flag_value
    // returns 0 for a value with a leading blank).
    std::string value = line.substr(eq + 1);
    const size_t vfirst = value.find_first_not_of(" \t");
    if (vfirst == std::string::npos) {
      value.clear();
    } else if (vfirst > 0) {
      value.erase(0, vfirst);
    }
    // (Hunt v1.4.6 ronda 19, A4-R19-01.) An unquoted trailing comment
    // ("key=value # why") is not part of the value: a bool with one was
    // applied as false by CLI11 ("vulkan_async_skip_incomplete_frames=
    // true # warmup" froze the guest: to_flag_value("true # warmup")
    // is 0) and a string kept the suffix ("gpu_plugin=xenos # use
    // xenos" failed the plugin lookup). Only a "#" preceded by a blank
    // starts a comment, so "a#b" survives; a value that IS a comment
    // ("key= # ...") is empty and falls through to the empty check
    // below. A "#" inside quotes is data: for a quoted value only a
    // comment AFTER the closing quote is dropped, so the R18-03 strip
    // below still sees the pair.
    if (!value.empty() && (value.front() == '"' || value.front() == '\'')) {
      const char q = value.front();
      const size_t close = value.find(q, 1);
      if (close != std::string::npos) {
        const std::string rest = value.substr(close + 1);
        const size_t rfirst = rest.find_first_not_of(" \t");
        if (rfirst == std::string::npos || rest[rfirst] == '#') {
          value.erase(close + 1);
        }
      }
    } else if (!value.empty() && value.front() == '#') {
      value.clear();
    } else {
      const size_t hash = value.find('#');
      if (hash != std::string::npos && hash > 0 &&
          (value[hash - 1] == ' ' || value[hash - 1] == '\t')) {
        value.erase(hash);
        while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.pop_back();
      }
    }
    // (Hunt v1.4.6 ronda 18, A4-R18-03, moved before the env.* branch in
    // ronda 19, A4-R19-01.) A value wrapped in one pair of matching
    // quotes ("xenos", 'xenos') is not a value with quotes in it: the
    // extra box has no shell, so nothing ever strips them, and CLI11
    // receives the quotes as part of the value -- gpu_plugin= "xenos"
    // fails the plugin lookup (black screen, verified against the
    // vendored CLI11: the stored value keeps both quote characters).
    // Strip one matching pair; an unbalanced quote is left alone, and a
    // value that is only quotes ("" / '') falls through to the empty
    // check below and is skipped there. It runs here, before the env.*
    // branch, so an env value gets the same unquoting: env.REX_FPS_CAP=
    // "30" used to setenv the quotes, and atof("\"30\"") is 0.
    if (value.size() >= 2) {
      const char q = value.front();
      if ((q == '"' || q == '\'') && value.back() == q) {
        ALOGW("settings.txt: stripped quotes from the value of '%s'",
              key.c_str());
        value = value.substr(1, value.size() - 2);
      }
    }
    if (key.rfind("env.", 0) == 0) {
      // env.NAME=value -> setenv(NAME, value); consumed by getenv() readers
      // such as the tolerant dispatcher (REX_HEAL_DISCOVER).
      std::string env_name = key.substr(4);
      const size_t efirst = env_name.find_first_not_of(" \t");
      if (efirst != std::string::npos) env_name.erase(0, efirst);
      // (Hunt v1.4.6 ronda 20, A4-R20-05.) An env.* line with no name
      // ("env.=1", "env. =1", "env.   =1"): setenv("") fails with EINVAL
      // and a blank-only name stores a junk variable nothing reads, but
      // the line still counted as applied in the "N lines applied" log
      // below -- the count overcounted and the typo'd line was silent.
      // Skip it with a warning, like the other malformed lines above.
      while (!env_name.empty() && (env_name.back() == ' ' || env_name.back() == '\t')) env_name.pop_back();
      if (env_name.empty()) {
        ALOGW("settings.txt: ignoring '%s' (env.* line with no variable name)", line.c_str());
        continue;
      }
      setenv(env_name.c_str(), value.c_str(), 1);
      if (env_set) env_set->emplace_back(env_name, value);
      if (env_count) ++(*env_count);
      continue;
    }
    // (Hunt v1.4.6 ronda 18, A4-R18-01.) An empty value is NOT "reset to
    // default": CLI11 reads "--key=" as "--key" with the value still to
    // come, so it eats the NEXT argv element as this key's value
    // (verified against the vendored CLI11: "--gpu_plugin=" swallows
    // "--log_flush_interval=1" as the plugin name, and
    // "--log_flush_interval=" swallows
    // "--vulkan_async_skip_incomplete_frames=false", leaving async_skip
    // at its SDK default true = guest 0.0 fps), and as the LAST arg it
    // throws "1 required TEXT missing", aborting the whole parse with no
    // cvar applied at all (no gpu_plugin -> black screen, license_mask 0
    // -> DLCs off). A "--bool=" line is just as bad in the other
    // direction: a flag with an empty value counts as a bare flag, i.e.
    // true ("--vulkan_async_skip_incomplete_frames=" freezes the guest).
    // Skip the line with a warning and keep the earlier value (mobile
    // default or an earlier settings line). env.* lines are exempt:
    // setenv(NAME, "") is meaningful -- REX_HEAL_DISCOVER is read as
    // presence, and REX_FPS_CAP="" parses to 0 and is ignored.
    if (value.empty()) {
      ALOGW("settings.txt: ignoring '%s' (empty value; delete the line to use the default)",
            key.c_str());
      continue;
    }
    out.emplace_back("--" + key + "=" + value);
  }
  return out;
}

// (Hunt v1.4.6 ronda 18, A4-R18-02.) Whether a string is a value CLI11's
// to_flag_value accepts as a bool literal: "true"/"false" (matched
// case-insensitively, as to_flag_value lowercases before comparing),
// on/off/yes/no/enable/disable, single letters t/y/+/f/n/-, and single
// digits 0/1. Multi-digit numbers are deliberately NOT in the set:
// to_flag_value accepts them, but a "--no-<int-key>=5" line is nonsense
// input, and keeping the "no-" key distinct is the safe side for it
// (the un-stripped form is a harmless unknown option to CLI11).
bool IsBoolLiteral(const std::string& v) {
  size_t b = 0, e = v.size();
  while (b < e && (v[b] == ' ' || v[b] == '\t')) ++b;
  while (e > b && (v[e - 1] == ' ' || v[e - 1] == '\t')) --e;
  std::string lower;
  for (size_t i = b; i < e; ++i) lower += char(std::tolower(static_cast<unsigned char>(v[i])));
  if (lower == "true" || lower == "false" || lower == "on" || lower == "off" ||
      lower == "yes" || lower == "no" || lower == "enable" || lower == "disable") {
    return true;
  }
  if (lower.size() == 1) {
    const char c = lower[0];
    return (c >= '0' && c <= '1') || c == 't' || c == 'y' || c == '+' || c == 'f' ||
           c == 'n' || c == '-';
  }
  return false;
}

// (Hunt v1.4.6, R-A-M4.) Warn about settings.txt lines whose key names no
// registered cvar. Must run AFTER the runtime exists (all modules, incl. the
// GPU plugin, have registered their cvars by then): at cvar::Init time most
// GPU/kernel cvars are not registered yet, so checking there would warn for
// every legitimate vulkan_* line. A key that registers even later still
// applies (cvar::Init stashes it as a pending value), so the message says
// "not registered yet", not "unknown".
void LogUnknownSettingsCvars(const std::vector<std::string>& settings_args) {
  for (const auto& arg : settings_args) {
    if (arg.size() < 3 || arg[0] != '-' || arg[1] != '-') continue;
    const auto eq = arg.find('=');
    std::string name =
        arg.substr(2, eq == std::string::npos ? std::string::npos : eq - 2);
    if (name.empty()) continue;
    // (Hunt v1.4.6 ronda 19, A4-R19-03.) A "--no-key" line names the
    // key with its negation prefix: without the strip every legitimate
    // negation warned spuriously about a cvar named "no-key". Look the
    // base key up; an unknown base still warns, under its own name.
    // (Hunt v1.4.6 ronda 25, A4-R25-02.) The strip used to be
    // unconditional: it also swallowed the prefix of a NON-bool key
    // ("--no-gpu_plugin=turnip"; gpu_plugin is a String cvar), so the
    // line warned nowhere -- the dedupe (R18-02) and
    // LogSuspiciousSettingsValues only treat --no-key as a negation
    // when the base is a bool cvar, and CLI11 takes the un-stripped
    // form as a harmless unknown option. Strip only when the base is
    // a Boolean cvar (same guard as LogSuspiciousSettingsValues):
    // a "--no-<string-key>" line now warns under its own name.
    if (name.rfind("no-", 0) == 0) {
      const std::string base = name.substr(3);
      const rex::cvar::FlagEntry* base_info = rex::cvar::GetFlagInfo(base);
      if (base_info && base_info->type == rex::cvar::FlagType::Boolean) name = base;
    }
    if (name.empty()) continue;
    if (!rex::cvar::GetFlagInfo(name)) {
      REXLOG_WARN("settings.txt: no cvar named '{}' is registered yet "
                  "(typo? the line has no effect unless a cvar with that "
                  "name registers later)",
                  name);
    }
  }
}

// (Hunt v1.4.6 ronda 19, A4-R19-03.) What CLI11's to_flag_value (vendored
// CLI11 TypeTools.hpp) makes of a bool value: exact true/false (any case),
// on/off/yes/no/enable/disable, single letters t/y/+ /f/n/- and single
// digits 0/1, or any integer (strtoll base 0, so "2" and "0x10" count as
// true, "-1" as false). Anything else yields a count of 0 -- the flag is
// applied as false -- with no diagnostic from CLI11 or from the cvar
// setter (the bool setter always returns true). A number with trailing
// junk ("1.5", "2x") applies as its numeric prefix, which is still not a
// bool literal. CLI11 trims TRAILING blanks from the value ("true "
// applies as true) but not leading ones (" true" applies as false), so
// only trailing blanks are trimmed here. Verified against the vendored
// CLI11: "maybe", "tru", "yesplease", "enabled", " true" and
// "true # comment" all apply as false; "1.5" and "2x" apply as true; a
// single unknown letter ("q") applies as false; none of them throws, so
// the parse continues and the wrong value is silent. `recognised` is
// false for those; `applies_true` is what the flag ends up as.
bool SettingsBoolAppliesAs(const std::string& v, bool& applies_true, bool& recognised) {
  std::string t = v;
  while (!t.empty() && (t.back() == ' ' || t.back() == '\t')) t.pop_back();
  std::string lower;
  for (char c : t) lower += char(std::tolower(static_cast<unsigned char>(c)));
  if (lower == "true" || lower == "on" || lower == "yes" || lower == "enable") {
    applies_true = true;
    recognised = true;
    return true;
  }
  if (lower == "false" || lower == "off" || lower == "no" || lower == "disable") {
    applies_true = false;
    recognised = true;
    return true;
  }
  if (lower.size() == 1) {
    const char c = lower[0];
    if (c >= '1' && c <= '9') {
      applies_true = true;
      recognised = true;
      return true;
    }
    if (c == '0' || c == 'f' || c == 'n' || c == '-') {
      applies_true = false;
      recognised = true;
      return true;
    }
    if (c == 't' || c == 'y' || c == '+') {
      applies_true = true;
      recognised = true;
      return true;
    }
  }
  char* end = nullptr;
  const long long n = std::strtoll(t.c_str(), &end, 0);
  if (end != t.c_str()) {
    applies_true = (n != 0);
    recognised = (end == t.c_str() + t.size());
    return true;
  }
  applies_true = false;
  recognised = false;
  return true;
}

// (Hunt v1.4.6 ronda 22, A4-R22-01.) The remaining half of A4-R18-04:
// LogSuspiciousSettingsValues warns when the setter rejects a value or
// applies only its numeric prefix, but it never looks at the cvar's
// declared constraints -- and the CLI path never enforces them either
// (cvar::Init calls ApplyFromSource, which skips ValidateConstraints;
// only SetFlagFromSource, the console/config path, calls it). So
// log_flush_interval=999 (range 0-60, logging.cpp), a texture-cache
// limit above its range (soft 64-4096, cache.cpp), or present_effect=fsr
// (allowed {"bilinear"} on Android, presenter.cpp, no FidelityFX SDK)
// all apply in silence: the cache limits are even consumed raw
// (CompletedSubmissionUpdated adds them to a uint32 with no clamp), so a
// 5000 MiB soft limit on a 4 GiB phone barely ever evicts. Warn here,
// next to the other post-hoc checks, using the same public fields
// ValidateConstraints reads (info->constraints); warnings only, the
// applied values do not change -- enforcing them on the CLI path would
// mean routing cvar::Init through SetFlagFromCommandLine, which also
// fires change callbacks and marks kRequiresRestart flags mid-parse,
// a behaviour change this warning-only fix deliberately avoids.
void WarnIfOutsideConstraints(const std::string& key, const std::string& value,
                              const rex::cvar::FlagEntry* info) {
  const auto& c = info->constraints;
  // Range: numeric types only, mirroring ValidateConstraints (cvar.cpp),
  // which skips String/Boolean here. ParseDouble requires full
  // consumption, so a value the switch below already warns about ("2x",
  // "0x2", "abc") never reaches the comparison.
  if (c.HasRangeConstraint() && info->type != rex::cvar::FlagType::String &&
      info->type != rex::cvar::FlagType::Boolean) {
    double d = 0;
    if (rex::cvar::ParseDouble(value, d) &&
        ((c.min.has_value() && d < *c.min) || (c.max.has_value() && d > *c.max))) {
      // A negative texture-cache limit already warns specifically about
      // the ~4 GiB wrap in the Int32 case below; do not warn twice for
      // the same line. A limit ABOVE its range still warns here.
      const bool cache_limit = key == "texture_cache_memory_limit_soft" ||
                               key == "texture_cache_memory_limit_hard" ||
                               key == "texture_cache_memory_limit_render_to_texture" ||
                               key == "texture_cache_memory_limit_soft_lifetime";
      if (!(cache_limit && d < 0)) {
        REXLOG_WARN("settings.txt: value '{}' for cvar '{}' is outside its declared range "
                    "[{}, {}]; the CLI path does not enforce constraints, so the value "
                    "still applies",
                    value, key, c.min.has_value() ? std::to_string(*c.min) : std::string("-inf"),
                    c.max.has_value() ? std::to_string(*c.max) : std::string("+inf"));
      }
    }
  }
  // Allowed values: every type, mirroring ValidateConstraints.
  if (c.HasAllowedValues()) {
    bool found = false;
    for (const auto& allowed : c.allowed_values) {
      if (allowed == value) {
        found = true;
        break;
      }
    }
    if (!found) {
      std::string allowed_list;
      for (size_t i = 0; i < c.allowed_values.size(); ++i) {
        if (i != 0) allowed_list += ", ";
        allowed_list += c.allowed_values[i];
      }
      REXLOG_WARN("settings.txt: value '{}' for cvar '{}' is not in its allowed values "
                  "({}); the CLI path does not enforce constraints, so the value still "
                  "applies (check the consumer's fallback)",
                  value, key, allowed_list);
    }
  }
  // Custom validator: none in the tree (grep: zero .validator( uses), but
  // mirror ValidateConstraints so a future one is covered.
  if (c.custom_validator && !c.custom_validator(value)) {
    REXLOG_WARN("settings.txt: value '{}' for cvar '{}' failed its custom validation; "
                "the CLI path does not enforce constraints, so the value still applies",
                value, key);
  }
}

// (Hunt v1.4.6 ronda 23, A4-R23-02.) The per-value half of
// LogSuspiciousSettingsValues, extracted verbatim so the env.* path
// (LogSuspiciousEnvValues below) gets the same warnings the CLI path
// gets: a bool value that is not a bool literal, an int the setter
// rejects or truncates, a negative cache limit that wraps to ~4 GiB.
// `negated` is only true for a "--no-key=value" line, which has no env
// equivalent; the env path always passes false.
void WarnIfSuspiciousValue(const std::string& key, const std::string& value,
                           const rex::cvar::FlagEntry* info, bool negated) {
  switch (info->type) {
    case rex::cvar::FlagType::Boolean: {
      bool applies_true = false, recognised = false;
      SettingsBoolAppliesAs(value, applies_true, recognised);
      if (negated && recognised) applies_true = !applies_true;
      // A negated non-literal was already warned about while building
      // the map (it is broken no matter what follows it); only warn
      // here for the plain form.
      if (!recognised && !negated) {
        REXLOG_WARN("settings.txt: value '{}' for bool cvar '{}' is not "
                    "a bool literal; CLI11 applied it as {} (use "
                    "true/false, on/off, yes/no, 0/1)",
                    value, key, applies_true ? "true" : "false");
      }
      break;
    }
    case rex::cvar::FlagType::Int32: {
      int32_t n = 0;
      const auto [ptr, ec] =
          std::from_chars(value.data(), value.data() + value.size(), n);
      if (ec != std::errc()) {
        REXLOG_WARN("settings.txt: value '{}' for cvar '{}' was rejected "
                    "by the setter (not a number for this type); the "
                    "previous/default value was kept",
                    value, key);
      } else if (ptr != value.data() + value.size()) {
        REXLOG_WARN("settings.txt: value '{}' for cvar '{}' applied as {}; "
                    "trailing characters '{}' were ignored",
                    value, key, n, value.substr(ptr - value.data()));
      } else if (n < 0 && (key == "texture_cache_memory_limit_soft" ||
                           key == "texture_cache_memory_limit_hard" ||
                           key == "texture_cache_memory_limit_render_to_texture" ||
                           key == "texture_cache_memory_limit_soft_lifetime")) {
        REXLOG_WARN("settings.txt: negative value {} for cvar '{}' wraps "
                    "to ~4 GiB when the texture cache converts it to "
                    "uint32; use 0 to disable or a positive MiB limit",
                    n, key);
      }
      break;
    }
    case rex::cvar::FlagType::Int64: {
      int64_t n = 0;
      const auto [ptr, ec] =
          std::from_chars(value.data(), value.data() + value.size(), n);
      if (ec != std::errc()) {
        REXLOG_WARN("settings.txt: value '{}' for cvar '{}' was rejected "
                    "by the setter (not a number for this type); the "
                    "previous/default value was kept",
                    value, key);
      } else if (ptr != value.data() + value.size()) {
        REXLOG_WARN("settings.txt: value '{}' for cvar '{}' applied as {}; "
                    "trailing characters '{}' were ignored",
                    value, key, n, value.substr(ptr - value.data()));
      }
      break;
    }
    case rex::cvar::FlagType::Uint32: {
      uint32_t n = 0;
      const auto [ptr, ec] =
          std::from_chars(value.data(), value.data() + value.size(), n);
      if (ec != std::errc()) {
        REXLOG_WARN("settings.txt: value '{}' for cvar '{}' was rejected "
                    "by the setter (not a number for this type); the "
                    "previous/default value was kept",
                    value, key);
      } else if (ptr != value.data() + value.size()) {
        REXLOG_WARN("settings.txt: value '{}' for cvar '{}' applied as {}; "
                    "trailing characters '{}' were ignored",
                    value, key, n, value.substr(ptr - value.data()));
      }
      break;
    }
    case rex::cvar::FlagType::Uint64: {
      uint64_t n = 0;
      const auto [ptr, ec] =
          std::from_chars(value.data(), value.data() + value.size(), n);
      if (ec != std::errc()) {
        REXLOG_WARN("settings.txt: value '{}' for cvar '{}' was rejected "
                    "by the setter (not a number for this type); the "
                    "previous/default value was kept",
                    value, key);
      } else if (ptr != value.data() + value.size()) {
        REXLOG_WARN("settings.txt: value '{}' for cvar '{}' applied as {}; "
                    "trailing characters '{}' were ignored",
                    value, key, n, value.substr(ptr - value.data()));
      }
      break;
    }
    case rex::cvar::FlagType::Double: {
      double d = 0;
      if (!rex::cvar::ParseDouble(value, d)) {
        REXLOG_WARN("settings.txt: value '{}' for cvar '{}' was rejected "
                    "by the setter (not a number); the previous/default "
                    "value was kept",
                    value, key);
      }
      break;
    }
    default:
      break;  // String stores anything; Command is not a setting.
  }
}

// (Hunt v1.4.6 ronda 19, A4-R19-03.) Warn about settings.txt values the
// parse silently misapplied. Runs next to LogUnknownSettingsCvars, after
// the runtime exists, so the cvar types are known; warnings only, the
// applied values do not change. Three silent cases, all verified against
// the vendored CLI11 and the cvar setters (cvar.h):
//  * a bool value that is not a bool literal ("tru", "yesplease",
//    "enabled", " true", "true # comment") is applied as false -- or as
//    its numeric prefix ("1.5", "2x" apply as true) -- with no diagnostic
//    from CLI11 or the setter;
//  * an int value the setter rejects (" 2", "abc", "-1" for a uint32, a
//    number too large for the type) is dropped and the previous/default
//    value kept, with no diagnostic (cvar::Init ignores the setter's
//    return value);
//  * an int value with trailing junk ("2x", "0x2") applies as its numeric
//    prefix (from_chars stops at the first bad char and the setter only
//    checks ec, not full consumption): "0x2" applies as 0, and a negative
//    texture-cache limit wraps to ~4 GiB where the cache converts the
//    INT32 to uint32 (cache.cpp CompletedSubmissionUpdated).
// The last-wins value per key is checked, matching the dedupe: a dropped
// duplicate with a bad value does not warn. A "--no-key=value" line is
// checked against the base key; a non-literal value there is doubly
// wrong, because CLI11 does NOT negate a numeric prefix
// ("--no-key=2x" applies as true, verified against the vendored CLI11),
// so only a recognised literal is flipped.
void LogSuspiciousSettingsValues(const std::vector<std::string>& settings_args) {
  std::map<std::string, std::pair<std::string, bool>> last;  // key -> (value, negated)
  for (const auto& arg : settings_args) {
    if (arg.size() < 3 || arg[0] != '-' || arg[1] != '-') continue;
    const auto eq = arg.find('=');
    std::string key =
        arg.substr(2, eq == std::string::npos ? std::string::npos : eq - 2);
    std::string value = (eq == std::string::npos) ? "true" : arg.substr(eq + 1);
    bool negated = false;
    // A "--no-key" line targets the base key when the base is a bool
    // cvar (the "--key,!--no-key" registration). A non-literal value
    // there ("--no-key=2x") is broken no matter what follows it: CLI11
    // does NOT negate a numeric prefix (it counts +2), and no later
    // line cancels that count (bool flags sum), so warn here, at the
    // line, instead of only when it happens to win.
    if (key.rfind("no-", 0) == 0) {
      const std::string base = key.substr(3);
      const rex::cvar::FlagEntry* base_info = rex::cvar::GetFlagInfo(base);
      if (base_info && base_info->type == rex::cvar::FlagType::Boolean) {
        key = base;
        negated = true;
        if (eq != std::string::npos && !IsBoolLiteral(value)) {
          bool applies_true = false, recognised = false;
          SettingsBoolAppliesAs(value, applies_true, recognised);
          REXLOG_WARN("settings.txt: '--no-{}={}' is not a bool negation "
                      "(the value is not a bool literal); CLI11 applied it "
                      "as {} -- a numeric value is not negated by --no-",
                      key, value, applies_true ? "true" : "false");
        }
      }
    }
    if (key.empty()) continue;
    last[key] = {value, negated};
  }
  for (const auto& [key, value_negated] : last) {
    const auto& [value, negated] = value_negated;
    const rex::cvar::FlagEntry* info = rex::cvar::GetFlagInfo(key);
    if (!info) continue;  // LogUnknownSettingsCvars already warns.
    // (Hunt v1.4.6 ronda 22, A4-R22-01.) Range / allowed-values /
    // custom-validator half of A4-R18-04: WarnIfSuspiciousValue above
    // only catches values the setter rejects or truncates, never a value
    // the setter accepts outside its declared constraints.
    WarnIfOutsideConstraints(key, value, info);
    WarnIfSuspiciousValue(key, value, info, negated);
  }
}

// (Hunt v1.4.6 ronda 23, A4-R23-02.) The env.* half of A4-R22-01:
// WarnIfOutsideConstraints only ever saw the --key=value lines, but an
// env.REX_* line reaches the same cvar through ApplyEnvironment, which
// -- like cvar::Init's ApplyFromSource -- never calls
// ValidateConstraints (cvar.cpp: only SetFlagFromSource, the
// console/config path, validates). So env.REX_LOG_FLUSH_INTERVAL=999
// (range 0-60) or env.REX_RESOLUTION_SCALE=99 (range 1-8) applied in
// silence, with no warning from anywhere: not from the setter (it
// accepts), not from LogSuspiciousSettingsValues (it only iterates the
// cvar lines). Reachable from the UI, not just by hand-editing: the
// "extra" box in the graphics dialog exports any env.* line verbatim
// (GraphicsSettings.asCvars), and the shipped file already carries
// env.REX_HEAL_DISCOVER / env.REX_FPS_CAP. Warnings only, like the CLI
// path: the applied values do not change.
//
// Only an env value that is actually in effect warns: GetFlagSource
// tells which source last wrote the cvar, and the priority order is
// default < config < environment < command line (cvar.h), so an env
// value loses to any --key=value line for the same cvar (settings.txt
// or a mobile default). And when the setter rejects the env value,
// ApplyEnvironment already warns ("Env: failed to parse") and the
// source stays whatever it was -- so source == kEnvironment is
// exactly "the env value won and is in effect". Names that do not
// start with REX_ cannot be a cvar (FlagNameToEnvVar always prefixes
// REX_), and a REX_ name that maps to no cvar (REX_HEAL_DISCOVER,
// REX_FPS_CAP, REX_PROFILE and friends, which other getenv() readers
// consume) is skipped silently, as today. Ambient REX_* variables
// from outside settings.txt are NOT covered: this only sees the lines
// ReadSettingsArgs collected -- on Android there is no realistic way
// for one to arrive (zygote does not carry them), and the native
// setenvs in this file (REX_PROFILE, REX_FRAMES_OK_PATH, ...) are not
// cvar overrides.
void LogSuspiciousEnvValues(
    const std::vector<std::pair<std::string, std::string>>& env_set) {
  std::map<std::string, std::string> last;  // env NAME -> value, last wins
  for (const auto& [name, value] : env_set) last[name] = value;
  for (const auto& [name, value] : last) {
    if (name.rfind("REX_", 0) != 0) continue;
    std::string key = name.substr(4);
    for (char& c : key) c = char(std::tolower(static_cast<unsigned char>(c)));
    const rex::cvar::FlagEntry* info = rex::cvar::GetFlagInfo(key);
    if (!info) continue;
    if (rex::cvar::GetFlagSource(key) != rex::cvar::Source::kEnvironment) continue;
    WarnIfOutsideConstraints(key, value, info);
    WarnIfSuspiciousValue(key, value, info, false);
  }
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
  // (Hunt v1.4.6 ronda 24, A4-R24-01.) Bluetooth Steam Controllers:
  // DORMANT -- the SDL HIDAPI Steam driver stays at its default "0"
  // (SDL_hints.h: "1 ... requires Bluetooth access and may prompt the
  // user for permission on iOS and Android"). R20 (A4-R20-01) set this
  // hint to "1", so SDL's hid_init() asked for BLUETOOTH_CONNECT at
  // every launch, before the title -- the "Nearby devices" dialog the
  // player saw on start -- and the player has no Steam Controller
  // (his controller is the phone itself) and ordered no permission
  // prompts at game start. With the hint at "0", hid_init() still
  // runs HIDDeviceManager.initialize(true, false) for USB, but its
  // Bluetooth branch (initialize(false, true), the bonded-device
  // enumeration, the GATT connect and the Chromebook poll) never runs
  // and no runtime permission is requested; the manifest declarations
  // are gone too (AndroidManifest.xml), so the permission is not even
  // listed. The BLE stack (HIDDeviceManager /
  // HIDDeviceBLESteamController) is untouched and still works if
  // re-enabled: call SDL_SetHint(SDL_HINT_JOYSTICK_HIDAPI_STEAM, "1")
  // AND restore the manifest lines,
  // both together -- the hint alone requests a permission the manifest
  // does not declare (auto-denied, no dialog), and the manifest alone
  // requests nothing. A lazy in-context request was considered and
  // rejected: there is no in-app "connect a BLE controller" action to
  // attach it to (pairing happens in Android Settings; the app only
  // enumerates bonded devices once, at SDL init), and hid_init() runs
  // once (g_initialized), so a toggle could only take effect after a
  // restart -- where it would show the same startup dialog the player
  // banned -- for hardware he does not own. Standard Bluetooth
  // gamepads, USB controllers and the touch pad are unaffected: they
  // arrive through Android's InputDevice path, which needs no
  // BLUETOOTH_CONNECT from the app.
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
        // (Hunt v1.4.6, A2-R6-07.) SetStfsAssetSource now reports
        // failure (dup() with the fd table full): abort the launch with
        // a clean startup-failure report instead of logging success and
        // letting SetupVfs "succeed" with no game mounted, which only
        // surfaced later as a generic LoadXexImage failure.
        if (!rex::filesystem::SetStfsAssetSource(asset_fd, uint64_t(asset_offset),
                                                 uint64_t(asset_length))) {
          ALOGE("game root is %s but the STFS asset fd=%d could not be stored "
                "(see childoflight.log) - the game cannot start",
                game_root.c_str(), asset_fd);
          WriteStartupFailureReport(
              log_dir, "STFS asset fd could not be stored",
              "SetStfsAssetSource failed (dup() of the APK asset fd failed, "
              "most likely the fd table is full). See the REXFS_ERROR line "
              "in childoflight.log just above; it carries the errno.");
          return EXIT_FAILURE;
        }
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
  args.emplace_back("--log_flush_interval=1");  // (Hunt v1.4.6, R-A-M2.) Was 5:
  // up to 5 s of log sat unflushed before a crash, and the crash report is
  // often the only diagnosis. 1 s loses at most 1 s; spdlog flush_every(1s)
  // costs one periodic flush, far less than 5 s of lost diagnosis.
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
  // (Hunt v1.4.6, R-A-M4.) Keep the settings.txt lines so they can be
  // checked against the registered cvars once the runtime exists (below):
  // a typo'd key used to die silently -- cvar::Init stashes unknown
  // --options as pending values and only a later-registered cvar ever
  // applies them, so an unknown key never produced any feedback at all.
  // (Hunt v1.4.6 ronda 17, A4-R17-03.) env.* lines are consumed by
  // ReadSettingsArgs (setenv) and never reach argv; count them so the
  // log below does not undercount.
  int env_lines = 0;
  std::vector<std::pair<std::string, std::string>> env_set;
  const std::vector<std::string> settings_args =
      ReadSettingsArgs(external_dir + "/" + kSettingsFileName, &env_lines, &env_set);
  for (const auto& a : settings_args) {
    ALOGI("setting: %s", a.c_str());
    args.emplace_back(a);
  }

  // (Hunt v1.4.6 ronda 17, A4-R17-01/02.) Deduplicate --key=value args,
  // last occurrence wins. cvar::Init does NOT do last-wins, despite the
  // comment on the R16 log below claiming so: bool cvars are registered
  // with CLI11 add_flag_function + Sum policy (cvar.cpp), so
  // "--key=false --key=true" sums to 0 and applies as FALSE -- an
  // "extra" override of vulkan_async_skip_incomplete_frames=true was
  // silently inverted to false (verified against the vendored CLI11:
  // to_flag_value("false")=-1, to_flag_value("true")=+1, Sum adds
  // them). String/int cvars use the default Throw policy, so a duplicate
  // aborts the whole parse with a CLI11 ParseError that only reaches
  // stderr, no cvar callback runs at all, and the game boots on SDK
  // defaults (no gpu_plugin -> black screen, license_mask 0 -> DLCs
  // off, async_skip true -> guest 0.0 fps). Duplicates are reachable:
  // the mobile defaults above share a key with settings.txt
  // (vulkan_async_skip_incomplete_frames), and the "extra" box or a
  // hand-added line can repeat any argv key (gpu_plugin,
  // log_flush_interval, game_data_root, ...). Collapsing here makes
  // the documented "settings.txt wins" contract true for every type.
  // Positionals (argv[0], anything not starting with "--") pass through
  // untouched; "--no-key" counts as the same key as "--key".
  {
    std::unordered_map<std::string, size_t> first_pos;
    std::vector<std::string> deduped;
    deduped.reserve(args.size());
    for (const auto& a : args) {
      if (a.size() > 2 && a[0] == '-' && a[1] == '-') {
        const size_t eq = a.find('=');
        std::string key = a.substr(2, eq == std::string::npos ? std::string::npos : eq - 2);
        // (Hunt v1.4.6 ronda 18, A4-R18-02.) Only treat "--no-key" as the
        // same key as "--key" when it can BE a bool negation: a bare
        // "--no-key", or "--no-key=<bool literal>". The "--no-" form only
        // exists for bool flags (cvar.cpp registers "--key,!--no-key");
        // for a string/int key it is an unknown option CLI11 would stash
        // as an extra and ignore -- but the unconditional strip above
        // collapsed it onto the real key, so "--gpu_plugin=xenos" plus
        // "--no-gpu_plugin=turnip" kept ONLY the unknown form and
        // gpu_plugin was never set (verified against the vendored CLI11:
        // black screen). A value that is not a bool literal (a name, a
        // path, a multi-digit number) cannot be a flag value, so the
        // "--no-" form keeps its own key and passes through as a harmless
        // unknown instead of swallowing the real one.
        if (key.rfind("no-", 0) == 0 &&
            (eq == std::string::npos || IsBoolLiteral(a.substr(eq + 1)))) {
          key.erase(0, 3);
        }
        if (key.empty()) {
          deduped.emplace_back(a);
          continue;
        }
        auto it = first_pos.find(key);
        if (it == first_pos.end()) {
          first_pos.emplace(key, deduped.size());
          deduped.emplace_back(a);
        } else {
          // Same value twice (the normal case: the mobile default and
          // settings.txt agree) is silent; only a real override warns.
          if (deduped[it->second] != a) {
            ALOGW("android_main: duplicate cvar arg '%s' dropped, keeping '%s'",
                  deduped[it->second].c_str(), a.c_str());
          }
          deduped[it->second] = a;
        }
      } else {
        deduped.emplace_back(a);
      }
    }
    args.swap(deduped);
  }

  std::vector<char*> argv_ptrs;
  argv_ptrs.reserve(args.size());
  for (auto& arg : args) argv_ptrs.push_back(arg.data());

  auto remaining = rex::cvar::Init(static_cast<int>(argv_ptrs.size()), argv_ptrs.data());
  rex::cvar::ApplyEnvironment();
  rex::InitLoggingEarly();

  // (Hunt v1.4.6, R-A-M4.) cvar::Init returns the arguments it did NOT
  // consume: positionals. argv[0] (the app name) is expected; anything
  // else is not a setting and was silently dropped before.
  for (const auto& arg : remaining) {
    if (arg == kAppIdentifier) continue;
    REXLOG_WARN("android_main: ignoring unexpected positional argument '{}' "
                "(settings.txt lines must be key=value)",
                arg);
  }

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
      // (Hunt v1.4.6, R-A-M4.) The runtime exists now, so every cvar the
      // game can ever set is registered: a settings.txt key still unknown
      // here is a typo (or a hand-added line for a module that never
      // loads), and the player finally hears about it in childoflight.log.
      LogUnknownSettingsCvars(settings_args);
      // (Hunt v1.4.6 ronda 19, A4-R19-03.) Same point, same argument: a
      // key can be known and its value still silently wrong (a bool typo
      // applied as false, an int the setter dropped, a negative cache
      // limit that wraps to ~4 GiB). Warnings only.
      LogSuspiciousSettingsValues(settings_args);
      // (Hunt v1.4.6 ronda 23, A4-R23-02.) Same point, same argument,
      // for the env.* lines: an env.REX_* value that maps to a cvar
      // reaches it through ApplyEnvironment, unvalidated, and the two
      // checks above never see it.
      LogSuspiciousEnvValues(env_set);
      // (Hunt v1.4.6 ronda 16, A4-R16-01.) Record the preset outcome in
      // childoflight.log: the per-line "setting:" log in RunAndroidApp
      // only goes to logcat (ALOGI), so a pasted childoflight.log never
      // showed whether settings.txt was even read, let alone which
      // present mode the preset selected. At this point the runtime
      // exists, so the present-mode cvars are registered and REXCVAR_GET
      // reads the effective values (settings.txt wins over the mobile
      // defaults: its lines were appended after them, and same-source
      // re-apply is last-wins). A missing/empty file boots on SDK
      // defaults, which on Mali selects MAILBOX -- say so loudly
      // instead of silently.
      // (Hunt v1.4.6 ronda 17, A4-R17-03.) A file with only env.* lines
      // is NOT missing/empty: its lines were consumed (setenv) above.
      // Only warn when nothing at all came out of settings.txt.
      if (settings_args.empty() && env_lines == 0) {
        REXLOG_WARN("settings.txt: missing or empty under {} -- running on "
                    "SDK defaults (all present modes allowed; on Mali this "
                    "selects MAILBOX)",
                    external_dir);
      } else {
        REXLOG_INFO("settings.txt: {} cvar lines + {} env lines applied from {}; effective "
                    "present modes: immediate={} mailbox={} fifo_relaxed={}",
                    settings_args.size(), env_lines, external_dir,
                    REXCVAR_GET(vulkan_allow_present_mode_immediate),
                    REXCVAR_GET(vulkan_allow_present_mode_mailbox),
                    REXCVAR_GET(vulkan_allow_present_mode_fifo_relaxed));
      }
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

// --- pause/resume from the Android lifecycle (hunt v1.4.6, A4-R6-01) ------
// MainActivity.onPause/onResume (and onStop/onStart in multi-window) call
// these via JNI. They reach the runtime through the global
// Runtime::instance() (set in Runtime::Setup, cleared in ~Runtime): null
// before OnInitialize / after teardown, in which case nothing is running
// yet and this is a no-op. Pause()/Resume() are virtual no-ops on the
// IAudioSystem/IGraphicsSystem interfaces, so this compiles against the
// interfaces with no link dependency on the concrete systems (SDL audio
// driver, GPU plugin).
// Ordering: pause graphics first (command processor + vblank), then audio;
// resume in the reverse order. Each Pause() waits on its worker with a
// BOUNDED fence (A4-R3-02): CommandProcessor::Pause and AudioSystem::Pause
// wait at most 1000 ms each, XmaDecoder::Pause another 1000 ms, so a pause
// on the UI thread costs ~3 s worst case, sequential, when every worker is
// stuck inside a guest callback / FFmpeg decode — and each timeout leaves
// paused_ set, so the worker parks late and Resume() unparks it. That is
// under Android's 5 s input-dispatch ANR threshold (and a Home press
// dispatches no input event to the app at all), so the unbounded onPause
// hang this comment used to warn about is gone: it was closed by the R3/R4
// bounds, not by moving the pause off the UI thread (which would leave the
// guest running in the background — worse). The one live unbounded
// UI-thread block of this class was the Reset delete in PadSettingsDialog,
// fixed in ronda 26 (A4-R26-03).
// (Hunt v1.4.6 ronda 26, A4-R26-04 — cierra el diferido ANR-on-pause.)
extern "C" {

JNIEXPORT void JNICALL
Java_com_rexauto_port_MainActivity_nativePauseEmulation(JNIEnv* /*env*/, jclass /*clazz*/) {
  rex::Runtime* runtime = rex::Runtime::instance();
  if (!runtime) return;
  if (auto* graphics_system = runtime->graphics_system()) graphics_system->Pause();
  if (auto* audio_system = runtime->audio_system()) audio_system->Pause();
}

JNIEXPORT void JNICALL
Java_com_rexauto_port_MainActivity_nativeResumeEmulation(JNIEnv* /*env*/, jclass /*clazz*/) {
  rex::Runtime* runtime = rex::Runtime::instance();
  if (!runtime) return;
  if (auto* audio_system = runtime->audio_system()) audio_system->Resume();
  if (auto* graphics_system = runtime->graphics_system()) graphics_system->Resume();
}

// (Hunt v1.4.6 ronda 23, A4-R23-01.) Audio-focus ducking, from
// MainActivity (see requestAudioFocus() there). The SDL audio callback
// snapshots rex::audio::GetOutputGain() once per frame
// (sdl_audio_driver.cpp), so this takes effect on the next callback
// with no thread, lock or lifecycle involved; the gain is a
// mutex-guarded global, safe to set before the audio system exists and
// after it is gone. 0.2 linear is ~-14 dB, the usual ducking depth;
// 1.0 is unity. There is no volume API on IAudioSystem, so this JNI
// is the only ducking path.
JNIEXPORT void JNICALL
Java_com_rexauto_port_MainActivity_nativeSetAudioDucked(JNIEnv* /*env*/, jclass /*clazz*/,
                                                        jboolean ducked) {
  rex::audio::SetOutputGain(ducked ? 0.2f : 1.0f);
}

}  // extern "C"

int main(int argc, char* argv[]) {
  (void)argc;
  (void)argv;
  return RunAndroidApp();
}

#endif  // REX_PLATFORM_ANDROID
