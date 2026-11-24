#!/bin/bash
# android_sdk.sh -- clone ReXGlue SDK v0.10.0 (the upstream tag the Android
# patches were written against), init submodules, apply the Android patch set
# from hells-gate-recomp-android (deivid22srk), stage SDL3's Java glue.
#
#   tools/android_sdk.sh [dest=android/sdk/rexglue-sdk]
#
# (A5-R4-03, ronda 4.) SDK_TAG is a MUTABLE tag: pin the exact commit
# below (SDK_COMMIT, resolved with `git ls-remote` 2026-11-20) and assert
# after the clone that HEAD equals it, so a moved/deleted tag can never
# change the build silently. The workflow SDK-cache key hashes this file,
# so changing the pin invalidates the cache automatically.
# (A5-R4-04, ronda 4.) Known, accepted skew: the desktop codegen runs the
# 0.10.1 repack bundle while this runtime builds from 0.10.0 + patches.
# Do NOT bump SDK_TAG to 0.10.1: the patches were written against 0.10.0.
# A workflow gate fails the run if major.minor ever diverge.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK_DIR="${1:-$ROOT/android/sdk/rexglue-sdk}"
SDK_REPO="https://github.com/rexglue/rexglue-sdk.git"
SDK_TAG="v0.10.0"
SDK_COMMIT="f5337cdc947ff6d4c4196737e2c807a48f2a1fc2"
PATCHES="$ROOT/android/patches"

# (A5-R4-03.) Retry helper for network commands: transient failures used
# to kill the run with no retry, unlike the apt/sdkmanager steps in the
# workflow, which all retry 3x. Returns 1 after $1 attempts (set -e kills
# the script at the call site); the guarded `if` keeps set -e from firing
# inside the helper itself.
retry() { # retry <attempts> <delay-seconds> <command...>
  local _attempts="$1" _delay="$2" _i=1
  shift 2
  while true; do
    if "$@"; then return 0; fi
    if [ "$_i" -ge "$_attempts" ]; then
      echo "[android_sdk] ERROR: command failed after $_attempts attempts: $*" >&2
      return 1
    fi
    echo "[android_sdk] WARNING: attempt $_i failed, retrying in ${_delay}s: $*"
    _i=$((_i + 1))
    sleep "$_delay"
  done
}

if [ -f "$SDK_DIR/.patches-applied" ]; then
  echo "[android_sdk] SDK already set up at $SDK_DIR"
  # (A5-R7-07, ronda 7.) Re-validate on re-execution: the marker used to
  # short-circuit this whole block, so a hand-modified SDK tree, a stale
  # patch set, or a moved tag was accepted silently. The pin assertion
  # below mirrors the fresh-clone check below. A missing SDK dir or a
  # non-git checkout fails here instead of being accepted.
  _sdk_head="$(git -C "$SDK_DIR" rev-parse HEAD 2>/dev/null)" || { echo "[android_sdk] ERROR: $SDK_DIR is not a git checkout (or is missing) -- remove it and re-run to rebuild from the pinned tag"; exit 1; }
  [ "$_sdk_head" = "$SDK_COMMIT" ] || { echo "[android_sdk] ERROR: SDK at $SDK_DIR is $_sdk_head, expected pinned commit $SDK_COMMIT (tag moved, or tree modified?) -- remove $SDK_DIR and re-run"; exit 1; }
  echo "[android_sdk] SDK commit OK (re-validated): $_sdk_head"
  # (A5-R8-07, ronda 8.) Re-validate the TREE, not just HEAD: a deleted
  # file or a deleted submodule still has HEAD == SDK_COMMIT and used to
  # pass. Deleted tracked files fail loudly (neither the patches nor the
  # repo overlay ever delete SDK files). Submodules must be initialized
  # AND at the indexed rev (`git submodule status` prefixes `-` for a
  # missing/uninitialized one, `+` for a wrong rev and `U` for a merge
  # conflict); if
  # thirdparty/sdl3 is gone the SDL glue copy below dies, but other
  # submodules would only fail later in CMake.
  # DELIBERATELY NOT checked here: a plain `git diff --quiet` / full
  # reverse-check of the patch set. The tree legitimately differs from
  # HEAD far beyond the patches (the repo overlay edits 183 files; the
  # 11 patches touch 22, and 5 of the 11 fail `--check --reverse` on the
  # legitimate overlaid tree), so a hand edit to a patch-touched file
  # cannot be told apart from an overlay edit in this script -- that
  # case stays covered by the CI cache key (which hashes this file +
  # the patches) and the M-5 guard in the workflow.
  # (A5-R9-04, ronda 9.) `diff HEAD` (not bare `diff`): a staged deletion
  # (`git rm`) compares equal against the INDEX and used to pass; against
  # HEAD it is listed. `--diff-filter=D` only ever lists deletions, so
  # the 185 overlay-modified files (`M`, verified on the local tree) are
  # unaffected. The submodule grep also takes `U` (merge conflict).
  _sdk_deleted="$(git -C "$SDK_DIR" diff HEAD --name-only --diff-filter=D 2>/dev/null)"
  [ -z "$_sdk_deleted" ] || { echo "[android_sdk] ERROR: SDK tree at $SDK_DIR has deleted files (e.g. $(echo "$_sdk_deleted" | head -3 | tr '\n' ' ')) -- remove $SDK_DIR and re-run to rebuild from the pinned tag"; exit 1; }
  _sdk_sub_status="$(git -C "$SDK_DIR" submodule status 2>/dev/null)" || { echo "[android_sdk] ERROR: cannot list SDK submodules at $SDK_DIR (git submodule status failed) -- remove $SDK_DIR and re-run to re-clone and re-init submodules"; exit 1; }
  _sdk_sub_bad="$(echo "$_sdk_sub_status" | grep -E '^[-+U]' || true)"
  [ -z "$_sdk_sub_bad" ] || { echo "[android_sdk] ERROR: SDK submodules missing or at the wrong rev at $SDK_DIR (e.g. $(echo "$_sdk_sub_bad" | head -3 | tr '\n' ' ')) -- remove $SDK_DIR and re-run to re-clone and re-init submodules"; exit 1; }
  echo "[android_sdk] SDK tree OK (re-validated): no deleted files, submodules initialized at the indexed revs"
else
  rm -rf "$SDK_DIR"; mkdir -p "$(dirname "$SDK_DIR")"
  echo "[android_sdk] cloning $SDK_REPO@$SDK_TAG ($SDK_COMMIT)"
  # (A5-R4-03.) The clone is retried (a partial clone is wiped before
  # each attempt: git refuses to clone into a non-empty directory).
  _cloned=0
  for _attempt in 1 2 3; do
    rm -rf "$SDK_DIR"
    if git clone --depth 1 --branch "$SDK_TAG" "$SDK_REPO" "$SDK_DIR"; then _cloned=1; break; fi
    echo "[android_sdk] WARNING: clone attempt $_attempt failed, retrying in 30s..."
    if [ "$_attempt" -lt 3 ]; then sleep 30; fi
  done
  [ "$_cloned" = "1" ] || { echo "[android_sdk] ERROR: git clone failed after 3 attempts"; exit 1; }
  # (A5-R4-03.) Pin check: the tag must still point at SDK_COMMIT.
  _sdk_head="$(git -C "$SDK_DIR" rev-parse HEAD)"
  [ "$_sdk_head" = "$SDK_COMMIT" ] || { echo "[android_sdk] ERROR: SDK tag $SDK_TAG resolved to $_sdk_head, expected pinned commit $SDK_COMMIT (tag moved?)"; exit 1; }
  echo "[android_sdk] SDK commit OK: $_sdk_head"
  retry 3 30 git -C "$SDK_DIR" submodule update --init --depth 1
  for p in rexglue-sdk-v0.10.0.patch rexglue-sdk-v0.10.0-android.patch rexglue-sdk-v0.10.0-android-perf.patch rexglue-sdk-v0.10.0-tolerant-dispatch.patch rexglue-sdk-v0.10.0-android-custom-vulkan.patch rexglue-sdk-v0.10.0-fps-cap.patch rexglue-sdk-v0.10.0-android-quiet.patch rexglue-sdk-v0.10.0-signal-chain.patch rexglue-sdk-v0.10.0-join-once.patch rexglue-sdk-v0.10.0-mali-vertex-stores.patch rexglue-sdk-v0.10.0-dlc-extract-errors.patch; do
    echo "[android_sdk] applying $p"
    git -C "$SDK_DIR" apply "$PATCHES/$p"
  done
  touch "$SDK_DIR/.patches-applied"
fi

# libadrenotools (BSD-2): loads a user-supplied Turnip / Adreno driver on
# Qualcomm phones. Pinned commits; built as part of the app's CMake project.
AT_DIR="$(dirname "$SDK_DIR")/libadrenotools"
AT_REV="8fae8ce254dfc1344527e05301e43f37dea2df80"
LNB_REV="aa3975893d83ef1bc84c321ec60c65fbf1287887"
if [ ! -f "$AT_DIR/CMakeLists.txt" ]; then
  # (J-9.) Shallow-fetch the PINNED commits only: a plain `git clone
  # --depth 1` + `checkout $REV` would work today (both revs are HEAD,
  # verified 2026-11-19) but break on the next upstream commit, when the
  # pinned SHA is no longer the tip. `fetch --depth 1 origin <sha>`
  # downloads exactly that commit (GitHub allows fetching arbitrary SHAs).
  # Fallback if fetch-by-SHA ever fails: drop `--depth 1` (full clone).
  git init -q "$AT_DIR"
  git -C "$AT_DIR" remote add origin https://github.com/bylaws/libadrenotools.git
  retry 3 30 git -C "$AT_DIR" fetch -q --depth 1 origin "$AT_REV"
  git -C "$AT_DIR" checkout -q FETCH_HEAD
  mkdir -p "$AT_DIR/lib"
  git init -q "$AT_DIR/lib/linkernsbypass"
  git -C "$AT_DIR/lib/linkernsbypass" remote add origin https://github.com/bylaws/liblinkernsbypass.git
  retry 3 30 git -C "$AT_DIR/lib/linkernsbypass" fetch -q --depth 1 origin "$LNB_REV"
  git -C "$AT_DIR/lib/linkernsbypass" checkout -q FETCH_HEAD
  echo "[android_sdk] libadrenotools -> $AT_DIR"
else
  # (A5-R7-07, ronda 7.) Re-validate the pinned revs on re-execution:
  # an existing checkout at another rev used to be kept forever, with no
  # rev-parse assertion like the SDK pin above. AT_REV is the
  # libadrenotools checkout itself; LNB_REV is the nested
  # lib/linkernsbypass checkout. A missing or non-git checkout fails
  # clearly instead of being accepted silently.
  _at_head="$(git -C "$AT_DIR" rev-parse HEAD 2>/dev/null)" || { echo "[android_sdk] ERROR: $AT_DIR is not a git checkout (or is missing) -- remove it and re-run to re-clone the pinned revs"; exit 1; }
  [ "$_at_head" = "$AT_REV" ] || { echo "[android_sdk] ERROR: libadrenotools at $AT_DIR is $_at_head, expected pinned rev $AT_REV -- remove $AT_DIR and re-run"; exit 1; }
  _lnb_head="$(git -C "$AT_DIR/lib/linkernsbypass" rev-parse HEAD 2>/dev/null)" || { echo "[android_sdk] ERROR: $AT_DIR/lib/linkernsbypass is not a git checkout (or is missing) -- remove $AT_DIR and re-run"; exit 1; }
  [ "$_lnb_head" = "$LNB_REV" ] || { echo "[android_sdk] ERROR: linkernsbypass at $AT_DIR/lib/linkernsbypass is $_lnb_head, expected pinned rev $LNB_REV -- remove $AT_DIR and re-run"; exit 1; }
  echo "[android_sdk] libadrenotools revs OK (re-validated): $AT_REV / $LNB_REV"
fi

# (Ronda 8, auditor E — R8-E3.) libadrenotools upstream devuelve
# nullptr desde hook_android_dlopen_ext cuando libhook_impl.so no
# recarga (o su init_hook_param falta): vkCreateInstance falla y el
# juego sale en silencio en vez de caer al driver del sistema como
# hace cualquier otro fallo de esa funcion. El arreglo pertenece a
# upstream (bylaws/libadrenotools), pero el hook esta fijado en
# AT_REV y este repo ya lleva su propio set de parches, asi que un
# parche de dos lineas + este punto de aplicacion es la forma acotada
# de enviar el fallback. El parche solo toca los dos return nullptr
# de hook_android_dlopen_ext; el tercer nullptr (hook_android_load_
# sphal_library, sin extinfo para un fallback equivalente) se deja
# como esta, igual que en R6-E7.
# (A5-R8-07, ronda 8.) Re-validate the hook-fallback patch on every run,
# not just its marker: a reverted patch with the marker still present used
# to be accepted silently, and a deleted marker with the patch applied used
# to die in `git apply` with a confusing error. Three states, all handled:
# patch present -> touch the marker and continue; patch absent but
# applicable -> apply it now; neither -> loud error telling the user to
# remove $AT_DIR and re-run.
if git -C "$AT_DIR" apply --check --reverse "$PATCHES/libadrenotools-8fae8ce-hook-fallback.patch" 2>/dev/null; then
  touch "$AT_DIR/.hook-fallback-applied"
elif git -C "$AT_DIR" apply --check "$PATCHES/libadrenotools-8fae8ce-hook-fallback.patch" 2>/dev/null; then
  echo "[android_sdk] hook-fallback patch not applied, applying it now"
  git -C "$AT_DIR" apply "$PATCHES/libadrenotools-8fae8ce-hook-fallback.patch"
  touch "$AT_DIR/.hook-fallback-applied"
else
  echo "[android_sdk] ERROR: libadrenotools hook-fallback patch is neither applied nor applicable at $AT_DIR (tree modified?) -- remove $AT_DIR and re-run" >&2
  exit 1
fi

SDL_JAVA_SRC="$SDK_DIR/thirdparty/sdl3/android-project/app/src/main/java/org/libsdl/app"
SDL_JAVA_DST="$ROOT/android/app/src/main/java/org/libsdl/app"
mkdir -p "$SDL_JAVA_DST"
cp "$SDL_JAVA_SRC"/*.java "$SDL_JAVA_DST/"
echo "[android_sdk] SDL3 Java glue -> $SDL_JAVA_DST"
echo "[android_sdk] done"
