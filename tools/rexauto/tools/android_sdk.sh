#!/bin/bash
# android_sdk.sh -- clone ReXGlue SDK v0.10.0 (the upstream tag the Android
# patches were written against), init submodules, apply the Android patch set
# from hells-gate-recomp-android (deivid22srk), stage SDL3's Java glue.
#
#   tools/android_sdk.sh [dest=android/sdk/rexglue-sdk]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK_DIR="${1:-$ROOT/android/sdk/rexglue-sdk}"
SDK_REPO="https://github.com/rexglue/rexglue-sdk.git"
SDK_TAG="v0.10.0"
PATCHES="$ROOT/android/patches"

if [ -f "$SDK_DIR/.patches-applied" ]; then
  echo "[android_sdk] SDK already set up at $SDK_DIR"
else
  rm -rf "$SDK_DIR"; mkdir -p "$(dirname "$SDK_DIR")"
  echo "[android_sdk] cloning $SDK_REPO@$SDK_TAG"
  git clone --depth 1 --branch "$SDK_TAG" "$SDK_REPO" "$SDK_DIR"
  git -C "$SDK_DIR" submodule update --init --depth 1
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
  git -C "$AT_DIR" fetch -q --depth 1 origin "$AT_REV"
  git -C "$AT_DIR" checkout -q FETCH_HEAD
  mkdir -p "$AT_DIR/lib"
  git init -q "$AT_DIR/lib/linkernsbypass"
  git -C "$AT_DIR/lib/linkernsbypass" remote add origin https://github.com/bylaws/liblinkernsbypass.git
  git -C "$AT_DIR/lib/linkernsbypass" fetch -q --depth 1 origin "$LNB_REV"
  git -C "$AT_DIR/lib/linkernsbypass" checkout -q FETCH_HEAD
  echo "[android_sdk] libadrenotools -> $AT_DIR"
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
if [ ! -f "$AT_DIR/.hook-fallback-applied" ]; then
  git -C "$AT_DIR" apply "$PATCHES/libadrenotools-8fae8ce-hook-fallback.patch"
  touch "$AT_DIR/.hook-fallback-applied"
fi

SDL_JAVA_SRC="$SDK_DIR/thirdparty/sdl3/android-project/app/src/main/java/org/libsdl/app"
SDL_JAVA_DST="$ROOT/android/app/src/main/java/org/libsdl/app"
mkdir -p "$SDL_JAVA_DST"
cp "$SDL_JAVA_SRC"/*.java "$SDL_JAVA_DST/"
echo "[android_sdk] SDL3 Java glue -> $SDL_JAVA_DST"
echo "[android_sdk] done"
