cmake_minimum_required(VERSION 3.25)
project(rexauto_android LANGUAGES C CXX ASM)

# NOTE: local builds on a low-RAM machine can serialize compiles with
# -DCMAKE_JOB_POOL_COMPILE=... / -DCMAKE_JOB_POOL_LINK=... on the command
# line. Do NOT hardcode job pools here: CI runners have their own
# parallelism and the recompiled code is huge.

# Handed over from Gradle (-D... in build.gradle.kts), with fallbacks for a
# direct CMake invocation.
set(REX_PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../.." CACHE PATH "rexauto checkout")  # (Ronda 9, auditor F - R9-F5.) ../../../.. es .../android, no el checkout rexauto: REXSDK_DIR quedaba en .../android/android/sdk/... y el FATAL_ERROR saltaba con el SDK instalado. Gradle siempre pasa -D, asi que solo pica en un cmake directo.
set(REXSDK_DIR "${REX_PROJECT_ROOT}/android/sdk/rexglue-sdk" CACHE PATH "patched ReXGlue SDK tree")
set(REX_PORT_DIR "" CACHE PATH "rexauto port dir (autoports/<name>/port)")
set(REX_APP_NAME "game" CACHE STRING "rexglue project name")

if(NOT EXISTS "${REXSDK_DIR}/CMakeLists.txt")
    # (Ronda 5, auditor F — R5-F8.) El mensaje apuntaba a tools/android_sdk.sh,
# que no existe en la raiz del repo: el script vive en tools/rexauto/tools/.
message(FATAL_ERROR "ReXGlue SDK not found at ${REXSDK_DIR} - run tools/rexauto/tools/android_sdk.sh first (from the repo root)")
endif()
if(NOT EXISTS "${REX_PORT_DIR}/generated/default/sources.cmake")
    message(FATAL_ERROR "no generated code at ${REX_PORT_DIR}/generated/default - run the desktop pipeline (rexauto.py --until build) first")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(REXGLUE_ENABLE_TRACY OFF CACHE BOOL "" FORCE)
set(REXGLUE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(REXGLUE_USE_VULKAN ON CACHE BOOL "" FORCE)
set(REXGLUE_USE_D3D12 OFF CACHE BOOL "" FORCE)

# --- mobile performance flags --------------------------------------------------
# Applied to everything below (SDK runtime, GPU plugin, recompiled code):
#   * -O3 + thin LTO across the runtime; the SDK adds -O3 itself for Release,
#     repeated here so the flag also reaches Gradle-injected configs.
#   * ARMv8.2-A + fp16/dotprod: every 64-bit Android SoC since ~2018 (Snapdragon
#     660+, Exynos 9810+, Kirin 970+, Dimensity/Helio G) has it; the hot loops
#     (byte-swapping guest memory, vector ops emitted for VMX128) benefit.
#     Gated by REX_ANDROID_BASELINE_ARM=1 to fall back to plain armv8-a.
#   * -fno-plt / -fomit-frame-pointer: fewer indirections per call. The
#     recompiled code is millions of small functions calling through the
#     dispatcher; per-call overhead is the CPU bottleneck on phones.
#   * -fno-semantic-interposition / hidden visibility: lets LTO inline across
#     the runtime library instead of going through the GOT.
#   * -fstack-protector-strong for the runtime / GPU plugin / app code: the
#     native tree executes guest-controlled data (round-4 hunt), so the
#     hardening stays ON there. Only the generated recompiled code opts
#     OUT below (target_compile_options(recomp ...)): millions of tiny
#     functions is where the win actually is. (A5-R4-13: the old global
#     -fno-stack-protector turned the protector off for the whole tree;
#     Gradle's base flags already carry -fstack-protector-strong -- proven
#     in the .cxx configure reply -- and the last flag wins, so recomp's
#     PRIVATE -fno-stack-protector still disables it for that target
#     only. Verified with the NDK 27.2 clang: strong, then -fno-... on the
#     same command line, leaves no __stack_chk_fail reference.)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
  add_compile_options(-O3 -DNDEBUG -fomit-frame-pointer -fno-plt
                      -fno-semantic-interposition -fmerge-all-constants
                      -fstack-protector-strong)
  # Keep the unwind tables: the in-app crash reporter (_Unwind_Backtrace
  # + dladdr in android_main.cpp) cannot produce backtraces without them.
  if(NOT DEFINED ENV{REX_ANDROID_BASELINE_ARM})
    add_compile_options(-march=armv8.2-a+fp16+dotprod -mtune=cortex-a76)
  endif()
  add_link_options(-Wl,-O2 -Wl,--gc-sections -Wl,--icf=all -Wl,--as-needed -Wl,-z,now)
  # (Hunt v1.4.6, ronda 10, A5-R10-01.) 16 KB page-size alignment: NDK r27
  # (pinned in app/build.gradle.kts:35) aligns PT_LOAD to 4 KB by default,
  # so on a 16 KB-page device the dynamic loader rejects every .so built
  # here. NDK r28+ aligns to 16 KB by default, but the NDK is pinned in
  # TWO places (build.gradle.kts + the workflow's sdkmanager install) and
  # r28 changes defaults beyond page size, so the surgical fix is the
  # official r27-and-lower linker flags (developer.android.com/guide/
  # practices/page-sizes). These are directory link options, set BEFORE
  # the add_subdirectory() calls below, so they reach every native target
  # in this tree: rexruntime + rexgpu-xenos (rexglue-sdk), libadrenotools
  # + the 4 hook libs (libadrenotools), and libmain. The prebuilt
  # libc++_shared.so already has p_align 0x4000 and needs nothing.
  # Verified by the FULL script + CI "Verify APK" 16 KB gates (readelf).
  add_link_options(-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384)
  # (Hunt v1.4.6, ronda 10, A5-R10-08.) Remap the absolute checkout path
  # out of __FILE__: the release .so carried 162 "/home/hatch/workspace/
  # col-recomp/..." strings (log/assert __FILE__, no .debug_* sections).
  # -ffile-prefix-map (not -fdebug-prefix-map, which only remaps debug
  # info) rewrites __FILE__ too. The mapped prefix is the checkout root,
  # computed from REX_PROJECT_ROOT (tools/rexauto, handed over by Gradle)
  # so it works on any builder machine, not just this one; __FILE__
  # becomes a repo-relative path (e.g. tools/rexauto/android/sdk/...).
  # Same directory-scope rule as above: set before add_subdirectory().
  get_filename_component(REX_CHECKOUT_ROOT "${REX_PROJECT_ROOT}/../.." ABSOLUTE)
  add_compile_options("-ffile-prefix-map=${REX_CHECKOUT_ROOT}=.")
endif()

add_subdirectory("${REXSDK_DIR}" rexglue-sdk)

# --- libadrenotools: custom Turnip/Adreno Vulkan driver loader ---------------
# Ships as libadrenotools.so + its hook libs (libmain_hook.so, libhook_impl.so,
# libfile_redirect_hook.so, libgsl_alloc_hook.so); android_main.cpp dlopen()s
# the driver through it when the launcher has one configured.
set(ADRENOTOOLS_DIR "${REXSDK_DIR}/../libadrenotools" CACHE PATH "libadrenotools checkout")
if(EXISTS "${ADRENOTOOLS_DIR}/CMakeLists.txt")
    set(BUILD_SHARED_LIBS ON)
    add_subdirectory("${ADRENOTOOLS_DIR}" adrenotools)
    set(REX_HAVE_ADRENOTOOLS ON)
else()
    message(WARNING "libadrenotools not found at ${ADRENOTOOLS_DIR} - custom GPU drivers disabled")
endif()

# --- recompiled guest code (from the desktop rexauto pipeline) ---------------
set(REX_GEN_DIR "${REX_PORT_DIR}/generated/default")
include("${REX_GEN_DIR}/sources.cmake")
set(REX_GEN_SOURCES "")
foreach(src ${GENERATED_SOURCES})
    if(IS_ABSOLUTE "${src}")
        list(APPEND REX_GEN_SOURCES "${src}")
    else()
        list(APPEND REX_GEN_SOURCES "${REX_GEN_DIR}/${src}")
    endif()
endforeach()

add_library(recomp STATIC ${REX_GEN_SOURCES})
target_include_directories(recomp PRIVATE "${REX_PORT_DIR}" "${REX_PORT_DIR}/src" "${REX_GEN_DIR}")
target_precompile_headers(recomp PRIVATE "${REX_GEN_DIR}/${REX_APP_NAME}_pch.h")
# The generated PPC->C++ is enormous (hundreds of MB of source): strip debug
# info entirely, keep -O3. (No -fno-exceptions: REX_UNIMPLEMENTED in the
# generated PCH throws.) No RTTI: nothing in it uses dynamic_cast/typeid.
target_compile_options(recomp PRIVATE
    -g0 -O3
    -fno-stack-protector  # (A5-R4-13.) Perf opt-out scoped to the generated
                          # code only: millions of small functions calling
                          # through the dispatcher. The runtime / GPU plugin
                          # / app code keeps -fstack-protector-strong (above).
    -fno-rtti
    -fno-math-errno -fno-trapping-math
    -Wno-unused-variable -Wno-unused-label -Wno-unused-but-set-variable
    -Wno-unused-value -Wno-parentheses-equality)
# Data-section relocation pressure: the register/init tables are huge.
set_target_properties(recomp PROPERTIES INTERPROCEDURAL_OPTIMIZATION OFF)
target_link_libraries(recomp PUBLIC rex::runtime rexui)

# --- app library loaded by SDLActivity ----------------------------------------
add_library(main SHARED
    android_gamepad.cpp
    android_main.cpp
    stfs_asset_jni.cpp
    # M1 v1.4.2: the port src/main.cpp is NOT used here. It registers
    # ChildoflightApp, which has no ReXApp hooks; col_main.cpp registers
    # ColDlcApp instead (same "childoflight" identifier), whose OnPostSetup
    # installs the DLC packages. Keeping the registration in this tracked
    # tree also means a future `rexglue init` regenerating the port
    # directory cannot drop the hook.
    col_main.cpp
    col_dlc_installer.cpp
    "${REXSDK_DIR}/src/ui/rex_app.cpp"
)
target_include_directories(main PRIVATE
    "${REX_PORT_DIR}" "${REX_PORT_DIR}/src" "${REX_GEN_DIR}"
    "${REXSDK_DIR}/include" "${REXSDK_DIR}/src/ui")
target_compile_options(main PRIVATE -Wno-unused-variable)
target_compile_definitions(main PRIVATE
    REXGLUE_BUILD_CONFIG="$<CONFIG>"
    REX_APP_NAME="${REX_APP_NAME}")
target_link_libraries(main PRIVATE recomp rex::runtime rexui)
if(REX_HAVE_ADRENOTOOLS)
    target_compile_definitions(main PRIVATE REX_HAVE_ADRENOTOOLS=1)
    target_link_libraries(main PRIVATE adrenotools)
    add_dependencies(main main_hook file_redirect_hook gsl_alloc_hook hook_impl)
endif()
target_link_options(main PRIVATE -Wl,--export-dynamic)
add_dependencies(main rexgpu-xenos)
set_target_properties(main PROPERTIES CXX_VISIBILITY_PRESET default VISIBILITY_INLINES_HIDDEN OFF)
