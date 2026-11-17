// App subclass that installs DLC packages after the runtime is ready
// (M1, v1.4.2).
//
// The generated port app (autoports/childoflight/port/src/childoflight_app.h)
// has no ReXApp hooks at all, so there is no place to run post-setup work.
// This subclass adds the one hook the port needs: OnPostSetup runs the DLC
// installer (col_dlc_installer) once the kernel state and content manager
// exist, before the game starts. It keeps ChildoflightApp as its base so
// any behaviour the generated app gains later is inherited.
//
// Registration lives in col_main.cpp (REX_DEFINE_APP), compiled into the
// `main` lib instead of the port's src/main.cpp, so a future `rexglue init`
// regenerating the port directory cannot drop the hook.

#pragma once

#include <exception>
#include <memory>

#include <rex/logging.h>

// The generated childoflight_app.h uses PPCImageConfig (declared extern in
// the generated PCH, via childoflight_init.h) but includes neither header
// itself: the generated src/main.cpp provides it by including the init header
// first. Our col_main.cpp bypasses that main.cpp, so include it here, before
// the app header, or this TU fails with "use of undeclared identifier
// 'PPCImageConfig'" (run #1, APK job, Gradle assembleRelease). The init header
// lives in generated/default/, which CMake adds to this target's includes.
#include "childoflight_init.h"
#include "childoflight_app.h"
#include "col_dlc_installer.h"

class ColDlcApp : public ChildoflightApp {
 public:
  using ChildoflightApp::ChildoflightApp;

  // NOTE: the return type must be unique_ptr<WindowedApp> (the Creator
  // type), exactly like ChildoflightApp::Create — NOT unique_ptr<ColDlcApp>.
  // A function returning unique_ptr<Derived> does NOT convert to a function
  // pointer returning unique_ptr<Base>, so REX_DEFINE_APP rejects it
  // ("no matching constructor for CreatorRegistration"). The inner
  // unique_ptr<ColDlcApp> converts to unique_ptr<WindowedApp> on return.
  static std::unique_ptr<rex::ui::WindowedApp> Create(
      rex::ui::WindowedAppContext& ctx) {
    return std::unique_ptr<ColDlcApp>(
        new ColDlcApp(ctx, "childoflight", PPCImageConfig));
  }

 protected:
  void OnPostSetup() override {
    // Hunt 4 P1-1: the DLC scan must never kill the app at startup. The
    // scan itself uses error_code overloads, but any future throw here
    // would reach std::terminate (android_main.cpp) and abort before the
    // game boots, so catch and continue without DLCs instead.
    try {
      col_dlc::InstallDlcPackages(runtime());
    } catch (const std::exception& e) {
      REXLOG_ERROR("DLC install failed (continuing without DLCs): {}", e.what());
    } catch (...) {
      REXLOG_ERROR("DLC install failed with an unknown exception (continuing without DLCs)");
    }
  }
};
