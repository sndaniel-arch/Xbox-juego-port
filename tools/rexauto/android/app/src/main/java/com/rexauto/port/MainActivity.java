package com.rexauto.port;

import android.app.AlertDialog;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.Toast;

import com.rexauto.port.gamepad.PadSettings;
import com.rexauto.port.gamepad.PadSettingsDialog;
import com.rexauto.port.gamepad.VirtualPadView;

import org.libsdl.app.SDLActivity;

/** SDL3 activity hosting the recompiled game (SDL is linked statically into libmain.so). */
public class MainActivity extends SDLActivity {
    private VirtualPadView mGamepad;
    private boolean mDeferSdlStart;

    // (Hunt v1.4.6 ronda 7, A4-R7-01.) True while the guest is paused by
    // one of the lifecycle/focus paths below. The native Pause()/Resume()
    // calls are idempotent on their own (see pauseEmulation()), but the
    // flag keeps the JNI crossing to one per transition: focus loss,
    // onPause and onStop can all fire for a single Home press, and
    // without it the pause would be issued three times.
    private boolean mEmulationPaused;

    // (Hunt v1.4.6 ronda 7, A4-R7-02.) Live instance of the exit-confirm
    // dialog, so a second gesture back while it is up does not stack
    // another one on top.
    private AlertDialog mExitConfirmDialog;

    // (Ronda 3, auditor E — mitigación de X-A-1.) While a crash-guard /
    // crash-report dialog is up, the SDL thread must not start behind it:
    // the native side deletes logs/crash.txt on launch (android_main.cpp)
    // and would create the Vulkan instance with the (possibly bad) custom
    // driver before the user can choose "Volver al sistema". See
    // resumeNativeThread() below for the mechanism.
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        // v1.4.1: super.onCreate() SIEMPRE primero. Antes el return temprano
        // (sin game_root.txt en instalacion limpia) salia sin llamar al
        // super y Android mataba la app con SuperNotCalledException en cada
        // toque al icono (log-v14.txt, 9 veces). SetupActivity escribe el
        // marcador asset:game.stfs y relanza; en la segunda entrada el root
        // ya es valido y se entra directo al juego.
        super.onCreate(savedInstanceState);
        if (!GameFiles.hasValidGameRoot(this)) {
            startActivity(new Intent(this, SetupActivity.class));
            finish();
            return;
        }
        // (Ronda 3, Auditor A, R3-A1.) Enforce the experimental switch HERE:
        // GraphicsSettings promises the custom driver "only loads when a zip
        // was imported AND selected AND this is on", but the native loader
        // (android_main.cpp LoadCustomVulkanDriver, called from RunAndroidApp)
        // reads driver.txt unconditionally -- it never consults the switch,
        // and asCvars() does not export it to settings.txt. Turning the
        // switch off in the graphics dialog therefore left a previously
        // selected PanVK/Turnip loading on the next launch: the kill-switch
        // did not switch anything off. Drop the selection (driver.txt +
        // pref, same as the crash guard's "Volver al sistema") while the
        // switch is off, before any dialog and before SDL can start (the SDL
        // thread only starts at RESUMED, after onCreate). The driver files
        // stay installed; re-enabling the switch just needs re-picking it
        // in the driver dialog. SetupActivity reaches here too (launchGame
        // starts MainActivity), so this one point covers both entry paths.
        if (!new GraphicsSettings(this).experimentalGpuDriver()) {
            try {
                GpuDriver gd = new GpuDriver(this);
                // (Hunt v1.4.6 ronda 3, A4-R3-10.) Also clear when only
                // driver.txt survives (selected() now falls back to the
                // file, and driverConfigExists() covers a corrupt file
                // whose slug cannot be read): the old selected()-only
                // guard skipped the clear and the custom driver kept
                // loading while the switch claimed it was off.
                if (gd.selected() != null || gd.driverConfigExists()) gd.select(null);
            } catch (Exception e) {
                // (Hunt v1.4.6, sweep of R-A-M1.) select(null) throws when
                // the driver.txt delete fails; swallowing it left the
                // custom driver loading on the next launch while the UI
                // claimed the system driver. Say so (and log it): the
                // game still starts, but the player knows the switch-off
                // did not take.
                Log.w("MainActivity", "could not clear selected GPU driver", e);
                Toast.makeText(this, getString(R.string.err_driver_disable,
                        e.getMessage() == null ? e.toString() : e.getMessage()),
                        Toast.LENGTH_LONG).show();
            }
        }
        // Driver crash guard first (E, ronda 2, fusion §7): if the last
        // run crashed with a custom GPU driver selected, offer the system
        // driver BEFORE the game starts -- before any Vulkan instance is
        // created. Then the generic crash report, then the game.
        // (Ronda 3, X-A-1:) while either dialog is up, defer the SDL
        // thread (mDeferSdlStart, see resumeNativeThread()).
        if (LogsDialog.showDriverCrashGuardIfAny(this, this::startAfterGuard)) {
            mDeferSdlStart = true;
            return;
        }
        startAfterGuard();
    }

    /** After the driver crash guard: the generic crash report, then the game. */
    private void startAfterGuard() {
        // Crash report first (G-P1, ronda 2): the only reader of
        // logs/crash.txt was SetupActivity.onCreate, which only runs when
        // the game root is INVALID -- so after a real in-game crash the
        // next launch came straight here, SDL started, and the native side
        // (RunAndroidApp) deleted crash.txt unread. The crash reporter --
        // the only no-adb diagnostic -- was dead in exactly the flow that
        // matters. Show it here instead: the SDL thread only starts at
        // RESUMED (SDLActivity starts SDLMain on the resume transition,
        // after surface + focus), so the report is still on disk at this
        // point and the game only starts once the dialog is dismissed.
        // Dismiss renames crash.txt -> crash.prev.txt (LogsDialog), so the
        // in-game Logs viewer still finds it afterwards.
        if (LogsDialog.showCrashReportIfAny(this, this::startGame)) {
            mDeferSdlStart = true;
            return;
        }
        startGame();
    }

    /** Everything that used to run inline in onCreate after the root check. */
    private void startGame() {
        // (Hunt v1.4.6 ronda 16, A4-R16-01.) Rewrite settings.txt from the
        // current prefs on EVERY boot, before the SDL thread can start:
        // MainActivity is the LAUNCHER (AndroidManifest.xml), so a normal
        // launch never goes through SetupActivity.launchGame(), and
        // settings.txt was only a snapshot rewritten when the graphics
        // dialog was OKed or the game was (re)installed. A snapshot that
        // predates the prefs (failed write, hand-deleted file) booted the
        // game on SDK defaults with no word to anyone -- on Mali that
        // silently selects MAILBOX (all present modes allowed, IMMEDIATE
        // not offered), which is exactly the mode 1 the R15 phone log
        // shows against a performance/balanced preset. The write is
        // atomic (tmp+rename, hand-added lines preserved), and a failure
        // here only logs: the game still starts, exactly like
        // launchGame(). BEFORE releaseDeferredSdlStart(): the SDL thread
        // (and the native settings.txt read) can start as soon as the
        // deferred flag is released.
        try {
            new GraphicsSettings(this).write(this);
        } catch (Exception e) {
            Log.w("MainActivity", "startGame: settings rewrite failed; running on the previous settings.txt", e);
        }
        releaseDeferredSdlStart();
        applyOrientation();
        // Ask the OS for the sustained (thermally stable) clock profile instead of
        // the burst-then-throttle default, and never dim while playing.
        android.view.Window w = getWindow();
        w.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        if (android.os.Build.VERSION.SDK_INT >= 24) w.setSustainedPerformanceMode(true);
        if (android.os.Build.VERSION.SDK_INT >= 31) {
            android.view.WindowManager.LayoutParams lp = w.getAttributes();
            lp.preferredRefreshRate = 0;
            w.setAttributes(lp);
        }
        if (PadSettings.get(this).enabled()) {
            mGamepad = VirtualPadView.install(this);
        }
    }

    /**
     * Mitigación de X-A-1 (ronda 3, auditor E): no dejar que el hilo SDL
     * arranque detrás del diálogo de crash-guard / reporte de crash.
     *
     * Por qué esto funciona — todo el arranque del hilo SDL pasa por UN
     * solo choke point, SDLActivity.handleNativeState() (public static):
     * su rama RESUMED solo crea el hilo si
     * {@code mSurface.mIsSurfaceReady && (mHasFocus || mHasMultiWindow)
     * && mIsResumedCalled} (SDLActivity.java:848). Y mIsResumedCalled
     * solo se pone a true en resumeNativeThread() (:516, protected), al
     * que llegan los TRES disparadores: onResume (:548), onStart en
     * multi-ventana (:566) y — indirectamente — onWindowFocusChanged y
     * SDLSurface.surfaceChanged, que llaman a handleNativeState() pero
     * no tocan el flag. Retener el flag mientras el diálogo está abierto
     * bloquea TODOS los caminos de arranque; al descartar el diálogo la
     * continuación llega a startGame() -> releaseDeferredSdlStart(), que
     * llama al resume real y el hilo arranca entonces (o más tarde, en
     * el siguiente surfaceChanged/focus, con el flag ya en true).
     *
     * Seguridad: no se toca ninguna API de SDL ni la máquina de estados
     * salvo registrar la intención (mNextNativeState = RESUMED, lo que
     * ya hace onWindowFocusChanged). Si no se muestra ningún diálogo, el
     * flag es false y el comportamiento es idéntico al actual. Si la
     * activity se pausa con el diálogo abierto, pauseNativeThread()
     * limpia el flag y el siguiente onResume vuelve a diferir (el flag
     * propio sigue en true hasta startGame()). El diálogo es cancelable
     * por defecto (atrás / toque fuera), así que onDismiss — y con él
     * la liberación — siempre llega; si el proceso muere con el diálogo
     * abierto, el próximo arranque vuelve a mostrar el guard con
     * crash.txt intacto, que es justo lo que se quiere. La rotación no
     * recrea la activity (manifest: configChanges con orientation y
     * screenOrientation sensorLandscape). En un proceso fresco tras un
     * crash mSDLThread es null, así que no hay reanudación que retener.
     */
    @Override
    protected void resumeNativeThread() {
        if (mDeferSdlStart) {
            mNextNativeState = NativeState.RESUMED;
            return;
        }
        super.resumeNativeThread();
    }

    private void releaseDeferredSdlStart() {
        if (!mDeferSdlStart) return;
        mDeferSdlStart = false;
        resumeNativeThread();
    }

    /** Orientation chosen in the launcher (Graphics dialog); landscape by default. */
    private void applyOrientation() {
        String o = new GraphicsSettings(this).orientation();
        int req;
        switch (o) {
            case "portrait": req = android.content.pm.ActivityInfo.SCREEN_ORIENTATION_PORTRAIT; break;
            case "auto": req = android.content.pm.ActivityInfo.SCREEN_ORIENTATION_FULL_USER; break;
            default: req = android.content.pm.ActivityInfo.SCREEN_ORIENTATION_SENSOR_LANDSCAPE;
        }
        setRequestedOrientation(req);
    }

    /**
     * SDL asks Java for an orientation on every window (re)creation, and with
     * its empty hint + resizable window it resolves to FULL_USER — which
     * follows the user's rotation lock instead of forcing landscape (v1.3
     * bug A: the first surface was born vertical and the title rendered
     * letterboxed). Neutralize it: apply the orientation the user chose in
     * the graphics settings (landscape by default) instead of SDL's request.
     * The native side sets the same choice via the SDL_ORIENTATIONS hint.
     */
    @Override
    public void setOrientationBis(int w, int h, boolean resizable, String hint) {
        applyOrientation();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        // GPU driver zip picked from the hidden in-game menu (GraphicsDialog).
        if (requestCode == GraphicsDialog.REQ_PICK_DRIVER && resultCode == RESULT_OK) {
            GraphicsDialog.onDriverPicked(this, data);
        }
    }

    @Override
    protected void onPause() {
        if (mGamepad != null) mGamepad.onHostPause();
        // (Hunt v1.4.6 ronda 7, A4-R7-01.) The !mHasMultiWindow gate is
        // gone: it is (SDK_INT >= 24) and minSdk is 28, so it was true on
        // every device and this pause never ran. Pause on every onPause.
        pauseEmulation();
        super.onPause();
    }

    /**
     * (Hunt v1.4.6 ronda 3, A4-R3-03, fixed in ronda 7 by A4-R7-01.)
     * Focus loss pauses the guest: pulling down the notification shade,
     * opening quick settings, a system dialog or the assistant takes
     * window focus without calling onStop, so the onPause/onStop paths
     * never fired and the game kept running with audio behind the shade.
     * The original A4-R3-03 split was gated on !mHasMultiWindow, but
     * mHasMultiWindow is (SDK_INT >= 24) and minSdk is 28 -- true on
     * every device that can install this APK -- so the gate made this
     * whole override dead code and the fix never paused anything.
     * Focus now pauses unconditionally, and the mEmulationPaused guard
     * in pauseEmulation()/resumeEmulation() absorbs the overlap with
     * onPause/onResume/onStop (Home, incoming call, screen-off fire
     * several of them for one event). An AlertDialog opened by the game
     * itself DOES take window focus from the activity (Android calls
     * onWindowFocusChanged even when the activity itself shows a dialog),
     * so opening an in-game menu (gear, graphics, logs, driver, exit
     * confirm) pauses the guest -- that is the wanted auto-pause, and
     * dismissing the menu resumes it via onWindowFocusChanged(true).
     * (Hunt v1.4.6 ronda 8, A4-R8-01.) The R7-01 text this paragraph
     * replaces claimed the opposite ("does NOT take window focus");
     * that was false and it hid the resume hole fixed in
     * onResume()/onStart(): they must not resume without focus.
     * SDL's own focus handling
     * (SDLActivity.onWindowFocusChanged) is untouched: the SDL thread
     * keeps pumping events while the guest (graphics + audio) is
     * parked, which is what the player experiences as paused.
     * Emulation goes first, then SDL's own handling, so the guest stops
     * before the SDL thread parks and resumes before it unparks.
     */
    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        if (hasFocus) resumeEmulation(); else pauseEmulation();
        super.onWindowFocusChanged(hasFocus);
    }

    @Override
    protected void onResume() {
        // (Hunt v1.4.6 ronda 3, A4-R3-09.) The old order resumed the SDL
        // thread (super.onResume) before the emulation, the reverse of
        // onPause: the guest CPU threads ran a window while the CP was
        // still suspended and vblank interrupts resumed. Resume the
        // emulation first, mirroring onPause.
        // (Hunt v1.4.6 ronda 7, A4-R7-01.) Same dead gate as onPause:
        // resume on every onResume.
        // (Hunt v1.4.6 ronda 8, A4-R8-01.) ... except without focus:
        // onResume fires BEFORE onWindowFocusChanged(true), so resuming
        // here unconditionally also resumed behind a dialog that was
        // still open (and still holding focus) when the activity came
        // back from Home / a call / the file picker -- the pause that
        // focus loss had applied was undone with no focus callback to
        // re-apply it. Only resume when the window already has focus
        // (or the activity is genuinely in multi-window, where the
        // unfocused pane is still visible and SDL keeps running); the
        // onWindowFocusChanged(true) callback resumes in the normal
        // case, so skipping here loses nothing.
        if (shouldResumeEmulation()) resumeEmulation();
        super.onResume();
    }

    @Override
    protected void onStop() {
        if (mHasMultiWindow) pauseEmulation();
        super.onStop();
    }

    @Override
    protected void onStart() {
        // (A4-R3-09, multi-window half.) Same reversal as onResume: the
        // emulation resumes before the SDL thread, mirroring onStop.
        // (Hunt v1.4.6 ronda 8, A4-R8-01.) Same focus gate as onResume:
        // onStart fires before any focus callback, so an unconditional
        // resume here also restarted the guest behind a still-open
        // dialog after an interruption.
        if (shouldResumeEmulation()) resumeEmulation();
        super.onStart();
    }

    /**
     * (Hunt v1.4.6 ronda 11, A4-R11-04.) Eager release of the in-game dialog statics: PadSettingsDialog (the R10-02 residual), GraphicsDialog and LogsDialog all keep a static reference to this activity, and the framework does not fire OnDismissListener when the activity is destroyed with a dialog open — so without this hook the dead activity survived until the next gear tap observed the stale state. onDestroy is the hook: every dialog here belongs to this activity, and the dismiss listeners no-op once the statics are null. SetupActivity needs no hook: the crash guard/report dialogs it shows are untracked (no statics).
     */
    @Override
    protected void onDestroy() {
        PadSettingsDialog.clearStale();
        GraphicsDialog.clearStale();
        LogsDialog.clearStale();
        super.onDestroy();
    }

    /**
     * (Hunt v1.4.6 ronda 8, A4-R8-01.) Whether onStart/onResume may
     * resume the guest. The window has focus in the normal return path
     * (and onWindowFocusChanged(true) resumes anyway right after, so
     * the gate costs nothing there); it does NOT have focus while a
     * dialog -- an in-game menu, the driver picker, the share chooser --
     * is still open over the activity, and resuming then would run the
     * game with audio behind a modal the player cannot dismiss by
     * playing. The multi-window half mirrors SDL's own resume
     * condition in handleNativeState() (SDLActivity.java:869,
     * {@code mHasFocus || mHasMultiWindow}): in split-screen the
     * unfocused pane is still visible, so the game keeps running.
     * Note the condition here is the real one -- isInMultiWindowMode()
     * -- not SDL's static mHasMultiWindow, which is just
     * (SDK_INT >= 24) and therefore true on every device this APK can
     * install on (minSdk 28): gating on it would make this whole check
     * a no-op. isInMultiWindowMode() needs API 24; minSdk is 28, so no
     * SDK guard is needed. hasWindowFocus() exists since API 1.
     */
    private boolean shouldResumeEmulation() {
        return hasWindowFocus() || isInMultiWindowMode();
    }

    /**
     * (Hunt v1.4.6, A4-R6-01.) Pause/resume the guest with the activity:
     * before this, Home / screen-off / switching apps left the game
     * running (audio included) in the background. The native side reaches
     * the runtime via Runtime::instance() and is a no-op before the
     * runtime exists (crash-guard dialogs, first launch). The native calls
     * are best-effort: a missing lib (mBrokenLibraries) must not crash
     * the lifecycle.
     * (Hunt v1.4.6 ronda 7, A4-R7-01.) The !mHasMultiWindow split the old
     * comment described is gone: the flag is (SDK_INT >= 24) and minSdk
     * is 28, so onPause/onResume used to never pause/resume and onStop
     * was the only real pause. Now onPause and focus loss pause
     * unconditionally, onStop/onStart keep their branches as a safety
     * net, and the overlap collapses to one native call via
     * mEmulationPaused. (Hunt v1.4.6 ronda 8, A4-R8-01.) The resumes
     * are NOT unconditional anymore: onResume/onStart only resume when
     * shouldResumeEmulation() says the window has focus or the activity
     * is genuinely in multi-window mode -- resuming without focus
     * restarted the guest behind a dialog that was still open. The
     * onWindowFocusChanged(true) callback is the resumer in the normal
     * path. Idempotence, verified in the SDK sources rather
     * than assumed: AudioSystem::Pause/Resume, CommandProcessor::
     * Pause/Resume and XmaDecoder::Pause/Resume all early-return on
     * their paused_ flag, and GraphicsSystem::Pause only delegates to
     * the (idempotent) command-processor pause. Deliberate asymmetry:
     * pause is guarded by the flag, resume is not -- resume always
     * reaches native code, so a pause that outlived its activity
     * instance (system killed the activity while paused, process
     * survived) self-heals on the next onStart instead of leaving the
     * guest parked forever under a fresh flag.
     */
    private static native void nativePauseEmulation();
    private static native void nativeResumeEmulation();

    private void pauseEmulation() {
        if (mEmulationPaused) return;
        mEmulationPaused = true;
        try { nativePauseEmulation(); } catch (Throwable t) { Log.w("MainActivity", "pause emulation failed", t); }
    }

    private void resumeEmulation() {
        // (A4-R7-01.) Deliberately unguarded: see the comment above.
        mEmulationPaused = false;
        try { nativeResumeEmulation(); } catch (Throwable t) { Log.w("MainActivity", "resume emulation failed", t); }
    }

    /**
     * (Hunt v1.4.6 ronda 7, A4-R7-02.) The Android gesture back (edge
     * swipe, the default navigation on Android 16) reaches here, while
     * the hardware back key never does: SDL's key dispatch consumes
     * KEYCODE_BACK (SDLActivity.java:1535-1541) and returns true, so it
     * never reaches the system. Before this, the gesture ran
     * SDLActivity.onBackPressed(), whose super.onBackPressed() finished
     * the activity and killed the game with no confirmation and no save
     * -- an accidental swipe mid-fight lost all unsaved progress. Ask
     * first; only a confirmed "Salir" takes the old exit path
     * (super.onBackPressed(), i.e. SDLActivity's, which finishes the
     * activity and sends QUIT in onDestroy).
     *
     * Why an onBackPressed() override and not the two alternatives:
     * - SDL_ANDROID_TRAP_BACK_BUTTON (SDLActivity.java:736-754) would
     *   only swallow the gesture: with the hint on, the gesture does
     *   nothing at all and the player has no way out of the game short
     *   of Home, because the game itself never handles the back key.
     *   There is also no Java-side nativeSetHint in this tree (the only
     *   SDL_SetHint call is the orientations hint in android_main.cpp),
     *   so the hint could not even be set from here without new JNI.
     * - OnBackPressedCallback needs getOnBackPressedDispatcher(), which
     *   android.app.Activity (SDLActivity's base class, no AppCompat
     *   here) only gained in API 33; minSdk is 28, so it would need an
     *   SDK guard plus a second path for older devices. The override
     *   works on every API level with a single path.
     * manualBackButton() (SDLActivity.java:791-796, the JNI path by which
     * the game itself asks to exit) calls superOnBackPressed() directly
     * and bypasses this override, so a game-requested exit is still
     * immediate and never shows the dialog. A showing AlertDialog
     * (crash guard, graphics, ...) consumes the gesture itself to
     * dismiss, so this only fires while actually playing. (Hunt v1.4.6
     * ronda 8, A4-R8-01.) The R7-02 comment used to claim the game
     * "keeps running behind the dialog" because "an AlertDialog does
     * not take window focus" -- false on both counts: opening this
     * dialog takes focus, so the A4-R7-01 focus pause parks the guest
     * behind it, exactly like behind every other in-game dialog; the
     * game resumes when the dialog is dismissed and focus returns.
     */
    @Override
    public void onBackPressed() {
        if (isFinishing() || isDestroyed()) return;
        if (mExitConfirmDialog != null && mExitConfirmDialog.isShowing()) return;
        mExitConfirmDialog = new AlertDialog.Builder(this)
                .setTitle(R.string.exit_confirm_title)
                .setMessage(R.string.exit_confirm_msg)
                .setPositiveButton(R.string.exit_confirm_yes, (d, w) -> super.onBackPressed())
                .setNegativeButton(android.R.string.cancel, null)
                .create();
        mExitConfirmDialog.show();
    }

    @Override
    protected String[] getLibraries() {
        return new String[]{"main"};
    }

    public static ParcelFileDescriptor openContentFd(String uri, String mode) {
        SDLActivity self = mSingleton;
        if (self == null || uri == null) return null;
        try {
            return self.getContentResolver().openFileDescriptor(Uri.parse(uri), mode == null ? "r" : mode);
        } catch (Exception e) {
            return null;
        }
    }
}
