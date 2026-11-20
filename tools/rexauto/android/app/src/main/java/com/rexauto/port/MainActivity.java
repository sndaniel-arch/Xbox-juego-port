package com.rexauto.port;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.Toast;

import com.rexauto.port.gamepad.PadSettings;
import com.rexauto.port.gamepad.VirtualPadView;

import org.libsdl.app.SDLActivity;

/** SDL3 activity hosting the recompiled game (SDL is linked statically into libmain.so). */
public class MainActivity extends SDLActivity {
    private VirtualPadView mGamepad;
    private boolean mDeferSdlStart;

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
        if (!mHasMultiWindow) pauseEmulation();
        super.onPause();
    }
    /**
     * (Hunt v1.4.6 ronda 3, A4-R3-03.) Focus loss pauses the SDL thread
     * but NOT the guest: opening any in-game dialog (gear menu, graphics
     * / logs / driver) froze rendering while the simulation kept
     * advancing behind it. Mirror the onPause/onResume split on focus
     * change, only when not multi-window — the same split SDLActivity's
     * own onWindowFocusChanged uses for its native pause. Emulation goes
     * first (as in onPause/onResume below), then SDL's own handling, so
     * the guest stops before the SDL thread parks and resumes before it
     * unparks. Pause/resume are idempotent natively, so a focus change
     * arriving together with onPause/onResume (Home, incoming call,
     * screen-off) is a harmless second call, and a focus change before
     * the runtime exists is a no-op.
     */
@Override
    public void onWindowFocusChanged(boolean hasFocus) {
        if (!mHasMultiWindow) {
            if (hasFocus) resumeEmulation(); else pauseEmulation();
        }
        super.onWindowFocusChanged(hasFocus);
    }

    @Override
    protected void onResume() {
        // (Hunt v1.4.6 ronda 3, A4-R3-09.) The old order resumed the SDL
        // thread (super.onResume) before the emulation, the reverse of
        // onPause: the guest CPU threads ran a window while the CP was
        // still suspended and vblank interrupts resumed. Resume the
        // emulation first, mirroring onPause.
        if (!mHasMultiWindow) resumeEmulation();
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
        if (mHasMultiWindow) resumeEmulation();
        super.onStart();
    }

    /**
     * (Hunt v1.4.6, A4-R6-01.) Pause/resume the guest with the activity:
     * before this, Home / screen-off / switching apps left the game
     * running (audio included) in the background. The native side reaches
     * the runtime via Runtime::instance() and is a no-op before the
     * runtime exists (crash-guard dialogs, first launch). The split
     * mirrors SDLActivity's own: onPause/onResume when not multi-window,
     * onStop/onStart when it is (mHasMultiWindow is SDLActivity's own
     * public static flag, API 24+; minSdk here is 28). The native calls
     * are best-effort: a missing lib (mBrokenLibraries) must not crash
     * the lifecycle.
     */
    private static native void nativePauseEmulation();
    private static native void nativeResumeEmulation();

    private void pauseEmulation() {
        try { nativePauseEmulation(); } catch (Throwable t) { Log.w("MainActivity", "pause emulation failed", t); }
    }

    private void resumeEmulation() {
        try { nativeResumeEmulation(); } catch (Throwable t) { Log.w("MainActivity", "resume emulation failed", t); }
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
