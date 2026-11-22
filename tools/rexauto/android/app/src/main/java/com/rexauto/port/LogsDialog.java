package com.rexauto.port;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Typeface;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;

/**
 * Log viewer + crash report. Moved verbatim from SetupActivity (v1.2).
 * In v1.3 the launcher home is gone, so the full log viewer lives in the
 * hidden in-game menu (the gear on the virtual gamepad) and the crash report
 * is shown by the first-run router before the game starts — never on the way
 * into the game.
 */
public final class LogsDialog {
    private LogsDialog() {
    }

    // (Hunt v1.4.6 ronda 4, A4-R4-09.) One live instance, same pattern as
    // PadSettingsDialog: the dialog object is the guard, so a
    // destroy-without-dismiss cannot stick a boolean (see there). The
    // crash-report / driver-guard dialogs below are one-shot startup
    // gates, not double-tappable buttons, so they keep their own flow.
    private static AlertDialog sDialog;
    private static Activity sDialogActivity;

    /** True when the log viewer is currently up in a live activity. */
    private static boolean isShowing() {
        return sDialog != null && sDialog.isShowing()
                && sDialogActivity != null
                && !sDialogActivity.isFinishing() && !sDialogActivity.isDestroyed();
    }

    private static File logsDir(Activity activity) {
        // (Ronda 3, auditor G.) getExternalFilesDir() returns null when
        // external storage is not mounted; GameFiles and DlcAssets already
        // guard this, LogsDialog did not -- new File(null, "logs") throws
        // NPE and the crash guard/report in onCreate would crash the app
        // on exactly the launch that should show the report. Fall back to
        // internal files, like GameFiles does (the native side cannot have
        // written crash.txt anywhere in that state either, so the report is
        // simply absent, not lost).
        File ext = activity.getExternalFilesDir(null);
        return new File(ext != null ? ext : activity.getFilesDir(), "logs");
    }

    private static File crashFile(Activity activity) { return new File(logsDir(activity), "crash.txt"); }

    private static File gameLog(Activity activity) { return new File(logsDir(activity), BuildConfig.PROJECT + ".log"); }

    private static String tail(File f, int maxChars) {
        if (f == null || !f.isFile()) return "";
        try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(f, "r")) {
            long len = raf.length();
            long from = Math.max(0, len - maxChars);
            raf.seek(from);
            byte[] buf = new byte[(int) (len - from)];
            raf.readFully(buf);
            return new String(buf, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * True when the previous run wrote a crash report (libmain.so writes
     * logs/crash.txt from its signal handler; the native side wipes it on a
     * fresh launch, so at SetupActivity time it can only be from last run).
     */
    public static boolean hasCrashReport(Activity activity) {
        File c = crashFile(activity);
        return c != null && c.isFile();
    }

    private static File framesOkFile(Activity activity) { return new File(logsDir(activity), "frames.ok"); }

    /**
     * True when the previous run reached 300 presented guest frames
     * (Ronda 4, auditor E — R4-E1): the presenter writes <logs>/frames.ok
     * when presented_frame_count_ hits 300 in PaintAndPresent — ronda 5,
     * R5-E2 moved the write there from RefreshGuestOutput (antes contaba
     * guest_frame_count_, solo refreshes; ver android_main.cpp, R6-A1),
     * and the native side deletes it on every fresh launch next to
     * crash.txt. A marker therefore means the
     * custom driver booted and presented fine last run, so a crash after
     * that point was not a driver-boot failure and the guard must stay
     * silent — only a crash BEFORE 300 frames blames the driver.
     */
    public static boolean hasFramesOk(Activity activity) {
        File f = framesOkFile(activity);
        return f != null && f.isFile();
    }

    /**
     * Crash guard for custom GPU drivers (PanVK / Turnip), NocturneRecomp
     * pattern: when the last run crashed AND a custom driver is selected,
     * offer to fall back to the system driver BEFORE the game starts — i.e.
     * before any Vulkan instance is created (the native loader runs inside
     * RunAndroidApp, after SetupActivity launches the game). Returns true
     * when the guard dialog was shown (the caller must wait: onDismiss runs
     * the continuation). "Volver al sistema" clears driver.txt + the
     * selection, so the next launch uses the system driver; "Reintentar"
     * keeps the custom driver and continues to the generic crash report.
     * (Ronda 4, R4-E1:) the guard only fires when the crashed run never
     * reached 300 presented frames (no <logs>/frames.ok): a crash after
     * 300 frames proves the driver booted and presented, so it was not a
     * driver-boot failure and the generic report is shown instead.
     */
    public static boolean showDriverCrashGuardIfAny(Activity activity, Runnable onDismiss) {
        // (Caza ronda 7, A4-R7-03.) Same guard as show() (A4-R6-07):
        // without it, a show() on a finishing/destroyed activity throws
        // WindowManager$BadTokenException. This gate runs first in
        // onCreate, so the activity has just been born -- narrow window,
        // same class as the four sites A4-R6-07 closed.
        if (activity.isFinishing() || activity.isDestroyed()) return false;
        GpuDriver gd = new GpuDriver(activity);
        String slug = gd.selected();
        if (slug == null || !hasCrashReport(activity) || hasFramesOk(activity)) return false;
        String name = gd.selectedDisplayName();
        if (name == null) name = slug;
        final String driverName = name;
        new AlertDialog.Builder(activity)
                .setTitle(activity.getString(R.string.gpu_driver_crash_title, driverName))
                .setMessage(activity.getString(R.string.gpu_driver_crash_msg, driverName))
                .setPositiveButton(R.string.gpu_driver_crash_reset, (d, w) -> {
                    try {
                        gd.select(null);
                        Toast.makeText(activity, R.string.gpu_driver_system, Toast.LENGTH_SHORT).show();
                    } catch (Exception e) {
                        Toast.makeText(activity, e.toString(), Toast.LENGTH_LONG).show();
                    }
                })
                .setNegativeButton(R.string.gpu_driver_crash_retry, null)
                .setOnDismissListener(d -> {
                    if (onDismiss != null) onDismiss.run();
                })
                .show();
        return true;
    }

    /**
     * libmain.so writes logs/crash.txt from its signal handler; show it once.
     * Returns true when a report was shown (the caller must wait for the
     * dialog: onDismiss runs after the report is renamed away).
     */
    public static boolean showCrashReportIfAny(Activity activity, Runnable onDismiss) {
        // (Caza ronda 7, A4-R7-03.) Same guard as showDriverCrashGuardIfAny
        // above (A4-R6-07 family): no show() on a finishing/destroyed
        // activity (WindowManager$BadTokenException).
        if (activity.isFinishing() || activity.isDestroyed()) return false;
        File c = crashFile(activity);
        if (!c.isFile()) return false;
        String report = tail(c, 20000);
        String log = tail(gameLog(activity), 20000);
        String text = report + "\n--- últimas líneas del registro ---\n" + log;
        TextView tv = new TextView(activity);
        tv.setText(text);
        tv.setTextSize(11);
        tv.setTypeface(Typeface.MONOSPACE);
        tv.setTextIsSelectable(true);
        int p = (int) (12 * activity.getResources().getDisplayMetrics().density);
        tv.setPadding(p, p, p, p);
        ScrollView sv = new ScrollView(activity);
        sv.addView(tv);
        new AlertDialog.Builder(activity)
                .setTitle(R.string.crash_title)
                .setView(sv)
                .setPositiveButton(R.string.share, (d, w) -> shareText(activity, activity.getString(R.string.crash_title), text))
                .setNeutralButton(R.string.copy, (d, w) -> copyText(activity, text))
                .setNegativeButton(android.R.string.ok, null)
                .setOnDismissListener(d -> {
                    // (Ronda 6, auditor F — R6-F6.) renameTo() devuelve false
                    // sin tirar: si el renombre falla, crash.txt sigue ahi y
                    // el informe vuelve a aparecer en cada arranque. Avisar
                    // en logcat; el informe ya se mostro, asi que la
                    // continuacion corre igual.
                    if (!c.renameTo(new File(logsDir(activity), "crash.prev.txt"))) {
                        android.util.Log.w("LogsDialog", "no se pudo renombrar " + c + " a crash.prev.txt");
                    }
                    if (onDismiss != null) onDismiss.run();
                })
                .show();
        return true;
    }

    public static void show(Activity activity) {
        // (Hunt v1.4.6 ronda 4, A4-R4-09.) Refuse a duplicate while one is up.
        if (isShowing()) return;
        // (Caza ronda 6, A4-R6-07.) Sin este guard, un show() sobre una
        // activity terminada/destruida tira WindowManager$BadTokenException;
        // mismo guard que GraphicsDialog.showRestartDialog ya usa.
        if (activity.isFinishing() || activity.isDestroyed()) return;
        String prev = tail(new File(logsDir(activity), "crash.prev.txt"), 4000);
        String cur = tail(crashFile(activity), 4000);
        String log = tail(gameLog(activity), 200000);
        String prof = tail(new File(logsDir(activity), "profile.txt"), 5000);
        String text = (cur.isEmpty() ? prev : cur);
        if (!text.isEmpty()) text = "--- último fallo ---\n" + text + "\n";
        if (!prof.isEmpty()) text += "--- perfil (dónde va el tiempo de CPU) ---\n" + prof + "\n";
        text += "--- " + BuildConfig.PROJECT + ".log (final) ---\n" + (log.isEmpty() ? activity.getString(R.string.log_empty) : log);
        final String all = text;
        TextView tv = new TextView(activity);
        tv.setText(all);
        tv.setTextSize(11);
        tv.setTypeface(Typeface.MONOSPACE);
        tv.setTextIsSelectable(true);
        int p = (int) (12 * activity.getResources().getDisplayMetrics().density);
        tv.setPadding(p, p, p, p);
        ScrollView sv = new ScrollView(activity);
        sv.addView(tv);
        AlertDialog dialog = new AlertDialog.Builder(activity)
                .setTitle(R.string.logs)
                .setView(sv)
                .setPositiveButton(R.string.share, (d, w) -> shareText(activity, BuildConfig.PROJECT + " log", all))
                .setNeutralButton(R.string.copy, (d, w) -> copyText(activity, all))
                .setNegativeButton(android.R.string.ok, null)
                .create();
        // (Hunt v1.4.6 ronda 4, A4-R4-09.) Track the live instance for the
        // isShowing() guard; clear it on dismiss.
        sDialog = dialog;
        sDialogActivity = activity;
        dialog.setOnDismissListener(d -> {
            if (sDialog == dialog) {
                sDialog = null;
                sDialogActivity = null;
            }
        });
        dialog.show();
    }

    private static void shareText(Activity activity, String subject, String text) {
        Intent i = new Intent(Intent.ACTION_SEND);
        i.setType("text/plain");
        i.putExtra(Intent.EXTRA_SUBJECT, subject);
        i.putExtra(Intent.EXTRA_TEXT, text);
        try { activity.startActivity(Intent.createChooser(i, subject)); } catch (Exception e) { copyText(activity, text); }
    }

    private static void copyText(Activity activity, String text) {
        android.content.ClipboardManager cm = (android.content.ClipboardManager) activity.getSystemService(Activity.CLIPBOARD_SERVICE);
        if (cm != null) cm.setPrimaryClip(android.content.ClipData.newPlainText("log", text));
        Toast.makeText(activity, R.string.copied, Toast.LENGTH_SHORT).show();
    }
}
