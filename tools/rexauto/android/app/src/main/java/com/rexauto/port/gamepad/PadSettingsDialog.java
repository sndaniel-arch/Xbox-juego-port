package com.rexauto.port.gamepad;

import android.app.Activity;
import android.app.AlertDialog;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.LinearLayout;
import android.widget.SeekBar;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import com.rexauto.port.GameFiles;
import com.rexauto.port.GpuDriver;
import com.rexauto.port.GraphicsDialog;
import com.rexauto.port.LogsDialog;
import com.rexauto.port.R;

import java.io.File;

/**
 * In-game settings for the virtual gamepad: size, opacity, haptics and a
 * "hide overlay" action. Fully programmatic (no XML layout), dark themed to
 * match the gamepad's glass style, and centered so it stays reachable in
 * landscape. Changes persist immediately via PadSettings; the onChanged
 * callback lets the overlay re-layout while the dialog stays open.
 */
final class PadSettingsDialog {

    // (Hunt v1.4.6 ronda 4, A4-R4-09.) A fast double-tap on the gear opened
    // two dialogs over the same PadSettings; both wrote on OK and the last
    // one won. One dialog at a time: the live instance is the guard, not a
    // bare boolean — a boolean cleared only by OnDismissListener would stick
    // if the activity is destroyed with the dialog open, since the framework
    // does not fire OnDismissListener then; a stale instance whose activity
    // is gone, or which is no longer showing, is dropped and the dialog can
    // open again.
    private static AlertDialog sDialog;
    private static Activity sDialogActivity;

    /** True when this dialog is currently up in a live activity. */
    static boolean isShowing() {
        return sDialog != null && sDialog.isShowing()
                && sDialogActivity != null
                && !sDialogActivity.isFinishing() && !sDialogActivity.isDestroyed();
    }

    /** One labeled percent slider bound to a clamped settings value. */
    private static final class SliderRow {
        final TextView label;
        final SeekBar bar;
        final float min;
        final float max;
        final int labelRes;
        final Activity activity;

        SliderRow(Activity activity, float density, int labelRes,
                  float min, float max, float initial,
                  ExtraListener extra) {
            this.activity = activity;
            this.min = min;
            this.max = max;
            this.labelRes = labelRes;

            final LinearLayout box = new LinearLayout(activity);
            box.setOrientation(LinearLayout.VERTICAL);
            box.setPadding(0, (int) (10 * density), 0, 0);

            label = new TextView(activity);
            label.setTextSize(14);
            box.addView(label);

            bar = new SeekBar(activity);
            bar.setMax(100);
            box.addView(bar);

            bar.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
                @Override
                public void onProgressChanged(SeekBar seekBar, int progress,
                                              boolean fromUser) {
                    final float value = fromProgress(progress);
                    // getString(res, arg) applies the %1$d%% format properly.
                    label.setText(activity.getString(labelRes, Math.round(value * 100)));
                    if (fromUser && extra != null) {
                        extra.onProgress(progress, true);
                    }
                }

                @Override
                public void onStartTrackingTouch(SeekBar seekBar) {
                }

                @Override
                public void onStopTrackingTouch(SeekBar seekBar) {
                }
            });
            setValue(initial);

            view = box;
        }

        final View view;

        float fromProgress(int progress) {
            return min + (max - min) * (progress / 100f);
        }

        void setValue(float value) {
            final int progress = Math.round((value - min) / (max - min) * 100f);
            bar.setProgress(progress);
            label.setText(activity.getString(labelRes, Math.round(value * 100)));
        }
    }

    /** Single-method hook for the caller's on-change handling. */
    private interface ExtraListener {
        void onProgress(int progress, boolean fromUser);
    }

    interface OnChanged {
        void onPadSettingsChanged();
    }

    private PadSettingsDialog() {
    }

    static void show(Activity activity, PadSettings settings, OnChanged onChanged) {
        // (Hunt v1.4.6 ronda 4, A4-R4-09.) Refuse a second instance while
        // one is up; VirtualPadView checks isShowing() too, but show() is
        // the choke point.
        if (isShowing()) return;
        // (Caza ronda 6, A4-R6-07.) Sin este guard, un show() sobre una
        // activity terminada/destruida tira WindowManager$BadTokenException;
        // mismo guard que GraphicsDialog.showRestartDialog ya usa.
        if (activity.isFinishing() || activity.isDestroyed()) return;
        final float density = activity.getResources().getDisplayMetrics().density;
        final int pad = (int) (20 * density);

        final LinearLayout root = new LinearLayout(activity);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, pad, pad, pad / 2);

        final TextView title = new TextView(activity);
        title.setText(R.string.pad_settings_title);
        title.setTextSize(18);
        title.setPadding(0, 0, 0, (int) (10 * density));
        root.addView(title);

        final SliderRow size = new SliderRow(activity, density, R.string.pad_size,
                PadSettings.SCALE_MIN, PadSettings.SCALE_MAX, settings.scale(),
                (progress, fromUser) -> {
                    if (fromUser) {
                        settings.setScale(PadSettings.SCALE_MIN
                                + (PadSettings.SCALE_MAX - PadSettings.SCALE_MIN)
                                * (progress / 100f));
                        onChanged.onPadSettingsChanged();
                    }
                });
        root.addView(size.view);

        final SliderRow opacity = new SliderRow(activity, density, R.string.pad_opacity,
                PadSettings.OPACITY_MIN, PadSettings.OPACITY_MAX, settings.opacity(),
                (progress, fromUser) -> {
                    if (fromUser) {
                        settings.setOpacity(PadSettings.OPACITY_MIN
                                + (PadSettings.OPACITY_MAX - PadSettings.OPACITY_MIN)
                                * (progress / 100f));
                        onChanged.onPadSettingsChanged();
                    }
                });
        root.addView(opacity.view);

        final Switch haptics = new Switch(activity);
        haptics.setText(R.string.pad_haptics);
        haptics.setTextSize(15);
        haptics.setPadding(0, (int) (14 * density), 0, (int) (6 * density));
        haptics.setChecked(settings.haptics());
        haptics.setOnCheckedChangeListener((CompoundButton b, boolean checked) -> {
            settings.setHaptics(checked);
            onChanged.onPadSettingsChanged();
        });
        root.addView(haptics);

        final AlertDialog dialog = new AlertDialog.Builder(activity,
                android.R.style.Theme_DeviceDefault_Dialog_Alert)
                .setView(root)
                .setCancelable(true)
                .create();

        // Buttons row: reset defaults + hide overlay.
        final LinearLayout buttons = new LinearLayout(activity);
        buttons.setOrientation(LinearLayout.HORIZONTAL);
        buttons.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        final Button reset = new Button(activity);
        reset.setText(R.string.pad_reset);
        reset.setOnClickListener(v -> {
            settings.resetToDefaults();
            haptics.setChecked(settings.haptics());
            size.setValue(settings.scale());
            opacity.setValue(settings.opacity());
            onChanged.onPadSettingsChanged();
        });
        buttons.addView(reset, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        final Button hide = new Button(activity);
        hide.setText(R.string.pad_hide);
        hide.setOnClickListener(v -> {
            settings.setHidden(true);
            dialog.dismiss();
            onChanged.onPadSettingsChanged();
        });
        buttons.addView(hide, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        root.addView(buttons);

        // Hidden settings (v1.3): the launcher home is gone, so graphics,
        // logs, GPU driver and reset live here, inside the game. Nothing
        // settings-like shows on the way into the game.
        final LinearLayout hidden = new LinearLayout(activity);
        hidden.setOrientation(LinearLayout.HORIZONTAL);
        hidden.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        hidden.setPadding(0, (int) (8 * density), 0, 0);

        final Button gfxBtn = new Button(activity);
        gfxBtn.setText(R.string.graphics);
        gfxBtn.setOnClickListener(v -> GraphicsDialog.show(activity));
        hidden.addView(gfxBtn, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        final Button logsBtn = new Button(activity);
        logsBtn.setText(R.string.logs);
        logsBtn.setOnClickListener(v -> LogsDialog.show(activity));
        hidden.addView(logsBtn, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(hidden);

        final LinearLayout hidden2 = new LinearLayout(activity);
        hidden2.setOrientation(LinearLayout.HORIZONTAL);
        hidden2.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        hidden2.setPadding(0, (int) (8 * density), 0, 0);

        final Button resetGame = new Button(activity);
        resetGame.setText(R.string.reset);
        resetGame.setOnClickListener(v -> new AlertDialog.Builder(activity)
                .setMessage(R.string.reset_confirm)
                .setPositiveButton(android.R.string.ok, (d, w) -> {
                    // (Ronda 7, auditor F — R7-F7.) delete() devuelve
                    // boolean, no tira: si el borrado fallaba (almacenamiento
                    // retirado a mitad, fichero retenido), el reset se daba
                    // por hecho igual — activity.finish() y el proximo toque
                    // volvia a entrar al juego como si nada. Misma familia
                    // que R6-F6 (renameTo ignorado), en el otro sentido: aqui
                    // el silencio miente sobre un borrado, no sobre un
                    // renombre. Solo se sale cuando todo se borro de verdad.
                    boolean ok = false;
                    try {
                        ok = deleteRecursively(GameFiles.gameDir(activity));
                        // Full builds have no extracted game files: the game
                        // data lives in <external>/data (saves, installed
                        // DLC, shader cache). Without this the reset was a
                        // no-op there and the game came back on next launch.
                        ok = deleteRecursively(GameFiles.dataDir(activity)) && ok;
                        File cfg = GameFiles.configFile(activity);
                        if (cfg.exists() && !cfg.delete()) ok = false;
                    } catch (Exception e) {
                        Toast.makeText(activity, e.toString(), Toast.LENGTH_LONG).show();
                    }
                    if (!ok) {
                        Toast.makeText(activity, R.string.err_generic, Toast.LENGTH_LONG).show();
                        return;
                    }
                    // Game files gone: back to the icon; next tap opens the
                    // first-run import screen again.
                    activity.finish();
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show());
        hidden2.addView(resetGame, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        if (GpuDriver.supportsCustomDriver()) {
            final Button driverBtn = new Button(activity);
            driverBtn.setText(R.string.gpu_driver);
            driverBtn.setOnClickListener(v -> GraphicsDialog.showDriverDialog(activity));
            hidden2.addView(driverBtn, new LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        }
        root.addView(hidden2);

        // Center the dialog on landscape screens.
        if (dialog.getWindow() != null) {
            dialog.getWindow().setGravity(Gravity.CENTER);
        }
        // (Hunt v1.4.6 ronda 4, A4-R4-09.) Track the live instance for the
        // isShowing() guard; clear it on dismiss (the == check keeps a
        // newer dialog from being cleared by an older one's dismiss).
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

    private static boolean deleteRecursively(File f) {
        if (f == null || !f.exists()) return true;
        boolean ok = true;
        if (f.isDirectory()) {
            File[] kids = f.listFiles();
            if (kids != null) for (File k : kids) ok = deleteRecursively(k) && ok;
        }
        return f.delete() && ok;
    }
}
