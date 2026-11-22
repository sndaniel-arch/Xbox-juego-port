package com.rexauto.port;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.Uri;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.util.List;

/**
 * Hidden settings, reachable only from the in-game menu (the gear on the
 * virtual gamepad). The launcher home is gone in v1.3 (official-port UX),
 * so graphics, GPU driver, logs and reset live here instead — nothing
 * settings-like shows on the way into the game.
 *
 * Moved verbatim from SetupActivity (v1.2) except for the Activity parameter:
 * these are static so any activity can open them. Changes apply on the next
 * launch (the runtime reads settings.txt once, at startup).
 */
public final class GraphicsDialog {
    /** Request code for the driver-zip picker; MainActivity forwards it here. */
    public static final int REQ_PICK_DRIVER = 3;

    private GraphicsDialog() {
    }

    // (Hunt v1.4.6 ronda 4, A4-R4-09.) One live instance per dialog, same
    // pattern as PadSettingsDialog: the dialog object is the guard, so a
    // destroy-without-dismiss cannot stick a boolean (see there). The
    // graphics, driver and restart dialogs are different dialogs and may
    // stack over each other by design (restart follows graphics OK); each
    // is only guarded against a duplicate of itself.
    private static AlertDialog sDialog;
    private static Activity sDialogActivity;
    private static AlertDialog sDriverDialog;
    private static Activity sDriverActivity;
    private static AlertDialog sRestartDialog;
    private static Activity sRestartActivity;

    private static boolean isShowing(AlertDialog dialog, Activity activity) {
        return dialog != null && dialog.isShowing()
                && activity != null && !activity.isFinishing() && !activity.isDestroyed();
    }

    private static void trackGraphicsDialog(Activity activity, AlertDialog dialog) {
        sDialog = dialog;
        sDialogActivity = activity;
        dialog.setOnDismissListener(d -> {
            if (sDialog == dialog) { sDialog = null; sDialogActivity = null; }
        });
    }

    private static void trackDriverDialog(Activity activity, AlertDialog dialog) {
        sDriverDialog = dialog;
        sDriverActivity = activity;
        dialog.setOnDismissListener(d -> {
            if (sDriverDialog == dialog) { sDriverDialog = null; sDriverActivity = null; }
        });
    }

    private static void trackRestartDialog(Activity activity, AlertDialog dialog) {
        sRestartDialog = dialog;
        sRestartActivity = activity;
        dialog.setOnDismissListener(d -> {
            if (sRestartDialog == dialog) { sRestartDialog = null; sRestartActivity = null; }
        });
    }

    public static void show(Activity activity) {
        // (Hunt v1.4.6 ronda 4, A4-R4-09.) Refuse a duplicate while one is up.
        if (isShowing(sDialog, sDialogActivity)) return;
        // (Caza ronda 6, A4-R6-07.) Sin este guard, un show() sobre una
        // activity terminada/destruida tira WindowManager$BadTokenException;
        // mismo guard que showRestartDialog ya usa.
        if (activity.isFinishing() || activity.isDestroyed()) return;
        GraphicsSettings gs = new GraphicsSettings(activity);
        float dp = activity.getResources().getDisplayMetrics().density;
        int pad = (int) (16 * dp);
        LinearLayout box = new LinearLayout(activity);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(pad, pad, pad, pad);

        label(activity, box, R.string.gfx_preset);
        Spinner preset = new Spinner(activity);
        String[] presets = {"performance", "balanced", "accuracy"};
        preset.setAdapter(new ArrayAdapter<>(activity, android.R.layout.simple_spinner_dropdown_item,
                new String[]{activity.getString(R.string.preset_performance), activity.getString(R.string.preset_balanced), activity.getString(R.string.preset_accuracy)}));
        // (Hunt v1.4.6 ronda 3, A4-R3-12.) If the stored value matches no
        // offered option, the spinner sits at position 0 and the OK handler
        // below must NOT write that first option back over the stored
        // value. The *_known flags record whether the stored value was
        // offered; an unknown stored value is only overwritten when the
        // user actually picks a different position.
        final boolean[] presetKnown = {false};
        for (int i = 0; i < presets.length; i++) if (presets[i].equals(gs.preset())) { preset.setSelection(i); presetKnown[0] = true; }
        box.addView(preset);

        label(activity, box, R.string.gfx_fps_cap);
        Spinner fps = new Spinner(activity);
        int[] caps = {0, 30, 60};
        fps.setAdapter(new ArrayAdapter<>(activity, android.R.layout.simple_spinner_dropdown_item,
                new String[]{activity.getString(R.string.fps_off), activity.getString(R.string.fps_30), activity.getString(R.string.fps_60)}));
        final boolean[] fpsKnown = {false};
        for (int i = 0; i < caps.length; i++) if (caps[i] == gs.fpsCap()) { fps.setSelection(i); fpsKnown[0] = true; }
        box.addView(fps);

        label(activity, box, R.string.gfx_scale);
        Spinner scale = new Spinner(activity);
        scale.setAdapter(new ArrayAdapter<>(activity, android.R.layout.simple_spinner_dropdown_item,
                activity.getResources().getStringArray(R.array.gfx_scale_options)));
        scale.setSelection(gs.resolutionScale() - 1);
        box.addView(scale);
        // (Ronda 5, C-R5-01.) Warn under the spinner when 2x/3x is
        // picked: on Mali without sparse residency the native side
        // reserves 512 MiB x scale^2 (2 GiB at 2x, 4,5 GiB at 3x) and
        // falls back to 1x on its own if it does not fit, so the user
        // should know the choice may silently run at 1x. The text
        // follows the spinner live; at 1x there is no warning to show.
        final TextView scaleWarn = new TextView(activity);
        scaleWarn.setTextSize(12);
        // Ice blue #8CCBEB: the port palette has no yellow/gold anywhere
        // (user rule), so the warning uses ice blue, not amber.
        scaleWarn.setTextColor(0xFF8CCBEB);
        scaleWarn.setPadding(0, 2, 0, 4);
        box.addView(scaleWarn);
        final Runnable updateScaleWarn = new Runnable() {
            @Override
            public void run() {
                String w = GraphicsSettings.resolutionScaleWarningFor(
                        scale.getSelectedItemPosition() + 1);
                scaleWarn.setText(w == null ? "" : w);
                scaleWarn.setVisibility(w == null ? View.GONE : View.VISIBLE);
            }
        };
        updateScaleWarn.run();
        scale.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                updateScaleWarn.run();
            }
            @Override
            public void onNothingSelected(AdapterView<?> parent) {
            }
        });

        label(activity, box, R.string.gfx_effect);
        Spinner effect = new Spinner(activity);
        // (Hunt v1.4.6 ronda 3, A4-R3-05.) CAS/FSR removed: the Android
        // build has no FidelityFX (REXGLUE_ENABLE_FIDELITYFX OFF, no
        // Gradle flag), so the present_effect cvar only accepts
        // "bilinear" and a stored "cas"/"fsr" was rejected in silence.
        // Bilinear is the only honest option until FidelityFX is enabled;
        // a stored cas/fsr is migrated to bilinear by the OK handler.
        String[] effects = {"bilinear"};
        effect.setAdapter(new ArrayAdapter<>(activity, android.R.layout.simple_spinner_dropdown_item,
                activity.getResources().getStringArray(R.array.gfx_effect_options)));
        for (int i = 0; i < effects.length; i++) if (effects[i].equals(gs.presentEffect())) effect.setSelection(i);
        box.addView(effect);

        label(activity, box, R.string.gfx_video_mode);
        Spinner mode = new Spinner(activity);
        int[][] modes = {{1280, 720}, {1920, 1080}, {1024, 576}, {960, 540}};
        mode.setAdapter(new ArrayAdapter<>(activity, android.R.layout.simple_spinner_dropdown_item,
                activity.getResources().getStringArray(R.array.gfx_mode_options)));
        final boolean[] modeKnown = {false};
        // (A4-R3-12.) Match on width AND height: the old width-only match
        // showed e.g. 1280x800 as 1280x720 and OK then overwrote the
        // height as well.
        for (int i = 0; i < modes.length; i++) if (modes[i][0] == gs.videoWidth() && modes[i][1] == gs.videoHeight()) { mode.setSelection(i); modeKnown[0] = true; }
        box.addView(mode);

        label(activity, box, R.string.gfx_orientation);
        Spinner orient = new Spinner(activity);
        String[] orients = {"landscape", "portrait", "auto"};
        orient.setAdapter(new ArrayAdapter<>(activity, android.R.layout.simple_spinner_dropdown_item,
                new String[]{activity.getString(R.string.orient_landscape), activity.getString(R.string.orient_portrait), activity.getString(R.string.orient_auto)}));
        final boolean[] orientKnown = {false};
        for (int i = 0; i < orients.length; i++) if (orients[i].equals(gs.orientation())) { orient.setSelection(i); orientKnown[0] = true; }
        box.addView(orient);

        CheckBox vsync = new CheckBox(activity);
        vsync.setText(R.string.gfx_vsync);
        vsync.setChecked(gs.vsync());
        box.addView(vsync);

        CheckBox letterbox = new CheckBox(activity);
        letterbox.setText(R.string.gfx_letterbox);
        letterbox.setChecked(gs.letterbox());
        box.addView(letterbox);

        CheckBox tolerant = new CheckBox(activity);
        tolerant.setText(R.string.gfx_tolerant);
        tolerant.setChecked(gs.tolerant());
        box.addView(tolerant);

        CheckBox experimentalDriver = new CheckBox(activity);
        experimentalDriver.setText(R.string.gpu_driver_experimental);
        experimentalDriver.setChecked(gs.experimentalGpuDriver());
        box.addView(experimentalDriver);

        label(activity, box, R.string.gfx_extra);
        EditText extra = new EditText(activity);
        extra.setHint("key=value");
        extra.setText(gs.extra());
        extra.setMinLines(2);
        box.addView(extra);

        ScrollView sv = new ScrollView(activity);
        sv.addView(box);
        AlertDialog dialog = new AlertDialog.Builder(activity)
                .setTitle(R.string.graphics)
                .setView(sv)
                .setPositiveButton(android.R.string.ok, (d, w) -> {
                    // (A4-R3-12.) Unknown stored values are preserved:
                    // a spinner left untouched at its display position 0
                    // must not overwrite a value the dialog never offered.
                    // Picking any other position is a real choice and is
                    // written. The scale spinner is exempt (always in
                    // range) and the effect spinner has one option only
                    // (bilinear, A4-R3-05), so it always writes bilinear.
                    if (presetKnown[0] || preset.getSelectedItemPosition() != 0) gs.setPreset(presets[preset.getSelectedItemPosition()]);
                    if (fpsKnown[0] || fps.getSelectedItemPosition() != 0) gs.setFpsCap(caps[fps.getSelectedItemPosition()]);
                    gs.setResolutionScale(scale.getSelectedItemPosition() + 1);
                    gs.setPresentEffect(effects[effect.getSelectedItemPosition()]);
                    if (modeKnown[0] || mode.getSelectedItemPosition() != 0) {
                        int[] m = modes[mode.getSelectedItemPosition()];
                        gs.setVideoMode(m[0], m[1]);
                    }
                    if (orientKnown[0] || orient.getSelectedItemPosition() != 0) gs.setOrientation(orients[orient.getSelectedItemPosition()]);
                    gs.setVsync(vsync.isChecked());
                    gs.setLetterbox(letterbox.isChecked());
                    gs.setTolerant(tolerant.isChecked());
                    gs.setExperimentalGpuDriver(experimentalDriver.isChecked());
                    gs.setExtra(extra.getText().toString());
                    try {
                        gs.write(activity);
                        // (Hunt v1.4.6, A4-R6-02.) settings.txt is only read
                        // once, at startup: nothing above takes effect
                        // until the game restarts, and before this the
                        // dialog said nothing at all. Offer the restart
                        // now instead of leaving the player believing the
                        // change applied.
                        showRestartDialog(activity);
                    } catch (Exception e) { Toast.makeText(activity, e.toString(), Toast.LENGTH_LONG).show(); }
                })
                .setNegativeButton(android.R.string.cancel, null)
                .create();
        trackGraphicsDialog(activity, dialog);
        dialog.show();
    }

    /** After a successful write, offer the restart the settings need. */
    private static void showRestartDialog(Activity activity) {
        if (activity.isFinishing() || activity.isDestroyed()) return;
        // (Hunt v1.4.6 ronda 4, A4-R4-09.) A double-tap on OK ran the
        // handler twice and stacked two restart offers.
        if (isShowing(sRestartDialog, sRestartActivity)) return;
        AlertDialog dialog = new AlertDialog.Builder(activity)
                .setMessage(R.string.gfx_restart_required)
                .setPositiveButton(R.string.gfx_restart_now, (d, w) -> restartGame(activity))
                .setNegativeButton(R.string.gfx_restart_later, null)
                .create();
        trackRestartDialog(activity, dialog);
        dialog.show();
    }

    /**
     * Restart the game so the new settings.txt takes effect. The native
     * runtime (SDL thread + guest threads) lives in this process, so
     * finishing the activity alone would leave it running: queue the fresh
     * MainActivity with the system first, then exit this process. The
     * queued launch survives the exit (ActivityManager holds the intent),
     * so the game comes back in a fresh process; SetupActivity routes
     * straight back into MainActivity because the game root is valid.
     * Phone verification required: this path has no CI coverage.
     */
    private static void restartGame(Activity activity) {
        Intent i = new Intent(activity, MainActivity.class);
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        activity.startActivity(i);
        activity.finish();
        System.exit(0);
    }

    private static void label(Activity activity, LinearLayout parent, int text) {
        TextView t = new TextView(activity);
        t.setText(text);
        t.setTextSize(13);
        t.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        t.setTextColor(0xFFDCE8F5);
        t.setPadding(0, 12, 0, 4);
        parent.addView(t);
    }

    // --- custom GPU driver (Turnip on Adreno, PanVK on Mali) ----------------

    public static void showDriverDialog(Activity activity) {
        // (Hunt v1.4.6 ronda 4, A4-R4-09.) Refuse a duplicate while one is up.
        if (isShowing(sDriverDialog, sDriverActivity)) return;
        // (Caza ronda 6, A4-R6-07.) Igual que en show(): no mostrar nada
        // sobre una activity terminada/destruida (BadTokenException).
        if (activity.isFinishing() || activity.isDestroyed()) return;
        // Experimental gate (user rule: risky core changes behind a switch).
        // The switch lives in the graphics dialog; offer to turn it on here.
        GraphicsSettings gs = new GraphicsSettings(activity);
        if (!gs.experimentalGpuDriver()) {
            AlertDialog prompt = new AlertDialog.Builder(activity)
                    .setTitle(R.string.gpu_driver)
                    .setMessage(R.string.gpu_driver_experimental_off)
                    .setPositiveButton(R.string.gpu_driver_experimental_enable, (dd, ww) -> {
                        gs.setExperimentalGpuDriver(true);
                        // The prompt is still showing when this listener
                        // runs (AlertDialog dismisses after the listener):
                        // clear its guard entry first, or the recursive
                        // call below would see it and refuse to open.
                        sDriverDialog = null;
                        sDriverActivity = null;
                        showDriverDialog(activity);
                    })
                    .setNegativeButton(android.R.string.cancel, null)
                    .create();
            // (Caza ronda 6, A4-R6-07.) Guard antes de mostrar el prompt
            // de experimental-off (misma familia que el de la entrada).
            if (activity.isFinishing() || activity.isDestroyed()) return;
            trackDriverDialog(activity, prompt);
            prompt.show();
            return;
        }
        GpuDriver gd = new GpuDriver(activity);
        List<GpuDriver.Info> list = gd.installed();
        String[] names = new String[list.size() + 1];
        names[0] = activity.getString(R.string.gpu_driver_system);
        int checked = 0;
        for (int i = 0; i < list.size(); i++) {
            GpuDriver.Info d = list.get(i);
            names[i + 1] = d.name + (d.version.isEmpty() ? "" : "  (" + d.version + ")");
            if (d.slug.equals(gd.selected())) checked = i + 1;
        }
        final int[] pick = {checked};
        AlertDialog.Builder b = new AlertDialog.Builder(activity)
                .setTitle(R.string.gpu_driver)
                .setSingleChoiceItems(names, checked, (d, w) -> pick[0] = w)
                .setPositiveButton(android.R.string.ok, (d, w) -> {
                    try {
                        gd.select(pick[0] == 0 ? null : list.get(pick[0] - 1).slug);
                        Toast.makeText(activity, pick[0] == 0 ? activity.getString(R.string.gpu_driver_system) : list.get(pick[0] - 1).name, Toast.LENGTH_SHORT).show();
                    } catch (Exception e) { Toast.makeText(activity, e.toString(), Toast.LENGTH_LONG).show(); }
                })
                .setNeutralButton(R.string.gpu_driver_import, (d, w) -> {
                    Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                    i.addCategory(Intent.CATEGORY_OPENABLE);
                    i.setType("*/*");
                    i.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{"application/zip", "application/x-zip-compressed", "application/octet-stream"});
                    activity.startActivityForResult(i, REQ_PICK_DRIVER);
                })
                .setNegativeButton(android.R.string.cancel, null);
        if (!GpuDriver.supportsCustomDriver()) {
            b.setMessage(R.string.gpu_driver_not_supported);
        } else if (GpuDriver.isMali()) {
            // Mali: only PanVK packs fit (libraryName libvulkan_panfrost.so
            // or libvulkan_panvk.so, both recognised since R7-E2 - R8-F6);
            // a Turnip/Adreno zip would load and then fail back to system.
            b.setMessage(R.string.gpu_driver_mali_note);
        }
        AlertDialog dlg = b.create();
        // getListView() is null until the dialog is shown (the ListView is
        // created in onCreate): show first, then attach the listener.
        // (Caza ronda 6, A4-R6-07.) Guard antes de dlg.show(), como en la
        // entrada de este metodo.
        if (activity.isFinishing() || activity.isDestroyed()) return;
        trackDriverDialog(activity, dlg);
        dlg.show();
        dlg.getListView().setOnItemLongClickListener((p, v, pos, id) -> {
            if (pos == 0) return true;
            GpuDriver.Info d = list.get(pos - 1);
            new AlertDialog.Builder(activity).setMessage(activity.getString(R.string.gpu_driver_remove, d.name))
                    .setPositiveButton(android.R.string.ok, (dd, ww) -> {
                        try { gd.remove(d.slug); } catch (Exception e) { Toast.makeText(activity, e.toString(), Toast.LENGTH_LONG).show(); }
                        dlg.dismiss();
                        showDriverDialog(activity);
                    }).setNegativeButton(android.R.string.cancel, null).show();
            return true;
        });
    }

    /** Called by the host activity's onActivityResult for REQ_PICK_DRIVER. */
    public static void onDriverPicked(Activity activity, Intent data) {
        if (data == null || data.getData() == null) return;
        Uri uri = data.getData();
        new Thread(() -> {
            try {
                GpuDriver gd = new GpuDriver(activity);
                // (Ronda 6, auditor F — R6-F7.) getLastPathSegment() puede
                // devolver null (content:// sin segmento): el null llegaba
                // a importZip como displayName y a los mensajes como "null".
                String name = uri.getLastPathSegment();
                if (name == null) name = "driver.zip";
                GpuDriver.Info info = gd.importZip(activity.getContentResolver(), uri, name);
                gd.select(info.slug);
                activity.runOnUiThread(() -> {
                    // (Ronda 8, auditor F - R8-F2.) El import corre en un
                    // hilo: si la actividad murio antes de que el callback
                    // llegara (el usuario salio de la app a mitad del
                    // import), mostrar un Toast o un dialogo con su
                    // contexto tira WindowManager$BadTokenException y
                    // crashea el hilo principal. Sin dialogo que reabrir
                    // ni toast que mostrar: el driver quedo instalado
                    // igual (importZip + select ya corrieron).
                    if (activity.isFinishing() || activity.isDestroyed()) return;
                    Toast.makeText(activity, activity.getString(R.string.gpu_driver_installed, info.name), Toast.LENGTH_LONG).show();
                    showDriverDialog(activity);
                });
            } catch (Exception e) {
                activity.runOnUiThread(() -> {
                    if (activity.isFinishing() || activity.isDestroyed()) return;
                    Toast.makeText(activity, e.getMessage() == null ? activity.getString(R.string.err_generic) : e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }, "import-driver").start();
    }
}
