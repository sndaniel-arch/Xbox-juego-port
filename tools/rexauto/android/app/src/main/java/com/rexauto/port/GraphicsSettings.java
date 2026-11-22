package com.rexauto.port;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Graphics / performance options exposed by the launcher. Each maps 1:1 to a
 * ReXGlue runtime cvar; the native side reads settings.txt and hands every
 * line over as --key=value before the runtime is constructed.
 */
public final class GraphicsSettings {
    private final SharedPreferences prefs;
    // Application context (never an Activity): needed to read the selected
    // GPU driver in asCvars() (R-A-M6) without leaking the caller.
    private final Context appCtx;

    public GraphicsSettings(Context ctx) {
        prefs = ctx.getSharedPreferences("graphics", Context.MODE_PRIVATE);
        appCtx = ctx.getApplicationContext();
    }

    // --- knobs (defaults tuned for a mid-range Adreno/Mali phone) -----------
    /** Internal render scale: 1 = native 720p (fastest), 2 = 2x, 3 = 3x. */
    public int resolutionScale() { return Math.max(1, Math.min(3, prefs.getInt("resolution_scale", 1))); }
    public void setResolutionScale(int v) { prefs.edit().putInt("resolution_scale", Math.max(1, Math.min(3, v))).apply(); }

    /**
     * (Ronda 5, C-R5-01.) Warning text for a resolution scale above 1x,
     * or null at 1x. On GPUs without sparse residency (Mali-G57) the
     * native side reserves ONE non-sparse buffer of 512 MiB x scale^2 for
     * the scaled resolve: 2 GiB at 2x, 4,5 GiB at 3x. If it does not fit,
     * the native side now falls back to 1x on its own (probe in
     * VulkanCommandProcessor::SetupContext) instead of failing the boot,
     * but the user should still know 2x/3x may silently run at 1x on this
     * phone. GraphicsDialog shows this under the scale spinner.
     */
    public String resolutionScaleWarning() {
        return resolutionScaleWarningFor(resolutionScale());
    }

    /** Same warning for a scale value that is not stored yet (dialog preview). */
    public static String resolutionScaleWarningFor(int s) {
        s = Math.max(1, Math.min(3, s));
        if (s <= 1) return null;
        int mb = 512 * s * s;
                // (Caza ronda 6, A4-R6-01 — regresion de C-R5-01.) mb/1024 era
                // division entera: a 3x 4608/1024 = 4 y el texto decia "4 GiB"
                // cuando el buffer real es 4,5 GiB. Un decimal con coma, con
                // aritmetica entera (sin Locale: el texto es espanol y debe decir
                // "4,5", no "4.5" segun la locale del telefono). A 2x sigue
                // diciendo "2 GiB" exactos (resto 0).
                String size;
                if (mb >= 1024) {
                                int whole = mb / 1024, rem = mb % 1024;
                                size = rem == 0 ? whole + " GiB" : whole + "," + (rem * 10 / 1024) + " GiB";
                } else {
                                size = mb + " MiB";
                }
        return "A " + s + "x la GPU reserva un buffer de " + size
                + " que puede no caber en este teléfono: si no cabe, el juego arranca a 1x.";
    }

    public boolean vsync() { return prefs.getBoolean("vsync", true); }
    public void setVsync(boolean v) { prefs.edit().putBoolean("vsync", v).apply(); }

    /** bilinear only: CAS/FSR need FidelityFX, which the Android build does not enable (A4-R3-05). */
    public String presentEffect() { return prefs.getString("present_effect", "bilinear"); }
    public void setPresentEffect(String v) { prefs.edit().putString("present_effect", v).apply(); }

    /** Guest video mode (what the game thinks the TV is). 720p is the safe pick. */
    public int videoWidth() { return prefs.getInt("video_mode_width", 1280); }
    public int videoHeight() { return prefs.getInt("video_mode_height", 720); }
    public void setVideoMode(int w, int h) { prefs.edit().putInt("video_mode_width", w).putInt("video_mode_height", h).apply(); }

    /** Keep 4:3/16:9 letterbox instead of stretching to the phone's aspect. */
    public boolean letterbox() { return prefs.getBoolean("present_letterbox", true); }
    public void setLetterbox(boolean v) { prefs.edit().putBoolean("present_letterbox", v).apply(); }

    /** Tolerant dispatcher: log-and-return on an unregistered indirect call
     *  instead of aborting (what the desktop `play <name>.cmd` does). */
    public boolean tolerant() { return prefs.getBoolean("tolerant", true); }
    public void setTolerant(boolean v) { prefs.edit().putBoolean("tolerant", v).apply(); }

    /** Screen orientation while playing: landscape (default) | portrait | auto. */
    public String orientation() { return prefs.getString("orientation", "landscape"); }
    public void setOrientation(String v) { prefs.edit().putString("orientation", v).apply(); }

    /**
     * Experimental GPU driver (PanVK on Mali, Turnip on Adreno): OFF by
     * default, per the user rule that risky core changes live behind a
     * switch he turns on himself. The driver picker (GraphicsDialog)
     * refuses to open while this is off. Default Sistema: the custom
     * driver only loads when a zip was imported AND selected AND this is on.
     */
    public boolean experimentalGpuDriver() { return prefs.getBoolean("experimental_gpu_driver", false); }
    public void setExperimentalGpuDriver(boolean v) { prefs.edit().putBoolean("experimental_gpu_driver", v).apply(); }

    /**
     * True when the selected custom GPU driver is a PanVK (Mesa/Mali)
     * build (hunt v1.4.6, R-A-M6). No driver selected, or a Turnip/Adreno
     * driver, means the running driver has fragment stores+atomics and
     * the requirement must stay on.
     */
    private boolean selectedDriverIsPanvk() {
        try {
            GpuDriver gd = new GpuDriver(appCtx);
            String sel = gd.selected();
            if (sel == null) return false;
            for (GpuDriver.Info info : gd.installed()) {
                if (sel.equals(info.slug)) return GpuDriver.isPanvk(info);
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    /**
     * Game language (ISO 639 code, e.g. "es", "en"). First run auto-detects
     * from the Android system locale and stores it, so the game speaks the
     * phone's language without any visible setting — an official port has no
     * language screen. The Xbox 360 game reads it via ExGetXConfigSetting
     * (XCONFIG_USER_LANGUAGE) backed by the kernel cvar user_language
     * (1 = English … 5 = Spanish); user_country matches it for locale.
     */
    public String language() {
        String v = prefs.getString("language", null);
        if (v == null) {
            v = Locale.getDefault().getLanguage();
            if (v == null || v.isEmpty()) v = "es";
            prefs.edit().putString("language", v).apply();
        }
        return v;
    }
    public void setLanguage(String v) { prefs.edit().putString("language", v == null ? "es" : v).apply(); }

    /** XLanguage id for an ISO 639 code (xcontent.h: es=5, en=1, …). */
    public static int languageId(String lang) {
        if (lang == null) return 1;
        switch (lang) {
            case "es": return 5;
            case "ja": return 2;
            case "de": return 3;
            case "fr": return 4;
            case "it": return 6;
            case "ko": return 7;
            case "pt": return 9;
            case "ru": return 12;
            case "pl": return 11;
            default: return 1;
        }
    }

    /**
     * XCountry id matching a language. Only es→31 (ES) is verified against
     * the kernel table (xam_locale.cpp); everything else keeps 103 (US),
     * which was the previous default — no behavior change for other languages.
     */
    public static int countryId(String lang) {
        if ("es".equals(lang)) return 31;
        return 103;
    }

    /**
     * Performance preset. Each one is a bundle of runtime cvars on top of the
     * knobs above; "performance" is the default because a phone GPU is roughly a
     * tenth of the Xenos+CPU budget the game was tuned for.
     *
     *   performance  -- 720p guest mode, 1x scale, no anisotropic filtering, no
     *                   memexport readback (GPU->CPU sync stall every frame),
     *                   occlusion queries answered with a constant instead of a
     *                   GPU round-trip, vsync via FIFO (no tearing, no busy loop),
     *                   texture cache capped so it never evicts mid-level.
     *   balanced     -- like performance but 4x anisotropic and real occlusion
     *                   queries (some games use them for lens flares / LOD).
     *   accuracy     -- the SDK defaults for every knob in the bundle below
     *                   (verified against the REXCVAR_DEFINE_* defaults, so
     *                   picking it really undoes the bundle). The mobile
     *                   platform defaults from android_main.cpp
     *                   (clear_memory_page_state=false,
     *                   ignore_thread_affinities/priorities=true,
     *                   vulkan_pipeline_creation_threads=2, log_flush_interval)
     *                   still apply: they are platform defaults, not preset
     *                   knobs, and no preset restores the desktop values
     *                   for them.
     *
     * On Mali GPUs (GpuDriver.isMali()) the performance/balanced presets
     * also get the Mali runtime overlay (R-A-10): no occlusion queries and
     * no native 2x MSAA (docs/RENDIMIENTO.md points 7 and 5). Accuracy
     * never gets the overlay: it is the SDK defaults by definition.
     */
    public String preset() { return prefs.getString("preset", "performance"); }
    public void setPreset(String v) { prefs.edit().putString("preset", v).apply(); }

    /** Frame-rate cap 0 = off. 30 halves GPU work for games that already ran at 30 on the 360. */
    public int fpsCap() { return prefs.getInt("fps_cap", 0); }
    public void setFpsCap(int v) { prefs.edit().putInt("fps_cap", v).apply(); }

    /** Extra raw cvars (advanced): "key=value" per line. */
    public String extra() { return prefs.getString("extra", ""); }
    public void setExtra(String v) { prefs.edit().putString("extra", v == null ? "" : v).apply(); }

    public Map<String, String> asCvars() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("resolution_scale", Integer.toString(resolutionScale()));
        m.put("draw_resolution_scale_x", Integer.toString(resolutionScale()));
        m.put("draw_resolution_scale_y", Integer.toString(resolutionScale()));
        m.put("vsync", Boolean.toString(vsync()));
        m.put("present_effect", presentEffect());
        m.put("video_mode_width", Integer.toString(videoWidth()));
        m.put("video_mode_height", Integer.toString(videoHeight()));
        m.put("present_letterbox", Boolean.toString(letterbox()));

        // (Caza P-H4, corregido hunt v1.4.6, R-A-M6.) Vulkan feature
        // requirements: the native side defaults
        // vulkan_require_fragment_stores_and_atomics=true (vulkan_device.cpp)
        // and PanVK on Mali lacks both stores+atomics features, so the
        // requirement is relaxed ONLY when a PanVK driver is actually
        // selected -- not whenever the experimental switch is on. With the
        // switch on but no driver selected (or a Turnip/Adreno driver
        // selected) the system/Adreno driver runs, which has the feature,
        // and relaxing it made draws that use fragment stores fail one by
        // one for nothing. Vertex stays false in both cases: its SDK
        // default is already false, and Mali may lack it, so emitting true
        // would risk the system-driver boot too. A hand-written line in
        // "extra" still wins (it is applied after this block).
        boolean relaxFragmentStores =
                experimentalGpuDriver() && selectedDriverIsPanvk();
        m.put("vulkan_require_fragment_stores_and_atomics", Boolean.toString(!relaxFragmentStores));
        m.put("vulkan_require_vertex_pipeline_stores_and_atomics", "false");

        // DLC license (hunt 2 DLC, P0-1): the game checks bit 0 of the
        // GLOBAL license mask (XamContentGetLicenseMask returns only this
        // cvar, default 0) before enabling any DLC. The per-package mask
        // (0x1, written into the .header by InstallContent) does NOT feed
        // that check, so without this line the game enumerates the DLCs
        // but never enables them. 0xFFFFFFFF covers bit 0 with margin.
        // Always on (all presets): licensing has nothing to do with graphics.
        m.put("license_mask", "4294967295");

        // --- preset bundle -------------------------------------------------
        String p = preset();
        if (p.equals("accuracy")) {
            // (Hunt v1.4.6, R-A-M5.) Accuracy is the SDK defaults for every
            // knob the performance/balanced bundle sets below, emitted
            // explicitly with the compiled-in defaults (verified against
            // the REXCVAR_DEFINE_* in the SDK): before this, accuracy
            // emitted nothing, so it silently kept the mobile platform
            // defaults from android_main.cpp (notably
            // vulkan_async_skip_incomplete_frames=false) while the UI
            // promised "desktop values". Emitting the defaults also makes
            // accuracy differ from the bundle where the SDK disagrees with
            // it (skip-incomplete-frames true, present immediate/mailbox
            // allowed, 4x anisotropic, real occlusion queries, 2x MSAA).
            m.put("readback_memexport", "true");
            m.put("vulkan_readback_memexport", "false");
            m.put("vulkan_readback_resolve", "false");
            m.put("texture_cache_memory_limit_soft", "384");
            m.put("texture_cache_memory_limit_hard", "768");
            m.put("texture_cache_memory_limit_render_to_texture", "24");
            m.put("async_shader_compilation", "true");
            m.put("vulkan_async_skip_incomplete_frames", "true");
            m.put("vulkan_allow_present_mode_immediate", "true");
            m.put("vulkan_allow_present_mode_mailbox", "true");
            m.put("vulkan_allow_present_mode_fifo_relaxed", "true");
            m.put("log_level", "info");
            // (Hunt v1.4.6 ronda 3, A4-R3-11.) log_high_frequency_kernel_calls
            // was a dead cvar (defined, never read by any logging path), so
            // it is no longer emitted; the definition/declaration were
            // removed with it.
            m.put("vulkan_log_debug_messages", "false");
            m.put("gpu_debug_markers", "false");
            m.put("vulkan_dynamic_rendering", "true");
            m.put("anisotropic_override", "3");
            m.put("occlusion_query_enable", "true");
            m.put("native_2x_msaa", "true");
            m.put("gamma_render_target_as_unorm16", "true");
        } else {
            // no per-frame GPU->CPU copy of memexport buffers; almost no title
            // reads them back on the CPU, and the sync costs a full frame stall
            m.put("readback_memexport", "false");
            m.put("vulkan_readback_memexport", "false");
            m.put("vulkan_readback_resolve", "false");
            // texture cache: SDK defaults (384/768/24). v1.4.1 used half
            // (192/384/16) and with the DXT->uncompressed 4x fallback the
            // cache held ~48 MB DXT-equivalent before evicting: constant
            // evict + re-decode, the texture errors on the phone (hunt
            // app-java P0-2 + nativo-sdk P0-2, both verified in code).
            m.put("texture_cache_memory_limit_soft", "384");
            m.put("texture_cache_memory_limit_hard", "768");
            m.put("texture_cache_memory_limit_render_to_texture", "24");
            // shader compile off the render thread; present frames that used a
            // placeholder pipeline instead of dropping them (the skip drops
            // whole frames during shader warm-up, which reads as stutter;
            // v1.4.1 proved the engine default alone does not hold because
            // this settings value overrode it)
            m.put("async_shader_compilation", "true");
            m.put("vulkan_async_skip_incomplete_frames", "false");
            // present: FIFO_RELAXED when the driver offers it (FIFO with
            // tearing allowed if a frame arrives late -- the SDK default,
            // and the value that actually ships here), else strict FIFO.
            // Mailbox/immediate stay off: they keep the GPU busy rendering
            // frames the panel never shows -- pure heat on a phone.
            m.put("vulkan_allow_present_mode_immediate", "false");
            m.put("vulkan_allow_present_mode_mailbox", "false");
            m.put("vulkan_allow_present_mode_fifo_relaxed", "true");
            // log I/O on the render/guest threads is not free
            // log_level=info while diagnosing (hunt P1-2): warning hid the
            // info lines the FASE5 checklist needs (presenter geometry,
            // STFS fd, affinity pin, pipelines created) -- that is why the
            // v1.4.1 log the user sent was warnings-only.
            m.put("log_level", "info");
            m.put("vulkan_log_debug_messages", "false");
            m.put("gpu_debug_markers", "false");
            // dynamic rendering: no VkRenderPass objects, fewer pipeline variants
            m.put("vulkan_dynamic_rendering", "true");
        }
        if (p.equals("performance")) {
            m.put("anisotropic_override", "0");          // 0 = off
            m.put("occlusion_query_enable", "false");    // constant answer, no GPU round-trip
            m.put("native_2x_msaa", "false");            // resolve 2xMSAA as 1x
            m.put("gamma_render_target_as_unorm16", "false"); // 8-bit gamma RTs: half the bandwidth
        } else if (p.equals("balanced")) {
            m.put("anisotropic_override", "3");          // 4x
        }
        // (Hunt v1.4.6, R-A-10.) Per-GPU profile, Mali runtime overlay: on
        // Mali GPUs the performance/balanced presets force occlusion
        // queries off and native 2x MSAA off (docs/RENDIMIENTO.md, Mali-G57
        // points 7 and 5). For performance this restates the preset; for
        // balanced it is the actual per-GPU difference (balanced alone
        // would keep real occlusion queries). Accuracy never gets the
        // overlay: it is the SDK defaults by definition. This plus the
        // driver-.so selection in GpuDriver.pickLibrary() is the whole
        // per-GPU profile the code has; the rest of the 12-point Mali list
        // in docs/RENDIMIENTO.md is build/translator constraints, and the
        // docs now say so instead of promising more.
        if (!p.equals("accuracy") && GpuDriver.isMali()) {
            m.put("occlusion_query_enable", "false");
            m.put("native_2x_msaa", "false");
        }
        if (fpsCap() > 0) m.put("env.REX_FPS_CAP", Integer.toString(fpsCap()));
        // "env.NAME=value" lines are exported as environment variables by the
        // native side (the dispatcher reads REX_HEAL_DISCOVER via getenv).
        if (tolerant()) m.put("env.REX_HEAL_DISCOVER", "1");
        // Game language: the 360 game reads XCONFIG_USER_LANGUAGE (cvar
        // user_language) at boot; Spanish resources exist in the bundle
        // (localization_spanish.isg, *.es.srt). Before the manual "extra"
        // lines so a hand-written user_language= there still wins.
        String lang = language();
        m.put("user_language", Integer.toString(languageId(lang)));
        m.put("user_country", Integer.toString(countryId(lang)));
        for (String line : extra().split("\n")) {
            line = line.trim();
            int eq = line.indexOf('=');
            if (line.startsWith("#") || eq <= 0) continue;
            m.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
        }
        return m;
    }

        // (Caza ronda 6, A4-R6-02.) Union of every key asCvars() can emit, in
        // any branch: the always-on knobs, the preset bundle (accuracy and
        // performance/balanced share the same base keys), the preset-only
        // keys (anisotropic/occlusion/MSAA/gamma), the Mali overlay keys,
        // the conditional env keys (FPS cap, tolerant) and the language
        // keys. write() must never "preserve" one of these from the old
        // settings.txt: a key asCvars() no longer emits is a knob the user
        // turned OFF (tolerant, FPS cap) or a preset that changed
        // (performance -> balanced on a non-Mali GPU), not a hand-added
        // line. Keys from the "extra" box are already inside the cvars map
        // itself, so they are rewritten from prefs, never preserved — a
        // hand-added line survives only when its key is in NEITHER set.
        private static final Set<String> OWNED_CVAR_KEYS = new HashSet<>(Arrays.asList(
                        "resolution_scale", "draw_resolution_scale_x", "draw_resolution_scale_y",
                        "vsync", "present_effect", "video_mode_width", "video_mode_height",
                        "present_letterbox",
                        "vulkan_require_fragment_stores_and_atomics",
                        "vulkan_require_vertex_pipeline_stores_and_atomics",
                        "license_mask",
                        "readback_memexport", "vulkan_readback_memexport", "vulkan_readback_resolve",
                        "texture_cache_memory_limit_soft", "texture_cache_memory_limit_hard",
                        "texture_cache_memory_limit_render_to_texture",
                        "async_shader_compilation", "vulkan_async_skip_incomplete_frames",
                        "vulkan_allow_present_mode_immediate", "vulkan_allow_present_mode_mailbox",
                        "vulkan_allow_present_mode_fifo_relaxed",
                        "log_level", "vulkan_log_debug_messages", "gpu_debug_markers",
                        "vulkan_dynamic_rendering",
                        "anisotropic_override", "occlusion_query_enable", "native_2x_msaa",
                        "gamma_render_target_as_unorm16",
                        "env.REX_FPS_CAP", "env.REX_HEAL_DISCOVER",
                        "user_language", "user_country"));
    
    /** Writes settings.txt for the native side. */
    public void write(Context ctx) throws IOException {
        File f = GameFiles.settingsFile(ctx);
        File parent = f.getParentFile();
        if (parent != null) parent.mkdirs();
        Map<String, String> cvars = asCvars();
        // (Ronda 4, R4-G3.) settings.txt is the ONLY channel for cvars with
        // no UI knob (e.g. xbmovie_probe=true for the video probe: no Java
        // surface writes it), and users hand-edit the file for them. This
        // used to rewrite the file from prefs alone, silently dropping
        // every hand-added line on each Graphics-dialog OK / import /
        // launchGame. Preserve lines whose key we do not write (ours win
        // for keys we own; the "extra" box already covers those durably).
        // A read failure here must never break the write: fall through to
        // a prefs-only file, as before.
        List<String> preserved = new ArrayList<>();
        if (f.isFile()) {
            try (BufferedReader r = new BufferedReader(new FileReader(f))) {
                String line;
                while ((line = r.readLine()) != null) {
                    String t = line.trim();
                    if (t.isEmpty() || t.startsWith("#")) continue;
                    int eq = t.indexOf('=');
                    if (eq <= 0) continue;
                    String key = t.substring(0, eq).trim();
                                        // (Caza ronda 6, A4-R6-02.) Only preserve keys we do
                                        // not own: a key in OWNED_CVAR_KEYS that asCvars()
                                        // did not emit this time was deliberately turned off
                                        // or left behind by a preset change, and preserving
                                        // it would resurrect it on the next boot.
                                        if (!cvars.containsKey(key) && !OWNED_CVAR_KEYS.contains(key)) {
                        preserved.add(key + "=" + t.substring(eq + 1).trim());
                    }
                }
            } catch (IOException ignored) {
                preserved.clear();
            }
        }
        // (Hunt v1.4.6 ronda 2, A4-R2-02.) Write to settings.txt.tmp and
        // rename over settings.txt, exactly as GpuDriver.select() does for
        // driver.txt: the old code truncated the live file first and then
        // wrote line by line, so a kill/crash mid-write left a torn
        // settings.txt (e.g. license_mask lost -> DLCs off for a session).
        // The rename is atomic on the same directory, so the live file is
        // either the old complete one or the new complete one. No fsync:
        // select() does not do one either.
        File tmp = new File(parent != null ? parent : f.getAbsoluteFile().getParentFile(),
                f.getName() + ".tmp");
        try (PrintWriter w = new PrintWriter(new FileWriter(tmp, false))) {
            w.println("# Child of Light — settings - one cvar per line");
            for (Map.Entry<String, String> e : cvars.entrySet()) {
                w.println(e.getKey() + "=" + e.getValue());
            }
            if (!preserved.isEmpty()) {
                w.println("# hand-added lines preserved from the previous settings.txt");
                for (String line : preserved) w.println(line);
            }
            // (Ronda 5, auditor F — R5-F4.) PrintWriter traga los errores de
            // E/S: sin checkError() un settings.txt truncado o vacio (disco
            // lleno, almacenamiento retirado) parecia escrito y el arranque
            // siguiente corria con los defaults del SDK sin avisar.
            if (w.checkError()) throw new IOException("write " + tmp);
        } catch (IOException e) {
            // (Round 2 second sweep, LOW-3.) Don't leave a stale .tmp behind
            // on the failure path: nothing reads *.tmp, but delete it here
            // like the rename failure below does.
            tmp.delete();
            throw e;
        }
        if (!tmp.renameTo(f)) {
            tmp.delete();
            throw new IOException("write " + f);
        }
    }
}
