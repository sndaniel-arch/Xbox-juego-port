package com.rexauto.port;

import android.content.ContentResolver;
import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;

import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Custom Vulkan driver packs (Turnip / newer Adreno blobs, PanVK for Mali) -
 * the same zip format Yuzu, Skyline, Dolphin and Winlator use: a {@code meta.json} with
 * {@code name}, {@code libraryName} (e.g. libvulkan_freedreno.so, or
 * libvulkan_panfrost.so for PanVK) and one or more .so files. Installed under
 * {@code <internal files>/gpu_driver/<slug>/}; the native side reads
 * {@code gpu_driver/driver.txt} and loads the library through libadrenotools
 * before the runtime starts.
 *
 * PanVK (Mesa, Mali) loads through the SAME adrenotools CUSTOM path as
 * Turnip: the hook only redirects the dlopen of the Vulkan driver by name
 * (hook_impl.cpp, ADRENOTOOLS_DRIVER_CUSTOM branch) and never checks which
 * GPU the library targets — the panvk-kbase releases even ship a dedicated
 * {@code ...-adrenotools.zip}. The Adreno-only gate that used to hide this
 * whole feature on Mali is gone: see {@link #supportsCustomDriver}.
 * PanVK is EXPERIMENTAL (see GraphicsSettings.experimentalGpuDriver) and
 * untested on this phone: no PanVK binary ships in the repo or the APK,
 * the user imports the zip (panvk-kbase v26.3.1 adrenotools zip).
 */
public final class GpuDriver {
    public static final class Info {
        public final String slug, name, description, library, vendor, version;
        Info(String slug, String name, String description, String library, String vendor, String version) {
            this.slug = slug; this.name = name; this.description = description; this.library = library; this.vendor = vendor; this.version = version;
        }
        @Override public String toString() { return name; }
    }

    private static final String PREF = "gpu_driver";
    // (Ronda 9, auditor A - R9-A1.) Candado estatico de importacion (ver
    // importZip/importZipLocked abajo): las instancias de GpuDriver se
    // crean frescas por pick, asi que un synchronized de instancia no
    // serviria; el candado tiene que ser estatico para serializar de
    // verdad dos picks seguidos.
    private static final Object IMPORT_LOCK = new Object();
    private final Context ctx;
    private final SharedPreferences prefs;

    public GpuDriver(Context ctx) {
        this.ctx = ctx;
        prefs = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    public static boolean isAdreno() {
        String soc = Build.VERSION.SDK_INT >= 31 ? (Build.SOC_MANUFACTURER + " " + Build.SOC_MODEL) : "";
        // Locale.ROOT (G-P2, ronda 2): toLowerCase() without a locale uses
        // the device locale; in Turkish (tr) 'I' -> 'ı' (dotless i), so a
        // SoC string containing 'I' would miss the "pineapple" needle below
        // and hide the driver dialog on an Adreno phone. The needles are
        // ASCII identifiers, not user text.
        String hw = (Build.HARDWARE + " " + Build.BOARD + " " + soc).toLowerCase(Locale.ROOT);
        return hw.contains("qcom") || hw.contains("qualcomm") || hw.contains("msm") || hw.contains("sm8") || hw.contains("sm7") || hw.contains("sm6") || hw.contains("sdm") || hw.contains("kona") || hw.contains("lahaina") || hw.contains("taro") || hw.contains("kalama") || hw.contains("pineapple") || hw.contains("sun");
    }

    /**
     * Mali GPU (PanVK target). Heuristic on Build fields: MediaTek Helio /
     * Dimensity (mt67xx/mt68xx/mt69xx), Exynos, Tensor and Kirin SoCs all
     * ship Mali GPUs, but none of their Build strings contains "mali", so
     * the SoC families are matched instead. (Hunt v1.4.6 ronda 3,
     * A4-R3-06 — the single fix for the duplicate A1-R3-06.) The old list
     * missed Mali on Unisoc (ums512/ums9230), Rockchip (rk3588/rk3566)
     * and Amlogic (s905/sm1/g12/sc2), and on API < 31 Build.SOC_MODEL is
     * unavailable so only HARDWARE/BOARD carry the SoC codename — the
     * families below are matched on those fields too. A Mali SoC outside
     * this list is still a false negative — the driver dialog stays
     * reachable anyway, because {@link #supportsCustomDriver} only
     * excludes GPUs positively known NOT to work (PowerVR/Apple); the
     * loader falls back to the system driver when a custom .so fails to
     * load, so showing the option is safe.
     * toLowerCase(Locale.ROOT): same Turkish-locale reason as isAdreno().
     */
    public static boolean isMali() {
        String soc = Build.VERSION.SDK_INT >= 31 ? (Build.SOC_MANUFACTURER + " " + Build.SOC_MODEL) : "";
        String hw = (Build.HARDWARE + " " + Build.BOARD + " " + soc).toLowerCase(Locale.ROOT);
        if (hw.contains("mali")) return true;
        if (hw.contains("mt67") || hw.contains("mt68") || hw.contains("mt69")) return true; // MediaTek Helio/Dimensity
        if (hw.contains("exynos") || hw.contains("tensor") || hw.contains("gs20") || hw.contains("gs10")) return true;
        if (hw.contains("kirin") || hw.contains("hi36")) return true;
        if (hw.contains("ums") || hw.contains("unisoc")) return true; // Unisoc (ums512, ums9230)
        if (hw.contains("rk35") || hw.contains("rockchip")) return true; // Rockchip (rk3588, rk3566)
        if (hw.contains("s905") || hw.contains("sm1") || hw.contains("g12") || hw.contains("sc2")
                || hw.contains("amlogic")) return true; // Amlogic (s905, sm1, g12, sc2 families)
        return false;
    }

    /** GPUs positively known to have no replacement-driver path (PowerVR, Apple). */
    public static boolean isKnownUnsupportedGpu() {
        String soc = Build.VERSION.SDK_INT >= 31 ? (Build.SOC_MANUFACTURER + " " + Build.SOC_MODEL) : "";
        String hw = (Build.HARDWARE + " " + Build.BOARD + " " + soc).toLowerCase(Locale.ROOT);
        return hw.contains("powervr") || hw.contains("imagination") || hw.contains("apple");
    }

    /** A custom Vulkan driver can be attempted on this device (Adreno, Mali, or unknown). */
    public static boolean supportsCustomDriver() {
        return !isKnownUnsupportedGpu();
    }

    /**
     * Driver family from the library name: "panvk", "turnip", or "unknown".
     * Library-name-only: it cannot tell the GameHub PanVK pack apart from
     * real Turnip — that zip names its library libvulkan_freedreno.so
     * (vulkan_device.cpp, R6-E1) — so isPanvk() below must not rely on
     * this alone. Kept as the library-name signal for pickLibrary-style
     * matching; the family decision lives in isPanvk(Info).
     */
    public static String familyOfLibrary(String library) {
        if (library == null) return "unknown";
        String l = library.toLowerCase(Locale.ROOT);
        // (Ronda 7, auditor E — R7-E2.) "panvk" también es nombre
        // PanVK: un pack cuyo .so es libvulkan_panvk.so caía en
        // "unknown" (R6-E8, observación sin código). Lo mismo para
        // pickLibrary abajo, donde caía a la rama genérica libvulkan
        // por detrás de freedreno/turnip.
        if (l.contains("panfrost") || l.contains("panvk")) return "panvk";
        if (l.contains("freedreno") || l.contains("turnip")) return "turnip";
        return "unknown";
    }

    private static boolean containsPanvk(String s) {
        if (s == null) return false;
        String l = s.toLowerCase(Locale.ROOT);
        return l.contains("panfrost") || l.contains("panvk");
    }

    /**
     * True when this installed driver is a PanVK (Mesa/Mali) build.
     * (Hunt v1.4.6 ronda 2, A4-R2-01.) The library name alone is NOT
     * enough: the GameHub PanVK zip names its library
     * libvulkan_freedreno.so, so familyOfLibrary() says "turnip" for a
     * pack that really is PanVK, the R-A-M6 relax never fired, and the
     * game could not boot on it (vulkan_device.cpp returns nullptr
     * without fragmentStoresAndAtomics). There is no driverID to consult
     * here — settings.txt is written before launch, and the driverID is
     * only known natively after device creation — so the classifier uses
     * the signals that ARE present at classification time, in the
     * Info the zip's meta.json already carries:
     *  1. a panvk/panfrost library name (as before);
     *  2. a panvk/panfrost meta name, vendor or description;
     *  3. a freedreno/turnip library name on a Mali GPU: Turnip is
     *     Adreno-only, so a freedreno-named pack on Mali is the GameHub
     *     PanVK pack (same ambiguity the native R6-E1 check already
     *     accepts for those names). A genuine Turnip pack mis-installed
     *     on Mali is harmless here: its .so cannot load on Mali, the
     *     hook falls back to the system driver, which HAS the feature.
     * "mesa" alone is deliberately NOT a signal: Mesa ships both
     * Turnip and PanVK.
     */
    public static boolean isPanvk(Info info) {
        if (info == null) return false;
        if ("panvk".equals(familyOfLibrary(info.library))) return true;
        if (containsPanvk(info.name) || containsPanvk(info.vendor)
                || containsPanvk(info.description)) return true;
        if ("turnip".equals(familyOfLibrary(info.library)) && isMali()) return true;
        return false;
    }

    /** Display name of the selected driver, or the slug when its meta is gone. */
    public String selectedDisplayName() {
        String slug = selected();
        if (slug == null) return null;
        Info info = readMeta(new File(root(), slug));
        return info != null ? info.name : slug;
    }

    public File root() { return new File(ctx.getFilesDir(), "gpu_driver"); }
    private File configFile() { return new File(root(), "driver.txt"); }

    /** Selected driver slug, or null for the system driver.
     * (Hunt v1.4.6 ronda 3, A4-R3-10.) The native loader reads ONLY
     * driver.txt, so a stale driver.txt with a null pref (process died
     * between the file write and the pref write in select(slug), or the
     * pref was cleared/lost) used to keep loading the custom driver
     * while this returned null. Fall back to the slug in driver.txt:
     * the file is the durable half of the selection, and the launch-time
     * switch-off guards consult selected() — with the fallback they now
     * see the stale selection and clear it. A corrupt/empty file still
     * returns null; driverConfigExists() covers that case for the guards.
     */
public String selected() {
        String slug = prefs.getString("selected", null);
    if (slug != null) return slug;
    File f = configFile();
    if (!f.isFile()) return null;
    try (BufferedReader r = new BufferedReader(new FileReader(f))) {
            String line = r.readLine();
        if (line == null) return null;
        int slash = line.indexOf('/');
        String s = (slash >= 0 ? line.substring(0, slash) : line).trim();
        return s.isEmpty() ? null : s;
    } catch (Exception e) {
            return null;
    }
}

    /** True when the native config file exists, even if its slug is unreadable. */
    public boolean driverConfigExists() { return configFile().exists(); }

    public List<Info> installed() {
        List<Info> out = new ArrayList<>();
        File[] dirs = root().listFiles(File::isDirectory);
        if (dirs == null) return out;
        for (File d : dirs) {
            if (d.getName().equals("tmp")) continue;
            Info i = readMeta(d);
            if (i != null) out.add(i);
        }
        return out;
    }

    private Info readMeta(File dir) {
        File meta = new File(dir, "meta.json");
        if (!meta.isFile()) return null;
        // (Ronda 7, auditor F — R7-F5.) meta.json se leia entero sin tope:
        // un zip artesano con un meta.json de cientos de MB (el tope del
        // zip es 512 MB) lo cargaba entero en RAM antes de parsearlo. Un
        // meta.json real mide ~200 B; por encima de 1 MB no es un
        // meta.json, es un ataque o un zip corrupto.
        if (meta.length() > (1L << 20)) return null;
        try (InputStream in = new java.io.FileInputStream(meta)) {
            JSONObject j = new JSONObject(new String(readAll(in), StandardCharsets.UTF_8));
            String lib = j.optString("libraryName", "");
            // (Ronda 7, auditor F — R7-F4.) libraryName no se saneaba: con
            // "../" (o "..\\") salia de su propio directorio — el slug
            // SI se saneo en R4-G1, pero este campo no. El lado nativo
            // (LoadCustomVulkanDriver) une spec = slug + "/" + library bajo
            // gpu_driver/ y toma lo que hay tras la ultima '/', asi que un
            // meta.json artesano hacia dlopen de un .so preexistente fuera
            // del directorio del driver (p. ej. el libvulkan del sistema).
            // libraryName legitimo es siempre un nombre pelado dentro de su
            // directorio; nada con separador es valido.
            if (lib.isEmpty() || lib.contains("/") || lib.contains("\\")
                    || lib.equals(".") || lib.equals("..")
                    || !new File(dir, lib).isFile()) return null;
            return new Info(dir.getName(), j.optString("name", dir.getName()), j.optString("description", ""), lib,
                    j.optString("vendor", ""), j.optString("driverVersion", j.optString("version", "")));
        } catch (Exception e) {
            return null;
        }
    }

    /** Unpack a driver zip picked with SAF. Returns the installed driver. */
    public Info importZip(ContentResolver cr, Uri uri, String displayName) throws IOException {
        // (Ronda 9, auditor A - R9-A1.) onDriverPicked lanza un hilo
        // "import-driver" POR PICK, sin serializar: dos picks seguidos
        // solapaban sus importZip(). El segundo borraba el tmp del
        // primero a mitad de descompresion (su readMeta() aun es null
        // hasta que aterrizan meta.json + .so) y el primer import
        // fallaba; y si ambos caian en el mismo milisegundo, los dos
        // compartian el mismo tmp "import_<millis>" y mezclaban los
        // dos zips en un solo directorio (meta de uno + .so del otro).
        // Serializar aqui: el segundo pick espera a que el primero
        // termine (import + rename a su slug) en vez de pisarlo. El
        // hilo de import no es el hilo de UI, asi que la espera no
        // bloquea la interfaz; el candado cubre solo el import, no el
        // select() posterior de onDriverPicked (tmp+rename atomico).
        // El cuerpo no se reindenta: vive en importZipLocked().
        synchronized (IMPORT_LOCK) {
            return importZipLocked(cr, uri, displayName);
        }
    }

    /** Cuerpo de importZip; llamar solo bajo IMPORT_LOCK (ver arriba). */
    private Info importZipLocked(ContentResolver cr, Uri uri, String displayName) throws IOException {
        // (Ronda 7, auditor F — R7-F6.) Un proceso muerto a mitad de un
        // import dejaba su import_<millis>/ huesped: installed() lo salta
        // (sin meta.json) pero nadie lo borraba nunca, asi que cada import
        // interrumpido dejaba un directorio para siempre bajo gpu_driver/.
        // Limpiar los restos de intentos anteriores antes de crear el
        // nuevo (las importaciones van en serie desde el dialogo, asi que
        // ningun import vivo puede perder su tmp aqui).
        // (Ronda 8, auditor A — R8-A1.) Solo los huespedes SIN meta
        // valido: el predicado por nombre de R7-F6 tambien borraba un
        // driver INSTALADO y valido cuyo slug empieza por "import_" (un
        // meta.json con name "import_panvk", o un zip sin meta llamado
        // "import_panvk.zip" — stripZip lo convierte en slug — se
        // instala como import_panvk/ y installed() SI lo lista, porque
        // solo salta "tmp" por nombre). El siguiente importZip lo
        // borraba en silencio antes de empezar, y si era el driver
        // seleccionado el proximo arranque caia al driver del sistema
        // (LoadCustomVulkanDriver: "... is missing"). Un import_*
        // con meta.json valido es un driver, no un resto: solo se
        // borra cuando readMeta() dice que no lo es. El prefijo
        // "import_" queda ademas reservado en el guard del slug
        // (abajo), asi que ningun driver nuevo puede llevarlo.
        File[] stale = root().listFiles(f -> f.isDirectory() && f.getName().startsWith("import_") && readMeta(f) == null);
        if (stale != null) for (File s : stale) deleteTree(s);
        File tmp = new File(root(), "import_" + System.currentTimeMillis());
        if (!tmp.mkdirs() && !tmp.isDirectory()) throw new IOException("mkdir " + tmp);
        List<String> sos = new ArrayList<>();
        boolean hasMeta = false;
        try (InputStream raw = requireOpenStream(cr, uri, displayName);
             ZipInputStream zip = new ZipInputStream(new BufferedInputStream(raw))) {
            ZipEntry e;
            long total = 0;
            while ((e = zip.getNextEntry()) != null) {
                if (e.isDirectory()) continue;
                // flatten: driver packs are flat, but some are zipped inside a folder
                String name = e.getName().replace('\\', '/');
                name = name.substring(name.lastIndexOf('/') + 1);
                if (name.isEmpty() || name.startsWith(".")) continue;
                if (!(name.endsWith(".so") || name.equals("meta.json"))) continue;
                File out = new File(tmp, name);
                try (OutputStream os = new FileOutputStream(out)) {
                    byte[] buf = new byte[1 << 16];
                    int n;
                    while ((n = zip.read(buf)) > 0) { os.write(buf, 0, n); total += n; if (total > (512L << 20)) throw new IOException("driver zip too large"); }
                }
                if (name.equals("meta.json")) hasMeta = true; else sos.add(name);
            }
        } catch (IOException | RuntimeException e) {
            // (Ronda 4, R4-G2.) The catch used to be IOException-only, so a
            // null stream (NPE in the resource initializer) or a
            // SecurityException on a revoked SAF grant escaped it: the tmp
            // dir leaked under gpu_driver/ and the user only got a generic
            // toast. Runtime failures clean up exactly like I/O ones; the
            // exception is rethrown unchanged for the caller.
            deleteTree(tmp);
            throw e;
        }
        if (sos.isEmpty()) { deleteTree(tmp); throw new IOException(ctx.getString(R.string.err_driver_zip, displayName)); }
        if (!hasMeta) {
            // no meta.json: synthesize one around the only/first .so
            String lib = sos.size() == 1 ? sos.get(0) : pickLibrary(sos);
            try (PrintWriter w = new PrintWriter(new FileWriter(new File(tmp, "meta.json")))) {
                w.println(new JSONObject().put("name", stripZip(displayName)).put("libraryName", lib).put("description", "imported without meta.json").toString());
            } catch (Exception e) { throw new IOException(e); }
        }
        Info info = readMeta(tmp);
        if (info == null) { deleteTree(tmp); throw new IOException(ctx.getString(R.string.err_driver_zip, displayName)); }
        String slug = info.name.replaceAll("[^A-Za-z0-9._-]+", "_");
        // (Ronda 4, R4-G1.) "." and ".." survive the filter above, and
        // dest = new File(root(), "..") is the app files dir itself:
        // deleteTree(dest) below would wipe every installed driver (and
        // driver.txt) before the rename then fails. A crafted meta.json
        // name (or a "..zip" display name in the no-meta path, via
        // stripZip) must never reach the file system as a slug.
        // (Ronda 7, auditor E — R7-E3.) Nombres reservados más allá
        // de "." / ".." (R4-G1): "tmp" es el scratch dir de
        // adrenotools (<internal>/gpu_driver/tmp, android_main.cpp)
        // Y el nombre que installed() salta, así que un driver con
        // slug "tmp" quedaría invisible en la UI compartiendo su
        // carpeta con los ficheros temporales del hook; "driver.txt"
        // es la propia config de selección (un directorio con ese
        // nombre hace que select(null) no pueda borrarla y select()
        // no pueda renombrar sobre ella) y "driver.txt.tmp" es la
        // escritura en curso de esa misma config. Los tres caen al
        // slug plano "driver", como "." / "..".
        if (slug.isEmpty() || slug.equals(".") || slug.equals("..") || slug.equals("tmp") ||
            slug.equals("driver.txt") || slug.equals("driver.txt.tmp") ||
            slug.startsWith("import_")) slug = "driver";
        File dest = new File(root(), slug);
        if (dest.exists()) deleteTree(dest);
        if (!tmp.renameTo(dest)) { deleteTree(tmp); throw new IOException("rename " + tmp + " -> " + dest); }
        // dlopen() needs the files to be non-writable by others; files dir is private already,
        // but make sure the .so is readable + executable for the loader.
        // (Ronda 5, auditor F — R5-F3.) File.listFiles() devuelve null ante
        // un error de E/S, no un array vacio: tras un rename con exito, un
        // fallo aqui tiraba NPE y el import se reportaba como fallido para
        // un driver que SI quedo instalado. installed() (:137) ya lo
        // comprueba; este era el unico bucle sin el guard.
        File[] installed = dest.listFiles();
        if (installed != null) for (File f : installed) { f.setReadable(true, false); f.setExecutable(true, false); }
        return readMeta(dest);
    }

    /**
     * ContentResolver.openInputStream() may return null instead of throwing
     * when the Uri cannot be opened. A null here used to die as a
     * NullPointerException in the try-with-resources initializer of
     * importZip, which the IOException-only catch could not catch (wrong
     * type): tmp leaked and the user got a generic error. Turn it into an
     * IOException with the real message, so the existing catch cleans up
     * and the caller shows it. (Ronda 4, R4-G2.)
     */
    private static InputStream requireOpenStream(ContentResolver cr, Uri uri, String displayName) throws IOException {
        InputStream raw = cr.openInputStream(uri);
        if (raw == null) throw new IOException("no se pudo abrir " + displayName);
        return raw;
    }

    private static String pickLibrary(List<String> sos) {
        // (Caza extra X-E-1, ronda 2.) Prefer the driver family that matches
        // this GPU: a zip can carry both .so files, and the old order always
        // preferred PanVK even on Adreno (harmless -- the loader falls back
        // to system -- but a silly selection). Matching is case-insensitive
        // (Locale.ROOT, same Turkish-locale reason as isAdreno()): a
        // libvulkan_PanFrost.so must not fall through to the generic branch.
        // On an unknown GPU, or when the matched family is absent, the old
        // global preference order (panfrost, then freedreno/turnip, then any
        // libvulkan) still applies.
        if (isMali()) {
            for (String s : sos) if (s.toLowerCase(Locale.ROOT).contains("panfrost") || s.toLowerCase(Locale.ROOT).contains("panvk")) return s;
        }
        if (isAdreno()) {
            for (String s : sos) {
                String l = s.toLowerCase(Locale.ROOT);
                if (l.contains("freedreno") || l.contains("turnip")) return s;
            }
        }
        for (String s : sos) if (s.toLowerCase(Locale.ROOT).contains("panfrost") || s.toLowerCase(Locale.ROOT).contains("panvk")) return s;
        for (String s : sos) {
            String l = s.toLowerCase(Locale.ROOT);
            if (l.contains("freedreno") || l.contains("turnip")) return s;
        }
        for (String s : sos) if (s.toLowerCase(Locale.ROOT).startsWith("libvulkan")) return s;
        return sos.get(0);
    }

    private static String stripZip(String n) {
        if (n == null) return "driver";
        int i = n.lastIndexOf('.');
        return i > 0 ? n.substring(0, i) : n;
    }

    /** Select a driver (null = system) and write the native config. */
    public void select(String slug) throws IOException {
        root().mkdirs();
        if (slug == null) {
            // (Ronda 3, auditor G.) File first, prefs second: the old order
            // cleared the preference and then deleted driver.txt, so a
            // failed delete left the native loader on the crashing custom
            // driver while the UI claimed "system" -- the crash guard's
            // whole purpose is breaking that loop. If the file is still
            // there after the delete, say so instead of lying.
            if (configFile().exists() && !configFile().delete() && configFile().exists()) {
                throw new IOException("could not remove " + configFile());
            }
            prefs.edit().remove("selected").apply();
            return;
        }
        Info info = readMeta(new File(root(), slug));
        if (info == null) throw new IOException("driver " + slug + " is not installed");
        // (Ronda 3, auditor G.) Write driver.txt FIRST (tmp + rename, like
        // the DLC installer), and only then record the selection in prefs.
        // The old order applied the prefs first: a failed/partial write
        // left prefs saying "driver X" while the native loader read a
        // stale (or empty) driver.txt and loaded the wrong driver -- or
        // the system one -- with the UI showing X. PrintWriter also
        // swallows write errors, so check them explicitly.
        File tmp = new File(root(), "driver.txt.tmp");
        try (PrintWriter w = new PrintWriter(new FileWriter(tmp, false))) {
            w.println(slug + "/" + info.library);
            if (w.checkError()) throw new IOException("could not write " + tmp);
        }
        if (!tmp.renameTo(configFile())) {
            tmp.delete();
            throw new IOException("could not install " + configFile());
        }
        prefs.edit().putString("selected", slug).apply();
    }

    public void remove(String slug) throws IOException {
        if (slug == null) throw new IOException("driver is null");
        // (Ronda 7, auditor E — R7-E3.) Los mismos nombres reservados
        // que importZip: deleteTree(root(), "..") borraría todo el
        // files dir, y "tmp" / "driver.txt" borrarían el scratch del
        // hook / la config de selección. Hoy solo llega aquí con un
        // slug de la lista de instalados (un nombre de directorio no
        // puede ser ".."), pero remove() no debe fiarse del argumento.
        // (Ronda 8, auditor A — R8-A2.) R7-E3 endurecio remove() contra
        // ".", "..", "tmp" y la config, pero dejo fuera "": new
        // File(root(), "") ES root(), asi que deleteTree(root()) borraria
        // todos los drivers instalados y driver.txt. Hoy solo llega aqui
        // con un slug de la lista de instalados (nunca vacio), pero
        // remove() no debe fiarse del argumento — mismo criterio que R7-E3.
        if (slug.isEmpty() || slug.equals(".") || slug.equals("..") || slug.equals("tmp") ||
            slug.equals("driver.txt") || slug.equals("driver.txt.tmp")) {
            throw new IOException("driver slug is reserved: " + slug);
        }
        if (slug.equals(selected())) select(null);
        // (Ronda 8, auditor F - R8-F5.) deleteTree() ignoraba el retorno
        // de delete(): si el borrado fallaba, remove() no se enteraba y
        // el dialogo se reabria sin decir nada (misma familia que R7-F7).
        if (!deleteTree(new File(root(), slug))) throw new IOException("could not remove driver " + slug);
    }

    // Devuelve false si algun borrado falla. Los callers de limpieza
    // (importZip) lo siguen ignorando a proposito; remove() lo comprueba.
    private static boolean deleteTree(File f) {
        boolean ok = true;
        File[] kids = f.listFiles();
        if (kids != null) for (File k : kids) ok = deleteTree(k) && ok;
        return f.delete() && ok;
    }

    private static byte[] readAll(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
        byte[] b = new byte[8192];
        int n;
        while ((n = in.read(b)) > 0) bo.write(b, 0, n);
        return bo.toByteArray();
    }
}
