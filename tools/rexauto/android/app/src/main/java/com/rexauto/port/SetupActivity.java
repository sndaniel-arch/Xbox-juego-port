package com.rexauto.port;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * First-run router + minimal import screen. Official-port UX (v1.4): tapping
 * the icon goes straight to the game — this activity has NO home anymore,
 * and in full builds it shows NO screen at all.
 *
 *   - Game already installed -> launchGame() at once, no UI at all.
 *   - Full build, first run -> write the asset marker (game.stfs lives
 *     inside the APK, read in place by the VFS — nothing is copied or
 *     extracted, ever) and launch. No picker, no progress screen.
 *   - Normal build, first run -> one minimal screen: pick the game once.
 *     The normal build is a development variant only.
 *
 * Knows exactly which game this APK was recompiled for (title + title ID
 * baked in at build time via BuildConfig), so it can refuse the wrong disc.
 * Takes an ISO, a bare default.xex or an already-extracted folder, unpacks
 * into the app's own storage (no permissions needed). Graphics, GPU driver,
 * logs and reset moved to the hidden in-game menu (gear on the virtual
 * gamepad, see GraphicsDialog / LogsDialog / PadSettingsDialog).
 */
public class SetupActivity extends Activity {
    private static final int REQ_PICK_FILE = 1;
    private static final int REQ_PICK_TREE = 2;

    private TextView status;
    private ProgressBar progress;
    private Button pickBtn, pickDirBtn;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private volatile boolean busy;

    // --- palette: aurora boreal sobre negro AMOLED -------------------------
    // Azul hielo #8CCBEB, azul lavanda #6578B8, lavanda #A99ACD,
    // turquesa #75D6CE, plata #DCE8F5, fondo #10131D. Nada de amarillo/dorado.
    private static final int COL_BG = 0xFF10131D;
    private static final int COL_LAVENDER = 0xFFA99ACD;
    private static final int COL_TURQUOISE = 0xFF75D6CE;
    private static final int COL_SILVER = 0xFFDCE8F5;
    private static final int COL_MUTED = 0xFFB9C4D6;
    private static final int COL_ERROR = 0xFFE8A0B0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        // (Ronda 4, R4-B2 = R4-E4: mismo enforcement, dos auditores.)
        // Enforce the experimental GPU-driver switch HERE too, like
        // MainActivity does (R3-A1, ronda 3): without this, the crash guard
        // below could offer "Reintentar" with a custom driver while the
        // switch is off, and MainActivity would then silently clear the
        // selection before SDL starts -- the dialog would promise something
        // the next screen voids. Same one-point enforcement (drop the
        // selection, driver.txt + pref); the driver files stay installed.
        // The safety property itself already held (MainActivity enforces
        // before SDL starts on every path); this only makes the guard's
        // offer honest on the SetupActivity-first path. A failed clear
        // leaves prefs + driver.txt consistent (see G-N3) and the guard
        // shows again next launch.
        if (!new GraphicsSettings(this).experimentalGpuDriver()) {
            try {
                GpuDriver gd = new GpuDriver(this);
                // (Hunt v1.4.6 ronda 3, A4-R3-10.) Same stale-driver.txt
                // clear as MainActivity: also clear when only the file
                // survives (see GpuDriver.selected() fallback /
                // driverConfigExists()).
                if (gd.selected() != null || gd.driverConfigExists()) gd.select(null);
            } catch (Exception e) {
                // (Hunt v1.4.6, sweep of R-A-M1.) Same swallowed
                // select(null) as MainActivity: say so instead of
                // launching with a driver the switch claims is off.
                Log.w("SetupActivity", "could not clear selected GPU driver", e);
                Toast.makeText(this, getString(R.string.err_driver_disable,
                        e.getMessage() == null ? e.toString() : e.getMessage()),
                        Toast.LENGTH_LONG).show();
            }
        }
        // Crash guard for custom GPU drivers first (PanVK / Turnip): if the
        // last run crashed with one selected, offer the system driver BEFORE
        // the game starts — before any Vulkan instance is created. Then the
        // generic crash report, then the router. The native side wipes
        // crash.txt on a fresh launch, so the report must be shown (and
        // renamed away) before the game starts. When shown, the router
        // continues on dismiss.
        if (LogsDialog.showDriverCrashGuardIfAny(this, this::continueStartAfterGuard)) return;
        continueStartAfterGuard();
    }

    /** After the driver crash guard: the generic crash report, then the router. */
    private void continueStartAfterGuard() {
        if (LogsDialog.showCrashReportIfAny(this, this::continueStart)) return;
        continueStart();
    }

    /** Router: straight to the game when installed, else the import screen. */
    private void continueStart() {
        if (GameFiles.hasValidGameRoot(this)) {
            launchGame();
            finish();
            return;
        }
        if (BuildConfig.FULL && launchBundledAsset()) {
            // Full build with a usable bundled asset: marker written, game
            // launched, no UI shown at all. Nothing is copied or imported.
            finish();
            return;
        }
        // M-17 (auditoria run #16): en FULL el picker NO existe como opcion
        // — un port oficial no importa el juego. Si el asset empaquetado
        // falta, esta corrupto o es de otro titulo, la APK esta rota y lo
        // unico que el jugador puede hacer es reinstalar. En builds
        // normal/dev, el picker sigue siendo la pantalla de primera vez.
        if (BuildConfig.FULL) {
            showBundledAssetMissingError();
            return;
        }
        // Normal/dev build: fall back to the manual picker.
        buildFirstRunScreen();
    }

    /**
     * M-17: FULL build whose bundled asset is unusable (missing, corrupt
     * or wrong title). Never offer the manual import picker: an official
     * port has no import flow. The dialog stays up until the user
     * dismisses it; either way the activity finishes — there is nothing
     * else this screen can do for a broken FULL build.
     */
    private void showBundledAssetMissingError() {
        new AlertDialog.Builder(this)
                .setMessage(R.string.err_full_missing_asset)
                .setPositiveButton(android.R.string.ok, (d, w) -> finish())
                .setOnCancelListener(d -> finish())
                .show();
    }

    /**
     * Full builds: the game ships inside the APK as the game.stfs asset and
     * is read in place by the VFS (StfsAsset hands its fd to native code in
     * PortApp.onCreate). All this does is verify the asset is really a
     * usable STFS package for this title, write the {@code asset:game.stfs}
     * marker into game_root.txt, and launch the game. Returns false when
     * there is no usable bundled asset — the caller falls back to the
     * manual import screen (dev builds) or shows the reinstall error
     * (FULL builds, M-17).
     */
    private boolean launchBundledAsset() {
        if (!StfsAsset.verifyUsable(getAssets(), BuildConfig.TITLE_ID)) return false;
        // The asset is fine on disk, but if its fd never reached native
        // code (the PortApp handover failed) the game cannot start from
        // it: return false instead of launching into a certain native
        // failure (see GameFiles.hasValidGameRoot). The caller decides
        // what false means: picker on dev, reinstall error on FULL (M-17).
        if (!StfsAsset.isHandedOver()) return false;
        // (Hunt v1.4.6 ronda 2, A4-R2-02.) Tmp + rename, as GpuDriver.select()
        // does for driver.txt: truncating game_root.txt in place left a torn
        // file on a kill/crash mid-write, and the next launch showed the
        // reinstall error instead of booting. The rename runs after the
        // writer closes, so the file it installs is complete.
        File config = GameFiles.configFile(this);
        File tmp = new File(config.getParentFile(), config.getName() + ".tmp");
        try (PrintWriter w = new PrintWriter(new FileWriter(tmp, false))) {
            w.println(GameFiles.ASSET_PREFIX + StfsAsset.ASSET_NAME);
            // (Ronda 5, auditor F — R5-F4.) PrintWriter traga los errores de
            // E/S en silencio: sin checkError() un disco lleno dejaba
            // game_root.txt vacio y el arranque siguiente caia al picker.
            if (w.checkError()) throw new java.io.IOException("write game_root.txt");
        } catch (Exception e) {
            tmp.delete();
            return false;
        }
        if (!tmp.renameTo(config)) {
            tmp.delete();
            return false;
        }
        launchGame();
        return true;
    }

    /** The only screen this activity ever shows: pick the game, once. */
    private void buildFirstRunScreen() {
        float dp = getResources().getDisplayMetrics().density;
        int pad = (int) (20 * dp);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, (int) (12 * dp), pad, pad);
        root.setBackgroundColor(COL_BG);

        TextView title = new TextView(this);
        title.setText(BuildConfig.GAME_TITLE);
        title.setTextSize(30);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setTextColor(Color.WHITE);
        root.addView(title);

        TextView edition = new TextView(this);
        edition.setText(getString(R.string.edition, BuildConfig.TITLE_ID));
        edition.setTextSize(13);
        edition.setTypeface(Typeface.DEFAULT_BOLD);
        edition.setTextColor(COL_SILVER);
        edition.setPadding(0, (int) (4 * dp), 0, (int) (12 * dp));
        root.addView(edition);

        TextView help = new TextView(this);
        help.setText(getString(R.string.first_run_help, BuildConfig.GAME_TITLE));
        help.setTextSize(14);
        help.setTextColor(COL_MUTED);
        help.setPadding(0, 0, 0, (int) (16 * dp));
        root.addView(help);

        pickBtn = button(root, R.string.pick_iso, v -> pickFile());
        pickDirBtn = button(root, R.string.pick_folder, v -> pickFolder());

        status = new TextView(this);
        status.setTextSize(15);
        status.setTextColor(COL_LAVENDER);
        status.setPadding(0, (int) (16 * dp), 0, 0);
        root.addView(status);
        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setVisibility(View.GONE);
        progress.setMax(1000);
        progress.setProgressTintList(ColorStateList.valueOf(COL_TURQUOISE));
        progress.setIndeterminateTintList(ColorStateList.valueOf(COL_TURQUOISE));
        LinearLayout.LayoutParams progLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        progLp.topMargin = (int) (10 * dp);
        progress.setLayoutParams(progLp);
        root.addView(progress);

        ScrollView sv = new ScrollView(this);
        sv.setBackgroundColor(COL_BG);
        sv.addView(root);
        setContentView(sv);
    }

    /** Boton secundario: superficie oscura, borde azul lavanda, texto plata. */
    private Button button(LinearLayout parent, int text, View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(text);
        b.setTextSize(16);
        b.setTextColor(COL_SILVER);
        b.setAllCaps(false);
        b.setBackgroundResource(R.drawable.btn_secondary);
        b.setOnClickListener(l);
        float dp = getResources().getDisplayMetrics().density;
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.topMargin = (int) (4 * dp);
        lp.bottomMargin = (int) (4 * dp);
        b.setLayoutParams(lp);
        parent.addView(b);
        return b;
    }

    // --- input pickers ------------------------------------------------------
    private void pickFile() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        i.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{"application/octet-stream", "application/x-iso9660-image", "*/*"});
        startActivityForResult(i, REQ_PICK_FILE);
    }

    private void pickFolder() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        startActivityForResult(i, REQ_PICK_TREE);
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (res != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData();
        if (req == REQ_PICK_FILE) importFile(uri);
        else if (req == REQ_PICK_TREE) importTree(uri);
    }

    private void setBusy(boolean b) {
        busy = b;
        pickBtn.setEnabled(!b);
        pickDirBtn.setEnabled(!b);
        progress.setVisibility(b ? View.VISIBLE : View.GONE);
        progress.setIndeterminate(true);
    }

    private void post(String s) { ui.post(() -> status.setText(s)); }

    private void postProgress(String s, long done, long total) {
        ui.post(() -> {
            progress.setIndeterminate(total <= 0);
            if (total > 0) progress.setProgress((int) (done * 1000 / total));
            status.setText(String.format(Locale.US, "%s  %d / %d MB", s, done >> 20, total >> 20));
        });
    }

    /** ISO or bare default.xex picked with the document picker. */
    private void importFile(Uri uri) {
        setBusy(true);
        String name = displayName(uri);
        post(getString(R.string.status_reading, name));
        new Thread(() -> {
            File dest = GameFiles.gameDir(this);
            try {
                IsoExtractor iso = IsoExtractor.open(getContentResolver(), uri);
                File xex;
                if (iso != null) {
                    dest.mkdirs();
                    // (Ronda 7, auditor F — R7-F1.) Sin try/finally, un
                    // extractAll() que tira (ISO truncado, I/O del provider)
                    // dejaba el canal + PFD del ISO abiertos: iso.close()
                    // nunca se alcanzaba. Las ramas SVOD y STFS de
                    // importPackage/importTree SI cierran en finally; esta
                    // era la unica que no.
                    try {
                        xex = iso.extractAll(dest, this::postProgress);
                    } finally {
                        iso.close();
                    }
                    if (xex == null) throw new Exception(getString(R.string.err_no_xex_in_iso));
                } else if ((xex = importPackage(uri, name, dest)) != null) {
                    // CON/LIVE/PIRS handled
                } else {
                    // not a disc: accept a raw default.xex
                    try (InputStream probe = getContentResolver().openInputStream(uri)) {
                        // (Ronda 5, auditor F — R5-F2.) openInputStream() puede
                        // devolver null (permiso SAF revocado): xexTitleId(null)
                        // tira NPE, que xexTitleId NO caza (solo IOException).
                        if (probe == null) throw new Exception(getString(R.string.err_not_iso, name));
                        if (GameFiles.xexTitleId(probe) == null)
                            throw new Exception(getString(R.string.err_not_iso, name));
                    }
                    xex = new File(dest, "default.xex");
                    try (InputStream in = getContentResolver().openInputStream(uri)) {
                        // (Ronda 5, auditor F — R5-F2.) Igual que el probe de
                        // arriba: copyStream(null, ...) tira NPE en in.read().
                        if (in == null) throw new Exception(getString(R.string.err_not_iso, name));
                        IsoExtractor.copyStream(in, xex);
                    }
                }
                finish(xex);
            } catch (Exception e) {
                fail(e.getMessage());
            }
        }, "import").start();
    }

    /**
     * CON / LIVE / PIRS picked as a single file: STFS (XBLA, arcade titles) is
     * unpacked entry by entry; a single-file Games-on-Demand image goes through
     * the GDFX path. A multi-part GoD needs its ".data" folder, so the user is
     * pointed at the folder picker. Returns null when the file is not a package.
     */
    private File importPackage(Uri uri, String name, File dest) throws Exception {
        java.nio.ByteBuffer hdr;
        android.os.ParcelFileDescriptor pfd = getContentResolver().openFileDescriptor(uri, "r");
        // (Ronda 6, auditor F — R6-F2.) Un fd que no se puede abrir no es
        // "no es un paquete": devolver null hacia que importFile lo tratase
        // como un .xex suelto y fallase con err_not_iso, el mensaje
        // equivocado para un STFS/GoD ilegible. Tirar con el motivo real.
        if (pfd == null) throw new java.io.IOException("cannot open " + uri);
        java.nio.channels.FileChannel ch = new java.io.FileInputStream(pfd.getFileDescriptor()).getChannel();
        try {
            hdr = StfsExtractor.readHeader(ch);
        } catch (Exception e) {
            // (Ronda 6, auditor F — R6-F2.) readHeader() puede tirar (I/O a
            // mitad de cabecera): sin este catch el canal y el pfd quedaban
            // abiertos en cada intento fallido — el finally de abajo solo
            // cubre la extraccion, no la lectura de cabecera.
            try { ch.close(); } catch (Exception ignored) { }
            try { pfd.close(); } catch (Exception ignored) { }
            throw e;
        }
        if (hdr == null) { ch.close(); pfd.close(); return null; }
        dest.mkdirs();
        if (StfsExtractor.volumeType(hdr) == StfsExtractor.VOLUME_SVOD) {
            ch.close(); pfd.close();
            if (hdr.getInt(0x39D) > 1)
                throw new Exception(getString(R.string.err_god_needs_folder, name));
            StfsExtractor.Found f = new StfsExtractor.Found(uri, name, hdr, null);
            post(getString(R.string.status_reading, name + " (Games on Demand)"));
            IsoExtractor god = StfsExtractor.openSvod(getContentResolver(), f, null);
            try {
                File xex = god.extractAll(dest, this::postProgress);
                if (xex == null) throw new Exception(getString(R.string.err_no_xex_in_iso));
                return xex;
            } finally { god.close(); }
        }
        post(getString(R.string.status_reading, name + " (STFS)"));
        try {
            File xex = new StfsExtractor.Stfs(ch, hdr).extractAll(dest, this::postProgress);
            if (xex == null) throw new Exception(getString(R.string.err_no_xex_in_stfs, name));
            return xex;
        } finally { ch.close(); pfd.close(); }
    }

    /** Already-extracted folder picked with the tree picker: copy it in. */
    private void importTree(Uri tree) {
        setBusy(true);
        post(getString(R.string.status_copying));
        new Thread(() -> {
            File dest = GameFiles.gameDir(this);
            try {
                dest.mkdirs();
                File xex;
                StfsExtractor.Found pkg = StfsExtractor.findInTree(getContentResolver(), tree, DocumentsContract.getTreeDocumentId(tree), 0);
                if (pkg != null && pkg.volumeType() == StfsExtractor.VOLUME_SVOD) {
                    // Games on Demand dump: <id>/<header> + <header>.data/Data0000..
                    post(getString(R.string.status_reading, pkg.name + " (Games on Demand)"));
                    IsoExtractor god = StfsExtractor.openSvod(getContentResolver(), pkg, tree);
                    try { xex = god.extractAll(dest, this::postProgress); } finally { god.close(); }
                    if (xex == null) throw new Exception(getString(R.string.err_no_xex_in_iso));
                } else if (pkg != null) {
                    post(getString(R.string.status_reading, pkg.name + " (STFS)"));
                    android.os.ParcelFileDescriptor pfd = getContentResolver().openFileDescriptor(pkg.headerDoc, "r");
                    // (Ronda 5, auditor F — R5-F2.) openFileDescriptor() puede
                    // devolver null; IsoExtractor.open() SI lo comprueba (:54),
                    // esta rama no: pfd.getFileDescriptor() tira NPE y el
                    // import por carpeta de un STFS fallaba con err_generic.
                    if (pfd == null) throw new java.io.IOException("cannot open " + pkg.headerDoc);
                    java.nio.channels.FileChannel ch = new java.io.FileInputStream(pfd.getFileDescriptor()).getChannel();
                    try { xex = new StfsExtractor.Stfs(ch, pkg.hdr).extractAll(dest, this::postProgress); }
                    finally { ch.close(); pfd.close(); }
                    if (xex == null) throw new Exception(getString(R.string.err_no_xex_in_stfs, pkg.name));
                } else {
                    long[] counter = {0};
                    copyTree(tree, DocumentsContract.getTreeDocumentId(tree), dest, counter, 0);
                    xex = findXex(dest, 0);
                }
                if (xex == null) throw new Exception(getString(R.string.err_no_xex_in_folder));
                finish(xex);
            } catch (Exception e) {
                fail(e.getMessage());
            }
        }, "import-tree").start();
    }

    private void copyTree(Uri tree, String docId, File dest, long[] counter, int depth) throws Exception {
        if (depth > 12) return;
        Uri children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, docId);
        List<String[]> rows = new ArrayList<>();
        try (Cursor c = getContentResolver().query(children, new String[]{
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE}, null, null, null)) {
            while (c != null && c.moveToNext()) rows.add(new String[]{c.getString(0), c.getString(1), c.getString(2)});
        }
        for (String[] r : rows) {
            String name = r[1] == null ? "file" : r[1].replace("/", "_");
            File out = new File(dest, name);
            if (DocumentsContract.Document.MIME_TYPE_DIR.equals(r[2])) {
                out.mkdirs();
                copyTree(tree, r[0], out, counter, depth + 1);
            } else {
                Uri doc = DocumentsContract.buildDocumentUriUsingTree(tree, r[0]);
                try (InputStream in = getContentResolver().openInputStream(doc)) {
                    // (Ronda 5, auditor F — R5-F2.) openInputStream() null ->
                    // NPE en copyStream; convertirlo en error con el doc.
                    if (in == null) throw new java.io.IOException("cannot open " + doc);
                    IsoExtractor.copyStream(in, out);
                }
                counter[0]++;
                post(getString(R.string.status_copied, counter[0], name));
            }
        }
    }

    private static File findXex(File dir, int depth) {
        if (depth > 12) return null;
        File[] kids = dir.listFiles();
        if (kids == null) return null;
        for (File f : kids) if (f.isFile() && f.getName().equalsIgnoreCase("default.xex")) return f;
        for (File f : kids) if (f.isDirectory()) { File x = findXex(f, depth + 1); if (x != null) return x; }
        return null;
    }

    /**
     * Title-ID gate + write game_root.txt, then straight into the game.
     * Official-port UX: no "installed" screen, no JUGAR button — the game
     * starts right away. Called from import threads, so the launch runs on
     * the UI thread.
     */
    private void finish(File xex) throws Exception {
        String got = GameFiles.xexTitleId(xex);
        String want = BuildConfig.TITLE_ID;
        if (want != null && !want.isEmpty() && !want.equals("00000000")) {
            if (got == null) {
                throw new Exception(getString(R.string.err_xex_unreadable));
            }
            if (!got.equalsIgnoreCase(want)) {
                String other = TitleDb.lookup(this, got);
                throw new Exception(getString(R.string.err_wrong_game,
                        other != null ? other : ("Title ID " + got), BuildConfig.GAME_TITLE, want));
            }
        }
        File root = xex.getParentFile();
        // (Hunt v1.4.6 ronda 2, A4-R2-02.) Tmp + rename, as GpuDriver.select()
        // does for driver.txt (same reason as launchBundledAsset above: a
        // torn game_root.txt makes the next launch show the reinstall
        // error). The rename runs after the writer closes.
        File config = GameFiles.configFile(this);
        File tmp = new File(config.getParentFile(), config.getName() + ".tmp");
        try (PrintWriter w = new PrintWriter(new FileWriter(tmp, false))) {
            w.println(root.getAbsolutePath());
            // (Ronda 5, auditor F — R5-F4.) Igual que en launchBundledAsset:
            // sin checkError() un fallo de escritura era invisible y el
            // siguiente arranque no encontraba el juego importado.
            if (w.checkError()) throw new java.io.IOException("write game_root.txt");
        } catch (java.io.IOException e) {
            // (Round 2 second sweep, LOW-3.) Don't leave a stale .tmp behind
            // on the failure path, mirroring launchBundledAsset above.
            tmp.delete();
            throw e;
        }
        if (!tmp.renameTo(config)) {
            tmp.delete();
            throw new java.io.IOException("write game_root.txt");
        }
        new GraphicsSettings(this).write(this);
        ui.post(() -> {
            // (Ronda 9, auditor F - R9-F1.) finish() corre en el hilo de
            // import y el runnable llega por ui.post: si el usuario pulso
            // Atras a mitad del import, la actividad ya esta destruida
            // cuando corre, y launchGame() lanzaria el juego contra su
            // voluntad (misma familia que R8-F2, en el otro sentido: alli
            // era un Toast/dialogo, aqui un startActivity). Sin juego que
            // lanzar: el import ya esta completo (game_root.txt escrito)
            // y el proximo arranque entra directo al juego.
            if (isFinishing() || isDestroyed()) return;
            setBusy(false);
            launchGame();
            finish();
        });
    }

    private void fail(String msg) {
        ui.post(() -> {
            setBusy(false);
            status.setText(msg == null ? getString(R.string.err_generic) : msg);
            status.setTextColor(COL_ERROR);
        });
    }

    private String displayName(Uri uri) {
        // (Ronda 7, auditor F — R7-F2.) DISPLAY_NAME puede ser null en
        // algunos providers y getLastPathSegment() tambien (content:// sin
        // segmento final): el null llegaba al estado ("Leyendo null") y a
        // err_not_iso como "%1$s" = "null". Misma familia que R6-F7
        // (GraphicsDialog), en el otro picker. El URI completo no es prosa
        // localizable, asi que vale como ultimo recurso.
        try (Cursor c = getContentResolver().query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                String name = c.getString(0);
                if (name != null) return name;
            }
        } catch (Exception ignored) { }
        String seg = uri.getLastPathSegment();
        return seg != null ? seg : uri.toString();
    }

    private void launchGame() {
        try {
            new GraphicsSettings(this).write(this);
        } catch (Exception e) {
            // (Hunt v1.4.6, R-A-M1.) The write failure used to be swallowed
            // and the game launched on a stale settings.txt (or SDK
            // defaults) with no word to anyone. Warn and launch anyway: a
            // stale settings.txt still boots, while refusing to launch
            // would strand a FULL build on an activity with no UI at all.
            Log.w("SetupActivity", "launchGame: settings write failed", e);
            Toast.makeText(this, getString(R.string.err_settings_write,
                    e.getMessage() == null ? e.toString() : e.getMessage()),
                    Toast.LENGTH_LONG).show();
        }
        startActivity(new Intent(this, MainActivity.class));
    }
}
