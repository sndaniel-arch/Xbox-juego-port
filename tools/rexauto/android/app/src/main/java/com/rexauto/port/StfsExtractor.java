package com.rexauto.port;

import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Xbox 360 CON / LIVE / PIRS packages - Java port of rexauto's extract.py:
 * <ul>
 *   <li><b>STFS</b> (XBLA titles, title updates, DLC): a block-chained file
 *       system with a file table; extracted entry by entry.</li>
 *   <li><b>SVOD / Games on Demand</b>: a GDFX disc split across
 *       {@code <header>.data/Data0000..} fragments with hash tables interleaved;
 *       exposed as an {@link IsoExtractor.SectorSource} so the ISO code path
 *       does the actual extraction.</li>
 * </ul>
 * Everything is read through SAF ParcelFileDescriptors, so it works on picked
 * files and folders without any storage permission.
 */
public final class StfsExtractor {
    private static final int BLOCK = 0x1000;
    private static final int[] L = {170, 28900, 4913000};
    private static final int END = 0xFFFFFF;

    public static final int VOLUME_STFS = 0;
    public static final int VOLUME_SVOD = 1;

    /** Reads the first 0x400 bytes and tells whether this is a CON/LIVE/PIRS package. Returns null when it is not a package. */
    public static ByteBuffer readHeader(FileChannel ch) throws IOException {
        if (ch.size() < 0x400) return null;
        ByteBuffer h = ByteBuffer.allocate(0x400).order(ByteOrder.BIG_ENDIAN);
        // (Hunt v1.4.6 ronda 8, A4-R8-03.) Misma familia que A4-R7-05
        // (magicAt): el break en lectura corta y el return null
        // posterior no distinguian "no es un paquete" de "paquete
        // truncado" -- un STFS/GoD truncado (o un provider SAF que
        // entrega menos bytes de los que size() promete) caia en
        // importPackage como null y terminaba en err_not_iso, el
        // mensaje equivocado. Una lectura corta aqui es un paquete
        // truncado: tirar con el motivo real, que importPackage
        // propaga hasta fail() (SetupActivity). El guard de tamano de
        // arriba se queda como null, igual que el de magicAt: un
        // fichero que por su propio tamano no llega a 0x400 no puede
        // ser un paquete. El chequeo de limit() posterior ya no hace
        // falta: el bucle solo sale con el buffer lleno, o tirando.
        while (h.hasRemaining()) {
            if (ch.read(h, h.position()) <= 0)
                throw new IOException("STFS: truncated package header (short read, file truncated?)");
        }
        h.flip();
        String magic = new String(h.array(), 0, 4, java.nio.charset.StandardCharsets.ISO_8859_1);
        if (!magic.equals("CON ") && !magic.equals("LIVE") && !magic.equals("PIRS")) return null;
        return h;
    }

    public static int volumeType(ByteBuffer hdr) { return hdr.getInt(0x3A9); }

    /** Title ID from the package metadata (0x360, big-endian). */
    public static String titleId(ByteBuffer hdr) {
        return String.format("%08X", hdr.getInt(0x360));
    }

    private static int u24le(ByteBuffer b, int off) {
        return (b.get(off) & 0xFF) | ((b.get(off + 1) & 0xFF) << 8) | ((b.get(off + 2) & 0xFF) << 16);
    }

    // ------------------------------------------------------------------ STFS

    public static final class Stfs {
        public static final class Entry {
            public String name; public boolean contiguous, directory; public int parent, start; public long length;
        }

        private final FileChannel ch;
        private final int headerSize, bpht;
        private final boolean readOnly;
        private final int ftBlockCount, ftBlockNumber;
        private final long baseOff;
        private final long[] blockStep = new long[2];
        // (Caza ronda 7, A4-R7-06.) Bounded LRU: the old unbounded HashMap
        // kept one 4 KiB hash block per distinct hash-block offset visited
        // until the Stfs was released at the end of the import -- ~43 MB
        // on a very fragmented 7 GiB package (~10.8 K level-0 hash blocks:
        // one hash block covers L[0] = 170 data blocks). 512 entries is
        // 2 MiB worst case and still far above the live working set: a
        // hash block is hit ~170 times in a row while its data blocks are
        // walked, then abandoned, so only a handful of entries are hot at
        // any moment and sequential imports never notice the eviction.
        // Access-ordered so the eviction drops the least-recently-used
        // entry, not an arbitrary one.
        private static final int HASH_CACHE_MAX_ENTRIES = 512;
        private final Map<Long, ByteBuffer> hashCache = new LinkedHashMap<Long, ByteBuffer>(64, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<Long, ByteBuffer> eldest) {
                return size() > HASH_CACHE_MAX_ENTRIES;
            }
        };

        public Stfs(FileChannel ch, ByteBuffer d) {
            this.ch = ch;
            headerSize = d.getInt(0x340);
            int vd = 0x379;
            if ((d.get(vd) & 0xFF) != 0x24) {
                for (int off = 0x360; off < 0x390; off++) {
                    if ((d.get(off) & 0xFF) == 0x24 && (d.get(off + 1) & 0xFF) <= 1) { vd = off; break; }
                }
            }
            int flags = d.get(vd + 2) & 0xFF;
            readOnly = (flags & 1) != 0;
            ftBlockCount = ((d.get(vd + 3) & 0xFF) | ((d.get(vd + 4) & 0xFF) << 8));
            ftBlockNumber = u24le(d, vd + 5);
            bpht = readOnly ? 1 : 2;
            baseOff = (headerSize + BLOCK - 1) & ~(BLOCK - 1);
            blockStep[0] = L[0] + bpht;
            blockStep[1] = L[1] + (L[0] + 1L) * bpht;
        }

        private long blockToOffset(long bi) {
            long base = L[0], block = bi;
            for (int i = 0; i < 3; i++) {
                block += ((bi + base) / base) * bpht;
                if (bi < base) break;
                base *= L[0];
            }
            return baseOff + (block << 12);
        }

        private long hashBlockNumber(long bi) {
            if (bi < L[0]) return 0;
            long block = (bi / L[0]) * blockStep[0];
            block += ((bi / L[1]) + 1) * bpht;
            return bi < L[1] ? block : block + bpht;
        }

        private ByteBuffer readAt(long off, int n) throws IOException {
            ByteBuffer b = ByteBuffer.allocate(n).order(ByteOrder.BIG_ENDIAN);
            while (b.hasRemaining()) { if (ch.read(b, off + b.position()) <= 0) break; }
            b.flip();
            return b;
        }

        private int nextBlock(long bi) throws IOException {
            long hoff = baseOff + (hashBlockNumber(bi) << 12);
            ByteBuffer hb = hashCache.get(hoff);
            if (hb == null) { hb = readAt(hoff, BLOCK); hashCache.put(hoff, hb); }
            int rec = (int) ((bi % L[0]) * 0x18 + 0x14);
            if (rec + 4 > hb.limit()) return END;
            return hb.getInt(rec) & 0xFFFFFF;
        }

        public List<Entry> fileTable() throws IOException {
            List<Entry> out = new ArrayList<>();
            long bi = ftBlockNumber;
            for (int t = 0; t < ftBlockCount; t++) {
                ByteBuffer blk = readAt(blockToOffset(bi), BLOCK);
                for (int m = 0; m < BLOCK / 0x40; m++) {
                    int o = m * 0x40;
                    // (Ronda 6, auditor F — R6-F4.) Un bloque de tabla corto
                    // (STFS truncado: readAt devuelve menos de BLOCK) hacia
                    // que blk.get(o + 0x28...) tirase IndexOutOfBoundsException,
                    // no IOException: el import moria con err_generic en vez
                    // de un error legible.
                    if (o + 0x40 > blk.limit()) break;
                    if (blk.get(o) == 0) break;
                    int flags = blk.get(o + 0x28) & 0xFF;
                    int nlen = flags & 0x3F;
                    Entry e = new Entry();
                    e.name = new String(blk.array(), o, Math.min(nlen, 0x28), java.nio.charset.StandardCharsets.ISO_8859_1);
                    e.contiguous = (flags & 0x40) != 0;
                    e.directory = (flags & 0x80) != 0;
                    e.parent = blk.getShort(o + 0x32) & 0xFFFF;
                    e.start = u24le(blk, o + 0x2F);
                    e.length = blk.getInt(o + 0x34) & 0xFFFFFFFFL;
                    out.add(e);
                }
                bi = nextBlock(bi);
                if (bi == END) break;
            }
            return out;
        }

        public static String relPath(List<Entry> entries, int idx) {
            List<String> parts = new ArrayList<>();
            HashSet<Integer> seen = new HashSet<>();
            int i = idx;
            while (i != 0xFFFF && i >= 0 && i < entries.size() && seen.add(i)) {
                String comp = entries.get(i).name.replace('\\', '/');
                StringBuilder sb = new StringBuilder();
                for (String c : comp.split("/")) {
                    if (c.isEmpty() || c.equals(".") || c.equals("..")) continue;
                    if (sb.length() > 0) sb.append('/');
                    sb.append(c);
                }
                if (sb.length() > 0) parts.add(sb.toString());
                i = entries.get(i).parent;
            }
            Collections.reverse(parts);
            return String.join("/", parts);
        }

        /** Extract every file into dest; returns default.xex if there was one. */
        public File extractAll(File dest, IsoExtractor.Progress progress) throws IOException {
            List<Entry> entries = fileTable();
            long total = 0, done = 0;
            for (Entry e : entries) if (!e.directory) total += e.length;
            File xex = null;
            for (int i = 0; i < entries.size(); i++) {
                Entry e = entries.get(i);
                String rel = relPath(entries, i);
                if (rel.isEmpty()) continue;
                File out = new File(dest, rel);
                // (Caza ronda 6, A4-R6-06.) startsWith sin separador dejaba
                // pasar un hermano con prefijo (game-evil pasa como game):
                // exigir el separador tras el destino.
                if (!out.getCanonicalPath().startsWith(dest.getCanonicalPath() + File.separator)) continue;
                if (e.directory) { out.mkdirs(); continue; }
                File parent = out.getParentFile();
                if (parent != null && !parent.isDirectory() && !parent.mkdirs()) throw new IOException("mkdir " + parent);
                if (!(out.isFile() && out.length() == e.length)) {
                    try (OutputStream os = new FileOutputStream(out)) {
                        long bi = e.start, remaining = e.length;
                        while (remaining > 0 && bi != END) {
                            int n = (int) Math.min(BLOCK, remaining);
                            ByteBuffer b = readAt(blockToOffset(bi), n);
                            // (Caza ronda 6, A4-R6-03.) La lectura corta y
                            // la cadena de bloques rota terminaban el bucle
                            // en silencio y dejaban un archivo corto que
                            // pasaba la validacion de titulo (solo mira
                            // 16 KiB de cabecera). El ISO y GoD SI tiran
                            // en lectura corta (R7-F3 / R8-F3): misma
                            // convencion aqui, antes de escribir nada.
                            if (b.limit() < n) throw new IOException("STFS: short read at block " + bi + " (truncated package?)");
                            os.write(b.array(), 0, b.limit());
                            done += b.limit();
                            remaining -= n;
                            bi = e.contiguous ? bi + 1 : nextBlock(bi);
                        }
                        if (remaining > 0) throw new IOException("STFS: truncated file " + rel + ": block chain ended at " + (e.length - remaining) + " of " + e.length + " bytes");
                    }
                    // (Caza ronda 6, A4-R6-03.) Comprobacion final: el
                    // archivo en disco debe medir exactamente lo que la
                    // tabla promete, aunque el bucle de arriba no fallara.
                    if (out.length() != e.length) throw new IOException("STFS: truncated file " + rel + ": wrote " + out.length() + " of " + e.length + " bytes");
                    if (progress != null) progress.onProgress(rel, done, total);
                } else {
                    done += e.length;
                    if (progress != null) progress.onProgress(rel, done, total);
                }
                if (out.getName().equalsIgnoreCase("default.xex")) xex = out;
            }
            return xex;
        }
    }

    // ------------------------------------------------------------------ SVOD

    /**
     * GDFX sector source over a Games-on-Demand container. {@code hdr} is the
     * 0x400-byte package header, {@code files} the data fragments in order
     * (just the header file for the single-file layout).
     */
    public static final class Svod implements IsoExtractor.SectorSource {
        private static final long BPF = 0x14388, MAXF = 0xA290000L;
        private final List<FileChannel> files;
        private final List<ParcelFileDescriptor> pfds;
        private final boolean egdf;
        private final long startDataBlock;
        private final String layout;
        private final ByteBuffer vd;

        public Svod(ByteBuffer hdr, List<ParcelFileDescriptor> pfds) throws IOException {
            this.pfds = pfds;
            files = new ArrayList<>();
            for (ParcelFileDescriptor p : pfds) files.add(new FileInputStream(p.getFileDescriptor()).getChannel());
            int v = 0x379;
            egdf = (hdr.get(v + 0x18) & 0x40) != 0;
            startDataBlock = u24le(hdr, v + 0x1C);
            int dataFileCount = hdr.getInt(0x39D);
            FileChannel f0 = files.get(0);
            long magicOff;
            if (egdf) {
                if (!magicAt(f0, 0x2000)) throw new IOException("GoD: EGDF layout but no GDFX magic at 0x2000");
                layout = "egdf"; magicOff = 0x2000;
            } else if (magicAt(f0, 0x12000)) {
                layout = "xsf"; magicOff = 0x12000;
            } else if (magicAt(f0, 0xD000)) {
                if (dataFileCount > 1) throw new IOException("GoD: single-file layout but header declares " + dataFileCount + " data files");
                layout = "single"; magicOff = 0xD000;
            } else {
                throw new IOException("GoD: GDFX magic block not found");
            }
            vd = ByteBuffer.allocate(0x800).order(ByteOrder.LITTLE_ENDIAN);
            while (vd.hasRemaining()) { if (f0.read(vd, magicOff + vd.position()) <= 0) break; }
            vd.flip();
            // (Hunt v1.4.6 ronda 4, A4-R4-12.) Same truncated-descriptor
            // hole as IsoExtractor.list(): a GoD cut short after the 20
            // magic bytes left vd short, and the getInt(0x14/0x18) calls
            // in list() threw BufferUnderflowException (unchecked). Fail
            // here, at open time, with a clean IOException instead.
            if (vd.limit() < 0x1C) throw new IOException("GoD: truncated volume descriptor");
        }

        private static boolean magicAt(FileChannel f, long off) throws IOException {
            if (off + 20 > f.size()) return false;
            ByteBuffer m = ByteBuffer.allocate(20);
            // (Caza ronda 7, A4-R7-05.) Same family as A4-R6-09: the old
            // code ignored f.read()'s return, so a short read (a SAF
            // provider handing back fewer bytes than f.size() promises)
            // degraded to "no magic at this offset" and the Svod
            // constructor ended up throwing "GDFX magic block not
            // found" -- the wrong diagnosis for a truncated container.
            // Loop until the 20 bytes are in, like readAt()/readHeader()
            // do elsewhere in this file; a short read is a truncated
            // file, so say so (distinct message from the constructor's
            // "not found"). The size guard above still returns false
            // when the offset is out of range by the file's own size.
            while (m.hasRemaining()) {
                if (f.read(m, off + m.position()) <= 0)
                    throw new IOException("GoD: truncated GDFX magic block at offset 0x"
                            + Long.toHexString(off) + " (short read, file truncated?)");
            }
            m.flip();
            return IsoExtractor.isGdfxMagic(m);
        }

        /** -> {fragment index, byte offset in that fragment} */
        private long[] blockToOffset(long block) {
            long tb = block - startDataBlock * 2 + (egdf ? 2 : 0);
            long fb = tb % BPF, fi = tb / BPF;
            long l0 = fb / 0x198 + 1;
            long offset = l0 * 0x1000 + (l0 / 0xA1C4 + 1) * 0x1000;
            if (layout.equals("single")) offset += 0xB000;
            long addr = fb * 0x800 + offset;
            if (addr >= MAXF) { fi += 1; addr = addr % MAXF + 0x2000; }
            return new long[]{fi, addr};
        }

        @Override public ByteBuffer volumeDescriptor() { return vd.duplicate().order(ByteOrder.LITTLE_ENDIAN); }

        @Override public void read(long sector, ByteBuffer dst) throws IOException {
            int count = (dst.remaining() + 0x7FF) / 0x800;
            int i = 0;
            while (i < count && dst.hasRemaining()) {
                long[] fa = blockToOffset(sector + i);
                int run = 1;
                while (i + run < count) {
                    long[] nx = blockToOffset(sector + i + run);
                    if (nx[0] != fa[0] || nx[1] != fa[1] + run * 0x800L) break;
                    run++;
                }
                // (Ronda 8, auditor F - R8-F3.) blockToOffset() puede
                // devolver fragmento u offset NEGATIVOS cuando el sector
                // pedido cae por debajo del primer bloque de datos (vd
                // corrupto/truncado con un rootSector basura: tb < 0; en
                // Java % y / truncan hacia cero, asi que tb negativo da
                // fi <= 0 y addr negativo, mientras extract.py usa //
                // y % con signo de divisor). El guard solo miraba
                // fa[0] >= size, asi que un fi negativo llegaba a
                // files.get(-n) (IndexOutOfBoundsException) o un addr
                // negativo a FileChannel.read (IllegalArgumentException):
                // excepciones no chequeadas que el import solo reporta
                // como err_generic (misma familia que R6-F4). Un sector
                // valido nunca mapea negativo.
                if (fa[0] < 0 || fa[0] >= files.size() || fa[1] < 0) throw new IOException("GoD: block maps outside the container (sector " + (sector + i) + ", truncated/corrupt?)");
                FileChannel f = files.get((int) fa[0]);
                int want = (int) Math.min(run * 0x800L, dst.remaining());
                ByteBuffer slice = dst.duplicate();
                slice.limit(dst.position() + want);
                long off = fa[1];
                while (slice.hasRemaining()) {
                    int n = f.read(slice, off);
                    if (n <= 0) throw new IOException("GoD: short read in fragment " + fa[0]);
                    off += n;
                }
                dst.position(dst.position() + want);
                i += run;
            }
        }

        @Override public void close() {
            for (FileChannel f : files) try { f.close(); } catch (IOException ignored) { }
            for (ParcelFileDescriptor p : pfds) try { p.close(); } catch (IOException ignored) { }
        }
    }

    // ------------------------------------------------------------- SAF glue

    /** A CON/LIVE/PIRS header found while scanning a picked folder. */
    public static final class Found {
        public final Uri headerDoc; public final String name; public final ByteBuffer hdr; public final Uri dataDirDoc;
        Found(Uri h, String n, ByteBuffer b, Uri d) { headerDoc = h; name = n; hdr = b; dataDirDoc = d; }
        public int volumeType() { return StfsExtractor.volumeType(hdr); }
    }

    /**
     * Walk a picked document tree (depth-bounded) looking for a package header,
     * preferring an SVOD header with its '.data' folder beside it (a GoD dump).
     */
    public static Found findInTree(ContentResolver cr, Uri tree, String docId, int depth) {
        if (depth > 5) return null;
        Uri children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, docId);
        List<String[]> rows = new ArrayList<>();
        try (Cursor c = cr.query(children, new String[]{
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_SIZE}, null, null, null)) {
            while (c != null && c.moveToNext()) rows.add(new String[]{c.getString(0), c.getString(1), c.getString(2), c.getString(3)});
        } catch (Exception e) {
            return null;
        }
        Map<String, String> dirs = new HashMap<>();
        for (String[] r : rows) if (DocumentsContract.Document.MIME_TYPE_DIR.equals(r[2]) && r[1] != null) dirs.put(r[1], r[0]);
        Found best = null;
        for (String[] r : rows) {
            if (DocumentsContract.Document.MIME_TYPE_DIR.equals(r[2])) continue;
            long size = 0;
            try { size = r[3] == null ? 0 : Long.parseLong(r[3]); } catch (NumberFormatException ignored) { }
            if (size > 0 && size < 0x3B0) continue;
            Uri doc = DocumentsContract.buildDocumentUriUsingTree(tree, r[0]);
            ByteBuffer hdr;
            try (ParcelFileDescriptor pfd = cr.openFileDescriptor(doc, "r")) {
                if (pfd == null) continue;
                try (FileChannel ch = new FileInputStream(pfd.getFileDescriptor()).getChannel()) {
                    // (Hunt v1.4.6 ronda 8, A4-R8-03.) readHeader tira
                    // IOException en lectura corta (paquete truncado);
                    // aqui se traga a proposito y el archivo se salta,
                    // igual que un no-paquete: esto es un escaneo de
                    // carpeta buscando CUALQUIER paquete valido, y un
                    // candidato truncado no debe abortar la busqueda de
                    // los demas. Si la carpeta solo contiene el
                    // truncado, el import termina en "no se encontro el
                    // juego en la carpeta" -- diagnostico menos preciso
                    // que en importPackage (fichero unico, donde el
                    // throw si llega al usuario), pero abortar el
                    // escaneo seria peor: una carpeta puede tener el
                    // truncado Y el valido. Decision documentada.
                    hdr = readHeader(ch);
                }
            } catch (Exception e) {
                continue;
            }
            if (hdr == null) continue;
            String dataDirId = dirs.get(r[1] + ".data");
            Uri dataDir = dataDirId == null ? null : DocumentsContract.buildDocumentUriUsingTree(tree, dataDirId);
            Found f = new Found(doc, r[1], hdr, dataDir);
            if (volumeType(hdr) == VOLUME_SVOD && dataDir != null) return f;
            if (best == null) best = f;
        }
        for (String[] r : rows) {
            if (!DocumentsContract.Document.MIME_TYPE_DIR.equals(r[2]) || (r[1] != null && r[1].endsWith(".data"))) continue;
            Found f = findInTree(cr, tree, r[0], depth + 1);
            if (f != null && (f.volumeType() == VOLUME_SVOD && f.dataDirDoc != null)) return f;
            if (best == null) best = f;
        }
        return best;
    }

    /** Open an SVOD container: header + (optional) .data fragments, sorted by name. */
    public static IsoExtractor openSvod(ContentResolver cr, Found f, Uri tree) throws IOException {
        int dataFileCount = f.hdr.getInt(0x39D);
        List<ParcelFileDescriptor> pfds = new ArrayList<>();
        try {
            if (dataFileCount <= 1) {
                // (Ronda 5, auditor F — R5-F2.) openFileDescriptor() puede devolver
                // null; el null entraba en pfds y el constructor Svod tiraba NPE
                // en new FileInputStream(p.getFileDescriptor()).
                ParcelFileDescriptor pfd = cr.openFileDescriptor(f.headerDoc, "r");
                if (pfd == null) throw new IOException("GoD: cannot open " + f.headerDoc);
                pfds.add(pfd);
            } else {
                if (f.dataDirDoc == null) throw new IOException("GoD: '" + f.name + ".data' folder not found next to the header - pick the folder that holds both");
                String dataId = DocumentsContract.getDocumentId(f.dataDirDoc);
                Uri children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, dataId);
                List<String[]> parts = new ArrayList<>();
                try (Cursor c = cr.query(children, new String[]{
                        DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                        DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                        DocumentsContract.Document.COLUMN_MIME_TYPE}, null, null, null)) {
                    while (c != null && c.moveToNext()) {
                        if (DocumentsContract.Document.MIME_TYPE_DIR.equals(c.getString(2))) continue;
                        // (Ronda 8, auditor F - R8-F4.) Solo los fragmentos
                        // DataNNNN son datos: un archivo extra en .data
                        // (Thumbs.db, desktop.ini, .DS_Store) hacia fallar
                        // el import con "incomplete copy?" aunque todos los
                        // fragmentos estuvieran presentes. Los fragmentos
                        // GoD se llaman siempre Data0000..DataNNNN
                        // (extract.py:682). El sort null-safe de R6-F5 se
                        // mantiene: un nombre null simplemente no casa.
                        String nm = c.getString(1);
                        if (nm != null && nm.matches("(?i)Data\\d+")) parts.add(new String[]{c.getString(0), nm});
                    }
                }
                // (Ronda 6, auditor F — R6-F5.) DISPLAY_NAME puede ser null en
                // algunos providers; el comparador tiraba NPE y el import GoD
                // multipart moria con err_generic.
                Collections.sort(parts, (a, b) -> {
                    if (a[1] == null) return b[1] == null ? 0 : -1;
                    if (b[1] == null) return 1;
                    return a[1].compareTo(b[1]);
                });
                if (parts.size() != dataFileCount)
                    throw new IOException("GoD: header expects " + dataFileCount + " data files, folder holds " + parts.size() + " (incomplete copy?)");
                // (Caza ronda 6, A4-R6-11.) El conteo solo no basta: una
                // carpeta con el numero justo pero la secuencia rota (falta
                // Data0000 y sobra Data0005) desplazaba todo el volumen
                // sin error legible, porque Svod lee por orden de nombre.
                // Exigir exactamente Data0000..Data{count-1}.
                for (int i = 0; i < parts.size(); i++) {
                    String num = Integer.toString(i);
                    while (num.length() < 4) num = "0" + num;
                    String want = "Data" + num;
                    if (!want.equalsIgnoreCase(parts.get(i)[1]))
                        throw new IOException("GoD: data files out of sequence: expected " + want + ", found " + parts.get(i)[1] + " (incomplete copy?)");
                }
                for (String[] part : parts) {
                    // (Ronda 5, auditor F — R5-F2.) Igual que el header: un pfd
                    // null aqui llegaba al constructor Svod y tiraba NPE.
                    ParcelFileDescriptor pfd = cr.openFileDescriptor(DocumentsContract.buildDocumentUriUsingTree(tree, part[0]), "r");
                    if (pfd == null) throw new IOException("GoD: cannot open data file " + part[1]);
                    pfds.add(pfd);
                }
            }
            return new IsoExtractor(new Svod(f.hdr, pfds));
        } catch (IOException | RuntimeException e) {
            // (Ronda 6, auditor F — R6-F3.) Si un openFileDescriptor posterior
            // tira, o el constructor Svod rechaza el contenedor (magia
            // ausente), los pfds ya abiertos quedaban sin cerrar: cada
            // intento fallido dejaba fds abiertos. En exito la propiedad
            // pasa a Svod (su close() los cierra), asi que aqui solo se
            // cierra en el camino de error.
            for (ParcelFileDescriptor q : pfds) {
                if (q != null) { try { q.close(); } catch (IOException ignored) { } }
            }
            throw e;
        }
    }
}
