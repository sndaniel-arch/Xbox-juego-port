package com.rexauto.port;

import android.content.ContentResolver;
import android.net.Uri;
import android.os.ParcelFileDescriptor;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/**
 * Xbox 360 disc image (GDFX / XDVDFS) extractor; also the extraction engine for GoD via StfsExtractor.Svod - a Java port of the reader in
 * rexauto's extract.py. Handles plain ISOs and the usual redump/XGD offsets.
 * Also copies a bare default.xex or a folder pick through unchanged.
 */
public final class IsoExtractor {
    private static final byte[] GDFX_MAGIC = "MICROSOFT*XBOX*MEDIA".getBytes();
    private static final long[] BASES = {0L, 0xFD90000L, 0x2080000L, 0x18300000L, 0xB000L};
    private static final int SECTOR = 0x800;

    public interface Progress {
        void onProgress(String status, long doneBytes, long totalBytes);
    }

    public static final class Entry {
        final String rel; final long sector; final long size;
        Entry(String rel, long sector, long size) { this.rel = rel; this.sector = sector; this.size = size; }
    }

    /** Random-access source of 2 KB GDFX sectors (plain ISO or an SVOD/GoD layout). */
    public interface SectorSource {
        void read(long sector, ByteBuffer dst) throws IOException;
        /** Volume descriptor if the layout knows where it is (SVOD); null = sector 32. */
        default ByteBuffer volumeDescriptor() throws IOException { return null; }
        void close();
    }

    private final SectorSource src;

    IsoExtractor(SectorSource src) { this.src = src; }

    /** Opens a content:// or file path as an ISO; returns null if it is not GDFX. */
    public static IsoExtractor open(ContentResolver cr, Uri uri) throws IOException {
        ParcelFileDescriptor pfd = cr.openFileDescriptor(uri, "r");
        if (pfd == null) throw new IOException("cannot open " + uri);
        FileChannel ch = new FileInputStream(pfd.getFileDescriptor()).getChannel();
        try {
            for (long b : BASES) {
                if (b + 0x10000 + 20 > ch.size()) continue;
                ByteBuffer m = ByteBuffer.allocate(20);
                ch.read(m, b + 0x10000);
                if (java.util.Arrays.equals(m.array(), GDFX_MAGIC)) {
                    final long base = b;
                    return new IsoExtractor(new SectorSource() {
                        @Override public void read(long sector, ByteBuffer dst) throws IOException {
                            long off = base + sector * SECTOR;
                            while (dst.hasRemaining()) {
                                int n = ch.read(dst, off + dst.position());
                                if (n <= 0) break;
                            }
                            // (Ronda 7, auditor F — R7-F3.) Un ISO truncado
                            // dejaba el resto del sector a ceros (el buffer
                            // se aloca a ceros) y extractAll() los escribia
                            // como si fueran datos reales: el default.xex
                            // salia con la longitud correcta pero relleno de
                            // ceros, y el fallo solo aparecia despues como
                            // err_xex_unreadable. El camino GoD (Svod.read)
                            // SI tira en lectura corta; este era el unico
                            // SectorSource que tragaba el truncado en silencio.
                            if (dst.hasRemaining()) throw new IOException("short read at sector " + sector + " (truncated ISO?)");
                        }
                        @Override public void close() { try { ch.close(); pfd.close(); } catch (IOException ignored) { } }
                    });
                }
            }
        } catch (IOException | RuntimeException e) {
            // (Ronda 6, auditor F — R6-F1.) ch.size()/ch.read() pueden tirar
            // a mitad del escaneo (I/O del provider SAF): sin este catch el
            // canal y el ParcelFileDescriptor quedaban abiertos en cada
            // intento fallido. En exito el return de dentro no pasa por
            // aqui: el SectorSource devuelto es quien los cierra.
            try { ch.close(); } catch (IOException ignored) { }
            try { pfd.close(); } catch (IOException ignored) { }
            throw e;
        }
        ch.close();
        pfd.close();
        return null;
    }

    static boolean isGdfxMagic(ByteBuffer b) {
        if (b.limit() < 20) return false;
        for (int i = 0; i < 20; i++) if (b.get(i) != GDFX_MAGIC[i]) return false;
        return true;
    }

    private ByteBuffer readSector(long sector, int nbytes) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(nbytes).order(ByteOrder.LITTLE_ENDIAN);
        src.read(sector, buf);
        buf.flip();
        return buf;
    }

    public List<Entry> list() throws IOException {
        ByteBuffer vd = src.volumeDescriptor();
        if (vd == null) vd = readSector(32, SECTOR);
        vd.order(ByteOrder.LITTLE_ENDIAN);
        if (!isGdfxMagic(vd)) throw new IOException("no GDFX volume (unsupported layout)");
        // (Hunt v1.4.6 ronda 4, A4-R4-12.) A truncated GoD volume
        // descriptor (magic present, fewer than 0x1C bytes) made the two
        // getInt() calls below throw BufferUnderflowException (unchecked)
        // instead of a clean "truncated file" error. The plain-ISO path
        // already throws IOException on a short sector read (R7-F3); the
        // SVOD descriptor is built with a break-on-short-read loop, so
        // guard the length here too (Svod's constructor guards its own
        // build as well).
        if (vd.remaining() < 0x1C) throw new IOException("truncated volume descriptor");
        long rootSector = vd.getInt(0x14) & 0xFFFFFFFFL;
        long rootSize = vd.getInt(0x18) & 0xFFFFFFFFL;
        List<Entry> out = new ArrayList<>();
        walk(rootSector, rootSize, "", out, 0);
        return out;
    }

    private void walk(long sector, long size, String prefix, List<Entry> out, int depth) throws IOException {
        if (depth > 16 || size <= 0 || size > (64L << 20)) return;
        int n = (int) ((size + 0x7FF) & ~0x7FFL);
        ByteBuffer d = readSector(sector, n);
        HashSet<Integer> seen = new HashSet<>();
        ArrayDeque<Integer> stack = new ArrayDeque<>();
        stack.push(0);
        while (!stack.isEmpty()) {
            int pos = stack.pop();
            if (!seen.add(pos)) continue;
            int o = pos * 4;
            if (o + 0x0E > d.limit()) continue;
            int left = d.getShort(o) & 0xFFFF, right = d.getShort(o + 2) & 0xFFFF;
            long sec = d.getInt(o + 4) & 0xFFFFFFFFL, sz = d.getInt(o + 8) & 0xFFFFFFFFL;
            int attr = d.get(o + 0x0C) & 0xFF, nlen = d.get(o + 0x0D) & 0xFF;
            if (o + 0x0E + nlen > d.limit()) continue;
            byte[] nb = new byte[nlen];
            for (int i = 0; i < nlen; i++) nb[i] = d.get(o + 0x0E + i);
            String name = new String(nb, java.nio.charset.StandardCharsets.ISO_8859_1);
            if (left != 0 && left != 0xFFFF) stack.push(left);
            if (right != 0 && right != 0xFFFF) stack.push(right);
            if (name.isEmpty() || name.equals(".") || name.equals("..") || name.contains("/") || name.contains("\\")) continue;
            String rel = prefix.isEmpty() ? name : prefix + "/" + name;
            if ((attr & 0x10) != 0) {
                if (sz > 0) walk(sec, sz, rel, out, depth + 1);
            } else {
                out.add(new Entry(rel, sec, sz));
            }
        }
    }

    /** Extracts everything into dest; returns the path of default.xex or null. */
    public File extractAll(File dest, Progress progress) throws IOException {
        List<Entry> files = list();
        long total = 0;
        for (Entry e : files) total += e.size;
        long done = 0;
        File xex = null;
        byte[] chunk = new byte[1 << 20];
        for (Entry e : files) {
            File out = new File(dest, e.rel);
            if (!out.getCanonicalPath().startsWith(dest.getCanonicalPath())) continue;
            File parent = out.getParentFile();
            if (parent != null && !parent.isDirectory() && !parent.mkdirs()) throw new IOException("mkdir " + parent);
            if (!(out.isFile() && out.length() == e.size)) {
                try (OutputStream os = new FileOutputStream(out)) {
                    long remaining = e.size, sec = e.sector;
                    while (remaining > 0) {
                        int n = (int) Math.min(chunk.length, remaining);
                        int padded = (n + 0x7FF) & ~0x7FF;
                        ByteBuffer b = readSector(sec, padded);
                        os.write(b.array(), 0, n);
                        remaining -= n;
                        sec += padded / SECTOR;
                        done += n;
                        if (progress != null) progress.onProgress(e.rel, done, total);
                    }
                }
            } else {
                done += e.size;
                if (progress != null) progress.onProgress(e.rel, done, total);
            }
            if (out.getName().equalsIgnoreCase("default.xex")) xex = out;
        }
        return xex;
    }

    public void close() { src.close(); }

    /** Plain stream copy used for a picked default.xex / loose files. */
    public static void copyStream(InputStream in, File dest) throws IOException {
        File parent = dest.getParentFile();
        if (parent != null) parent.mkdirs();
        try (OutputStream out = new FileOutputStream(dest)) {
            byte[] buf = new byte[1 << 20];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        }
    }
}
