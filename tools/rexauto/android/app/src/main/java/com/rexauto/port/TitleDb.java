package com.rexauto.port;

import android.content.Context;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Locale;

/** Title ID -> game name, from the bundled tools/xbox360_titles.json asset. */
public final class TitleDb {
    private static JSONObject db;

    private TitleDb() { }

    public static synchronized String lookup(Context ctx, String titleId) {
        if (titleId == null) return null;
        try {
            if (db == null) {
                try (InputStream in = ctx.getAssets().open("xbox360_titles.json")) {
                    ByteArrayOutputStream bo = new ByteArrayOutputStream();
                    byte[] buf = new byte[1 << 16];
                    int n;
                    while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
                    db = new JSONObject(bo.toString("UTF-8"));
                }
            }
            // Locale.ROOT (G-P2, ronda 2): same latent class as GpuDriver --
            // a locale-sensitive case conversion on an ASCII identifier.
            // Hex title IDs contain no 'i', so this is hygiene, not a live
            // bug; the key lookup must not depend on the device locale.
            return db.optString(titleId.toUpperCase(Locale.ROOT), null);
        } catch (Exception e) {
            return null;
        }
    }
}
