// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.xer0bit.nullveil;

import android.app.AppOpsManager;
import android.app.usage.UsageEvents;
import android.app.usage.UsageStatsManager;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.PowerManager;
import android.os.Process;
import android.os.SystemClock;

import java.util.concurrent.ConcurrentHashMap;

/** Is an app in the background? Which sensitive permissions does it hold? */
final class Watch {
    static final int MIC = 1, CAM = 2, LOC = 4;

    private static volatile String foreground;
    private static long since;
    private static final ConcurrentHashMap<String, long[]> PERMS = new ConcurrentHashMap<>(); // pkg -> {perms, ms}

    private Watch() {}

    private static volatile long usageCheckedAt = -10_000;
    private static volatile boolean usageCached;

    /** usageAccess() costs a system call; the answer rarely changes, so reuse it for 3 s per lookup. */
    private static boolean usageAccessCached(Context c) {
        long now = SystemClock.elapsedRealtime();
        if (now - usageCheckedAt > 3000) {
            usageCached = usageAccess(c);
            usageCheckedAt = now;
        }
        return usageCached;
    }

    static String foreground() {
        return foreground;
    }

    @SuppressWarnings("deprecation")
    static boolean usageAccess(Context c) {
        AppOpsManager a = c.getSystemService(AppOpsManager.class);
        return a.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), c.getPackageName())
                == AppOpsManager.MODE_ALLOWED;
    }

    /** Track which app is in front, from usage events (needs Usage Access). */
    static void poll(Context c) {
        if (!usageAccess(c)) return;
        long now = System.currentTimeMillis();
        long from = since == 0 ? now - 600_000 : since;
        since = now;
        UsageEvents ev = c.getSystemService(UsageStatsManager.class).queryEvents(from, now);
        UsageEvents.Event e = new UsageEvents.Event();
        while (ev.hasNextEvent()) {
            ev.getNextEvent(e);
            if (e.getEventType() == UsageEvents.Event.ACTIVITY_RESUMED) foreground = e.getPackageName();
            else if (e.getEventType() == UsageEvents.Event.ACTIVITY_PAUSED && e.getPackageName().equals(foreground)) foreground = null;
        }
    }

    /**
     * Screen off = everything is background. Screen on = background only for a known app that is
     * not the one in front (needs Usage Access; without it we cannot tell, so we say no).
     */
    static boolean background(Context c, String app) {
        if (!c.getSystemService(PowerManager.class).isInteractive()) return true;
        if (app.equals(c.getPackageName()) || app.equals("?") || app.startsWith("uid:")) return false;
        return usageAccessCached(c) && !app.equals(foreground);
    }

    static int perms(Context c, String pkg) {
        long now = System.currentTimeMillis();
        long[] hit = PERMS.get(pkg);
        if (hit != null && now - hit[1] < 60_000) return (int) hit[0];
        int p = 0;
        try {
            p = permsOf(c.getPackageManager().getPackageInfo(pkg, PackageManager.GET_PERMISSIONS));
        } catch (PackageManager.NameNotFoundException | RuntimeException ignored) {
            // unknown package: no permissions known
        }
        PERMS.put(pkg, new long[]{p, now});
        return p;
    }

    static int permsOf(PackageInfo pi) {
        int p = 0;
        if (pi.requestedPermissions == null) return 0;
        for (int i = 0; i < pi.requestedPermissions.length; i++) {
            if ((pi.requestedPermissionsFlags[i] & PackageInfo.REQUESTED_PERMISSION_GRANTED) == 0) continue;
            switch (pi.requestedPermissions[i]) {
                case "android.permission.RECORD_AUDIO": p |= MIC; break;
                case "android.permission.CAMERA": p |= CAM; break;
                case "android.permission.ACCESS_FINE_LOCATION":
                case "android.permission.ACCESS_COARSE_LOCATION":
                case "android.permission.ACCESS_BACKGROUND_LOCATION": p |= LOC; break;
                default: break;
            }
        }
        return p;
    }
}
