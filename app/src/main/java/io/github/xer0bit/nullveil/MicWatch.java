// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.xer0bit.nullveil;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.media.AudioManager;
import android.media.AudioRecordingConfiguration;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

/**
 * Notices when ANY app records audio and whether you were using an app at the time. Android hides
 * which app it was from regular apps, so this tells you "when" and "what was in front", and the
 * Apps tab lists who could have done it. In memory only.
 */
final class MicWatch {
    static final class Entry {
        final long start = System.currentTimeMillis();
        long end;
        final boolean suspicious;
        final String where;
        volatile boolean silenced;

        Entry(boolean suspicious, String where) {
            this.suspicious = suspicious;
            this.where = where;
        }
    }

    private static final int MAX = 40;
    private static final ArrayDeque<Entry> LOG = new ArrayDeque<>();
    private static AudioManager.AudioRecordingCallback callback;

    static volatile boolean active;
    static volatile String where = "";
    static volatile boolean suspicious;
    static volatile boolean silenced; // Mic Guard is giving the recording app silence

    private MicWatch() {}

    static synchronized List<Entry> recent() {
        return new ArrayList<>(LOG);
    }

    private static int users;

    static synchronized void start(Context app) {
        if (users++ > 0) return;
        callback = new AudioManager.AudioRecordingCallback() {
            @Override
            public void onRecordingConfigChanged(List<AudioRecordingConfiguration> configs) {
                evaluate(app, configs);
            }
        };
        AudioManager am = app.getSystemService(AudioManager.class);
        am.registerAudioRecordingCallback(callback, new Handler(Looper.getMainLooper()));
        evaluate(app, am.getActiveRecordingConfigurations());
    }

    static synchronized void stop(Context app) {
        if (users == 0 || --users > 0) return;
        app.getSystemService(AudioManager.class).unregisterAudioRecordingCallback(callback);
        callback = null;
        active = false;
    }

    /** Recordings by OTHER apps only: our own Mic Guard capture does not count. */
    private static void evaluate(Context c, List<AudioRecordingConfiguration> configs) {
        boolean other = false, allSilenced = true;
        for (AudioRecordingConfiguration cfg : configs) {
            if (cfg.getClientAudioSessionId() == MicGuardService.sessionId) continue;
            other = true;
            if (Build.VERSION.SDK_INT < 29 || !cfg.isClientSilenced()) allSilenced = false;
        }
        changed(c, other, other && allSilenced && MicGuardService.running);
    }

    private static synchronized void changed(Context c, boolean now, boolean blocked) {
        if (now && !active) {
            boolean screenOn = c.getSystemService(PowerManager.class).isInteractive();
            String fg = Watch.foreground();
            if (!screenOn) {
                where = "screen off";
                suspicious = true;
            } else if (!Watch.usageAccess(c)) {
                where = "screen on (grant usage access to see what was in front)";
                suspicious = false;
            } else if (fg == null || fg.equals(c.getPackageName()) || fg.equals(homePackage(c))) {
                where = "you were on the home screen";
                suspicious = true;
            } else {
                where = "in front: " + fg;
                suspicious = false;
            }
            active = true;
            silenced = blocked;
            LOG.addFirst(new Entry(suspicious, where));
            LOG.getFirst().silenced = blocked;
            if (LOG.size() > MAX) LOG.removeLast();
            if (suspicious) alert(c);
        } else if (now) {
            silenced = blocked; // Mic Guard may take effect a moment after the app started recording
            if (!LOG.isEmpty()) LOG.getFirst().silenced = blocked;
        } else if (active) {
            active = false;
            silenced = false;
            if (!LOG.isEmpty()) LOG.getFirst().end = System.currentTimeMillis();
        }
        Events.version.incrementAndGet();
    }

    private static String homePackage(Context c) {
        ResolveInfo ri = c.getPackageManager().resolveActivity(new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME),
                PackageManager.MATCH_DEFAULT_ONLY);
        return ri == null ? "" : ri.activityInfo.packageName;
    }

    private static void alert(Context c) {
        NotificationManager nm = c.getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel("mic", "Microphone alerts", NotificationManager.IMPORTANCE_HIGH));
        PendingIntent open = PendingIntent.getActivity(c, 0, new Intent(c, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        try {
            nm.notify(3, new Notification.Builder(c, "mic")
                    .setSmallIcon(R.drawable.ic_stat_veil)
                    .setContentTitle("Something is using your microphone")
                    .setContentText("Not an app you opened (" + where + ")." + (silenced ? " Mic Guard silenced it." : " Turn on Mic Guard to silence it."))
                    .setContentIntent(open)
                    .setAutoCancel(true)
                    .build());
        } catch (SecurityException ignored) {
            // notifications not allowed: the in-app log still has it
        }
    }
}
