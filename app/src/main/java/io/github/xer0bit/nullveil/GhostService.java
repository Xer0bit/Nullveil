// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.xer0bit.nullveil;

import android.annotation.SuppressLint;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.location.Location;
import android.location.LocationManager;
import android.location.Criteria;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.SystemClock;

import java.util.Random;

/**
 * Ghost mode: feeds a different position to every app (through Android's test-location providers).
 * Android only lets an app do this after a one-time unlock (see SETUP > Ghost mode access).
 * Apps can still detect mock locations if they look for the flag.
 */
public class GhostService extends Service {
    static final String ACTION_STOP = "io.github.xer0bit.nullveil.GHOST_STOP";
    static final String LAT = "lat", LON = "lon";
    private static final String[] PROVIDERS = {LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER};

    static volatile boolean running;
    static volatile String error = "";

    private final Handler h = new Handler(Looper.getMainLooper());
    private final Random rnd = new Random();
    private LocationManager lm;
    private double lat, lon;

    private final Runnable push = new Runnable() {
        @Override
        public void run() {
            try {
                for (String p : PROVIDERS) {
                    Location l = new Location(p);
                    l.setLatitude(lat + (rnd.nextDouble() - 0.5) * 4e-5); // ~2 m of natural jitter
                    l.setLongitude(lon + (rnd.nextDouble() - 0.5) * 4e-5);
                    l.setAccuracy(5f);
                    l.setTime(System.currentTimeMillis());
                    l.setElapsedRealtimeNanos(SystemClock.elapsedRealtimeNanos());
                    lm.setTestProviderLocation(p, l);
                }
                error = "";
            } catch (SecurityException e) {
                error = "Ghost mode is locked. Open SETUP > Ghost mode access.";
                stop();
                return;
            } catch (RuntimeException e) {
                error = "Could not set location: " + e.getClass().getSimpleName();
            }
            h.postDelayed(this, 1000);
        }
    };

    // Criteria.POWER_LOW/ACCURACY_FINE == ProviderProperties.POWER_USAGE_LOW/ACCURACY_FINE (both 1); the new class needs API 31.
    @SuppressLint("WrongConstant")
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null || ACTION_STOP.equals(intent.getAction())) {
            stop();
            return START_NOT_STICKY;
        }
        lat = intent.getDoubleExtra(LAT, 0);
        lon = intent.getDoubleExtra(LON, 0);
        foreground();
        lm = getSystemService(LocationManager.class);
        try {
            for (String p : PROVIDERS) {
                try {
                    lm.removeTestProvider(p);
                } catch (IllegalArgumentException ignored) {
                    // none registered yet
                }
                lm.addTestProvider(p, false, false, false, false, true, true, true, Criteria.POWER_LOW, Criteria.ACCURACY_FINE);
                lm.setTestProviderEnabled(p, true);
            }
        } catch (SecurityException e) {
            error = "Ghost mode is locked. Open SETUP > Ghost mode access.";
            stop();
            return START_NOT_STICKY;
        }
        running = true;
        h.removeCallbacks(push);
        h.post(push);
        return START_NOT_STICKY;
    }

    private void foreground() {
        NotificationChannel ch = new NotificationChannel("ghost", "Ghost location", NotificationManager.IMPORTANCE_LOW);
        getSystemService(NotificationManager.class).createNotificationChannel(ch);
        Notification n = new Notification.Builder(this, "ghost")
                .setSmallIcon(R.drawable.ic_stat_veil)
                .setContentTitle("Nullveil ghost location is on")
                .setOngoing(true)
                .build();
        if (Build.VERSION.SDK_INT >= 34) startForeground(2, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        else startForeground(2, n);
    }

    private void stop() {
        running = false;
        h.removeCallbacks(push);
        if (lm != null) {
            for (String p : PROVIDERS) {
                try {
                    lm.removeTestProvider(p);
                } catch (RuntimeException ignored) {
                    // not registered or not allowed
                }
            }
        }
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    @Override
    public void onDestroy() {
        stop();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
