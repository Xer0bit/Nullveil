// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.xer0bit.nullveil;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioRecord;
import android.media.AudioRecordingConfiguration;
import android.media.MediaRecorder;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.SystemClock;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Mic Guard: Nullveil holds the microphone with a privacy-sensitive capture, so Android's own
 * concurrent-capture policy gives every other app silence (developer.android.com/media/platform/sharing-audio-input).
 *
 * Privacy: audio is read only to keep the capture alive and is dropped on the very next line.
 * It is never stored, never sent anywhere, never analysed.
 *
 * Limits: if another app starts capturing after us it can win for a moment; we notice (our own capture
 * reports "silenced") and take the mic back at once. A phone call (telephony) always gets audio.
 */
public class MicGuardService extends Service {
    static final String ACTION_STOP = "io.github.xer0bit.nullveil.GUARD_STOP";

    static volatile boolean running;
    static volatile int sessionId = -1; // our own capture, so MicWatch does not count it as "someone else"
    static final AtomicInteger reclaims = new AtomicInteger();

    private final Object lock = new Object();
    private final Handler main = new Handler(Looper.getMainLooper());
    private volatile boolean alive;
    private AudioRecord rec;
    private AudioManager.AudioRecordingCallback callback;
    private long lastReclaim;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            shutdown();
            return START_NOT_STICKY;
        }
        if (running) return START_NOT_STICKY;
        if (checkSelfPermission(android.Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            stopSelf();
            return START_NOT_STICKY;
        }
        foreground();
        try {
            rec = open();
            rec.startRecording();
        } catch (RuntimeException e) {
            shutdown();
            return START_NOT_STICKY;
        }
        sessionId = rec.getAudioSessionId();
        alive = true;
        running = true;
        MicWatch.start(getApplicationContext());
        watchOwnCapture();
        new Thread(this::drain, "mic-guard").start();
        Events.version.incrementAndGet();
        return START_NOT_STICKY;
    }

    /** A capture the system treats as privacy-sensitive, which outranks ordinary apps and the Assistant. */
    private AudioRecord open() {
        if (checkSelfPermission(android.Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            throw new IllegalStateException("microphone permission missing"); // caller shuts the guard down
        }
        AudioFormat f = new AudioFormat.Builder().setSampleRate(16000)
                .setChannelMask(AudioFormat.CHANNEL_IN_MONO).setEncoding(AudioFormat.ENCODING_PCM_16BIT).build();
        int min = AudioRecord.getMinBufferSize(16000, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT);
        AudioRecord.Builder b = new AudioRecord.Builder().setAudioFormat(f).setBufferSizeInBytes(Math.max(min, 4096));
        if (Build.VERSION.SDK_INT >= 30) {
            b.setAudioSource(MediaRecorder.AudioSource.MIC).setPrivacySensitive(true);
        } else {
            b.setAudioSource(MediaRecorder.AudioSource.VOICE_COMMUNICATION); // privacy-sensitive by default before Android 11
        }
        return b.build();
    }

    /** Keeps the capture alive. The audio is discarded immediately. */
    private void drain() {
        byte[] buf = new byte[4096];
        while (alive) {
            AudioRecord r;
            synchronized (lock) {
                r = rec;
            }
            if (r == null || r.read(buf, 0, buf.length) < 0) SystemClock.sleep(100); // read result and buffer are never used
        }
    }

    /** If the system silences us because another app started capturing after us, start again to take the mic back. */
    private void watchOwnCapture() {
        if (Build.VERSION.SDK_INT < 29) return;
        callback = new AudioManager.AudioRecordingCallback() {
            @Override
            public void onRecordingConfigChanged(List<AudioRecordingConfiguration> configs) {
                for (AudioRecordingConfiguration c : configs) {
                    if (c.getClientAudioSessionId() == sessionId && c.isClientSilenced()) reclaim();
                }
            }
        };
        getSystemService(AudioManager.class).registerAudioRecordingCallback(callback, main);
    }

    // ponytail: restarts at most every 400 ms, even if a phone call keeps silencing us; add backoff if that ever costs battery
    private void reclaim() {
        long now = SystemClock.elapsedRealtime();
        if (now - lastReclaim < 400) return;
        lastReclaim = now;
        synchronized (lock) {
            try {
                rec.stop();
                rec.startRecording();
                reclaims.incrementAndGet();
            } catch (RuntimeException ignored) {
                // capture already released
            }
        }
        Events.version.incrementAndGet();
    }

    private void foreground() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel("guard", "Mic Guard", NotificationManager.IMPORTANCE_LOW));
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        PendingIntent stop = PendingIntent.getService(this, 1, new Intent(this, MicGuardService.class).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE);
        Notification n = new Notification.Builder(this, "guard")
                .setSmallIcon(R.drawable.ic_stat_veil)
                .setContentTitle("Mic Guard is on")
                .setContentText("Other apps hear silence. Nullveil discards the audio.")
                .setContentIntent(open)
                .addAction(new Notification.Action.Builder(null, "Stop", stop).build())
                .setOngoing(true)
                .build();
        if (Build.VERSION.SDK_INT >= 30) startForeground(4, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE);
        else startForeground(4, n);
    }

    private void shutdown() {
        alive = false;
        running = false;
        sessionId = -1;
        if (callback != null) {
            getSystemService(AudioManager.class).unregisterAudioRecordingCallback(callback);
            callback = null;
        }
        synchronized (lock) {
            if (rec != null) {
                try {
                    rec.stop();
                } catch (IllegalStateException ignored) {
                    // never started
                }
                rec.release();
                rec = null;
            }
        }
        MicWatch.stop(getApplicationContext());
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
        Events.version.incrementAndGet();
    }

    @Override
    public void onDestroy() {
        if (running || rec != null) shutdown();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
