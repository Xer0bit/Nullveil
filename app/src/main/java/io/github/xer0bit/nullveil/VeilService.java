// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.xer0bit.nullveil;

import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Local VPN that captures ONLY DNS (one /32 route to a fake resolver). Everything else bypasses
 * the tunnel. Blocked names get a sinkhole answer; the rest are forwarded to the phone's own
 * DNS server, so no third-party resolver ever sees your lookups.
 */
public class VeilService extends VpnService {
    static final String ACTION_STOP = "io.github.xer0bit.nullveil.STOP";
    private static final String DNS_ADDR = "10.111.0.2";

    private ParcelFileDescriptor tun;
    private ExecutorService pool;
    private ScheduledExecutorService watcher;
    private DotClient dot;
    private int dotMode;
    private final ConcurrentHashMap<Integer, String> uidPkg = new ConcurrentHashMap<>();

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            shutdown();
        } else if (tun == null) {
            start();
        }
        return START_NOT_STICKY;
    }

    private void start() {
        InetAddress upstream = systemDns();
        if (upstream == null) {
            stopSelf();
            return;
        }
        try {
            tun = new Builder().setSession("Nullveil")
                    .addAddress("10.111.0.1", 32)
                    .addDnsServer(DNS_ADDR)
                    .addRoute(DNS_ADDR, 32)
                    .setBlocking(true)
                    .establish();
        } catch (RuntimeException e) {
            tun = null;
        }
        if (tun == null) {
            stopSelf();
            return;
        }
        Settings.applyRules(this);
        pool = Executors.newFixedThreadPool(16); // bounded: a burst of lookups cannot spawn unlimited threads
        watcher = Executors.newSingleThreadScheduledExecutor();
        watcher.scheduleWithFixedDelay(() -> Watch.poll(this), 0, 2, TimeUnit.SECONDS);
        MicWatch.start(getApplicationContext());
        Events.running = true;
        FileInputStream in = new FileInputStream(tun.getFileDescriptor());
        FileOutputStream out = new FileOutputStream(tun.getFileDescriptor());
        new Thread(() -> loop(in, out, upstream), "veil-loop").start();
    }

    private void loop(FileInputStream in, FileOutputStream out, InetAddress upstream) {
        byte[] buf = new byte[32767];
        try {
            int n;
            while ((n = in.read(buf)) >= 0) {
                byte[] pkt = Arrays.copyOf(buf, n);
                String name = Native.query(pkt);
                if (name == null) continue;
                String app = appFor(pkt);
                boolean bg = Watch.background(this, app);
                String verdict = Native.decide(name, app, bg, Watch.perms(this, app), Settings.strict(this));
                String[] v = (verdict == null ? "0|0|" : verdict).split("\\|", 3); // bad input: let it through
                boolean block = v[0].equals("1");
                int score = score(v);
                String why = v.length > 2 ? v[2] : "";
                int mode = Settings.appMode(this, app);
                if (mode == 1 && bg) { // you locked this app: no lookups while it is not in front
                    block = true;
                    score = 99;
                    why = "app locked in background by you";
                } else if (mode == 2 && block && !why.contains("blocked by you")) { // you trust this app
                    block = false;
                    why = "app trusted by you";
                }
                if (block) {
                    write(out, Native.blockedReply(pkt));
                    Events.add(app, name, true, why, score);
                } else {
                    final String fwhy = why;
                    final int fscore = score;
                    pool.execute(() -> forward(pkt, name, app, fwhy, fscore, out, upstream));
                }
            }
        } catch (IOException | RuntimeException ignored) {
            // tunnel closed (stop/revoke) or pool shut down
        }
    }

    private static int score(String[] verdict) {
        try {
            return Integer.parseInt(verdict[1]);
        } catch (NumberFormatException | ArrayIndexOutOfBoundsException e) {
            return 0;
        }
    }

    private void forward(byte[] pkt, String name, String app, String why, int score, FileOutputStream out, InetAddress upstream) {
        int off = (pkt[0] & 15) * 4 + 8; // DNS payload follows IP + UDP headers
        byte[] query = Arrays.copyOfRange(pkt, off, pkt.length);
        byte[] answer = null;
        int mode = Settings.dotMode(this);
        if (mode != 0) {
            try {
                answer = dotClient(mode).query(query);
            } catch (IOException e) {
                Events.plainFallbacks.incrementAndGet(); // resolver unreachable: fall back so the phone keeps working
            }
        }
        if (answer == null) answer = plain(query, upstream);
        if (answer == null) return; // timeout or network down: the asking app retries on its own
        write(out, Native.wrap(pkt, answer));
        Events.add(app, name, false, why, score);
    }

    private synchronized DotClient dotClient(int mode) {
        if (dot == null || dotMode != mode) {
            if (dot != null) dot.close();
            dot = new DotClient(s -> protect(s), DotClient.Resolver.values()[mode - 1]);
            dotMode = mode;
        }
        return dot;
    }

    private byte[] plain(byte[] query, InetAddress upstream) {
        try (DatagramSocket s = new DatagramSocket()) {
            protect(s); // keep our own lookups out of the tunnel
            s.setSoTimeout(3000);
            s.send(new DatagramPacket(query, query.length, upstream, 53));
            byte[] rb = new byte[4096];
            DatagramPacket resp = new DatagramPacket(rb, rb.length);
            s.receive(resp);
            return Arrays.copyOf(rb, resp.getLength());
        } catch (IOException e) {
            return null;
        }
    }

    private static void write(FileOutputStream out, byte[] packet) {
        if (packet == null) return;
        synchronized (out) {
            try {
                out.write(packet);
            } catch (IOException ignored) {
                // tunnel closed
            }
        }
    }

    /** Which app asked. Android 10+ only; the UID may belong to the system resolver, not the app. */
    private String appFor(byte[] pkt) {
        if (Build.VERSION.SDK_INT < 29) return "?";
        try {
            int ihl = (pkt[0] & 15) * 4;
            int sport = ((pkt[ihl] & 0xff) << 8) | (pkt[ihl + 1] & 0xff);
            InetSocketAddress src = new InetSocketAddress(InetAddress.getByAddress(Arrays.copyOfRange(pkt, 12, 16)), sport);
            InetSocketAddress dst = new InetSocketAddress(InetAddress.getByAddress(Arrays.copyOfRange(pkt, 16, 20)), 53);
            int uid = getSystemService(ConnectivityManager.class).getConnectionOwnerUid(17, src, dst);
            return uidPkg.computeIfAbsent(uid, u -> {
                String[] pkgs = getPackageManager().getPackagesForUid(u);
                return pkgs != null && pkgs.length > 0 ? pkgs[0] : "uid:" + u;
            });
        } catch (Exception e) {
            return "?";
        }
    }

    private InetAddress systemDns() {
        ConnectivityManager cm = getSystemService(ConnectivityManager.class);
        Network net = cm.getActiveNetwork();
        LinkProperties lp = net == null ? null : cm.getLinkProperties(net);
        if (lp == null) return null;
        List<InetAddress> dns = lp.getDnsServers();
        return dns.isEmpty() ? null : dns.get(0);
    }

    private void shutdown() {
        Events.running = false;
        MicWatch.stop(getApplicationContext());
        if (pool != null) pool.shutdownNow();
        if (watcher != null) watcher.shutdownNow();
        if (dot != null) dot.close();
        if (tun != null) {
            try {
                tun.close(); // also unblocks the read loop
            } catch (IOException ignored) {
            }
            tun = null;
        }
        stopSelf();
    }

    @Override
    public void onRevoke() {
        shutdown();
    }

    @Override
    public void onDestroy() {
        shutdown();
    }
}
