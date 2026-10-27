// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.xer0bit.nullveil;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/** In-memory only. Nothing is written to disk and nothing leaves the device. */
final class Events {
    private static final int MAX = 150;

    static final class Entry {
        final long time = System.currentTimeMillis();
        final String app, domain, why;
        final boolean blocked;
        final int score;

        Entry(String app, String domain, boolean blocked, String why, int score) {
            this.score = score;
            this.app = app;
            this.domain = domain;
            this.blocked = blocked;
            this.why = why;
        }
    }

    static final class Caught {
        final String app;
        int count;
        String lastDomain = "", why = "";

        Caught(String app) {
            this.app = app;
        }
    }

    private static final ArrayDeque<Entry> LOG = new ArrayDeque<>();
    private static final Map<String, Caught> CAUGHT = new HashMap<>();

    static volatile boolean running;
    static final AtomicInteger sunk = new AtomicInteger();
    static final AtomicInteger passed = new AtomicInteger();
    static final AtomicInteger version = new AtomicInteger();
    static final AtomicInteger plainFallbacks = new AtomicInteger();

    private Events() {}

    static synchronized void add(String app, String domain, boolean blocked, String why, int score) {
        (blocked ? sunk : passed).incrementAndGet();
        LOG.addFirst(new Entry(app, domain, blocked, why, score));
        if (LOG.size() > MAX) LOG.removeLast();
        if (blocked) {
            Caught c = CAUGHT.computeIfAbsent(app, Caught::new);
            c.count++;
            c.lastDomain = domain;
            c.why = why;
        }
        version.incrementAndGet();
    }

    static synchronized void clear() {
        LOG.clear();
        CAUGHT.clear();
        sunk.set(0);
        passed.set(0);
        version.incrementAndGet();
    }

    static synchronized List<Entry> recent() {
        return new ArrayList<>(LOG);
    }

    /** Apps caught collecting in the background, worst first. */
    static synchronized List<Caught> caught() {
        List<Caught> l = new ArrayList<>(CAUGHT.values());
        l.sort((a, b) -> b.count - a.count);
        return l;
    }

    static synchronized boolean isCaught(String app) {
        return CAUGHT.containsKey(app);
    }
}
