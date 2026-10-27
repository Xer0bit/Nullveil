// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.xer0bit.nullveil;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Private on-device prefs. Your rules (domain allow/block, app lock/trust) are stored encrypted
 * (AES-256-GCM, Keystore key) and cached in memory, so checking them per lookup is free.
 * Plain flags (strict, encrypted DNS) hold nothing personal.
 */
final class Settings {
    private static final String RULES = "rules_enc";

    private Settings() {}

    private static SharedPreferences sp(Context c) {
        return c.getSharedPreferences("nullveil", Context.MODE_PRIVATE);
    }

    private static final class Rules {
        final Set<String> allow = ConcurrentHashMap.newKeySet(), block = ConcurrentHashMap.newKeySet();
        final Set<String> lock = ConcurrentHashMap.newKeySet(), trust = ConcurrentHashMap.newKeySet();
    }

    private static Rules mem;

    private static synchronized Rules load(Context c) {
        if (mem != null) return mem;
        Rules r = new Rules();
        SharedPreferences p = sp(c);
        String enc = p.getString(RULES, null);
        if (enc != null) {
            String plain = SecureStore.decrypt(enc);
            if (plain != null) {
                String[] parts = plain.split("\u0000", -1);
                for (int i = 0; i < parts.length && i < 4; i++) fill(r, i, parts[i]);
            }
        } else if (p.contains("allow") || p.contains("block")) {
            // older builds kept the lists in plain text: move them into the encrypted blob, then erase them
            r.allow.addAll(p.getStringSet("allow", new java.util.HashSet<>()));
            r.block.addAll(p.getStringSet("block", new java.util.HashSet<>()));
            save(c, r);
        }
        mem = r;
        return r;
    }

    private static void fill(Rules r, int which, String lines) {
        Set<String> into = which == 0 ? r.allow : which == 1 ? r.block : which == 2 ? r.lock : r.trust;
        for (String l : lines.split("\n")) if (!l.isEmpty()) into.add(l);
    }

    private static void save(Context c, Rules r) {
        String enc = SecureStore.encrypt(String.join("\n", r.allow) + "\u0000" + String.join("\n", r.block)
                + "\u0000" + String.join("\n", r.lock) + "\u0000" + String.join("\n", r.trust));
        SharedPreferences.Editor e = sp(c).edit().remove("allow").remove("block");
        if (enc != null) e.putString(RULES, enc); // no Keystore: keep nothing on disk rather than plain text
        e.apply();
    }

    private static void push(Rules r) {
        Native.setRules(String.join("\n", r.allow), String.join("\n", r.block));
    }

    static void applyRules(Context c) {
        push(load(c));
    }

    /** Domain override (domain and subdomains). Pressing the same choice again removes it. */
    static void toggleRule(Context c, String domain, boolean allow) {
        Rules r = load(c);
        Set<String> target = allow ? r.allow : r.block;
        if (!target.remove(domain)) {
            target.add(domain);
            (allow ? r.block : r.allow).remove(domain);
        }
        save(c, r);
        push(r);
    }

    /** 0 = no rule, 1 = always allowed, 2 = always blocked. */
    static int domainState(Context c, String domain) {
        Rules r = load(c);
        return r.allow.contains(domain) ? 1 : r.block.contains(domain) ? 2 : 0;
    }

    /** 0 = normal, 1 = locked (no lookups while in background), 2 = trusted (engine never blocks it). */
    static int appMode(Context c, String pkg) {
        Rules r = load(c);
        return r.lock.contains(pkg) ? 1 : r.trust.contains(pkg) ? 2 : 0;
    }

    static void toggleAppMode(Context c, String pkg, int mode) {
        Rules r = load(c);
        boolean same = appMode(c, pkg) == mode;
        r.lock.remove(pkg);
        r.trust.remove(pkg);
        if (!same) (mode == 1 ? r.lock : r.trust).add(pkg);
        save(c, r);
    }

    static synchronized void clearRules(Context c) {
        mem = new Rules();
        sp(c).edit().remove(RULES).remove("allow").remove("block").apply();
        Native.setRules("", "");
    }

    static int ruleCount(Context c) {
        Rules r = load(c);
        return r.allow.size() + r.block.size() + r.lock.size() + r.trust.size();
    }

    static boolean strict(Context c) {
        return sp(c).getBoolean("strict", false);
    }

    static boolean toggleStrict(Context c) {
        boolean v = !strict(c);
        sp(c).edit().putBoolean("strict", v).apply();
        return v;
    }

    /** 0 = off (phone's own DNS), 1 = TLS to Quad9, 2 = TLS to Cloudflare. Off by default. */
    static int dotMode(Context c) {
        return sp(c).getInt("dot_mode", 0);
    }

    static void cycleDot(Context c) {
        sp(c).edit().putInt("dot_mode", (dotMode(c) + 1) % (DotClient.Resolver.values().length + 1)).apply();
    }
}
