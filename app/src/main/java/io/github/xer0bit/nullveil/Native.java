// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.xer0bit.nullveil;

/** JNI bridge to the Rust core in /rust. All packets are raw IPv4. */
final class Native {
    static {
        System.loadLibrary("privacycore");
    }

    private Native() {}

    /** Domain asked by a DNS query packet, or null if it is not one. */
    static native String query(byte[] packet);

    /**
     * Behaviour verdict for one lookup: "1|score|reasons" = block, "0|score|reasons" = pass.
     * perms: bit 1 mic, 2 camera, 4 location granted to the asking app.
     */
    static native String decide(String domain, String app, boolean background, int perms, boolean strict);

    /** Your overrides, one domain per line. */
    static native void setRules(String allow, String block);

    /** Reply packet carrying the sinkhole answer (0.0.0.0 / ::) for a blocked query. */
    static native byte[] blockedReply(byte[] packet);

    /** Reply packet carrying a real upstream DNS answer back to the asker. */
    static native byte[] wrap(byte[] packet, byte[] dnsAnswer);
}
