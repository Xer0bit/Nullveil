// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.xer0bit.nullveil;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.channels.SocketChannel;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * DNS-over-TLS (RFC 7858) to Quad9, tried over IPv4 first, then IPv6. One long-lived connection is
 * reused for every lookup, so the TLS handshake cost is paid once, not per lookup. The certificate
 * name is checked on every connection.
 */
final class DotClient {
    interface Protector {
        void protect(Socket s); // keep this socket outside the VPN tunnel
    }

    /** Resolver choices. IPv4 addresses come first, IPv6 after, so IPv6-only networks work too. */
    enum Resolver {
        QUAD9("Quad9", "dns.quad9.net", "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"),
        CLOUDFLARE("Cloudflare", "cloudflare-dns.com", "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001");

        final String label, host;
        final String[] addrs;

        Resolver(String label, String host, String... addrs) {
            this.label = label;
            this.host = host;
            this.addrs = addrs;
        }
    }

    private final Protector protector;
    private final Resolver resolver;
    private SSLSocket sock;
    private DataInputStream in;
    private DataOutputStream out;

    DotClient(Protector protector, Resolver resolver) {
        this.protector = protector;
        this.resolver = resolver;
    }

    /** One DNS message in, one DNS message out. Throws if the resolver cannot be reached securely. */
    synchronized byte[] query(byte[] dns) throws IOException {
        for (int attempt = 0; ; attempt++) {
            try {
                ensure();
                out.writeShort(dns.length);
                out.write(dns);
                out.flush();
                byte[] answer = new byte[in.readUnsignedShort()];
                in.readFully(answer);
                return answer;
            } catch (IOException e) {
                close(); // stale connection: reconnect once, then give up
                if (attempt == 1) throw e;
            }
        }
    }

    synchronized void close() {
        try {
            if (sock != null) sock.close();
        } catch (IOException ignored) {
            // already closed
        }
        sock = null;
    }

    private void ensure() throws IOException {
        if (sock != null && !sock.isClosed()) return;
        IOException failed = new IOException("no resolver reachable"); // keeps every attempt as a suppressed cause
        for (String addr : resolver.addrs) {
            try {
                SocketChannel ch = SocketChannel.open(); // a real descriptor exists now, so it can be protected
                Socket raw = ch.socket();
                protector.protect(raw);
                raw.connect(new InetSocketAddress(java.net.InetAddress.getByName(addr), 853), 4000);
                SSLSocket s = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(raw, resolver.host, 853, true);
                SSLParameters p = s.getSSLParameters();
                p.setEndpointIdentificationAlgorithm("HTTPS"); // certificate must be issued for the resolver's own name
                s.setSSLParameters(p);
                if (java.util.Arrays.asList(s.getSupportedProtocols()).contains("TLSv1.3")) {
                    s.setEnabledProtocols(new String[]{"TLSv1.3"}); // no legacy protocol options when the phone supports 1.3
                }
                s.setSoTimeout(4000);
                s.startHandshake();
                sock = s;
                in = new DataInputStream(s.getInputStream());
                out = new DataOutputStream(s.getOutputStream());
                return;
            } catch (IOException e) {
                failed.addSuppressed(e);
            }
        }
        throw failed;
    }
}
