package li.haas.pcap4j.ext;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Just enough TLS to read the server name out of a ClientHello, which pcap4j does not decode.
 * Everything after the handshake is encrypted, but the SNI extension travels in clear text,
 * so a capture shows which host each client is reaching for.
 */
import java.util.Collections;

import java.util.LinkedHashMap;

import java.util.LinkedHashSet;

import java.util.Map;

import java.util.Set;

public record Tls(int recordVersion, int handshakeVersion, String serverName, List<String> alpn) implements Protocol {

    /** The usual port. Detection is by the record and handshake structure, not by port. */
    public static final int DEFAULT_PORT = 443;
    public Tls {
        alpn = copy(alpn);
    }


    private static final int RECORD_HANDSHAKE = 22;
    private static final int HANDSHAKE_CLIENT_HELLO = 1;

    private static final int EXT_SERVER_NAME = 0x0000;
    private static final int EXT_ALPN = 0x0010;

    @Override
    public String toString() {
        return "TLS client hello"
                + (serverName == null ? "" : " sni=" + serverName)
                + (alpn.isEmpty() ? "" : " alpn=" + alpn);
    }

    /** Returns null unless the data starts a TLS record holding a ClientHello with a server name. */
    public static Tls parse(byte[] p) {
        // record header: type (1), version (2), length (2)
        if (p.length < 45 || (p[0] & 0xff) != RECORD_HANDSHAKE) return null;
        final int recordLength = u16(p, 3);
        if (recordLength < 4) return null;
        return parseHandshake(p, 5, u16(p, 1));
    }

    /**
     * The same ClientHello without a record around it, as QUIC carries it in CRYPTO frames.
     */
    public static Tls parseHandshake(byte[] p) {
        return parseHandshake(p, 0, 0);
    }

    private static Tls parseHandshake(byte[] p, int start, int recordVersion) {
        if (start + 40 > p.length) return null;
        // handshake header: type (1), length (3)
        int off = start;
        if ((p[off] & 0xff) != HANDSHAKE_CLIENT_HELLO) return null;

        // the whole message has to be here: a truncated hello would parse to whatever extensions
        // happen to have arrived, and a caller reassembling one would stop too early
        final int handshakeLength = ((p[start + 1] & 0xff) << 16)
                | ((p[start + 2] & 0xff) << 8) | (p[start + 3] & 0xff);
        // 34 is the shortest possible body: version, random and three empty length fields
        if (handshakeLength < 34 || start + 4 + handshakeLength > p.length) return null;
        final int handshakeVersion = u16(p, off + 4);
        off += 4 + 2 + 32;                       // header, version, random

        if (off >= p.length) return null;
        off += 1 + (p[off] & 0xff);              // session id
        if (off + 2 > p.length) return null;
        off += 2 + u16(p, off);                  // cipher suites
        if (off >= p.length) return null;
        off += 1 + (p[off] & 0xff);              // compression methods
        if (off + 2 > p.length) return null;

        final int extensionsLength = u16(p, off);
        off += 2;
        final int end = Math.min(off + extensionsLength, p.length);

        String serverName = null;
        final List<String> alpn = new ArrayList<>();

        while (off + 4 <= end) {
            final int type = u16(p, off);
            final int len = u16(p, off + 2);
            final int v = off + 4;
            if (v + len > end) break;

            if (type == EXT_SERVER_NAME && len >= 5) {
                // server name list: list length (2), then type (1), length (2), name
                final int nameLength = u16(p, v + 3);
                if ((p[v + 2] & 0xff) == 0 && v + 5 + nameLength <= end) {
                    serverName = new String(p, v + 5, nameLength, StandardCharsets.US_ASCII);
                }
            } else if (type == EXT_ALPN && len >= 3) {
                // protocol list: list length (2), then length-prefixed strings
                int a = v + 2;
                while (a < v + len && a < end) {
                    final int protocolLength = p[a] & 0xff;
                    if (a + 1 + protocolLength > end) break;
                    alpn.add(new String(p, a + 1, protocolLength, StandardCharsets.US_ASCII));
                    a += 1 + protocolLength;
                }
            }
            off = v + len;
        }

        if (serverName == null && alpn.isEmpty()) return null;
        return new Tls(recordVersion, handshakeVersion, serverName, alpn);
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
    }

    // defensive copies that keep insertion order, which several of these rely on
    private static <T> List<T> copy(List<T> in) {
        return in == null ? List.of() : Collections.unmodifiableList(new ArrayList<>(in));
    }

    private static <T> Set<T> copy(Set<T> in) {
        return in == null ? Set.of() : Collections.unmodifiableSet(new LinkedHashSet<>(in));
    }

    private static <K, V> Map<K, V> copy(Map<K, V> in) {
        return in == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(in));
    }

}
