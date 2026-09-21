package li.haas.pcap4j.ext;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * STUN (RFC 5389), which pcap4j does not decode. Port 3478 by default, but ICE runs it on
 * arbitrary ports, so it is recognised by the magic cookie instead.
 * The mapped address in a response is the public address the NAT gave this client.
 */
public record Stun(int messageType, InetAddress mappedAddress, int mappedPort,
                   String software, String username) {

    public static final int MAGIC_COOKIE = 0x2112a442;
    private static final int HEADER_LENGTH = 20;

    private static final int ATTR_MAPPED_ADDRESS = 0x0001;
    private static final int ATTR_USERNAME = 0x0006;
    private static final int ATTR_XOR_MAPPED_ADDRESS = 0x0020;
    private static final int ATTR_SOFTWARE = 0x8022;

    /** Message class, from bits 4 and 8 of the type. */
    public String messageClass() {
        return switch (messageType & 0x0110) {
            case 0x0000 -> "request";
            case 0x0010 -> "indication";
            case 0x0100 -> "success response";
            case 0x0110 -> "error response";
            default -> "unknown";  // unreachable, the mask has 4 values
        };
    }

    /** Method, e.g. 0x001 for Binding. */
    public int method() {
        return (messageType & 0x000f) | ((messageType & 0x00e0) >> 1) | ((messageType & 0x3e00) >> 2);
    }

    @Override
    public String toString() {
        return "STUN " + (method() == 0x001 ? "binding" : "method 0x" + Integer.toHexString(method()))
                + " " + messageClass()
                + (mappedAddress == null ? "" : " mapped=" + hostPort(mappedAddress, mappedPort))
                + (software == null ? "" : " software=" + software)
                + (username == null ? "" : " username=" + username);
    }

    // IPv6 goes in brackets, otherwise the port is unreadable next to the colons
    private static String hostPort(InetAddress a, int port) {
        final String h = a.getHostAddress();
        return (h.contains(":") ? "[" + h + "]" : h) + ":" + port;
    }

    /** Returns null if the data is not STUN. */
    public static Stun parse(byte[] p) {
        // the first two bits must be zero and the magic cookie must match
        if (p.length < HEADER_LENGTH || (p[0] & 0xc0) != 0 || u32(p, 4) != MAGIC_COOKIE) return null;
        final int messageType = u16(p, 0);
        final int length = u16(p, 2);
        if (HEADER_LENGTH + length > p.length) return null;

        InetAddress mapped = null;
        int mappedPort = 0;
        String software = null, username = null;

        int off = HEADER_LENGTH;
        final int end = HEADER_LENGTH + length;
        while (off + 4 <= end) {
            final int type = u16(p, off);
            final int len = u16(p, off + 2);
            final int v = off + 4;
            if (v + len > end) break;
            switch (type) {
                case ATTR_XOR_MAPPED_ADDRESS, ATTR_MAPPED_ADDRESS -> {
                    final int[] portOut = new int[1];
                    final InetAddress a = address(p, v, len, type == ATTR_XOR_MAPPED_ADDRESS, portOut);
                    // prefer the XOR variant, it survives NATs that rewrite addresses in the payload
                    if (a != null && (mapped == null || type == ATTR_XOR_MAPPED_ADDRESS)) {
                        mapped = a;
                        mappedPort = portOut[0];
                    }
                }
                case ATTR_SOFTWARE -> software = new String(p, v, len, StandardCharsets.UTF_8);
                case ATTR_USERNAME -> username = new String(p, v, len, StandardCharsets.UTF_8);
                default -> { }
            }
            off = v + ((len + 3) & ~3);  // values are padded to a multiple of 4
        }
        return new Stun(messageType, mapped, mappedPort, software, username);
    }

    /** MAPPED-ADDRESS: reserved (1), family (1), port (2), address. The XOR variant masks port and address. */
    private static InetAddress address(byte[] p, int off, int len, boolean xor, int[] portOut) {
        if (len < 4) return null;
        final int family = p[off + 1] & 0xff;
        final int size = family == 0x01 ? 4 : family == 0x02 ? 16 : -1;
        if (size < 0 || len < 4 + size) return null;

        int port = u16(p, off + 2);
        final byte[] a = Arrays.copyOfRange(p, off + 4, off + 4 + size);
        if (xor) {
            port ^= MAGIC_COOKIE >>> 16;
            // IPv4 is xored with the cookie, IPv6 with the cookie followed by the transaction ID
            for (int i = 0; i < size; i++) {
                a[i] ^= i < 4 ? (byte) (MAGIC_COOKIE >>> (24 - 8 * i)) : p[4 + i];
            }
        }
        portOut[0] = port;
        try {
            return InetAddress.getByAddress(a);
        } catch (UnknownHostException e) {
            return null;  // cannot happen for 4 or 16 bytes
        }
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
    }

    private static int u32(byte[] p, int off) {
        return (u16(p, off) << 16) | u16(p, off + 2);
    }
}
