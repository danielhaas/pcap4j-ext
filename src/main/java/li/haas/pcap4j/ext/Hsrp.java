package li.haas.pcap4j.ext;

import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Cisco Hot Standby Router Protocol (RFC 2281 describes version 1), which pcap4j does not decode.
 *
 * <p>The oldest of the first hop redundancy protocols, and still the most common one inside Cisco networks.
 * Two or more routers share one virtual IP and one virtual MAC; the highest priority router in the group
 * becomes active and answers for the address, the next in line becomes standby and takes over if the hellos
 * stop. Hosts point their default gateway at the virtual address and never notice the handover. A capture
 * shows which routers are in which group, which one is currently active, and how long a failover will take.
 *
 * <p><b>On the wire:</b> version 1 is a fixed 20-byte message on UDP 1985 to 224.0.0.2. Version 2 is a TLV
 * format on UDP 1985 for IPv4, to 224.0.0.102, or UDP 2029 for IPv6, and carries a six-byte identifier plus
 * a 32-bit group number. Hellos are every three seconds by default. The virtual MAC is
 * 00:00:0c:07:ac:{group} for version 1.
 *
 * <p><b>Parsed:</b> both versions into one shape. The opcode and state, the group, the priority, the hello
 * and hold timers, the virtual address, the authentication string and, for version 2, the sender's
 * identifier. See {@link #usesDefaultPassword()}: HSRP's plain text authentication defaults to the string
 * "cisco" and is sent in every hello.
 */
public record Hsrp(int version, int opcode, int state, int group, long priority,
                   int helloSeconds, int holdSeconds, InetAddress virtualAddress,
                   String authentication, MacAddress identifier) implements Protocol {

    public static final int PORT_V1 = 1985;
    public static final int PORT_V6 = 2029;

    /** The default password Cisco ships with, sent in clear text. */
    public static final String DEFAULT_AUTH = "cisco";

    public String opcodeName() {
        return switch (opcode) {
            case 0 -> "hello";
            case 1 -> "coup";       // taking over the active role
            case 2 -> "resign";     // giving it up
            case 3 -> "advertise";
            default -> "opcode " + opcode;
        };
    }

    /** The state names differ between the two versions. */
    public String stateName() {
        if (version >= 2) {
            return switch (state) {
                case 0 -> "initial";
                case 1 -> "learn";
                case 2 -> "listen";
                case 3 -> "speak";
                case 4 -> "standby";
                case 5 -> "active";
                default -> "state " + state;
            };
        }
        return switch (state) {
            case 0 -> "initial";
            case 1 -> "learn";
            case 2 -> "listen";
            case 4 -> "speak";
            case 8 -> "standby";
            case 16 -> "active";
            default -> "state " + state;
        };
    }

    public boolean isActive() {
        return version >= 2 ? state == 5 : state == 16;
    }

    public boolean usesDefaultPassword() {
        return DEFAULT_AUTH.equals(authentication);
    }

    @Override
    public String toString() {
        return "HSRPv" + version + " group " + group + " " + stateName() + " " + opcodeName()
                + " priority=" + priority
                + (virtualAddress == null ? "" : " virtual=" + virtualAddress.getHostAddress())
                + (identifier == null ? "" : " id=" + identifier)
                + (authentication == null || authentication.isEmpty() ? "" : " auth=" + authentication);
    }

    /**
     * Parses bytes the caller has already identified as HSRP, for example by protocol id or port.
     * Throws rather than returning null: at this point the bytes claim to be this protocol.
     */
    public static Hsrp parse(byte[] p) throws IllegalRawDataException {
        final Hsrp parsed = parseOrNull(p);
        if (parsed == null) throw Raw.notA("HSRP", p);
        return parsed;
    }

    /** Returns null if the data is not HSRP. */
    private static Hsrp parseOrNull(byte[] p) {
        if (p.length < 20) return null;
        // version 1 starts with a zero version byte; version 2 starts with a TLV of type 1
        return (p[0] & 0xff) == 0 ? parseV1(p) : parseV2(p);
    }

    private static Hsrp parseV1(byte[] p) {
        final int opcode = p[1] & 0xff;
        final int state = p[2] & 0xff;
        if (opcode > 3) return null;
        final String auth = text(p, 8, 8);
        return new Hsrp(1, opcode, state, p[6] & 0xff, p[5] & 0xff,
                p[3] & 0xff, p[4] & 0xff, address(p, 16, 4), auth, null);
    }

    private static Hsrp parseV2(byte[] p) {
        Integer opcode = null, state = null, group = null, helloMs = null, holdMs = null, ipVersion = null;
        long priority = 0;
        InetAddress virtual = null;
        MacAddress identifier = null;
        String auth = null;

        int off = 0;
        while (off + 2 <= p.length) {
            final int type = p[off] & 0xff;
            final int len = p[off + 1] & 0xff;
            final int v = off + 2;
            if (len == 0 || v + len > p.length) break;

            switch (type) {
                case 1 -> {   // group state
                    if (len < 24 || (p[v] & 0xff) != 2) return null;   // version 2
                    opcode = p[v + 1] & 0xff;
                    state = p[v + 2] & 0xff;
                    ipVersion = p[v + 3] & 0xff;
                    group = u16(p, v + 4);
                    identifier = MacAddress.getByAddress(Arrays.copyOfRange(p, v + 6, v + 12));
                    priority = u32(p, v + 12);
                    helloMs = (int) u32(p, v + 16);
                    holdMs = (int) u32(p, v + 20);
                    virtual = address(p, v + 24, ipVersion == 6 ? 16 : 4);
                }
                case 3 -> auth = text(p, v, len);                      // text authentication
                case 4 -> auth = "md5";                                // MD5 authentication, digest not shown
                default -> { }
            }
            off = v + len;
        }

        if (opcode == null) return null;
        return new Hsrp(2, opcode, state, group, priority,
                helloMs == null ? 0 : helloMs / 1000, holdMs == null ? 0 : holdMs / 1000,
                virtual, auth, identifier);
    }

    private static InetAddress address(byte[] p, int off, int size) {
        if (off + size > p.length) return null;
        try {
            return InetAddress.getByAddress(Arrays.copyOfRange(p, off, off + size));
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static String text(byte[] p, int off, int len) {
        int end = Math.min(off + len, p.length);
        while (end > off && (p[end - 1] == 0 || p[end - 1] == ' ')) end--;
        return new String(p, off, Math.max(end - off, 0), StandardCharsets.US_ASCII);
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
    }

    private static long u32(byte[] p, int off) {
        return ((long) (p[off] & 0xff) << 24) | ((p[off + 1] & 0xff) << 16)
                | ((p[off + 2] & 0xff) << 8) | (p[off + 3] & 0xff);
    }
}
