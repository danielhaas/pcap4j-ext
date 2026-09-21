package li.haas.pcap4j.ext;

import org.pcap4j.packet.IllegalRawDataException;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * OSPF (RFC 2328 for version 2, RFC 5340 for version 3), IP protocol 89, which pcap4j does not decode.
 * Only the header and the hello are read: a hello names the router, its area, the designated
 * router and every neighbour it has heard from, which is enough to map the routed topology.
 * The other message types are reported by name and left alone.
 */
public record Ospf(int version, int type, Inet4Address routerId, Inet4Address areaId,
                   int authType, String authentication,
                   Inet4Address networkMask, Integer helloInterval, Integer deadInterval,
                   Integer priority, Inet4Address designatedRouter, Inet4Address backupDesignatedRouter,
                   List<Inet4Address> neighbours) implements Protocol {

    public Ospf {
        neighbours = neighbours == null ? List.of() : Collections.unmodifiableList(new ArrayList<>(neighbours));
    }

    public static final int IP_PROTOCOL = 89;

    public static final int TYPE_HELLO = 1;
    public static final int TYPE_DATABASE_DESCRIPTION = 2;
    public static final int TYPE_LINK_STATE_REQUEST = 3;
    public static final int TYPE_LINK_STATE_UPDATE = 4;
    public static final int TYPE_LINK_STATE_ACK = 5;

    public String typeName() {
        return switch (type) {
            case TYPE_HELLO -> "hello";
            case TYPE_DATABASE_DESCRIPTION -> "database description";
            case TYPE_LINK_STATE_REQUEST -> "link state request";
            case TYPE_LINK_STATE_UPDATE -> "link state update";
            case TYPE_LINK_STATE_ACK -> "link state ack";
            default -> "type " + type;
        };
    }

    /** Version 2 only; version 3 moved authentication into IPsec. */
    public String authTypeName() {
        return switch (authType) {
            case 0 -> "none";
            case 1 -> "simple text";
            case 2 -> "md5";
            default -> "type " + authType;
        };
    }

    public boolean isHello() {
        return type == TYPE_HELLO;
    }

    /** A hello with no neighbours listed has not heard anyone yet, or is alone on the segment. */
    public boolean alone() {
        return isHello() && neighbours.isEmpty();
    }

    @Override
    public String toString() {
        return "OSPFv" + version + " " + typeName()
                + (routerId == null ? "" : " router=" + routerId.getHostAddress())
                + (areaId == null ? "" : " area=" + areaId.getHostAddress())
                + (helloInterval == null ? "" : " hello=" + helloInterval + "s dead=" + deadInterval + "s")
                + (designatedRouter == null || designatedRouter.isAnyLocalAddress()
                        ? "" : " dr=" + designatedRouter.getHostAddress())
                + (neighbours.isEmpty() ? "" : " neighbours=" + neighbours.stream()
                        .map(Inet4Address::getHostAddress).toList())
                + (authentication == null ? "" : " auth=" + authentication);
    }

    /** Returns null if the data is not OSPF. */
    public static Ospf parseOrNull(byte[] p) {
        if (p.length < 16) return null;
        final int version = p[0] & 0xff;
        final int type = p[1] & 0xff;
        if (version < 2 || version > 3 || type < TYPE_HELLO || type > TYPE_LINK_STATE_ACK) return null;

        final Inet4Address routerId = ipv4(p, 4);
        final Inet4Address areaId = ipv4(p, 8);

        // version 2 carries the authentication in the header; version 3 has an instance id instead
        int authType = 0;
        String authentication = null;
        int body = 24;
        if (version == 2) {
            if (p.length < 24) return null;
            authType = u16(p, 14);
            if (authType == 1) {
                authentication = text(p, 16, 8);
                if (authentication.isEmpty()) authentication = null;
            } else if (authType == 2) {
                authentication = "md5";
            }
        } else {
            body = 16;
        }

        if (type != TYPE_HELLO) {
            return new Ospf(version, type, routerId, areaId, authType, authentication,
                    null, null, null, null, null, null, List.of());
        }

        // hello: network mask (v2 only), intervals, priority, designated routers, neighbours
        Inet4Address mask = null;
        int off = body;
        if (version == 2) {
            if (off + 20 > p.length) return null;
            mask = ipv4(p, off);
            off += 4;
        } else {
            if (off + 20 > p.length) return null;
            off += 4;                      // interface id
        }
        // v2: hello (2), options (1), priority (1), dead (4), then the designated routers
        // v3: priority (1), options (3), hello (2), dead (2), then the designated routers
        final int hello = version == 2 ? u16(p, off) : u16(p, off + 4);
        final int priority = version == 2 ? p[off + 3] & 0xff : p[off] & 0xff;
        final int dead = version == 2 ? (int) u32(p, off + 4) : u16(p, off + 6);
        final int afterIntervals = off + 8;
        if (afterIntervals + 8 > p.length) return null;
        final Inet4Address designated = ipv4(p, afterIntervals);
        final Inet4Address backup = ipv4(p, afterIntervals + 4);

        final List<Inet4Address> neighbours = new ArrayList<>();
        for (int i = afterIntervals + 8; i + 4 <= p.length; i += 4) {
            final Inet4Address neighbour = ipv4(p, i);
            if (neighbour == null || neighbour.isAnyLocalAddress()) break;
            neighbours.add(neighbour);
        }

        return new Ospf(version, type, routerId, areaId, authType, authentication,
                mask, hello, dead, priority, designated, backup, neighbours);
    }

    /** Parses bytes the caller has already identified as OSPF by IP protocol 89. */
    public static Ospf parse(byte[] p) throws IllegalRawDataException {
        final Ospf parsed = parseOrNull(p);
        if (parsed == null) throw Raw.notA("OSPF", p);
        return parsed;
    }

    private static Inet4Address ipv4(byte[] p, int off) {
        if (off + 4 > p.length) return null;
        try {
            return (Inet4Address) Inet4Address.getByAddress(Arrays.copyOfRange(p, off, off + 4));
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
