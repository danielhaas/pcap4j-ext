package li.haas.pcap4j.ext;

import org.pcap4j.packet.IllegalRawDataException;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * VRRP (RFC 3768 for version 2, RFC 5798 for version 3), which pcap4j does not decode.
 *
 * <p>The standard first hop redundancy protocol, and what non-Cisco equipment runs in place of HSRP.
 * Routers in a group share a virtual address and a virtual MAC; the one with the highest priority becomes
 * master and is the only one that advertises. That last point is what makes a capture useful: two routers
 * advertising the same VRID at the same time means the group has split, usually because the advertisements
 * are not reaching one of them, and both are now answering for the same address.
 *
 * <p><b>On the wire:</b> directly in IP with protocol 112, not over UDP, to 224.0.0.18 or ff02::12, with
 * TTL 255. The virtual MAC is 00:00:5e:00:01:{vrid} for IPv4 and 00:00:5e:00:02:{vrid} for IPv6. Version 3
 * drops authentication entirely and states the advertisement interval in centiseconds, which allows
 * sub-second failover.
 *
 * <p><b>Parsed:</b> the version and type, the VRID and priority, the advertisement interval, every virtual
 * address, and for version 2 the authentication type and string. The interval component keeps the units its
 * version uses, seconds for version 2 and centiseconds for version 3; {@link #advertIntervalSeconds()}
 * normalises it. Priority 255 means the router owns the address outright and 0 means it is resigning; see
 * {@link #isOwner()} and {@link #isResigning()}.
 */
public record Vrrp(int version, int type, int virtualRouterId, int priority,
                   int advertIntervalCentiseconds, List<InetAddress> virtualAddresses,
                   int authType, String authentication) implements Protocol {
    public Vrrp {
        virtualAddresses = copy(virtualAddresses);
    }


    public static final int IP_PROTOCOL = 112;

    /** The router that owns the address itself always uses this priority. */
    public static final int PRIORITY_OWNER = 255;
    /** A router sends this when it gives up the master role, e.g. on shutdown. */
    public static final int PRIORITY_RESIGN = 0;

    public boolean isOwner() {
        return priority == PRIORITY_OWNER;
    }

    public boolean isResigning() {
        return priority == PRIORITY_RESIGN;
    }

    /** Version 2 counts in seconds, version 3 in centiseconds. */
    public double advertIntervalSeconds() {
        return version >= 3 ? advertIntervalCentiseconds / 100.0 : advertIntervalCentiseconds;
    }

    public String authTypeName() {
        return switch (authType) {
            case 0 -> "none";
            case 1 -> "simple text";
            case 2 -> "ip authentication header";
            default -> "type " + authType;
        };
    }

    @Override
    public String toString() {
        return "VRRPv" + version + " vrid " + virtualRouterId
                + (isResigning() ? " resigning" : " priority=" + priority + (isOwner() ? " (owner)" : ""))
                + " virtual=" + virtualAddresses.stream().map(InetAddress::getHostAddress).toList()
                + " interval=" + advertIntervalSeconds() + "s"
                + (authentication == null || authentication.isEmpty() ? "" : " auth=" + authentication);
    }

    /**
     * Parses bytes the caller has already identified as VRRP by IP protocol 112.
     * Throws rather than returning null: at this point the bytes claim to be an advertisement.
     */
    public static Vrrp parse(byte[] p, boolean ipv6) throws IllegalRawDataException {
        final Vrrp parsed = parseOrNull(p, ipv6);
        if (parsed == null) throw Raw.notA("a VRRP advertisement", p);
        return parsed;
    }

    /** Returns null if the data is not a VRRP advertisement. */
    private static Vrrp parseOrNull(byte[] p, boolean ipv6) {
        if (p.length < 8) return null;
        final int version = (p[0] & 0xf0) >> 4;
        final int type = p[0] & 0x0f;
        if (version < 2 || version > 3 || type != 1) return null;   // only advertisements exist

        final int vrid = p[1] & 0xff;
        final int priority = p[2] & 0xff;
        final int count = p[3] & 0xff;
        final int addressSize = ipv6 ? 16 : 4;

        int authType = 0;
        int interval;
        int off;
        if (version == 2) {
            authType = p[4] & 0xff;
            interval = p[5] & 0xff;          // seconds
            off = 8;                         // after the checksum
        } else {
            interval = ((p[4] & 0x0f) << 8) | (p[5] & 0xff);   // centiseconds, 12 bits
            off = 8;
        }

        final List<InetAddress> addresses = new ArrayList<>();
        for (int i = 0; i < count && off + addressSize <= p.length; i++, off += addressSize) {
            try {
                addresses.add(InetAddress.getByAddress(Arrays.copyOfRange(p, off, off + addressSize)));
            } catch (UnknownHostException e) {
                return null;
            }
        }
        if (addresses.isEmpty()) return null;

        // version 2 with simple text authentication puts the password in the clear after the addresses
        String auth = null;
        if (version == 2 && authType == 1 && off + 8 <= p.length) {
            auth = text(p, off, 8);
        }
        return new Vrrp(version, type, vrid, priority, interval, addresses, authType, auth);
    }

    private static String text(byte[] p, int off, int len) {
        int end = Math.min(off + len, p.length);
        while (end > off && (p[end - 1] == 0 || p[end - 1] == ' ')) end--;
        return new String(p, off, Math.max(end - off, 0), StandardCharsets.US_ASCII);
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
