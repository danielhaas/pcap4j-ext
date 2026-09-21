package li.haas.pcap4j.ext;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Multicast Listener Discovery (RFC 2710 for version 1, RFC 3810 for version 2),
 * the IPv6 counterpart of IGMP, which pcap4j does not decode.
 * It rides inside ICMPv6: types 130 query, 131 report, 132 done, and 143 for a version 2 report.
 */
import org.pcap4j.packet.IllegalRawDataException;

import java.util.Collections;

import java.util.LinkedHashMap;

import java.util.LinkedHashSet;

import java.util.Map;

import java.util.Set;

public record Mld(int version, int type, int maxResponseMillis,
                  Inet6Address group, List<GroupRecord> records, List<Inet6Address> querySources,
                  Integer robustness, Integer queryInterval) implements Protocol {
    public Mld {
        records = copy(records);
        querySources = copy(querySources);
    }


    public static final int TYPE_QUERY = 130;
    public static final int TYPE_V1_REPORT = 131;
    public static final int TYPE_DONE = 132;
    public static final int TYPE_V2_REPORT = 143;

    /** One group in a version 2 report, with the sources the listener includes or excludes. */
    public record GroupRecord(int recordType, Inet6Address group, List<Inet6Address> sources) {

        public String recordTypeName() {
            return switch (recordType) {
                case 1 -> "listening to only";
                case 2 -> "listening to all but";
                case 3 -> "now only";
                case 4 -> "now all but";
                case 5 -> "also";
                case 6 -> "no longer";
                default -> "record type " + recordType;
            };
        }

        /** As in IGMPv3, a change to include mode with no sources means the listener is leaving. */
        public boolean isLeave() {
            return recordType == 3 && sources.isEmpty();
        }

        @Override
        public String toString() {
            return group.getHostAddress()
                    + (sources.isEmpty() ? (isLeave() ? " (leaving)" : "") : " " + recordTypeName() + " "
                        + sources.stream().map(InetAddress::getHostAddress).toList());
        }
    }

    public boolean isQuery() {
        return type == TYPE_QUERY;
    }

    public boolean isGeneralQuery() {
        return isQuery() && (group == null || group.isAnyLocalAddress());
    }

    public String typeName() {
        return switch (type) {
            case TYPE_QUERY -> isGeneralQuery() ? "general query" : "group query";
            case TYPE_V1_REPORT -> "report";
            case TYPE_DONE -> "done";
            case TYPE_V2_REPORT -> "v2 report";
            default -> "type " + type;
        };
    }

    @Override
    public String toString() {
        return "MLDv" + version + " " + typeName()
                + (group == null || group.isAnyLocalAddress() ? "" : " " + group.getHostAddress())
                + (records.isEmpty() ? "" : " " + records)
                + (querySources.isEmpty() ? "" : " sources=" + querySources.stream().map(InetAddress::getHostAddress).toList());
    }

    /**
     * Finds MLD in the raw bytes after an IPv6 fixed header, walking the extension headers.
     * MLD always travels behind a hop-by-hop header with a router alert, and pcap4j ends that
     * header two bytes early when it is padded with PadN, so the walk is done here instead.
     */
    public static Mld parseAfterIpv6(int firstNextHeader, byte[] p) {
        int nextHeader = firstNextHeader;
        int off = 0;
        // hop-by-hop, routing, destination options and mobility all share the length encoding
        while (nextHeader == 0 || nextHeader == 43 || nextHeader == 60 || nextHeader == 135) {
            if (off + 2 > p.length) return null;
            final int length = ((p[off + 1] & 0xff) + 1) * 8;
            nextHeader = p[off] & 0xff;
            off += length;
        }
        if (nextHeader != 58 || off + 4 > p.length) return null;   // 58 is ICMPv6
        // a locator, so it stays permissive: most ICMPv6 messages are not MLD
        return parseOrNull(p[off] & 0xff, Arrays.copyOfRange(p, off + 4, p.length));
    }

    /**
     * Parses the body of an ICMPv6 message whose type the caller has already matched as MLD.
     * Throws rather than returning null: the type says these bytes are MLD.
     */
    public static Mld parse(int icmpType, byte[] p) throws IllegalRawDataException {
        final Mld parsed = parseOrNull(icmpType, p);
        if (parsed == null) throw Raw.notA("MLD", p);
        return parsed;
    }

    /**
     * Parses the body of an ICMPv6 message, i.e. everything after type, code and checksum.
     * Returns null if the type is not MLD or the body does not fit.
     */
    private static Mld parseOrNull(int icmpType, byte[] p) {
        return switch (icmpType) {
            case TYPE_QUERY -> parseQuery(p);
            case TYPE_V1_REPORT, TYPE_DONE -> p.length < 20 ? null
                    : new Mld(1, icmpType, u16(p, 0), ipv6(p, 4), List.of(), List.of(), null, null);
            case TYPE_V2_REPORT -> parseV2Report(p);
            default -> null;
        };
    }

    /** A version 1 query body is 20 bytes; version 2 adds the source list after it. */
    private static Mld parseQuery(byte[] p) {
        if (p.length < 20) return null;
        final int maxResponse = u16(p, 0);
        final Inet6Address group = ipv6(p, 4);
        if (p.length < 24) {
            return new Mld(1, TYPE_QUERY, maxResponse, group, List.of(), List.of(), null, null);
        }
        final int robustness = p[20] & 0x07;
        final int qqic = p[21] & 0xff;
        final int sourceCount = u16(p, 22);
        final List<Inet6Address> sources = new ArrayList<>();
        for (int i = 0, off = 24; i < sourceCount && off + 16 <= p.length; i++, off += 16) {
            final Inet6Address s = ipv6(p, off);
            if (s != null) sources.add(s);
        }
        return new Mld(2, TYPE_QUERY, maxResponse, group, List.of(), sources, robustness, decodeTime(qqic));
    }

    private static Mld parseV2Report(byte[] p) {
        if (p.length < 4) return null;
        final int recordCount = u16(p, 2);
        final List<GroupRecord> records = new ArrayList<>();
        int off = 4;
        for (int i = 0; i < recordCount && off + 20 <= p.length; i++) {
            final int recordType = p[off] & 0xff;
            final int auxWords = p[off + 1] & 0xff;
            final int sourceCount = u16(p, off + 2);
            final Inet6Address group = ipv6(p, off + 4);
            final List<Inet6Address> sources = new ArrayList<>();
            int s = off + 20;
            for (int k = 0; k < sourceCount && s + 16 <= p.length; k++, s += 16) {
                final Inet6Address source = ipv6(p, s);
                if (source != null) sources.add(source);
            }
            if (group != null) records.add(new GroupRecord(recordType, group, sources));
            off = s + auxWords * 4;
        }
        if (records.isEmpty()) return null;
        return new Mld(2, TYPE_V2_REPORT, 0, null, records, List.of(), null, null);
    }

    /** Above 32768 the interval is stored as a floating point value. */
    private static int decodeTime(int code) {
        if (code < 128) return code;
        final int mantissa = code & 0x0f;
        final int exponent = (code >> 4) & 0x07;
        return (mantissa | 0x10) << (exponent + 3);
    }

    private static Inet6Address ipv6(byte[] p, int off) {
        if (off + 16 > p.length) return null;
        try {
            return (Inet6Address) InetAddress.getByAddress(Arrays.copyOfRange(p, off, off + 16));
        } catch (UnknownHostException | ClassCastException e) {
            return null;
        }
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
