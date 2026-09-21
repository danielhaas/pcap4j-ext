package li.haas.pcap4j.ext;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * IGMP (RFC 2236 for version 2, RFC 3376 for version 3), IP protocol 2, which pcap4j does not decode.
 * Hosts announce which multicast groups they want; the elected querier on the segment asks
 * periodically who is still listening. Version 3 reports also name the sources a host will accept.
 */
public record Igmp(int version, int type, int maxResponseSeconds,
                   Inet4Address group, List<GroupRecord> records, List<Inet4Address> querySources,
                   Integer robustness, Integer queryInterval) {

    public static final int IP_PROTOCOL = 2;

    public static final int TYPE_QUERY = 0x11;
    public static final int TYPE_V1_REPORT = 0x12;
    public static final int TYPE_V2_REPORT = 0x16;
    public static final int TYPE_LEAVE = 0x17;
    public static final int TYPE_V3_REPORT = 0x22;

    /** One group in a version 3 report, with the sources the host includes or excludes. */
    public record GroupRecord(int recordType, Inet4Address group, List<Inet4Address> sources) {

        public String recordTypeName() {
            return switch (recordType) {
                case 1 -> "listening to only";     // MODE_IS_INCLUDE
                case 2 -> "listening to all but";  // MODE_IS_EXCLUDE
                case 3 -> "now only";              // CHANGE_TO_INCLUDE_MODE, an empty list means leaving
                case 4 -> "now all but";           // CHANGE_TO_EXCLUDE_MODE
                case 5 -> "also";                  // ALLOW_NEW_SOURCES
                case 6 -> "no longer";             // BLOCK_OLD_SOURCES
                default -> "record type " + recordType;
            };
        }

        /** A change to include mode with no sources is how version 3 leaves a group. */
        public boolean isLeave() {
            return recordType == 3 && sources.isEmpty();
        }

        @Override
        public String toString() {
            return group.getHostAddress()
                    + (sources.isEmpty() ? (isLeave() ? " (leaving)" : "") : " " + recordTypeName() + " "
                        + sources.stream().map(Inet4Address::getHostAddress).toList());
        }
    }

    public boolean isQuery() {
        return type == TYPE_QUERY;
    }

    /** A general query asks about every group; a group specific one names a single group. */
    public boolean isGeneralQuery() {
        return isQuery() && (group == null || group.isAnyLocalAddress());
    }

    public String typeName() {
        return switch (type) {
            case TYPE_QUERY -> isGeneralQuery() ? "general query" : "group query";
            case TYPE_V1_REPORT -> "v1 report";
            case TYPE_V2_REPORT -> "report";
            case TYPE_LEAVE -> "leave";
            case TYPE_V3_REPORT -> "v3 report";
            default -> String.format("type 0x%02x", type);
        };
    }

    @Override
    public String toString() {
        return "IGMPv" + version + " " + typeName()
                + (group == null || group.isAnyLocalAddress() ? "" : " " + group.getHostAddress())
                + (records.isEmpty() ? "" : " " + records)
                + (querySources.isEmpty() ? "" : " sources=" + querySources.stream().map(Inet4Address::getHostAddress).toList());
    }

    /** Returns null if the data is not IGMP. */
    public static Igmp parse(byte[] p) {
        if (p.length < 8) return null;
        final int type = p[0] & 0xff;

        return switch (type) {
            case TYPE_V3_REPORT -> parseV3Report(p);
            case TYPE_QUERY -> parseQuery(p);
            case TYPE_V1_REPORT, TYPE_V2_REPORT, TYPE_LEAVE -> {
                final int version = type == TYPE_V1_REPORT ? 1 : 2;
                yield new Igmp(version, type, (p[1] & 0xff) / 10, ipv4(p, 4),
                        List.of(), List.of(), null, null);
            }
            default -> null;
        };
    }

    /** Version 3 queries are longer than version 2 ones and carry a source list. */
    private static Igmp parseQuery(byte[] p) {
        final Inet4Address group = ipv4(p, 4);
        if (p.length < 12) {
            return new Igmp(2, TYPE_QUERY, (p[1] & 0xff) / 10, group, List.of(), List.of(), null, null);
        }
        final int robustness = p[8] & 0x07;
        final int qqic = p[9] & 0xff;
        final int sourceCount = u16(p, 10);
        final List<Inet4Address> sources = new ArrayList<>();
        for (int i = 0, off = 12; i < sourceCount && off + 4 <= p.length; i++, off += 4) {
            final Inet4Address s = ipv4(p, off);
            if (s != null) sources.add(s);
        }
        return new Igmp(3, TYPE_QUERY, (p[1] & 0xff) / 10, group, List.of(), sources,
                robustness, decodeTime(qqic));
    }

    private static Igmp parseV3Report(byte[] p) {
        final int groupCount = u16(p, 6);
        final List<GroupRecord> records = new ArrayList<>();
        int off = 8;
        for (int i = 0; i < groupCount && off + 8 <= p.length; i++) {
            final int recordType = p[off] & 0xff;
            final int auxWords = p[off + 1] & 0xff;
            final int sourceCount = u16(p, off + 2);
            final Inet4Address group = ipv4(p, off + 4);
            final List<Inet4Address> sources = new ArrayList<>();
            int s = off + 8;
            for (int k = 0; k < sourceCount && s + 4 <= p.length; k++, s += 4) {
                final Inet4Address source = ipv4(p, s);
                if (source != null) sources.add(source);
            }
            if (group != null) records.add(new GroupRecord(recordType, group, sources));
            off = s + auxWords * 4;
        }
        if (records.isEmpty()) return null;
        return new Igmp(3, TYPE_V3_REPORT, 0, null, records, List.of(), null, null);
    }

    /** Times above 128 are stored as a floating point value, not as tenths of a second. */
    private static int decodeTime(int code) {
        if (code < 128) return code;
        final int mantissa = code & 0x0f;
        final int exponent = (code >> 4) & 0x07;
        return (mantissa | 0x10) << (exponent + 3);
    }

    private static Inet4Address ipv4(byte[] p, int off) {
        if (off + 4 > p.length) return null;
        try {
            return (Inet4Address) Inet4Address.getByAddress(Arrays.copyOfRange(p, off, off + 4));
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
    }
}
