package li.haas.pcap4j.ext;

import org.pcap4j.util.MacAddress;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Cisco Group Management Protocol, which pcap4j does not decode.
 * SNAP with OUI 00:00:0c and protocol ID 0x2001, sent to 01:00:0c:dd:dd:dd.
 * The router tells the switch which host joined or left which multicast group, so the switch
 * can forward that group to one port instead of flooding it. Superseded by IGMP snooping.
 */
import org.pcap4j.packet.IllegalRawDataException;

import java.util.Collections;

import java.util.LinkedHashMap;

import java.util.LinkedHashSet;

import java.util.Map;

import java.util.Set;

public record Cgmp(int version, int type, List<Entry> entries) implements Protocol {
    public Cgmp {
        entries = copy(entries);
    }


    public static final int PROTOCOL_ID = 0x2001;

    public static final int TYPE_JOIN = 0;
    public static final int TYPE_LEAVE = 1;

    /** A group and the host joining or leaving it. */
    public record Entry(MacAddress group, MacAddress host) {
        @Override
        public String toString() {
            return group + " <- " + host;
        }
    }

    public boolean isJoin() {
        return type == TYPE_JOIN;
    }

    public String typeName() {
        return switch (type) {
            case TYPE_JOIN -> "join";
            case TYPE_LEAVE -> "leave";
            default -> "type " + type;
        };
    }

    @Override
    public String toString() {
        return "CGMP " + typeName() + " " + entries;
    }

    /**
     * Parses bytes the caller has already identified as CGMP, for example by protocol id or port.
     * Throws rather than returning null: at this point the bytes claim to be this protocol.
     */
    public static Cgmp parse(byte[] p) throws IllegalRawDataException {
        final Cgmp parsed = parseOrNull(p);
        if (parsed == null) throw Raw.notA("CGMP", p);
        return parsed;
    }

    /** Returns null if the data is not CGMP. */
    private static Cgmp parseOrNull(byte[] p) {
        if (p.length < 4) return null;
        final int version = (p[0] & 0xf0) >> 4;
        final int type = p[0] & 0x0f;
        if (version != 1 || type > TYPE_LEAVE) return null;

        final int count = p[3] & 0xff;
        final List<Entry> entries = new ArrayList<>();
        int off = 4;
        for (int i = 0; i < count && off + 12 <= p.length; i++, off += 12) {
            entries.add(new Entry(MacAddress.getByAddress(Arrays.copyOfRange(p, off, off + 6)),
                    MacAddress.getByAddress(Arrays.copyOfRange(p, off + 6, off + 12))));
        }
        return new Cgmp(version, type, entries);
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
