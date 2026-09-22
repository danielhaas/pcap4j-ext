package li.haas.pcap4j.ext;

import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.MacAddress;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Cisco Group Management Protocol, which pcap4j does not decode.
 *
 * <p>A switch floods multicast to every port unless something tells it better. CGMP is the pre-standard way
 * Cisco solved that: the router, which sees the IGMP joins and leaves, tells the switch which host MAC
 * joined or left which group MAC, and the switch programs its forwarding table accordingly. IGMP snooping
 * does the same job by watching IGMP directly and has replaced CGMP almost everywhere, so seeing it at all
 * dates the equipment.
 *
 * <p><b>On the wire:</b> SNAP with OUI 00:00:0c and protocol id 0x2001, sent to 01:00:0c:dd:dd:dd. The
 * payload is the version and the type, join or leave, in the two nibbles of the first byte, two reserved
 * bytes, a count, and then that many pairs of group MAC and host MAC.
 *
 * <p><b>Parsed:</b> the type and every group/host pair. The special all-zero group MAC, which means "leave
 * all", is returned as it appears rather than being expanded.
 */
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
