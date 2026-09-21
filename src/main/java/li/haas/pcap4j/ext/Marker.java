package li.haas.pcap4j.ext;

import org.pcap4j.util.MacAddress;

import java.util.Arrays;

/**
 * The Marker protocol (IEEE 802.1AX), the other half of the slow protocol LACP rides on:
 * EtherType 0x8809, subtype 2. pcap4j does not decode it.
 * Before an aggregator moves a conversation from one link of a bundle to another it sends a
 * marker down the old link; once the partner echoes it back, everything in flight has arrived
 * and the move cannot reorder frames. An unanswered marker means the move stalled.
 */
import org.pcap4j.packet.IllegalRawDataException;

public record Marker(int version, int type, int requesterPort, MacAddress requesterSystem,
                     long transactionId) implements Protocol {

    public static final int SUBTYPE = 2;

    public static final int TYPE_REQUEST = 1;
    public static final int TYPE_RESPONSE = 2;

    public boolean isRequest() {
        return type == TYPE_REQUEST;
    }

    public String typeName() {
        return switch (type) {
            case TYPE_REQUEST -> "marker";
            case TYPE_RESPONSE -> "marker response";
            default -> "type " + type;
        };
    }

    /** Identifies the exchange, so a response can be matched to its request. */
    public String exchangeId() {
        return requesterSystem + "/" + requesterPort + "/" + transactionId;
    }

    @Override
    public String toString() {
        return "LACP " + typeName() + " from " + requesterSystem + " port " + requesterPort
                + " transaction " + transactionId;
    }

    /**
     * Parses bytes the caller has already identified as a marker PDU, for example by protocol id or port.
     * Throws rather than returning null: at this point the bytes claim to be this protocol.
     */
    public static Marker parse(byte[] p) throws IllegalRawDataException {
        final Marker parsed = parseOrNull(p);
        if (parsed == null) throw Raw.notA("a marker PDU", p);
        return parsed;
    }

    /** Returns null if the data is not a marker PDU. */
    private static Marker parseOrNull(byte[] p) {
        if (p.length < 20 || (p[0] & 0xff) != SUBTYPE) return null;
        final int version = p[1] & 0xff;
        final int type = p[2] & 0xff;
        final int length = p[3] & 0xff;
        if ((type != TYPE_REQUEST && type != TYPE_RESPONSE) || length < 16) return null;

        return new Marker(version, type, u16(p, 4),
                MacAddress.getByAddress(Arrays.copyOfRange(p, 6, 12)), u32(p, 12));
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
    }

    private static long u32(byte[] p, int off) {
        return ((long) (p[off] & 0xff) << 24) | ((p[off + 1] & 0xff) << 16)
                | ((p[off + 2] & 0xff) << 8) | (p[off + 3] & 0xff);
    }
}
