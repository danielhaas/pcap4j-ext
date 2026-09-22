package li.haas.pcap4j.ext;

import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.MacAddress;

import java.util.Arrays;

/**
 * The Marker protocol (IEEE 802.1AX), the other half of the slow protocol that LACP rides on. pcap4j does
 * not decode it.
 *
 * <p>Frames of one conversation must not be reordered, which makes moving a conversation from one link of a
 * bundle to another awkward: packets already in flight on the old link could arrive after packets sent on
 * the new one. The marker solves it. Before the move the aggregator sends a marker down the old link; when
 * the partner echoes it back, everything that was in flight has arrived and the move is safe. So a marker
 * request without a matching response means a rebalance is stuck, and a partner that never answers markers
 * has an incomplete LACP implementation.
 *
 * <p><b>On the wire:</b> EtherType 0x8809, subtype 2, to 01:80:c2:00:00:02. Sent only when a move is
 * pending, not periodically.
 *
 * <p><b>Parsed:</b> the type, the requester's port and system, and the transaction id. See {@link
 * #exchangeId()}, which is the system, port and transaction id joined into a key that matches a response to
 * its request.
 */
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
