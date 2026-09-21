package li.haas.pcap4j.ext;

import org.pcap4j.util.MacAddress;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * LACP (IEEE 802.1AX, formerly 802.3ad), which pcap4j does not decode.
 * A slow protocol: EtherType 0x8809, subtype 1, sent to 01:80:c2:00:00:02, once a second or
 * once every 30 seconds. Each side describes itself (actor) and what it hears (partner),
 * so one LACPDU names both ends of the link and says whether the bundle is actually up.
 */
import org.pcap4j.packet.IllegalRawDataException;

public record Lacp(int version, Endpoint actor, Endpoint partner, Integer collectorMaxDelay) implements Protocol {

    public static final int ETHER_TYPE = 0x8809;
    public static final int SUBTYPE_LACP = 1;
    public static final int SUBTYPE_MARKER = 2;

    private static final int TLV_ACTOR = 1;
    private static final int TLV_PARTNER = 2;
    private static final int TLV_COLLECTOR = 3;
    private static final int TLV_TERMINATOR = 0;

    /** One side of the link: who it is, which bundle the port belongs to, and its state. */
    public record Endpoint(int systemPriority, MacAddress system, int key,
                           int portPriority, int port, int state) {

        public boolean active() {
            return (state & 0x01) != 0;      // sends LACPDUs rather than only answering
        }

        public boolean shortTimeout() {
            return (state & 0x02) != 0;      // expects one per second instead of one per 30s
        }

        public boolean aggregatable() {
            return (state & 0x04) != 0;
        }

        public boolean synchronized_() {
            return (state & 0x08) != 0;      // the port is in the bundle
        }

        public boolean collecting() {
            return (state & 0x10) != 0;      // accepting frames
        }

        public boolean distributing() {
            return (state & 0x20) != 0;      // sending frames
        }

        /** True when this side has heard nothing and is using configured defaults for the partner. */
        public boolean defaulted() {
            return (state & 0x40) != 0;
        }

        /** True when the partner information has aged out. */
        public boolean expired() {
            return (state & 0x80) != 0;
        }

        /** Carrying traffic: in the bundle and both receiving and sending. */
        public boolean bundled() {
            return synchronized_() && collecting() && distributing();
        }

        public List<String> stateNames() {
            final List<String> f = new ArrayList<>();
            f.add(active() ? "active" : "passive");
            f.add(shortTimeout() ? "short timeout" : "long timeout");
            if (!aggregatable()) f.add("individual");
            if (synchronized_()) f.add("in sync");
            if (collecting()) f.add("collecting");
            if (distributing()) f.add("distributing");
            if (defaulted()) f.add("defaulted");
            if (expired()) f.add("expired");
            return f;
        }

        @Override
        public String toString() {
            return system + " key=" + key + " port=" + port + " [" + String.join(", ", stateNames()) + "]";
        }
    }

    /** True when both ends agree the link is carrying traffic. */
    public boolean bundleUp() {
        return actor != null && partner != null && actor.bundled() && partner.bundled();
    }

    /** The other end is not speaking LACP: the port is probably configured static ("mode on"). */
    public boolean partnerMissing() {
        return partner != null && (partner.defaulted() || partner.expired()
                || MacAddress.getByName("00:00:00:00:00:00").equals(partner.system()));
    }

    @Override
    public String toString() {
        return "LACP actor " + actor + "  partner " + partner + (bundleUp() ? "  bundle up" : "");
    }

    /**
     * Parses bytes the caller has already identified as an LACPDU, for example by protocol id or port.
     * Throws rather than returning null: at this point the bytes claim to be this protocol.
     */
    public static Lacp parse(byte[] p) throws IllegalRawDataException {
        final Lacp parsed = parseOrNull(p);
        if (parsed == null) throw Raw.notA("an LACPDU", p);
        return parsed;
    }

    /** Returns null if the data is not an LACPDU. */
    private static Lacp parseOrNull(byte[] p) {
        if (p.length < 36 || (p[0] & 0xff) != SUBTYPE_LACP) return null;
        final int version = p[1] & 0xff;

        Endpoint actor = null, partner = null;
        Integer maxDelay = null;

        int off = 2;
        while (off + 2 <= p.length) {
            final int type = p[off] & 0xff;
            final int len = p[off + 1] & 0xff;
            if (type == TLV_TERMINATOR) break;
            if (len < 2 || off + len > p.length) break;
            final int v = off + 2;

            switch (type) {
                case TLV_ACTOR -> { if (len >= 20) actor = endpoint(p, v); }
                case TLV_PARTNER -> { if (len >= 20) partner = endpoint(p, v); }
                case TLV_COLLECTOR -> { if (len >= 4) maxDelay = u16(p, v); }
                default -> { }
            }
            off += len;
        }

        if (actor == null) return null;
        return new Lacp(version, actor, partner, maxDelay);
    }

    /** system priority (2), system (6), key (2), port priority (2), port (2), state (1). */
    private static Endpoint endpoint(byte[] p, int off) {
        return new Endpoint(u16(p, off),
                MacAddress.getByAddress(Arrays.copyOfRange(p, off + 2, off + 8)),
                u16(p, off + 8), u16(p, off + 10), u16(p, off + 12), p[off + 14] & 0xff);
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
    }
}
