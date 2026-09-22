package li.haas.pcap4j.ext;

/**
 * PTP, the Precision Time Protocol (IEEE 1588-2008, known as PTPv2), which pcap4j does not decode.
 *
 * <p>Where NTP is happy with milliseconds, PTP aims at sub-microsecond and gets there by having the network
 * hardware timestamp the packets. A best master clock algorithm elects a grandmaster from the announce
 * messages, everyone else synchronises down the tree from it, and delay requests measure the path so it can
 * be subtracted. Announce messages are therefore the interesting ones: each clock advertises its own
 * priority and quality, so the announces on a segment tell you which clock won, how good it claims to be
 * and how many hops away it is. Common on broadcast, industrial and trading networks, and increasingly in
 * mobile backhaul.
 *
 * <p><b>On the wire:</b> either EtherType 0x88f7 for the layer 2 mapping, usually to 01:1b:19:00:00:00, or
 * UDP, with the timestamped event messages on port 319 and everything else on port 320. A 34-byte common
 * header, then the body for the message type.
 *
 * <p><b>Parsed:</b> the common header for every type, and the grandmaster fields for an announce. Clock
 * identities are rendered as the usual colon-separated eight bytes. See {@link #clockClassName()} and
 * {@link #timeSourceName()} for what the grandmaster claims about itself. Timestamps themselves are not
 * read; this identifies the timing hierarchy rather than measuring it.
 */
public record Ptp(int version, int messageType, int domain, String sourceClockId, int sourcePort,
                  long sequenceId,
                  Integer priority1, Integer priority2, Integer clockClass, Integer clockAccuracy,
                  String grandmasterClockId, Integer stepsRemoved, Integer timeSource)
        implements Protocol {

    public static final int ETHER_TYPE = 0x88f7;
    public static final int EVENT_PORT = 319;
    public static final int GENERAL_PORT = 320;

    public static final int TYPE_SYNC = 0x0;
    public static final int TYPE_DELAY_REQ = 0x1;
    public static final int TYPE_FOLLOW_UP = 0x8;
    public static final int TYPE_DELAY_RESP = 0x9;
    public static final int TYPE_ANNOUNCE = 0xb;

    public String messageTypeName() {
        return switch (messageType) {
            case TYPE_SYNC -> "sync";
            case TYPE_DELAY_REQ -> "delay request";
            case 0x2 -> "peer delay request";
            case 0x3 -> "peer delay response";
            case TYPE_FOLLOW_UP -> "follow up";
            case TYPE_DELAY_RESP -> "delay response";
            case 0xa -> "peer delay response follow up";
            case TYPE_ANNOUNCE -> "announce";
            case 0xc -> "signaling";
            case 0xd -> "management";
            default -> String.format("type 0x%x", messageType);
        };
    }

    public boolean isAnnounce() {
        return messageType == TYPE_ANNOUNCE;
    }

    /** How the grandmaster describes its own quality; 6 and 7 mean it is locked to a real source. */
    public String clockClassName() {
        if (clockClass == null) return null;
        return switch (clockClass) {
            case 6 -> "primary reference, locked";
            case 7 -> "primary reference, holdover";
            case 13 -> "application specific, locked";
            case 14 -> "application specific, holdover";
            case 52, 58 -> "degraded";
            case 248 -> "default";
            case 255 -> "slave only";
            default -> "class " + clockClass;
        };
    }

    public String timeSourceName() {
        if (timeSource == null) return null;
        return switch (timeSource) {
            case 0x10 -> "atomic clock";
            case 0x20 -> "gps";
            case 0x30 -> "terrestrial radio";
            case 0x40 -> "ptp";
            case 0x50 -> "ntp";
            case 0x60 -> "hand set";
            case 0x90 -> "other";
            case 0xa0 -> "internal oscillator";
            default -> String.format("source 0x%02x", timeSource);
        };
    }

    @Override
    public String toString() {
        return "PTPv" + version + " " + messageTypeName() + " domain " + domain
                + " clock=" + sourceClockId
                + (grandmasterClockId == null ? "" : " grandmaster=" + grandmasterClockId)
                + (clockClassName() == null ? "" : " " + clockClassName())
                + (timeSourceName() == null ? "" : " from " + timeSourceName())
                + (priority1 == null ? "" : " priority=" + priority1 + "/" + priority2);
    }

    /** Returns null if the data is not PTP. */
    public static Ptp parse(byte[] p) {
        if (p.length < 34) return null;
        final int messageType = p[0] & 0x0f;
        final int version = p[1] & 0x0f;
        if (version < 1 || version > 2 || messageType > 0xd) return null;
        final int length = u16(p, 2);
        if (length < 34 || length > p.length + 8) return null;   // some captures truncate the payload

        final int domain = p[4] & 0xff;
        final String clockId = clockId(p, 20);
        final int sourcePort = u16(p, 28);
        final long sequence = u16(p, 30);

        if (messageType != TYPE_ANNOUNCE || p.length < 64) {
            return new Ptp(version, messageType, domain, clockId, sourcePort, sequence,
                    null, null, null, null, null, null, null);
        }

        // announce: origin timestamp (10), utc offset (2), reserved (1), priority1 (1),
        // grandmaster clock quality (4), priority2 (1), grandmaster identity (8),
        // steps removed (2), time source (1)
        final int priority1 = p[47] & 0xff;
        final int clockClass = p[48] & 0xff;
        final int clockAccuracy = p[49] & 0xff;
        final int priority2 = p[52] & 0xff;
        final String grandmaster = clockId(p, 53);
        final int stepsRemoved = u16(p, 61);
        final int timeSource = p[63] & 0xff;

        return new Ptp(version, messageType, domain, clockId, sourcePort, sequence,
                priority1, priority2, clockClass, clockAccuracy, grandmaster, stepsRemoved, timeSource);
    }

    /** An eight byte clock identity, written the way every PTP tool writes it. */
    private static String clockId(byte[] p, int off) {
        if (off + 8 > p.length) return null;
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", p[off + i]));
        }
        return sb.toString();
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
    }
}
