package li.haas.pcap4j.ext;

import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.MacAddress;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Cisco Port Aggregation Protocol, the pre-standard counterpart of LACP, which pcap4j does not decode.
 *
 * <p>PAgP does what LACP does, bundle several links into one and make sure both ends agree, and predates
 * the standard. Cisco equipment still defaults to it in some configurations, and a link where one end runs
 * PAgP and the other LACP will never bundle, which is a common enough fault that it is worth being able to
 * see which of the two a port is speaking. Its TLVs also carry the neighbour's device and port name, the
 * same identification CDP gives, so a PAgP frame identifies its sender even without CDP.
 *
 * <p><b>On the wire:</b> SNAP with OUI 00:00:0c and protocol id 0x0104, to 01:00:0c:cc:cc:cc. Two different
 * formats share that id: version 1 is the info packet that carries the state, version 2 is a flush packet,
 * sent when a conversation moves between links, in the same role as the LACP marker.
 *
 * <p><b>Parsed:</b> the info packet into both endpoints, each with device id, learn capability, port
 * priority and ifindex, plus the partner count, the device and port name and the agport MAC. Flush packets
 * are a different shape and are read by {@link #parseFlush(byte[])} into {@link Pagp.Flush}.
 */
public record Pagp(int version, int flags,
                   Endpoint local, Endpoint partner,
                   int partnerCount, String deviceName, String portName, MacAddress agportMac) implements Protocol {

    public static final int PROTOCOL_ID = 0x0104;

    public static final int VERSION_INFO = 1;
    public static final int VERSION_FLUSH = 2;

    private static final int FLAG_SLOW_HELLO = 0x01;
    private static final int FLAG_AUTO_MODE = 0x02;
    private static final int FLAG_CONSISTENT_STATE = 0x04;

    private static final int TLV_DEVICE_NAME = 1;
    private static final int TLV_PORT_NAME = 2;
    private static final int TLV_AGPORT_MAC = 3;

    /** One side of the link: who it is, which bundle the port can join, and which port it is. */
    public record Endpoint(MacAddress deviceId, int learnCapability, int portPriority,
                           long sentPortIfIndex, long groupCapability, long groupIfIndex) {

        /** Ports that agree on the group capability may be bundled together. */
        @Override
        public String toString() {
            return deviceId + " port=" + sentPortIfIndex + " group=" + groupCapability
                    + (groupIfIndex == 0 ? "" : " agport=" + groupIfIndex);
        }
    }

    /** Hellos every 30 seconds instead of every second. */
    public boolean slowHello() {
        return (flags & FLAG_SLOW_HELLO) != 0;
    }

    /** Waiting to be asked ("auto") rather than starting negotiation ("desirable"). */
    public boolean autoMode() {
        return (flags & FLAG_AUTO_MODE) != 0;
    }

    /** Both ends agree on what they see, which is the condition for the bundle to form. */
    public boolean consistentState() {
        return (flags & FLAG_CONSISTENT_STATE) != 0;
    }

    /** No partner device id means nothing is answering on this link. */
    public boolean partnerMissing() {
        return partner == null || partner.deviceId() == null
                || MacAddress.getByName("00:00:00:00:00:00").equals(partner.deviceId());
    }

    @Override
    public String toString() {
        return "PAgP " + (deviceName == null ? "" : deviceName + " ")
                + (portName == null ? "" : portName + " ")
                + "local " + local + (partner == null ? "" : "  partner " + partner)
                + (consistentState() ? "  consistent" : "  not consistent")
                + (autoMode() ? "  auto" : "  desirable");
    }

    /**
     * A flush packet, PAgP's counterpart of the LACP marker: before a conversation moves to
     * another link of the bundle, the sender asks the partner to flush what is still in flight.
     * Version 2, and a completely different layout from the info packet.
     */
    public record Flush(MacAddress localDeviceId, MacAddress partnerDeviceId, long transactionId) {

        public String exchangeId() {
            return localDeviceId + "/" + partnerDeviceId + "/" + transactionId;
        }

        @Override
        public String toString() {
            return "PAgP flush " + localDeviceId + " -> " + partnerDeviceId + " transaction " + transactionId;
        }
    }

    /**
     * Parses bytes the caller has already identified as a PAgP flush packet, by protocol id and
     * a version byte of 2. Throws rather than returning null.
     */
    public static Flush parseFlush(byte[] p) throws IllegalRawDataException {
        final Flush parsed = parseFlushOrNull(p);
        if (parsed == null) throw Raw.notA("a PAgP flush packet", p);
        return parsed;
    }

    /** Returns null if the data is not a PAgP flush packet. */
    private static Flush parseFlushOrNull(byte[] p) {
        if (p.length < 18 || (p[0] & 0xff) != VERSION_FLUSH) return null;
        return new Flush(MacAddress.getByAddress(Arrays.copyOfRange(p, 2, 8)),
                MacAddress.getByAddress(Arrays.copyOfRange(p, 8, 14)), u32(p, 14));
    }

    /**
     * Parses bytes the caller has already identified as a PAgP info packet, by protocol id and
     * a version byte of 1. Throws rather than returning null.
     */
    public static Pagp parse(byte[] p) throws IllegalRawDataException {
        final Pagp parsed = parseOrNull(p);
        if (parsed == null) throw Raw.notA("a PAgP info packet", p);
        return parsed;
    }

    /** Returns null if the data is not a PAgP info packet. */
    private static Pagp parseOrNull(byte[] p) {
        if (p.length < 50) return null;
        final int version = p[0] & 0xff;
        if (version != VERSION_INFO) return null;   // a flush packet goes to parseFlush
        final int flags = p[1] & 0xff;

        final Endpoint local = endpoint(p, 2);
        final Endpoint partner = endpoint(p, 22);
        final int partnerCount = u16(p, 42);
        final int tlvCount = u16(p, 44);

        String deviceName = null, portName = null;
        MacAddress agport = null;

        int off = 46;
        for (int i = 0; i < tlvCount && off + 4 <= p.length; i++) {
            final int type = u16(p, off);
            final int len = u16(p, off + 2);        // the length includes these four bytes
            if (len < 4 || off + len > p.length) break;
            final int v = off + 4;
            final int vlen = len - 4;
            switch (type) {
                case TLV_DEVICE_NAME -> deviceName = text(p, v, vlen);
                case TLV_PORT_NAME -> portName = text(p, v, vlen);
                case TLV_AGPORT_MAC -> {
                    if (vlen >= 6) agport = MacAddress.getByAddress(Arrays.copyOfRange(p, v, v + 6));
                }
                default -> { }
            }
            off += len;
        }

        return new Pagp(version, flags, local, partner, partnerCount, deviceName, portName, agport);
    }

    /** device id (6), learn capability (1), port priority (1), sent port ifindex (4), group capability (4), group ifindex (4). */
    private static Endpoint endpoint(byte[] p, int off) {
        return new Endpoint(MacAddress.getByAddress(Arrays.copyOfRange(p, off, off + 6)),
                p[off + 6] & 0xff, p[off + 7] & 0xff,
                u32(p, off + 8), u32(p, off + 12), u32(p, off + 16));
    }

    private static String text(byte[] p, int off, int len) {
        int end = Math.min(off + len, p.length);
        while (end > off && p[end - 1] == 0) end--;
        return new String(p, off, Math.max(end - off, 0), StandardCharsets.UTF_8).trim();
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
    }

    private static long u32(byte[] p, int off) {
        return ((long) (p[off] & 0xff) << 24) | ((p[off + 1] & 0xff) << 16)
                | ((p[off + 2] & 0xff) << 8) | (p[off + 3] & 0xff);
    }
}
