package li.haas.pcap4j.ext;

import org.pcap4j.util.MacAddress;

import java.util.Arrays;

/**
 * Spanning Tree BPDU (IEEE 802.1D / 802.1w / 802.1s common part), which pcap4j does not decode.
 * It arrives after an LLC header with DSAP/SSAP 0x42, or after SNAP (OUI 00:00:0c, PID 0x010b) for Cisco PVST+.
 */
import org.pcap4j.packet.IllegalRawDataException;

public record Bpdu(int version, int type, int flags,
                   BridgeId root, long rootPathCost, BridgeId bridge, int portId,
                   double messageAge, double maxAge, double helloTime, double forwardDelay) implements Protocol {

    /** Cisco PVST+ carries a BPDU under this SNAP protocol id instead of LLC DSAP 0x42. */
    public static final int PVST_PROTOCOL_ID = 0x010b;
    /** The LLC service access point that carries a plain BPDU. */
    public static final int LLC_SAP = 0x42;

    public static final int VERSION_STP = 0;
    public static final int VERSION_RSTP = 2;
    public static final int VERSION_MSTP = 3;

    public static final int TYPE_CONFIG = 0x00;
    public static final int TYPE_RST = 0x02;   // RSTP and MSTP
    public static final int TYPE_TCN = 0x80;   // topology change notification, carries no bridge info

    /** Priority (upper 4 bits, multiple of 4096) plus system ID extension (lower 12 bits, the VLAN for PVST+). */
    public record BridgeId(int priority, int systemIdExtension, MacAddress mac) {
        @Override
        public String toString() {
            return priority + "/" + systemIdExtension + "/" + mac;
        }
    }

    public boolean isTcn() {
        return type == TYPE_TCN;
    }

    public boolean topologyChange() {
        return (flags & 0x01) != 0;
    }

    /**
     * Parses bytes the caller has already identified as a BPDU, for example by protocol id or port.
     * Throws rather than returning null: at this point the bytes claim to be this protocol.
     */
    public static Bpdu parse(byte[] p) throws IllegalRawDataException {
        final Bpdu parsed = parseOrNull(p);
        if (parsed == null) throw Raw.notA("a BPDU", p);
        return parsed;
    }

    /** Returns null if the data is not a BPDU. */
    private static Bpdu parseOrNull(byte[] p) {
        if (p.length < 4 || u16(p, 0) != 0x0000) return null;
        final int version = p[2] & 0xff;
        final int type = p[3] & 0xff;

        if (type == TYPE_TCN) {
            return new Bpdu(version, type, 0, null, 0, null, 0, 0, 0, 0, 0);
        }
        if ((type != TYPE_CONFIG && type != TYPE_RST) || p.length < 35) return null;

        return new Bpdu(version, type, p[4] & 0xff,
                bridgeId(p, 5), u32(p, 13), bridgeId(p, 17), u16(p, 25),
                time(p, 27), time(p, 29), time(p, 31), time(p, 33));
    }

    private static BridgeId bridgeId(byte[] p, int off) {
        final int prio = u16(p, off);
        return new BridgeId(prio & 0xf000, prio & 0x0fff,
                MacAddress.getByAddress(Arrays.copyOfRange(p, off + 2, off + 8)));
    }

    // timers are in units of 1/256 second
    private static double time(byte[] p, int off) {
        return u16(p, off) / 256.0;
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
    }

    private static long u32(byte[] p, int off) {
        return ((long) u16(p, off) << 16) | u16(p, off + 2);
    }
}
