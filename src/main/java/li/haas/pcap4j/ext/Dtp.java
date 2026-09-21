package li.haas.pcap4j.ext;

import org.pcap4j.util.MacAddress;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Cisco Dynamic Trunking Protocol, which pcap4j does not decode.
 * It arrives after SNAP with OUI 00:00:0c and protocol ID 0x2004, sent to 01:00:0c:cc:cc:cc.
 * Payload: version byte, then TLVs of type (2), length (2, includes these 4 bytes), value.
 */
import org.pcap4j.packet.IllegalRawDataException;

public record Dtp(int version, String domain, int status, int trunkType, MacAddress neighbor) {

    private static final int TLV_DOMAIN = 0x0001;
    private static final int TLV_STATUS = 0x0002;
    private static final int TLV_TYPE = 0x0003;
    private static final int TLV_NEIGHBOR = 0x0004;

    /** Trunk operating status: whether the port currently is a trunk. */
    public boolean isTrunk() {
        return (status & 0x80) != 0;
    }

    /** Trunk administrative status, i.e. the configured "switchport mode". */
    public String adminMode() {
        return switch (status & 0x07) {
            case 0x01 -> "on";
            case 0x02 -> "off";
            case 0x03 -> "desirable";
            case 0x04 -> "auto";
            default -> String.format("unknown 0x%x", status & 0x07);
        };
    }

    /** Trunk encapsulation, operating (upper 3 bits) and administrative (lower 3 bits). */
    public String encapsulation() {
        return encapsulation((trunkType >> 5) & 0x07) + "/" + encapsulation(trunkType & 0x07);
    }

    private static String encapsulation(int v) {
        return switch (v) {
            case 0x00 -> "negotiated";
            case 0x01 -> "native";
            case 0x02 -> "isl";
            case 0x05 -> "802.1q";
            default -> String.format("unknown 0x%x", v);
        };
    }

    @Override
    public String toString() {
        return "DTP " + (isTrunk() ? "trunk" : "access") + " mode=" + adminMode()
                + " encap=" + encapsulation()
                + (domain.isEmpty() ? "" : " domain=" + domain)
                + (neighbor == null ? "" : " neighbor=" + neighbor);
    }

    /**
     * Parses bytes the caller has already identified as DTP, for example by protocol id or port.
     * Throws rather than returning null: at this point the bytes claim to be this protocol.
     */
    public static Dtp parse(byte[] p) throws IllegalRawDataException {
        final Dtp parsed = parseOrNull(p);
        if (parsed == null) throw Raw.notA("DTP", p);
        return parsed;
    }

    /** Returns null if the data is not a DTP frame. */
    private static Dtp parseOrNull(byte[] p) {
        // there is no magic number, so require a plausible version and one well formed TLV
        if (p.length < 5) return null;
        final int version = p[0] & 0xff;
        if (version != 1) return null;
        int known = 0;
        String domain = "";
        int status = 0;
        int trunkType = 0;
        MacAddress neighbor = null;

        int off = 1;
        while (off + 4 <= p.length) {
            final int type = u16(p, off);
            final int len = u16(p, off + 2);
            if (len < 4 || off + len > p.length) break;  // malformed or trailing padding
            final int v = off + 4;
            final int vlen = len - 4;
            switch (type) {
                case TLV_DOMAIN -> { domain = string(p, v, vlen); known++; }
                case TLV_STATUS -> { if (vlen >= 1) { status = p[v] & 0xff; known++; } }
                case TLV_TYPE -> { if (vlen >= 1) { trunkType = p[v] & 0xff; known++; } }
                case TLV_NEIGHBOR -> {
                    if (vlen >= 6) {
                        neighbor = MacAddress.getByAddress(Arrays.copyOfRange(p, v, v + 6));
                        known++;
                    }
                }
                default -> { }
            }
            off += len;
        }
        if (known == 0) return null;
        return new Dtp(version, domain, status, trunkType, neighbor);
    }

    // the domain is a NUL-terminated string, all zeros when no VTP domain is set
    private static String string(byte[] p, int off, int len) {
        int end = off;
        while (end < off + len && p[end] != 0) end++;
        return new String(p, off, end - off, StandardCharsets.US_ASCII);
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
    }
}
