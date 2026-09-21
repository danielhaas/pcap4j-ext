package li.haas.pcap4j.ext;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.Arrays;

/**
 * NAT Port Mapping Protocol (RFC 6886), which pcap4j does not decode.
 * UDP port 5351 towards the gateway, announcements to 224.0.0.1:5350. Version byte is 0.
 */
import org.pcap4j.packet.IllegalRawDataException;

public record NatPmp(int opcode, Integer resultCode, Long epochSeconds,
                     Inet4Address externalAddress,
                     Integer internalPort, Integer externalPort, Long lifetime) {

    public static final int OP_EXTERNAL_ADDRESS = 0;
    public static final int OP_MAP_UDP = 1;
    public static final int OP_MAP_TCP = 2;
    private static final int RESPONSE = 128;  // responses are the request opcode + 128

    public boolean isResponse() {
        return opcode >= RESPONSE;
    }

    public String operation() {
        return switch (opcode & 0x7f) {
            case OP_EXTERNAL_ADDRESS -> "external address";
            case OP_MAP_UDP -> "map udp";
            case OP_MAP_TCP -> "map tcp";
            default -> "opcode " + (opcode & 0x7f);
        };
    }

    @Override
    public String toString() {
        return "NAT-PMP " + operation() + (isResponse() ? " response" : " request")
                + (resultCode == null ? "" : " result=" + resultCode)
                + (externalAddress == null ? "" : " external=" + externalAddress.getHostAddress())
                + (internalPort == null ? "" : " " + internalPort + " -> " + externalPort)
                + (lifetime == null ? "" : " lifetime=" + lifetime + "s");
    }

    /**
     * Parses bytes the caller has already identified as NAT-PMP, for example by protocol id or port.
     * Throws rather than returning null: at this point the bytes claim to be this protocol.
     */
    public static NatPmp parse(byte[] p) throws IllegalRawDataException {
        final NatPmp parsed = parseOrNull(p);
        if (parsed == null) throw Raw.notA("NAT-PMP", p);
        return parsed;
    }

    /** Returns null if the data is not NAT-PMP. */
    private static NatPmp parseOrNull(byte[] p) {
        if (p.length < 2 || p[0] != 0) return null;  // version 0; PCP uses 2
        final int opcode = p[1] & 0xff;

        if (opcode < RESPONSE) {
            // request: external address is 2 bytes, a mapping request 12
            if (opcode == OP_EXTERNAL_ADDRESS) {
                return new NatPmp(opcode, null, null, null, null, null, null);
            }
            if ((opcode == OP_MAP_UDP || opcode == OP_MAP_TCP) && p.length >= 12) {
                return new NatPmp(opcode, null, null, null, u16(p, 4), u16(p, 6), u32(p, 8));
            }
            return null;
        }

        if (p.length < 8) return null;
        final int result = u16(p, 2);
        final long epoch = u32(p, 4);
        return switch (opcode) {
            case RESPONSE + OP_EXTERNAL_ADDRESS -> p.length < 12 ? null
                    : new NatPmp(opcode, result, epoch, ipv4(p, 8), null, null, null);
            case RESPONSE + OP_MAP_UDP, RESPONSE + OP_MAP_TCP -> p.length < 16 ? null
                    : new NatPmp(opcode, result, epoch, null, u16(p, 8), u16(p, 10), u32(p, 12));
            default -> null;
        };
    }

    private static Inet4Address ipv4(byte[] p, int off) {
        try {
            return (Inet4Address) Inet4Address.getByAddress(Arrays.copyOfRange(p, off, off + 4));
        } catch (UnknownHostException e) {
            return null;  // cannot happen for 4 bytes
        }
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
    }

    private static long u32(byte[] p, int off) {
        return ((long) u16(p, off) << 16) | u16(p, off + 2);
    }
}
