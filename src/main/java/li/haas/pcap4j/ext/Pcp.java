package li.haas.pcap4j.ext;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

/**
 * Port Control Protocol version 2 (RFC 6887), the successor of NAT-PMP, which pcap4j does not decode.
 * Same UDP port 5351, told apart from NAT-PMP by the version byte (2 instead of 0).
 * Addresses are always 16 bytes; IPv4 is carried as an IPv4-mapped IPv6 address.
 */
import org.pcap4j.packet.IllegalRawDataException;

public record Pcp(int opcode, boolean response, long lifetime,
                  InetAddress clientAddress,          // requests only
                  Integer resultCode, Long epochSeconds,  // responses only
                  Integer protocol, Integer internalPort, Integer externalPort, InetAddress externalAddress) implements Protocol {

    /** PCP shares NAT-PMP's port and is told apart by this version byte. */
    public static final int VERSION = 2;

    public static final int OP_ANNOUNCE = 0;
    public static final int OP_MAP = 1;
    public static final int OP_PEER = 2;

    private static final int HEADER_LENGTH = 24;

    public String operation() {
        return switch (opcode) {
            case OP_ANNOUNCE -> "announce";
            case OP_MAP -> "map";
            case OP_PEER -> "peer";
            default -> "opcode " + opcode;
        };
    }

    @Override
    public String toString() {
        return "PCP " + operation() + (response ? " response" : " request")
                + " lifetime=" + lifetime + "s"
                + (resultCode == null ? "" : " result=" + resultCode)
                + (clientAddress == null ? "" : " client=" + clientAddress.getHostAddress())
                + (internalPort == null ? "" : " " + protocolName() + " " + internalPort + " -> " + externalPort)
                // an all-zero address means "any", i.e. the client has no preference
                + (externalAddress == null || externalAddress.isAnyLocalAddress()
                        ? "" : " external=" + externalAddress.getHostAddress());
    }

    private String protocolName() {
        if (protocol == null) return "";
        return switch (protocol) {
            case 0 -> "all";
            case 6 -> "tcp";
            case 17 -> "udp";
            default -> "proto " + protocol;
        };
    }

    /**
     * Parses bytes the caller has already identified as PCP, for example by protocol id or port.
     * Throws rather than returning null: at this point the bytes claim to be this protocol.
     */
    public static Pcp parse(byte[] p) throws IllegalRawDataException {
        final Pcp parsed = parseOrNull(p);
        if (parsed == null) throw Raw.notA("PCP", p);
        return parsed;
    }

    /** Returns null if the data is not PCP version 2. */
    private static Pcp parseOrNull(byte[] p) {
        if (p.length < HEADER_LENGTH || p[0] != 2) return null;  // version 2; NAT-PMP uses 0
        final boolean response = (p[1] & 0x80) != 0;
        final int opcode = p[1] & 0x7f;
        final long lifetime = u32(p, 4);

        InetAddress client = null;
        Integer result = null;
        Long epoch = null;
        if (response) {
            result = p[3] & 0xff;
            epoch = u32(p, 8);
        } else {
            client = address(p, 8);
        }

        Integer protocol = null, internalPort = null, externalPort = null;
        InetAddress external = null;
        // MAP and PEER carry: nonce (12), protocol (1), reserved (3), internal port (2), external port (2), external IP (16)
        if ((opcode == OP_MAP || opcode == OP_PEER) && p.length >= HEADER_LENGTH + 36) {
            final int d = HEADER_LENGTH;
            protocol = p[d + 12] & 0xff;
            internalPort = u16(p, d + 16);
            externalPort = u16(p, d + 18);
            external = address(p, d + 20);
        }
        return new Pcp(opcode, response, lifetime, client, result, epoch,
                protocol, internalPort, externalPort, external);
    }

    /** 16 bytes; an IPv4-mapped address (::ffff:a.b.c.d) is returned as an Inet4Address. */
    private static InetAddress address(byte[] p, int off) {
        if (off + 16 > p.length) return null;
        final byte[] b = Arrays.copyOfRange(p, off, off + 16);
        try {
            return InetAddress.getByAddress(b);  // maps ::ffff:a.b.c.d to Inet4Address itself
        } catch (UnknownHostException e) {
            return null;  // cannot happen for 16 bytes
        }
    }

    public boolean isIpv4Client() {
        return clientAddress instanceof Inet4Address;
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
    }

    private static long u32(byte[] p, int off) {
        return ((long) u16(p, off) << 16) | u16(p, off + 2);
    }
}
