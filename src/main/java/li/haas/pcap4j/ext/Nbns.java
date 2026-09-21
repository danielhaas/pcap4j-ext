package li.haas.pcap4j.ext;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * NetBIOS Name Service (RFC 1002), UDP 137. A DNS-shaped message with NetBIOS names.
 * A node status response is the interesting one: it lists every name the host owns
 * and ends with the adapter's MAC address.
 */
public record Nbns(int transactionId, boolean response, int opcode,
                   List<Netbios.Name> questions,
                   List<Netbios.Name> names,          // names the host claims
                   List<Inet4Address> addresses,      // from NB records
                   String unitId) {                   // MAC from a node status response

    public static final int PORT = 137;

    private static final int OP_QUERY = 0;
    private static final int OP_REGISTRATION = 5;
    private static final int OP_RELEASE = 6;
    private static final int OP_WACK = 7;
    private static final int OP_REFRESH = 8;

    private static final int TYPE_NB = 0x0020;
    private static final int TYPE_NBSTAT = 0x0021;

    public String operation() {
        return switch (opcode) {
            case OP_QUERY -> "query";
            case OP_REGISTRATION -> "registration";
            case OP_RELEASE -> "release";
            case OP_WACK -> "wack";
            case OP_REFRESH -> "refresh";
            default -> "opcode " + opcode;
        };
    }

    @Override
    public String toString() {
        return "NBNS " + operation() + (response ? " response" : " request")
                + (questions.isEmpty() ? "" : " asks=" + questions)
                + (names.isEmpty() ? "" : " names=" + names)
                + (addresses.isEmpty() ? "" : " addresses=" + addresses.stream().map(Inet4Address::getHostAddress).toList())
                + (unitId == null ? "" : " mac=" + unitId);
    }

    /** Returns null if the data is not NBNS. */
    public static Nbns parse(byte[] p) {
        if (p.length < 12) return null;
        final int flags = u16(p, 2);
        final boolean response = (flags & 0x8000) != 0;
        final int opcode = (flags >> 11) & 0x0f;
        final int qdCount = u16(p, 4);
        final int anCount = u16(p, 6);
        final int arCount = u16(p, 10);

        final List<Netbios.Name> questions = new ArrayList<>();
        final List<Netbios.Name> names = new ArrayList<>();
        final List<Inet4Address> addresses = new ArrayList<>();
        String unitId = null;

        int off = 12;
        for (int i = 0; i < qdCount; i++) {
            final Netbios.Name n = Netbios.decode(p, off);
            if (n == null) return null;
            questions.add(n);
            off += Netbios.encodedLength(p, off) + 4;  // plus type and class
            if (off > p.length) return null;
        }

        // answers and additional records have the same shape; authority records are skipped by the counts
        for (int i = 0; i < anCount + arCount && off + 10 <= p.length; i++) {
            final Netbios.Name owner = Netbios.decode(p, off);
            if (owner == null) break;
            off += Netbios.encodedLength(p, off);
            if (off + 10 > p.length) break;
            final int type = u16(p, off);
            final int rdLength = u16(p, off + 8);
            final int rd = off + 10;
            if (rd + rdLength > p.length) break;

            switch (type) {
                case TYPE_NB -> {
                    names.add(owner);
                    // pairs of name flags (2) and address (4)
                    for (int a = rd; a + 6 <= rd + rdLength; a += 6) {
                        final Inet4Address ip = ipv4(p, a + 2);
                        if (ip != null && !ip.isAnyLocalAddress()) addresses.add(ip);
                    }
                }
                case TYPE_NBSTAT -> {
                    // number of names (1), then 15-byte name, suffix, flags (2) each, then the MAC
                    if (rdLength < 1) break;
                    final int count = p[rd] & 0xff;
                    int n = rd + 1;
                    for (int k = 0; k < count && n + 18 <= p.length; k++, n += 18) {
                        final String raw = new String(p, n, 15, java.nio.charset.StandardCharsets.US_ASCII).trim();
                        names.add(new Netbios.Name(raw, p[n + 15] & 0xff));
                    }
                    if (n + 6 <= p.length) {
                        unitId = mac(p, n);
                    }
                }
                default -> { }
            }
            off = rd + rdLength;
        }

        if (questions.isEmpty() && names.isEmpty()) return null;
        return new Nbns(u16(p, 0), response, opcode, questions, names, addresses, unitId);
    }

    private static String mac(byte[] p, int off) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", p[off + i]));
        }
        return sb.toString();
    }

    private static Inet4Address ipv4(byte[] p, int off) {
        try {
            return (Inet4Address) Inet4Address.getByAddress(Arrays.copyOfRange(p, off, off + 4));
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
    }
}
