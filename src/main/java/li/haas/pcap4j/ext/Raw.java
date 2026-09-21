package li.haas.pcap4j.ext;

import org.pcap4j.packet.IllegalRawDataException;

/** Shared helper for reporting bytes that were dispatched to a parser but did not fit it. */
final class Raw {

    private Raw() {
    }

    /**
     * The caller already decided what these bytes are, from an EtherType, a SNAP protocol id,
     * an IP protocol number or a port, so bytes that do not fit are a malformed frame and worth
     * a message rather than a silent null.
     */
    static IllegalRawDataException notA(String protocol, byte[] p) {
        return new IllegalRawDataException(
                "not " + protocol + ": " + p.length + " bytes starting " + preview(p));
    }

    private static String preview(byte[] p) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(p.length, 8); i++) {
            if (i > 0) sb.append(' ');
            sb.append(String.format("%02x", p[i]));
        }
        if (p.length > 8) sb.append(" ...");
        return sb.toString();
    }
}
