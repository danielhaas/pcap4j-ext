package li.haas.pcap4j.ext;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * NTP (RFC 5905), UDP 123, which pcap4j does not decode.
 * A reply says how far the server is from a reference clock (the stratum) and, for a
 * secondary server, which upstream it follows, so a capture reveals the time hierarchy.
 */
public record Ntp(int leapIndicator, int version, int mode, int stratum,
                  int pollInterval, int precision, String referenceId) {

    public static final int PORT = 123;

    public static final int MODE_CLIENT = 3;
    public static final int MODE_SERVER = 4;
    public static final int MODE_BROADCAST = 5;
    public static final int MODE_CONTROL = 6;
    public static final int MODE_PRIVATE = 7;

    public String modeName() {
        return switch (mode) {
            case 1 -> "symmetric active";
            case 2 -> "symmetric passive";
            case MODE_CLIENT -> "client";
            case MODE_SERVER -> "server";
            case MODE_BROADCAST -> "broadcast";
            case MODE_CONTROL -> "control";
            case MODE_PRIVATE -> "private";
            default -> "mode " + mode;
        };
    }

    /** Stratum 1 is a reference clock, 2..15 are servers behind it, 16 and up means unsynchronised. */
    public String stratumName() {
        if (stratum == 0) return "unspecified";
        if (stratum == 1) return "reference clock";
        if (stratum >= 16) return "unsynchronised";
        return "stratum " + stratum;
    }

    /** Modes 6 and 7 are the query interfaces abused for amplification attacks. */
    public boolean isControlOrPrivate() {
        return mode == MODE_CONTROL || mode == MODE_PRIVATE;
    }

    /** Seconds between polls, encoded as a power of two. */
    public int pollSeconds() {
        return pollInterval <= 0 || pollInterval > 17 ? 0 : 1 << pollInterval;
    }

    @Override
    public String toString() {
        return "NTP v" + version + " " + modeName() + " " + stratumName()
                + (referenceId == null || referenceId.isEmpty() ? "" : " reference=" + referenceId)
                + (pollSeconds() == 0 ? "" : " poll=" + pollSeconds() + "s");
    }

    /** Returns null if the data is not NTP. */
    public static Ntp parse(byte[] p) {
        if (p.length < 48) return null;
        final int leap = (p[0] & 0xc0) >> 6;
        final int version = (p[0] & 0x38) >> 3;
        final int mode = p[0] & 0x07;
        if (version < 1 || version > 4 || mode == 0) return null;

        final int stratum = p[1] & 0xff;
        // a reference clock names itself in four ASCII characters; a server names its upstream by address
        String reference = null;
        if (stratum == 1) {
            final StringBuilder sb = new StringBuilder();
            for (int i = 12; i < 16; i++) {
                final int c = p[i] & 0xff;
                if (c >= 32 && c < 127) sb.append((char) c);
            }
            reference = sb.toString().trim();
        } else if (stratum > 1 && stratum < 16) {
            try {
                reference = Inet4Address.getByAddress(Arrays.copyOfRange(p, 12, 16)).getHostAddress();
            } catch (UnknownHostException e) {
                reference = null;
            }
        }
        return new Ntp(leap, version, mode, stratum, p[2], p[3], reference);
    }

    private static String text(byte[] p, int off, int len) {
        return new String(p, off, len, StandardCharsets.US_ASCII).trim();
    }
}
