package li.haas.pcap4j.ext;

/**
 * Shared NetBIOS bits (RFC 1001/1002), which pcap4j does not decode.
 * A NetBIOS name is 15 characters plus a one-byte suffix that says what the name is for.
 * On the wire it is "first level encoded": every byte becomes two characters, each holding
 * one nibble added to 'A', so 16 bytes become 32 characters.
 */
public final class Netbios {

    private Netbios() {
    }

    /** A decoded name with its suffix, e.g. GAMORA<00>. */
    public record Name(String name, int suffix) {

        /** What the suffix says the name is used for. */
        public String role() {
            return switch (suffix) {
                case 0x00 -> "workstation";
                case 0x03 -> "messenger";
                case 0x1b -> "domain master browser";
                case 0x1c -> "domain controllers";
                case 0x1d -> "master browser";
                case 0x1e -> "browser elections";
                case 0x20 -> "file server";
                default -> String.format("suffix 0x%02x", suffix);
            };
        }

        @Override
        public String toString() {
            return String.format("%s<%02x>", name, suffix);
        }
    }

    /** Length of an encoded name on the wire: length byte, 32 characters, terminator. */
    public static final int ENCODED_LENGTH = 34;

    /**
     * Decodes the name at the given offset. Returns null if the bytes are not a valid encoded name.
     * Only the flat (non-scoped) form is handled, which is all a LAN capture contains.
     */
    public static Name decode(byte[] p, int off) {
        if (off + 33 > p.length || (p[off] & 0xff) != 32) return null;

        final byte[] decoded = new byte[16];
        for (int i = 0; i < 16; i++) {
            final int hi = p[off + 1 + 2 * i] - 'A';
            final int lo = p[off + 2 + 2 * i] - 'A';
            if (hi < 0 || hi > 15 || lo < 0 || lo > 15) return null;
            decoded[i] = (byte) ((hi << 4) | lo);
        }

        final StringBuilder name = new StringBuilder();
        for (int i = 0; i < 15; i++) {
            final int c = decoded[i] & 0xff;
            if (c == 0x20 || c == 0) continue;  // names are padded with spaces
            name.append((char) c);
        }
        return new Name(name.toString().trim(), decoded[15] & 0xff);
    }

    /** Names can be followed by a scope, so the encoded name is not always exactly 34 bytes. */
    public static int encodedLength(byte[] p, int off) {
        int i = off + 33;  // length byte plus 32 characters
        while (i < p.length && (p[i] & 0xff) != 0) {
            i += (p[i] & 0xff) + 1;  // skip a scope label
        }
        return i + 1 - off;
    }
}
