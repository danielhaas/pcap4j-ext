package li.haas.pcap4j.ext;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * QUIC Initial packets (RFC 9000 and 9001), which pcap4j does not decode.
 * The payload is encrypted, but an Initial packet's keys are derived from its destination
 * connection id with a salt published in the RFC, so anyone can decrypt it. That is how the
 * client hello, and with it the server name, can still be read off the wire.
 */
public record Quic(long version, String destinationConnectionId, String sourceConnectionId,
                   List<Fragment> fragments) {

    /** One piece of the handshake, at its offset in the stream. A client hello spans several. */
    public record Fragment(long offset, byte[] data) {
    }

    /** Initial salts, per version (RFC 9001 for v1, RFC 9369 for v2). */
    private static final byte[] SALT_V1 = hex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    private static final byte[] SALT_V2 = hex("0dede3def700a6db819381be6e269dcbf9bd2ed9");

    public static final long VERSION_1 = 0x00000001L;
    public static final long VERSION_2 = 0x6b3343cfL;

    private static final int PACKET_TYPE_INITIAL_V1 = 0;
    private static final int PACKET_TYPE_INITIAL_V2 = 1;   // v2 renumbered the long header types

    @Override
    public String toString() {
        return "QUIC initial v" + Long.toHexString(version) + " dcid=" + destinationConnectionId
                + " " + fragments.size() + " crypto fragments";
    }

    /** Returns null unless this is a QUIC Initial whose client hello could be read. */
    public static Quic parse(byte[] p) {
        // long header: 1 fixed bit, 1 header form bit, then version and connection ids
        if (p.length < 1200 || (p[0] & 0x80) == 0 || (p[0] & 0x40) == 0) return null;
        if (p.length < 7) return null;

        final long version = u32(p, 1);
        final byte[] salt;
        final int initialType;
        if (version == VERSION_1) {
            salt = SALT_V1;
            initialType = PACKET_TYPE_INITIAL_V1;
        } else if (version == VERSION_2) {
            salt = SALT_V2;
            initialType = PACKET_TYPE_INITIAL_V2;
        } else {
            return null;                       // a version we have no salt for, or version negotiation
        }
        if (((p[0] & 0x30) >> 4) != initialType) return null;

        int off = 5;
        final int dcidLength = p[off] & 0xff;
        if (dcidLength > 20 || off + 1 + dcidLength > p.length) return null;
        final byte[] dcid = Arrays.copyOfRange(p, off + 1, off + 1 + dcidLength);
        off += 1 + dcidLength;

        if (off >= p.length) return null;
        final int scidLength = p[off] & 0xff;
        if (scidLength > 20 || off + 1 + scidLength > p.length) return null;
        final byte[] scid = Arrays.copyOfRange(p, off + 1, off + 1 + scidLength);
        off += 1 + scidLength;

        final long[] token = varint(p, off);
        if (token == null) return null;
        off = (int) token[1] + (int) token[0];      // skip the token
        final long[] length = varint(p, off);
        if (length == null || length[0] < 20) return null;
        final int payloadStart = (int) length[1];   // first byte of the packet number
        final int payloadEnd = payloadStart + (int) length[0];
        if (payloadEnd > p.length) return null;

        try {
            final byte[] plain = decryptInitial(p, payloadStart, payloadEnd, dcid, salt);
            if (plain == null) return null;
            final List<Fragment> fragments = cryptoFrames(plain);
            if (fragments.isEmpty()) return null;
            return new Quic(version, hexOf(dcid), hexOf(scid), fragments);
        } catch (Exception e) {
            return null;                        // any crypto or parsing failure just means "not readable"
        }
    }

    /** Removes header protection and decrypts the payload with the client's initial keys. */
    private static byte[] decryptInitial(byte[] p, int payloadStart, int payloadEnd,
                                         byte[] dcid, byte[] salt) throws Exception {
        final byte[] initialSecret = hkdfExtract(salt, dcid);
        final byte[] clientSecret = hkdfExpandLabel(initialSecret, "client in", 32);
        final byte[] key = hkdfExpandLabel(clientSecret, "quic key", 16);
        final byte[] iv = hkdfExpandLabel(clientSecret, "quic iv", 12);
        final byte[] hp = hkdfExpandLabel(clientSecret, "quic hp", 16);

        // the sample starts four bytes after the packet number, which is at most four bytes long
        final int sampleOffset = payloadStart + 4;
        if (sampleOffset + 16 > p.length) return null;
        final Cipher ecb = Cipher.getInstance("AES/ECB/NoPadding");
        ecb.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(hp, "AES"));
        final byte[] mask = ecb.doFinal(Arrays.copyOfRange(p, sampleOffset, sampleOffset + 16));

        byte[] header = Arrays.copyOfRange(p, 0, payloadStart);
        final byte firstByte = (byte) (p[0] ^ (mask[0] & 0x0f));
        header[0] = firstByte;
        final int pnLength = (firstByte & 0x03) + 1;
        if (payloadStart + pnLength > payloadEnd) return null;

        final byte[] packetNumber = new byte[pnLength];
        for (int i = 0; i < pnLength; i++) {
            packetNumber[i] = (byte) (p[payloadStart + i] ^ mask[1 + i]);
            header = append(header, packetNumber[i]);
        }

        long pn = 0;
        for (byte b : packetNumber) pn = (pn << 8) | (b & 0xff);

        // the nonce is the iv with the packet number xored into its right hand end
        final byte[] nonce = iv.clone();
        for (int i = 0; i < 8; i++) {
            nonce[nonce.length - 1 - i] ^= (byte) ((pn >> (8 * i)) & 0xff);
        }

        final Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        gcm.updateAAD(header);
        return gcm.doFinal(p, payloadStart + pnLength, payloadEnd - payloadStart - pnLength);
    }

    /**
     * Walks the frames of a decrypted payload and returns the CRYPTO pieces.
     * A client hello is usually larger than one packet, so the pieces carry their stream offset
     * and are put back together by the caller.
     */
    private static List<Fragment> cryptoFrames(byte[] plain) {
        final List<Fragment> out = new ArrayList<>();
        int off = 0;
        while (off < plain.length) {
            final int type = plain[off] & 0xff;
            switch (type) {
                case 0x00, 0x01 -> off++;                      // PADDING, PING
                case 0x02, 0x03 -> {                           // ACK, with an optional ECN section
                    long[] v = varint(plain, off + 1);         // largest acknowledged
                    if (v == null) return out;
                    v = varint(plain, (int) v[1]);             // ack delay
                    if (v == null) return out;
                    final long[] rangeCount = varint(plain, (int) v[1]);
                    if (rangeCount == null) return out;
                    v = varint(plain, (int) rangeCount[1]);    // first range
                    if (v == null) return out;
                    for (long i = 0; i < rangeCount[0] && v != null; i++) {
                        v = varint(plain, (int) v[1]);         // gap
                        if (v != null) v = varint(plain, (int) v[1]);   // range length
                    }
                    if (v == null) return out;
                    if (type == 0x03) {
                        for (int i = 0; i < 3 && v != null; i++) v = varint(plain, (int) v[1]);
                        if (v == null) return out;
                    }
                    off = (int) v[1];
                }
                case 0x06 -> {                                 // CRYPTO
                    final long[] offset = varint(plain, off + 1);
                    if (offset == null) return out;
                    final long[] length = varint(plain, (int) offset[1]);
                    if (length == null) return out;
                    final int start = (int) length[1];
                    final int end = start + (int) length[0];
                    if (end > plain.length) return out;
                    out.add(new Fragment(offset[0], Arrays.copyOfRange(plain, start, end)));
                    off = end;
                }
                case 0x1c, 0x1d -> {                           // CONNECTION_CLOSE ends the packet for us
                    return out;
                }
                default -> {
                    return out;                                // an unknown frame: stop rather than guess
                }
            }
        }
        return out;
    }

    // HKDF as used by TLS 1.3, which QUIC borrows wholesale
    private static byte[] hkdfExtract(byte[] salt, byte[] input) throws Exception {
        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        return mac.doFinal(input);
    }

    private static byte[] hkdfExpandLabel(byte[] secret, String label, int length) throws Exception {
        final byte[] full = ("tls13 " + label).getBytes(StandardCharsets.US_ASCII);
        final ByteArrayOutputStream info = new ByteArrayOutputStream();
        info.write((length >> 8) & 0xff);
        info.write(length & 0xff);
        info.write(full.length);
        info.writeBytes(full);
        info.write(0);                 // empty context

        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret, "HmacSHA256"));
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] block = new byte[0];
        for (int i = 1; out.size() < length; i++) {
            mac.reset();
            mac.update(block);
            mac.update(info.toByteArray());
            mac.update((byte) i);
            block = mac.doFinal();
            out.writeBytes(block);
        }
        return Arrays.copyOf(out.toByteArray(), length);
    }

    /** QUIC variable length integer: the top two bits give the length. Returns {value, offset after}. */
    private static long[] varint(byte[] p, int off) {
        if (off < 0 || off >= p.length) return null;
        final int prefix = (p[off] & 0xc0) >> 6;
        final int len = 1 << prefix;
        if (off + len > p.length) return null;
        long value = p[off] & 0x3f;
        for (int i = 1; i < len; i++) {
            value = (value << 8) | (p[off + i] & 0xff);
        }
        return new long[] {value, off + len};
    }

    private static byte[] append(byte[] a, byte b) {
        final byte[] out = Arrays.copyOf(a, a.length + 1);
        out[a.length] = b;
        return out;
    }

    private static long u32(byte[] p, int off) {
        return ((long) (p[off] & 0xff) << 24) | ((p[off + 1] & 0xff) << 16)
                | ((p[off + 2] & 0xff) << 8) | (p[off + 3] & 0xff);
    }

    private static byte[] hex(String s) {
        final byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    private static String hexOf(byte[] b) {
        final StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
