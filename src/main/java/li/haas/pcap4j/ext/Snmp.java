package li.haas.pcap4j.ext;

import org.pcap4j.packet.IllegalRawDataException;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * SNMP v1 and v2c (RFC 1157, 3416), UDP 161 and 162, which pcap4j does not decode.
 * Only as much BER as the interesting parts need: the version, the community string, which is
 * the password and travels in clear text, the operation, and the variable bindings.
 * Version 3 is recognised but not decoded, since its payload may be encrypted.
 */
public record Snmp(int version, String community, Integer pduType, Long requestId,
                   List<Binding> bindings) implements Protocol {

    public Snmp {
        bindings = bindings == null ? List.of() : Collections.unmodifiableList(new ArrayList<>(bindings));
    }

    public static final int PORT = 161;
    public static final int TRAP_PORT = 162;

    /** The community strings every SNMP deployment is told to change, and often does not. */
    public static final List<String> DEFAULT_COMMUNITIES = List.of("public", "private");

    /** One variable binding: an object id and whatever it was set to or reported as. */
    public record Binding(String oid, String value) {
        @Override
        public String toString() {
            return oid + "=" + value;
        }
    }

    public String versionName() {
        return switch (version) {
            case 0 -> "v1";
            case 1 -> "v2c";
            case 3 -> "v3";
            default -> "version " + version;
        };
    }

    public String operation() {
        if (pduType == null) return null;
        return switch (pduType) {
            case 0xa0 -> "get";
            case 0xa1 -> "get next";
            case 0xa2 -> "response";
            case 0xa3 -> "set";
            case 0xa4 -> "trap";           // version 1 trap
            case 0xa5 -> "get bulk";
            case 0xa6 -> "inform";
            case 0xa7 -> "trap";           // version 2 trap
            case 0xa8 -> "report";
            default -> String.format("pdu 0x%02x", pduType);
        };
    }

    /** A write with a community string is a full compromise of the device if it is guessable. */
    public boolean isWrite() {
        return pduType != null && pduType == 0xa3;
    }

    public boolean usesDefaultCommunity() {
        return community != null && DEFAULT_COMMUNITIES.contains(community.toLowerCase());
    }

    @Override
    public String toString() {
        return "SNMP " + versionName() + (operation() == null ? "" : " " + operation())
                + (community == null ? "" : " community=" + community)
                + (bindings.isEmpty() ? "" : " " + bindings);
    }

    /** Returns null if the data is not SNMP. */
    public static Snmp parseOrNull(byte[] p) {
        final Ber ber = new Ber(p);
        if (!ber.sequence()) return null;
        final Long version = ber.integer();
        if (version == null || version > 3) return null;
        if (version == 3) {
            // the rest is the v3 security model, and may be encrypted
            return new Snmp(3, null, null, null, List.of());
        }
        final String community = ber.octetString();
        if (community == null) return null;

        final Integer pduType = ber.constructed();
        if (pduType == null) {
            return new Snmp(version.intValue(), community, null, null, List.of());
        }

        Long requestId = null;
        final List<Binding> bindings = new ArrayList<>();
        if (pduType == 0xa4) {
            // a version 1 trap has a different shape: enterprise, agent address, two trap fields, time
            ber.skipValue();               // enterprise oid
            ber.skipValue();               // agent address
            ber.skipValue();               // generic trap
            ber.skipValue();               // specific trap
            ber.skipValue();               // time stamp
        } else {
            requestId = ber.integer();
            ber.skipValue();               // error status
            ber.skipValue();               // error index
        }

        if (ber.sequence()) {              // the variable binding list
            while (ber.sequence()) {       // one binding
                final String oid = ber.oid();
                final String value = ber.anyValue();
                if (oid == null) break;
                bindings.add(new Binding(oid, value));
            }
        }
        return new Snmp(version.intValue(), community, pduType, requestId, bindings);
    }

    /** Parses bytes the caller has already identified as SNMP by its port. */
    public static Snmp parse(byte[] p) throws IllegalRawDataException {
        final Snmp parsed = parseOrNull(p);
        if (parsed == null) throw Raw.notA("SNMP", p);
        return parsed;
    }

    /** Just enough BER to walk an SNMP message. Every method returns null rather than throwing. */
    private static final class Ber {
        private final byte[] p;
        private int off;

        Ber(byte[] p) {
            this.p = p;
        }

        /** Steps into a sequence, leaving the position at its first member. */
        boolean sequence() {
            if (off >= p.length || (p[off] & 0xff) != 0x30) return false;
            off++;
            return length() >= 0;
        }

        /** Steps into a context specific constructed value, returning its tag. */
        Integer constructed() {
            if (off >= p.length) return null;
            final int tag = p[off] & 0xff;
            if ((tag & 0xe0) != 0xa0) return null;
            off++;
            return length() >= 0 ? tag : null;
        }

        Long integer() {
            if (off >= p.length || (p[off] & 0xff) != 0x02) return null;
            off++;
            final int len = length();
            if (len < 0 || off + len > p.length) return null;
            long value = 0;
            for (int i = 0; i < len; i++) value = (value << 8) | (p[off + i] & 0xff);
            off += len;
            return value;
        }

        String octetString() {
            if (off >= p.length || (p[off] & 0xff) != 0x04) return null;
            off++;
            final int len = length();
            if (len < 0 || off + len > p.length) return null;
            final String s = new String(p, off, len, StandardCharsets.UTF_8);
            off += len;
            return s;
        }

        String oid() {
            if (off >= p.length || (p[off] & 0xff) != 0x06) return null;
            off++;
            final int len = length();
            if (len < 0 || off + len > p.length) return null;
            final StringBuilder sb = new StringBuilder();
            final int first = p[off] & 0xff;
            sb.append(first / 40).append('.').append(first % 40);
            long value = 0;
            for (int i = 1; i < len; i++) {
                final int b = p[off + i] & 0xff;
                value = (value << 7) | (b & 0x7f);
                if ((b & 0x80) == 0) {
                    sb.append('.').append(value);
                    value = 0;
                }
            }
            off += len;
            return sb.toString();
        }

        /** The value of a binding, printed the way it reads best for its type. */
        String anyValue() {
            if (off >= p.length) return null;
            final int tag = p[off] & 0xff;
            return switch (tag) {
                case 0x02 -> String.valueOf(integer());
                case 0x04 -> octetString();
                case 0x06 -> oid();
                case 0x05 -> {
                    skipValue();
                    yield "null";
                }
                case 0x40 -> {             // IpAddress
                    off++;
                    final int len = length();
                    if (len != 4 || off + 4 > p.length) yield null;
                    final String s = (p[off] & 0xff) + "." + (p[off + 1] & 0xff) + "."
                            + (p[off + 2] & 0xff) + "." + (p[off + 3] & 0xff);
                    off += 4;
                    yield s;
                }
                case 0x41, 0x42, 0x43, 0x46 -> {   // Counter, Gauge, TimeTicks, Counter64
                    off++;
                    final int len = length();
                    if (len < 0 || off + len > p.length) yield null;
                    long value = 0;
                    for (int i = 0; i < len; i++) value = (value << 8) | (p[off + i] & 0xff);
                    off += len;
                    yield String.valueOf(value);
                }
                default -> {
                    skipValue();
                    yield null;
                }
            };
        }

        void skipValue() {
            if (off >= p.length) return;
            off++;
            final int len = length();
            if (len < 0) {
                off = p.length;
                return;
            }
            off = Math.min(off + len, p.length);
        }

        /** Reads a length, leaving the position at the value. Returns -1 if it does not fit. */
        private int length() {
            if (off >= p.length) return -1;
            final int first = p[off++] & 0xff;
            if ((first & 0x80) == 0) return first;
            final int count = first & 0x7f;
            if (count == 0 || count > 4 || off + count > p.length) return -1;
            int len = 0;
            for (int i = 0; i < count; i++) len = (len << 8) | (p[off++] & 0xff);
            return len;
        }
    }
}
