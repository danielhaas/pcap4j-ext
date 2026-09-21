package li.haas.pcap4j.ext;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Cisco VLAN Trunking Protocol, which pcap4j does not decode.
 * SNAP with OUI 00:00:0c and protocol ID 0x2003, sent to 01:00:0c:cc:cc:cc.
 * A summary advertisement names the domain and its configuration revision; a subset
 * advertisement carries the VLAN database itself. The highest revision in a domain wins,
 * which is why a switch joining with a higher revision can overwrite everyone's VLANs.
 */
import org.pcap4j.packet.IllegalRawDataException;

import java.util.Collections;

import java.util.LinkedHashMap;

import java.util.LinkedHashSet;

import java.util.Map;

import java.util.Set;

public record Vtp(int version, int code, String domain, Long revision,
                  Inet4Address updater, String updateTimestamp, String md5,
                  Integer followers, List<Vlan> vlans, Integer startValue) implements Protocol {
    public Vtp {
        vlans = copy(vlans);
    }


    public static final int PROTOCOL_ID = 0x2003;

    public static final int CODE_SUMMARY = 1;
    public static final int CODE_SUBSET = 2;
    public static final int CODE_REQUEST = 3;
    public static final int CODE_JOIN = 4;

    private static final int DOMAIN_OFFSET = 4;
    private static final int DOMAIN_LENGTH = 32;

    /** One VLAN out of a subset advertisement. */
    public record Vlan(int id, String name, int mtu, int status, int type) {
        public boolean suspended() {
            return (status & 0x01) != 0;
        }

        public String typeName() {
            return switch (type) {
                case 1 -> "ethernet";
                case 2 -> "fddi";
                case 3 -> "tr-crf";
                case 4 -> "fddi-net";
                case 5 -> "trbrf";
                default -> "type " + type;
            };
        }

        @Override
        public String toString() {
            return id + "=" + name + (mtu != 1500 ? " mtu=" + mtu : "") + (suspended() ? " suspended" : "");
        }
    }

    public String codeName() {
        return switch (code) {
            case CODE_SUMMARY -> "summary advertisement";
            case CODE_SUBSET -> "subset advertisement";
            case CODE_REQUEST -> "advertisement request";
            case CODE_JOIN -> "join/prune";
            default -> "code " + code;
        };
    }

    @Override
    public String toString() {
        return "VTP v" + version + " " + codeName() + " domain=" + domain
                + (revision == null ? "" : " revision=" + revision)
                + (updater == null ? "" : " updater=" + updater.getHostAddress())
                + (updateTimestamp == null ? "" : " updated=" + updateTimestamp)
                + (vlans.isEmpty() ? "" : " vlans=" + vlans);
    }

    /**
     * Parses bytes the caller has already identified as VTP, for example by protocol id or port.
     * Throws rather than returning null: at this point the bytes claim to be this protocol.
     */
    public static Vtp parse(byte[] p) throws IllegalRawDataException {
        final Vtp parsed = parseOrNull(p);
        if (parsed == null) throw Raw.notA("VTP", p);
        return parsed;
    }

    /** Returns null if the data is not VTP. */
    private static Vtp parseOrNull(byte[] p) {
        if (p.length < DOMAIN_OFFSET + DOMAIN_LENGTH) return null;
        final int version = p[0] & 0xff;
        final int code = p[1] & 0xff;
        if (version < 1 || version > 3 || code < 1 || code > 4) return null;

        final int domainLength = p[3] & 0xff;
        if (domainLength > DOMAIN_LENGTH) return null;
        final String domain = new String(p, DOMAIN_OFFSET, domainLength, StandardCharsets.UTF_8).trim();

        Long revision = null;
        Inet4Address updater = null;
        String timestamp = null, md5 = null;
        Integer followers = null, startValue = null;
        final List<Vlan> vlans = new ArrayList<>();
        final int afterDomain = DOMAIN_OFFSET + DOMAIN_LENGTH;   // 36

        switch (code) {
            case CODE_SUMMARY -> {
                // followers (1), then revision (4), updater (4), timestamp (12), MD5 (16)
                followers = p[2] & 0xff;
                if (p.length < afterDomain + 4) return null;
                revision = u32(p, afterDomain);
                if (p.length >= afterDomain + 8) updater = ipv4(p, afterDomain + 4);
                if (p.length >= afterDomain + 20) {
                    timestamp = new String(p, afterDomain + 8, 12, StandardCharsets.US_ASCII).trim();
                }
                if (p.length >= afterDomain + 36) md5 = hex(p, afterDomain + 20, 16);
            }
            case CODE_SUBSET -> {
                // sequence number (1) in the same byte as followers, then revision, then VLAN records
                followers = p[2] & 0xff;
                if (p.length < afterDomain + 4) return null;
                revision = u32(p, afterDomain);
                int off = afterDomain + 4;
                while (off + 12 <= p.length) {
                    final int length = p[off] & 0xff;
                    if (length < 12 || off + length > p.length) break;
                    final int status = p[off + 1] & 0xff;
                    final int type = p[off + 2] & 0xff;
                    final int nameLength = p[off + 3] & 0xff;
                    final int id = u16(p, off + 4);
                    final int mtu = u16(p, off + 6);
                    final String name = off + 12 + nameLength <= p.length
                            ? new String(p, off + 12, nameLength, StandardCharsets.UTF_8).trim() : "";
                    vlans.add(new Vlan(id, name, mtu, status, type));
                    off += length;
                }
            }
            case CODE_REQUEST -> {
                if (p.length >= afterDomain + 2) startValue = u16(p, afterDomain);
            }
            default -> { }
        }
        return new Vtp(version, code, domain, revision, updater, timestamp, md5, followers, vlans, startValue);
    }

    private static Inet4Address ipv4(byte[] p, int off) {
        try {
            return (Inet4Address) Inet4Address.getByAddress(Arrays.copyOfRange(p, off, off + 4));
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static String hex(byte[] p, int off, int len) {
        final StringBuilder sb = new StringBuilder();
        for (int i = off; i < off + len && i < p.length; i++) sb.append(String.format("%02x", p[i]));
        return sb.toString();
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
    }

    private static long u32(byte[] p, int off) {
        return ((long) (p[off] & 0xff) << 24) | ((p[off + 1] & 0xff) << 16)
                | ((p[off + 2] & 0xff) << 8) | (p[off + 3] & 0xff);
    }

    // defensive copies that keep insertion order, which several of these rely on
    private static <T> List<T> copy(List<T> in) {
        return in == null ? List.of() : Collections.unmodifiableList(new ArrayList<>(in));
    }

    private static <T> Set<T> copy(Set<T> in) {
        return in == null ? Set.of() : Collections.unmodifiableSet(new LinkedHashSet<>(in));
    }

    private static <K, V> Map<K, V> copy(Map<K, V> in) {
        return in == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(in));
    }

}
