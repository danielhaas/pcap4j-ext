package li.haas.pcap4j.ext;

import org.pcap4j.util.MacAddress;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * DHCPv6 (RFC 8415), UDP 546 (client) and 547 (server), which pcap4j does not decode.
 * Nothing like DHCPv4 on the wire: a one-byte message type, a three-byte transaction id,
 * then options of code (2) and length (2). Clients and servers identify themselves by DUID
 * rather than by MAC, though most DUIDs contain a MAC.
 */
import org.pcap4j.packet.IllegalRawDataException;

import java.util.Collections;

import java.util.LinkedHashMap;

import java.util.LinkedHashSet;

import java.util.Map;

import java.util.Set;

public record DhcpV6(int messageType, int transactionId,
                    String clientDuid, MacAddress clientMac,   // MAC out of the DUID, when it has one
                    String serverDuid,
                    List<Inet6Address> addresses,              // IA_NA / IA_TA addresses
                    List<String> prefixes,                     // IA_PD delegated prefixes
                    List<Inet6Address> dnsServers,
                    String fqdn, String vendorClass,
                    Integer elapsedSeconds, Integer statusCode,
                    List<Integer> optionRequest) implements Protocol {
    public DhcpV6 {
        addresses = copy(addresses);
        prefixes = copy(prefixes);
        dnsServers = copy(dnsServers);
        optionRequest = copy(optionRequest);
    }


    public static final int CLIENT_PORT = 546;
    public static final int SERVER_PORT = 547;

    private static final int OPT_CLIENTID = 1;
    private static final int OPT_SERVERID = 2;
    private static final int OPT_IA_NA = 3;
    private static final int OPT_IA_TA = 4;
    private static final int OPT_IAADDR = 5;
    private static final int OPT_ORO = 6;
    private static final int OPT_ELAPSED_TIME = 8;
    private static final int OPT_STATUS_CODE = 13;
    private static final int OPT_VENDOR_CLASS = 16;
    private static final int OPT_DNS_SERVERS = 23;
    private static final int OPT_IA_PD = 25;
    private static final int OPT_IAPREFIX = 26;
    private static final int OPT_CLIENT_FQDN = 39;

    public String messageTypeName() {
        return switch (messageType) {
            case 1 -> "solicit";
            case 2 -> "advertise";
            case 3 -> "request";
            case 4 -> "confirm";
            case 5 -> "renew";
            case 6 -> "rebind";
            case 7 -> "reply";
            case 8 -> "release";
            case 9 -> "decline";
            case 10 -> "reconfigure";
            case 11 -> "information request";
            case 12 -> "relay forward";
            case 13 -> "relay reply";
            default -> "type " + messageType;
        };
    }

    public boolean fromServer() {
        return messageType == 2 || messageType == 7 || messageType == 10 || messageType == 13;
    }

    @Override
    public String toString() {
        return "DHCPv6 " + messageTypeName()
                + (clientMac == null ? "" : " client=" + clientMac)
                + (fqdn == null ? "" : " fqdn=" + fqdn)
                + (addresses.isEmpty() ? "" : " addresses=" + addresses.stream().map(InetAddress::getHostAddress).toList())
                + (prefixes.isEmpty() ? "" : " prefixes=" + prefixes)
                + (vendorClass == null ? "" : " vendor=" + vendorClass);
    }

    /**
     * Parses bytes the caller has already identified as DHCPv6, for example by protocol id or port.
     * Throws rather than returning null: at this point the bytes claim to be this protocol.
     */
    public static DhcpV6 parse(byte[] p) throws IllegalRawDataException {
        final DhcpV6 parsed = parseOrNull(p);
        if (parsed == null) throw Raw.notA("DHCPv6", p);
        return parsed;
    }

    /** Returns null if the data is not DHCPv6. */
    private static DhcpV6 parseOrNull(byte[] p) {
        if (p.length < 4) return null;
        final int messageType = p[0] & 0xff;
        if (messageType < 1 || messageType > 13) return null;
        // a relay message has a different header: hop count and two addresses instead of a transaction id
        final int optionsStart = (messageType == 12 || messageType == 13) ? 34 : 4;
        if (p.length < optionsStart) return null;

        final int xid = messageType == 12 || messageType == 13 ? 0
                : ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff);

        String clientDuid = null, serverDuid = null, fqdn = null, vendorClass = null;
        MacAddress clientMac = null;
        Integer elapsed = null, status = null;
        List<Integer> oro = null;
        final List<Inet6Address> addresses = new ArrayList<>();
        final List<Inet6Address> dns = new ArrayList<>();
        final List<String> prefixes = new ArrayList<>();

        int off = optionsStart;
        boolean sawOption = false;
        while (off + 4 <= p.length) {
            final int code = u16(p, off);
            final int len = u16(p, off + 2);
            final int v = off + 4;
            if (v + len > p.length) break;
            sawOption = true;

            switch (code) {
                case OPT_CLIENTID -> {
                    clientDuid = hex(p, v, len);
                    clientMac = duidMac(p, v, len);
                }
                case OPT_SERVERID -> serverDuid = hex(p, v, len);
                case OPT_IA_NA, OPT_IA_PD -> {
                    // IAID (4), T1 (4), T2 (4), then nested options
                    int s = v + 12;
                    while (s + 4 <= v + len) {
                        final int sub = u16(p, s);
                        final int sublen = u16(p, s + 2);
                        if (s + 4 + sublen > v + len) break;
                        if (sub == OPT_IAADDR && sublen >= 16) {
                            final Inet6Address ip = ipv6(p, s + 4);
                            if (ip != null) addresses.add(ip);
                        } else if (sub == OPT_IAPREFIX && sublen >= 25) {
                            // preferred (4), valid (4), prefix length (1), prefix (16)
                            final Inet6Address prefix = ipv6(p, s + 4 + 9);
                            if (prefix != null) prefixes.add(prefix.getHostAddress() + "/" + (p[s + 4 + 8] & 0xff));
                        }
                        s += 4 + sublen;
                    }
                }
                case OPT_IA_TA -> {
                    int s = v + 4;  // IAID only
                    while (s + 4 <= v + len) {
                        final int sub = u16(p, s);
                        final int sublen = u16(p, s + 2);
                        if (s + 4 + sublen > v + len) break;
                        if (sub == OPT_IAADDR && sublen >= 16) {
                            final Inet6Address ip = ipv6(p, s + 4);
                            if (ip != null) addresses.add(ip);
                        }
                        s += 4 + sublen;
                    }
                }
                case OPT_DNS_SERVERS -> {
                    for (int i = v; i + 16 <= v + len; i += 16) {
                        final Inet6Address ip = ipv6(p, i);
                        if (ip != null) dns.add(ip);
                    }
                }
                case OPT_CLIENT_FQDN -> { if (len > 1) fqdn = domainName(p, v + 1, len - 1); }
                case OPT_VENDOR_CLASS -> {
                    // enterprise number (4), then length-prefixed strings
                    if (len > 6) vendorClass = text(p, v + 6, Math.min(u16(p, v + 4), len - 6));
                }
                case OPT_ELAPSED_TIME -> { if (len >= 2) elapsed = u16(p, v) / 100; }  // hundredths of a second
                case OPT_STATUS_CODE -> { if (len >= 2) status = u16(p, v); }
                case OPT_ORO -> {
                    oro = new ArrayList<>(len / 2);
                    for (int i = 0; i < len / 2; i++) oro.add(u16(p, v + 2 * i));
                }
                default -> { }
            }
            off = v + len;
        }

        if (!sawOption) return null;
        return new DhcpV6(messageType, xid, clientDuid, clientMac, serverDuid,
                addresses, prefixes, dns, fqdn, vendorClass, elapsed, status, oro);
    }

    /**
     * DUID-LLT (type 1) and DUID-LL (type 3) embed the link-layer address;
     * DUID-EN (2) and DUID-UUID (4) do not.
     */
    private static MacAddress duidMac(byte[] p, int off, int len) {
        if (len < 4) return null;
        final int duidType = u16(p, off);
        final int hardwareType = u16(p, off + 2);
        if (hardwareType != 1) return null;  // Ethernet only
        final int macOff = duidType == 1 ? off + 8 : duidType == 3 ? off + 4 : -1;
        if (macOff < 0 || macOff + 6 > off + len) return null;
        return MacAddress.getByAddress(Arrays.copyOfRange(p, macOff, macOff + 6));
    }

    /** A DNS style name: length-prefixed labels. */
    private static String domainName(byte[] p, int off, int len) {
        final StringBuilder sb = new StringBuilder();
        int i = off;
        while (i < off + len) {
            final int labelLength = p[i] & 0xff;
            if (labelLength == 0 || i + 1 + labelLength > off + len) break;
            if (sb.length() > 0) sb.append('.');
            sb.append(new String(p, i + 1, labelLength, StandardCharsets.UTF_8));
            i += 1 + labelLength;
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    private static Inet6Address ipv6(byte[] p, int off) {
        try {
            return (Inet6Address) InetAddress.getByAddress(Arrays.copyOfRange(p, off, off + 16));
        } catch (UnknownHostException | ClassCastException e) {
            return null;
        }
    }

    private static String hex(byte[] p, int off, int len) {
        final StringBuilder sb = new StringBuilder();
        for (int i = off; i < off + len && i < p.length; i++) sb.append(String.format("%02x", p[i]));
        return sb.toString();
    }

    private static String text(byte[] p, int off, int len) {
        int end = Math.min(off + Math.max(len, 0), p.length);
        while (end > off && p[end - 1] == 0) end--;
        return new String(p, off, end - off, StandardCharsets.UTF_8).trim();
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
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
