package li.haas.pcap4j.ext;

import org.pcap4j.util.MacAddress;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * DHCPv4 (RFC 2131 and 2132), UDP 67/68, which pcap4j does not decode.
 * The client tells the server its host name and vendor class; the server answers with the
 * address, the subnet mask, the gateway and DNS. The mask is the only place on the wire
 * that states the real prefix length.
 */
public record Dhcp(int messageType, long transactionId, MacAddress clientMac,
                   Inet4Address clientAddress,      // ciaddr, set when renewing
                   Inet4Address assignedAddress,    // yiaddr, what the server hands out
                   Inet4Address requestedAddress,   // option 50
                   Inet4Address serverId,           // option 54
                   Inet4Address subnetMask,         // option 1
                   List<Inet4Address> routers, List<Inet4Address> dnsServers,
                   String hostName, String domain, String vendorClass, String clientId,
                   Long leaseSeconds, int[] parameterRequestList,
                   String relayCircuitId, String relayRemoteId) {

    public static final int SERVER_PORT = 67;
    public static final int CLIENT_PORT = 68;

    private static final int MAGIC_COOKIE = 0x63825363;

    private static final int OPT_SUBNET_MASK = 1;
    private static final int OPT_ROUTER = 3;
    private static final int OPT_DNS = 6;
    private static final int OPT_HOST_NAME = 12;
    private static final int OPT_DOMAIN_NAME = 15;
    private static final int OPT_REQUESTED_IP = 50;
    private static final int OPT_LEASE_TIME = 51;
    private static final int OPT_MESSAGE_TYPE = 53;
    private static final int OPT_SERVER_ID = 54;
    private static final int OPT_PARAMETER_REQUEST_LIST = 55;
    private static final int OPT_VENDOR_CLASS = 60;
    private static final int OPT_CLIENT_ID = 61;
    private static final int OPT_RELAY_AGENT = 82;
    private static final int OPT_END = 255;

    public String messageTypeName() {
        return switch (messageType) {
            case 1 -> "discover";
            case 2 -> "offer";
            case 3 -> "request";
            case 4 -> "decline";
            case 5 -> "ack";
            case 6 -> "nak";
            case 7 -> "release";
            case 8 -> "inform";
            default -> "type " + messageType;
        };
    }

    public boolean fromServer() {
        return messageType == 2 || messageType == 5 || messageType == 6;
    }

    /** The prefix length the mask stands for, or -1 when no mask was given. */
    public int prefixLength() {
        if (subnetMask == null) return -1;
        int bits = 0;
        for (byte b : subnetMask.getAddress()) {
            bits += Integer.bitCount(b & 0xff);
        }
        return bits;
    }

    /** The option numbers a client asks for; the order is characteristic of the OS. */
    public String fingerprint() {
        if (parameterRequestList == null || parameterRequestList.length == 0) return null;
        final StringBuilder sb = new StringBuilder();
        for (int o : parameterRequestList) {
            if (sb.length() > 0) sb.append(',');
            sb.append(o);
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return "DHCP " + messageTypeName()
                + (clientMac == null ? "" : " client=" + clientMac)
                + (hostName == null ? "" : " host=" + hostName)
                + (assignedAddress == null ? "" : " assigned=" + assignedAddress.getHostAddress())
                + (requestedAddress == null ? "" : " requested=" + requestedAddress.getHostAddress())
                + (subnetMask == null ? "" : " mask=/" + prefixLength())
                + (serverId == null ? "" : " server=" + serverId.getHostAddress())
                + (leaseSeconds == null ? "" : " lease=" + leaseSeconds + "s")
                + (vendorClass == null ? "" : " vendor=" + vendorClass);
    }

    /** Returns null if the data is not DHCP. */
    public static Dhcp parse(byte[] p) {
        if (p.length < 240) return null;
        final int op = p[0] & 0xff;
        if (op != 1 && op != 2) return null;                       // request or reply
        if ((p[1] & 0xff) != 1) return null;                       // Ethernet hardware type
        if (u32(p, 236) != MAGIC_COOKIE) return null;

        final long xid = u32(p, 4);
        final int hlen = p[2] & 0xff;
        final MacAddress clientMac = hlen == 6
                ? MacAddress.getByAddress(Arrays.copyOfRange(p, 28, 34)) : null;
        final Inet4Address ciaddr = ipv4(p, 12);
        final Inet4Address yiaddr = ipv4(p, 16);

        int messageType = 0;
        Inet4Address requested = null, serverId = null, mask = null;
        final List<Inet4Address> routers = new ArrayList<>();
        final List<Inet4Address> dns = new ArrayList<>();
        String hostName = null, domain = null, vendorClass = null, clientId = null;
        String circuitId = null, remoteId = null;
        Long lease = null;
        int[] parameters = null;

        int off = 240;
        while (off < p.length) {
            final int code = p[off] & 0xff;
            if (code == OPT_END) break;
            if (code == 0) {           // padding
                off++;
                continue;
            }
            if (off + 2 > p.length) break;
            final int len = p[off + 1] & 0xff;
            final int v = off + 2;
            if (v + len > p.length) break;

            switch (code) {
                case OPT_MESSAGE_TYPE -> { if (len >= 1) messageType = p[v] & 0xff; }
                case OPT_SUBNET_MASK -> { if (len >= 4) mask = ipv4(p, v); }
                case OPT_ROUTER -> addresses(p, v, len, routers);
                case OPT_DNS -> addresses(p, v, len, dns);
                case OPT_HOST_NAME -> hostName = text(p, v, len);
                case OPT_DOMAIN_NAME -> domain = text(p, v, len);
                case OPT_REQUESTED_IP -> { if (len >= 4) requested = ipv4(p, v); }
                case OPT_SERVER_ID -> { if (len >= 4) serverId = ipv4(p, v); }
                case OPT_LEASE_TIME -> { if (len >= 4) lease = u32(p, v); }
                case OPT_VENDOR_CLASS -> vendorClass = text(p, v, len);
                case OPT_CLIENT_ID -> clientId = clientId(p, v, len);
                case OPT_PARAMETER_REQUEST_LIST -> {
                    parameters = new int[len];
                    for (int i = 0; i < len; i++) parameters[i] = p[v + i] & 0xff;
                }
                case OPT_RELAY_AGENT -> {
                    // sub-options: 1 is the circuit (the switch port), 2 the remote id (the switch)
                    int s = v;
                    while (s + 2 <= v + len) {
                        final int sub = p[s] & 0xff;
                        final int sublen = p[s + 1] & 0xff;
                        if (s + 2 + sublen > v + len) break;
                        if (sub == 1) circuitId = text(p, s + 2, sublen);
                        if (sub == 2) remoteId = text(p, s + 2, sublen);
                        s += 2 + sublen;
                    }
                }
                default -> { }
            }
            off = v + len;
        }

        if (messageType == 0) return null;  // every DHCP message carries option 53
        return new Dhcp(messageType, xid, clientMac,
                ciaddr != null && !ciaddr.isAnyLocalAddress() ? ciaddr : null,
                yiaddr != null && !yiaddr.isAnyLocalAddress() ? yiaddr : null,
                requested, serverId, mask, routers, dns,
                hostName, domain, vendorClass, clientId, lease, parameters, circuitId, remoteId);
    }

    /** A client id is usually hardware type 1 plus a MAC, otherwise an opaque string. */
    private static String clientId(byte[] p, int off, int len) {
        if (len == 7 && (p[off] & 0xff) == 1) {
            return MacAddress.getByAddress(Arrays.copyOfRange(p, off + 1, off + 7)).toString();
        }
        return text(p, off, len);
    }

    private static void addresses(byte[] p, int off, int len, List<Inet4Address> out) {
        for (int i = off; i + 4 <= off + len; i += 4) {
            final Inet4Address ip = ipv4(p, i);
            if (ip != null) out.add(ip);
        }
    }

    private static Inet4Address ipv4(byte[] p, int off) {
        try {
            return (Inet4Address) Inet4Address.getByAddress(Arrays.copyOfRange(p, off, off + 4));
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static String text(byte[] p, int off, int len) {
        int end = off + len;
        while (end > off && p[end - 1] == 0) end--;
        return new String(p, off, end - off, StandardCharsets.UTF_8).trim();
    }

    private static long u32(byte[] p, int off) {
        return ((long) (p[off] & 0xff) << 24) | ((p[off + 1] & 0xff) << 16)
                | ((p[off + 2] & 0xff) << 8) | (p[off + 3] & 0xff);
    }
}
