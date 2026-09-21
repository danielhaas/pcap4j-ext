package li.haas.pcap4j.ext;

import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Cisco Gateway Load Balancing Protocol, the third of the first hop redundancy protocols
 * alongside HSRP and VRRP, which pcap4j does not decode. UDP 3222, to 224.0.0.102 or ff02::66.
 * Unlike the other two it shares the load: one active virtual gateway hands out several virtual
 * MACs, each owned by a forwarder, so a group has one AVG and several AVFs.
 */
public record Glbp(int version, int group, MacAddress ownerId,
                   Integer gatewayState, Integer gatewayPriority,
                   Integer helloMillis, Integer holdMillis, InetAddress virtualAddress,
                   List<Forwarder> forwarders, Integer authType, String authentication)
        implements Protocol {

    public Glbp {
        forwarders = forwarders == null ? List.of() : Collections.unmodifiableList(new ArrayList<>(forwarders));
    }

    public static final int PORT = 3222;

    private static final int TLV_HELLO = 1;
    private static final int TLV_REQUEST_RESPONSE = 2;
    private static final int TLV_AUTH = 3;

    /** One virtual forwarder: a virtual MAC and whoever currently answers for it. */
    public record Forwarder(int number, int state, int priority, int weight, MacAddress virtualMac) {

        public String stateName() {
            return Glbp.stateName(state);
        }

        @Override
        public String toString() {
            return "forwarder " + number + " " + stateName() + " priority=" + priority
                    + " weight=" + weight + (virtualMac == null ? "" : " mac=" + virtualMac);
        }
    }

    static String stateName(int state) {
        return switch (state) {
            case 0x00 -> "disabled";
            case 0x01 -> "initial";
            case 0x02 -> "listen";
            case 0x04 -> "listen";
            case 0x08 -> "speak";
            case 0x10 -> "standby";
            case 0x20 -> "active";
            default -> String.format("state 0x%02x", state);
        };
    }

    public String gatewayStateName() {
        return gatewayState == null ? null : stateName(gatewayState);
    }

    /** The active virtual gateway is the one handing out the virtual MACs. */
    public boolean isActiveGateway() {
        return gatewayState != null && gatewayState == 0x20;
    }

    public boolean usesPlainTextAuthentication() {
        return authType != null && authType == 1;
    }

    @Override
    public String toString() {
        return "GLBP group " + group + (gatewayStateName() == null ? "" : " " + gatewayStateName())
                + (gatewayPriority == null ? "" : " priority=" + gatewayPriority)
                + (virtualAddress == null ? "" : " virtual=" + virtualAddress.getHostAddress())
                + (ownerId == null ? "" : " owner=" + ownerId)
                + (forwarders.isEmpty() ? "" : " " + forwarders)
                + (authentication == null ? "" : " auth=" + authentication);
    }

    /** Returns null if the data is not GLBP. */
    public static Glbp parseOrNull(byte[] p) {
        if (p.length < 12) return null;
        final int version = p[0] & 0xff;
        if (version != 1) return null;
        final int group = u16(p, 2);
        final MacAddress owner = MacAddress.getByAddress(Arrays.copyOfRange(p, 6, 12));

        Integer gatewayState = null, gatewayPriority = null, helloMillis = null, holdMillis = null;
        Integer authType = null;
        String authentication = null;
        InetAddress virtual = null;
        final List<Forwarder> forwarders = new ArrayList<>();

        int off = 12;
        boolean sawTlv = false;
        while (off + 2 <= p.length) {
            final int type = p[off] & 0xff;
            final int length = p[off + 1] & 0xff;   // includes these two bytes
            if (length < 2 || off + length > p.length) break;
            final int v = off + 2;
            sawTlv = true;

            switch (type) {
                case TLV_HELLO -> {
                    if (length < 24) break;
                    gatewayState = p[v + 1] & 0xff;
                    gatewayPriority = p[v + 3] & 0xff;
                    helloMillis = (int) u32(p, v + 6);
                    holdMillis = (int) u32(p, v + 10);
                    final int addressType = p[v + 20] & 0xff;
                    final int addressLength = p[v + 21] & 0xff;
                    if ((addressType == 1 && addressLength == 4) || (addressType == 2 && addressLength == 16)) {
                        virtual = address(p, v + 22, addressLength);
                    }
                }
                case TLV_REQUEST_RESPONSE -> {
                    if (length < 20) break;
                    forwarders.add(new Forwarder(p[v] & 0xff, p[v + 1] & 0xff, p[v + 3] & 0xff,
                            p[v + 4] & 0xff, MacAddress.getByAddress(Arrays.copyOfRange(p, v + 12, v + 18))));
                }
                case TLV_AUTH -> {
                    if (length < 4) break;
                    authType = p[v] & 0xff;
                    final int authLength = Math.min(p[v + 1] & 0xff, length - 4);
                    if (authType == 1 && authLength > 0) {
                        authentication = text(p, v + 2, authLength);
                    } else if (authType == 2 || authType == 3) {
                        authentication = "md5";
                    }
                }
                default -> { }
            }
            off += length;
        }

        if (!sawTlv) return null;
        return new Glbp(version, group, owner, gatewayState, gatewayPriority,
                helloMillis, holdMillis, virtual, forwarders, authType, authentication);
    }

    /** Parses bytes the caller has already identified as GLBP by its port. Throws if they do not fit. */
    public static Glbp parse(byte[] p) throws IllegalRawDataException {
        final Glbp parsed = parseOrNull(p);
        if (parsed == null) throw Raw.notA("GLBP", p);
        return parsed;
    }

    private static InetAddress address(byte[] p, int off, int size) {
        if (off + size > p.length) return null;
        try {
            return InetAddress.getByAddress(Arrays.copyOfRange(p, off, off + size));
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static String text(byte[] p, int off, int len) {
        int end = Math.min(off + len, p.length);
        while (end > off && (p[end - 1] == 0 || p[end - 1] == ' ')) end--;
        return new String(p, off, Math.max(end - off, 0), java.nio.charset.StandardCharsets.US_ASCII);
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
    }

    private static long u32(byte[] p, int off) {
        return ((long) (p[off] & 0xff) << 24) | ((p[off + 1] & 0xff) << 16)
                | ((p[off + 2] & 0xff) << 8) | (p[off + 3] & 0xff);
    }
}
