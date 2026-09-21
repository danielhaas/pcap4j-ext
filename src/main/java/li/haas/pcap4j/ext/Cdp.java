package li.haas.pcap4j.ext;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Cisco Discovery Protocol, which pcap4j does not decode.
 * SNAP with OUI 00:00:0c and protocol ID 0x2000, sent to 01:00:0c:cc:cc:cc.
 * Header: version (1), TTL (1), checksum (2), then TLVs of type (2), length (2, including these 4 bytes).
 * It names the switch and the exact port this capture point is plugged into.
 */
import org.pcap4j.packet.IllegalRawDataException;

public record Cdp(int version, int ttl,
                  String deviceId, String portId, String platform, String softwareVersion,
                  String vtpDomain, Integer nativeVlan, Integer duplex, Integer mtu,
                  long capabilities, List<InetAddress> addresses, List<InetAddress> managementAddresses) {

    public static final int PROTOCOL_ID = 0x2000;

    private static final int TLV_DEVICE_ID = 0x0001;
    private static final int TLV_ADDRESSES = 0x0002;
    private static final int TLV_PORT_ID = 0x0003;
    private static final int TLV_CAPABILITIES = 0x0004;
    private static final int TLV_SOFTWARE_VERSION = 0x0005;
    private static final int TLV_PLATFORM = 0x0006;
    private static final int TLV_VTP_DOMAIN = 0x0009;
    private static final int TLV_NATIVE_VLAN = 0x000a;
    private static final int TLV_DUPLEX = 0x000b;
    private static final int TLV_MTU = 0x0011;
    private static final int TLV_SYSTEM_NAME = 0x0014;
    private static final int TLV_MANAGEMENT_ADDRESSES = 0x0016;

    /** Capability bits; a device usually claims several. */
    public List<String> capabilityNames() {
        final List<String> c = new ArrayList<>();
        if ((capabilities & 0x01) != 0) c.add("router");
        if ((capabilities & 0x02) != 0) c.add("transparent bridge");
        if ((capabilities & 0x04) != 0) c.add("source route bridge");
        if ((capabilities & 0x08) != 0) c.add("switch");
        if ((capabilities & 0x10) != 0) c.add("host");
        if ((capabilities & 0x20) != 0) c.add("igmp");
        if ((capabilities & 0x40) != 0) c.add("repeater");
        if ((capabilities & 0x80) != 0) c.add("phone");
        if ((capabilities & 0x100) != 0) c.add("remotely managed");
        return c;
    }

    /** The version string spans several lines; the first one names the release. */
    public String softwareSummary() {
        if (softwareVersion == null) return null;
        final String first = softwareVersion.lines().findFirst().orElse("").trim();
        return first.isEmpty() ? null : first;
    }

    public String duplexName() {
        if (duplex == null) return null;
        return duplex == 0 ? "half" : "full";
    }

    @Override
    public String toString() {
        return "CDP " + (deviceId == null ? "" : deviceId)
                + (portId == null ? "" : " port=" + portId)
                + (platform == null ? "" : " platform=" + platform)
                + (nativeVlan == null ? "" : " nativeVlan=" + nativeVlan)
                + (vtpDomain == null ? "" : " vtp=" + vtpDomain)
                + (duplexName() == null ? "" : " duplex=" + duplexName())
                + (capabilityNames().isEmpty() ? "" : " " + capabilityNames())
                + (softwareSummary() == null ? "" : " sw=" + softwareSummary());
    }

    /**
     * Parses bytes the caller has already identified as CDP, for example by protocol id or port.
     * Throws rather than returning null: at this point the bytes claim to be this protocol.
     */
    public static Cdp parse(byte[] p) throws IllegalRawDataException {
        final Cdp parsed = parseOrNull(p);
        if (parsed == null) throw Raw.notA("CDP", p);
        return parsed;
    }

    /** Returns null if the data is not CDP. */
    private static Cdp parseOrNull(byte[] p) {
        if (p.length < 8) return null;
        final int version = p[0] & 0xff;
        if (version < 1 || version > 2) return null;
        final int ttl = p[1] & 0xff;

        String deviceId = null, portId = null, platform = null, software = null, vtpDomain = null;
        Integer nativeVlan = null, duplex = null, mtu = null;
        long capabilities = 0;
        final List<InetAddress> addresses = new ArrayList<>();
        final List<InetAddress> management = new ArrayList<>();

        int off = 4;
        while (off + 4 <= p.length) {
            final int type = u16(p, off);
            final int len = u16(p, off + 2);
            if (len < 4 || off + len > p.length) break;  // malformed or padding
            final int v = off + 4;
            final int vlen = len - 4;

            switch (type) {
                case TLV_DEVICE_ID, TLV_SYSTEM_NAME -> {
                    if (deviceId == null) deviceId = text(p, v, vlen);
                }
                case TLV_PORT_ID -> portId = text(p, v, vlen);
                case TLV_PLATFORM -> platform = text(p, v, vlen);
                case TLV_SOFTWARE_VERSION -> software = text(p, v, vlen);
                case TLV_VTP_DOMAIN -> vtpDomain = text(p, v, vlen);
                case TLV_NATIVE_VLAN -> { if (vlen >= 2) nativeVlan = u16(p, v); }
                case TLV_DUPLEX -> { if (vlen >= 1) duplex = p[v] & 0xff; }
                case TLV_MTU -> { if (vlen >= 4) mtu = (int) u32(p, v); }
                case TLV_CAPABILITIES -> { if (vlen >= 4) capabilities = u32(p, v); }
                case TLV_ADDRESSES -> addresses.addAll(addresses(p, v, vlen));
                case TLV_MANAGEMENT_ADDRESSES -> management.addAll(addresses(p, v, vlen));
                default -> { }
            }
            off += len;
        }

        if (deviceId == null && portId == null && platform == null) return null;
        return new Cdp(version, ttl, deviceId, portId, platform, software, vtpDomain,
                nativeVlan, duplex, mtu, capabilities, addresses, management);
    }

    /** count (4), then per entry: protocol type (1), protocol length (1), protocol, address length (2), address. */
    private static List<InetAddress> addresses(byte[] p, int off, int len) {
        final List<InetAddress> out = new ArrayList<>();
        if (len < 4) return out;
        final long count = u32(p, off);
        int i = off + 4;
        final int end = off + len;
        for (long n = 0; n < count && i + 5 <= end; n++) {
            final int protoLength = p[i + 1] & 0xff;
            i += 2 + protoLength;
            if (i + 2 > end) break;
            final int addrLength = u16(p, i);
            i += 2;
            if (i + addrLength > end) break;
            if (addrLength == 4 || addrLength == 16) {
                try {
                    out.add(InetAddress.getByAddress(Arrays.copyOfRange(p, i, i + addrLength)));
                } catch (UnknownHostException e) {
                    // cannot happen for 4 or 16 bytes
                }
            }
            i += addrLength;
        }
        return out;
    }

    private static String text(byte[] p, int off, int len) {
        int end = off + len;
        while (end > off && p[end - 1] == 0) end--;  // some devices pad with NUL
        return new String(p, off, end - off, StandardCharsets.UTF_8).trim();
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
    }

    private static long u32(byte[] p, int off) {
        return ((long) u16(p, off) << 16) | u16(p, off + 2);
    }
}
