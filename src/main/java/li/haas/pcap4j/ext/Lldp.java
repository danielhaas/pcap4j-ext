package li.haas.pcap4j.ext;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * LLDP (IEEE 802.1AB), the vendor-neutral neighbour discovery, which pcap4j does not decode.
 * EtherType 0x88cc, usually to 01:80:c2:00:00:0e.
 * TLVs are type (7 bits) and length (9 bits) packed into two bytes, then the value.
 * The organisation-specific TLVs add VLAN data (802.1), link settings (802.3)
 * and, from LLDP-MED, real asset data such as model and serial number.
 */
import org.pcap4j.packet.IllegalRawDataException;

public record Lldp(String chassisId, String portId, Integer ttl,
                   String portDescription, String systemName, String systemDescription,
                   Integer capabilities, Integer enabledCapabilities,
                   List<InetAddress> managementAddresses,
                   Integer portVlanId, Map<Integer, String> vlanNames, Integer maxFrameSize,
                   Integer voiceVlan, Map<String, String> inventory) {

    public static final int ETHER_TYPE = 0x88cc;

    private static final int TLV_END = 0;
    private static final int TLV_CHASSIS_ID = 1;
    private static final int TLV_PORT_ID = 2;
    private static final int TLV_TTL = 3;
    private static final int TLV_PORT_DESCRIPTION = 4;
    private static final int TLV_SYSTEM_NAME = 5;
    private static final int TLV_SYSTEM_DESCRIPTION = 6;
    private static final int TLV_CAPABILITIES = 7;
    private static final int TLV_MANAGEMENT_ADDRESS = 8;
    private static final int TLV_ORG_SPECIFIC = 127;

    private static final int OUI_8021 = 0x0080c2;
    private static final int OUI_8023 = 0x00120f;
    private static final int OUI_MED = 0x0012bb;

    public List<String> capabilityNames() {
        return capabilityNames(enabledCapabilities != null ? enabledCapabilities : capabilities);
    }

    private static List<String> capabilityNames(Integer bits) {
        final List<String> c = new ArrayList<>();
        if (bits == null) return c;
        if ((bits & 0x0001) != 0) c.add("other");
        if ((bits & 0x0002) != 0) c.add("repeater");
        if ((bits & 0x0004) != 0) c.add("bridge");
        if ((bits & 0x0008) != 0) c.add("wlan access point");
        if ((bits & 0x0010) != 0) c.add("router");
        if ((bits & 0x0020) != 0) c.add("telephone");
        if ((bits & 0x0040) != 0) c.add("docsis");
        if ((bits & 0x0080) != 0) c.add("station only");
        return c;
    }

    /** The first line of the system description, which usually names the OS release. */
    public String softwareSummary() {
        if (systemDescription == null) return null;
        final String first = systemDescription.lines().findFirst().orElse("").trim();
        return first.isEmpty() ? null : first;
    }

    @Override
    public String toString() {
        return "LLDP " + (systemName == null ? chassisId : systemName)
                + (portId == null ? "" : " port=" + portId)
                + (portVlanId == null ? "" : " pvid=" + portVlanId)
                + (voiceVlan == null ? "" : " voiceVlan=" + voiceVlan)
                + (capabilityNames().isEmpty() ? "" : " " + capabilityNames())
                + (inventory.isEmpty() ? "" : " " + inventory);
    }

    /**
     * Parses bytes the caller has already identified as an LLDPDU, for example by protocol id or port.
     * Throws rather than returning null: at this point the bytes claim to be this protocol.
     */
    public static Lldp parse(byte[] p) throws IllegalRawDataException {
        final Lldp parsed = parseOrNull(p);
        if (parsed == null) throw Raw.notA("an LLDPDU", p);
        return parsed;
    }

    /** Returns null if the data is not an LLDPDU. */
    private static Lldp parseOrNull(byte[] p) {
        String chassisId = null, portId = null, portDescription = null, systemName = null, systemDescription = null;
        Integer ttl = null, capabilities = null, enabled = null, portVlanId = null, maxFrame = null, voiceVlan = null;
        final List<InetAddress> management = new ArrayList<>();
        final Map<Integer, String> vlanNames = new LinkedHashMap<>();
        final Map<String, String> inventory = new LinkedHashMap<>();

        int off = 0;
        boolean sawChassis = false;
        while (off + 2 <= p.length) {
            final int header = u16(p, off);
            final int type = header >> 9;
            final int len = header & 0x01ff;
            final int v = off + 2;
            if (type == TLV_END) break;
            if (v + len > p.length) return null;  // truncated: not a valid LLDPDU

            switch (type) {
                case TLV_CHASSIS_ID -> {
                    if (len >= 2) {
                        chassisId = idString(p, v, len);
                        sawChassis = true;
                    }
                }
                case TLV_PORT_ID -> { if (len >= 2) portId = idString(p, v, len); }
                case TLV_TTL -> { if (len >= 2) ttl = u16(p, v); }
                case TLV_PORT_DESCRIPTION -> portDescription = text(p, v, len);
                case TLV_SYSTEM_NAME -> systemName = text(p, v, len);
                case TLV_SYSTEM_DESCRIPTION -> systemDescription = text(p, v, len);
                case TLV_CAPABILITIES -> {
                    if (len >= 4) {
                        capabilities = u16(p, v);
                        enabled = u16(p, v + 2);
                    }
                }
                case TLV_MANAGEMENT_ADDRESS -> {
                    // address string length (1), subtype (1), address, then interface and OID data
                    if (len >= 2) {
                        final int addrLen = (p[v] & 0xff) - 1;  // the length includes the subtype byte
                        if (addrLen == 4 || addrLen == 16) {
                            try {
                                management.add(InetAddress.getByAddress(Arrays.copyOfRange(p, v + 2, v + 2 + addrLen)));
                            } catch (UnknownHostException e) {
                                // cannot happen for 4 or 16 bytes
                            }
                        }
                    }
                }
                case TLV_ORG_SPECIFIC -> {
                    if (len < 4) break;
                    final int oui = ((p[v] & 0xff) << 16) | ((p[v + 1] & 0xff) << 8) | (p[v + 2] & 0xff);
                    final int subtype = p[v + 3] & 0xff;
                    final int d = v + 4;
                    final int dlen = len - 4;
                    switch (oui) {
                        case OUI_8021 -> {
                            if (subtype == 1 && dlen >= 2) {
                                portVlanId = u16(p, d);
                            } else if (subtype == 3 && dlen >= 4) {
                                // VLAN ID (2), name length (1), name
                                final int vid = u16(p, d);
                                final int nameLen = p[d + 2] & 0xff;
                                if (d + 3 + nameLen <= p.length) vlanNames.put(vid, text(p, d + 3, nameLen));
                            }
                        }
                        case OUI_8023 -> {
                            if (subtype == 4 && dlen >= 2) maxFrame = u16(p, d);
                        }
                        case OUI_MED -> {
                            switch (subtype) {
                                // network policy: application type (1), flags and VLAN packed into 3 bytes
                                case 2 -> {
                                    if (dlen >= 4 && (p[d] & 0xff) == 1) {  // application type 1 is voice
                                        voiceVlan = ((p[d + 1] & 0x1f) << 7) | ((p[d + 2] & 0xfe) >> 1);
                                    }
                                }
                                case 5 -> inventory.put("hardware", text(p, d, dlen));
                                case 6 -> inventory.put("firmware", text(p, d, dlen));
                                case 7 -> inventory.put("software", text(p, d, dlen));
                                case 8 -> inventory.put("serial", text(p, d, dlen));
                                case 9 -> inventory.put("manufacturer", text(p, d, dlen));
                                case 10 -> inventory.put("model", text(p, d, dlen));
                                case 11 -> inventory.put("asset", text(p, d, dlen));
                                default -> { }
                            }
                        }
                        default -> { }
                    }
                }
                default -> { }
            }
            off = v + len;
        }

        // the first three TLVs are mandatory; without a chassis ID this is not LLDP
        if (!sawChassis || ttl == null) return null;
        return new Lldp(chassisId, portId, ttl, portDescription, systemName, systemDescription,
                capabilities, enabled, management, portVlanId, vlanNames, maxFrame, voiceVlan, inventory);
    }

    /** Chassis and port IDs start with a subtype that says how to read the rest. */
    private static String idString(byte[] p, int off, int len) {
        final int subtype = p[off] & 0xff;
        final int vlen = len - 1;
        final int v = off + 1;
        return switch (subtype) {
            case 4 -> vlen == 6 ? mac(p, v) : text(p, v, vlen);                 // MAC address
            case 5 -> address(p, v, vlen);                                       // network address
            case 3 -> vlen == 6 ? mac(p, v) : text(p, v, vlen);                  // port: MAC (port id subtype 3)
            default -> text(p, v, vlen);                                         // interface name, locally assigned, ...
        };
    }

    /** subtype (1), then the address itself. */
    private static String address(byte[] p, int off, int len) {
        if (len >= 5 && (p[off] & 0xff) == 1) {
            try {
                return InetAddress.getByAddress(Arrays.copyOfRange(p, off + 1, off + 5)).getHostAddress();
            } catch (UnknownHostException e) {
                return text(p, off, len);
            }
        }
        return text(p, off, len);
    }

    private static String mac(byte[] p, int off) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", p[off + i]));
        }
        return sb.toString();
    }

    private static String text(byte[] p, int off, int len) {
        int end = off + Math.max(len, 0);
        if (end > p.length) end = p.length;
        while (end > off && p[end - 1] == 0) end--;
        return new String(p, off, end - off, StandardCharsets.UTF_8).trim();
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
    }
}
