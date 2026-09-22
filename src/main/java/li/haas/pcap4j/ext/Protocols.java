package li.haas.pcap4j.ext;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.Dot1qVlanTagPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.LlcPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SnapPacket;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Routes a captured packet to the parsers that can read it, so a caller does not have to know
 * that SNAP protocol id 0x2000 means CDP or that UDP 5351 carries NAT-PMP and PCP together.
 *
 * <pre>
 * for (Protocols.Finding found : Protocols.decode(packet).found()) {
 *     switch (found.protocol()) {
 *         case Cdp cdp -&gt; System.out.println(cdp.deviceId() + " " + cdp.portId());
 *         case Dhcp dhcp -&gt; System.out.println(dhcp.hostName());
 *         default -&gt; { }
 *     }
 * }
 * </pre>
 *
 * Only the layers pcap4j itself hands over are visited. Protocols that need state across
 * packets, QUIC in particular, are returned as they arrive; feed them to {@link QuicAssembler}.
 */
public final class Protocols {

    private Protocols() {
    }

    /**
     * One protocol and the frame it came in on. Without the sender a finding cannot be filed
     * against a device, and the caller would have to walk the layers again to recover it.
     *
     * @param protocol    what was read
     * @param source      the MAC that sent the frame
     * @param destination the MAC it was sent to
     * @param vlans       the VLAN tags it arrived under, outermost first, empty when untagged
     */
    public record Finding(Protocol protocol, MacAddress source, MacAddress destination, List<Integer> vlans) {

        public Finding {
            vlans = vlans == null ? List.of() : Collections.unmodifiableList(new ArrayList<>(vlans));
        }

        @Override
        public String toString() {
            return (source == null ? "?" : source) + (vlans.isEmpty() ? "" : " " + vlans) + "  " + protocol;
        }
    }

    /**
     * What one packet turned out to hold.
     *
     * @param found    everything that parsed, outermost layer first, with the frame it came in on
     * @param rejected messages from parsers whose layer identified them but whose bytes did not fit
     */
    public record Decoded(List<Finding> found, List<String> rejected) {

        public Decoded {
            found = Collections.unmodifiableList(new ArrayList<>(found));
            rejected = Collections.unmodifiableList(new ArrayList<>(rejected));
        }

        public boolean isEmpty() {
            return found.isEmpty();
        }

        /** Just the protocols, for a caller that does not care who sent them. */
        public List<Protocol> protocols() {
            return found.stream().map(Finding::protocol).toList();
        }

        /** The first decoded protocol of the given kind, or null. */
        public <T extends Protocol> T first(Class<T> kind) {
            for (Finding f : found) {
                if (kind.isInstance(f.protocol())) return kind.cast(f.protocol());
            }
            return null;
        }
    }

    /**
     * The packet's layers, outermost first, including ones pcap4j hands over as raw data.
     * An 802.1ad or legacy QinQ tag is decoded here, because pcap4j knows only 0x8100 and would
     * otherwise stop at the outer tag and hide everything behind it.
     */
    public static Iterable<Packet> layers(Packet packet) {
        final List<Packet> out = new ArrayList<>();
        for (Packet layer = packet; layer != null; layer = next(layer)) {
            out.add(layer);
        }
        return out;
    }

    /** The next layer, decoding a stacked VLAN tag that pcap4j left as raw data. */
    private static Packet next(Packet packet) {
        final Packet payload = packet.getPayload();
        final EtherType type = switch (packet) {
            case EthernetPacket eth -> eth.getHeader().getType();
            case Dot1qVlanTagPacket tag -> tag.getHeader().getType();
            default -> null;
        };
        if (payload instanceof UnknownPacket && type != null) {
            final int value = type.value() & 0xffff;
            if (value == ETHER_TYPE_8021AD || value == ETHER_TYPE_QINQ_LEGACY) {
                final byte[] raw = payload.getRawData();
                try {
                    return Dot1qVlanTagPacket.newPacket(raw, 0, raw.length);
                } catch (IllegalRawDataException e) {
                    return payload;
                }
            }
        }
        return payload;
    }

    /** 802.1ad, and the pre-standard tag some switches still use. */
    public static final int ETHER_TYPE_8021AD = 0x88a8;
    public static final int ETHER_TYPE_QINQ_LEGACY = 0x9100;

    /** Walks the packet's layers and parses what it recognises. Never returns null. */
    public static Decoded decode(Packet packet) {
        final List<Protocol> found = new ArrayList<>();
        final List<String> rejected = new ArrayList<>();
        MacAddress source = null;
        MacAddress destination = null;
        final List<Integer> vlans = new ArrayList<>();

        for (Packet layer : layers(packet)) {
            // the outermost Ethernet header is the one that sent this frame; an ICMP error or a
            // tunnelled copy carries another one further in, which is somebody else's
            if (layer instanceof EthernetPacket eth && source == null) {
                source = eth.getHeader().getSrcAddr();
                destination = eth.getHeader().getDstAddr();
            } else if (layer instanceof Dot1qVlanTagPacket tag) {
                vlans.add(tag.getHeader().getVidAsInt());
            }
            try {
                decodeLayer(layer, found);
            } catch (IllegalRawDataException e) {
                rejected.add(e.getMessage());
            }
        }

        final List<Finding> findings = new ArrayList<>(found.size());
        for (Protocol protocol : found) {
            findings.add(new Finding(protocol, source, destination, vlans));
        }
        return new Decoded(findings, rejected);
    }

    private static void decodeLayer(Packet layer, List<Protocol> found) throws IllegalRawDataException {
        switch (layer) {
            case EthernetPacket eth -> ethernet(eth.getHeader().getType(), eth.getPayload(), found);
            case Dot1qVlanTagPacket tag -> ethernet(tag.getHeader().getType(), tag.getPayload(), found);
            case LlcPacket llc -> llc(llc, found);
            case SnapPacket snap -> snap(snap, found);
            case IpV4Packet ip -> ipv4(ip, found);
            case IpV6Packet ip -> ipv6(ip, found);
            case UdpPacket udp -> udp(udp, found);
            case TcpPacket tcp -> tcp(tcp, found);
            case IcmpV6CommonPacket icmp6 -> {
                // MLD sits behind a hop-by-hop header pcap4j mis-slices, so it is found from IPv6
            }
            default -> { }
        }
    }

    /** LLDP and the ECTP loopback both sit directly on Ethernet, tagged or not. */
    private static void ethernet(EtherType type, Packet payload, List<Protocol> found)
            throws IllegalRawDataException {
        if (payload == null) return;
        final int etherType = type.value() & 0xffff;
        if (etherType == Eapol.ETHER_TYPE) {
            found.add(Eapol.parse(payload.getRawData()));
        } else if (etherType == Ptp.ETHER_TYPE) {
            addIfPresent(found, Ptp.parse(payload.getRawData()));
        } else if (etherType == Lldp.ETHER_TYPE) {
            found.add(Lldp.parse(payload.getRawData()));
        } else if (etherType == Lacp.ETHER_TYPE) {
            final byte[] raw = payload.getRawData();
            if (raw.length > 0 && (raw[0] & 0xff) == Marker.SUBTYPE) {
                found.add(Marker.parse(raw));
            } else {
                found.add(Lacp.parse(raw));
            }
        }
    }

    private static void llc(LlcPacket llc, List<Protocol> found) throws IllegalRawDataException {
        if (llc.getPayload() == null) return;
        // DSAP 0x42 is spanning tree; 0xaa is SNAP, which the next layer handles
        if ((llc.getHeader().getDsap().value() & 0xff) == Bpdu.LLC_SAP) {
            found.add(Bpdu.parse(llc.getPayload().getRawData()));
        }
    }

    private static void snap(SnapPacket snap, List<Protocol> found) throws IllegalRawDataException {
        if (snap.getPayload() == null || snap.getHeader().getOui().value() != 0x00000c) return;
        final byte[] raw = snap.getPayload().getRawData();
        switch (snap.getHeader().getProtocolId().value() & 0xffff) {
            case Cdp.PROTOCOL_ID -> found.add(Cdp.parse(raw));
            case Vtp.PROTOCOL_ID -> found.add(Vtp.parse(raw));
            case Dtp.PROTOCOL_ID -> found.add(Dtp.parse(raw));
            case Cgmp.PROTOCOL_ID -> found.add(Cgmp.parse(raw));
            case Udld.PROTOCOL_ID -> found.add(Udld.parse(raw));
            case Bpdu.PVST_PROTOCOL_ID -> found.add(Bpdu.parse(raw));
            case Pagp.PROTOCOL_ID -> {
                // one protocol id, two formats, told apart by the version byte
                if (raw.length > 0 && (raw[0] & 0xff) == Pagp.VERSION_FLUSH) {
                    Pagp.parseFlush(raw);   // a flush is not a Protocol of its own
                } else {
                    found.add(Pagp.parse(raw));
                }
            }
            default -> { }
        }
    }

    private static void ipv4(IpV4Packet ip, List<Protocol> found) throws IllegalRawDataException {
        if (ip.getPayload() == null) return;
        final int protocol = ip.getHeader().getProtocol().value() & 0xff;
        if (protocol == Ospf.IP_PROTOCOL) {
            found.add(Ospf.parse(ip.getPayload().getRawData()));
        } else if (protocol == Igmp.IP_PROTOCOL) {
            found.add(Igmp.parse(ip.getPayload().getRawData()));
        } else if (protocol == Vrrp.IP_PROTOCOL) {
            found.add(Vrrp.parse(ip.getPayload().getRawData(), false));
        }
    }

    private static void ipv6(IpV6Packet ip, List<Protocol> found) throws IllegalRawDataException {
        if (ip.getPayload() == null) return;
        final int nextHeader = ip.getHeader().getNextHeader().value() & 0xff;
        if (nextHeader == Ospf.IP_PROTOCOL) {
            found.add(Ospf.parse(ip.getPayload().getRawData()));
            return;
        }
        if (nextHeader == Vrrp.IP_PROTOCOL) {
            found.add(Vrrp.parse(ip.getPayload().getRawData(), true));
            return;
        }
        // MLD travels behind a hop-by-hop header, which pcap4j ends two bytes early when it is
        // padded with PadN, so the extension headers are walked here instead
        final Mld mld = Mld.parseAfterIpv6(nextHeader, ip.getPayload().getRawData());
        if (mld != null) found.add(mld);
    }

    private static void udp(UdpPacket udp, List<Protocol> found) throws IllegalRawDataException {
        if (udp.getPayload() == null) return;
        final byte[] raw = udp.getPayload().getRawData();
        final int src = udp.getHeader().getSrcPort().valueAsInt();
        final int dst = udp.getHeader().getDstPort().valueAsInt();

        if (on(src, dst, Dhcp.SERVER_PORT) || on(src, dst, Dhcp.CLIENT_PORT)) {
            found.add(Dhcp.parse(raw));
        }
        if (on(src, dst, DhcpV6.CLIENT_PORT) || on(src, dst, DhcpV6.SERVER_PORT)) {
            found.add(DhcpV6.parse(raw));
        }
        if (on(src, dst, Nbns.PORT)) {
            found.add(Nbns.parse(raw));
        }
        if (on(src, dst, Nbds.PORT)) {
            found.add(Nbds.parse(raw));
        }
        if (on(src, dst, Ntp.PORT)) {
            found.add(Ntp.parse(raw));
        }
        if (on(src, dst, Hsrp.PORT_V1) || on(src, dst, Hsrp.PORT_V6)) {
            found.add(Hsrp.parse(raw));
        }
        if (on(src, dst, NatPmp.PORT) || on(src, dst, NatPmp.ANNOUNCE_PORT)) {
            // NAT-PMP and PCP share the port and differ in their first byte
            if (raw.length > 0 && (raw[0] & 0xff) == Pcp.VERSION) {
                found.add(Pcp.parse(raw));
            } else {
                found.add(NatPmp.parse(raw));
            }
        }
        if (on(src, dst, Glbp.PORT)) {
            found.add(Glbp.parse(raw));
        }
        if (on(src, dst, Snmp.PORT) || on(src, dst, Snmp.TRAP_PORT)) {
            found.add(Snmp.parse(raw));
        }
        if (on(src, dst, Syslog.PORT)) {
            addIfPresent(found, Syslog.parse(raw));
        }
        if (on(src, dst, Tftp.PORT)) {
            addIfPresent(found, Tftp.parse(raw));
        }
        if (on(src, dst, WsDiscovery.PORT)) {
            addIfPresent(found, WsDiscovery.parse(raw));
        }
        if (on(src, dst, Ptp.EVENT_PORT) || on(src, dst, Ptp.GENERAL_PORT)) {
            addIfPresent(found, Ptp.parse(raw));
        }
        if (on(src, dst, Mdns.PORT) || on(src, dst, Llmnr.PORT)) {
            final DnsPacket dns = DnsPacket.newPacket(raw, 0, raw.length);
            if (on(src, dst, Mdns.PORT)) {
                final Mdns mdns = Mdns.parse(dns);
                if (!mdns.isEmpty()) found.add(mdns);
            } else {
                final Llmnr llmnr = Llmnr.parse(dns);
                if (!llmnr.isEmpty()) found.add(llmnr);
            }
        }

        // these recognise themselves, because the port says nothing
        addIfPresent(found, Ssdp.parse(raw));
        addIfPresent(found, Stun.parse(raw));
        addIfPresent(found, Quic.parse(raw));
    }

    private static void tcp(TcpPacket tcp, List<Protocol> found) {
        if (tcp.getPayload() == null) return;
        final byte[] raw = tcp.getPayload().getRawData();
        addIfPresent(found, Tls.parse(raw));
        addIfPresent(found, Http.parse(raw));
    }

    private static void addIfPresent(List<Protocol> found, Protocol parsed) {
        if (parsed != null) found.add(parsed);
    }

    private static boolean on(int src, int dst, int port) {
        return src == port || dst == port;
    }

    /** ARP is decoded by pcap4j itself, and is listed here only so callers can find it in one place. */
    public static ArpPacket arp(Packet packet) {
        return packet.get(ArpPacket.class);
    }
}
