package li.haas.pcap4j.ext;

/**
 * Anything this library can decode. The set is closed so a caller can switch over it
 * exhaustively, which is how {@link Protocols#decode} hands its findings back.
 */
public sealed interface Protocol
        permits Bpdu, Cdp, Cgmp, Dhcp, DhcpV6, Dtp, Eapol, Glbp, Hsrp, Http, Igmp, Lacp,
                Lldp, Llmnr, Marker, Mdns, Mld, NatPmp, Nbds, Nbns, Ntp, Ospf, Pagp, Pcp, Ptp,
                Quic, Snmp, Ssdp, Stun, Syslog, Tftp, Tls, Udld, Vrrp, Vtp, WsDiscovery {
}
