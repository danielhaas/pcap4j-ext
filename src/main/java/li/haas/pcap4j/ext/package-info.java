/**
 * Parsers for link and network layer protocols that pcap4j does not decode.
 *
 * <p>Every parser is a {@code record} implementing {@link li.haas.pcap4j.ext.Protocol}, with a
 * static {@code parse}, and its class documentation describes the protocol itself: what it is for,
 * how it is carried, and which of its fields this library reads.
 *
 * <h2>What is here</h2>
 *
 * <dl>
 *   <dt>Spanning tree</dt>
 *   <dd>{@link li.haas.pcap4j.ext.Bpdu} — STP, RSTP, the common part of MSTP and Cisco PVST+: which
 *       switch is root and which ports are blocked.</dd>
 *
 *   <dt>Cisco layer 2</dt>
 *   <dd>{@link li.haas.pcap4j.ext.Cdp} — the neighbour announcement that names the switch and the
 *       port this capture is plugged into.<br>
 *       {@link li.haas.pcap4j.ext.Dtp} — whether a port negotiated a trunk, and in which mode.<br>
 *       {@link li.haas.pcap4j.ext.Vtp} — the VLAN database and the revision number that overwrites
 *       it.<br>
 *       {@link li.haas.pcap4j.ext.Pagp} — Cisco's pre-standard link bundling.<br>
 *       {@link li.haas.pcap4j.ext.Udld} — the echo that proves a fibre works in both
 *       directions.<br>
 *       {@link li.haas.pcap4j.ext.Cgmp} — the router telling the switch who joined which multicast
 *       group.</dd>
 *
 *   <dt>Link aggregation</dt>
 *   <dd>{@link li.haas.pcap4j.ext.Lacp} — both ends of a bundle and whether it is actually up.<br>
 *       {@link li.haas.pcap4j.ext.Marker} — the flush that lets a conversation move between links
 *       without reordering.</dd>
 *
 *   <dt>Neighbour discovery</dt>
 *   <dd>{@link li.haas.pcap4j.ext.Lldp} — the vendor-neutral CDP, including the LLDP-MED inventory
 *       TLVs that carry model and serial number.</dd>
 *
 *   <dt>Gateway redundancy</dt>
 *   <dd>{@link li.haas.pcap4j.ext.Hsrp}, {@link li.haas.pcap4j.ext.Vrrp} and
 *       {@link li.haas.pcap4j.ext.Glbp} — who currently answers for the default gateway address,
 *       and how long a failover takes.</dd>
 *
 *   <dt>Routing</dt>
 *   <dd>{@link li.haas.pcap4j.ext.Ospf} — the hello that names the router, its area and every
 *       neighbour it has heard from.</dd>
 *
 *   <dt>Address configuration</dt>
 *   <dd>{@link li.haas.pcap4j.ext.Dhcp} and {@link li.haas.pcap4j.ext.DhcpV6} — what a host asked
 *       for, what it was given, and the host name and vendor class it volunteered.</dd>
 *
 *   <dt>Name resolution</dt>
 *   <dd>{@link li.haas.pcap4j.ext.Mdns} — .local names, services, ports and the TXT records that
 *       state the hardware model.<br>
 *       {@link li.haas.pcap4j.ext.Llmnr} — the Windows fallback when DNS has no answer.<br>
 *       {@link li.haas.pcap4j.ext.Nbns} and {@link li.haas.pcap4j.ext.Nbds} — NetBIOS names, the
 *       adapter MAC, and the Windows Browser announcements, with the shared pieces in
 *       {@link li.haas.pcap4j.ext.Netbios}.</dd>
 *
 *   <dt>Discovery</dt>
 *   <dd>{@link li.haas.pcap4j.ext.Ssdp} — UPnP, including the gateways that will open ports on
 *       request.<br>
 *       {@link li.haas.pcap4j.ext.WsDiscovery} — what Windows and network printers announce
 *       themselves with.</dd>
 *
 *   <dt>NAT traversal</dt>
 *   <dd>{@link li.haas.pcap4j.ext.NatPmp} and {@link li.haas.pcap4j.ext.Pcp} — hosts asking the
 *       gateway to open inbound ports.<br>
 *       {@link li.haas.pcap4j.ext.Stun} — the public address a NAT handed a client, and the sign
 *       that a real-time session is starting.</dd>
 *
 *   <dt>Multicast</dt>
 *   <dd>{@link li.haas.pcap4j.ext.Igmp} and {@link li.haas.pcap4j.ext.Mld} — which hosts want which
 *       groups, and from which sources.</dd>
 *
 *   <dt>Access control</dt>
 *   <dd>{@link li.haas.pcap4j.ext.Eapol} — 802.1X: who authenticates on which port, with what
 *       method, and whether it worked.</dd>
 *
 *   <dt>Management</dt>
 *   <dd>{@link li.haas.pcap4j.ext.Snmp} — the clear text community string and the variables being
 *       read or written.<br>
 *       {@link li.haas.pcap4j.ext.Syslog} — where devices log, and what they log.<br>
 *       {@link li.haas.pcap4j.ext.Tftp} — the configuration and firmware files devices fetch
 *       unauthenticated at boot.</dd>
 *
 *   <dt>Time</dt>
 *   <dd>{@link li.haas.pcap4j.ext.Ntp} — the stratum hierarchy.<br>
 *       {@link li.haas.pcap4j.ext.Ptp} — the grandmaster clock and what it claims about itself.</dd>
 *
 *   <dt>Application</dt>
 *   <dd>{@link li.haas.pcap4j.ext.Tls} — the server name and ALPN out of a client hello.<br>
 *       {@link li.haas.pcap4j.ext.Http} — the request line, Host, User-Agent and Server.<br>
 *       {@link li.haas.pcap4j.ext.Quic} — Initial packets, decrypted, with
 *       {@link li.haas.pcap4j.ext.QuicAssembler} putting a split client hello back together.</dd>
 * </dl>
 *
 * <h2>Two parse contracts</h2>
 *
 * <p>Which contract applies depends on whether the caller can identify the protocol before parsing:
 *
 * <ul>
 *   <li><b>Strict.</b> The caller dispatched by EtherType, SNAP protocol id, IP protocol number or
 *       port, so bytes that do not fit are a malformed frame: {@code parse} throws
 *       {@link org.pcap4j.packet.IllegalRawDataException} naming the protocol and the first bytes,
 *       and never returns null. STP, CDP, DTP, VTP, PAgP, UDLD, CGMP, LLDP, LACP, the marker
 *       protocol, 802.1X, HSRP, VRRP, GLBP, OSPF, DHCP, DHCPv6, NBNS, NBDS, NTP, SNMP, IGMP, MLD,
 *       NAT-PMP and PCP. Where a caller wants to probe rather than dispatch, 802.1X, GLBP, OSPF and
 *       SNMP also expose the underlying {@code parseOrNull}.
 *   <li><b>Sniffing.</b> Nothing identifies the protocol beforehand, or the port that carries it is
 *       not proof enough, so the parser recognises itself and returns null when the bytes are not
 *       its own. SSDP, STUN, TLS, HTTP, QUIC, syslog, TFTP, PTP and WS-Discovery, plus the locators
 *       {@code Mld.parseAfterIpv6} and {@code Netbios.parseName}.
 * </ul>
 *
 * <p>{@link li.haas.pcap4j.ext.Protocols#decode} applies the right one for each layer of a packet,
 * which saves the caller from knowing the dispatch keys. Each parser also exposes its own key as a
 * constant, such as {@code Cdp.PROTOCOL_ID} or {@code Lldp.ETHER_TYPE}.
 *
 * <p>Records are immutable and copy any collection handed to them. {@link li.haas.pcap4j.ext.QuicAssembler}
 * is the one stateful class here and is not thread safe.
 */
package li.haas.pcap4j.ext;
