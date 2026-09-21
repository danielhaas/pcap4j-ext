/**
 * Parsers for link and network layer protocols that pcap4j does not decode.
 *
 * <p>Every parser is a {@code record} implementing {@link li.haas.pcap4j.ext.Protocol}, with a
 * static {@code parse}. Which contract applies depends on whether the caller can identify the
 * protocol before parsing:
 *
 * <ul>
 *   <li><b>Strict.</b> The caller dispatched by EtherType, SNAP protocol id, IP protocol number or
 *       port, so bytes that do not fit are a malformed frame: {@code parse} throws
 *       {@link org.pcap4j.packet.IllegalRawDataException} naming the protocol and the first bytes,
 *       and never returns null. STP, CDP, DTP, VTP, PAgP, UDLD, CGMP, LLDP, LACP, the marker
 *       protocol, HSRP, VRRP, DHCP, DHCPv6, NBNS, NBDS, NTP, IGMP, MLD, NAT-PMP and PCP.
 *   <li><b>Sniffing.</b> Nothing identifies the protocol beforehand, so the parser recognises
 *       itself and returns null when the bytes are not its own. SSDP, STUN, TLS, HTTP and QUIC,
 *       plus the locators {@code Mld.parseAfterIpv6} and {@code Netbios.parseName}.
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
