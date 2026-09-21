# Changelog

## Unreleased

First working version, split out of a network inventory tool.

### Parsers

Spanning tree (STP, RSTP, the common part of MSTP, PVST+), the Cisco layer 2 family (CDP, DTP,
VTP, PAgP with its flush packets, UDLD, CGMP), link aggregation (LACP and the marker protocol),
LLDP with its 802.1, 802.3 and MED extensions, gateway redundancy (HSRP v1 and v2, VRRP v2 and v3,
GLBP), address configuration (DHCP, DHCPv6), name resolution (mDNS, LLMNR, NetBIOS name and
datagram services with Windows Browser), discovery (SSDP, WS-Discovery), NAT traversal (NAT-PMP,
PCP, STUN), multicast (IGMP v1 to v3, MLD v1 and v2), port authentication (802.1X and EAP),
routing (OSPF hellos), management (SNMP v1 and v2c), timing (NTP, PTP), and the parts of TLS,
QUIC, HTTP, syslog and TFTP that identify a device.

### Notes

- QUIC initial packets are decrypted with the keys derived from their connection id, so a server
  name can be read out of an otherwise encrypted handshake. Hellos spanning several packets are
  reassembled by `QuicAssembler`.
- Parsers reached through a dispatch key throw `IllegalRawDataException`; those that have to
  recognise themselves return null. `package-info` explains which is which.
- `Protocols.decode` routes a packet to the right parsers and returns each finding with the MAC
  and VLAN tags it arrived on.
- Every parser is checked against tshark by `tools/crosscheck.py`: 448 field values over twenty
  captures at the time of writing, with no disagreement.
