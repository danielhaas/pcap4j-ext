# pcap4j-ext

Parsers for link and network layer protocols that [pcap4j](https://github.com/kaitoy/pcap4j) does
not decode. pcap4j handles Ethernet, IPv4/IPv6, TCP/UDP, ARP, ICMP, DNS and a good deal more; this
library fills in the protocols a network inventory or audit tool tends to need and pcap4j leaves as
`UnknownPacket`.

It is a companion, not a fork: add it next to pcap4j and hand it the raw payload bytes.

## What it parses

| Area | Protocols |
|---|---|
| Spanning tree | STP, RSTP, the common part of MSTP, Cisco PVST+ |
| Cisco layer 2 | CDP, DTP, VTP, PAgP (info and flush), UDLD, CGMP |
| Link aggregation | LACP, the Marker protocol |
| Neighbour discovery | LLDP, including 802.1, 802.3 and LLDP-MED inventory TLVs |
| Gateway redundancy | HSRP v1 and v2, VRRP v2 and v3 |
| Address configuration | DHCP, DHCPv6 |
| Name resolution | mDNS/DNS-SD, LLMNR, NetBIOS name service and datagram service with Windows Browser |
| Discovery | SSDP/UPnP |
| NAT traversal | NAT-PMP, PCP, STUN |
| Multicast | IGMP v1/v2/v3, MLD v1/v2 |
| Other | NTP, TLS client hello (SNI and ALPN), HTTP request and response headers, QUIC initial packets |

## Usage

Every parser is a record with a static `parse` that returns `null` when the bytes are not that
protocol, so it is safe to try several:

```java
UdpPacket udp = packet.get(UdpPacket.class);
byte[] payload = udp.getPayload().getRawData();

Dhcp dhcp = Dhcp.parse(payload);
if (dhcp != null) {
    System.out.println(dhcp.hostName() + " asked for " + dhcp.requestedAddress());
}
```

Protocols that sit under SNAP or a specific EtherType expose the identifier they use, for example
`Cdp.PROTOCOL_ID`, `Lldp.ETHER_TYPE` or `Vrrp.IP_PROTOCOL`, so the caller can dispatch before parsing.

QUIC needs one extra step, because a client hello no longer fits in a single packet:

```java
QuicAssembler assembler = new QuicAssembler();     // keep one per capture
Quic initial = Quic.parse(payload);
if (initial != null) {
    Tls hello = assembler.add(initial);            // null until the hello is complete
    if (hello != null) System.out.println(hello.serverName());
}
```

The Initial packet is decrypted with the keys derived from its own connection id and the salt from
RFC 9001, so no secrets are required.

### DNS based protocols

`Mdns` and `Llmnr` take a `DnsPacket` that the caller builds, so pcap4j needs one of its packet
factories on the classpath to decode record data:

```xml
<dependency>
    <groupId>org.pcap4j</groupId>
    <artifactId>pcap4j-packetfactory-static</artifactId>
    <version>1.8.2</version>
</dependency>
```

Without it, `DnsPacket.newPacket` throws when it reaches the first resource record. The dependency is
declared optional here so it is not forced on callers who use the properties based factory instead.

## Things to know

- **Some of this is reverse engineered.** DTP, PAgP, UDLD and CGMP are Cisco proprietary and have no
  published specification. Their field meanings come from observed traffic and from Wireshark's
  dissectors. Treat the decoded values as informative, not authoritative.
- **No stream reassembly.** TLS and HTTP are read from a single segment. A client hello split across
  TCP segments is missed. QUIC is the exception, because its fragments carry offsets.
- **Detection is best effort.** Several of these protocols have no magic number, so a parser can only
  check that the structure is plausible. Dispatch on the port or EtherType where you can.
- **Nothing here validates checksums.**

## Working around pcap4j

Two defects in pcap4j 1.8.2 affect this ground, and the library works around both:

- A hop-by-hop options header padded with **PadN** is ended two bytes early, so the following ICMPv6
  type is read from the wrong byte. That hides all of MLD, which always travels behind such a header.
  `Mld.parseAfterIpv6` walks the extension headers itself instead.
- **EtherType 0x88a8** (802.1ad) is not decoded, so a QinQ frame stops at the outer tag. A caller can
  re-parse the payload as a `Dot1qVlanTagPacket`.

## Building

```
mvn install
```

Java 25, pcap4j 1.8.2, JUnit 5. The tests build their packets byte by byte from the specifications,
so no capture files are needed and no real network data ships with the library.

## Licence

MIT, the same as pcap4j. No pcap4j code was copied; the parsers were written from the RFCs, from
public protocol documentation and from packet bytes.
