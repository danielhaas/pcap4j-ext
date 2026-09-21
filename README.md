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

## Relationship to pcap4j

This is a companion library, not a set of pcap4j `Packet` classes, and it does not plug into
pcap4j's packet factory. `packet.get(CdpPacket.class)` will not start working because this jar is on
the classpath: `PacketFactories` binds a single `PacketFactoryBinderProvider` through
`ServiceLoader` and takes the first one it finds, and the static factory's tables are private maps
filled in a class initializer. Registering new protocols means replacing the binder or switching to
the properties based factory, neither of which a library should do to its users behind their back.

Two other differences are deliberate:

- **pcap4j builds packets as well as reading them.** `Dot1qVlanTagPacket` is 315 lines for a four
  byte header, most of it `Builder`, `calcLength()` and `getRawFields()`. Nothing here constructs a
  packet, so none of that machinery would ever be called.
- **Detection is part of the job here.** pcap4j's parsers assume the factory already knows the layer
  from a named number. For DTP, SSDP replies, STUN under ICE or QUIC on an unexpected port there is
  often nothing authoritative to dispatch on.

### Strict and sniffing parsers

That second difference is why there are two contracts, and which one applies depends on whether the
caller can identify the protocol before parsing:

- **Strict**: the caller dispatched by EtherType, SNAP protocol id, IP protocol number or port, so
  bytes that do not fit are a malformed frame. `parse` throws `IllegalRawDataException` naming the
  protocol and the first bytes. This covers STP, CDP, DTP, VTP, PAgP, UDLD, CGMP, LLDP, LACP, the
  marker protocol, HSRP, VRRP, DHCP, DHCPv6, NBNS, NBDS, NTP, IGMP, MLD, NAT-PMP and PCP.
- **Sniffing**: nothing identifies the protocol beforehand, so the parser has to recognise itself and
  returns `null` when the bytes are not its own. This covers SSDP, STUN, TLS, HTTP and QUIC, plus the
  locators `Mld.parseAfterIpv6` and `Netbios.decode`.

The split is not cosmetic. While it was being introduced, the permissive contract had already let two
bugs through: `Bpdu.parse` accepted a tunneled frame's payload as a BPDU with a 0.058 second max age,
and `Dtp.parse` accepted sixteen bytes of arbitrary data. Both were silent, because a null looks the
same as "not this protocol".

## Things to know

- **Some of this is reverse engineered.** DTP, PAgP, UDLD and CGMP are Cisco proprietary and have no
  published specification. Their field meanings come from observed traffic and from Wireshark's
  dissectors. Treat the decoded values as informative, not authoritative.
- **No stream reassembly.** TLS and HTTP are read from a single segment. A client hello split across
  TCP segments is missed. QUIC is the exception, because its fragments carry offsets.
- **Sniffing parsers are best effort.** SSDP, STUN, TLS, HTTP and QUIC have to recognise themselves,
  so they check that the structure is plausible and nothing more. Dispatch on a port or EtherType
  where you can, and prefer the strict parsers, which say why they rejected something.
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
