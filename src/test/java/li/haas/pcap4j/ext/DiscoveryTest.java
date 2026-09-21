package li.haas.pcap4j.ext;

import org.junit.jupiter.api.Test;
import org.pcap4j.packet.DnsPacket;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import static li.haas.pcap4j.ext.ParserTest.hex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Name resolution, service discovery, address configuration and NAT traversal. */
class DiscoveryTest {

    static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    /** A DNS name as length prefixed labels. */
    static byte[] dnsName(String name) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String label : name.split("\\.")) {
            out.write(label.length());
            out.writeBytes(ascii(label));
        }
        out.write(0);
        return out.toByteArray();
    }

    @Test
    void parsesSsdpNotifyAndRejectsSip() {
        final String notify = String.join("\r\n",
                "NOTIFY * HTTP/1.1",
                "HOST: 239.255.255.250:1900",
                "CACHE-CONTROL: max-age = 1800",
                "LOCATION: http://10.0.0.42:1400/xml/device_description.xml",
                "NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                "NTS: ssdp:alive",
                "SERVER: OpenWrt/23.05 UPnP/1.1 MiniUPnPd/2.3.3",
                "USN: uuid:fc4ec57e-b051-11db-88f8-0060085db3f6::upnp:rootdevice",
                "", "");

        final Ssdp ssdp = Ssdp.parse(ascii(notify));
        assertNotNull(ssdp);
        assertEquals(Ssdp.Type.NOTIFY, ssdp.type());
        assertEquals("fc4ec57e-b051-11db-88f8-0060085db3f6", ssdp.uuid());
        assertEquals("10.0.0.42", ssdp.locationHost());
        assertEquals(1400, ssdp.locationPort());
        assertEquals(1800, ssdp.maxAge());          // tolerates the spaces around the equals sign
        assertTrue(ssdp.isInternetGatewayDevice());
        assertFalse(ssdp.isByebye());

        // SIP also uses NOTIFY over UDP, but with a URI rather than an asterisk
        final String sip = "NOTIFY sip:user@10.0.0.9 SIP/2.0\r\nEvent: message-summary\r\n\r\n";
        assertNull(Ssdp.parse(ascii(sip)));
    }

    @Test
    void readsSsdpSearchAsClientNotDevice() {
        final String search = String.join("\r\n",
                "M-SEARCH * HTTP/1.1",
                "HOST: 239.255.255.250:1900",
                "MAN: \"ssdp:discover\"",
                "ST: urn:dial-multiscreen-org:service:dial:1",
                "USER-AGENT: Windows/10.0 UPnP/1.0",
                "", "");
        final Ssdp ssdp = Ssdp.parse(ascii(search));
        assertNotNull(ssdp);
        assertEquals(Ssdp.Type.SEARCH, ssdp.type());
        assertEquals("Windows/10.0 UPnP/1.0", ssdp.server());   // the user agent, for a search
        assertNull(ssdp.uuid());
    }

    @Test
    void parsesNbnsRegistrationAndNodeStatus() {
        final byte[] encoded = ParserTest.encodeNetbiosName("GAMORA", 0x00);
        final ByteArrayOutputStream registration = new ByteArrayOutputStream();
        registration.writeBytes(hex("3a2e 2910 0001 0000 0000 0001"));   // registration, one question
        registration.writeBytes(encoded);
        registration.writeBytes(hex("0020 0001"));                       // NB, class IN

        final Nbns nbns = Nbns.parse(registration.toByteArray());
        assertNotNull(nbns);
        assertEquals("registration", nbns.operation());
        assertEquals(1, nbns.questions().size());
        assertEquals("GAMORA", nbns.questions().get(0).name());

        // node status response: one answer holding two names and the adapter MAC
        final ByteArrayOutputStream status = new ByteArrayOutputStream();
        status.writeBytes(hex("1234 8400 0000 0001 0000 0000"));
        status.writeBytes(ParserTest.encodeNetbiosName("*", 0x00));
        status.writeBytes(hex("0021 0001 00000000"));                    // NBSTAT
        final ByteArrayOutputStream rdata = new ByteArrayOutputStream();
        rdata.write(2);
        rdata.writeBytes(ascii("GAMORA         ")); rdata.write(0x00); rdata.writeBytes(hex("0400"));
        rdata.writeBytes(ascii("WORKGROUP      ")); rdata.write(0x1e); rdata.writeBytes(hex("8400"));
        rdata.writeBytes(hex("6c5ab06c151a"));
        rdata.writeBytes(new byte[46]);                                  // statistics
        status.write(rdata.size() >> 8); status.write(rdata.size() & 0xff);
        status.writeBytes(rdata.toByteArray());

        final Nbns node = Nbns.parse(status.toByteArray());
        assertNotNull(node);
        assertTrue(node.response());
        assertEquals(2, node.names().size());
        assertEquals("6c:5a:b0:6c:15:1a", node.unitId());
    }

    @Test
    void parsesNbdsHostAnnouncement() {
        final ByteArrayOutputStream p = new ByteArrayOutputStream();
        p.write(0x11); p.write(0x0a);                                     // direct group datagram
        p.writeBytes(hex("3378"));                                        // datagram id
        p.writeBytes(hex("c0a81146"));                                    // source 192.168.17.70
        p.writeBytes(hex("008a"));                                        // source port
        p.writeBytes(hex("00c7 0000"));                                   // length and offset
        p.writeBytes(ParserTest.encodeNetbiosName("GAMORA", 0x00));
        p.writeBytes(ParserTest.encodeNetbiosName("WORKGROUP", 0x1d));
        p.writeBytes(ascii("\\MAILSLOT\\BROWSE"));
        p.write(0);
        // host announcement: command, update count, periodicity, name, OS version, server type
        p.write(0x01); p.write(0x0a);
        p.writeBytes(hex("30750000"));
        final byte[] name = new byte[16];
        System.arraycopy(ascii("GAMORA"), 0, name, 0, 6);
        p.writeBytes(name);
        p.write(6); p.write(1);                                           // OS 6.1
        p.writeBytes(hex("03908119"));                                    // server type, little endian
        p.writeBytes(hex("0f01 55aa"));                                   // browser version and signature
        p.writeBytes(ascii("Samba 4.23.5"));
        p.write(0);

        final Nbds nbds = Nbds.parse(p.toByteArray());
        assertNotNull(nbds);
        assertEquals("GAMORA", nbds.sourceName().name());
        assertEquals("WORKGROUP", nbds.workgroup());
        assertEquals("host announcement", nbds.browserCommandName());
        assertEquals("6.1", nbds.osVersion());
        assertEquals("Samba 4.23.5", nbds.comment());
        assertTrue(nbds.roles().contains("workstation"));
        assertFalse(nbds.isDomainAnnouncement());
    }

    @Test
    void extractsHostAndServicesFromMdns() throws Exception {
        final ByteArrayOutputStream dns = new ByteArrayOutputStream();
        dns.writeBytes(hex("0000 8400 0000 0002 0000 0000"));             // two answers
        // PTR: _airplay._tcp.local -> Apple TV._airplay._tcp.local
        dns.writeBytes(dnsName("_airplay._tcp.local"));
        dns.writeBytes(hex("000c 0001 00001194"));
        final byte[] instance = dnsName("AppleTV._airplay._tcp.local");
        dns.write(instance.length >> 8); dns.write(instance.length & 0xff);
        dns.writeBytes(instance);
        // A: appletv.local -> 10.0.0.50
        dns.writeBytes(dnsName("appletv.local"));
        dns.writeBytes(hex("0001 8001 00000078 0004 0a000032"));

        final byte[] raw = dns.toByteArray();
        final Mdns mdns = Mdns.parse(DnsPacket.newPacket(raw, 0, raw.length));
        assertNotNull(mdns);
        assertFalse(mdns.isEmpty());
        assertEquals("appletv.local", mdns.hostname());
        assertTrue(mdns.addresses().contains("10.0.0.50"));
        assertTrue(mdns.services().contains("_airplay._tcp.local"));
        assertTrue(mdns.instances().contains("AppleTV._airplay._tcp.local"));
    }

    @Test
    void separatesLlmnrQueriesFromClaims() throws Exception {
        final ByteArrayOutputStream query = new ByteArrayOutputStream();
        query.writeBytes(hex("1234 0000 0001 0000 0000 0000"));
        query.writeBytes(dnsName("claudia"));
        query.writeBytes(hex("0001 0001"));
        byte[] raw = query.toByteArray();
        final Llmnr asked = Llmnr.parse(DnsPacket.newPacket(raw, 0, raw.length));
        assertNotNull(asked);
        assertTrue(asked.queried().contains("claudia"));
        assertTrue(asked.claimed().isEmpty());

        final ByteArrayOutputStream response = new ByteArrayOutputStream();
        response.writeBytes(hex("1234 8000 0001 0001 0000 0000"));
        response.writeBytes(dnsName("claudia"));
        response.writeBytes(hex("0001 0001"));
        response.writeBytes(dnsName("claudia"));
        response.writeBytes(hex("0001 0001 0000001e 0004 0a000064"));
        raw = response.toByteArray();
        final Llmnr answered = Llmnr.parse(DnsPacket.newPacket(raw, 0, raw.length));
        assertNotNull(answered);
        assertTrue(answered.claimed().contains("claudia"));
        assertTrue(answered.addresses().contains("10.0.0.100"));
    }

    @Test
    void parsesDhcpv6SolicitAndReply() {
        // solicit with a DUID-LL client id, which carries the MAC
        final byte[] solicit = hex("01 123456 0001 000a 0003 0001 aa0000000055 0008 0002 00fa");
        final Dhcp6 asked = Dhcp6.parse(solicit);
        assertNotNull(asked);
        assertEquals("solicit", asked.messageTypeName());
        assertNotNull(asked.clientMac());
        assertEquals("aa:00:00:00:00:55", asked.clientMac().toString());
        assertFalse(asked.fromServer());

        // reply carrying an address and a delegated prefix
        final String iaaddr = "0005 0018 20010db8000100000000000000000001 00000e10 00001c20";
        final String iana = "0003 0028 11223344 00000708 00000b40 " + iaaddr;
        final String iaprefix = "001a 0019 00000e10 00001c20 38 20010db8beef00000000000000000000";
        final String iapd = "0019 0029 55667788 00000708 00000b40 " + iaprefix;
        final Dhcp6 reply = Dhcp6.parse(hex("07 123456 0002 000a 0003 0001 bb0000000066 " + iana + " " + iapd));
        assertNotNull(reply);
        assertTrue(reply.fromServer());
        assertEquals(1, reply.addresses().size());
        assertEquals(1, reply.prefixes().size());
        assertTrue(reply.prefixes().get(0).endsWith("/56"));
    }

    @Test
    void parsesNatPmpAndPcpOnTheSamePort() {
        final NatPmp response = NatPmp.parse(hex("00 80 0000 000004d2 cb00710f"));
        assertNotNull(response);
        assertTrue(response.isResponse());
        assertEquals("external address", response.operation());
        assertEquals("203.0.113.15", response.externalAddress().getHostAddress());
        // PCP starts with version 2, so the two never collide
        assertNull(Dhcp.parse(hex("00 80 0000 000004d2 cb00710f")));

        final String clientAddress = "00000000000000000000ffff0a000007";
        final Pcp request = Pcp.parse(hex("02 01 0000 00000e10 " + clientAddress
                + " 0b0b0b0b0b0b0b0b0b0b0b0b 06 000000 1f90 0000 " + "00".repeat(16)));
        assertNotNull(request);
        assertEquals("map", request.operation());
        assertFalse(request.response());
        assertEquals(8080, request.internalPort());
        assertTrue(request.isIpv4Client());
        assertNull(NatPmp.parse(hex("02 01 0000 00000e10")));
    }

    @Test
    void readsXorMappedAddressFromStun() {
        // binding success response with an XOR mapped IPv4 address: 203.0.113.9:62000
        final int port = 62000 ^ 0x2112;
        final byte[] address = hex("cb007109");
        final byte[] cookie = hex("2112a442");
        final byte[] xored = new byte[4];
        for (int i = 0; i < 4; i++) xored[i] = (byte) (address[i] ^ cookie[i]);

        final ByteArrayOutputStream p = new ByteArrayOutputStream();
        p.writeBytes(hex("0101 000c 2112a442"));
        p.writeBytes(hex("a1".repeat(12)));                    // transaction id
        p.writeBytes(hex("0020 0008 0001"));                   // XOR mapped address, IPv4
        p.write(port >> 8); p.write(port & 0xff);
        p.writeBytes(xored);

        final Stun stun = Stun.parse(p.toByteArray());
        assertNotNull(stun);
        assertEquals("success response", stun.messageClass());
        assertEquals(0x001, stun.method());
        assertEquals("203.0.113.9", stun.mappedAddress().getHostAddress());
        assertEquals(62000, stun.mappedPort());
    }

    @Test
    void readsHttpRequestAndResponseHeaders() {
        final String request = "GET /index.html HTTP/1.1\r\nHost: example.test\r\n"
                + "User-Agent: curl/8.6.0\r\nAccept: */*\r\n\r\n";
        final Http get = Http.parse(ascii(request));
        assertNotNull(get);
        assertFalse(get.isResponse());
        assertEquals("GET", get.method());
        assertEquals("example.test", get.host());
        assertEquals("curl/8.6.0", get.userAgent());

        final String response = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.68 (Debian)\r\n\r\n";
        final Http ok = Http.parse(ascii(response));
        assertNotNull(ok);
        assertTrue(ok.isResponse());
        assertEquals("Apache/2.4.68 (Debian)", ok.server());

        assertNull(Http.parse(ascii("not a request at all\r\n\r\n")));
    }

    @Test
    void reassemblesQuicClientHelloFromFragments() {
        // the hello is split the way a browser splits one: out of order, with a gap until the last piece
        final byte[] hello = clientHello("quic.example");
        final int cut = hello.length / 2;
        final byte[] first = java.util.Arrays.copyOfRange(hello, 0, cut);
        final byte[] second = java.util.Arrays.copyOfRange(hello, cut, hello.length);

        final QuicAssembler assembler = new QuicAssembler();
        final Quic tail = new Quic(Quic.VERSION_1, "abcd", "ef01",
                java.util.List.of(new Quic.Fragment(cut, second)));
        assertNull(assembler.add(tail), "nothing to parse until the first fragment arrives");

        final Quic head = new Quic(Quic.VERSION_1, "abcd", "ef01",
                java.util.List.of(new Quic.Fragment(0, first)));
        final Tls complete = assembler.add(head);
        assertNotNull(complete);
        assertEquals("quic.example", complete.serverName());
    }

    /** A minimal client hello carrying one server name. */
    static byte[] clientHello(String host) {
        final byte[] name = ascii(host);
        final ByteArrayOutputStream sni = new ByteArrayOutputStream();
        sni.write(0x00); sni.write(0x00);
        sni.write((name.length + 5) >> 8); sni.write((name.length + 5) & 0xff);
        sni.write((name.length + 3) >> 8); sni.write((name.length + 3) & 0xff);
        sni.write(0x00);
        sni.write(name.length >> 8); sni.write(name.length & 0xff);
        sni.writeBytes(name);

        final ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0x01);
        body.writeBytes(new byte[3]);
        body.write(0x03); body.write(0x03);
        body.writeBytes(new byte[32]);
        body.write(0x00);
        body.write(0x00); body.write(0x02); body.write(0x13); body.write(0x01);
        body.write(0x01); body.write(0x00);
        body.write(sni.size() >> 8); body.write(sni.size() & 0xff);
        body.writeBytes(sni.toByteArray());
        return body.toByteArray();
    }
}
