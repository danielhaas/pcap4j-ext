package li.haas.pcap4j.ext;

import org.junit.jupiter.api.Test;
import org.pcap4j.packet.IllegalRawDataException;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Every vector here is synthetic, built from the wire format in the relevant specification,
 * so no real capture is needed and nothing from a real network is published with the library.
 */
class ParserTest {

    static byte[] hex(String s) {
        final String clean = s.replaceAll("\\s", "");
        final byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    @Test
    void parsesConfigurationBpdu() throws Exception {
        final Bpdu bpdu = Bpdu.parse(hex(
                "0000 00 00 00 8000 001122334455 00000004 8000 001122334455 8001 0100 1400 0200 0f00"));
        assertNotNull(bpdu);
        assertEquals(Bpdu.TYPE_CONFIG, bpdu.type());
        assertEquals(32768, bpdu.root().priority());
        assertEquals(4, bpdu.rootPathCost());
        assertEquals(20.0, bpdu.maxAge());
        assertEquals(2.0, bpdu.helloTime());
        assertFalse(bpdu.topologyChange());
    }

    @Test
    void readsTopologyChangeFlagFromRstpBpdu() throws Exception {
        final Bpdu bpdu = Bpdu.parse(hex(
                "0000 02 02 7d 1000aaaaaaaaaaaa 00004e20 8000bbbbbbbbbbbb 8002 0100 1400 0200 0f00 00"));
        assertNotNull(bpdu);
        assertEquals(Bpdu.VERSION_RSTP, bpdu.version());
        assertTrue(bpdu.topologyChange());
        assertEquals(20000, bpdu.rootPathCost());
    }

    @Test
    void parsesDtpWithDomainAndStatus() throws Exception {
        // version 1, domain "HONGKONGDC", status 0x04 (access/auto), type 0x40, neighbour MAC
        final Dtp dtp = Dtp.parse(hex(
                "01 0001 000f 484f4e474b4f4e474443 00 0002 0005 04 0003 0005 40 0004 000a 7c69f673868a"));
        assertNotNull(dtp);
        assertEquals("HONGKONGDC", dtp.domain());
        assertEquals("auto", dtp.adminMode());
        assertFalse(dtp.isTrunk());
        assertNotNull(dtp.neighbor());
    }

    /** First level encoding: every byte becomes two characters, each a nibble plus 'A'. */
    static byte[] encodeNetbiosName(String name, int suffix) {
        final byte[] padded = new byte[16];
        java.util.Arrays.fill(padded, (byte) ' ');
        final byte[] raw = name.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(raw, 0, padded, 0, raw.length);
        padded[15] = (byte) suffix;

        final byte[] out = new byte[34];
        out[0] = 32;
        for (int i = 0; i < 16; i++) {
            out[1 + 2 * i] = (byte) ('A' + ((padded[i] & 0xff) >> 4));
            out[2 + 2 * i] = (byte) ('A' + (padded[i] & 0x0f));
        }
        return out;
    }

    @Test
    void decodesNetbiosEncodedName() throws Exception {
        final byte[] encoded = encodeNetbiosName("GAMORA", 0x00);
        final Netbios.Name name = Netbios.decode(encoded, 0);
        assertNotNull(name);
        assertEquals("GAMORA", name.name());
        assertEquals(0x00, name.suffix());
        assertEquals("workstation", name.role());
    }

    @Test
    void parsesDhcpDiscoverWithHostNameAndMask() throws Exception {
        final byte[] p = new byte[300];
        p[0] = 1;                       // request
        p[1] = 1;                       // Ethernet
        p[2] = 6;                       // hardware address length
        System.arraycopy(hex("0004f26f9f41"), 0, p, 28, 6);
        System.arraycopy(hex("63825363"), 0, p, 236, 4);
        int off = 240;
        p[off++] = 53; p[off++] = 1; p[off++] = 1;                     // discover
        p[off++] = 12; p[off++] = 4;                                    // host name
        System.arraycopy("lab1".getBytes(StandardCharsets.US_ASCII), 0, p, off, 4);
        off += 4;
        p[off++] = 1; p[off++] = 4;                                     // subnet mask 255.255.254.0
        System.arraycopy(hex("fffffe00"), 0, p, off, 4);
        off += 4;
        p[off] = (byte) 255;                                            // end

        final Dhcp dhcp = Dhcp.parse(p);
        assertNotNull(dhcp);
        assertEquals("discover", dhcp.messageTypeName());
        assertEquals("lab1", dhcp.hostName());
        assertEquals(23, dhcp.prefixLength());
        assertNotNull(dhcp.clientMac());
    }

    /**
     * A parser the caller dispatched to by protocol id or port throws, because the bytes claimed
     * to be that protocol. One that has to recognise itself returns null instead.
     */
    @Test
    void rejectsDataThatIsNotTheProtocol() {
        final byte[] noise = hex("deadbeefcafebabe0011223344556677");
        assertThrows(IllegalRawDataException.class, () -> Bpdu.parse(noise));
        assertThrows(IllegalRawDataException.class, () -> Dtp.parse(new byte[] {0x02}));
        assertThrows(IllegalRawDataException.class, () -> Cdp.parse(noise));
        assertThrows(IllegalRawDataException.class, () -> Vtp.parse(noise));
        assertThrows(IllegalRawDataException.class, () -> Ntp.parse(noise));

        assertNull(Http.parse(noise));
        assertNull(Tls.parse(noise));
        assertNull(Ssdp.parse(noise));
        assertNull(Stun.parse(noise));
    }

    @Test
    void namesTheProtocolAndTheBytesWhenItThrows() {
        final IllegalRawDataException thrown = assertThrows(IllegalRawDataException.class,
                () -> Cdp.parse(hex("deadbeefcafebabe")));
        assertTrue(thrown.getMessage().contains("not CDP"), thrown.getMessage());
        assertTrue(thrown.getMessage().contains("de ad be ef"), thrown.getMessage());
    }

    @Test
    void parsesNtpServerReplyWithUpstream() throws Exception {
        final byte[] p = new byte[48];
        p[0] = 0x24;                    // version 4, mode 4 (server)
        p[1] = 2;                       // stratum 2
        p[2] = 6;                       // poll interval, 64 seconds
        System.arraycopy(hex("c0a80101"), 0, p, 12, 4);   // upstream 192.168.1.1

        final Ntp ntp = Ntp.parse(p);
        assertNotNull(ntp);
        assertEquals("server", ntp.modeName());
        assertEquals(2, ntp.stratum());
        assertEquals("192.168.1.1", ntp.referenceId());
        assertEquals(64, ntp.pollSeconds());
        assertFalse(ntp.isControlOrPrivate());
    }

    @Test
    void namesReferenceClockForStratumOne() throws Exception {
        final byte[] p = new byte[48];
        p[0] = 0x24;
        p[1] = 1;
        System.arraycopy("GPS ".getBytes(StandardCharsets.US_ASCII), 0, p, 12, 4);
        final Ntp ntp = Ntp.parse(p);
        assertNotNull(ntp);
        assertEquals("reference clock", ntp.stratumName());
        assertEquals("GPS", ntp.referenceId());
    }

    @Test
    void readsIgmpV3ReportWithSourceList() throws Exception {
        final Igmp igmp = Igmp.parse(hex(
                "22 00 0000 0000 0001"      // v3 report, one group record
                        + "01 00 0001 e8010101 c6336405"));   // include 232.1.1.1 from 198.51.100.5
        assertNotNull(igmp);
        assertEquals(3, igmp.version());
        assertEquals(1, igmp.records().size());
        assertEquals("232.1.1.1", igmp.records().get(0).group().getHostAddress());
        assertEquals(1, igmp.records().get(0).sources().size());
        assertFalse(igmp.records().get(0).isLeave());
    }

    @Test
    void treatsEmptyIncludeChangeAsLeave() throws Exception {
        final Igmp igmp = Igmp.parse(hex("22 00 0000 0000 0001 03 00 0000 efc00014"));
        assertNotNull(igmp);
        assertTrue(igmp.records().get(0).isLeave());
    }

    @Test
    void findsMldBehindHopByHopHeaderWithPadN() throws Exception {
        // router alert followed by PadN, the padding pcap4j itself gets wrong
        final byte[] hopByHop = hex("3a 00 05 02 0000 0100");
        final byte[] icmp = hex("83 00 0000 0000 0000 ff020000000000000000000000000fb".replace("0fb", "00fb"));
        final byte[] p = new byte[hopByHop.length + icmp.length];
        System.arraycopy(hopByHop, 0, p, 0, hopByHop.length);
        System.arraycopy(icmp, 0, p, hopByHop.length, icmp.length);

        final Mld mld = Mld.parseAfterIpv6(0, p);
        assertNotNull(mld);
        assertEquals(Mld.TYPE_V1_REPORT, mld.type());
        assertEquals(1, mld.version());
        assertNotNull(mld.group());
    }

    @Test
    void readsServerNameFromTlsClientHello() throws Exception {
        final String host = "example.test";
        final byte[] name = host.getBytes(StandardCharsets.US_ASCII);

        final java.io.ByteArrayOutputStream sni = new java.io.ByteArrayOutputStream();
        sni.write(0x00); sni.write(0x00);                                   // server name extension
        sni.write((name.length + 5) >> 8); sni.write((name.length + 5) & 0xff);
        sni.write((name.length + 3) >> 8); sni.write((name.length + 3) & 0xff);
        sni.write(0x00);                                                    // host name type
        sni.write(name.length >> 8); sni.write(name.length & 0xff);
        sni.writeBytes(name);

        final java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
        body.write(0x01);                                                   // client hello
        body.writeBytes(new byte[3]);                                       // length, not checked
        body.write(0x03); body.write(0x03);                                 // version
        body.writeBytes(new byte[32]);                                      // random
        body.write(0x00);                                                   // no session id
        body.write(0x00); body.write(0x02); body.write(0x13); body.write(0x01);   // one cipher suite
        body.write(0x01); body.write(0x00);                                 // one compression method
        body.write(sni.size() >> 8); body.write(sni.size() & 0xff);
        body.writeBytes(sni.toByteArray());

        final Tls tls = Tls.parseHandshake(body.toByteArray());
        assertNotNull(tls);
        assertEquals(host, tls.serverName());
    }
}
