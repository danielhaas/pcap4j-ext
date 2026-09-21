package li.haas.pcap4j.ext;

import org.junit.jupiter.api.Test;
import org.pcap4j.packet.IllegalRawDataException;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import static li.haas.pcap4j.ext.ParserTest.hex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Link aggregation and gateway redundancy: LACP, the marker protocol, HSRP and VRRP. */
class RedundancyTest {

    private static final int STATE_BUNDLED = 0x3d;   // active, aggregatable, sync, collecting, distributing

    static byte[] lacpEndpoint(String mac, int key, int port, int state) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(hex("8000"));                 // system priority
        out.writeBytes(hex(mac));
        out.write(key >> 8); out.write(key & 0xff);
        out.writeBytes(hex("8000"));                 // port priority
        out.write(port >> 8); out.write(port & 0xff);
        out.write(state);
        out.writeBytes(new byte[3]);                 // reserved
        return out.toByteArray();
    }

    @Test
    void parsesLacpWithBothEndsBundled() throws Exception {
        final ByteArrayOutputStream p = new ByteArrayOutputStream();
        p.write(Lacp.SUBTYPE_LACP); p.write(1);
        p.write(1); p.write(20); p.writeBytes(lacpEndpoint("0011aabbcc00", 10, 1, STATE_BUNDLED));
        p.write(2); p.write(20); p.writeBytes(lacpEndpoint("00aabbcc1100", 5, 101, STATE_BUNDLED));
        p.write(3); p.write(16); p.writeBytes(new byte[14]);
        p.write(0); p.write(0);

        final Lacp lacp = Lacp.parse(p.toByteArray());
        assertNotNull(lacp);
        assertEquals(10, lacp.actor().key());
        assertEquals(101, lacp.partner().port());
        assertTrue(lacp.actor().bundled());
        assertTrue(lacp.bundleUp());
        assertFalse(lacp.partnerMissing());
        assertTrue(lacp.actor().stateNames().contains("distributing"));
    }

    @Test
    void detectsLacpPartnerThatNeverAnswers() throws Exception {
        final ByteArrayOutputStream p = new ByteArrayOutputStream();
        p.write(Lacp.SUBTYPE_LACP); p.write(1);
        p.write(1); p.write(20); p.writeBytes(lacpEndpoint("0011aabbcc00", 10, 3, 0x05));
        p.write(2); p.write(20); p.writeBytes(lacpEndpoint("000000000000", 0, 0, 0x45));  // defaulted
        p.write(0); p.write(0);

        final Lacp lacp = Lacp.parse(p.toByteArray());
        assertNotNull(lacp);
        assertTrue(lacp.partner().defaulted());
        assertTrue(lacp.partnerMissing());
        assertFalse(lacp.bundleUp());
    }

    @Test
    void parsesMarkerRequestAndResponse() throws Exception {
        // real marker PDUs are padded out to the minimum frame size
        final byte[] request = hex("02 01 01 10 0001 0011aabbcc00 00001b59 0000" + "00".repeat(90));
        final Marker marker = Marker.parse(request);
        assertNotNull(marker);
        assertTrue(marker.isRequest());
        assertEquals(1, marker.requesterPort());
        assertEquals(7001L, marker.transactionId());

        final byte[] response = hex("02 01 02 10 0001 0011aabbcc00 00001b59 0000" + "00".repeat(90));
        final Marker answer = Marker.parse(response);
        assertNotNull(answer);
        assertFalse(answer.isRequest());
        // both halves of one exchange share an id, which is how they are matched
        assertEquals(marker.exchangeId(), answer.exchangeId());
    }

    @Test
    void doesNotReadLacpAsMarker() throws Exception {
        final byte[] lacpdu = hex("01 01 01 14" + "00".repeat(40));
        assertThrows(IllegalRawDataException.class, () -> Marker.parse(lacpdu));
    }

    @Test
    void parsesHsrpVersionOneWithDefaultPassword() throws Exception {
        // version 0, hello, active (16), hello 3s, hold 10s, priority 110, group 1
        final byte[] p = hex("00 00 10 03 0a 6e 01 00 " + hexText("cisco", 8) + " c0a81101");
        final Hsrp hsrp = Hsrp.parse(p);
        assertNotNull(hsrp);
        assertEquals(1, hsrp.version());
        assertEquals("active", hsrp.stateName());
        assertTrue(hsrp.isActive());
        assertEquals(110, hsrp.priority());
        assertEquals(1, hsrp.group());
        assertEquals("192.168.17.1", hsrp.virtualAddress().getHostAddress());
        assertTrue(hsrp.usesDefaultPassword());
    }

    @Test
    void parsesHsrpVersionTwoWithTextAuthentication() throws Exception {
        final ByteArrayOutputStream p = new ByteArrayOutputStream();
        // group state TLV: type 1, length 40
        p.write(1); p.write(40);
        p.write(2); p.write(0); p.write(5); p.write(4);          // version, hello, active, IPv4
        p.writeBytes(hex("0014"));                                // group 20
        p.writeBytes(hex("000000000aa1"));                        // identifier
        p.writeBytes(hex("00000078"));                            // priority 120
        p.writeBytes(hex("00000bb8 00002710"));                   // hello 3s, hold 10s, in milliseconds
        final byte[] virtualAddress = new byte[16];
        System.arraycopy(hex("0a001401"), 0, virtualAddress, 0, 4);
        p.writeBytes(virtualAddress);
        p.write(3); p.write(8); p.writeBytes(hex(hexText("secret42", 8)));

        final Hsrp hsrp = Hsrp.parse(p.toByteArray());
        assertNotNull(hsrp);
        assertEquals(2, hsrp.version());
        assertEquals("active", hsrp.stateName());
        assertEquals(120, hsrp.priority());
        assertEquals(20, hsrp.group());
        assertEquals("10.0.20.1", hsrp.virtualAddress().getHostAddress());
        assertEquals("secret42", hsrp.authentication());
        assertFalse(hsrp.usesDefaultPassword());
        assertEquals(3, hsrp.helloSeconds());
    }

    @Test
    void parsesVrrpVersionTwoWithPassword() throws Exception {
        // version 2 type 1, vrid 10, priority 150, one address, simple text auth, interval 1s
        final byte[] p = hex("21 0a 96 01 01 01 0000 0a010001 " + hexText("vrrppass", 8));
        final Vrrp vrrp = Vrrp.parse(p, false);
        assertNotNull(vrrp);
        assertEquals(2, vrrp.version());
        assertEquals(10, vrrp.virtualRouterId());
        assertEquals(150, vrrp.priority());
        assertEquals("simple text", vrrp.authTypeName());
        assertEquals("vrrppass", vrrp.authentication());
        assertEquals(1.0, vrrp.advertIntervalSeconds());
        assertFalse(vrrp.isOwner());
        assertFalse(vrrp.isResigning());
    }

    @Test
    void recognisesVrrpOwnerAndResignation() throws Exception {
        final Vrrp owner = Vrrp.parse(hex("31 05 ff 01 0064 0000 0a020001"), false);
        assertNotNull(owner);
        assertEquals(3, owner.version());
        assertTrue(owner.isOwner());
        assertEquals(1.0, owner.advertIntervalSeconds());   // version 3 counts in centiseconds

        final Vrrp resigning = Vrrp.parse(hex("21 0a 00 01 00 01 0000 0a010001"), false);
        assertNotNull(resigning);
        assertTrue(resigning.isResigning());
    }

    @Test
    void parsesVrrpOverIpv6() throws Exception {
        final byte[] p = hex("31 07 78 01 0064 0000 20010db8000000000000000000000001");
        final Vrrp vrrp = Vrrp.parse(p, true);
        assertNotNull(vrrp);
        assertEquals(7, vrrp.virtualRouterId());
        assertEquals(1, vrrp.virtualAddresses().size());
        assertTrue(vrrp.virtualAddresses().get(0).getHostAddress().startsWith("2001:db8"));
    }

    /** ASCII as hex, padded with zero bytes to the given width. */
    static String hexText(String s, int width) {
        final StringBuilder sb = new StringBuilder();
        final byte[] raw = s.getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < width; i++) {
            sb.append(String.format("%02x", i < raw.length ? raw[i] : 0));
        }
        return sb.toString();
    }
}
