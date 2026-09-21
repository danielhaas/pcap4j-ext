package li.haas.pcap4j.ext;

import org.junit.jupiter.api.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import static li.haas.pcap4j.ext.ParserTest.hex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The dispatcher: hand it a frame, get back whatever the library could read out of it. */
class ProtocolsTest {

    /** An 802.3 frame with an LLC and SNAP header, as the Cisco protocols use. */
    static Packet snapFrame(String sourceMac, int protocolId, byte[] payload) throws Exception {
        final ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.writeBytes(hex("aaaa03"));                      // LLC: SNAP
        body.writeBytes(hex("00000c"));                      // Cisco OUI
        body.write(protocolId >> 8); body.write(protocolId & 0xff);
        body.writeBytes(payload);

        final ByteArrayOutputStream frame = new ByteArrayOutputStream();
        frame.writeBytes(hex("01000ccccccc"));
        frame.writeBytes(hex(sourceMac));
        frame.write(body.size() >> 8); frame.write(body.size() & 0xff);
        frame.writeBytes(body.toByteArray());
        final byte[] raw = frame.toByteArray();
        return EthernetPacket.newPacket(raw, 0, raw.length);
    }

    static Packet etherFrame(int etherType, byte[] payload) throws Exception {
        final ByteArrayOutputStream frame = new ByteArrayOutputStream();
        frame.writeBytes(hex("0180c200000e 0011aabbccdd"));
        frame.write(etherType >> 8); frame.write(etherType & 0xff);
        frame.writeBytes(payload);
        final byte[] raw = frame.toByteArray();
        return EthernetPacket.newPacket(raw, 0, raw.length);
    }

    @Test
    void findsCdpWithoutTheCallerKnowingTheProtocolId() throws Exception {
        final ByteArrayOutputStream cdp = new ByteArrayOutputStream();
        cdp.write(2); cdp.write(180); cdp.write(0); cdp.write(0);
        cdp.writeBytes(CiscoProtocolTest.tlv(1, "sw-core-01".getBytes(StandardCharsets.US_ASCII)));
        cdp.writeBytes(CiscoProtocolTest.tlv(3, "Gi1/0/24".getBytes(StandardCharsets.US_ASCII)));

        final Protocols.Decoded decoded = Protocols.decode(snapFrame("aabbccdd0001", 0x2000, cdp.toByteArray()));
        assertTrue(decoded.rejected().isEmpty(), decoded.rejected().toString());

        final Cdp found = decoded.first(Cdp.class);
        assertNotNull(found);
        assertEquals("sw-core-01", found.deviceId());
        assertEquals("Gi1/0/24", found.portId());
    }

    @Test
    void findsLldpOnItsEtherType() throws Exception {
        final ByteArrayOutputStream lldpdu = new ByteArrayOutputStream();
        lldpdu.writeBytes(LldpTest.tlv(1, LldpTest.prefixed(4, hex("0011aabbccdd"))));
        lldpdu.writeBytes(LldpTest.tlv(2, LldpTest.prefixed(5, "Gi1/0/5".getBytes(StandardCharsets.US_ASCII))));
        lldpdu.writeBytes(LldpTest.tlv(3, hex("0078")));
        lldpdu.writeBytes(LldpTest.tlv(5, "sw-access-02".getBytes(StandardCharsets.US_ASCII)));
        lldpdu.writeBytes(LldpTest.tlv(0, new byte[0]));

        final Protocols.Decoded decoded = Protocols.decode(etherFrame(Lldp.ETHER_TYPE, lldpdu.toByteArray()));
        final Lldp found = decoded.first(Lldp.class);
        assertNotNull(found);
        assertEquals("sw-access-02", found.systemName());
    }

    @Test
    void reportsBytesThatClaimedAProtocolAndDidNotFit() throws Exception {
        final Protocols.Decoded decoded =
                Protocols.decode(snapFrame("aabbccdd0002", 0x2000, hex("deadbeefcafebabe")));
        assertTrue(decoded.isEmpty());
        assertEquals(1, decoded.rejected().size());
        assertTrue(decoded.rejected().get(0).contains("not CDP"), decoded.rejected().toString());
    }

    @Test
    void returnsNothingForATrafficTypeItDoesNotCover() throws Exception {
        final Protocols.Decoded decoded = Protocols.decode(etherFrame(0x0800, new byte[40]));
        assertTrue(decoded.isEmpty());
        assertTrue(decoded.rejected().isEmpty());
        assertNull(decoded.first(Cdp.class));
    }

    @Test
    void decodedListsAreNotTheCallersToChange() throws Exception {
        final Protocols.Decoded decoded = Protocols.decode(etherFrame(0x0800, new byte[40]));
        org.junit.jupiter.api.Assertions.assertThrows(UnsupportedOperationException.class,
                () -> decoded.found().add(null));
    }
}
