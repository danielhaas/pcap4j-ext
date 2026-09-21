package li.haas.pcap4j.ext;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import static li.haas.pcap4j.ext.ParserTest.hex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** LLDP, whose TLVs pack a 7 bit type and a 9 bit length into two bytes. */
class LldpTest {

    static byte[] tlv(int type, byte[] value) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final int header = (type << 9) | value.length;
        out.write(header >> 8);
        out.write(header & 0xff);
        out.writeBytes(value);
        return out.toByteArray();
    }

    static byte[] organisational(String oui, int subtype, byte[] value) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(hex(oui));
        out.write(subtype);
        out.writeBytes(value);
        return tlv(127, out.toByteArray());
    }

    static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    static byte[] prefixed(int first, byte[] rest) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(first);
        out.writeBytes(rest);
        return out.toByteArray();
    }

    @Test
    void parsesFullLldpdu() {
        final ByteArrayOutputStream p = new ByteArrayOutputStream();
        p.writeBytes(tlv(1, prefixed(4, hex("0011aabbccdd"))));           // chassis id, subtype MAC
        p.writeBytes(tlv(2, prefixed(5, ascii("GigabitEthernet1/0/5")))); // port id, interface name
        p.writeBytes(tlv(3, hex("0078")));                                 // ttl 120
        p.writeBytes(tlv(4, ascii("Uplink to floor 3")));
        p.writeBytes(tlv(5, ascii("sw-access-02")));
        p.writeBytes(tlv(6, ascii("Aruba JL258A 2930F, revision WC.16.10.0023\nsecond line")));
        p.writeBytes(tlv(7, hex("0014 0004")));                            // bridge+router, only bridge enabled
        // management address: length, subtype, address, interface numbering, interface, OID length
        p.writeBytes(tlv(8, hex("05 01 0a010107 02 00000003 00")));
        p.writeBytes(organisational("0080c2", 1, hex("0014")));            // port VLAN id 20
        p.writeBytes(tlv(0, new byte[0]));

        final Lldp lldp = Lldp.parse(p.toByteArray());
        assertNotNull(lldp);
        assertEquals("00:11:aa:bb:cc:dd", lldp.chassisId());
        assertEquals("GigabitEthernet1/0/5", lldp.portId());
        assertEquals(120, lldp.ttl());
        assertEquals("sw-access-02", lldp.systemName());
        assertEquals("Uplink to floor 3", lldp.portDescription());
        assertEquals("Aruba JL258A 2930F, revision WC.16.10.0023", lldp.softwareSummary());
        assertEquals(20, lldp.portVlanId());
        assertEquals("10.1.1.7", lldp.managementAddresses().get(0).getHostAddress());
        // capabilities are reported as enabled, not as supported
        assertTrue(lldp.capabilityNames().contains("bridge"));
        assertEquals(1, lldp.capabilityNames().size());
    }

    @Test
    void readsVlanNameAndMedInventory() {
        final ByteArrayOutputStream vlanName = new ByteArrayOutputStream();
        vlanName.writeBytes(hex("0014"));            // vlan 20
        vlanName.write(5);                            // name length
        vlanName.writeBytes(ascii("VOICE"));

        final ByteArrayOutputStream p = new ByteArrayOutputStream();
        p.writeBytes(tlv(1, prefixed(4, hex("0011aabbccdd"))));
        p.writeBytes(tlv(2, prefixed(5, ascii("1/1/1"))));
        p.writeBytes(tlv(3, hex("0078")));
        p.writeBytes(organisational("0080c2", 3, vlanName.toByteArray()));
        p.writeBytes(organisational("00120f", 4, hex("05f2")));            // max frame size 1522
        // MED network policy: application type 1 (voice), vlan 20, priority 5, dscp 46
        p.writeBytes(organisational("0012bb", 2, hex("01 00 29 6e")));
        p.writeBytes(organisational("0012bb", 8, ascii("SG92KX1234")));    // serial number
        p.writeBytes(organisational("0012bb", 9, ascii("Aruba")));
        p.writeBytes(organisational("0012bb", 10, ascii("JL258A")));
        p.writeBytes(tlv(0, new byte[0]));

        final Lldp lldp = Lldp.parse(p.toByteArray());
        assertNotNull(lldp);
        assertEquals("VOICE", lldp.vlanNames().get(20));
        assertEquals(1522, lldp.maxFrameSize());
        assertEquals(20, lldp.voiceVlan());
        assertEquals("SG92KX1234", lldp.inventory().get("serial"));
        assertEquals("Aruba", lldp.inventory().get("manufacturer"));
        assertEquals("JL258A", lldp.inventory().get("model"));
    }

    @Test
    void requiresTheMandatoryTlvs() {
        // a chassis id on its own is not an LLDPDU: the TTL is mandatory too
        final byte[] withoutTtl = tlv(1, prefixed(4, hex("0011aabbccdd")));
        assertNull(Lldp.parse(withoutTtl));
        assertNull(Lldp.parse(hex("deadbeefcafebabe")));
    }
}
