package li.haas.pcap4j.ext;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import static li.haas.pcap4j.ext.ParserTest.hex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Port authentication, gateway load balancing, routing, management and timing. */
class InfrastructureTest {

    static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    @Test
    void readsTheSupplicantIdentityFrom8021x() throws Exception {
        // EAPOL version 2, EAP response, identity
        final byte[] identity = ascii("host/lab-pc-07");
        final ByteArrayOutputStream p = new ByteArrayOutputStream();
        p.write(2); p.write(Eapol.TYPE_EAP);
        p.write(0); p.write(5 + identity.length);
        p.write(2); p.write(1);                                   // response, id 1
        p.write(0); p.write(5 + identity.length);
        p.write(1);                                               // type: identity
        p.writeBytes(identity);

        final Eapol eapol = Eapol.parse(p.toByteArray());
        assertNotNull(eapol);
        assertEquals("eap", eapol.packetTypeName());
        assertEquals("response", eapol.eapCodeName());
        assertEquals("identity", eapol.methodName());
        assertEquals("host/lab-pc-07", eapol.identity());
        assertFalse(eapol.authenticated());
    }

    @Test
    void recognisesSuccessFailureAndWeakMethods() throws Exception {
        final Eapol success = Eapol.parse(hex("02 00 0004 03 02 0004"));
        assertTrue(success.authenticated());

        final Eapol failure = Eapol.parse(hex("02 00 0004 04 02 0004"));
        assertTrue(failure.rejected());

        // MD5 challenge: no TLS around the credential
        final Eapol md5 = Eapol.parse(hex("02 00 0016 01 02 0016 04 10" + "00".repeat(16)));
        assertEquals("md5 challenge", md5.methodName());
        assertTrue(md5.weakMethod());

        final Eapol start = Eapol.parse(hex("02 01 0000"));
        assertEquals("start", start.packetTypeName());
        assertNull(start.identity());
    }

    @Test
    void parsesGlbpHelloWithForwarderAndPassword() throws Exception {
        final ByteArrayOutputStream hello = new ByteArrayOutputStream();
        hello.writeBytes(hex("00 20 00 96 0000"));                // state active, priority 150
        hello.writeBytes(hex("00000bb8 00002710"));               // hello 3s, hold 10s, in milliseconds
        hello.writeBytes(hex("0258 3840 0000"));                  // redirect, timeout, unknown
        hello.writeBytes(hex("01 04 0a001e01"));                  // IPv4, 10.0.30.1

        final ByteArrayOutputStream forwarder = new ByteArrayOutputStream();
        forwarder.writeBytes(hex("01 20 00 87 01"));              // forwarder 1, active, priority 135
        forwarder.writeBytes(new byte[7]);
        forwarder.writeBytes(hex("0007b4000701"));                // the virtual MAC it owns
        forwarder.writeBytes(new byte[2]);

        final ByteArrayOutputStream p = new ByteArrayOutputStream();
        p.writeBytes(hex("01 00 0007 0000"));                     // version, group 7
        p.writeBytes(hex("000000aa0001"));                        // owner id
        p.write(1); p.write(hello.size() + 2); p.writeBytes(hello.toByteArray());
        p.write(2); p.write(forwarder.size() + 2); p.writeBytes(forwarder.toByteArray());
        p.write(3); p.write(12); p.write(1); p.write(8); p.writeBytes(ascii("glbppass"));

        final Glbp glbp = Glbp.parse(p.toByteArray());
        assertNotNull(glbp);
        assertEquals(7, glbp.group());
        assertTrue(glbp.isActiveGateway());
        assertEquals(150, glbp.gatewayPriority());
        assertEquals("10.0.30.1", glbp.virtualAddress().getHostAddress());
        assertEquals(3000, glbp.helloMillis());
        assertEquals(1, glbp.forwarders().size());
        assertEquals("00:07:b4:00:07:01", glbp.forwarders().get(0).virtualMac().toString());
        assertEquals("glbppass", glbp.authentication());
        assertTrue(glbp.usesPlainTextAuthentication());
    }

    @Test
    void mapsNeighboursFromAnOspfHello() throws Exception {
        final ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.writeBytes(hex("ffffff00"));                         // network mask
        body.writeBytes(hex("000a 02 01"));                       // hello 10s, options, priority 1
        body.writeBytes(hex("00000028"));                         // dead 40s
        body.writeBytes(hex("0a002801 0a002802"));                // designated and backup
        body.writeBytes(hex("0a002802 0a002803"));                // two neighbours

        final ByteArrayOutputStream p = new ByteArrayOutputStream();
        p.write(2); p.write(1);
        p.write(0); p.write(24 + body.size());
        p.writeBytes(hex("0a002801 00000000"));                   // router id, area 0
        p.writeBytes(hex("0000 0001"));                           // checksum, simple auth
        p.writeBytes(ascii("ospfpass"));
        p.writeBytes(body.toByteArray());

        final Ospf ospf = Ospf.parse(p.toByteArray());
        assertNotNull(ospf);
        assertTrue(ospf.isHello());
        assertEquals("10.0.40.1", ospf.routerId().getHostAddress());
        assertEquals("0.0.0.0", ospf.areaId().getHostAddress());
        assertEquals(10, ospf.helloInterval());
        assertEquals(40, ospf.deadInterval());
        assertEquals(1, ospf.priority());
        assertEquals("simple text", ospf.authTypeName());
        assertEquals("ospfpass", ospf.authentication());
        assertEquals(2, ospf.neighbours().size());
        assertFalse(ospf.alone());
    }

    /** BER, as little of it as an SNMP message needs. */
    static byte[] ber(int tag, byte[] value) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        out.write(value.length);
        out.writeBytes(value);
        return out.toByteArray();
    }

    @Test
    void readsCommunityAndBindingsFromSnmp() throws Exception {
        final byte[] oid = ber(0x06, hex("2b 06 01 02 01 01 05 00"));       // 1.3.6.1.2.1.1.5.0
        final byte[] binding = ber(0x30, concat(oid, ber(0x04, ascii("sw-core-01"))));
        final byte[] pdu = ber(0xa2, concat(ber(0x02, hex("3039")),          // request id 12345
                ber(0x02, new byte[] {0}), ber(0x02, new byte[] {0}), ber(0x30, binding)));
        final byte[] message = ber(0x30, concat(ber(0x02, new byte[] {1}),   // v2c
                ber(0x04, ascii("public")), pdu));

        final Snmp snmp = Snmp.parse(message);
        assertNotNull(snmp);
        assertEquals("v2c", snmp.versionName());
        assertEquals("public", snmp.community());
        assertTrue(snmp.usesDefaultCommunity());
        assertEquals("response", snmp.operation());
        assertEquals(12345L, snmp.requestId());
        assertEquals(1, snmp.bindings().size());
        assertEquals("1.3.6.1.2.1.1.5.0", snmp.bindings().get(0).oid());
        assertEquals("sw-core-01", snmp.bindings().get(0).value());
        assertFalse(snmp.isWrite());
    }

    @Test
    void flagsAnSnmpWrite() throws Exception {
        final byte[] oid = ber(0x06, hex("2b 06 01 02 01 01 06 00"));
        final byte[] binding = ber(0x30, concat(oid, ber(0x04, ascii("rack 4"))));
        final byte[] pdu = ber(0xa3, concat(ber(0x02, hex("3039")),
                ber(0x02, new byte[] {0}), ber(0x02, new byte[] {0}), ber(0x30, binding)));
        final Snmp snmp = Snmp.parse(ber(0x30, concat(ber(0x02, new byte[] {1}),
                ber(0x04, ascii("private")), pdu)));
        assertTrue(snmp.isWrite());
        assertTrue(snmp.usesDefaultCommunity());
    }

    @Test
    void parsesBothSyslogFormats() {
        final Syslog old = Syslog.parse(ascii(
                "<134>Sep 21 10:45:00 sw-core-01 %LINK-3-UPDOWN: Interface Gi1/0/5, changed state to down"));
        assertNotNull(old);
        assertEquals("local0", old.facilityName());
        assertEquals("info", old.severityName());
        assertEquals("sw-core-01", old.hostname());
        assertFalse(old.isSerious());

        final Syslog modern = Syslog.parse(ascii(
                "<27>1 2026-09-21T10:46:00Z fw-edge-01 sshd 1234 ID47 - Failed password for root"));
        assertNotNull(modern);
        assertTrue(modern.structured());
        assertEquals("daemon", modern.facilityName());
        assertEquals("error", modern.severityName());
        assertEquals("fw-edge-01", modern.hostname());
        assertEquals("sshd", modern.tag());
        assertTrue(modern.isSerious());

        assertNull(Syslog.parse(ascii("no priority here")));
    }

    @Test
    void namesTheFileInATftpRequest() {
        final ByteArrayOutputStream read = new ByteArrayOutputStream();
        read.write(0); read.write(1);
        read.writeBytes(ascii("switch-config.cfg")); read.write(0);
        read.writeBytes(ascii("octet")); read.write(0);

        final Tftp tftp = Tftp.parse(read.toByteArray());
        assertNotNull(tftp);
        assertEquals("read", tftp.opcodeName());
        assertEquals("switch-config.cfg", tftp.filename());
        assertEquals("octet", tftp.mode());
        assertTrue(tftp.isTransferRequest());

        final ByteArrayOutputStream error = new ByteArrayOutputStream();
        error.write(0); error.write(5); error.write(0); error.write(1);
        error.writeBytes(ascii("File not found")); error.write(0);
        final Tftp failed = Tftp.parse(error.toByteArray());
        assertEquals(1, failed.errorCode());
        assertEquals("File not found", failed.errorMessage());
    }

    @Test
    void readsTheGrandmasterFromAPtpAnnounce() {
        final ByteArrayOutputStream p = new ByteArrayOutputStream();
        p.write(0x0b); p.write(0x02); p.write(0); p.write(64);    // announce, version 2, length
        p.write(0); p.write(0); p.write(0); p.write(0);           // domain, reserved, flags
        p.writeBytes(new byte[8]);                                 // correction
        p.writeBytes(new byte[4]);                                 // reserved
        p.writeBytes(hex("0011aafffebbcc00"));                     // clock identity
        p.writeBytes(hex("0001 0001"));                            // source port, sequence
        p.writeBytes(hex("00 7f"));                                // control, log interval
        p.writeBytes(new byte[10]);                                // origin timestamp
        p.writeBytes(hex("0025"));                                 // utc offset
        p.write(0);                                                // reserved
        p.write(128);                                              // priority1
        p.writeBytes(hex("06 21 436a"));                           // class 6, accuracy, variance
        p.write(128);                                              // priority2
        p.writeBytes(hex("0011aafffebbcc00"));                     // grandmaster identity
        p.writeBytes(hex("0000"));                                 // steps removed
        p.write(0x20);                                             // time source: GPS

        final Ptp ptp = Ptp.parse(p.toByteArray());
        assertNotNull(ptp);
        assertTrue(ptp.isAnnounce());
        assertEquals("00:11:aa:ff:fe:bb:cc:00", ptp.sourceClockId());
        assertEquals(128, ptp.priority1());
        assertEquals("primary reference, locked", ptp.clockClassName());
        assertEquals("gps", ptp.timeSourceName());
    }

    @Test
    void readsDeviceIdentityFromWsDiscovery() {
        final String hello = "<?xml version=\"1.0\"?>"
                + "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\">"
                + "<soap:Header>"
                + "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello</wsa:Action>"
                + "</soap:Header><soap:Body><wsd:Hello>"
                + "<wsa:EndpointReference><wsa:Address>urn:uuid:aabbccdd-1111-2222-3333-444455556666"
                + "</wsa:Address></wsa:EndpointReference>"
                + "<wsd:Types>wsdp:Device pub:Computer</wsd:Types>"
                + "<wsd:XAddrs>http://10.0.60.5:5357/aabbccdd/</wsd:XAddrs>"
                + "</wsd:Hello></soap:Body></soap:Envelope>";

        final WsDiscovery wsd = WsDiscovery.parse(ascii(hello));
        assertNotNull(wsd);
        assertEquals("Hello", wsd.actionName());
        assertEquals("aabbccdd-1111-2222-3333-444455556666", wsd.uuid());
        assertEquals(2, wsd.types().size());
        assertEquals("http://10.0.60.5:5357/aabbccdd/", wsd.transportAddresses().get(0));
        assertFalse(wsd.isLeaving());

        // an ordinary SOAP message that is not discovery must not be taken for one
        assertNull(WsDiscovery.parse(ascii("<soap:Envelope><soap:Body/></soap:Envelope>")));
    }

    static byte[] concat(byte[]... parts) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) out.writeBytes(part);
        return out.toByteArray();
    }
}
