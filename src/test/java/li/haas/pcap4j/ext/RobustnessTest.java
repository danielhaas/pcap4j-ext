package li.haas.pcap4j.ext;

import org.junit.jupiter.api.Test;
import org.pcap4j.packet.IllegalRawDataException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * A parser may reject bytes, by throwing IllegalRawDataException or returning null, and it may
 * accept them. It may not fall over. These tests feed every parser truncated, extended and
 * random input and insist that nothing else escapes.
 */
class RobustnessTest {

    /** Each entry runs one parser over the bytes it is given. */
    private static Map<String, Consumer<byte[]>> parsers() {
        final Map<String, Consumer<byte[]>> out = new LinkedHashMap<>();
        out.put("Bpdu", p -> swallow(() -> Bpdu.parse(p)));
        out.put("Cdp", p -> swallow(() -> Cdp.parse(p)));
        out.put("Cgmp", p -> swallow(() -> Cgmp.parse(p)));
        out.put("Dhcp", p -> swallow(() -> Dhcp.parse(p)));
        out.put("DhcpV6", p -> swallow(() -> DhcpV6.parse(p)));
        out.put("Dtp", p -> swallow(() -> Dtp.parse(p)));
        out.put("Eapol", p -> swallow(() -> Eapol.parse(p)));
        out.put("Glbp", p -> swallow(() -> Glbp.parse(p)));
        out.put("Hsrp", p -> swallow(() -> Hsrp.parse(p)));
        out.put("Http", p -> Http.parse(p));
        out.put("Igmp", p -> swallow(() -> Igmp.parse(p)));
        out.put("Lacp", p -> swallow(() -> Lacp.parse(p)));
        out.put("Lldp", p -> swallow(() -> Lldp.parse(p)));
        out.put("Marker", p -> swallow(() -> Marker.parse(p)));
        out.put("Mld", p -> swallow(() -> Mld.parse(130, p)));
        out.put("Mld.afterIpv6", p -> Mld.parseAfterIpv6(0, p));
        out.put("NatPmp", p -> swallow(() -> NatPmp.parse(p)));
        out.put("Nbds", p -> swallow(() -> Nbds.parse(p)));
        out.put("Nbns", p -> swallow(() -> Nbns.parse(p)));
        out.put("Netbios.parseName", p -> Netbios.parseName(p, 0));
        out.put("Ntp", p -> swallow(() -> Ntp.parse(p)));
        out.put("Ospf", p -> swallow(() -> Ospf.parse(p)));
        out.put("Pagp", p -> swallow(() -> Pagp.parse(p)));
        out.put("Pagp.flush", p -> swallow(() -> Pagp.parseFlush(p)));
        out.put("Pcp", p -> swallow(() -> Pcp.parse(p)));
        out.put("Ptp", p -> Ptp.parse(p));
        out.put("Quic", p -> Quic.parse(p));
        out.put("Snmp", p -> swallow(() -> Snmp.parse(p)));
        out.put("Ssdp", p -> Ssdp.parse(p));
        out.put("Stun", p -> Stun.parse(p));
        out.put("Syslog", p -> Syslog.parse(p));
        out.put("Tftp", p -> Tftp.parse(p));
        out.put("Tls", p -> Tls.parse(p));
        out.put("Tls.handshake", p -> Tls.parseHandshake(p));
        out.put("Udld", p -> swallow(() -> Udld.parse(p)));
        out.put("Vrrp", p -> swallow(() -> Vrrp.parse(p, false)));
        out.put("Vrrp.v6", p -> swallow(() -> Vrrp.parse(p, true)));
        out.put("Vtp", p -> swallow(() -> Vtp.parse(p)));
        out.put("WsDiscovery", p -> WsDiscovery.parse(p));
        return out;
    }

    /** A rejection is a valid outcome, so the expected exception is not a failure here. */
    private static void swallow(ThrowingCall call) {
        try {
            call.run();
        } catch (IllegalRawDataException expected) {
            // saying no is allowed
        }
    }

    private interface ThrowingCall {
        void run() throws IllegalRawDataException;
    }

    /** Valid messages, from the other tests, that the truncation runs start from. */
    private static List<byte[]> samples() throws Exception {
        final List<byte[]> out = new ArrayList<>();
        out.add(ParserTest.hex("0000 00 00 00 8000 001122334455 00000004 8000 001122334455 8001 0100 1400 0200 0f00"));
        out.add(ParserTest.hex("01 0001 000f 484f4e474b4f4e474443 00 0002 0005 04 0003 0005 40 0004 000a 7c69f673868a"));
        out.add(ParserTest.hex("10 0000 02 01005e0a0b0c aabbccddee01 01005e0a0b0d aabbccddee02"));
        out.add(ParserTest.hex("22 00 0000 0000 0001 01 00 0001 e8010101 c6336405"));
        out.add(ParserTest.hex("00 80 0000 000004d2 cb00710f"));
        out.add(ParserTest.hex("21 0a 96 01 01 01 0000 0a010001 76727270706173730000000000000000"));
        out.add(ParserTest.hex("02 01 01 10 0001 0011aabbcc00 00001b59 0000" + "00".repeat(90)));
        out.add(ParserTest.encodeNetbiosName("GAMORA", 0x00));
        out.add(DiscoveryTest.clientHello("example.test"));
        out.add("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        out.add("<134>Sep 21 10:45:00 host tag: message".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        final byte[] ntp = new byte[48];
        ntp[0] = 0x24;
        ntp[1] = 2;
        out.add(ntp);
        return out;
    }

    @Test
    void survivesEveryTruncationOfAValidMessage() throws Exception {
        final Map<String, Consumer<byte[]>> parsers = parsers();
        int runs = 0;
        for (byte[] sample : samples()) {
            for (int length = 0; length <= sample.length; length++) {
                final byte[] cut = Arrays.copyOfRange(sample, 0, length);
                for (Map.Entry<String, Consumer<byte[]>> parser : parsers.entrySet()) {
                    runs++;
                    try {
                        parser.getValue().accept(cut);
                    } catch (RuntimeException e) {
                        fail(parser.getKey() + " threw " + e + " on " + length
                                + " bytes of a " + sample.length + " byte message");
                    }
                }
            }
        }
        assertTrue(runs > 10000, "expected a decent number of runs, got " + runs);
    }

    @Test
    void survivesRandomInput() {
        final Map<String, Consumer<byte[]>> parsers = parsers();
        final Random random = new Random(20260921);       // fixed, so a failure can be repeated
        for (int i = 0; i < 400; i++) {
            final byte[] noise = new byte[random.nextInt(600)];
            random.nextBytes(noise);
            for (Map.Entry<String, Consumer<byte[]>> parser : parsers.entrySet()) {
                try {
                    parser.getValue().accept(noise);
                } catch (RuntimeException e) {
                    fail(parser.getKey() + " threw " + e + " on " + noise.length + " random bytes: "
                            + java.util.HexFormat.of().formatHex(noise, 0, Math.min(noise.length, 32)));
                }
            }
        }
    }

    @Test
    void survivesTrailingRubbish() throws Exception {
        final Map<String, Consumer<byte[]>> parsers = parsers();
        final Random random = new Random(7);
        for (byte[] sample : samples()) {
            final byte[] extended = Arrays.copyOf(sample, sample.length + 64);
            random.nextBytes(Arrays.copyOfRange(extended, sample.length, extended.length));
            for (Map.Entry<String, Consumer<byte[]>> parser : parsers.entrySet()) {
                try {
                    parser.getValue().accept(extended);
                } catch (RuntimeException e) {
                    fail(parser.getKey() + " threw " + e + " on a message with 64 bytes appended");
                }
            }
        }
    }
}
