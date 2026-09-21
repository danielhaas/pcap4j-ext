package li.haas.pcap4j.ext;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Cisco UniDirectional Link Detection, which pcap4j does not decode.
 * SNAP with OUI 00:00:0c and protocol ID 0x0111, sent to 01:00:0c:cc:cc:cc.
 * Each port announces its own device and port id and echoes back the ids it has heard.
 * Seeing your own id in a neighbour's echo is the proof that the link works in both
 * directions; a fibre pair with one broken strand is exactly what this catches.
 */
import org.pcap4j.packet.IllegalRawDataException;

import java.util.Collections;

import java.util.LinkedHashMap;

import java.util.LinkedHashSet;

import java.util.Map;

import java.util.Set;

public record Udld(int version, int opcode, int flags,
                   String deviceId, String portId, String deviceName,
                   Integer messageInterval, Integer timeoutInterval, Long sequence,
                   List<String> echo) implements Protocol {
    public Udld {
        echo = copy(echo);
    }


    public static final int PROTOCOL_ID = 0x0111;

    public static final int OP_PROBE = 1;
    public static final int OP_ECHO = 2;
    public static final int OP_FLUSH = 3;

    private static final int FLAG_REPLY_TIMER = 0x01;
    private static final int FLAG_RESYNC = 0x02;

    private static final int TLV_DEVICE_ID = 0x0001;
    private static final int TLV_PORT_ID = 0x0002;
    private static final int TLV_ECHO = 0x0003;
    private static final int TLV_MESSAGE_INTERVAL = 0x0004;
    private static final int TLV_TIMEOUT_INTERVAL = 0x0005;
    private static final int TLV_DEVICE_NAME = 0x0006;
    private static final int TLV_SEQUENCE_NUMBER = 0x0007;

    public String opcodeName() {
        return switch (opcode) {
            case OP_PROBE -> "probe";
            case OP_ECHO -> "echo";
            case OP_FLUSH -> "flush";      // the port is going away
            default -> "opcode " + opcode;
        };
    }

    public boolean replyTimerRunning() {
        return (flags & FLAG_REPLY_TIMER) != 0;
    }

    public boolean resynchronising() {
        return (flags & FLAG_RESYNC) != 0;
    }

    /** Nothing echoed back yet: the neighbour has not heard this port, so the link may be one-way. */
    public boolean nothingHeard() {
        return opcode != OP_FLUSH && echo.isEmpty();
    }

    @Override
    public String toString() {
        return "UDLD " + opcodeName()
                + (deviceName == null ? "" : " " + deviceName)
                + (deviceId == null ? "" : " device=" + deviceId)
                + (portId == null ? "" : " port=" + portId)
                + (echo.isEmpty() ? "" : " hears=" + echo)
                + (messageInterval == null ? "" : " every " + messageInterval + "s");
    }

    /**
     * Parses bytes the caller has already identified as UDLD, for example by protocol id or port.
     * Throws rather than returning null: at this point the bytes claim to be this protocol.
     */
    public static Udld parse(byte[] p) throws IllegalRawDataException {
        final Udld parsed = parseOrNull(p);
        if (parsed == null) throw Raw.notA("UDLD", p);
        return parsed;
    }

    /** Returns null if the data is not UDLD. */
    private static Udld parseOrNull(byte[] p) {
        if (p.length < 8) return null;
        final int version = (p[0] & 0xe0) >> 5;
        final int opcode = p[0] & 0x1f;
        if (version != 1 || opcode < OP_PROBE || opcode > OP_FLUSH) return null;
        final int flags = p[1] & 0xff;

        String deviceId = null, portId = null, deviceName = null;
        Integer messageInterval = null, timeout = null;
        Long sequence = null;
        final List<String> echo = new ArrayList<>();

        int off = 4;   // after opcode, flags and checksum
        while (off + 4 <= p.length) {
            final int type = u16(p, off);
            final int len = u16(p, off + 2);        // includes these four bytes
            if (len < 4 || off + len > p.length) break;
            final int v = off + 4;
            final int vlen = len - 4;

            switch (type) {
                case TLV_DEVICE_ID -> deviceId = text(p, v, vlen);
                case TLV_PORT_ID -> portId = text(p, v, vlen);
                case TLV_DEVICE_NAME -> deviceName = text(p, v, vlen);
                case TLV_MESSAGE_INTERVAL -> { if (vlen >= 1) messageInterval = p[v] & 0xff; }
                case TLV_TIMEOUT_INTERVAL -> { if (vlen >= 1) timeout = p[v] & 0xff; }
                case TLV_SEQUENCE_NUMBER -> { if (vlen >= 4) sequence = u32(p, v); }
                case TLV_ECHO -> {
                    // NUL separated device and port ids of every neighbour this port hears
                    int start = v;
                    for (int i = v; i < v + vlen; i++) {
                        if (p[i] == 0) {
                            if (i > start) echo.add(text(p, start, i - start));
                            start = i + 1;
                        }
                    }
                    if (start < v + vlen) echo.add(text(p, start, v + vlen - start));
                }
                default -> { }
            }
            off += len;
        }

        if (deviceId == null && portId == null && opcode != OP_FLUSH) return null;
        return new Udld(version, opcode, flags, deviceId, portId, deviceName,
                messageInterval, timeout, sequence, echo);
    }

    private static String text(byte[] p, int off, int len) {
        int end = Math.min(off + len, p.length);
        while (end > off && p[end - 1] == 0) end--;
        return new String(p, off, Math.max(end - off, 0), StandardCharsets.UTF_8).trim();
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
    }

    private static long u32(byte[] p, int off) {
        return ((long) (p[off] & 0xff) << 24) | ((p[off + 1] & 0xff) << 16)
                | ((p[off + 2] & 0xff) << 8) | (p[off + 3] & 0xff);
    }

    // defensive copies that keep insertion order, which several of these rely on
    private static <T> List<T> copy(List<T> in) {
        return in == null ? List.of() : Collections.unmodifiableList(new ArrayList<>(in));
    }

    private static <T> Set<T> copy(Set<T> in) {
        return in == null ? Set.of() : Collections.unmodifiableSet(new LinkedHashSet<>(in));
    }

    private static <K, V> Map<K, V> copy(Map<K, V> in) {
        return in == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(in));
    }

}
