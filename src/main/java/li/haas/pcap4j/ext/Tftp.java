package li.haas.pcap4j.ext;

import java.nio.charset.StandardCharsets;

/**
 * TFTP (RFC 1350), UDP 69, which pcap4j does not decode.
 * Switches and phones fetch their configuration and firmware with it, unauthenticated and in
 * clear text, so a read request names a file worth knowing about and often the device asking.
 */
public record Tftp(int opcode, String filename, String mode, Integer errorCode, String errorMessage)
        implements Protocol {

    public static final int PORT = 69;

    public static final int OP_READ = 1;
    public static final int OP_WRITE = 2;
    public static final int OP_DATA = 3;
    public static final int OP_ACK = 4;
    public static final int OP_ERROR = 5;

    public String opcodeName() {
        return switch (opcode) {
            case OP_READ -> "read";
            case OP_WRITE -> "write";
            case OP_DATA -> "data";
            case OP_ACK -> "ack";
            case OP_ERROR -> "error";
            default -> "opcode " + opcode;
        };
    }

    /** A write means something is being uploaded to the server, such as a configuration backup. */
    public boolean isTransferRequest() {
        return opcode == OP_READ || opcode == OP_WRITE;
    }

    @Override
    public String toString() {
        return "TFTP " + opcodeName()
                + (filename == null ? "" : " " + filename)
                + (mode == null ? "" : " (" + mode + ")")
                + (errorMessage == null ? "" : " error " + errorCode + ": " + errorMessage);
    }

    /** Returns null if the data is not TFTP. */
    public static Tftp parse(byte[] p) {
        if (p.length < 4) return null;
        final int opcode = ((p[0] & 0xff) << 8) | (p[1] & 0xff);
        if (opcode < OP_READ || opcode > OP_ERROR) return null;

        if (opcode == OP_READ || opcode == OP_WRITE) {
            final int nameEnd = indexOfZero(p, 2);
            if (nameEnd < 0) return null;
            final String filename = new String(p, 2, nameEnd - 2, StandardCharsets.UTF_8);
            final int modeEnd = indexOfZero(p, nameEnd + 1);
            final String mode = modeEnd < 0 ? null
                    : new String(p, nameEnd + 1, modeEnd - nameEnd - 1, StandardCharsets.UTF_8);
            if (filename.isEmpty()) return null;
            return new Tftp(opcode, filename, mode, null, null);
        }

        if (opcode == OP_ERROR) {
            final int code = ((p[2] & 0xff) << 8) | (p[3] & 0xff);
            final int end = indexOfZero(p, 4);
            final String message = end < 0 ? null : new String(p, 4, end - 4, StandardCharsets.UTF_8);
            return new Tftp(opcode, null, null, code, message);
        }

        // data and ack carry only a block number, which says nothing about the device
        return new Tftp(opcode, null, null, null, null);
    }

    private static int indexOfZero(byte[] p, int from) {
        for (int i = from; i < p.length; i++) {
            if (p[i] == 0) return i;
        }
        return -1;
    }
}
