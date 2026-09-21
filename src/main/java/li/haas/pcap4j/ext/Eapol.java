package li.haas.pcap4j.ext;

import java.nio.charset.StandardCharsets;

/**
 * 802.1X port authentication (IEEE 802.1X, EAP per RFC 3748), which pcap4j does not decode.
 * EtherType 0x888e, usually to 01:80:c2:00:00:03. The supplicant's identity travels in clear
 * text in the first EAP response, so a capture shows who authenticates on which port, with what
 * method, and whether it worked.
 */
public record Eapol(int version, int packetType, Integer eapCode, Integer eapId, Integer eapType,
                    String identity) implements Protocol {

    public static final int ETHER_TYPE = 0x888e;

    public static final int TYPE_EAP = 0;
    public static final int TYPE_START = 1;
    public static final int TYPE_LOGOFF = 2;
    public static final int TYPE_KEY = 3;
    public static final int TYPE_ALERT = 4;
    public static final int TYPE_MKA = 5;

    private static final int EAP_REQUEST = 1;
    private static final int EAP_RESPONSE = 2;
    private static final int EAP_SUCCESS = 3;
    private static final int EAP_FAILURE = 4;

    private static final int EAP_TYPE_IDENTITY = 1;

    public String packetTypeName() {
        return switch (packetType) {
            case TYPE_EAP -> "eap";
            case TYPE_START -> "start";
            case TYPE_LOGOFF -> "logoff";
            case TYPE_KEY -> "key";
            case TYPE_ALERT -> "alert";
            case TYPE_MKA -> "mka";
            default -> "type " + packetType;
        };
    }

    public String eapCodeName() {
        if (eapCode == null) return null;
        return switch (eapCode) {
            case EAP_REQUEST -> "request";
            case EAP_RESPONSE -> "response";
            case EAP_SUCCESS -> "success";
            case EAP_FAILURE -> "failure";
            default -> "code " + eapCode;
        };
    }

    /** The authentication method the supplicant and server settled on. */
    public String methodName() {
        if (eapType == null) return null;
        return switch (eapType) {
            case 1 -> "identity";
            case 2 -> "notification";
            case 3 -> "nak";
            case 4 -> "md5 challenge";
            case 6 -> "gtc";
            case 13 -> "eap-tls";
            case 17 -> "leap";
            case 18 -> "eap-sim";
            case 21 -> "eap-ttls";
            case 23 -> "eap-aka";
            case 25 -> "peap";
            case 26 -> "mschapv2";
            case 43 -> "eap-fast";
            case 50 -> "eap-aka'";
            default -> "method " + eapType;
        };
    }

    public boolean authenticated() {
        return eapCode != null && eapCode == EAP_SUCCESS;
    }

    public boolean rejected() {
        return eapCode != null && eapCode == EAP_FAILURE;
    }

    /** MD5 challenge and LEAP are broken; anything without TLS exposes the credential. */
    public boolean weakMethod() {
        return eapType != null && (eapType == 4 || eapType == 17);
    }

    @Override
    public String toString() {
        return "EAPOL v" + version + " " + packetTypeName()
                + (eapCodeName() == null ? "" : " " + eapCodeName())
                + (methodName() == null ? "" : " " + methodName())
                + (identity == null ? "" : " identity=" + identity);
    }

    /** Returns null if the data is not EAPOL. */
    public static Eapol parseOrNull(byte[] p) {
        if (p.length < 4) return null;
        final int version = p[0] & 0xff;
        final int packetType = p[1] & 0xff;
        if (version < 1 || version > 3 || packetType > TYPE_MKA) return null;
        final int bodyLength = u16(p, 2);

        if (packetType != TYPE_EAP || bodyLength < 4 || 4 + bodyLength > p.length) {
            return new Eapol(version, packetType, null, null, null, null);
        }

        // EAP: code (1), identifier (1), length (2), then a type byte for requests and responses
        final int code = p[4] & 0xff;
        final int id = p[5] & 0xff;
        final int eapLength = u16(p, 6);
        Integer type = null;
        String identity = null;
        if ((code == EAP_REQUEST || code == EAP_RESPONSE) && p.length > 8) {
            type = p[8] & 0xff;
            if (type == EAP_TYPE_IDENTITY && eapLength > 5) {
                final int end = Math.min(4 + eapLength, p.length);
                identity = new String(p, 9, Math.max(end - 9, 0), StandardCharsets.UTF_8).trim();
                if (identity.isEmpty()) identity = null;
            }
        }
        return new Eapol(version, packetType, code, id, type, identity);
    }

    /**
     * Parses bytes the caller has already identified as EAPOL by EtherType.
     * Throws rather than returning null: at this point the bytes claim to be this protocol.
     */
    public static Eapol parse(byte[] p) throws org.pcap4j.packet.IllegalRawDataException {
        final Eapol parsed = parseOrNull(p);
        if (parsed == null) throw Raw.notA("EAPOL", p);
        return parsed;
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xff) << 8) | (p[off + 1] & 0xff);
    }
}
