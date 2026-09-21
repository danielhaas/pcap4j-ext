package li.haas.pcap4j.ext;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * SSDP, the discovery part of UPnP, which pcap4j does not decode.
 * HTTP-like text over UDP 1900, multicast to 239.255.255.250; responses are unicast to the searching host.
 * Everything here is self-reported by the device and trivially spoofed.
 */
public record Ssdp(Type type, Map<String, String> headers) {

    public enum Type {
        /** A device announcing itself (ssdp:alive) or leaving (ssdp:byebye). */
        NOTIFY,
        /** A host searching for devices. */
        SEARCH,
        /** A device answering an M-SEARCH. */
        RESPONSE
    }

    public String header(String name) {
        return headers.get(name.toUpperCase());
    }

    /** Device or service type: NT in a notification, ST in a search or response. */
    public String serviceType() {
        return type == Type.NOTIFY ? header("NT") : header("ST");
    }

    /** ssdp:alive, ssdp:byebye or ssdp:update; only notifications have it. */
    public String subType() {
        return header("NTS");
    }

    public boolean isByebye() {
        return "ssdp:byebye".equalsIgnoreCase(subType());
    }

    /** The device UUID out of the USN header, a stable id that survives IP changes. */
    public String uuid() {
        final String usn = header("USN");
        if (usn == null) return null;
        final int start = usn.indexOf("uuid:");
        if (start < 0) return null;
        final int from = start + "uuid:".length();
        final int end = usn.indexOf("::", from);
        return end < 0 ? usn.substring(from).trim() : usn.substring(from, end).trim();
    }

    /** Free-text fingerprint, e.g. "Linux/4.4 UPnP/1.0 Sonos/70.3-35220". */
    public String server() {
        return type == Type.SEARCH ? header("USER-AGENT") : header("SERVER");
    }

    /** URL of the device description, e.g. http://10.0.0.42:1400/xml/device_description.xml */
    public String location() {
        return header("LOCATION");
    }

    /** Host part of LOCATION: the device's own idea of its address, which may differ from the packet source. */
    public String locationHost() {
        final String loc = location();
        if (loc == null) return null;
        try {
            return new URI(loc.trim()).getHost();
        } catch (URISyntaxException e) {
            return null;
        }
    }

    /** Port from LOCATION, where the device serves its description; -1 if the URL has none. */
    public int locationPort() {
        final String loc = location();
        if (loc == null) return -1;
        try {
            final URI u = new URI(loc.trim());
            return u.getPort() != -1 ? u.getPort() : "https".equalsIgnoreCase(u.getScheme()) ? 443 : 80;
        } catch (URISyntaxException e) {
            return -1;
        }
    }

    /** True for a router that offers UPnP port mapping. */
    public boolean isInternetGatewayDevice() {
        final String st = serviceType();
        return st != null && st.contains("InternetGatewayDevice");
    }

    /** Seconds until the device is expected to announce itself again, from CACHE-CONTROL; -1 if absent. */
    public int maxAge() {
        final String cc = header("CACHE-CONTROL");
        if (cc == null) return -1;
        final int i = cc.toLowerCase().indexOf("max-age");
        if (i < 0) return -1;
        final int eq = cc.indexOf('=', i);
        if (eq < 0) return -1;
        try {
            return Integer.parseInt(cc.substring(eq + 1).trim().split("[^0-9]", 2)[0]);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    @Override
    public String toString() {
        return "SSDP " + type
                + (subType() == null ? "" : " " + subType())
                + (serviceType() == null ? "" : " " + serviceType())
                + (uuid() == null ? "" : " uuid=" + uuid())
                + (server() == null ? "" : " server=" + server())
                + (location() == null ? "" : " location=" + location());
    }

    /** Returns null if the data is not SSDP. */
    public static Ssdp parse(byte[] p) {
        if (p.length < 16) return null;
        // ISO-8859-1 never fails on arbitrary bytes; header values are ASCII in practice
        final String text = new String(p, StandardCharsets.ISO_8859_1);
        final int firstLineEnd = text.indexOf('\n');
        if (firstLineEnd < 0) return null;
        final String startLine = text.substring(0, firstLineEnd).trim();

        final Type type;
        if (startLine.regionMatches(true, 0, "NOTIFY * ", 0, 9)) {
            type = Type.NOTIFY;
        } else if (startLine.regionMatches(true, 0, "M-SEARCH * ", 0, 11)) {
            type = Type.SEARCH;
        } else if (startLine.regionMatches(true, 0, "HTTP/1.", 0, 7)) {
            type = Type.RESPONSE;
        } else {
            return null;  // SIP and other text protocols over UDP start differently
        }

        final Map<String, String> headers = new LinkedHashMap<>();
        for (String line : text.substring(firstLineEnd + 1).split("\r?\n")) {
            if (line.isBlank()) break;  // end of the header block
            final int colon = line.indexOf(':');
            if (colon <= 0) continue;
            headers.put(line.substring(0, colon).trim().toUpperCase(),
                    line.substring(colon + 1).trim());
        }

        // a response only counts as SSDP if it carries discovery headers, HTTP/1.1 alone is not enough
        if (type == Type.RESPONSE && !headers.containsKey("ST") && !headers.containsKey("USN")) {
            return null;
        }
        return new Ssdp(type, headers);
    }
}
