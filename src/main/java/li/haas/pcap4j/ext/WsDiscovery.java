package li.haas.pcap4j.ext;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * WS-Discovery (OASIS ws-dd), UDP 3702 to 239.255.255.250 or ff02::c, which pcap4j does not decode.
 * SOAP over UDP, and the discovery protocol Windows and most network printers use alongside SSDP
 * and mDNS. A Hello or ProbeMatch names the device, its stable UUID and the addresses it serves on.
 */
public record WsDiscovery(String action, String address, List<String> types,
                          List<String> scopes, List<String> transportAddresses) implements Protocol {

    public WsDiscovery {
        types = copy(types);
        scopes = copy(scopes);
        transportAddresses = copy(transportAddresses);
    }

    public static final int PORT = 3702;

    // the payload is XML, and the elements wanted here are simple enough to read without a parser
    private static final Pattern ACTION = Pattern.compile("<[^>]*Action[^>]*>\\s*([^<\\s]+)\\s*<");
    private static final Pattern ADDRESS = Pattern.compile("<[^>]*Address[^>]*>\\s*([^<\\s]+)\\s*<");
    private static final Pattern TYPES = Pattern.compile("<[^>]*Types[^>]*>\\s*([^<]+)\\s*<");
    private static final Pattern SCOPES = Pattern.compile("<[^>]*Scopes[^>]*>\\s*([^<]+)\\s*<");
    private static final Pattern XADDRS = Pattern.compile("<[^>]*XAddrs[^>]*>\\s*([^<]+)\\s*<");

    /** The last part of the action URI: Hello, Bye, Probe, ProbeMatches, Resolve, ResolveMatches. */
    public String actionName() {
        if (action == null) return null;
        final int slash = action.lastIndexOf('/');
        return slash < 0 ? action : action.substring(slash + 1);
    }

    /** The device's stable identifier, which survives address changes. */
    public String uuid() {
        if (address == null) return null;
        final int i = address.indexOf("uuid:");
        return i < 0 ? null : address.substring(i + 5);
    }

    public boolean isLeaving() {
        return "Bye".equals(actionName());
    }

    @Override
    public String toString() {
        return "WS-Discovery " + (actionName() == null ? "" : actionName())
                + (uuid() == null ? "" : " uuid=" + uuid())
                + (types.isEmpty() ? "" : " types=" + types)
                + (transportAddresses.isEmpty() ? "" : " at=" + transportAddresses);
    }

    /** Returns null if the data is not a WS-Discovery message. */
    public static WsDiscovery parse(byte[] p) {
        if (p.length < 32) return null;
        final String text = new String(p, StandardCharsets.UTF_8);
        // every message is a SOAP envelope carrying the discovery namespace
        if (!text.contains("Envelope") || !text.contains("discovery")) return null;

        final String action = first(ACTION, text);
        if (action == null || !action.contains("discovery")) return null;

        return new WsDiscovery(action, first(ADDRESS, text),
                words(first(TYPES, text)), words(first(SCOPES, text)), words(first(XADDRS, text)));
    }

    private static String first(Pattern pattern, String text) {
        final Matcher m = pattern.matcher(text);
        return m.find() ? m.group(1).trim() : null;
    }

    /** These elements hold whitespace separated lists. */
    private static List<String> words(String value) {
        if (value == null || value.isBlank()) return List.of();
        final List<String> out = new ArrayList<>();
        for (String word : value.trim().split("\\s+")) {
            if (!word.isEmpty()) out.add(word);
        }
        return out;
    }

    private static List<String> copy(List<String> in) {
        return in == null ? List.of() : Collections.unmodifiableList(new ArrayList<>(in));
    }
}
