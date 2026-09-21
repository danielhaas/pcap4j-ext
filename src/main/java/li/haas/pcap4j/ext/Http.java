package li.haas.pcap4j.ext;

import java.nio.charset.StandardCharsets;

/**
 * The first line and a few headers of a plain HTTP request, which pcap4j does not decode.
 * The User-Agent identifies the client and the Host says which site it asked for.
 * Only requests that start at the beginning of a segment are read; this is not a stream reassembler.
 */
public record Http(String method, String target, String version,
                   String host, String userAgent, String server) {

    private static final String[] METHODS = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
            "OPTIONS ", "PATCH ", "TRACE ", "CONNECT ", "PROPFIND ", "M-SEARCH "};

    public boolean isResponse() {
        return method == null;
    }

    @Override
    public String toString() {
        return isResponse()
                ? "HTTP response" + (server == null ? "" : " server=" + server)
                : "HTTP " + method + " " + (host == null ? "" : host) + target
                        + (userAgent == null ? "" : "  agent=" + userAgent);
    }

    /** Returns null if the data does not begin with an HTTP request or response. */
    public static Http parse(byte[] p) {
        if (p.length < 16) return null;
        final String text = new String(p, 0, Math.min(p.length, 2048), StandardCharsets.ISO_8859_1);

        final int firstLineEnd = text.indexOf('\n');
        if (firstLineEnd < 0) return null;
        final String startLine = text.substring(0, firstLineEnd).trim();

        boolean request = false;
        for (String m : METHODS) {
            if (startLine.startsWith(m)) {
                request = true;
                break;
            }
        }
        final boolean response = startLine.startsWith("HTTP/1.");
        if (!request && !response) return null;

        String method = null, target = null, version = null;
        if (request) {
            final String[] parts = startLine.split(" ");
            if (parts.length < 3 || !parts[2].startsWith("HTTP/")) return null;
            method = parts[0];
            target = parts[1];
            version = parts[2];
        } else {
            version = startLine.split(" ")[0];
        }

        String host = null, userAgent = null, server = null;
        for (String line : text.substring(firstLineEnd + 1).split("\r?\n")) {
            if (line.isBlank()) break;              // end of the header block
            final int colon = line.indexOf(':');
            if (colon <= 0) continue;
            final String name = line.substring(0, colon).trim().toLowerCase();
            final String value = line.substring(colon + 1).trim();
            switch (name) {
                case "host" -> host = value;
                case "user-agent" -> userAgent = value;
                case "server" -> server = value;
                default -> { }
            }
        }
        return new Http(method, target, version, host, userAgent, server);
    }
}
