package li.haas.pcap4j.ext;

import java.nio.charset.StandardCharsets;

/**
 * The start line and a few headers of plain, unencrypted HTTP, which pcap4j does not decode.
 *
 * <p>Almost all browsing has moved to TLS, so what is left on port 80 is mostly the things that never
 * moved: captive portal probes, firmware and update checks, printers, cameras, embedded management
 * interfaces and UPnP device descriptions. That makes it valuable for identification rather than for
 * content. The User-Agent names the client and often its exact OS build, the Host says which site it asked
 * for, and a response's Server header names the embedded web server, which is usually enough to identify
 * the device.
 *
 * <p><b>Parsed:</b> the request line, or the status line's version for a response, plus Host, User-Agent
 * and Server. Detection is by the start line, not by port, so HTTP on an unusual port is still found.
 *
 * <p>This is not a stream reassembler. Only a request or response that begins at the start of a TCP segment
 * is read, headers past the first 2 KiB are ignored, and bodies are never touched. {@link #parse(byte[])}
 * returns null rather than throwing when the bytes are not HTTP.
 */
public record Http(String method, String target, String version,
                   String host, String userAgent, String server) implements Protocol {

    /** The usual port. Detection is by the request line, not by port. */
    public static final int DEFAULT_PORT = 80;

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
