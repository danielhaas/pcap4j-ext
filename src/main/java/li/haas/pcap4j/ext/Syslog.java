package li.haas.pcap4j.ext;

import java.nio.charset.StandardCharsets;

/**
 * Syslog (RFC 3164 and 5424), UDP 514, which pcap4j does not decode.
 * Devices log to it in clear text, so a capture shows which hosts log where, what they call
 * themselves, and often the events themselves: link changes, authentication failures, reboots.
 */
public record Syslog(int facility, int severity, String hostname, String tag, String message,
                     boolean structured) implements Protocol {

    public static final int PORT = 514;

    private static final String[] FACILITIES = {
        "kernel", "user", "mail", "daemon", "auth", "syslog", "printer", "news", "uucp", "clock",
        "authpriv", "ftp", "ntp", "audit", "alert", "cron", "local0", "local1", "local2", "local3",
        "local4", "local5", "local6", "local7"
    };

    private static final String[] SEVERITIES = {
        "emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"
    };

    public String facilityName() {
        return facility < FACILITIES.length ? FACILITIES[facility] : "facility " + facility;
    }

    public String severityName() {
        return severity < SEVERITIES.length ? SEVERITIES[severity] : "severity " + severity;
    }

    /** Error and worse, which is what an audit usually wants to see. */
    public boolean isSerious() {
        return severity <= 3;
    }

    @Override
    public String toString() {
        return "syslog " + facilityName() + "." + severityName()
                + (hostname == null ? "" : " " + hostname)
                + (tag == null ? "" : " " + tag)
                + (message == null ? "" : ": " + message);
    }

    /** Returns null if the data is not a syslog message. */
    public static Syslog parse(byte[] p) {
        if (p.length < 5 || p[0] != '<') return null;
        final String text = new String(p, StandardCharsets.UTF_8);
        final int close = text.indexOf('>');
        if (close < 2 || close > 4) return null;

        final int priority;
        try {
            priority = Integer.parseInt(text.substring(1, close));
        } catch (NumberFormatException e) {
            return null;
        }
        if (priority > 191) return null;

        String rest = text.substring(close + 1).trim();
        // RFC 5424 puts a version number straight after the priority
        final boolean structured = rest.startsWith("1 ");
        if (structured) rest = rest.substring(2).trim();

        String hostname = null, tag = null;
        if (structured) {
            // version, timestamp, hostname, app name, process id, message id, then the rest
            final String[] parts = rest.split(" ", 6);
            if (parts.length >= 3) {
                hostname = nil(parts[1]);
                tag = nil(parts[2]);
            }
            rest = parts.length >= 6 ? parts[5] : rest;
            // then comes the structured data: "-" when there is none, otherwise [id key="value"]
            if (rest.startsWith("- ")) {
                rest = rest.substring(2);
            } else if (rest.startsWith("[")) {
                int depth = 0, i = 0;
                for (; i < rest.length(); i++) {
                    if (rest.charAt(i) == '[') depth++;
                    if (rest.charAt(i) == ']' && --depth == 0) break;
                }
                rest = i + 1 < rest.length() ? rest.substring(i + 1) : "";
            }
        } else {
            // the old format: "Mmm dd hh:mm:ss host tag: message", with the timestamp optional
            final String[] parts = rest.split(" ");
            int i = 0;
            if (parts.length > 3 && parts[0].length() == 3 && Character.isLetter(parts[0].charAt(0))) {
                i = 3;                                   // skip the timestamp
            }
            if (i < parts.length) hostname = parts[i++];
            if (i < parts.length && parts[i].endsWith(":")) {
                tag = parts[i].substring(0, parts[i].length() - 1);
                i++;
            }
            rest = String.join(" ", java.util.Arrays.copyOfRange(parts, Math.min(i, parts.length), parts.length));
        }

        return new Syslog(priority / 8, priority % 8, hostname, tag, rest.trim(), structured);
    }

    private static String nil(String s) {
        return "-".equals(s) ? null : s;
    }
}
