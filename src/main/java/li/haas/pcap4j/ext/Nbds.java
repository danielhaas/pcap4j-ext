package li.haas.pcap4j.ext;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * NetBIOS Datagram Service (RFC 1002), UDP 138, and the Windows Browser announcements it carries.
 * The datagram header names the sender and the workgroup; the SMB mailslot payload adds
 * the host name, OS version and what roles the host claims. pcap4j decodes none of it.
 */
import org.pcap4j.packet.IllegalRawDataException;

public record Nbds(int messageType, Netbios.Name sourceName, Netbios.Name destName, Inet4Address sourceAddress,
                   Integer browserCommand, String hostName, Integer osMajor, Integer osMinor,
                   Long serverType, String comment) {

    public static final int PORT = 138;

    private static final byte[] MAILSLOT_BROWSE = "\\MAILSLOT\\BROWSE".getBytes(StandardCharsets.US_ASCII);

    private static final int CMD_HOST_ANNOUNCEMENT = 0x01;
    private static final int CMD_ANNOUNCEMENT_REQUEST = 0x02;
    private static final int CMD_REQUEST_ELECTION = 0x08;
    private static final int CMD_DOMAIN_ANNOUNCEMENT = 0x0c;
    private static final int CMD_MASTER_ANNOUNCEMENT = 0x0d;
    private static final int CMD_LOCAL_MASTER_ANNOUNCEMENT = 0x0f;

    /** The workgroup or domain the sender announces into; null for the browser-wide __MSBROWSE__ name. */
    public String workgroup() {
        if (isDomainAnnouncement()) return hostName;  // there the name field holds the domain
        if (destName == null || destName.name().startsWith("__MSBROWSE__")) return null;
        return destName.name();
    }

    /**
     * A domain announcement describes the workgroup, not the sender: its name field is the domain
     * and its comment is the master browser's host name.
     */
    public boolean isDomainAnnouncement() {
        return browserCommand != null && browserCommand == CMD_DOMAIN_ANNOUNCEMENT;
    }

    /** The announcing host's own name, or null when the message describes something else. */
    public String announcedHost() {
        return isDomainAnnouncement() ? null : hostName;
    }

    public String browserCommandName() {
        if (browserCommand == null) return null;
        return switch (browserCommand) {
            case CMD_HOST_ANNOUNCEMENT -> "host announcement";
            case CMD_ANNOUNCEMENT_REQUEST -> "announcement request";
            case CMD_REQUEST_ELECTION -> "election request";
            case CMD_DOMAIN_ANNOUNCEMENT -> "domain announcement";
            case CMD_MASTER_ANNOUNCEMENT -> "master announcement";
            case CMD_LOCAL_MASTER_ANNOUNCEMENT -> "local master announcement";
            default -> String.format("browser command 0x%02x", browserCommand);
        };
    }

    /** OS version as announced, e.g. "10.0"; self-reported and often stale on Samba. */
    public String osVersion() {
        return osMajor == null ? null : osMajor + "." + osMinor;
    }

    /** The roles from the server type bitmask (SV_TYPE_*). */
    public List<String> roles() {
        final List<String> roles = new ArrayList<>();
        if (serverType == null) return roles;
        final long t = serverType;
        if ((t & 0x00000001L) != 0) roles.add("workstation");
        if ((t & 0x00000002L) != 0) roles.add("server");
        if ((t & 0x00000004L) != 0) roles.add("sql server");
        if ((t & 0x00000008L) != 0) roles.add("domain controller");
        if ((t & 0x00000010L) != 0) roles.add("backup domain controller");
        if ((t & 0x00000020L) != 0) roles.add("time source");
        if ((t & 0x00000040L) != 0) roles.add("apple server");
        if ((t & 0x00000080L) != 0) roles.add("novell server");
        if ((t & 0x00000100L) != 0) roles.add("domain member");
        if ((t & 0x00000200L) != 0) roles.add("print server");
        if ((t & 0x00000400L) != 0) roles.add("dialin server");
        if ((t & 0x00000800L) != 0) roles.add("unix server");
        if ((t & 0x00001000L) != 0) roles.add("nt workstation");
        if ((t & 0x00002000L) != 0) roles.add("wfw");
        if ((t & 0x00008000L) != 0) roles.add("nt server");
        if ((t & 0x00010000L) != 0) roles.add("potential browser");
        if ((t & 0x00020000L) != 0) roles.add("backup browser");
        if ((t & 0x00040000L) != 0) roles.add("master browser");
        if ((t & 0x00080000L) != 0) roles.add("domain master browser");
        if ((t & 0x01000000L) != 0) roles.add("windows 95+");
        if ((t & 0x08000000L) != 0) roles.add("terminal server");
        return roles;
    }

    @Override
    public String toString() {
        return "NBDS " + sourceName + " -> " + destName
                + (browserCommandName() == null ? "" : "  " + browserCommandName())
                + (hostName == null ? "" : " host=" + hostName)
                + (osVersion() == null ? "" : " os=" + osVersion())
                + (roles().isEmpty() ? "" : " roles=" + roles())
                + (comment == null || comment.isEmpty() ? "" : " comment=" + comment);
    }

    /**
     * Parses bytes the caller has already identified as a NetBIOS datagram, for example by protocol id or port.
     * Throws rather than returning null: at this point the bytes claim to be this protocol.
     */
    public static Nbds parse(byte[] p) throws IllegalRawDataException {
        final Nbds parsed = parseOrNull(p);
        if (parsed == null) throw Raw.notA("a NetBIOS datagram", p);
        return parsed;
    }

    /** Returns null if the data is not a NetBIOS datagram. */
    private static Nbds parseOrNull(byte[] p) {
        if (p.length < 82) return null;
        final int messageType = p[0] & 0xff;
        // 0x10 direct unique, 0x11 direct group, 0x12 broadcast; the others carry no names
        if (messageType < 0x10 || messageType > 0x12) return null;

        final Inet4Address src = ipv4(p, 4);
        final Netbios.Name sourceName = Netbios.decode(p, 14);
        if (sourceName == null) return null;
        final int destOff = 14 + Netbios.encodedLength(p, 14);
        final Netbios.Name destName = Netbios.decode(p, destOff);
        if (destName == null) return null;

        // the SMB payload follows; find the browser mailslot rather than decoding all of SMB
        final int m = indexOf(p, MAILSLOT_BROWSE, destOff);
        if (m < 0) {
            return new Nbds(messageType, sourceName, destName, src, null, null, null, null, null, null);
        }
        int off = m + MAILSLOT_BROWSE.length;
        while (off < p.length && p[off] == 0) off++;  // the mailslot name is NUL terminated
        if (off >= p.length) {
            return new Nbds(messageType, sourceName, destName, src, null, null, null, null, null, null);
        }

        final int command = p[off] & 0xff;
        Integer osMajor = null, osMinor = null;
        Long serverType = null;
        String hostName = null, comment = null;

        // announcements share a layout: count (1), periodicity (4), name (16), OS major/minor, server type (4)
        if ((command == CMD_HOST_ANNOUNCEMENT || command == CMD_DOMAIN_ANNOUNCEMENT
                || command == CMD_LOCAL_MASTER_ANNOUNCEMENT) && off + 28 <= p.length) {
            hostName = text(p, off + 6, 16);
            osMajor = p[off + 22] & 0xff;
            osMinor = p[off + 23] & 0xff;
            serverType = u32le(p, off + 24);
            // browser version (2) and signature (2) follow, then a NUL terminated comment
            if (off + 32 < p.length) {
                comment = text(p, off + 32, p.length - (off + 32));
            }
        }
        return new Nbds(messageType, sourceName, destName, src, command, hostName, osMajor, osMinor, serverType, comment);
    }

    /** Fixed-width or NUL terminated ASCII. */
    private static String text(byte[] p, int off, int max) {
        int end = off;
        while (end < p.length && end < off + max && p[end] != 0) end++;
        return new String(p, off, end - off, StandardCharsets.US_ASCII).trim();
    }

    private static int indexOf(byte[] haystack, byte[] needle, int from) {
        outer:
        for (int i = Math.max(from, 0); i + needle.length <= haystack.length; i++) {
            for (int k = 0; k < needle.length; k++) {
                if (haystack[i + k] != needle[k]) continue outer;
            }
            return i;
        }
        return -1;
    }

    private static Inet4Address ipv4(byte[] p, int off) {
        try {
            return (Inet4Address) Inet4Address.getByAddress(Arrays.copyOfRange(p, off, off + 4));
        } catch (UnknownHostException e) {
            return null;
        }
    }

    // the browser payload is little endian, unlike the NetBIOS header
    private static long u32le(byte[] p, int off) {
        return (p[off] & 0xffL) | ((p[off + 1] & 0xffL) << 8) | ((p[off + 2] & 0xffL) << 16) | ((p[off + 3] & 0xffL) << 24);
    }
}
