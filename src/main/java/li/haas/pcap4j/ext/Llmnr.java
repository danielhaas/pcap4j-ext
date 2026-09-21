package li.haas.pcap4j.ext;

import org.pcap4j.packet.DnsDomainName;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsQuestion;
import org.pcap4j.packet.DnsRDataA;
import org.pcap4j.packet.DnsRDataAaaa;
import org.pcap4j.packet.DnsResourceRecord;
import org.pcap4j.packet.IllegalRawDataException;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Link-Local Multicast Name Resolution (RFC 4795), UDP 5355 to 224.0.0.252 or ff02::1:3.
 * DNS shaped, like mDNS, but for plain single-label host names rather than service discovery,
 * and Windows falls back to it when DNS has no answer. pcap4j only decodes port 53.
 */
import java.util.ArrayList;

import java.util.Collections;

import java.util.LinkedHashMap;

import java.util.List;

import java.util.Map;

public record Llmnr(boolean response, Set<String> queried, Set<String> claimed, Set<String> addresses) implements Protocol {
    public Llmnr {
        queried = copy(queried);
        claimed = copy(claimed);
        addresses = copy(addresses);
    }


    public static final int PORT = 5355;

    public boolean isEmpty() {
        return queried.isEmpty() && claimed.isEmpty();
    }

    @Override
    public String toString() {
        return "LLMNR " + (response ? "response" : "query")
                + (queried.isEmpty() ? "" : " asks=" + queried)
                + (claimed.isEmpty() ? "" : " claims=" + claimed)
                + (addresses.isEmpty() ? "" : " " + addresses);
    }

    /** Everything this message says: what was asked for, and what the responder claims to be. */
    public static Llmnr parse(DnsPacket dns) {
        final boolean response = dns.getHeader().isResponse();
        final Set<String> queried = new LinkedHashSet<>();
        final Set<String> claimed = new LinkedHashSet<>();
        final Set<String> addresses = new LinkedHashSet<>();

        for (DnsQuestion q : dns.getHeader().getQuestions()) {
            final String name = name(q.getQName(), dns);
            if (!name.isEmpty()) queried.add(name);
        }

        // a responder answers only for its own name, so an answer is a claim by the sender
        for (DnsResourceRecord r : dns.getHeader().getAnswers()) {
            final String name = name(r.getName(), dns);
            if (!name.isEmpty()) claimed.add(name);
            if (r.getRData() instanceof DnsRDataA a) addresses.add(a.getAddress().getHostAddress());
            if (r.getRData() instanceof DnsRDataAaaa a) addresses.add(a.getAddress().getHostAddress());
        }
        return new Llmnr(response, queried, claimed, addresses);
    }

    private static String name(DnsDomainName name, DnsPacket dns) {
        try {
            final String s = name.decompress(dns.getHeader().getRawData());
            return s.startsWith(".") ? s.substring(1) : s;
        } catch (IllegalRawDataException e) {
            return name.getName();
        }
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
