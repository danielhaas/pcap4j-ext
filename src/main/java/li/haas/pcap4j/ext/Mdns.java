package li.haas.pcap4j.ext;

import org.pcap4j.packet.DnsDomainName;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsQuestion;
import org.pcap4j.packet.DnsRDataA;
import org.pcap4j.packet.DnsRDataAaaa;
import org.pcap4j.packet.DnsRDataPtr;
import org.pcap4j.packet.DnsRDataTxt;
import org.pcap4j.packet.DnsResourceRecord;
import org.pcap4j.packet.IllegalRawDataException;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Multicast DNS / DNS-SD (RFC 6762, 6763): DNS messages on UDP 5353 to 224.0.0.251 or ff02::fb.
 * pcap4j only decodes port 53, so the payload has to be handed to DnsPacket.newPacket separately.
 * What a device publishes here is self-reported, but it is the best passive source of host names.
 */
import java.util.Collections;

public record Mdns(String hostname,              // e.g. "gamora.local"
                   Set<String> addresses,        // A and AAAA records it announces
                   Set<String> services,         // service types it offers, e.g. "_smb._tcp.local"
                   Set<String> instances,        // e.g. "GAMORA._smb._tcp.local"
                   Map<String, String> txt,      // TXT key/value pairs, e.g. model=MacBookPro18,3
                   Map<String, Integer> ports,   // SRV port per instance, e.g. GAMORA._smb._tcp.local -> 445
                   Set<String> browsing) implements Protocol {
    public Mdns {
        addresses = copy(addresses);
        services = copy(services);
        instances = copy(instances);
        txt = copy(txt);
        ports = copy(ports);
        browsing = copy(browsing);
    }
       // service types it is searching for

    public static final int PORT = 5353;

    private static final int TYPE_A = 1;
    private static final int TYPE_PTR = 12;
    private static final int TYPE_TXT = 16;
    private static final int TYPE_AAAA = 28;
    private static final int TYPE_SRV = 33;

    /** Service enumeration; its PTR targets are service types, not instances. */
    private static final String SERVICE_ENUMERATION = "_services._dns-sd._udp.local";

    public boolean isEmpty() {
        return hostname == null && addresses.isEmpty() && services.isEmpty()
                && instances.isEmpty() && txt.isEmpty() && ports.isEmpty() && browsing.isEmpty();
    }

    /** Apple devices publish their real MAC here even when the interface uses a randomised one. */
    public String deviceId() {
        return txt.get("deviceid");
    }

    /** Hardware model, e.g. "MacBookPro18,3" from Apple, "ty"/"usb_MDL" from printers. */
    public String model() {
        for (String key : new String[] {"model", "am", "ty", "usb_MDL", "product"}) {
            final String v = txt.get(key);
            if (v != null) return v;
        }
        return null;
    }

    @Override
    public String toString() {
        return "mDNS " + (hostname == null ? "" : hostname)
                + (addresses.isEmpty() ? "" : " " + addresses)
                + (services.isEmpty() ? "" : " offers=" + services)
                + (ports.isEmpty() ? "" : " ports=" + ports)
                + (browsing.isEmpty() ? "" : " browsing=" + browsing)
                + (model() == null ? "" : " model=" + model());
    }

    /** Everything this message says about its sender. Never null, but may be empty. */
    public static Mdns parse(DnsPacket dns) {
        String hostname = null;
        final Set<String> addresses = new LinkedHashSet<>();
        final Set<String> services = new LinkedHashSet<>();
        final Set<String> instances = new LinkedHashSet<>();
        final Map<String, String> txt = new LinkedHashMap<>();
        final Map<String, Integer> ports = new LinkedHashMap<>();
        final Set<String> browsing = new LinkedHashSet<>();

        for (DnsQuestion q : dns.getHeader().getQuestions()) {
            final String name = name(q.getQName(), dns);
            // a device browsing for a service type says what it is looking for, not what it has
            if (name.startsWith("_") && !name.startsWith(SERVICE_ENUMERATION)) {
                browsing.add(name);
            }
        }

        final List<DnsResourceRecord> records = new ArrayList<>(dns.getHeader().getAnswers());
        records.addAll(dns.getHeader().getAuthorities());
        records.addAll(dns.getHeader().getAdditionalInfo());

        for (DnsResourceRecord r : records) {
            final String name = name(r.getName(), dns);
            switch (r.getDataType().value() & 0xffff) {
                case TYPE_A -> {
                    if (r.getRData() instanceof DnsRDataA a) {
                        addresses.add(a.getAddress().getHostAddress());
                        if (hostname == null) hostname = name;
                    }
                }
                case TYPE_AAAA -> {
                    if (r.getRData() instanceof DnsRDataAaaa a) {
                        addresses.add(a.getAddress().getHostAddress());
                        if (hostname == null) hostname = name;
                    }
                }
                case TYPE_PTR -> {
                    if (r.getRData() instanceof DnsRDataPtr ptr) {
                        final String target = name(ptr.getPtrDName(), dns);
                        if (name.startsWith(SERVICE_ENUMERATION)) {
                            services.add(target);           // the target is a service type
                        } else if (name.startsWith("_")) {
                            services.add(name);             // the owner is the service type
                            instances.add(target);
                        }
                    }
                }
                case TYPE_SRV -> {
                    // pcap4j has no SRV class: priority (2), weight (2), port (2), target name
                    instances.add(name);
                    final byte[] rd = r.getRData() == null ? null : r.getRData().getRawData();
                    if (rd != null && rd.length > 6) {
                        // priority (2), weight (2), port (2), target
                        ports.put(name, ((rd[4] & 0xff) << 8) | (rd[5] & 0xff));
                        final String target = srvTarget(rd, dns);
                        if (target != null && hostname == null) hostname = target;
                    }
                }
                case TYPE_TXT -> {
                    if (r.getRData() instanceof DnsRDataTxt t) {
                        for (String entry : t.getTexts()) {
                            final int eq = entry.indexOf('=');
                            if (eq > 0) {
                                txt.putIfAbsent(entry.substring(0, eq).trim().toLowerCase(), entry.substring(eq + 1));
                            }
                        }
                    }
                    if (name.startsWith("_") || name.contains("._")) instances.add(name);
                }
                default -> { }
            }
        }
        return new Mdns(hostname, addresses, services, instances, txt, ports, browsing);
    }

    private static String srvTarget(byte[] rd, DnsPacket dns) {
        try {
            return clean(DnsDomainName.newInstance(rd, 6, rd.length - 6).decompress(dns.getHeader().getRawData()));
        } catch (IllegalRawDataException e) {
            return null;
        }
    }

    /** Names are usually compressed; decompress() needs the whole message to follow the pointer. */
    private static String name(DnsDomainName name, DnsPacket dns) {
        try {
            return clean(name.decompress(dns.getHeader().getRawData()));
        } catch (IllegalRawDataException e) {
            return name.getName();
        }
    }

    private static String clean(String s) {
        return s.startsWith(".") ? s.substring(1) : s;
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
