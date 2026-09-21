import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import li.haas.pcap4j.ext.*;
import java.util.*;

/** Prints what our parsers make of a capture, one line per packet, for comparison with tshark. */
public class CrossDump {
    public static void main(String[] a) throws Exception {
        try (PcapHandle h = Pcaps.openOffline(a[0])) {
            Packet p;
            int n = 0;
            while ((p = h.getNextPacket()) != null) {
                n++;
                final List<String> out = new ArrayList<>();
                for (Protocol found : Protocols.decode(p).found()) {
                    switch (found) {
                        case Hsrp x -> {
                            out.add("hsrp.opcode=" + x.opcode());
                            out.add("hsrp.state=" + x.state());
                            out.add("hsrp.priority=" + x.priority());
                            out.add("hsrp.group=" + x.group());
                            out.add("hsrp.virt_ip=" + host(x.virtualAddress()));
                            out.add("hsrp.auth=" + (x.authentication() == null ? "" : x.authentication()));
                        }
                        case Vrrp x -> {
                            out.add("vrrp.version=" + x.version());
                            out.add("vrrp.vrid=" + x.virtualRouterId());
                            out.add("vrrp.prio=" + x.priority());
                            out.add("vrrp.count=" + x.virtualAddresses().size());
                            out.add("vrrp.ip=" + host(x.virtualAddresses().get(0)));
                            out.add("vrrp.auth_type=" + x.authType());
                        }
                        case Lacp x -> {
                            out.add("lacp.actor.sysid=" + x.actor().system());
                            out.add("lacp.actor.key=" + x.actor().key());
                            out.add("lacp.actor.port=" + x.actor().port());
                            out.add("lacp.actor.state=" + String.format("0x%02x", x.actor().state()));
                            out.add("lacp.partner.sysid=" + x.partner().system());
                            out.add("lacp.partner.key=" + x.partner().key());
                            out.add("lacp.partner.port=" + x.partner().port());
                        }
                        case Marker x -> {
                            out.add("marker.type=" + x.type());
                            out.add("marker.port=" + x.requesterPort());
                            out.add("marker.sysid=" + x.requesterSystem());
                            out.add("marker.xid=" + x.transactionId());
                        }
                        case Pagp x -> {
                            out.add("pagp.localdevid=" + x.local().deviceId());
                            out.add("pagp.localport=" + x.local().sentPortIfIndex());
                            out.add("pagp.localgroup=" + x.local().groupCapability());
                            out.add("pagp.partnerdevid=" + x.partner().deviceId());
                            out.add("pagp.devname=" + (x.deviceName() == null ? "" : x.deviceName()));
                            out.add("pagp.portname=" + (x.portName() == null ? "" : x.portName()));
                        }
                        case Udld x -> {
                            out.add("udld.opcode=" + x.opcode());
                            out.add("udld.device=" + (x.deviceId() == null ? "" : x.deviceId()));
                            out.add("udld.port=" + (x.portId() == null ? "" : x.portId()));
                            out.add("udld.name=" + (x.deviceName() == null ? "" : x.deviceName()));
                        }
                        case Cgmp x -> {
                            out.add("cgmp.type=" + x.type());
                            out.add("cgmp.count=" + x.entries().size());
                            out.add("cgmp.group0=" + x.entries().get(0).group());
                            out.add("cgmp.host0=" + x.entries().get(0).host());
                        }
                        case Mld x -> {
                            out.add("mld.type=" + x.type());
                            out.add("mld.records=" + x.records().size());
                            if (x.group() != null) out.add("mld.group=" + host(x.group()));
                            if (!x.records().isEmpty()) out.add("mld.rec0=" + host(x.records().get(0).group()));
                        }
                        case Lldp x -> {
                            out.add("lldp.chassis=" + x.chassisId());
                            out.add("lldp.port=" + x.portId());
                            out.add("lldp.ttl=" + x.ttl());
                            out.add("lldp.sysname=" + (x.systemName() == null ? "" : x.systemName()));
                            if (x.portVlanId() != null) out.add("lldp.pvid=" + x.portVlanId());
                        }
                        case DhcpV6 x -> {
                            out.add("dhcpv6.msgtype=" + x.messageType());
                            out.add("dhcpv6.xid=" + x.transactionId());
                            if (!x.addresses().isEmpty()) out.add("dhcpv6.addr=" + host(x.addresses().get(0)));
                        }
                        case Igmp x -> {
                            out.add("igmp.type=" + String.format("0x%02x", x.type()));
                            out.add("igmp.version=" + x.version());
                            if (x.group() != null) out.add("igmp.maddr=" + host(x.group()));
                            out.add("igmp.recs=" + x.records().size());
                            if (!x.records().isEmpty()) out.add("igmp.rec0=" + host(x.records().get(0).group()));
                        }
                        case Vtp x -> {
                            out.add("vtp.version=" + x.version());
                            out.add("vtp.code=" + x.code());
                            out.add("vtp.domain=" + x.domain());
                            if (x.revision() != null) out.add("vtp.rev=" + x.revision());
                            if (x.updater() != null) out.add("vtp.updater=" + host(x.updater()));
                            if (!x.vlans().isEmpty()) {
                                out.add("vtp.vlan0.id=" + x.vlans().get(0).id());
                                out.add("vtp.vlan0.name=" + x.vlans().get(0).name());
                            }
                        }
                        case Cdp x -> {
                            out.add("cdp.deviceid=" + x.deviceId());
                            out.add("cdp.portid=" + x.portId());
                            if (x.nativeVlan() != null) out.add("cdp.nativevlan=" + x.nativeVlan());
                        }
                        case Dtp x -> {
                            out.add("dtp.domain=" + x.domain());
                            // tshark splits the status byte into operating and administrative parts
                            out.add("dtp.tas=" + String.format("0x%02x", x.status() & 0x07));
                            out.add("dtp.tos=" + String.format("0x%02x", (x.status() & 0x80) >> 7));
                        }
                        default -> { }
                    }
                }
                if (!out.isEmpty()) System.out.println(n + " " + String.join("|", out));
            }
        }
    }
    static String host(java.net.InetAddress a) { return a == null ? "" : a.getHostAddress(); }
}
