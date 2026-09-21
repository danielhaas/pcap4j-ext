#!/usr/bin/env python3
"""
Compares our parsers against tshark, field by field.

Wireshark is an independent reading of the same bytes, which is the point: a test written by
whoever wrote the parser agrees with the parser's own misunderstandings. Run it over the
generated captures and over any real capture you have.

    javac -d /tmp/cd -cp "$(cat cp.txt)" tools/CrossDump.java
    python3 tools/crosscheck.py

One unknown -e field name makes tshark refuse the whole run, which would look like agreement,
so the script fails loudly instead.
"""
import json, subprocess, sys, collections

S = '/tmp/claude-1000/-home-daha-code-jiso/38eae4af-6af8-4835-a4e4-bb55793cd1d0/scratchpad'
CP = open(S + '/cp2.txt').read().strip()

# our key -> tshark field. A tuple means "any of these", for protocols whose
# version variants live under different field names in Wireshark.
MAP = {
 'hsrp.pcap': {'hsrp.opcode': ('hsrp.opcode','hsrp2.opcode'), 'hsrp.state': ('hsrp.state','hsrp2.state'),
               'hsrp.priority': ('hsrp.priority','hsrp2.priority'), 'hsrp.group': ('hsrp.group','hsrp2.group'),
               'hsrp.virt_ip': ('hsrp.virt_ip','hsrp2.virt_ip'), 'hsrp.auth': ('hsrp.auth_data','hsrp2.auth_data')},
 'vrrp.pcap': {'vrrp.version': 'vrrp.version', 'vrrp.vrid': 'vrrp.virt_rtr_id', 'vrrp.prio': 'vrrp.prio',
               'vrrp.count': 'vrrp.addr_count', 'vrrp.ip': ('vrrp.ip_addr','vrrp.ipv6_addr'),
               'vrrp.auth_type': 'vrrp.auth_type'},
 'lacp.pcap': {'lacp.actor.sysid': 'lacp.actor.sysid', 'lacp.actor.key': 'lacp.actor.key',
               'lacp.actor.port': 'lacp.actor.port', 'lacp.actor.state': 'lacp.actor.state',
               'lacp.partner.sysid': 'lacp.partner.sysid', 'lacp.partner.key': 'lacp.partner.key',
               'lacp.partner.port': 'lacp.partner.port'},
 'marker.pcap': {'marker.port': 'marker.requesterPort',
                 'marker.sysid': 'marker.requesterSystem', 'marker.xid': 'marker.requesterTransId'},
 'pagp.pcap': {'pagp.localdevid': 'pagp.localdevid', 'pagp.localport': 'pagp.localsentportifindex',
               'pagp.localgroup': 'pagp.localgroupcap', 'pagp.partnerdevid': 'pagp.partnerdevid',
               'pagp.devname': 'pagp.tlvdevname', 'pagp.portname': 'pagp.tlvportname'},
 'udld.pcap': {'udld.opcode': 'udld.opcode', 'udld.device': 'udld.device_id',
               'udld.port': 'udld.sent_through_interface'},
 'cgmp.pcap': {'cgmp.type': 'cgmp.type', 'cgmp.count': 'cgmp.count',
               'cgmp.group0': 'cgmp.gda', 'cgmp.host0': 'cgmp.usa'},
 'mld.pcap': {'mld.type': 'icmpv6.type', 'mld.group': 'icmpv6.mld.multicast_address',
              'mld.rec0': 'icmpv6.mldr.mar.multicast_address'},
 'lldp.pcap': {'lldp.chassis': 'lldp.chassis.id.mac', 'lldp.port': 'lldp.port.id',
               'lldp.ttl': 'lldp.time_to_live', 'lldp.sysname': 'lldp.tlv.system.name',
               'lldp.pvid': 'lldp.ieee.802_1.port_vlan.id'},
 'dhcp6.pcap': {'dhcpv6.msgtype': 'dhcpv6.msgtype', 'dhcpv6.xid': 'dhcpv6.xid',
                'dhcpv6.addr': 'dhcpv6.iaaddr.ip'},
 'igmp.pcap': {'igmp.type': 'igmp.type', 'igmp.version': 'igmp.version',
               'igmp.maddr': 'igmp.maddr', 'igmp.recs': 'igmp.num_grp_recs'},
 'vtp.pcap': {'vtp.version': 'vtp.version', 'vtp.code': 'vtp.code', 'vtp.domain': 'vtp.md',
              'vtp.rev': 'vtp.conf_rev_num', 'vtp.updater': 'vtp.upd_id',
              'vtp.vlan0.id': 'vtp.vlan_info.isl_vlan_id', 'vtp.vlan0.name': 'vtp.vlan_info.vlan_name'},
 '/home/daha/maren1.pcapng': {'cdp.deviceid': 'cdp.deviceid', 'cdp.portid': 'cdp.portid',
                             'cdp.nativevlan': 'cdp.native_vlan',
                             'dtp.domain': 'dtp.domain', 'dtp.tas': 'dtp.tas', 'dtp.tos': 'dtp.tos',
                             'vtp.domain': 'vtp.md', 'vtp.rev': 'vtp.conf_rev_num',
                             'vtp.updater': 'vtp.upd_id', 'vtp.version': 'vtp.version',
                             'dhcpv6.msgtype': 'dhcpv6.msgtype', 'dhcpv6.xid': 'dhcpv6.xid'},
 '/home/daha/fortina2.pcap': {'igmp.type': 'igmp.type', 'igmp.version': 'igmp.version',
                              'igmp.recs': 'igmp.num_grp_recs', 'igmp.rec0': 'igmp.maddr'},
}

def ours(pcap):
    out = subprocess.run(['java', '-cp', S + '/t:' + CP, 'CrossDump',
                          pcap if pcap.startswith('/') else S + '/' + pcap],
                         capture_output=True, text=True).stdout
    rows = {}
    for line in out.splitlines():
        n, _, rest = line.partition(' ')
        rows[int(n)] = dict(kv.split('=', 1) for kv in rest.split('|'))
    return rows

def theirs(pcap, mapping):
    """tshark's own reading, one row per packet. -T fields avoids the JSON nesting entirely."""
    names = []
    for value in mapping.values():
        names.extend(value if isinstance(value, tuple) else (value,))
    names = list(dict.fromkeys(names))
    args = ['tshark', '-r', pcap if pcap.startswith('/') else S + '/' + pcap,
            '-T', 'fields', '-e', 'frame.number']
    for n in names:
        args += ['-e', n]
    run = subprocess.run(args, capture_output=True, text=True)
    if run.returncode != 0 or 'was unexpected' in run.stderr or "aren't valid" in run.stderr:
        # one unknown field name makes tshark refuse the whole run, which would look like agreement
        raise SystemExit(f'tshark rejected the fields for {pcap}: {run.stderr.strip()[:200]}')
    out = run.stdout
    rows = {}
    for line in out.splitlines():
        cells = line.split('\t')
        if not cells or not cells[0].strip():
            continue
        row = {}
        for name, cell in zip(names, cells[1:]):
            if cell != '':
                row[name] = cell.split(',')[0]        # a repeated field: compare the first
        rows[int(cells[0])] = row
    return rows

def norm(v):
    s = str(v).strip().lower()
    if s.count(':') >= 2:
        # Java writes IPv6 out in full, Wireshark compresses it
        try:
            import ipaddress
            return str(ipaddress.ip_address(s))
        except ValueError:
            pass
    if s.startswith('0x'):
        try: return str(int(s, 16))
        except ValueError: return s
    try: return str(int(s))
    except ValueError: return s

total = agree = missing = 0
problems = []
per_capture = {}
for pcap, mapping in MAP.items():
    if not mapping: continue
    mine, theirs_rows = ours(pcap), theirs(pcap, mapping)
    for n, fields in sorted(mine.items()):
        their = theirs_rows.get(n, {})
        for key, value in fields.items():
            names = mapping.get(key)
            if names is None: continue
            if isinstance(names, str): names = (names,)
            found = next((their[x] for x in names if x in their), None)
            stats = per_capture.setdefault(pcap.split('/')[-1], collections.Counter())
            if found is None:
                missing += 1
                stats['missing:' + key] += 1
                continue
            total += 1
            stats['compared'] += 1
            if norm(found) == norm(value):
                agree += 1
            else:
                problems.append(f'{pcap} #{n} {key}: ours={value!r} tshark={found!r}')

print(f'compared {total} field values, {agree} agree, {len(problems)} differ, {missing} not exposed by tshark')
for name, stats in per_capture.items():
    gaps = sorted((k.split(':',1)[1], stats[k]) for k in stats if k.startswith('missing:'))
    detail = ', '.join(f'{k} x{n}' for k, n in gaps)
    print(f"  {name}: {stats['compared']} compared" + (f"; tshark had no value for {detail}" if gaps else ''))
for p in problems[:40]:
    print('  ' + p)
