#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
yokohama_kit.py -- configuration + service-injection toolkit for the
Yokohama Automated Maritime Logistics Terminal (Y-AMLT) Packet Tracer model.

Two responsibilities:

1.  IOS / ASA running-config generators (pure functions returning ``list[str]``).
    Every command emitted here is one Packet Tracer's IOS parser accepts and
    that the reference corpus attests (``tools/audit_ios_commands.py``).

2.  XML service injection for ``Server-PT`` / end devices: DNS zones, DHCP
    pools, HTTP/HTTPS, FTP accounts, NTP, Syslog, AAA (RADIUS), e-mail.  These
    live in ``<ENGINE>`` sub-elements rather than in ``RUNNINGCONFIG``, so they
    are written straight into the device element.

Element shapes were derived from Cisco's own PT 9.0.1 sample labs and from the
1,059-entry reference corpus.

Credentials
-----------
The ``enable secret`` / user secrets below are **real MD5-crypt hashes** of the
passwords documented in ``README.md`` and ``docs/DESIGN.md``.  A lab whose
credentials nobody can reproduce is a lab nobody can log into, so the plaintext
is published next to the hash and both are exercised by gate 5
(``tools/pt_runtime_verify.py --username ... --password ...``).
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

# --------------------------------------------------------------------------- #
# enterprise constants
# --------------------------------------------------------------------------- #
DOMAIN = "yokohama-amlc.example.jp"

# Service plane lives on VLAN 60 at the primary terminal data centre (site 11).
TDC = 11
NTP_PRIMARY = f"10.{TDC}.60.25"
NTP_SECONDARY = f"10.{TDC}.60.26"
SYSLOG_HOST = f"10.{TDC}.60.27"
AAA_HOST = f"10.{TDC}.60.28"
AAA_HOST2 = f"10.{TDC}.60.29"
DNS_PRIMARY = f"10.{TDC}.60.21"
DNS_SECONDARY = f"10.{TDC}.60.22"
TFTP_HOST = f"10.{TDC}.60.30"
WEB_HOST = f"10.{TDC}.60.45"
SNMP_RO = "YML-RO-4c1e"
SNMP_RW = "YML-RW-9b73"
SNMP_LOCATION = "Yokohama AMLC - Minami-Honmoku Pier"
SNMP_CONTACT = "YML Terminal NOC <noc@yokohama-amlc.example.jp>"

# Documented credentials (plaintext in README.md / docs/DESIGN.md).
ENABLE_SECRET = "5 $1$3a84$CdoPOjU5KMiie8weuVMSp/"          # "Yokohama#2026"
OPS_SECRET = "5 $1$fd2f$CZd/H1zlwACYTbCpZzysO1"             # "Ops#Terminal-2026"
AAA_KEY = "r4d1us-YML-2026-k3y"
TACACS_KEY = "t4c4cs-YML-2026-k3y"

# Autonomous systems
YML_ASN = 65100          # terminal operator
ISP_ASN = 65101          # carrier / transit
CUSTOMS_ASN = 65102      # Japan Customs / NACCS
RAIL_ASN = 65103         # rail operator
LINE_ASN = 65104         # shipping-line EDI community

# OSPF areas.  Area 0 is the terminal backbone; every operational zone is a
# stub area so a flapping yard block cannot inject external LSAs into the core.
AREA_BACKBONE = 0
AREA_TDC = 11
AREA_OPS = 20
AREA_APRON = 21
AREA_YARD = 30
AREA_AGV = 50
AREA_GATE = 55
AREA_RAIL = 60
AREA_OT = 90
AREA_EDGE = 100
AREA_NOC = 200

# --------------------------------------------------------------------------- #
# Which models carry an IOS/ASA running-config.
#
# This set is the definition of "a configured network device", and both the
# generator (to decide what must not carry a config) and validate.py (to decide
# what must) key off it.  Two tools answering that question from two different
# lists is how a statistic becomes unfalsifiable.
# --------------------------------------------------------------------------- #
NETWORK_DEVICE_MODELS = frozenset({
    "3650-24PS", "3560-24PS", "2960-24TT", "2950-24", "2950T-24",
    "2911", "2901", "1941", "1841", "2811", "ISR4331", "ISR4321",
    "5505", "IE-2000", "IE-3400", "IE-9320", "IR1101", "IR8340",
    "ISA-3000", "CGR1240", "WLC-3504", "WLC-2504", "Meraki-MX65W",
})

# --------------------------------------------------------------------------- #
# VLAN plan (shared by every switch and by the router-on-a-stick subinterfaces)
# --------------------------------------------------------------------------- #
V_OPS, V_TOS, V_VOICE, V_MGMT, V_WIFI, V_SRV = 10, 20, 30, 40, 50, 60
V_OT, V_CCTV, V_IOT, V_CUS, V_EDI, V_AGV = 70, 80, 90, 100, 110, 120
V_REEFER, V_RAIL, V_DG, V_GUEST = 130, 140, 150, 160

VLAN_NAMES = {
    V_OPS: "TERMINAL-OPS",
    V_TOS: "TOS-APP",
    V_VOICE: "RADIO-DISPATCH",
    V_MGMT: "MGMT-OOB",
    V_WIFI: "HANDHELD-WIFI",
    V_SRV: "SERVER-FARM",
    V_OT: "INDUSTRIAL-CTRL",
    V_CCTV: "CCTV-SECURITY",
    V_IOT: "IOT-SENSOR-MESH",
    V_CUS: "CUSTOMS-ENCLAVE",
    V_EDI: "EDI-PARTNER",
    V_AGV: "AGV-CONTROL",
    V_REEFER: "REEFER-MONITOR",
    V_RAIL: "RAIL-SIGNALLING",
    V_DG: "DANGEROUS-GOODS",
    V_GUEST: "CONTRACTOR-GUEST",
}

ALL_ZONE_VLANS = [V_OPS, V_TOS, V_VOICE, V_MGMT, V_WIFI, V_SRV, V_OT,
                  V_CCTV, V_IOT, V_AGV, V_REEFER]

# VLANs that carry industrial / OT control traffic and therefore get the
# low-latency treatment rather than the best-effort default.
OT_VLANS = (V_OT, V_AGV, V_RAIL, V_REEFER, V_CCTV)


# --------------------------------------------------------------------------- #
# generic helpers
# --------------------------------------------------------------------------- #
def _hdr(hostname: str, role: str,
         syslog: str = SYSLOG_HOST,
         aaa: str = AAA_HOST,
         ntp: str = NTP_PRIMARY,
         dns: str = DNS_PRIMARY,
         dns2: str = DNS_SECONDARY,
         snmp_location: str = SNMP_LOCATION) -> list[str]:
    """Common hardening / housekeeping preamble shared by routers and L3 switches."""
    return [
        "!",
        "service timestamps debug datetime msec localtime",
        "service timestamps log datetime msec localtime",
        "service password-encryption",
        "service tcp-keepalives-in",
        "service tcp-keepalives-out",
        "service sequence-numbers",
        "!",
        f"hostname {hostname}",
        "!",
        "boot-start-marker",
        "boot-end-marker",
        "!",
        "logging buffered 16384 debugging",
        "logging console critical",
        "logging synchronous",
        f"logging host {syslog}",
        "!",
        f"enable secret {ENABLE_SECRET}",
        f"username yml-admin privilege 15 secret {ENABLE_SECRET}",
        f"username yml-ops privilege 1 secret {OPS_SECRET}",
        "!",
        "! --- device administration: RADIUS first, local fallback ---",
        "aaa new-model",
        "aaa authentication login default group radius local",
        "aaa authentication enable default group radius enable",
        "aaa authorization exec default group radius local",
        "aaa authorization commands 15 default group radius local",
        "aaa accounting exec default start-stop group radius",
        "aaa accounting commands 15 default start-stop group radius",
        "aaa session-id common",
        f"radius-server host {aaa} auth-port 1645 acct-port 1646 key {AAA_KEY}",
        "radius-server retransmit 2",
        "radius-server timeout 3",
        "ip radius source-interface Loopback0",
        "!",
        "clock timezone JST 9",
        "!",
        f"ip domain-name {DOMAIN}",
        "ip domain-lookup",
        f"ip name-server {dns}",
        f"ip name-server {dns2}",
        "!",
        "ip cef",
        "no ip source-route",
        "no ip gratuitous-arps",
        "no ip bootp server",
        "no ip http server",
        "no ip http secure-server",
        "ip tcp synwait-time 10",
        "ip ssh time-out 60",
        "ip ssh authentication-retries 3",
        "ip ssh version 2",
        "!",
        "crypto key generate rsa modulus 2048",
        "!",
        f"ntp authentication-key 1 md5 {AAA_KEY}",
        "ntp authenticate",
        "ntp trusted-key 1",
        f"ntp server {ntp} key 1 source Loopback0 prefer",
        "ntp update-calendar",
        "!",
        "snmp-server ifindex persist",
        f"snmp-server community {SNMP_RO} RO",
        f"snmp-server community {SNMP_RW} RW",
        f"snmp-server location {snmp_location}",
        f"snmp-server contact {SNMP_CONTACT}",
        f"snmp-server host {syslog} version 2c {SNMP_RO}",
        "snmp-server enable traps snmp authentication linkdown linkup coldstart warmstart",
        "!",
        f"! role: {role}",
        "!",
    ]


def _banner(name: str, role: str, zone: str = "TERMINAL") -> list[str]:
    """MOTD banner.

    Deliberately avoids ``^C`` (0x03): a raw control byte is not valid XML 1.0
    and would corrupt the container.  ``#`` is a legal delimiter.
    """
    return [
        "banner motd #",
        "*" * 76,
        f"*  YOKOHAMA AUTOMATED MARITIME LOGISTICS TERMINAL -- {zone}",
        f"*  {name}",
        f"*  {role}",
        "*  RESTRICTED SYSTEM. Authorised terminal personnel only.",
        "*  All activity is monitored and logged to the Terminal NOC.",
        "*" * 76,
        "#",
    ]


AAA_LINE_BLOCK = [
    "line con 0",
    " exec-timeout 5 0",
    " logging synchronous",
    " login authentication default",
    "line aux 0",
    " exec-timeout 5 0",
    "line vty 0 4",
    " access-class 90 in",
    " exec-timeout 5 0",
    " logging synchronous",
    " login authentication default",
    " transport input ssh",
    "line vty 5 15",
    " access-class 90 in",
    " exec-timeout 5 0",
    " login authentication default",
    " transport input ssh",
    "!",
]


def mgmt_acl_lines() -> list[str]:
    """ACL 90 -- management-plane filter (vty access-class).

    Only the out-of-band NOC management plane and the terminal's own RFC1918
    space may open a vty.  Everything else is dropped and logged.
    """
    return [
        "ip access-list standard 90",
        " remark Y-AMLT management plane - NOC + terminal address space only",
        " permit 10.200.0.0 0.0.255.255",
        " permit 10.0.0.0 0.255.255.255",
        " deny   any log",
        "!",
    ]


def _lines(cfg: list[str]) -> list[str]:
    cfg += AAA_LINE_BLOCK
    return cfg


# --------------------------------------------------------------------------- #
# QoS -- the terminal's control plane
# --------------------------------------------------------------------------- #
def terminal_qos_lines() -> list[str]:
    """AGV control, crane control and terminal-ops priority treatment (LLQ + WRED).

    The terminal's hard real-time flows are the AGV guidance loop (a dropped
    packet is a stopped vehicle), the crane control loop, and the TOS job
    dispatch feed.  These are marked at the edge and serviced ahead of the bulk
    container-data and CCTV streams.
    """
    return [
        "class-map match-any CM-AGV-CONTROL",
        " match access-group name ACL-AGV-CONTROL",
        "class-map match-any CM-CRANE-CONTROL",
        " match access-group name ACL-CRANE-CONTROL",
        "class-map match-any CM-TOS-DISPATCH",
        " match access-group name ACL-TOS-DISPATCH",
        "class-map match-any CM-VOICE",
        " match access-group name ACL-VOICE",
        "!",
        "policy-map PM-YML-WAN",
        " class CM-AGV-CONTROL",
        "  priority 2048",
        "  set dscp cs5",
        " class CM-CRANE-CONTROL",
        "  priority 2048",
        "  set dscp cs5",
        " class CM-VOICE",
        "  priority 512",
        " class CM-TOS-DISPATCH",
        "  bandwidth remaining percent 40",
        "  random-detect dscp-based",
        " class class-default",
        "  fair-queue",
        "  random-detect",
        "!",
        "ip access-list extended ACL-AGV-CONTROL",
        " remark AGV guidance / fleet-dispatch loop (safety critical)",
        " permit udp any any range 5100 5110",
        " permit udp any any eq 5300",
        "ip access-list extended ACL-CRANE-CONTROL",
        " remark STS / RTG crane motion control (safety critical)",
        " permit udp any any range 4800 4810",
        " permit tcp any any eq 4840",
        "ip access-list extended ACL-TOS-DISPATCH",
        " remark Terminal Operating System work-queue traffic",
        " permit tcp any any eq 8443",
        " permit tcp any any eq 8080",
        " permit tcp any any eq 1521",
        "ip access-list extended ACL-VOICE",
        " remark radio dispatch / VoIP",
        " permit udp any any range 16384 32767",
        "!",
    ]


def industrial_qos_lines() -> list[str]:
    """Reduced QoS profile for IE-xxxx industrial switches (no LLQ on L2)."""
    return [
        "mls qos",
        "!",
        "class-map match-any CM-AGV-CONTROL",
        " match access-group name ACL-AGV-CONTROL",
        "class-map match-any CM-CRANE-CONTROL",
        " match access-group name ACL-CRANE-CONTROL",
        "!",
        "policy-map PM-YML-OT-EDGE",
        " class CM-AGV-CONTROL",
        "  set dscp cs5",
        " class CM-CRANE-CONTROL",
        "  set dscp cs5",
        " class class-default",
        "  set dscp default",
        "!",
        "ip access-list extended ACL-AGV-CONTROL",
        " permit udp any any range 5100 5110",
        " permit udp any any eq 5300",
        "ip access-list extended ACL-CRANE-CONTROL",
        " permit udp any any range 4800 4810",
        " permit tcp any any eq 4840",
        "!",
    ]


# --------------------------------------------------------------------------- #
# routers
# --------------------------------------------------------------------------- #
def router_config(name: str, role: str,
                  interfaces: list[tuple[str, str, str]],
                  loopback: str | None = None,
                  ospf: list[tuple[str, str, int]] | None = None,
                  default_area: int = AREA_BACKBONE,
                  ospf_passive_default: bool = True,
                  ospf_active: list[str] | None = None,
                  bgp: dict | None = None,
                  statics: list[tuple[str, str, str]] | None = None,
                  extra: list[str] | None = None,
                  qos: bool = True,
                  serial_clock: dict[str, int] | None = None,
                  asn: int = YML_ASN,
                  zone: str = "TERMINAL") -> list[str]:
    """Build a complete IOS running configuration for a Y-AMLT router.

    interfaces : ``(ifname, ip, mask)`` triples
    ospf       : ``(network, wildcard[, area])`` triples
    bgp        : ``{'router_id', 'networks':[(net,mask)], 'neighbors':[(ip,asn,desc)]}``
    statics    : ``(prefix, mask, next_hop)`` triples
    """
    cfg = _hdr(name, role)
    cfg += [f"! zone: {zone}", "!"]

    if loopback:
        cfg += ["interface Loopback0",
                f" description {role} router-id / OOB anchor",
                f" ip address {loopback} 255.255.255.255",
                " no shutdown", "!"]

    for ifname, ip, mask in interfaces:
        cfg += [f"interface {ifname}"]
        if ip and ip != "unnamed":
            cfg += [f" ip address {ip} {mask}"]
        cfg += [" no shutdown"]
        if ifname.startswith("Serial"):
            if serial_clock and ifname in serial_clock:
                cfg += [f" clock rate {serial_clock[ifname]}"]
        else:
            cfg += [" duplex auto", " speed auto"]
        cfg += ["!"]

    cfg += mgmt_acl_lines()

    if ospf:
        cfg += ["router ospf 1",
                f" router-id {loopback or interfaces[0][1]}",
                " auto-cost reference-bandwidth 10000"]
        if ospf_passive_default:
            cfg += [" passive-interface default"]
            for i in (ospf_active or []):
                cfg += [f" no passive-interface {i}"]
        for entry in ospf:
            net, wc = entry[0], entry[1]
            a = entry[2] if len(entry) > 2 else default_area
            cfg += [f" network {net} {wc} area {a}"]
        cfg += [" log-adjacency-changes detail", "!"]

    if statics:
        for pfx, mask, nh in statics:
            cfg += [f"ip route {pfx} {mask} {nh}"]
        cfg += ["!"]

    if bgp:
        cfg += [f"router bgp {asn}",
                f" bgp router-id {bgp['router_id']}",
                " bgp log-neighbor-changes",
                " no synchronization",
                " bgp graceful-restart restart-time 120"]
        for net, mask in bgp.get("networks", []):
            cfg += [f" network {net} mask {mask}"]
        for ip, asn_n, desc in bgp["neighbors"]:
            cfg += [f" neighbor {ip} remote-as {asn_n}",
                    f" neighbor {ip} description {desc}",
                    f" neighbor {ip} update-source Loopback0"]
        cfg += ["!"]

    if qos:
        cfg += terminal_qos_lines()

    if extra:
        cfg += extra

    cfg = _lines(cfg)
    cfg += _banner(name, role, zone)
    cfg += ["!", "end"]
    return cfg


# --------------------------------------------------------------------------- #
# switches
# --------------------------------------------------------------------------- #
def _vlan_block(vlans: list[int]) -> list[str]:
    out = ["!"] if vlans else []
    for v in vlans:
        out += [f"vlan {v}", f" name {VLAN_NAMES.get(v, f'VLAN{v}')}"]
    return out


def l2_switch_config(name: str, role: str, vlans: list[int],
                     mgmt: tuple[str, str] | None = None,
                     mgmt_vlan: int = V_MGMT,
                     uplinks: list[str] | None = None,
                     access_ports: dict[str, int] | None = None,
                     stp_root: list[int] | None = None,
                     zone: str = "TERMINAL") -> list[str]:
    """Access-layer switch: VLANs, trunk uplinks, access ports, STP hardening."""
    cfg = [
        "!",
        "service timestamps debug datetime msec localtime",
        "service timestamps log datetime msec localtime",
        "service password-encryption",
        "service sequence-numbers",
        "!",
        f"hostname {name}",
        "!",
        "no ip domain-lookup",
        f"ip domain-name {DOMAIN}",
        f"enable secret {ENABLE_SECRET}",
        "!",
        "vtp mode transparent",
        "vtp domain YML-TERMINAL",
        "!",
    ]
    cfg += _vlan_block(vlans)
    cfg += [
        "!",
        "spanning-tree mode rapid-pvst",
        "spanning-tree extend system-id",
        "spanning-tree portfast bpduguard default",
        "spanning-tree loopguard default",
        "!",
    ]
    for v in (stp_root or []):
        cfg += [f"spanning-tree vlan {v} root primary"]
    if stp_root:
        cfg += ["!"]

    if mgmt:
        ip, mask = mgmt
        cfg += [f"interface Vlan{mgmt_vlan}",
                f" description out-of-band management",
                f" ip address {ip} {mask}",
                " no shutdown", "!"]
        cfg += [f"ip default-gateway {_gw(ip)}"]

    for i, u in enumerate(uplinks or []):
        cfg += [f"interface {u}",
                " description uplink trunk",
                " switchport trunk encapsulation dot1q",
                " switchport mode trunk",
                " switchport trunk native vlan 999",
                " switchport trunk allowed vlan " + ",".join(str(v) for v in vlans),
                " no shutdown", "!"]

    for port, v in (access_ports or {}).items():
        cfg += [f"interface {port}",
                f" description access vlan {v} ({VLAN_NAMES.get(v, v)})",
                " switchport mode access",
                f" switchport access vlan {v}",
                " switchport port-security",
                " switchport port-security maximum 3",
                " switchport port-security violation restrict",
                " switchport port-security aging time 10",
                " spanning-tree portfast",
                " spanning-tree bpduguard enable",
                " no shutdown", "!"]

    cfg += [
        "line con 0",
        " exec-timeout 5 0",
        " logging synchronous",
        "line vty 0 4",
        " access-class 90 in",
        " exec-timeout 5 0",
        " login local",
        " transport input ssh",
        "line vty 5 15",
        " access-class 90 in",
        " exec-timeout 5 0",
        " login local",
        " transport input ssh",
        "!",
        "ip access-list standard 90",
        " permit 10.200.0.0 0.0.255.255",
        " permit 10.0.0.0 0.255.255.255",
        " deny   any log",
        "!",
        "ntp server " + NTP_PRIMARY,
        f"logging host {SYSLOG_HOST}",
        "!",
        "end",
    ]
    cfg = [f"! role: {role}", f"! zone: {zone}"] + cfg
    return cfg


def l3_switch_config(name: str, role: str, vlans: list[int],
                     svis: dict[int, tuple[str, str]],
                     loopback: str | None,
                     ospf: list[tuple[str, str, int]] | None = None,
                     default_area: int = AREA_BACKBONE,
                     hsrp: dict[int, tuple[int, str]] | None = None,
                     trunks: list[str] | None = None,
                     access_ports: dict[str, int] | None = None,
                     routed_ports: list[tuple[str, str, str]] | None = None,
                     ospf_active: list[str] | None = None,
                     ip_routing: bool = True,
                     zone: str = "TERMINAL",
                     asn: int = YML_ASN,
                     bgp: dict | None = None) -> list[str]:
    """Multilayer switch config: SVIs, routed WAN ports, OSPF, optional HSRP.

    hsrp : ``{vlan: (group, virtual_ip)}`` -- the SVI keeps its own address and
           gains a standby group, which is how every redundant zone pair in the
           terminal provides a first-hop gateway.
    """
    cfg = [
        "!",
        "service timestamps debug datetime msec localtime",
        "service timestamps log datetime msec localtime",
        "service password-encryption",
        "service sequence-numbers",
        "!",
        f"hostname {name}",
        "!",
        "no ip domain-lookup",
        f"ip domain-name {DOMAIN}",
        f"enable secret {ENABLE_SECRET}",
        f"username yml-admin privilege 15 secret {ENABLE_SECRET}",
        "!",
        "vtp mode transparent",
        "vtp domain YML-TERMINAL",
        "!",
    ]
    if ip_routing:
        cfg += ["ip routing", "!"]
    cfg += _vlan_block(vlans)
    cfg += [
        "!",
        "spanning-tree mode rapid-pvst",
        "spanning-tree extend system-id",
        "spanning-tree portfast bpduguard default",
        "!",
    ]

    if loopback:
        cfg += ["interface Loopback0",
                f" description {role} router-id",
                f" ip address {loopback} 255.255.255.255",
                " no shutdown", "!"]

    for v, (ip, mask) in sorted(svis.items()):
        cfg += [f"interface Vlan{v}",
                f" description {VLAN_NAMES.get(v, f'VLAN{v}')} gateway",
                f" ip address {ip} {mask}"]
        if hsrp and v in hsrp:
            grp, vip = hsrp[v]
            cfg += [f" standby {grp} ip {vip}",
                    f" standby {grp} priority 110",
                    f" standby {grp} preempt",
                    f" standby {grp} track 1 decrement 20"]
        cfg += [" no shutdown", "!"]

    if hsrp:
        cfg += ["track 1 interface GigabitEthernet0/1 line-protocol", "!"]

    for ifname, ip, mask in (routed_ports or []):
        cfg += [f"interface {ifname}",
                " description routed uplink",
                " no switchport",
                f" ip address {ip} {mask}",
                " no shutdown", "!"]

    for t in (trunks or []):
        cfg += [f"interface {t}",
                " description downlink trunk",
                " switchport trunk encapsulation dot1q",
                " switchport mode trunk",
                " switchport trunk native vlan 999",
                " switchport trunk allowed vlan " + ",".join(str(v) for v in vlans),
                " no shutdown", "!"]

    for port, v in (access_ports or {}).items():
        cfg += [f"interface {port}",
                f" switchport mode access",
                f" switchport access vlan {v}",
                " spanning-tree portfast",
                " spanning-tree bpduguard enable",
                " no shutdown", "!"]

    cfg += mgmt_acl_lines()

    if ospf:
        cfg += ["router ospf 1",
                f" router-id {loopback or '0.0.0.0'}",
                " auto-cost reference-bandwidth 10000",
                " passive-interface default"]
        for i in (ospf_active or []):
            cfg += [f" no passive-interface {i}"]
        for entry in ospf:
            net, wc = entry[0], entry[1]
            a = entry[2] if len(entry) > 2 else default_area
            cfg += [f" network {net} {wc} area {a}"]
        cfg += [" log-adjacency-changes detail", "!"]

    if bgp:
        cfg += [f"router bgp {asn}",
                f" bgp router-id {bgp['router_id']}",
                " bgp log-neighbor-changes",
                " no synchronization"]
        for net, mask in bgp.get("networks", []):
            cfg += [f" network {net} mask {mask}"]
        for ip, asn_n, desc in bgp["neighbors"]:
            cfg += [f" neighbor {ip} remote-as {asn_n}",
                    f" neighbor {ip} description {desc}",
                    f" neighbor {ip} update-source Loopback0"]
        cfg += ["!"]

    cfg += AAA_LINE_BLOCK
    cfg += _banner(name, role, zone)
    cfg += ["!", "end"]
    return [f"! role: {role}", f"! zone: {zone}"] + cfg


def industrial_switch_config(name: str, role: str, vlans: list[int],
                             mgmt: tuple[str, str] | None = None,
                             mgmt_vlan: int = V_MGMT,
                             uplinks: list[str] | None = None,
                             access_ports: dict[str, int] | None = None,
                             stp_priority: int | None = None,
                             zone: str = "OT") -> list[str]:
    """IE-2x00 / IE-3x00 / IE-9320 industrial switch.

    Same shape as the office access switch, plus the OT hardening an industrial
    Ethernet segment needs: storm control on every access port (a broadcast
    storm on a crane segment stops container handling), and no VTP client
    behaviour.  ``mac address-table static`` entries are deliberately not
    emitted: the terminal's OT addressing is DHCP-reserved, not static.
    """
    cfg = [
        "!",
        "service timestamps debug datetime msec localtime",
        "service timestamps log datetime msec localtime",
        "service password-encryption",
        "service sequence-numbers",
        "!",
        f"hostname {name}",
        "!",
        "no ip domain-lookup",
        f"ip domain-name {DOMAIN}",
        f"enable secret {ENABLE_SECRET}",
        "!",
        "vtp mode transparent",
        "!",
    ]
    cfg += _vlan_block(vlans)
    cfg += [
        "!",
        "spanning-tree mode rapid-pvst",
        "spanning-tree extend system-id",
        "spanning-tree portfast bpduguard default",
        "!",
    ]
    if stp_priority is not None:
        cfg += ["spanning-tree vlan " + ",".join(str(v) for v in vlans) +
                f" priority {stp_priority}", "!"]

    if mgmt:
        ip, mask = mgmt
        cfg += [f"interface Vlan{mgmt_vlan}",
                " description industrial switch management",
                f" ip address {ip} {mask}",
                " no shutdown", "!"]
        cfg += [f"ip default-gateway {_gw(ip)}", "!"]

    for u in (uplinks or []):
        cfg += [f"interface {u}",
                " description OT uplink trunk",
                " switchport trunk encapsulation dot1q",
                " switchport mode trunk",
                " switchport trunk native vlan 999",
                " switchport trunk allowed vlan " + ",".join(str(v) for v in vlans),
                " storm-control broadcast level 5.00",
                " storm-control multicast level 5.00",
                " no shutdown", "!"]

    for port, v in (access_ports or {}).items():
        cfg += [f"interface {port}",
                f" description OT access vlan {v} ({VLAN_NAMES.get(v, v)})",
                " switchport mode access",
                f" switchport access vlan {v}",
                " switchport port-security",
                " switchport port-security maximum 2",
                " switchport port-security violation restrict",
                " spanning-tree portfast",
                " spanning-tree bpduguard enable",
                " storm-control broadcast level 2.00",
                " storm-control action shutdown",
                " no shutdown", "!"]

    cfg += industrial_qos_lines()
    cfg += [
        "line con 0",
        " exec-timeout 10 0",
        " logging synchronous",
        "line vty 0 4",
        " access-class 90 in",
        " exec-timeout 10 0",
        " login local",
        " transport input ssh",
        "!",
        "ip access-list standard 90",
        " permit 10.200.0.0 0.0.255.255",
        " permit 10.0.0.0 0.255.255.255",
        " deny   any log",
        "!",
        f"ntp server {NTP_PRIMARY}",
        f"logging host {SYSLOG_HOST}",
        "!",
        "end",
    ]
    return [f"! role: {role}", f"! zone: {zone}"] + cfg


def plc_config(name: str, role: str, ip: str, mask: str, gateway: str,
               zone: str = "OT") -> list[str]:
    """Config for the PLC / MCU-class controller line (PT models them as IOS-like).

    Packet Tracer's PLC-PT and MCU-PT accept a small IOS subset; this emits only
    commands they parse, and no routing protocol -- an OT controller is an end
    station on the industrial segment, never a transit hop.
    """
    return [
        "!",
        f"hostname {name}",
        "!",
        "no ip domain-lookup",
        f"ip domain-name {DOMAIN}",
        "!",
        f"! role: {role}",
        f"! zone: {zone}",
        "!",
        f"ip address {ip} {mask}",
        f"ip default-gateway {gateway}",
        "!",
        f"ntp server {NTP_PRIMARY}",
        f"logging host {SYSLOG_HOST}",
        "no ip http server",
        "!",
        "end",
    ]


def _gw(ip: str) -> str:
    """Last octet -> 1 (the SVI/HSRP address of the segment)."""
    o = ip.split(".")
    return ".".join(o[:3] + ["1"])


# --------------------------------------------------------------------------- #
# ASA firewalls
# --------------------------------------------------------------------------- #
def asa_config(name: str, role: str,
               zones: list[dict],
               acls: list[str] | None = None,
               statics: list[tuple[str, str, str]] | None = None,
               routes: list[tuple[str, str, str]] | None = None,
               bgp: dict | None = None) -> list[str]:
    """ASA 5505 config.

    zones: list of ``{'vlan', 'nameif', 'sec', 'ip', 'mask', 'ports', 'dhcp'}``
    """
    zoned_ports = {p for z in zones for p in z["ports"]}
    cfg = [
        "!",
        f"hostname {name}",
        "enable password 8Ry2YjIyt7RRXU24 encrypted",
        "passwd 2KFQnbNIdI.2KYOU encrypted",
        "names",
        "!",
        f"! role: {role}",
        "!",
    ]
    for z in zones:
        for p in z["ports"]:
            cfg += [f"interface {p}", f" switchport access vlan {z['vlan']}", "!"]
    for z in zones:
        cfg += [f"interface Vlan{z['vlan']}",
                f" nameif {z['nameif']}",
                f" security-level {z['sec']}"]
        if z.get("dhcp"):
            cfg += [" ip address dhcp"]
        else:
            cfg += [f" ip address {z['ip']} {z['mask']}"]
        cfg += ["!"]
    # Shut only the ports no zone claims.  A blanket `interface Ethernet0/0 /
    # shutdown` also shuts the *outside* port, which is how every firewall in an
    # earlier build shipped with its uplink administratively down.
    for p in (f"Ethernet0/{i}" for i in range(8)):
        if p not in zoned_ports:
            cfg += [f"interface {p}", " shutdown", "!"]
    cfg += [
        "boot system disk0:/asa981-lbf.sbin",
        "ftp mode passive",
        "clock timezone JST 9",
        "!",
        f"dns domain-lookup outside",
        f"dns server-group DefaultDNS",
        f" name-server {DNS_PRIMARY}",
        f" name-server {DNS_SECONDARY}",
        f" domain-name {DOMAIN}",
        "!",
        "object network YML-ANY",
        " subnet 0.0.0.0 0.0.0.0",
        "!",
        f"logging enable",
        f"logging timestamp",
        f"logging buffered informational",
        f"logging host inside {SYSLOG_HOST}",
        "!",
        f"ntp server {NTP_PRIMARY} source inside",
        "ntp authenticate",
        "ntp authentication-key 1 md5 " + AAA_KEY,
        "ntp trusted-key 1",
        "!",
        "snmp-server host inside " + SYSLOG_HOST + " community " + SNMP_RO,
        f"snmp-server location {SNMP_LOCATION}",
        f"snmp-server contact {SNMP_CONTACT}",
        "!",
        "aaa-server RADIUS protocol radius",
        f"aaa-server RADIUS (inside) host {AAA_HOST}",
        f" key {AAA_KEY}",
        "!",
        "aaa authentication ssh console RADIUS LOCAL",
        "aaa authorization exec authentication-server",
        "!",
        "username yml-admin password " + ENABLE_SECRET.split()[-1] + " encrypted privilege 15",
        "!",
    ]
    for z in zones:
        cfg += [f"icmp permit any {z['nameif']}"]
    cfg += ["!"]

    if acls:
        cfg += acls

    for s in (statics or []):
        cfg += [f"object network OBJ-{s[0].replace('.', '_').replace('/', '_')}",
                f" host {s[0]}",
                f" nat (inside,outside) static {s[2]}"]

    if routes:
        for pfx, mask, nh in routes:
            cfg += [f"route outside {pfx} {mask} {nh}"]

    if bgp:
        cfg += ["router bgp " + str(bgp["asn"]),
                " bgp router-id " + bgp["router_id"],
                " address-family ipv4 unicast",
                "  no auto-summary",
                "  no synchronization"]
        for net, mask in bgp.get("networks", []):
            cfg += [f"  network {net} mask {mask}"]
        for ip, asn_n, desc in bgp.get("neighbors", []):
            cfg += [f"  neighbor {ip} remote-as {asn_n}",
                    f"  neighbor {ip} description {desc}",
                    f"  neighbor {ip} activate"]
        cfg += [" exit-address-family", "!"]

    cfg += [
        "class-map inspection_default",
        " match default-inspection-traffic",
        "!",
        "policy-map global_policy",
        " class inspection_default",
        "  inspect dns preset_dns_map",
        "  inspect ftp",
        "  inspect h323 h225",
        "  inspect icmp",
        "  inspect icmp error",
        "  inspect netbios",
        "  inspect rsh",
        "  inspect rtsp",
        "  inspect skinny",
        "  inspect esmtp",
        "  inspect sqlnet",
        "  inspect sunrpc",
        "  inspect tftp",
        "  inspect sip",
        "  inspect xdmcp",
        "!",
        "service-policy global_policy global",
        "!",
        "telnet timeout 5",
        "ssh timeout 10",
        "ssh version 2",
        "!",
        "console timeout 0",
        "!",
        "class-map type management global-policy",
        "!",
        f"crypto key generate rsa modulus 2048",
        "!",
        "end",
    ]
    return cfg


def customs_acl_lines() -> list[str]:
    """The customs enclave's boundary policy, as an ASA access list.

    A port terminal's customs zone is not merely "another VLAN": it holds the
    manifest database and the NACCS link, and the only traffic that may cross is
    the declared message set.  Everything else is denied and logged.
    """
    return [
        "! --- customs enclave boundary ---",
        "access-list CUSTOMS-IN extended permit tcp 10.11.0.0 255.255.0.0 "
        "172.20.10.0 255.255.255.0 eq 1521",
        "access-list CUSTOMS-IN extended permit tcp 10.11.0.0 255.255.0.0 "
        "172.20.10.0 255.255.255.0 eq 8443",
        "access-list CUSTOMS-IN extended permit tcp 10.11.0.0 255.255.0.0 "
        "172.20.20.0 255.255.255.0 eq 9443",
        "access-list CUSTOMS-IN extended deny ip any any log",
        "access-list CUSTOMS-OUT extended permit tcp 172.20.0.0 255.255.0.0 "
        "198.51.100.0 255.255.255.0 eq 443",
        "access-list CUSTOMS-OUT extended permit tcp 172.20.0.0 255.255.0.0 "
        "203.0.113.0 255.255.255.0 eq 443",
        "access-list CUSTOMS-OUT extended deny ip any any log",
        "!",
    ]


# --------------------------------------------------------------------------- #
# Server-PT / end-device service injection
# --------------------------------------------------------------------------- #
def _child(parent: ET.Element, tag: str) -> ET.Element:
    e = parent.find(tag)
    if e is None:
        e = ET.SubElement(parent, tag)
    return e


def _set(parent: ET.Element, tag: str, text) -> ET.Element:
    e = _child(parent, tag)
    e.text = str(text)
    return e


def _clear(parent: ET.Element, tag: str) -> ET.Element:
    e = _child(parent, tag)
    for c in list(e):
        e.remove(c)
    return e


#: Every service block a Server-PT device can carry.  ``configure_server``
#: clears all of them before writing the requested ones, and
#: ``build_yokohama_amlc.strip_unconfigured_services`` removes them from devices
#: that were given no service at all.  One list, used by both, so a device can
#: never advertise a service nobody authored -- a harvested template ships these
#: blocks already marked <ENABLED>1</ENABLED>, which is how 52 devices in an
#: early build claimed to be NTP servers.
SERVICE_BLOCKS = ("DNS_SERVER", "DHCP_SERVERS", "ACS_SERVER", "NTP_SERVER",
                  "SYSLOG_SERVER", "HTTP_SERVER", "HTTPS_SERVER",
                  "FTP_SERVER", "EMAIL_SERVER")


def _strip_service_blocks(eng: ET.Element) -> int:
    """Remove every service block from an ENGINE, wherever it is nested."""
    n = 0
    for tag in SERVICE_BLOCKS:
        for parent in list(eng.iter()):
            for el in list(parent.findall(tag)):
                parent.remove(el)
                n += 1
    return n


def configure_server(dev_el: ET.Element, *,
                     dns_records: list[tuple[str, str]] | None = None,
                     dhcp_pools: list[dict] | None = None,
                     http: bool = False, http_user: str = "", http_pass: str = "",
                     https: bool = False,
                     ftp_user: str | None = None, ftp_pass: str = "cisco",
                     ntp: bool = False,
                     syslog: bool = False,
                     email: bool = False,
                     aaa_users: list[tuple[str, str]] | None = None,
                     aaa_clients: list[tuple[str, str, str]] | None = None,
                     email_domain: str | None = None,
                     iface: str = "FastEthernet0") -> None:
    """Write Server-PT service configuration into the device's ``<ENGINE>``.

    Only the services explicitly requested are written.  A harvested Server-PT
    template arrives carrying whatever the save it came from had configured, so
    every caller must go through this function rather than inheriting it (see
    ``build_yokohama_amlc.strip_template_leftovers``).
    """
    eng = dev_el.find("ENGINE")
    if eng is None:
        return
    _strip_service_blocks(eng)

    if https:
        _set(_child(eng, "HTTPS_SERVER"), "HTTPSENABLED", 1)
    if http:
        h = _child(eng, "HTTP_SERVER")
        _set(h, "ENABLED", 1)
        _set(h, "USERNAME", http_user)
        _set(h, "PASSWORD", http_pass)

    if dns_records is not None:
        d = _child(eng, "DNS_SERVER")
        _set(d, "ENABLED", 1)
        db = _clear(d, "NAMESERVER-DATABASE")
        for name, ip in dns_records:
            r = ET.SubElement(db, "RESOURCE-RECORD")
            ET.SubElement(r, "TYPE").text = "A-REC"
            ET.SubElement(r, "NAME").text = name
            ET.SubElement(r, "TTL").text = "86400"
            ET.SubElement(r, "IPADDRESS").text = ip

    if dhcp_pools:
        wrap = _child(eng, "DHCP_SERVERS")
        ports = _clear(wrap, "ASSOCIATED_PORTS")
        for pool in dhcp_pools:
            ap = ET.SubElement(ports, "ASSOCIATED_PORT")
            ET.SubElement(ap, "NAME").text = pool.get("iface", iface)
            srv = ET.SubElement(ap, "DHCP_SERVER")
            ET.SubElement(srv, "ENABLED").text = "1"
            pools = ET.SubElement(srv, "POOLS")
            p = ET.SubElement(pools, "POOL")
            ET.SubElement(p, "NAME").text = pool["name"]
            ET.SubElement(p, "NETWORK").text = pool["network"]
            ET.SubElement(p, "MASK").text = pool["mask"]
            ET.SubElement(p, "DEFAULT_ROUTER").text = pool["router"]
            ET.SubElement(p, "TFTP_ADDRESS").text = pool.get("tftp", TFTP_HOST)
            ET.SubElement(p, "START_IP").text = pool["start"]
            ET.SubElement(p, "END_IP").text = pool["end"]
            ET.SubElement(p, "DNS_SERVER").text = pool.get("dns", DNS_PRIMARY)
            ET.SubElement(p, "MAX_USERS").text = str(pool.get("max", 512))
            ET.SubElement(p, "DOMAIN_NAME").text = pool.get("domain", DOMAIN)
            ET.SubElement(p, "DHCP_POOL_LEASES")
            ET.SubElement(p, "LEASE_TIME").text = str(pool.get("lease", 86400000))
            ET.SubElement(p, "WLC_ADDRESS").text = "0.0.0.0"
            ET.SubElement(srv, "DHCP_RESERVATIONS")
            ET.SubElement(srv, "AUTOCONFIG")

    if ftp_user:
        f = _child(eng, "FTP_SERVER")
        _set(f, "ENABLED", 1)
        m = _clear(f, "USER_ACCOUNT_MNGR")
        a = ET.SubElement(m, "ACCOUNT")
        ET.SubElement(a, "USERNAME").text = ftp_user
        ET.SubElement(a, "PASSWORD").text = ftp_pass
        ET.SubElement(a, "PERMISSIONS").text = "RWDNL"

    if ntp:
        n = _child(eng, "NTP_SERVER")
        _set(n, "ENABLED", 1)
        _set(n, "ENABLED_SERVER_AUTHENTICATE", 0)
        _set(n, "KEY", 1)
        _set(n, "MD5PASSWORD", AAA_KEY)

    if syslog:
        _set(_child(eng, "SYSLOG_SERVER"), "ENABLED", 1)

    if aaa_users is not None or aaa_clients is not None:
        s = _child(eng, "ACS_SERVER")
        _set(s, "ENABLED", 1)
        us = _clear(s, "USERS")
        for u, p in (aaa_users or []):
            x = ET.SubElement(us, "USER")
            ET.SubElement(x, "NAME").text = u
            ET.SubElement(x, "PASSWORD").text = p
            ET.SubElement(x, "DESCRIPTION").text = "Y-AMLT privileged operator"
        cs = _clear(s, "ACS_CLIENTS")
        for ip, key, desc in (aaa_clients or []):
            c = ET.SubElement(cs, "CLIENT")
            ET.SubElement(c, "HOST_IP").text = ip
            ET.SubElement(c, "KEY").text = key
            ET.SubElement(c, "DESCRIPTION").text = desc
            ET.SubElement(c, "SERVER_TYPE").text = "RADIUS"
        rs = _child(s, "RADIUS_SETTINGS")
        _set(rs, "AUTH_PORT", 1645)

    if email or email_domain:
        e = _child(eng, "EMAIL_SERVER")
        _set(e, "SMTP_ENABLED", 1)
        _set(e, "SMTP_DOMAIN", email_domain or DOMAIN)
        _set(e, "POP3_ENABLED", 1)
        _set(e, "FORWARD_MAIL", 0)
        _set(e, "NO_OF_USERS", 0)
