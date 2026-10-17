#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
build_iruma_ab.py -- generate a large, fully-configured Cisco Packet Tracer
model of **JASDF Iruma Air Base** (入間基地), Sayama/Iruma, Saitama -- the
largest JASDF base by personnel, home of the Central Air Defence Force, the
Central Aircraft Control & Warning Wing, the Air Rescue Wing, the 2nd Tactical
Airlift Group and two air depots.

    python3 build_iruma_ab.py --profile enterprise --out out/IRUMA_AB.pkt

Architecture modelled (the shape a JASDF air base's ICT estate actually has):

    Carrier & external liaison edge ...... commercial transit, MoD backbone,
                                           Yokota AB approach/departure control,
                                           JWS-II weather feed, prefectural
                                           police air corps, SIGINT detachment
    Base backbone & NetOps ............... dual collapsed core + core routers
                                           + dual WAN edge (OSPF area 0)
    Air defence & mission data centre .... spine/leaf + core services + CADF /
                                           CACW / OSW mission applications
    Backup data centre ................... standby twin over a DCI link
    Operations-security enclave .......... isolated 172.21/16 zone: mission
                                           database, crypto gateway, HSM,
                                           WORM audit log, IDS, capture tap
    Air Operations Centre / tower ........ CADF HQ operations, tower positions,
                                           ground movement, flight data
    Air traffic control & navaids ........ GCA radar, TACAN YLT, ILS 17/35,
                                           runway / taxiway / approach lighting,
                                           ATIS, statutory voice recording
    Tenant squadrons & hangars ........... 402SQ, Iruma Helicopter Airlift Sqn,
                                           Flight Check Sqn, CADF HQ Support
                                           Flight, EWC, Patriot group, CACE,
                                           ASAR, district police, SIGINT, and
                                           the JSDF Iruma Hospital
    Apron, flight line & vehicles ........ west/north apron, helipad dispersal
                                           and the police heliport; GSE, hot
                                           refuelling, ARFF, bird control,
                                           runway sweep, ground vehicles
    Air Weather Squadron ................. forecasting, observation, JWS-II
                                           client and the surface sensor field
    Air depots & POL ..................... 3rd Air Depot (comms/electronics and
                                           meteorological materiel), 4th Air
                                           Depot supply, bulk fuel farm
    Security, utilities & wireless ....... perimeter CCTV/IDS/access control,
                                           substation and standby power OT,
                                           WLAN controllers and outdoor APs
    Mobile estate ........................ EFB tablets, handsets

Everything is generated: placement (through ``lab_api.Layout``), modules,
cabling, complete IOS and ASA running-configurations, Server-PT services
(DNS/DHCP/AAA/NTP/syslog/HTTP/FTP), and end-device addressing.

What is sourced and what is modelled
------------------------------------
Unit names, abbreviations, aircraft types, the single runway (17/35,
2,000 x 45 m), the TACAN ident ``YLT``, the radio-frequency plan and the tenant
list come from the sources listed in ``docs/iruma/EVIDENCE.md``.  Several
facilities every air base has -- the control tower, the fuel farm, ammunition
storage, the ARFF station and a passenger terminal -- could **not** be sourced
for Iruma specifically; they are modelled from JASDF convention and flagged as
such in the design document rather than presented as fact.  No United States
unit is modelled as based here: the 1987 arrangement was temporary joint use
administered as part of Yokota AB, and no US flying unit is based at Iruma.
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent))
from iruma_paths import bootstrap as _bootstrap            # noqa: E402
TOOLKIT = _bootstrap()
for _p in (str(ROOT), str(TOOLKIT), str(TOOLKIT / "tools"), str(TOOLKIT / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import lab_api                        # noqa: E402
from pkt_core import decode_bytes     # noqa: E402
import iruma_kit as K                 # noqa: E402
from iruma_tiers import section_of     # noqa: E402

NETWORK_DEVICE_MODELS = K.NETWORK_DEVICE_MODELS

M24 = "255.255.255.0"
M30 = "255.255.255.252"

# --------------------------------------------------------------------------- #
# scale profiles
# --------------------------------------------------------------------------- #
PROFILES = {
    "smoke": dict(tenants_full=2, tenants_light=2, apron=2, depot_terms=4,
                  tanks=3, aps=6, cams=6, clients=8, apps=8, vehicles=4),
    "standard": dict(tenants_full=3, tenants_light=4, apron=3, depot_terms=6,
                     tanks=5, aps=9, cams=9, clients=12, apps=12, vehicles=6),
    "enterprise": dict(tenants_full=4, tenants_light=5, apron=4, depot_terms=8,
                       tanks=6, aps=12, cams=12, clients=15, apps=15,
                       vehicles=8),
}

# --------------------------------------------------------------------------- #
# site numbering -- the second octet of 10.<site>.<vlan>.0/24
# --------------------------------------------------------------------------- #
S_CORE = 10          # base backbone / transport      (loopbacks 10.255.x.x)
S_MDC = 11           # air defence & mission data centre
S_BDC = 12           # backup data centre
S_OPSEC = 13         # operations-security enclave (addressed out of 172.21/16)
S_AOC = 20           # air operations centre / control tower
S_ATC = 21           # air traffic control & navaids
S_WX = 25            # air weather squadron
S_TNT0 = 30          # tenant complexes -> 30, 31, 32, ...
S_HOSP = 44          # JSDF Iruma Hospital
S_APRON0 = 45        # apron and flight line
S_DEP0 = 55          # air depots
S_POL = 60           # bulk fuel farm (POL)
S_SEC = 70           # security forces
S_UTIL = 75          # utilities / standby power OT
S_WLAN = 80          # wireless infrastructure
S_EDGE = 100         # carrier + external liaison edge
S_NOC = 200          # NetOps / out-of-band management

OPSEC_NET = "172.21"
OPSEC_SITE = 30      # the enclave's own VLAN-30-equivalent inside 172.21/16

# --------------------------------------------------------------------------- #
# addressing helpers
# --------------------------------------------------------------------------- #
net = lambda s, v: f"10.{s}.{v}.0"            # noqa: E731
gw = lambda s, v: f"10.{s}.{v}.1"             # noqa: E731
host = lambda s, v, h: f"10.{s}.{v}.{h}"      # noqa: E731

# Mission data-centre service addresses (VLAN 60 @ site 11)
SRV = {
    "dns":        host(S_MDC, K.V_SRV, 21),
    "dns2":       host(S_MDC, K.V_SRV, 22),
    "dhcp":       host(S_MDC, K.V_SRV, 23),
    "dhcp2":      host(S_MDC, K.V_SRV, 24),
    "ntp":        host(S_MDC, K.V_SRV, 25),
    "ntp2":       host(S_MDC, K.V_SRV, 26),
    "syslog":     host(S_MDC, K.V_SRV, 27),
    "syslog2":    host(S_MDC, K.V_SRV, 28),
    "aaa":        host(S_MDC, K.V_SRV, 29),
    "aaa2":       host(S_MDC, K.V_SRV, 30),
    "tftp":       host(S_MDC, K.V_SRV, 31),
    "sortie":     host(S_MDC, K.V_SRV, 41),
    "mission":    host(S_MDC, K.V_SRV, 42),
    "ato":        host(S_MDC, K.V_SRV, 43),
    "mxmis":      host(S_MDC, K.V_SRV, 44),
    "supply":     host(S_MDC, K.V_SRV, 45),
    "fltrec":     host(S_MDC, K.V_SRV, 46),
    "afops":      host(S_MDC, K.V_SRV, 47),
    "track":      host(S_MDC, K.V_SRV, 48),
    "wxint":      host(S_MDC, K.V_SRV, 49),
    "pers":       host(S_MDC, K.V_SRV, 50),
    "lms":        host(S_MDC, K.V_SRV, 51),
    "portal":     host(S_MDC, K.V_SRV, 52),
    "pki":        host(S_MDC, K.V_SRV, 53),
    "flow":       host(S_MDC, K.V_SRV, 54),
    "historian":  host(S_MDC, K.V_SRV, 55),
}

# --------------------------------------------------------------------------- #
# base order of battle
# --------------------------------------------------------------------------- #
# (key, name, role, weight).  Every one of these is a real Iruma tenant from the
# base's own unit list; ``weight`` says whether it gets a complete ops LAN plus
# a hangar industrial segment ("full") or an ops LAN only ("light").
#
# Deliberately absent: a fighter squadron (Iruma has no fighter operations by
# agreement with the surrounding residential areas), the 1st Air Wing (it is at
# Hamamatsu) and 救難教育隊 (it is at Komaki).  The Air Rescue Wing has its
# headquarters here, but Iruma's own rescue squadron was disbanded in 1968 --
# the wing's Iruma flying unit is an *airlift* squadron, so that is modelled.
TENANTS = [
    ("402SQ", "402 Hikotai", "2nd Tactical Airlift Group flying squadron "
     "(C-2 / RC-2 / U-4)", "full"),
    ("ARWHAS", "Iruma Helicopter Airlift Sq", "Air Rescue Wing helicopter "
     "airlift squadron (CH-47J)", "full"),
    ("FCS", "Hiko Tenken-tai", "Flight Check Squadron - national navaid and "
     "ATC flight inspection (U-125 / U-680A)", "full"),
    ("SI", "CADF HQ Support Flt", "Central Air Defence Force HQ support flight "
     "- T-4 'Silver Impulse' / U-4", "full"),
    ("EWC", "Denshi Sentai", "Electronic Warfare Squadron / Electronic Flight "
     "Measurement Squadron (RC-2)", "light"),
    ("CAMG", "Chubu Koshagun", "Central Air Defence Missile Group - Patriot "
     "PAC-3", "light"),
    ("CACE", "Chubu Shisetsu-tai", "Central Air Facility Squadron - airfield "
     "and facility engineering", "light"),
    ("ASAR", "Aeromedical Safety Res Unit", "Aeromedical and flight safety "
     "research unit (2025)", "light"),
    ("IMP", "Iruma District Police", "MOD-direct district police (keimutai)",
     "light"),
    ("SIGINT", "Johobu Denpa-bu", "Signals Intelligence HQ radio branch, Iruma "
     "communications detachment", "light"),
]

# Apron sectors -- the physical flight line.
APRON_SECTORS = [
    ("W", "west apron", "main concrete apron - airlift parking"),
    ("N", "north apron", "north-west apron on the hangar line"),
    ("H", "helipad dispersal", "dispersed helicopter landing pads"),
    ("P", "police heliport", "Saitama Prefectural Police Air Corps hangar "
     "and pads"),
]

# Bulk fuel farm tanks (POL).  The farm itself is modelled from JASDF
# convention -- see docs/iruma/DESIGN.md, "what is sourced and what is not".
POL_TANKS = [
    ("TK01", "AVTUR 1", "jet fuel, west bund"),
    ("TK02", "AVTUR 2", "jet fuel, west bund"),
    ("TK03", "AVTUR 3", "jet fuel, east bund"),
    ("TK04", "AVTUR 4", "jet fuel, east bund"),
    ("TK05", "AVGAS 1", "aviation gasoline"),
    ("TK06", "AVTUR 5", "jet fuel, north bund"),
    ("TK07", "AVTUR 6", "jet fuel, north bund"),
    ("TK08", "FSII", "fuel system icing inhibitor store"),
]

# Airfield radio plan -- frequencies are the published Iruma/Yokota ones.
FREQ_GND = "275.800"
FREQ_TWR = "322.200"
FREQ_GCA = "335.600"
FREQ_RESCUE = "138.050"
TACAN_IDENT = "YLT"

DNS_DOMAIN = K.DOMAIN

# port-name shorthand, all from build/port_table.json (see tools/port_table.py).
GE1 = lambda i: f"GigabitEthernet1/0/{i}"       # noqa: E731  (3650-24PS / IE-9320)
GE1_1 = lambda i: f"GigabitEthernet1/{i}"       # noqa: E731  (IE-3400)
FE0 = lambda i: f"FastEthernet0/{i}"            # noqa: E731  (2960 / 3560)
GE0 = lambda i: f"GigabitEthernet0/{i}"         # noqa: E731  (3560 / 2960 uplinks)
GE2000 = lambda i: f"GigabitEthernet1/{i}"      # noqa: E731  (IE-2000 gig)
FE2000 = lambda i: f"FastEthernet1/{i}"         # noqa: E731  (IE-2000 fast)

# Layout tiers.  Every tier costs vertical space before a device is placed, and
# the primary page holds only ~26 rows -- so tier count, not device count, is
# what decides whether a model fits.  Related zones therefore share one band.
GROUP_MERGE = {
    "T1-edge": "T1-edge-carrier",
    "T2-core": "T2-core-noc",
    "T3-mdc": "T3-datacentres",
    "T4-bdc": "T3-datacentres",
    "T5-opsec": "T4-opsec",
    "T6-aoc": "T5-aoc-tower",
    "T7-atc": "T6-atc-navaid",
    "T8-tenants": "T7-tenants",
    "T9-apron": "T8-apron",
    "T10-wx": "T9-weather",
    "T11-depot": "T10-depot-pol",
    "T12-pol": "T10-depot-pol",
    "T13-sec": "T11-facilities",
    "T14-util": "T11-facilities",
    "T15-wlan": "T11-facilities",
    "T16-mobile": "T12-mobile",
}


class P2P:
    """/30 allocator for point-to-point links (10.0.x.y)."""

    def __init__(self) -> None:
        self.i = 0

    def next(self):
        i = self.i
        self.i += 1
        return (f"10.0.{i // 64}.{(i % 64) * 4 + 1}",
                f"10.0.{i // 64}.{(i % 64) * 4 + 2}", M30)


class Base:
    """The JASDF Iruma Air Base model."""

    # Devices deliberately staged powered-down.  Empty: everything placed here
    # is part of the live base and must come up at load.
    STAGED_OFF: frozenset[str] = frozenset()

    def __init__(self, profile: str) -> None:
        self.p = PROFILES[profile]
        self.profile = profile
        self.models, self.modules = lab_api.load_templates(
            str(TOOLKIT / "tools" / "device_templates.json"))
        self.lab = lab_api.Lab(str(TOOLKIT / "tools" / "network_seed.xml"),
                               self.models, self.modules)
        self.seed_removed = self.lab.prune_seed_devices()
        self.layout = lab_api.Layout()
        self.sid: dict[str, str] = {}
        self.meta: dict[str, dict] = {}
        self.has_nic_ip: set[str] = set()
        self.routed: list[tuple[str, str, str, str]] = []
        self.links: list[tuple] = []
        self.serial_meta: list[tuple] = []
        self.dns: list[tuple[str, str]] = []
        self.wlans: list[tuple[str, str]] = []
        self.p2p = P2P()
        self.servers: list[tuple] = []
        self.tenants: list[dict] = []
        self.aprons: list[dict] = []
        self.static_iot: list[tuple[str, str, str, str]] = []
        self.service_notes: list[tuple[str, str]] = []
        self.serviced: set[str] = set()
        self.access_override: dict[str, dict[str, int]] = {}
        self.l3_keys: set[str] = {
            "bb1", "bb2", "cr1", "cr2", "we1", "we2", "dci1", "mgw",
            "ce1", "ce2", "modgw", "yokgw", "jwsgw", "polgw", "sigintgw",
            "mdcs1", "mdcs2", "bdcs1",
            "aocr1", "aocr2", "atcr1", "atcr2",
            "depr1", "polr1", "secr1", "utilr1", "wxr1", "hospr1",
        }
        self.asa_keys: set[str] = {"fwext", "mdcfw", "mdcfw2", "bdcfw",
                                   "osfw1", "osfw2"}
        self.port_completions: list[tuple[str, str, int]] = []
        self.leftover_report: dict = {}
        self.startup_lines_cleared = 0
        self._ip_owner: dict[str, str] = {}
        self._loop_seq = 0

    # -- primitives ------------------------------------------------------ #
    def _claim_ip(self, ip: str | None, name: str) -> None:
        if not ip:
            return
        prev = self._ip_owner.get(ip)
        if prev == name:
            return
        if prev is not None:
            raise SystemExit(
                f"address collision: {ip} is claimed by both {prev!r} and {name!r}. "
                "Every device address must be derived from its own zone, VLAN and "
                "role; a repeated host octet means two devices share a segment slot."
            )
        self._ip_owner[ip] = name

    def add(self, key: str, model: str, name: str, *, group: str, role: str = "",
            site: str = "", ip: str | None = None, cfg: list[str] | None = None,
            pc_ip: tuple[str, str, str] | None = None,
            modules: list[str] | None = None, dns: bool = True,
            vlan: int | None = None) -> str:
        p = self.layout.place(name, model, group=GROUP_MERGE.get(group, group))
        sid = self.lab.add_device(model, name, p.x, p.y,
                                  ios_config=cfg, pc_ip=pc_ip)
        for mod in (modules or []):
            self.lab.install_module(sid, mod)
        self.sid[key] = sid
        self._claim_ip(ip, name)
        # An end device's VLAN is a property of the segment it was addressed on,
        # so derive it from its own default gateway rather than from a second,
        # hand-maintained table.  ``10.<site>.<vlan>.1`` -> ``<vlan>``.
        if vlan is None and pc_ip:
            try:
                vlan = int(pc_ip[2].split(".")[-2])
            except (ValueError, IndexError):
                vlan = None
        self.meta[key] = dict(name=name, model=model, role=role, site=site,
                              ip=ip, group=group, vlan=vlan)
        if pc_ip:
            self.has_nic_ip.add(key)
        if dns and ip:
            self.dns.append((name.lower(), ip))
        return sid

    def link(self, a: str, ap: str, b: str, bp: str, kind: str = "copper",
             dce: str | None = None, clock: int = 2_000_000) -> None:
        self.lab.link(self.sid[a], ap, self.sid[b], bp, kind=kind,
                      dce=self.sid[dce] if dce else None, clock=clock)
        self.links.append((a, ap, b, bp, kind, dce))

    def rlink(self, a: str, ap: str, b: str, bp: str):
        ia, ib, m = self.p2p.next()
        self.routed += [(a, ap, ia, m), (b, bp, ib, m)]
        self.link(a, ap, b, bp)
        return ia, ib

    def slink(self, a: str, ap: str, b: str, bp: str, dce: str,
              clock: int = 2_000_000):
        ia, ib, m = self.p2p.next()
        self.routed += [(a, ap, ia, m), (b, bp, ib, m)]
        self.link(a, ap, b, bp, kind="serial", dce=dce, clock=clock)
        self.serial_meta.append((a, ap, b, bp, dce, clock))
        return ia, ib

    def _asa_uplink(self, key: str, port: str, fallback: str) -> str:
        for (_d, p, ip, _m) in self.routed:
            if _d == key and p == port:
                return ip
        return fallback

    def cabled_ports(self, key: str) -> dict[str, str]:
        """{port: peer key} for every cable terminating on this device.

        The authority for "which ports exist" is the cabling, not a list typed
        beside it: two hand-maintained lists drift, and they drift into a cabled
        port that nothing configures -- a link that renders dead while every
        structural check passes.
        """
        out: dict[str, str] = {}
        for (a, ap, b, bp, _k, _d) in self.links:
            if a == key:
                out[ap] = b
            elif b == key:
                out[bp] = a
        return out

    def routed_ports(self, key: str) -> set[str]:
        return {p for (d, p, _i, _m) in self.routed if d == key}

    def ifaces(self, key: str):
        return [(p, ip, m) for (d, p, ip, m) in self.routed if d == key]

    def wans(self, key: str, area: int = K.AREA_BACKBONE):
        out = []
        for _p, ip, m in self.ifaces(key):
            o = ip.split(".")
            out.append((f"{o[0]}.{o[1]}.{o[2]}.0",
                        "0.0.0.3" if m == M30 else "0.0.0.255", area))
        return out

    def loop(self) -> str:
        i = self._loop_seq
        self._loop_seq += 1
        return f"10.255.{i // 250}.{i % 250 + 1}"

    def set_cfg(self, key: str, cfg: list[str]) -> None:
        eng = self.lab._els[self.sid[key]].find("ENGINE")
        for rc in list(eng.findall("RUNNINGCONFIG")):
            eng.remove(rc)
        rc = ET.SubElement(eng, "RUNNINGCONFIG")
        for line in cfg:
            ET.SubElement(rc, "LINE").text = line

    def wireless(self, key: str, ssid: str) -> None:
        self.lab.set_wireless(self.sid[key], ssid=ssid, auth_type=5,
                              encrypt_type=5, password="irm-wlan-4d92")
        self.wlans.append((self.meta[key]["name"], ssid))

    def end(self, key: str, model: str, name: str, *, group: str, ip: str,
            gw_: str, mask: str = M24, role: str = "", site: str = "") -> str:
        return self.add(key, model, name, group=group, role=role, site=site,
                        ip=ip, pc_ip=(ip, mask, gw_))

    def iot(self, key: str, model: str, name: str, *, group: str, ip: str,
            vlan: int, site: int, role: str) -> str:
        """An addressed IoT/OT endpoint (NIC address, not an IOS config)."""
        sid = self.add(key, model, name, group=group, role=role, site=str(site),
                       ip=ip)
        self.static_iot.append((key, ip, M24, gw(site, vlan)))
        return sid

    # ================================================================== #
    # 1. carrier / external liaison edge
    # ================================================================== #
    def build_edge(self) -> None:
        g = "T1-edge"
        self.add("isp1", "Cloud-PT", "CARRIER-NTT-EDGE", group=g, site="EDGE",
                 role="NTT Communications transit cloud (AS65011)")
        self.add("isp2", "Cloud-PT", "CARRIER-KDDI-EDGE", group=g, site="EDGE",
                 role="KDDI transit cloud (diverse backup carrier)")
        self.add("ce1", "ISR4331", "IRM-EDGE-RTR-01", group=g, site="EDGE",
                 ip=self.loop(), modules=["NIM-2T"],
                 role="Base edge router A (eBGP to carriers, AS65010)")
        self.add("ce2", "ISR4331", "IRM-EDGE-RTR-02", group=g, site="EDGE",
                 ip=self.loop(), modules=["NIM-2T"],
                 role="Base edge router B (eBGP, diverse path)")
        self.add("fwext", "5505", "FW-INTERNET-EDGE", group=g, site="EDGE",
                 ip="10.99.0.2",
                 role="Internet / liaison DMZ edge firewall")
        for key, name, role in [
            ("modgw", "MOD-BACKBONE-GW",
             "Japan Ministry of Defense backbone gateway (eBGP AS65012)"),
            ("yokgw", "YOKOTA-ATC-GW",
             "Yokota AB approach/departure control liaison (APP/DEP for Iruma)"),
            ("jwsgw", "JWS-II-WX-GW",
             "JWS-II integrated weather system feed, Air Weather Group (Fuchu)"),
            ("polgw", "SPPOL-AIR-GW",
             "Saitama Prefectural Police Air Corps liaison (co-located hangar)"),
            ("sigintgw", "SIGINT-BRANCH-GW",
             "Signals Intelligence HQ radio branch, Iruma detachment"),
        ]:
            self.add(key, "ISR4331", name, group=g, site="EDGE", ip=self.loop(),
                     role=role, modules=["NIM-2T"])
        self.add("dmzsw", "2960-24TT", "EDGE-DMZ-SW", group=g, site="EDGE",
                 ip=host(S_EDGE, K.V_LIAISON, 10),
                 role="Liaison DMZ access switch (partner file exchange)")
        self.add("edisrv", "Server-PT", "LIAISON-FILE-SVR", group=g, site="EDGE",
                 ip=host(S_EDGE, K.V_LIAISON, 20),
                 role="Liaison file exchange broker (AS2 / SFTP)",
                 pc_ip=(host(S_EDGE, K.V_LIAISON, 20), M24,
                        host(S_EDGE, K.V_LIAISON, 1)))
        self.add("proxy", "Server-PT", "EDGE-PROXY-01", group=g, site="EDGE",
                 ip=host(S_EDGE, K.V_LIAISON, 21),
                 role="Internet proxy / content filter for the base",
                 pc_ip=(host(S_EDGE, K.V_LIAISON, 21), M24,
                        host(S_EDGE, K.V_LIAISON, 1)))
        self.add("mailgw", "Server-PT", "EDGE-MAIL-RELAY", group=g, site="EDGE",
                 ip=host(S_EDGE, K.V_LIAISON, 22),
                 role="Official mail relay / gateway",
                 pc_ip=(host(S_EDGE, K.V_LIAISON, 22), M24,
                        host(S_EDGE, K.V_LIAISON, 1)))

    # ================================================================== #
    # 2. base backbone & NetOps
    # ================================================================== #
    def build_core(self) -> None:
        g = "T2-core"
        self.add("bb1", "3650-24PS", "IRM-CORE-SW-01", group=g, site="CORE",
                 ip=self.loop(),
                 role="Base collapsed core A (OSPF area 0, iBGP edge)")
        self.add("bb2", "3650-24PS", "IRM-CORE-SW-02", group=g, site="CORE",
                 ip=self.loop(),
                 role="Base collapsed core B (OSPF area 0, iBGP edge)")
        for i, (k, n) in enumerate([("cr1", "IRM-CORE-RTR-01"),
                                    ("cr2", "IRM-CORE-RTR-02")]):
            self.add(k, "ISR4331", n, group=g, site="CORE", ip=self.loop(),
                     role=f"Base core router {'A' if i == 0 else 'B'} "
                          "(OSPF ABR, iBGP speaker)", modules=["NIM-2T"])
        for i, (k, n) in enumerate([("we1", "IRM-WAN-EDGE-01"),
                                    ("we2", "IRM-WAN-EDGE-02")]):
            self.add(k, "2911", n, group=g, site="CORE", ip=self.loop(),
                     role=f"Base WAN edge ({'primary' if i == 0 else 'backup'} "
                          "carrier)", modules=["HWIC-2T"])
        self.add("dci1", "ISR4331", "IRM-DCI-RTR-01", group=g, site="CORE",
                 ip=self.loop(), modules=["NIM-2T"],
                 role="Data-centre interconnect router (MDC <-> BDC)")
        self.add("mgw", "ISR4331", "IRM-NETOPS-GW-01", group=g, site="CORE",
                 ip=self.loop(), modules=["NIM-2T"],
                 role="Out-of-band management gateway / NetOps edge")
        self.add("nocsw1", "2960-24TT", "NETOPS-SW-01", group=g, site="NOC",
                 ip=host(S_NOC, K.V_MGMT, 11),
                 role="Base NetOps / base communications enclave switch")
        for key, name, model, role, h in [
            ("nms", "NETOPS-NMS-01", "Server-PT",
             "Network management station (SNMP / syslog / NetFlow)", 21),
            ("jump", "NETOPS-JUMP-01", "Server-PT",
             "Privileged jump host (all admin access transits here)", 22),
            ("cobs", "NETOPS-CYBER-OBS", "CyberObserver",
             "Base cyber defence anomaly / OT intrusion detection", 23),
            ("tap", "NETOPS-TAP-01", "Sniffer",
             "NetOps packet capture tap", 24),
            ("tacacs", "NETOPS-TACACS-01", "Server-PT",
             "TACACS+ / command accounting collector", 25),
        ]:
            ip = host(S_NOC, K.V_MGMT, h)
            self.add(key, model, name, group=g, site="NOC", ip=ip, role=role)
            if model == "Server-PT":
                self.lab._els[self.sid[key]].find(".//PORT").find("IP").text = ip
                self.has_nic_ip.add(key)

    # ================================================================== #
    # 3. air defence & mission data centre
    # ================================================================== #
    def build_mdc(self) -> None:
        g = "T3-mdc"
        s = S_MDC
        self.add("mdcs1", "3650-24PS", "MDC-SPINE-01", group=g, site="MDC",
                 ip=host(s, K.V_SRV, 11),
                 role="MDC spine A (VLAN 60 gateway, HSRP active)")
        self.add("mdcs2", "3650-24PS", "MDC-SPINE-02", group=g, site="MDC",
                 ip=host(s, K.V_SRV, 12), role="MDC spine B (HSRP standby)")
        self.add("mdcl1", "3560-24PS", "MDC-LEAF-01", group=g, site="MDC",
                 ip=host(s, K.V_SRV, 13), role="MDC leaf A (core services)")
        self.add("mdcl2", "3560-24PS", "MDC-LEAF-02", group=g, site="MDC",
                 ip=host(s, K.V_SRV, 14),
                 role="MDC leaf B (CADF / CACW / OSW mission applications)")
        self.add("mdcfw", "5505", "FW-MDC-PERIMETER", group=g, site="MDC",
                 ip="10.99.1.2", role="MDC perimeter firewall (outside/inside)")
        self.add("mdcfw2", "5505", "FW-MDC-INT", group=g, site="MDC",
                 ip="10.99.2.2",
                 role="MDC internal segmentation firewall (apps / services)")

        # Core services are present in every profile: a base without DNS, DHCP
        # or AAA is not a smaller base, it is a broken one.
        core = [
            ("s_dns", "DNS-SVR-01", "dns", "Authoritative DNS - " + DNS_DOMAIN),
            ("s_dns2", "DNS-SVR-02", "dns2", "Secondary DNS (zone replicated)"),
            ("s_dhcp", "DHCP-SVR-01", "dhcp", "Base DHCP (all zones)"),
            ("s_dhcp2", "DHCP-SVR-02", "dhcp2", "Standby DHCP node (no pools held)"),
            ("s_ntp", "NTP-SVR-01", "ntp", "Stratum-2 NTP, GPS disciplined"),
            ("s_ntp2", "NTP-SVR-02", "ntp2", "Standby NTP node"),
            ("s_syslog", "SYSLOG-SVR-01", "syslog", "Central syslog / SIEM collector"),
            ("s_syslog2", "SYSLOG-SVR-02", "syslog2", "Standby syslog archive"),
            ("s_aaa", "AAA-SVR-01", "aaa", "RADIUS + TACACS+ (Cisco ACS)"),
            ("s_aaa2", "AAA-SVR-02", "aaa2", "Standby AAA node"),
            ("s_tftp", "TFTP-ARCHIVE-01", "tftp", "Configuration and image archive"),
        ]
        listed = [
            ("s_adsys", "ADSYS-OPS-01", "track",
             "Air defence system operations (CACW / OSW mission system)"),
            ("s_sortie", "SORTIE-TASK-01", "sortie",
             "Sortie tasking and flying programme service"),
            ("s_mission", "MISSION-PLAN-01", "mission",
             "Mission planning and route generation"),
            ("s_ato", "ATO-SVR-01", "ato", "Air tasking order distribution"),
            ("s_mxmis", "MX-MIS-01", "mxmis",
             "Maintenance management information system"),
            ("s_supply", "SUPPLY-APP-01", "supply",
             "Supply chain and spares management"),
            ("s_fltrec", "FLTREC-SVR-01", "fltrec",
             "Aircrew flight records and currency"),
            ("s_afops", "AIRFIELD-OPS-01", "afops",
             "Airfield operations and movements"),
            ("s_wxint", "WX-INTEG-01", "wxint",
             "Weather integration for flight planning"),
            ("s_pers", "PERS-SVR-01", "pers",
             "Personnel and establishment records"),
            ("s_lms", "TRAINING-LMS-01", "lms",
             "Aircrew and technical training management"),
            ("s_portal", "IRM-PORTAL-01", "portal",
             "Base intranet portal (HTTPS)"),
            ("s_pki", "PKI-CA-01", "pki", "Base internal certificate authority"),
            ("s_flow", "NETFLOW-SVR-01", "flow", "NetFlow / IPFIX collector"),
            ("s_hist", "DATA-HISTORIAN", "historian",
             "Mission and equipment data historian"),
        ]
        n_app = max(4, self.p["apps"])
        for key, name, svc, desc in core + listed[:n_app]:
            ip = SRV[svc]
            self.add(key, "Server-PT", name, group=g, site="MDC", ip=ip,
                     role=desc, pc_ip=(ip, M24, gw(s, K.V_SRV)))
            self.servers.append((key, name, svc, desc, ip))

    def build_bdc(self) -> None:
        g = "T4-bdc"
        s = S_BDC
        self.add("bdcs1", "3650-24PS", "BDC-SPINE-01", group=g, site="BDC",
                 ip=host(s, K.V_SRV, 11),
                 role="Backup site spine (standby mission services gateway)")
        self.add("bdcl1", "3560-24PS", "BDC-LEAF-01", group=g, site="BDC",
                 ip=host(s, K.V_SRV, 12), role="Backup site server access")
        self.add("bdcfw", "5505", "FW-BDC-PERIMETER", group=g, site="BDC",
                 ip="10.99.4.2", role="Backup site perimeter firewall")
        srv = [
            ("b_sortie", "BDC-SORTIE-APP", 41,
             "Standby sortie tasking (replication target)"),
            ("b_msn", "BDC-MISSION-DB", 42, "Standby mission planning database"),
            ("b_supply", "BDC-SUPPLY-APP", 43, "Standby supply chain application"),
            ("b_dns", "BDC-DNS-SVR-01", 44, "Standby DNS resolver"),
            ("b_repl", "BDC-REPLICA-SVR", 45, "Asynchronous replication target"),
            ("b_vault", "BDC-BACKUP-VAULT", 46, "Offline backup vault"),
            ("b_adsys", "BDC-ADSYS-APP", 47, "Standby air defence system node"),
        ]
        for key, name, h, desc in srv:
            ip = host(s, K.V_SRV, h)
            self.add(key, "Server-PT", name, group=g, site="BDC", ip=ip,
                     role=desc, pc_ip=(ip, M24, gw(s, K.V_SRV)))

    # ================================================================== #
    # 4. operations-security enclave  (172.21.0.0/16)
    # ================================================================== #
    def build_opsec(self) -> None:
        g = "T5-opsec"
        cn = OPSEC_NET
        self.add("osfw1", "5505", "OPSEC-FW-OUTER", group=g, site="OPSEC",
                 ip=f"{cn}.255.1",
                 role="Enclave outer firewall (base -> enclave DMZ)")
        self.add("osfw2", "5505", "OPSEC-FW-INNER", group=g, site="OPSEC",
                 ip=f"{cn}.255.2",
                 role="Enclave inner firewall (DMZ -> mission database)")
        self.add("ossw1", "3560-24PS", "OPSEC-DMZ-SW-01", group=g, site="OPSEC",
                 ip=f"{cn}.10.10",
                 role="Enclave DMZ switch (tasking brokers, workstations)")
        self.add("ossw2", "3560-24PS", "OPSEC-DB-SW-01", group=g, site="OPSEC",
                 ip=f"{cn}.20.10",
                 role="Enclave protected switch (mission database, HSM)")
        self.add("osids", "CyberObserver", "OPSEC-IDS-01", group=g, site="OPSEC",
                 ip=f"{cn}.10.20", role="Enclave intrusion detection sensor")
        self.add("ostap", "Sniffer", "OPSEC-TAP-01", group=g, site="OPSEC",
                 ip=f"{cn}.10.21", role="Enclave audit / intercept tap")
        vlan = OPSEC_SITE
        srv = [
            ("os_db1", "OPSEC-MSNDB-01", f"{cn}.20.21",
             "Mission database (primary, encrypted at rest)"),
            ("os_db2", "OPSEC-MSNDB-02", f"{cn}.20.22",
             "Mission database (synchronous standby)"),
            ("os_ato", "OPSEC-ATO-BROKER-01", f"{cn}.10.31",
             "Air tasking order broker (primary)"),
            ("os_task", "OPSEC-TASKING-APP-01", f"{cn}.10.32",
             "Tasking and fragging application"),
            ("os_hsm", "OPSEC-HSM-KEY-01", f"{cn}.20.23",
             "Hardware security module / key custodian"),
            ("os_audit", "OPSEC-AUDIT-LOG-01", f"{cn}.20.24",
             "Immutable enclave audit log (WORM)"),
            ("os_crypt", "OPSEC-CRYPT-01", f"{cn}.10.33",
             "Cryptographic gateway to the MoD backbone"),
        ]
        for key, name, ip, desc in srv:
            self.add(key, "Server-PT", name, group=g, site="OPSEC", ip=ip,
                     role=desc, pc_ip=(ip, M24, f"{cn}.{vlan}.1"))
        for i, (key, name) in enumerate([("os_ws1", "OPSEC-WS-01"),
                                         ("os_ws2", "OPSEC-WS-02")]):
            ip = f"{cn}.10.{40 + i}"
            self.end(key, "PC-PT", name, group=g, ip=ip, gw_=f"{cn}.10.1",
                     role="Mission planning workstation (enclave)", site="OPSEC")

    # ================================================================== #
    # 5. air operations centre / control tower
    # ================================================================== #
    def build_aoc(self) -> None:
        g = "T6-aoc"
        s = S_AOC
        for i, (k, n, r) in enumerate([
            ("aocr1", "AOC-RTR-01", "Air operations centre router (active)"),
            ("aocr2", "AOC-RTR-02", "Air operations centre router (standby)"),
        ]):
            self.add(k, "ISR4331", n, group=g, site="AOC",
                     ip=host(s, K.V_MGMT, 2 + i), role=r, modules=["NIM-2T"])
        self.add("aocd1", "3560-24PS", "AOC-DSW-01", group=g, site="AOC",
                 ip=host(s, K.V_MGMT, 11), role="AOC distribution switch A")
        self.add("aocd2", "3560-24PS", "AOC-DSW-02", group=g, site="AOC",
                 ip=host(s, K.V_MGMT, 12), role="AOC distribution switch B")
        self.add("aoca1", "2960-24TT", "AOC-ACC-01", group=g, site="AOC",
                 ip=host(s, K.V_MGMT, 21), role="Control tower cab access switch")
        self.add("aoca2", "2960-24TT", "AOC-ACC-02", group=g, site="AOC",
                 ip=host(s, K.V_MGMT, 22), role="CADF HQ operations floor access")
        ctl = [
            ("aoc_pos", "TWR-POS-CTL-01", K.V_SORTIE,
             f"Tower position controller (local control {FREQ_TWR} MHz)"),
            ("aoc_dis", "TWR-DISPLAY-01", K.V_SORTIE,
             "Tower situational display processor"),
            ("aoc_gnd", "GND-MOVEMENT-CTL", K.V_SORTIE,
             f"Ground movement control position ({FREQ_GND} MHz)"),
            ("aoc_app", "APCH-DISPLAY-01", K.V_SORTIE,
             "Approach control display (Yokota APP/DEP co-ordination)"),
            ("aoc_vw", "AOC-VIDWALL-01", K.V_OPS,
             "CADF HQ operations video wall controller"),
            ("aoc_flt", "FLT-DATA-SVR-01", K.V_SORTIE,
             "Flight data processing and strip printing"),
        ]
        for i, (key, name, vlan, role) in enumerate(ctl):
            ip = host(s, vlan, 30 + i)
            self.add(key, "Server-PT", name, group=g, site="AOC", ip=ip, role=role,
                     pc_ip=(ip, M24, gw(s, vlan)))
        for i in range(3):
            ip = host(s, K.V_OPS, 40 + i)
            self.end(f"aoc_ws{i + 1}", "PC-PT", f"AOC-OPS-WS-{i + 1:02d}", group=g,
                     ip=ip, gw_=gw(s, K.V_OPS), site="AOC",
                     role="CADF HQ operations controller workstation")
        for i in range(2):
            ip = host(s, K.V_VOICE, 20 + i)
            self.end(f"aoc_ph{i + 1}", "7960", f"TWR-RADIO-{i + 1:02d}", group=g,
                     ip=ip, gw_=gw(s, K.V_VOICE), site="AOC",
                     role="Tower / ground radio dispatch console")

    # ================================================================== #
    # 6. air traffic control & navaids
    # ================================================================== #
    def build_atc(self) -> None:
        g = "T7-atc"
        s = S_ATC
        for i, (k, n, r) in enumerate([
            ("atcr1", "ATC-RTR-01", "ATC and navaid router (active)"),
            ("atcr2", "ATC-RTR-02", "ATC and navaid router (standby)"),
        ]):
            self.add(k, "ISR4331", n, group=g, site="ATC",
                     ip=host(s, K.V_MGMT, 2 + i), role=r, modules=["NIM-2T"])
        self.add("atcsw1", "IE-9320", "ATC-SW-01", group=g, site="ATC",
                 ip=host(s, K.V_MGMT, 11),
                 role="ATC radar and navaid industrial switch A")
        self.add("atcsw2", "IE-3400", "ATC-SW-02", group=g, site="ATC",
                 ip=host(s, K.V_MGMT, 12),
                 role="ATC navaid and airfield lighting switch B")
        for key, name, vlan, h, role in [
            ("atc_gca", "GCA-RADAR-SVR-01", K.V_NAVAID, 20,
             f"GCA / precision approach radar processor (GCA {FREQ_GCA} MHz)"),
            ("atc_asr", "ASR-PROC-SVR-01", K.V_NAVAID, 21,
             "Air surveillance radar plot extractor (CACW)"),
            ("atc_mon", "NAVAID-MON-01", K.V_NAVAID, 22,
             f"Navaid status and drift monitoring (TACAN ident {TACAN_IDENT})"),
            ("atc_atis", "ATIS-SVR-01", K.V_VOICE, 23,
             "Automatic terminal information service (voice)"),
            ("atc_datis", "D-ATIS-SVR-01", K.V_SORTIE, 24,
             "Digital ATIS / departure information"),
            ("atc_rec", "ATC-RECORDER-01", K.V_SORTIE, 25,
             "ATC voice and radar recording (statutory retention)"),
        ]:
            ip = host(s, vlan, h)
            self.add(key, "Server-PT", name, group=g, site="ATC", ip=ip, role=role,
                     pc_ip=(ip, M24, gw(s, vlan)))
        for key, name, vlan, h, role in [
            ("atc_par", "PAR-CTL-01", K.V_OT, 30,
             "precision approach radar azimuth/elevation control"),
            ("atc_tac", "TACAN-CTL-01", K.V_NAVAID, 31,
             f"TACAN beacon control and monitoring (ident {TACAN_IDENT})"),
            ("atc_ils17", "ILS-CTL-17", K.V_NAVAID, 32,
             "instrument landing system, runway 17 localiser/glidepath"),
            ("atc_ils35", "ILS-CTL-35", K.V_NAVAID, 33,
             "instrument landing system, runway 35 localiser/glidepath"),
            ("atc_rwy", "RWY-LIGHT-CTL-01", K.V_OT, 34,
             "runway 17/35 edge, threshold and centreline lighting control"),
            ("atc_twy", "TWY-LIGHT-CTL-01", K.V_OT, 35,
             "parallel taxiway lighting and guidance sign control"),
            ("atc_apch", "APCH-LGT-CTL-01", K.V_OT, 36,
             "approach lighting, PAPI and sequenced flasher control"),
            ("atc_arff", "ARFF-ALERT-CTL-01", K.V_OT, 37,
             "crash alarm and ARFF alerting relay from the tower"),
        ]:
            ip = host(s, vlan, h)
            self.iot(key, "PLC-PT", name, group=g, ip=ip, vlan=vlan, site=s,
                     role=f"Airfield system PLC - {role}")
        for i, (key, name) in enumerate([("atc_hmi1", "ATC-HMI-01"),
                                         ("atc_hmi2", "ATC-HMI-02")]):
            ip = host(s, K.V_OT, 45 + i)
            self.iot(key, "HMI-PT", name, group=g, ip=ip, vlan=K.V_OT, site=s,
                     role="Airfield engineering panel (lighting and navaids)")

    # ================================================================== #
    # 7. tenant squadrons, hangars and the hospital
    # ================================================================== #
    def build_tenants(self) -> None:
        """Each tenant gets its own ops LAN; the flying units also get a hangar
        industrial segment.  Losing one unit's switch does not touch another."""
        g = "T8-tenants"
        full = self.p["tenants_full"]
        light = self.p["tenants_light"]
        chosen = ([t for t in TENANTS if t[3] == "full"][:full]
                  + [t for t in TENANTS if t[3] == "light"][:light])
        for i, (code, display, role, weight) in enumerate(chosen):
            site = S_TNT0 + i
            self.tenants.append(dict(idx=i + 1, code=code, display=display,
                                     role=role, weight=weight, site=site))
            self._build_tenant(i + 1, code, display, role, weight, site, g)
        self._build_hospital(g, S_HOSP)

    def _build_tenant(self, n: int, code: str, display: str, role: str,
                      weight: str, site: int, g: str) -> None:
        self.add(f"tn{n}sw", "2960-24TT", f"{code}-SW-01", group=g, site=code,
                 ip=host(site, K.V_MGMT, 10), role=f"{display} - {role}")
        self.add(f"tn{n}ops", "Server-PT", f"{code}-OPS-SVR", group=g, site=code,
                 ip=host(site, K.V_SORTIE, 20),
                 role=f"{display} operations and tasking server",
                 pc_ip=(host(site, K.V_SORTIE, 20), M24, gw(site, K.V_SORTIE)))
        for j in range(2):
            ip = host(site, K.V_OPS, 30 + j)
            self.end(f"tn{n}ws{j + 1}", "PC-PT", f"{code}-OPS-WS-{j + 1:02d}",
                     group=g, ip=ip, gw_=gw(site, K.V_OPS), site=code,
                     role=f"{display} operations desk workstation")
        if weight != "full":
            return
        self.add(f"tn{n}mx", "Server-PT", f"{code}-MX-SVR", group=g, site=code,
                 ip=host(site, K.V_SRV, 20),
                 role=f"{display} maintenance and servicing record server",
                 pc_ip=(host(site, K.V_SRV, 20), M24, gw(site, K.V_SRV)))
        ip = host(site, K.V_WIFI, 30)
        self.end(f"tn{n}efb", "Laptop-PT", f"{code}-EFB-01", group=g, ip=ip,
                 gw_=gw(site, K.V_WIFI), site=code,
                 role=f"{display} electronic flight bag (aircrew tablet)")
        self.wireless(f"tn{n}efb", "IRM-AIRCREW-WLAN")
        ip = host(site, K.V_VOICE, 20)
        self.end(f"tn{n}rad", "7960", f"{code}-RADIO-01", group=g, ip=ip,
                 gw_=gw(site, K.V_VOICE), site=code,
                 role=f"{display} squadron radio dispatch position")
        self.add(f"tn{n}hgr", "2960-24TT", f"{code}-HGR-SW-01", group=g,
                 site=code, ip=host(site, K.V_MGMT, 11),
                 role=f"{display} hangar industrial segment switch")
        ip = host(site, K.V_OT, 20)
        self.iot(f"tn{n}plc", "PLC-PT", f"{code}-HGR-PLC-01", group=g, ip=ip,
                 vlan=K.V_OT, site=site,
                 role=f"{display} hangar door and servicing-bay interlock PLC")
        ip = host(site, K.V_IOT, 20)
        self.iot(f"tn{n}fire", "Fire Monitor", f"{code}-HGR-FIRE", group=g, ip=ip,
                 vlan=K.V_IOT, site=site,
                 role=f"{display} hangar high-expansion foam fire suppression "
                      "monitor")

    def _build_hospital(self, g: str, site: int) -> None:
        """JSDF Iruma Hospital -- 10 departments, 60 beds, accepts civilian
        emergencies, so it is addressed as a zone of its own."""
        self.add("hospr1", "ISR4331", "IHS-RTR-01", group=g, site="HOSP",
                 ip=host(site, K.V_MGMT, 2),
                 role="JSDF Iruma Hospital zone router (OSPF ABR)",
                 modules=["NIM-2T"])
        self.add("hosp_sw", "2960-24TT", "IHS-SW-01", group=g, site="HOSP",
                 ip=host(site, K.V_MGMT, 11),
                 role="JSDF Iruma Hospital LAN switch")
        for key, name, vlan, h, role in [
            ("hosp_med", "IHS-MED-SVR", K.V_SRV, 20,
             "Hospital medical records and appointments"),
            ("hosp_rec", "IHS-RECEPT-CTL", K.V_SRV, 21,
             "Outpatient reception and queue management"),
        ]:
            ip = host(site, vlan, h)
            self.add(key, "Server-PT", name, group=g, site="HOSP", ip=ip,
                     role=role, pc_ip=(ip, M24, gw(site, vlan)))
        for i in range(2):
            ip = host(site, K.V_OPS, 30 + i)
            self.end(f"hosp_ws{i + 1}", "PC-PT", f"IHS-WS-{i + 1:02d}", group=g,
                     ip=ip, gw_=gw(site, K.V_OPS), site="HOSP",
                     role="Hospital clinical workstation")
        for key, name, model, vlan, h, role in [
            ("hosp_cam", "IHS-CAM-01", "Webcam", K.V_CCTV, 30,
             "hospital entrance and pharmacy CCTV"),
            ("hosp_door", "IHS-DOOR-01", "Door", K.V_CCTV, 40,
             "pharmacy controlled-substance store door controller"),
            ("hosp_smk", "IHS-SMOKE-01", "Smoke Detector", K.V_IOT, 30,
             "hospital ward smoke detection"),
            ("hosp_oxy", "IHS-OXY-MON-01", "Atm Pressure Monitor(0)", K.V_IOT, 31,
             "medical oxygen plant pressure monitoring"),
        ]:
            ip = host(site, vlan, h)
            self.iot(key, model, name, group=g, ip=ip, vlan=vlan, site=site,
                     role=f"JSDF Iruma Hospital - {role}")

    # ================================================================== #
    # 8. apron, flight line & ground vehicles
    # ================================================================== #
    def build_apron(self) -> None:
        g = "T9-apron"
        s = S_APRON0
        self.add("apragg1", "IE-9320", "APRON-AGG-01", group=g, site="APRON",
                 ip=host(s, K.V_MGMT, 3),
                 role="Apron industrial aggregation A (aprons and helipads)")
        self.add("apragg2", "IE-9320", "APRON-AGG-02", group=g, site="APRON",
                 ip=host(s, K.V_MGMT, 4),
                 role="Apron industrial aggregation B (flight line and ARFF)")
        for i, (code, label, note) in enumerate(
                APRON_SECTORS[:self.p["apron"]]):
            self.aprons.append(dict(idx=i + 1, code=code, label=label,
                                    note=note, site=s))
            self._build_apron_sector(i + 1, code, label, note, s, g)
        self._build_flightline(g, s)

    def _build_apron_sector(self, n: int, code: str, label: str, note: str,
                            site: int, g: str) -> None:
        tag = f"APRON-{code}"
        self.add(f"ap{n}sw", "IE-3400", f"{tag}-SW-01", group=g, site="APRON",
                 ip=host(site, K.V_MGMT, 10 + n),
                 role=f"{label} industrial switch ({note})")
        pairs = [
            ("gse", "PLC-PT", K.V_GV,
             "ground support equipment and power cart control"),
            ("fuel", "PLC-PT", K.V_OT,
             "apron refuelling point and bonding interlock"),
            ("lgt", "Light", K.V_OT, "apron floodlighting and obstruction lights"),
            ("cam", "Webcam", K.V_CCTV, "apron surveillance camera head"),
            ("fod", "Motion Detector", K.V_IOT,
             "apron movement and debris detection"),
        ]
        for j, (suffix, model, vlan, role) in enumerate(pairs):
            ip = host(site, vlan, 20 + n * 5 + j)
            self.iot(f"ap{n}{suffix}", model, f"{tag}-{suffix.upper()}-01",
                     group=g, ip=ip, vlan=vlan, site=site,
                     role=f"{label} {role}")

    def _build_flightline(self, g: str, site: int) -> None:
        self.add("fltsw1", "IE-9320", "FLT-LINE-SW-01", group=g, site="APRON",
                 ip=host(site, K.V_MGMT, 20),
                 role="Flight line industrial switch A (hot refuelling, GSE)")
        self.add("fltsw2", "IE-3400", "FLT-LINE-SW-02", group=g, site="APRON",
                 ip=host(site, K.V_MGMT, 21),
                 role="Flight line industrial switch B (ARFF, sweep, birds)")
        # Host octets start at 100 so the flight line cannot collide with the
        # apron sectors' 20 + n*5 + j block in the same VLAN.
        for key, name, model, vlan, h, role in [
            ("flt_fuel", "FUEL-CTL-01", "PLC-PT", K.V_OT, 100,
             "bulk fuel issue and hot-refuelling control"),
            ("flt_hot", "HOTFUEL-CTL-01", "PLC-PT", K.V_OT, 101,
             "hot refuelling point interlock and metering"),
            ("flt_sweep", "RWY-SWEEP-PLC", "PLC-PT", K.V_GV, 100,
             "runway sweep and FOD clearance tasking"),
            ("flt_tow", "TOW-TRACTOR-PLC", "PLC-PT", K.V_GV, 101,
             "tow tractor and aircraft movement control"),
            ("flt_gse", "GSE-MAINT-PLC", "PLC-PT", K.V_GV, 102,
             "GSE maintenance bay and test bench control"),
        ]:
            ip = host(site, vlan, h)
            self.iot(key, model, name, group=g, ip=ip, vlan=vlan, site=site,
                     role=f"Airfield PLC - {role}")
        for key, name, vlan, h, role in [
            ("arff_srv", "ARFF-DISP-SVR", K.V_SRV, 30,
             f"Airfield rescue and firefighting dispatch (RESCUE {FREQ_RESCUE} "
             "MHz, crash alarm relay)"),
            ("bird_srv", "BIRD-CONTROL-SVR", K.V_SRV, 31,
             "Bird activity control and dispersal tasking"),
            ("fm_srv", "FOLLOWME-SVR-01", K.V_SRV, 32,
             "Follow-me and marshalling task dispatch"),
        ]:
            ip = host(site, vlan, h)
            self.add(key, "Server-PT", name, group=g, site="APRON", ip=ip,
                     role=role, pc_ip=(ip, M24, gw(site, vlan)))
        ip = host(site, K.V_OPS, 40)
        self.end("arff_ws", "PC-PT", "ARFF-CMD-WS-01", group=g, ip=ip,
                 gw_=gw(site, K.V_OPS), site="APRON",
                 role="ARFF watch room command workstation")
        ip = host(site, K.V_OT, 102)
        self.iot("arff_plc", "PLC-PT", "ARFF-VEH-PLC-01", group=g, ip=ip,
                 vlan=K.V_OT, site=site,
                 role="ARFF vehicle readiness and foam-system monitor")
        for i in range(self.p["vehicles"]):
            tag = f"GND-VEH-{i + 1:02d}"
            ip = host(site, K.V_GV, 60 + i)
            key = f"gv{i + 1}"
            self.add(key, "PLC-PT", tag, group=g, site="APRON", ip=ip,
                     role=f"{tag} airfield ground vehicle controller "
                          "(follow-me, fuelling, towing)")
            self.wireless(key, "IRM-APRON-WLAN")

    # ================================================================== #
    # 9. air weather squadron
    # ================================================================== #
    def build_weather(self) -> None:
        g = "T10-wx"
        s = S_WX
        self.add("wxr1", "ISR4331", "IWS-RTR-01", group=g, site="WX",
                 ip=host(s, K.V_MGMT, 2),
                 role="Iruma Weather Squadron zone router (OSPF ABR)",
                 modules=["NIM-2T"])
        self.add("wxsw1", "2960-24TT", "IWS-SW-01", group=g, site="WX",
                 ip=host(s, K.V_MGMT, 11),
                 role="Iruma Weather Squadron LAN switch")
        for key, name, vlan, h, role in [
            ("wx_fc", "IWS-FCST-SVR", K.V_SRV, 20,
             "Local forecasting and briefing production"),
            ("wx_obs", "IWS-OBS-SVR", K.V_SRV, 21,
             "Surface and upper-air observation ingest"),
            ("wx_dis", "IWS-DISSEM-SVR", K.V_SRV, 22,
             "Weather dissemination to aircrew, ATC and CADF HQ"),
            ("wx_jws", "IWS-JWS-CLIENT", K.V_SRV, 23,
             "JWS-II integrated weather system client (Air Weather Group)"),
        ]:
            ip = host(s, vlan, h)
            self.add(key, "Server-PT", name, group=g, site="WX", ip=ip, role=role,
                     pc_ip=(ip, M24, gw(s, vlan)))
        sensors = [
            ("wx_wind1", "WIND-DET-01", "Wind Detector", K.V_IOT, 20,
             "anemometer, runway 35 touchdown zone"),
            ("wx_wind2", "WIND-DET-02", "Wind Detector", K.V_IOT, 21,
             "anemometer, runway 17 touchdown zone"),
            ("wx_temp1", "TEMP-DET-01", "Temperature Monitor", K.V_IOT, 22,
             "air temperature and dewpoint, instrument field"),
            ("wx_hum", "HUMID-DET-01", "Humidity Monitor", K.V_IOT, 23,
             "relative humidity, instrument field"),
            ("wx_press", "PRESS-DET-01", "Atm Pressure Monitor(0)", K.V_IOT, 24,
             "barometric pressure, instrument field"),
            ("wx_rain", "RAIN-DET-01", "Water Level Monitor", K.V_IOT, 25,
             "rain gauge and precipitation accumulation"),
            ("wx_vis", "VIS-DET-01", "Light", K.V_IOT, 26,
             "visibility and ambient light sensor, instrument field"),
            ("wx_rvr", "RVR-DET-01", "Light", K.V_IOT, 27,
             "runway visual range transmissometer, runway 35"),
        ]
        for key, name, model, vlan, h, role in sensors:
            ip = host(s, vlan, h)
            self.iot(key, model, name, group=g, ip=ip, vlan=vlan, site=s, role=role)
        ip = host(s, K.V_OT, 30)
        self.iot("wx_bal", "PLC-PT", "IWS-BALLOON-CTL", group=g, ip=ip,
                 vlan=K.V_OT, site=s,
                 role="Upper-air balloon release and radiosonde tracking control")
        ip = host(s, K.V_OT, 31)
        self.iot("wx_hmi", "HMI-PT", "IWS-HMI-01", group=g, ip=ip, vlan=K.V_OT,
                 site=s, role="Forecaster panel (instrument status)")
        ip = host(s, K.V_OT, 32)
        self.iot("wx_mob", "PLC-PT", "IWS-MOBILE-CTL", group=g, ip=ip,
                 vlan=K.V_OT, site=s,
                 role="Mobile observation system deployment control")

    # ================================================================== #
    # 10. air depots & bulk fuel farm
    # ================================================================== #
    def build_depot(self) -> None:
        """3rd Air Depot holds communications/electronics and meteorological
        materiel; 4th Air Depot holds general supply."""
        g = "T11-depot"
        s = S_DEP0
        self.add("depr1", "ISR4331", "DEP-RTR-01", group=g, site="DEPOT",
                 ip=host(s, K.V_MGMT, 2),
                 role="Air depot zone router (OSPF ABR)", modules=["NIM-2T"])
        self.add("depsw1", "2960-24TT", "3DEP-SW-01", group=g, site="DEPOT",
                 ip=host(s, K.V_MGMT, 11),
                 role="3rd Air Depot electronics and met-materiel switch")
        self.add("depsw2", "2960-24TT", "4DEP-SW-01", group=g, site="DEPOT",
                 ip=host(s, K.V_MGMT, 12),
                 role="4th Air Depot general supply switch")
        for key, name, vlan, h, role in [
            ("dep_wms", "3DEP-WMS-SVR", K.V_SRV, 20,
             "Depot warehouse management system"),
            ("dep_elx", "3DEP-ELX-SVR", K.V_SRV, 21,
             "Communications and electronics repair bench management"),
            ("dep_met", "3DEP-MET-SVR", K.V_SRV, 22,
             "Meteorological materiel calibration and stock"),
            ("dep_sup", "4DEP-SUPPLY-SVR", K.V_SRV, 23,
             "General supply chain and spares application"),
            ("dep_hist", "DEP-HIST-01", K.V_SRV, 24,
             "Depot stock movement historian"),
        ]:
            ip = host(s, vlan, h)
            self.add(key, "Server-PT", name, group=g, site="DEPOT", ip=ip,
                     role=role, pc_ip=(ip, M24, gw(s, vlan)))
        for i in range(4):
            ip = host(s, K.V_IOT, 20 + i)
            self.iot(f"dep_rfid{i + 1}", "RFID Reader", f"DEP-RFID-{i + 1:02d}",
                     group=g, ip=ip, vlan=K.V_IOT, site=s,
                     role=f"Warehouse bay {i + 1} stock RFID portal")
        for i in range(2):
            ip = host(s, K.V_GV, 20 + i)
            self.iot(f"dep_fork{i + 1}", "PLC-PT", f"DEP-FORK-PLC-{i + 1:02d}",
                     group=g, ip=ip, vlan=K.V_GV, site=s,
                     role=f"Warehouse forklift {i + 1} guidance controller")
        for i in range(self.p["depot_terms"]):
            ip = host(s, K.V_OPS, 40 + i)
            self.end(f"dep_pc{i + 1}", "PC-PT", f"DEP-TERM-{i + 1:02d}", group=g,
                     ip=ip, gw_=gw(s, K.V_OPS), site="DEPOT",
                     role="Depot stores and issue terminal")
        for i in range(2):
            ip = host(s, K.V_CCTV, 30 + i)
            self.iot(f"dep_cam{i + 1}", "Webcam", f"DEP-CAM-{i + 1:02d}", group=g,
                     ip=ip, vlan=K.V_CCTV, site=s,
                     role=f"Warehouse aisle {i + 1} security camera")
            ip = host(s, K.V_CCTV, 40 + i)
            self.iot(f"dep_door{i + 1}", "Door", f"DEP-DOOR-{i + 1:02d}", group=g,
                     ip=ip, vlan=K.V_CCTV, site=s,
                     role=f"Warehouse secure store door {i + 1} controller")
        for i in range(2):
            ip = host(s, K.V_IOT, 40 + i)
            self.iot(f"dep_smk{i + 1}", "Smoke Detector", f"DEP-SMOKE-{i + 1:02d}",
                     group=g, ip=ip, vlan=K.V_IOT, site=s,
                     role=f"Warehouse bay {i + 1} smoke detection")
        ip = host(s, K.V_IOT, 50)
        self.iot("dep_fire", "Fire Monitor", "DEP-FIRE-01", group=g, ip=ip,
                 vlan=K.V_IOT, site=s, role="Depot sprinkler and fire monitor")
        ip = host(s, K.V_OT, 50)
        self.iot("dep_pwr", "Power Meter", "DEP-PWR-01", group=g, ip=ip,
                 vlan=K.V_OT, site=s, role="Depot switchboard power meter")

    def build_pol(self) -> None:
        g = "T12-pol"
        s = S_POL
        self.add("polr1", "ISR4331", "POL-RTR-01", group=g, site="POL",
                 ip=host(s, K.V_MGMT, 2),
                 role="Bulk fuel farm zone router (OSPF ABR)", modules=["NIM-2T"])
        self.add("polsw1", "IE-3400", "POL-SW-01", group=g, site="POL",
                 ip=host(s, K.V_MGMT, 11),
                 role="Fuel farm tank farm industrial switch (ex-rated)")
        self.add("polsw2", "IE-2000", "POL-SW-02", group=g, site="POL",
                 ip=host(s, K.V_MGMT, 12),
                 role="Fuel farm pump house and issue point switch")
        self.add("polsw3", "IE-3400", "POL-SW-03", group=g, site="POL",
                 ip=host(s, K.V_MGMT, 13),
                 role="Fuel farm tank gauging switch (level and leak detection)")
        ip = host(s, K.V_SRV, 20)
        self.add("pol_srv", "Server-PT", "POL-FUEL-SVR", group=g, site="POL",
                 ip=ip, role="Fuel stock accounting and issue authorisation",
                 pc_ip=(ip, M24, gw(s, K.V_SRV)))
        for key, name, vlan, h, role in [
            ("pol_pmp1", "POL-PUMP-PLC-01", K.V_OT, 20,
             "main fuel transfer pump set control"),
            ("pol_pmp2", "POL-PUMP-PLC-02", K.V_OT, 21,
             "backup pump set and filtration control"),
        ]:
            ip = host(s, vlan, h)
            self.iot(key, "PLC-PT", name, group=g, ip=ip, vlan=vlan, site=s,
                     role=f"Fuel farm PLC - {role}")
        n_tanks = max(2, min(self.p["tanks"], len(POL_TANKS)))
        for i, (code, label, note) in enumerate(POL_TANKS[:n_tanks]):
            ip = host(s, K.V_OT, 30 + i)
            self.iot(f"pol_tk{i + 1}", "PLC-PT", f"POL-{code}-PLC", group=g, ip=ip,
                     vlan=K.V_OT, site=s,
                     role=f"{label} tank gauging and valve control ({note})")
            ip = host(s, K.V_POL, 30 + i)
            self.iot(f"pol_lv{i + 1}", "Water Level Monitor", f"POL-{code}-LEVEL",
                     group=g, ip=ip, vlan=K.V_POL, site=s,
                     role=f"{label} tank level and water-bottom detection")
        for i in range(2):
            ip = host(s, K.V_POL, 60 + i)
            self.iot(f"pol_leak{i + 1}", "Water Level Monitor",
                     f"POL-LEAK-{i + 1:02d}", group=g, ip=ip, vlan=K.V_POL,
                     site=s, role=f"Fuel farm bund {i + 1} leak detection")
            ip = host(s, K.V_IOT, 60 + i)
            self.iot(f"pol_fire{i + 1}", "Fire Monitor", f"POL-FIRE-{i + 1:02d}",
                     group=g, ip=ip, vlan=K.V_IOT, site=s,
                     role=f"Fuel farm bund {i + 1} foam fire suppression monitor")
        ip = host(s, K.V_IOT, 70)
        self.iot("pol_siren", "Siren", "POL-SIREN-01", group=g, ip=ip,
                 vlan=K.V_IOT, site=s, role="Fuel farm evacuation alarm")
        ip = host(s, K.V_OT, 70)
        self.iot("pol_hmi", "HMI-PT", "POL-HMI-01", group=g, ip=ip,
                 vlan=K.V_OT, site=s, role="Fuel farm operator panel")
        ip = host(s, K.V_OT, 80)
        self.iot("pol_mtr1", "Power Meter", "POL-METER-01", group=g, ip=ip,
                 vlan=K.V_OT, site=s, role="Fuel farm pump house power meter")

    # ================================================================== #
    # 11. security, utilities & wireless
    # ================================================================== #
    def build_security(self) -> None:
        g = "T13-sec"
        s = S_SEC
        self.add("secr1", "ISR4331", "SEC-RTR-01", group=g, site="SEC",
                 ip=host(s, K.V_MGMT, 2),
                 role="Security forces zone router (OSPF ABR)", modules=["NIM-2T"])
        self.add("secsw1", "3560-24PS", "SEC-SW-01", group=g, site="SEC",
                 ip=host(s, K.V_MGMT, 11), role="Physical security PoE switch A")
        self.add("secsw2", "2960-24TT", "SEC-SW-02", group=g, site="SEC",
                 ip=host(s, K.V_MGMT, 12), role="Physical security PoE switch B")
        for key, name, vlan, h, role in [
            ("sec_nvr", "CCTV-NVR-01", K.V_CCTV, 20,
             "CCTV recording and video analytics"),
            ("sec_acs", "ACS-DOOR-SVR-01", K.V_CCTV, 21,
             "Door access control and credential service"),
        ]:
            ip = host(s, vlan, h)
            self.add(key, "Server-PT", name, group=g, site="SEC", ip=ip,
                     role=role, pc_ip=(ip, M24, gw(s, vlan)))
        n_cam = self.p["cams"]
        for i in range(n_cam):
            ip = host(s, K.V_CCTV, 30 + i)
            zone = ["perimeter north", "perimeter east", "perimeter south",
                    "perimeter west", "main gate", "hangar line"][i % 6]
            self.iot(f"cam{i + 1}", "Webcam", f"PERIM-CAM-{i + 1:02d}", group=g,
                     ip=ip, vlan=K.V_CCTV, site=s,
                     role=f"Perimeter CCTV camera head - {zone}")
        for i in range(4):
            ip = host(s, K.V_CCTV, 60 + i)
            self.iot(f"acs{i + 1}", "Door", f"ACS-DOOR-{i + 1:02d}", group=g,
                     ip=ip, vlan=K.V_CCTV, site=s,
                     role=f"Controlled door {i + 1} access controller")
        for i in range(2):
            ip = host(s, K.V_IOT, 30 + i)
            self.iot(f"perim{i + 1}", "Trip Sensor", f"PERIM-TRIP-{i + 1:02d}",
                     group=g, ip=ip, vlan=K.V_IOT, site=s,
                     role=f"Perimeter intrusion trip sensor line {i + 1}")
        for key, name, model, vlan, h, role in [
            ("sec_siren", "PERIM-SIREN-01", "Siren", K.V_IOT, 40,
             "perimeter intrusion alarm and dispersal siren"),
            ("sec_fire", "SEC-FIRE-01", "Fire Monitor", K.V_IOT, 41,
             "crash crew building fire monitor"),
            ("sec_co", "SEC-CO-01", "CO Detector", K.V_IOT, 42,
             "appliance bay carbon monoxide detection"),
            ("sec_smoke", "SEC-SMOKE-01", "Smoke Detector", K.V_IOT, 43,
             "security operations room smoke detection"),
        ]:
            ip = host(s, vlan, h)
            self.iot(key, model, name, group=g, ip=ip, vlan=vlan, site=s, role=role)
        self.add("ghsw1", "2960-24TT", "GATE-HOUSE-SW-01", group=g, site="SEC",
                 ip=host(s, K.V_MGMT, 21), role="Main gate house access switch")
        ip = host(s, K.V_OPS, 30)
        self.end("gh_ws", "PC-PT", "GATE-HOUSE-WS-01", group=g, ip=ip,
                 gw_=gw(s, K.V_OPS), site="SEC",
                 role="Main gate pass and visitor processing workstation")
        ip = host(s, K.V_CCTV, 70)
        self.iot("gh_cam", "Webcam", "GATE-HOUSE-CAM-01", group=g, ip=ip,
                 vlan=K.V_CCTV, site=s, role="Main gate vehicle inspection camera")

    def build_utilities(self) -> None:
        g = "T14-util"
        s = S_UTIL
        self.add("utilr1", "ISR4331", "UTIL-RTR-01", group=g, site="UTIL",
                 ip=host(s, K.V_MGMT, 2),
                 role="Utilities and standby power zone router (OSPF ABR)",
                 modules=["NIM-2T"])
        self.add("utilsw1", "IE-3400", "UTIL-SW-01", group=g, site="UTIL",
                 ip=host(s, K.V_MGMT, 11),
                 role="Substation and standby power industrial switch")
        self.add("utilsw2", "IE-2000", "UTIL-SW-02", group=g, site="UTIL",
                 ip=host(s, K.V_MGMT, 12), role="Base services industrial switch")
        for key, name, vlan, h, role in [
            ("util_sub", "SUBSTN-PLC-01", K.V_OT, 20,
             "Primary substation protection and switching PLC"),
            ("util_gen", "GENERATOR-PLC-01", K.V_OT, 21,
             "Standby generator start and load-transfer PLC"),
            ("util_ups", "UPS-CTL-01", K.V_OT, 22,
             "UPS and static transfer switch controller"),
        ]:
            ip = host(s, vlan, h)
            self.iot(key, "PLC-PT", name, group=g, ip=ip, vlan=vlan, site=s,
                     role=f"Base utilities - {role}")
        for i in range(4):
            ip = host(s, K.V_OT, 30 + i)
            self.iot(f"util_pm{i + 1}", "Power Meter", f"PWR-METER-{i + 1:02d}",
                     group=g, ip=ip, vlan=K.V_OT, site=s,
                     role=f"Base electrical power quality meter {i + 1}")
        for key, name, model, vlan, h, role in [
            ("util_smk1", "UTIL-SMOKE-01", "Smoke Detector", K.V_IOT, 20,
             "substation smoke detection"),
            ("util_smk2", "UTIL-SMOKE-02", "Smoke Detector", K.V_IOT, 21,
             "standby generator hall smoke detection"),
            ("util_water", "UTIL-WATER-01", "Water Level Monitor", K.V_IOT, 22,
             "base water reservoir level and pump control"),
            ("util_fire", "UTIL-FIRE-01", "Fire Monitor", K.V_IOT, 23,
             "substation fire suppression monitor"),
            ("util_batt", "UTIL-BATT-01", "Battery", K.V_OT, 40,
             "grid-scale battery energy storage controller"),
            ("util_solar", "UTIL-SOLAR-01", "Solar Panel", K.V_OT, 41,
             "base solar photovoltaic array controller"),
        ]:
            ip = host(s, vlan, h)
            self.iot(key, model, name, group=g, ip=ip, vlan=vlan, site=s, role=role)
        ip = host(s, K.V_OT, 50)
        self.iot("util_hmi", "HMI-PT", "UTIL-HMI-01", group=g, ip=ip,
                 vlan=K.V_OT, site=s,
                 role="Base utilities operator panel (power and water)")

    def build_wireless(self) -> None:
        g = "T15-wlan"
        s = S_WLAN
        for i, (k, n, r) in enumerate([
            ("wlc1", "IRM-WLC-01", "Base WLAN controller A (aircrew, apron, guest)"),
            ("wlc2", "IRM-WLC-02", "Base WLAN controller B (HA pair)"),
        ]):
            self.add(k, "WLC-3504", n, group=g, site="WLAN",
                     ip=host(s, K.V_MGMT, 2 + i), role=r)
        self.add("wlsw1", "3560-24PS", "WLAN-DSW-01", group=g, site="WLAN",
                 ip=host(s, K.V_MGMT, 11), role="WLAN distribution switch (PoE)")
        self.add("wlsw2", "2960-24TT", "WLAN-ACC-01", group=g, site="WLAN",
                 ip=host(s, K.V_MGMT, 12), role="WLAN access switch (outdoor APs)")
        n_ap = self.p["aps"]
        for i in range(n_ap):
            zone = ["APRON", "TENANT", "DEPOT", "TOWER", "POL", "SECURITY"][i % 6]
            key = f"ap{i + 1}"
            self.add(key, "AccessPoint-PT-N", f"IRM-AP-{i + 1:02d}", group=g,
                     site="WLAN", ip=host(s, K.V_MGMT, 30 + i),
                     role=f"Outdoor 802.11ac AP - {zone} coverage")
            self.wireless(key, "IRM-APRON-WLAN" if zone in ("APRON", "POL")
                          else "IRM-BASE-WLAN")

    # ================================================================== #
    # 12. mobile estate
    # ================================================================== #
    def build_clients(self) -> None:
        g = "T16-mobile"
        s = S_AOC
        n = self.p["clients"]
        for i in range(n):
            ip = host(s, K.V_WIFI, 60 + i)
            self.end(f"efb{i + 1}", "TabletPC-PT", f"EFB-{i + 1:02d}", group=g,
                     ip=ip, gw_=gw(s, K.V_WIFI), site="MOBILE",
                     role="Aircrew electronic flight bag tablet")
            self.wireless(f"efb{i + 1}", "IRM-AIRCREW-WLAN")
        for i in range(max(2, n // 4)):
            ip = host(s, K.V_WIFI, 90 + i)
            self.end(f"hh{i + 1}", "SMARTPHONE-PT", f"HANDSET-{i + 1:02d}", group=g,
                     ip=ip, gw_=gw(s, K.V_WIFI), site="MOBILE",
                     role="Base duty handset (voice and alerting)")
            self.wireless(f"hh{i + 1}", "IRM-BASE-WLAN")

    # ================================================================== #
    # cabling
    # ================================================================== #
    def cable(self) -> None:
        """Cable the base.

        Port names are not free text: each one is a name Packet Tracer resolves
        at load, and a single name that matches no port on the device makes the
        **whole file** refuse to open.  Every name below is either attested by
        the model's own factory config (``build/port_table.json``) or verified
        against Packet Tracer by ``tools/pt_port_verify.py``.
        """
        # ---- backbone ------------------------------------------------ #
        self.rlink("bb1", GE1(1), "bb2", GE1(1))
        self.rlink("bb1", GE1(2), "cr1", "GigabitEthernet0/0/0")
        self.rlink("bb2", GE1(2), "cr2", "GigabitEthernet0/0/0")
        self.rlink("bb1", GE1(3), "cr2", "GigabitEthernet0/0/1")
        self.rlink("bb2", GE1(3), "cr1", "GigabitEthernet0/0/1")
        self.rlink("cr1", "GigabitEthernet0/0/2", "we1", "GigabitEthernet0/0")
        self.rlink("cr2", "GigabitEthernet0/0/2", "we2", "GigabitEthernet0/0")
        self.slink("we1", "Serial0/0/0", "we2", "Serial0/0/0", dce="we1",
                   clock=4_000_000)
        self.rlink("bb1", GE1(4), "dci1", "GigabitEthernet0/0/0")
        self.rlink("bb2", GE1(4), "mgw", "GigabitEthernet0/0/0")

        # ---- carrier / external liaison edge -------------------------- #
        self.rlink("bb1", GE1(5), "ce1", "GigabitEthernet0/0/0")
        self.rlink("bb2", GE1(5), "ce2", "GigabitEthernet0/0/0")
        # Cloud-PT exposes "Port 0"; every Ethernet/Gigabit/Serial/Coaxial name
        # was tested and rejected (see tools/port_table.py).
        self.rlink("isp1", "Port 0", "ce1", "GigabitEthernet0/0/1")
        self.rlink("isp2", "Port 0", "ce2", "GigabitEthernet0/0/1")
        self.rlink("ce1", "GigabitEthernet0/0/2", "fwext", "Ethernet0/0")
        self.link("fwext", "Ethernet0/1", "dmzsw", GE0(1))
        # liaison partners terminate on the DMZ switch behind the firewall
        for i, key in enumerate(("modgw", "yokgw", "jwsgw", "polgw", "sigintgw",
                                 "edisrv", "proxy", "mailgw")):
            port = ("FastEthernet0" if self.meta[key]["model"] == "Server-PT"
                    else "GigabitEthernet0/0/0")
            self.link("dmzsw", FE0(1 + i), key, port)

        # ---- air defence & mission data centre ------------------------ #
        self.rlink("bb1", GE1(6), "mdcfw", "Ethernet0/0")
        self.link("mdcfw", "Ethernet0/1", "mdcs1", GE1(1))
        self.link("mdcs1", GE1(2), "mdcs2", GE1(2))
        # The second spine reaches its leaf through the internal segmentation
        # firewall, so that device is genuinely in a path rather than built,
        # cabled to nothing and left holding its template's config.
        self.link("mdcs1", GE1(3), "mdcl1", GE0(1))
        self.rlink("mdcs2", GE1(3), "mdcfw2", "Ethernet0/0")
        self.link("mdcfw2", "Ethernet0/1", "mdcl2", GE0(1))
        self.link("mdcl1", GE0(2), "mdcl2", GE0(2))
        for i, (key, _n, _s, _d, _ip) in enumerate(self.servers):
            sw = "mdcl1" if i < 24 else "mdcl2"
            self.link(sw, FE0(1 + (i % 24)), key, "FastEthernet0")

        # ---- backup data centre -------------------------------------- #
        self.rlink("bb2", GE1(18), "bdcfw", "Ethernet0/0")
        self.link("bdcfw", "Ethernet0/1", "bdcs1", GE1(1))
        self.link("bdcs1", GE1(2), "bdcl1", GE0(1))
        for i, key in enumerate(self._bdc_keys()):
            self.link("bdcl1", FE0(1 + (i % 24)), key, "FastEthernet0")

        # ---- operations-security enclave ------------------------------ #
        self.rlink("bb2", GE1(6), "osfw1", "Ethernet0/0")
        self.link("osfw1", "Ethernet0/1", "ossw1", GE0(1))
        self.link("osfw1", "Ethernet0/2", "osfw2", "Ethernet0/0")
        self.link("osfw2", "Ethernet0/1", "ossw2", GE0(1))
        dmz = [("osids", "GigabitEthernet0"), ("ostap", "Ethernet1"),
               ("os_ato", "FastEthernet0"), ("os_task", "FastEthernet0"),
               ("os_crypt", "FastEthernet0"), ("os_ws1", "FastEthernet0"),
               ("os_ws2", "FastEthernet0")]
        for i, (key, port) in enumerate(dmz):
            self.link("ossw1", FE0(1 + i), key, port)
        for i, key in enumerate(("os_db1", "os_db2", "os_hsm", "os_audit")):
            self.link("ossw2", FE0(1 + i), key, "FastEthernet0")

        # ---- air operations centre / tower ---------------------------- #
        self.rlink("bb1", GE1(7), "aocr1", "GigabitEthernet0/0/0")
        self.rlink("bb2", GE1(7), "aocr2", "GigabitEthernet0/0/0")
        self.link("aocr1", "GigabitEthernet0/0/1", "aocd1", GE0(1))
        self.link("aocr2", "GigabitEthernet0/0/1", "aocd2", GE0(1))
        self.link("aocd1", GE0(2), "aocd2", GE0(2))
        self.link("aocd1", FE0(1), "aoca1", GE0(1))
        self.link("aocd2", FE0(1), "aoca2", GE0(1))
        aoc_end = [k for k in self.sid if k.startswith(("aoc_", "aocw", "aocp"))]
        for i, key in enumerate(aoc_end):
            sw = "aoca1" if i < 8 else "aoca2"
            model = self.meta[key]["model"]
            # A 7960 IP phone rejects FastEthernet0; its network port is "Switch"
            # (the "PC" port is the passthrough for a co-located workstation).
            port = "Switch" if model == "7960" else "FastEthernet0"
            self.link(sw, FE0(1 + (i % 8)), key, port)

        # ---- air traffic control & navaids ---------------------------- #
        self.rlink("bb1", GE1(8), "atcr1", "GigabitEthernet0/0/0")
        self.rlink("bb2", GE1(8), "atcr2", "GigabitEthernet0/0/0")
        self.link("atcr1", "GigabitEthernet0/0/1", "atcsw1", GE1(1))
        self.link("atcr2", "GigabitEthernet0/0/1", "atcsw2", GE1_1(1))
        self.link("atcsw1", GE1(2), "atcsw2", GE1_1(2))
        atc_srv = [k for k in self.sid if k.startswith("atc_")
                   and self.meta[k]["model"] == "Server-PT"]
        for i, key in enumerate(atc_srv):
            self.link("atcsw1", GE1(3 + i), key, "FastEthernet0")
        atc_plc = [k for k in self.sid if k.startswith("atc_")
                   and self.meta[k]["model"] in ("PLC-PT", "HMI-PT")]
        for i, key in enumerate(atc_plc):
            if i < 4:
                self.link("atcsw1", GE1(9 + i), key, "GigabitEthernet0")
            else:
                self.link("atcsw2", GE1_1(3 + (i - 4)), key, "GigabitEthernet0")

        # ---- tenants and the hospital --------------------------------- #
        for tn in self.tenants:
            n = tn["idx"]
            self.rlink("bb1", GE1(9 + n), f"tn{n}sw", GE0(1))
            tn_end = [k for k in self.sid
                      if k.startswith(f"tn{n}")
                      and k not in (f"tn{n}sw", f"tn{n}hgr",
                                    f"tn{n}plc", f"tn{n}fire")]
            for i, key in enumerate(tn_end):
                model = self.meta[key]["model"]
                port = "Switch" if model == "7960" else "FastEthernet0"
                self.link(f"tn{n}sw", FE0(1 + i), key, port)
            if tn["weight"] == "full":
                self.link(f"tn{n}sw", GE0(2), f"tn{n}hgr", GE0(1))
                self.link(f"tn{n}hgr", FE0(1), f"tn{n}plc", "GigabitEthernet0")
                self.link(f"tn{n}hgr", FE0(2), f"tn{n}fire", "FastEthernet0")
        self.rlink("bb2", GE1(19), "hospr1", "GigabitEthernet0/0/0")
        self.link("hospr1", "GigabitEthernet0/0/1", "hosp_sw", GE0(1))
        hosp_end = [k for k in self.sid
                    if k.startswith(("hosp_", "hosp_w"))
                    and k != "hosp_sw"]
        for i, key in enumerate(hosp_end):
            self.link("hosp_sw", FE0(1 + i), key, "FastEthernet0")

        # ---- apron and flight line ------------------------------------ #
        self.rlink("bb1", GE1(16), "apragg1", GE1(1))
        self.rlink("bb2", GE1(16), "apragg2", GE1(1))
        self.link("apragg1", GE1(28), "apragg2", GE1(28))
        for ap in self.aprons:
            n = ap["idx"]
            self.link("apragg1", GE1(1 + n), f"ap{n}sw", GE1_1(1))
            for j, suffix in enumerate(("gse", "fuel", "lgt", "cam", "fod")):
                model = self.meta[f"ap{n}{suffix}"]["model"]
                port = ("GigabitEthernet0" if model == "PLC-PT"
                        else "FastEthernet0")
                self.link(f"ap{n}sw", GE1_1(2 + j), f"ap{n}{suffix}", port)
        self.link("apragg2", GE1(2), "fltsw1", GE1(1))
        self.link("apragg2", GE1(3), "fltsw2", GE1_1(1))
        self.link("fltsw1", GE1(2), "fltsw2", GE1_1(2))
        for i, key in enumerate(("arff_srv", "bird_srv", "fm_srv")):
            self.link("fltsw1", GE1(3 + i), key, "FastEthernet0")
        self.link("fltsw1", GE1(6), "arff_ws", "FastEthernet0")
        for i, key in enumerate(("flt_fuel", "flt_hot", "flt_sweep", "flt_tow",
                                 "flt_gse", "arff_plc")):
            if i < 3:
                self.link("fltsw1", GE1(7 + i), key, "GigabitEthernet0")
            else:
                self.link("fltsw2", GE1_1(3 + (i - 3)), key, "GigabitEthernet0")

        # ---- air weather squadron ------------------------------------- #
        self.link("wxr1", "GigabitEthernet0/0/1", "wxsw1", GE0(1))
        wx_srv = [k for k in self.sid if k.startswith("wx_")
                  and self.meta[k]["model"] == "Server-PT"]
        wx_sen = [k for k in self.sid if k.startswith("wx_")
                  and self.meta[k]["model"] not in ("Server-PT", "2960-24TT")]
        for i, key in enumerate(wx_srv + wx_sen):
            model = self.meta[key]["model"]
            port = ("GigabitEthernet0" if model in ("PLC-PT", "HMI-PT")
                    else "FastEthernet0")
            self.link("wxsw1", FE0(1 + i), key, port)

        # ---- air depots ------------------------------------------------ #
        self.rlink("bb1", GE1(21), "depr1", "GigabitEthernet0/0/0")
        self.link("depr1", "GigabitEthernet0/0/1", "depsw1", GE0(1))
        self.link("depsw1", GE0(2), "depsw2", GE0(1))
        dep_end = [k for k in self.sid
                   if k.startswith("dep_") or k.startswith("dep_pc")]
        for i, key in enumerate(dep_end):
            sw = "depsw1" if i < 12 else "depsw2"
            model = self.meta[key]["model"]
            port = "GigabitEthernet0" if model == "PLC-PT" else "FastEthernet0"
            self.link(sw, FE0(1 + (i % 12)), key, port)

        # ---- bulk fuel farm ------------------------------------------- #
        self.rlink("bb2", GE1(20), "polr1", "GigabitEthernet0/0/0")
        self.link("polr1", "GigabitEthernet0/0/1", "polsw1", GE1_1(1))
        self.link("polsw1", GE1_1(2), "polsw2", GE2000(1))
        self.link("polsw1", GE1_1(3), "polsw3", GE1_1(1))
        self.link("polsw1", GE1_1(10), "pol_srv", "FastEthernet0")
        pol_tank = [k for k in self.sid if k.startswith("pol_tk")]
        pol_lvl = [k for k in self.sid if k.startswith("pol_lv")]
        for i, key in enumerate(pol_tank):
            self.link("polsw1", GE1_1(4 + i), key, "GigabitEthernet0")
        for i, key in enumerate(pol_lvl):
            self.link("polsw3", GE1_1(2 + i), key, "FastEthernet0")
        pol_rest = [k for k in self.sid
                    if k.startswith("pol_") and k != "pol_srv"
                    and not k.startswith(("pol_tk", "pol_lv"))]
        for i, key in enumerate(pol_rest):
            model = self.meta[key]["model"]
            port = ("GigabitEthernet0"
                    if model in ("PLC-PT", "HMI-PT") else "FastEthernet0")
            if i < 8:
                self.link("polsw2", FE2000(1 + i), key, port)
            else:
                self.link("polsw2", GE2000(2 + (i - 8)), key, port)

        # ---- security -------------------------------------------------- #
        self.rlink("bb1", GE1(22), "secr1", "GigabitEthernet0/0/0")
        self.link("secr1", "GigabitEthernet0/0/1", "secsw1", GE0(1))
        self.link("secsw1", GE0(2), "secsw2", GE0(1))
        self.link("secsw1", FE0(1), "ghsw1", GE0(1))
        sec_end = [k for k in self.sid
                   if k.startswith(("sec_", "cam", "acs", "perim", "gh_"))
                   and k != "ghsw1"]
        for i, key in enumerate(sec_end):
            if i < 12:
                sw, slot = "secsw1", i
            elif i < 24:
                sw, slot = "secsw2", i - 12
            else:
                sw, slot = "ghsw1", i - 24
            model = self.meta[key]["model"]
            port = ("GigabitEthernet0" if model == "CyberObserver"
                    else "FastEthernet0")
            self.link(sw, FE0(1 + (slot % 12)), key, port)

        # ---- utilities -------------------------------------------------- #
        self.rlink("bb2", GE1(21), "utilr1", "GigabitEthernet0/0/0")
        self.link("utilr1", "GigabitEthernet0/0/1", "utilsw1", GE1_1(1))
        self.link("utilsw1", GE1_1(2), "utilsw2", GE2000(1))
        util_end = [k for k in self.sid if k.startswith("util_")]
        for i, key in enumerate(util_end):
            model = self.meta[key]["model"]
            port = ("GigabitEthernet0"
                    if model in ("PLC-PT", "HMI-PT", "Solar Panel")
                    else "FastEthernet0")
            if i < 6:
                self.link("utilsw1", GE1_1(3 + i), key, port)
            else:
                self.link("utilsw2", FE2000(1 + (i - 6)), key, port)

        # ---- wireless ---------------------------------------------------- #
        # A 3560-24PS has exactly two GigabitEthernet0/x uplinks (0/1 and 0/2),
        # so the two controllers hang off different switches.
        #
        # A WLC-3504 rejects every GigabitEthernet0/x name; its network port is
        # GigabitEthernet1 (verified against Packet Tracer).
        self.link("bb1", GE1(23), "wlsw1", GE0(1))
        self.link("wlsw1", GE0(2), "wlc1", "GigabitEthernet1")
        self.link("wlsw2", GE0(1), "wlsw1", FE0(1))
        self.link("wlsw2", GE0(2), "wlc2", "GigabitEthernet1")
        for i in range(self.p["aps"]):
            key = f"ap{i + 1}"
            if i < 10:
                self.link("wlsw1", FE0(2 + i), key, "Port 0")
            else:
                self.link("wlsw2", FE0(2 + (i - 10)), key, "Port 0")

        # ---- NetOps enclave ---------------------------------------------- #
        self.rlink("mgw", "GigabitEthernet0/0/1", "nocsw1", GE0(1))
        for i, (key, port) in enumerate([
                ("nms", "FastEthernet0"), ("jump", "FastEthernet0"),
                ("cobs", "GigabitEthernet0"), ("tap", "Ethernet1"),
                ("tacacs", "FastEthernet0")]):
            self.link("nocsw1", FE0(1 + i), key, port)

    def order_devices_for_layout(self) -> int:
        """Reorder the DEVICE elements so each device packs beside its cables.

        ``finalise_lab`` repacks in **document order**, so document order *is*
        packing order.  Emitting each band as a breadth-first walk of its own
        cable graph puts a switch next to the devices it serves instead of
        scattering them.  Only the order of ``<DEVICE>`` children changes;
        links reference devices by id, so nothing else is affected.
        """
        adj = self._adjacency()
        band = self._bands()
        band_order = self._band_order_for_layout(band)

        # Chunks are sized to one packing row.  The packer fills a row
        # left-to-right and wraps at the row end, so a cluster that straddles a
        # boundary gets its switch at one end of the page and its access devices
        # at the other -- measured at 3,538 units for a tenant switch to its own
        # workstation.  A chunk that *is* a row cannot straddle: its cables run
        # along the row instead of across the page.
        row_capacity = self._row_capacity()

        # Ties are broken by creation index throughout.  A `set` iterates in an
        # order that varies between processes, so a set-based `max` here makes
        # two runs of the same profile produce different files -- which breaks
        # the byte-identical rebuild this repo publishes a hash for.
        seq = {k: i for i, k in enumerate(self.sid)}
        order: list[str] = []
        for grp in band_order:
            members = set(k for k in self.sid if band[k] == grp)
            while members:
                seed = max(members, key=lambda k: (
                    sum(1 for n in adj[k] if n in members), -seq[k]))
                chunk: list[str] = []
                queue = [seed]
                while queue and len(chunk) < row_capacity:
                    cur = queue.pop(0)
                    if cur not in members:
                        continue
                    members.discard(cur)
                    chunk.append(cur)
                    queue.extend(sorted(
                        (n for n in adj[cur] if n in members),
                        key=lambda n: (-sum(1 for m in adj[n] if m in members),
                                       seq[n])))
                # Centre the hub in its row.  A chunk is a packing row, so the
                # hub at one end is ~3,400 units from the child at the other;
                # in the middle it is at most half that, and its fan is
                # symmetric instead of one-sided.
                hub, rest = chunk[0], chunk[1:]
                half = len(rest) // 2
                order.extend(rest[:half][::-1] + [hub] + rest[half:])
        if len(order) != len(self.sid):
            raise SystemExit("layout ordering lost or duplicated a device")

        devs = self.lab.devs
        for el in list(devs.findall("DEVICE")):
            devs.remove(el)
        for key in order:
            devs.append(self.lab._els[self.sid[key]])
        return len(order)

    def _row_capacity(self) -> int:
        """How many of this lab's devices fit across one packing row.

        Derived from the same label-inclusive boxes the packer uses, so it
        tracks the actual names rather than assuming a width.
        """
        import lab_api                                        # noqa: PLC0415
        widths = []
        for k, m in self.meta.items():
            kind = lab_api.kind_for_model(m["model"])
            widths.append(lab_api.device_box(kind, m["name"], m["model"])[0])
        if not widths:
            return 1
        usable = lab_api.CANVAS_MAX - lab_api.CANVAS_MIN - 60
        # The packer places boxes until the next one would not fit, so the
        # capacity is how many *median-width* boxes fit, less one for slack.
        widths.sort()
        median = widths[len(widths) // 2]
        return max(1, usable // median - 1)

    def _band_order_for_layout(self, band: dict[str, str]) -> list[str]:
        """Order the bands by their cable graph, not by their narrative.

        Bands are stacked in the order their first device appears in the
        document, so this decides where each band sits on the page.  The stock
        answer -- the order the generator happens to build them in -- puts the
        collapsed core at the top and every zone below it, so the core's fan to
        ~17 zone devices crosses everything in between: **70% of all cable
        crossings on this lab involve a core-band cable.**

        A fan is shortest when its source sits at the centroid of its
        destinations, so the band with the most inter-band cables goes in the
        middle and the rest alternate around it, strongest connection nearest.
        This trades the conventional "edge at the top" reading order for a
        measurably calmer picture; the trade is recorded in VALIDATION.md.
        """
        counts: collections.Counter = collections.Counter()
        for (a, _ap, b, _bp, _k, _d) in self.links:
            if band[a] != band[b]:
                counts[band[a]] += 1
                counts[band[b]] += 1
        if not counts:
            return list(dict.fromkeys(band[k] for k in self.sid))

        hub = counts.most_common(1)[0][0]
        rest = [g for g in dict.fromkeys(band[k] for k in self.sid) if g != hub]
        rest.sort(key=lambda g: -counts[g])

        # Alternate strongest-connection-nearest, above and below the hub.
        above: list[str] = []
        below: list[str] = []
        for i, g in enumerate(rest):
            (below if i % 2 == 0 else above).append(g)
        return list(reversed(above)) + [hub] + below

    # -- cluster placement ------------------------------------------------ #
    def _adjacency(self) -> dict[str, list[str]]:
        adj: dict[str, list[str]] = collections.defaultdict(list)
        for (a, _ap, b, _bp, _k, _d) in self.links:
            adj[a].append(b)
            adj[b].append(a)
        return adj

    def _bands(self) -> dict[str, str]:
        return {k: GROUP_MERGE.get(m["group"], m["group"])
                for k, m in self.meta.items()}

    def place_sections(self, max_width: int = 1150, col_gap: int = 90,
                       row_gap: int = 70, rect_pad: int = 55) -> list[dict]:
        """Lay the model out as labelled **sections**, not as one long chain.

        A band of loose icons is still a chain: the reader can see that there are
        392 devices and no way to find the fuel farm.  This places each section
        as its own block -- a rectangle of devices with space around it -- and
        returns the blocks so :meth:`add_section_clusters` can wrap each one in a
        Packet Tracer cluster, which draws the section's **name** on the canvas.

        Blocks are packed masonry-style into three columns, each block going to
        the shortest column that can hold it.  Sections are emitted in the order
        they are declared, so the reading order is stable.

        Coordinates are written directly, so this lab's ``run_all.sh`` calls the
        single writer with ``--no-repack``: the generator owns the placement, and
        ``finalise_lab`` still sanitises, re-gates and round-trip-checks the bytes
        it writes.
        """
        import lab_api                                        # noqa: PLC0415

        order: list[str] = []
        members: dict[str, list[str]] = collections.OrderedDict()
        for key in self.sid:
            sec = section_of(self.meta[key]["name"])
            if sec not in members:
                members[sec] = []
                order.append(sec)
            members[sec].append(key)

        def box(key: str) -> tuple[int, int]:
            name = self.meta[key]["name"]
            model = self.meta[key]["model"]
            return lab_api.device_box(lab_api.kind_for_model(model), name, model)

        blocks = []
        for sec in order:
            keys = members[sec]
            pitch = max(box(k)[0] for k in keys)
            cols = max(1, min(len(keys), int(max_width // pitch)))
            rows = (len(keys) + cols - 1) // cols
            blocks.append(dict(name=sec, keys=keys, pitch=pitch, cols=cols,
                               rows=rows, w=cols * pitch,
                               h=rows * lab_api.ROW_PITCH))

        n_cols = 3
        left = lab_api.CANVAS_MIN + 20
        col_x = [left + i * (max_width + col_gap) for i in range(n_cols)]
        col_y = [lab_api.CANVAS_MIN + 40] * n_cols

        rects: list[dict] = []
        for b in blocks:
            col = min(range(n_cols), key=lambda i: col_y[i])
            x0, y0 = col_x[col], col_y[col]
            for i, key in enumerate(b["keys"]):
                cx = x0 + (i % b["cols"]) * b["pitch"] + b["pitch"] // 2
                cy = y0 + (i // b["cols"]) * lab_api.ROW_PITCH \
                    + lab_api.ROW_PITCH // 2
                ws = self.lab._els[self.sid[key]].find("WORKSPACE/LOGICAL")
                ws.find("X").text = str(cx)
                ws.find("Y").text = str(cy)
            col_y[col] = y0 + b["h"] + row_gap
            rects.append(dict(name=b["name"], n=len(b["keys"]),
                              x0=x0 - rect_pad, y0=y0 - rect_pad,
                              x1=x0 + b["w"] + rect_pad,
                              y1=y0 + b["h"] + rect_pad, col=col))
        self.section_rects = rects
        return rects

    def add_section_clusters(self) -> int:
        """Wrap each section in a Packet Tracer cluster, so it is *named*.

        A cluster is a labelled group box: the element carries the name and the
        members point at it through ``LOGICAL/DEVCLUSTERID``.  Shape taken from a
        Cisco-authored lab shipped inside Packet Tracer itself
        (``isa3000_dmz.pkt``), where a cluster is

            <CLUSTER><NAME>Internet</NAME><X>..</X><Y>..</Y>
              <CLOUDID>1-1</CLOUDID>
              <CLUSTERID>2-{uuid}#2</CLUSTERID> ... </CLUSTER>

        and a member device carries ``<DEVCLUSTERID>2-{uuid}#2</DEVCLUSTERID>``.
        ``1-1`` is the root cluster every device belongs to by default.
        """
        clusters = self.lab.base.find("CLUSTERS")
        rootcl = clusters.find("ROOTCLUSTER") if clusters is not None else None
        if rootcl is None:
            return 0

        members: dict[str, list[str]] = collections.defaultdict(list)
        for key in self.sid:
            members[section_of(self.meta[key]["name"])].append(key)

        n = 0
        for rect in getattr(self, "section_rects", []):
            keys = members.get(rect["name"]) or []
            if not keys:
                continue
            # Deterministic id: a random uuid per run would make two builds of
            # the same profile differ, and this repo publishes a re-derivable
            # SHA-256 for every artefact.
            cid = f"2-{{{uuid.uuid5(uuid.NAMESPACE_URL, 'iruma-ab/section/' + rect['name'])}}}#2"
            el = ET.SubElement(rootcl, "CLUSTER")
            ET.SubElement(el, "NAME", {"translate": "true"}).text = rect["name"]
            ET.SubElement(el, "X").text = str((rect["x0"] + rect["x1"]) // 2)
            ET.SubElement(el, "Y").text = str(rect["y0"] + 40)
            ET.SubElement(el, "CLOUDID").text = "1-1"
            ET.SubElement(el, "CLUSTERID").text = cid
            # Stable, not hash(): Python randomises string hashing per process,
            # so hash() makes every run produce a different file.
            ET.SubElement(el, "MEM_ADDR").text = str(uuid.uuid5(
                uuid.NAMESPACE_URL, cid).int % 10 ** 12)
            ET.SubElement(el, "CLUSTER_BG_IMAGE", {"isanim": "false"})
            ET.SubElement(el, "CLUSTER_EMBEDDED_BG_IMAGE")
            ET.SubElement(el, "CLUSTER_ICON_IMAGE").text = \
                "../art/Workspace/Logical/iCluster.png"
            ET.SubElement(el, "TILED_BG").text = "false"
            for key in keys:
                logical = self.lab._els[self.sid[key]].find("WORKSPACE/LOGICAL")
                dc = logical.find("DEVCLUSTERID")
                if dc is None:
                    dc = ET.SubElement(logical, "DEVCLUSTERID")
                dc.text = cid
            n += 1
        return n

    def _bdc_keys(self) -> list[str]:
        return [k for k in self.sid if k.startswith("b_")]

    # ================================================================== #
    # configuration
    # ================================================================== #
    def configure(self) -> None:
        self._cfg_core()
        self._cfg_edge()
        self._cfg_mdc()
        self._cfg_bdc()
        self._cfg_opsec()
        self._cfg_aoc()
        self._cfg_atc()
        self._cfg_tenants()
        self._cfg_apron()
        self._cfg_weather()
        self._cfg_depot()
        self._cfg_pol()
        self._cfg_security()
        self._cfg_utilities()
        self._cfg_wireless()

    def _zone_routers(self, keys: list[str], site: int, vlans: list[int],
                      area: int, role: str, vip: bool = True) -> None:
        """Dual zone routers: router-on-a-stick subinterfaces with HSRP.

        The physical parent of a subinterface is administratively down by
        default, and every subinterface inherits that: a router-on-a-stick whose
        parent is never brought up carries nothing.
        """
        for i, key in enumerate(keys):
            ifaces = [("GigabitEthernet0/0/1", "", M24)]
            for v in vlans:
                sub = f"GigabitEthernet0/0/1.{v}"
                ifaces.append((sub, host(site, v, 1 if i == 0 else 2), M24))
            for p, ip, m in self.ifaces(key):
                ifaces.append((p, ip, m))
            ospf = [(net(site, v), "0.0.0.255", area) for v in vlans]
            ospf += [(f"{ip.split('.')[0]}.{ip.split('.')[1]}.{ip.split('.')[2]}.0",
                      "0.0.0.3", K.AREA_BACKBONE) for _p, ip, m in self.ifaces(key)
                     if m == M30]
            body = K.router_config(
                self.meta[key]["name"], role,
                ifaces, loopback=self.meta[key]["ip"], ospf=ospf, default_area=area,
                ospf_active=[p for p, _i, _m in self.ifaces(key)],
                qos=True, zone=role)
            if i == 0 and vip:
                body = self._inject_hsrp(body, vlans, site)
            self.set_cfg(key, body)

    @staticmethod
    def _inject_hsrp(cfg: list[str], vlans: list[int], site: int) -> list[str]:
        out: list[str] = []
        i = 0
        while i < len(cfg):
            line = cfg[i]
            out.append(line)
            m = None
            if line.startswith("interface GigabitEthernet0/0/1."):
                m = line.split(".")[-1]
            if m and m.isdigit() and int(m) in vlans:
                g = 10 + int(m) % 100
                out += [f" standby {g} ip {host(site, int(m), 1)}",
                        f" standby {g} priority 110",
                        f" standby {g} preempt"]
            i += 1
        return out

    def _port_plan(self, key: str, uplinks: list[str],
                   access: dict[str, int], default_vlan: int
                   ) -> tuple[list[str], dict[str, int]]:
        """Decide trunk-or-access for every cabled port, from the cabling.

        A port's role is a property of what is plugged into it, not of which
        list someone remembered to edit:

        * peer terminates Layer 3, or is itself a switch -> **trunk**;
        * peer is a firewall whose port sits in an access VLAN -> **access in
          that VLAN**, so the two ends of one cable agree;
        * anything else (host, PLC, camera, sensor) -> **access** in the
          device's default VLAN.

        Anything the explicit map did not mention is *recorded* in
        ``self.port_completions``, so an unconsidered port shows up in the build
        report instead of silently becoming a dead link.
        """
        trunks = list(uplinks)
        out = dict(access)
        for port, peer in self.cabled_ports(key).items():
            if port in out or port in trunks:
                continue
            peer_model = self.meta.get(peer, {}).get("model", "")
            if peer in self.l3_keys or (peer_model in NETWORK_DEVICE_MODELS
                                        and peer not in self.asa_keys):
                trunks.append(port)
                self.port_completions.append((self.meta[key]["name"], port, -1))
            else:
                # The access VLAN is a property of the peer, not of a port list
                # typed elsewhere: using the peer's own segment is what keeps the
                # two ends of one cable in agreement.
                vlan = self.meta.get(peer, {}).get("vlan") or default_vlan
                out[port] = vlan
                self.port_completions.append((self.meta[key]["name"], port, vlan))
        return trunks, out

    def _l2(self, key: str, role: str, vlans: list[int], uplinks: list[str],
            access: dict[str, int], mgmt_vlan: int = K.V_MGMT,
            stp_root: list[int] | None = None,
            default_vlan: int = K.V_OPS) -> None:
        ip = self.meta[key]["ip"]
        uplinks, access = self._port_plan(key, uplinks, access, default_vlan)
        self.set_cfg(key, K.l2_switch_config(
            self.meta[key]["name"], role, vlans,
            mgmt=(ip, M24) if ip else None, mgmt_vlan=mgmt_vlan,
            uplinks=uplinks, access_ports=access, stp_root=stp_root, zone=role))

    def _ind(self, key: str, role: str, vlans: list[int], uplinks: list[str],
             access: dict[str, int], default_vlan: int = K.V_OT) -> None:
        ip = self.meta[key]["ip"]
        uplinks, access = self._port_plan(key, uplinks, access, default_vlan)
        self.set_cfg(key, K.industrial_switch_config(
            self.meta[key]["name"], role, vlans,
            mgmt=(ip, M24) if ip else None, uplinks=uplinks,
            access_ports=access, zone=role))

    def _l3_ports(self, key: str, uplinks: list[str]
                  ) -> tuple[list[str], dict[str, int]]:
        """Split a switch's cabled ports into trunks and access ports.

        A routed port must never also be written as a trunk: the parser applies
        the later block, the port reverts to Layer 2, and the routed neighbour
        on the other end never comes up.  Deriving both sets from the cabling
        makes that impossible.
        """
        routed = self.routed_ports(key)
        allow_access = set(uplinks)
        trunks: list[str] = []
        for port in self.cabled_ports(key):
            if port in routed or port in allow_access:
                continue
            trunks.append(port)
        return sorted(trunks), dict(self.access_override.get(key, {}))

    # -- per-tier configuration ------------------------------------------ #
    def _cfg_core(self) -> None:
        for i, key in enumerate(["bb1", "bb2"]):
            svis = {K.V_MGMT: (host(S_CORE, K.V_MGMT, 11 + i), M24),
                    K.V_SRV: (host(S_CORE, K.V_SRV, 11 + i), M24)}
            hsrp = {K.V_MGMT: (10, host(S_CORE, K.V_MGMT, 1)),
                    K.V_SRV: (20, host(S_CORE, K.V_SRV, 1))}
            trunks, access = self._l3_ports(key, uplinks=[])
            body = K.l3_switch_config(
                self.meta[key]["name"],
                f"base collapsed core {'A' if i == 0 else 'B'} "
                f"(OSPF area 0 backbone, iBGP AS{K.IRM_ASN})",
                [K.V_MGMT, K.V_SRV, K.V_OPS], svis, self.meta[key]["ip"],
                ospf=[(net(S_CORE, K.V_MGMT), "0.0.0.255", K.AREA_BACKBONE),
                      (net(S_CORE, K.V_SRV), "0.0.0.255", K.AREA_BACKBONE)]
                     + self.wans(key),
                default_area=K.AREA_BACKBONE,
                hsrp=hsrp if i == 0 else None,
                trunks=trunks, access_ports=access,
                routed_ports=[(p, ip, m) for (p, ip, m) in self.ifaces(key)],
                ospf_active=[p for p, _i, _m in self.ifaces(key)],
                zone="CORE")
            body = self._bgp_inject(body, self.meta[key]["ip"])
            self.set_cfg(key, body)

        for i, key in enumerate(["cr1", "cr2"]):
            ospf = [(net(S_CORE, K.V_MGMT), "0.0.0.255", K.AREA_BACKBONE)] + \
                self.wans(key)
            ospf += [("10.0.0.0", "0.255.255.255", K.AREA_BACKBONE)]
            body = K.router_config(
                self.meta[key]["name"],
                f"base core router {'A' if i == 0 else 'B'} "
                f"(OSPF ABR, iBGP AS{K.IRM_ASN})",
                self.ifaces(key), loopback=self.meta[key]["ip"],
                ospf=ospf, default_area=K.AREA_BACKBONE,
                ospf_active=[p for p, _i, _m in self.ifaces(key)], zone="CORE")
            body = self._bgp_inject(body, self.meta[key]["ip"])
            self.set_cfg(key, body)

        for i, key in enumerate(["we1", "we2"]):
            self.set_cfg(key, K.router_config(
                self.meta[key]["name"],
                f"base WAN edge ({'primary' if i == 0 else 'backup'} carrier)",
                self.ifaces(key), loopback=self.meta[key]["ip"],
                ospf=self.wans(key), default_area=K.AREA_BACKBONE,
                ospf_active=[p for p, _i, _m in self.ifaces(key)],
                statics=[("0.0.0.0", "0.0.0.0", "10.0.0.1")],
                serial_clock={p: c for (_a, p, _b, _bp, _d, c) in self.serial_meta
                              if _a == key or _b == key},
                zone="CORE"))

        self.set_cfg("dci1", K.router_config(
            "IRM-DCI-RTR-01", "data-centre interconnect (MDC <-> BDC)",
            self.ifaces("dci1"), loopback=self.meta["dci1"]["ip"],
            ospf=self.wans("dci1") + [(net(S_BDC, K.V_SRV), "0.0.0.255",
                                       K.AREA_DC)],
            default_area=K.AREA_BACKBONE,
            ospf_active=[p for p, _i, _m in self.ifaces("dci1")], zone="CORE"))

        self.set_cfg("mgw", K.router_config(
            "IRM-NETOPS-GW-01", "out-of-band management gateway / NetOps edge",
            self.ifaces("mgw"), loopback=self.meta["mgw"]["ip"],
            ospf=self.wans("mgw") + [(net(S_NOC, K.V_MGMT), "0.0.0.255",
                                      K.AREA_NOC)],
            default_area=K.AREA_BACKBONE,
            ospf_active=[p for p, _i, _m in self.ifaces("mgw")], zone="NOC"))
        self._l2("nocsw1", "Base NetOps / base communications enclave",
                 [K.V_MGMT, K.V_SRV], [GE0(1)], {}, default_vlan=K.V_MGMT)

    @staticmethod
    def _bgp_inject(cfg: list[str], router_id: str) -> list[str]:
        out = list(cfg)
        peers = [(host(S_CORE, K.V_MGMT, 11), "IRM-CORE-SW-01"),
                 (host(S_CORE, K.V_MGMT, 12), "IRM-CORE-SW-02")]
        block = [f"router bgp {K.IRM_ASN}", f" bgp router-id {router_id}",
                 " bgp log-neighbor-changes", " no synchronization",
                 " bgp graceful-restart restart-time 120",
                 f" network {net(S_MDC, K.V_SRV)} mask {M24}",
                 f" network {net(S_AOC, K.V_OPS)} mask {M24}"]
        for ip, desc in peers:
            if ip == router_id:
                continue
            block += [f" neighbor {ip} remote-as {K.IRM_ASN}",
                      f" neighbor {ip} description {desc} (iBGP)",
                      f" neighbor {ip} update-source Loopback0"]
        block.append("!")
        anchor = next((i for i, l in enumerate(out)
                       if l.startswith("class-map")), len(out))
        return out[:anchor] + block + out[anchor:]

    def _cfg_edge(self) -> None:
        for i, key in enumerate(["ce1", "ce2"]):
            ospf = self.wans(key) + [(net(S_EDGE, K.V_LIAISON), "0.0.0.255",
                                      K.AREA_EDGE)]
            self.set_cfg(key, K.router_config(
                self.meta[key]["name"],
                f"base edge router {'A' if i == 0 else 'B'} (eBGP AS{K.ISP_ASN})",
                self.ifaces(key), loopback=self.meta[key]["ip"],
                ospf=ospf, default_area=K.AREA_EDGE,
                ospf_active=[p for p, _i, _m in self.ifaces(key)],
                statics=[("0.0.0.0", "0.0.0.0", "10.0.0.1")], zone="EDGE"))
        for i, (key, asn, desc) in enumerate([
            ("modgw", K.MOD_ASN,
             "Japan Ministry of Defense backbone (AS65012)"),
            ("yokgw", 0,
             "Yokota AB approach/departure control liaison (APP/DEP for Iruma)"),
            ("jwsgw", 0,
             "JWS-II integrated weather system, Air Weather Group (Fuchu)"),
            ("polgw", 0,
             "Saitama Prefectural Police Air Corps liaison"),
            ("sigintgw", 0,
             "Signals Intelligence HQ radio branch, Iruma detachment"),
        ]):
            for port in self.cabled_ports(key):
                if port not in self.routed_ports(key):
                    self.routed.append((key, port,
                                        host(S_EDGE, K.V_LIAISON, 30 + i), M24))
            extra = []
            if asn:
                extra = ["!", f"router bgp {K.IRM_ASN}",
                         f" bgp router-id {self.meta[key]['ip']}",
                         " bgp log-neighbor-changes",
                         f" neighbor 10.0.0.1 remote-as {asn}",
                         f" neighbor 10.0.0.1 description {desc}",
                         "!"]
            self.set_cfg(key, K.router_config(
                self.meta[key]["name"], desc, self.ifaces(key),
                loopback=self.meta[key]["ip"], ospf=self.wans(key),
                default_area=K.AREA_EDGE,
                ospf_active=[p for p, _i, _m in self.ifaces(key)],
                extra=extra, qos=False, zone="EDGE"))
        # The firewall's DMZ port is an access port in V_LIAISON, so the switch
        # port facing it must be access in the same VLAN -- not a trunk.
        self._l2("dmzsw", "liaison DMZ access switch", [K.V_LIAISON, K.V_MGMT],
                 [], {GE0(1): K.V_LIAISON}, default_vlan=K.V_LIAISON)
        out_ip = self._asa_uplink("fwext", "Ethernet0/0", "10.99.0.1")
        self.set_cfg("fwext", K.asa_config(
            "FW-INTERNET-EDGE", "internet / liaison DMZ edge firewall",
            zones=[dict(vlan=1, nameif="outside", sec=0, ip=out_ip, mask=M24,
                        ports=["Ethernet0/0"], dhcp=False),
                   dict(vlan=K.V_LIAISON, nameif="dmz", sec=50,
                        ip=gw(S_EDGE, K.V_LIAISON), mask=M24,
                        ports=["Ethernet0/1"], dhcp=False)],
            acls=K.customs_acl_lines()))

    def _cfg_mdc(self) -> None:
        s = S_MDC
        vlans = [K.V_SRV, K.V_MGMT, K.V_SORTIE]
        for i, key in enumerate(["mdcs1", "mdcs2"]):
            self.access_override[key] = {GE1(1): K.V_SRV}
            trunks, access = self._l3_ports(key, uplinks=[GE1(1)])
            svis = {K.V_SRV: (host(s, K.V_SRV, 11 + i), M24),
                    K.V_SORTIE: (host(s, K.V_SORTIE, 11 + i), M24)}
            hsrp = {K.V_SRV: (10, gw(s, K.V_SRV)),
                    K.V_SORTIE: (20, gw(s, K.V_SORTIE))}
            self.set_cfg(key, K.l3_switch_config(
                self.meta[key]["name"],
                "air defence / mission data centre spine "
                "(VLAN 60 service gateway)",
                vlans, svis, self.meta[key]["ip"],
                ospf=[(net(s, K.V_SRV), "0.0.0.255", K.AREA_DC),
                      (net(s, K.V_SORTIE), "0.0.0.255", K.AREA_DC)] + self.wans(key),
                default_area=K.AREA_DC, hsrp=hsrp if i == 0 else None,
                trunks=trunks, access_ports=access,
                routed_ports=[(p, ip, m) for (p, ip, m) in self.ifaces(key)],
                ospf_active=[p for p, _i, _m in self.ifaces(key)], zone="MDC"))
        self._l2("mdcl1", "mission data centre core-services leaf", vlans,
                 [GE0(1), GE0(2)], {FE0(i): K.V_SRV for i in range(1, 25)})
        # leaf B's uplink faces the internal firewall's inside port, which is an
        # access port in V_SRV -- so this end is access in the same VLAN, and
        # GE0(2) stays the interswitch trunk to leaf A.
        self._l2("mdcl2", "mission data centre application leaf", vlans,
                 [GE0(2)], {GE0(1): K.V_SRV,
                            **{FE0(i): K.V_SRV for i in range(1, 25)}})
        for i, key in enumerate(["mdcfw", "mdcfw2"]):
            cabled = self.cabled_ports(key)
            if not cabled:
                continue
            zones = []
            if "Ethernet0/0" in cabled:
                zones.append(dict(vlan=1, nameif="outside", sec=0,
                                  ip=self._asa_uplink(key, "Ethernet0/0",
                                                      f"10.99.{i + 1}.1"),
                                  mask=M24, ports=["Ethernet0/0"], dhcp=False))
            if "Ethernet0/1" in cabled:
                zones.append(dict(vlan=K.V_SRV, nameif="inside", sec=100,
                                  ip=gw(S_MDC, K.V_SRV), mask=M24,
                                  ports=["Ethernet0/1"], dhcp=False))
            self.set_cfg(key, K.asa_config(
                self.meta[key]["name"],
                "MDC perimeter firewall" if i == 0
                else "MDC internal segmentation firewall",
                zones=zones, acls=K.customs_acl_lines()))

    def _cfg_bdc(self) -> None:
        s = S_BDC
        self.access_override["bdcs1"] = {GE1(1): K.V_SRV}
        trunks, access = self._l3_ports("bdcs1", uplinks=[GE1(1)])
        self.set_cfg("bdcs1", K.l3_switch_config(
            "BDC-SPINE-01", "backup site spine / standby mission gateway",
            [K.V_SRV, K.V_MGMT], {K.V_SRV: (host(s, K.V_SRV, 11), M24)},
            self.meta["bdcs1"]["ip"],
            ospf=[(net(s, K.V_SRV), "0.0.0.255", K.AREA_DC)]
                 + self.wans("bdcs1"),
            default_area=K.AREA_DC, trunks=trunks, access_ports=access,
            routed_ports=[(p, ip, m) for (p, ip, m) in self.ifaces("bdcs1")],
            ospf_active=[p for p, _i, _m in self.ifaces("bdcs1")], zone="BDC"))
        self._l2("bdcl1", "backup site server access", [K.V_SRV, K.V_MGMT],
                 [GE0(1)], {FE0(i): K.V_SRV for i in range(1, 12)})
        self.set_cfg("bdcfw", K.asa_config(
            "FW-BDC-PERIMETER", "backup site perimeter firewall",
            zones=[dict(vlan=1, nameif="outside", sec=0,
                        ip=self._asa_uplink("bdcfw", "Ethernet0/0", "10.99.4.1"),
                        mask=M24, ports=["Ethernet0/0"], dhcp=False),
                   dict(vlan=K.V_SRV, nameif="inside", sec=100,
                        ip=gw(S_BDC, K.V_SRV), mask=M24,
                        ports=["Ethernet0/1"], dhcp=False)],
            acls=K.customs_acl_lines()))

    def _cfg_opsec(self) -> None:
        cn = OPSEC_NET
        for i, key in enumerate(["osfw1", "osfw2"]):
            cabled = self.cabled_ports(key)
            zones = []
            if "Ethernet0/0" in cabled:
                zones.append(dict(
                    vlan=1, nameif="outside" if i == 0 else "dmz",
                    sec=0 if i == 0 else 50,
                    ip=self._asa_uplink(key, "Ethernet0/0", f"{cn}.255.{1 + i}"),
                    mask=M24, ports=["Ethernet0/0"], dhcp=False))
            if "Ethernet0/1" in cabled:
                zones.append(dict(
                    vlan=K.V_CUS, nameif="dmz" if i == 0 else "inside",
                    sec=50 if i == 0 else 100,
                    ip=gw(OPSEC_SITE, K.V_CUS) if i == 1 else f"{cn}.10.254",
                    mask=M24, ports=["Ethernet0/1"], dhcp=False))
            if "Ethernet0/2" in cabled:
                zones.append(dict(vlan=K.V_CUS + 1, nameif="dbzone", sec=75,
                                  ip=f"{cn}.255.5", mask=M24,
                                  ports=["Ethernet0/2"], dhcp=False))
            if zones:
                self.set_cfg(key, K.asa_config(
                    self.meta[key]["name"],
                    "operations-security enclave outer firewall" if i == 0
                    else "enclave inner firewall (mission database protection)",
                    zones=zones, acls=K.customs_acl_lines()))
        self._l2("ossw1", "enclave DMZ switch (tasking brokers)",
                 [K.V_CUS, K.V_MGMT], [], {GE0(1): K.V_CUS},
                 default_vlan=K.V_CUS)
        self._l2("ossw2", "enclave protected switch (mission database)",
                 [K.V_CUS, K.V_MGMT], [], {GE0(1): K.V_CUS},
                 default_vlan=K.V_CUS)

    def _cfg_aoc(self) -> None:
        s = S_AOC
        self._zone_routers(["aocr1", "aocr2"], s,
                           [K.V_OPS, K.V_SORTIE, K.V_VOICE, K.V_MGMT, K.V_WIFI],
                           K.AREA_OPS, "air operations centre router")
        self._l2("aocd1", "AOC distribution A",
                 [K.V_OPS, K.V_SORTIE, K.V_VOICE, K.V_MGMT],
                 [GE0(1), GE0(2), FE0(1)], {FE0(2): K.V_OPS},
                 stp_root=[K.V_OPS])
        self._l2("aocd2", "AOC distribution B",
                 [K.V_OPS, K.V_SORTIE, K.V_VOICE, K.V_MGMT],
                 [GE0(1), GE0(2), FE0(1)], {FE0(2): K.V_OPS})
        self._l2("aoca1", "control tower cab access",
                 [K.V_OPS, K.V_SORTIE, K.V_VOICE, K.V_MGMT], [GE0(1)],
                 {FE0(i): (K.V_SORTIE if i <= 4 else K.V_VOICE)
                  for i in range(1, 9)})
        self._l2("aoca2", "CADF HQ operations floor access",
                 [K.V_OPS, K.V_SORTIE, K.V_VOICE, K.V_MGMT], [GE0(1)],
                 {FE0(i): K.V_OPS for i in range(1, 9)})

    def _cfg_atc(self) -> None:
        s = S_ATC
        self._zone_routers(["atcr1", "atcr2"], s,
                           [K.V_OT, K.V_NAVAID, K.V_SORTIE, K.V_MGMT],
                           K.AREA_ATC, "air traffic control router")
        self._ind("atcsw1", "ATC radar and navaid switch A",
                  [K.V_OT, K.V_NAVAID, K.V_SORTIE, K.V_MGMT],
                  [GE1(1), GE1(2)], {})
        atc_plc = [k for k in self.sid if k.startswith("atc_")
                   and self.meta[k]["model"] in ("PLC-PT", "HMI-PT")]
        acc: dict[str, int] = {}
        for i, _key in enumerate(atc_plc):
            if i >= 4:
                acc[GE1_1(3 + (i - 4))] = K.V_OT
        self._ind("atcsw2", "ATC navaid and airfield lighting switch B",
                  [K.V_OT, K.V_NAVAID, K.V_SORTIE, K.V_MGMT],
                  [GE1_1(1), GE1_1(2)], acc)

    def _cfg_tenants(self) -> None:
        for tn in self.tenants:
            n = tn["idx"]
            vlans = [K.V_OPS, K.V_SORTIE, K.V_SRV, K.V_MGMT,
                     K.V_VOICE, K.V_WIFI]
            self._l2(f"tn{n}sw", f"{tn['display']} - {tn['role']}", vlans,
                     [GE0(1), GE0(2)], {})
            if tn["weight"] == "full":
                self._l2(f"tn{n}hgr",
                         f"{tn['display']} hangar industrial segment",
                         [K.V_OT, K.V_IOT, K.V_MGMT], [GE0(1)],
                         {FE0(1): K.V_OT, FE0(2): K.V_IOT}, default_vlan=K.V_OT)
        s = S_HOSP
        self._zone_routers(["hospr1"], s,
                           [K.V_OPS, K.V_SRV, K.V_CCTV, K.V_IOT, K.V_MGMT],
                           K.AREA_OT, "JSDF Iruma Hospital zone router", vip=False)
        self._l2("hosp_sw", "JSDF Iruma Hospital LAN",
                 [K.V_OPS, K.V_SRV, K.V_CCTV, K.V_IOT, K.V_MGMT], [GE0(1)], {})

    def _cfg_apron(self) -> None:
        vlans = [K.V_GV, K.V_OT, K.V_CCTV, K.V_IOT, K.V_MGMT]
        self._ind("apragg1", "apron industrial aggregation A (aprons, helipads)",
                  vlans, [GE1(1), GE1(28)], {}, default_vlan=K.V_GV)
        self._ind("apragg2", "apron industrial aggregation B (flight line)",
                  vlans, [GE1(1), GE1(28)], {}, default_vlan=K.V_GV)
        for ap in self.aprons:
            n = ap["idx"]
            self._ind(f"ap{n}sw",
                      f"{ap['label']} industrial switch ({ap['note']})",
                      vlans, [GE1_1(1)], {})
        self._ind("fltsw1", "flight line switch A (refuelling, GSE)",
                  [K.V_GV, K.V_OT, K.V_SRV, K.V_MGMT],
                  [GE1(1), GE1(2)],
                  {GE1(3): K.V_SRV, GE1(4): K.V_SRV, GE1(5): K.V_SRV,
                   GE1(6): K.V_OPS, GE1(7): K.V_OT, GE1(8): K.V_OT,
                   GE1(9): K.V_GV})
        self._ind("fltsw2", "flight line switch B (ARFF, sweep, birds)",
                  [K.V_GV, K.V_OT, K.V_SRV, K.V_MGMT],
                  [GE1_1(1), GE1_1(2)],
                  {GE1_1(3): K.V_GV, GE1_1(4): K.V_GV, GE1_1(5): K.V_GV,
                   GE1_1(6): K.V_OT})

    def _cfg_weather(self) -> None:
        s = S_WX
        self._zone_routers(["wxr1"], s,
                           [K.V_SRV, K.V_IOT, K.V_OT, K.V_MGMT], K.AREA_WX,
                           "Iruma Weather Squadron router", vip=False)
        self._l2("wxsw1", "Iruma Weather Squadron LAN",
                 [K.V_SRV, K.V_IOT, K.V_OT, K.V_MGMT], [GE0(1)], {},
                 default_vlan=K.V_IOT)

    def _cfg_depot(self) -> None:
        s = S_DEP0
        self._zone_routers(["depr1"], s,
                           [K.V_OPS, K.V_SRV, K.V_IOT, K.V_CCTV, K.V_GV,
                            K.V_OT, K.V_MGMT],
                           K.AREA_OT, "air depot zone router", vip=False)
        self._l2("depsw1", "3rd Air Depot electronics and met-materiel switch",
                 [K.V_OPS, K.V_SRV, K.V_IOT, K.V_GV, K.V_MGMT],
                 [GE0(1), GE0(2)], {})
        self._l2("depsw2", "4th Air Depot general supply switch",
                 [K.V_OPS, K.V_SRV, K.V_IOT, K.V_CCTV, K.V_GV, K.V_OT,
                  K.V_MGMT], [GE0(1)], {})

    def _cfg_pol(self) -> None:
        s = S_POL
        self._zone_routers(["polr1"], s,
                           [K.V_OT, K.V_POL, K.V_IOT, K.V_SRV, K.V_MGMT],
                           K.AREA_OT, "bulk fuel farm zone router", vip=False)
        vlans = [K.V_OT, K.V_POL, K.V_IOT, K.V_SRV, K.V_MGMT]
        # Access VLANs are derived from each cabled peer's own segment, so these
        # maps only need to name the uplinks; everything else is completed from
        # the cabling and recorded in self.port_completions.
        self._ind("polsw1", "fuel farm tank farm switch (ex-rated)", vlans,
                  [GE1_1(1), GE1_1(2), GE1_1(3)], {}, default_vlan=K.V_OT)
        self._ind("polsw2", "fuel farm pump house and issue point switch",
                  vlans, [GE2000(1)], {}, default_vlan=K.V_OT)
        self._ind("polsw3", "fuel farm tank gauging and leak detection switch",
                  vlans, [GE1_1(1)], {}, default_vlan=K.V_POL)

    def _cfg_security(self) -> None:
        s = S_SEC
        self._zone_routers(["secr1"], s,
                           [K.V_CCTV, K.V_IOT, K.V_OPS, K.V_MGMT],
                           K.AREA_OT, "security forces zone router", vip=False)
        self._l2("secsw1", "physical security PoE switch A",
                 [K.V_CCTV, K.V_IOT, K.V_OPS, K.V_MGMT],
                 [GE0(1), GE0(2), FE0(1)], {})
        self._l2("secsw2", "physical security PoE switch B",
                 [K.V_CCTV, K.V_IOT, K.V_OPS, K.V_MGMT], [GE0(1)], {})
        self._l2("ghsw1", "main gate house access switch",
                 [K.V_CCTV, K.V_OPS, K.V_MGMT], [GE0(1)], {})

    def _cfg_utilities(self) -> None:
        s = S_UTIL
        self._zone_routers(["utilr1"], s,
                           [K.V_OT, K.V_IOT, K.V_MGMT], K.AREA_OT,
                           "utilities zone router", vip=False)
        self._ind("utilsw1", "substation and standby power switch",
                  [K.V_OT, K.V_IOT, K.V_MGMT], [GE1_1(1), GE1_1(2)], {},
                  default_vlan=K.V_OT)
        self._ind("utilsw2", "base services switch", [K.V_OT, K.V_IOT, K.V_MGMT],
                  [GE2000(1)], {}, default_vlan=K.V_OT)

    def _cfg_wireless(self) -> None:
        for key in ("wlc1", "wlc2"):
            uplink = next(iter(self.cabled_ports(key)), "GigabitEthernet1")
            self.set_cfg(key, [
                "!", f"hostname {self.meta[key]['name']}", "!",
                f"! {self.meta[key]['role']}", "!",
                f"interface {uplink}",
                f" ip address {self.meta[key]['ip']} {M24}",
                " no shutdown", "!",
                f"ip default-gateway {gw(S_WLAN, K.V_MGMT)}", "!",
                "wlan create IRM-AIRCREW-WLAN 1 IRM-AIRCREW-WLAN",
                "wlan create IRM-BASE-WLAN 2 IRM-BASE-WLAN",
                "wlan create IRM-APRON-WLAN 3 IRM-APRON-WLAN", "!",
                "wlan security wpa2 IRM-AIRCREW-WLAN",
                "wlan security wpa2 IRM-BASE-WLAN",
                "wlan security wpa2 IRM-APRON-WLAN", "!",
                f"ntp server {K.NTP_PRIMARY}",
                "!", "end",
            ])
        self._l2("wlsw1", "WLAN distribution (PoE)", [K.V_MGMT, K.V_WIFI],
                 [GE0(1), FE0(1)],
                 {GE0(2): K.V_MGMT, GE0(3): K.V_MGMT,
                  **{FE0(i): K.V_MGMT for i in range(2, 11)}},
                 default_vlan=K.V_MGMT)
        self._l2("wlsw2", "WLAN outdoor AP access", [K.V_MGMT, K.V_WIFI],
                 [GE0(1)], {FE0(i): K.V_MGMT for i in range(1, 11)})

    # ================================================================== #
    # services
    # ================================================================== #
    def services(self) -> None:
        pools: list[dict] = []
        zones = [(f"TNT{tn['idx']:02d}", tn["site"]) for tn in self.tenants]
        zones += [("AOC", S_AOC), ("ATC", S_ATC), ("WX", S_WX),
                  ("HOSP", S_HOSP), ("DEPOT", S_DEP0), ("POL", S_POL),
                  ("SEC", S_SEC), ("UTIL", S_UTIL), ("WLAN", S_WLAN),
                  ("MDC", S_MDC), ("APRON", S_APRON0)]
        vlan_of_zone = {
            "AOC": [K.V_OPS, K.V_SORTIE, K.V_VOICE, K.V_WIFI],
            "ATC": [K.V_OT, K.V_NAVAID, K.V_SORTIE],
            "WX": [K.V_IOT, K.V_OT],
            "HOSP": [K.V_OPS, K.V_SRV],
            "DEPOT": [K.V_OPS, K.V_GV],
            "POL": [K.V_POL, K.V_IOT],
            "SEC": [K.V_CCTV, K.V_IOT],
            "UTIL": [K.V_OT, K.V_IOT],
            "WLAN": [K.V_MGMT, K.V_WIFI],
            "MDC": [K.V_SRV],
            "APRON": [K.V_GV, K.V_CCTV],
        }
        for label, site in zones:
            vlans = (vlan_of_zone.get(label)
                     or [K.V_OPS, K.V_SORTIE, K.V_WIFI])
            for v in vlans:
                pools.append(dict(
                    name=f"{label}-S{site}-V{v}",
                    network=net(site, v), mask=M24,
                    router=gw(site, v),
                    start=host(site, v, 100), end=host(site, v, 200),
                    dns=SRV["dns"], domain=DNS_DOMAIN))
        seen = collections.Counter(p["name"] for p in pools)
        clashes = {n: c for n, c in seen.items() if c > 1}
        if clashes:
            raise SystemExit(
                "DHCP pool names collide (Packet Tracer pools are name-keyed, so "
                f"one would shadow the other): {clashes}. Qualify the zone label "
                "with its site number so it is unique.")

        clients = [(SRV["sortie"], K.AAA_KEY, "sortie tasking service"),
                   (SRV["mission"], K.AAA_KEY, "mission planning service"),
                   (SRV["track"], K.AAA_KEY, "air defence system ops"),
                   (gw(S_MDC, K.V_SRV), K.AAA_KEY, "MDC server SVI")]
        for key, meta in self.meta.items():
            ip = meta.get("ip")
            if ip and meta["model"] in ("3650-24PS", "3560-24PS", "2960-24TT",
                                        "IE-3400", "IE-9320", "IE-2000",
                                        "ISR4331", "2911", "IR1101"):
                clients.append((ip, K.AAA_KEY, meta["name"]))

        # Packet Tracer keys DHCP pools and AAA clients by identity across the
        # whole document, so a second server holding the same records reads as
        # duplication rather than as replication.  Each service therefore has
        # exactly one authoritative server here; the standby node is present and
        # addressed but holds no records.  DNS is the exception the audit models
        # explicitly: a zone is a set per server, so both DNS servers serve it.
        for key, name, svc, desc, ip in self.servers:
            el = self.lab._els[self.sid[key]]
            kw: dict = {}
            if svc in ("dns", "dns2"):
                kw["dns_records"] = sorted(set(self.dns))
            if svc == "dhcp":
                kw["dhcp_pools"] = pools
            if svc == "ntp":
                kw["ntp"] = True
            if svc == "syslog":
                kw["syslog"] = True
            if svc == "aaa":
                kw["aaa_clients"] = clients
                kw["aaa_users"] = [("irm-admin", K.ENABLE_SECRET.split()[-1]),
                                   ("irm-ops", K.OPS_SECRET.split()[-1])]
            if svc == "tftp":
                kw["ftp_user"] = "irm-archive"
                kw["ftp_pass"] = "arch1ve-irm"
            if svc == "portal":
                kw["http"] = True
                kw["http_user"] = "irm-portal"
                kw["http_pass"] = "p0rtal-irm"
                kw["https"] = True
            if kw:
                K.configure_server(el, **kw)
                self.serviced.add(key)
                self.service_notes.append((name, ",".join(sorted(kw))))

    # ================================================================== #
    # finishing passes
    # ================================================================== #
    @staticmethod
    def _serial_slot_idx(port_name: str) -> int:
        try:
            slot, idx = (int(x) for x in port_name.split("/")[-2:])
        except ValueError:
            return 0
        return slot * 2 + idx

    def _set_port(self, key: str, port_name: str, clock: int, is_dce: bool) -> bool:
        el = self.lab._els[self.sid[key]]
        ports = [p for p in el.iter("PORT") if p.findtext("TYPE") == "eSmartSerial"]
        i = self._serial_slot_idx(port_name)
        if i >= len(ports):
            return False
        p = ports[i]
        for tag, val in (("POWER", "true"),
                         ("CLOCKRATE", str(clock) if is_dce else "0"),
                         ("CLOCKRATEFLAG", "true" if is_dce else "false")):
            e = p.find(tag)
            if e is None:
                e = ET.SubElement(p, tag)
            e.text = val
        return True

    def fix_serial(self) -> int:
        n = 0
        for (a, ap, b, bp, dce, clock) in self.serial_meta:
            dce_key, dce_port = (a, ap) if dce == a else (b, bp)
            dte_key, dte_port = (b, bp) if dce == a else (a, ap)
            n += self._set_port(dce_key, dce_port, clock, True)
            n += self._set_port(dte_key, dte_port, clock, False)
        return n

    def power_all_devices(self) -> int:
        keep = set(self.STAGED_OFF)
        n = 0
        for key, sid in self.sid.items():
            if self.meta[key]["name"] in keep:
                continue
            eng = self.lab._els[sid].find("ENGINE")
            if eng is None:
                continue
            e = eng.find("POWER")
            if e is None:
                e = ET.SubElement(eng, "POWER")
            if e.text != "true":
                e.text = "true"
                n += 1
        return n

    def power_cabled_ports(self) -> int:
        cabled = set()
        for (a, _ap, b, _bp, _k, _d) in self.links:
            cabled.add(a)
            cabled.add(b)
        n = 0
        for key in cabled:
            for p in self.lab._els[self.sid[key]].iter("PORT"):
                e = p.find("POWER")
                if e is None:
                    e = ET.SubElement(p, "POWER")
                if e.text != "true":
                    e.text = "true"
                    n += 1
        return n

    def sanitize(self) -> int:
        """Clear NIC addressing we did not author.

        ``has_nic_ip`` marks devices whose *first* port we set.  A harvested
        template can carry an address on a later port too, and if those survive
        several devices report the same address and the endpoint inventory is no
        longer distinct.
        """
        cleared = 0
        for key, sid in self.sid.items():
            el = self.lab._els[sid]
            ports = list(el.iter("PORT"))
            authored = ports[:1] if key in self.has_nic_ip else []
            for port in ports:
                if port in authored:
                    continue
                if port.find("IP") is None:
                    continue
                for tag in ("IP", "SUBNET", "PORT_GATEWAY", "PORT_DNS"):
                    e = port.find(tag)
                    if e is not None and (e.text or "").strip():
                        e.text = ""
                        cleared += 1
                dh = port.find("PORT_DHCP_ENABLE")
                if dh is not None:
                    dh.text = "false"
        return cleared

    def strip_template_leftovers(self) -> int:
        from pkt_core.audit import (          # noqa: PLC0415
            SanitizeReport, TemplateLeftovers, sanitize_template_leftovers)
        leftovers = TemplateLeftovers.from_device_templates_json(
            TOOLKIT / "tools" / "device_templates.json")
        report = SanitizeReport()
        for dev in self.lab.devs.findall("DEVICE"):
            report = report.merge(sanitize_template_leftovers(dev, leftovers=leftovers))
        self.leftover_report = report.as_dict()
        return sum(self.leftover_report.values())

    def clear_end_device_configs(self) -> int:
        """Strip RUNNINGCONFIG from devices that do not run IOS."""
        removed = 0
        for key, sid in self.sid.items():
            if self.meta[key]["model"] in NETWORK_DEVICE_MODELS:
                continue
            eng = self.lab._els[sid].find("ENGINE")
            if eng is None:
                continue
            for rc in list(eng.findall("RUNNINGCONFIG")):
                eng.remove(rc)
                removed += 1
        return removed

    def strip_unconfigured_services(self) -> int:
        """Remove service blocks from devices that were never given a service.

        A harvested template does not just carry leftover *records* -- it
        carries the whole block, already marked ``<ENABLED>1</ENABLED>``.  Left
        in place, dozens of devices advertise themselves as NTP and HTTP servers
        that nobody authored.
        """
        removed = 0
        for key, sid in self.sid.items():
            if key in self.serviced:
                continue
            eng = self.lab._els[sid].find("ENGINE")
            if eng is None:
                continue
            removed += K._strip_service_blocks(eng)
        return removed

    def clear_template_startup_config(self) -> int:
        removed = 0
        for sid in self.sid.values():
            eng = self.lab._els[sid].find("ENGINE")
            if eng is None:
                continue
            startup = eng.find("STARTUPCONFIG")
            if startup is None:
                continue
            for line in list(startup):
                if line.tag == "LINE":
                    startup.remove(line)
                    removed += 1
        self.startup_lines_cleared = removed
        return removed

    def attach_static_ips(self) -> int:
        """Write IP/SUBNET/GATEWAY onto the first port of every IoT endpoint."""
        n = 0
        for key, ip, mask, g in self.static_iot:
            self._claim_ip(ip, self.meta[key]["name"])
            el = self.lab._els[self.sid[key]]
            port = el.find(".//PORT")
            if port is None:
                continue
            for tag, val in (("IP", ip), ("SUBNET", mask),
                             ("PORT_GATEWAY", g), ("PORT_DHCP_ENABLE", "false")):
                e = port.find(tag)
                if e is None:
                    e = ET.SubElement(port, tag)
                e.text = val
            self.has_nic_ip.add(key)
            n += 1
        return n

    def save(self, path: Path) -> None:
        self.lab.save(str(path))

    def report(self) -> dict:
        by_model: dict[str, int] = {}
        by_group: dict[str, int] = {}
        for m in self.meta.values():
            by_model[m["model"]] = by_model.get(m["model"], 0) + 1
            by_group[m["group"]] = by_group.get(m["group"], 0) + 1
        return dict(
            profile=self.profile,
            devices=len(self.sid),
            links=len(self.links),
            routed_ports=len(self.routed),
            serial_bearers=len(self.serial_meta),
            dns_records=len(set(self.dns)),
            wlans=len(self.wlans),
            static_iot_endpoints=len(self.static_iot),
            by_model=dict(sorted(by_model.items(), key=lambda kv: -kv[1])),
            by_tier=dict(sorted(by_group.items())),
            seed_removed=self.seed_removed,
        )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", choices=list(PROFILES), default="enterprise")
    ap.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                    help="override a profile knob, e.g. --set tenants_full=2")
    ap.add_argument("--out", type=Path, default=ROOT / "out" / "IRUMA_AB.pkt")
    ap.add_argument("--report", type=Path, default=None)
    ap.add_argument("--inventory", type=Path, default=None)
    a = ap.parse_args(argv)
    rep_path = a.report or (ROOT / "build" / f"report_{a.profile}.json")
    inv_path = a.inventory or (ROOT / "docs" / f"INVENTORY_{a.profile}.csv")

    if a.set:
        over = dict(PROFILES[a.profile])
        for item in a.set:
            k, _, v = item.partition("=")
            over[k] = (v.lower() in ("1", "true", "yes")) if v.lower() in (
                "true", "false", "yes", "no") else int(v)
        PROFILES[a.profile] = over

    t = Base(a.profile)
    for step in (t.build_edge, t.build_core, t.build_mdc, t.build_bdc,
                 t.build_opsec, t.build_aoc, t.build_atc, t.build_tenants,
                 t.build_apron, t.build_weather, t.build_depot, t.build_pol,
                 t.build_security, t.build_utilities, t.build_wireless,
                 t.build_clients):
        step()
    t.cable()
    # Order the devices for packing *after* the cabling, because the cabling is
    # what defines the adjacency the order is derived from.
    n_ordered = t.order_devices_for_layout()
    section_rects = t.place_sections()
    n_sections = t.add_section_clusters()
    t.configure()
    t.services()
    n_serial = t.fix_serial()
    n_static = t.attach_static_ips()
    n_power = t.power_all_devices()
    n_ports = t.power_cabled_ports()
    cleared = t.sanitize()
    n_endcfg = t.clear_end_device_configs()
    leftovers = t.strip_template_leftovers()
    n_svc = t.strip_unconfigured_services()
    startup = t.clear_template_startup_config()

    # Hand the single writer the band rules for *this* lab.  Without them it
    # falls back to the toolkit's built-in name rules -- another lab's naming
    # convention -- and every device lands in one 'misc' band, which repacks
    # into the tangle the bands exist to prevent.
    import iruma_tiers                                    # noqa: PLC0415
    n_tiers = iruma_tiers.write_tier_map(ROOT / "build" / "tier_map.json")
    print(f"tier map: {n_tiers} rule(s) -> build/tier_map.json")

    a.out.parent.mkdir(parents=True, exist_ok=True)
    t.save(a.out)

    # A cable is not a configuration.  Every cabled port must be brought up by
    # the config that ships with it, so the build fails here rather than
    # delivering a lab full of links that render dead.
    sys.path.insert(0, str(ROOT / "tools"))
    import audit_links                                  # noqa: PLC0415
    _findings = audit_links.audit_xml(
        ET.fromstring(decode_bytes(a.out.read_bytes()).xml))
    if _findings:
        for f_ in _findings[:10]:
            print(f"  {f_['kind']}: {f_['device']} {f_['port']} peer={f_['peer']}",
                  file=sys.stderr)
        raise SystemExit(
            f"{len(_findings)} link endpoint(s) are cabled but not brought up by "
            "their configuration; the artefact would render dead links.")

    rep = t.report()
    rep.update(devices_ordered_for_layout=n_ordered,
               sections=len(section_rects), section_clusters=n_sections,
               serial_ports_clocked=n_serial, static_ips_written=n_static,
               devices_powered=n_power, ports_powered_on=n_ports,
               stale_nic_fields_cleared=cleared,
               end_device_configs_cleared=n_endcfg,
               template_leftovers_removed=leftovers,
               unconfigured_service_blocks_removed=n_svc,
               startup_lines_cleared=startup,
               leftover_report=t.leftover_report,
               output=str(a.out), size_bytes=a.out.stat().st_size)
    rep_path.parent.mkdir(parents=True, exist_ok=True)
    rep_path.write_text(json.dumps(rep, indent=1, sort_keys=True))

    inv_path.parent.mkdir(parents=True, exist_ok=True)
    with inv_path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["name", "model", "tier", "role", "site", "mgmt_ip"])
        for nd in t.meta.values():
            w.writerow([nd["name"], nd["model"], nd["group"], nd["role"],
                        nd["site"], nd["ip"] or ""])

    print(f"built  : {a.out}  ({rep['size_bytes']:,} bytes)")
    print(f"devices: {rep['devices']}   links: {rep['links']}   "
          f"routed ports: {rep['routed_ports']}")
    print(f"report : {rep_path}")
    print(f"inventory: {inv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
