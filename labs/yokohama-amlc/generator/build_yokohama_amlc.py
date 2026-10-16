#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
build_yokohama_amlc.py -- generate a large, fully-configured Cisco Packet
Tracer model of the **Yokohama Automated Maritime Logistics Terminal**
(Y-AMLT), a multi-zone, high-availability container terminal.

    python3 build_yokohama_amlc.py --profile enterprise --out out/YOKOHAMA_AMLC.pkt

Architecture modelled (a real automated container terminal's shape):

    Carrier / partner edge ............... transit ISPs, NACCS customs gateway,
                                           VTS port authority, rail operator,
                                           shipping-line EDI community
    Terminal backbone .................... dual collapsed core + core routers
                                           + dual WAN edge (OSPF area 0)
    Primary data centre (TDC) ............ spine/leaf + 24-service server farm
                                           (TOS, WMS, EDI, GIS, billing, ...)
    Disaster-recovery site (DRC) ......... hot-standby twin + DCI link
    Customs enclave ...................... isolated 172.20/16 zone: manifest
                                           database, NACCS link, IDS, tap
    Terminal Operations Centre (TOC) ..... control tower, video wall, dispatch
    Berth apron .......................... STS ship-to-shore gantry cranes
                                           (PLC + HMI + RFID + motion sensor
                                           behind IE-3400 industrial switches)
    Container yard ....................... 16 RTG yard blocks with reefer
                                           monitoring and yard RFID
    AGV fleet ............................ fleet controllers + onboard PLCs
    Gate complex ......................... OCR portals, RFID, barrier PLC
    Rail intermodal ...................... RMG cranes + signalling
    CFS / warehouse, reefer & DG yard
    Wireless infrastructure .............. dual WLC + outdoor APs (AGV radio)
    Physical security .................... CCTV, perimeter, access control
    OT / power ........................... substation, RMG power, environment
    Terminal NOC ......................... jump host, NMS, cyber observer, tap

Tiers: backbone L3 core -> zone distribution -> industrial/access switching ->
control and end devices, plus firewalled OT and customs zones and a parallel
carrier/partner boundary speaking eBGP.

Everything is generated: placement (through ``lab_api.Layout``), modules,
cabling, complete IOS and ASA running-configurations, Server-PT services
(DNS/DHCP/AAA/NTP/syslog/HTTP/FTP), and end-device addressing.
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from yokohama_paths import bootstrap as _bootstrap   # noqa: E402
TOOLKIT = _bootstrap()
for _p in (str(ROOT), str(TOOLKIT), str(TOOLKIT / "tools"), str(TOOLKIT / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import lab_api                       # noqa: E402
from pkt_core import decode_bytes    # noqa: E402
import yokohama_kit as K             # noqa: E402

NETWORK_DEVICE_MODELS = K.NETWORK_DEVICE_MODELS
import xml.etree.ElementTree as ET   # noqa: E402

M24 = "255.255.255.0"
M30 = "255.255.255.252"
M25 = "255.255.255.128"

# --------------------------------------------------------------------------- #
# scale profiles
# --------------------------------------------------------------------------- #
PROFILES = {
    "smoke": dict(berths=2, cranes=1, yard=4, agv=4, gates=2, rail=1,
                  reoffer=False, servers=10, aps=6, clients=8),
    "standard": dict(berths=3, cranes=2, yard=10, agv=10, gates=4, rail=2,
                     reoffer=True, servers=18, aps=12, clients=20),
    "enterprise": dict(berths=4, cranes=3, yard=16, agv=12, gates=6, rail=3,
                       reoffer=True, servers=24, aps=14, clients=18),
}

# --------------------------------------------------------------------------- #
# site numbering -- the second octet of 10.<site>.<vlan>.0/24
# --------------------------------------------------------------------------- #
S_CORE = 10          # backbone / transport            (loopbacks 10.255.x.x)
S_TDC = 11           # primary terminal data centre
S_DRC = 12           # disaster-recovery data centre
S_CUS = 13           # customs enclave (addressed out of 172.20.0.0/16)
CUSTOMS_SITE = 20    # customs-protected segment uses site 20 of 172.20/16
S_TOC = 20           # terminal operations centre
S_BERTH0 = 21        # berths 1..4  ->  21, 22, 23, 24
S_YARD0 = 30         # yard blocks 1..16 -> 30..45
S_AGV = 50           # AGV control
S_GATE = 55          # gate complex
S_RAIL = 60          # rail intermodal terminal
S_CFS = 70           # container freight station / warehouse
S_REEFER = 75        # reefer + dangerous-goods yard
S_WLAN = 80          # wireless infrastructure
S_SEC = 85           # physical security
S_OT = 90            # OT / power / utilities
S_EDGE = 100         # carrier + partner edge
S_NOC = 200          # NOC / out-of-band management

CUSTOMS_NET = "172.20"

# --------------------------------------------------------------------------- #
# addressing helpers
# --------------------------------------------------------------------------- #
net = lambda s, v: f"10.{s}.{v}.0"            # noqa: E731
gw = lambda s, v: f"10.{s}.{v}.1"             # noqa: E731
host = lambda s, v, h: f"10.{s}.{v}.{h}"      # noqa: E731

# Terminal data-centre service addresses (VLAN 60 @ site 11)
SRV = {
    "tos":       host(S_TDC, K.V_SRV, 31),
    "tos2":      host(S_TDC, K.V_SRV, 32),
    "wms":       host(S_TDC, K.V_SRV, 33),
    "edi":       host(S_TDC, K.V_SRV, 34),
    "gis":       host(S_TDC, K.V_SRV, 35),
    "billing":   host(S_TDC, K.V_SRV, 36),
    "vbs":       host(S_TDC, K.V_SRV, 37),
    "cargo":     host(S_TDC, K.V_SRV, 38),
    "agvdisp":   host(S_TDC, K.V_SRV, 39),
    "cranescada": host(S_TDC, K.V_SRV, 40),
    "reefer":    host(S_TDC, K.V_SRV, 41),
    "dns":       host(S_TDC, K.V_SRV, 21),
    "dns2":      host(S_TDC, K.V_SRV, 22),
    "dhcp":      host(S_TDC, K.V_SRV, 23),
    "dhcp2":     host(S_TDC, K.V_SRV, 24),
    "ntp":       host(S_TDC, K.V_SRV, 25),
    "ntp2":      host(S_TDC, K.V_SRV, 26),
    "syslog":    host(S_TDC, K.V_SRV, 27),
    "syslog2":   host(S_TDC, K.V_SRV, 28),
    "aaa":       host(S_TDC, K.V_SRV, 29),
    "aaa2":      host(S_TDC, K.V_SRV, 30),
    "tftp":      host(S_TDC, K.V_SRV, 42),
    "web":       host(S_TDC, K.V_SRV, 43),
    "mail":      host(S_TDC, K.V_SRV, 44),
    "ca":        host(S_TDC, K.V_SRV, 45),
    "flow":      host(S_TDC, K.V_SRV, 46),
    "historian": host(S_TDC, K.V_SRV, 47),
    "backup":    host(S_TDC, K.V_SRV, 48),
}

# --------------------------------------------------------------------------- #
# terminal layout -- named berths and yard blocks
# --------------------------------------------------------------------------- #
BERTHS = [
    ("BC1", "Minami-Honmoku BC-1", "deep-water 16.5 m, 2 x 24 000 TEU"),
    ("BC2", "Minami-Honmoku BC-2", "deep-water 16.5 m"),
    ("BC3", "Honmoku D-4", "14.0 m, feeder + intra-Asia"),
    ("BC4", "Honmoku D-5", "14.0 m, feeder + intra-Asia"),
]

YARD_BLOCKS = [
    ("Y01", "A1", "import laden"),   ("Y02", "A2", "import laden"),
    ("Y03", "A3", "export laden"),   ("Y04", "A4", "export laden"),
    ("Y05", "B1", "transshipment"),  ("Y06", "B2", "transshipment"),
    ("Y07", "B3", "empty"),          ("Y08", "B4", "empty"),
    ("Y09", "C1", "reefer"),         ("Y10", "C2", "reefer"),
    ("Y11", "C3", "dangerous goods"), ("Y12", "C4", "dangerous goods"),
    ("Y13", "D1", "rail-served"),    ("Y14", "D2", "rail-served"),
    ("Y15", "D3", "over-height / OOG"), ("Y16", "D4", "over-height / OOG"),
]

GATE_LANES = [
    ("G1", "inbound OCR 1"), ("G2", "inbound OCR 2"),
    ("G3", "inbound OCR 3"), ("G4", "outbound OCR 1"),
    ("G5", "outbound OCR 2"), ("G6", "hazmat / oversize"),
]

RAIL_TRACKS = [
    ("R1", "track 1 - Shinkansen freight corridor"),
    ("R2", "track 2 - Tokaido feeder"),
    ("R3", "track 3 - yard transfer"),
]

# Terminal DNS zone contents
TML_DOMAIN = K.DOMAIN

GE1 = lambda i: f"GigabitEthernet1/0/{i}"      # noqa: E731  (3650-24PS)
FE0 = lambda i: f"FastEthernet0/{i}"           # noqa: E731  (2960 / 3560)
GE0 = lambda i: f"GigabitEthernet0/{i}"        # noqa: E731  (3560 uplinks)
GE1_1 = lambda i: f"GigabitEthernet1/{i}"      # noqa: E731  (IE-3400)
GE9320 = lambda i: f"GigabitEthernet1/0/{i}"   # noqa: E731  (IE-9320)
GE000 = "GigabitEthernet0/0/0"                 # ISR4331 WAN port


# Layout tiers.  Every tier costs one row of vertical space before any device
# is placed (the packer stacks bands), and the primary page holds only 26 rows
# at ROW_PITCH=150 -- so tier count, not device count, is what decides whether a
# model fits.  Related zones therefore share a band.
GROUP_MERGE = {
    "T1-carrier-edge": "T1-edge-carrier",
    "T2-backbone": "T2-core-and-noc",
    "T17-noc": "T2-core-and-noc",
    "T3-primary-dc": "T3-data-centres",
    "T4-dr-site": "T3-data-centres",
    "T5-customs": "T4-customs",
    "T6-control-tower": "T5-control-tower",
    "T7-berth-sts": "T6-berth-sts",
    "T8-container-yard": "T7-container-yard",
    "T9-agv-fleet": "T8-agv-fleet",
    "T10-gate": "T9-gate-and-rail",
    "T11-rail": "T9-gate-and-rail",
    "T12-cfs": "T10-facilities",
    "T14-wireless": "T10-facilities",
    "T15-security": "T10-facilities",
    "T13-reefer-dg": "T11-utilities",
    "T16-ot-power": "T11-utilities",
    "T18-clients": "T12-mobile-estate",
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


class Terminal:
    """The Y-AMLT model."""

    # Devices deliberately staged powered-down (spares).  Empty: everything
    # placed here is part of the live terminal and must come up at load.
    STAGED_OFF: frozenset[str] = frozenset()

    def __init__(self, profile: str) -> None:
        self.p = PROFILES[profile]
        self.profile = profile
        self.models, self.modules = lab_api.load_templates(
            str(TOOLKIT / "tools" / "device_templates.json"))
        self.lab = lab_api.Lab(str(TOOLKIT / "tools" / "network_seed.xml"),
                               self.models, self.modules)
        self.seed_removed = self.lab.prune_seed_devices()
        # Placement is owned by lab_api.Layout: label-inclusive boxes, greedy
        # row-major packing per semantic tier, 80-unit centre floor, canvas wrap.
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
        self.cranes: list[dict] = []
        self.yards: list[dict] = []
        self.static_iot: list[tuple[str, str, str, str]] = []   # key, ip, mask, gw
        self.service_notes: list[tuple[str, str]] = []
        self.serviced: set[str] = set()
        # ports whose access VLAN the tier config states explicitly; everything
        # else cabled is completed from the cabling and recorded here
        self.access_override: dict[str, dict[str, int]] = {}
        # Which peers terminate Layer 3 (so a switch port facing them is a
        # trunk) and which are firewalls (so the switch port faces an access
        # port and must be in the same VLAN).
        self.l3_keys: set[str] = {
            "bb1", "bb2", "cr1", "cr2", "we1", "we2", "dci1", "mgw",
            "ce1", "ce2", "naccs", "vts", "railop", "lineedi",
            "tdcs1", "tdcs2", "drcs1", "toc1", "toc2", "agvr1", "agvr2",
            "gater1", "gater2", "railr1", "railr2",
        } | {f"brt{b}{x}" for b in range(1, 5) for x in ("a", "b")}
        self.asa_keys: set[str] = {"fwext", "tdcfw", "tdcfw2", "drcfw",
                                   "cusfw1", "cusfw2"}
        self.port_completions: list[tuple[str, str, int]] = []
        self.leftover_report: dict = {}
        self.startup_lines_cleared = 0
        # address -> device name, so an allocation collision fails at the point
        # it is created rather than surfacing later as a duplicate-IP finding.
        self._ip_owner: dict[str, str] = {}
        self._loop_seq = 0

    def _claim_ip(self, ip: str | None, name: str) -> None:
        if not ip:
            return
        prev = self._ip_owner.get(ip)
        if prev == name:
            return            # a device re-asserting its own address is not a clash
        if prev is not None:
            raise SystemExit(
                f"address collision: {ip} is claimed by both {prev!r} and {name!r}. "
                "Every device address must be derived from its own zone, VLAN and "
                "role; a repeated host octet means two devices share a segment slot."
            )
        self._ip_owner[ip] = name

    # -- primitives ------------------------------------------------------ #
    def add(self, key: str, model: str, name: str, *, group: str, role: str = "",
            site: str = "", ip: str | None = None, cfg: list[str] | None = None,
            pc_ip: tuple[str, str, str] | None = None,
            modules: list[str] | None = None, dns: bool = True) -> str:
        p = self.layout.place(name, model, group=GROUP_MERGE.get(group, group))
        sid = self.lab.add_device(model, name, p.x, p.y,
                                  ios_config=cfg, pc_ip=pc_ip)
        for mod in (modules or []):
            self.lab.install_module(sid, mod)
        self.sid[key] = sid
        self._claim_ip(ip, name)
        self.meta[key] = dict(name=name, model=model, role=role, site=site,
                              ip=ip, group=group)
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

    def slink(self, a: str, ap: str, b: str, bp: str, dce: str, clock: int = 2_000_000):
        ia, ib, m = self.p2p.next()
        self.routed += [(a, ap, ia, m), (b, bp, ib, m)]
        self.link(a, ap, b, bp, kind="serial", dce=dce, clock=clock)
        self.serial_meta.append((a, ap, b, bp, dce, clock))
        return ia, ib

    def _asa_uplink(self, key: str, port: str, fallback: str) -> str:
        """The address the router side of this ASA link was given.

        ``rlink`` allocated a /30 for both ends; the firewall must use *its* end
        of that pair, or the two ends sit in different subnets on one cable.
        """
        for (_d, p, ip, _m) in self.routed:
            if _d == key and p == port:
                return ip
        return fallback

    def cabled_ports(self, key: str) -> dict[str, str]:
        """{port: peer key} for every cable terminating on this device.

        The authority for "which ports exist" is the cabling, not a list typed
        beside it.  Two hand-maintained lists drift, and the way they drift is a
        cabled port that nothing configures -- a link that renders dead while
        every structural check passes.
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

    def loop(self, _n: int | None = None) -> str:
        """Next loopback address.

        Allocation is by call order, not by a number the caller guesses: passing
        a hand-picked index is how two devices end up claiming 10.255.0.16, and
        the address guard then has to fail the build to say so.
        """
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
                              encrypt_type=5, password="yml-wlan-2f81")
        self.wlans.append((self.meta[key]["name"], ssid))

    # -- end devices ------------------------------------------------------ #
    def end(self, key: str, model: str, name: str, *, group: str, ip: str,
            gw_: str, mask: str = M24, role: str = "", site: str = "") -> str:
        return self.add(key, model, name, group=group, role=role, site=site,
                        ip=ip, pc_ip=(ip, mask, gw_))

    # ================================================================== #
    # 1. carrier / partner edge
    # ================================================================== #
    def build_edge(self) -> None:
        g = "T1-carrier-edge"
        self.add("isp1", "Cloud-PT", "CARRIER-NTT-EDGE", group=g, site="EDGE",
                 role="NTT Communications transit cloud (AS65101)")
        self.add("isp2", "Cloud-PT", "CARRIER-KDDI-EDGE", group=g, site="EDGE",
                 role="KDDI transit cloud (backup carrier)")
        self.add("ce1", "ISR4331", "YML-CE-01", group=g, site="EDGE",
                 ip=self.loop(),
                 role="Carrier edge router A (eBGP AS65101)", modules=["NIM-2T"])
        self.add("ce2", "ISR4331", "YML-CE-02", group=g, site="EDGE",
                 ip=self.loop(),
                 role="Carrier edge router B (eBGP, diverse path)", modules=["NIM-2T"])
        self.add("fwext", "5505", "FW-INTERNET-EDGE", group=g, site="EDGE",
                 ip="10.99.0.2",
                 role="Internet/DMZ edge firewall (outside->dmz->inside)")
        for key, name, role in [
            ("naccs", "NACCS-CUSTOMS-GW",
             "Japan Customs NACCS gateway (eBGP AS65102, IPsec)"),
            ("vts", "VTS-PORT-AUTH-GW",
             "Vessel Traffic Service / port authority gateway"),
            ("railop", "RAIL-OPERATOR-GW",
             "Rail operator intermodal gateway (eBGP AS65103)"),
            ("lineedi", "SHIPLINE-EDI-GW",
             "Shipping-line EDI community gateway (eBGP AS65104)"),
        ]:
            self.add(key, "ISR4331", name, group=g, site="EDGE", ip=self.loop(),
                     role=role, modules=["NIM-2T"])
        self.add("dmzsw", "2960-24TT", "EDGE-DMZ-SW", group=g, site="EDGE",
                 ip=host(S_EDGE, K.V_EDI, 10),
                 role="Partner DMZ access switch (EDI / NACCS brokers)")
        self.add("edisrv", "Server-PT", "PARTNER-EDI-SVR", group=g, site="EDGE",
                 ip=host(S_EDGE, K.V_EDI, 20),
                 role="Partner EDI broker (AS2 / SFTP)",
                 pc_ip=(host(S_EDGE, K.V_EDI, 20), M24, host(S_EDGE, K.V_EDI, 1)))

    # ================================================================== #
    # 2. terminal backbone
    # ================================================================== #
    def build_backbone(self) -> None:
        g = "T2-backbone"
        self.add("bb1", "3650-24PS", "YML-CORE-SW-01", group=g, site="CORE",
                 ip=self.loop(),
                 role="Terminal collapsed core A (OSPF area 0, iBGP edge)")
        self.add("bb2", "3650-24PS", "YML-CORE-SW-02", group=g, site="CORE",
                 ip=self.loop(),
                 role="Terminal collapsed core B (OSPF area 0, iBGP edge)")
        self.add("cr1", "ISR4331", "YML-CORE-RTR-01", group=g, site="CORE",
                 ip=self.loop(),
                 role="Terminal core router / OSPF ABR / iBGP speaker",
                 modules=["NIM-2T"])
        self.add("cr2", "ISR4331", "YML-CORE-RTR-02", group=g, site="CORE",
                 ip=self.loop(),
                 role="Terminal core router / OSPF ABR / iBGP speaker",
                 modules=["NIM-2T"])
        self.add("we1", "2911", "YML-WAN-EDGE-01", group=g, site="CORE",
                 ip=self.loop(),
                 role="Terminal WAN edge (primary carrier)", modules=["HWIC-2T"])
        self.add("we2", "2911", "YML-WAN-EDGE-02", group=g, site="CORE",
                 ip=self.loop(),
                 role="Terminal WAN edge (backup carrier)", modules=["HWIC-2T"])
        self.add("dci1", "ISR4331", "YML-DCI-RTR-01", group=g, site="CORE",
                 ip=self.loop(),
                 role="Data-centre interconnect router (TDC<->DRC)",
                 modules=["NIM-2T"])
        self.add("mgw", "ISR4331", "YML-MGMT-GW-01", group=g, site="CORE",
                 ip=self.loop(),
                 role="Out-of-band management gateway / NOC edge")

    # ================================================================== #
    # 3. primary terminal data centre
    # ================================================================== #
    def build_tdc(self) -> None:
        g = "T3-primary-dc"
        s = S_TDC
        self.add("tdcs1", "3650-24PS", "TDC-SPINE-01", group=g, site="TDC",
                 ip=host(s, K.V_SRV, 11), role="TDC spine A (VLAN 60 gateway, HSRP active)")
        self.add("tdcs2", "3650-24PS", "TDC-SPINE-02", group=g, site="TDC",
                 ip=host(s, K.V_SRV, 12), role="TDC spine B (HSRP standby)")
        self.add("tdcl1", "3560-24PS", "TDC-LEAF-01", group=g, site="TDC",
                 ip=host(s, K.V_SRV, 13), role="TDC leaf A (server access)")
        self.add("tdcl2", "3560-24PS", "TDC-LEAF-02", group=g, site="TDC",
                 ip=host(s, K.V_SRV, 14), role="TDC leaf B (server access)")
        self.add("tdcfw", "5505", "FW-TDC-PERIMETER", group=g, site="TDC",
                 ip="10.99.1.2", role="TDC perimeter firewall (inside/dmz)")
        self.add("tdcfw2", "5505", "FW-TDC-INT", group=g, site="TDC",
                 ip="10.99.2.2", role="TDC internal segmentation firewall")

        # Core services are present in every profile: a lab without a DNS, DHCP
        # or AAA server is not a smaller lab, it is a broken one, and slicing
        # the whole farm by profile silently dropped them at small sizes.
        core = [
            ("s_dns",     "DNS-SVR-01",       "dns",        "Authoritative DNS - " + TML_DOMAIN),
            ("s_dns2",    "DNS-SVR-02",       "dns2",       "Secondary DNS (zone replicated)"),
            ("s_dhcp",    "DHCP-SVR-01",      "dhcp",       "Terminal DHCP (all zones)"),
            ("s_dhcp2",   "DHCP-SVR-02",      "dhcp2",      "Terminal DHCP (HA pair)"),
            ("s_ntp",     "NTP-SVR-01",       "ntp",        "Stratum-2 NTP, GPS disciplined"),
            ("s_ntp2",    "NTP-SVR-02",       "ntp2",       "Secondary NTP"),
            ("s_syslog",  "SYSLOG-SVR-01",    "syslog",     "Central syslog / SIEM collector"),
            ("s_syslog2", "SYSLOG-SVR-02",    "syslog2",    "Secondary syslog / archive"),
            ("s_aaa",     "AAA-SVR-01",       "aaa",        "RADIUS + TACACS+ (Cisco ACS)"),
            ("s_aaa2",    "AAA-SVR-02",       "aaa2",       "Secondary AAA"),
            ("s_tftp",    "TFTP-ARCHIVE-01",  "tftp",       "Configuration and image archive"),
        ]
        listed = [
            ("s_tos",     "TOS-APP-01",       "tos",        "Terminal Operating System application server (primary)"),
            ("s_tos2",    "TOS-APP-02",       "tos2",       "TOS application server (HA pair)"),
            ("s_wms",     "WMS-APP-01",       "wms",        "Warehouse / yard management system"),
            ("s_edi",     "EDI-BROKER-01",    "edi",        "EDI / AS2 broker to shipping lines"),
            ("s_gis",     "GIS-YARD-01",      "gis",        "Yard GIS and block visualisation"),
            ("s_billing", "BILLING-SVR-01",   "billing",    "Tariff and billing engine"),
            ("s_vbs",     "VBS-SLOT-SVR",     "vbs",        "Vehicle booking system / slot allocation"),
            ("s_cargo",   "CARGO-TRACK-01",   "cargo",      "Container tracking and event service"),
            ("s_agvd",    "AGV-DISPATCH-01",  "agvdisp",    "AGV fleet dispatch (safety critical)"),
            ("s_csc",     "CRANE-SCADA-01",   "cranescada", "Crane SCADA / equipment management"),
            ("s_reefer",  "REEFER-MON-01",    "reefer",     "Reefer temperature compliance service"),
            ("s_web",     "TML-PORTAL-01",    "web",        "Terminal portal (HTTPS)"),
            ("s_mail",    "MAIL-RELAY-01",    "mail",       "Official mail relay"),
            ("s_ca",      "PKI-CA-01",        "ca",         "Terminal internal certificate authority"),
            ("s_flow",    "NETFLOW-SVR-01",   "flow",       "NetFlow / IPFIX collector"),
            ("s_hist",    "DATA-HISTORIAN",   "historian",  "Container and equipment data historian"),
            ("s_backup",  "BACKUP-SVR-01",    "backup",     "Nightly configuration and TOS backup"),
        ]
        n_app = max(1, self.p["servers"] - len(core))
        for i, (key, name, svc, desc) in enumerate(core + listed[:n_app]):
            ip = SRV[svc]
            self.add(key, "Server-PT", name, group=g, site="TDC", ip=ip, role=desc,
                     pc_ip=(ip, M24, gw(S_TDC, K.V_SRV)))
            self.servers.append((key, name, svc, desc, ip))

    # ================================================================== #
    # 4. disaster-recovery data centre
    # ================================================================== #
    def build_drc(self) -> None:
        g = "T4-dr-site"
        s = S_DRC
        self.add("drcs1", "3650-24PS", "DRC-SPINE-01", group=g, site="DRC",
                 ip=host(s, K.V_SRV, 11), role="DR site spine A (standby TOS)")
        self.add("drcs2", "3560-24PS", "DRC-LEAF-01", group=g, site="DRC",
                 ip=host(s, K.V_SRV, 12), role="DR site leaf / server access")
        self.add("drcfw", "5505", "FW-DRC-PERIMETER", group=g, site="DRC",
                 ip="10.99.4.2", role="DR site perimeter firewall")
        srv = [
            ("d_tos", "DR-TOS-APP-01", 41, "Standby TOS application (replication target)"),
            ("d_db",  "DR-MANIFEST-DB", 42, "Standby manifest / TOS database"),
            ("d_wms", "DR-WMS-APP-01", 43, "Standby yard management"),
            ("d_dns", "DR-DNS-SVR-01", 44, "DR DNS"),
            ("d_rep", "DR-REPLICA-SVR", 45, "Asynchronous replication target"),
            ("d_bak", "DR-BACKUP-VAULT", 46, "Offline backup vault (air-gapped)"),
        ]
        for key, name, h, desc in srv[:max(2, self.p["servers"] // 4)]:
            ip = host(s, K.V_SRV, h)
            self.add(key, "Server-PT", name, group=g, site="DRC", ip=ip, role=desc,
                     pc_ip=(ip, M24, gw(s, K.V_SRV)))

    # ================================================================== #
    # 5. customs enclave  (172.20.0.0/16 -- its own address space)
    # ================================================================== #
    def build_customs(self) -> None:
        g = "T5-customs"
        self.add("cusfw1", "5505", "CUS-FW-OUTER", group=g, site="CUSTOMS",
                 ip=f"{CUSTOMS_NET}.255.1",
                 role="Customs enclave outer firewall (terminal -> customs DMZ)")
        self.add("cusfw2", "5505", "CUS-FW-INNER", group=g, site="CUSTOMS",
                 ip=f"{CUSTOMS_NET}.255.2",
                 role="Customs enclave inner firewall (DMZ -> manifest DB)")
        self.add("cussw1", "3560-24PS", "CUS-DMZ-SW-01", group=g, site="CUSTOMS",
                 ip=f"{CUSTOMS_NET}.10.10", role="Customs DMZ switch (NACCS brokers)")
        self.add("cussw2", "3560-24PS", "CUS-DB-SW-01", group=g, site="CUSTOMS",
                 ip=f"{CUSTOMS_NET}.20.10", role="Customs protected switch (manifest DB)")
        self.add("cusids", "CyberObserver", "CUS-IDS-01", group=g, site="CUSTOMS",
                 ip=f"{CUSTOMS_NET}.10.20",
                 role="Customs enclave intrusion detection sensor")
        self.add("custap", "Sniffer", "CUS-TAP-01", group=g, site="CUSTOMS",
                 ip=f"{CUSTOMS_NET}.10.21",
                 role="Customs enclave lawful-intercept / audit tap")
        srv = [
            ("c_db1",  "CUS-MANIFEST-DB-01", f"{CUSTOMS_NET}.20.21", K.V_CUS,
             "Customs manifest database (primary, encrypted at rest)"),
            ("c_db2",  "CUS-MANIFEST-DB-02", f"{CUSTOMS_NET}.20.22", K.V_CUS,
             "Customs manifest database (synchronous standby)"),
            ("c_nac1", "NACCS-BROKER-01", f"{CUSTOMS_NET}.10.31", K.V_CUS,
             "NACCS declaration broker (primary)"),
            ("c_nac2", "NACCS-BROKER-02", f"{CUSTOMS_NET}.10.32", K.V_CUS,
             "NACCS declaration broker (standby)"),
            ("c_app",  "CUS-DECL-APP-01", f"{CUSTOMS_NET}.10.33", K.V_CUS,
             "Declaration processing application"),
            ("c_hsm",  "CUS-HSM-KEY-01", f"{CUSTOMS_NET}.20.23", K.V_CUS,
             "Hardware security module / key custodian"),
            ("c_audit", "CUS-AUDIT-LOG-01", f"{CUSTOMS_NET}.20.24", K.V_CUS,
             "Immutable customs audit log (WORM)"),
        ]
        for key, name, ip, vlan, desc in srv:
            self.add(key, "Server-PT", name, group=g, site="CUSTOMS", ip=ip, role=desc,
                     pc_ip=(ip, M24, f"{CUSTOMS_NET}.{vlan}.1"))
        for i, (key, name) in enumerate([("c_ws1", "CUS-OFFICER-WS-01"),
                                         ("c_ws2", "CUS-OFFICER-WS-02")]):
            ip = f"{CUSTOMS_NET}.10.{40 + i}"
            self.end(key, "PC-PT", name, group=g, ip=ip, gw_=f"{CUSTOMS_NET}.10.1",
                     role="Customs officer examination workstation", site="CUSTOMS")

    # ================================================================== #
    # 6. terminal operations centre
    # ================================================================== #
    def build_toc(self) -> None:
        g = "T6-control-tower"
        s = S_TOC
        for i, (k, n, r) in enumerate([
            ("toc1", "TOC-RTR-01", "TOC zone router (active) / OSPF ABR"),
            ("toc2", "TOC-RTR-02", "TOC zone router (standby) / OSPF ABR"),
        ]):
            self.add(k, "ISR4331", n, group=g, site="TOC", ip=host(s, K.V_MGMT, 2 + i),
                     role=r, modules=["NIM-2T"])
        self.add("tocd1", "3560-24PS", "TOC-DSW-01", group=g, site="TOC",
                 ip=host(s, K.V_MGMT, 11), role="TOC distribution switch A")
        self.add("tocd2", "3560-24PS", "TOC-DSW-02", group=g, site="TOC",
                 ip=host(s, K.V_MGMT, 12), role="TOC distribution switch B")
        self.add("toca1", "2960-24TT", "TOC-ACC-01", group=g, site="TOC",
                 ip=host(s, K.V_MGMT, 21), role="TOC operations floor access A")
        self.add("toca2", "2960-24TT", "TOC-ACC-02", group=g, site="TOC",
                 ip=host(s, K.V_MGMT, 22), role="TOC operations floor access B")
        ops = [
            ("toc_vt1", "TOC-VIDEO-WALL-1", "Video wall controller (berth cameras)"),
            ("toc_vt2", "TOC-GATE-VIEW-1",  "Gate OCR monitoring workstation"),
            ("toc_disp", "TOS-DISPATCH-WS", "TOS dispatch console"),
        ]
        for i, (k, n, r) in enumerate(ops):
            ip = host(s, K.V_OPS, 30 + i)
            self.add(k, "Server-PT", n, group=g, site="TOC", ip=ip, role=r,
                     pc_ip=(ip, M24, gw(s, K.V_OPS)))
        for i in range(max(4, self.p["clients"] // 4)):
            ip = host(s, K.V_OPS, 40 + i)
            self.end(f"toc_ws{i + 1}", "PC-PT", f"TOC-OPS-WS-{i + 1:02d}", group=g,
                     ip=ip, gw_=gw(s, K.V_OPS),
                     role="Terminal operations controller workstation", site="TOC")
        for i in range(2):
            ip = host(s, K.V_VOICE, 20 + i)
            self.end(f"toc_ph{i + 1}", "7960", f"TOC-RADIO-DISP-{i + 1:02d}", group=g,
                     ip=ip, gw_=gw(s, K.V_VOICE),
                     role="Radio dispatch console (port operations VHF)", site="TOC")

    # ================================================================== #
    # 7. berth apron / STS gantry cranes
    # ================================================================== #
    def build_berths(self) -> None:
        """Each berth is served by a *pair* of L3 industrial switches.

        They hold the berth's SVIs with HSRP and dual-home to the two collapsed
        core switches, so losing one switch or one core uplink does not stop
        container handling -- the cranes' own IE-3400 switches uplink to both.
        """
        g = "T7-berth-sts"
        for bi, (code, label, note) in enumerate(BERTHS[:self.p["berths"]]):
            site = S_BERTH0 + bi
            for suffix, tag in (("a", "A"), ("b", "B")):
                self.add(f"brt{bi + 1}{suffix}", "IE-9320",
                         f"BRT{bi + 1}-IAG-{tag}", group=g, site=code,
                         ip=host(site, K.V_MGMT, 2 + (0 if suffix == "a" else 1)),
                         role=f"{label} berth industrial aggregation {tag} "
                              f"({note})")
            for ci in range(self.p["cranes"]):
                n = bi * self.p["cranes"] + ci + 1
                self.cranes.append(dict(idx=n, berth=bi + 1, site=site, code=code))
                self._build_crane(n, bi + 1, site, code, g)

    def _build_crane(self, n: int, berth: int, site: int, code: str, g: str) -> None:
        """One STS crane: industrial switch + motion PLC + operator HMI +
        spreader RFID + travel motion detector, all on the crane's own VLAN."""
        tag = f"STS{n:02d}"
        base = 20
        self.add(f"st{n}sw", "IE-3400", f"{tag}-SW-01", group=g, site=code,
                 ip=host(site, K.V_MGMT, base + n),
                 role=f"{tag} crane control-cabinet industrial switch (berth {berth})")
        for suffix, model, role in [
            ("plc", "PLC-PT", "gantry/ trolley motion controller (safety PLC)"),
            ("hmi", "HMI-PT", "crane operator panel"),
        ]:
            key = f"st{n}{suffix}"
            # Distinct host octets per role band.  Two devices on one segment
            # must never share an address, and an off-by-one here stays invisible
            # until a duplicate-address check catches it much later.
            ip = host(site, K.V_OT, base + n + (0 if suffix == "plc" else 30))
            self.add(key, model, f"{tag}-{suffix.upper()}-01", group=g, site=code,
                     ip=ip, role=f"{tag} {role}")
            self.static_iot.append((key, ip, M24, gw(site, K.V_OT)))
        for suffix, model, role in [
            ("rfid", "RFID Reader", "spreader twistlock / container ID reader"),
            ("mot", "Motion Detector", "gantry travel and anti-collision sensor"),
        ]:
            key = f"st{n}{suffix}"
            ip = host(site, K.V_IOT, base + n + (0 if suffix == "rfid" else 30))
            self.add(key, model, f"{tag}-{suffix.upper()}-01", group=g, site=code,
                     ip=ip, role=f"{tag} {role}")
            self.static_iot.append((key, ip, M24, gw(site, K.V_IOT)))

    # ================================================================== #
    # 8. container yard blocks
    # ================================================================== #
    def build_yard(self) -> None:
        g = "T8-container-yard"
        self.add("yrdagg1", "IE-9320", "YARD-AGG-01", group=g, site="YARD",
                 ip=host(S_YARD0, K.V_MGMT, 3),
                 role="Yard industrial aggregation switch A (blocks A-D)")
        self.add("yrdagg2", "IE-9320", "YARD-AGG-02", group=g, site="YARD",
                 ip=host(S_YARD0, K.V_MGMT, 4),
                 role="Yard industrial aggregation switch B (blocks E-H)")
        for bi, (code, block, kind) in enumerate(YARD_BLOCKS[:self.p["yard"]]):
            site = S_YARD0 + bi
            self.yards.append(dict(idx=bi + 1, code=code, block=block, kind=kind,
                                   site=site))
            self._build_yard_block(bi + 1, code, block, kind, site, g)

    def _build_yard_block(self, n: int, code: str, block: str, kind: str,
                          site: int, g: str) -> None:
        """One RTG yard block.

        Modelled contents: the block's industrial switch, its RTG crane
        controller, a yard-position RFID portal and a reefer bank temperature
        monitor.  ``docs/DESIGN.md`` records the ground-slot arithmetic this
        stands in for (240 TEU slots and 64 reefer plugs per block).
        """
        tag = f"YRD{n:02d}"
        self.add(f"yb{n}sw", "IE-3400", f"{tag}-SW-01", group=g, site=code,
                 ip=host(site, K.V_MGMT, 10),
                 role=f"{tag} block {block} industrial switch ({kind})")
        pairs = [
            ("plc", "PLC-PT", K.V_OT, 10, f"RTG crane controller, block {block}"),
            ("rfid", "RFID Reader", K.V_IOT, 10, f"yard position RFID portal, block {block}"),
            ("temp", "Temperature Monitor", K.V_REEFER, 10,
             f"reefer bank temperature monitor, block {block}"),
            ("siren", "Siren", K.V_IOT, 11, f"yard safety alarm, block {block}"),
        ]
        for j, (suffix, model, vlan, h, role) in enumerate(pairs):
            key = f"yb{n}{suffix}"
            ip = host(site, vlan, h + j)
            self.add(key, model, f"{tag}-{suffix.upper()}-01", group=g, site=code,
                     ip=ip, role=f"{tag} {role}")
            self.static_iot.append((key, ip, M24, gw(site, vlan)))

    # ================================================================== #
    # 9. AGV fleet
    # ================================================================== #
    def build_agv(self) -> None:
        g = "T9-agv-fleet"
        s = S_AGV
        for i, (k, n, r) in enumerate([
            ("agvr1", "AGV-RTR-01", "AGV control zone router (active)"),
            ("agvr2", "AGV-RTR-02", "AGV control zone router (standby)"),
        ]):
            self.add(k, "ISR4331", n, group=g, site="AGV", ip=host(s, K.V_MGMT, 2 + i),
                     role=r, modules=["NIM-2T"])
        self.add("agvsw1", "IE-9320", "AGV-CTL-SW-01", group=g, site="AGV",
                 ip=host(s, K.V_MGMT, 11), role="AGV control-room industrial switch A")
        self.add("agvsw2", "IE-9320", "AGV-CTL-SW-02", group=g, site="AGV",
                 ip=host(s, K.V_MGMT, 12), role="AGV control-room industrial switch B")
        for i, (k, n, h, r) in enumerate([
            ("agv_disp", "AGV-FLEET-DISP-01", 21,
             "AGV fleet dispatcher (route optimisation, safety interlock)"),
            ("agv_disp2", "AGV-FLEET-DISP-02", 22, "AGV dispatcher HA pair"),
        ]):
            ip = host(s, K.V_SRV, h)
            self.add(k, "Server-PT", n, group=g, site="AGV", ip=ip, role=r,
                     pc_ip=(ip, M24, gw(s, K.V_SRV)))
        for i in range(self.p["agv"]):
            tag = f"AGV{i + 1:03d}"
            key = f"agv{i + 1}"
            ip = host(s, K.V_AGV, 30 + i)
            self.add(key, "PLC-PT", f"{tag}-CTL", group=g, site="AGV", ip=ip,
                     role=f"{tag} onboard vehicle controller (guidance + safety)")
            self.static_iot.append((key, ip, M24, gw(s, K.V_AGV)))
            self.wireless(key, "YML-AGV-MESH")
        # AGV radio coverage APs are added by build_wireless()

    # ================================================================== #
    # 10. gate complex
    # ================================================================== #
    def build_gates(self) -> None:
        g = "T10-gate"
        s = S_GATE
        for i, (k, n, r) in enumerate([
            ("gater1", "GATE-RTR-01", "Gate complex router (active)"),
            ("gater2", "GATE-RTR-02", "Gate complex router (standby)"),
        ]):
            self.add(k, "ISR4331", n, group=g, site="GATE", ip=host(s, K.V_MGMT, 2 + i),
                     role=r, modules=["NIM-2T"])
        self.add("gatesw1", "IE-9320", "GATE-SW-01", group=g, site="GATE",
                 ip=host(s, K.V_MGMT, 11), role="Gate lane industrial switch A")
        self.add("gatesw2", "IE-3400", "GATE-SW-02", group=g, site="GATE",
                 ip=host(s, K.V_MGMT, 12), role="Gate lane industrial switch B")
        self.add("gateocr", "Server-PT", "GATE-OCR-SVR-01", group=g, site="GATE",
                 ip=host(s, K.V_SRV, 21),
                 role="Container number OCR recognition service",
                 pc_ip=(host(s, K.V_SRV, 21), M24, gw(s, K.V_SRV)))
        for i, (code, lane) in enumerate(GATE_LANES[:self.p["gates"]]):
            for suffix, model, role in [
                ("rfid", "RFID Reader", f"{code} {lane} - vehicle/container RFID portal"),
                ("bar", "PLC-PT", f"{code} {lane} - barrier and weighbridge PLC"),
                ("cam", "Webcam", f"{code} {lane} - OCR camera head"),
            ]:
                key = f"gate{i + 1}{suffix}"
                ip = host(s, K.V_OT, 30 + i * 3 + {"rfid": 0, "bar": 1, "cam": 2}[suffix])
                self.add(key, model, f"GATE-{code}-{suffix.upper()}", group=g,
                         site="GATE", ip=ip, role=role)
                self.static_iot.append((key, ip, M24, gw(s, K.V_OT)))

    # ================================================================== #
    # 11. rail intermodal terminal
    # ================================================================== #
    def build_rail(self) -> None:
        g = "T11-rail"
        s = S_RAIL
        for i, (k, n, r) in enumerate([
            ("railr1", "RAIL-RTR-01", "Rail terminal router (active)"),
            ("railr2", "RAIL-RTR-02", "Rail terminal router (standby)"),
        ]):
            self.add(k, "ISR4331", n, group=g, site="RAIL", ip=host(s, K.V_MGMT, 2 + i),
                     role=r, modules=["NIM-2T"])
        self.add("railsw1", "IE-9320", "RAIL-SW-01", group=g, site="RAIL",
                 ip=host(s, K.V_MGMT, 11), role="Rail terminal industrial switch A")
        self.add("railsw2", "IE-3400", "RAIL-SW-02", group=g, site="RAIL",
                 ip=host(s, K.V_MGMT, 12), role="Rail terminal industrial switch B")
        self.add("rail_sig", "Server-PT", "RAIL-SIGNAL-SVR", group=g, site="RAIL",
                 ip=host(s, K.V_RAIL, 20),
                 role="Rail signalling interlock interface",
                 pc_ip=(host(s, K.V_RAIL, 20), M24, gw(s, K.V_RAIL)),
                 )
        self.add("rail_tos", "Server-PT", "RAIL-TOS-GW", group=g, site="RAIL",
                 ip=host(s, K.V_RAIL, 21),
                 role="Rail/TOS interchange gateway",
                 pc_ip=(host(s, K.V_RAIL, 21), M24, gw(s, K.V_RAIL)),
                 )
        for i, (code, track) in enumerate(RAIL_TRACKS[:self.p["rail"]]):
            for suffix, model, role in [
                ("plc", "PLC-PT", f"{code} RMG crane controller ({track})"),
                ("hmi", "HMI-PT", f"{code} RMG operator panel ({track})"),
                ("rfid", "RFID Reader", f"{code} wagon/container RFID portal ({track})"),
            ]:
                key = f"rail{i + 1}{suffix}"
                ip = host(s, K.V_OT, 30 + i * 3 + {"plc": 0, "hmi": 1, "rfid": 2}[suffix])
                self.add(key, model, f"RAIL-{code}-{suffix.upper()}", group=g,
                         site="RAIL", ip=ip, role=role)
                self.static_iot.append((key, ip, M24, gw(s, K.V_OT)))

    # ================================================================== #
    # 12. CFS / warehouse
    # ================================================================== #
    def build_cfs(self) -> None:
        g = "T12-cfs"
        s = S_CFS
        self.add("cfssw1", "2960-24TT", "CFS-SW-01", group=g, site="CFS",
                 ip=host(s, K.V_MGMT, 11), role="CFS / warehouse access switch A")
        self.add("cfssw2", "2960-24TT", "CFS-SW-02", group=g, site="CFS",
                 ip=host(s, K.V_MGMT, 12), role="CFS / warehouse access switch B")
        self.add("cfs_wms", "Server-PT", "CFS-WMS-01", group=g, site="CFS",
                 ip=host(s, K.V_SRV, 21), role="CFS warehouse management node",
                 pc_ip=(host(s, K.V_SRV, 21), M24, gw(s, K.V_SRV)),
                 )
        self.add("cfs_dg", "Server-PT", "CFS-DG-COMPLY-01", group=g, site="CFS",
                 ip=host(s, K.V_SRV, 22),
                 role="Dangerous-goods segregation compliance service",
                 pc_ip=(host(s, K.V_SRV, 22), M24, gw(s, K.V_SRV)),
                 )
        for i in range(max(4, self.p["clients"] // 6)):
            ip = host(s, K.V_OPS, 40 + i)
            self.end(f"cfs_pc{i + 1}", "PC-PT", f"CFS-TERM-{i + 1:02d}", group=g,
                     ip=ip, gw_=gw(s, K.V_OPS),
                     role="CFS cargo handling terminal", site="CFS")
        if self.p["reoffer"]:
            for i in range(2):
                self.add(f"cfsap{i + 1}", "AccessPoint-PT-N", f"CFS-AP-{i + 1:02d}",
                         group=g, site="CFS", ip=host(s, K.V_MGMT, 30 + i),
                         role="CFS indoor WLAN access point")
                self.wireless(f"cfsap{i + 1}", "YML-OPS-WLAN")

    # ================================================================== #
    # 13. reefer / dangerous-goods yard
    # ================================================================== #
    def build_reefer(self) -> None:
        g = "T13-reefer-dg"
        s = S_REEFER
        self.add("rfsw1", "IE-3400", "REEFER-SW-01", group=g, site="REEFER",
                 ip=host(s, K.V_MGMT, 11),
                 role="Reefer yard industrial switch A (temperature compliance)")
        self.add("rfsw2", "IE-3400", "DG-SW-01", group=g, site="REEFER",
                 ip=host(s, K.V_MGMT, 12),
                 role="Dangerous-goods yard industrial switch B (ex-rated)")
        n_reefer = max(4, self.p["yard"] // 2)
        for i in range(n_reefer):
            key = f"rf{i + 1}"
            ip = host(s, K.V_REEFER, 30 + i)
            self.add(key, "Temperature Monitor", f"REEFER-BANK-{i + 1:02d}", group=g,
                     site="REEFER", ip=ip,
                     role=f"Reefer bank {i + 1} temperature monitor (cold-chain compliance)")
            self.static_iot.append((key, ip, M24, gw(s, K.V_REEFER)))
        for i in range(4):
            key = f"dg{i + 1}"
            ip = host(s, K.V_DG, 30 + i)
            model, role = [
                ("Smoke Detector", "DG store smoke detection"),
                ("Water Level Monitor", "DG bund water-level / spill detection"),
                ("Siren", "DG yard evacuation alarm"),
                ("Motion Detector", "DG store intrusion detection"),
            ][i]
            self.add(key, model, f"DG-{['SMOKE', 'BUND', 'ALARM', 'INTR'][i]}-01",
                     group=g, site="REEFER", ip=ip, role=f"{role} (hazmat yard)")
            self.static_iot.append((key, ip, M24, gw(s, K.V_DG)))

    # ================================================================== #
    # 14. wireless infrastructure
    # ================================================================== #
    def build_wireless(self) -> None:
        g = "T14-wireless"
        s = S_WLAN
        for i, (k, _model, n, r) in enumerate([
            ("wlc1", "WLC-3504", "YML-WLC-01",
             "Terminal WLAN controller A (AGV radio + handhelds)"),
            ("wlc2", "WLC-3504", "YML-WLC-02", "Terminal WLAN controller B (HA pair)"),
        ]):
            self.add(k, "WLC-3504", n, group=g, site="WLAN", ip=host(s, K.V_MGMT, 2 + i),
                     role=r)
        self.add("wlsw1", "3560-24PS", "WLAN-DSW-01", group=g, site="WLAN",
                 ip=host(s, K.V_MGMT, 11), role="WLAN distribution switch (PoE)")
        self.add("wlsw2", "2960-24TT", "WLAN-ACC-01", group=g, site="WLAN",
                 ip=host(s, K.V_MGMT, 12), role="WLAN access switch (outdoor APs)")
        n_ap = self.p["aps"]
        for i in range(n_ap):
            zone = ["AGV-MESH", "YARD", "BERTH", "GATE", "RAIL", "TOC"][i % 6]
            key = f"ap{i + 1}"
            self.add(key, "AccessPoint-PT-N", f"YML-AP-{i + 1:02d}", group=g,
                     site="WLAN", ip=host(s, K.V_MGMT, 30 + i),
                     role=f"Outdoor 802.11ac AP - {zone} coverage")
            self.wireless(key, "YML-AGV-MESH" if zone == "AGV-MESH" else "YML-OPS-WLAN")

    # ================================================================== #
    # 15. physical security
    # ================================================================== #
    def build_security(self) -> None:
        g = "T15-security"
        s = S_SEC
        self.add("secsw1", "3560-24PS", "SEC-SW-01", group=g, site="SEC",
                 ip=host(s, K.V_MGMT, 11), role="Physical security PoE switch A")
        self.add("secsw2", "2960-24TT", "SEC-SW-02", group=g, site="SEC",
                 ip=host(s, K.V_MGMT, 12), role="Physical security PoE switch B")
        self.add("sec_nvr", "Server-PT", "CCTV-NVR-01", group=g, site="SEC",
                 ip=host(s, K.V_CCTV, 20), role="CCTV recording / video analytics",
                 pc_ip=(host(s, K.V_CCTV, 20), M24, gw(s, K.V_CCTV)),
                 )
        self.add("sec_acs", "Server-PT", "ACS-DOOR-SVR-01", group=g, site="SEC",
                 ip=host(s, K.V_CCTV, 21),
                 role="Door access control / TWIC-equivalent credential service",
                 pc_ip=(host(s, K.V_CCTV, 21), M24, gw(s, K.V_CCTV)),
                 )
        for i in range(6):
            key = f"cam{i + 1}"
            ip = host(s, K.V_CCTV, 30 + i)
            self.add(key, "Webcam", f"PERIM-CAM-{i + 1:02d}", group=g, site="SEC",
                     ip=ip, role=f"Perimeter CCTV camera head {i + 1}")
            self.static_iot.append((key, ip, M24, gw(s, K.V_CCTV)))
        for i in range(4):
            key = f"acs{i + 1}"
            ip = host(s, K.V_CCTV, 40 + i)
            self.add(key, "RFID Reader", f"ACS-DOOR-{i + 1:02d}", group=g, site="SEC",
                     ip=ip, role=f"Perimeter gate access-control reader {i + 1}")
            self.static_iot.append((key, ip, M24, gw(s, K.V_CCTV)))
        for i in range(2):
            key = f"perim{i + 1}"
            ip = host(s, K.V_IOT, 40 + i)
            self.add(key, "Trip Sensor", f"PERIM-TRIP-{i + 1:02d}", group=g, site="SEC",
                     ip=ip, role=f"Perimeter intrusion trip sensor {i + 1}")
            self.static_iot.append((key, ip, M24, gw(s, K.V_IOT)))

    # ================================================================== #
    # 16. OT / power / environment
    # ================================================================== #
    def build_ot(self) -> None:
        g = "T16-ot-power"
        s = S_OT
        self.add("otsw1", "IE-3400", "OT-SW-01", group=g, site="OT",
                 ip=host(s, K.V_MGMT, 11), role="Substation / utilities industrial switch")
        self.add("otsw2", "IE-2000", "OT-SW-02", group=g, site="OT",
                 ip=host(s, K.V_MGMT, 12), role="Shore-power / reefer-rack switch")
        self.add("ot_plc1", "PLC-PT", "OT-SUBSTATION-PLC", group=g, site="OT",
                 ip=host(s, K.V_OT, 20), role="Terminal HV substation PLC")
        self.static_iot.append(("ot_plc1", host(s, K.V_OT, 20), M24, gw(s, K.V_OT)))
        self.add("ot_plc2", "PLC-PT", "OT-SHOREPOWER-PLC", group=g, site="OT",
                 ip=host(s, K.V_OT, 21), role="Cold-ironing / shore power PLC")
        self.static_iot.append(("ot_plc2", host(s, K.V_OT, 21), M24, gw(s, K.V_OT)))
        self.add("ot_ctrl", "NetworkController", "OT-ENERGY-CTL-01", group=g, site="OT",
                 ip=host(s, K.V_OT, 22), role="Energy management / demand controller")
        self.static_iot.append(("ot_ctrl", host(s, K.V_OT, 22), M24, gw(s, K.V_OT)))
        for i in range(4):
            key = f"ot_pm{i + 1}"
            ip = host(s, K.V_IOT, 50 + i)
            self.add(key, "Power Meter", f"OT-POWER-METER-{i + 1:02d}", group=g,
                     site="OT", ip=ip,
                     role=f"RMG/shore power meter {i + 1} (kWh, power quality)")
            self.static_iot.append((key, ip, M24, gw(s, K.V_IOT)))
        for i, (model, role) in enumerate([
            ("Smoke Detector", "Substation smoke detection"),
            ("Siren", "Substation evacuation alarm"),
        ]):
            key = f"ot_env{i + 1}"
            ip = host(s, K.V_IOT, 60 + i)
            self.add(key, model, f"OT-ENV-{i + 1:02d}", group=g, site="OT", ip=ip, role=role)
            self.static_iot.append((key, ip, M24, gw(s, K.V_IOT)))

    # ================================================================== #
    # 17. terminal NOC / management enclave
    # ================================================================== #
    def build_noc(self) -> None:
        g = "T17-noc"
        s = S_NOC
        self.add("nocsw1", "2960-24TT", "NOC-SW-01", group=g, site="NOC",
                 ip=host(s, K.V_MGMT, 11), role="NOC management enclave switch")
        self.add("nocsrv", "Server-PT", "NOC-NMS-01", group=g, site="NOC",
                 ip=host(s, K.V_MGMT, 21),
                 role="Network management station (SNMP/Syslog/NetFlow)",
                 pc_ip=(host(s, K.V_MGMT, 21), M24, gw(s, K.V_MGMT)),
                 )
        mon = [
            ("noc_jump", "NOC-JUMP-01", "Server-PT",
             "Privileged jump host (all admin access transits here)"),
            ("noc_cobs", "NOC-CYBER-OBS", "CyberObserver",
             "Behavioural anomaly / OT intrusion detection"),
            ("noc_tap", "NOC-TAP-01", "Sniffer", "NOC packet capture tap"),
        ]
        for i, (k, n, model, r) in enumerate(mon):
            ip = host(s, K.V_MGMT, 22 + i)
            self.add(k, model, n, group=g, site="NOC", ip=ip, role=r)
            if model == "Server-PT":
                self.lab._els[self.sid[k]].find(".//PORT").find("IP").text = ip
                self.has_nic_ip.add(k)

    # ================================================================== #
    # 18. dispersed end-user / handheld estate
    # ================================================================== #
    def build_clients(self) -> None:
        g = "T18-clients"
        s = S_TOC
        n = self.p["clients"]
        for i in range(n):
            ip = host(s, K.V_WIFI, 50 + (i % 100))
            self.end(f"hh{i + 1}", "Laptop-PT", f"YML-HANDHELD-{i + 1:02d}", group=g,
                     ip=ip, gw_=gw(s, K.V_WIFI),
                     role="Vehicle-mount / handheld terminal (yard and gate ops)",
                     site="MOBILE")
            self.wireless(f"hh{i + 1}", "YML-OPS-WLAN")

    # ================================================================== #
    # cabling
    # ================================================================== #
    def cable(self) -> None:
        """Cable the terminal.

        Port names are not free text: each one is a name Packet Tracer resolves
        at load, and a single name that matches no port on the device makes the
        **whole file** refuse to open (measured -- see
        ``tools/pt_port_verify.py``).  Every name below is therefore either
        attested by the model's own factory config (``build/port_table.json``)
        or verified against Packet Tracer by that tool.

        The port plan is explicit rather than clever, so a reader can check it:
        the two collapsed-core switches carry all zone fan-out, and the core
        routers carry only routed /30 links and serial bearers.
        """
        # ---- backbone ------------------------------------------------ #
        self.rlink("bb1", GE1(1), "bb2", GE1(1))
        self.rlink("bb1", GE1(2), "cr1", "GigabitEthernet0/0/0")
        self.rlink("bb2", GE1(2), "cr2", "GigabitEthernet0/0/0")
        self.rlink("bb1", GE1(3), "cr2", "GigabitEthernet0/0/1")
        self.rlink("bb2", GE1(3), "cr1", "GigabitEthernet0/0/1")
        self.rlink("cr2", "GigabitEthernet0/0/2", "we1", "GigabitEthernet0/0")
        self.rlink("cr1", "GigabitEthernet0/0/2", "we2", "GigabitEthernet0/0")
        self.slink("we1", "Serial0/0/0", "we2", "Serial0/0/0", dce="we1",
                   clock=4_000_000)
        self.rlink("bb1", GE1(4), "dci1", "GigabitEthernet0/0/0")
        self.rlink("bb2", GE1(4), "mgw", "GigabitEthernet0/0/0")

        # ---- carrier / partner edge ---------------------------------- #
        self.rlink("bb1", GE1(5), "ce1", "GigabitEthernet0/0/0")
        self.rlink("bb2", GE1(5), "ce2", "GigabitEthernet0/0/0")
        # Cloud-PT exposes only "Port 0"; every Ethernet/Gigabit/Serial/Coaxial
        # name was tested and rejected (see tools/port_table.py).
        self.rlink("isp1", "Port 0", "ce1", "GigabitEthernet0/0/1")
        self.rlink("isp2", "Port 0", "ce2", "GigabitEthernet0/0/1")
        self.rlink("ce1", "GigabitEthernet0/0/2", "fwext", "Ethernet0/0")
        self.link("fwext", "Ethernet0/1", "dmzsw", "GigabitEthernet0/1")
        # partner gateways terminate on the DMZ switch behind the firewall
        for i, key in enumerate(("naccs", "vts", "railop", "lineedi", "edisrv")):
            port = "FastEthernet0" if key == "edisrv" else "GigabitEthernet0/0/0"
            self.link("dmzsw", FE0(1 + i), key, port)

        # ---- primary data centre ------------------------------------- #
        self.rlink("bb1", GE1(6), "tdcfw", "Ethernet0/0")
        self.link("tdcfw", "Ethernet0/1", "tdcs1", GE1(1))
        self.link("tdcs1", GE1(2), "tdcs2", GE1(2))
        # The second spine reaches its leaf through the internal segmentation
        # firewall, so that device is genuinely in a path rather than built,
        # cabled to nothing, and left holding its template's config.
        self.link("tdcs1", GE1(3), "tdcl1", GE0(1))
        self.rlink("tdcs2", GE1(3), "tdcfw2", "Ethernet0/0")
        self.link("tdcfw2", "Ethernet0/1", "tdcl2", GE0(1))
        self.link("tdcl1", GE0(2), "tdcl2", GE0(2))
        for i, (key, _n, _s, _d, _ip) in enumerate(self.servers):
            sw = "tdcl1" if i < 14 else "tdcl2"
            self.link(sw, FE0(1 + (i % 14)), key, "FastEthernet0")

        # ---- disaster-recovery site ---------------------------------- #
        self.rlink("bb2", GE1(18), "drcfw", "Ethernet0/0")
        self.link("drcfw", "Ethernet0/1", "drcs1", GE1(1))
        self.link("drcs1", GE1(2), "drcs2", GE0(1))
        for i, key in enumerate(self._dr_keys()):
            self.link("drcs2", FE0(1 + (i % 20)), key, "FastEthernet0")

        # ---- customs enclave ----------------------------------------- #
        self.rlink("bb2", GE1(6), "cusfw1", "Ethernet0/0")
        self.link("cusfw1", "Ethernet0/1", "cussw1", GE0(1))
        self.link("cusfw1", "Ethernet0/2", "cusfw2", "Ethernet0/0")
        self.link("cusfw2", "Ethernet0/1", "cussw2", GE0(1))
        dmz = [("cusids", "GigabitEthernet0"), ("custap", "Ethernet1"),
               ("c_nac1", "FastEthernet0"), ("c_nac2", "FastEthernet0"),
               ("c_app", "FastEthernet0"), ("c_ws1", "FastEthernet0"),
               ("c_ws2", "FastEthernet0")]
        for i, (key, port) in enumerate(dmz):
            self.link("cussw1", FE0(1 + i), key, port)
        for i, key in enumerate(("c_db1", "c_db2", "c_hsm", "c_audit")):
            self.link("cussw2", FE0(1 + i), key, "FastEthernet0")

        # ---- terminal operations centre ------------------------------ #
        self.rlink("bb1", GE1(7), "toc1", "GigabitEthernet0/0/0")
        self.rlink("bb2", GE1(7), "toc2", "GigabitEthernet0/0/0")
        self.link("toc1", "GigabitEthernet0/0/1", "tocd1", GE0(1))
        self.link("toc2", "GigabitEthernet0/0/1", "tocd2", GE0(1))
        self.link("tocd1", GE0(2), "tocd2", GE0(2))
        self.link("tocd1", FE0(1), "toca1", GE0(1))
        self.link("tocd2", FE0(1), "toca2", GE0(1))
        toc_end = [k for k in self.sid if k.startswith(("toc_", "tocw", "tocp"))]
        for i, key in enumerate(toc_end):
            sw = "toca1" if i < 12 else "toca2"
            model = self.meta[key]["model"]
            # A 7960 IP phone rejects FastEthernet0; its network port is "Switch"
            # (the "PC" port is the passthrough for a co-located workstation).
            port = "Switch" if model == "7960" else "FastEthernet0"
            self.link(sw, FE0(1 + (i % 12)), key, port)

        # ---- berths / STS cranes ------------------------------------- #
        for bi in range(self.p["berths"]):
            a, b = f"brt{bi + 1}a", f"brt{bi + 1}b"
            self.rlink("bb1", GE1(9 + bi), a, GE9320(1))
            self.rlink("bb2", GE1(9 + bi), b, GE9320(1))
            self.link(a, GE9320(2), b, GE9320(2))
            cranes = [x for x in self.cranes if x["berth"] == bi + 1]
            for j, c in enumerate(cranes):
                n = c["idx"]
                self.link(a, GE9320(3 + j), f"st{n}sw", GE1_1(1))
                self.link(b, GE9320(3 + j), f"st{n}sw", GE1_1(2))
                for k, (suffix, port) in enumerate([
                        ("plc", "GigabitEthernet0"), ("hmi", "GigabitEthernet0"),
                        ("rfid", "FastEthernet0"), ("mot", "FastEthernet0")]):
                    self.link(f"st{n}sw", GE1_1(3 + k), f"st{n}{suffix}", port)

        # ---- container yard ------------------------------------------ #
        self.link("bb1", GE1(13), "yrdagg1", GE9320(1))
        self.link("bb2", GE1(13), "yrdagg2", GE9320(1))
        self.link("yrdagg1", GE9320(28), "yrdagg2", GE9320(28))
        for y in self.yards:
            n = y["idx"]
            agg = "yrdagg1" if n <= 8 else "yrdagg2"
            self.link(agg, GE9320(2 + ((n - 1) % 8)), f"yb{n}sw", GE1_1(1))
            for j, (suffix, port) in enumerate([
                    ("plc", "GigabitEthernet0"), ("rfid", "FastEthernet0"),
                    ("temp", "FastEthernet0"), ("siren", "FastEthernet0")]):
                self.link(f"yb{n}sw", GE1_1(2 + j), f"yb{n}{suffix}", port)

        # ---- AGV fleet ------------------------------------------------ #
        self.rlink("bb1", GE1(8), "agvr1", "GigabitEthernet0/0/0")
        self.rlink("bb2", GE1(8), "agvr2", "GigabitEthernet0/0/0")
        self.link("agvr1", "GigabitEthernet0/0/1", "agvsw1", GE9320(1))
        self.link("agvr2", "GigabitEthernet0/0/1", "agvsw2", GE9320(1))
        self.link("agvsw1", GE9320(2), "agvsw2", GE9320(2))
        self.link("agvsw1", GE9320(3), "agv_disp", "FastEthernet0")
        self.link("agvsw2", GE9320(3), "agv_disp2", "FastEthernet0")
        # the vehicles themselves are wireless clients of the AGV-mesh APs

        # ---- gate complex --------------------------------------------- #
        self.rlink("bb1", GE1(14), "gater1", "GigabitEthernet0/0/0")
        self.rlink("bb2", GE1(14), "gater2", "GigabitEthernet0/0/0")
        self.link("gater1", "GigabitEthernet0/0/1", "gatesw1", GE9320(1))
        self.link("gater2", "GigabitEthernet0/0/1", "gatesw2", GE1_1(1))
        self.link("gatesw1", GE9320(2), "gatesw2", GE1_1(2))
        self.link("gatesw1", GE9320(3), "gateocr", "FastEthernet0")
        lane = [k for k in self.sid if k.startswith("gate") and k[-3:] in
                ("fid", "bar", "cam")]
        for i, key in enumerate(lane):
            model = self.meta[key]["model"]
            port = "GigabitEthernet0" if model == "PLC-PT" else "FastEthernet0"
            if i < 12:
                self.link("gatesw1", GE9320(4 + i), key, port)
            else:
                self.link("gatesw2", GE1_1(3 + (i - 12)), key, port)

        # ---- rail intermodal terminal ---------------------------------- #
        self.rlink("bb1", GE1(15), "railr1", "GigabitEthernet0/0/0")
        self.rlink("bb2", GE1(15), "railr2", "GigabitEthernet0/0/0")
        self.link("railr1", "GigabitEthernet0/0/1", "railsw1", GE9320(1))
        self.link("railr2", "GigabitEthernet0/0/1", "railsw2", GE1_1(1))
        self.link("railsw1", GE9320(2), "railsw2", GE1_1(2))
        self.link("railsw1", GE9320(3), "rail_sig", "FastEthernet0")
        self.link("railsw2", GE1_1(3), "rail_tos", "FastEthernet0")
        rail_end = [k for k in self.sid if k.startswith("rail") and k[-3:] in
                    ("plc", "hmi", "fid")]
        for i, key in enumerate(rail_end):
            model = self.meta[key]["model"]
            port = ("GigabitEthernet0" if model in ("PLC-PT", "HMI-PT")
                    else "FastEthernet0")
            if i < 5:
                self.link("railsw1", GE9320(4 + i), key, port)
            else:
                self.link("railsw2", GE1_1(4 + (i - 5)), key, port)

        # ---- CFS / warehouse ------------------------------------------- #
        self.link("bb1", GE1(19), "cfssw1", GE0(1))
        self.link("cfssw1", GE0(2), "cfssw2", GE0(1))
        cfs_end = [k for k in self.sid
                   if k.startswith("cfs")
                   and self.meta[k]["model"] not in ("AccessPoint-PT-N", "2960-24TT")]
        for i, key in enumerate(cfs_end):
            sw = "cfssw1" if i < 8 else "cfssw2"
            self.link(sw, FE0(1 + (i % 8)), key, "FastEthernet0")
        for i in range(2):
            k = f"cfsap{i + 1}"
            if k in self.sid:
                self.link("cfssw2", FE0(10 + i), k, "Port 0")

        # ---- reefer / dangerous goods ---------------------------------- #
        self.link("bb1", GE1(16), "rfsw1", GE1_1(1))
        self.link("bb2", GE1(16), "rfsw2", GE1_1(1))
        for i in range(max(4, self.p["yard"] // 2)):
            self.link("rfsw1", GE1_1(2 + i), f"rf{i + 1}", "FastEthernet0")
        for i in range(4):
            self.link("rfsw2", GE1_1(2 + i), f"dg{i + 1}", "FastEthernet0")

        # ---- wireless infrastructure ------------------------------------ #
        # A 3560-24PS has exactly two GigabitEthernet0/x uplinks (0/1 and 0/2),
        # so the two controllers hang off different switches: wlc1 on the
        # distribution switch's second uplink, wlc2 on the access switch's.
        #
        # A WLC-3504 rejects every GigabitEthernet0/x name; its network port is
        # GigabitEthernet1 (verified against Packet Tracer -- see
        # tools/port_table.py).
        self.link("bb1", GE1(17), "wlsw1", GE0(1))
        self.link("wlsw1", GE0(2), "wlc1", "GigabitEthernet1")
        self.link("wlsw2", GE0(1), "wlsw1", FE0(1))
        self.link("wlsw2", GE0(2), "wlc2", "GigabitEthernet1")
        for i in range(self.p["aps"]):
            key = f"ap{i + 1}"
            if i < 10:
                self.link("wlsw1", FE0(2 + i), key, "Port 0")
            else:
                self.link("wlsw2", FE0(2 + (i - 10)), key, "Port 0")

        # ---- physical security ------------------------------------------ #
        self.link("bb1", GE1(20), "secsw1", GE0(1))
        self.link("secsw1", GE0(2), "secsw2", GE0(1))
        sec_end = [k for k in self.sid
                   if k.startswith(("sec_", "cam", "acs", "perim"))]
        for i, key in enumerate(sec_end):
            sw = "secsw1" if i < 8 else "secsw2"
            self.link(sw, FE0(1 + (i % 8)), key, "FastEthernet0")

        # ---- OT / power -------------------------------------------------- #
        self.link("bb2", GE1(17), "otsw1", GE1_1(1))
        self.link("otsw1", GE1_1(2), "otsw2", "GigabitEthernet1/1")
        ot_on_a = ["ot_plc1", "ot_plc2", "ot_ctrl", "ot_pm1"]
        ot_on_b = ["ot_pm2", "ot_pm3", "ot_pm4", "ot_env1", "ot_env2"]
        for i, key in enumerate(ot_on_a):
            if key not in self.sid:
                continue
            model = self.meta[key]["model"]
            port = ("GigabitEthernet0" if model == "NetworkController"
                    else "GigabitEthernet0" if model == "PLC-PT" else "FastEthernet0")
            self.link("otsw1", GE1_1(3 + i), key, port)
        for i, key in enumerate(ot_on_b):
            if key not in self.sid:
                continue
            self.link("otsw2", f"FastEthernet1/{1 + i}", key, "FastEthernet0")

        # ---- NOC --------------------------------------------------------- #
        self.rlink("mgw", "GigabitEthernet0/0/1", "nocsw1", GE0(1))
        for i, (key, port) in enumerate([
                ("noc_jump", "FastEthernet0"), ("noc_cobs", "GigabitEthernet0"),
                ("noc_tap", "Ethernet1"), ("nocsrv", "FastEthernet0")]):
            self.link("nocsw1", FE0(1 + i), key, port)

    def _dr_keys(self) -> list[str]:
        return [k for k in self.sid if k.startswith("d_")]

    # ================================================================== #
    # configuration
    # ================================================================== #
    def configure(self) -> None:
        self._cfg_backbone()
        self._cfg_edge()
        self._cfg_tdc()
        self._cfg_drc()
        self._cfg_customs()
        self._cfg_toc()
        self._cfg_berths()
        self._cfg_yard()
        self._cfg_agv()
        self._cfg_gates()
        self._cfg_rail()
        self._cfg_cfs()
        self._cfg_reefer()
        self._cfg_wireless()
        self._cfg_security()
        self._cfg_ot()
        self._cfg_noc()

    def _ros(self, site: int, vlans: list[int], hsrp: dict | None = None,
             trunk: str = "GigabitEthernet0/0/1") -> list[str]:
        svis = {v: (host(site, v, 1), M24) for v in vlans}
        return K.l3_switch_config(
            name="", role="", vlans=vlans, svis=svis, loopback=None,
            hsrp=hsrp, trunks=[trunk])

    def _zone_routers(self, keys: list[str], site: int, vlans: list[int],
                      area: int, role: str, vip: bool = True) -> None:
        """Dual zone routers: router-on-a-stick subinterfaces with HSRP.

        Subinterface addresses are allocated from the zone's /24s: the active
        router takes .1 (the HSRP virtual address) via the standby group, the
        standby takes .2.
        """
        for i, key in enumerate(keys):
            # The physical parent of a subinterface is administratively down by
            # default, and every subinterface inherits that: a router-on-a-stick
            # whose parent is never brought up carries nothing.
            ifaces = [("GigabitEthernet0/0/1", "", M24)]
            for v in vlans:
                sub = f"GigabitEthernet0/0/1.{v}"
                ip = host(site, v, 1 if i == 0 else 2)
                ifaces.append((sub, ip, M24))
            for p, ip, m in self.ifaces(key):
                ifaces.append((p, ip, m))
            extra = []
            ospf = [(net(site, v), "0.0.0.255", area) for v in vlans]
            ospf += [(f"{ip.split('.')[0]}.{ip.split('.')[1]}.{ip.split('.')[2]}.0",
                      "0.0.0.3", K.AREA_BACKBONE) for _p, ip, m in self.ifaces(key)
                     if m == M30]
            body = K.router_config(
                self.meta[key]["name"], f"{role} ({'active' if i == 0 else 'standby'})",
                ifaces, loopback=self.meta[key]["ip"], ospf=ospf, default_area=area,
                ospf_active=[p for p, _i, _m in self.ifaces(key)],
                qos=True, zone=role)
            # HSRP must be emitted per subinterface: rebuild with standby lines
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
                out[port] = default_vlan
                self.port_completions.append((self.meta[key]["name"], port,
                                              default_vlan))
        return trunks, out

    def _l2(self, key: str, role: str, vlans: list[int], uplinks: list[str],
            access: dict[str, int], mgmt_vlan: int = K.V_MGMT,
            stp_root: list[int] | None = None, default_vlan: int = K.V_OPS) -> None:
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

    def _l3_ports(self, key: str, uplinks: list[str]) -> tuple[list[str], dict[str, int]]:
        """Split this switch's cabled ports into trunks and access ports.

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
    def _cfg_backbone(self) -> None:
        vlans = [K.V_MGMT, K.V_SRV, K.V_OPS]
        for i, key in enumerate(["bb1", "bb2"]):
            svis = {K.V_MGMT: (host(S_CORE, K.V_MGMT, 11 + i), M24),
                    K.V_SRV: (host(S_CORE, K.V_SRV, 11 + i), M24)}
            hsrp = {K.V_MGMT: (10, host(S_CORE, K.V_MGMT, 1)),
                    K.V_SRV: (20, host(S_CORE, K.V_SRV, 1))}
            # Trunks and access ports are derived from the cabling: a routed
            # port written again as a trunk reverts to Layer 2 and its routed
            # neighbour never comes up.
            trunks, access = self._l3_ports(key, uplinks=[])
            body = K.l3_switch_config(
                self.meta[key]["name"],
                f"terminal collapsed core {'A' if i == 0 else 'B'} "
                f"(OSPF area 0 backbone, iBGP AS{K.YML_ASN})",
                vlans, svis, self.meta[key]["ip"],
                ospf=[(net(S_CORE, K.V_MGMT), "0.0.0.255", K.AREA_BACKBONE),
                      (net(S_CORE, K.V_SRV), "0.0.0.255", K.AREA_BACKBONE)]
                     + self.wans(key),
                default_area=K.AREA_BACKBONE,
                hsrp=hsrp if i == 0 else None,
                trunks=trunks,
                access_ports=access,
                routed_ports=[(p, ip, m) for (p, ip, m) in self.ifaces(key)],
                ospf_active=[p for p, _i, _m in self.ifaces(key)],
                zone="CORE")
            body = self._bgp_inject(body, self.meta[key]["ip"], i == 0)
            self.set_cfg(key, body)

        for i, key in enumerate(["cr1", "cr2"]):
            ospf = [(net(S_CORE, K.V_MGMT), "0.0.0.255", K.AREA_BACKBONE)] + self.wans(key)
            ospf += [("10.0.0.0", "0.255.255.255", K.AREA_BACKBONE)]
            body = K.router_config(
                self.meta[key]["name"],
                f"terminal core router {'A' if i == 0 else 'B'} "
                f"(OSPF ABR, iBGP AS{K.YML_ASN})",
                self.ifaces(key), loopback=self.meta[key]["ip"],
                ospf=ospf, default_area=K.AREA_BACKBONE,
                ospf_active=[p for p, _i, _m in self.ifaces(key)], zone="CORE")
            body = self._bgp_inject(body, self.meta[key]["ip"], False)
            self.set_cfg(key, body)

        for i, key in enumerate(["we1", "we2"]):
            body = K.router_config(
                self.meta[key]["name"],
                f"terminal WAN edge {'primary' if i == 0 else 'backup'} carrier",
                self.ifaces(key), loopback=self.meta[key]["ip"],
                ospf=self.wans(key), default_area=K.AREA_BACKBONE,
                ospf_active=[p for p, _i, _m in self.ifaces(key)],
                statics=[("0.0.0.0", "0.0.0.0", "10.0.0.1")],
                serial_clock={p: c for (_a, p, _b, _bp, _d, c) in self.serial_meta
                              if _a == key or _b == key},
                zone="CORE")
            self.set_cfg(key, body)

        body = K.router_config(
            "YML-DCI-RTR-01", "terminal data-centre interconnect (TDC <-> DR)",
            self.ifaces("dci1"), loopback=self.meta["dci1"]["ip"],
            ospf=self.wans("dci1") + [(net(S_DRC, K.V_SRV), "0.0.0.255", K.AREA_TDC)],
            default_area=K.AREA_BACKBONE,
            ospf_active=[p for p, _i, _m in self.ifaces("dci1")], zone="CORE")
        self.set_cfg("dci1", body)

        self.set_cfg("mgw", K.router_config(
            "YML-MGMT-GW-01", "out-of-band management gateway / NOC edge",
            self.ifaces("mgw"), loopback=self.meta["mgw"]["ip"],
            ospf=self.wans("mgw") + [(net(S_NOC, K.V_MGMT), "0.0.0.255", K.AREA_NOC)],
            default_area=K.AREA_BACKBONE,
            ospf_active=[p for p, _i, _m in self.ifaces("mgw")], zone="NOC"))

    @staticmethod
    def _bgp_inject(cfg: list[str], router_id: str, full: bool) -> list[str]:
        out: list[str] = []
        for line in cfg:
            out.append(line)
        peers = [("10.255.0.13", "YML-CORE-RTR-01"), ("10.255.0.14", "YML-CORE-RTR-02")]
        block = [f"router bgp {K.YML_ASN}", f" bgp router-id {router_id}",
                 " bgp log-neighbor-changes", " no synchronization",
                 " bgp graceful-restart restart-time 120",
                 f" network {net(S_TDC, K.V_SRV)} mask {M24}",
                 f" network {net(S_TOC, K.V_OPS)} mask {M24}"]
        for ip, desc in peers:
            if ip == router_id:
                continue
            block += [f" neighbor {ip} remote-as {K.YML_ASN}",
                      f" neighbor {ip} description {desc} (iBGP)",
                      f" neighbor {ip} update-source Loopback0"]
        block.append("!")
        # insert before the QoS section so the file reads backbone-first
        anchor = next((i for i, l in enumerate(out) if l.startswith("class-map")), len(out))
        return out[:anchor] + block + out[anchor:]

    def _cfg_edge(self) -> None:
        for i, key in enumerate(["ce1", "ce2"]):
            ospf = self.wans(key) + [(net(S_EDGE, K.V_EDI), "0.0.0.255", K.AREA_EDGE)]
            body = K.router_config(
                self.meta[key]["name"],
                f"carrier edge router {'A' if i == 0 else 'B'} (eBGP AS{K.ISP_ASN})",
                self.ifaces(key), loopback=self.meta[key]["ip"],
                ospf=ospf, default_area=K.AREA_EDGE,
                ospf_active=[p for p, _i, _m in self.ifaces(key)],
                statics=[("0.0.0.0", "0.0.0.0", "10.0.0.1")], zone="EDGE")
            self.set_cfg(key, body)
        for i, (key, asn, desc) in enumerate([
            ("naccs", K.CUSTOMS_ASN, "Japan Customs NACCS (AS65102, IPsec)"),
            ("vts", 0, "Vessel Traffic Service / port authority"),
            ("railop", K.RAIL_ASN, "rail operator intermodal (AS65103)"),
            ("lineedi", K.LINE_ASN, "shipping-line EDI community (AS65104)"),
        ]):
            # The cable to the DMZ switch is a configuration too: without an
            # interface block this port stays administratively down.
            for port in self.cabled_ports(key):
                if port not in self.routed_ports(key):
                    self.routed.append((key, port,
                                        host(S_EDGE, K.V_EDI, 30 + i), M24))
            extra = []
            if asn:
                extra = ["!", f"router bgp {K.YML_ASN}",
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
        # The firewall's DMZ port is an access port in V_EDI, so the switch port
        # facing it must be access in the same VLAN -- not a trunk.
        self._l2("dmzsw", "partner DMZ access switch", [K.V_EDI, K.V_MGMT],
                 [], {GE0(1): K.V_EDI}, default_vlan=K.V_EDI)
        out_ip = self._asa_uplink("fwext", "Ethernet0/0", "10.99.0.1")
        self.set_cfg("fwext", K.asa_config(
            "FW-INTERNET-EDGE", "internet / partner DMZ edge firewall",
            zones=[dict(vlan=1, nameif="outside", sec=0, ip=out_ip, mask=M24,
                        ports=["Ethernet0/0"], dhcp=False),
                   # Eth0/1 faces the DMZ switch, whose hosts are in V_EDI; the
                   # two ends of one cable must be in the same VLAN.
                   dict(vlan=K.V_EDI, nameif="dmz", sec=50,
                        ip=gw(S_EDGE, K.V_EDI), mask=M24,
                        ports=["Ethernet0/1"], dhcp=False)],
            acls=K.customs_acl_lines()))

    def _cfg_tdc(self) -> None:
        s = S_TDC
        vlans = [K.V_SRV, K.V_MGMT, K.V_TOS]
        for i, key in enumerate(["tdcs1", "tdcs2"]):
            self.access_override[key] = {GE1(1): K.V_SRV}
            trunks, access = self._l3_ports(key, uplinks=[GE1(1)])
            svis = {K.V_SRV: (host(s, K.V_SRV, 11 + i), M24),
                    K.V_TOS: (host(s, K.V_TOS, 11 + i), M24)}
            hsrp = {K.V_SRV: (10, gw(s, K.V_SRV)), K.V_TOS: (20, gw(s, K.V_TOS))}
            self.set_cfg(key, K.l3_switch_config(
                self.meta[key]["name"], "TDC spine (VLAN 60 server gateway)",
                vlans, svis, self.meta[key]["ip"],
                ospf=[(net(s, K.V_SRV), "0.0.0.255", K.AREA_TDC),
                      (net(s, K.V_TOS), "0.0.0.255", K.AREA_TDC)] + self.wans(key),
                default_area=K.AREA_TDC, hsrp=hsrp if i == 0 else None,
                trunks=trunks, access_ports=access,
                routed_ports=[(p, ip, m) for (p, ip, m) in self.ifaces(key)],
                ospf_active=[p for p, _i, _m in self.ifaces(key)], zone="TDC"))
        self._l2("tdcl1", "TDC server leaf A", vlans, [GE0(1), GE0(2)],
                 {FE0(i): K.V_SRV for i in range(1, 15)})
        # leaf B's uplink faces the internal firewall's inside port, which is an
        # access port in V_SRV -- so this end is access in the same VLAN, and
        # GE0(2) stays the interswitch trunk to leaf A.
        self._l2("tdcl2", "TDC server leaf B", vlans, [GE0(2)],
                 {GE0(1): K.V_SRV, **{FE0(i): K.V_SRV for i in range(1, 15)}})
        for i, key in enumerate(["tdcfw", "tdcfw2"]):
            cabled = self.cabled_ports(key)
            if not cabled:
                continue                       # an uncabled firewall is not built
            out_port = "Ethernet0/0"
            in_port = "Ethernet0/1"
            zones = []
            if out_port in cabled:
                zones.append(dict(vlan=1, nameif="outside", sec=0,
                                  ip=self._asa_uplink(key, out_port, f"10.99.{i + 1}.1"),
                                  mask=M24, ports=[out_port], dhcp=False))
            if in_port in cabled:
                # faces the TDC spine, whose server segment is V_SRV
                zones.append(dict(vlan=K.V_SRV, nameif="inside", sec=100,
                                  ip=gw(S_TDC, K.V_SRV), mask=M24,
                                  ports=[in_port], dhcp=False))
            self.set_cfg(key, K.asa_config(
                self.meta[key]["name"],
                "TDC perimeter firewall" if i == 0
                else "TDC internal segmentation firewall",
                zones=zones, acls=K.customs_acl_lines()))

    def _cfg_drc(self) -> None:
        s = S_DRC
        self.access_override["drcs1"] = {GE1(1): K.V_SRV}
        trunks, access = self._l3_ports("drcs1", uplinks=[GE1(1)])
        self.set_cfg("drcs1", K.l3_switch_config(
            "DRC-SPINE-01", "DR site spine / standby TOS gateway",
            [K.V_SRV, K.V_MGMT], {K.V_SRV: (host(s, K.V_SRV, 11), M24)},
            self.meta["drcs1"]["ip"],
            ospf=[(net(s, K.V_SRV), "0.0.0.255", K.AREA_TDC)] + self.wans("drcs1"),
            default_area=K.AREA_TDC, trunks=trunks, access_ports=access,
            routed_ports=[(p, ip, m) for (p, ip, m) in self.ifaces("drcs1")],
            ospf_active=[p for p, _i, _m in self.ifaces("drcs1")], zone="DRC"))
        self._l2("drcs2", "DR site server access", [K.V_SRV, K.V_MGMT], [GE0(1)],
                 {FE0(i): K.V_SRV for i in range(1, 9)})
        self.set_cfg("drcfw", K.asa_config(
            "FW-DRC-PERIMETER", "DR site perimeter firewall",
            zones=[dict(vlan=1, nameif="outside", sec=0,
                        ip=self._asa_uplink("drcfw", "Ethernet0/0", "10.99.4.1"),
                        mask=M24, ports=["Ethernet0/0"], dhcp=False),
                   dict(vlan=K.V_SRV, nameif="inside", sec=100,
                        ip=gw(S_DRC, K.V_SRV), mask=M24,
                        ports=["Ethernet0/1"], dhcp=False)],
            acls=K.customs_acl_lines()))

    def _cfg_customs(self) -> None:
        cn = CUSTOMS_NET
        for i, key in enumerate(["cusfw1", "cusfw2"]):
            cabled = self.cabled_ports(key)
            zones = []
            if "Ethernet0/0" in cabled:
                zones.append(dict(
                    vlan=1, nameif="outside" if i == 0 else "dmz",
                    sec=0 if i == 0 else 50,
                    ip=self._asa_uplink(key, "Ethernet0/0", f"{cn}.255.{1 + i}"),
                    mask=M24, ports=["Ethernet0/0"], dhcp=False))
            if "Ethernet0/1" in cabled:
                # faces cussw1 (DMZ) / cussw2 (protected), both in V_CUS
                zones.append(dict(
                    vlan=K.V_CUS, nameif="dmz" if i == 0 else "inside",
                    sec=50 if i == 0 else 100,
                    ip=gw(CUSTOMS_SITE, K.V_CUS) if i == 1 else f"{cn}.10.254",
                    mask=M24, ports=["Ethernet0/1"], dhcp=False))
            if "Ethernet0/2" in cabled:
                zones.append(dict(vlan=K.V_CUS + 1, nameif="dbzone", sec=75,
                                  ip=f"{cn}.255.5", mask=M24,
                                  ports=["Ethernet0/2"], dhcp=False))
            if zones:
                self.set_cfg(key, K.asa_config(
                    self.meta[key]["name"],
                    "customs enclave outer firewall" if i == 0
                    else "customs enclave inner firewall (manifest DB protection)",
                    zones=zones, acls=K.customs_acl_lines()))
        self._l2("cussw1", "customs DMZ switch (NACCS brokers)",
                 [K.V_CUS, K.V_MGMT], [], {GE0(1): K.V_CUS},
                 default_vlan=K.V_CUS)
        self._l2("cussw2", "customs protected switch (manifest database)",
                 [K.V_CUS, K.V_MGMT], [], {GE0(1): K.V_CUS},
                 default_vlan=K.V_CUS)

    def _cfg_toc(self) -> None:
        s = S_TOC
        self._zone_routers(["toc1", "toc2"], s,
                           [K.V_OPS, K.V_VOICE, K.V_MGMT, K.V_WIFI],
                           K.AREA_OPS, "TOC zone router")
        self._l2("tocd1", "TOC distribution A", [K.V_OPS, K.V_VOICE, K.V_MGMT],
                 [GE0(1), GE0(2), FE0(1)], {FE0(2): K.V_OPS},
                 stp_root=[K.V_OPS])
        self._l2("tocd2", "TOC distribution B", [K.V_OPS, K.V_VOICE, K.V_MGMT],
                 [GE0(1), GE0(2), FE0(1)], {FE0(2): K.V_OPS})
        self._l2("toca1", "TOC operations floor A",
                 [K.V_OPS, K.V_VOICE, K.V_MGMT], [GE0(1)],
                 {FE0(i): (K.V_OPS if i <= 8 else K.V_VOICE) for i in range(1, 13)})
        self._l2("toca2", "TOC operations floor B",
                 [K.V_OPS, K.V_VOICE, K.V_MGMT], [GE0(1)],
                 {FE0(i): K.V_OPS for i in range(1, 9)})

    def _cfg_berths(self) -> None:
        for bi in range(self.p["berths"]):
            site = S_BERTH0 + bi
            vlans = [K.V_OT, K.V_IOT, K.V_CCTV, K.V_MGMT]
            for j, suffix in enumerate(("a", "b")):
                key = f"brt{bi + 1}{suffix}"
                trunks, access = self._l3_ports(key, uplinks=[])
                svis = {v: (host(site, v, 2 + j), M24) for v in vlans}
                hsrp = {v: (100 + v, gw(site, v)) for v in vlans}
                self.set_cfg(key, K.l3_switch_config(
                    self.meta[key]["name"],
                    f"berth {bi + 1} industrial aggregation "
                    f"{'A' if j == 0 else 'B'} (STS crane OT segment)",
                    vlans, svis, self.meta[key]["ip"],
                    ospf=[(net(site, v), "0.0.0.255", K.AREA_APRON) for v in vlans]
                         + self.wans(key),
                    default_area=K.AREA_APRON,
                    hsrp=hsrp if j == 0 else None,
                    trunks=trunks, access_ports=access,
                    routed_ports=[(p, ip, m) for (p, ip, m) in self.ifaces(key)],
                    ospf_active=[p for p, _i, _m in self.ifaces(key)],
                    zone=f"BERTH{bi + 1}"))
            for c in [x for x in self.cranes if x["berth"] == bi + 1]:
                n = c["idx"]
                self._ind(f"st{n}sw", f"STS{n:02d} crane control cabinet",
                          [K.V_OT, K.V_IOT, K.V_MGMT],
                          [GE1_1(1), GE1_1(2)],
                          {GE1_1(3): K.V_OT, GE1_1(4): K.V_OT,
                           GE1_1(5): K.V_IOT, GE1_1(6): K.V_IOT})

    def _cfg_yard(self) -> None:
        vlans = [K.V_OT, K.V_IOT, K.V_REEFER, K.V_MGMT]
        # Block-facing ports are switch-to-switch links carrying OT, IoT, reefer
        # and management VLANs: they are trunks.  Declaring them access left one
        # end a trunk and the other an access port, which never forwards.
        self._ind("yrdagg1", "yard aggregation A (blocks A-D)", vlans,
                  [GE9320(1), GE9320(28)], {}, default_vlan=K.V_OT)
        self._ind("yrdagg2", "yard aggregation B (blocks E-H)", vlans,
                  [GE9320(1), GE9320(28)], {}, default_vlan=K.V_OT)
        for y in self.yards:
            n = y["idx"]
            self._ind(f"yb{n}sw",
                      f"yard block {y['block']} industrial switch ({y['kind']})",
                      vlans, [GE1_1(1)],
                      {GE1_1(2): K.V_OT, GE1_1(3): K.V_IOT,
                       GE1_1(4): K.V_REEFER, GE1_1(5): K.V_IOT})

    def _cfg_agv(self) -> None:
        s = S_AGV
        self._zone_routers(["agvr1", "agvr2"], s,
                           [K.V_AGV, K.V_SRV, K.V_MGMT], K.AREA_AGV, "AGV zone router")
        self._ind("agvsw1", "AGV control room switch A",
                  [K.V_AGV, K.V_SRV, K.V_MGMT], [GE9320(1), GE9320(2)],
                  {GE9320(3): K.V_SRV})
        self._ind("agvsw2", "AGV control room switch B",
                  [K.V_AGV, K.V_SRV, K.V_MGMT], [GE9320(1), GE9320(2)],
                  {GE9320(3): K.V_SRV})

    def _cfg_gates(self) -> None:
        s = S_GATE
        self._zone_routers(["gater1", "gater2"], s,
                           [K.V_OT, K.V_IOT, K.V_SRV, K.V_MGMT], K.AREA_GATE,
                           "gate complex router")
        self._ind("gatesw1", "gate lane switch A (inbound + OCR)",
                  [K.V_OT, K.V_IOT, K.V_SRV, K.V_MGMT],
                  [GE9320(1), GE9320(2)], {GE9320(3): K.V_SRV})
        self._ind("gatesw2", "gate lane switch B (outbound + hazmat)",
                  [K.V_OT, K.V_IOT, K.V_SRV, K.V_MGMT], [GE1_1(1), GE1_1(2)], {})

    def _cfg_rail(self) -> None:
        s = S_RAIL
        self._zone_routers(["railr1", "railr2"], s,
                           [K.V_OT, K.V_RAIL, K.V_MGMT], K.AREA_RAIL,
                           "rail terminal router")
        self._ind("railsw1", "rail terminal switch A (RMG cranes)",
                  [K.V_OT, K.V_RAIL, K.V_MGMT], [GE9320(1), GE9320(2)],
                  {GE9320(3): K.V_RAIL})
        self._ind("railsw2", "rail terminal switch B (signalling)",
                  [K.V_OT, K.V_RAIL, K.V_MGMT], [GE1_1(1), GE1_1(2)],
                  {GE9320(3): K.V_RAIL})

    def _cfg_cfs(self) -> None:
        vlans = [K.V_OPS, K.V_SRV, K.V_MGMT, K.V_WIFI, K.V_IOT]
        self._l2("cfssw1", "CFS / warehouse access A", vlans, [GE0(1), GE0(2)],
                 {FE1: K.V_OPS, FE2: K.V_OPS, FE3: K.V_OPS,
                  4: K.V_OPS} if False else
                 {FE0(i): K.V_OPS for i in range(1, 7)})
        self._l2("cfssw2", "CFS / warehouse access B", vlans, [GE0(1)],
                 {FE0(i): (K.V_SRV if i <= 2 else K.V_WIFI) for i in range(1, 11)})

    def _cfg_reefer(self) -> None:
        self._ind("rfsw1", "reefer yard industrial switch (cold chain)",
                  [K.V_REEFER, K.V_IOT, K.V_MGMT], [GE1_1(1)],
                  {GE1_1(2 + i): K.V_REEFER for i in range(max(4, self.p["yard"] // 2))})
        self._ind("rfsw2", "dangerous-goods yard switch (hazmat)",
                  [K.V_DG, K.V_IOT, K.V_MGMT], [GE1_1(1)],
                  {GE1_1(2 + i): K.V_DG for i in range(4)})

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
                "wlan create YML-AGV-MESH 1 YML-AGV-MESH",
                "wlan create YML-OPS-WLAN 2 YML-OPS-WLAN", "!",
                "wlan security wpa2 YML-AGV-MESH", "wlan security wpa2 YML-OPS-WLAN",
                "!",
                f"ntp server {K.NTP_PRIMARY}",
                "!", "end",
            ])
        self._l2("wlsw1", "WLAN distribution (PoE)", [K.V_MGMT, K.V_WIFI],
                 [GE0(1), FE0(1)], {GE0(2): K.V_MGMT, GE0(3): K.V_MGMT,
                                    **{FE0(i): K.V_MGMT for i in range(2, 11)}},
                 default_vlan=K.V_MGMT)
        self._l2("wlsw2", "WLAN outdoor AP access", [K.V_MGMT, K.V_WIFI],
                 [GE0(1)], {FE0(i): K.V_MGMT for i in range(1, 11)})

    def _cfg_security(self) -> None:
        vlans = [K.V_CCTV, K.V_IOT, K.V_MGMT]
        self._l2("secsw1", "physical security PoE switch A", vlans, [GE0(1), GE0(2)],
                 {FE0(i): K.V_CCTV for i in range(1, 9)})
        self._l2("secsw2", "physical security PoE switch B", vlans, [GE0(1)],
                 {FE0(i): (K.V_CCTV if i <= 4 else K.V_IOT) for i in range(1, 9)})

    def _cfg_ot(self) -> None:
        vlans = [K.V_OT, K.V_IOT, K.V_MGMT]
        self._ind("otsw1", "substation / utilities industrial switch", vlans,
                  [GE1_1(1), GE1_1(2)],
                  {GE1_1(3 + i): K.V_OT for i in range(4)})
        self._ind("otsw2", "shore power / reefer rack switch", vlans,
                  [GE1_1(1)], {GE1_1(3 + i): K.V_IOT for i in range(4)})

    def _cfg_noc(self) -> None:
        self._l2("nocsw1", "NOC management enclave",
                 [K.V_MGMT, K.V_SRV], [GE0(1)],
                 {FE0(i): K.V_MGMT for i in range(1, 5)})

    # ================================================================== #
    # services
    # ================================================================== #
    def services(self) -> None:
        pools: list[dict] = []
        # one pool per (zone, vlan) so every pool name is unique across sites
        zones = [(f"BERTH{bi + 1}", S_BERTH0 + bi) for bi in range(self.p["berths"])]
        zones += [(f"YARD{y['idx']:02d}", y["site"]) for y in self.yards]
        zones += [("TOC", S_TOC), ("AGV", S_AGV), ("GATE", S_GATE),
                  ("RAIL", S_RAIL), ("CFS", S_CFS), ("REEFER", S_REEFER),
                  ("WLAN", S_WLAN), ("SEC", S_SEC), ("OT", S_OT), ("TDC", S_TDC)]
        vlan_of_zone = {
            "TOC": [K.V_OPS, K.V_WIFI, K.V_VOICE],
            "AGV": [K.V_AGV],
            "GATE": [K.V_OT],
            "RAIL": [K.V_OT],
            "CFS": [K.V_OPS, K.V_WIFI],
            "REEFER": [K.V_REEFER, K.V_DG],
            "WLAN": [K.V_MGMT],
            "SEC": [K.V_CCTV, K.V_IOT],
            "OT": [K.V_OT],
            "TDC": [K.V_SRV],
        }
        for label, site in zones:
            vlans = (vlan_of_zone.get(label)
                     or [K.V_OT, K.V_IOT, K.V_REEFER])
            for v in vlans:
                pools.append(dict(
                    name=f"{label}-S{site}-V{v}",
                    network=net(site, v), mask=M24,
                    router=gw(site, v),
                    start=host(site, v, 100), end=host(site, v, 200),
                    dns=SRV["dns"], domain=TML_DOMAIN))
        seen = collections.Counter(p["name"] for p in pools)
        clashes = {n: c for n, c in seen.items() if c > 1}
        if clashes:
            raise SystemExit(
                "DHCP pool names collide (Packet Tracer pools are name-keyed, so "
                f"one would shadow the other): {clashes}. Qualify the zone label "
                "with its site number so it is unique.")

        clients = [(ip, K.AAA_KEY, desc) for ip, desc in [
            (SRV["tos"], "TOS application"), (SRV["wms"], "WMS"),
            (gw(S_TDC, K.V_SRV), "TDC SVI")]]
        for key, meta in self.meta.items():
            ip = meta.get("ip")
            if ip and meta["model"] in ("3650-24PS", "3560-24PS", "2960-24TT",
                                        "IE-3400", "IE-9320", "IE-2000",
                                        "ISR4331", "2911", "IR1101"):
                clients.append((ip, K.AAA_KEY, meta["name"]))

        # Packet Tracer keys DHCP pools and AAA clients by identity across the
        # whole document, so a second server holding the same records reads as
        # duplication rather than as replication (pkt_core.audit:
        # duplicate-dhcp-pool / duplicate-aaa-client are document-wide).  Each
        # service therefore has exactly one authoritative server here; the
        # standby node is present and addressed but holds no records.  DNS is
        # the exception the audit models explicitly: a zone is a set per server
        # and replicating it is legitimate, so both DNS servers serve the zone.
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
                kw["aaa_users"] = [("yml-admin", K.ENABLE_SECRET.split()[-1]),
                                   ("yml-ops", K.OPS_SECRET.split()[-1])]
            if svc == "tftp":
                kw["ftp_user"] = "yml-archive"
                kw["ftp_pass"] = "arch1ve-yml"
            if svc == "web":
                kw["http"] = True
                kw["http_user"] = "yml-portal"
                kw["http_pass"] = "p0rtal-yml"
                kw["https"] = True
            if svc == "mail":
                kw["email"] = True
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
        template can carry an address on a later port too -- every ``Siren``
        template ships an APIPA ``169.254.x.x`` on its second port -- and if
        those survive, several devices report the same address and the endpoint
        inventory is no longer distinct.
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
        """Strip RUNNINGCONFIG from devices that do not run IOS.

        A harvested ``Server-PT`` template carries the running-config of whatever
        lab it was saved from.  Leaving it in place means the artefact contains
        devices whose configuration belongs to a different network -- and a
        presence check ("has a config") would call them configured.
        """
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
        in place, 52 devices advertise themselves as NTP servers and 52 as HTTP
        servers, none of which anyone authored.  Clearing the block is the
        difference between "this device runs a service" and "this device's
        template came from a lab where something did".
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
                    help="override a profile knob, e.g. --set yard=4 --set agv=0")
    ap.add_argument("--out", type=Path, default=ROOT / "out" / "YOKOHAMA_AMLC.pkt")
    ap.add_argument("--report", type=Path, default=None)
    ap.add_argument("--inventory", type=Path, default=None)
    a = ap.parse_args(argv)
    rep_path = a.report or (ROOT / "build" / f"report_{a.profile}.json")
    inv_path = a.inventory or (ROOT / "docs" / f"INVENTORY_{a.profile}.csv")

    if a.set:
        # Overrides exist for bisection: a defect that only appears at a certain
        # size is found by building controlled sizes, not by guessing.
        over = dict(PROFILES[a.profile])
        for item in a.set:
            k, _, v = item.partition("=")
            over[k] = (v.lower() in ("1", "true", "yes")) if v.lower() in (
                "true", "false", "yes", "no") else int(v)
        PROFILES[a.profile] = over

    t = Terminal(a.profile)
    for step in (t.build_edge, t.build_backbone, t.build_tdc, t.build_drc,
                 t.build_customs, t.build_toc, t.build_berths, t.build_yard,
                 t.build_agv, t.build_gates, t.build_rail, t.build_cfs,
                 t.build_reefer, t.build_wireless, t.build_security,
                 t.build_ot, t.build_noc, t.build_clients):
        step()
    t.cable()
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
    rep.update(serial_ports_clocked=n_serial, static_ips_written=n_static,
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
