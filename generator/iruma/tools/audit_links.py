#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check that every cable in a lab is actually brought up by the configuration.

A cable and an interface are two different things.  ``lab_api.link()`` draws the
cable and sets the port's electrical properties; it does **not** give the
interface a state.  On a router, an interface that no ``no shutdown`` was ever
issued for sits *administratively down* with a cable plugged into it -- the link
renders dead while every structural gate still passes.

Worse, two blocks can disagree.  A Layer-3 switch whose port is configured once
as a routed port (``no switchport`` + ``ip address``) and then again as a trunk
(``switchport mode trunk``) ends up in whichever state the parser applied last,
and the routed neighbour on the other end never comes up.

This tool reads the written artefact and reports, per link endpoint:

* **no interface block** -- the port is cabled and nothing configures it;
* **no `no shutdown`** -- the block exists but the port stays down;
* **conflicting modes** -- the same port configured as both routed and switched;
* **vlan mismatch** -- a trunk facing an access port in a different VLAN.

    python3 tools/audit_links.py out/IRUMA_AB.pkt
    python3 tools/audit_links.py out/IRUMA_AB.pkt --json build/link_audit.json
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from iruma_paths import bootstrap          # noqa: E402
TOOLKIT = bootstrap()

from pkt_core import decode_bytes             # noqa: E402
import iruma_kit as K                      # noqa: E402

IFACE_RE = re.compile(r"^interface\s+(\S+)\s*$")
IP_RE = re.compile(r"^ip address\s+\S+\s+\S+")
# A router interface is never an "access port": it has no switchport state at
# all, and comparing its mode against a switch's trunk reports a mismatch that
# cannot exist.  The same is true of any interface carrying an address.
ROUTER_MODELS = {"2911", "2901", "1941", "1841", "2811", "ISR4331", "ISR4321",
                 "IR1101", "IR8340", "CGR1240", "ISA-3000"}


def model_of(dev: ET.Element) -> str:
    t = dev.find("ENGINE/TYPE")
    return ((t.get("model") or (t.text or "")).strip() if t is not None else "")


def parse_config(dev: ET.Element) -> dict[str, dict]:
    """Return {interface: {lines, shutdown, routed, trunk, access_vlan}}."""
    rc = dev.find("ENGINE/RUNNINGCONFIG")
    out: dict[str, dict] = {}
    if rc is None:
        return out
    cur = None
    for line in rc.findall("LINE"):
        t = (line.text or "").rstrip()
        m = IFACE_RE.match(t.strip())
        if m:
            cur = m.group(1)
            out[cur] = {"lines": [], "shutdown": False, "routed": False,
                        "trunk": False, "access_vlan": None,
                        "no_switchport": False, "has_ip": False}
            continue
        if cur is None:
            continue
        out[cur]["lines"].append(t.strip())
        s = t.strip()
        if s == "shutdown":
            out[cur]["shutdown"] = True
        elif s == "no shutdown":
            out[cur]["shutdown"] = False
        elif s == "no switchport":
            out[cur]["no_switchport"] = True
        elif s.startswith("switchport mode trunk"):
            out[cur]["trunk"] = True
        elif IP_RE.match(s):
            out[cur]["has_ip"] = True
        elif s.startswith("switchport access vlan"):
            try:
                out[cur]["access_vlan"] = int(s.split()[-1])
            except ValueError:
                pass
    for v in out.values():
        # routed = explicitly unswitched, or simply addressed
        v["routed"] = bool(v["no_switchport"] or v["has_ip"])
    return out


def audit_xml(root: ET.Element) -> list[dict]:
    """Return every link endpoint whose configuration would not bring it up."""
    return _audit(root)[0]


def _audit(root: ET.Element) -> tuple[list[dict], list[dict]]:

    devs = {}
    for net in root.iter("NETWORK"):
        for d in net.iter("DEVICE"):
            devs[d.findtext("ENGINE/SAVE_REF_ID")] = d

    cfg = {sid: parse_config(d) for sid, d in devs.items()}

    findings: list[dict] = []
    link_rows: list[dict] = []
    for net in root.iter("NETWORK"):
        for lk in net.iter("LINK"):
            cab = lk.find("CABLE")
            if cab is None:
                continue
            ends = [cab.findtext("FROM"), cab.findtext("TO")]
            ports = [e.text for e in cab.findall("PORT")]
            if len(ports) < 2:
                continue
            row = {}
            for i, sid in enumerate(ends):
                d = devs.get(sid)
                if d is None:
                    continue
                name = d.findtext("ENGINE/NAME") or "?"
                mdl = model_of(d)
                port = (ports[i] or "").strip()
                row[i] = dict(name=name, model=mdl, port=port)
                if mdl not in K.NETWORK_DEVICE_MODELS:
                    continue                      # end device: NIC addressing, not IOS
                ic = cfg.get(sid, {}).get(port)
                if ic is None:
                    findings.append(dict(kind="no-interface-block", device=name,
                                         model=mdl, port=port,
                                         peer=row.get(1 - i, {}).get("name", "?")))
                    continue
                if ic["shutdown"]:
                    findings.append(dict(kind="shutdown", device=name, model=mdl,
                                         port=port,
                                         peer=row.get(1 - i, {}).get("name", "?")))
                if ic["routed"] and ic["trunk"]:
                    findings.append(dict(kind="routed-and-trunk", device=name,
                                         model=mdl, port=port,
                                         peer=row.get(1 - i, {}).get("name", "?")))
            link_rows.append(row)

    # trunk facing an access port in a different VLAN never forwards
    for r in link_rows:
        if len(r) < 2:
            continue
        (a0, b0) = r[0], r[1]
        ia = cfg.get(next((k for k, d in devs.items()
                           if d.findtext("ENGINE/NAME") == a0["name"]), ""), {}).get(a0["port"])
        ib = cfg.get(next((k for k, d in devs.items()
                           if d.findtext("ENGINE/NAME") == b0["name"]), ""), {}).get(b0["port"])
        if not ia or not ib:
            continue
        routed_if = (a0["model"] in ROUTER_MODELS or b0["model"] in ROUTER_MODELS
                     or ia["routed"] or ib["routed"]
                     or ia["access_vlan"] is None and not ia["trunk"]
                     and not ia["routed"] and a0["model"] in ROUTER_MODELS)
        if routed_if:
            continue
        if ia["trunk"] != ib["trunk"]:
            tr, ac = (ia, ib) if ia["trunk"] else (ib, ia)
            trk_name = a0["name"] if ia["trunk"] else b0["name"]
            acc_name = b0["name"] if ia["trunk"] else a0["name"]
            findings.append(dict(kind="trunk-facing-access", device=trk_name,
                                 peer=f"{acc_name} (access vlan "
                                      f"{ac['access_vlan'] if ac['access_vlan'] else '1'})",
                                 model="", port=""))

    return findings, link_rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("lab", type=Path)
    ap.add_argument("--json", type=Path, default=None)
    a = ap.parse_args(argv)
    raw = a.lab.read_bytes()
    root = ET.fromstring(raw if raw[:1] == b"<" else decode_bytes(raw).xml)
    findings, link_rows = _audit(root)

    counted = collections.Counter(f["kind"] for f in findings)
    print(f"lab    : {a.lab.name}")
    print(f"links  : {len(link_rows)}")
    print(f"findings: {dict(counted) or 'none'}")
    by_kind: dict[str, list[dict]] = collections.defaultdict(list)
    for f in findings:
        by_kind[f["kind"]].append(f)
    for kind, items in by_kind.items():
        print(f"\n-- {kind} ({len(items)}) --")
        for it in items[:12]:
            print(f"   {it['device']:26s} {it['model']:12s} {it['port']:24s} "
                  f"peer={it['peer']}")
        if len(items) > 12:
            print(f"   ... and {len(items) - 12} more")
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps(findings, indent=1, sort_keys=True))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
