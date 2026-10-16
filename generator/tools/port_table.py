#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build ``build/port_table.json`` -- the one home for "what is this model's
port called".

Evidence tiers, strongest first
-------------------------------
``template``
    The model's harvested factory configuration lists ``interface <NAME>``
    lines (``tools/port_inventory.py``).  This is what Packet Tracer itself
    wrote, so a name from this tier is observed, not inferred.  29 models.

``attested``
    A ``<LINK><CABLE><PORT>`` string naming this model in a real saved lab.
    Taken from the toolkit's corpus mine; covers the end-system models whose
    factory config is empty (``Server-PT`` -> ``FastEthernet0``,
    ``AccessPoint-PT-N`` -> ``Port 0``, ``Sniffer`` -> ``Ethernet1``).

``convention``
    **Inference, not observation.**  The model has no factory config and no
    attested link, but its template declares its port inventory by *type*
    (``eCopperFastEthernet`` x1, ``eCopperGigabitEthernet`` x2, ...), and PT
    names a lone copper port of a family ``<Family>0``.  This tier is what the
    PT load/render verification exists to check -- ``validate.py`` reports the
    tier of every name it accepts, and the rendering gate is what promotes or
    falsifies it.

A model with no name in any tier is reported as unknown and must not be cabled.

    python3 tools/port_table.py
    python3 tools/port_table.py --check     # exit 1 if any used model is unknown
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from yokohama_paths import bootstrap as _bootstrap   # noqa: E402
TOOLKIT = _bootstrap()
for _p in (str(TOOLKIT), str(TOOLKIT / "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import lab_api  # noqa: E402

# tier 2 -- link strings observed in real saves (toolkit corpus mine +
# the JASDF package's own PT-attested monitoring-appliance names).
ATTESTED: dict[str, list[str]] = {
    "PC-PT":            ["FastEthernet0"],
    "Server-PT":        ["FastEthernet0"],
    "Laptop-PT":        ["FastEthernet0"],
    "AccessPoint-PT":   ["Port 0"],
    "AccessPoint-PT-N": ["Port 0"],
    "Sniffer":          ["Ethernet1", "Ethernet2"],
    "CyberObserver":    ["GigabitEthernet0", "GigabitEthernet1"],
    "WLC-3504":         ["GigabitEthernet0/1"],
    "WLC-2504":         ["GigabitEthernet0/2"],
    "Meraki-MX65W":     ["GigabitEthernet0", "Internet 1", "FastEthernet0"],
    "Cloud-PT":         ["GigabitEthernet0", "GigabitEthernet1", "GigabitEthernet2",
                         "Port 0", "Serial0/0/0", "Serial1/0", "Coaxial1"],
    "7960":             ["FastEthernet0", "FastEthernet0/1"],
    "AccessPoint-PT":   ["Port 0"],
}

# Ports a device gains from an installed module.  A WAN router's serial
# interfaces are not in its base factory config -- they exist because a HWIC-2T
# or NIM-2T sits in a bay -- so the base-inventory tier alone would call every
# serial bearer unattested.  Names are the corpus-attested ones for each module.
MODULE_PORTS: dict[str, list[str]] = {
    "2911":     ["Serial0/0/0", "Serial0/0/1", "Serial0/1/0", "Serial0/1/1",
                 "Serial0/2/0", "Serial0/2/1", "Serial0/3/0", "Serial0/3/1"],
    "ISR4331":  ["Serial0/1/0", "Serial0/1/1", "Serial0/2/0", "Serial0/2/1"],
    "ISR4321":  ["Serial0/1/0", "Serial0/1/1"],
    "1841":     ["Serial0/0/0", "Serial0/0/1", "Serial0/1/0", "Serial0/1/1"],
    "2811":     ["Serial0/0/0", "Serial0/0/1", "Serial0/1/0", "Serial0/1/1",
                 "Serial0/2/0", "Serial0/2/1", "Serial0/3/0", "Serial0/3/1"],
}

# tier 3 -- names verified against this Packet Tracer by
# tools/pt_accept.py + tools/pt_port_verify.py.  A model:port pair that PT
# *rejects* makes the whole file unopenable, so a name that has not been
# observed in a factory config or attested by a real save must be tested, and
# the result recorded here.
#
# Measured negatives, kept so nobody re-tries them:
#   7960      FastEthernet0, FastEthernet0/1        -> rejected
#   Cloud-PT  GigabitEthernet0/1/2, Ethernet0/1/2,
#             Serial0/0/0, Coaxial1                 -> rejected
#   WLC-3504  GigabitEthernet0/0 .. 0/5, 0/1/1     -> rejected
# Names measured as REJECTED by this Packet Tracer.  They appear in the corpus
# and in harvested factory configs, but cabling one makes the whole file
# unopenable, so they are removed from the table rather than merely annotated:
# a table that still permits them would pass a link the artefact cannot carry.
PT_REJECTED: dict[str, list[str]] = {
    "7960":     ["FastEthernet0", "FastEthernet0/1"],
    "Cloud-PT": ["GigabitEthernet0", "GigabitEthernet1", "GigabitEthernet2",
                 "Ethernet0", "Ethernet1", "Ethernet2", "Serial0/0/0",
                 "Coaxial1"],
    "WLC-3504": ["GigabitEthernet0/0", "GigabitEthernet0/1", "GigabitEthernet0/2",
                 "GigabitEthernet0/3", "GigabitEthernet0/4", "GigabitEthernet0/5",
                 "GigabitEthernet0/1/1"],
}

PT_VERIFIED: dict[str, list[str]] = {
    "7960":     ["Switch", "PC"],
    "Cloud-PT": ["Port 0"],
    "WLC-3504": ["GigabitEthernet1", "Port 0"],
}

# The port TYPES PT uses, and the family name it gives a cableable port.
COPPER_TYPES = {
    "eCopperFastEthernet": "FastEthernet",
    "eCopperGigabitEthernet": "GigabitEthernet",
    "eFiberGigabitEthernet": "GigabitEthernet",
    "eCopperEthernet": "Ethernet",
    "eCopperGigabitManagement": "GigabitEthernet",
}
WIRELESS_TYPES = {"eAccessPointWirelessN", "eAccessPointWirelessAC",
                  "eHostWirelessN", "eHostWirelessAC"}


def convention_names(types: list[str]) -> list[str]:
    """Names implied by the template's port inventory, by PT's own convention.

    ``Ethernet`` is 1-based (``Ethernet1``) because that is what the corpus
    attests for ``Sniffer``; the Fast/Gigabit families are 0-based because
    every attested end system uses ``...0``.  A multi-port industrial switch
    has a factory config, so it never reaches this function.
    """
    out: list[str] = []
    counts: collections.Counter = collections.Counter()
    for t in types:
        fam = COPPER_TYPES.get(t)
        if fam:
            counts[fam] += 1
    for fam, n in counts.items():
        base = 1 if fam == "Ethernet" else 0
        for i in range(n):
            out.append(f"{fam}{base + i}")
    return out


def build() -> dict:
    models, _modules = lab_api.load_templates(str(TOOLKIT / "tools" / "device_templates.json"))
    inv_path = ROOT / "build" / "port_inventory.json"
    inv = json.loads(inv_path.read_text()) if inv_path.exists() else {}

    table: dict[str, dict] = {}
    for model, ports in (inv or {}).items():
        if ports.get("all"):
            table[model] = {"ports": ports["all"], "tier": "template"}
    for model, ports in ATTESTED.items():
        if model in table:
            # template tier wins for names it covers; attestation adds the rest
            extra = [p for p in ports if p not in table[model]["ports"]]
            if extra:
                table[model]["ports"] += extra
                table[model]["tier"] = "template+attested"
            continue
        table[model] = {"ports": list(ports), "tier": "attested"}

    for model, bad in PT_REJECTED.items():
        if model in table:
            kept = [x for x in table[model]["ports"] if x not in bad]
            if len(kept) != len(table[model]["ports"]):
                table[model]["ports"] = kept
                table[model]["tier"] += "+pt-rejected-removed"

    for model, ports in PT_VERIFIED.items():
        if model in table:
            add = [x for x in ports if x not in table[model]["ports"]]
            if add:
                table[model]["ports"] += add
                table[model]["tier"] += "+pt-verified"
        else:
            table[model] = {"ports": list(ports), "tier": "pt-verified"}

    for model, extra in MODULE_PORTS.items():
        if model in table:
            add = [x for x in extra if x not in table[model]["ports"]]
            if add:
                table[model]["ports"] += add
                table[model]["tier"] += "+module"

    for model, blob in models.items():
        if model in table:
            continue
        import xml.etree.ElementTree as ET
        try:
            el = ET.fromstring(blob)
        except ET.ParseError:
            table[model] = {"ports": [], "tier": "unknown"}
            continue
        # Only the model's own cabled copper ports.  Element order inside
        # <PORT> is not fixed (an IoE device puts ACL/TIMEOUT children before
        # <TYPE>), so this parses rather than pattern-matches.
        types = [p.findtext("TYPE") for p in el.iter("PORT")]
        names = convention_names([t for t in types if t])
        if names:
            table[model] = {"ports": names, "tier": "convention"}
        elif any(t in WIRELESS_TYPES for t in types if t):
            table[model] = {"ports": [], "tier": "wireless-only"}
        else:
            table[model] = {"ports": [], "tier": "unknown"}
    return table


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=ROOT / "build" / "port_table.json")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--show", nargs="*", default=None)
    a = ap.parse_args(argv)
    table = build()
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(table, indent=1, sort_keys=True))

    tiers = collections.Counter(v["tier"] for v in table.values())
    print("port table:", dict(tiers))
    for m in (a.show or []):
        v = table.get(m)
        print(f"  {m:26s} {v['tier'] if v else 'ABSENT':18s} {v['ports'] if v else ''}")
    if a.check:
        usable = [m for m, v in table.items() if v["ports"]]
        unknown = [m for m, v in table.items() if not v["ports"]]
        print(f"  cableable models: {len(usable)}   without a cabled port: {len(unknown)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
