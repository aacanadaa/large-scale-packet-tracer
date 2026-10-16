#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Derive PT-attested port names for IoT / server / wireless models from
Packet Tracer's own device-template definitions.

Evidence tier: **ptd-template**.  ``ptd_templates.json`` is a dump of the
``<DEVICE>`` definitions Packet Tracer ships inside its AppImage (mined by the
JASDF package's ``tools/mine_corpus.py``).  Unlike the *lab* templates in
``tools/device_templates.json`` -- which are harvested from saved labs and only
carry interface lines for models that have a factory IOS config -- these cover
the IoE/MCU families (sensors, actuators, PLC/HMI, webcams) that carry none.

Port names are read from ``<PORT><NAME>`` when present, and otherwise from the
interface lines of the template's own ``RUNNINGCONFIG``/``STARTUPCONFIG``.

    python3 tools/mine_ptd_ports.py [--show MODEL ...]
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SRC = Path(os.environ.get("PTD_TEMPLATES",
                                  ROOT / "build" / "ptd_templates.json"))
IFACE_RE = re.compile(r"<LINE>\s*interface ([A-Za-z]+[0-9][0-9/.\s]*?)\s*</LINE>")

FAMILY_RANK = ["TenGigabitEthernet", "GigabitEthernet", "FastEthernet", "Ethernet",
               "Port", "Wireless", "Bluetooth"]


def family_of(name: str) -> str:
    for f in FAMILY_RANK:
        if name.startswith(f):
            return f
    return "other"


def ports_of(blob: str) -> list[str]:
    """Port names for one PT device-template document."""
    names: list[str] = []
    # 1. explicit <PORT><NAME> elements
    for m in re.finditer(r"<PORT>(.*?)</PORT>", blob, re.S):
        nm = re.search(r"<NAME>([^<]*)</NAME>", m.group(1))
        if nm and nm.group(1).strip():
            names.append(nm.group(1).strip())
    # 2. interface lines in the template's own config
    names += IFACE_RE.findall(blob)
    seen = set()
    out = []
    for n in names:
        n = n.strip()
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return sorted(out, key=lambda x: (FAMILY_RANK.index(family_of(x))
                                      if family_of(x) in FAMILY_RANK else 99, x))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--src", type=Path, default=DEFAULT_SRC)
    ap.add_argument("--out", type=Path, default=ROOT / "build" / "ptd_ports.json")
    ap.add_argument("--show", nargs="*", default=[])
    a = ap.parse_args(argv)

    if not a.src.exists():
        print(f"error: {a.src} not found (mined from the PT AppImage)", file=sys.stderr)
        return 2
    data = json.loads(a.src.read_text())
    inv = {m: {"ports": ports_of(blob)} for m, blob in data.items()}
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(inv, indent=1, sort_keys=True))

    withports = [m for m, v in inv.items() if v["ports"]]
    print(f"ptd templates: {len(inv)}   with port names: {len(withports)}")
    for m in (a.show or sorted(withports)):
        if m in inv:
            print(f"  {m:28s} {inv[m]['ports']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
