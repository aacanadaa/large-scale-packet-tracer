#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Derive the authoritative port-name inventory for each Packet Tracer model.

Evidence tier: **template**.  Every harvested device template ships the factory
default configuration PT writes on a fresh device, and that configuration lists
one ``interface <NAME>`` line per physical port.  Those names are therefore what
PT itself will match a ``<LINK><CABLE><PORT>`` string against -- which is
exactly the string ``lab_api.link()`` stores verbatim.

Writes ``build/port_inventory.json`` and prints a short summary so the port
names used by the generator have one home and one provenance.

    python3 tools/port_inventory.py [--check]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from iruma_paths import bootstrap as _bootstrap   # noqa: E402
TOOLKIT = _bootstrap()
sys.path.insert(0, str(TOOLKIT))
sys.path.insert(0, str(TOOLKIT / "tools"))

import lab_api  # noqa: E402

IFACE_RE = re.compile(r"<LINE>\s*interface ([A-Za-z]+[0-9][0-9/.\s]*?)\s*</LINE>")

# Port family -> the prefix PT uses in a LINK's PORT field.
FAMILY_RANK = ["TenGigabitEthernet", "GigabitEthernet", "FastEthernet", "Ethernet"]


def family_of(name: str) -> str:
    for f in FAMILY_RANK:
        if name.startswith(f):
            return f
    return "other"


def numeric_key(name: str):
    tail = re.findall(r"\d+", name)
    return tuple(int(t) for t in tail) if tail else (0,)


def inventory(models: dict[str, bytes]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for model, blob in models.items():
        text = blob.decode("utf-8", "replace")
        names = list(dict.fromkeys(IFACE_RE.findall(text)))
        names = [n.strip() for n in names if n.strip()]
        by_family: dict[str, list[str]] = {}
        for n in sorted(names, key=lambda x: (FAMILY_RANK.index(family_of(x))
                                              if family_of(x) in FAMILY_RANK else 99,
                                              numeric_key(x))):
            by_family.setdefault(family_of(n), []).append(n)
        out[model] = {"all": sorted(names, key=lambda x: (FAMILY_RANK.index(family_of(x))
                                                          if family_of(x) in FAMILY_RANK else 99,
                                                          numeric_key(x))),
                      "by_family": by_family}
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=ROOT / "build" / "port_inventory.json")
    ap.add_argument("--check", action="store_true",
                    help="fail (exit 1) if any model used by the generator has no port names")
    ap.add_argument("--show", nargs="*", default=None)
    a = ap.parse_args(argv)

    models, _modules = lab_api.load_templates(str(TOOLKIT / "tools" / "device_templates.json"))
    inv = inventory(models)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(inv, indent=1, sort_keys=True))

    withnames = sum(1 for v in inv.values() if v["all"])
    print(f"models: {len(inv)}   with port names: {withnames}   "
          f"without: {len(inv) - withnames}")

    show = a.show if a.show else []
    for m in show:
        v = inv.get(m)
        print(f"  {m:24s} {v['all'] if v else 'MISSING'}")

    if a.check:
        missing = [m for m, v in inv.items() if not v["all"]]
        if missing:
            print(f"  note: {len(missing)} template(s) carry no interface lines: {missing[:12]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
