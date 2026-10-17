#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Render an architecture diagram of the built Iruma Air Base lab as SVG.

The diagram is derived from the artefact (devices, tiers and links), not from
the generator's design intent, so it cannot flatter the model: a device that was
never cabled shows as an isolated node and a tier that was dropped shows as a
missing band.

Layout is a deterministic grid: devices are grouped into their layout tier, and
each tier is one horizontal band.  That is the same grouping the .pkt itself
uses, so the diagram and the workspace agree.

    python3 tools/draw_topology.py out/IRUMA_AB.pkt docs/img/topology.svg
"""
from __future__ import annotations

import argparse
import collections
import html
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from iruma_paths import bootstrap as _bootstrap   # noqa: E402
TOOLKIT = _bootstrap()
for _p in (str(ROOT), str(TOOLKIT), str(TOOLKIT / "tools"), str(TOOLKIT / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from pkt_core import decode_bytes      # noqa: E402
import iruma_kit as K               # noqa: E402

# tier -> (colour, display name)  order fixed so the picture is stable
from iruma_tiers import TIERS, tier_of  # noqa: E402

KIND_SHAPE = {
    "router": ("rect", 26, 14),
    "multilayer-switch": ("rect", 26, 14),
    "switch": ("rect", 24, 13),
    "firewall": ("diamond", 26, 16),
    "server": ("rect", 20, 22),
    "pc": ("rect", 20, 20),
    "laptop": ("rect", 20, 18),
    "access-point": ("circle", 22, 22),
    "sniffer": ("circle", 20, 20),
    "pdd": ("rect", 22, 22),
    "iot": ("circle", 18, 18),
    "default": ("rect", 24, 16),
}


def model_of(dev):
    t = dev.find("ENGINE/TYPE")
    return ((t.get("model") or (t.text or "")).strip() if t is not None else "")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("lab", type=Path)
    ap.add_argument("out", type=Path)
    a = ap.parse_args(argv)
    raw = a.lab.read_bytes()
    root = ET.fromstring(raw if raw[:1] == b"<" else decode_bytes(raw).xml)

    devices = {}
    for d in root.iter("DEVICE"):
        nm = d.findtext("ENGINE/NAME")
        if nm:
            devices[nm] = model_of(d)
    sid_name = {d.findtext("ENGINE/SAVE_REF_ID"): d.findtext("ENGINE/NAME")
                for d in root.iter("DEVICE")}
    edges = []
    for lk in root.iter("LINK"):
        cab = lk.find("CABLE")
        if cab is None:
            continue
        x, y = sid_name.get(cab.findtext("FROM")), sid_name.get(cab.findtext("TO"))
        if x and y:
            edges.append((x, y))

    bands = collections.OrderedDict((t, []) for t, _c, _n in TIERS)
    for nm in sorted(devices):
        bands.setdefault(tier_of(nm), []).append(nm)

    # geometry
    PAD, ROW, COLW, NODE = 40, 150, 210, 30
    width = max(1400, PAD * 2 + COLW * 14 + 260)
    pos, y = {}, PAD + 40
    band_meta = []
    for tier, colour, label in TIERS:
        members = bands.get(tier) or []
        if not members:
            continue
        per_row = max(1, (width - PAD * 2) // COLW)
        rows = (len(members) + per_row - 1) // per_row
        band_meta.append((tier, colour, label, y, rows, len(members)))
        for i, nm in enumerate(members):
            cx = PAD + NODE + (i % per_row) * COLW
            cy = y + 30 + (i // per_row) * 46
            pos[nm] = (cx, cy)
        y += 30 + rows * 46 + 60
    height = y + PAD

    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
           f'viewBox="0 0 {width} {height}" font-family="Helvetica,Arial,sans-serif">',
           f'<rect width="{width}" height="{height}" fill="#fbfbfd"/>']
    for tier, colour, label, by, rows, n in band_meta:
        out.append(f'<rect x="{PAD//2}" y="{by}" width="{width-PAD}" '
                   f'height="{30+rows*46+30}" rx="8" fill="{colour}" opacity="0.06"/>')
        out.append(f'<text x="{PAD//2+12}" y="{by+20}" font-size="15" font-weight="bold" '
                   f'fill="{colour}">{html.escape(label)} '
                   f'<tspan font-weight="normal" fill="#666">({n} devices)</tspan></text>')
    for x, y2 in edges:
        if x in pos and y2 in pos:
            (x1, y1), (x2, y2_) = pos[x], pos[y2]
            out.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2_}" '
                       f'stroke="#9aa4b0" stroke-width="0.7" opacity="0.75"/>')
    for nm, (cx, cy) in pos.items():
        colour = next(c for t, c, _l in TIERS if t == tier_of(nm))
        out.append(f'<circle cx="{cx}" cy="{cy}" r="6" fill="{colour}"/>')
        out.append(f'<text x="{cx+10}" y="{cy+4}" font-size="9" fill="#222">'
                   f'{html.escape(nm)}</text>')
    out.append('</svg>')
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text("\n".join(out))
    print(f"diagram: {a.out}  ({len(devices)} devices, {len(edges)} links, "
          f"{len(band_meta)} tiers)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
