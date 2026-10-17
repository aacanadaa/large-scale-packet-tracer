#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Measure how readable a lab's logical layout actually is.

`check_layout.py` answers "does anything overlap or fall off the page?". It does
not answer the question a reader asks first: *can I follow a cable?* A lab can
pass every geometry gate and still be a wall of crossing lines, because a layout
that is geometrically valid is not necessarily legible.

Two measurements, both computed from the written artefact:

``crossings``
    How many times two cables cross each other. A crossing is where a reader's
    eye is pulled onto the wrong cable; this is the single best proxy for
    "spaghetti".

``cable length``
    Centre-to-centre distance in canvas units (1 unit = 1 px at 100% zoom).
    Long cables are the *cause* of most crossings: a cable that spans eight tier
    bands crosses everything in between.

Reported per band, so the report says *which* part of the model is tangled
rather than only that the model is tangled.

    python3 tools/check_readability.py out/IRUMA_AB.pkt
    python3 tools/check_readability.py out/IRUMA_AB.pkt --json build/readability.json
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from iruma_paths import bootstrap          # noqa: E402
TOOLKIT = bootstrap()
for _p in (str(TOOLKIT), str(TOOLKIT / "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from pkt_core import decode_bytes          # noqa: E402
import xml.etree.ElementTree as ET         # noqa: E402

from iruma_tiers import section_of          # noqa: E402


def _segments_intersect(p, p2, q, q2) -> bool:
    """True when open segments p-p2 and q-q2 cross (touching does not count)."""
    def orient(a, b, c):
        v = (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])
        return (v > 0) - (v < 0)

    o1, o2 = orient(p, p2, q), orient(p, p2, q2)
    o3, o4 = orient(q, q2, p), orient(q, q2, p2)
    return o1 != o2 and o3 != o4


def analyse(root: ET.Element) -> dict:
    pos: dict[str, tuple[int, int]] = {}
    band: dict[str, str] = {}
    for d in root.iter("DEVICE"):
        nm = d.findtext("ENGINE/NAME")
        x = d.findtext("WORKSPACE/LOGICAL/X")
        y = d.findtext("WORKSPACE/LOGICAL/Y")
        if not nm or x is None or y is None:
            continue
        pos[nm] = (int(float(x)), int(float(y)))
        band[nm] = section_of(nm)

    sid_name = {d.findtext("ENGINE/SAVE_REF_ID"): d.findtext("ENGINE/NAME")
                for d in root.iter("DEVICE")}
    cables: list[tuple[str, str]] = []
    for lk in root.iter("LINK"):
        cab = lk.find("CABLE")
        if cab is None:
            continue
        a = sid_name.get(cab.findtext("FROM"))
        b = sid_name.get(cab.findtext("TO"))
        if a in pos and b in pos and a != b:
            cables.append((a, b))

    # de-duplicate: the same pair cabled twice is one visual line
    seen = set()
    uniq = []
    for a, b in cables:
        k = tuple(sorted((a, b)))
        if k in seen:
            continue
        seen.add(k)
        uniq.append((a, b))

    lengths = []
    per_band = collections.Counter()
    per_band_len = collections.Counter()
    for a, b in uniq:
        (x1, y1), (x2, y2) = pos[a], pos[b]
        d = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5
        lengths.append((d, a, b))
        for nm in (a, b):
            per_band[band[nm]] += 1
            per_band_len[band[nm]] += d

    crossings = 0
    crossing_pairs = []
    n = len(uniq)
    for i in range(n):
        a1, b1 = uniq[i]
        for j in range(i + 1, n):
            a2, b2 = uniq[j]
            if len({a1, b1, a2, b2}) < 4:
                continue                      # share an endpoint: not a crossing
            if _segments_intersect(pos[a1], pos[b1], pos[a2], pos[b2]):
                crossings += 1
                if len(crossing_pairs) < 20:
                    crossing_pairs.append((a1, b1, a2, b2))

    lengths.sort(reverse=True)
    vals = [d for d, _a, _b in lengths] or [0]
    vals_sorted = sorted(vals)
    return dict(
        devices=len(pos),
        cables=len(uniq),
        crossings=crossings,
        crossings_per_cable=round(crossings / max(1, len(uniq)), 2),
        length_min=round(min(vals), 1),
        length_median=round(vals_sorted[len(vals_sorted) // 2], 1),
        length_p95=round(vals_sorted[int(len(vals_sorted) * 0.95) - 1], 1),
        length_max=round(max(vals), 1),
        length_mean=round(sum(vals) / len(vals), 1),
        longest=[dict(length=round(d, 1), a=a, b=b) for d, a, b in lengths[:10]],
        band_cables=dict(sorted(per_band.items())),
        band_mean_length={k: round(per_band_len[k] / per_band[k], 1)
                          for k in sorted(per_band)},
        crossing_pairs=crossing_pairs,
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("lab", type=Path)
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--max-crossings", type=int, default=None,
                    help="exit 1 when crossings exceed this")
    ap.add_argument("--show-pairs", action="store_true")
    a = ap.parse_args(argv)

    raw = a.lab.read_bytes()
    root = ET.fromstring(raw if raw[:1] == b"<" else decode_bytes(raw).xml)
    r = analyse(root)

    print(f"lab       : {a.lab.name}")
    print(f"devices   : {r['devices']}   cables: {r['cables']}")
    print(f"crossings : {r['crossings']}  ({r['crossings_per_cable']} per cable)")
    print(f"length    : min {r['length_min']}  median {r['length_median']}  "
          f"p95 {r['length_p95']}  max {r['length_max']}  mean {r['length_mean']}")
    print("\n-- per section: cables and mean cable length --")
    for b in r["band_cables"]:
        print(f"   {b:20s} cables {r['band_cables'][b]:4d}   "
              f"mean length {r['band_mean_length'][b]:7.1f}")
    print("\n-- longest ten cables --")
    for e in r["longest"]:
        print(f"   {e['length']:7.1f}  {e['a']}  <->  {e['b']}")
    if a.show_pairs:
        print("\n-- first crossing pairs --")
        for a1, b1, a2, b2 in r["crossing_pairs"]:
            print(f"   ({a1} - {b1})  x  ({a2} - {b2})")
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps(r, indent=1, sort_keys=True))
    if a.max_crossings is not None and r["crossings"] > a.max_crossings:
        print(f"\nFAIL: {r['crossings']} crossings exceeds {a.max_crossings}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
