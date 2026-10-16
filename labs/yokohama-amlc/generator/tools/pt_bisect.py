#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Find the smallest set of devices that makes Packet Tracer refuse a lab.

Packet Tracer's failure mode here is unhelpful: a file it will not load produces
one generic modal -- "not compatible with this version" -- that names no device
and no reason.  Guessing which of several hundred devices caused it is how hours
disappear.

This tool removes devices from an already-built ``.pkt`` (together with their
physical-workspace node and CPUR entry, so the document stays self-consistent)
and asks Packet Tracer about each reduced variant.  Halving on the failing
subset converges on the culprit in a handful of launches.

    python3 tools/pt_bisect.py out/YOKOHAMA_AMLC_smoke.pkt
    python3 tools/pt_bisect.py lab.pkt --keep-only 40     # stop at <=40 devices
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from yokohama_paths import bootstrap as _bootstrap   # noqa: E402
TOOLKIT = _bootstrap()
for _p in (str(ROOT), str(TOOLKIT), str(TOOLKIT / "tools"), str(TOOLKIT / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import pt_runtime_verify as V            # noqa: E402
import pt_accept                         # noqa: E402
from pkt_core import decode_bytes, encode_bytes   # noqa: E402

ERROR_PAT = re.compile(r"unable to open|not compatible|cannot open|invalid file",
                       re.IGNORECASE)


def load(path: Path):
    raw = path.read_bytes()
    xml = raw if raw[:1] == b"<" else decode_bytes(raw).xml
    return ET.fromstring(xml)


def device_map(root: ET.Element) -> dict[str, ET.Element]:
    out = {}
    for d in root.iter("DEVICE"):
        nm = d.findtext("ENGINE/NAME")
        if nm:
            out.setdefault(nm, d)
    return out


def subset(root: ET.Element, keep: set[str]) -> bytes:
    """Return an encoded lab containing only ``keep`` and links between them."""
    import copy
    r = copy.deepcopy(root)
    dropped_uuids: set[str] = set()
    for devs in r.iter("DEVICES"):
        for d in list(devs.findall("DEVICE")):
            nm = d.findtext("ENGINE/NAME")
            if nm in keep:
                continue
            ph = (d.findtext("PHYSICAL") or "")
            m = re.search(r"\{([^}]*)\}", ph)
            if m:
                dropped_uuids.add("{%s}" % m.group(1))
            devs.remove(d)
    # links
    for links in r.iter("LINKS"):
        for lk in list(links.findall("LINK")):
            cab = lk.find("CABLE")
            if cab is None:
                continue
            ends = {cab.findtext("FROM"), cab.findtext("TO")}
            if not ends <= set(keep_ids(r)):
                links.remove(lk)
    # physical workspace: drop the leaves and CPUR rows of removed devices
    ids = set(keep_ids(r))
    for pw in r.iter("PHYSICALWORKSPACE"):
        stack = [pw]
        while stack:
            node = stack.pop()
            for ch in list(node.findall("NODE")):
                u = ch.findtext("UUID_STR")
                if u in dropped_uuids:
                    node.remove(ch)
                else:
                    stack.append(ch)
        for cpur in list(pw.iter("PHYSICAL_CPUR")):
            if (cpur.findtext("ORIGINAL_DEVICE_UUID") or "") in dropped_uuids:
                pw.remove(cpur)
    _ = ids
    return encode_bytes(ET.tostring(r, encoding="unicode").encode("utf-8"), "pkt")


def keep_ids(root: ET.Element) -> list[str]:
    return [d.findtext("ENGINE/SAVE_REF_ID") or "" for d in root.iter("DEVICE")]


def accepts(tc, path: Path, outdir: Path, settle: float, tag: str) -> bool:
    """True when Packet Tracer opens the file.

    Delegates to ``pt_accept``, which reads the verdict from the window title
    ("Incompatible File -- Cisco Packet Tracer").  An earlier version scraped
    the modal from a screenshot and reported rejected files as accepted, which
    sent this investigation down two blind alleys.
    """
    ok, _evidence = pt_accept.verdict(tc, path, outdir, wait=max(45.0, settle * 4))
    return ok


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("lab", type=Path)
    ap.add_argument("--keep-only", type=int, default=12,
                    help="stop bisecting once the failing set is this small")
    ap.add_argument("--settle", type=float, default=14.0)
    ap.add_argument("--outdir", type=Path, default=ROOT / "build" / "bisect_run")
    a = ap.parse_args(argv)

    root = load(a.lab)
    names = sorted(device_map(root))
    a.outdir.mkdir(parents=True, exist_ok=True)
    tc = V.Toolchain.probe()

    full = a.outdir / "full.pkt"
    full.write_bytes(subset(root, set(names)))
    if accepts(tc, full, a.outdir, a.settle, "full"):
        print("the full lab loads -- nothing to bisect")
        return 0
    print(f"full lab ({len(names)} devices) is REJECTED; bisecting ...")

    failing = names
    while len(failing) > a.keep_only:
        half = len(failing) // 2
        left, right = failing[:half], failing[half:]
        # A reduced set still needs something to be a lab at all, so test each
        # half on its own; if neither fails, the cause needs both and we stop.
        found = None
        for label, part in (("left", left), ("right", right)):
            if not part:
                continue
            p = a.outdir / f"part_{len(part)}.pkt"
            p.write_bytes(subset(root, set(part)))
            ok = accepts(tc, p, a.outdir, a.settle, f"part_{label}_{len(part)}")
            print(f"  {len(part):4d} devices ({label}): "
                  f"{'loads' if ok else 'REJECTED'}")
            if not ok:
                found = part
                break
        if found is None:
            print("  neither half fails alone -- the cause needs devices from "
                  "both halves (a combination, not a single device)")
            (a.outdir / "failing_set.json").write_text(
                json.dumps({"combination": True, "candidates": failing}, indent=1))
            return 1
        failing = found

    print(f"\nsmallest failing set ({len(failing)} devices):")
    for n in failing:
        print(f"  {n}")
    (a.outdir / "failing_set.json").write_text(
        json.dumps({"combination": False, "devices": failing}, indent=1))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
