#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Does this Packet Tracer accept a given .pkt?  Answer from the window title.

Screen-scraping the modal is unreliable: the dialog can appear after a
screenshot is taken, and OCR misses it often enough to report a rejected file as
accepted -- which is how an earlier round of this investigation drew the wrong
conclusion twice.  Packet Tracer puts the verdict in a *window title*:

    "Incompatible File -- Cisco Packet Tracer"

so the title is the signal, and it is unambiguous.  This is the detector the
toolkit's own ``tools/pt_runtime_verify.py`` uses.

    python3 tools/pt_accept.py a.pkt b.pkt c.pkt
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
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

import pt_runtime_verify as V  # noqa: E402

BAD_TITLE = ("incompatible", "unable to open", "cannot open")


def verdict(tc, path: Path, outdir: Path, wait: float = 90.0) -> tuple[bool, str]:
    """Return (accepted, evidence).  Polls window titles, not pixels."""
    outdir.mkdir(parents=True, exist_ok=True)
    work = outdir / f"probe_{path.stem}.pkt"
    shutil.copy2(path, work)
    xs = V.XServer(tc, (1400, 900))
    xdo = V.Xdo(tc, xs.env_display)
    screen = V.Screen(tc, xs.env_display, outdir)
    pt = V.PacketTracer(tc, xdo, screen, xs.env_display)
    titles: list[str] = []
    try:
        xs.start()
        pt.launch(work)
        # Packet Tracer shows "Please wait. Opening file..." while it parses.
        # Once that window is gone and no rejection appeared, the file opened --
        # no need to wait out the full timeout, which keeps a bisect affordable.
        deadline = time.time() + wait
        saw_wait = False
        while time.time() < deadline:
            names = []
            for wid in xdo.windows(".", pid=pt.pid):
                nm = xdo.window_name(wid)
                if nm:
                    names.append(nm)
                    if nm not in titles:
                        titles.append(nm)
                    if any(b in nm.lower() for b in BAD_TITLE):
                        screen.capture(f"{path.stem}_rejected.png")
                        return False, nm
            if any("please wait" in n.lower() or "opening file" in n.lower()
                   for n in names):
                saw_wait = True
            elif saw_wait:
                return True, "; ".join(titles[-3:])
            time.sleep(0.4)
        return True, "; ".join(titles[-3:])
    except Exception as exc:                                   # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        try:
            if pt.pid:
                os.killpg(os.getpgid(pt.pid), 15)
        except Exception:                                      # noqa: BLE001
            pass
        time.sleep(1.0)
        try:
            xs.stop()
        except Exception:                                      # noqa: BLE001
            pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("labs", nargs="+", type=Path)
    ap.add_argument("--wait", type=float, default=75.0)
    ap.add_argument("--outdir", type=Path, default=ROOT / "build" / "accept")
    ap.add_argument("--json", type=Path, default=ROOT / "build" / "accept.json")
    a = ap.parse_args(argv)
    tc = V.Toolchain.probe()
    results = {}
    for lab in a.labs:
        ok, ev = verdict(tc, lab, a.outdir, a.wait)
        results[lab.name] = {"accepted": ok, "evidence": ev}
        print(f"  {lab.name:36s} {'ACCEPTED' if ok else 'REJECTED'}   {ev[:60]}")
        a.json.write_text(json.dumps(results, indent=1, sort_keys=True))
    bad = [k for k, v in results.items() if not v["accepted"]]
    print(f"\naccepted {len(results) - len(bad)}/{len(results)}")
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(main())
