#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Open a probe lab in a real Packet Tracer, save it, and report what changed.

This is the "open the result" half of ``tools/pt_port_probe.py``: a candidate
port name that Packet Tracer does not recognise cannot survive a save, and one
it does recognise comes back in PT's own canonical spelling.  Either way the
answer is read from PT's output rather than inferred.

Reuses the toolkit's ``tools/pt_runtime_verify.py`` launch / Xvfb / xdotool
primitives so the two tools cannot disagree about how a PT window is found or
how long a large topology takes to draw.

    python3 tools/pt_probe_run.py build/probe_ports.pkt --save-as build/probe_truth.pkt
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
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

import pt_runtime_verify as V  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("artifact", type=Path)
    ap.add_argument("--save-as", type=Path, required=True)
    ap.add_argument("--screen", default="1600x1000")
    ap.add_argument("--load-timeout", type=float, default=300.0)
    ap.add_argument("--settle", type=float, default=15.0)
    ap.add_argument("--outdir", type=Path, default=ROOT / "build" / "pt_probe")
    a = ap.parse_args(argv)

    artifact = a.artifact.resolve()
    if not artifact.exists():
        print(f"error: {artifact} not found", file=sys.stderr)
        return 2

    tc = V.Toolchain.probe()
    if not tc.pt_bin:
        print("error: no Packet Tracer executable found", file=sys.stderr)
        return 2
    W, H = (int(x) for x in a.screen.lower().split("x"))
    xs = V.XServer(tc, (W, H))
    xdo = V.Xdo(tc, xs.env_display)
    screen = V.Screen(tc, xs.env_display, a.outdir)
    pt = V.PacketTracer(tc, xdo, screen, xs.env_display)

    # Never let PT write into the source tree: work on a copy.
    work = a.outdir / (artifact.stem + ".work.pkt")
    a.outdir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(artifact, work)
    before_size = work.stat().st_size

    xs.start()
    print(f"PT      : {tc.pt_bin}")
    print(f"display : {xs.env_display}")
    print(f"input   : {work}  ({before_size} bytes)")
    ok = False
    try:
        t0 = time.time()
        proc = pt.launch(work)
        print(f"  loaded in {time.time() - t0:.1f}s, window {proc.window} "
              f"{proc.geometry[2]}x{proc.geometry[3]}")
        time.sleep(a.settle)
        screen.capture("before_save.png")

        # Ctrl+S saves in place for a document opened from disk; the Return
        # answers a format/"save as" prompt by accepting the shown default.
        xdo("key", "--window", str(proc.window), "--clearmodifiers", "ctrl+s")
        time.sleep(6.0)
        screen.capture("after_ctrl_s.png")
        xdo("key", "--window", str(proc.window), "--clearmodifiers", "Return")
        time.sleep(8.0)
        screen.capture("after_return.png")
        print("  save keystrokes sent")

        after = work.stat()
        ok = after.st_size != before_size
        print(f"  output  : {after.st_size} bytes  "
              f"{'CHANGED' if ok else 'UNCHANGED'}")
    except Exception as exc:                                   # noqa: BLE001
        print(f"  note: {type(exc).__name__}: {exc}", file=sys.stderr)
    finally:
        try:
            if pt.pid:
                os.killpg(os.getpgid(pt.pid), 15)
        except Exception:                                      # noqa: BLE001
            pass
        time.sleep(2.0)
        try:
            xs.stop()
        except Exception:                                      # noqa: BLE001
            pass

    if work.exists():
        a.save_as.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(work, a.save_as)
        print(f"  copied  -> {a.save_as}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
