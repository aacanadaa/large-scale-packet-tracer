#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Open a lab in Packet Tracer, answer its startup prompts, and screenshot it.

``tools/pt_runtime_verify.py`` waits for the "Please wait. Opening file..."
window to clear, and a lab built from many device templates also raises an
**"Update Devices?"** prompt that blocks that wait -- so a file which loaded
perfectly is reported as a load timeout.  The window list makes the difference
visible at a glance:

    ['Cisco Packet Tracer - /tmp/lab.pkt -', 'Please wait. Opening file...']
    ['Cisco Packet Tracer - /tmp/lab.pkt -', 'Update Devices? -- ...']

The first is a load in progress; the second is a load that succeeded and is
waiting for an answer.  This tool dismisses the prompt, waits for the workspace,
and captures what is actually drawn.

    python3 tools/pt_render_check.py out/YOKOHAMA_AMLC.pkt --shots 4
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from yokohama_paths import bootstrap          # noqa: E402
TOOLKIT = bootstrap()

import pt_runtime_verify as V                 # noqa: E402

# Informational prompts Packet Tracer raises for a lab built from many device
# templates: "Update Devices?" (model versions) and "Would you allow external
# network access to Network Controller devices?" (IoE).  Neither is an error and
# neither has a wrong answer for a static model; both block the workspace until
# dismissed, which is what makes a *loaded* file look like a load timeout.
PROMPT_PAT = ("update devices", "update device", "would you allow",
              "network controller", "upgrade", "confirm", "warning")
BAD_PAT = ("incompatible", "unable to open", "cannot open")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("lab", type=Path)
    ap.add_argument("--outdir", type=Path, default=ROOT / "build" / "pt_render")
    ap.add_argument("--shots", type=int, default=3)
    ap.add_argument("--load-wait", type=float, default=240.0)
    ap.add_argument("--settle", type=float, default=30.0)
    ap.add_argument("--screen", default="1600x1000")
    ap.add_argument("--zoom-out", type=int, default=0,
                    help="clicks on the zoom-out control before capturing")
    a = ap.parse_args(argv)

    tc = V.Toolchain.probe()
    W, H = (int(x) for x in a.screen.lower().split("x"))
    xs = V.XServer(tc, (W, H))
    xdo = V.Xdo(tc, xs.env_display)
    screen = V.Screen(tc, xs.env_display, a.outdir)
    pt = V.PacketTracer(tc, xdo, screen, xs.env_display)
    work = a.outdir / f"render_{a.lab.name}"
    a.outdir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(a.lab, work)

    xs.start()
    print(f"display {xs.env_display}   PT {tc.pt_bin}")
    try:
        pt.launch(work)
        deadline = time.time() + a.load_wait
        answered = 0
        while time.time() < deadline:
            names = {}
            for wid in xdo.windows(".", pid=pt.pid):
                nm = xdo.window_name(wid)
                if nm:
                    names[wid] = nm
            for nm in names.values():
                if any(b in nm.lower() for b in BAD_PAT):
                    screen.capture("REJECTED.png")
                    print(f"REJECTED by PT: {nm}")
                    return 1
            prompts = [w for w, n in names.items()
                       if any(k in n.lower() for k in PROMPT_PAT)]
            if prompts:
                for wid in prompts:
                    print(f"  answering prompt: {names[wid]}")
                    xdo("windowfocus", "--sync", str(wid))
                    xdo("key", "--window", str(wid), "--clearmodifiers", "Return")
                    answered += 1
                time.sleep(2.0)
            if not any("please wait" in n.lower() for n in names.values()) and answered:
                break
            time.sleep(1.0)

        # Keep answering while the workspace settles: a prompt can appear only
        # after the first one is dismissed.
        quiet, end = 0.0, time.time() + a.settle
        while time.time() < end:
            found = False
            for wid in xdo.windows(".", pid=pt.pid):
                nm = xdo.window_name(wid) or ""
                if any(k in nm.lower() for k in PROMPT_PAT):
                    print(f"  answering prompt: {nm}")
                    xdo("windowfocus", "--sync", str(wid))
                    xdo("key", "--window", str(wid), "--clearmodifiers", "Return")
                    answered += 1
                    found = True
                    time.sleep(1.5)
            quiet = 0.0 if found else quiet + 1.0
            time.sleep(1.0)
        print(f"prompts answered: {answered}")
        # Zoom out so the capture shows the model rather than one corner of it.
        # The zoom-out control sits at a fixed place in the 9.0.1 toolbar.
        for _ in range(a.zoom_out):
            # No window manager: mousemove --sync can block forever waiting on a
            # pointer motion event, so move and click without it.
            xdo("mousemove", "384", "38", timeout=10.0)
            xdo("click", "1", timeout=10.0)
            time.sleep(0.6)
        for i in range(a.shots):
            shot = screen.capture(f"workspace_{i}.png")
            print(f"  captured {shot}")
            if i + 1 < a.shots:
                xdo("key", "--window", str(pt._main or 0), "--clearmodifiers", "Right")
                time.sleep(2.0)
        return 0
    finally:
        try:
            if pt.pid:
                os.killpg(os.getpgid(pt.pid), 15)
        except Exception:                                      # noqa: BLE001
            pass
        time.sleep(1.5)
        try:
            xs.stop()
        except Exception:                                      # noqa: BLE001
            pass


if __name__ == "__main__":
    raise SystemExit(main())
