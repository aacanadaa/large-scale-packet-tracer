#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Capture a whole-model view of a lab inside Packet Tracer.

The default workspace shows one corner of a 3900x3900 page, which is not
evidence that a 386-device model is all there.  This drives the zoom control
until the whole page is visible and captures the result, trying several ways to
zoom because Packet Tracer's accelerator for it is not documented.

    python3 tools/pt_fullview.py out/YOKOHAMA_AMLC.pkt
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

PROMPT_PAT = ("update devices", "update device", "would you allow",
              "network controller", "upgrade", "confirm", "warning")
BAD_PAT = ("incompatible", "unable to open", "cannot open")


def answer_prompts(xdo, pt, screen, seconds: float) -> int:
    n = 0
    end = time.time() + seconds
    while time.time() < end:
        hit = False
        for wid in xdo.windows(".", pid=pt.pid):
            nm = xdo.window_name(wid) or ""
            if any(b in nm.lower() for b in BAD_PAT):
                screen.capture("REJECTED.png")
                raise SystemExit(f"Packet Tracer rejected the file: {nm}")
            if any(k in nm.lower() for k in PROMPT_PAT):
                xdo("windowfocus", "--sync", str(wid))
                xdo("key", "--window", str(wid), "--clearmodifiers", "Return")
                n += 1
                hit = True
                time.sleep(1.5)
        if not hit:
            time.sleep(0.7)
    return n


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("lab", type=Path)
    ap.add_argument("--outdir", type=Path, default=ROOT / "build" / "pt_fullview")
    ap.add_argument("--screen", default="1600x1000")
    a = ap.parse_args(argv)

    tc = V.Toolchain.probe()
    W, H = (int(x) for x in a.screen.lower().split("x"))
    xs = V.XServer(tc, (W, H))
    xdo = V.Xdo(tc, xs.env_display)
    screen = V.Screen(tc, xs.env_display, a.outdir)
    pt = V.PacketTracer(tc, xdo, screen, xs.env_display)
    a.outdir.mkdir(parents=True, exist_ok=True)
    work = a.outdir / f"view_{a.lab.name}"
    shutil.copy2(a.lab, work)

    xs.start()
    print(f"display {xs.env_display}")
    try:
        pt.launch(work)
        print(f"  prompts answered: {answer_prompts(xdo, pt, screen, 45)}")
        main = pt._main or pt.window

        # Grow the window to fill the virtual screen.  A 3900x3900 page cannot
        # fit a 950x460 viewport at any readable zoom, so the viewport has to be
        # made taller before zooming out; otherwise "the whole topology" is
        # either a corner of it or a handful of unreadable specks.
        w, h = W - 20, H - 60
        for cmd in (("windowsize", str(main), str(w), str(h)),
                    ("windowmove", str(main), "0", "0")):
            try:
                xdo(*cmd, timeout=15.0)
            except Exception as exc:                           # noqa: BLE001
                print(f"  note: {cmd[0]} failed: {exc}")
            time.sleep(1.5)
        try:
            print("  window now", xdo.geometry(main))
        except Exception:                                      # noqa: BLE001
            pass
        screen.capture("00_resized.png")

        # The View menu names the zoom commands; read it rather than guess.
        xdo("key", "--window", str(main), "--clearmodifiers", "Alt+v")
        time.sleep(1.5)
        screen.capture("01_view_menu.png")
        xdo("key", "--window", str(main), "--clearmodifiers", "Escape")
        time.sleep(1.0)

        # Keyboard zoom does not work under a bare Xvfb (no window manager to
        # deliver the accelerator), so drive the toolbar.  Toolbar geometry was
        # read off a 4x crop of the toolbar itself rather than guessed: zoom-in
        # is the "+" magnifier at x=382, zoom-out the "-" at x=450.  Clicking the
        # wrong one is what made an earlier attempt produce a blank workspace.
        ZOOM_OUT = ("450", "38")
        for n in (4, 8, 12, 16, 20, 24, 28):
            xdo("mousemove", *ZOOM_OUT, timeout=10.0)
            xdo("click", "1", timeout=10.0)
            time.sleep(0.5)
            screen.capture(f"zoom_{n:02d}.png")
            print(f"  captured zoom_{n:02d}.png")
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
