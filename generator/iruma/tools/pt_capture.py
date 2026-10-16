#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Capture the rendered workspace of a large lab inside Packet Tracer.

Three things about this environment cost real time to learn, and all three are
baked in here.

1. **Packet Tracer parses for minutes.** A ~390-device file takes roughly eight
   minutes to load on this machine, during which the workspace is blank. A blank
   workspace looks exactly like a render failure and is not one, so this tool
   waits for **evidence that something was drawn** -- saturated pixels inside the
   measured canvas rectangle -- rather than for a dialog to disappear.

2. **The progress dialog never clears.** Packet Tracer raises a modal prompt
   while the *Please wait. Opening file...* window is still up, so waiting for
   that window is not a usable completion signal.  (The workspace draws behind
   the prompt, which is why the ink test works.)

3. **Answer the prompt with Escape, never Return.** The prompt reads *"This file
   contains N device(s) that have outdated run-time scripts"* and offers
   **Yes** / **No** / **Update and Make a Copy**.  Return activates the default,
   **Yes**, which rewrites every affected device's run-time script -- on this
   392-device lab that closes the document and leaves an empty untitled window,
   which is indistinguishable from a load failure.  Escape selects **No** and
   leaves every device in its original state, and the loaded topology survives.

    python3 tools/pt_capture.py out/IRUMA_AB.pkt --outdir build/pt_capture
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
from iruma_paths import bootstrap          # noqa: E402
TOOLKIT = bootstrap()

import pt_runtime_verify as V              # noqa: E402

PROMPT_PAT = ("update devices", "update device", "would you allow",
              "network controller", "upgrade", "confirm", "warning",
              "external access")
BAD_PAT = ("incompatible", "unable to open", "cannot open")


def answer_prompts(xdo, pt, screen, seconds: float) -> int:
    """Dismiss informational prompts; abort if PT rejects the file."""
    n = 0
    end = time.time() + seconds
    while time.time() < end:
        hit = False
        for wid in xdo.windows(".", pid=pt.pid):
            nm = xdo.window_name(wid) or ""
            low = nm.lower()
            if any(b in low for b in BAD_PAT):
                screen.capture("REJECTED.png")
                raise SystemExit(f"Packet Tracer rejected the file: {nm}")
            if any(k in low for k in PROMPT_PAT):
                # Escape, not Return: Return picks the default "Yes" and rewrites
                # every device's run-time script, which closes the document on a
                # lab this size.  Escape picks "No" and changes nothing.
                try:
                    xdo("windowfocus", str(wid), timeout=10.0)
                    xdo("key", "--window", str(wid), "--clearmodifiers", "Escape",
                        timeout=10.0)
                except Exception:                              # noqa: BLE001
                    pass
                n += 1
                hit = True
                time.sleep(1.0)
        if not hit:
            time.sleep(0.5)
    return n


def canvas_ink(screen, shot: Path, region: tuple[int, int, int, int]) -> int:
    """Saturated pixels in the canvas -- device artwork and link lights.

    An empty Packet Tracer workspace is white with a light grey grid, so
    saturation is the discriminator: it is near zero when nothing is drawn and
    large once 392 devices and their labels are on the page.
    """
    hist = screen.histogram(shot, region=region, sample=4)
    ink = 0
    for (r, g, b), n in hist.items():
        if max(r, g, b) - min(r, g, b) > 40:
            ink += n
    return ink


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("lab", type=Path)
    ap.add_argument("--outdir", type=Path, default=ROOT / "build" / "pt_capture")
    ap.add_argument("--screen", default="1600x1000")
    ap.add_argument("--load-timeout", type=float, default=1800.0,
                    help="seconds to allow Packet Tracer to parse and draw")
    ap.add_argument("--ink-threshold", type=int, default=600,
                    help="saturated sampled pixels that count as 'drawn'")
    ap.add_argument("--stable-samples", type=int, default=3)
    ap.add_argument("--zoom-clicks", type=int, default=24)
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
        main = pt._main or pt.window
        # Fill the virtual screen first: a 3900x3900 page cannot fit any
        # readable viewport, and Packet Tracer restores its own geometry when
        # loading finishes, so this is repeated after the load.
        for cmd in (("windowsize", str(main), str(W - 20), str(H - 60)),
                    ("windowmove", str(main), "0", "0")):
            try:
                xdo(*cmd, timeout=15.0)
            except Exception:                                  # noqa: BLE001
                pass
            time.sleep(1.0)

        # The canvas is the white workspace between Packet Tracer's chrome.
        # Measured on a 1600x1000 screen with the window at (0,0): the
        # Logical/Physical tab bar and the workspace border are a dark blue
        # (13,39,77) that occupies y~95-130 and the frame edges, and the device
        # palette starts at y~805.  This rectangle is *measured* to contain zero
        # saturated pixels while the file is still parsing, which is what makes
        # "has anything been drawn" a usable load signal -- sampling the tab bar
        # is what made two earlier runs declare a blank workspace "loaded".
        try:
            gx, gy, gw, gh = xdo.geometry(main)
        except Exception:                                      # noqa: BLE001
            gx, gy, gw, gh = 0, 0, W, H
        canvas = (gx + 22, gy + 142, max(200, gw - 60), 596)
        print(f"  canvas region {canvas} (window {gx},{gy} {gw}x{gh})")

        deadline = time.time() + a.load_timeout
        deadline = time.time() + a.load_timeout
        stable = 0
        ink = 0
        while time.time() < deadline:
            answered = answer_prompts(xdo, pt, screen, 5)
            shot = screen.capture("_probe.png")
            ink = canvas_ink(screen, shot, canvas)
            print(f"  t={int(time.time() - (deadline - a.load_timeout)):>4}s "
                  f"ink={ink:>6}  prompts={answered}", flush=True)
            stable = stable + 1 if ink >= a.ink_threshold else 0
            if stable >= a.stable_samples:
                break
            time.sleep(5)
        if stable < a.stable_samples:
            raise SystemExit(
                f"nothing was drawn within {a.load_timeout:.0f}s "
                f"(last ink={ink}); the workspace is still blank")
        print("loaded: workspace has content")

        # Re-assert geometry now that the load has completed.
        for cmd in (("windowsize", str(main), str(W - 20), str(H - 60)),
                    ("windowmove", str(main), "0", "0")):
            try:
                xdo(*cmd, timeout=15.0)
            except Exception:                                  # noqa: BLE001
                pass
            time.sleep(1.0)

        # Packet Tracer's STP convergence finishes on its own after a load this
        # large; give it a moment so link lights are not captured mid-state.
        time.sleep(20)
        answer_prompts(xdo, pt, screen, 2)
        screen.capture("01_loaded.png")
        print("  captured 01_loaded.png")

        # Drive the toolbar zoom-out.  Keyboard zoom does not work under a bare
        # Xvfb (no window manager delivers the accelerator).  Toolbar geometry
        # was measured off a 4x crop: zoom-out is the "-" magnifier at x=450,
        # y=38 with the window at 0,0.
        ZOOM_OUT = ("450", "38")
        for n in range(1, a.zoom_clicks + 1):
            xdo("mousemove", *ZOOM_OUT, timeout=10.0)
            xdo("click", "1", timeout=10.0)
            time.sleep(0.6)
            if n % 4 == 0:
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
