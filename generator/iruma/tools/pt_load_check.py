#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Which device models does this Packet Tracer actually accept?

Builds one tiny lab per model (a switch plus the model under test), opens each
in a real Packet Tracer under Xvfb, and reads the screen back with OCR.  PT
raises a modal

    "Unable to open file ... is not compatible with this version of Cisco
     Packet Tracer"

for a container it will not load -- and because that dialog is *modal*, a file
that triggers it can never be saved, so a failure is otherwise silent.  Reading
it off the screen turns "the file did not change" into a definite verdict.

A model PT refuses is not a cosmetic problem: `tools/port_inventory.py` cannot
give it port names, the probe cannot cable it, and shipping it would make the
whole lab unopenable.

    python3 tools/pt_load_check.py --models IE-3400 PLC-PT "RFID Reader"
    python3 tools/pt_load_check.py --all
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

import lab_api            # noqa: E402
import pt_runtime_verify as V  # noqa: E402

# every model this project is considering, in one place
ALL_MODELS = [
    "3650-24PS", "3560-24PS", "2960-24TT", "2911", "ISR4331", "ISR4321", "5505",
    "IE-2000", "IE-3400", "IE-9320", "IR1101", "IR8340", "ISA-3000", "CGR1240",
    "PLC-PT", "HMI-PT", "NetworkController", "DataHistorianServer",
    "CyberObserver", "Sniffer", "Server-PT", "PC-PT", "Laptop-PT",
    "AccessPoint-PT-N", "LAP-PT", "WLC-3504", "Meraki-MX65W", "7960",
    "Webcam", "RFID Reader", "Motion Detector", "Temperature Monitor",
    "Smoke Detector", "Water Level Monitor", "Siren", "Smart LED",
    "Trip Sensor", "Power Meter", "Beacon", "MCU-PT", "Metal Sensor",
    "Temperature Sensor", "Photo Sensor", "Wind Sensor",
    "Generic Environment Sensor", "Cloud-PT",
]

ERROR_PAT = re.compile(
    r"unable to open|not compatible|cannot open|error (?:loading|opening)|"
    r"invalid file|corrupt", re.IGNORECASE)


def build_one(model: str, out: Path) -> bool:
    models, modules = lab_api.load_templates(str(TOOLKIT / "tools" / "device_templates.json"))
    if model not in models:
        return False
    lab = lab_api.Lab(str(TOOLKIT / "tools" / "network_seed.xml"), models, modules)
    lab.prune_seed_devices()
    layout = lab_api.Layout()
    for nm, mdl in (("L-SW", "2960-24TT"), ("L-DUT", model)):
        p = layout.place(nm, mdl, group="t")
        lab.add_device(mdl, nm, p.x, p.y)
    out.parent.mkdir(parents=True, exist_ok=True)
    lab.save(str(out))
    return True


def ocr(path: Path) -> str:
    if not shutil.which("tesseract"):
        return ""
    try:
        r = subprocess.run(["tesseract", str(path), "stdout"],
                           capture_output=True, text=True, timeout=90)
        return r.stdout
    except Exception:                                          # noqa: BLE001
        return ""


def check_files(files: list[Path], outdir: Path, settle: float) -> dict:
    """Load each already-built .pkt and report whether PT accepts it."""
    tc = V.Toolchain.probe()
    outdir.mkdir(parents=True, exist_ok=True)
    results: dict[str, dict] = {}
    for src in files:
        slug = re.sub(r"[^A-Za-z0-9]+", "_", src.stem)
        work = outdir / f"{slug}.pkt"
        shutil.copy2(src, work)
        xs = V.XServer(tc, (1200, 800))
        xdo = V.Xdo(tc, xs.env_display)
        screen = V.Screen(tc, xs.env_display, outdir)
        pt = V.PacketTracer(tc, xdo, screen, xs.env_display)
        status, text = "unknown", ""
        try:
            xs.start()
            pt.launch(work)
            time.sleep(settle)
            text = ocr(screen.capture(f"{slug}.png"))
            status = "rejected" if ERROR_PAT.search(text) else "loaded"
        except Exception as exc:                               # noqa: BLE001
            status = f"error:{type(exc).__name__}"
        finally:
            try:
                if pt.pid:
                    os.killpg(os.getpgid(pt.pid), 15)
            except Exception:                                  # noqa: BLE001
                pass
            time.sleep(0.8)
            try:
                xs.stop()
            except Exception:                                  # noqa: BLE001
                pass
        results[src.name] = {"status": status, "path": str(src),
                             "ocr": " ".join(text.split())[:160]}
        print(f"  {src.name:34s} {status}")
        (outdir / "file_check.json").write_text(
            json.dumps(results, indent=1, sort_keys=True))
    return results


def check(models: list[str], outdir: Path, settle: float = 9.0) -> dict:
    tc = V.Toolchain.probe()
    results: dict[str, dict] = {}
    outdir.mkdir(parents=True, exist_ok=True)
    for model in models:
        slug = re.sub(r"[^A-Za-z0-9]+", "_", model)
        work = outdir / f"{slug}.pkt"
        if not build_one(model, work):
            results[model] = {"status": "no-template"}
            print(f"  {model:26s} NO TEMPLATE")
            continue
        xs = V.XServer(tc, (1400, 900))
        xdo = V.Xdo(tc, xs.env_display)
        screen = V.Screen(tc, xs.env_display, outdir)
        pt = V.PacketTracer(tc, xdo, screen, xs.env_display)
        status, text = "unknown", ""
        try:
            xs.start()
            pt.launch(work)
            time.sleep(settle)
            shot = screen.capture(f"{slug}.png")
            text = ocr(shot)
            bad = bool(ERROR_PAT.search(text))
            # A clean load paints the workspace; an error dialog covers it.
            status = "rejected" if bad else "loaded"
        except Exception as exc:                               # noqa: BLE001
            status = f"error:{type(exc).__name__}"
        finally:
            try:
                if pt.pid:
                    os.killpg(os.getpgid(pt.pid), 15)
            except Exception:                                  # noqa: BLE001
                pass
            time.sleep(1.0)
            try:
                xs.stop()
            except Exception:                                  # noqa: BLE001
                pass
        results[model] = {"status": status,
                          "ocr": " ".join(text.split())[:200]}
        print(f"  {model:26s} {status}")
    return results


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--models", nargs="*", default=[])
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--files", nargs="*", type=Path, default=[])
    ap.add_argument("--outdir", type=Path, default=ROOT / "build" / "load_check")
    ap.add_argument("--settle", type=float, default=9.0)
    a = ap.parse_args(argv)
    if a.files:
        res = check_files(a.files, a.outdir, a.settle)
        bad = [m for m, v in res.items() if v["status"] != "loaded"]
        print(f"\naccepted: {len(res) - len(bad)}/{len(res)}")
        if bad:
            print("REJECTED: " + ", ".join(bad))
        return 0 if not bad else 1
    models = ALL_MODELS if a.all else a.models
    if not models:
        print("error: give --models ... or --all", file=sys.stderr)
        return 2
    res = check(models, a.outdir, a.settle)
    (a.outdir / "load_check.json").write_text(json.dumps(res, indent=1, sort_keys=True))
    bad = [m for m, v in res.items() if v["status"] != "loaded"]
    print(f"\naccepted: {len(res) - len(bad)}/{len(res)}")
    if bad:
        print("NOT accepted: " + ", ".join(bad))
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(main())
