#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify individual (model, port) pairs against a real Packet Tracer.

Why one pair per file
---------------------
``tools/pt_load_check.py`` proves every model loads on its own.  It does not
prove a *cable* is legal, and that is the sharper question: ``lab_api.link()``
writes the port-name string into the ``<LINK>`` verbatim, and Packet Tracer
resolves it at load time.  When a name does not match any port on the device,
PT does not drop the cable and carry on -- it refuses the **whole file** with

    "Unable to open file ... is not compatible with this version of Cisco
     Packet Tracer"

Measured on this project's 37-model probe: one bad name among ~40 cables made
the entire lab unopenable, while each model loaded fine in isolation.  So a
single guessed port name is enough to destroy the deliverable, and "it rendered
in my head" is not evidence.

This tool therefore builds one tiny lab per pair -- a switch, the device, and
exactly one cable naming the candidate port -- opens it, and reads the screen
back.  A pair PT accepts is a pair this lab may use.

    python3 tools/pt_port_verify.py --all
    python3 tools/pt_port_verify.py --pairs PLC-PT:GigabitEthernet0 Siren:FastEthernet0
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

import lab_api                # noqa: E402
import pt_runtime_verify as V  # noqa: E402

# Every (model, port) pair this project's design depends on.  Ordered so the
# least-certain names are tested first: a run that has to stop early has then
# still answered the questions that mattered most.
PAIRS: list[tuple[str, str]] = [
    # --- convention tier: no factory config, no attested link ---
    ("PLC-PT", "GigabitEthernet0"),
    ("HMI-PT", "GigabitEthernet0"),
    ("RFID Reader", "FastEthernet0"),
    ("Motion Detector", "FastEthernet0"),
    ("Temperature Monitor", "FastEthernet0"),
    ("Smoke Detector", "FastEthernet0"),
    ("Water Level Monitor", "FastEthernet0"),
    ("Siren", "FastEthernet0"),
    ("Smart LED", "FastEthernet0"),
    ("Trip Sensor", "FastEthernet0"),
    ("Power Meter", "FastEthernet0"),
    ("Webcam", "FastEthernet0"),
    ("NetworkController", "GigabitEthernet0"),
    ("DataHistorianServer", "GigabitEthernet0"),
    ("LAP-PT", "GigabitEthernet0"),
    ("7960", "FastEthernet0"),
    # --- attested / template tier, spot-checked because the design uses them ---
    ("CyberObserver", "GigabitEthernet0"),
    ("Sniffer", "Ethernet1"),
    ("Cloud-PT", "GigabitEthernet0"),
    ("WLC-3504", "GigabitEthernet0/1"),
    ("AccessPoint-PT-N", "Port 0"),
    ("IE-2000", "FastEthernet1/1"),
    ("IE-2000", "GigabitEthernet1/1"),
    ("IE-3400", "GigabitEthernet1/5"),
    ("IE-9320", "GigabitEthernet1/0/5"),
    ("IR1101", "FastEthernet0/0/1"),
    ("IR1101", "GigabitEthernet0/0/0"),
    ("CGR1240", "FastEthernet2/3"),
    ("ISA-3000", "GigabitEthernet1/1"),
    ("Meraki-MX65W", "Internet 1"),
    ("2911", "Serial0/0/0"),
    ("ISR4331", "Serial0/1/0"),
    ("ISR4331", "GigabitEthernet0/0/2"),
    ("3650-24PS", "GigabitEthernet1/0/20"),
    ("3560-24PS", "GigabitEthernet0/2"),
    ("2960-24TT", "GigabitEthernet0/2"),
    ("5505", "Ethernet0/2"),
]

ERROR_PAT = re.compile(r"unable to open|not compatible|cannot open|invalid file",
                       re.IGNORECASE)


def build_pair(model: str, port: str, out: Path) -> bool:
    models, modules = lab_api.load_templates(str(TOOLKIT / "tools" / "device_templates.json"))
    if model not in models:
        return False
    lab = lab_api.Lab(str(TOOLKIT / "tools" / "network_seed.xml"), models, modules)
    lab.prune_seed_devices()
    layout = lab_api.Layout()
    p1 = layout.place("V-SW", "2960-24TT", group="t")
    sw = lab.add_device("2960-24TT", "V-SW", p1.x, p1.y)
    p2 = layout.place("V-DUT", model, group="t")
    dut = lab.add_device(model, "V-DUT", p2.x, p2.y)
    # The switch end is always an attested name, so only `port` is under test.
    lab.link(sw, "FastEthernet0/1", dut, port)
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


def run(pairs: list[tuple[str, str]], outdir: Path, settle: float) -> dict:
    tc = V.Toolchain.probe()
    outdir.mkdir(parents=True, exist_ok=True)
    results: dict[str, dict] = {}
    for model, port in pairs:
        slug = re.sub(r"[^A-Za-z0-9]+", "_", f"{model}__{port}")
        work = outdir / f"{slug}.pkt"
        if not build_pair(model, port, work):
            results[f"{model}|{port}"] = {"status": "no-template"}
            print(f"  {model:22s} {port:22s} NO TEMPLATE")
            continue
        xs = V.XServer(tc, (1200, 800))
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
            status = "rejected" if ERROR_PAT.search(text) else "accepted"
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
        results[f"{model}|{port}"] = {"model": model, "port": port,
                                      "status": status,
                                      "ocr": " ".join(text.split())[:160]}
        print(f"  {model:22s} {port:22s} {status}")
        # write after every pair so an interrupted run keeps its answers
        (outdir / "port_verify.json").write_text(
            json.dumps(results, indent=1, sort_keys=True))
    return results


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pairs", nargs="*", default=[],
                    help="MODEL:PORT entries; default is the built-in list")
    ap.add_argument("--all", action="store_true", help="use the built-in list")
    ap.add_argument("--outdir", type=Path, default=ROOT / "build" / "port_verify")
    ap.add_argument("--settle", type=float, default=7.0)
    a = ap.parse_args(argv)
    if a.pairs:
        pairs = []
        for item in a.pairs:
            model, _, port = item.rpartition(":")
            pairs.append((model, port))
    elif a.all:
        pairs = PAIRS
    else:
        print("error: give --all or --pairs MODEL:PORT ...", file=sys.stderr)
        return 2
    res = run(pairs, a.outdir, a.settle)
    bad = [k for k, v in res.items() if v["status"] != "accepted"]
    print(f"\naccepted: {len(res) - len(bad)}/{len(res)}")
    if bad:
        print("REJECTED (do not use these names):")
        for k in bad:
            print(f"  {k}")
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(main())
