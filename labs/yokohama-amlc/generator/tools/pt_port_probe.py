#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build a probe lab whose only purpose is to make Packet Tracer *tell us* the
canonical port names of the models that carry no factory configuration.

Why this exists
---------------
``tools/port_inventory.py`` reads port names out of each model's harvested
factory config.  That works for IOS/ASA models and for nothing else: 108 of the
137 templates ship no interface lines, and they are exactly the devices this
model needs (PLC/HMI, RFID readers, reefer temperature monitors, smoke and water
detectors, access points, servers).

``lab_api.link()`` stores the port-name string verbatim and Packet Tracer
resolves it at load time, so a guessed name is not a syntax error -- it is a
silently dead cable.  The only authority is Packet Tracer itself.

How it works
------------
Each probe device is cabled to a switch with a *candidate* port name.  The lab
is then opened and saved by a real Packet Tracer, and the saved bytes are
compared with what we wrote.  A name PT does not recognise cannot survive a
save; a name it does recognise comes back canonicalised.  Either way the answer
is read from PT's own output rather than inferred.

    python3 tools/pt_port_probe.py --out build/probe_ports.pkt
    # ... open + save under Xvfb (see tools/pt_port_probe.sh) ...
    python3 tools/pt_port_probe.py --read build/probe_ports_saved.pkt
"""
from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from yokohama_paths import bootstrap as _bootstrap   # noqa: E402
TOOLKIT = _bootstrap()
for _p in (str(TOOLKIT), str(TOOLKIT / "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import lab_api  # noqa: E402

# model -> list of CANDIDATE port names, in the order the template declares them.
# Candidates come from the two conventions PT uses for end devices
# (`FastEthernet0` for a single FE, `GigabitEthernet0` for a single GE), and are
# deliberately wrong where the truth is unknown -- the probe is what decides.
CANDIDATES: dict[str, list[str]] = {
    # --- industrial switching / routing (template-derived, being confirmed) ---
    "IE-2000":     ["GigabitEthernet1/1", "FastEthernet1/1"],
    "IE-3400":     ["GigabitEthernet1/1", "GigabitEthernet1/2"],
    "IE-9320":     ["GigabitEthernet1/0/1", "GigabitEthernet1/0/2"],
    "IR1101":      ["GigabitEthernet0/0/0", "FastEthernet0/0/1"],
    "CGR1240":     ["GigabitEthernet0/1", "FastEthernet2/3"],
    "ISA-3000":    ["GigabitEthernet1/1", "GigabitEthernet1/2"],
    # --- IoE / OT controllers ---
    "PLC-PT":      ["GigabitEthernet0"],
    "HMI-PT":      ["GigabitEthernet0"],
    "NetworkController": ["GigabitEthernet0", "GigabitEthernet1"],
    "DataHistorianServer": ["GigabitEthernet0", "GigabitEthernet1"],
    "CyberObserver": ["GigabitEthernet0", "GigabitEthernet1"],
    "Sniffer":     ["Ethernet1", "Ethernet2"],
    # --- IoE sensors / actuators (all single eCopperFastEthernet) ---
    "RFID Reader":         ["FastEthernet0"],
    "Motion Detector":     ["FastEthernet0"],
    "Temperature Monitor": ["FastEthernet0"],
    "Smoke Detector":      ["FastEthernet0"],
    "Water Level Monitor": ["FastEthernet0"],
    "Siren":               ["FastEthernet0"],
    "Smart LED":           ["FastEthernet0"],
    "Trip Sensor":         ["FastEthernet0"],
    "Power Meter":         ["FastEthernet0"],
    "Webcam":              ["FastEthernet0"],
    # --- end systems / wireless ---
    "Server-PT":   ["FastEthernet0"],
    "PC-PT":       ["FastEthernet0"],
    "Laptop-PT":   ["FastEthernet0"],
    "7960":        ["FastEthernet0"],
    "AccessPoint-PT-N": ["Port 0"],
    "LAP-PT":      ["GigabitEthernet0"],
    "WLC-3504":    ["GigabitEthernet0/1", "GigabitEthernet0/2"],
    "Meraki-MX65W": ["GigabitEthernet0", "Internet 1"],
}

# Models that have no usable copper port at all; listed so the probe records
# their absence rather than failing to cable them silently.
NO_COPPER = ["Metal Sensor", "Temperature Sensor", "Photo Sensor", "Wind Sensor",
             "Generic Environment Sensor", "MCU-PT", "Beacon"]


def build(out: Path) -> dict:
    models, modules = lab_api.load_templates(str(TOOLKIT / "tools" / "device_templates.json"))
    lab = lab_api.Lab(str(TOOLKIT / "tools" / "network_seed.xml"), models, modules)
    lab.prune_seed_devices()
    layout = lab_api.Layout()

    def add(model, name, group):
        p = layout.place(name, model, group=group)
        return lab.add_device(model, name, p.x, p.y)

    probes: dict[str, dict] = {}
    industrial = ["IE-2000", "IE-3400", "IE-9320", "IR1101", "CGR1240", "ISA-3000"]
    # One 24-port access switch per chunk.  Chunking counts *candidate ports*,
    # not models: a model with two candidates consumes two switch ports, and
    # running out of ports must never be mistaken for a rejected port name.
    groups: list[tuple[str, list[str]]] = [("industrial", industrial)]

    def chunk(models_: list[str], budget: int = 22) -> list[list[str]]:
        out, cur, used = [], [], 0
        for m in models_:
            n = len(CANDIDATES.get(m, []))
            if cur and used + n > budget:
                out.append(cur)
                cur, used = [], 0
            cur.append(m)
            used += n
        if cur:
            out.append(cur)
        return out

    rest = [m for m in CANDIDATES if m not in industrial]
    for i, members in enumerate(chunk(rest)):
        groups.append((f"edge{i + 1}", members))

    for group, members in groups:
        sw = add("2960-24TT", f"PROBE-SW-{group.upper()}", group)
        port = 1
        for m in members:
            if m not in CANDIDATES:
                continue
            dev = add(m, f"P-{m.replace(' ', '')[:18]}", group)
            got = []
            for cand in CANDIDATES[m]:
                if port > 24:
                    break
                try:
                    lab.link(sw, f"FastEthernet0/{port}", dev, cand)
                    got.append({"candidate": cand, "switch_port": f"FastEthernet0/{port}"})
                    port += 1
                except Exception as exc:                    # noqa: BLE001
                    got.append({"candidate": cand, "error": str(exc)})
            probes[m] = {"device": lab._els[dev].findtext("ENGINE/NAME"),
                         "ports_tried": got}
    for m in NO_COPPER:
        if m in models:
            try:
                add(m, f"P-{m.replace(' ', '')[:18]}", "nocable")
                probes[m] = {"device": f"P-{m.replace(' ', '')[:18]}", "ports_tried": [],
                             "note": "placed unlinked (no cabled port type)"}
            except Exception as exc:                        # noqa: BLE001
                probes[m] = {"error": str(exc)}

    out.parent.mkdir(parents=True, exist_ok=True)
    lab.save(str(out))
    (out.with_suffix(".probes.json")).write_text(json.dumps(probes, indent=1, sort_keys=True))
    return probes


def read(saved: Path) -> dict:
    """Read back what PT kept: LINK PORT strings keyed by device name."""
    models, modules = lab_api.load_templates(str(TOOLKIT / "tools" / "device_templates.json"))
    lab = lab_api.Lab.from_file(str(saved), models, modules) if hasattr(lab_api.Lab, "from_file") else None
    raw = saved.read_bytes()
    if raw[:1] != b"<":
        import pt9
        raw = pt9.decode(str(saved), "pkt", verify_tag=False).encode()
    root = ET.fromstring(raw)
    names = {}
    for d in root.iter("DEVICE"):
        sid = d.findtext("ENGINE/SAVE_REF_ID")
        nm = d.findtext("ENGINE/NAME")
        if sid:
            names[sid] = nm
    out: dict[str, list[dict]] = {}
    for net in root.iter("NETWORK"):
        for lk in net.iter("LINK"):
            cab = lk.find("CABLE")
            if cab is None:
                continue
            fr, to = cab.findtext("FROM"), cab.findtext("TO")
            ports = [e.text for e in cab.findall("PORT")]
            if len(ports) < 2:
                continue
            for end, other, p in ((fr, to, ports[0]), (to, fr, ports[1])):
                nm = names.get(end)
                if nm and nm.startswith("P-"):
                    out.setdefault(nm, []).append(
                        {"port": p, "peer": names.get(other)})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=ROOT / "build" / "probe_ports.pkt")
    ap.add_argument("--read", type=Path, default=None)
    a = ap.parse_args(argv)
    if a.read:
        got = read(a.read)
        print(json.dumps(got, indent=1, sort_keys=True))
        return 0
    probes = build(a.out)
    print(f"probe written: {a.out}  ({len(probes)} models)")
    for m, v in sorted(probes.items()):
        tried = ", ".join(p.get("candidate", "?") for p in v.get("ports_tried", []))
        print(f"  {m:24s} -> {tried or v.get('note', '')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
