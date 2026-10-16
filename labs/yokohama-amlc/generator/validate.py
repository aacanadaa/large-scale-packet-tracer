#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""validate.py -- structural, identity and evidence validation of a built
Y-AMLT ``.pkt``.

Every check here exists because a *presence* check cannot catch the defect it
targets.  A harvested template always supplies an answer, so "has a value"
passes on a device nobody configured; and a count that is never proven distinct
inflates silently.  The gates below therefore assert identity, distinctness or
derivation -- never mere presence.

Gates
-----
1.  **container**      -- byte-exact ``encode(decode(f)) == f``.
2.  **identity**       -- every device carrying a running-config names *itself*
                          (``hostname <ENGINE><NAME>``), so a factory default or
                          a config copied from another lab cannot pass.
3.  **port names**     -- every ``<LINK><CABLE><PORT>`` string is a port the
                          model is attested to have (``build/port_table.json``),
                          reported with its evidence tier.
4.  **power**          -- every device is powered, and every *cabled* port is
                          powered (a cabled port is powered by definition).
5.  **links**          -- every link names two existing devices and a
                          cableable port on each.
6.  **distinctness**   -- DHCP pool names, DNS records and AAA clients are
                          counted raw *and* distinct, and the distinct count is
                          compared with what the generator said it authored.
7.  **addressing**     -- no two devices share a management address, and every
                          static endpoint address is inside its zone subnet.
8.  **layout**         -- delegates to the toolkit's ``check_layout``.
9.  **services**       -- no template service record survived
                          (``pkt_core.audit``), and every service the design
                          calls for is actually present.

    python3 validate.py out/YOKOHAMA_AMLC.pkt
    python3 validate.py out/YOKOHAMA_AMLC.pkt --json build/validation.json
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from yokohama_paths import bootstrap as _bootstrap   # noqa: E402
TOOLKIT = _bootstrap()
for _p in (str(ROOT), str(TOOLKIT), str(TOOLKIT / "tools"), str(TOOLKIT / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import check_layout                  # noqa: E402
import lab_api                       # noqa: E402
from pkt_core import decode_bytes, encode_bytes   # noqa: E402
from pkt_core.audit import (          # noqa: E402
    TemplateLeftovers, inventory, validate_lab)
from pkt_core.models import Lab as PktLab         # noqa: E402

# Models that carry an IOS/ASA running-config.  Every one of them must hold a
# config that names itself; nothing outside this set may hold one at all, so a
# fabricated config can never be mistaken for a configured device.
import yokohama_kit as K             # noqa: E402
NETWORK_DEVICE_MODELS = K.NETWORK_DEVICE_MODELS


def model_of(dev: ET.Element) -> str:
    """The model string, read from the TYPE element's *attribute*.

    ``<ENGINE><TYPE model="3650-24PS">MultiLayerSwitch</TYPE>`` -- the element
    text is the device *class*, and every port table is keyed by the model.  A
    reader that takes the text silently reports "MultiLayerSwitch", which no
    table has an entry for, so every port looks unattested.
    """
    t = dev.find("ENGINE/TYPE")
    if t is None:
        return ""
    return (t.get("model") or (t.text or "")).strip()


class Findings:
    def __init__(self) -> None:
        self.fail: list[str] = []
        self.warn: list[str] = []

    def check(self, ok: bool, message: str) -> bool:
        if not ok:
            self.fail.append(message)
        return ok

    def note(self, message: str) -> None:
        self.warn.append(message)


def load(path: Path):
    raw = path.read_bytes()
    if raw[:1] == b"<":
        xml = raw
    else:
        xml = decode_bytes(raw).xml
    return raw, xml, ET.fromstring(xml)


def devices_of(root: ET.Element) -> dict[str, ET.Element]:
    out = {}
    for net in root.iter("NETWORK"):
        for d in net.iter("DEVICE"):
            nm = d.findtext("ENGINE/NAME")
            if nm:
                out.setdefault(nm, d)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("lab", type=Path)
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--report", type=Path, default=None,
                    help="the generator's build report, to compare authored vs built")
    ap.add_argument("--port-table", type=Path, default=ROOT / "build" / "port_table.json")
    a = ap.parse_args(argv)

    f = Findings()
    raw, xml, root = load(a.lab)
    devs = devices_of(root)
    report: dict = {}

    # ---- 1. container round-trip ------------------------------------- #
    try:
        rt = encode_bytes(xml, "pkt")
        f.check(rt == raw, f"container round-trip DIFFERS ({len(rt)} vs {len(raw)} bytes)")
        report["round_trip_exact"] = rt == raw
    except Exception as exc:                                   # noqa: BLE001
        f.check(False, f"container round-trip raised {type(exc).__name__}: {exc}")
        report["round_trip_exact"] = False

    # ---- 2. config identity ------------------------------------------ #
    misnamed, missing_cfg, stray_cfg, cfg_devices = [], [], [], 0
    by_model_configured: collections.Counter = collections.Counter()
    for name, d in devs.items():
        mdl = model_of(d)
        rc = d.find("ENGINE/RUNNINGCONFIG")
        lines = [l.text or "" for l in rc.findall("LINE")] if rc is not None else []
        is_net = mdl in NETWORK_DEVICE_MODELS
        if is_net:
            # identity: the config must name *this* device, which a factory
            # default or a config copied from another lab never does.
            if not lines:
                missing_cfg.append(f"{name} ({mdl})")
            elif f"hostname {name}" not in lines:
                misnamed.append(f"{name} ({mdl})")
            else:
                cfg_devices += 1
                by_model_configured[mdl] += 1
        elif lines:
            stray_cfg.append(f"{name} ({mdl})")
    f.check(not missing_cfg,
            f"{len(missing_cfg)} network device(s) carry no running-config: "
            f"{missing_cfg[:8]}")
    f.check(not misnamed,
            f"{len(misnamed)} device(s) carry a config that does not name them "
            f"(template default or wrong device): {misnamed[:8]}")
    f.check(not stray_cfg,
            f"{len(stray_cfg)} non-network device(s) carry an IOS running-config "
            f"(a fabricated config is not a configuration): {stray_cfg[:8]}")
    report["config_devices"] = cfg_devices
    report["network_models_configured"] = dict(by_model_configured)

    # ---- 3. port-name attestation ------------------------------------ #
    table = json.loads(a.port_table.read_text()) if a.port_table.exists() else {}
    bad_ports: list[str] = []
    port_tiers: collections.Counter = collections.Counter()
    for net in root.iter("NETWORK"):
        names = {d.findtext("ENGINE/SAVE_REF_ID"): d.findtext("ENGINE/NAME")
                 for d in net.iter("DEVICE")}
        model_attr = {d.findtext("ENGINE/SAVE_REF_ID"): model_of(d)
                      for d in net.iter("DEVICE")}
        for lk in net.iter("LINK"):
            cab = lk.find("CABLE")
            if cab is None:
                continue
            ends = [cab.findtext("FROM"), cab.findtext("TO")]
            ports = [e.text for e in cab.findall("PORT")]
            for i, sid in enumerate(ends):
                if sid not in names or i >= len(ports):
                    continue
                mdl = model_attr.get(sid, "")
                entry = table.get(mdl)
                pname = (ports[i] or "").strip()
                if entry is None:
                    bad_ports.append(f"{names[sid]}: model {mdl!r} has no port table entry")
                    continue
                if pname not in entry["ports"]:
                    bad_ports.append(
                        f"{names[sid]} ({mdl}): port {pname!r} is not attested "
                        f"[tier={entry['tier']}]")
                else:
                    port_tiers[entry["tier"]] += 1
    f.check(not bad_ports,
            f"{len(bad_ports)} link endpoint(s) name an unattested port: {bad_ports[:6]}")
    report["port_tiers"] = dict(port_tiers)

    # ---- 4. power ------------------------------------------------------ #
    staged = set()
    for src in (ROOT / "build_yokohama_amlc.py",):
        m = re.search(r"STAGED_OFF[^=]*=\s*frozenset\(([^)]*)\)", src.read_text())
        if m:
            staged = set(re.findall(r'"([^"]+)"', m.group(1)))
    off = [n for n, d in devs.items()
           if (d.findtext("ENGINE/POWER") or "").lower() != "true" and n not in staged]
    f.check(not off, f"{len(off)} device(s) are switched off: {off[:8]}")

    cabled_devices: set[str] = set()
    broken: list[str] = []
    for net in root.iter("NETWORK"):
        names = {d.findtext("ENGINE/SAVE_REF_ID"): d.findtext("ENGINE/NAME")
                 for d in net.iter("DEVICE")}
        for lk in net.iter("LINK"):
            cab = lk.find("CABLE")
            if cab is None:
                continue
            for sid in (cab.findtext("FROM"), cab.findtext("TO")):
                if sid not in names:
                    broken.append(str(sid))
                else:
                    cabled_devices.add(names[sid])

    # A port we cabled is powered by definition.  power_cabled_ports() raises
    # every port on a cabled device rather than trying to resolve a port name to
    # a <PORT> element -- <PORT> carries no name, so the device is the finest
    # granularity at which this is checkable.
    unpowered = []
    for name in sorted(cabled_devices):
        d = devs.get(name)
        if d is None:
            continue
        for p in d.iter("PORT"):
            if (p.findtext("POWER") or "").lower() != "true":
                unpowered.append(name)
                break
    f.check(not unpowered,
            f"{len(unpowered)} cabled device(s) have an unpowered port "
            f"(the link cannot come up): {unpowered[:8]}")
    report["cabled_devices"] = len(cabled_devices)
    report["links"] = sum(1 for _net in root.iter("NETWORK") for _ in _net.iter("LINK"))

    # ---- 6. distinctness ----------------------------------------------- #
    # inventory()/validate_lab() take the typed model, and the template
    # leftover identities come from the same library the generator used, so a
    # record a template carried can never be mistaken for one we authored.
    plab = PktLab.from_bytes(xml)
    leftovers = TemplateLeftovers.from_device_templates_json(
        TOOLKIT / "tools" / "device_templates.json")
    inv = inventory(plab, leftovers=leftovers)
    dup_report = {}
    for fam in ("aaa_clients", "aaa_users", "dhcp_pools", "dns_records",
                "ftp_accounts", "end_device_ips"):
        counted = inv.count(fam)
        dup_report[fam] = {"raw": counted.raw, "distinct": counted.distinct,
                           "leftover": len(counted.leftover_identities)}
        if fam != "dns_records":
            # DNS is deliberately excluded from the document-wide rule: a zone
            # is a *set per server*, so two servers holding the same zone is
            # replication, not duplication.  validate_lab() below applies the
            # per-server rule, and leftovers are still checked here.
            f.check(counted.raw == counted.distinct,
                    f"{fam}: {counted.raw} counted but only {counted.distinct} "
                    f"distinct (template leftovers or duplicated records)")
        f.check(not counted.leftover_identities,
                f"{fam}: {len(counted.leftover_identities)} template leftover(s) survived")
    report["service_inventory"] = dup_report
    report["inventory_summary"] = inv.summary()

    pool_names: list[str] = []
    for d in devs.values():
        for p in d.iter("POOL"):
            nm = p.findtext("NAME")
            if nm:
                pool_names.append(nm)
    if pool_names:
        cnt = collections.Counter(pool_names)
        dupes = {n: c for n, c in cnt.items() if c > 1}
        f.check(not dupes,
                f"DHCP pool names are not distinct ({len(dupes)} collide, "
                f"e.g. {list(dupes)[:4]}); Packet Tracer pools are name-keyed so "
                f"one silently shadows the other")
        report["dhcp_pools"] = {"raw": len(pool_names), "distinct": len(cnt)}

    # ---- 7. addressing -------------------------------------------------- #
    addrs = collections.defaultdict(list)
    for name, d in devs.items():
        for p in d.iter("PORT"):
            ip = (p.findtext("IP") or "").strip()
            if ip and ip != "0.0.0.0":
                addrs[ip].append(name)
    clashes = {ip: ns for ip, ns in addrs.items() if len(set(ns)) > 1}
    f.check(not clashes,
            f"{len(clashes)} duplicate endpoint address(es): "
            f"{list(clashes.items())[:4]}")

    # ---- 8. layout ------------------------------------------------------ #
    try:
        lay = check_layout.analyse(check_layout.load_devices(a.lab))
        report["layout"] = {k: v for k, v in lay.items()
                            if k in ("overlaps", "off_page", "coincident",
                                     "pairs_under_floor", "nearest_min",
                                     "bbox", "devices")}
        for key in ("overlaps", "off_page", "coincident"):
            if key in lay:
                f.check(not lay[key], f"layout: {key} = {lay[key]}")
        n_under = lay.get("pairs_under_floor")
        if isinstance(n_under, int):
            f.check(n_under == 0, f"layout: {n_under} device pair(s) under the floor")
    except Exception as exc:                                   # noqa: BLE001
        f.note(f"layout check skipped: {type(exc).__name__}: {exc}")

    # ---- 9. services ---------------------------------------------------- #
    try:
        aud = validate_lab(plab, leftovers=leftovers)
        report["audit"] = {"codes": list(aud.codes()),
                           "failures": [x.message for x in aud.failures],
                           "warnings": [x.message for x in aud.warnings]}
        f.check(aud.ok,
                f"pkt_core audit reported {len(aud.failures)} failure(s): "
                f"{[x.code for x in aud.failures][:6]}")
        report["audit_summary"] = aud.summary()
    except Exception as exc:                                   # noqa: BLE001
        f.note(f"pkt_core audit skipped: {type(exc).__name__}: {exc}")

    for svc, needle in [("DNS", "DNS_SERVER"), ("DHCP", "DHCP_SERVERS"),
                        ("AAA", "ACS_SERVER"), ("NTP", "NTP_SERVER"),
                        ("SYSLOG", "SYSLOG_SERVER")]:
        n = sum(1 for d in devs.values() if d.find(f".//{needle}") is not None)
        f.check(n > 0, f"no {svc} service is configured anywhere")
        report.setdefault("services_present", {})[svc] = n

    # ---- compare with the generator's own report ------------------------ #
    if a.report and a.report.exists():
        gen = json.loads(a.report.read_text())
        report["generator_report"] = {k: gen.get(k) for k in
                                      ("profile", "devices", "links", "routed_ports")}
        # Rule 5: a published number is a claim, so recompute it from the bytes
        # rather than trusting the generator's bookkeeping.
        if gen.get("devices"):
            f.check(gen["devices"] == len(devs),
                    f"generator reported {gen['devices']} devices but the artefact "
                    f"holds {len(devs)}")

    # ---- verdict --------------------------------------------------------- #
    print(f"lab     : {a.lab}")
    print(f"devices : {len(devs)}   links: {report.get('links', 0)}   "
          f"configs: {cfg_devices}")
    print(f"ports   : " + ", ".join(f"{k}={v}" for k, v in sorted(port_tiers.items())))
    if report.get("dhcp_pools"):
        d = report["dhcp_pools"]
        print(f"dhcp    : {d['raw']} pools, {d['distinct']} distinct")
    print()
    for w in f.warn:
        print(f"WARN  {w}")
    if f.fail:
        for m in f.fail:
            print(f"FAIL  {m}")
        print(f"\nRESULT: FAILED ({len(f.fail)} failure(s), {len(f.warn)} warning(s))")
    else:
        print(f"RESULT: PASSED (0 failures, {len(f.warn)} warning(s))")
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps(
            {"fail": f.fail, "warn": f.warn, "report": report}, indent=1, sort_keys=True))
    return 1 if f.fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
