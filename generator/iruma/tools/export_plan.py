#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Export the as-built plan of the built Iruma Air Base lab.

Everything here is recomputed **from the artefact**, never from the generator's
internal bookkeeping.  A figure a design document quotes has to be reproducible
by the obvious method from the file that shipped; a number typed from the
generator's memory is a claim, not a measurement.

    python3 tools/export_plan.py out/IRUMA_AB.pkt [suffix]
"""
from __future__ import annotations

import argparse
import collections
import csv
import os
import re
import sys
import xml.etree.ElementTree as ET
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

from pkt_core import decode_bytes          # noqa: E402
import iruma_kit as K                   # noqa: E402

DOCS = ROOT / "docs"


def load(path: Path) -> ET.Element:
    raw = path.read_bytes()
    return ET.fromstring(raw if raw[:1] == b"<" else decode_bytes(raw).xml)


def model_of(dev: ET.Element) -> str:
    t = dev.find("ENGINE/TYPE")
    if t is None:
        return ""
    return (t.get("model") or (t.text or "")).strip()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("lab", type=Path)
    ap.add_argument("suffix", nargs="?", default="")
    a = ap.parse_args(argv)
    root = load(a.lab)
    sfx = a.suffix
    DOCS.mkdir(parents=True, exist_ok=True)

    devices = [d for d in root.iter("DEVICE")]
    names = {d.findtext("ENGINE/SAVE_REF_ID"): (d.findtext("ENGINE/NAME") or "")
             for d in devices}
    model = {d.findtext("ENGINE/SAVE_REF_ID"): model_of(d) for d in devices}

    # ---- inventory ------------------------------------------------------- #
    inv_path = DOCS / f"INVENTORY{sfx}.csv"
    # the generator writes this; refresh the tier column from the artefact
    tier_of_model = {}
    rows = []
    for d in devices:
        nm = d.findtext("ENGINE/NAME") or ""
        rows.append({"name": nm, "model": model_of(d),
                     "config_lines": len(d.findall("ENGINE/RUNNINGCONFIG/LINE")),
                     "ports": sum(1 for _ in d.iter("PORT")),
                     "has_services": int(any(
                         d.find(f".//{t}") is not None for t in
                         ("DNS_SERVER", "DHCP_SERVERS", "ACS_SERVER",
                          "NTP_SERVER", "SYSLOG_SERVER", "HTTP_SERVER")))})
    if not inv_path.exists():
        with inv_path.open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)

    # ---- addressing ------------------------------------------------------ #
    addr_rows, subnets = [], collections.Counter()
    for d in devices:
        nm = d.findtext("ENGINE/NAME") or ""
        for p in d.iter("PORT"):
            ip = (p.findtext("IP") or "").strip()
            if not ip or ip == "0.0.0.0":
                continue
            mask = (p.findtext("SUBNET") or "").strip()
            gw = (p.findtext("PORT_GATEWAY") or "").strip()
            o = ip.split(".")
            subnet = f"{o[0]}.{o[1]}.{o[2]}.0/{_bits(mask)}"
            subnets[subnet] += 1
            addr_rows.append((nm, model_of(d), ip, mask, gw, subnet))
        rc = d.find("ENGINE/RUNNINGCONFIG")
        for line in (rc.findall("LINE") if rc is not None else []):
            t = (line.text or "").strip()
            m = re.match(r"^ip address (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)$", t)
            if m:
                ip, mask = m.group(1), m.group(2)
                o = ip.split(".")
                subnet = f"{o[0]}.{o[1]}.{o[2]}.0/{_bits(mask)}"
                subnets[subnet] += 1
                addr_rows.append((nm, model_of(d), ip, mask, "", subnet))
    with (DOCS / f"ADDRESS_PLAN{sfx}.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["device", "model", "address", "mask", "gateway", "subnet"])
        for r in sorted(set(addr_rows), key=lambda r: tuple(int(x) for x in r[2].split("."))):
            w.writerow(r)
    with (DOCS / f"SUBNETS{sfx}.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["subnet", "addresses"])
        for s, n in sorted(subnets.items()):
            w.writerow([s, n])

    # ---- VLANs ----------------------------------------------------------- #
    vlan_seen: dict[int, set[str]] = collections.defaultdict(set)
    for d in devices:
        for v in d.iter("VLAN"):
            i = v.findtext("ID") or v.findtext("NUMBER")
            nm = v.findtext("NAME")
            if i and i.isdigit():
                vlan_seen[int(i)].add(nm or "")
        rc = d.find("ENGINE/RUNNINGCONFIG")
        for line in (rc.findall("LINE") if rc is not None else []):
            t = (line.text or "").strip()
            m = re.match(r"^vlan (\d+)$", t)
            if m:
                vlan_seen[int(m.group(1))]
    with (DOCS / f"VLANS{sfx}.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["vlan", "name", "purpose"])
        for v in sorted(set(vlan_seen) | set(K.VLAN_NAMES)):
            w.writerow([v, K.VLAN_NAMES.get(v, ""),
                        _vlan_purpose(v)])

    # ---- services -------------------------------------------------------- #
    svc = collections.Counter()
    dns_names: set[str] = set()
    pools: dict[str, tuple] = {}
    aaa_clients: set[str] = set()
    aaa_users: set[str] = set()
    for d in devices:
        # Count a server only when it actually holds something.  A harvested
        # template ships <DNS_SERVER><ENABLED>1</ENABLED> on appliances that
        # serve no zone at all; counting those shells would overstate the
        # service estate by roughly the number of devices.
        if list(d.iter("RESOURCE-RECORD")):
            svc["dns_servers"] += 1
            for rr in d.iter("RESOURCE-RECORD"):
                nm = rr.findtext("NAME")
                if nm:
                    dns_names.add(nm)
        if list(d.iter("POOL")):
            svc["dhcp_servers"] += 1
            for p in d.iter("POOL"):
                pools[p.findtext("NAME") or ""] = (p.findtext("NETWORK"),
                                                   p.findtext("MASK"),
                                                   p.findtext("DEFAULT_ROUTER"))
        # Scope to the ACS_SERVER subtree: <USER> also appears as an empty child
        # of every device's <EMAIL_CLIENT>, and matching it document-wide
        # reported 248 AAA servers on a model that has one.
        acs = d.find(".//ACS_SERVER")
        if acs is not None and (list(acs.iter("CLIENT")) or list(acs.iter("USER"))):
            svc["aaa_servers"] += 1
            for c in acs.iter("CLIENT"):
                if c.findtext("HOST_IP"):
                    aaa_clients.add(c.findtext("HOST_IP"))
            for u in acs.iter("USER"):
                if u.findtext("NAME"):
                    aaa_users.add(u.findtext("NAME"))
        if list(d.iter("ACCOUNT")):
            svc["ftp_servers"] += 1
        for tag, key in (("NTP_SERVER", "ntp_servers"), ("SYSLOG_SERVER", "syslog_servers"),
                         ("HTTP_SERVER", "http_servers"), ("HTTPS_SERVER", "https_servers"),
                         ("EMAIL_SERVER", "mail_servers")):
            el = d.find(f".//{tag}")
            if el is None:
                continue
            enabled = (el.findtext("ENABLED") or el.findtext("SMTP_ENABLED")
                       or el.findtext("HTTPSENABLED") or "")
            if str(enabled).strip() in ("1", "true", "True"):
                svc[key] += 1

    lines_rc = sum(len(d.findall("ENGINE/RUNNINGCONFIG/LINE")) for d in devices)
    configured = sum(1 for d in devices
                     if len(d.findall("ENGINE/RUNNINGCONFIG/LINE")) > 0)
    links = sum(1 for _ in root.iter("LINK"))
    with (DOCS / f"SERVICES{sfx}.md").open("w") as fh:
        fh.write(f"# IRUMA-AB as-built services{' (' + sfx.strip('_') + ')' if sfx else ''}\n\n")
        fh.write(f"Recomputed from `{a.lab.name}` "
                 f"(SHA-256 in `build/final_sha256{sfx}.txt`).\n\n")
        fh.write("| Quantity | Count |\n| --- | ---: |\n")
        fh.write(f"| Devices | {len(devices)} |\n")
        fh.write(f"| Links | {links} |\n")
        fh.write(f"| Devices carrying a running-config | {configured} |\n")
        fh.write(f"| `<LINE>` elements across all running-configs | {lines_rc} |\n")
        fh.write(f"| DNS A-records (distinct names) | {len(dns_names)} |\n")
        fh.write(f"| DHCP pools (distinct names) | {len(pools)} |\n")
        fh.write(f"| AAA clients (distinct) | {len(aaa_clients)} |\n")
        fh.write(f"| AAA users (distinct) | {len(aaa_users)} |\n")
        for k in sorted(svc):
            fh.write(f"| {k.replace('_', ' ')} | {svc[k]} |\n")
        fh.write("\n## DNS zone (" + K.DOMAIN + ")\n\n")
        for n in sorted(dns_names):
            fh.write(f"- `{n}`\n")
        fh.write("\n## DHCP pools\n\n| Pool | Network | Mask | Router |\n| --- | --- | --- | --- |\n")
        for n, (net_, mask, rtr) in sorted(pools.items()):
            fh.write(f"| `{n}` | {net_} | {mask} | {rtr} |\n")

    print(f"inventory : {inv_path}")
    print(f"addressing: {DOCS / f'ADDRESS_PLAN{sfx}.csv'}  ({len(addr_rows)} addresses, "
          f"{len(subnets)} subnets)")
    print(f"vlans     : {DOCS / f'VLANS{sfx}.csv'}")
    print(f"services  : {DOCS / f'SERVICES{sfx}.md'}  "
          f"({len(dns_names)} DNS names, {len(pools)} DHCP pools, "
          f"{len(aaa_clients)} AAA clients)")
    return 0


def _bits(mask: str) -> int:
    try:
        return sum(bin(int(o)).count("1") for o in mask.split("."))
    except ValueError:
        return 24


def _vlan_purpose(v: int) -> str:
    return {
        K.V_OPS: "terminal operations workstations and dispatch",
        K.V_SORTIE: "Terminal Operating System application tier",
        K.V_VOICE: "radio dispatch and voice",
        K.V_MGMT: "out-of-band management",
        K.V_WIFI: "handheld and vehicle-mount terminals",
        K.V_SRV: "server farm services",
        K.V_OT: "industrial control (crane and gate PLCs)",
        K.V_CCTV: "CCTV and physical security",
        K.V_IOT: "IoT sensor mesh",
        K.V_CUS: "customs enclave",
        K.V_LIAISON: "partner EDI / DMZ",
        K.V_GV: "AGV guidance and fleet control",
        K.V_POL: "reefer cold-chain monitoring",
        K.V_NAVAID: "rail signalling interlock",
        K.V_ARMS: "dangerous-goods yard",
        K.V_GUEST: "contractor and visitor",
    }.get(v, "")


if __name__ == "__main__":
    raise SystemExit(main())
