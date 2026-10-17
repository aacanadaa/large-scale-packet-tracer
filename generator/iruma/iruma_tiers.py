#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""IRUMA-AB's semantic tier bands -- one definition, three consumers.

The bands have to agree in three places, and they used to be three separate
lists:

* the generator's ``GROUP_MERGE`` decides which band a device is built into;
* ``finalise_lab``'s repack decides which band a device is *packed* into, and it
  does that from the device **name**;
* ``draw_topology`` decides which band a device is *drawn* in.

When they disagree the failure is silent.  The repack still succeeds; it just
puts every device in one band, and the model repacks into the tangle the bands
existed to prevent.  That is what happened here: the toolkit's built-in rules
are another lab's naming convention, and 361 of these 392 devices matched none
of them.

So the rules live here once.  :func:`write_tier_map` emits them in the shape
``lab_api.load_tier_map`` reads, and ``run_all.sh`` hands that file to the single
writer with ``--tiers``.
"""
from __future__ import annotations

import json
from pathlib import Path

# (tier, colour, label) -- order is the vertical order on the page, and it is
# chosen so that each band is cabled mostly to its neighbours.
TIERS: list[tuple[str, str, str]] = [
    ("T1-edge-carrier",   "#7b1fa2", "Carrier & external liaison edge"),
    ("T2-core-noc",       "#c62828", "Base backbone & NetOps"),
    ("T3-datacentres",    "#1565c0", "Air defence & mission DC (+ backup)"),
    ("T4-opsec",          "#4a148c", "Operations-security enclave"),
    ("T5-aoc-tower",      "#00695c", "Air Operations Centre / tower"),
    ("T6-atc-navaid",     "#ef6c00", "Air traffic control & navaids"),
    ("T7-tenants",        "#f9a825", "Tenant squadrons, hangars, hospital"),
    ("T8-apron",          "#2e7d32", "Apron, flight line & vehicles"),
    ("T9-weather",        "#00838f", "Air Weather Squadron"),
    ("T10-depot-pol",     "#5d4037", "Air depots & bulk fuel farm"),
    ("T11-facilities",    "#0277bd", "Security, utilities & wireless"),
    ("T12-mobile",        "#455a64", "Mobile estate"),
]

# (tier, name prefixes), first match wins.  Order matters: the specific tokens
# come first, so ``SIGINT-`` is claimed by the tenant band before the district
# police's ``SI-`` token can see it.
TIER_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("T1-edge-carrier", (
        "CARRIER-", "IRM-EDGE-RTR", "FW-INTERNET", "EDGE-DMZ",
        "MOD-BACKBONE-GW", "YOKOTA-ATC-GW", "JWS-II-WX-GW", "SPPOL-AIR-GW",
        "SIGINT-BRANCH-GW", "LIAISON-FILE-SVR", "EDGE-PROXY",
        "EDGE-MAIL-RELAY")),
    ("T2-core-noc", (
        "IRM-CORE-SW", "IRM-CORE-RTR", "IRM-WAN-EDGE", "IRM-DCI-RTR",
        "IRM-NETOPS-GW", "NETOPS-")),
    ("T3-datacentres", (
        "MDC-", "BDC-", "FW-MDC", "FW-BDC", "DNS-SVR", "DHCP-SVR", "NTP-SVR",
        "SYSLOG-SVR", "AAA-SVR", "TFTP-ARCHIVE", "ADSYS-OPS", "SORTIE-TASK",
        "MISSION-PLAN", "ATO-SVR", "MX-MIS", "SUPPLY-APP", "FLTREC-SVR",
        "AIRFIELD-OPS", "WX-INTEG", "PERS-SVR", "TRAINING-LMS", "IRM-PORTAL",
        "PKI-CA", "NETFLOW-SVR", "DATA-HISTORIAN")),
    ("T4-opsec", ("OPSEC-",)),
    ("T5-aoc-tower", (
        "AOC-", "TWR-", "GND-MOVEMENT", "APCH-DISPLAY", "FLT-DATA")),
    ("T6-atc-navaid", (
        "ATC-", "GCA-", "ASR-", "NAVAID-", "ATIS-", "D-ATIS-", "PAR-CTL",
        "TACAN-CTL", "ILS-CTL", "RWY-LIGHT", "TWY-LIGHT", "APCH-LGT",
        "ARFF-ALERT")),
    ("T7-tenants", (
        "402SQ-", "ARWHAS-", "FCS-", "EWC-", "CAMG-", "CACE-", "ASAR-",
        "SIGINT-", "IMP-", "SI-", "IHS-")),
    ("T8-apron", (
        "APRON-", "FLT-LINE", "FUEL-CTL", "HOTFUEL", "RWY-SWEEP", "TOW-TRACTOR",
        "GSE-MAINT", "ARFF-DISP", "BIRD-CONTROL", "FOLLOWME", "ARFF-CMD",
        "ARFF-VEH", "GND-VEH")),
    ("T9-weather", (
        "IWS-", "WIND-DET", "TEMP-DET", "HUMID-DET", "PRESS-DET", "RAIN-DET",
        "VIS-DET", "RVR-DET")),
    ("T10-depot-pol", ("3DEP-", "4DEP-", "DEP-", "POL-")),
    ("T11-facilities", (
        "SEC-", "CCTV-NVR", "ACS-DOOR", "PERIM-", "GATE-HOUSE", "UTIL-",
        "SUBSTN-", "GENERATOR-", "UPS-CTL", "PWR-METER", "IRM-WLC", "WLAN-",
        "IRM-AP-")),
    ("T12-mobile", ("EFB-", "HANDSET-")),
]

FALLBACK = "T11-facilities"


def tier_of(name: str) -> str:
    """Which band this device belongs to, from its own hostname."""
    for tier, needles in TIER_RULES:
        if any(name.startswith(n) for n in needles):
            return tier
    return FALLBACK


def write_tier_map(path: str | Path) -> int:
    """Write the rules in the shape ``lab_api.load_tier_map`` reads.

    Prefixes are literal, so each one is anchored with ``^`` and escaped of the
    only regex metacharacter a hostname realistically contains.
    """
    rules = [{"tier": tier,
              "patterns": [f"^{p.replace('-', r'\\-')}" for p in needles]}
             for tier, needles in TIER_RULES]
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"rules": rules}, indent=1) + "\n")
    return len(rules)
