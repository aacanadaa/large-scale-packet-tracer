# IRUMA-AB — provenance of every fact in this model

This lab is a **model**, not a survey. Some of it is sourced from public
material about JASDF Iruma Air Base; some of it is modelled from JASDF
convention and is a plausible network design for a base of this kind rather than
a description of the real one. The two are kept apart here so that a reader can
tell which is which, and so that nobody cites this repository as a source about
the actual base.

The rule applied throughout: **if a fact could not be sourced, it is marked as
modelled.** Nothing in this document is presented as confirmed unless a source
is listed for it.

---

## 1. Confirmed — organisation

Sourced from the base's own unit list
(`mod.go.jp/asdf/iruma/butai/`, retrieved for this build) and Japanese Wikipedia.

| Unit (JA) | Romaji / English | In this model as |
| --- | --- | --- |
| 中部航空方面隊 | Central Air Defence Force (CADF), HQ | `T5-aoc-tower` zone + CADF HQ support flight tenant |
| 中部航空警戒管制団 | Central Aircraft Control & Warning Wing (CACW) | air-defence mission system (`ADSYS-OPS-01`), ASR plot extractor |
| 基地業務群 | Base Group — facilities, **base communications**, cyber, supply | `T2-core-noc` NetOps enclave (`NETOPS-*`) |
| 中部高射群 | Central Air Defence Missile Group (Patriot) | tenant `CAMG` |
| 中部航空方面隊司令部支援飛行隊 | CADF HQ Support Flight (T-4 "Silver Impulse", U-4) | tenant `SI` |
| 中部航空施設隊 | Central Air Facility Squadron (CACE) | tenant `CACE` |
| 航空救難団 | **Air Rescue Wing, HQ** | tenant `ARWHAS` (the wing's Iruma flying unit is the helicopter airlift squadron) |
| 電子戦隊 / 電子飛行測定隊 | Electronic Warfare / Electronic Flight Measurement Squadron | tenant `EWC` |
| 作戦システム管理群 | Operations System Management Group (OSW) | MDC mission applications |
| 第2輸送航空隊 | **2nd Tactical Airlift Group (2TAG)**, incl. 第402飛行隊 | tenant `402SQ` |
| 入間管制隊 | Iruma ATC Squadron (under 航空保安管制群, HQ Fuchu) | `T6-atc-navaid` zone |
| 入間気象隊 | Iruma Weather Squadron (under 航空気象群, HQ Fuchu) | `T9-weather` zone |
| 飛行点検隊 | Flight Check Squadron (U-125 / U-680A) | tenant `FCS` |
| 航空医学安全研究隊 | Aeromedical Safety Research Unit (2025) | tenant `ASAR` |
| 入間地方警務隊 | Iruma District Police (MOD-direct) | tenant `IMP` |
| 第3補給処 / 第4補給処 | 3rd / 4th Air Depot | `3DEP-*` / `4DEP-*` |
| 自衛隊入間病院 | JSDF Iruma Hospital (2022, 10 depts, 60 beds) | `IHS-*` |
| 情報本部 電波部 入間通信支所 | Signals Intelligence HQ radio branch, Iruma detachment | `SIGINT-*` |

### Corrections applied to an earlier draft

Five premises that an early draft of this lab assumed were wrong, and the model
was changed to match the sources rather than the assumption:

| Assumed | Actually |
| --- | --- |
| 1st Air Wing at Iruma | It is at **Hamamatsu** — not modelled |
| 管制航空団 (ATC Wing) | No such unit; the group HQ is at **Fuchu**, only 入間管制隊 is here |
| 気象群 at Iruma | The group HQ is at **Fuchu**; only 入間気象隊 is here |
| 救難教育隊 at Iruma | At **Komaki** — not modelled |
| Two runways (~2,000 m and ~2,700 m) | **One** runway, 17/35, 2,000 × 45 m |

Also corrected: **C-130H was never based at Iruma** (Komaki/Miho);
**UH-60J and U-125A are not based here** — Iruma's rescue squadron disbanded in
1968 and its U-125 is the *flight-check* variant, so the rescue tenant is
modelled as a **helicopter airlift** squadron (CH-47J), which is what the base
actually hosts. The C-1 retired from Iruma on 2025-03-14, so the airlift
squadron is modelled on C-2 / RC-2 / U-4.

---

## 2. Confirmed — airfield, navaids and radio

| Fact | Value | Where it is used |
| --- | --- | --- |
| ICAO / location | RJTJ, Sayama + Iruma, Saitama, elev. 90 m | design document |
| Runway | **one**, 17/35, 2,000 × 45 m asphalt; parallel taxiway, ~10 connectors | `ILS-CTL-17`, `ILS-CTL-35`, `RWY-LIGHT-CTL-01`, `TWY-LIGHT-CTL-01` |
| Base area | ≈3 km² | design document |
| TACAN | station 入間, ident **YLT**, maintained by 入間管制隊. **No VOR/DME published** | `TACAN-CTL-01`, `NAVAID-MON-01`; no VOR/DME device is modelled |
| GND | **275.800** MHz | `GND-MOVEMENT-CTL` description |
| TWR | 122.05 / 126.2 / 236.8 / **322.2** MHz | `TWR-POS-CTL-01` description |
| GCA | 125.30 / 225.40 / **335.60** / 258.20 MHz | `GCA-RADAR-SVR-01` description |
| APP / DEP | provided by **Yokota AB** (270.6 / 363.8 MHz) | `YOKOTA-ATC-GW` edge circuit |
| RESCUE | 123.1x / **138.05** / 247.0x MHz | `ARFF-DISP-SVR` description |
| Airspace | Class D | design document |
| Weather system | tri-service **JWS-II**, run by 航空気象群 via 中枢気象隊 | `IWS-JWS-CLIENT` + edge circuit to Fuchu |
| Aircraft types | C-2, RC-2, U-4, T-4, U-125, U-680A, CH-47J, Patriot PAC-3 | tenant roles |
| No fighter operations | agreement with the surrounding residential areas | no fighter squadron is modelled |

---

## 3. Modelled, not sourced — read this before citing anything

The following appear in the lab because **every air base of this kind has
them**, not because they were confirmed for Iruma. Each is marked with
`[MODELLED]` in the device role string where the role text names the facility.

| Modelled element | Why it is modelled | Not sourced because |
| --- | --- | --- |
| Control tower and its positions | required for the ATC function the base certainly has | tower identity/equipment not published |
| Bulk fuel farm (POL), 6 tanks | every air base has bulk AVTUR storage | no public source for Iruma's farm |
| Ammunition storage / arms monitoring | standard base function | not published |
| ARFF (crash crew) station and vehicles | required by the runway | station identity not published |
| Passenger / VIP terminal | modelled only as an edge liaison service, not as a building | not published |
| The entire addressing plan, VLAN plan, OSPF areas, ASNs and device hostnames | these are this model's design | no public source exists for the real one |
| The six tank designations and their capacities | illustrative | not published |
| `BIRD-CONTROL-SVR` | bird-strike control is universal at airfields | not published for Iruma |
| Saitama Prefectural Police Air Corps hangar | the police air corps **is** co-located; the hangar and its network are modelled | facility details not published |
| Solar / battery / wind at the base | modelled as a modern base energy estate | not published |

**Not modelled at all, deliberately:**

* **Any United States unit.** The 1987 arrangement was *temporary joint use*
  under SOFA Art. II(4)(b), administered as part of **Yokota AB**; no US flying
  unit is based at Iruma. The only US-facing element in the model is a control
  liaison circuit to Yokota AB, because Yokota really does provide Iruma's
  approach and departure control.
* **A JGSDF element.** 入間分屯地 (1963) status could not be confirmed, so it is
  not asserted.
* **Civil airline service.** The 入間基地共用化構想 civil joint-use concept is
  unsourced and is not modelled.

---

## 4. Platform facts used to build the file

These are not about Iruma; they are the Packet Tracer facts the generator
depends on, and each was measured on this machine with Packet Tracer 9.0.1
rather than assumed.

| Fact | Evidence |
| --- | --- |
| The lab **opens** in Packet Tracer 9.0.1 | `tools/pt_accept.py`, verdict read from the window title, with a known-good control in the same batch |
| Every port name resolves | `build/port_table.json` records the tier of every name; `validate.py` refuses a link endpoint whose name is not in it |
| `7960` → `Switch` (not `FastEthernet0`) | measured; the rejected names are recorded in `tools/port_table.py` |
| `Cloud-PT` → `Port 0` (not `GigabitEthernet0`) | measured; every other candidate name was rejected |
| `WLC-3504` → `GigabitEthernet1` (not `GigabitEthernet0/1`) | measured |
| A container round-trips byte-exactly | `finalise_lab.py` gate 1, `round-trip: byte-exact` |
| The lab renders and converges | `tools/pt_runtime_verify.py` (see `VALIDATION.md`) |

## Sources

* <https://en.wikipedia.org/wiki/Iruma_Air_Base>
* <https://ja.wikipedia.org/wiki/入間基地> — tenant units, ATC/nav frequencies, base data
* <https://ja.wikipedia.org/wiki/第2輸送航空隊>
* <https://ja.wikipedia.org/wiki/中部航空方面隊>
* <https://ja.wikipedia.org/wiki/中部航空警戒管制団>
* <https://ja.wikipedia.org/wiki/中部高射群>
* <https://ja.wikipedia.org/wiki/航空救難団>
* <https://ja.wikipedia.org/wiki/入間ヘリコプター空輸隊>
* <https://ja.wikipedia.org/wiki/飛行点検隊>
* <https://ja.wikipedia.org/wiki/航空保安管制群>
* <https://ja.wikipedia.org/wiki/航空気象群>
* <https://ja.wikipedia.org/wiki/航空自衛隊第3補給処>
* <https://ja.wikipedia.org/wiki/基地業務群>
* <https://en.wikipedia.org/wiki/United_States_Forces_Japan>
* <https://www.mod.go.jp/asdf/iruma/butai/index.html> — official tenant list
* OpenStreetMap Overpass API — runway, taxiways, aprons, hangars, helipads
