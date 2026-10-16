# Y-AMLT — architecture specification

The Yokohama Automated Maritime Logistics Terminal (Y-AMLT) is a multi-zone,
high-availability model of an automated container terminal: **386 devices,
379 links** across 12 tiers, generated from `build_yokohama_amlc.py`.

This document is the design. `docs/VALIDATION.md` is what was checked and what
that proves; `docs/EVIDENCE.md` is where every format and port fact came from.

---

## 1. What the terminal does, and what the network therefore has to do

A container terminal moves boxes between three interfaces — ship, road and rail
— through a yard. Automation replaces the human drivers and crane operators with
machines under central control, which changes the network's job:

* **Safety-critical control loops.** An AGV guidance packet that is dropped is a
  vehicle that stops; a crane control packet that arrives late is a spreader
  that moves at the wrong moment. These flows need priority and a predictable
  path, not best effort.
* **A hard real-time OT estate on the same site as IT.** Crane PLCs and gate
  barriers are industrial Ethernet devices with decades-long service lives; the
  TOS is a modern application stack. They must be separable, and a broadcast
  storm in the yard must not reach the data centre.
* **Statutory separation.** Customs manifests and the NACCS link are not "another
  VLAN". They are a regulated enclave with a narrow, declared message set.
* **No maintenance window.** A terminal that stops moving boxes costs money by
  the minute, so every zone has redundant first-hop gateways and dual uplinks.

The model reflects each of those as a visible structure rather than a note.

---

## 2. Zones

| # | Zone | Site | Devices | Role |
| --- | --- | ---: | ---: | --- |
| 1 | Carrier & partner edge | 100 | 11 | transit clouds, eBGP edge, NACCS/VTS/rail/EDI gateways, partner DMZ |
| 2 | Terminal backbone & NOC | 10 / 200 | 8 | dual collapsed core, core routers, dual WAN edge, DCI, management gateway |
| 3 | Primary data centre (TDC) | 11 | 30 | spine/leaf + 24-service server farm |
| 4 | Disaster recovery (DRC) | 12 | 9 | hot-standby twin, reached over the DCI link |
| 5 | Customs enclave | 172.20/16 | 15 | dual firewall, manifest DB pair, NACCS brokers, HSM, audit log, IDS, tap |
| 6 | Terminal operations centre | 20 | 15 | control tower, video wall, dispatch, radio |
| 7 | Berth apron / STS cranes | 21–24 | 68 | 4 berths (dual L3 industrial switches) + 12 STS cranes |
| 8 | Container yard | 30–45 | 82 | 16 RTG blocks, reefer monitoring, yard RFID |
| 9 | AGV fleet | 50 | 18 | dual zone routers, control-room switches, dispatchers, vehicle controllers |
| 10 | Gate complex & rail | 55 / 60 | 38 | 6 OCR lanes, rail RMG cranes, signalling interlock |
| 11 | Wireless / CFS / security | 80 / 70 / 85 | 49 | dual WLC, outdoor APs, warehouse, CCTV, access control |
| 12 | Reefer / DG / OT power | 75 / 90 | 25 | cold-chain monitors, hazmat detection, substation and shore-power PLCs |
| 13 | Mobile estate | — | 18 | handheld and vehicle-mount terminals |

Site numbering is the second octet of `10.<site>.<vlan>.0/24`, so an address
states where it is: `10.21.70.21` is berth 1 (site 21), industrial-control VLAN
70, host 21. The customs enclave is addressed out of `172.20.0.0/16` — separate
space for a separate trust domain. Carrier and partner networks use the
documentation ranges `198.51.100.0/24` and `203.0.113.0/24`.

---

## 3. VLAN plan

| VLAN | Name | Purpose |
| ---: | --- | --- |
| 10 | TERMINAL-OPS | operations workstations and dispatch |
| 20 | TOS-APP | Terminal Operating System application tier |
| 30 | RADIO-DISPATCH | radio dispatch and voice |
| 40 | MGMT-OOB | out-of-band management |
| 50 | HANDHELD-WIFI | handheld and vehicle-mount terminals |
| 60 | SERVER-FARM | server services |
| 70 | INDUSTRIAL-CTRL | crane, gate and rail PLCs |
| 80 | CCTV-SECURITY | CCTV and access control |
| 90 | IOT-SENSOR-MESH | sensor mesh |
| 100 | CUSTOMS-ENCLAVE | customs (172.20/16) |
| 110 | EDI-PARTNER | partner DMZ |
| 120 | AGV-CONTROL | AGV guidance and fleet control |
| 130 | REEFER-MONITOR | cold-chain monitoring |
| 140 | RAIL-SIGNALLING | rail signalling interlock |
| 150 | DANGEROUS-GOODS | hazmat yard |
| 160 | CONTRACTOR-GUEST | visitors and contractors |

`yokohama_kit.VLAN_NAMES` is the single definition; the switch configs, the
router-on-a-stick subinterfaces and the as-built `docs/VLANS.csv` all read it.

---

## 4. The industrial estate (the part that makes this a terminal)

### 4.1 STS cranes

Each of the 12 ship-to-shore gantry cranes is a small network of its own:

```
BRT1-IAG-A ──┐                        (IE-9320, L3, HSRP active)
             ├── STS01-SW-01 (IE-3400 industrial switch, control cabinet)
BRT1-IAG-B ──┘        ├── STS01-PLC-01    PLC-PT   motion controller   VLAN 70
                      ├── STS01-HMI-01    HMI-PT   operator panel      VLAN 70
                      ├── STS01-RFID-01   RFID     spreader/box ID     VLAN 90
                      └── STS01-MOT-01    Motion   travel/anti-collision VLAN 90
```

The crane's switch uplinks to **both** berth aggregation switches, which hold the
berth SVIs with HSRP and themselves dual-home to the two collapsed-core
switches. Losing one switch, one uplink or one core does not stop container
handling.

### 4.2 Container yard

Each of the 16 yard blocks has an IE-3400 with an RTG crane controller (VLAN 70),
a yard-position RFID portal (VLAN 90), a reefer bank temperature monitor
(VLAN 130) and a safety alarm. Blocks are dual-homed to `YARD-AGG-01/02`.

**What one block stands in for.** Packet Tracer renders a device, not a
container. A block here is one *monitoring and control point* standing in for
the block's real contents: 240 TEU ground slots and 64 reefer plugs. The model
therefore represents 3,840 ground slots and 1,024 monitored reefer plugs with
16 industrial switches, 16 controllers and 32 sensor endpoints. The ratio is
stated rather than implied: this is a control-plane model, not a per-box one.

### 4.3 AGV fleet

AGVs are horizontal transport between the apron and the yard. The modelled
control plane is wired and redundant — dual zone routers, dual control-room
switches, two fleet dispatchers — while the vehicles themselves are **wireless
clients** of the AGV-mesh APs, which is how real AGV fleets are connected. Each
of the 12 onboard controllers is a `PLC-PT` associated to `YML-AGV-MESH`.

### 4.4 OT hardening

Industrial switches carry `storm-control` on every access port with
`storm-control action shutdown`: a broadcast storm on a crane segment stops
container handling, so the port is shut rather than degraded. OT segments are
`passive-interface` in OSPF — a controller is an end station, never a transit
hop.

---

## 5. The IT estate

### 5.1 Data centres

```
                    bb1 ──(FW-TDC-PERIMETER)── TDC-SPINE-01 ══╗
                                                              ╠══ TDC-LEAF-01/02 ── 24 servers
                    bb2 ──(FW-TDC-PERIMETER)── TDC-SPINE-02 ══╝
```

Spines hold the VLAN 60 SVI with HSRP; leaves are server access. The DR site
(`DRC-SPINE-01`) is reached over a dedicated DCI router pair and holds standby
TOS, a standby manifest database, a replication target and an offline backup
vault.

Services: TOS application (HA pair), WMS, EDI broker, GIS/yard visualisation,
billing, VBS slot allocation, cargo tracking, AGV dispatch, crane SCADA, reefer
compliance, DNS ×2, DHCP, NTP, syslog, AAA (RADIUS), TFTP archive, portal,
mail, PKI CA, NetFlow collector, data historian and backup.

### 5.2 Service placement, and why only one DHCP server has pools

Packet Tracer keys DHCP pools and AAA clients by identity **across the whole
document**, so a second server holding the same records is indistinguishable
from duplication — `pkt_core.audit` reports it as `duplicate-dhcp-pool` /
`duplicate-aaa-client` and the gate fails. Each service therefore has exactly
one authoritative server in this model; the standby node exists and is
addressed but holds no records. DNS is the exception the audit models
explicitly: a zone is a *set per server*, so both DNS servers hold all 384
records and that is reported as `768 records (384 distinct × 2 servers)`.

This is a modelling constraint of the artefact format, not a design preference,
and it is stated here rather than hidden behind a passing gate.

### 5.3 Customs enclave

Two firewalls in series, a DMZ switch carrying the NACCS brokers and
declaration application, and a protected switch carrying the manifest database
pair, the HSM and the WORM audit log. The boundary policy (`customs_acl_lines`)
permits only the declared message set — Oracle on 1521, the declaration API on
8443, the audit feed on 9443 — and denies everything else with logging. An IDS
sensor and a capture tap sit on the DMZ span.

---

## 6. Routing and high availability

* **OSPF** — area 0 is the backbone; every operational zone is its own area
  (11 data centres, 21 apron, 30 yard, 50 AGV, 55 gate, 60 rail, 90 OT, 100
  edge), so a flapping yard block cannot inject external LSAs into the core.
* **iBGP AS65100** — the collapsed core, core routers and zone edge routers
  peer over loopbacks (`10.255.x.x`), carrying the terminal's own prefixes.
* **eBGP** — carrier transit (AS65101), Japan Customs/NACCS (AS65102), rail
  operator (AS65103) and the shipping-line EDI community (AS65104).
* **First-hop redundancy** — HSRP on every redundant pair: core SVIs, TDC
  spines, TOC routers, AGV routers, gate routers, rail routers and berth
  aggregation switches. Tracked interfaces decrement priority so a router that
  loses its uplink steps down.
* **Dual homing** — every berth switch, yard aggregation switch, zone router and
  core-facing access switch reaches both collapsed-core switches.

---

## 7. Quality of service

The terminal's hard real-time flows are marked at the edge and serviced ahead of
bulk data and CCTV (`terminal_qos_lines`):

| Class | Traffic | Treatment |
| --- | --- | --- |
| `CM-AGV-CONTROL` | AGV guidance/dispatch, UDP 5100-5110, 5300 | priority 2048 kb/s, DSCP CS5 |
| `CM-CRANE-CONTROL` | crane motion, UDP 4800-4810, TCP 4840 | priority 2048 kb/s, DSCP CS5 |
| `CM-VOICE` | radio dispatch | priority 512 kb/s |
| `CM-TOS-DISPATCH` | TOS work queue, 8443/8080/1521 | 40% remaining, WRED |
| `class-default` | bulk container data, CCTV | fair-queue, WRED |

Industrial switches carry the reduced `PM-YML-OT-EDGE` profile, since a
Layer-2 industrial switch cannot shape at Layer 3.

---

## 8. Addressing and scale

* 507 addressed interfaces, 133 subnets, 16 VLANs.
* Point-to-point links are allocated from `10.0.0.0/16` as `/30`s by a single
  counter (`P2P`), so two links can never be handed the same pair.
* Loopbacks are `10.255.x.x/32`, allocated **by call order** rather than by a
  hand-picked index — a hand-picked index is how two devices end up claiming
  the same address.
* Every allocation passes an address guard (`Terminal._claim_ip`) that **fails
  the build** if an address is claimed twice. A repeated host octet is caught
  where it is created, not later as a duplicate-IP finding.

---

## 9. Scale profiles

| Profile | Berths × cranes | Yard blocks | AGVs | Gates | Rail | APs | Handhelds | Devices |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| smoke | 2 × 1 | 4 | 4 | 2 | 1 | 6 | 8 | 206 |
| enterprise | 4 × 3 | 16 | 12 | 6 | 3 | 14 | 18 | **386** |

**The page is the binding constraint, not the device count.** Packet Tracer's
logical workspace is 3900×3900 at 100 % zoom and `check_layout` requires every
device on the primary page, so a model fits only ~26 rows at a 150-unit row
pitch. Because `lab_api.Layout` stacks one band per semantic tier, *tier count*
costs vertical space before any device is placed; related zones therefore share
a band (`GROUP_MERGE` in the generator), which is what makes 386 devices fit
where 18 separate tiers would not.
