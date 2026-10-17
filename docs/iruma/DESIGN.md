# IRUMA-AB — architecture specification

**JASDF Iruma Air Base (入間基地)** — an enterprise-scale Cisco Packet Tracer
model of a multi-tenant air base's ICT estate: an air-defence headquarters, an
airlift wing, air traffic control and navaids, an air weather squadron, two air
depots, and the base infrastructure that holds them together.

| | |
| --- | --- |
| **Devices** | **392** |
| **Links** | **372** |
| Devices carrying a running-config | 84 |
| `<LINE>` elements across those configs | 13,728 |
| Addressed interfaces / subnets | 494 / 117 |
| VLANs | 16 |
| DNS A-records (distinct) | 390 |
| DHCP pools (distinct) | 51 |
| RADIUS/AAA clients (distinct) | 80 |
| Address families | `10.0.0.0/8` (base), `172.21.0.0/16` (opsec enclave), `10.99.x` (firewall outside) |
| Tier bands | 12 |
| Distinct device models | 40 |
| Cable crossings | 1,330 (3.58 per cable) |

Read [`EVIDENCE.md`](EVIDENCE.md) first if you intend to cite anything about the
real base: it separates what is sourced from what is modelled.

---

## What the model represents

An air base's network is not a campus network with aircraft next to it. Three
things drive the design, and each is visible in the file:

1. **Air traffic control and navaids are flight-safety systems.** Runway
   lighting, ILS, TACAN and the GCA radar are in their own zone with their own
   industrial switches, and they are PLC-controlled, not workstation-controlled.
   The tower alerting relay to the crash crew is a distinct path.
2. **Tenants are independent commands.** 402SQ, the helicopter airlift
   squadron, the Flight Check Squadron and the HQ support flight each have their
   own switch, their own operations and maintenance servers, and — for the
   flying units — their own hangar industrial segment. Losing one unit's switch
   does not touch another unit's.
3. **The base's mission systems are not the base's business systems.** The
   air-defence and mission data centre, the operations-security enclave, and the
   general IT estate are three separate zones with three different trust levels.

## Tenants modelled

| Token | Unit | Role |
| --- | --- | --- |
| `402SQ` | 402 Hikotai (2TAG) | tactical airlift squadron — C-2 / RC-2 / U-4 |
| `ARWHAS` | Iruma Helicopter Airlift Sqn | Air Rescue Wing helicopter airlift — CH-47J |
| `FCS` | Hiko Tenken-tai | Flight Check Squadron — national navaid/ATC flight inspection |
| `SI` | CADF HQ Support Flight | T-4 "Silver Impulse" / U-4 |
| `EWC` | Denshi Sentai | electronic warfare / electronic flight measurement |
| `CAMG` | Chubu Koshagun | Central Air Defence Missile Group — Patriot PAC-3 |
| `CACE` | Chubu Shisetsu-tai | Central Air Facility Squadron (engineering) |
| `ASAR` | Aeromedical Safety Research Unit | aeromedical and flight safety research |
| `IMP` | Iruma District Police | MOD-direct district police |
| `SIGINT` | Johobu Denpa-bu | Signals Intelligence HQ radio branch detachment |
| `IHS` | JSDF Iruma Hospital | 10 departments, 60 beds, accepts civilian emergencies |

The four "flying" tenants get a complete complex (ops LAN + maintenance server +
aircrew EFB + radio position + hangar industrial segment); the remaining tenants
get an ops LAN. The split is a profile knob, so a smaller build is a smaller
base rather than a stubbed one.

---

## The twelve tier bands

| # | Band | Devices | What it is |
| --- | --- | ---: | --- |
| 1 | Carrier & external liaison edge | 14 | two commercial transit clouds, base edge routers, internet/DMZ firewall, and circuits to the MoD backbone, Yokota AB approach/departure control, the JWS-II weather system, the prefectural police air corps and the SIGINT detachment |
| 2 | Base backbone & NetOps | 14 | dual collapsed core, core routers, dual WAN edge, DCI router, and the Base Group's communications/cyber enclave (NMS, jump host, cyber observer, capture tap, TACACS+) |
| 3 | Air defence & mission DC (+ backup) | 42 | spine/leaf, 11 core services, 15 mission applications, and a 10-device backup site over a DCI link |
| 4 | Operations-security enclave | 15 | dual firewalls, mission database pair, ATO broker, tasking application, crypto gateway, HSM, WORM audit log, IDS, intercept tap |
| 5 | Air Operations Centre / tower | 17 | AOC distribution and access, tower position controller, ground movement, approach display, CADF HQ video wall, flight data, radio positions |
| 6 | Air traffic control & navaids | 20 | GCA/ASR radar processors, navaid monitoring, ATIS and D-ATIS, statutory recorder, and PLCs for PAR, TACAN (ident `YLT`), ILS 17/35, runway/taxiway/approach lighting and the crash alarm |
| 7 | Tenant squadrons, hangars, hospital | 70 | ten tenants and the hospital |
| 8 | Apron, flight line & vehicles | 46 | four apron sectors (west apron, north apron, helipad dispersal, police heliport), the flight-line switches, GSE, hot refuelling, runway sweep, tow tractors, bird control, follow-me, ARFF, and the ground-vehicle fleet |
| 9 | Air Weather Squadron | 17 | forecasting, observation, dissemination, JWS-II client, and the surface sensor field (wind ×2, temperature, humidity, pressure, rain, visibility, RVR) |
| 10 | Air depots & bulk fuel farm | 56 | 3rd Air Depot (communications/electronics and meteorological materiel), 4th Air Depot supply, and the POL farm (tank gauging, pumps, level and leak detection, foam fire suppression) |
| 11 | Security, utilities & wireless | 63 | perimeter CCTV/IDS/access control, main gate house, substation and standby power OT, water, solar/battery, WLAN controllers and 12 outdoor APs |
| 12 | Mobile estate | 18 | aircrew EFB tablets and duty handsets |

---

## Addressing

Everything is derived, never typed twice. A device's VLAN is a property of the
segment its own gateway sits on, and its address is derived from
`10.<site>.<vlan>.<host>`:

| Site | Use |
| ---: | --- |
| 10 | base backbone / transport (loopbacks `10.255.x.x`) |
| 11–12 | mission data centre, backup site |
| 20–21 | air operations centre, ATC and navaids |
| 25 | air weather squadron |
| 30–43 | tenant complexes (one site number each) |
| 44 | JSDF Iruma Hospital |
| 45–48 | apron and flight line |
| 55 | air depots |
| 60 | bulk fuel farm |
| 70–80 | security, utilities, wireless |
| 100 | carrier and external liaison edge |
| 200 | NetOps / out-of-band management |

Point-to-point links come from a `/30` allocator (`10.0.x.y/30`). The enclave is
addressed out of `172.21.0.0/16` so that no misroute can reach it by accident.
The full list is in [`ADDRESS_PLAN.csv`](ADDRESS_PLAN.csv) (494 interfaces, 117
subnets); the VLAN plan is [`VLANS.csv`](VLANS.csv).

### VLAN plan

| VLAN | Name | VLAN | Name |
| ---: | --- | ---: | --- |
| 10 | BASE-OPS | 90 | SENSOR-MESH |
| 20 | FLIGHT-OPS | 100 | OPSEC-ENCLAVE |
| 30 | RADIO-DISPATCH | 110 | LIAISON-DMZ |
| 40 | MGMT-OOB | 120 | GROUND-VEHICLE |
| 50 | EFB-TABLET-WIFI | 130 | POL-FUEL |
| 60 | SERVER-FARM | 140 | NAVAID-RADAR |
| 70 | AIRFIELD-CTRL | 150 | ARMS-STORAGE |
| 80 | CCTV-SECURITY | 160 | CONTRACTOR-GUEST |

## Routing and switching

* **OSPF, single process, multi-area.** Area 0 is the base backbone. Each
  operational zone is its own area (11 datacentres, 20 AOC, 21 apron, 25
  weather, 30 tenants, 50 ground vehicles, 55 ATC, 60 navaids, 90 utilities,
  100 edge, 200 NetOps), so a flapping apron switch cannot inject external LSAs
  into the core.
* **iBGP AS65010** between the collapsed core and the core routers, with
  loopback-sourced sessions; **eBGP** to the MoD backbone (AS65012) and the
  carriers (AS65011).
* **Redundant first hop.** Each zone's router pair runs HSRP on its
  router-on-a-stick subinterfaces, and each zone's access switches are
  dual-homed to the two collapsed-core switches.
* **Industrial Ethernet at the edge.** Apron, hangar, navaid, POL and utility
  segments are IE-2000/IE-3400/IE-9320 switches with `storm-control … action
  shutdown`, so a broadcast storm in a hangar cannot reach the data centre.
* **Management.** RADIUS first with local fallback, SSH only, an ACL 90
  management filter, SNMPv2c, NTP with authentication, and syslog to a central
  collector.

## Services

One authoritative server per document-keyed service, with a standby node that is
present and addressed but holds **no records** — because Packet Tracer keys DHCP
pools and AAA clients across the whole document, so a second server holding the
same records is indistinguishable from duplication. DNS is the one exception:
a zone is a set per server, so both DNS servers serve it and the audit reports
`780 records (390 distinct × 2 servers)`.

| Service | Host | Notes |
| --- | --- | --- |
| DNS (primary/secondary) | `DNS-SVR-01/02` | zone replicated, 390 names |
| DHCP | `DHCP-SVR-01` | 51 pools, one per zone/VLAN; standby holds none |
| RADIUS + TACACS+ | `AAA-SVR-01` | 80 distinct clients, 2 users |
| NTP, syslog | `NTP-SVR-01`, `SYSLOG-SVR-01` | standby nodes addressed but empty |
| TFTP archive | `TFTP-ARCHIVE-01` | configuration and image archive |
| HTTPS portal | `IRM-PORTAL-01` | base intranet |
| PKI | `PKI-CA-01` | internal certificate authority |
| NetFlow | `NETFLOW-SVR-01` | flow collection |

Mission applications in the MDC: air-defence system operations (`ADSYS-OPS-01`),
sortie tasking, mission planning, air tasking order distribution, maintenance
MIS, supply chain, flight records, airfield operations, weather integration,
personnel, training, intranet portal, PKI, NetFlow and a data historian.

Full detail: [`SERVICES.md`](SERVICES.md).

## Redundancy and independence

* Two collapsed-core switches, each dual-homed to every zone's router pair.
* Every zone router pair runs HSRP; every access layer is dual-homed.
* The apron has two independent industrial aggregations, and the flight line
  hangs off the second one.
* The POL farm has separate switches for tank gauging, the pump house and leak
  detection, so an earth-fault trip on one does not blind the others.
* The hospital is a zone of its own with its own router.

---

## What "all links work" means here

Every cable in this lab is **brought up by the configuration that ships with
it**. That is not a claim, it is a gate: `tools/audit_links.py` reads the written
artefact and asks one question per cable — *would this port come up?* — and the
generator refuses to write a file that fails it. It checks for a missing
interface block, an administrative shutdown, a port written as both routed and
trunked, and a trunk facing an access port in a different VLAN.

Three defects of exactly that kind were found and fixed while building this lab,
and each is worth recording because none of them was visible in the XML:

| Defect | What it was |
| --- | --- |
| The weather zone router had **no configuration at all** | it shipped holding its ISR factory config, with the uplink administratively shut |
| The ATC switch's uplinks were **also declared as access ports** | the same two ports were written as trunks *and* as `switchport access vlan 140`, so whichever block the parser applied last won, and the interswitch link could not forward |
| The POL tank and level monitors **shared one port range** | each of those ports carried two cables; the level monitors now have their own switch |

A fourth, of the same family, was caught by the address guard rather than the
link audit: a flight-line PLC and an apron refuelling PLC had been given the
same address on the same VLAN.

## Scale honesty

Packet Tracer renders a device, not a facility. What this lab represents:

| In the model | Stands for |
| --- | --- |
| One apron switch per sector | the sector's power, lighting and refuelling distribution |
| One PLC per tank | that tank's gauging and valve control |
| One hangar switch per flying unit | the unit's hangar line |
| One sensor per instrument | a representative point in the instrument field |
| One ground-vehicle controller | a vehicle class, not a single vehicle |

The ratio is stated rather than implied. This is a **control-plane model**, not a
per-asset model, and it should not be read as an inventory of the real base.

## Layout

The page is the binding constraint. 392 label-inclusive boxes at a 200-unit pitch
need roughly 11.8 M units² of Packet Tracer's 14.4 M unit² page, so the model
fits — but only just, and that density is what makes a generated lab look like
spaghetti.

Three things keep it legible, and all three are free (they change the picture,
not the network):

* **Twelve semantic bands**, each holding one tier, so the eye can find the
  navaids or the fuel farm without reading every label.
* **Cable-graph band order** — the collapsed core sits in the middle of the band
  order rather than at the top, because a fan is shortest when its source is at
  the centroid of its destinations. With the core at the top, 70% of all cable
  crossings involved a core-band cable.
* **Cable-graph document order** — devices are emitted as a breadth-first walk of
  each band's own cable graph, in chunks sized to one packing row, with each hub
  centred in its row. The packer fills rows in document order, so this is what
  decides whether a switch sits beside its access devices or at the far end of
  the page.

Measured with `tools/check_readability.py`: 1,330 crossings (3.58 per cable),
median cable 825 units, 95th percentile 2,408.

The bands are defined once, in `iruma_tiers.py`, and three consumers read that
one table: the generator's grouping, the diagram's banding, and the tier map that
`finalise_lab` uses to repack. Three separate lists is how a layout silently
collapses into a single band — which is what happened here first.

## Reproducing the build

The build is deterministic: placement, physical-workspace identifiers, MAC
addresses and every other identifier derive from stable inputs, so two runs of
the same profile produce **byte-identical** output and the published SHA-256 can
be re-derived by anyone.

```console
$ git clone https://github.com/aacanadaa/packet-tracer-pkt-format.git
$ cd packet-tracer-pkt-format && python3 -m venv .venv && . .venv/bin/activate
$ pip install -e . pytest pydantic
$ export PKT_TOOLKIT="$PWD"

$ cd /path/to/large-scale-packet-tracer/generator/iruma
$ ./run_all.sh enterprise
```

Nothing hardcodes a developer's home directory: the toolkit is located by
`PKT_TOOLKIT` or by searching upwards, and the build fails with instructions
rather than a `ModuleNotFoundError` if it cannot be found.
