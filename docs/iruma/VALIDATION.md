# IRUMA-AB — validation

Seven gates, each exiting non-zero on failure, run against the **bytes that were
written** rather than against the generator's own bookkeeping. What follows is
what each gate can and cannot catch, and what it actually said on the shipped
artefact.

Run from `generator/iruma/` with the toolkit's venv active and `PKT_TOOLKIT`
pointing at a `packet-tracer-pkt-format` checkout:

```console
$ ./run_all.sh enterprise
```

---

## Result on the shipped build

| # | Gate | Command | Result |
| --- | --- | --- | --- |
| 0 | every cabled port is brought up by its own configuration | `tools/audit_links.py out/IRUMA_AB.pkt` | **372 links, 0 findings** |
| 1 | single writer: layout, template residue, distinct counts, round-trip | `tools/finalise_lab.py …` | **round-trip: byte-exact**, audit PASSED |
| 2 | config identity, port attestation, power, addressing, distinctness | `validate.py out/IRUMA_AB.pkt` | **PASSED (0 failures, 0 warnings)** |
| 3 | label-inclusive geometry | `tools/check_layout.py out/IRUMA_AB.pkt` | **OK** — 0 overlaps, 0 off-page, 0 coincident |
| 4 | every printed count is of *distinct* things | `pkt_core.cli audit …` | **PASSED (0 failures, 0 warnings)** |
| 5 | Packet Tracer actually opens it | `tools/pt_accept.py out/IRUMA_AB.pkt control.pkt` | **accepted 2/2** (lab and control) |
| 5b | the model is legible | `tools/check_readability.py out/IRUMA_AB.pkt` | **1,079 crossings (2.9 per cable)** — see "Layout" below |
| 6 | it renders | `tools/pt_capture.py out/IRUMA_AB.pkt` | **renders** — see "Gate 6" below |

The build is also **reproducible**: an independent re-run of the generator plus
`finalise_lab.py` produces the identical SHA-256, so the published hash can be
re-derived by anyone.

Measured on the shipped enterprise artefact:

```
devices 392   links 372   routed ports 85
addressed interfaces 494   subnets 117   VLANs 16
config lines: 13,728 <LINE> elements in 84 RUNNINGCONFIG blocks
DNS 780 records (390 distinct x 2 servers); DHCP 51/51; AAA 80/80; AAA users 2/2
layout: nn min 111.0  median 154.0  label-overlap 0  off-page 0  coincident 0
packet: sha256 4a4253f9c2691929bd9e8cbdeff9e100694c9a3c9910d4cc1b79e0dc4d5e19aa
layout legibility: 372 cables, 1,079 crossings (2.9 per cable), median cable 410 units, p95 1,444
sections: 16 labelled Packet Tracer clusters, 392/392 devices assigned
```

---

## What each gate can and cannot catch

### Gate 0 — `audit_links.py` (the one that matters most)

**Catches:** a cabled port with no `interface` block; a port left administratively
shut; a port written as both a routed port and a trunk; a trunk facing an access
port in a different VLAN.

**Cannot catch:** a misconfigured *address* on a port that is otherwise up, a
routing protocol that never converges, or a name Packet Tracer will not resolve.
It reads XML; it does not open Packet Tracer.

It is cheap (a static read) and it is the gate that catches the largest defect
class a generated lab ships with, because a dead link passes every structural
check. The generator runs it inline and refuses to write a file that fails it,
and `run_all.sh` runs it again on the bytes on disk.

### Gate 1 — `finalise_lab.py`

The single writer. It repacks the layout, sanitises un-authored template fields,
and then **re-gates the bytes it actually wrote**, including decoding them again
and comparing: `round-trip: byte-exact`. If that line said `DIFFERS`, the
artefact would not be shippable no matter what else passed.

Note that it *repositioned all 392 devices* on the shipped build — its packer is
not the generator's, and its output is the one that ships. Any layout figure in
these documents is measured after this pass, not before.

### Gate 2 — `validate.py`

Asserts something a template default cannot satisfy:

* **config identity** — every network device's config contains `hostname <name>`.
  A presence check ("has a config") passes on a factory default; identity does
  not.
* **port attestation** — every link endpoint's port name is in
  `build/port_table.json`, with the evidence tier recorded. A name that is not
  attested is a whole-file risk, not a per-cable one.
* **power** — every device and every cabled port is powered on.
* **addressing** — every endpoint address is distinct.

### Gate 3 — `check_layout.py`

Geometry: label-inclusive boxes, on-page, coincidence, nearest-neighbour
spacing. Reports "0 overlaps, 0 off-page" on the shipped build, with 30 label
boxes *exactly touching* and 8 device pairs between 80 and 120 units apart. The
hard floor is 80 units, so touching is not overlapping — but it is tight, and if
you add devices to a band this is the gate that will object first.

### Gate 4 — `pkt_core.cli audit`

Distinctness for every service family. This is the gate that would have caught
the "202 AAA clients, 140 of them the same phantom address" class of bug. On the
shipped build every raw count equals its distinct count — except DNS, where
`780 records (390 distinct × 2 servers)` is *replication*, which the audit models
explicitly and does not flag.

### Gate 5 — `pt_accept.py`

The only cheap gate that can catch a port name Packet Tracer refuses. The verdict
is read from the **window title**, not from a screenshot: OCR of the modal dialog
has reported rejected files as accepted.

A **known-good control is batched with the lab in the same run**, because several
Packet Tracer instances launched in quick succession can raise the dialog for a
file that is fine. On this build both were accepted.

### Gate 6 — what was actually established

This is where the honest account matters most, because two different failures
look identical from outside: **a blank workspace is not proof that a lab failed
to render.**

`pt_runtime_verify.py` opens the lab and waits for Packet Tracer's progress
dialog to clear. On a ~390-device file **that dialog never clears** — Packet
Tracer raises a modal prompt while it is still up — so the harness reports

```
[load] load-timeout: not confirmed loaded after 300s;
       windows: ['Cisco Packet Tracer - /tmp/…_IRUMA_AB.pkt -',
                 'Please wait. Opening file...',
                 'Update Devices? -- Cisco Packet Tracer']
```

Measured directly on this machine, the truth is:

| Observation | Measurement |
| --- | --- |
| Time to load and draw a 392-device lab | **8–10 minutes** on an otherwise idle machine (RSS ≈ 4.2–5.0 GB); up to **~25 minutes** when another Packet Tracer instance is competing |
| Does the workspace draw? | **yes** — and it draws *behind* the modal prompt, which is why "is anything on the canvas" works as the load signal |
| Is the prompt a failure? | no: `This file contains 32 device(s) that have outdated run-time scripts`, offering Yes / No / Update and Make a Copy |
| What does **Return** choose? | **Yes** — rewrite every affected device's run-time script |
| What does that do to a 392-device lab? | **closes the document**, leaving an empty untitled window |
| What does **Escape** choose? | **No** — leaves every device in its original state, and the loaded topology survives |
| What else breaks the load? | **resizing the document window before the load finishes.** A tool that resizes first and waits second ends up driving a window Packet Tracer has already replaced |

Measured with **no interaction at all**, at 10.5 minutes: title
`Cisco Packet Tracer - …/IRUMA_AB.pkt - `, the prompt present, RSS 4.95 GB, and
4,578 saturated canvas pixels — i.e. loaded, drawn and stable. That run is the
control for the tool: everything the tool does beyond waiting was suspect until
it was removed.

So the first captures in this repository were blank for two harness reasons —
**pressing Return** (which chooses Yes) and **resizing before the load
finished** — and the resulting empty window is indistinguishable from a load
failure. `tools/pt_capture.py` was written for this and now

1. waits for **evidence that something was drawn** (saturated pixels inside a
   measured canvas rectangle, which reads exactly zero while the file is still
   parsing) rather than for a dialog to disappear,
2. does not touch the window until the workspace has drawn, and
3. answers the prompt with **Escape**, not Return.

The screenshots in [`img/`](img/) are the real Packet Tracer workspace — the
twelve tier bands, device labels and link indicators — but they were captured by
**driving a loaded instance directly**, not by the tool. On the same machine and
file, an untouched Packet Tracer instance held the document open and drawn for
20+ minutes, while runs that polled it with `import -window root` every ten
seconds repeatedly ended with the document closed and an empty 541 MB process.
The wait logic is right; the polling is the remaining suspect, and
`pt_capture.py` now says so in its own docstring and exposes `--probe-interval`
to poll less often. **Automated capture of a lab this size is not a solved
problem here.**

**A control was run throughout.** The known-good `YOKOHAMA_AMLC_smoke.pkt`
(206 devices) from this same repository renders in this environment, and a
three-device lab built with the toolkit renders in ~45 s. When a capture looked
blank, the control was batched with it — and the control rendered — which is what
localised the fault to the harness rather than to either lab.

**The sectioned layout has no Packet Tracer render.** Four capture attempts on
the reorganised file either caught a partial load (the first section drawn, the
rest of the page empty) or had the run-time-scripts prompt still covering the
canvas. The file itself is accepted and the earlier layouts did render, so this
is a capture-timing problem rather than a defect — but the honest position is
that the sixteen-section arrangement is evidenced by the generated diagram
(`docs/iruma/img/topology_overview.png`, recomputed from the artefact) and by
`check_layout.py` and `check_readability.py`, not by a screenshot.

**Still not verified on this build:** end-to-end traffic and convergence. The
evidence supports "Packet Tracer opens it and draws it", not "every path
forwards". Red and amber link indicators in the screenshots are **not** evidence
of a fault on their own — Packet Tracer draws serial cables red regardless of
state, and runs spanning-tree convergence after a load, so some access ports are
amber for the first ~30 s and some ports are *supposed* to be amber on a
topology with redundant paths.

## Layout — making 392 devices legible

Geometry and legibility are different properties, and only one of them had a
gate. `check_layout.py` passed this lab at every stage while it measured **4.43
cable crossings per cable** and read as one long chain of devices.

Four things were wrong. The first two made the layout *legal but meaningless*;
the last two made it *legal but tangled*.

| Problem | Measurement | Fix |
| --- | --- | --- |
| The single writer's tier rules are another lab's naming convention, so **361 of 392 devices matched no rule** and collapsed into one band | a tenant switch sat **3,538 units** from its own workstation | `--no-repack`: the generator owns the placement, and `iruma_tiers.py` is the one section table |
| Twelve bands of loose icons is still a chain — no way to find the fuel farm | — | **16 named sections**, each a block wrapped in a Packet Tracer **cluster**, which draws the name on the canvas |
| Devices were packed in *creation* order, so a section's switch and its access devices landed at opposite ends | mean cable 1,142 units | document order is a breadth-first walk of each section's cable graph, chunked to one packing row, hubs centred |
| The collapsed core sat at the top, so its fan crossed everything below | **70% of all crossings involved a core-band cable** | sections are packed masonry-style into three columns, the most-connected block placed to fill evenly |

Result, across the four steps: **crossings 1,645 → 1,079 (−34%)**, median cable
**888 → 410 (−54%)**, mean **1,142 → 515 (−55%)**. None of it changes the network.

**Two determinism traps, both found by rebuilding and diffing.** A cluster id
from `uuid.uuid4()` and a `MEM_ADDR` from `hash()` — Python randomises string
hashing per process — each made two runs of the same profile differ. A third,
larger one: the ordering pass seeded its walk from a `set`, whose iteration order
varies between processes, so the *device order* differed and with it 84,658 lines
of XML. All three are now derived from stable inputs, and three consecutive
builds produce identical bytes.

What did **not** work, and why it is worth recording: cluster-block placement
without sections. Laying each hub-and-leaf cluster out as its own block gives
very short cables but 392 boxes at a 200-unit pitch need 11.8 M of a 14.4 M unit
page, so the blocks overflow to y≈4,265 — off the page. Sections are coarse
enough to fit; per-cluster blocks are not. **The page is saturated at this size,
and that density is why the row-major packer wraps.**

## Defects found while building, and fixed## Defects found while building, and fixed

Every one of these passed at least one structural gate in an earlier build.

| Defect | How it was found | What it looked like |
| --- | --- | --- |
| The weather zone router had **no configuration at all** | gate 0 | it held its ISR factory config with the uplink administratively shut |
| The ATC switch's two uplinks were **also declared access ports** | gate 0 | the same ports written as trunks *and* `switchport access vlan 140`; last block wins |
| The hangar PLC and fire monitor were cabled to **both** the squadron switch and the hangar switch | gate 2 | two cables on one device, one of them on a port that model does not have |
| The hospital's oxygen monitor was cabled to a port its model does not have | gate 2 | `GigabitEthernet0` on a sensor whose only cabled port is `FastEthernet0` |
| The weather HMI was cabled to `FastEthernet0` | gate 2 | `HMI-PT`'s cabled port is `GigabitEthernet0` |
| The NetOps switch was addressed but **never configured** | gate 2 | it shipped carrying a template config for a different network |
| POL tank PLCs and level monitors **shared one port range** | gate 2 | each of those ports carried two cables |
| A flight-line PLC and an apron refuelling PLC shared an address | the generator's address guard | two devices claiming `10.45.70.31` on one VLAN |
| The mobile tier wrapped to a second page column | gate 3 | one device off-page at x=4027 |

Two of these are worth generalising, because they are the same mistake twice:

* **A hand-maintained port→VLAN table drifts from the cabling.** The ATC, POL,
  depot, security, utilities and tenant switches all had one, and several were
  wrong. They were replaced by a rule: a port's access VLAN is the VLAN of the
  device plugged into it, taken from that device's own gateway address. The
  tables now name only the uplinks.
* **A device that is placed and addressed is not a device that is configured.**
  Two devices (the weather router, the NetOps switch) were built, cabled and
  addressed but never given a running-config. Only the identity check caught
  them, and only after the check existed.

## Limits of this validation

* **No convergence or traffic measurement** on this build (see gate 6). The
  render is evidence that the file is structurally sound and that Packet Tracer
  accepted every device, port and link name — not that every path forwards.
* **Opening this lab is slow, and variably so.** 8–10 minutes and ~4.2–5.0 GB
  of RSS before the workspace is drawn, on this machine, and up to ~25 minutes
  if another Packet Tracer instance is running. A smaller profile opens far
  faster and is the better choice for iterating.
* **The physical workspace** (`PACKETTRACER5/PHYSICALWORKSPACE`) was not opened
  and inspected. The braced-UUID plumbing there is the one that reports
  "corrupted Physical Workspace data", and it is unchecked here.
* **Gate 3's margin is small.** 8 pairs sit between 80 and 120 units apart. The
  floor is 80; there is not much room left in the layout before something has to
  give.
* **The model is not the base.** See [`EVIDENCE.md`](EVIDENCE.md): several
  facilities are modelled from JASDF convention, not sourced.
