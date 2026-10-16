# Evidence — where every fact in this model came from

A generated lab is full of claims that are easy to assert and hard to check:
that a port is called what we think, that a device is configured, that a count
means what it says. This file records the source of each class of fact, and the
things that were measured and turned out **not** to be true.

Toolchain in use:

| | |
| --- | --- |
| Packet Tracer | `/opt/pt/packettracer.AppImage`, version **9.0.1**, sha256 `cd8d4fc74bbf31e47674ba5f27987a030a94e673d01bcac3dcb218904227c87e` |
| Toolkit | `packet-tracer-pkt-format` @ `54743b8` (GPL-3.0-or-later) |
| Corpus | 952 files present locally, verified against the toolkit's `CORPUS_INDEX.tsv` (1059 entries): **0 mismatches** |

The corpus is *identity-verified but not redistributed*; `corpus/fetch_corpus.py`
reproduces it.

---

## 1. The container format

Taken as given from the toolkit, which demonstrates `encode(decode(f)) == f` on
1,058 real containers. This model re-tests the promise on its own output rather
than trusting it: `validate.py` decodes the written bytes and compares, and
`finalise_lab` does the same after writing. Both report **byte-exact**.

---

## 2. Port names — the highest-risk fact in the model

`lab_api.link()` stores a port-name string in the `<LINK>` verbatim; Packet
Tracer resolves it at load time. A name it cannot resolve does not merely leave
one cable dead — **Packet Tracer refuses the entire file**, with a modal that
names no device:

> Unable to open file. The file … is not compatible with this version of Cisco
> Packet Tracer

The verdict is in a window title (`Incompatible File -- Cisco Packet Tracer`),
which is how `tools/pt_accept.py` reads it. Earlier attempts to OCR the modal
from a screenshot reported rejected files as accepted, which sent this
investigation down two blind alleys; the title is unambiguous and is what the
toolkit's own `pt_runtime_verify.py` uses.

Names therefore come from four tiers, recorded per model in
`build/port_table.json`:

| Tier | Source | Models | Example |
| --- | --- | ---: | --- |
| **template** | the model's own harvested factory config lists `interface <NAME>` lines | 29 | `3650-24PS` → `GigabitEthernet1/0/1` |
| **template+module** | ports a fitted module adds | 5 | `2911` + HWIC-2T → `Serial0/0/0` |
| **attested** | a `<LINK><CABLE><PORT>` string naming that model in a real saved lab | 10 | `AccessPoint-PT-N` → `Port 0` |
| **convention** | **inference**: the model has no factory config, but its template declares port *types*, and PT names a lone copper port of a family `<Family>0` | 56 | `RFID Reader` → `FastEthernet0` |
| **pt-verified** | measured against this Packet Tracer by `tools/pt_accept.py` | 3 | `7960` → `Switch` |

### 2.1 The convention tier is verified, not assumed

Every convention-tier name this model actually cables was tested as a
`(model, port)` pair in a two-device lab, and accepted:

```
PLC-PT GigabitEthernet0 · HMI-PT GigabitEthernet0 · RFID Reader FastEthernet0
Motion Detector FastEthernet0 · Temperature Monitor FastEthernet0
Smoke Detector FastEthernet0 · Water Level Monitor FastEthernet0
Siren FastEthernet0 · Smart LED FastEthernet0 · Trip Sensor FastEthernet0
Power Meter FastEthernet0 · Webcam FastEthernet0
NetworkController GigabitEthernet0 · DataHistorianServer GigabitEthernet0
```

### 2.2 Names measured as REJECTED

Three models in this model's design do **not** use the name the corpus or a
factory config suggested. Each rejected pair was tested at least twice, and the
rejection reproduces:

| Model | Rejected | Accepted instead |
| --- | --- | --- |
| `7960` | `FastEthernet0`, `FastEthernet0/1` | `Switch` (uplink), `PC` (passthrough) |
| `Cloud-PT` | `GigabitEthernet0/1/2`, `Ethernet0/1/2`, `Serial0/0/0`, `Coaxial1` | `Port 0` |
| `WLC-3504` | `GigabitEthernet0/0` … `0/5`, `GigabitEthernet0/1/1` | `GigabitEthernet1` |

These are recorded in `tools/port_table.py` as `PT_REJECTED`, and the names are
**removed from the table** rather than annotated: a table that still permitted
them would let the validator pass a link the artefact cannot carry.

The corpus's own counts for these models were misleading — it lists
`7960 → FastEthernet0` (27 occurrences) and `Cloud-PT → GigabitEthernet0`, both
of which Packet Tracer 9.0.1 rejects. Corpus frequency is evidence of what some
older Packet Tracer wrote, not of what this one accepts.

### 2.3 What could NOT be used as evidence

* **The reference corpus cannot attest the industrial/IoT models.** A full mine
  of all 952 files found **zero** instances of `IE-9320`, `IE-3400`, `IE-2000`,
  `IR1101`, `CGR1240`, `ISA-3000`, `PLC-PT`, `HMI-PT`, `RFID Reader`, or any of
  the sensor families. The corpus is CCNA-era lab gear: 28 device classes in
  total. (A first attempt at this mine keyed on `ENGINE/TYPE`'s *text*, which is
  the device class — `Router`, `Switch` — not the model; the model is the
  `model=` **attribute**. That mistake is why the first pass reported "28 models
  of interest, all zero".)
* **Packet Tracer's own palette templates don't carry port names.** The 89
  `.ptd` files inside the AppImage decode cleanly with the toolkit's codec, but
  they describe modules and slots (`PT-IOT-NM-1CFE`), not instantiated port
  names.
* **A model loading alone does not mean a cable is legal.** All 46 candidate
  models load individually in a two-device file; that says nothing about whether
  a port name resolves.

---

## 3. Device configuration

* **Config content** is emitted by `yokohama_kit.py`, whose command shapes are
  adapted from the JASDF AEW&C package's `jasdf_kit.py` (same author, same
  toolkit lineage), which cross-checks every line against what real Packet
  Tracer saves attest via `tools/audit_ios_commands.py`.
* **Config identity** is proven per device: every device carrying a
  running-config must contain `hostname <ENGINE><NAME>`. A factory default, or a
  config copied from another lab, cannot satisfy that. 98 of 98 pass.
* **Non-IOS devices carry no running-config at all.** Harvested `Server-PT` and
  IoE templates ship the running-config of whatever lab they were saved from;
  `clear_end_device_configs()` removes it, and `validate.py` fails if any
  non-network device holds one. Their configuration is their addressing.

---

## 4. Service records

Harvested templates carry **service blocks**, not just example records: AAA
clients, DHCP pools, DNS zones, FTP accounts — and blocks already marked
`<ENABLED>1</ENABLED>`. Two passes deal with this:

* `strip_template_leftovers()` (the toolkit's own `sanitize_template_leftovers`,
  applied per `DEVICE` — the helper resolves `DEVICE/ENGINE` and returns an
  empty report for anything else, which looks exactly like a clean sweep).
* `strip_unconfigured_services()` removes the blocks entirely from devices that
  were given no service, and `configure_server()` clears them before writing.
  Without this, **52 devices advertised themselves as NTP servers and 52 as HTTP
  servers**, none of which anyone authored.

Measured effect on the published figures: `http/ntp/syslog servers` went 52 → 1,
`aaa servers` 248 → 1, `dhcp servers` 57 → 1. The 248 was `<USER>` elements
inside each device's inert `<EMAIL_CLIENT>` block being counted as AAA users.

---

## 5. Layout

`lab_api.Layout` owns placement: label-inclusive boxes, greedy row-major packing
per semantic tier, an 80-unit centre floor, and canvas containment. The
generator places through it, `check_layout.analyse` measures it, and both agree
by construction.

The known limits, measured rather than assumed:

* The logical page is **3900×3900** at 100 % zoom; `check_layout` requires every
  device (and its label box) on the **primary page** — `on_page()`'s
  `allow_wrap` page-column strategy is not what `analyse()` calls, and
  `finalise_lab` gates on `off_page` being empty.
* At `ROW_PITCH = 150` that is ~26 rows, and `Layout` gives each semantic tier
  its own band, so **tier count is what decides whether a model fits**. Merging
  related zones (`GROUP_MERGE`) is what lets 386 devices fit where 18 tiers
  would not.

---

## 6. Things that looked like failures and were not

* **"Incompatible File" on a file that then loads.** Repeated Packet Tracer
  launches in quick succession can produce the dialog for a file that is fine;
  a longer gap and a longer settle removed it. Every rejection reported here was
  therefore reproduced, and the three genuine rejections in §2.2 reproduce
  across runs while the known-good controls (the toolkit's minimal example, and
  a freshly built JASDF model) are accepted every time.
* **Red serial cables.** Packet Tracer draws serial cables red regardless of
  link state.
* **Amber link lights after opening.** Spanning-tree convergence, ~30 s on a
  model with this many switches.
