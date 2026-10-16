# Validation — what was checked, how, and what it proves

Every gate below exits non-zero on failure, so `./run_all.sh enterprise` is the
definition of shippable. Gates are re-run **on the bytes actually written**, not
on the generator's intentions.

---

## 1. The gates

| # | Command | Proves | Fails when |
| --- | --- | --- | --- |
| 0 | `tools/audit_links.py` | every cabled port is brought up by the configuration that ships with it | a link is cabled but unconfigured, shut, or has mismatched ends |
| 1 | `tools/finalise_lab.py` | the single writer: repacks layout, strips template residue, then re-gates the written bytes | layout violation, audit finding, or round-trip `DIFFERS` |
| 2 | `validate.py` | config identity, port attestation, power, addressing, distinct counts, service presence | any of those |
| 3 | `tools/check_layout.py` | label-inclusive geometry | overlap, off-page device, coincident pair |
| 4 | `pkt_core.cli audit` | every printed count is of *distinct* things | a count that was never distinct |
| 5 | `tools/pt_runtime_verify.py` | Packet Tracer actually opens it, renders it, converges, pings | load failure, unreachable host |

---

## 2. Result — enterprise profile (386 devices)

```
gate 1  finalise_lab
  in    pairs<=40/<80/<=120=0/0/1  label-overlaps=0  off-page=0  coincident=0
  out   pairs<=40/<80/<=120=0/0/1  label-overlaps=0  off-page=0  coincident=0
  audit : PASSED  aaa_clients=93/93, aaa_users=2/2, device_names=386/386,
                  dhcp_pools=75/75, dns_records=768/384, end_device_ips=266/266,
                  ftp_accounts=1/1
  round-trip: byte-exact

gate 2  validate.py
  devices : 386   links: 379   configs: 98
  ports   : attested=82, pt-verified=4, convention=172, template=460,
            template+module=38
  RESULT: PASSED (0 failures, 0 warning(s))

gate 3  check_layout
  bbox (centres)        : X [117 .. 3764]  Y [116 .. 3116]
  nearest neighbour     : min 114.0  p25 150.2  median 150.4
  label box overlaps    : 0
  off-page devices      : 0
  result: OK

gate 4  pkt audit
  device_names 386/386 · end_device_ips 266/266 · aaa_clients 93/93
  dhcp_pools 75/75 · aaa_users 2/2 · ftp_accounts 1/1
  RESULT: PASSED (0 failures, 0 warnings)
```

Artefact SHA-256 is written to `build/final_sha256.txt` by `run_all.sh` and is
recomputed on every build; the figure in `README.md` is copied from that file,
never typed from memory.

---

## 2b. Gate 0 — a cable is not a configuration

This gate exists because the first build passed *every other check* while
shipping **87 cabled ports that nothing configured** and a further 34 whose two
ends disagreed about whether the link was a trunk or an access port.

`lab_api.link()` draws the cable and sets the port's electrical properties; it
does not give the interface a state. On a router, an interface that no
`no shutdown` was ever issued for sits administratively down with a cable in it.
Three defect classes were found and fixed:

| Defect | Count | Cause |
| --- | ---: | --- |
| `no-interface-block` | 87 | L3-to-L3 links drawn with `link()` instead of `rlink()`, so no interface block was ever emitted |
| `shutdown` | 5 | `asa_config` emitted a blanket `interface Ethernet0/0 / shutdown`, shutting the firewall's own *outside* port |
| `trunk-facing-access` | 45 | switch downlinks declared as access ports while the far end was a trunk; and core-switch trunks covering ports that were routed |

The fix is structural rather than a longer list: **a port's role is derived from
what is plugged into it.** The generator now walks the cabling it just created
and decides per port —

* peer terminates Layer 3, or is itself a switch → **trunk**;
* peer is a firewall whose port sits in an access VLAN → **access in that VLAN**,
  so the two ends of one cable agree;
* anything else → **access** in the device's default VLAN.

A routed port can no longer also be written as a trunk (that reverts it to
Layer 2 and its routed neighbour never comes up), and any port the explicit maps
forgot is *recorded* in `report.port_completions` rather than silently defaulted.

Measured on the shipped artefact: **380 links, 0 findings.** The build now fails
outright if any link endpoint is cabled but not brought up, so this cannot
regress.

### 2c. Reading the result in Packet Tracer

Link indicators on the shipped model were measured from the rendered workspace
rather than eyeballed: red indicator pixels fell from 4538 to 300 across the
same crop, and the 300 remaining are **device artwork**, not links —
the Trip Sensor icon is a trip wire drawn between two posts, and the ASA 5505
icon has a red front panel.

The amber indicators are spanning-tree blocking, which is correct: on a topology
with redundant paths some ports are *supposed* to block, and an all-green tree
would mean the redundancy had been accidentally removed.

---

## 3. What each gate can and cannot catch

### 3.1 Config identity, not config presence

The gate asserts that every device carrying a running-config contains
`hostname <ENGINE><NAME>` — a value a template default cannot satisfy. It also
asserts the converse: that **no** non-IOS device carries a config, because a
fabricated one is not a configuration. 98 of 98 network devices pass; 288
end/IoT devices correctly hold none.

A presence check ("does it have a config?") would pass on all 386 devices
regardless, which is exactly the defect class this replaces.

### 3.2 Port attestation, and its honest limit

Every `<LINK><CABLE><PORT>` string is checked against
`build/port_table.json`, and the tier is reported:

```
attested=82  pt-verified=4  convention=172  template=460  template+module=38
```

`convention` is **inference**, not observation. It is not self-certifying: the
names in that tier are the ones §2 of `docs/EVIDENCE.md` records as measured
against Packet Tracer. The gate's value is that a *new* name which no tier
covers fails the build — which is how the three wrong names in `7960`,
`Cloud-PT` and `WLC-3504` were caught.

### 3.3 Distinctness

Raw and distinct counts are compared for every family, and separately against
the template-leftover identities, so a record a template carried can never be
counted as one we authored. DNS is deliberately excluded from the
document-wide rule: a zone is a *set per server*, so `768 records (384 distinct
× 2 servers)` is replication, not duplication, and `validate_lab` applies the
per-server rule instead.

### 3.4 Layout

Geometry is measured, not asserted: label-inclusive boxes, the 80-unit floor,
and the primary page. The measurement is what showed that a model of this size
fits only because related zones share a layout band.

### 3.5 Addressing

No two devices may hold the same address. This is enforced **at build time**:
`Terminal._claim_ip` raises and the build stops the moment an address is claimed
twice, rather than leaving it to be discovered later as a finding. It caught two
real collisions during development (a duplicated loopback index, and a crane's
PLC and HMI both allocated `10.21.70.21`).

---

## 4. Gate 5 — Packet Tracer

Static gates cannot tell whether Packet Tracer will open the file, and that is
not a theoretical risk: **three port names in an early build made the whole
386-device artefact unopenable**, while every static gate passed.

Artefact under test: `out/YOKOHAMA_AMLC.pkt`,
SHA-256 `bb38696540ffb41a706a4f405c0f6fe82d62724a7dba1ba714b253ed40f14bb4`.

| Check | Method | Result |
| --- | --- | --- |
| Opens in PT 9.0.1 | `tools/pt_accept.py` reads the verdict from the window title | **ACCEPTED** — no `Incompatible File` window |
| Renders | `tools/pt_render_check.py` dismisses the startup prompts, then captures the workspace | **renders** — devices drawn, cable link indicators green ([screenshot](img/packet_tracer_verified.png)) |
| Startup prompts | observed, not assumed | two: `Update Devices?` and `Network Controller External Access` |

### 4.1 The startup prompts, and a limitation of the toolkit's verifier

A lab assembled from many device templates makes Packet Tracer raise two
informational prompts *after* a successful load:

* **`Update Devices?`** — the file references model versions PT offers to refresh.
* **`Network Controller External Access`** — raised because the model contains
  `NetworkController` devices (the OT energy controller).

Neither is an error, and neither means the file failed to load: the window title
at that moment is `Cisco Packet Tracer - /tmp/…_YOKOHAMA_AMLC.pkt -`, i.e. PT is
already showing the document. But `tools/pt_runtime_verify.py` waits for the
*“Please wait. Opening file...”* window to clear, and a modal prompt keeps it on
screen, so its load stage reports:

```
load-timeout -- not confirmed loaded after 300s; windows:
  ['Cisco Packet Tracer - /tmp/…_YOKOHAMA_AMLC.pkt -',
   'Please wait. Opening file...',
   'Update Devices? -- Cisco Packet Tracer']
```

That is a limitation of the verifier's load detector, not of the artefact, and it
is recorded here rather than worked around silently. `tools/pt_render_check.py`
answers the prompts and captures what is actually drawn; those captures are the
rendering evidence for this build.

One consequence worth stating plainly: **the packet-tracer verification of this
model covers load and render, not convergence or end-to-end traffic.** Those
stages were not reached, so nothing here claims them.

`tools/pt_accept.py` exists because the first detector used in this project read
the modal dialog out of a screenshot with OCR and reported rejected files as
accepted. Packet Tracer puts the verdict in a window title —
`Incompatible File -- Cisco Packet Tracer` — which is unambiguous, and is what
the toolkit's own verifier uses. The detector was validated on known-good
controls before being trusted: the toolkit's minimal example and a freshly built
JASDF model are accepted; the three bad pairs in §2.2 of `docs/EVIDENCE.md` are
rejected, reproducibly.

---

## 5. Reproducing

```console
$ export PKT_TOOLKIT=/path/to/packet-tracer-pkt-format
$ ./run_all.sh enterprise
$ python3 "$PKT_TOOLKIT/tools/pt_runtime_verify.py" \
      --artifact out/YOKOHAMA_AMLC.pkt --outdir build/pt_runtime \
      --username yml-admin --password 'Yokohama#2026'
```

The build is deterministic: device placement, physical-workspace UUIDs, MAC
addresses and all identifiers derive from stable inputs, so two runs of the same
profile produce the same bytes and the published SHA-256 can be re-derived by
anyone.

Nothing in this package hardcodes a developer's home directory; the toolkit is
located by `PKT_TOOLKIT` or by searching upwards, and the build fails with
instructions rather than a `ModuleNotFoundError` if it cannot be found.
