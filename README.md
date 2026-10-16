# Large-Scale Packet Tracer

A curated library of **enterprise-scale Cisco Packet Tracer topologies** — the
kind that are too big to build by hand: multi-site WANs, campus backbones,
redundant core and distribution layers, dynamic routing, and security
architectures that actually route.

Every lab here is generated from code, so the model is reproducible, the numbers
are recomputable from the artefact, and the topology can be re-scaled rather
than redrawn. Each one ships with its generator, its validation gates and an
as-built address plan.

All labs are verified to **open and render in Packet Tracer 9.0.1**.

---

## The labs

| Lab | Devices | Links | Configured | Config lines | Addressed interfaces | Subnets | Model size |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| [Yokohama Automated Maritime Logistics Terminal](labs/yokohama-amlc/) | **386** | **380** | 98 | 15,345 | 507 | 133 | 1.33 MB |
| ↳ *standard* profile | 303 | 289 | 84 | 12,758 | — | — | 1.01 MB |
| ↳ *smoke* profile | 206 | 205 | 72 | 11,049 | — | — | 0.74 MB |

*Configured* = devices carrying a full IOS/ASA running-config.
*Config lines* = `<LINE>` elements across every running-config.

---

## Yokohama Automated Maritime Logistics Terminal (Y-AMLT)

![Y-AMLT topology](labs/yokohama-amlc/docs/img/topology_overview.png)

An automated container terminal: a berth apron of ship-to-shore gantry cranes, a
rubber-tyred-gantry container yard, an AGV horizontal-transport fleet, an
automated gate complex, a rail intermodal terminal, and the IT/OT estate that
runs them — including a segregated customs enclave holding the manifest database
and the customs link.

| | |
| --- | --- |
| **Devices** | **386** (12 tiers) |
| **Links** | **380**, every one cabled *and* brought up by its configuration |
| **Switching** | 16 VLANs, per-zone distribution, redundant first-hop gateways |
| **Routing** | OSPF multi-area, iBGP AS65100, eBGP to four external parties |
| **Services** | 384 DNS records · 75 DHCP pools · 93 RADIUS clients · NTP · syslog · SNMPv2c · TFTP · HTTPS · PKI · NetFlow |
| **Verified** | opens and renders in Packet Tracer 9.0.1 |

→ **[Full notes, figures and gate results](labs/yokohama-amlc/README.md)**

---

## What "verified" means here

A `.pkt` that opens is not a `.pkt` that works, and a topology that renders is
not a topology that converges. Each lab publishes the checks it passed, and —
just as importantly — the ones it did not:

* **opens and renders in Packet Tracer 9.0.1** — confirmed by launching a real
  Packet Tracer under Xvfb and reading the result back, not by inspection;
* **every link is cabled *and* configured** — an audit walks each cable and
  requires the configuration that ships with it to bring both ends up;
* **every port name is attested or tested** — a name Packet Tracer cannot
  resolve does not merely kill one cable, it makes the whole file refuse to
  open;
* **every count is proven distinct** — a figure a README quotes is recomputed
  from the artefact, not from the generator's memory.

Where a check was *not* run, the lab says so rather than implying otherwise.

---

## Repository layout

```
labs/
  <lab>/
    README.md            what it models, and the figures for this build
    *.pkt                the artefacts, one per scale profile
    generator/           the topology generator
    generator/tools/     validation, auditing and export tools
    docs/                design, validation, evidence, as-built plans
    docs/img/            architecture diagram and Packet Tracer screenshots
```

---

## Building a lab yourself

Every lab depends on
[packet-tracer-pkt-format](https://github.com/aacanadaa/packet-tracer-pkt-format),
the offline `.pkt` codec and authoring toolkit:

```console
$ git clone https://github.com/aacanadaa/packet-tracer-pkt-format.git
$ cd packet-tracer-pkt-format && python3 -m venv .venv && . .venv/bin/activate
$ pip install -e . pytest pydantic
$ export PKT_TOOLKIT="$PWD"

$ cd labs/yokohama-amlc/generator
$ ./run_all.sh enterprise          # build, then every gate
```

---

## Licence

GPL-3.0-or-later, matching the toolkit the labs are built with. The generated
`.pkt` files are your own artefacts.
