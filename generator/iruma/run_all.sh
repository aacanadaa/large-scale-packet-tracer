#!/usr/bin/env bash
# Build, repair, validate and document the JASDF Iruma Air Base Packet Tracer
# model.
#
#   ./run_all.sh [profile]        profile = smoke | standard | enterprise (default)
#
# Every gate exits non-zero on failure, so this script is the definition of
# "shippable": if it completes, the artefact passed all of them *on the bytes
# that were written*.
#
# This package contains only the MODEL.  The format toolkit (pkt-core:
# tools/lab_api.py, tools/finalise_lab.py, src/pkt_core) is a separate checkout.
# Set PKT_TOOLKIT to it, or place this directory inside it -- the script
# searches upwards before giving up.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PY:-python3}"
PROFILE="${1:-enterprise}"

# ---- locate the toolkit ----------------------------------------------------
if [ -z "${PKT_TOOLKIT:-}" ]; then
  for cand in "$ROOT" "$ROOT/.." "$ROOT/../.." "$ROOT/../../.." "$ROOT/../../../.."; do
    if [ -f "$cand/tools/lab_api.py" ] && [ -d "$cand/src/pkt_core" ]; then
      PKT_TOOLKIT="$(cd "$cand" && pwd)"
      break
    fi
  done
fi
if [ -z "${PKT_TOOLKIT:-}" ]; then
  cat >&2 <<'EOF'
error: cannot find the pkt-core toolkit (tools/lab_api.py + src/pkt_core).

This package builds a lab; the toolkit does the encoding.  Clone it and point
PKT_TOOLKIT at the checkout:

    git clone https://github.com/aacanadaa/packet-tracer-pkt-format.git
    PKT_TOOLKIT=/path/to/packet-tracer-pkt-format ./run_all.sh
EOF
  exit 1
fi
export PKT_TOOLKIT
echo "toolkit : $PKT_TOOLKIT"
echo "python  : $($PY -c 'import sys; print(sys.executable)')"

"$PY" - <<'EOF'
import os, sys
sys.path[:0] = [os.environ["PKT_TOOLKIT"], os.path.join(os.environ["PKT_TOOLKIT"], "src")]
try:
    import pkt_core  # noqa: F401
except Exception as exc:  # pragma: no cover - diagnostic path
    raise SystemExit(
        f"error: this python cannot import pkt_core from {os.environ['PKT_TOOLKIT']}/src "
        f"({exc}).\n       Install the toolkit first:  pip install -e {os.environ['PKT_TOOLKIT']}"
    )
EOF

if [ "$PROFILE" = "enterprise" ]; then SFX=""; else SFX="_$PROFILE"; fi
OUT="out/IRUMA_AB${SFX}.pkt"

echo
echo "== evidence: port names =="
# Regenerates build/port_table.json, which records the *tier* each port name
# came from (template / attested / convention).  validate.py refuses any link
# endpoint whose name is not in it.
"$PY" tools/port_inventory.py
"$PY" tools/port_table.py

echo
echo "== build ($PROFILE) =="
"$PY" build_iruma_ab.py --profile "$PROFILE" --out "$OUT"

echo
echo "== gate 0: every cable is brought up by its configuration =="
# The generator already fails on this, but re-running it here proves the claim
# on the bytes on disk rather than on the generator's own bookkeeping.
"$PY" tools/audit_links.py "$OUT" --json "build/link_audit${SFX}.json"

echo
echo "== gate 1: layout, template leftovers, distinct counts, round-trip =="
# The single writer.  The generator already lays out through lab_api.Layout and
# strips template service records, so this pass should be a no-op -- it is kept
# because it *proves* that on the bytes actually written, and re-checks the
# round-trip.
# --tiers is not optional for this lab.  The repack groups devices into bands by
# name, and the toolkit's built-in rules are another lab's naming convention:
# without a tier map, 361 of these 392 devices match nothing, collapse into one
# 'misc' band, and repack into a tangle.  The generator writes the map from
# iruma_tiers.py, which is the same table the diagram uses.
"$PY" "$PKT_TOOLKIT/tools/finalise_lab.py" \
      --templates "$PKT_TOOLKIT/tools/device_templates.json" \
      --tiers build/tier_map.json \
      "$OUT"

echo
echo "== gate 2: project validation (identity, ports, power, distinctness) =="
"$PY" validate.py "$OUT" --report "build/report_${PROFILE}.json" \
      --json "build/validation${SFX}.json"

echo
echo "== gate 3: layout =="
"$PY" "$PKT_TOOLKIT/tools/check_layout.py" "$OUT"

echo
echo "== gate 3b: is the model legible? =="
# Geometry and legibility are different properties.  check_layout.py answers
# "does anything overlap or fall off the page"; this answers "can I follow a
# cable".  A lab can pass the first and still measure 4.4 crossings per cable.
"$PY" tools/check_readability.py "$OUT" --json "build/readability${SFX}.json"

echo
echo "== gate 4: every printed count is of distinct things =="
"$PY" -m pkt_core.cli.main audit "$OUT" \
      --templates "$PKT_TOOLKIT/tools/device_templates.json"

echo
echo "== as-built documentation =="
"$PY" tools/export_plan.py "$OUT" "$SFX"
"$PY" tools/draw_topology.py "$OUT" "docs/img/topology${SFX}.svg"
if command -v convert >/dev/null 2>&1; then
  convert -density 96 -background white "docs/img/topology${SFX}.svg" \
          -resize 2000x "docs/img/topology_overview${SFX}.png"
else
  echo "  (skipped PNG: ImageMagick 'convert' not found)"
fi

echo
echo "== hashes =="
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$OUT" | tee "build/final_sha256${SFX}.txt"
else
  shasum -a 256 "$OUT" | tee "build/final_sha256${SFX}.txt"
fi

echo
echo "== gates 5 and 6 (separate: need Packet Tracer under Xvfb) =="
cat <<EOF
  # Gate 5 -- does Packet Tracer open it?  Batch a known-good control.
  "$PY" "$PKT_TOOLKIT/tools/pt_accept.py" "$OUT" good-control.pkt

  # Gate 6 -- does it render?
  #
  # NOT pt_runtime_verify.py on this lab: it waits for Packet Tracer's progress
  # dialog to clear, and on a ~390-device file that dialog never clears because
  # the informational "Update Devices?" prompt blocks it.  The tool then reports
  # a load timeout on a file that is already open.  pt_capture.py answers the
  # prompts and waits for evidence that something was drawn instead.
  "$PY" tools/pt_capture.py "$OUT" --outdir build/pt_capture

  # End-to-end traffic and convergence are NOT measured by either tool here.
EOF

echo
echo "done -> $OUT"
