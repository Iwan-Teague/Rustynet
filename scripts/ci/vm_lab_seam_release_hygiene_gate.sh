#!/usr/bin/env bash
# Lab-manifest-seam release hygiene gate.
#
# --lab-throwaway-release-manifest is a LAB-ONLY seam: it lets a throwaway
# per-run Ed25519 seed sign the release manifest used by macOS lab nodes. That
# code path must NEVER ship: production daemons verify releases against the
# pinned key (RUSTYNET_DEFAULT_RELEASE_VERIFIER_KEY_HEX), not a minted one.
#
# The seam lives under crates/rustynet-cli/src/vm_lab/ (feature "vm-lab", not
# enabled by default or in release builds). This gate fails closed if any seam
# marker string leaks into a default-features RELEASE binary of rustynet-cli.
#
# Usage:
#   vm_lab_seam_release_hygiene_gate.sh            # build, then scan
#   vm_lab_seam_release_hygiene_gate.sh <binary>   # scan an existing binary
#                                                  # (negative-test helper:
#                                                  # a binary CONTAINING the
#                                                  # markers must fail here)

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Marker strings minted/emitted only by the lab seam. The usage-line flag
# string is deliberately NOT a marker: usage text is compiled into release
# binaries ungated, so it cannot witness the seam.
markers=(
  "macos_manifest_seam"
  "LabManifestSeam"
  "mint_throwaway_seed"
  "RUSTYNET_RELEASE_PINNED_KEY_HEX"
)

binary="${1:-}"

if [ -z "$binary" ]; then
  echo "[vm-lab-seam-gate] building rustynet-cli (release, default features)"
  (cd "$root" && cargo build --release --locked -p rustynet-cli)
  binary="$root/target/release/rustynet-cli"
fi

if [ ! -f "$binary" ]; then
  echo "::error::[vm-lab-seam-gate] binary not found: $binary" >&2
  exit 1
fi

status=0
for marker in "${markers[@]}"; do
  if grep -a -q -F -- "$marker" "$binary"; then
    echo "::error::[vm-lab-seam-gate] lab-manifest-seam marker '$marker' FOUND in release binary $binary — the vm-lab-only seam leaked into a production build" >&2
    status=1
  else
    echo "[vm-lab-seam-gate] ok: '$marker' absent from $(basename "$binary")"
  fi
done

if [ "$status" -ne 0 ]; then
  echo "::error::[vm-lab-seam-gate] FAILED: lab-only release-manifest seam is present in a release binary. Ship builds must not enable the seam (cargo feature vm-lab stays off; see crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_manifest_seam.rs)." >&2
  exit 1
fi
echo "[vm-lab-seam-gate] PASS: no lab-manifest-seam markers in release binary"
