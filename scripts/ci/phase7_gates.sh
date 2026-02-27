#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features

./scripts/ci/phase6_gates.sh

if ! rg -q "HaCluster" crates/rustynet-control/src/scale.rs; then
  echo "missing HA cluster implementation"
  exit 1
fi
if ! rg -q "TenantBoundaryGuard" crates/rustynet-control/src/scale.rs; then
  echo "missing tenant boundary guard"
  exit 1
fi
if ! rg -q "authorize_trusted_key" crates/rustynet-control/src/scale.rs; then
  echo "missing trust-hardening key authorization"
  exit 1
fi
if ! rg -q "RelaySelectionPolicy" crates/rustynet-relay/src/lib.rs; then
  echo "missing relay regional policy primitives"
  exit 1
fi

echo "Phase 7 CI gates: PASS"
