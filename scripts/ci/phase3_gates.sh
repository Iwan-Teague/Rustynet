#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features

scripts/perf/run_phase1_baseline.sh
scripts/perf/run_phase3_baseline.sh

if rg -n "(Wireguard|WireGuard|wg[-_]|wgctrl)" \
  crates/rustynet-control crates/rustynet-policy crates/rustynet-crypto \
  crates/rustynet-backend-api crates/rustynet-cli crates/rustynet-relay; then
  echo "WireGuard leakage gate failed"
  exit 1
fi

if rg -n "\\bunsafe\\b" crates; then
  echo "Unsafe code gate failed"
  exit 1
fi

echo "Phase 3 CI gates: PASS"
