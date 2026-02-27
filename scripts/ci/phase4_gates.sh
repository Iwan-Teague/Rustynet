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

if ! rg -q "ensure_egress_allowed" crates/rustynetd/src/dataplane.rs; then
  echo "missing tunnel fail-close enforcement entrypoint"
  exit 1
fi

if ! rg -q "ensure_dns_allowed" crates/rustynetd/src/dataplane.rs; then
  echo "missing dns fail-close enforcement entrypoint"
  exit 1
fi

if ! rg -q "ContextualPolicySet" crates/rustynet-policy/src/lib.rs; then
  echo "missing contextual protocol-filter policy enforcement"
  exit 1
fi

echo "Phase 4 CI gates: PASS"
