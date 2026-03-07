#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

RUSTYNET_GATE_TEST_THREADS="${RUSTYNET_GATE_TEST_THREADS:-1}"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
# Enforce compiler-level unsafe prohibition for workspace code paths.
PHASE3_UNSAFE_RUSTFLAGS="${RUSTFLAGS:-} -Dunsafe_code -Dunsafe_op_in_unsafe_fn"
RUSTFLAGS="${PHASE3_UNSAFE_RUSTFLAGS}" cargo check --workspace --all-targets --all-features
RUST_TEST_THREADS="${RUSTYNET_GATE_TEST_THREADS}" cargo test --workspace --all-targets --all-features

scripts/perf/run_phase1_baseline.sh
scripts/perf/run_phase3_baseline.sh

./scripts/ci/check_backend_boundary_leakage.sh

if ! ./scripts/ci/check_no_unsafe_code.sh; then
  echo "Unsafe code gate failed"
  exit 1
fi

echo "Phase 3 CI gates: PASS"
