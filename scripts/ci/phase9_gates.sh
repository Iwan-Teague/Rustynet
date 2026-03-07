#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

RUSTYNET_GATE_TEST_THREADS="${RUSTYNET_GATE_TEST_THREADS:-1}"

require_command() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "missing required command: ${cmd}" >&2
    exit 1
  fi
}

require_cargo_subcommand() {
  local subcommand="$1"
  if ! cargo "${subcommand}" --version >/dev/null 2>&1; then
    echo "missing required cargo subcommand: cargo ${subcommand}" >&2
    echo "install toolchain components/tools and retry." >&2
    exit 1
  fi
}

require_command cargo
require_command rg
require_cargo_subcommand fmt
require_cargo_subcommand clippy
require_cargo_subcommand audit
require_cargo_subcommand deny

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
RUST_TEST_THREADS="${RUSTYNET_GATE_TEST_THREADS}" cargo test --workspace --all-targets --all-features

./scripts/ci/phase8_gates.sh
./scripts/ci/phase1_gates.sh

./scripts/ci/run_required_test.sh rustynet-control ga::tests --all-features
cargo test -p rustynet-backend-wireguard --test conformance --all-features
cargo test -p rustynet-backend-api --all-targets --all-features

./scripts/operations/collect_phase9_raw_evidence.sh

RUSTYNET_PHASE9_EVIDENCE_ENVIRONMENT="${RUSTYNET_PHASE9_EVIDENCE_ENVIRONMENT:-ci}" \
  ./scripts/operations/generate_phase9_artifacts.sh

./scripts/ci/check_phase9_readiness.sh

for required_doc in \
  "documents/operations/CompatibilitySupportPolicy.md" \
  "documents/operations/ProductionSLOAndIncidentReadiness.md" \
  "documents/operations/ProductionRunbook.md" \
  "documents/operations/DisasterRecoveryValidation.md" \
  "documents/operations/BackendAgilityValidation.md" \
  "documents/operations/CryptoDeprecationSchedule.md" \
  "documents/operations/PostQuantumTransitionPlan.md" \
  "documents/operations/FinalLaunchChecklist.md"; do
  if [[ ! -f "$required_doc" ]]; then
    echo "missing phase9 operations artifact: $required_doc"
    exit 1
  fi
done

echo "Phase 9 CI gates: PASS"
