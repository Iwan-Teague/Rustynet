#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

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
cargo test --workspace --all-targets --all-features

./scripts/ci/phase8_gates.sh
./scripts/ci/phase1_gates.sh

cargo test -p rustynet-control ga::tests --all-features
cargo test -p rustynet-backend-wireguard --test conformance --all-features
cargo test -p rustynet-backend-api --all-targets --all-features

if [[ "${RUSTYNET_PHASE9_COLLECT_RAW:-1}" == "1" ]]; then
  ./scripts/operations/collect_phase9_raw_evidence.sh
fi

if [[ "${RUSTYNET_PHASE9_GENERATE_ARTIFACTS:-1}" == "1" ]]; then
  RUSTYNET_PHASE9_EVIDENCE_ENVIRONMENT="${RUSTYNET_PHASE9_EVIDENCE_ENVIRONMENT:-ci}" \
    ./scripts/operations/generate_phase9_artifacts.sh
fi

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
