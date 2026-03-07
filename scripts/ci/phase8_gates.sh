#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

RUSTYNET_GATE_TEST_THREADS="${RUSTYNET_GATE_TEST_THREADS:-1}"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
RUST_TEST_THREADS="${RUSTYNET_GATE_TEST_THREADS}" cargo test --workspace --all-targets --all-features

./scripts/ci/phase7_gates.sh
./scripts/ci/check_dependency_exceptions.sh
./scripts/ci/supply_chain_integrity_gates.sh

for required_doc in \
  "documents/operations/SecurityAssuranceProgram.md" \
  "documents/operations/DependencyExceptionPolicy.md" \
  "documents/operations/PrivacyRetentionPolicy.md" \
  "documents/operations/ComplianceControlMap.md"; do
  if [[ ! -f "$required_doc" ]]; then
    echo "missing phase8 operations artifact: $required_doc"
    exit 1
  fi
done

echo "Phase 8 CI gates: PASS"
