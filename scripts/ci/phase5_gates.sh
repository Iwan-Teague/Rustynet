#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features

./scripts/ci/phase4_gates.sh
./scripts/ci/perf_regression_gate.sh

cargo build --workspace --all-targets --all-features
./scripts/release/generate_sbom.sh
./scripts/release/create_provenance.sh "target/debug/rustynetd" "beta" "artifacts/release/rustynetd.provenance.json"

for required_doc in \
  "documents/operations/VulnerabilityResponse.md" \
  "documents/operations/PolicyRolloutRunbook.md" \
  "documents/operations/SecretRedactionCoverage.md"; do
  if [[ ! -f "$required_doc" ]]; then
    echo "missing required operations document: $required_doc"
    exit 1
  fi
done

echo "Phase 5 CI gates: PASS"
