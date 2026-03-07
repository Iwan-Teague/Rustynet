#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

RUSTYNET_GATE_TEST_THREADS="${RUSTYNET_GATE_TEST_THREADS:-1}"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
RUST_TEST_THREADS="${RUSTYNET_GATE_TEST_THREADS}" cargo test --workspace --all-targets --all-features

./scripts/ci/phase5_gates.sh

./scripts/ci/run_required_test.sh rustynet-control admin::tests::clickjacking_headers_are_hardened --all-features
./scripts/ci/run_required_test.sh rustynet-control admin::tests::privileged_helper_validation_rejects_shell_construction --all-features
./scripts/ci/run_required_test.sh rustynet-control admin::tests::privileged_helper_validation_accepts_argv_only_commands --all-features

if [[ "${RUSTYNET_PHASE6_COLLECT_PARITY:-0}" == "1" ]]; then
  ./scripts/release/collect_platform_parity_bundle.sh
fi

if [[ "${RUSTYNET_PHASE6_GENERATE_PARITY_REPORT:-1}" == "1" ]]; then
  RUSTYNET_PHASE6_PARITY_ENVIRONMENT="${RUSTYNET_PHASE6_PARITY_ENVIRONMENT:-ci}" \
    ./scripts/release/generate_platform_parity_report.sh
fi

./scripts/ci/run_required_test.sh rustynetd platform::tests --all-features
./scripts/ci/check_phase6_platform_parity.sh

for artifact in \
  "artifacts/release/sbom.cargo-metadata.json" \
  "artifacts/release/sbom.sha256" \
  "artifacts/release/rustynetd.provenance.json"; do
  if [[ ! -f "$artifact" ]]; then
    echo "missing beta release integrity artifact: $artifact"
    exit 1
  fi
done

echo "Phase 6 CI gates: PASS"
