#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features

./scripts/ci/phase5_gates.sh

if ! rg -q "default_web_security_headers" crates/rustynet-control/src/admin.rs; then
  echo "missing web security header baseline"
  exit 1
fi

if ! rg -q "validate_privileged_command" crates/rustynet-control/src/admin.rs; then
  echo "missing privileged helper validation"
  exit 1
fi

if ! rg -q "validate_platform_parity" crates/rustynetd/src/platform.rs; then
  echo "missing cross-platform parity validation"
  exit 1
fi

cargo test -p rustynetd platform::tests --all-features
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
