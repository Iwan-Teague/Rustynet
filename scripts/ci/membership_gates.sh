#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

AUDIT_DB="${RUSTYNET_AUDIT_DB_PATH:-$ROOT_DIR/.cargo-audit-db}"
if [[ ! -d "$AUDIT_DB" && -d "$HOME/.cargo/advisory-db" ]]; then
  mkdir -p "$(dirname "$AUDIT_DB")"
  cp -R "$HOME/.cargo/advisory-db" "$AUDIT_DB"
fi

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features
CARGO_HOME="$ROOT_DIR/.cargo-home" cargo audit --deny warnings --stale --no-fetch --db "$AUDIT_DB"
cargo deny check bans licenses sources advisories

./scripts/ci/phase9_gates.sh
./scripts/ci/phase10_gates.sh

if rg -n "(Wireguard|WireGuard|wg[-_]|wgctrl)" \
  crates/rustynet-control \
  crates/rustynet-policy \
  crates/rustynet-crypto \
  crates/rustynet-backend-api \
  crates/rustynet-cli \
  crates/rustynet-relay; then
  echo "WireGuard boundary leakage gate failed"
  exit 1
fi

cargo test -p rustynet-control membership::tests --all-features
cargo test -p rustynet-policy membership_aware --all-features
cargo test -p rustynetd daemon_runtime_denies_exit_selection_for_revoked_membership_node --all-features

MEMBERSHIP_SNAPSHOT_PATH="${RUSTYNET_MEMBERSHIP_SNAPSHOT_PATH:-/var/lib/rustynet/membership.snapshot}"
MEMBERSHIP_LOG_PATH="${RUSTYNET_MEMBERSHIP_LOG_PATH:-/var/lib/rustynet/membership.log}"
MEMBERSHIP_EVIDENCE_ENVIRONMENT="${RUSTYNET_MEMBERSHIP_EVIDENCE_ENVIRONMENT:-ci}"

mkdir -p artifacts/membership
cargo run -p rustynet-cli -- membership generate-evidence \
  --snapshot "${MEMBERSHIP_SNAPSHOT_PATH}" \
  --log "${MEMBERSHIP_LOG_PATH}" \
  --output-dir artifacts/membership \
  --environment "${MEMBERSHIP_EVIDENCE_ENVIRONMENT}"

for artifact in \
  "artifacts/membership/membership_conformance_report.json" \
  "artifacts/membership/membership_negative_tests_report.json" \
  "artifacts/membership/membership_recovery_report.json" \
  "artifacts/membership/membership_audit_integrity.log"; do
  if [[ ! -f "$artifact" ]]; then
    echo "missing membership artifact: $artifact"
    exit 1
  fi
done

require_measured_evidence_metadata() {
  local artifact="$1"
  if ! rg -q '"evidence_mode"\s*:\s*"measured"' "${artifact}"; then
    echo "artifact is not measured evidence: ${artifact}"
    exit 1
  fi
  if ! rg -q '"captured_at_unix"\s*:\s*[0-9]+' "${artifact}"; then
    echo "artifact missing captured_at_unix metadata: ${artifact}"
    exit 1
  fi
  if ! rg -q '"environment"\s*:\s*"[^"]+"' "${artifact}"; then
    echo "artifact missing environment metadata: ${artifact}"
    exit 1
  fi
}

require_measured_evidence_metadata "artifacts/membership/membership_conformance_report.json"
require_measured_evidence_metadata "artifacts/membership/membership_negative_tests_report.json"
require_measured_evidence_metadata "artifacts/membership/membership_recovery_report.json"

if ! rg -q '"status"\s*:\s*"pass"' artifacts/membership/membership_conformance_report.json; then
  echo "membership conformance report is not pass"
  exit 1
fi
if ! rg -q '"status"\s*:\s*"pass"' artifacts/membership/membership_negative_tests_report.json; then
  echo "membership negative report is not pass"
  exit 1
fi
if ! rg -q '"status"\s*:\s*"pass"' artifacts/membership/membership_recovery_report.json; then
  echo "membership recovery report is not pass"
  exit 1
fi
if rg -q '"status"\s*:\s*"fail"' artifacts/membership/membership_negative_tests_report.json; then
  echo "membership negative report contains failure status"
  exit 1
fi
if ! rg -q 'index=' artifacts/membership/membership_audit_integrity.log; then
  echo "membership audit integrity log missing chain entries"
  exit 1
fi

echo "Membership CI gates: PASS"
