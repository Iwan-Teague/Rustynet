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

AUDIT_DB="${RUSTYNET_AUDIT_DB_PATH:-$ROOT_DIR/.cargo-audit-db}"
SECURITY_TOOLCHAIN="${RUSTYNET_SECURITY_TOOLCHAIN:-1.88.0}"
"$ROOT_DIR/scripts/ci/prepare_advisory_db.sh" "$AUDIT_DB"
SOURCE_CARGO_HOME="${RUSTYNET_SOURCE_CARGO_HOME:-${CARGO_HOME:-$HOME/.cargo}}"
AUDIT_HOME="${RUSTYNET_AUDIT_HOME:-$ROOT_DIR/.ci-home}"
CARGO_HOME_PATH="${RUSTYNET_CARGO_HOME_PATH:-$ROOT_DIR/.cargo-home}"
USE_SOURCE_CARGO_HOME=1
probe_file="$SOURCE_CARGO_HOME/.rustynet-ci-write-test.$$"
if [[ ! -d "$SOURCE_CARGO_HOME" ]]; then
  if ! mkdir -p "$SOURCE_CARGO_HOME" 2>/dev/null; then
    USE_SOURCE_CARGO_HOME=0
  fi
fi
if [[ "$USE_SOURCE_CARGO_HOME" -eq 1 ]]; then
  if ! ( : > "$probe_file" ) 2>/dev/null; then
    USE_SOURCE_CARGO_HOME=0
  else
    rm -f "$probe_file"
  fi
fi

if [[ "$USE_SOURCE_CARGO_HOME" -eq 1 ]]; then
  EFFECTIVE_HOME="$HOME"
  EFFECTIVE_CARGO_HOME="$SOURCE_CARGO_HOME"
  DENY_DISABLE_FETCH=0
else
  EFFECTIVE_HOME="$AUDIT_HOME"
  EFFECTIVE_CARGO_HOME="$CARGO_HOME_PATH"
  DENY_DISABLE_FETCH=1
  mkdir -p "$AUDIT_HOME" "$CARGO_HOME_PATH"
  if [[ "$SOURCE_CARGO_HOME" != "$CARGO_HOME_PATH" ]]; then
    if [[ ! -d "$CARGO_HOME_PATH/advisory-dbs" && -d "$SOURCE_CARGO_HOME/advisory-dbs" ]]; then
      cp -R "$SOURCE_CARGO_HOME/advisory-dbs" "$CARGO_HOME_PATH/advisory-dbs"
    fi
    if [[ ! -d "$CARGO_HOME_PATH/registry" && -d "$SOURCE_CARGO_HOME/registry" ]]; then
      cp -R "$SOURCE_CARGO_HOME/registry" "$CARGO_HOME_PATH/registry"
    fi
    if [[ ! -d "$CARGO_HOME_PATH/git" && -d "$SOURCE_CARGO_HOME/git" ]]; then
      cp -R "$SOURCE_CARGO_HOME/git" "$CARGO_HOME_PATH/git"
    fi
  fi
  DENY_DB_ROOT="$CARGO_HOME_PATH/advisory-dbs"
  # cargo-deny keys advisory DB directories by URL hash; allow override if upstream changes.
  DENY_DB_NAME="${RUSTYNET_CARGO_DENY_DB_NAME:-advisory-db-3157b0e258782691}"
  if [[ ! -d "$DENY_DB_ROOT/$DENY_DB_NAME" ]]; then
    mkdir -p "$DENY_DB_ROOT"
    cp -R "$AUDIT_DB" "$DENY_DB_ROOT/$DENY_DB_NAME"
  fi
fi

cargo_with_security_toolchain() {
  if cargo +"${SECURITY_TOOLCHAIN}" --version >/dev/null 2>&1; then
    cargo +"${SECURITY_TOOLCHAIN}" "$@"
  else
    cargo "$@"
  fi
}

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features
HOME="$EFFECTIVE_HOME" CARGO_HOME="$EFFECTIVE_CARGO_HOME" cargo_with_security_toolchain audit --deny warnings --stale --no-fetch --db "$AUDIT_DB"
if [[ "$DENY_DISABLE_FETCH" -eq 1 ]]; then
  HOME="$EFFECTIVE_HOME" CARGO_HOME="$EFFECTIVE_CARGO_HOME" cargo_with_security_toolchain deny check --disable-fetch bans licenses sources advisories
else
  HOME="$EFFECTIVE_HOME" CARGO_HOME="$EFFECTIVE_CARGO_HOME" cargo_with_security_toolchain deny check bans licenses sources advisories
fi

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
MEMBERSHIP_SOURCE_SNAPSHOT_PATH="${RUSTYNET_MEMBERSHIP_SOURCE_SNAPSHOT_PATH:-artifacts/membership/source/membership.snapshot}"
MEMBERSHIP_SOURCE_LOG_PATH="${RUSTYNET_MEMBERSHIP_SOURCE_LOG_PATH:-artifacts/membership/source/membership.log}"
MEMBERSHIP_BOOTSTRAP_STATE_DIR="${RUSTYNET_MEMBERSHIP_BOOTSTRAP_STATE_DIR:-artifacts/membership/tmp_membership}"
MEMBERSHIP_BOOTSTRAP_STATE=0

if [[ ! -f "$MEMBERSHIP_SNAPSHOT_PATH" || ! -f "$MEMBERSHIP_LOG_PATH" ]]; then
  if [[ -f "$MEMBERSHIP_SOURCE_SNAPSHOT_PATH" && -f "$MEMBERSHIP_SOURCE_LOG_PATH" ]]; then
    mkdir -p "$MEMBERSHIP_BOOTSTRAP_STATE_DIR"
    cp "$MEMBERSHIP_SOURCE_SNAPSHOT_PATH" "$MEMBERSHIP_BOOTSTRAP_STATE_DIR/membership.snapshot"
    cp "$MEMBERSHIP_SOURCE_LOG_PATH" "$MEMBERSHIP_BOOTSTRAP_STATE_DIR/membership.log"
    chmod 600 "$MEMBERSHIP_BOOTSTRAP_STATE_DIR/membership.snapshot" "$MEMBERSHIP_BOOTSTRAP_STATE_DIR/membership.log"
    MEMBERSHIP_SNAPSHOT_PATH="$MEMBERSHIP_BOOTSTRAP_STATE_DIR/membership.snapshot"
    MEMBERSHIP_LOG_PATH="$MEMBERSHIP_BOOTSTRAP_STATE_DIR/membership.log"
    MEMBERSHIP_BOOTSTRAP_STATE=1
  else
    echo "membership state sources are missing; provide runtime paths via RUSTYNET_MEMBERSHIP_SNAPSHOT_PATH/RUSTYNET_MEMBERSHIP_LOG_PATH or seed files under artifacts/membership/source"
    exit 1
  fi
fi

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
  if [[ "$MEMBERSHIP_BOOTSTRAP_STATE" != "1" ]] || \
    ! rg -q '"entries"\s*:\s*0' artifacts/membership/membership_conformance_report.json; then
    echo "membership audit integrity log missing chain entries"
    exit 1
  fi
fi

echo "Membership CI gates: PASS"
