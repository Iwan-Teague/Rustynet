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

if rg -n 'BEGIN PRIVATE KEY|SECRET_KEY=|API_KEY=|TOKEN=.{8,}|password\s*=\s*"[^"]+"' crates; then
  echo "Secret redaction gate failed"
  exit 1
fi

cargo test -p rustynetd phase10::tests --all-features
cargo test -p rustynet-backend-wireguard --all-targets --all-features

if [[ "${RUSTYNET_PHASE10_RUN_REAL_E2E:-0}" == "1" ]]; then
  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "real phase10 e2e can only run on Linux hosts"
    exit 1
  fi
  if [[ "$(id -u)" -eq 0 ]]; then
    ./scripts/e2e/real_wireguard_exitnode_e2e.sh
  else
    sudo -E ./scripts/e2e/real_wireguard_exitnode_e2e.sh
  fi
fi

for artifact in \
  "artifacts/phase10/netns_e2e_report.json" \
  "artifacts/phase10/leak_test_report.json" \
  "artifacts/phase10/perf_budget_report.json" \
  "artifacts/phase10/direct_relay_failover_report.json" \
  "artifacts/phase10/state_transition_audit.log"; do
  if [[ ! -f "$artifact" ]]; then
    echo "missing phase10 artifact: $artifact"
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

require_measured_evidence_metadata "artifacts/phase10/netns_e2e_report.json"
require_measured_evidence_metadata "artifacts/phase10/leak_test_report.json"
require_measured_evidence_metadata "artifacts/phase10/perf_budget_report.json"
require_measured_evidence_metadata "artifacts/phase10/direct_relay_failover_report.json"

if ! rg -q '"status"\s*:\s*"pass"' artifacts/phase10/netns_e2e_report.json; then
  echo "netns e2e artifact did not report pass"
  exit 1
fi
if ! rg -q '"status"\s*:\s*"pass"' artifacts/phase10/leak_test_report.json; then
  echo "leak test artifact did not report pass"
  exit 1
fi
if ! rg -q '"status"\s*:\s*"pass"' artifacts/phase10/direct_relay_failover_report.json; then
  echo "failover artifact did not report pass"
  exit 1
fi
if ! rg -q 'idle_cpu_percent' artifacts/phase10/perf_budget_report.json; then
  echo "perf artifact missing required metrics"
  exit 1
fi
if ! rg -q '"soak_status"\s*:\s*"pass"' artifacts/phase10/perf_budget_report.json; then
  echo "perf artifact did not report passing soak status"
  exit 1
fi
if rg -q '"status"\s*:\s*"fail"' artifacts/phase10/perf_budget_report.json; then
  echo "perf artifact contains failing metric status"
  exit 1
fi
if ! rg -q 'generation=' artifacts/phase10/state_transition_audit.log; then
  echo "state transition audit missing generation entries"
  exit 1
fi

echo "Phase 10 CI gates: PASS"
