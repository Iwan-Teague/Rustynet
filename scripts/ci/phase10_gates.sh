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
