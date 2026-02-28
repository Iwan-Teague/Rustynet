#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo audit --deny warnings
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

cargo run -p rustynetd -- --emit-phase10-evidence artifacts/phase10

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

if ! rg -q '"status": "pass"' artifacts/phase10/netns_e2e_report.json; then
  echo "netns e2e artifact did not report pass"
  exit 1
fi
if ! rg -q '"status": "pass"' artifacts/phase10/leak_test_report.json; then
  echo "leak test artifact did not report pass"
  exit 1
fi
if ! rg -q '"status": "pass"' artifacts/phase10/direct_relay_failover_report.json; then
  echo "failover artifact did not report pass"
  exit 1
fi
if ! rg -q 'idle_cpu_percent' artifacts/phase10/perf_budget_report.json; then
  echo "perf artifact missing required metrics"
  exit 1
fi
if ! rg -q 'generation=' artifacts/phase10/state_transition_audit.log; then
  echo "state transition audit missing generation entries"
  exit 1
fi

echo "Phase 10 CI gates: PASS"
