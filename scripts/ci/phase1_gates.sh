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

if rg -n "(Wireguard|WireGuard|wg[-_]|wgctrl)" \
  crates/rustynet-control crates/rustynet-policy crates/rustynet-crypto \
  crates/rustynet-backend-api crates/rustynet-cli crates/rustynet-relay; then
  echo "WireGuard leakage gate failed"
  exit 1
fi

if rg -n "\\bunsafe\\b" crates; then
  echo "Unsafe code gate failed"
  exit 1
fi

if rg -n "\\[\\[UNRESOLVED\\]\\]|\\{\\{UNRESOLVED\\}\\}" crates documents; then
  echo "Documentation hygiene gate failed"
  exit 1
fi

scripts/perf/run_phase1_baseline.sh

echo "Phase 1 CI gates: PASS"
