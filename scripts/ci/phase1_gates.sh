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
if [[ ! -d "$AUDIT_DB" && -d "$HOME/.cargo/advisory-db" ]]; then
  mkdir -p "$(dirname "$AUDIT_DB")"
  cp -R "$HOME/.cargo/advisory-db" "$AUDIT_DB"
fi

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features
CARGO_HOME="$ROOT_DIR/.cargo-home" cargo +"${SECURITY_TOOLCHAIN}" audit --deny warnings --stale --no-fetch --db "$AUDIT_DB"
cargo +"${SECURITY_TOOLCHAIN}" deny check bans licenses sources advisories

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
