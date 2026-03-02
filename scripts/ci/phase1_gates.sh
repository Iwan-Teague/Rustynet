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
HOME="$AUDIT_HOME" CARGO_HOME="$CARGO_HOME_PATH" cargo_with_security_toolchain audit --deny warnings --stale --no-fetch --db "$AUDIT_DB"
HOME="$AUDIT_HOME" CARGO_HOME="$CARGO_HOME_PATH" cargo_with_security_toolchain deny check --disable-fetch bans licenses sources advisories

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
