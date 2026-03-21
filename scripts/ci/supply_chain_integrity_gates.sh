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
require_command rustup
require_command rustc
require_cargo_subcommand audit
require_cargo_subcommand deny

AUDIT_DB="${RUSTYNET_AUDIT_DB_PATH:-$ROOT_DIR/.cargo-audit-db}"
HOST_TRIPLE="$(rustc -vV | awk '/^host: / {print $2}')"
SECURITY_TOOLCHAIN="${RUSTYNET_SECURITY_TOOLCHAIN:-1.88.0-${HOST_TRIPLE}}"
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
  EFFECTIVE_CARGO_HOME="$SOURCE_CARGO_HOME"
  DENY_DISABLE_FETCH=0
else
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
  DENY_DB_NAME="${RUSTYNET_CARGO_DENY_DB_NAME:-advisory-db-3157b0e258782691}"
  if [[ ! -d "$DENY_DB_ROOT/$DENY_DB_NAME" ]]; then
    mkdir -p "$DENY_DB_ROOT"
    cp -R "$AUDIT_DB" "$DENY_DB_ROOT/$DENY_DB_NAME"
  fi
fi

cargo_with_security_toolchain() {
  rustup run "${SECURITY_TOOLCHAIN}" cargo "$@"
}

if ! rustup run "${SECURITY_TOOLCHAIN}" cargo --version >/dev/null 2>&1; then
  echo "missing required pinned security toolchain: ${SECURITY_TOOLCHAIN}" >&2
  echo "install with: rustup toolchain install ${SECURITY_TOOLCHAIN}" >&2
  exit 1
fi

EFFECTIVE_RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
CARGO_HOME="$EFFECTIVE_CARGO_HOME" RUSTUP_HOME="$EFFECTIVE_RUSTUP_HOME" cargo_with_security_toolchain audit --deny warnings --stale --no-fetch --db "$AUDIT_DB"
if [[ "$DENY_DISABLE_FETCH" -eq 1 ]]; then
  CARGO_HOME="$EFFECTIVE_CARGO_HOME" RUSTUP_HOME="$EFFECTIVE_RUSTUP_HOME" cargo_with_security_toolchain deny check --disable-fetch bans licenses sources advisories
else
  CARGO_HOME="$EFFECTIVE_CARGO_HOME" RUSTUP_HOME="$EFFECTIVE_RUSTUP_HOME" cargo_with_security_toolchain deny check bans licenses sources advisories
fi

cargo build --release -p rustynetd
./scripts/release/generate_sbom.sh

RELEASE_ARTIFACT_PATH="${RUSTYNET_RELEASE_ARTIFACT_PATH:-target/release/rustynetd}"
RELEASE_TRACK="${RUSTYNET_RELEASE_TRACK:-beta}"
RELEASE_PROVENANCE_PATH="${RUSTYNET_RELEASE_PROVENANCE_PATH:-artifacts/release/rustynetd.provenance.json}"
RELEASE_SBOM_PATH="${RUSTYNET_RELEASE_SBOM_PATH:-artifacts/release/sbom.cargo-metadata.json}"
RELEASE_SBOM_SHA256_PATH="${RUSTYNET_RELEASE_SBOM_SHA256_PATH:-artifacts/release/sbom.sha256}"

for required_file in "$RELEASE_ARTIFACT_PATH" "$RELEASE_SBOM_PATH" "$RELEASE_SBOM_SHA256_PATH"; do
  if [[ ! -f "$required_file" ]]; then
    echo "missing required supply-chain input: $required_file" >&2
    exit 1
  fi
done

RUSTYNET_RELEASE_ARTIFACT_PATH="$RELEASE_ARTIFACT_PATH" \
RUSTYNET_RELEASE_TRACK="$RELEASE_TRACK" \
RUSTYNET_RELEASE_PROVENANCE_PATH="$RELEASE_PROVENANCE_PATH" \
RUSTYNET_RELEASE_SBOM_PATH="$RELEASE_SBOM_PATH" \
RUSTYNET_RELEASE_SBOM_SHA256_PATH="$RELEASE_SBOM_SHA256_PATH" \
cargo run --quiet -p rustynet-cli -- ops sign-release-artifact

RUSTYNET_RELEASE_ARTIFACT_PATH="$RELEASE_ARTIFACT_PATH" \
RUSTYNET_RELEASE_TRACK="$RELEASE_TRACK" \
RUSTYNET_RELEASE_PROVENANCE_PATH="$RELEASE_PROVENANCE_PATH" \
RUSTYNET_RELEASE_SBOM_PATH="$RELEASE_SBOM_PATH" \
RUSTYNET_RELEASE_SBOM_SHA256_PATH="$RELEASE_SBOM_SHA256_PATH" \
cargo run --quiet -p rustynet-cli -- ops verify-release-artifact

TMP_DIR="$ROOT_DIR/artifacts/release/.supply-chain-tmp"
mkdir -p "$TMP_DIR"
UNSIGNED_PROVENANCE_PATH="$(mktemp "$TMP_DIR/unsigned.XXXXXX")"
TAMPERED_ARTIFACT_PATH="$(mktemp "$TMP_DIR/tampered-artifact.XXXXXX")"
TAMPERED_PROVENANCE_PATH="$(mktemp "$TMP_DIR/tampered.XXXXXX")"
cleanup() {
  rm -f "$UNSIGNED_PROVENANCE_PATH" "$TAMPERED_ARTIFACT_PATH" "$TAMPERED_PROVENANCE_PATH"
}
trap cleanup EXIT

cargo run --quiet -p rustynet-cli -- ops write-unsigned-release-provenance \
  --input "$RELEASE_PROVENANCE_PATH" \
  --output "$UNSIGNED_PROVENANCE_PATH"

if RUSTYNET_RELEASE_ARTIFACT_PATH="$RELEASE_ARTIFACT_PATH" \
  RUSTYNET_RELEASE_TRACK="$RELEASE_TRACK" \
  RUSTYNET_RELEASE_PROVENANCE_PATH="$UNSIGNED_PROVENANCE_PATH" \
  RUSTYNET_RELEASE_SBOM_PATH="$RELEASE_SBOM_PATH" \
  RUSTYNET_RELEASE_SBOM_SHA256_PATH="$RELEASE_SBOM_SHA256_PATH" \
  cargo run --quiet -p rustynet-cli -- ops verify-release-artifact; then
  echo "supply-chain gate failed: unsigned provenance was accepted" >&2
  exit 1
fi

cp "$RELEASE_ARTIFACT_PATH" "$TAMPERED_ARTIFACT_PATH"
RUSTYNET_RELEASE_ARTIFACT_PATH="$TAMPERED_ARTIFACT_PATH" \
RUSTYNET_RELEASE_TRACK="$RELEASE_TRACK" \
RUSTYNET_RELEASE_PROVENANCE_PATH="$TAMPERED_PROVENANCE_PATH" \
RUSTYNET_RELEASE_SBOM_PATH="$RELEASE_SBOM_PATH" \
RUSTYNET_RELEASE_SBOM_SHA256_PATH="$RELEASE_SBOM_SHA256_PATH" \
cargo run --quiet -p rustynet-cli -- ops sign-release-artifact
printf "tamper\n" >> "$TAMPERED_ARTIFACT_PATH"

if RUSTYNET_RELEASE_ARTIFACT_PATH="$TAMPERED_ARTIFACT_PATH" \
  RUSTYNET_RELEASE_TRACK="$RELEASE_TRACK" \
  RUSTYNET_RELEASE_PROVENANCE_PATH="$TAMPERED_PROVENANCE_PATH" \
  RUSTYNET_RELEASE_SBOM_PATH="$RELEASE_SBOM_PATH" \
  RUSTYNET_RELEASE_SBOM_SHA256_PATH="$RELEASE_SBOM_SHA256_PATH" \
  cargo run --quiet -p rustynet-cli -- ops verify-release-artifact; then
  echo "supply-chain gate failed: tampered artifact was accepted" >&2
  exit 1
fi

echo "Supply-chain integrity gates: PASS"
