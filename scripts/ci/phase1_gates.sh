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
  rustup run "${SECURITY_TOOLCHAIN}" cargo "$@"
}

if ! rustup run "${SECURITY_TOOLCHAIN}" cargo --version >/dev/null 2>&1; then
  echo "missing required pinned security toolchain: ${SECURITY_TOOLCHAIN}" >&2
  echo "install with: rustup toolchain install ${SECURITY_TOOLCHAIN}" >&2
  exit 1
fi

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

if rg -n "(Wireguard|WireGuard|wg[-_]|wgctrl)" \
  crates/rustynet-control crates/rustynet-policy crates/rustynet-crypto \
  crates/rustynet-backend-api crates/rustynet-cli crates/rustynet-relay; then
  echo "WireGuard leakage gate failed"
  exit 1
fi

if ! python3 - <<'PY'
from pathlib import Path
import sys


def advance_position(text: str, index: int, line: int, column: int):
    ch = text[index]
    if ch == "\n":
        return index + 1, line + 1, 1
    return index + 1, line, column + 1


def scan_file(path: Path):
    text = path.read_text(encoding="utf-8")
    findings = []

    i = 0
    line = 1
    column = 1
    n = len(text)

    state = "normal"
    block_depth = 0
    raw_hashes = 0

    while i < n:
        ch = text[i]

        if state == "normal":
            if ch == "/" and i + 1 < n and text[i + 1] == "/":
                i, line, column = advance_position(text, i, line, column)
                i, line, column = advance_position(text, i, line, column)
                state = "line_comment"
                continue
            if ch == "/" and i + 1 < n and text[i + 1] == "*":
                i, line, column = advance_position(text, i, line, column)
                i, line, column = advance_position(text, i, line, column)
                state = "block_comment"
                block_depth = 1
                continue
            if ch == "\"":
                i, line, column = advance_position(text, i, line, column)
                state = "string"
                continue
            if ch == "'":
                i, line, column = advance_position(text, i, line, column)
                state = "char"
                continue
            if ch == "r":
                j = i + 1
                hashes = 0
                while j < n and text[j] == "#":
                    hashes += 1
                    j += 1
                if j < n and text[j] == "\"":
                    while i <= j:
                        i, line, column = advance_position(text, i, line, column)
                    state = "raw_string"
                    raw_hashes = hashes
                    continue
            if ch.isalpha() or ch == "_":
                start_i = i
                start_line = line
                start_col = column
                while i < n and (text[i].isalnum() or text[i] == "_"):
                    i, line, column = advance_position(text, i, line, column)
                token = text[start_i:i]
                if token == "unsafe":
                    findings.append((start_line, start_col))
                continue

            i, line, column = advance_position(text, i, line, column)
            continue

        if state == "line_comment":
            if ch == "\n":
                i, line, column = advance_position(text, i, line, column)
                state = "normal"
            else:
                i, line, column = advance_position(text, i, line, column)
            continue

        if state == "block_comment":
            if ch == "/" and i + 1 < n and text[i + 1] == "*":
                i, line, column = advance_position(text, i, line, column)
                i, line, column = advance_position(text, i, line, column)
                block_depth += 1
                continue
            if ch == "*" and i + 1 < n and text[i + 1] == "/":
                i, line, column = advance_position(text, i, line, column)
                i, line, column = advance_position(text, i, line, column)
                block_depth -= 1
                if block_depth == 0:
                    state = "normal"
                continue

            i, line, column = advance_position(text, i, line, column)
            continue

        if state == "string":
            if ch == "\\":
                i, line, column = advance_position(text, i, line, column)
                if i < n:
                    i, line, column = advance_position(text, i, line, column)
                continue
            if ch == "\"":
                i, line, column = advance_position(text, i, line, column)
                state = "normal"
                continue

            i, line, column = advance_position(text, i, line, column)
            continue

        if state == "char":
            if ch == "\\":
                i, line, column = advance_position(text, i, line, column)
                if i < n:
                    i, line, column = advance_position(text, i, line, column)
                continue
            if ch == "'":
                i, line, column = advance_position(text, i, line, column)
                state = "normal"
                continue

            i, line, column = advance_position(text, i, line, column)
            continue

        if state == "raw_string":
            if ch == "\"":
                suffix_start = i + 1
                suffix_end = suffix_start + raw_hashes
                if suffix_end <= n and text[suffix_start:suffix_end] == "#" * raw_hashes:
                    i, line, column = advance_position(text, i, line, column)
                    for _ in range(raw_hashes):
                        i, line, column = advance_position(text, i, line, column)
                    state = "normal"
                    continue

            i, line, column = advance_position(text, i, line, column)
            continue

        raise RuntimeError(f"unknown scanner state {state}")

    return findings


root = Path("crates")
all_findings = []

for path in sorted(root.rglob("*.rs")):
    if "target" in path.parts:
        continue
    for line, col in scan_file(path):
        all_findings.append((path, line, col))

if all_findings:
    print("unsafe keyword usage is forbidden in repository Rust sources:")
    for path, line, col in all_findings:
        print(f"{path}:{line}:{col}: unsafe keyword detected")
    sys.exit(1)
PY
then
  echo "Unsafe code gate failed"
  exit 1
fi

if rg -n "\\[\\[UNRESOLVED\\]\\]|\\{\\{UNRESOLVED\\}\\}" crates documents; then
  echo "Documentation hygiene gate failed"
  exit 1
fi

scripts/perf/run_phase1_baseline.sh

echo "Phase 1 CI gates: PASS"
