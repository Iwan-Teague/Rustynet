#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if ! command -v rg >/dev/null 2>&1; then
  echo "missing required command: rg" >&2
  exit 1
fi

LEAKAGE_PATTERN='(wireguard|wg[-_]|wgctrl)'
SCAN_TARGETS=(
  "crates/rustynet-control/src"
  "crates/rustynet-policy/src"
  "crates/rustynet-crypto/src"
  "crates/rustynet-backend-api/src"
  "crates/rustynet-relay/src"
)

if rg -n -i "$LEAKAGE_PATTERN" "${SCAN_TARGETS[@]}"; then
  echo "backend boundary leakage gate failed"
  exit 1
fi

echo "Backend boundary leakage checks: PASS"
