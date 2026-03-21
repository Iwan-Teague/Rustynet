#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

SCAN_ROOT="${RUSTYNET_UNSAFE_SCAN_ROOT:-crates}"

cargo run --quiet -p rustynet-cli -- ops check-no-unsafe-rust-sources \
  --root "$SCAN_ROOT"
