#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo-fuzz >/dev/null 2>&1; then
  echo "cargo-fuzz is required; install with: cargo install cargo-fuzz --locked" >&2
  exit 1
fi
if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup is required for nightly fuzz toolchain management." >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}/fuzz"

if ! rustup toolchain list | grep -q '^nightly'; then
  rustup toolchain install nightly --profile minimal
fi

for target in ipc_parse_command membership_decode_state membership_decode_signed_update; do
  cargo +nightly fuzz run "${target}" -- -max_total_time=10
  cargo +nightly fuzz cmin "${target}" || true
done
