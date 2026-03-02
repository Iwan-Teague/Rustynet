#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo-fuzz >/dev/null 2>&1; then
  echo "cargo-fuzz is required; install with: cargo install cargo-fuzz --locked" >&2
  exit 1
fi

for target in ipc_parse_command membership_decode_state membership_decode_signed_update; do
  cargo fuzz run "${target}" --manifest-path fuzz/Cargo.toml -- -max_total_time=10
  cargo fuzz cmin "${target}" --manifest-path fuzz/Cargo.toml || true
done
