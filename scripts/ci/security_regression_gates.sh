#!/usr/bin/env bash
set -euo pipefail
# Run the Rust-based gates
cargo run --quiet -p rustynet-cli --bin security_regression_gates -- "$@"
# Grep-based CI gate: detect raw equality on secret material (must use subtle::ConstantTimeEq)
if rg -n --hidden --no-ignore --glob 'crates/**' -e "\\.as_bytes\(\)\s*==\s*" -e "\\.as_slice\(\)\s*==\s*" -e "==.*csrf_token"; then
  echo "ERROR: raw equality on secret material detected — use subtle::ConstantTimeEq or verify_slices_are_equal" >&2
  exit 2
fi
exit 0

