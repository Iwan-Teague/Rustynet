#!/usr/bin/env bash
set -euo pipefail

echo "Running membership CI gates..."

# Lint and deny warnings
cargo clippy -p rustynet-control -- -D warnings

# Run membership unit tests (targeted)
cargo test -p rustynet-control membership -- --nocapture

# Run the higher-level ops membership gates (legacy wrapper)
exec cargo run --quiet -p rustynet-cli --bin membership_gates -- "$@"
