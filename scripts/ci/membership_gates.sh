#!/usr/bin/env bash
set -euo pipefail

echo "Running membership CI gates..."

# Lint and deny warnings
cargo clippy -p rustynet-control -- -D warnings

# Run membership unit tests (targeted)
cargo test -p rustynet-control membership -- --nocapture

# Run policy coupling tests (M5)
cargo test -p rustynet-policy -- --nocapture

# Generate artifacts/phase10/membership_report.json from the targeted test run
# above. Does not require lab artifacts.
cargo run --quiet -p rustynet-cli -- ops write-membership-phase10-report

# Verify the report was produced, parses against the typed schema, and has
# status=pass. The Rust subcommand fails closed on missing file, malformed
# JSON, missing/wrong-type required schema fields, or status!=pass, and maps
# each failure onto the X6 exit-code taxonomy (ConfigError vs PolicyReject).
cargo run --quiet -p rustynet-cli -- ops verify-membership-phase10-report

echo "Membership CI gates: PASS"
