#!/usr/bin/env bash
# Vendored unsafe-code census drift gate (AQ-248; T2 security-bar B1/C9).
# The gate logic and its failure modes live in the Rust bin; this wrapper
# only runs it the same way scripts/ci/check_backend_boundary_leakage.sh
# runs its bin.
exec cargo run --quiet -p rustynet-cli --bin check_vendored_unsafe_counts -- "$@"
