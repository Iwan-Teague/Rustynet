#!/usr/bin/env bash
set -euo pipefail

echo "Running security regression gates..."

# Run the Rust-based gates. The historical G1 grep-based secret-
# material-equality check that lived here has been migrated to a
# typed Rust scanner with a structured allowlist + self-tests — see
# `scan_source_for_secret_material_equality` in
# `crates/rustynetd/src/secret_log_audit.rs`. That scanner runs as
# part of `cargo test -p rustynetd` (e.g. via the full workspace
# test gate). The shell intentionally no longer attempts a
# fragile second pass for raw secret equality; the Rust scanner is
# now the single source of truth for that policy.
cargo run --quiet -p rustynet-cli --bin security_regression_gates -- "$@"

# G2a: Fail if a deprecated-crypto crate package name appears in
# Cargo.lock (fast, no network). Names must stay in sync with the
# [[bans.deny]] list in deny.toml (G2b leg).
echo "Checking Cargo.lock for deprecated cryptographic algorithm packages..."
if grep -iE '^name = "(sha1|md-5|md5|des|des3|3des|triple-des)"' Cargo.lock 2>/dev/null; then
  echo "FAIL: deprecated cryptographic algorithm crate found in Cargo.lock" >&2
  echo "FAIL: remove the dependency or disable the feature that pulls in sha1/3des/md5" >&2
  exit 1
fi
echo "PASS: no deprecated crypto algorithm crates in Cargo.lock"

# G2b: cargo deny check bans (enforces deny.toml [[bans.deny]] entries)
echo "Running cargo deny check bans for deprecated crypto algorithms..."
if ! cargo deny check bans 2>&1; then
  echo "FAIL: cargo deny check bans failed — check deny.toml for details" >&2
  exit 1
fi
echo "PASS: cargo deny bans check passed"

# G2c: Source scan — historical grep-based check migrated to a typed
# Rust scanner. `scan_source_for_deprecated_crypto_imports` in
# `crates/rustynetd/src/secret_log_audit.rs` walks every `.rs` file
# under `crates/` and rejects `use sha1` / `use md5` / `use md_5` /
# `use des` / `use des3` / `use triple_des` with a boundary-terminator
# check that correctly rejects safe-name lookalikes (sha2 / sha3 /
# descriptor / md_hashlib). The Rust scanner runs as a regular
# `#[test]` under every `cargo test -p rustynetd` invocation and is
# pinned by the `secret_log_audit:45` floor in the shared
# regression-coverage group, so silent removal of the scan trips a
# named test failure. The shell grep is no longer the source of
# truth — it lived here from before the X3 migration landed and the
# Rust scanner duplicates its coverage with stronger guarantees.

echo "All security regression gates passed."
exit 0
