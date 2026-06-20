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

# G3 (RN-22 / RSA-0077): all ed25519 signature verification must use the strict
# verifier. `VerifyingKey::verify_strict` (RFC 8032 strict / ZIP-215) rejects
# non-canonical S and small-order/torsion components — eliminating ed25519
# signature malleability — whereas the non-strict `Verifier::verify` accepts
# them. The migration covers control/crypto and (RSA-0077) the daemon / dns-zone
# / llm-gateway / cli trust-signature surface. This gate fails closed if a plain
# `.verify(` reappears, so the standard cannot silently regress to half-applied.
# (If a legitimate NON-ed25519 `.verify(` is ever introduced, prefer a typed
# wrapper; otherwise add a narrowly-scoped allowlist to the second grep.)
echo "Checking all ed25519 signature verification uses verify_strict (RN-22)..."
if grep -rn '\.verify(' crates --include='*.rs' \
    | grep -v 'verify_strict' \
    | grep -vE ':[0-9]+:[[:space:]]*(//|///|\*)'; then
  echo "FAIL: non-strict ed25519 .verify() found above — RN-22 mandates VerifyingKey::verify_strict" >&2
  echo "FAIL: verify_strict rejects malleable/non-canonical signatures; replace .verify( with .verify_strict(" >&2
  exit 1
fi
echo "PASS: all ed25519 signature verification uses verify_strict (RN-22 / RSA-0077)"

echo "All security regression gates passed."
exit 0
