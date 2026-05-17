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

# G2a: Fail if sha1 or 3des appear in Cargo.lock (fast, no network)
echo "Checking Cargo.lock for deprecated cryptographic algorithm packages..."
if grep -iE '^name = "(sha1|md-5|des|des3|3des|triple-des)"' Cargo.lock 2>/dev/null; then
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

# G2c: Source scan — reject any use statement importing deprecated crypto crates
echo "Scanning source for imports of deprecated cryptographic crates..."
if grep -rn --include="*.rs" -E \
  '^[[:space:]]*(pub[[:space:]]+)?use[[:space:]]+(sha1|md5|md_5|des|des3|triple_des)(::|;| )' \
  crates/ 2>/dev/null | grep -v "// EXCEPTION:"; then
  echo "FAIL: use-import of deprecated crypto crate found in source" >&2
  exit 1
fi
echo "PASS: no imports of deprecated crypto crates in source"

echo "All security regression gates passed."
exit 0
