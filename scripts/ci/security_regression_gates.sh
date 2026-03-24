#!/usr/bin/env bash
set -euo pipefail

echo "Running security regression gates..."

# Run the Rust-based gates
cargo run --quiet -p rustynet-cli --bin security_regression_gates -- "$@"

# G1: Grep-based CI gate for secret material equality
echo "Checking for raw equality on secret material..."
if grep -rn --include="*.rs" -E '(token|session_key|nonce|mac|hmac|hash|session_id)\s*(==|!=)\s' \
  crates/rustynet-relay/src/ crates/rustynet-control/src/ 2>/dev/null | \
  grep -v "// EXCEPTION:" | grep -v "ct_eq"; then
  echo "ERROR: raw equality on secret material detected — use subtle::ConstantTimeEq" >&2
  exit 2
fi

# Also check .as_bytes() == patterns
if grep -rn --hidden --no-ignore --glob 'crates/**/*.rs' -E '\\.as_bytes\(\)\s*==\s*|\\.as_slice\(\)\s*==\s*|==.*csrf_token' \
  crates/rustynet-relay/src/ crates/rustynet-control/src/ 2>/dev/null | \
  grep -v "// EXCEPTION:" | grep -v "ct_eq"; then
  echo "ERROR: raw equality on secret material detected — use subtle::ConstantTimeEq" >&2
  exit 2
fi

echo "PASS: no raw secret equality detected"

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

