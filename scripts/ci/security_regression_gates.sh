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

# G2: Fail if sha1 or 3des appear in dependency tree  
echo "Checking for deprecated cryptographic algorithms..."
if cargo audit --deny warnings 2>&1 | grep -iE "sha1|3des|triple.des"; then
  echo "FAIL: deprecated cryptographic algorithm in dependency tree"
  exit 1
fi
echo "PASS: no deprecated crypto algorithms"

echo "All security regression gates passed."
exit 0

