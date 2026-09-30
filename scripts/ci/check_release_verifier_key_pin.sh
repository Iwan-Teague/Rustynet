#!/usr/bin/env bash
# Fail unless the release manifest verifier key computed from the signing seed
# matches the key pinned in the macOS bootstrap script.
#
# The `manifest` job of .github/workflows/release.yml verifies the signed
# manifest against the manifest's OWN verifier_key_hex, which is tautological
# for pin drift: if the RUSTYNET_RELEASE_MANIFEST_SEED_HEX secret and
# RUSTYNET_DEFAULT_RELEASE_VERIFIER_KEY_HEX in Bootstrap-RustyNetMacos.sh ever
# disagree, that job still goes green and the first failure is a Mac bootstrap
# refusing the release. This script closes that gap in CI.
#
# Usage: check_release_verifier_key_pin.sh <computed-verifier-key-hex> [pin-file]
# Prints only the first 12 hex chars of each key (never the seed).

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
computed="${1:-}"
pin_file="${2:-$root/scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh}"

if [ -z "$computed" ]; then
  echo "usage: $0 <computed-verifier-key-hex> [pin-file]" >&2
  exit 2
fi
if [ ! -f "$pin_file" ]; then
  echo "::error::pinned-key file not found: $pin_file" >&2
  exit 1
fi

# Exactly one readonly assignment line must exist; anything else fails closed.
pin_lines="$(grep -E '^readonly RUSTYNET_DEFAULT_RELEASE_VERIFIER_KEY_HEX="[^"]*"[[:space:]]*$' "$pin_file" || true)"
if [ "$(printf '%s\n' "$pin_lines" | grep -c .)" -ne 1 ]; then
  echo "::error::expected exactly one RUSTYNET_DEFAULT_RELEASE_VERIFIER_KEY_HEX assignment in $pin_file" >&2
  exit 1
fi
pinned="$(printf '%s' "$pin_lines" | sed -E 's/^[^"]*"([^"]*)".*$/\1/')"

# Lowercase both sides (tr, not ${var,,}: keep bash 3.2 compatible), then
# require strict 64-hex before comparing.
computed="$(printf '%s' "$computed" | tr 'A-F' 'a-f')"
pinned="$(printf '%s' "$pinned" | tr 'A-F' 'a-f')"
for pair in "computed:$computed" "pinned:$pinned"; do
  label="${pair%%:*}"; val="${pair#*:}"
  if ! printf '%s' "$val" | grep -Eq '^[0-9a-f]{64}$'; then
    echo "::error::$label release verifier key is not 64 hex chars (first 12: ${val:0:12})" >&2
    exit 1
  fi
done

if [ "$computed" != "$pinned" ]; then
  echo "::error::release verifier key MISMATCH: the RUSTYNET_RELEASE_MANIFEST_SEED_HEX secret yields ${computed:0:12}... but Bootstrap-RustyNetMacos.sh pins ${pinned:0:12}... — a Mac bootstrap would refuse this release. Re-pin the scripts (Bootstrap-RustyNetMacos.sh, Verify-RustyNetRelease.sh) or fix the secret." >&2
  exit 1
fi
echo "release verifier key matches the bootstrap pin (${computed:0:12}...)"
