#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "Running membership CI gates..."

# Lint and deny warnings
cargo clippy -p rustynet-control -- -D warnings

# Run membership unit tests (targeted)
cargo test -p rustynet-control membership -- --nocapture

# Run policy coupling tests (M5)
cargo test -p rustynet-policy -- --nocapture

# Verify membership evidence artifact exists and is well-formed JSON
MEMBERSHIP_REPORT="${REPO_ROOT}/artifacts/phase10/membership_report.json"
if [[ ! -f "${MEMBERSHIP_REPORT}" ]]; then
    echo "GATE FAIL: artifacts/phase10/membership_report.json is missing" >&2
    exit 1
fi
if ! python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert d.get('status')=='pass', 'status!=pass'" \
        "${MEMBERSHIP_REPORT}" 2>/dev/null; then
    echo "GATE FAIL: artifacts/phase10/membership_report.json schema validation failed" >&2
    exit 1
fi
echo "membership_report.json schema validation: pass"

# Run the higher-level ops membership gates (legacy wrapper)
exec cargo run --quiet -p rustynet-cli --bin membership_gates -- "$@"
