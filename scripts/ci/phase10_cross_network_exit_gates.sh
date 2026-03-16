#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

ARTIFACT_DIR="${RUSTYNET_PHASE10_ARTIFACT_DIR:-${RUSTYNET_PHASE10_OUT_DIR:-artifacts/phase10}}"
MAX_EVIDENCE_AGE_SECONDS="${RUSTYNET_PHASE10_MAX_EVIDENCE_AGE_SECONDS:-2678400}"
SCHEMA_OUTPUT="${RUSTYNET_PHASE10_CROSS_NETWORK_EXIT_SCHEMA_OUTPUT:-$ARTIFACT_DIR/cross_network_remote_exit_schema_validation.md}"
EXPECTED_COMMIT="${RUSTYNET_PHASE10_CROSS_NETWORK_EXIT_EXPECTED_GIT_COMMIT:-$(git rev-parse HEAD)}"

require_command() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "missing required command: ${cmd}" >&2
    exit 1
  fi
}

require_command python3
require_command git

./scripts/ci/test_validate_cross_network_remote_exit_reports.sh

./scripts/ci/validate_cross_network_remote_exit_reports.py \
  --artifact-dir "$ARTIFACT_DIR" \
  --expected-git-commit "$EXPECTED_COMMIT" \
  --require-pass-status \
  --max-evidence-age-seconds "$MAX_EVIDENCE_AGE_SECONDS" \
  --output "$SCHEMA_OUTPUT"

echo "Phase 10 cross-network remote-exit schema gates: PASS"
