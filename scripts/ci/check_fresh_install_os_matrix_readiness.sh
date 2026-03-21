#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

REPORT_PATH="${RUSTYNET_FRESH_INSTALL_OS_MATRIX_REPORT_PATH:-artifacts/phase10/fresh_install_os_matrix_report.json}"
MAX_AGE_SECONDS="${RUSTYNET_FRESH_INSTALL_OS_MATRIX_MAX_AGE_SECONDS:-604800}"
PROFILE="${RUSTYNET_FRESH_INSTALL_OS_MATRIX_PROFILE:-cross_platform}"
EXPECTED_GIT_COMMIT="${RUSTYNET_FRESH_INSTALL_OS_MATRIX_EXPECTED_GIT_COMMIT:-}"

verify_args=(
  --report-path "$REPORT_PATH"
  --max-age-seconds "$MAX_AGE_SECONDS"
  --profile "$PROFILE"
)
if [[ -n "$EXPECTED_GIT_COMMIT" ]]; then
  verify_args+=(--expected-git-commit "$EXPECTED_GIT_COMMIT")
fi

cargo run --quiet -p rustynet-cli -- ops verify-linux-fresh-install-os-matrix-readiness "${verify_args[@]}"
