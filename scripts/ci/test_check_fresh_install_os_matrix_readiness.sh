#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

head_commit="$(git rev-parse HEAD | tr '[:upper:]' '[:lower:]')"
stale_commit="1111111111111111111111111111111111111111"
now_unix="$(date +%s)"

cargo run --quiet -p rustynet-cli -- ops write-fresh-install-os-matrix-readiness-fixtures \
  --output-dir "$tmpdir" \
  --head-commit "$head_commit" \
  --stale-commit "$stale_commit" \
  --now-unix "$now_unix"

RUSTYNET_FRESH_INSTALL_OS_MATRIX_PROFILE=linux \
RUSTYNET_FRESH_INSTALL_OS_MATRIX_REPORT_PATH="$tmpdir/report.json" \
RUSTYNET_FRESH_INSTALL_OS_MATRIX_EXPECTED_GIT_COMMIT="$head_commit" \
./scripts/ci/check_fresh_install_os_matrix_readiness.sh

if RUSTYNET_FRESH_INSTALL_OS_MATRIX_PROFILE=linux \
  RUSTYNET_FRESH_INSTALL_OS_MATRIX_REPORT_PATH="$tmpdir/report_with_stale_child.json" \
  RUSTYNET_FRESH_INSTALL_OS_MATRIX_EXPECTED_GIT_COMMIT="$head_commit" \
  ./scripts/ci/check_fresh_install_os_matrix_readiness.sh; then
  echo "expected stale child commit replay fixture to fail readiness validation" >&2
  exit 1
fi

echo "fresh install OS matrix readiness self-test: PASS"
