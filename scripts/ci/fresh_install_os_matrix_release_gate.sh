#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

./scripts/ci/check_fresh_install_os_matrix_readiness.sh

echo "Fresh install OS matrix release gate: PASS"
