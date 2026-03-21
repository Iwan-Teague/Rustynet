#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "no-leak dataplane gate requires Linux" >&2
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "no-leak dataplane gate requires root privileges" >&2
  exit 1
fi

REPORT_PATH="${RUSTYNET_NO_LEAK_REPORT_PATH:-artifacts/phase10/no_leak_dataplane_report.json}"

RUSTYNET_NO_LEAK_REPORT_PATH="${REPORT_PATH}" ./scripts/e2e/real_wireguard_no_leak_under_load.sh

cargo run --quiet -p rustynet-cli -- ops verify-no-leak-dataplane-report \
  --report-path "${REPORT_PATH}"
