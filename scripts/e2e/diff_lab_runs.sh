#!/usr/bin/env bash
# Usage: diff_lab_runs.sh <run-dir-A> <run-dir-B>
# Compares stage results between two lab run directories.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  printf 'Usage: %s <run-dir-A> <run-dir-B>\n' "$(basename "$0")" >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

exec cargo run --quiet -p rustynet-cli --features vm-lab -- ops diff-run-summaries \
  --run-a "${1}/run_summary.json" \
  --run-b "${2}/run_summary.json"
