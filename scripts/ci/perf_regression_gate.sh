#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

PHASE1_REPORT="${RUSTYNET_PHASE1_PERF_REPORT:-artifacts/perf/phase1/baseline.json}"
PHASE3_REPORT="${RUSTYNET_PHASE3_PERF_REPORT:-artifacts/perf/phase3/mesh_baseline.json}"

cargo run --quiet -p rustynet-cli -- ops check-perf-regression \
  --phase1-report "$PHASE1_REPORT" \
  --phase3-report "$PHASE3_REPORT"
