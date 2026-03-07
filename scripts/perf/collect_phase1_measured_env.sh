#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

PHASE1_SOURCE_PATH="${RUSTYNET_PHASE1_PERF_SAMPLES_PATH:-artifacts/perf/phase1/source/performance_samples.ndjson}"
if [[ "$PHASE1_SOURCE_PATH" != /* ]]; then
  PHASE1_SOURCE_PATH="$ROOT_DIR/$PHASE1_SOURCE_PATH"
fi

if [[ ! -f "$PHASE1_SOURCE_PATH" ]]; then
  echo "missing measured phase1 source: $PHASE1_SOURCE_PATH" >&2
  exit 1
fi

RUSTYNET_PHASE1_PERF_SAMPLES_PATH="$PHASE1_SOURCE_PATH" \
  exec cargo run --quiet -p rustynet-cli -- ops collect-phase1-measured-input
