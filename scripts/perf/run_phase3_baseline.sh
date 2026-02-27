#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

PHASE3_REPORT="artifacts/perf/phase3/mesh_baseline.json"
PHASE3_REPORT_ABS="$ROOT_DIR/$PHASE3_REPORT"

RUSTYNET_PHASE3_MESH_REPORT="$PHASE3_REPORT_ABS" cargo test -p rustynetd phase3_three_node_mesh_succeeds

if [[ ! -f "$PHASE3_REPORT" ]]; then
  echo "missing phase3 report: $PHASE3_REPORT"
  exit 1
fi

for key in connected_nodes peer_sessions relay_sessions; do
  if ! rg -q "$key" "$PHASE3_REPORT"; then
    echo "phase3 report missing required metric: $key"
    exit 1
  fi
done

echo "Phase 3 mesh baseline artifact generated:"
echo "  - $PHASE3_REPORT"
