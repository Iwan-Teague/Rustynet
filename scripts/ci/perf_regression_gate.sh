#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

PHASE1_REPORT="artifacts/perf/phase1/baseline.json"
PHASE3_REPORT="artifacts/perf/phase3/mesh_baseline.json"

if [[ ! -f "$PHASE1_REPORT" ]]; then
  echo "missing phase1 report: $PHASE1_REPORT"
  exit 1
fi

if [[ ! -f "$PHASE3_REPORT" ]]; then
  echo "missing phase3 report: $PHASE3_REPORT"
  exit 1
fi

if rg -q '"status":"fail"' "$PHASE1_REPORT"; then
  echo "phase1 report includes failing metric status"
  exit 1
fi

idle_cpu="$(rg -o '"name":"idle_cpu_percent","value":[0-9.]+' "$PHASE1_REPORT" | sed -E 's/.*"value":([0-9.]+)/\1/')"
idle_mem="$(rg -o '"name":"idle_memory_mb","value":[0-9.]+' "$PHASE1_REPORT" | sed -E 's/.*"value":([0-9.]+)/\1/')"
route_apply="$(rg -o '"name":"route_policy_apply_p95_seconds","value":[0-9.]+' "$PHASE1_REPORT" | sed -E 's/.*"value":([0-9.]+)/\1/')"
peer_sessions="$(rg -o '"name":"peer_sessions","value":[0-9.]+' "$PHASE3_REPORT" | sed -E 's/.*"value":([0-9.]+)/\1/')"

awk -v v="$idle_cpu" 'BEGIN { if (v <= 2.0) exit 0; exit 1 }' || {
  echo "idle cpu regression detected: $idle_cpu"
  exit 1
}

awk -v v="$idle_mem" 'BEGIN { if (v <= 120.0) exit 0; exit 1 }' || {
  echo "idle memory regression detected: $idle_mem"
  exit 1
}

awk -v v="$route_apply" 'BEGIN { if (v <= 2.0) exit 0; exit 1 }' || {
  echo "route apply latency regression detected: $route_apply"
  exit 1
}

awk -v v="$peer_sessions" 'BEGIN { if (v >= 6.0) exit 0; exit 1 }' || {
  echo "phase3 mesh benchmark too small: peer_sessions=$peer_sessions"
  exit 1
}

echo "Performance regression gate: PASS"
