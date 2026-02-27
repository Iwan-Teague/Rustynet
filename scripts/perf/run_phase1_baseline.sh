#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

RUNTIME_REPORT="artifacts/perf/phase1/baseline.json"
BACKEND_REPORT="artifacts/perf/phase1/backend_contract_perf.json"
BACKEND_REPORT_ABS="$ROOT_DIR/$BACKEND_REPORT"

cargo run -p rustynetd -- --emit-phase1-baseline "$RUNTIME_REPORT"
RUSTYNET_PHASE1_BACKEND_PERF_REPORT="$BACKEND_REPORT_ABS" cargo test -p rustynet-backend-api --test backend_contract_perf

for report in "$RUNTIME_REPORT" "$BACKEND_REPORT"; do
  if [[ ! -f "$report" ]]; then
    echo "missing report: $report"
    exit 1
  fi

done

required_keys=(
  "idle_cpu_percent"
  "idle_memory_mb"
  "reconnect_seconds"
  "route_policy_apply_p95_seconds"
  "throughput_overhead_vs_wireguard_percent"
)

for key in "${required_keys[@]}"; do
  if ! rg -q "$key" "$RUNTIME_REPORT"; then
    echo "runtime report missing required metric: $key"
    exit 1
  fi
done

if rg -q '"reason":"[^"]+"' "$RUNTIME_REPORT"; then
  # Report includes reason fields. Verify all not_measurable rows use approved reason codes.
  while IFS= read -r line; do
    reason="${line##*\"reason\":\"}"
    reason="${reason%%\"*}"
    status_line="${line}"
    if [[ "$status_line" == *'"status":"not_measurable"'* ]]; then
      if [[ "$reason" != "no_production_datapath" && "$reason" != "no_live_route_programmer" ]]; then
        echo "invalid not_measurable reason code: $reason"
        exit 1
      fi
    fi
  done < <(rg -o '"status":"[^"]+","reason":"[^"]+"' "$RUNTIME_REPORT")
fi

echo "Phase 1 baseline artifacts generated:"
echo "  - $RUNTIME_REPORT"
echo "  - $BACKEND_REPORT"
