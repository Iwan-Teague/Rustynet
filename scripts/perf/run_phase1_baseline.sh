#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

RUNTIME_REPORT="artifacts/perf/phase1/baseline.json"
BACKEND_REPORT="artifacts/perf/phase1/backend_contract_perf.json"
BACKEND_REPORT_ABS="$ROOT_DIR/$BACKEND_REPORT"

required_measurement_env=(
  "RUSTYNET_PHASE1_IDLE_CPU_PERCENT"
  "RUSTYNET_PHASE1_IDLE_MEMORY_MB"
  "RUSTYNET_PHASE1_RECONNECT_SECONDS"
  "RUSTYNET_PHASE1_ROUTE_POLICY_APPLY_P95_SECONDS"
  "RUSTYNET_PHASE1_THROUGHPUT_OVERHEAD_PERCENT"
  "RUSTYNET_PHASE1_BACKEND_THROUGHPUT_OVERHEAD_PERCENT"
)

for env_key in "${required_measurement_env[@]}"; do
  if [[ -z "${!env_key:-}" ]]; then
    echo "missing required measured input environment variable: $env_key"
    exit 1
  fi
done

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

backend_required_keys=(
  "configure_peer_avg_us"
  "apply_routes_avg_us"
  "stats_avg_us"
  "throughput_overhead_vs_wireguard_percent"
)

for key in "${backend_required_keys[@]}"; do
  if ! rg -q "$key" "$BACKEND_REPORT"; then
    echo "backend report missing required metric: $key"
    exit 1
  fi
done

for report in "$RUNTIME_REPORT" "$BACKEND_REPORT"; do
  if rg -q '"status":"fail"' "$report"; then
    echo "phase1 report contains failing metrics: $report"
    exit 1
  fi
  if rg -q '"status":"not_measurable"' "$report"; then
    echo "phase1 report contains non-measured metrics: $report"
    exit 1
  fi
  if rg -q '"reason":"measurement_unavailable"|"reason":"measurement_invalid"' "$report"; then
    echo "phase1 report contains unavailable/invalid measurements: $report"
    exit 1
  fi
done

echo "Phase 1 baseline artifacts generated:"
echo "  - $RUNTIME_REPORT"
echo "  - $BACKEND_REPORT"
