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

python3 - "$PHASE1_REPORT" "$PHASE3_REPORT" <<'PY'
import json
import math
import sys
from pathlib import Path

phase1_path = Path(sys.argv[1])
phase3_path = Path(sys.argv[2])


def load_json(path: Path, label: str):
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"{label} parse failed ({path}): {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"{label} must be a JSON object: {path}")
    return payload


def metric_map(payload: dict, label: str, path: Path):
    metrics = payload.get("metrics")
    if not isinstance(metrics, list) or not metrics:
        raise SystemExit(f"{label} metrics must be a non-empty array: {path}")

    values = {}
    for entry in metrics:
        if not isinstance(entry, dict):
            raise SystemExit(f"{label} metric entry must be object: {path}")
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            raise SystemExit(f"{label} metric missing non-empty name: {path}")
        raw = entry.get("value")
        if not isinstance(raw, (int, float)):
            raise SystemExit(f"{label} metric '{name}' missing numeric value: {path}")
        value = float(raw)
        if not math.isfinite(value) or value < 0:
            raise SystemExit(f"{label} metric '{name}' has invalid numeric value: {value}")
        status = entry.get("status")
        if status in ("fail", "not_measurable"):
            raise SystemExit(f"{label} metric '{name}' has failing status: {status}")
        values[name] = value
    return values


phase1_payload = load_json(phase1_path, "phase1 report")
phase3_payload = load_json(phase3_path, "phase3 report")

phase1_metrics = metric_map(phase1_payload, "phase1 report", phase1_path)
phase3_metrics = metric_map(phase3_payload, "phase3 report", phase3_path)


def require_metric(metrics: dict, name: str, label: str):
    if name not in metrics:
        raise SystemExit(f"{label} missing required metric: {name}")
    return metrics[name]


idle_cpu = require_metric(phase1_metrics, "idle_cpu_percent", "phase1 report")
idle_mem = require_metric(phase1_metrics, "idle_memory_mb", "phase1 report")
route_apply = require_metric(phase1_metrics, "route_policy_apply_p95_seconds", "phase1 report")
peer_sessions = require_metric(phase3_metrics, "peer_sessions", "phase3 report")

if idle_cpu > 2.0:
    raise SystemExit(f"idle cpu regression detected: {idle_cpu}")
if idle_mem > 120.0:
    raise SystemExit(f"idle memory regression detected: {idle_mem}")
if route_apply > 2.0:
    raise SystemExit(f"route apply latency regression detected: {route_apply}")
if peer_sessions < 6.0:
    raise SystemExit(f"phase3 mesh benchmark too small: peer_sessions={peer_sessions}")

print("Performance regression gate: PASS")
PY
