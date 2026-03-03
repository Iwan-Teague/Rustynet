#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

default_phase1_source="$ROOT_DIR/artifacts/perf/phase1/source/performance_samples.ndjson"
default_phase9_source="$ROOT_DIR/artifacts/operations/source/performance_samples.ndjson"
default_phase9_out_perf_report="$ROOT_DIR/artifacts/operations/performance_budget_report.json"
default_phase10_perf_report="$ROOT_DIR/artifacts/phase10/perf_budget_report.json"
default_phase9_perf_report="$ROOT_DIR/artifacts/operations/raw/performance_budget_report.json"

source_path="${RUSTYNET_PHASE1_PERF_SAMPLES_PATH:-}"
if [[ -z "$source_path" ]]; then
  if [[ -f "$default_phase1_source" ]]; then
    source_path="$default_phase1_source"
  elif [[ -f "$default_phase9_source" ]]; then
    source_path="$default_phase9_source"
  elif [[ -f "$default_phase9_out_perf_report" ]]; then
    source_path="$default_phase9_out_perf_report"
  elif [[ -f "$default_phase10_perf_report" ]]; then
    source_path="$default_phase10_perf_report"
  elif [[ -f "$default_phase9_perf_report" ]]; then
    source_path="$default_phase9_perf_report"
  fi
fi

if [[ -z "$source_path" ]]; then
  echo "missing measured source file for phase1 metrics collector" >&2
  echo "set RUSTYNET_PHASE1_PERF_SAMPLES_PATH or provide one of:" >&2
  echo "  - $default_phase1_source" >&2
  echo "  - $default_phase9_source" >&2
  echo "  - $default_phase9_out_perf_report" >&2
  echo "  - $default_phase10_perf_report" >&2
  echo "  - $default_phase9_perf_report" >&2
  exit 1
fi

if [[ ! -f "$source_path" ]]; then
  echo "phase1 metrics source path does not exist: $source_path" >&2
  exit 1
fi

if [[ ! -s "$source_path" ]]; then
  echo "phase1 metrics source file is empty: $source_path" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "missing required command: python3" >&2
  exit 1
fi

output_path="${RUSTYNET_PHASE1_MEASURED_ENV_OUT:-$ROOT_DIR/artifacts/perf/phase1/measured_env.sh}"
mkdir -p "$(dirname "$output_path")"

python3 - "$source_path" "$output_path" <<'PY'
import json
import math
import shlex
import sys
import time
from pathlib import Path

source_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])

metric_aliases = {
    "idle_cpu_percent": ["idle_cpu_percent"],
    "idle_memory_mb": ["idle_memory_mb", "idle_rss_mb"],
    "reconnect_seconds": ["reconnect_seconds", "reconnect_p95_seconds"],
    "route_apply_p95_seconds": ["route_apply_p95_seconds", "route_apply_seconds_p95"],
    "throughput_overhead_percent": [
        "throughput_overhead_percent",
        "throughput_overhead_vs_wireguard_percent",
    ],
    "backend_throughput_overhead_percent": [
        "backend_throughput_overhead_percent",
        "backend_overhead_percent",
        "throughput_overhead_percent",
        "throughput_overhead_vs_wireguard_percent",
    ],
}


def as_number(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def require_metric(entry, aliases, line_number):
    for key in aliases:
        value = as_number(entry.get(key))
        if value is not None:
            return value
    raise SystemExit(
        f"missing required metric on line {line_number}; expected one of {aliases}"
    )


max_values = {name: None for name in metric_aliases}
sample_count = 0

def consume_entry(entry, line_number):
    global sample_count
    if not isinstance(entry, dict):
        raise SystemExit(f"invalid record at line {line_number}: expected JSON object")
    sample_count += 1
    for metric_name, aliases in metric_aliases.items():
        value = require_metric(entry, aliases, line_number)
        if not math.isfinite(value) or value < 0.0:
            raise SystemExit(
                f"invalid {metric_name} value on line {line_number}: {value}"
            )
        current = max_values[metric_name]
        max_values[metric_name] = value if current is None else max(current, value)


if source_path.suffix.lower() == ".ndjson":
    with source_path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                entry = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise SystemExit(
                    f"invalid ndjson at {source_path}:{line_number}: {exc}"
                ) from exc
            consume_entry(entry, line_number)
else:
    try:
        payload = json.loads(source_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid json in {source_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"json source must be object: {source_path}")
    if "evidence_mode" in payload and payload.get("evidence_mode") != "measured":
        raise SystemExit(
            f"json source is not measured evidence ({source_path}): evidence_mode={payload.get('evidence_mode')}"
        )

    metrics = payload.get("metrics")
    if isinstance(metrics, list):
        flattened = {}
        for index, metric in enumerate(metrics):
            if not isinstance(metric, dict):
                raise SystemExit(
                    f"invalid metrics entry at index {index} in {source_path}: expected object"
                )
            name = metric.get("name")
            value = metric.get("value")
            if isinstance(name, str) and as_number(value) is not None:
                flattened[name] = float(value)
        for key in (
            "idle_cpu_percent",
            "idle_memory_mb",
            "idle_rss_mb",
            "reconnect_seconds",
            "route_apply_p95_seconds",
            "throughput_overhead_percent",
            "throughput_overhead_vs_wireguard_percent",
            "backend_throughput_overhead_percent",
            "backend_overhead_percent",
        ):
            value = as_number(payload.get(key))
            if value is not None and key not in flattened:
                flattened[key] = value
        consume_entry(flattened, 1)
    else:
        consume_entry(payload, 1)

if sample_count == 0:
    raise SystemExit(f"no measured entries found in {source_path}")

for metric_name, value in max_values.items():
    if value is None:
        raise SystemExit(f"failed to derive metric {metric_name} from {source_path}")

env_map = {
    "RUSTYNET_PHASE1_IDLE_CPU_PERCENT": max_values["idle_cpu_percent"],
    "RUSTYNET_PHASE1_IDLE_MEMORY_MB": max_values["idle_memory_mb"],
    "RUSTYNET_PHASE1_RECONNECT_SECONDS": max_values["reconnect_seconds"],
    "RUSTYNET_PHASE1_ROUTE_POLICY_APPLY_P95_SECONDS": max_values[
        "route_apply_p95_seconds"
    ],
    "RUSTYNET_PHASE1_THROUGHPUT_OVERHEAD_PERCENT": max_values[
        "throughput_overhead_percent"
    ],
    "RUSTYNET_PHASE1_BACKEND_THROUGHPUT_OVERHEAD_PERCENT": max_values[
        "backend_throughput_overhead_percent"
    ],
}

captured_at_unix = int(time.time())
lines = [
    "#!/usr/bin/env bash",
    "# Auto-generated measured Phase 1 baseline environment.",
    f"# source={source_path}",
    f"# captured_at_unix={captured_at_unix}",
    f"export RUSTYNET_PHASE1_METRICS_SOURCE={shlex.quote(str(source_path))}",
]
for key, value in env_map.items():
    lines.append(f"export {key}={value:.6f}")

output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
output_path.chmod(0o600)
print(
    f"phase1 measured env generated: path={output_path} samples={sample_count} source={source_path}"
)
PY
