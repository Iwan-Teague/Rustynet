#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

SOURCE_DIR="${RUSTYNET_PHASE10_SOURCE_DIR:-artifacts/phase10/source}"
OUT_DIR="${RUSTYNET_PHASE10_OUT_DIR:-artifacts/phase10}"
EVIDENCE_ENVIRONMENT="${RUSTYNET_PHASE10_EVIDENCE_ENVIRONMENT:-}"
MAX_SOURCE_AGE_SECONDS="${RUSTYNET_PHASE10_MAX_SOURCE_AGE_SECONDS:-2678400}"

if [[ -z "$EVIDENCE_ENVIRONMENT" ]]; then
  echo "missing required environment variable: RUSTYNET_PHASE10_EVIDENCE_ENVIRONMENT"
  exit 1
fi

required_sources=(
  "netns_e2e_report.json"
  "leak_test_report.json"
  "perf_budget_report.json"
  "direct_relay_failover_report.json"
  "state_transition_audit.log"
)

for source_name in "${required_sources[@]}"; do
  if [[ ! -f "$SOURCE_DIR/$source_name" ]]; then
    echo "missing raw phase10 evidence source: $SOURCE_DIR/$source_name"
    exit 1
  fi
done

mkdir -p "$OUT_DIR"

python3 - "$SOURCE_DIR" "$OUT_DIR" "$EVIDENCE_ENVIRONMENT" "$MAX_SOURCE_AGE_SECONDS" <<'PY'
import json
import re
import sys
import time
from pathlib import Path

source_dir = Path(sys.argv[1])
out_dir = Path(sys.argv[2])
environment = sys.argv[3]
max_source_age_seconds = int(sys.argv[4])
captured_at_unix = int(time.time())

required_json_sources = {
    "netns_e2e_report.json": "netns_e2e_report",
    "leak_test_report.json": "leak_test_report",
    "perf_budget_report.json": "perf_budget_report",
    "direct_relay_failover_report.json": "direct_relay_failover_report",
}


def load_source_json(filename: str, label: str):
    source_path = source_dir / filename
    with source_path.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)
    if not isinstance(payload, dict):
        raise SystemExit(f"{label} source must be a JSON object: {source_path}")
    if payload.get("evidence_mode") != "measured":
        raise SystemExit(f"{label} source must set evidence_mode=measured: {source_path}")

    source_captured_at_unix = payload.get("captured_at_unix")
    if not isinstance(source_captured_at_unix, int) or source_captured_at_unix <= 0:
        raise SystemExit(
            f"{label} source requires positive integer captured_at_unix: {source_path}"
        )
    if source_captured_at_unix > captured_at_unix + 300:
        raise SystemExit(f"{label} source timestamp is too far in the future: {source_path}")
    if captured_at_unix - source_captured_at_unix > max_source_age_seconds:
        raise SystemExit(
            f"{label} source evidence is stale; recollect measured data: {source_path}"
        )

    return payload, source_path


payloads = {
    label: load_source_json(filename, label)
    for filename, label in required_json_sources.items()
}

netns_payload, _ = payloads["netns_e2e_report"]
if netns_payload.get("status") != "pass":
    raise SystemExit("netns_e2e_report source must report status=pass")
if not isinstance(netns_payload.get("checks"), dict) or not netns_payload.get("checks"):
    raise SystemExit("netns_e2e_report source must include checks object")
if any(value != "pass" for value in netns_payload["checks"].values()):
    raise SystemExit("netns_e2e_report source checks must all pass")

leak_payload, _ = payloads["leak_test_report"]
if leak_payload.get("status") != "pass":
    raise SystemExit("leak_test_report source must report status=pass")

direct_payload, _ = payloads["direct_relay_failover_report"]
if direct_payload.get("status") != "pass":
    raise SystemExit("direct_relay_failover_report source must report status=pass")
if not isinstance(direct_payload.get("checks"), dict) or not direct_payload.get("checks"):
    raise SystemExit("direct_relay_failover_report source must include checks object")
if any(value != "pass" for value in direct_payload["checks"].values()):
    raise SystemExit("direct_relay_failover_report source checks must all pass")

perf_payload, _ = payloads["perf_budget_report"]
if perf_payload.get("soak_status") != "pass":
    raise SystemExit("perf_budget_report source must report soak_status=pass")
metrics = perf_payload.get("metrics")
if not isinstance(metrics, list) or not metrics:
    raise SystemExit("perf_budget_report source must include non-empty metrics list")
if any((not isinstance(metric, dict)) or metric.get("status") != "pass" for metric in metrics):
    raise SystemExit("perf_budget_report source must not contain failing metrics")

for filename, label in required_json_sources.items():
    payload, source_path = payloads[label]
    payload = dict(payload)
    payload.pop("gate_passed", None)
    payload["phase"] = "phase10"
    payload["evidence_mode"] = "measured"
    payload["environment"] = environment
    payload["captured_at_unix"] = captured_at_unix
    payload["source_artifacts"] = [str(source_path)]

    target_path = out_dir / filename
    with target_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=False)
        fh.write("\n")

state_source = source_dir / "state_transition_audit.log"
state_content = state_source.read_text(encoding="utf-8")
if not re.search(r"generation=\d+", state_content):
    raise SystemExit("state_transition_audit.log source missing generation entries")
(out_dir / "state_transition_audit.log").write_text(state_content, encoding="utf-8")

print("generated 5 phase10 artifact(s)")
PY

./scripts/ci/check_phase10_readiness.sh

echo "Phase 10 artifacts generated and validated under: $OUT_DIR"
