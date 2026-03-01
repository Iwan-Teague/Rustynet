#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

RAW_DIR="${RUSTYNET_PHASE9_RAW_DIR:-artifacts/operations/raw}"
OUT_DIR="${RUSTYNET_PHASE9_OUT_DIR:-artifacts/operations}"
EVIDENCE_ENVIRONMENT="${RUSTYNET_PHASE9_EVIDENCE_ENVIRONMENT:-}"

if [[ -z "$EVIDENCE_ENVIRONMENT" ]]; then
  echo "missing required environment variable: RUSTYNET_PHASE9_EVIDENCE_ENVIRONMENT"
  exit 1
fi

required_raw=(
  "compatibility_policy.json"
  "slo_error_budget_report.json"
  "performance_budget_report.json"
  "incident_drill_report.json"
  "dr_failover_report.json"
  "backend_agility_report.json"
  "crypto_deprecation_schedule.json"
)

for filename in "${required_raw[@]}"; do
  if [[ ! -f "$RAW_DIR/$filename" ]]; then
    echo "missing raw phase9 evidence input: $RAW_DIR/$filename"
    exit 1
  fi
done

mkdir -p "$OUT_DIR"

python3 - "$RAW_DIR" "$OUT_DIR" "$EVIDENCE_ENVIRONMENT" <<'PY'
import json
import time
from pathlib import Path
import sys

raw_dir = Path(sys.argv[1])
out_dir = Path(sys.argv[2])
environment = sys.argv[3]

artifacts = [
    "compatibility_policy.json",
    "slo_error_budget_report.json",
    "performance_budget_report.json",
    "incident_drill_report.json",
    "dr_failover_report.json",
    "backend_agility_report.json",
    "crypto_deprecation_schedule.json",
]

captured_at_unix = int(time.time())

for filename in artifacts:
    source = raw_dir / filename
    target = out_dir / filename

    with source.open("r", encoding="utf-8") as fh:
        document = json.load(fh)

    if not isinstance(document, dict):
        raise SystemExit(f"raw evidence must be JSON object: {source}")

    # Prevent static toggle fields from bypassing gate derivation.
    document.pop("gate_passed", None)

    document["evidence_mode"] = "measured"
    document["captured_at_unix"] = captured_at_unix
    document["environment"] = environment
    document["source_artifacts"] = [str(source)]

    with target.open("w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=False)
        fh.write("\n")

print(f"generated {len(artifacts)} phase9 artifact(s)")
PY

./scripts/ci/check_phase9_readiness.sh

echo "Phase 9 artifacts generated and validated under: $OUT_DIR"
