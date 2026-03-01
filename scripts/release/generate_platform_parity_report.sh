#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

RAW_DIR="${RUSTYNET_PHASE6_PARITY_RAW_DIR:-artifacts/release/raw}"
OUT_PATH="${RUSTYNET_PHASE6_PARITY_OUT:-artifacts/release/platform_parity_report.json}"
EVIDENCE_ENVIRONMENT="${RUSTYNET_PHASE6_PARITY_ENVIRONMENT:-}"

if [[ -z "$EVIDENCE_ENVIRONMENT" ]]; then
  echo "missing required environment variable: RUSTYNET_PHASE6_PARITY_ENVIRONMENT"
  exit 1
fi

required_raw=(
  "platform_parity_linux.json"
  "platform_parity_macos.json"
  "platform_parity_windows.json"
)

for filename in "${required_raw[@]}"; do
  if [[ ! -f "$RAW_DIR/$filename" ]]; then
    echo "missing raw platform parity input: $RAW_DIR/$filename"
    exit 1
  fi
done

mkdir -p "$(dirname "$OUT_PATH")"

python3 - "$RAW_DIR" "$OUT_PATH" "$EVIDENCE_ENVIRONMENT" <<'PY'
import json
import time
from pathlib import Path
import sys

raw_dir = Path(sys.argv[1])
out_path = Path(sys.argv[2])
environment = sys.argv[3]

platform_files = [
    ("linux", "platform_parity_linux.json"),
    ("macos", "platform_parity_macos.json"),
    ("windows", "platform_parity_windows.json"),
]

results = []
source_artifacts = []


def require_bool(payload: dict, key: str, source: Path) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise SystemExit(f"{source} requires boolean field: {key}")
    return value

for platform, filename in platform_files:
    source = raw_dir / filename
    with source.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)

    if not isinstance(payload, dict):
        raise SystemExit(f"raw platform parity payload must be object: {source}")

    result = {
        "platform": platform,
        "route_hook_ready": require_bool(payload, "route_hook_ready", source),
        "dns_hook_ready": require_bool(payload, "dns_hook_ready", source),
        "firewall_hook_ready": require_bool(payload, "firewall_hook_ready", source),
        "leak_matrix_passed": require_bool(payload, "leak_matrix_passed", source),
    }
    results.append(result)
    source_artifacts.append(str(source))

report = {
    "evidence_mode": "measured",
    "captured_at_unix": int(time.time()),
    "environment": environment,
    "source_artifacts": source_artifacts,
    "platform_results": results,
}

with out_path.open("w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=False)
    fh.write("\n")

print(f"wrote platform parity report: {out_path}")
PY

./scripts/ci/check_phase6_platform_parity.sh
