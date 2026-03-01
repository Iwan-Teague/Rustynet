#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

REPORT_PATH="${RUSTYNET_PHASE6_PLATFORM_PARITY_REPORT:-artifacts/release/platform_parity_report.json}"
if [[ ! -f "$REPORT_PATH" ]]; then
  echo "missing platform parity report: $REPORT_PATH"
  exit 1
fi

python3 - "$REPORT_PATH" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

report_path = Path(sys.argv[1])
root = Path(".")

with report_path.open("r", encoding="utf-8") as fh:
    report = json.load(fh)

if report.get("evidence_mode") != "measured":
    raise SystemExit("platform parity report must set evidence_mode=measured")

captured_at_unix = report.get("captured_at_unix")
if not isinstance(captured_at_unix, int) or captured_at_unix <= 0:
    raise SystemExit("platform parity report requires positive integer captured_at_unix")

now_unix = int(datetime.now(timezone.utc).timestamp())
if captured_at_unix > now_unix + 300:
    raise SystemExit("platform parity report captured_at_unix is too far in the future")
if now_unix - captured_at_unix > 31 * 24 * 60 * 60:
    raise SystemExit("platform parity report is stale; regenerate with fresh measurements")

environment = report.get("environment")
if not isinstance(environment, str) or not environment.strip():
    raise SystemExit("platform parity report requires non-empty environment")

if "gate_passed" in report:
    raise SystemExit("platform parity report must not include gate_passed toggle")

source_artifacts = report.get("source_artifacts")
if not isinstance(source_artifacts, list) or not source_artifacts:
    raise SystemExit("platform parity report requires non-empty source_artifacts list")
for source in source_artifacts:
    if not isinstance(source, str) or not source.strip():
        raise SystemExit("platform parity report has invalid source_artifacts entry")
    source_path = Path(source)
    if not source_path.is_absolute():
        source_path = root / source
    if not source_path.exists():
        raise SystemExit(f"platform parity source artifact missing: {source}")

platform_results = report.get("platform_results")
if not isinstance(platform_results, list) or not platform_results:
    raise SystemExit("platform parity report requires non-empty platform_results list")

required_platforms = {"linux", "macos", "windows"}
seen = set()
for result in platform_results:
    if not isinstance(result, dict):
        raise SystemExit("platform parity report has invalid platform_results entry")

    platform = result.get("platform")
    if not isinstance(platform, str):
        raise SystemExit("platform parity report entry missing platform")
    platform_lc = platform.strip().lower()
    if platform_lc not in required_platforms:
        raise SystemExit(f"unexpected platform in parity report: {platform}")
    seen.add(platform_lc)

    for key in (
        "route_hook_ready",
        "dns_hook_ready",
        "firewall_hook_ready",
        "leak_matrix_passed",
    ):
        value = result.get(key)
        if value is not True:
            raise SystemExit(
                f"platform parity requirement failed for {platform}: {key} must be true"
            )

if seen != required_platforms:
    missing = sorted(required_platforms - seen)
    raise SystemExit(f"platform parity report missing platforms: {', '.join(missing)}")

print("Phase 6 platform parity checks: PASS")
PY
