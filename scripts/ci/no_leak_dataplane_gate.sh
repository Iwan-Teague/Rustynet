#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "no-leak dataplane gate requires Linux" >&2
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "no-leak dataplane gate requires root privileges" >&2
  exit 1
fi

REPORT_PATH="${RUSTYNET_NO_LEAK_REPORT_PATH:-artifacts/phase10/no_leak_dataplane_report.json}"

RUSTYNET_NO_LEAK_REPORT_PATH="${REPORT_PATH}" ./scripts/e2e/real_wireguard_no_leak_under_load.sh

python3 - "${REPORT_PATH}" <<'PY'
import json
import sys
from pathlib import Path

report_path = Path(sys.argv[1])
if not report_path.is_file():
    raise SystemExit(f"missing no-leak report: {report_path}")

payload = json.loads(report_path.read_text(encoding="utf-8"))
if payload.get("status") != "pass":
    raise SystemExit("no-leak dataplane report status must be pass")
checks = payload.get("checks")
if not isinstance(checks, dict) or not checks:
    raise SystemExit("no-leak dataplane report must contain non-empty checks")
failed = [key for key, value in checks.items() if value != "pass"]
if failed:
    raise SystemExit("no-leak dataplane checks failed: " + ", ".join(sorted(failed)))
print("No-leak dataplane gate: PASS")
PY
