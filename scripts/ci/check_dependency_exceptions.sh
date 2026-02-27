#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

python3 - <<'PY'
import datetime
import json
from pathlib import Path

path = Path("documents/operations/dependency_exceptions.json")
if not path.exists():
    raise SystemExit("missing dependency exception file")

content = json.loads(path.read_text())
exceptions = content.get("exceptions", [])
now = datetime.datetime.now(datetime.timezone.utc)
required = {"id", "crate", "reason", "owner", "approved_by", "expires_utc"}

for entry in exceptions:
    missing = sorted(required - set(entry.keys()))
    if missing:
        raise SystemExit(f"dependency exception missing fields: {missing}")
    expires = datetime.datetime.fromisoformat(entry["expires_utc"].replace("Z", "+00:00"))
    if expires <= now:
        raise SystemExit(f"dependency exception expired: {entry['id']}")

print("Dependency exception policy check: PASS")
PY
