#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT

source_file="$temp_dir/source.txt"
log_file="$temp_dir/report.log"
printf 'source\n' >"$source_file"
printf 'log\n' >"$log_file"

current_commit="$(git rev-parse HEAD)"
captured_at_unix="$(date +%s)"

python3 - "$temp_dir" "$source_file" "$log_file" "$current_commit" "$captured_at_unix" <<'PY'
import json
import sys
from pathlib import Path

sys.path.insert(0, str((Path.cwd() / "scripts" / "ci").resolve()))
from cross_network_remote_exit_schema import REPORT_SPECS

temp_dir = Path(sys.argv[1])
source_file = Path(sys.argv[2])
log_file = Path(sys.argv[3])
git_commit = sys.argv[4]
captured_at_unix = int(sys.argv[5])


def network_context_for_spec(spec, nat_profile: str) -> dict[str, str]:
    context: dict[str, str] = {}
    for field in spec.required_network_fields:
        if field == "client_network_id":
            context[field] = "net-a"
        elif field == "exit_network_id":
            context[field] = "net-b"
        elif field == "relay_network_id":
            context[field] = "net-c"
        elif field == "nat_profile":
            context[field] = nat_profile
        elif field == "impairment_profile":
            context[field] = "none"
        else:
            context[field] = f"value-{field}"
    return context


def participants_for_spec(spec) -> dict[str, str]:
    return {field: f"{field}@example" for field in spec.required_participants}


def write_report(spec, nat_profile: str, suffix: str = "") -> None:
    checks = {check: "pass" for check in spec.required_checks}
    payload = {
        "schema_version": 1,
        "phase": "phase10",
        "suite": spec.suite,
        "environment": "ci",
        "evidence_mode": "measured",
        "captured_at_unix": captured_at_unix,
        "git_commit": git_commit,
        "status": "pass",
        "participants": participants_for_spec(spec),
        "network_context": network_context_for_spec(spec, nat_profile),
        "checks": checks,
        "source_artifacts": [str(source_file)],
        "log_artifacts": [str(log_file)],
    }
    filename = spec.filename
    if suffix:
        filename = filename.removesuffix(".json") + f"_{suffix}.json"
    (temp_dir / filename).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


for spec in REPORT_SPECS:
    write_report(spec, "baseline_lan")

write_report(REPORT_SPECS[0], "symmetric_nat", "symmetric_partial")
PY

./scripts/ci/validate_cross_network_nat_matrix.py \
  --artifact-dir "$temp_dir" \
  --required-nat-profiles baseline_lan \
  --expected-git-commit "$current_commit" \
  --require-pass-status \
  --output "$temp_dir/nat_matrix_baseline.md"

if ./scripts/ci/validate_cross_network_nat_matrix.py \
  --artifact-dir "$temp_dir" \
  --required-nat-profiles baseline_lan,symmetric_nat \
  --expected-git-commit "$current_commit" \
  --require-pass-status; then
  echo "expected matrix validation to fail when only one suite has symmetric_nat evidence" >&2
  exit 1
fi

python3 - "$temp_dir" "$source_file" "$log_file" "$current_commit" "$captured_at_unix" <<'PY'
import json
import sys
from pathlib import Path

sys.path.insert(0, str((Path.cwd() / "scripts" / "ci").resolve()))
from cross_network_remote_exit_schema import REPORT_SPECS

temp_dir = Path(sys.argv[1])
source_file = Path(sys.argv[2])
log_file = Path(sys.argv[3])
git_commit = sys.argv[4]
captured_at_unix = int(sys.argv[5])


def network_context_for_spec(spec) -> dict[str, str]:
    context: dict[str, str] = {}
    for field in spec.required_network_fields:
        if field == "client_network_id":
            context[field] = "net-a"
        elif field == "exit_network_id":
            context[field] = "net-b"
        elif field == "relay_network_id":
            context[field] = "net-c"
        elif field == "nat_profile":
            context[field] = "symmetric_nat"
        elif field == "impairment_profile":
            context[field] = "none"
        else:
            context[field] = f"value-{field}"
    return context


for spec in REPORT_SPECS:
    payload = {
        "schema_version": 1,
        "phase": "phase10",
        "suite": spec.suite,
        "environment": "ci",
        "evidence_mode": "measured",
        "captured_at_unix": captured_at_unix,
        "git_commit": git_commit,
        "status": "pass",
        "participants": {field: f"{field}@example" for field in spec.required_participants},
        "network_context": network_context_for_spec(spec),
        "checks": {check: "pass" for check in spec.required_checks},
        "source_artifacts": [str(source_file)],
        "log_artifacts": [str(log_file)],
    }
    filename = spec.filename.removesuffix(".json") + "_symmetric_full.json"
    (temp_dir / filename).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY

./scripts/ci/validate_cross_network_nat_matrix.py \
  --artifact-dir "$temp_dir" \
  --required-nat-profiles baseline_lan,symmetric_nat \
  --expected-git-commit "$current_commit" \
  --require-pass-status \
  --output "$temp_dir/nat_matrix_dual.md"

echo "Cross-network NAT matrix validation tests: PASS"
