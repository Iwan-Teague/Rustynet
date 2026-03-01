#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

required_artifacts=(
  "artifacts/operations/compatibility_policy.json"
  "artifacts/operations/slo_error_budget_report.json"
  "artifacts/operations/performance_budget_report.json"
  "artifacts/operations/incident_drill_report.json"
  "artifacts/operations/dr_failover_report.json"
  "artifacts/operations/backend_agility_report.json"
  "artifacts/operations/crypto_deprecation_schedule.json"
)

for artifact in "${required_artifacts[@]}"; do
  if [[ ! -f "$artifact" ]]; then
    echo "missing phase9 artifact: $artifact"
    exit 1
  fi
done

python3 - <<'PY'
import json
import re
from datetime import datetime, timezone
from pathlib import Path

root = Path(".")
max_evidence_age_seconds = 31 * 24 * 60 * 60


def load(path: str):
    with (root / path).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def parse_utc(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"{label} must be a non-empty UTC string")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemExit(f"{label} is invalid UTC timestamp: {value}") from exc


def require_nonempty_string(document: dict, key: str, label: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"{label} requires non-empty string field: {key}")
    return value


def require_bool(document: dict, key: str, label: str):
    value = document.get(key)
    if not isinstance(value, bool):
        raise SystemExit(f"{label} requires boolean field: {key}")
    return value


def require_number(document: dict, key: str, label: str):
    value = document.get(key)
    if not isinstance(value, (int, float)):
        raise SystemExit(f"{label} requires numeric field: {key}")
    return float(value)


def require_measured_evidence_metadata(document: dict, label: str):
    if "gate_passed" in document:
        raise SystemExit(
            f"{label} contains deprecated gate_passed toggle; gate pass must be derived, not asserted"
        )

    if document.get("evidence_mode") != "measured":
        raise SystemExit(f"{label} must set evidence_mode=measured")

    captured_at_unix = document.get("captured_at_unix")
    if not isinstance(captured_at_unix, int) or captured_at_unix <= 0:
        raise SystemExit(f"{label} requires positive integer captured_at_unix")

    now_unix = int(datetime.now(timezone.utc).timestamp())
    if captured_at_unix > now_unix + 300:
        raise SystemExit(f"{label} captured_at_unix is too far in the future")
    if now_unix - captured_at_unix > max_evidence_age_seconds:
        raise SystemExit(f"{label} evidence is too old; regenerate with fresh measurements")

    require_nonempty_string(document, "environment", label)

    sources = document.get("source_artifacts")
    if not isinstance(sources, list) or not sources:
        raise SystemExit(f"{label} requires non-empty source_artifacts list")

    for source in sources:
        if not isinstance(source, str) or not source.strip():
            raise SystemExit(f"{label} has invalid source artifact entry: {source!r}")
        source_path = Path(source)
        if not source_path.is_absolute():
            source_path = root / source
        if not source_path.exists():
            raise SystemExit(f"{label} source artifact does not exist: {source}")


compat = load("artifacts/operations/compatibility_policy.json")
require_measured_evidence_metadata(compat, "compatibility_policy")
require_nonempty_string(compat, "policy_version", "compatibility_policy")
min_client = compat.get("minimum_supported_client")
latest_server = compat.get("latest_server")
if not isinstance(min_client, dict) or not isinstance(latest_server, dict):
    raise SystemExit("compatibility policy requires minimum_supported_client and latest_server objects")
if (int(min_client["major"]), int(min_client["minor"])) > (
    int(latest_server["major"]),
    int(latest_server["minor"]),
):
    raise SystemExit("compatibility policy invalid: minimum client is greater than latest server")
if compat.get("deprecation_window_days", 0) <= 0:
    raise SystemExit("compatibility policy invalid: deprecation window must be > 0")
mode = compat.get("insecure_compatibility_mode", {})
if mode.get("default_enabled"):
    raise SystemExit("compatibility policy invalid: insecure compatibility default must be disabled")
if not mode.get("risk_acceptance_required") or not mode.get("auto_expiry_required"):
    raise SystemExit("compatibility policy invalid: risk acceptance + auto-expiry are mandatory")

slo = load("artifacts/operations/slo_error_budget_report.json")
require_measured_evidence_metadata(slo, "slo_error_budget_report")
start_utc = parse_utc(require_nonempty_string(slo, "window_start_utc", "slo_error_budget_report"), "slo window_start_utc")
end_utc = parse_utc(require_nonempty_string(slo, "window_end_utc", "slo_error_budget_report"), "slo window_end_utc")
if end_utc <= start_utc:
    raise SystemExit("slo gate failed: window_end_utc must be after window_start_utc")
if require_number(slo, "measured_availability_percent", "slo_error_budget_report") < require_number(
    slo, "availability_slo_percent", "slo_error_budget_report"
):
    raise SystemExit("slo gate failed: measured availability below target")
if require_number(slo, "measured_error_budget_consumed_percent", "slo_error_budget_report") > require_number(
    slo, "max_error_budget_consumed_percent", "slo_error_budget_report"
):
    raise SystemExit("slo gate failed: error budget over-consumed")

perf = load("artifacts/operations/performance_budget_report.json")
require_measured_evidence_metadata(perf, "performance_budget_report")
if require_number(perf, "idle_cpu_percent", "performance_budget_report") > 2.0:
    raise SystemExit("performance gate failed: idle CPU above 2%")
if require_number(perf, "idle_memory_mb", "performance_budget_report") > 120.0:
    raise SystemExit("performance gate failed: idle memory above 120 MB")
if require_number(perf, "reconnect_seconds", "performance_budget_report") > 5.0:
    raise SystemExit("performance gate failed: reconnect above 5 seconds")
if require_number(perf, "route_apply_p95_seconds", "performance_budget_report") > 2.0:
    raise SystemExit("performance gate failed: route apply p95 above 2 seconds")
if require_number(perf, "throughput_overhead_percent", "performance_budget_report") > 15.0:
    raise SystemExit("performance gate failed: throughput overhead above 15%")
if require_number(perf, "soak_test_hours", "performance_budget_report") < 24.0:
    raise SystemExit("performance gate failed: soak test duration under 24 hours")

incident = load("artifacts/operations/incident_drill_report.json")
require_measured_evidence_metadata(incident, "incident_drill_report")
parse_utc(require_nonempty_string(incident, "executed_at_utc", "incident_drill_report"), "incident executed_at_utc")
if not require_bool(incident, "postmortem_completed", "incident_drill_report"):
    raise SystemExit("incident gate failed: postmortem not completed")
if not require_bool(incident, "action_items_closed", "incident_drill_report"):
    raise SystemExit("incident gate failed: action items not closed")
if not require_bool(incident, "oncall_readiness_confirmed", "incident_drill_report"):
    raise SystemExit("incident gate failed: on-call readiness not confirmed")

dr = load("artifacts/operations/dr_failover_report.json")
require_measured_evidence_metadata(dr, "dr_failover_report")
parse_utc(require_nonempty_string(dr, "executed_at_utc", "dr_failover_report"), "dr executed_at_utc")
if int(dr.get("region_count", 0)) < 2:
    raise SystemExit("dr gate failed: fewer than two regions validated")
if require_number(dr, "measured_rpo_minutes", "dr_failover_report") > require_number(
    dr, "rpo_target_minutes", "dr_failover_report"
):
    raise SystemExit("dr gate failed: RPO target not met")
if require_number(dr, "measured_rto_minutes", "dr_failover_report") > require_number(
    dr, "rto_target_minutes", "dr_failover_report"
):
    raise SystemExit("dr gate failed: RTO target not met")
if not require_bool(dr, "restore_integrity_verified", "dr_failover_report"):
    raise SystemExit("dr gate failed: restore integrity not verified")

backend = load("artifacts/operations/backend_agility_report.json")
require_measured_evidence_metadata(backend, "backend_agility_report")
if str(backend.get("default_backend", "")).lower() != "wireguard":
    raise SystemExit("backend agility gate failed: default backend must be wireguard")
additional_paths = backend.get("additional_backend_paths", [])
if not isinstance(additional_paths, list) or len(additional_paths) < 1:
    raise SystemExit("backend agility gate failed: at least one additional backend path is required")
for path in additional_paths:
    if not isinstance(path, str) or not path.strip():
        raise SystemExit("backend agility gate failed: invalid additional backend path entry")
    if re.search(r"(stub|fake|mock|simulat)", path, re.IGNORECASE):
        raise SystemExit(f"backend agility gate failed: synthetic backend path not allowed: {path}")
    candidate = Path(path)
    if not candidate.is_absolute():
        if "/" in path:
            candidate = root / path
        else:
            candidate = root / "crates" / path
    if not candidate.exists():
        raise SystemExit(f"backend agility gate failed: backend path does not exist: {path}")
if not require_bool(backend, "conformance_passed", "backend_agility_report"):
    raise SystemExit("backend agility gate failed: conformance not passed")
if not require_bool(backend, "security_review_complete", "backend_agility_report"):
    raise SystemExit("backend agility gate failed: security review incomplete")
if not require_bool(backend, "wireguard_is_adapter_boundary", "backend_agility_report"):
    raise SystemExit("backend agility gate failed: wireguard boundary not preserved")
if require_bool(backend, "protocol_leakage_detected", "backend_agility_report"):
    raise SystemExit("backend agility gate failed: protocol leakage detected")

commands = backend.get("evidence_commands", [])
if not isinstance(commands, list) or not commands:
    raise SystemExit("backend agility gate failed: evidence_commands must be a non-empty list")
for command in commands:
    if not isinstance(command, str) or not command.strip():
        raise SystemExit("backend agility gate failed: invalid command in evidence_commands")
    if re.search(r"(backend-stub|stub-backend)", command, re.IGNORECASE):
        raise SystemExit("backend agility gate failed: stub backend command is not valid evidence")

crypto = load("artifacts/operations/crypto_deprecation_schedule.json")
require_measured_evidence_metadata(crypto, "crypto_deprecation_schedule")
entries = crypto.get("entries", [])
if not entries:
    raise SystemExit("crypto schedule gate failed: no deprecation entries present")
for entry in entries:
    if not isinstance(entry, dict):
        raise SystemExit("crypto schedule gate failed: invalid entry type")
    deprecates_at = parse_utc(entry.get("deprecates_at_utc"), "crypto deprecates_at_utc")
    removal_at = parse_utc(entry.get("removal_at_utc"), "crypto removal_at_utc")
    if removal_at <= deprecates_at:
        raise SystemExit(
            "crypto schedule gate failed: removal timestamp must be after deprecation timestamp"
        )
if crypto.get("exceptions_default_enabled", True):
    raise SystemExit("crypto schedule gate failed: insecure exceptions must be disabled by default")
if not crypto.get("exceptions_require_risk_acceptance", False):
    raise SystemExit("crypto schedule gate failed: exceptions must require risk acceptance")
if not crypto.get("exceptions_auto_expire", False):
    raise SystemExit("crypto schedule gate failed: exceptions must auto-expire")

print("Phase 9 operational readiness checks: PASS")
PY
