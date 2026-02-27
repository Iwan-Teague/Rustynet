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
from datetime import datetime
from pathlib import Path

root = Path(".")


def load(path: str):
    with (root / path).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

compat = load("artifacts/operations/compatibility_policy.json")
min_client = compat["minimum_supported_client"]
latest_server = compat["latest_server"]
if (min_client["major"], min_client["minor"]) > (latest_server["major"], latest_server["minor"]):
    raise SystemExit("compatibility policy invalid: minimum client is greater than latest server")
if compat.get("deprecation_window_days", 0) <= 0:
    raise SystemExit("compatibility policy invalid: deprecation window must be > 0")
mode = compat["insecure_compatibility_mode"]
if mode.get("default_enabled"):
    raise SystemExit("compatibility policy invalid: insecure compatibility default must be disabled")
if not mode.get("risk_acceptance_required") or not mode.get("auto_expiry_required"):
    raise SystemExit("compatibility policy invalid: risk acceptance + auto-expiry are mandatory")

slo = load("artifacts/operations/slo_error_budget_report.json")
if slo["measured_availability_percent"] < slo["availability_slo_percent"]:
    raise SystemExit("slo gate failed: measured availability below target")
if slo["measured_error_budget_consumed_percent"] > slo["max_error_budget_consumed_percent"]:
    raise SystemExit("slo gate failed: error budget over-consumed")
if not slo.get("gate_passed", False):
    raise SystemExit("slo gate failed: artifact gate flag is false")

perf = load("artifacts/operations/performance_budget_report.json")
if perf["idle_cpu_percent"] > 2.0:
    raise SystemExit("performance gate failed: idle CPU above 2%")
if perf["idle_memory_mb"] > 120.0:
    raise SystemExit("performance gate failed: idle memory above 120 MB")
if perf["reconnect_seconds"] > 5.0:
    raise SystemExit("performance gate failed: reconnect above 5 seconds")
if perf["route_apply_p95_seconds"] > 2.0:
    raise SystemExit("performance gate failed: route apply p95 above 2 seconds")
if perf["throughput_overhead_percent"] > 15.0:
    raise SystemExit("performance gate failed: throughput overhead above 15%")
if perf["soak_test_hours"] < 24.0:
    raise SystemExit("performance gate failed: soak test duration under 24 hours")
if not perf.get("gate_passed", False):
    raise SystemExit("performance gate failed: artifact gate flag is false")

incident = load("artifacts/operations/incident_drill_report.json")
if not incident.get("postmortem_completed", False):
    raise SystemExit("incident gate failed: postmortem not completed")
if not incident.get("action_items_closed", False):
    raise SystemExit("incident gate failed: action items not closed")
if not incident.get("oncall_readiness_confirmed", False):
    raise SystemExit("incident gate failed: on-call readiness not confirmed")
if not incident.get("gate_passed", False):
    raise SystemExit("incident gate failed: artifact gate flag is false")

dr = load("artifacts/operations/dr_failover_report.json")
if dr["region_count"] < 2:
    raise SystemExit("dr gate failed: fewer than two regions validated")
if dr["measured_rpo_minutes"] > dr["rpo_target_minutes"]:
    raise SystemExit("dr gate failed: RPO target not met")
if dr["measured_rto_minutes"] > dr["rto_target_minutes"]:
    raise SystemExit("dr gate failed: RTO target not met")
if not dr.get("restore_integrity_verified", False):
    raise SystemExit("dr gate failed: restore integrity not verified")
if not dr.get("gate_passed", False):
    raise SystemExit("dr gate failed: artifact gate flag is false")

backend = load("artifacts/operations/backend_agility_report.json")
if backend["default_backend"].lower() != "wireguard":
    raise SystemExit("backend agility gate failed: default backend must be wireguard")
if len(backend.get("additional_backend_paths", [])) < 1:
    raise SystemExit("backend agility gate failed: at least one additional backend path is required")
if not backend.get("conformance_passed", False):
    raise SystemExit("backend agility gate failed: conformance not passed")
if not backend.get("security_review_complete", False):
    raise SystemExit("backend agility gate failed: security review incomplete")
if not backend.get("wireguard_is_adapter_boundary", False):
    raise SystemExit("backend agility gate failed: wireguard boundary not preserved")
if backend.get("protocol_leakage_detected", True):
    raise SystemExit("backend agility gate failed: protocol leakage detected")
if not backend.get("gate_passed", False):
    raise SystemExit("backend agility gate failed: artifact gate flag is false")

crypto = load("artifacts/operations/crypto_deprecation_schedule.json")
entries = crypto.get("entries", [])
if not entries:
    raise SystemExit("crypto schedule gate failed: no deprecation entries present")
for entry in entries:
    deprecates_at = parse_utc(entry["deprecates_at_utc"])
    removal_at = parse_utc(entry["removal_at_utc"])
    if removal_at <= deprecates_at:
        raise SystemExit("crypto schedule gate failed: removal timestamp must be after deprecation timestamp")
if crypto.get("exceptions_default_enabled", True):
    raise SystemExit("crypto schedule gate failed: insecure exceptions must be disabled by default")
if not crypto.get("exceptions_require_risk_acceptance", False):
    raise SystemExit("crypto schedule gate failed: exceptions must require risk acceptance")
if not crypto.get("exceptions_auto_expire", False):
    raise SystemExit("crypto schedule gate failed: exceptions must auto-expire")

print("Phase 9 operational readiness checks: PASS")
PY
