#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

SOURCE_DIR="${RUSTYNET_PHASE9_SOURCE_DIR:-artifacts/operations/source}"
RAW_DIR="${RUSTYNET_PHASE9_RAW_DIR:-artifacts/operations/raw}"
RUN_BACKEND_PROBES="${RUSTYNET_PHASE9_RUN_BACKEND_PROBES:-1}"
STRICT_MODE="${RUSTYNET_PHASE9_COLLECT_STRICT:-1}"

mkdir -p "$SOURCE_DIR"
mkdir -p "$RAW_DIR"

required_sources=(
  "compatibility_policy.json"
  "crypto_deprecation_schedule.json"
  "slo_windows.ndjson"
  "performance_samples.ndjson"
  "incident_drills.ndjson"
  "dr_drills.ndjson"
  "backend_security_review.json"
)

for source_name in "${required_sources[@]}"; do
  if [[ ! -f "$SOURCE_DIR/$source_name" ]]; then
    echo "missing phase9 evidence source: $SOURCE_DIR/$source_name" >&2
    exit 1
  fi
done

conformance_wireguard=false
conformance_backend_api=false
protocol_leakage_detected=true

if [[ "$RUN_BACKEND_PROBES" == "1" ]]; then
  if cargo test -p rustynet-backend-wireguard --test conformance --all-features >"$SOURCE_DIR/backend_conformance_wireguard.log" 2>&1; then
    conformance_wireguard=true
  fi

  if cargo test -p rustynet-backend-api --all-targets --all-features >"$SOURCE_DIR/backend_conformance_api.log" 2>&1; then
    conformance_backend_api=true
  fi

  set +e
  rg -n "(Wireguard|WireGuard|wg[-_]|wgctrl)" \
    crates/rustynet-control \
    crates/rustynet-policy \
    crates/rustynet-crypto \
    crates/rustynet-backend-api \
    crates/rustynet-cli \
    crates/rustynet-relay >"$SOURCE_DIR/backend_leakage_scan.log" 2>&1
  rg_exit=$?
  set -e

  if [[ "$rg_exit" -eq 0 ]]; then
    protocol_leakage_detected=true
  elif [[ "$rg_exit" -eq 1 ]]; then
    protocol_leakage_detected=false
  else
    echo "backend leakage scan failed unexpectedly; see $SOURCE_DIR/backend_leakage_scan.log" >&2
    exit 1
  fi
fi

export SOURCE_DIR
export RAW_DIR
export CONFORMANCE_WIREGUARD="$conformance_wireguard"
export CONFORMANCE_BACKEND_API="$conformance_backend_api"
export PROTOCOL_LEAKAGE_DETECTED="$protocol_leakage_detected"

python3 - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

source_dir = Path(os.environ["SOURCE_DIR"])
raw_dir = Path(os.environ["RAW_DIR"])
conformance_wireguard = os.environ["CONFORMANCE_WIREGUARD"] == "true"
conformance_backend_api = os.environ["CONFORMANCE_BACKEND_API"] == "true"
protocol_leakage_detected = os.environ["PROTOCOL_LEAKAGE_DETECTED"] == "true"


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_ndjson(path: Path):
    entries = []
    with path.open("r", encoding="utf-8") as fh:
        for line_number, line in enumerate(fh, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"invalid ndjson at {path}:{line_number}: {exc}") from exc
            if not isinstance(payload, dict):
                raise SystemExit(f"invalid ndjson object at {path}:{line_number}")
            entries.append(payload)
    if not entries:
        raise SystemExit(f"no entries in ndjson source: {path}")
    return entries


def parse_utc(value: str, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"missing or invalid UTC field: {field}")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemExit(f"invalid UTC timestamp for {field}: {value}") from exc


def pick_latest(entries, key):
    return max(entries, key=lambda entry: parse_utc(entry.get(key, ""), key))


def numeric(entry, keys, label):
    for key in keys:
        value = entry.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    raise SystemExit(f"missing numeric field for {label}; expected one of {keys}")


compat = load_json(source_dir / "compatibility_policy.json")
if not isinstance(compat, dict):
    raise SystemExit("compatibility_policy.json must be an object")

for required in ("policy_version", "minimum_supported_client", "latest_server", "deprecation_window_days", "insecure_compatibility_mode"):
    if required not in compat:
        raise SystemExit(f"compatibility policy missing field: {required}")

crypto = load_json(source_dir / "crypto_deprecation_schedule.json")
if not isinstance(crypto, dict):
    raise SystemExit("crypto_deprecation_schedule.json must be an object")
if not isinstance(crypto.get("entries"), list) or not crypto.get("entries"):
    raise SystemExit("crypto deprecation schedule requires non-empty entries")

slo_entries = load_ndjson(source_dir / "slo_windows.ndjson")
slo_latest = pick_latest(slo_entries, "window_end_utc")

performance_entries = load_ndjson(source_dir / "performance_samples.ndjson")
performance_entries_sorted = sorted(
    performance_entries,
    key=lambda entry: parse_utc(entry.get("measured_at_utc") or entry.get("timestamp_utc") or "", "performance timestamp"),
)
start_time = parse_utc(
    performance_entries_sorted[0].get("measured_at_utc") or performance_entries_sorted[0].get("timestamp_utc"),
    "performance start timestamp",
)
end_time = parse_utc(
    performance_entries_sorted[-1].get("measured_at_utc") or performance_entries_sorted[-1].get("timestamp_utc"),
    "performance end timestamp",
)
soak_test_hours = (end_time - start_time).total_seconds() / 3600.0

perf = {
    "benchmark_matrix": performance_entries_sorted[-1].get("benchmark_matrix", {}),
    "idle_cpu_percent": max(numeric(entry, ["idle_cpu_percent"], "idle_cpu_percent") for entry in performance_entries_sorted),
    "idle_memory_mb": max(numeric(entry, ["idle_memory_mb"], "idle_memory_mb") for entry in performance_entries_sorted),
    "reconnect_seconds": max(
        numeric(entry, ["reconnect_seconds", "reconnect_p95_seconds"], "reconnect_seconds")
        for entry in performance_entries_sorted
    ),
    "route_apply_p95_seconds": max(
        numeric(entry, ["route_apply_p95_seconds", "route_apply_seconds_p95"], "route_apply_p95_seconds")
        for entry in performance_entries_sorted
    ),
    "throughput_overhead_percent": max(
        numeric(entry, ["throughput_overhead_percent", "throughput_overhead_vs_wireguard_percent"], "throughput_overhead_percent")
        for entry in performance_entries_sorted
    ),
    "soak_test_hours": round(soak_test_hours, 3),
}

incident_entries = load_ndjson(source_dir / "incident_drills.ndjson")
incident_latest = pick_latest(incident_entries, "executed_at_utc")

dr_entries = load_ndjson(source_dir / "dr_drills.ndjson")
dr_latest = pick_latest(dr_entries, "executed_at_utc")

backend_review = load_json(source_dir / "backend_security_review.json")
if not isinstance(backend_review, dict):
    raise SystemExit("backend_security_review.json must be an object")

additional_paths = backend_review.get("additional_backend_paths")
if not isinstance(additional_paths, list) or not additional_paths:
    raise SystemExit("backend_security_review.json requires non-empty additional_backend_paths")
for path in additional_paths:
    if not isinstance(path, str) or not path.strip():
        raise SystemExit("backend additional path must be non-empty string")

backend = {
    "default_backend": backend_review.get("default_backend", "wireguard"),
    "additional_backend_paths": additional_paths,
    "conformance_passed": conformance_wireguard and conformance_backend_api,
    "security_review_complete": bool(backend_review.get("security_review_complete", False)),
    "wireguard_is_adapter_boundary": bool(backend_review.get("wireguard_is_adapter_boundary", False)),
    "protocol_leakage_detected": protocol_leakage_detected,
    "evidence_commands": [
        "cargo test -p rustynet-backend-wireguard --test conformance --all-features",
        "cargo test -p rustynet-backend-api --all-targets --all-features",
        "rg -n '(Wireguard|WireGuard|wg[-_]|wgctrl)' crates/rustynet-control crates/rustynet-policy crates/rustynet-crypto crates/rustynet-backend-api crates/rustynet-cli crates/rustynet-relay",
    ],
}

raw_payloads = {
    "compatibility_policy.json": compat,
    "slo_error_budget_report.json": {
        "window_start_utc": slo_latest.get("window_start_utc"),
        "window_end_utc": slo_latest.get("window_end_utc"),
        "availability_slo_percent": numeric(slo_latest, ["availability_slo_percent"], "availability_slo_percent"),
        "measured_availability_percent": numeric(slo_latest, ["measured_availability_percent"], "measured_availability_percent"),
        "max_error_budget_consumed_percent": numeric(slo_latest, ["max_error_budget_consumed_percent"], "max_error_budget_consumed_percent"),
        "measured_error_budget_consumed_percent": numeric(slo_latest, ["measured_error_budget_consumed_percent"], "measured_error_budget_consumed_percent"),
    },
    "performance_budget_report.json": perf,
    "incident_drill_report.json": {
        "drill_id": incident_latest.get("drill_id"),
        "executed_at_utc": incident_latest.get("executed_at_utc"),
        "scenario": incident_latest.get("scenario"),
        "detection_minutes": numeric(incident_latest, ["detection_minutes"], "incident detection_minutes"),
        "containment_minutes": numeric(incident_latest, ["containment_minutes"], "incident containment_minutes"),
        "recovery_minutes": numeric(incident_latest, ["recovery_minutes"], "incident recovery_minutes"),
        "postmortem_completed": bool(incident_latest.get("postmortem_completed", False)),
        "action_items_closed": bool(incident_latest.get("action_items_closed", False)),
        "oncall_readiness_confirmed": bool(incident_latest.get("oncall_readiness_confirmed", False)),
    },
    "dr_failover_report.json": {
        "drill_id": dr_latest.get("drill_id"),
        "executed_at_utc": dr_latest.get("executed_at_utc"),
        "regions_tested": dr_latest.get("regions_tested", []),
        "region_count": int(numeric(dr_latest, ["region_count"], "dr region_count")),
        "rpo_target_minutes": int(numeric(dr_latest, ["rpo_target_minutes"], "dr rpo_target_minutes")),
        "rto_target_minutes": int(numeric(dr_latest, ["rto_target_minutes"], "dr rto_target_minutes")),
        "measured_rpo_minutes": int(numeric(dr_latest, ["measured_rpo_minutes"], "dr measured_rpo_minutes")),
        "measured_rto_minutes": int(numeric(dr_latest, ["measured_rto_minutes"], "dr measured_rto_minutes")),
        "restore_integrity_verified": bool(dr_latest.get("restore_integrity_verified", False)),
    },
    "backend_agility_report.json": backend,
    "crypto_deprecation_schedule.json": crypto,
}

for filename, payload in raw_payloads.items():
    out = raw_dir / filename
    with out.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=False)
        fh.write("\n")

print(f"wrote {len(raw_payloads)} raw phase9 evidence files to {raw_dir}")
PY

if [[ "$STRICT_MODE" == "1" ]]; then
  if [[ "$conformance_wireguard" != "true" || "$conformance_backend_api" != "true" || "$protocol_leakage_detected" == "true" ]]; then
    echo "backend agility probe controls failed; raw evidence written but collection is failing closed" >&2
    exit 1
  fi
fi

echo "phase9 raw evidence collected from source logs/config and command probes"
