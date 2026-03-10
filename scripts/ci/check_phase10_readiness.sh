#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

ARTIFACT_DIR="${RUSTYNET_PHASE10_ARTIFACT_DIR:-${RUSTYNET_PHASE10_OUT_DIR:-artifacts/phase10}}"
MAX_EVIDENCE_AGE_SECONDS="${RUSTYNET_PHASE10_MAX_EVIDENCE_AGE_SECONDS:-2678400}"

cargo run --quiet -p rustynet-cli -- ops verify-phase10-provenance

python3 - "$ARTIFACT_DIR" "$MAX_EVIDENCE_AGE_SECONDS" <<'PY'
import json
import re
import sys
import time
from pathlib import Path

artifact_dir = Path(sys.argv[1])
max_evidence_age_seconds = int(sys.argv[2])
now_unix = int(time.time())

required_json = {
    "netns_e2e_report.json": "netns_e2e_report",
    "leak_test_report.json": "leak_test_report",
    "perf_budget_report.json": "perf_budget_report",
    "direct_relay_failover_report.json": "direct_relay_failover_report",
    "traversal_path_selection_report.json": "traversal_path_selection_report",
    "traversal_probe_security_report.json": "traversal_probe_security_report",
    "managed_dns_report.json": "managed_dns_report",
}

required_state_log = artifact_dir / "state_transition_audit.log"


def load_json_artifact(filename: str, label: str):
    path = artifact_dir / filename
    if not path.is_file():
        raise SystemExit(f"missing phase10 artifact: {path}")
    with path.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)
    if not isinstance(payload, dict):
        raise SystemExit(f"{label} must be a JSON object")

    if payload.get("evidence_mode") != "measured":
        raise SystemExit(f"{label} must set evidence_mode=measured")
    environment = payload.get("environment")
    if not isinstance(environment, str) or not environment.strip():
        raise SystemExit(f"{label} requires non-empty environment")

    captured_at_unix = payload.get("captured_at_unix")
    if not isinstance(captured_at_unix, int) or captured_at_unix <= 0:
        raise SystemExit(f"{label} requires positive integer captured_at_unix")
    if captured_at_unix > now_unix + 300:
        raise SystemExit(f"{label} captured_at_unix is too far in the future")
    if now_unix - captured_at_unix > max_evidence_age_seconds:
        raise SystemExit(f"{label} evidence is stale; recollect measured evidence")

    source_artifacts = payload.get("source_artifacts")
    if not isinstance(source_artifacts, list) or not source_artifacts:
        raise SystemExit(f"{label} requires non-empty source_artifacts list")
    for source in source_artifacts:
        if not isinstance(source, str) or not source.strip():
            raise SystemExit(f"{label} contains invalid source_artifacts entry")
        source_path = Path(source)
        if not source_path.is_absolute():
            source_path = (Path.cwd() / source_path).resolve()
        if not source_path.exists():
            raise SystemExit(f"{label} source artifact does not exist: {source}")

    return payload


payloads = {
    label: load_json_artifact(filename, label)
    for filename, label in required_json.items()
}

netns = payloads["netns_e2e_report"]
if netns.get("status") != "pass":
    raise SystemExit("netns_e2e_report must report status=pass")
netns_checks = netns.get("checks")
if not isinstance(netns_checks, dict) or not netns_checks:
    raise SystemExit("netns_e2e_report requires non-empty checks object")
if any(value != "pass" for value in netns_checks.values()):
    raise SystemExit("netns_e2e_report checks must all pass")

leak = payloads["leak_test_report"]
if leak.get("status") != "pass":
    raise SystemExit("leak_test_report must report status=pass")

failover = payloads["direct_relay_failover_report"]
if failover.get("status") != "pass":
    raise SystemExit("direct_relay_failover_report must report status=pass")
failover_checks = failover.get("checks")
if not isinstance(failover_checks, dict) or not failover_checks:
    raise SystemExit("direct_relay_failover_report requires non-empty checks object")
if any(value != "pass" for value in failover_checks.values()):
    raise SystemExit("direct_relay_failover_report checks must all pass")

traversal_path = payloads["traversal_path_selection_report"]
if traversal_path.get("status") != "pass":
    raise SystemExit("traversal_path_selection_report must report status=pass")
traversal_path_checks = traversal_path.get("checks")
if not isinstance(traversal_path_checks, dict) or not traversal_path_checks:
    raise SystemExit("traversal_path_selection_report requires non-empty checks object")
for check_name in (
    "direct_probe_success",
    "relay_fallback_success",
    "direct_failback_success",
):
    if traversal_path_checks.get(check_name) != "pass":
        raise SystemExit(
            f"traversal_path_selection_report check must pass: {check_name}"
        )

traversal_security = payloads["traversal_probe_security_report"]
if traversal_security.get("status") != "pass":
    raise SystemExit("traversal_probe_security_report must report status=pass")
traversal_security_checks = traversal_security.get("checks")
if not isinstance(traversal_security_checks, dict) or not traversal_security_checks:
    raise SystemExit("traversal_probe_security_report requires non-empty checks object")
for check_name in (
    "replay_rejected",
    "fail_closed_on_invalid_traversal",
    "no_unauthorized_endpoint_mutation",
    "managed_peer_coverage_required",
    "unmanaged_peer_bundle_rejected",
):
    if traversal_security_checks.get(check_name) != "pass":
        raise SystemExit(
            f"traversal_probe_security_report check must pass: {check_name}"
        )

managed_dns = payloads["managed_dns_report"]
if managed_dns.get("status") != "pass":
    raise SystemExit("managed_dns_report must report status=pass")
managed_dns_checks = managed_dns.get("checks")
if not isinstance(managed_dns_checks, dict) or not managed_dns_checks:
    raise SystemExit("managed_dns_report requires non-empty checks object")
for check_name in (
    "zone_issue_verify_passes",
    "dns_inspect_valid",
    "managed_dns_service_active",
    "resolvectl_split_dns_configured",
    "loopback_resolver_answers_managed_name",
    "systemd_resolved_answers_managed_name",
    "alias_resolves_to_expected_ip",
    "non_managed_query_refused",
    "stale_bundle_fail_closed",
    "valid_bundle_restored",
):
    if managed_dns_checks.get(check_name) != "pass":
        raise SystemExit(
            f"managed_dns_report check must pass: {check_name}"
        )

perf = payloads["perf_budget_report"]
if perf.get("soak_status") != "pass":
    raise SystemExit("perf_budget_report must report soak_status=pass")
metrics = perf.get("metrics")
if not isinstance(metrics, list) or not metrics:
    raise SystemExit("perf_budget_report requires non-empty metrics list")

required_metric_names = {
    "idle_cpu_percent",
    "idle_rss_mb",
    "reconnect_seconds",
    "route_apply_p95_seconds",
    "throughput_overhead_percent",
}
seen_metric_names = set()
for metric in metrics:
    if not isinstance(metric, dict):
        raise SystemExit("perf_budget_report metrics entries must be objects")
    name = metric.get("name")
    status = metric.get("status")
    if not isinstance(name, str) or not name.strip():
        raise SystemExit("perf_budget_report metric is missing name")
    if status != "pass":
        raise SystemExit(f"perf_budget_report metric did not pass: {name}")
    seen_metric_names.add(name)
missing_metric_names = sorted(required_metric_names - seen_metric_names)
if missing_metric_names:
    raise SystemExit(
        f"perf_budget_report missing required metrics: {', '.join(missing_metric_names)}"
    )

if not required_state_log.is_file():
    raise SystemExit(f"missing phase10 artifact: {required_state_log}")
state_log = required_state_log.read_text(encoding="utf-8")
if not re.search(r"generation=\d+", state_log):
    raise SystemExit("state_transition_audit.log missing generation entries")

print("Phase 10 readiness checks: PASS")
PY
