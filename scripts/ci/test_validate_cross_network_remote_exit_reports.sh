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

temp_dir = Path(sys.argv[1])
source_file = Path(sys.argv[2])
log_file = Path(sys.argv[3])
git_commit = sys.argv[4]
captured_at_unix = int(sys.argv[5])


def write_report(name: str, payload: dict) -> None:
    path = temp_dir / name
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


common = {
    "schema_version": 1,
    "phase": "phase10",
    "environment": "ci",
    "evidence_mode": "measured",
    "captured_at_unix": captured_at_unix,
    "git_commit": git_commit,
    "source_artifacts": [str(source_file)],
    "log_artifacts": [str(log_file)],
}

write_report(
    "cross_network_direct_remote_exit_report.json",
    {
        **common,
        "suite": "cross_network_direct_remote_exit",
        "status": "pass",
        "participants": {"client_host": "client@example", "exit_host": "exit@example"},
        "network_context": {"client_network_id": "net-a", "exit_network_id": "net-b"},
        "checks": {
            "direct_remote_exit_success": "pass",
            "remote_exit_no_underlay_leak": "pass",
            "remote_exit_server_ip_bypass_is_narrow": "pass",
        },
    },
)

write_report(
    "cross_network_relay_remote_exit_report.json",
    {
        **common,
        "suite": "cross_network_relay_remote_exit",
        "status": "pass",
        "participants": {
            "client_host": "client@example",
            "exit_host": "exit@example",
            "relay_host": "relay@example",
        },
        "network_context": {
            "client_network_id": "net-a",
            "exit_network_id": "net-b",
            "relay_network_id": "net-c",
        },
        "checks": {
            "relay_remote_exit_success": "pass",
            "remote_exit_no_underlay_leak": "pass",
            "remote_exit_server_ip_bypass_is_narrow": "pass",
        },
    },
)

write_report(
    "cross_network_failback_roaming_report.json",
    {
        **common,
        "suite": "cross_network_failback_roaming",
        "status": "pass",
        "participants": {
            "client_host": "client@example",
            "exit_host": "exit@example",
            "relay_host": "relay@example",
        },
        "network_context": {
            "client_network_id": "net-a",
            "exit_network_id": "net-b",
            "relay_network_id": "net-c",
        },
        "checks": {
            "relay_to_direct_failback_success": "pass",
            "endpoint_roam_recovery_success": "pass",
            "remote_exit_no_underlay_leak": "pass",
        },
    },
)

write_report(
    "cross_network_traversal_adversarial_report.json",
    {
        **common,
        "suite": "cross_network_traversal_adversarial",
        "status": "pass",
        "participants": {
            "client_host": "client@example",
            "exit_host": "exit@example",
            "probe_host": "probe@example",
        },
        "network_context": {"client_network_id": "net-a", "exit_network_id": "net-b"},
        "checks": {
            "forged_traversal_rejected": "pass",
            "stale_traversal_rejected": "pass",
            "replayed_traversal_rejected": "pass",
            "rogue_endpoint_rejected": "pass",
            "control_surface_exposure_blocked": "pass",
        },
    },
)

write_report(
    "cross_network_remote_exit_dns_report.json",
    {
        **common,
        "suite": "cross_network_remote_exit_dns",
        "status": "pass",
        "participants": {"client_host": "client@example", "exit_host": "exit@example"},
        "network_context": {"client_network_id": "net-a", "exit_network_id": "net-b"},
        "checks": {
            "managed_dns_resolution_success": "pass",
            "remote_exit_dns_fail_closed": "pass",
            "remote_exit_no_underlay_leak": "pass",
        },
    },
)

write_report(
    "cross_network_remote_exit_soak_report.json",
    {
        **common,
        "suite": "cross_network_remote_exit_soak",
        "status": "pass",
        "participants": {"client_host": "client@example", "exit_host": "exit@example"},
        "network_context": {"client_network_id": "net-a", "exit_network_id": "net-b"},
        "checks": {
            "long_soak_stable": "pass",
            "remote_exit_no_underlay_leak": "pass",
            "remote_exit_server_ip_bypass_is_narrow": "pass",
        },
    },
)

write_report(
    "invalid_same_network.json",
    {
        **common,
        "suite": "cross_network_direct_remote_exit",
        "status": "pass",
        "participants": {"client_host": "client@example", "exit_host": "exit@example"},
        "network_context": {"client_network_id": "net-a", "exit_network_id": "net-a"},
        "checks": {
            "direct_remote_exit_success": "pass",
            "remote_exit_no_underlay_leak": "pass",
            "remote_exit_server_ip_bypass_is_narrow": "pass",
        },
    },
)

write_report(
    "invalid_pass_with_failed_check.json",
    {
        **common,
        "suite": "cross_network_relay_remote_exit",
        "status": "pass",
        "participants": {
            "client_host": "client@example",
            "exit_host": "exit@example",
            "relay_host": "relay@example",
        },
        "network_context": {
            "client_network_id": "net-a",
            "exit_network_id": "net-b",
            "relay_network_id": "net-c",
        },
        "checks": {
            "relay_remote_exit_success": "fail",
            "remote_exit_no_underlay_leak": "pass",
            "remote_exit_server_ip_bypass_is_narrow": "pass",
        },
    },
)

write_report(
    "invalid_fail_without_summary.json",
    {
        **common,
        "suite": "cross_network_traversal_adversarial",
        "status": "fail",
        "participants": {
            "client_host": "client@example",
            "exit_host": "exit@example",
            "probe_host": "probe@example",
        },
        "network_context": {"client_network_id": "net-a", "exit_network_id": "net-b"},
        "checks": {
            "forged_traversal_rejected": "fail",
            "stale_traversal_rejected": "pass",
            "replayed_traversal_rejected": "pass",
            "rogue_endpoint_rejected": "pass",
            "control_surface_exposure_blocked": "pass",
        },
    },
)
PY

python3 "$ROOT_DIR/scripts/ci/validate_cross_network_remote_exit_reports.py" \
  --artifact-dir "$temp_dir" \
  --output "$temp_dir/valid.md"

if python3 "$ROOT_DIR/scripts/ci/validate_cross_network_remote_exit_reports.py" \
  --reports "$temp_dir/invalid_same_network.json"; then
  echo "expected invalid_same_network.json to fail validation" >&2
  exit 1
fi

if python3 "$ROOT_DIR/scripts/ci/validate_cross_network_remote_exit_reports.py" \
  --reports "$temp_dir/invalid_pass_with_failed_check.json"; then
  echo "expected invalid_pass_with_failed_check.json to fail validation" >&2
  exit 1
fi

if python3 "$ROOT_DIR/scripts/ci/validate_cross_network_remote_exit_reports.py" \
  --reports "$temp_dir/invalid_fail_without_summary.json"; then
  echo "expected invalid_fail_without_summary.json to fail validation" >&2
  exit 1
fi

if python3 "$ROOT_DIR/scripts/ci/validate_cross_network_remote_exit_reports.py" \
  --reports "$temp_dir/cross_network_direct_remote_exit_report.json" \
  --expected-git-commit "0000000000000000000000000000000000000000"; then
  echo "expected mismatched git commit to fail validation" >&2
  exit 1
fi

python3 - "$temp_dir/valid_fail_status.json" "$source_file" "$log_file" "$current_commit" "$captured_at_unix" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
source_file = sys.argv[2]
log_file = sys.argv[3]
git_commit = sys.argv[4]
captured_at_unix = int(sys.argv[5])

payload = {
    "schema_version": 1,
    "phase": "phase10",
    "suite": "cross_network_direct_remote_exit",
    "environment": "ci",
    "evidence_mode": "measured",
    "captured_at_unix": captured_at_unix,
    "git_commit": git_commit,
    "status": "fail",
    "participants": {"client_host": "client@example", "exit_host": "exit@example"},
    "network_context": {"client_network_id": "net-a", "exit_network_id": "net-b"},
    "checks": {
        "direct_remote_exit_success": "fail",
        "remote_exit_no_underlay_leak": "pass",
        "remote_exit_server_ip_bypass_is_narrow": "pass",
    },
    "failure_summary": "synthetic failure",
    "source_artifacts": [source_file],
    "log_artifacts": [log_file],
}
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY

if python3 "$ROOT_DIR/scripts/ci/validate_cross_network_remote_exit_reports.py" \
  --reports "$temp_dir/valid_fail_status.json" \
  --expected-git-commit "$current_commit" \
  --require-pass-status; then
  echo "expected require-pass-status to reject failing report" >&2
  exit 1
fi

echo "Cross-network remote-exit report schema tests: PASS"
