#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

head_commit="$(git rev-parse HEAD | tr '[:upper:]' '[:lower:]')"
stale_commit="1111111111111111111111111111111111111111"
now_unix="$(date +%s)"

TMPDIR_PATH="$tmpdir" HEAD_COMMIT="$head_commit" STALE_COMMIT="$stale_commit" NOW_UNIX="$now_unix" python3 - <<'PY'
import json
import os
from pathlib import Path

tmpdir = Path(os.environ["TMPDIR_PATH"])
head_commit = os.environ["HEAD_COMMIT"]
stale_commit = os.environ["STALE_COMMIT"]
now_unix = int(os.environ["NOW_UNIX"])

for name in (
    "bootstrap_hosts.log",
    "validate_baseline_runtime.log",
    "two_hop.log",
    "lan_toggle.log",
    "exit_handoff.log",
    "exit_handoff_monitor.log",
    "role_switch.md",
):
    (tmpdir / name).write_text(f"{name}\n", encoding="utf-8")


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


role_switch_report = {
    "schema_version": 1,
    "evidence_mode": "measured",
    "git_commit": head_commit,
    "captured_at_unix": now_unix,
    "status": "pass",
    "hosts": {
        key: {
            "transition": {"from_role": "client", "to_role": "admin", "status": "pass"},
            "checks": {
                "switch_execution": "pass",
                "post_switch_reconcile": "pass",
                "policy_still_enforced": "pass",
                "least_privilege_preserved": "pass",
            },
        }
        for key in ("debian13", "ubuntu", "fedora", "mint")
    },
    "source_artifact": str((tmpdir / "role_switch.md").resolve()),
}
write_json(tmpdir / "role_switch_matrix_report.json", role_switch_report)

for report_name, source_names in {
    "live_linux_two_hop_report.json": ["two_hop.log"],
    "live_linux_lan_toggle_report.json": ["lan_toggle.log"],
    "live_linux_exit_handoff_report.json": ["exit_handoff.log", "exit_handoff_monitor.log"],
}.items():
    payload = {
        "phase": "phase10",
        "mode": report_name.removesuffix(".json"),
        "evidence_mode": "measured",
        "captured_at_unix": now_unix,
        "git_commit": head_commit,
        "status": "pass",
        "source_artifacts": [str((tmpdir / name).resolve()) for name in source_names],
    }
    write_json(tmpdir / report_name, payload)


def section(source_artifacts, checks, hop_count=None, transitions=None):
    payload = {
        "status": "pass",
        "captured_at_unix": now_unix,
        "source_artifacts": source_artifacts,
        "checks": checks,
    }
    if hop_count is not None:
        payload["hop_count"] = hop_count
    if transitions is not None:
        payload["transitions"] = transitions
    return payload


top_level_report = {
    "schema_version": 1,
    "evidence_mode": "measured",
    "environment": "fixture",
    "captured_at_unix": now_unix,
    "git_commit": head_commit,
    "source_artifacts": [
        str((tmpdir / "bootstrap_hosts.log").resolve()),
        str((tmpdir / "validate_baseline_runtime.log").resolve()),
        str((tmpdir / "live_linux_two_hop_report.json").resolve()),
        str((tmpdir / "role_switch_matrix_report.json").resolve()),
        str((tmpdir / "live_linux_lan_toggle_report.json").resolve()),
        str((tmpdir / "live_linux_exit_handoff_report.json").resolve()),
        str((tmpdir / "role_switch.md").resolve()),
        str((tmpdir / "two_hop.log").resolve()),
        str((tmpdir / "lan_toggle.log").resolve()),
        str((tmpdir / "exit_handoff.log").resolve()),
        str((tmpdir / "exit_handoff_monitor.log").resolve()),
    ],
    "security_assertions": {
        "no_plaintext_secrets_at_rest": True,
        "encrypted_transport_required": True,
        "default_deny_enforced": True,
        "fail_closed_enforced": True,
        "least_privilege_role_switch": True,
    },
    "scenarios": {},
}

for os_id, host_profile in {
    "debian13": "linux",
    "ubuntu": "linux",
    "fedora": "linux",
    "mint": "linux",
}.items():
    top_level_report["scenarios"][os_id] = {
        "status": "pass",
        "host_profile": host_profile,
        "os_version": os_id,
        "node_id": f"{os_id}-node",
        "clean_install": section(
            [
                str((tmpdir / "bootstrap_hosts.log").resolve()),
                str((tmpdir / "validate_baseline_runtime.log").resolve()),
            ],
            {
                "host_pristine": "pass",
                "fresh_install_completed": "pass",
                "service_bootstrap_secure": "pass",
                "key_custody_hardened": "pass",
                "no_legacy_fallback_paths": "pass",
            },
        ),
        "one_hop": section(
            [
                str((tmpdir / "validate_baseline_runtime.log").resolve()),
                str((tmpdir / "live_linux_exit_handoff_report.json").resolve()),
                str((tmpdir / "exit_handoff.log").resolve()),
                str((tmpdir / "exit_handoff_monitor.log").resolve()),
            ],
            {
                "tunnel_established": "pass",
                "encrypted_transport": "pass",
                "egress_via_selected_exit": "pass",
                "dns_fail_closed": "pass",
                "no_underlay_leak": "pass",
            },
            hop_count=1,
        ),
        "two_hop": section(
            [
                str((tmpdir / "live_linux_two_hop_report.json").resolve()),
                str((tmpdir / "two_hop.log").resolve()),
            ],
            {
                "chain_enforced": "pass",
                "encrypted_transport": "pass",
                "entry_relay_forwarding": "pass",
                "final_exit_egress": "pass",
                "no_underlay_leak": "pass",
            },
            hop_count=2,
        ),
        "role_switch": section(
            [
                str((tmpdir / "role_switch_matrix_report.json").resolve()),
                str((tmpdir / "role_switch.md").resolve()),
            ],
            {
                "switch_execution": "pass",
                "post_switch_reconcile": "pass",
                "policy_still_enforced": "pass",
                "least_privilege_preserved": "pass",
            },
            transitions=[{"from_role": "client", "to_role": "admin", "status": "pass"}],
        ),
    }

write_json(tmpdir / "report.json", top_level_report)

stale_child_report = json.loads((tmpdir / "live_linux_two_hop_report.json").read_text(encoding="utf-8"))
stale_child_report["git_commit"] = stale_commit
write_json(tmpdir / "report_with_stale_child.json", top_level_report)
write_json(tmpdir / "live_linux_two_hop_report_stale.json", stale_child_report)

wrapper_replay = json.loads((tmpdir / "report_with_stale_child.json").read_text(encoding="utf-8"))
wrapper_replay["source_artifacts"] = [
    str((tmpdir / "bootstrap_hosts.log").resolve()),
    str((tmpdir / "validate_baseline_runtime.log").resolve()),
    str((tmpdir / "live_linux_two_hop_report_stale.json").resolve()),
    str((tmpdir / "role_switch_matrix_report.json").resolve()),
    str((tmpdir / "live_linux_lan_toggle_report.json").resolve()),
    str((tmpdir / "live_linux_exit_handoff_report.json").resolve()),
    str((tmpdir / "role_switch.md").resolve()),
    str((tmpdir / "two_hop.log").resolve()),
    str((tmpdir / "lan_toggle.log").resolve()),
    str((tmpdir / "exit_handoff.log").resolve()),
    str((tmpdir / "exit_handoff_monitor.log").resolve()),
]
for scenario in wrapper_replay["scenarios"].values():
    scenario["two_hop"]["source_artifacts"] = [
        str((tmpdir / "live_linux_two_hop_report_stale.json").resolve()),
        str((tmpdir / "two_hop.log").resolve()),
    ]
write_json(tmpdir / "report_with_stale_child.json", wrapper_replay)
PY

RUSTYNET_FRESH_INSTALL_OS_MATRIX_PROFILE=linux \
RUSTYNET_FRESH_INSTALL_OS_MATRIX_REPORT_PATH="$tmpdir/report.json" \
RUSTYNET_FRESH_INSTALL_OS_MATRIX_EXPECTED_GIT_COMMIT="$head_commit" \
./scripts/ci/check_fresh_install_os_matrix_readiness.sh

if RUSTYNET_FRESH_INSTALL_OS_MATRIX_PROFILE=linux \
  RUSTYNET_FRESH_INSTALL_OS_MATRIX_REPORT_PATH="$tmpdir/report_with_stale_child.json" \
  RUSTYNET_FRESH_INSTALL_OS_MATRIX_EXPECTED_GIT_COMMIT="$head_commit" \
  ./scripts/ci/check_fresh_install_os_matrix_readiness.sh; then
  echo "expected stale child commit replay fixture to fail readiness validation" >&2
  exit 1
fi

echo "fresh install OS matrix readiness self-test: PASS"
