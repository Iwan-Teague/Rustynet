#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

REPORT_PATH="${RUSTYNET_FRESH_INSTALL_OS_MATRIX_REPORT_PATH:-artifacts/phase10/fresh_install_os_matrix_report.json}"
MAX_AGE_SECONDS="${RUSTYNET_FRESH_INSTALL_OS_MATRIX_MAX_AGE_SECONDS:-604800}"
PROFILE="${RUSTYNET_FRESH_INSTALL_OS_MATRIX_PROFILE:-cross_platform}"

python3 - "$REPORT_PATH" "$MAX_AGE_SECONDS" "$PROFILE" <<'PY'
import json
import re
import subprocess
import sys
import time
from pathlib import Path

report_path = Path(sys.argv[1])
max_age_seconds = int(sys.argv[2])
profile = sys.argv[3]
now_unix = int(time.time())

if profile == "cross_platform":
    required_os_profiles = {
        "debian13": "linux",
        "ubuntu": "linux",
        "fedora": "linux",
        "mint": "linux",
        "macos": "macos",
    }
elif profile == "linux":
    required_os_profiles = {
        "debian13": "linux",
        "ubuntu": "linux",
        "fedora": "linux",
        "mint": "linux",
    }
else:
    raise SystemExit(
        "unsupported fresh install OS matrix profile: "
        f"{profile} (expected cross_platform or linux)"
    )

required_checks = {
    "clean_install": {
        "host_pristine",
        "fresh_install_completed",
        "service_bootstrap_secure",
        "key_custody_hardened",
        "no_legacy_fallback_paths",
    },
    "one_hop": {
        "tunnel_established",
        "encrypted_transport",
        "egress_via_selected_exit",
        "dns_fail_closed",
        "no_underlay_leak",
    },
    "two_hop": {
        "chain_enforced",
        "encrypted_transport",
        "entry_relay_forwarding",
        "final_exit_egress",
        "no_underlay_leak",
    },
    "role_switch": {
        "switch_execution",
        "post_switch_reconcile",
        "policy_still_enforced",
        "least_privilege_preserved",
    },
}

required_security_assertions = {
    "no_plaintext_secrets_at_rest",
    "encrypted_transport_required",
    "default_deny_enforced",
    "fail_closed_enforced",
    "least_privilege_role_switch",
}


def fail(message: str) -> None:
    raise SystemExit(message)


def require_nonempty_string(payload: dict, key: str, label: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        fail(f"{label} requires non-empty string field: {key}")
    return value


def require_positive_int(payload: dict, key: str, label: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or value <= 0:
        fail(f"{label} requires positive integer field: {key}")
    return value


def validate_timestamp(value: int, label: str) -> None:
    if value > now_unix + 300:
        fail(f"{label} timestamp is too far in the future")
    if now_unix - value > max_age_seconds:
        fail(f"{label} evidence is stale; refresh OS matrix evidence")


def validate_source_artifacts(payload: dict, label: str) -> None:
    artifacts = payload.get("source_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        fail(f"{label} requires non-empty source_artifacts list")
    for artifact in artifacts:
        if not isinstance(artifact, str) or not artifact.strip():
            fail(f"{label} has invalid source artifact entry")
        candidate = Path(artifact)
        if not candidate.is_absolute():
            candidate = (Path.cwd() / candidate).resolve()
        if not candidate.exists():
            fail(f"{label} source artifact does not exist: {artifact}")


if not report_path.is_file():
    fail(f"missing fresh install OS matrix report: {report_path}")

with report_path.open("r", encoding="utf-8") as fh:
    payload = json.load(fh)

if not isinstance(payload, dict):
    fail("fresh install OS matrix report must be a JSON object")

if payload.get("schema_version") != 1:
    fail("fresh install OS matrix report must set schema_version=1")
if payload.get("evidence_mode") != "measured":
    fail("fresh install OS matrix report must set evidence_mode=measured")

require_nonempty_string(payload, "environment", "fresh_install_os_matrix_report")
captured_at_unix = require_positive_int(
    payload, "captured_at_unix", "fresh_install_os_matrix_report"
)
validate_timestamp(captured_at_unix, "fresh_install_os_matrix_report")
validate_source_artifacts(payload, "fresh_install_os_matrix_report")

git_commit = require_nonempty_string(
    payload, "git_commit", "fresh_install_os_matrix_report"
)
if not re.fullmatch(r"[0-9a-f]{40}", git_commit):
    fail("fresh install OS matrix report git_commit must be a 40-char lowercase hex SHA")
head_commit = (
    subprocess.check_output(["git", "rev-parse", "HEAD"], text=True)
    .strip()
    .lower()
)
if git_commit != head_commit:
    fail(
        "fresh install OS matrix report git_commit does not match current HEAD; "
        "rerun matrix tests on this exact commit"
    )

security_assertions = payload.get("security_assertions")
if not isinstance(security_assertions, dict):
    fail("fresh install OS matrix report requires security_assertions object")
missing_assertions = sorted(
    key for key in required_security_assertions if key not in security_assertions
)
if missing_assertions:
    fail(
        "fresh install OS matrix report missing security_assertions: "
        + ", ".join(missing_assertions)
    )
for key in required_security_assertions:
    if security_assertions.get(key) is not True:
        fail(f"fresh install OS matrix security_assertion must be true: {key}")

scenarios = payload.get("scenarios")
if not isinstance(scenarios, dict):
    fail("fresh install OS matrix report requires scenarios object")
if set(scenarios.keys()) != set(required_os_profiles.keys()):
    missing = sorted(set(required_os_profiles.keys()) - set(scenarios.keys()))
    extra = sorted(set(scenarios.keys()) - set(required_os_profiles.keys()))
    details = []
    if missing:
        details.append(f"missing={','.join(missing)}")
    if extra:
        details.append(f"extra={','.join(extra)}")
    fail(
        "fresh install OS matrix scenarios must match required OS set "
        + "(" + "; ".join(details) + ")"
    )

for os_id, expected_profile in required_os_profiles.items():
    scenario = scenarios.get(os_id)
    label = f"fresh_install_os_matrix.scenarios.{os_id}"
    if not isinstance(scenario, dict):
        fail(f"{label} must be an object")
    if scenario.get("status") != "pass":
        fail(f"{label}.status must be pass")
    if require_nonempty_string(scenario, "host_profile", label) != expected_profile:
        fail(f"{label}.host_profile must be {expected_profile}")
    require_nonempty_string(scenario, "os_version", label)
    require_nonempty_string(scenario, "node_id", label)

    for section_name, expected_check_keys in required_checks.items():
        section = scenario.get(section_name)
        section_label = f"{label}.{section_name}"
        if not isinstance(section, dict):
            fail(f"{section_label} must be an object")
        if section.get("status") != "pass":
            fail(f"{section_label}.status must be pass")
        section_time = require_positive_int(section, "captured_at_unix", section_label)
        validate_timestamp(section_time, section_label)
        validate_source_artifacts(section, section_label)
        checks = section.get("checks")
        if not isinstance(checks, dict):
            fail(f"{section_label}.checks must be an object")
        missing_checks = sorted(key for key in expected_check_keys if key not in checks)
        if missing_checks:
            fail(
                f"{section_label}.checks missing required keys: "
                + ", ".join(missing_checks)
            )
        for key in expected_check_keys:
            if checks.get(key) != "pass":
                fail(f"{section_label}.checks.{key} must be pass")

    if scenario["one_hop"].get("hop_count") != 1:
        fail(f"{label}.one_hop.hop_count must be 1")
    if scenario["two_hop"].get("hop_count") != 2:
        fail(f"{label}.two_hop.hop_count must be 2")

    transitions = scenario["role_switch"].get("transitions")
    if not isinstance(transitions, list) or len(transitions) < 1:
        fail(f"{label}.role_switch.transitions must contain at least one transition")
    for index, transition in enumerate(transitions):
        transition_label = f"{label}.role_switch.transitions[{index}]"
        if not isinstance(transition, dict):
            fail(f"{transition_label} must be an object")
        source_role = require_nonempty_string(transition, "from_role", transition_label)
        target_role = require_nonempty_string(transition, "to_role", transition_label)
        if source_role == target_role:
            fail(f"{transition_label} must change role")
        if transition.get("status") != "pass":
            fail(f"{transition_label}.status must be pass")

print("Fresh install OS matrix readiness checks: PASS")
PY
