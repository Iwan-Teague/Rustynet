#!/usr/bin/env python3
"""Shared schema contract for cross-network remote-exit Phase 10 measured reports."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
CHECK_STATUSES = {"pass", "fail"}


@dataclass(frozen=True)
class CrossNetworkReportSpec:
    filename: str
    suite: str
    title: str
    required_participants: tuple[str, ...]
    required_network_fields: tuple[str, ...]
    required_checks: tuple[str, ...]


REPORT_SPECS: tuple[CrossNetworkReportSpec, ...] = (
    CrossNetworkReportSpec(
        filename="cross_network_direct_remote_exit_report.json",
        suite="cross_network_direct_remote_exit",
        title="Cross-Network Direct Remote Exit",
        required_participants=("client_host", "exit_host"),
        required_network_fields=(
            "client_network_id",
            "exit_network_id",
            "nat_profile",
            "impairment_profile",
        ),
        required_checks=(
            "direct_remote_exit_success",
            "remote_exit_no_underlay_leak",
            "remote_exit_server_ip_bypass_is_narrow",
        ),
    ),
    CrossNetworkReportSpec(
        filename="cross_network_relay_remote_exit_report.json",
        suite="cross_network_relay_remote_exit",
        title="Cross-Network Relay Remote Exit",
        required_participants=("client_host", "exit_host", "relay_host"),
        required_network_fields=(
            "client_network_id",
            "exit_network_id",
            "relay_network_id",
            "nat_profile",
            "impairment_profile",
        ),
        required_checks=(
            "relay_remote_exit_success",
            "remote_exit_no_underlay_leak",
            "remote_exit_server_ip_bypass_is_narrow",
        ),
    ),
    CrossNetworkReportSpec(
        filename="cross_network_failback_roaming_report.json",
        suite="cross_network_failback_roaming",
        title="Cross-Network Failback and Roaming",
        required_participants=("client_host", "exit_host", "relay_host"),
        required_network_fields=(
            "client_network_id",
            "exit_network_id",
            "relay_network_id",
            "nat_profile",
            "impairment_profile",
        ),
        required_checks=(
            "relay_to_direct_failback_success",
            "endpoint_roam_recovery_success",
            "remote_exit_no_underlay_leak",
        ),
    ),
    CrossNetworkReportSpec(
        filename="cross_network_traversal_adversarial_report.json",
        suite="cross_network_traversal_adversarial",
        title="Cross-Network Traversal Adversarial",
        required_participants=("client_host", "exit_host", "probe_host"),
        required_network_fields=(
            "client_network_id",
            "exit_network_id",
            "nat_profile",
            "impairment_profile",
        ),
        required_checks=(
            "forged_traversal_rejected",
            "stale_traversal_rejected",
            "replayed_traversal_rejected",
            "rogue_endpoint_rejected",
            "control_surface_exposure_blocked",
        ),
    ),
    CrossNetworkReportSpec(
        filename="cross_network_remote_exit_dns_report.json",
        suite="cross_network_remote_exit_dns",
        title="Cross-Network Remote Exit DNS",
        required_participants=("client_host", "exit_host"),
        required_network_fields=(
            "client_network_id",
            "exit_network_id",
            "nat_profile",
            "impairment_profile",
        ),
        required_checks=(
            "managed_dns_resolution_success",
            "remote_exit_dns_fail_closed",
            "remote_exit_no_underlay_leak",
        ),
    ),
    CrossNetworkReportSpec(
        filename="cross_network_remote_exit_soak_report.json",
        suite="cross_network_remote_exit_soak",
        title="Cross-Network Remote Exit Soak",
        required_participants=("client_host", "exit_host"),
        required_network_fields=(
            "client_network_id",
            "exit_network_id",
            "nat_profile",
            "impairment_profile",
        ),
        required_checks=(
            "long_soak_stable",
            "remote_exit_no_underlay_leak",
            "remote_exit_server_ip_bypass_is_narrow",
            "cross_network_topology_heuristic",
            "direct_remote_exit_ready",
            "post_soak_bypass_ready",
            "no_plaintext_passphrase_files",
        ),
    ),
)

REPORT_SPECS_BY_SUITE = {spec.suite: spec for spec in REPORT_SPECS}
REPORT_SPECS_BY_FILENAME = {spec.filename: spec for spec in REPORT_SPECS}


def resolve_artifact_path(report_path: Path, raw_path: str) -> Path:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate
    return (report_path.parent / candidate).resolve()


def path_is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def validate_report_payload(
    report_path: Path,
    payload: dict[str, Any],
    *,
    max_evidence_age_seconds: int | None = None,
    now_unix: int | None = None,
) -> list[str]:
    problems: list[str] = []
    if not isinstance(payload, dict):
        return [f"{report_path}: report must be a JSON object"]

    spec = REPORT_SPECS_BY_SUITE.get(payload.get("suite"))
    if spec is None:
        known = ", ".join(sorted(REPORT_SPECS_BY_SUITE))
        return [f"{report_path}: unknown suite {payload.get('suite')!r}; expected one of {known}"]

    expected_filename = REPORT_SPECS_BY_FILENAME.get(report_path.name)
    if expected_filename is not None and expected_filename.suite != spec.suite:
        problems.append(
            f"filename {report_path.name!r} does not match suite {spec.suite!r}"
        )

    if payload.get("schema_version") != 1:
        problems.append("schema_version must equal 1")
    if payload.get("phase") != "phase10":
        problems.append("phase must equal 'phase10'")
    if payload.get("evidence_mode") != "measured":
        problems.append("evidence_mode must equal 'measured'")

    environment = payload.get("environment")
    if not isinstance(environment, str) or not environment.strip():
        problems.append("environment must be a non-empty string")

    captured_at_unix = payload.get("captured_at_unix")
    if not isinstance(captured_at_unix, int) or captured_at_unix <= 0:
        problems.append("captured_at_unix must be a positive integer")
    else:
        if now_unix is None:
            now_unix = int(time.time())
        if captured_at_unix > now_unix + 300:
            problems.append("captured_at_unix is too far in the future")
        if max_evidence_age_seconds is not None and now_unix - captured_at_unix > max_evidence_age_seconds:
            problems.append("captured_at_unix is stale")

    git_commit = payload.get("git_commit")
    if not isinstance(git_commit, str) or not GIT_COMMIT_RE.fullmatch(git_commit):
        problems.append("git_commit must be a 40-character lowercase hex commit id")

    status = payload.get("status")
    if status not in {"pass", "fail"}:
        problems.append("status must be 'pass' or 'fail'")

    participants = payload.get("participants")
    if not isinstance(participants, dict):
        problems.append("participants must be an object")
    else:
        for field in spec.required_participants:
            value = participants.get(field)
            if not isinstance(value, str) or not value.strip():
                problems.append(f"participants.{field} must be a non-empty string")

    network_context = payload.get("network_context")
    if not isinstance(network_context, dict):
        problems.append("network_context must be an object")
    else:
        for field in spec.required_network_fields:
            value = network_context.get(field)
            if not isinstance(value, str) or not value.strip():
                problems.append(f"network_context.{field} must be a non-empty string")
        client_network_id = network_context.get("client_network_id")
        exit_network_id = network_context.get("exit_network_id")
        if (
            isinstance(client_network_id, str)
            and client_network_id.strip()
            and isinstance(exit_network_id, str)
            and exit_network_id.strip()
            and client_network_id == exit_network_id
        ):
            problems.append("client_network_id and exit_network_id must differ")

    report_dir = report_path.parent.resolve()
    repo_root = Path.cwd().resolve()
    for field_name in ("source_artifacts", "log_artifacts"):
        field_value = payload.get(field_name)
        if not isinstance(field_value, list) or not field_value:
            problems.append(f"{field_name} must be a non-empty list")
            continue
        for raw_path in field_value:
            if not isinstance(raw_path, str) or not raw_path.strip():
                problems.append(f"{field_name} contains an invalid path entry")
                continue
            if any(ch in raw_path for ch in ("\n", "\r", "\t")):
                problems.append(f"{field_name} contains control characters in path entry")
                continue
            artifact_path = resolve_artifact_path(report_path, raw_path)
            if not artifact_path.exists():
                problems.append(f"{field_name} path does not exist: {raw_path}")
                continue
            if artifact_path.is_symlink():
                problems.append(f"{field_name} path must not be a symlink: {raw_path}")
                continue
            if not artifact_path.is_file():
                problems.append(f"{field_name} path must be a regular file: {raw_path}")
                continue
            if not (
                path_is_within(artifact_path, report_dir)
                or path_is_within(artifact_path, repo_root)
            ):
                problems.append(
                    f"{field_name} path must stay within report directory or repository root: {raw_path}"
                )

    checks = payload.get("checks")
    if not isinstance(checks, dict):
        problems.append("checks must be an object")
    else:
        for check_name in spec.required_checks:
            value = checks.get(check_name)
            if value not in CHECK_STATUSES:
                problems.append(
                    f"checks.{check_name} must be one of {sorted(CHECK_STATUSES)}, got {value!r}"
                )

    failure_summary = payload.get("failure_summary")
    if status == "pass":
        if isinstance(checks, dict):
            failing = [name for name in spec.required_checks if checks.get(name) != "pass"]
            if failing:
                problems.append(
                    "status=pass requires all required checks to pass; failing checks: "
                    + ", ".join(failing)
                )
        if failure_summary not in (None, ""):
            problems.append("failure_summary must be absent or empty when status=pass")
    elif status == "fail":
        if not isinstance(failure_summary, str) or not failure_summary.strip():
            problems.append("failure_summary must be non-empty when status=fail")
        if isinstance(checks, dict):
            if all(checks.get(name) == "pass" for name in spec.required_checks):
                problems.append("status=fail requires at least one required check to fail")

    return [f"{report_path}: {problem}" for problem in problems]
