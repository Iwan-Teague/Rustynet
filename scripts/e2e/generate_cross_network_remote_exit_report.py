#!/usr/bin/env python3
"""Generate schema-valid measured cross-network remote-exit reports."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
CI_DIR = SCRIPT_DIR.parent / "ci"
if str(CI_DIR) not in sys.path:
    sys.path.insert(0, str(CI_DIR))

from cross_network_remote_exit_schema import REPORT_SPECS_BY_SUITE, validate_report_payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a cross-network remote-exit measured report."
    )
    parser.add_argument("--suite", required=True, help="Cross-network report suite name.")
    parser.add_argument("--report-path", required=True, help="Output report path.")
    parser.add_argument("--log-path", required=True, help="Primary log artifact path.")
    parser.add_argument("--status", required=True, choices=("pass", "fail"), help="Overall report status.")
    parser.add_argument("--failure-summary", default="", help="Failure summary for status=fail reports.")
    parser.add_argument("--environment", default="live_linux_skeleton", help="Measured evidence environment label.")
    parser.add_argument(
        "--implementation-state",
        default="not_implemented",
        help="Implementation state label recorded in the report metadata.",
    )
    parser.add_argument("--source-artifact", action="append", default=[], help="Additional source artifact path.")
    parser.add_argument("--log-artifact", action="append", default=[], help="Additional log artifact path.")
    parser.add_argument("--client-host", default="", help="Client host.")
    parser.add_argument("--exit-host", default="", help="Exit host.")
    parser.add_argument("--relay-host", default="", help="Relay host.")
    parser.add_argument("--probe-host", default="", help="Probe host.")
    parser.add_argument("--client-network-id", default="", help="Client network id.")
    parser.add_argument("--exit-network-id", default="", help="Exit network id.")
    parser.add_argument("--relay-network-id", default="", help="Relay network id.")
    parser.add_argument("--check", action="append", default=[], help="Check override in key=status form.")
    return parser.parse_args()


def current_git_commit() -> str:
    expected_commit = os.environ.get("RUSTYNET_EXPECTED_GIT_COMMIT", "").strip().lower()
    if expected_commit:
        return expected_commit
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip().lower()
    return commit


def parse_check_overrides(items: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise SystemExit(f"invalid --check value {item!r}; expected key=status")
        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or value not in {"pass", "fail"}:
            raise SystemExit(f"invalid --check value {item!r}; expected key=pass|fail")
        parsed[key] = value
    return parsed


def existing_artifacts(items: list[str]) -> list[str]:
    resolved: list[str] = []
    for item in items:
        path = Path(item).resolve()
        if path.exists():
            resolved.append(str(path))
    return resolved


def main() -> int:
    args = parse_args()
    spec = REPORT_SPECS_BY_SUITE.get(args.suite)
    if spec is None:
        known = ", ".join(sorted(REPORT_SPECS_BY_SUITE))
        raise SystemExit(f"unknown suite {args.suite!r}; expected one of {known}")

    report_path = Path(args.report_path).resolve()
    log_path = Path(args.log_path).resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if not log_path.exists():
        log_path.write_text("", encoding="utf-8")

    participants = {}
    if args.client_host:
        participants["client_host"] = args.client_host
    if args.exit_host:
        participants["exit_host"] = args.exit_host
    if args.relay_host:
        participants["relay_host"] = args.relay_host
    if args.probe_host:
        participants["probe_host"] = args.probe_host

    network_context = {}
    if args.client_network_id:
        network_context["client_network_id"] = args.client_network_id
    if args.exit_network_id:
        network_context["exit_network_id"] = args.exit_network_id
    if args.relay_network_id:
        network_context["relay_network_id"] = args.relay_network_id

    checks = {name: "fail" for name in spec.required_checks}
    checks.update(parse_check_overrides(args.check))

    source_artifacts = existing_artifacts(
        [str((SCRIPT_DIR / Path(__file__).name).resolve()), *args.source_artifact]
    )
    log_artifacts = existing_artifacts([str(log_path), *args.log_artifact])

    payload = {
        "schema_version": 1,
        "phase": "phase10",
        "suite": spec.suite,
        "environment": args.environment,
        "evidence_mode": "measured",
        "captured_at_unix": int(time.time()),
        "git_commit": current_git_commit(),
        "status": args.status,
        "participants": participants,
        "network_context": network_context,
        "checks": checks,
        "source_artifacts": source_artifacts,
        "log_artifacts": log_artifacts,
        "implementation_state": args.implementation_state,
    }
    if args.status == "fail":
        payload["failure_summary"] = args.failure_summary or f"{spec.title} is not implemented yet"

    problems = validate_report_payload(report_path, payload)
    if problems:
        raise SystemExit("\n".join(problems))

    report_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
