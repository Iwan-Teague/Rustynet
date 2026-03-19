#!/usr/bin/env python3
"""Validate cross-network remote-exit NAT profile matrix coverage."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from cross_network_remote_exit_schema import REPORT_SPECS, validate_report_payload


@dataclass(frozen=True)
class ReportRecord:
    path: Path
    suite: str
    nat_profile: str
    impairment_profile: str
    status: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate NAT profile matrix coverage for cross-network remote-exit reports."
    )
    parser.add_argument(
        "--artifact-dir",
        default="",
        help="Directory containing cross-network remote-exit reports (defaults to artifacts/phase10).",
    )
    parser.add_argument(
        "--reports",
        default="",
        help="Optional comma-separated explicit report paths. If set, discovery from --artifact-dir is skipped.",
    )
    parser.add_argument(
        "--required-nat-profiles",
        default="baseline_lan",
        help="Comma-separated NAT profiles required for every cross-network suite.",
    )
    parser.add_argument(
        "--max-evidence-age-seconds",
        type=int,
        default=2678400,
        help="Maximum allowed report age in seconds.",
    )
    parser.add_argument(
        "--expected-git-commit",
        default="",
        help="Optional expected git commit that every report must match.",
    )
    parser.add_argument(
        "--require-pass-status",
        action="store_true",
        help="Require all suite/profile matrix reports to have status=pass.",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Optional markdown output path.",
    )
    return parser.parse_args()


def parse_csv(raw_value: str) -> list[str]:
    values: list[str] = []
    for value in [part.strip() for part in raw_value.split(",") if part.strip()]:
        if value not in values:
            values.append(value)
    return values


def collect_paths(reports_raw: str, artifact_dir_raw: str) -> list[Path]:
    if reports_raw.strip():
        return [Path(value).resolve() for value in parse_csv(reports_raw)]

    artifact_dir = (
        Path(artifact_dir_raw).resolve()
        if artifact_dir_raw
        else Path.cwd() / "artifacts" / "phase10"
    )
    if not artifact_dir.is_dir():
        return []
    return sorted(path.resolve() for path in artifact_dir.glob("*.json"))


def discover_records(
    report_paths: list[Path],
    *,
    max_evidence_age_seconds: int,
    expected_git_commit: str,
    require_pass_status: bool,
) -> tuple[list[ReportRecord], list[str]]:
    known_suites = {spec.suite for spec in REPORT_SPECS}
    errors: list[str] = []
    records: list[ReportRecord] = []
    expected_commit = expected_git_commit.strip()

    for path in report_paths:
        if not path.is_file():
            errors.append(f"{path}: missing report file")
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{path}: invalid JSON ({exc})")
            continue
        if not isinstance(payload, dict):
            errors.append(f"{path}: report must be a JSON object")
            continue
        suite = payload.get("suite")
        if suite not in known_suites:
            continue
        errors.extend(
            validate_report_payload(
                path,
                payload,
                max_evidence_age_seconds=max_evidence_age_seconds,
            )
        )
        if expected_commit and payload.get("git_commit") != expected_commit:
            errors.append(
                f"{path}: git_commit {payload.get('git_commit')!r} does not match expected {expected_commit!r}"
            )
        if require_pass_status and payload.get("status") != "pass":
            errors.append(f"{path}: status must be 'pass' for matrix validation")

        network_context = payload.get("network_context", {})
        if not isinstance(network_context, dict):
            errors.append(f"{path}: network_context must be an object")
            continue
        nat_profile = str(network_context.get("nat_profile", "")).strip()
        impairment_profile = str(network_context.get("impairment_profile", "")).strip()
        if not nat_profile:
            errors.append(f"{path}: network_context.nat_profile must be non-empty")
            continue
        if not impairment_profile:
            errors.append(f"{path}: network_context.impairment_profile must be non-empty")
            continue
        records.append(
            ReportRecord(
                path=path,
                suite=str(suite),
                nat_profile=nat_profile,
                impairment_profile=impairment_profile,
                status=str(payload.get("status", "")),
            )
        )

    return records, errors


def validate_matrix(records: list[ReportRecord], required_nat_profiles: list[str]) -> list[str]:
    errors: list[str] = []
    if not required_nat_profiles:
        errors.append("required_nat_profiles must not be empty")
        return errors

    by_suite_nat: dict[tuple[str, str], list[ReportRecord]] = {}
    for record in records:
        by_suite_nat.setdefault((record.suite, record.nat_profile), []).append(record)

    for spec in REPORT_SPECS:
        for profile in required_nat_profiles:
            matches = by_suite_nat.get((spec.suite, profile), [])
            if not matches:
                errors.append(
                    f"missing matrix evidence: suite={spec.suite} nat_profile={profile}"
                )
    return errors


def render_markdown(
    report_paths: list[Path],
    required_nat_profiles: list[str],
    records: list[ReportRecord],
    errors: list[str],
) -> str:
    lines = [
        "# Cross-Network NAT Matrix Validation",
        "",
        "## Required NAT Profiles",
        "",
    ]
    for profile in required_nat_profiles:
        lines.append(f"- `{profile}`")

    lines.extend(["", "## Reports Considered", ""])
    if report_paths:
        for path in report_paths:
            lines.append(f"- `{path}`")
    else:
        lines.append("- none")

    lines.extend(["", "## Matrix Records", ""])
    if records:
        for record in sorted(records, key=lambda item: (item.suite, item.nat_profile, str(item.path))):
            lines.append(
                f"- suite=`{record.suite}` nat_profile=`{record.nat_profile}` impairment_profile=`{record.impairment_profile}` status=`{record.status}` path=`{record.path}`"
            )
    else:
        lines.append("- none")

    lines.extend(["", "## Result", ""])
    if errors:
        for error in errors:
            lines.append(f"- {error}")
    else:
        lines.append("Matrix validation passed.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    report_paths = collect_paths(args.reports, args.artifact_dir)
    required_nat_profiles = parse_csv(args.required_nat_profiles)

    records, errors = discover_records(
        report_paths,
        max_evidence_age_seconds=args.max_evidence_age_seconds,
        expected_git_commit=args.expected_git_commit,
        require_pass_status=args.require_pass_status,
    )
    errors.extend(validate_matrix(records, required_nat_profiles))

    if args.output:
        output_path = Path(args.output).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            render_markdown(report_paths, required_nat_profiles, records, errors),
            encoding="utf-8",
        )

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
