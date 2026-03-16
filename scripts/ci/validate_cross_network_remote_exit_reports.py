#!/usr/bin/env python3
"""Validate Phase 10 cross-network remote-exit measured report schemas."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cross_network_remote_exit_schema import (
    REPORT_SPECS,
    validate_report_payload,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate Phase 10 cross-network remote-exit measured reports."
    )
    parser.add_argument(
        "--reports",
        default="",
        help="Comma-separated report paths. Defaults to the canonical artifact set under --artifact-dir.",
    )
    parser.add_argument(
        "--artifact-dir",
        default="",
        help="Artifact directory containing canonical cross-network remote-exit reports.",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Optional markdown summary path.",
    )
    parser.add_argument(
        "--max-evidence-age-seconds",
        type=int,
        default=2678400,
        help="Maximum allowed evidence age in seconds.",
    )
    parser.add_argument(
        "--expected-git-commit",
        default="",
        help="Optional commit that every report must match exactly.",
    )
    parser.add_argument(
        "--require-pass-status",
        action="store_true",
        help="Require every supplied report to set status=pass.",
    )
    return parser.parse_args()


def collect_report_paths(reports_raw: str, artifact_dir_raw: str) -> list[Path]:
    paths: list[Path] = []
    if reports_raw.strip():
        for item in [part.strip() for part in reports_raw.split(",") if part.strip()]:
            paths.append(Path(item).resolve())
    else:
        artifact_dir = (
            Path(artifact_dir_raw).resolve()
            if artifact_dir_raw
            else Path.cwd() / "artifacts" / "phase10"
        )
        for spec in REPORT_SPECS:
            paths.append((artifact_dir / spec.filename).resolve())
    return paths


def load_payload(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise SystemExit(f"{path}: report must be a JSON object")
    return payload


def render_markdown(report_paths: list[Path], errors: list[str]) -> str:
    lines = [
        "# Cross-Network Remote Exit Report Validation",
        "",
        "## Reports",
        "",
    ]
    for path in report_paths:
        lines.append(f"- `{path}`")
    lines.append("")
    if errors:
        lines.extend(["## Errors", ""])
        for error in errors:
            lines.append(f"- {error}")
        lines.append("")
    else:
        lines.extend(
            [
                "## Result",
                "",
                "All supplied cross-network remote-exit reports matched the required schema.",
                "",
            ]
        )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    report_paths = collect_report_paths(args.reports, args.artifact_dir)
    errors: list[str] = []
    expected_git_commit = args.expected_git_commit.strip()
    for path in report_paths:
        if not path.is_file():
            errors.append(f"{path}: missing report file")
            continue
        payload = load_payload(path)
        errors.extend(
            validate_report_payload(
                path,
                payload,
                max_evidence_age_seconds=args.max_evidence_age_seconds,
            )
        )
        if expected_git_commit and payload.get("git_commit") != expected_git_commit:
            errors.append(
                f"{path}: git_commit {payload.get('git_commit')!r} does not match expected {expected_git_commit!r}"
            )
        if args.require_pass_status and payload.get("status") != "pass":
            errors.append(f"{path}: status must be 'pass' for gate usage")

    if args.output:
        output_path = Path(args.output).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(render_markdown(report_paths, errors), encoding="utf-8")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
