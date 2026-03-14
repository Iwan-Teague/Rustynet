#!/usr/bin/env python3
"""Validate Rustynet live-lab JSON report schema against the shared validation catalog."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from live_lab_catalog import MODE_INDEX


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate Rustynet live-lab JSON reports against the shared schema catalog."
    )
    parser.add_argument("--reports", default="", help="Comma-separated report paths.")
    parser.add_argument("--report-dir", default="", help="Optional directory to scan recursively for *.json reports.")
    parser.add_argument("--output", default="", help="Optional markdown summary path.")
    return parser.parse_args()


def collect_report_paths(reports_raw: str, report_dir_raw: str) -> list[Path]:
    paths: list[Path] = []
    for item in [part.strip() for part in reports_raw.split(",") if part.strip()]:
        paths.append(Path(item).resolve())
    if report_dir_raw:
        paths.extend(sorted(Path(report_dir_raw).resolve().rglob("*.json")))
    deduped: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        if path not in seen:
            seen.add(path)
            deduped.append(path)
    if not deduped:
        raise SystemExit("no report files supplied")
    return deduped


def load_payload(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit(f"report must be a JSON object: {path}")
    return payload


def validate_payload(path: Path, payload: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    mode = payload.get("mode")
    if not isinstance(mode, str):
        return [f"{path}: missing or invalid 'mode' field"]
    spec = MODE_INDEX.get(mode)
    if spec is None:
        return [f"{path}: unknown report mode '{mode}'"]
    for field in spec.required_report_fields:
        if field not in payload:
            problems.append(f"missing required field '{field}'")
    if payload.get("evidence_mode") != "measured":
        problems.append("field 'evidence_mode' must equal 'measured'")
    checks = payload.get("checks")
    if not isinstance(checks, dict):
        problems.append("field 'checks' must be an object")
        return [f"{path}: {problem}" for problem in problems]
    for check_name in spec.required_check_keys:
        if check_name not in checks:
            problems.append(f"missing required check '{check_name}'")
            continue
        if checks[check_name] not in {"pass", "fail", "skip", "skipped"}:
            problems.append(
                f"check '{check_name}' must be one of pass/fail/skip/skipped, got {checks[check_name]!r}"
            )
    if not isinstance(payload.get("captured_at_unix"), int):
        problems.append("field 'captured_at_unix' must be an integer")
    if payload.get("status") not in {"pass", "fail"}:
        problems.append("field 'status' must be 'pass' or 'fail'")
    return [f"{path}: {problem}" for problem in problems]


def render_markdown(report_paths: list[Path], errors: list[str]) -> str:
    lines = [
        "# Rustynet Live-Lab Report Validation",
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
        lines.extend(["## Result", "", "All supplied reports matched the expected shared schema.", ""])
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    report_paths = collect_report_paths(args.reports, args.report_dir)
    errors: list[str] = []
    for path in report_paths:
        errors.extend(validate_payload(path, load_payload(path)))
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(render_markdown(report_paths, errors), encoding="utf-8")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
