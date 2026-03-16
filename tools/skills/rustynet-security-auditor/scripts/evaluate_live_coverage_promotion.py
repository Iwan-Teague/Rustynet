#!/usr/bin/env python3
"""Evaluate whether live-lab evidence is strong enough to promote partial comparative coverage."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from live_lab_catalog import LIVE_VALIDATIONS, ValidationSpec
from validate_live_lab_reports import load_payload, validate_payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate whether Rustynet live-lab evidence is sufficient to promote comparative exploit coverage."
    )
    parser.add_argument("--reports", default="", help="Comma-separated report paths.")
    parser.add_argument("--report-dir", default="", help="Optional directory to scan recursively for *.json reports.")
    parser.add_argument(
        "--targets",
        default="all",
        help="Comma-separated validation keys or 'all'. Supported: " + ", ".join(sorted(LIVE_VALIDATIONS)),
    )
    parser.add_argument("--output", required=True, help="Output markdown path.")
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


def selected_specs(raw: str) -> list[ValidationSpec]:
    if raw.strip().lower() == "all":
        return [LIVE_VALIDATIONS[key] for key in sorted(LIVE_VALIDATIONS)]
    keys = [item.strip() for item in raw.split(",") if item.strip()]
    if not keys:
        raise SystemExit("no targets supplied")
    unknown = [key for key in keys if key not in LIVE_VALIDATIONS]
    if unknown:
        raise SystemExit("unknown targets: " + ", ".join(unknown))
    return [LIVE_VALIDATIONS[key] for key in keys]


def load_reports(paths: list[Path]) -> dict[str, dict[str, Any]]:
    loaded: dict[str, dict[str, Any]] = {}
    for path in paths:
        payload = load_payload(path)
        mode = payload.get("mode")
        if isinstance(mode, str):
            loaded[mode] = {"path": path, "payload": payload}
    return loaded


def evaluate_spec(spec: ValidationSpec, loaded: dict[str, dict[str, Any]]) -> dict[str, Any]:
    record = loaded.get(spec.mode)
    if record is None:
        return {
            "eligible": False,
            "reason": "required live report missing",
            "report_path": "[missing]",
        }
    payload = record["payload"]
    schema_errors = validate_payload(record["path"], payload)
    if schema_errors:
        return {
            "eligible": False,
            "reason": "report schema validation failed",
            "report_path": str(record["path"]),
        }
    checks = payload.get("checks", {})
    if payload.get("status") != "pass":
        return {
            "eligible": False,
            "reason": "report status is not pass",
            "report_path": str(record["path"]),
        }
    if not isinstance(checks, dict):
        return {
            "eligible": False,
            "reason": "report checks object is missing or invalid",
            "report_path": str(record["path"]),
        }
    failing = [name for name in spec.required_check_keys if checks.get(name) != "pass"]
    if failing:
        return {
            "eligible": False,
            "reason": "required checks did not all pass: " + ", ".join(failing),
            "report_path": str(record["path"]),
        }
    return {
        "eligible": True,
        "reason": "all required checks passed",
        "report_path": str(record["path"]),
    }


def render_markdown(results: list[dict[str, Any]]) -> str:
    lines = [
        "# Rustynet Live Coverage Promotion Gate",
        "",
        "| Validation | Comparative Targets | Eligible | Reason | Report |",
        "| --- | --- | --- | --- | --- |",
    ]
    for result in results:
        lines.append(
            f"| {result['validation']} | {result['targets']} | {str(result['eligible']).lower()} | {result['reason']} | `{result['report_path']}` |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    report_paths = collect_report_paths(args.reports, args.report_dir)
    specs = selected_specs(args.targets)
    loaded = load_reports(report_paths)
    results: list[dict[str, Any]] = []
    failed = False
    for spec in specs:
        evaluation = evaluate_spec(spec, loaded)
        failed = failed or not evaluation["eligible"]
        results.append(
            {
                "validation": spec.key,
                "targets": ", ".join(spec.coverage_targets),
                **evaluation,
            }
        )
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_markdown(results), encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
