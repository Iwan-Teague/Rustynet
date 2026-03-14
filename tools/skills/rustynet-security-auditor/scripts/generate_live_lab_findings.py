#!/usr/bin/env python3
"""Generate prioritized security findings from Rustynet live-lab JSON reports."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from live_lab_catalog import CheckMetadata, MODE_INDEX, ValidationSpec

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate prioritized security findings from Rustynet live-lab JSON reports."
    )
    parser.add_argument(
        "--reports",
        default="",
        help="Comma-separated report paths.",
    )
    parser.add_argument(
        "--report-dir",
        default="",
        help="Optional directory to scan recursively for *.json report files.",
    )
    parser.add_argument("--output", required=True, help="Output markdown path.")
    return parser.parse_args()


def collect_report_paths(reports_raw: str, report_dir_raw: str) -> list[Path]:
    paths: list[Path] = []
    for item in [part.strip() for part in reports_raw.split(",") if part.strip()]:
        paths.append(Path(item))
    if report_dir_raw:
        report_dir = Path(report_dir_raw)
        paths.extend(sorted(report_dir.rglob("*.json")))
    deduped: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            deduped.append(resolved)
    if not deduped:
        raise SystemExit("no report files supplied")
    return deduped


def load_report(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit(f"report must be a JSON object: {path}")
    return payload


def validate_report_schema(path: Path, payload: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    for key in ("mode", "status", "checks", "evidence_mode"):
        if key not in payload:
            problems.append(f"missing required field '{key}'")
    if "mode" in payload and not isinstance(payload["mode"], str):
        problems.append("field 'mode' must be a string")
    if "status" in payload and not isinstance(payload["status"], str):
        problems.append("field 'status' must be a string")
    if "checks" in payload and not isinstance(payload["checks"], dict):
        problems.append("field 'checks' must be an object")
    if "evidence_mode" in payload and payload.get("evidence_mode") != "measured":
        problems.append("field 'evidence_mode' must be 'measured'")
    if problems:
        return [f"{path}: {problem}" for problem in problems]
    return []


def stringify(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    return json.dumps(value, sort_keys=True)


def summarize_evidence(payload: dict[str, Any], limit: int = 600) -> str:
    evidence = payload.get("evidence", {})
    if not isinstance(evidence, dict) or not evidence:
        return "[no structured evidence present]"
    parts = []
    for key in sorted(evidence):
        rendered = stringify(evidence[key])
        if len(rendered) > 160:
            rendered = rendered[:160] + "..."
        parts.append(f"{key}={rendered}")
    summary = "; ".join(parts)
    if len(summary) > limit:
        summary = summary[:limit] + "..."
    return summary


def make_finding(
    severity: str,
    title: str,
    rationale: str,
    mode_metadata: ValidationSpec,
    report_path: Path,
    payload: dict[str, Any],
    check_name: str,
) -> dict[str, Any]:
    return {
        "severity": severity,
        "title": title,
        "exploit_family": mode_metadata.exploit_family,
        "mode_title": mode_metadata.title,
        "report_path": str(report_path),
        "check_name": check_name,
        "rationale": rationale,
        "affected_files": mode_metadata.affected_files,
        "evidence_summary": summarize_evidence(payload),
    }


def derive_findings(report_path: Path, payload: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    passes: list[dict[str, Any]] = []
    mode = payload.get("mode")
    status = payload.get("status")
    checks = payload.get("checks", {})
    mode_metadata = MODE_INDEX.get(mode)
    if mode_metadata is None:
        if status != "pass":
            findings.append(
                {
                    "severity": "high",
                    "title": f"Unknown report mode failed: {mode}",
                    "exploit_family": "unknown",
                    "mode_title": str(mode),
                    "report_path": str(report_path),
                    "check_name": "[mode]",
                    "rationale": "The live-lab report failed, but the skill does not yet know how to map this mode into enforcement points.",
                    "affected_files": tuple(),
                    "evidence_summary": summarize_evidence(payload),
                }
            )
        return findings, passes

    if not isinstance(checks, dict):
        findings.append(
            {
                "severity": "high",
                "title": f"{mode_metadata.title} report schema invalid",
                "exploit_family": mode_metadata.exploit_family,
                "mode_title": mode_metadata.title,
                "report_path": str(report_path),
                "check_name": "[schema]",
                "rationale": "The report did not contain a usable checks object, so the live result cannot be trusted.",
                "affected_files": mode_metadata.affected_files,
                "evidence_summary": summarize_evidence(payload),
            }
        )
        return findings, passes

    for check_name, value in checks.items():
        if value == "pass":
            passes.append(
                {
                    "mode_title": mode_metadata.title,
                    "check_name": check_name,
                    "report_path": str(report_path),
                }
            )
            continue
        if value in {"skip", "skipped"}:
            findings.append(
                make_finding(
                    "medium",
                    f"{mode_metadata.title} check skipped: {check_name}",
                    "A skipped adversarial check leaves the corresponding exploit class unvalidated on the live lab.",
                    mode_metadata,
                    report_path,
                    payload,
                    check_name,
                )
            )
            continue
        check_metadata = mode_metadata.check_metadata.get(
            check_name,
            CheckMetadata(
                severity="high",
                title=f"{mode_metadata.unknown_failure_title}: {check_name}",
                rationale="A live-lab check failed and needs manual review because the skill does not yet have a more specific mapping for it.",
            ),
        )
        findings.append(
            make_finding(
                check_metadata.severity,
                check_metadata.title,
                check_metadata.rationale,
                mode_metadata,
                report_path,
                payload,
                check_name,
            )
        )

    if status != "pass" and not findings:
        findings.append(
            make_finding(
                "high",
                mode_metadata.unknown_failure_title,
                "The report status failed even though no individual failed checks were extracted.",
                mode_metadata,
                report_path,
                payload,
                "[status]",
            )
        )
    return findings, passes


def render_markdown(
    findings: list[dict[str, Any]],
    passes: list[dict[str, Any]],
    schema_problems: list[str],
    analyzed_reports: list[Path],
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    ordered_findings = sorted(
        findings,
        key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], 99),
            item["mode_title"],
            item["title"],
        ),
    )
    lines = [
        "# Rustynet Live-Lab Security Findings",
        "",
        f"Generated: {now}",
        "",
        "## Summary",
        "",
        f"- Reports analyzed: {len(analyzed_reports)}",
        f"- Findings: {len(ordered_findings)}",
        f"- Passing checks recorded: {len(passes)}",
        f"- Schema problems: {len(schema_problems)}",
        "",
        "## Reports",
        "",
    ]
    for report in analyzed_reports:
        lines.append(f"- `{report}`")
    lines.append("")

    if ordered_findings:
        lines.extend(["## Findings", ""])
        for finding in ordered_findings:
            lines.extend(
                [
                    f"### [{finding['severity'].upper()}] {finding['title']}",
                    "",
                    f"- Exploit family: `{finding['exploit_family']}`",
                    f"- Validation mode: {finding['mode_title']}",
                    f"- Report: `{finding['report_path']}`",
                    f"- Failing check: `{finding['check_name']}`",
                    f"- Why it matters: {finding['rationale']}",
                    f"- Likely affected files: {', '.join('`' + path + '`' for path in finding['affected_files']) or '[unknown]'}",
                    f"- Evidence summary: {finding['evidence_summary']}",
                    "",
                ]
            )
    else:
        lines.extend(["## Findings", "", "No failing or skipped checks were found in the supplied reports.", ""])

    if schema_problems:
        lines.extend(["## Schema Problems", ""])
        for problem in schema_problems:
            lines.append(f"- {problem}")
        lines.append("")

    lines.extend(["## Passing Checks", ""])
    if passes:
        for passed in sorted(passes, key=lambda item: (item["mode_title"], item["check_name"])):
            lines.append(
                f"- {passed['mode_title']}: `{passed['check_name']}` in `{passed['report_path']}`"
            )
    else:
        lines.append("No passing checks were recorded.")
    lines.append("")

    lines.extend(
        [
            "## Next Actions",
            "",
            "1. Fix every `critical` finding before treating the corresponding exploit class as covered.",
            "2. Re-run the specific live validation report after each fix; do not rely on adjacent unit tests alone.",
            "3. If a report had schema problems, repair the reporting path before trusting any pass/fail outcome from that validator.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    report_paths = collect_report_paths(args.reports, args.report_dir)
    findings: list[dict[str, Any]] = []
    passes: list[dict[str, Any]] = []
    schema_problems: list[str] = []
    for report_path in report_paths:
        payload = load_report(report_path)
        schema_problems.extend(validate_report_schema(report_path, payload))
        report_findings, report_passes = derive_findings(report_path, payload)
        findings.extend(report_findings)
        passes.extend(report_passes)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        render_markdown(findings, passes, schema_problems, report_paths),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
