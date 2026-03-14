#!/usr/bin/env python3
"""Run selected Rustynet live-lab validators and consolidate their results deterministically."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from live_lab_catalog import LIVE_VALIDATIONS, ValidationSpec

ARG_TO_FLAG = {
    "exit_host": "--exit-host",
    "client_host": "--client-host",
    "entry_host": "--entry-host",
    "aux_host": "--aux-host",
    "extra_host": "--extra-host",
    "probe_host": "--probe-host",
    "dns_bind_addr": "--dns-bind-addr",
    "ssh_allow_cidrs": "--ssh-allow-cidrs",
    "probe_port": "--probe-port",
    "rogue_endpoint_ip": "--rogue-endpoint-ip",
    "socket_path": "--socket-path",
    "assignment_path": "--assignment-path",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run selected Rustynet live-lab validators and generate consolidated findings."
    )
    parser.add_argument("--repo-root", required=True, help="Rustynet repository root.")
    parser.add_argument("--ssh-password-file", required=True, help="SSH password file for the live lab.")
    parser.add_argument("--sudo-password-file", required=True, help="sudo password file for the live lab.")
    parser.add_argument(
        "--validations",
        default="all",
        help="Comma-separated validation keys or 'all'. Supported: " + ", ".join(sorted(LIVE_VALIDATIONS)),
    )
    parser.add_argument("--report-dir", default="", help="Directory to place reports in. Defaults to <repo-root>/artifacts/phase10.")
    parser.add_argument("--findings-output", default="", help="Optional findings markdown path.")
    parser.add_argument("--schema-output", default="", help="Optional schema validation markdown path.")
    parser.add_argument("--promotion-output", default="", help="Optional comparative coverage promotion markdown path.")
    parser.add_argument("--summary-output", default="", help="Optional run summary markdown path.")
    parser.add_argument("--dry-run", action="store_true", help="Print and record the commands without executing the live validators.")
    parser.add_argument("--exit-host", default="", help="Exit host user@host.")
    parser.add_argument("--client-host", default="", help="Client host user@host.")
    parser.add_argument("--entry-host", default="", help="Entry host user@host.")
    parser.add_argument("--aux-host", default="", help="Aux host user@host.")
    parser.add_argument("--extra-host", default="", help="Extra host user@host.")
    parser.add_argument("--probe-host", default="", help="Probe host user@host.")
    parser.add_argument("--dns-bind-addr", default="", help="DNS bind address override.")
    parser.add_argument("--ssh-allow-cidrs", default="", help="Management CIDRs for bypass validation.")
    parser.add_argument("--probe-port", default="", help="Probe port for bypass validation.")
    parser.add_argument("--rogue-endpoint-ip", default="", help="Rogue endpoint IP for endpoint hijack validation.")
    parser.add_argument("--socket-path", default="", help="Daemon socket path override.")
    parser.add_argument("--assignment-path", default="", help="Assignment bundle path override.")
    return parser.parse_args()


def selected_specs(raw: str) -> list[ValidationSpec]:
    if raw.strip().lower() == "all":
        return [LIVE_VALIDATIONS[key] for key in sorted(LIVE_VALIDATIONS)]
    keys = [item.strip() for item in raw.split(",") if item.strip()]
    if not keys:
        raise SystemExit("no validation keys supplied")
    unknown = [key for key in keys if key not in LIVE_VALIDATIONS]
    if unknown:
        raise SystemExit("unknown validation keys: " + ", ".join(unknown))
    return [LIVE_VALIDATIONS[key] for key in keys]


def require_spec_args(specs: list[ValidationSpec], args: argparse.Namespace) -> None:
    missing: list[str] = []
    for spec in specs:
        for arg_name in spec.required_args:
            if not getattr(args, arg_name):
                missing.append(f"{spec.key}:{arg_name}")
    if missing:
        raise SystemExit("missing required arguments for live validation run: " + ", ".join(missing))


def build_command(spec: ValidationSpec, args: argparse.Namespace, repo_root: Path, report_dir: Path) -> tuple[list[str], Path]:
    script_path = repo_root / spec.script_path
    if not script_path.is_file():
        raise SystemExit(f"validation script missing: {script_path}")
    report_path = report_dir / spec.default_report_name
    log_path = report_dir / spec.default_report_name.replace(".json", ".log")
    command = [
        str(script_path),
        "--ssh-password-file",
        args.ssh_password_file,
        "--sudo-password-file",
        args.sudo_password_file,
        "--report-path",
        str(report_path),
        "--log-path",
        str(log_path),
    ]
    for arg_name in spec.supported_args:
        value = getattr(args, arg_name)
        if value:
            command.extend([ARG_TO_FLAG[arg_name], value])
    return command, report_path


def run_validation(command: list[str], cwd: Path) -> dict[str, object]:
    proc = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    return {
        "command": command,
        "rc": proc.returncode,
        "stdout": (proc.stdout or "").strip(),
        "stderr": (proc.stderr or "").strip(),
    }


def render_summary(
    results: list[dict[str, object]],
    schema_rc: int,
    promotion_rc: int,
    findings_output: Path,
    schema_output: Path,
    promotion_output: Path,
) -> str:
    lines = [
        "# Rustynet Live-Lab Validation Run",
        "",
        "## Validator Commands",
        "",
        "| Validation | Exit Code | Report Path |",
        "| --- | --- | --- |",
    ]
    for result in results:
        lines.append(
            f"| {result['validation_key']} | {result['rc']} | `{result['report_path']}` |"
        )
    lines.extend(
        [
            "",
            "## Consolidated Outputs",
            "",
            f"- Findings report: `{findings_output}`",
            f"- Schema validation report: `{schema_output}`",
            f"- Schema validation exit code: `{schema_rc}`",
            f"- Coverage promotion report: `{promotion_output}`",
            f"- Coverage promotion exit code: `{promotion_rc}`",
            "",
        ]
    )
    for result in results:
        lines.extend(
            [
                f"### {result['validation_key']}",
                "",
                f"- Command: `{' '.join(result['command'])}`",
                f"- Exit code: `{result['rc']}`",
                "- stderr:",
                "```text",
                result["stderr"] or "[no stderr]",
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    report_dir = Path(args.report_dir).resolve() if args.report_dir else repo_root / "artifacts" / "phase10"
    report_dir.mkdir(parents=True, exist_ok=True)
    findings_output = Path(args.findings_output).resolve() if args.findings_output else report_dir / "live_lab_findings.md"
    schema_output = Path(args.schema_output).resolve() if args.schema_output else report_dir / "live_lab_schema_validation.md"
    promotion_output = Path(args.promotion_output).resolve() if args.promotion_output else report_dir / "live_lab_coverage_promotion.md"
    summary_output = Path(args.summary_output).resolve() if args.summary_output else report_dir / "live_lab_validation_summary.md"

    specs = selected_specs(args.validations)
    require_spec_args(specs, args)

    results: list[dict[str, object]] = []
    report_paths: list[Path] = []
    for spec in specs:
        command, report_path = build_command(spec, args, repo_root, report_dir)
        if args.dry_run:
            result = {
                "command": command,
                "rc": 0,
                "stdout": "",
                "stderr": "",
            }
        else:
            result = run_validation(command, repo_root)
        result["validation_key"] = spec.key
        result["report_path"] = str(report_path)
        results.append(result)
        if report_path.exists():
            report_paths.append(report_path)

    script_dir = Path(__file__).resolve().parent
    if args.dry_run:
        summary_output.write_text(
            render_summary(results, 0, 0, findings_output, schema_output, promotion_output),
            encoding="utf-8",
        )
        return 0

    if not report_paths:
        summary_output.write_text(
            render_summary(results, 1, 1, findings_output, schema_output, promotion_output),
            encoding="utf-8",
        )
        return 1

    schema_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "validate_live_lab_reports.py"),
            "--reports",
            ",".join(str(path) for path in report_paths),
            "--output",
            str(schema_output),
        ],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    subprocess.run(
        [
            sys.executable,
            str(script_dir / "generate_live_lab_findings.py"),
            "--reports",
            ",".join(str(path) for path in report_paths),
            "--output",
            str(findings_output),
        ],
        cwd=repo_root,
        check=False,
    )
    promotion_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "evaluate_live_coverage_promotion.py"),
            "--reports",
            ",".join(str(path) for path in report_paths),
            "--targets",
            ",".join(spec.key for spec in specs),
            "--output",
            str(promotion_output),
        ],
        cwd=repo_root,
        check=False,
    )
    summary_output.write_text(
        render_summary(
            results,
            schema_proc.returncode,
            promotion_proc.returncode,
            findings_output,
            schema_output,
            promotion_output,
        ),
        encoding="utf-8",
    )

    validator_failures = any(int(result["rc"]) != 0 for result in results)
    return 1 if validator_failures or schema_proc.returncode != 0 or promotion_proc.returncode != 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
