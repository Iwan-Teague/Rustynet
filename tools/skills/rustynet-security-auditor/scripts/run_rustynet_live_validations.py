#!/usr/bin/env python3
"""Run selected Rustynet live-lab validators and consolidate their results deterministically."""

from __future__ import annotations

import argparse
import os
import stat
import subprocess
import sys
import tempfile
import shutil
from datetime import datetime, timezone
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
        "--ssh-known-hosts-file",
        default="",
        help="Pinned SSH known_hosts file. Defaults to ~/.ssh/known_hosts if it exists.",
    )
    parser.add_argument(
        "--validations",
        default="all",
        help="Comma-separated validation keys or 'all'. Supported: " + ", ".join(sorted(LIVE_VALIDATIONS)),
    )
    parser.add_argument("--report-dir", default="", help="Directory to place reports in. Defaults to a timestamped directory under <repo-root>/artifacts/phase10/live_skill_runs/.")
    parser.add_argument("--findings-output", default="", help="Optional findings markdown path.")
    parser.add_argument("--schema-output", default="", help="Optional schema validation markdown path.")
    parser.add_argument("--promotion-output", default="", help="Optional comparative coverage promotion markdown path.")
    parser.add_argument("--summary-output", default="", help="Optional run summary markdown path.")
    parser.add_argument("--dry-run", action="store_true", help="Print and record the commands without executing the live validators.")
    parser.add_argument(
        "--skip-ssh-reachability-preflight",
        action="store_true",
        help="Skip active SSH login probes. Intended only for local dry-run validation of the runner itself.",
    )
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
    parser.add_argument("--connect-timeout-secs", type=int, default=15, help="SSH preflight connect timeout in seconds.")
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


def resolve_known_hosts_path(raw: str) -> Path:
    if raw:
        return Path(raw).expanduser().resolve()
    default_path = Path.home() / ".ssh" / "known_hosts"
    if default_path.is_file():
        return default_path.resolve()
    raise SystemExit("a pinned SSH known_hosts file is required; pass --ssh-known-hosts-file")


def require_known_hosts_file(path: Path) -> None:
    if not path.is_file():
        raise SystemExit(f"missing pinned SSH known_hosts file: {path}")
    if path.is_symlink():
        raise SystemExit(f"pinned SSH known_hosts file must not be a symlink: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o022:
        raise SystemExit(f"pinned SSH known_hosts file must not be group/world writable: {path} ({mode:03o})")


def target_host(target: str) -> str:
    return target.split("@", 1)[1] if "@" in target else target


def preflight_pinned_host_entries(targets: list[str], known_hosts_path: Path) -> None:
    missing_hosts: list[str] = []
    for target in targets:
        host = target_host(target)
        proc = subprocess.run(
            ["ssh-keygen", "-F", host, "-f", str(known_hosts_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            missing_hosts.append(host)
    if missing_hosts:
        raise SystemExit(
            "pinned known_hosts file lacks host keys for: "
            + ", ".join(sorted(dict.fromkeys(missing_hosts)))
            + f" ({known_hosts_path})"
        )


def ssh_reachability_check(
    target: str,
    password_file: Path,
    known_hosts_path: Path,
    connect_timeout_secs: int,
) -> None:
    script = f"""#!/usr/bin/expect -f
if {{$argc != 4}} {{
  puts stderr "usage: ssh-preflight.expect <password-file> <known-hosts-file> <target> <timeout>"
  exit 2
}}
set password_file [lindex $argv 0]
set known_hosts [lindex $argv 1]
set target [lindex $argv 2]
set timeout [lindex $argv 3]
set fh [open $password_file r]
gets $fh password
close $fh
log_user 0
match_max 2000000
spawn ssh -o LogLevel=ERROR -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$known_hosts -o ConnectTimeout=$timeout -- $target true
expect {{
  -re {{(?i)password:}} {{ send -- "$password\\r"; exp_continue }}
  eof {{
    catch wait result
    exit [lindex $result 3]
  }}
}}
"""
    with tempfile.TemporaryDirectory(prefix="rustynet-skill-preflight.") as temp_dir:
        script_path = Path(temp_dir) / "ssh_preflight.expect"
        script_path.write_text(script, encoding="utf-8")
        script_path.chmod(0o700)
        proc = subprocess.run(
            [
                "expect",
                str(script_path),
                str(password_file),
                str(known_hosts_path),
                target,
                str(connect_timeout_secs),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        if detail:
            raise SystemExit(f"SSH preflight failed for {target}: {detail}")
        raise SystemExit(f"SSH preflight failed for {target}")


def ssh_capture_command(
    target: str,
    password_file: Path,
    known_hosts_path: Path,
    connect_timeout_secs: int,
    remote_command: str,
) -> subprocess.CompletedProcess[str]:
    script = """#!/usr/bin/expect -f
if {$argc != 5} {
  puts stderr "usage: ssh-capture.expect <password-file> <known-hosts-file> <target> <timeout> <command>"
  exit 2
}
set password_file [lindex $argv 0]
set known_hosts [lindex $argv 1]
set target [lindex $argv 2]
set timeout [lindex $argv 3]
set remote_command [lindex $argv 4]
set fh [open $password_file r]
gets $fh password
close $fh
log_user 0
match_max 2000000
spawn ssh -o LogLevel=ERROR -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$known_hosts -o ConnectTimeout=$timeout -- $target sh -lc $remote_command
expect {
  -re {(?i)password:} { send -- "$password\\r"; exp_continue }
  eof {
    catch wait result
    exit [lindex $result 3]
  }
}
"""
    with tempfile.TemporaryDirectory(prefix="rustynet-skill-preflight.") as temp_dir:
        script_path = Path(temp_dir) / "ssh_capture.expect"
        script_path.write_text(script, encoding="utf-8")
        script_path.chmod(0o700)
        return subprocess.run(
            [
                "expect",
                str(script_path),
                str(password_file),
                str(known_hosts_path),
                target,
                str(connect_timeout_secs),
                remote_command,
            ],
            capture_output=True,
            text=True,
            check=False,
        )


def remote_runtime_requirements_check(
    target: str,
    password_file: Path,
    known_hosts_path: Path,
    connect_timeout_secs: int,
) -> None:
    remote_command = r"""
missing=""
for cmd in rustynet rustynetd wg systemctl ss python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing_binary:$cmd"
    missing=1
  fi
done
if command -v systemctl >/dev/null 2>&1; then
  load_state=$(systemctl show -p LoadState --value rustynetd.service 2>/dev/null || true)
  if [ "$load_state" = "loaded" ]; then
    echo "service_present:rustynetd.service"
  else
    echo "missing_service:rustynetd.service"
    missing=1
  fi
  if systemctl is-active --quiet rustynetd.service; then
    echo "service_active:rustynetd.service"
  else
    echo "inactive_service:rustynetd.service"
    missing=1
  fi
fi
if [ -n "$missing" ]; then
  exit 1
fi
"""
    proc = ssh_capture_command(
        target,
        password_file,
        known_hosts_path,
        connect_timeout_secs,
        remote_command,
    )
    if proc.returncode == 0:
        return
    detail = (proc.stdout or "").strip()
    if not detail:
        detail = (proc.stderr or "").strip()
    if not detail:
        detail = "missing remote prerequisite"
    raise SystemExit(f"remote prerequisite preflight failed for {target}: {detail}")


def selected_targets(args: argparse.Namespace) -> list[str]:
    ordered = [
        args.exit_host,
        args.client_host,
        args.entry_host,
        args.aux_host,
        args.extra_host,
        args.probe_host,
    ]
    deduped: list[str] = []
    seen: set[str] = set()
    for target in ordered:
        if target and target not in seen:
            seen.add(target)
            deduped.append(target)
    return deduped


def run_preflight(args: argparse.Namespace, specs: list[ValidationSpec]) -> Path:
    del specs  # kept for future per-spec expansion
    for cmd in ("ssh", "expect", "ssh-keygen"):
        if not shutil.which(cmd):
            raise SystemExit(f"missing required command for live-lab preflight: {cmd}")
    known_hosts_path = resolve_known_hosts_path(args.ssh_known_hosts_file)
    require_known_hosts_file(known_hosts_path)
    targets = selected_targets(args)
    preflight_pinned_host_entries(targets, known_hosts_path)
    if args.skip_ssh_reachability_preflight:
        return known_hosts_path
    password_file = Path(args.ssh_password_file).resolve()
    for target in targets:
        ssh_reachability_check(target, password_file, known_hosts_path, args.connect_timeout_secs)
    for target in targets:
        remote_runtime_requirements_check(
            target,
            password_file,
            known_hosts_path,
            args.connect_timeout_secs,
        )
    return known_hosts_path


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


def run_validation(command: list[str], cwd: Path, env: dict[str, str]) -> dict[str, object]:
    proc = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, check=False)
    return {
        "command": command,
        "rc": proc.returncode,
        "stdout": (proc.stdout or "").strip(),
        "stderr": (proc.stderr or "").strip(),
    }


def render_summary(
    results: list[dict[str, object]],
    known_hosts_path: Path,
    schema_rc: int,
    findings_rc: int,
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
            f"- Pinned SSH known_hosts file: `{known_hosts_path}`",
            f"- Findings report: `{findings_output}`",
            f"- Findings generation exit code: `{findings_rc}`",
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
    if args.skip_ssh_reachability_preflight and not args.dry_run:
        raise SystemExit("--skip-ssh-reachability-preflight is only allowed with --dry-run")
    repo_root = Path(args.repo_root).resolve()
    if args.report_dir:
        report_dir = Path(args.report_dir).resolve()
    else:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        report_dir = repo_root / "artifacts" / "phase10" / "live_skill_runs" / timestamp
    report_dir.mkdir(parents=True, exist_ok=True)
    findings_output = Path(args.findings_output).resolve() if args.findings_output else report_dir / "live_lab_findings.md"
    schema_output = Path(args.schema_output).resolve() if args.schema_output else report_dir / "live_lab_schema_validation.md"
    promotion_output = Path(args.promotion_output).resolve() if args.promotion_output else report_dir / "live_lab_coverage_promotion.md"
    summary_output = Path(args.summary_output).resolve() if args.summary_output else report_dir / "live_lab_validation_summary.md"

    specs = selected_specs(args.validations)
    require_spec_args(specs, args)
    known_hosts_path = run_preflight(args, specs)
    child_env = os.environ.copy()
    child_env["LIVE_LAB_PINNED_KNOWN_HOSTS_FILE"] = str(known_hosts_path)

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
            result = run_validation(command, repo_root, child_env)
        result["validation_key"] = spec.key
        result["report_path"] = str(report_path)
        results.append(result)
        if report_path.exists():
            report_paths.append(report_path)

    script_dir = Path(__file__).resolve().parent
    if args.dry_run:
        findings_output.write_text("# Dry Run\n\nNo findings were generated because the runner was executed with `--dry-run`.\n", encoding="utf-8")
        schema_output.write_text("# Dry Run\n\nNo schema validation was performed because the runner was executed with `--dry-run`.\n", encoding="utf-8")
        promotion_output.write_text("# Dry Run\n\nNo coverage promotion evaluation was performed because the runner was executed with `--dry-run`.\n", encoding="utf-8")
        summary_output.write_text(
            render_summary(results, known_hosts_path, 0, 0, 0, findings_output, schema_output, promotion_output),
            encoding="utf-8",
        )
        return 0

    if not report_paths:
        summary_output.write_text(
            render_summary(results, known_hosts_path, 1, 1, 1, findings_output, schema_output, promotion_output),
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
    findings_proc = subprocess.run(
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
            known_hosts_path,
            schema_proc.returncode,
            findings_proc.returncode,
            promotion_proc.returncode,
            findings_output,
            schema_output,
            promotion_output,
        ),
        encoding="utf-8",
    )

    validator_failures = any(int(result["rc"]) != 0 for result in results)
    return 1 if validator_failures or schema_proc.returncode != 0 or findings_proc.returncode != 0 or promotion_proc.returncode != 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
