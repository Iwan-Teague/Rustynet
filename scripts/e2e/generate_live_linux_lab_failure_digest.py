#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path


STAGE_TEXT = {
    "preflight": {
        "pass": "local prerequisites are ready",
        "fail": "local prerequisite validation failed",
    },
    "prepare_source_archive": {
        "pass": "deploy source archive prepared successfully",
        "fail": "deploy source archive preparation failed",
    },
    "prime_remote_access": {
        "pass": "all targeted nodes accepted remote SSH and sudo priming",
        "fail": "remote SSH or sudo priming failed on one or more targeted nodes",
    },
    "cleanup_hosts": {
        "pass": "all targeted nodes cleaned prior RustyNet state successfully",
        "fail": "prior RustyNet state cleanup failed on one or more targeted nodes",
    },
    "bootstrap_hosts": {
        "pass": "all targeted nodes bootstrapped and compiled RustyNet successfully",
        "fail": "bootstrap or compile failed on one or more targeted nodes",
    },
    "collect_pubkeys": {
        "pass": "all targeted nodes exported WireGuard public keys successfully",
        "fail": "WireGuard public key collection failed on one or more targeted nodes",
    },
    "membership_setup": {
        "pass": "primary exit applied signed membership updates successfully",
        "fail": "signed membership setup failed on the primary exit",
    },
    "distribute_membership_state": {
        "pass": "membership state distributed to all targeted peer nodes successfully",
        "fail": "membership state distribution failed on one or more targeted peer nodes",
    },
    "issue_and_distribute_assignments": {
        "pass": "signed assignments were issued and distributed to all targeted nodes successfully",
        "fail": "assignment issuance or distribution failed on one or more targeted nodes",
    },
    "enforce_baseline_runtime": {
        "pass": "all targeted nodes enforced baseline runtime successfully",
        "fail": "baseline runtime enforcement failed on one or more targeted nodes",
    },
    "validate_baseline_runtime": {
        "pass": "all targeted nodes connected to the network correctly under baseline validation",
        "fail": "baseline network validation failed on one or more targeted nodes",
    },
    "live_role_switch_matrix": {
        "pass": "controlled role-switch validation passed",
        "fail": "controlled role-switch validation failed",
    },
    "live_exit_handoff": {
        "pass": "live exit handoff validation passed",
        "fail": "live exit handoff validation failed",
    },
    "live_two_hop": {
        "pass": "live two-hop validation passed",
        "fail": "live two-hop validation failed",
    },
    "live_lan_toggle": {
        "pass": "LAN toggle and blind-exit validation passed",
        "fail": "LAN toggle or blind-exit validation failed",
    },
    "fresh_install_os_matrix_report": {
        "pass": "commit-bound fresh install OS matrix evidence was generated successfully",
        "fail": "fresh install OS matrix evidence generation failed",
    },
    "local_full_gate_suite": {
        "pass": "local full gate suite passed",
        "fail": "local full gate suite failed",
    },
    "extended_soak": {
        "pass": "extended soak and reboot recovery validation passed",
        "fail": "extended soak or reboot recovery validation failed",
    },
}

PREFERRED_REASON_PATTERNS = [
    re.compile(r"error:", re.IGNORECASE),
    re.compile(r"\bfail(?:ed|ure)?\b", re.IGNORECASE),
    re.compile(r"timed?\s*out", re.IGNORECASE),
    re.compile(r"permission denied", re.IGNORECASE),
    re.compile(r"auth(?:entication)? .*fail", re.IGNORECASE),
    re.compile(r"missing", re.IGNORECASE),
    re.compile(r"invalid", re.IGNORECASE),
    re.compile(r"mismatch", re.IGNORECASE),
    re.compile(r"does not exist", re.IGNORECASE),
    re.compile(r"no such", re.IGNORECASE),
    re.compile(r"unreachable", re.IGNORECASE),
]

IGNORE_LINE_PATTERNS = [
    re.compile(r"^\[stage:[^\]]+\] (START|PASS|FAIL)\b"),
    re.compile(r"^\[parallel:[^\]]+\] "),
    re.compile(r"^----- "),
]

ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-9;]*[A-Za-z]")

REBOOT_CHECK_REASON_TEXT = {
    "exit_reboot_returns": "exit did not return on SSH after reboot",
    "exit_boot_id_changes": "exit reboot was not proven by a new boot_id",
    "post_exit_reboot_twohop": "two-hop validation failed after exit reboot",
    "client_reboot_returns": "client did not return on SSH after reboot",
    "client_boot_id_changes": "client reboot was not proven by a new boot_id",
    "post_client_reboot_twohop": "two-hop validation failed after client reboot",
    "client_failure_salvage_twohop": "salvage two-hop validation failed after the client reboot outage",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nodes-tsv", required=True)
    parser.add_argument("--stages-tsv", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--network-id", required=True)
    parser.add_argument("--overall-status", required=True)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--output-md", required=True)
    return parser.parse_args()


def read_tsv(path: Path) -> list[list[str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        return [row for row in csv.reader(fh, delimiter="\t") if row]


def sanitize_line(line: str) -> str:
    line = ANSI_ESCAPE_RE.sub("", line)
    return line.strip()


def is_ignored_line(line: str) -> bool:
    return any(pattern.search(line) for pattern in IGNORE_LINE_PATTERNS)


def shorten(text: str, max_len: int = 220) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3].rstrip() + "..."


def extract_likely_reason(log_path: Path) -> str:
    if not log_path.exists():
        return "log file missing"
    try:
        lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return "log file unreadable"
    candidates = []
    for raw_line in lines:
        line = sanitize_line(raw_line)
        if not line or is_ignored_line(line):
            continue
        candidates.append(line)
    if not candidates:
        return "see full log"
    for line in reversed(candidates):
        if any(pattern.search(line) for pattern in PREFERRED_REASON_PATTERNS):
            return shorten(line)
    return shorten(candidates[-1])


def extract_extended_soak_reason(report_dir: Path) -> str | None:
    report_path = report_dir / "live_linux_reboot_recovery_report.json"
    if not report_path.exists():
        return None
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    failure_reasons = report.get("failure_reasons")
    if isinstance(failure_reasons, list):
        cleaned = [str(item).strip() for item in failure_reasons if str(item).strip()]
        if cleaned:
            return shorten("; ".join(cleaned))

    checks = report.get("checks")
    reasons: list[str] = []
    if isinstance(checks, dict):
        for name, value in checks.items():
            if value == "fail" and name in REBOOT_CHECK_REASON_TEXT:
                reasons.append(REBOOT_CHECK_REASON_TEXT[name])

    observations = report.get("observations")
    if isinstance(observations, str):
        for raw_line in observations.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line == "client_reboot_wait=fail":
                reasons.append("client reboot wait timed out")
            elif line == "exit_reboot_wait=fail":
                reasons.append("exit reboot wait timed out")
            elif line == "exit_post=":
                reasons.append("exit post-reboot boot_id capture was empty")
            elif line == "client_post=":
                reasons.append("client post-reboot boot_id capture was empty")
            elif line.startswith("ssh_port22_hosts="):
                reasons.append(line)

    if reasons:
        deduped = []
        seen = set()
        for reason in reasons:
            if reason not in seen:
                deduped.append(reason)
                seen.add(reason)
        return shorten("; ".join(deduped))
    return None


def extract_stage_reason(stage_name: str, report_dir: Path, log_path: Path) -> str:
    if stage_name == "extended_soak":
        report_reason = extract_extended_soak_reason(report_dir)
        if report_reason:
            return report_reason
    return extract_likely_reason(log_path)


def read_parallel_results(report_dir: Path, stage_name: str) -> list[dict[str, object]]:
    results_path = report_dir / "state" / f"parallel-{stage_name}" / "results.tsv"
    results = []
    for row in read_tsv(results_path):
        if len(row) != 6:
            continue
        label, target, node_id, role, rc, log_path = row
        results.append(
            {
                "label": label,
                "target": target,
                "node_id": node_id,
                "role": role,
                "rc": int(rc),
                "log_path": log_path,
                "likely_reason": extract_likely_reason(Path(log_path)),
            }
        )
    return results


def stage_sentence(stage_name: str, status: str, worker_results: list[dict[str, object]]) -> str:
    mapping = STAGE_TEXT.get(stage_name, {})
    if status == "pass":
        return mapping.get("pass", "stage passed")
    if status == "skipped":
        return "stage skipped"
    if worker_results:
        total = len(worker_results)
        failed = sum(1 for item in worker_results if item["rc"] != 0)
        base = mapping.get("fail", "stage failed")
        return f"{base} ({failed}/{total} targeted nodes failed)"
    return mapping.get("fail", "stage failed")


def build_digest(args: argparse.Namespace) -> tuple[dict[str, object], str]:
    report_dir = Path(args.report_dir)
    nodes = [
        {
            "label": row[0],
            "target": row[1],
            "node_id": row[2],
            "bootstrap_role": row[3],
        }
        for row in read_tsv(Path(args.nodes_tsv))
        if len(row) == 4
    ]
    stages = []
    failed_stages = []

    for row in read_tsv(Path(args.stages_tsv)):
        if len(row) != 8:
            continue
        stage_name, severity, status, rc, log_path, message, started_at, finished_at = row
        worker_results = read_parallel_results(report_dir, stage_name)
        failed_workers = [item for item in worker_results if item["rc"] != 0]
        likely_reason = extract_stage_reason(stage_name, report_dir, Path(log_path))
        if failed_workers:
            likely_reason = failed_workers[0]["likely_reason"]
        condensed = stage_sentence(stage_name, status, worker_results)
        stage_entry = {
            "stage": stage_name,
            "severity": severity,
            "status": status,
            "rc": int(rc),
            "description": message,
            "started_at": started_at,
            "finished_at": finished_at,
            "log_path": log_path,
            "condensed_result": condensed,
            "likely_reason": likely_reason,
            "failed_workers": failed_workers,
        }
        stages.append(stage_entry)
        if status == "fail":
            failed_stages.append(stage_entry)

    first_failure = failed_stages[0] if failed_stages else None
    digest = {
        "schema_version": 1,
        "run_id": args.run_id,
        "network_id": args.network_id,
        "report_dir": args.report_dir,
        "overall_status": args.overall_status,
        "node_count": len(nodes),
        "nodes": nodes,
        "stages": stages,
        "failed_stage_count": len(failed_stages),
        "first_failure": first_failure,
    }

    lines = [
        f"# Live Linux Lab Failure Digest ({args.run_id})",
        "",
        f"- overall_status: `{args.overall_status}`",
        f"- report_dir: `{args.report_dir}`",
        f"- node_count: `{len(nodes)}`",
        "",
        "## Condensed Checks",
        "",
    ]

    if not stages:
        lines.append("- no stage results recorded yet")
    else:
        for stage in stages:
            lines.append(
                f"- `{stage['status'].upper()}` `{stage['stage']}`: {stage['condensed_result']}"
            )

    lines.extend(["", "## Failure Focus", ""])
    if first_failure is None:
        lines.append("- no failed stage recorded")
    else:
        lines.append(f"- first_failed_stage: `{first_failure['stage']}`")
        lines.append(f"- severity: `{first_failure['severity']}`")
        lines.append(f"- rc: `{first_failure['rc']}`")
        lines.append(f"- likely_reason: {first_failure['likely_reason']}")
        lines.append(f"- full_log: `{first_failure['log_path']}`")
        if first_failure["failed_workers"]:
            lines.append("")
            lines.append("### Failed Nodes")
            lines.append("")
            for worker in first_failure["failed_workers"]:
                lines.append(
                    f"- `{worker['label']}` `{worker['target']}` (`{worker['node_id']}`): rc={worker['rc']} reason={worker['likely_reason']} log=`{worker['log_path']}`"
                )

    return digest, "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    digest, digest_md = build_digest(args)
    Path(args.output_json).write_text(json.dumps(digest, indent=2) + "\n", encoding="utf-8")
    Path(args.output_md).write_text(digest_md, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
