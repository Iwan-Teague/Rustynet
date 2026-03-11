#!/usr/bin/env python3
import argparse
import json
import shutil
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Copy live Linux OS-matrix evidence into canonical tracked phase10/source paths"
        )
    )
    parser.add_argument("--dest-dir", required=True)
    parser.add_argument("--bootstrap-log", required=True)
    parser.add_argument("--baseline-log", required=True)
    parser.add_argument("--two-hop-report", required=True)
    parser.add_argument("--role-switch-report", required=True)
    parser.add_argument("--lan-toggle-report", required=True)
    parser.add_argument("--exit-handoff-report", required=True)
    return parser.parse_args()


def fail(message: str) -> None:
    raise SystemExit(message)


def require_file(path: Path, label: str) -> Path:
    if not path.is_file():
        fail(f"missing {label}: {path}")
    return path.resolve()


def repo_relative(path: Path, root: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(root))
    except ValueError:
        return str(resolved)


def copy_artifact(source: Path, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return destination.resolve()


def canonicalize_report(
    report_path: Path,
    report_label: str,
    dest_dir: Path,
    root: Path,
    slug: str,
) -> Path:
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        fail(f"{report_label} must be a JSON object")

    canonical_report_path = dest_dir / report_path.name

    source_artifacts = payload.get("source_artifacts")
    if source_artifacts is not None:
        if not isinstance(source_artifacts, list) or not source_artifacts:
            fail(f"{report_label} requires a non-empty source_artifacts list")
        rebound = []
        for index, artifact in enumerate(source_artifacts, start=1):
            if not isinstance(artifact, str) or not artifact.strip():
                fail(f"{report_label} has invalid source_artifacts entry")
            source = Path(artifact)
            if not source.is_absolute():
                source = (root / source).resolve()
            require_file(source, f"{report_label} source artifact")
            canonical_source = copy_artifact(
                source,
                dest_dir / f"{slug}_{index:02d}_{source.name}",
            )
            rebound.append(repo_relative(canonical_source, root))
        payload["source_artifacts"] = rebound

    source_artifact = payload.get("source_artifact")
    if source_artifact is not None:
        if not isinstance(source_artifact, str) or not source_artifact.strip():
            fail(f"{report_label} has invalid source_artifact")
        source = Path(source_artifact)
        if not source.is_absolute():
            source = (root / source).resolve()
        require_file(source, f"{report_label} source artifact")
        canonical_source = copy_artifact(
            source,
            dest_dir / f"{slug}_source_{source.name}",
        )
        payload["source_artifact"] = repo_relative(canonical_source, root)

    canonical_report_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return canonical_report_path.resolve()


def main() -> None:
    args = parse_args()
    root = Path(__file__).resolve().parents[2]
    dest_dir = Path(args.dest_dir)
    if not dest_dir.is_absolute():
        dest_dir = (root / dest_dir).resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)

    bootstrap_log = require_file(Path(args.bootstrap_log), "bootstrap log")
    baseline_log = require_file(Path(args.baseline_log), "baseline log")
    two_hop_report = require_file(Path(args.two_hop_report), "two-hop report")
    role_switch_report = require_file(Path(args.role_switch_report), "role-switch report")
    lan_toggle_report = require_file(Path(args.lan_toggle_report), "LAN toggle report")
    exit_handoff_report = require_file(Path(args.exit_handoff_report), "exit handoff report")

    canonical_paths = {
        "bootstrap_log": copy_artifact(
            bootstrap_log,
            dest_dir / "bootstrap_hosts.log",
        ),
        "baseline_log": copy_artifact(
            baseline_log,
            dest_dir / "validate_baseline_runtime.log",
        ),
        "two_hop_report": canonicalize_report(
            two_hop_report,
            "two-hop report",
            dest_dir,
            root,
            "two_hop",
        ),
        "role_switch_report": canonicalize_report(
            role_switch_report,
            "role-switch report",
            dest_dir,
            root,
            "role_switch",
        ),
        "lan_toggle_report": canonicalize_report(
            lan_toggle_report,
            "LAN toggle report",
            dest_dir,
            root,
            "lan_toggle",
        ),
        "exit_handoff_report": canonicalize_report(
            exit_handoff_report,
            "exit handoff report",
            dest_dir,
            root,
            "exit_handoff",
        ),
    }
    print(json.dumps({key: repo_relative(value, root) for key, value in canonical_paths.items()}))


if __name__ == "__main__":
    main()
