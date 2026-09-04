#!/usr/bin/env python3
"""Quote-aware, read-only query tool for the live-lab evidence ledgers.

The live-lab ledgers
  documents/operations/live_lab_node_run_matrix.csv
  documents/operations/live_lab_node_stage_results.csv
carry QUOTED comma-bearing fields (notes, report dirs, run commands). An
`awk -F,` one-liner splits on every comma and lands on the wrong column,
which has already produced confidently-wrong conclusions (AGENTS.md §12.3,
tracked as QH-07). This tool parses with the stdlib `csv` module, which
honours quoting, and indexes every column BY NAME from the header row so
column reordering cannot silently break a query.

Subcommands:
  runs                     list recent runs from the run matrix
                           (run_id, commit, dirty, overall_result), newest last
  stage <stage-name>       list every per-stage row in the stage-results
                           ledger (run_id, commit, alias, os_family, status)
                           -- the PER-STAGE truth, not a masked column
  did-pass <stage>         has <stage> ever passed per the per-stage ledger?
                           [--os macos|linux|windows|debian|rocky|ubuntu|fedora]
                           matches either the os_family or the platform column;
                           prints the passing run_ids + commits; 0 pass is a
                           valid, honest answer

Options:
  --json                   machine-readable output on every subcommand
  --limit N                cap on rows listed (runs/stage; default 20)
  --ledger-dir DIR         alternate ledger directory (default: repo-relative)

This tool is strictly READ-ONLY: it never writes either ledger.

Caveat (always applies): a stage COLUMN can still lie (alias masking,
greener/redder than the artifact). Take the final pass/fail from the run's
own report artifact in the run's report directory (its `status` plus its
data block), never from a ledger column alone — AGENTS.md §6/§12.3.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

RUN_MATRIX = "live_lab_node_run_matrix.csv"
STAGE_RESULTS = "live_lab_node_stage_results.csv"

CAVEAT = (
    "caveat: column-vs-artifact rule still applies — take the final "
    "pass/fail from the run's report artifact, not the ledger column "
    "(AGENTS.md §12.3)"
)


def _repo_root() -> Path:
    """Locate the repo root (this script lives at <root>/scripts/operations/)."""
    return Path(__file__).resolve().parents[2]


def _ledger_path(ledger_dir: str | None, name: str) -> Path:
    base = Path(ledger_dir) if ledger_dir else _repo_root() / "documents" / "operations"
    path = base / name
    if not path.is_file():
        raise SystemExit(f"error: ledger not found: {path}")
    return path


def _read_ledger(path: Path) -> list[dict[str, str]]:
    """Quote-aware, header-driven read. Index by NAME, never position."""
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise SystemExit(f"error: empty ledger (no header row): {path}")
        rows = list(reader)
    return rows


def _cell(row: dict[str, str], name: str) -> str:
    """Header-driven cell access; a missing/renamed column fails loudly."""
    if name not in row:
        raise SystemExit(
            f"error: column {name!r} absent from ledger header — refusing positional guess"
        )
    return (row.get(name) or "").strip()


def _emit_json(payload) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _newest_key(row: dict[str, str]) -> tuple[str, str]:
    """Sort key: run_started_utc, falling back to run_id (both lexical)."""
    return (_cell(row, "run_started_utc"), _cell(row, "run_id"))


def cmd_runs(args: argparse.Namespace) -> int:
    path = _ledger_path(args.ledger_dir, RUN_MATRIX)
    rows = _read_ledger(path)
    rows.sort(key=_newest_key)
    rows = rows[-args.limit :] if args.limit and args.limit > 0 else rows

    payload = {
        "ledger": str(path),
        "caveat": CAVEAT,
        "runs": [
            {
                "run_id": _cell(r, "run_id"),
                "run_started_utc": _cell(r, "run_started_utc"),
                "commit": _cell(r, "git_commit"),
                "dirty": _cell(r, "git_dirty_state"),
                "overall_result": _cell(r, "overall_result"),
                "first_failed_stage": _cell(r, "first_failed_stage"),
            }
            for r in rows
        ],
    }
    if args.json:
        _emit_json(payload)
        return 0

    print(f"# {path.name} — {len(rows)} run(s), newest last")
    for r in rows:
        print(
            f"{_cell(r, 'run_id')}  {_cell(r, 'run_started_utc')}  "
            f"commit={_cell(r, 'git_commit')[:12]}  dirty={_cell(r, 'git_dirty_state')}  "
            f"result={_cell(r, 'overall_result')}"
            + (
                f"  first_failed_stage={_cell(r, 'first_failed_stage')}"
                if _cell(r, "first_failed_stage")
                else ""
            )
        )
    print(f"# {CAVEAT}")
    return 0


def cmd_stage(args: argparse.Namespace) -> int:
    path = _ledger_path(args.ledger_dir, STAGE_RESULTS)
    rows = _read_ledger(path)
    want = args.stage
    matched = [r for r in rows if _cell(r, "stage") == want]
    matched.sort(key=_newest_key)
    matched = matched[-args.limit :] if args.limit and args.limit > 0 else matched

    payload = {
        "ledger": str(path),
        "stage": want,
        "matched_rows": len(matched),
        "caveat": CAVEAT,
        "rows": [
            {
                "run_id": _cell(r, "run_id"),
                "run_started_utc": _cell(r, "run_started_utc"),
                "commit": _cell(r, "git_commit"),
                "alias": _cell(r, "alias"),
                "os_family": _cell(r, "os_family"),
                "status": _cell(r, "status"),
                "evidence_path": _cell(r, "evidence_path"),
            }
            for r in matched
        ],
    }
    if args.json:
        _emit_json(payload)
        return 0

    print(
        f"# {path.name} — stage={want} — {len(matched)} row(s), newest last (per-stage truth, not a column)"
    )
    for r in matched:
        print(
            f"{_cell(r, 'run_id')}  {_cell(r, 'run_started_utc')}  "
            f"commit={_cell(r, 'git_commit')[:12]}  alias={_cell(r, 'alias')}  "
            f"os={_cell(r, 'os_family')}  status={_cell(r, 'status')}"
        )
    print(f"# {CAVEAT}")
    return 0


def cmd_did_pass(args: argparse.Namespace) -> int:
    path = _ledger_path(args.ledger_dir, STAGE_RESULTS)
    rows = _read_ledger(path)
    want = args.stage
    want_os = args.os.lower() if args.os else None

    passing: list[dict[str, str]] = []
    total_rows = 0
    for r in rows:
        if _cell(r, "stage") != want:
            continue
        if want_os:
            os_family = _cell(r, "os_family").lower()
            platform = _cell(r, "platform").lower()
            # os_family holds distro families (debian/rocky/ubuntu/fedora);
            # platform holds the coarse OS (linux/macos/windows). Accept either.
            if want_os not in (os_family, platform):
                continue
        total_rows += 1
        if _cell(r, "status").lower() == "pass":
            passing.append(r)

    passing.sort(key=_newest_key)
    payload = {
        "ledger": str(path),
        "stage": want,
        "os_filter": want_os,
        "rows_examined": total_rows,
        "pass_count": len(passing),
        "has_ever_passed": len(passing) > 0,
        "caveat": CAVEAT,
        "passing": [
            {
                "run_id": _cell(r, "run_id"),
                "commit": _cell(r, "git_commit"),
                "run_started_utc": _cell(r, "run_started_utc"),
                "alias": _cell(r, "alias"),
                "os_family": _cell(r, "os_family"),
                "platform": _cell(r, "platform"),
                "evidence_path": _cell(r, "evidence_path"),
            }
            for r in passing
        ],
    }
    if args.json:
        _emit_json(payload)
        return 0

    scope = f" (os={want_os})" if want_os else ""
    print(f"# did-pass{scope}: stage={want} — examined {total_rows} per-stage row(s)")
    if not passing:
        print(
            "NEVER PASSED — 0 pass rows in the per-stage ledger. This is the honest answer."
        )
    else:
        print(f"PASSED in {len(passing)} row(s):")
        for r in passing:
            print(
                f"  {_cell(r, 'run_id')}  commit={_cell(r, 'git_commit')[:12]}  "
                f"alias={_cell(r, 'alias')}  os={_cell(r, 'os_family')}"
            )
    print(f"# {CAVEAT}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ledger_query.py",
        description="Quote-aware, read-only live-lab ledger queries (stdlib csv; never awk -F,).",
    )
    parser.add_argument(
        "--ledger-dir",
        default=None,
        help="directory holding the ledger CSVs (default: <repo>/documents/operations)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_runs = sub.add_parser("runs", help="list recent runs, newest last")
    p_runs.add_argument("--limit", type=int, default=20)
    p_runs.add_argument("--json", action="store_true")
    p_runs.set_defaults(func=cmd_runs)

    p_stage = sub.add_parser(
        "stage", help="per-stage rows from the stage-results ledger"
    )
    p_stage.add_argument("stage")
    p_stage.add_argument("--limit", type=int, default=20)
    p_stage.add_argument("--json", action="store_true")
    p_stage.set_defaults(func=cmd_stage)

    p_did = sub.add_parser(
        "did-pass", help="has this stage ever passed? (honest 0-pass allowed)"
    )
    p_did.add_argument("stage")
    p_did.add_argument(
        "--os",
        default=None,
        help="filter by os_family (debian/rocky/ubuntu/fedora) or platform (linux/macos/windows)",
    )
    p_did.add_argument("--json", action="store_true")
    p_did.set_defaults(func=cmd_did_pass)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
