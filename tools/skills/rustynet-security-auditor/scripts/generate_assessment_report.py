#!/usr/bin/env python3
"""Generate a markdown scaffold for an adversarial hardening assessment."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a markdown scaffold for a lab-only adversarial hardening report."
    )
    parser.add_argument("--project", required=True, help="Project or system name.")
    parser.add_argument("--output", required=True, help="Output markdown path.")
    parser.add_argument(
        "--attacks",
        default="",
        help="Comma-separated attack families that will be assessed.",
    )
    parser.add_argument(
        "--topology",
        default="",
        help="Short topology summary for the lab environment.",
    )
    return parser.parse_args()


def render(project: str, attacks: list[str], topology: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    attack_lines = "\n".join(f"- {attack}" for attack in attacks) or "- [fill in attack families]"
    topology_line = topology or "[fill in lab topology]"
    return f"""# {project} Adversarial Hardening Assessment

Generated: {now}

## Scope And Authorization

- Lab-only authorization confirmed: [yes/no]
- In-scope systems:
- Out-of-scope systems:
- Success criteria:

## Topology

{topology_line}

## Attack Plan

{attack_lines}

## Attack Matrix

| Attack Family | Hypothesis | Result | Fail-Closed? | Evidence |
| --- | --- | --- | --- | --- |
| [family] | [expected secure behavior] | [pass/fail/blocked/skipped] | [yes/no] | [logs, tests, reports] |

## Findings

### [Severity] [Title]

- Attack family:
- Evidence:
- Affected files/subsystems:
- Expected secure behavior:
- Actual behavior:
- Remediation:
- Required regression test or gate:

## Code Audit Notes

- Trust boundaries reviewed:
- Privileged boundaries reviewed:
- Fallback or legacy paths found:
- Tests and gates reviewed:

## Recommended Hardening Work

1. [Highest-priority change]
2. [Next change]
3. [Next change]

## Verification Plan

1. [Unit or integration test]
2. [Gate or live lab validation]
3. [Evidence artifact to regenerate]
"""


def main() -> int:
    args = parse_args()
    attacks = [item.strip() for item in args.attacks.split(",") if item.strip()]
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render(args.project, attacks, args.topology), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
