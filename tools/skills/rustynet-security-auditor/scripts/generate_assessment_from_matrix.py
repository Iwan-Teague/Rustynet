#!/usr/bin/env python3
"""Generate a merged markdown assessment report from a canonical JSON attack matrix."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a markdown adversarial hardening report from a JSON attack matrix."
    )
    parser.add_argument("--project", required=True, help="Project or system name.")
    parser.add_argument("--matrix-json", required=True, help="Path to the JSON attack matrix.")
    parser.add_argument("--output", required=True, help="Output markdown path.")
    parser.add_argument(
        "--topology",
        default="",
        help="Optional topology override. Defaults to a summary derived from the matrix nodes.",
    )
    parser.add_argument(
        "--authorization",
        default="[yes/no]",
        help="Authorization status text for the scope section.",
    )
    return parser.parse_args()


def load_matrix(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit("matrix payload must be a JSON object")
    nodes = payload.get("nodes")
    attacks = payload.get("attacks")
    if not isinstance(nodes, list) or not isinstance(attacks, list):
        raise SystemExit("matrix payload must contain 'nodes' and 'attacks' arrays")
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("label"), str) or not isinstance(node.get("role"), str):
            raise SystemExit("invalid node entry in matrix payload")
    required_attack_fields = {
        "attack_key",
        "attack_family",
        "primary_nodes",
        "hypothesis",
        "expected_secure_behavior",
        "result",
        "evidence",
    }
    for attack in attacks:
        if not isinstance(attack, dict):
            raise SystemExit("invalid attack entry in matrix payload")
        missing = [field for field in required_attack_fields if field not in attack or not isinstance(attack[field], str)]
        if missing:
            raise SystemExit("invalid attack entry in matrix payload; missing fields: " + ", ".join(missing))
    return payload


def topology_summary(nodes: list[dict[str, str]], override: str) -> str:
    if override:
        return override
    return ", ".join(f"{node['label']} ({node['role']})" for node in nodes) or "[fill in lab topology]"


def render(project: str, matrix: dict, topology: str, authorization: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    attacks = matrix["attacks"]
    plan_lines = "\n".join(f"- {attack['attack_family']}" for attack in attacks) or "- [fill in attack families]"
    matrix_lines = [
        "| Attack Family | Primary Nodes | Hypothesis | Expected Secure Behavior | Result | Evidence |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for attack in attacks:
        matrix_lines.append(
            f"| {attack['attack_family']} | {attack['primary_nodes']} | {attack['hypothesis']} | {attack['expected_secure_behavior']} | {attack['result']} | {attack['evidence']} |"
        )
    matrix_block = "\n".join(matrix_lines)
    return f"""# {project} Adversarial Hardening Assessment

Generated: {now}

## Scope And Authorization

- Lab-only authorization confirmed: {authorization}
- In-scope systems:
- Out-of-scope systems:
- Success criteria:

## Topology

{topology}

## Attack Plan

{plan_lines}

## Attack Matrix

{matrix_block}

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
    matrix = load_matrix(Path(args.matrix_json))
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        render(
            args.project,
            matrix,
            topology_summary(matrix["nodes"], args.topology),
            args.authorization,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
