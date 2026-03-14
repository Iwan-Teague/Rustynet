#!/usr/bin/env python3
"""Generate a deterministic attack matrix scaffold for lab-safe adversarial assessments."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ATTACKS = {
    "control-plane-replay": {
        "title": "Control-Plane Replay And Rollback",
        "hypothesis": "Stale or tampered signed artifacts must be rejected without widening runtime state.",
        "expected": "Reject artifact and preserve secure state or fail closed.",
    },
    "local-socket-spoofing": {
        "title": "Local Control Surface Spoofing",
        "hypothesis": "Clients must reject insecure or attacker-owned local control surfaces before connecting.",
        "expected": "Reject path based on ownership, symlink, or mode checks.",
    },
    "host-trust-downgrade": {
        "title": "Host Trust Downgrade",
        "hypothesis": "Automation must not silently trust changed host identity.",
        "expected": "Host-key verification fails closed.",
    },
    "route-hijack": {
        "title": "Route Or Exit Hijack",
        "hypothesis": "Unauthorized route or exit state must not widen the data path.",
        "expected": "Reject unauthorized path change and keep routing constrained.",
    },
    "dns-integrity": {
        "title": "DNS Integrity And Namespace Abuse",
        "hypothesis": "Managed DNS must reject stale, mismatched, or unauthorized name-to-node mappings.",
        "expected": "Managed names fail closed and non-managed names are refused.",
    },
    "traversal-abuse": {
        "title": "Traversal Hint Or Relay Abuse",
        "hypothesis": "Direct or relay path decisions must require current verified evidence.",
        "expected": "Reject stale hints and promote only with fresh evidence.",
    },
    "secret-custody": {
        "title": "Secret Custody And Log Leakage",
        "hypothesis": "Secrets must not leak through files, temp paths, argv, or logs.",
        "expected": "No plaintext leakage; secure custody and cleanup only.",
    },
    "missing-state-fail-closed": {
        "title": "Missing-State Fail-Closed Validation",
        "hypothesis": "Removing required trust inputs must make the system restrictive, not permissive.",
        "expected": "Operation fails closed with explicit error.",
    },
    "helper-input-abuse": {
        "title": "Privileged Helper Input Abuse",
        "hypothesis": "Malformed helper requests must be rejected before privileged execution.",
        "expected": "Deterministic parser rejection without shell execution.",
    },
    "release-evidence-integrity": {
        "title": "Release Evidence Integrity",
        "hypothesis": "Release evidence must bind to the exact source state and portable artifact paths.",
        "expected": "Mismatched or stale evidence is rejected.",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a deterministic attack matrix scaffold for a lab-only assessment."
    )
    parser.add_argument(
        "--attacks",
        required=True,
        help="Comma-separated attack keys. Supported keys: " + ", ".join(sorted(ATTACKS)),
    )
    parser.add_argument(
        "--nodes",
        required=True,
        help="Comma-separated node specs in label:role form, for example exit:admin,client1:client.",
    )
    parser.add_argument("--output", required=True, help="Output path.")
    parser.add_argument(
        "--format",
        choices=("md", "json"),
        default="md",
        help="Output format.",
    )
    return parser.parse_args()


def parse_attacks(raw: str) -> list[str]:
    attacks = [item.strip() for item in raw.split(",") if item.strip()]
    if not attacks:
        raise SystemExit("no attack keys supplied")
    unknown = [item for item in attacks if item not in ATTACKS]
    if unknown:
        raise SystemExit("unknown attack keys: " + ", ".join(unknown))
    return attacks


def parse_nodes(raw: str) -> list[dict[str, str]]:
    nodes = []
    for item in [part.strip() for part in raw.split(",") if part.strip()]:
        if ":" not in item:
            raise SystemExit(f"invalid node spec: {item}")
        label, role = item.split(":", 1)
        label = label.strip()
        role = role.strip()
        if not label or not role:
            raise SystemExit(f"invalid node spec: {item}")
        nodes.append({"label": label, "role": role})
    if not nodes:
        raise SystemExit("no nodes supplied")
    return nodes


def suggested_targets(attack_key: str, nodes: list[dict[str, str]]) -> str:
    roles = {node["role"] for node in nodes}
    if attack_key in {"route-hijack", "dns-integrity", "control-plane-replay"} and "admin" in roles:
        return ", ".join(node["label"] for node in nodes if node["role"] == "admin")
    if attack_key in {"local-socket-spoofing", "secret-custody", "missing-state-fail-closed"}:
        return ", ".join(node["label"] for node in nodes)
    if attack_key == "host-trust-downgrade":
        return "operator -> " + ", ".join(node["label"] for node in nodes)
    if attack_key == "traversal-abuse":
        return (
            ", ".join(
                node["label"]
                for node in nodes
                if node["role"] in {"client", "admin", "relay", "entry"}
            )
            or ", ".join(node["label"] for node in nodes)
        )
    if attack_key == "helper-input-abuse":
        return (
            ", ".join(node["label"] for node in nodes if node["role"] in {"client", "admin"})
            or ", ".join(node["label"] for node in nodes)
        )
    return ", ".join(node["label"] for node in nodes)


def build_rows(attacks: list[str], nodes: list[dict[str, str]]) -> list[dict[str, str]]:
    rows = []
    for key in attacks:
        spec = ATTACKS[key]
        rows.append(
            {
                "attack_key": key,
                "attack_family": spec["title"],
                "primary_nodes": suggested_targets(key, nodes),
                "hypothesis": spec["hypothesis"],
                "expected_secure_behavior": spec["expected"],
                "result": "[pass/fail/blocked/skipped]",
                "evidence": "[fill in logs, tests, reports]",
            }
        )
    return rows


def render_markdown(rows: list[dict[str, str]], nodes: list[dict[str, str]]) -> str:
    node_summary = ", ".join(f"{node['label']} ({node['role']})" for node in nodes)
    lines = [
        "# Attack Matrix",
        "",
        "## Lab Nodes",
        "",
        f"- {node_summary}",
        "",
        "## Planned Attacks",
        "",
        "| Attack Family | Primary Nodes | Hypothesis | Expected Secure Behavior | Result | Evidence |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            f"| {row['attack_family']} | {row['primary_nodes']} | {row['hypothesis']} | {row['expected_secure_behavior']} | {row['result']} | {row['evidence']} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    attacks = parse_attacks(args.attacks)
    nodes = parse_nodes(args.nodes)
    rows = build_rows(attacks, nodes)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.format == "json":
        payload = {"nodes": nodes, "attacks": rows}
        output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    else:
        output.write_text(render_markdown(rows, nodes), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
