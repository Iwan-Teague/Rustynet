#!/usr/bin/env python3
"""Validate cross-network discovery bundles collected from Rustynet nodes."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

NODE_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
HOST_RE = re.compile(r"^[A-Za-z0-9._:-]+$")
PUBLIC_KEY_KEYS = (
    "assignment_verifier_key_b64",
    "traversal_verifier_key_b64",
    "dns_zone_verifier_key_b64",
    "trust_evidence_verifier_key_b64",
)
FORBIDDEN_KEY_NAME_TOKENS = ("private_key", "signing_secret", "passphrase", "secret")
FORBIDDEN_STRING_TOKENS = (
    "BEGIN PRIVATE KEY",
    "PRIVATE KEY-----",
    "OPENSSH PRIVATE KEY",
)


@dataclass(frozen=True)
class ValidationConfig:
    max_age_seconds: int
    require_verifier_keys: bool
    require_daemon_active: bool
    require_socket_present: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate cross-network discovery bundle(s)."
    )
    parser.add_argument(
        "--bundle",
        action="append",
        default=[],
        help="Path to a discovery JSON bundle. Can be set multiple times.",
    )
    parser.add_argument(
        "--bundles",
        default="",
        help="Comma-separated discovery bundle paths.",
    )
    parser.add_argument(
        "--max-age-seconds",
        type=int,
        default=900,
        help="Maximum allowed age for collected_at_unix.",
    )
    parser.add_argument(
        "--require-verifier-keys",
        action="store_true",
        help="Require all verifier_keys entries to be present and valid.",
    )
    parser.add_argument(
        "--require-daemon-active",
        action="store_true",
        help="Require daemon_status.active to indicate active runtime.",
    )
    parser.add_argument(
        "--require-socket-present",
        action="store_true",
        help="Require daemon_status.socket_present=true.",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Optional markdown summary output path.",
    )
    return parser.parse_args()


def parse_csv(raw: str) -> list[str]:
    out: list[str] = []
    for part in raw.split(","):
        value = part.strip()
        if value and value not in out:
            out.append(value)
    return out


def collect_bundle_paths(args: argparse.Namespace) -> list[Path]:
    items: list[str] = []
    items.extend(args.bundle)
    items.extend(parse_csv(args.bundles))
    paths = [Path(item).resolve() for item in items if item.strip()]
    if not paths:
        raise SystemExit("at least one bundle path is required (--bundle or --bundles)")
    return paths


def decode_b64_32(value: str) -> bool:
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        return False
    return len(raw) == 32


def validate_host_endpoint(endpoint: str) -> bool:
    if ":" not in endpoint:
        return False
    host, raw_port = endpoint.rsplit(":", 1)
    if not host or not raw_port.isdigit():
        return False
    port = int(raw_port)
    if port <= 0 or port > 65535:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOST_RE.fullmatch(host))


def validate_path(raw: Any) -> bool:
    return isinstance(raw, str) and raw.startswith("/")


def validate_no_secrets(payload: Any, problems: list[str], path: str = "$") -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            lowered = str(key).lower()
            if any(token in lowered for token in FORBIDDEN_KEY_NAME_TOKENS):
                problems.append(f"{path}.{key}: forbidden secret-like key name")
            validate_no_secrets(value, problems, f"{path}.{key}")
        return
    if isinstance(payload, list):
        for idx, item in enumerate(payload):
            validate_no_secrets(item, problems, f"{path}[{idx}]")
        return
    if isinstance(payload, str):
        for token in FORBIDDEN_STRING_TOKENS:
            if token in payload:
                problems.append(f"{path}: contains forbidden secret-like token {token!r}")


def validate_bundle(path: Path, payload: Any, config: ValidationConfig) -> list[str]:
    problems: list[str] = []
    if not isinstance(payload, dict):
        return [f"{path}: payload must be a JSON object"]

    validate_no_secrets(payload, problems)

    if payload.get("schema_version") != 1:
        problems.append("schema_version must equal 1")
    if payload.get("purpose") != "cross_network_discovery_bundle":
        problems.append("purpose must equal 'cross_network_discovery_bundle'")

    collected_at_unix = payload.get("collected_at_unix")
    now_unix = int(time.time())
    if not isinstance(collected_at_unix, int) or collected_at_unix <= 0:
        problems.append("collected_at_unix must be a positive integer")
    else:
        if collected_at_unix > now_unix + 300:
            problems.append("collected_at_unix is too far in the future")
        if now_unix - collected_at_unix > config.max_age_seconds:
            problems.append("collected_at_unix is stale")

    node_identity = payload.get("node_identity")
    if not isinstance(node_identity, dict):
        problems.append("node_identity must be an object")
    else:
        node_id = node_identity.get("node_id")
        if not isinstance(node_id, str) or not NODE_ID_RE.fullmatch(node_id):
            problems.append("node_identity.node_id must match [A-Za-z0-9._-]+")
        for field in ("hostname", "os", "kernel", "arch"):
            value = node_identity.get(field)
            if not isinstance(value, str) or not value.strip():
                problems.append(f"node_identity.{field} must be a non-empty string")

    wireguard = payload.get("wireguard")
    if not isinstance(wireguard, dict):
        problems.append("wireguard must be an object")
    else:
        iface = wireguard.get("interface")
        if not isinstance(iface, str) or not iface.strip():
            problems.append("wireguard.interface must be a non-empty string")
        pubkey = wireguard.get("public_key")
        if not isinstance(pubkey, str) or not decode_b64_32(pubkey.strip()):
            problems.append("wireguard.public_key must be valid base64 for 32-byte key")
        listen_port = wireguard.get("listen_port")
        if not isinstance(listen_port, int) or listen_port <= 0 or listen_port > 65535:
            problems.append("wireguard.listen_port must be an integer in [1, 65535]")
        stanza = wireguard.get("peer_stanza_template")
        if not isinstance(stanza, str) or not stanza.strip():
            problems.append("wireguard.peer_stanza_template must be a non-empty string")

    endpoint_candidates = payload.get("endpoint_candidates")
    if not isinstance(endpoint_candidates, list) or not endpoint_candidates:
        problems.append("endpoint_candidates must be a non-empty list")
    else:
        seen: set[tuple[str, str]] = set()
        for idx, candidate in enumerate(endpoint_candidates):
            if not isinstance(candidate, dict):
                problems.append(f"endpoint_candidates[{idx}] must be an object")
                continue
            candidate_type = candidate.get("type")
            endpoint = candidate.get("endpoint", "")
            if candidate_type not in {"host", "server_reflexive", "relay"}:
                problems.append(
                    f"endpoint_candidates[{idx}].type must be host/server_reflexive/relay"
                )
                continue
            if not isinstance(endpoint, str):
                problems.append(f"endpoint_candidates[{idx}].endpoint must be a string")
                continue
            if candidate_type in {"host", "server_reflexive"}:
                if not endpoint or not validate_host_endpoint(endpoint):
                    problems.append(
                        f"endpoint_candidates[{idx}].endpoint must be host:port for {candidate_type}"
                    )
            elif endpoint and not validate_host_endpoint(endpoint):
                problems.append(
                    f"endpoint_candidates[{idx}].endpoint must be empty or host:port for relay"
                )
            priority = candidate.get("priority")
            if not isinstance(priority, int):
                problems.append(f"endpoint_candidates[{idx}].priority must be an integer")
            candidate_key = (str(candidate_type), endpoint)
            if candidate_key in seen:
                problems.append(
                    f"endpoint_candidates[{idx}] duplicates candidate type/endpoint pair"
                )
            seen.add(candidate_key)

    nat_profile = payload.get("nat_profile")
    if not isinstance(nat_profile, dict):
        problems.append("nat_profile must be an object")
    else:
        if not isinstance(nat_profile.get("behind_nat"), bool):
            problems.append("nat_profile.behind_nat must be boolean")
        for field in (
            "first_lan_ip",
            "detected_public_ip",
            "port_forwarded_hint",
            "recommended_traversal_strategy",
        ):
            value = nat_profile.get(field)
            if not isinstance(value, str):
                problems.append(f"nat_profile.{field} must be a string")

    verifier_keys = payload.get("verifier_keys")
    if not isinstance(verifier_keys, dict):
        problems.append("verifier_keys must be an object")
    else:
        for key in PUBLIC_KEY_KEYS:
            value = verifier_keys.get(key)
            if not isinstance(value, str):
                problems.append(f"verifier_keys.{key} must be a string")
                continue
            value = value.strip()
            if not value:
                if config.require_verifier_keys:
                    problems.append(f"verifier_keys.{key} must be non-empty in strict mode")
                continue
            if not decode_b64_32(value):
                problems.append(f"verifier_keys.{key} must decode to 32 bytes")

    rustynet_artifacts = payload.get("rustynet_artifacts")
    expected_artifacts = (
        "assignment_bundle",
        "traversal_bundle",
        "membership_snapshot",
        "membership_log",
        "dns_zone_bundle",
        "trust_evidence",
    )
    if not isinstance(rustynet_artifacts, dict):
        problems.append("rustynet_artifacts must be an object")
    else:
        for name in expected_artifacts:
            entry = rustynet_artifacts.get(name)
            if not isinstance(entry, dict):
                problems.append(f"rustynet_artifacts.{name} must be an object")
                continue
            if not validate_path(entry.get("path")):
                problems.append(f"rustynet_artifacts.{name}.path must be absolute")
            exists = entry.get("exists")
            if not isinstance(exists, bool):
                problems.append(f"rustynet_artifacts.{name}.exists must be boolean")
                continue
            size = entry.get("size_bytes")
            mtime = entry.get("mtime_unix")
            if not isinstance(size, int) or size < 0:
                problems.append(f"rustynet_artifacts.{name}.size_bytes must be >= 0")
            if not isinstance(mtime, int) or mtime < 0:
                problems.append(f"rustynet_artifacts.{name}.mtime_unix must be >= 0")
            if exists:
                if isinstance(size, int) and size <= 0:
                    problems.append(
                        f"rustynet_artifacts.{name}.size_bytes must be > 0 when exists=true"
                    )
                if isinstance(mtime, int) and mtime <= 0:
                    problems.append(
                        f"rustynet_artifacts.{name}.mtime_unix must be > 0 when exists=true"
                    )

    daemon_status = payload.get("daemon_status")
    if not isinstance(daemon_status, dict):
        problems.append("daemon_status must be an object")
    else:
        active = daemon_status.get("active")
        if active not in {"active", "inactive", "socket_present", "unknown"}:
            problems.append(
                "daemon_status.active must be one of active/inactive/socket_present/unknown"
            )
        if config.require_daemon_active and active not in {"active", "socket_present"}:
            problems.append("daemon_status.active must indicate active runtime")
        socket_present = daemon_status.get("socket_present")
        if not isinstance(socket_present, bool):
            problems.append("daemon_status.socket_present must be boolean")
        elif config.require_socket_present and not socket_present:
            problems.append("daemon_status.socket_present must be true in strict mode")
        if not validate_path(daemon_status.get("socket_path")):
            problems.append("daemon_status.socket_path must be absolute")

    known_peers = payload.get("known_peers")
    if not isinstance(known_peers, list):
        problems.append("known_peers must be a list")
    else:
        for idx, peer in enumerate(known_peers):
            if not isinstance(peer, dict):
                problems.append(f"known_peers[{idx}] must be an object")
                continue
            pubkey = peer.get("public_key")
            if not isinstance(pubkey, str) or not decode_b64_32(pubkey.strip()):
                problems.append(f"known_peers[{idx}].public_key must decode to 32 bytes")
            endpoint = peer.get("endpoint", "")
            if not isinstance(endpoint, str):
                problems.append(f"known_peers[{idx}].endpoint must be a string")
            elif endpoint and not validate_host_endpoint(endpoint):
                problems.append(f"known_peers[{idx}].endpoint must be host:port")

    checklist = payload.get("remote_network_checklist")
    if not isinstance(checklist, list) or not checklist:
        problems.append("remote_network_checklist must be a non-empty list")
    else:
        for idx, item in enumerate(checklist):
            if not isinstance(item, str) or not item.strip():
                problems.append(f"remote_network_checklist[{idx}] must be a non-empty string")

    return [f"{path}: {problem}" for problem in problems]


def render_markdown(results: list[tuple[Path, list[str]]]) -> str:
    lines = ["# Network Discovery Bundle Validation", ""]
    for bundle_path, errors in results:
        lines.append(f"## `{bundle_path}`")
        lines.append("")
        if errors:
            lines.extend(f"- {error}" for error in errors)
        else:
            lines.append("- Validation passed.")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    if args.max_age_seconds <= 0:
        raise SystemExit("--max-age-seconds must be > 0")

    config = ValidationConfig(
        max_age_seconds=args.max_age_seconds,
        require_verifier_keys=args.require_verifier_keys,
        require_daemon_active=args.require_daemon_active,
        require_socket_present=args.require_socket_present,
    )

    bundle_paths = collect_bundle_paths(args)
    all_results: list[tuple[Path, list[str]]] = []
    overall_errors: list[str] = []

    for bundle_path in bundle_paths:
        if not bundle_path.is_file():
            errors = [f"{bundle_path}: bundle file does not exist"]
            all_results.append((bundle_path, errors))
            overall_errors.extend(errors)
            continue
        try:
            payload = json.loads(bundle_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors = [f"{bundle_path}: invalid JSON ({exc})"]
            all_results.append((bundle_path, errors))
            overall_errors.extend(errors)
            continue
        errors = validate_bundle(bundle_path, payload, config)
        all_results.append((bundle_path, errors))
        overall_errors.extend(errors)

    if args.output:
        output_path = Path(args.output).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(render_markdown(all_results), encoding="utf-8")

    if overall_errors:
        for item in overall_errors:
            print(item)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
