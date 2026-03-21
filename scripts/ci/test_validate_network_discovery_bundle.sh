#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT

now_unix="$(date +%s)"

python3 - "$temp_dir" "$now_unix" <<'PY'
import json
import sys
from pathlib import Path

temp_dir = Path(sys.argv[1])
now_unix = int(sys.argv[2])

base = {
    "schema_version": 1,
    "collected_at_unix": now_unix,
    "collected_at_iso": "2026-03-19T00:00:00Z",
    "purpose": "cross_network_discovery_bundle",
    "note": "test bundle",
    "node_identity": {
        "node_id": "client-1",
        "hostname": "client-1.local",
        "os": "Linux Debian",
        "kernel": "6.8.0",
        "arch": "x86_64",
    },
    "wireguard": {
        "interface": "rustynet0",
        "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "listen_port": 51820,
        "interface_addresses": "100.64.0.2/32",
        "peer_stanza_template": "[Peer]\\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\\n",
    },
    "endpoint_candidates": [
        {"type": "host", "endpoint": "192.168.1.10:51820", "address": "192.168.1.10", "prefix_len": "24", "priority": 120},
        {"type": "server_reflexive", "endpoint": "203.0.113.10:51820", "address": "203.0.113.10", "priority": 200},
        {"type": "relay", "endpoint": "", "priority": 50, "note": "relay assigned by control plane"},
    ],
    "nat_profile": {
        "behind_nat": True,
        "first_lan_ip": "192.168.1.10",
        "detected_public_ip": "203.0.113.10",
        "port_forwarded_hint": "assumed_no",
        "recommended_traversal_strategy": "hole_punch_or_relay",
    },
    "verifier_keys": {
        "note": "verifier keys",
        "assignment_verifier_key_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "traversal_verifier_key_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "dns_zone_verifier_key_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "trust_evidence_verifier_key_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    },
    "rustynet_artifacts": {
        "assignment_bundle": {"path": "/var/lib/rustynet/rustynetd.assignment", "exists": True, "size_bytes": 100, "mtime_unix": now_unix - 10},
        "traversal_bundle": {"path": "/var/lib/rustynet/rustynetd.traversal", "exists": True, "size_bytes": 100, "mtime_unix": now_unix - 10},
        "membership_snapshot": {"path": "/var/lib/rustynet/membership.snapshot", "exists": True, "size_bytes": 100, "mtime_unix": now_unix - 10},
        "membership_log": {"path": "/var/lib/rustynet/membership.log", "exists": True, "size_bytes": 100, "mtime_unix": now_unix - 10},
        "dns_zone_bundle": {"path": "/var/lib/rustynet/rustynetd.dns-zone", "exists": True, "size_bytes": 100, "mtime_unix": now_unix - 10},
        "trust_evidence": {"path": "/var/lib/rustynet/rustynetd.trust", "exists": True, "size_bytes": 100, "mtime_unix": now_unix - 10},
    },
    "daemon_status": {
        "active": "active",
        "pid": "1234",
        "socket_path": "/run/rustynet/rustynetd.sock",
        "socket_present": True,
    },
    "known_peers": [
        {
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "endpoint": "198.51.100.20:51820",
            "allowed_ips": "100.64.0.3/32",
            "latest_handshake_unix": now_unix - 5,
            "rx_bytes": 10,
            "tx_bytes": 20,
        }
    ],
    "remote_network_checklist": [
        "1. add node",
        "2. issue bundles",
    ],
}

def write(name: str, payload: dict) -> None:
    (temp_dir / name).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

write("valid.json", base)

stale = dict(base)
stale["collected_at_unix"] = now_unix - 99999
write("invalid_stale.json", stale)

missing_key = json.loads(json.dumps(base))
missing_key["verifier_keys"]["assignment_verifier_key_b64"] = ""
write("invalid_missing_verifier_key.json", missing_key)

bad_endpoint = json.loads(json.dumps(base))
bad_endpoint["endpoint_candidates"][0]["endpoint"] = "not-an-endpoint"
write("invalid_endpoint.json", bad_endpoint)

secret_like = json.loads(json.dumps(base))
secret_like["leaked_private_key"] = "abc"
write("invalid_secret_like.json", secret_like)
PY

cargo run --quiet -p rustynet-cli -- ops validate-network-discovery-bundle \
  --bundle "$temp_dir/valid.json" \
  --max-age-seconds 900 \
  --require-verifier-keys \
  --require-daemon-active \
  --require-socket-present \
  --output "$temp_dir/valid.md"

if cargo run --quiet -p rustynet-cli -- ops validate-network-discovery-bundle \
  --bundle "$temp_dir/invalid_stale.json" \
  --max-age-seconds 900; then
  echo "expected invalid_stale.json to fail validation" >&2
  exit 1
fi

if cargo run --quiet -p rustynet-cli -- ops validate-network-discovery-bundle \
  --bundle "$temp_dir/invalid_missing_verifier_key.json" \
  --max-age-seconds 900 \
  --require-verifier-keys; then
  echo "expected invalid_missing_verifier_key.json to fail validation" >&2
  exit 1
fi

if cargo run --quiet -p rustynet-cli -- ops validate-network-discovery-bundle \
  --bundle "$temp_dir/invalid_endpoint.json" \
  --max-age-seconds 900 \
  --require-verifier-keys; then
  echo "expected invalid_endpoint.json to fail validation" >&2
  exit 1
fi

if cargo run --quiet -p rustynet-cli -- ops validate-network-discovery-bundle \
  --bundle "$temp_dir/invalid_secret_like.json" \
  --max-age-seconds 900 \
  --require-verifier-keys; then
  echo "expected invalid_secret_like.json to fail validation" >&2
  exit 1
fi

echo "Network discovery bundle validation tests: PASS"
