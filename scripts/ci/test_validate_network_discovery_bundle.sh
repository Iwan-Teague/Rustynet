#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT

now_unix="$(date +%s)"
stale_unix="$((now_unix - 99999))"
handshake_unix="$((now_unix - 5))"

default_key_b64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

auto_bundle() {
  local output_path="$1"
  local collected_at_unix="$2"
  local assignment_key_b64="$3"
  local host_endpoint="$4"
  local add_secret_like="$5"

  local extra_field_line=""
  if [[ "$add_secret_like" == "yes" ]]; then
    extra_field_line='  "leaked_private_key": "abc",'
  fi

  cat >"$output_path" <<JSON
{
  "schema_version": 1,
  "collected_at_unix": ${collected_at_unix},
  "collected_at_iso": "2026-03-19T00:00:00Z",
  "purpose": "cross_network_discovery_bundle",
  "note": "test bundle",
  "node_identity": {
    "node_id": "client-1",
    "hostname": "client-1.local",
    "os": "Linux Debian",
    "kernel": "6.8.0",
    "arch": "x86_64"
  },
  "wireguard": {
    "interface": "rustynet0",
    "public_key": "${default_key_b64}",
    "listen_port": 51820,
    "interface_addresses": "100.64.0.2/32",
    "peer_stanza_template": "[Peer]\\nPublicKey = ${default_key_b64}\\n"
  },
  "endpoint_candidates": [
    {
      "type": "host",
      "endpoint": "${host_endpoint}",
      "address": "192.168.1.10",
      "prefix_len": "24",
      "priority": 120
    },
    {
      "type": "server_reflexive",
      "endpoint": "203.0.113.10:51820",
      "address": "203.0.113.10",
      "priority": 200
    },
    {
      "type": "relay",
      "endpoint": "",
      "priority": 50,
      "note": "relay assigned by control plane"
    }
  ],
  "nat_profile": {
    "behind_nat": true,
    "first_lan_ip": "192.168.1.10",
    "detected_public_ip": "203.0.113.10",
    "port_forwarded_hint": "assumed_no",
    "recommended_traversal_strategy": "hole_punch_or_relay"
  },
  "verifier_keys": {
    "note": "verifier keys",
    "assignment_verifier_key_b64": "${assignment_key_b64}",
    "traversal_verifier_key_b64": "${default_key_b64}",
    "dns_zone_verifier_key_b64": "${default_key_b64}",
    "trust_evidence_verifier_key_b64": "${default_key_b64}"
  },
  "rustynet_artifacts": {
    "assignment_bundle": {
      "path": "/var/lib/rustynet/rustynetd.assignment",
      "exists": true,
      "size_bytes": 100,
      "mtime_unix": $((now_unix - 10))
    },
    "traversal_bundle": {
      "path": "/var/lib/rustynet/rustynetd.traversal",
      "exists": true,
      "size_bytes": 100,
      "mtime_unix": $((now_unix - 10))
    },
    "membership_snapshot": {
      "path": "/var/lib/rustynet/membership.snapshot",
      "exists": true,
      "size_bytes": 100,
      "mtime_unix": $((now_unix - 10))
    },
    "membership_log": {
      "path": "/var/lib/rustynet/membership.log",
      "exists": true,
      "size_bytes": 100,
      "mtime_unix": $((now_unix - 10))
    },
    "dns_zone_bundle": {
      "path": "/var/lib/rustynet/rustynetd.dns-zone",
      "exists": true,
      "size_bytes": 100,
      "mtime_unix": $((now_unix - 10))
    },
    "trust_evidence": {
      "path": "/var/lib/rustynet/rustynetd.trust",
      "exists": true,
      "size_bytes": 100,
      "mtime_unix": $((now_unix - 10))
    }
  },
  "daemon_status": {
    "active": "active",
    "pid": "1234",
    "socket_path": "/run/rustynet/rustynetd.sock",
    "socket_present": true
  },
  "known_peers": [
    {
      "public_key": "${default_key_b64}",
      "endpoint": "198.51.100.20:51820",
      "allowed_ips": "100.64.0.3/32",
      "latest_handshake_unix": ${handshake_unix},
      "rx_bytes": 10,
      "tx_bytes": 20
    }
  ],
${extra_field_line}
  "remote_network_checklist": [
    "1. add node",
    "2. issue bundles"
  ]
}
JSON
}

auto_bundle "$temp_dir/valid.json" "$now_unix" "$default_key_b64" "192.168.1.10:51820" no
auto_bundle "$temp_dir/invalid_stale.json" "$stale_unix" "$default_key_b64" "192.168.1.10:51820" no
auto_bundle "$temp_dir/invalid_missing_verifier_key.json" "$now_unix" "" "192.168.1.10:51820" no
auto_bundle "$temp_dir/invalid_endpoint.json" "$now_unix" "$default_key_b64" "not-an-endpoint" no
auto_bundle "$temp_dir/invalid_secret_like.json" "$now_unix" "$default_key_b64" "192.168.1.10:51820" yes

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
