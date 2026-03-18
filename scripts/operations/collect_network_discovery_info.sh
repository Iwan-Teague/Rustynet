#!/usr/bin/env bash
# collect_network_discovery_info.sh
#
# Collects all information a remote Rustynet network needs to discover and
# connect to devices on this network.  Run this on every node you want to
# expose cross-network, then share the resulting JSON bundle with the
# administrator of the remote network so they can provision matching
# traversal/assignment bundles pointing at this node.
#
# Output (JSON) includes:
#   - Node identity  (hostname, OS, node-id, WireGuard public key)
#   - Endpoint candidates  (host / server-reflexive / relay)
#   - WireGuard peer config stanza ready to paste into wg-quick
#   - Rustynet artifact status  (which signed bundles exist on this node)
#   - Known peers  (other nodes already peered here)
#   - NAT profile hints  (mapping/filtering behaviour detected locally)
#
# Usage:
#   ./collect_network_discovery_info.sh [OPTIONS]
#
# Options:
#   -o, --output <path>      Write JSON to <path> instead of stdout
#   -i, --interface <iface>  WireGuard interface to inspect (default: auto-detect)
#   -p, --wg-port <port>     WireGuard listen port override (default: 51820)
#   -n, --node-id <id>       Rustynet node-id (default: read from config or hostname)
#   -q, --quiet              Suppress progress messages on stderr
#   -h, --help               Show this help
#
# Dependencies (all standard on Debian/Ubuntu):
#   bash, ip, wg (wireguard-tools), curl or wget, hostname, uname, jq
#   Optional: dig or nslookup (DNS candidate verification)
#
# Security note:
#   This script reads only public information (public keys, IP addresses,
#   port numbers, artifact existence flags).  It never reads, prints, or
#   transmits private keys or secrets.

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
OUTPUT_PATH=""
WG_IFACE=""
WG_PORT_OVERRIDE=""
NODE_ID_OVERRIDE=""
QUIET=0

# Rustynet state paths (match rustynetd daemon defaults)
RUSTYNET_STATE_DIR="/var/lib/rustynet"
RUSTYNET_CONFIG_DIR="/etc/rustynet"
RUSTYNET_RUN_DIR="/run/rustynet"

ASSIGNMENT_BUNDLE="${RUSTYNET_STATE_DIR}/rustynetd.assignment"
TRAVERSAL_BUNDLE="${RUSTYNET_STATE_DIR}/rustynetd.traversal"
MEMBERSHIP_SNAPSHOT="${RUSTYNET_STATE_DIR}/membership.snapshot"
MEMBERSHIP_LOG="${RUSTYNET_STATE_DIR}/membership.log"
DNS_ZONE_BUNDLE="${RUSTYNET_STATE_DIR}/rustynetd.dns-zone"
TRUST_EVIDENCE="${RUSTYNET_STATE_DIR}/rustynetd.trust"
WG_PUBLIC_KEY_PATH="${RUSTYNET_STATE_DIR}/keys/wireguard.pub"

ASSIGNMENT_PUB_KEY="${RUSTYNET_CONFIG_DIR}/assignment.pub"
TRAVERSAL_PUB_KEY="${RUSTYNET_CONFIG_DIR}/traversal.pub"
TRUST_PUB_KEY="${RUSTYNET_CONFIG_DIR}/trust-evidence.pub"
DNS_ZONE_PUB_KEY="${RUSTYNET_CONFIG_DIR}/dns-zone.pub"
MEMBERSHIP_OWNER_KEY="${RUSTYNET_CONFIG_DIR}/membership.owner.key"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { [[ "$QUIET" -eq 0 ]] && echo "[collect-discovery] $*" >&2 || true; }
die() { echo "[collect-discovery] ERROR: $*" >&2; exit 1; }

usage() {
    grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \{0,1\}//'
    exit 0
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Required command '$1' not found. Install it and retry."
}

file_exists_flag() {
    [[ -f "$1" ]] && echo "true" || echo "false"
}

# Safely read the first line of a file; return empty string on error
read_first_line() {
    local f="$1"
    [[ -f "$f" ]] && head -n1 "$f" 2>/dev/null || echo ""
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output)    OUTPUT_PATH="$2"; shift 2 ;;
        -i|--interface) WG_IFACE="$2";    shift 2 ;;
        -p|--wg-port)   WG_PORT_OVERRIDE="$2"; shift 2 ;;
        -n|--node-id)   NODE_ID_OVERRIDE="$2"; shift 2 ;;
        -q|--quiet)     QUIET=1; shift ;;
        -h|--help)      usage ;;
        *) die "Unknown option: $1  (use --help for usage)" ;;
    esac
done

# ---------------------------------------------------------------------------
# 1. Dependency checks
# ---------------------------------------------------------------------------
log "Checking dependencies..."
require_cmd ip
require_cmd hostname
require_cmd uname

WG_AVAILABLE=0
command -v wg >/dev/null 2>&1 && WG_AVAILABLE=1

JQ_AVAILABLE=0
command -v jq >/dev/null 2>&1 && JQ_AVAILABLE=1

CURL_AVAILABLE=0
command -v curl >/dev/null 2>&1 && CURL_AVAILABLE=1

WGET_AVAILABLE=0
command -v wget >/dev/null 2>&1 && WGET_AVAILABLE=1

if [[ "$WG_AVAILABLE" -eq 0 ]]; then
    log "WARNING: 'wg' (wireguard-tools) not found – WireGuard fields will be empty."
fi

# ---------------------------------------------------------------------------
# 2. System identity
# ---------------------------------------------------------------------------
log "Collecting system identity..."
HOSTNAME_VAL="$(hostname -f 2>/dev/null || hostname)"
OS_NAME="$(uname -s)"
OS_RELEASE=""
if [[ -f /etc/os-release ]]; then
    OS_RELEASE="$(. /etc/os-release && echo "${PRETTY_NAME:-${NAME:-unknown}}")"
elif [[ -f /etc/issue ]]; then
    OS_RELEASE="$(head -n1 /etc/issue | tr -d '\n')"
fi
OS_FULL="${OS_NAME} ${OS_RELEASE}"
KERNEL="$(uname -r)"
ARCH="$(uname -m)"
COLLECTED_AT="$(date -u +%s)"
COLLECTED_AT_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---------------------------------------------------------------------------
# 3. Node identity
# ---------------------------------------------------------------------------
log "Resolving Rustynet node identity..."

# Prefer explicit override, then node-id file, then hostname
NODE_ID=""
if [[ -n "$NODE_ID_OVERRIDE" ]]; then
    NODE_ID="$NODE_ID_OVERRIDE"
elif [[ -f "${RUSTYNET_STATE_DIR}/node-id" ]]; then
    NODE_ID="$(read_first_line "${RUSTYNET_STATE_DIR}/node-id")"
elif [[ -f "${RUSTYNET_CONFIG_DIR}/node-id" ]]; then
    NODE_ID="$(read_first_line "${RUSTYNET_CONFIG_DIR}/node-id")"
fi
# Fallback: use hostname-derived ID
[[ -z "$NODE_ID" ]] && NODE_ID="${HOSTNAME_VAL}"

# ---------------------------------------------------------------------------
# 4. WireGuard interface detection
# ---------------------------------------------------------------------------
log "Detecting WireGuard interface..."

detect_wg_interface() {
    # Try common Rustynet/WireGuard interface names
    for iface in rustynet0 wg0 wg1 rustynet1; do
        if ip link show "$iface" >/dev/null 2>&1; then
            echo "$iface"; return 0
        fi
    done
    # Fall back to first interface reported by wg if available
    if [[ "$WG_AVAILABLE" -eq 1 ]]; then
        local first
        first="$(wg show interfaces 2>/dev/null | awk '{print $1; exit}')"
        [[ -n "$first" ]] && echo "$first" && return 0
    fi
    echo ""
}

if [[ -z "$WG_IFACE" ]]; then
    WG_IFACE="$(detect_wg_interface)"
fi

if [[ -z "$WG_IFACE" ]]; then
    log "WARNING: No WireGuard interface found. WireGuard fields will be empty."
fi

# ---------------------------------------------------------------------------
# 5. WireGuard public key and listen port
# ---------------------------------------------------------------------------
log "Reading WireGuard configuration..."

WG_PUBLIC_KEY=""
WG_LISTEN_PORT=""
WG_IFACE_ADDRESSES=""

# Try to read the public key from the Rustynet key store first (preferred –
# avoids needing to run wg as root)
if [[ -f "$WG_PUBLIC_KEY_PATH" ]]; then
    WG_PUBLIC_KEY="$(read_first_line "$WG_PUBLIC_KEY_PATH")"
    log "Public key read from ${WG_PUBLIC_KEY_PATH}"
fi

if [[ -n "$WG_IFACE" && "$WG_AVAILABLE" -eq 1 ]]; then
    # wg show may need root; try with sudo if available and needed
    WG_SHOW_OUTPUT=""
    if wg show "$WG_IFACE" >/dev/null 2>&1; then
        WG_SHOW_OUTPUT="$(wg show "$WG_IFACE" 2>/dev/null)"
    elif command -v sudo >/dev/null 2>&1 && sudo -n wg show "$WG_IFACE" >/dev/null 2>&1; then
        WG_SHOW_OUTPUT="$(sudo wg show "$WG_IFACE" 2>/dev/null)"
    fi

    if [[ -n "$WG_SHOW_OUTPUT" ]]; then
        # Extract public key from wg show if not already loaded from file
        if [[ -z "$WG_PUBLIC_KEY" ]]; then
            WG_PUBLIC_KEY="$(echo "$WG_SHOW_OUTPUT" | awk '/^  public key:/{print $3; exit}')"
            # wg show all format uses different spacing
            [[ -z "$WG_PUBLIC_KEY" ]] && \
                WG_PUBLIC_KEY="$(echo "$WG_SHOW_OUTPUT" | awk '/public key:/{print $NF; exit}')"
        fi
        WG_LISTEN_PORT="$(echo "$WG_SHOW_OUTPUT" | awk '/listening port:/{print $NF; exit}')"
    fi

    # Collect IP addresses assigned to the WireGuard interface
    WG_IFACE_ADDRESSES="$(ip -4 addr show "$WG_IFACE" 2>/dev/null | \
        awk '/inet /{print $2}' | tr '\n' ' ' | sed 's/ $//')"
fi

# Apply port override or default
if [[ -n "$WG_PORT_OVERRIDE" ]]; then
    WG_LISTEN_PORT="$WG_PORT_OVERRIDE"
elif [[ -z "$WG_LISTEN_PORT" ]]; then
    WG_LISTEN_PORT="51820"
fi

# ---------------------------------------------------------------------------
# 6. Host endpoint candidates – local network interfaces
# ---------------------------------------------------------------------------
log "Collecting local interface addresses (host candidates)..."

collect_host_candidates() {
    # Collect all non-loopback, non-WireGuard IPv4 addresses with their
    # broadcast scope, skipping link-local (169.254.x.x)
    ip -4 addr show 2>/dev/null | awk '
        /^[0-9]+: / {
            iface = $2
            sub(/:$/, "", iface)
            # Skip loopback and the WireGuard interface itself
            skip = (iface == "lo" || iface == "'"$WG_IFACE"'")
        }
        /inet / && !skip {
            split($2, a, "/")
            ip = a[1]
            prefix = a[2]
            # Skip link-local
            if (ip !~ /^169\.254\./) {
                print ip ":" prefix
            }
        }
    '
}

HOST_CANDIDATES_RAW="$(collect_host_candidates)"

# ---------------------------------------------------------------------------
# 7. Server-reflexive (public) IP detection
# ---------------------------------------------------------------------------
log "Detecting public/reflexive IP address..."

detect_public_ip() {
    local ip=""
    # Try multiple echo services in order; stop on first success
    local services=(
        "https://api4.ipify.org"
        "https://icanhazip.com"
        "https://ipv4.icanhazip.com"
        "https://checkip.amazonaws.com"
        "https://ifconfig.me/ip"
    )
    for svc in "${services[@]}"; do
        if [[ "$CURL_AVAILABLE" -eq 1 ]]; then
            ip="$(curl -s --max-time 5 --retry 1 "$svc" 2>/dev/null | tr -d '[:space:]')"
        elif [[ "$WGET_AVAILABLE" -eq 1 ]]; then
            ip="$(wget -qO- --timeout=5 "$svc" 2>/dev/null | tr -d '[:space:]')"
        fi
        # Validate that we got something that looks like an IPv4 address
        if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            echo "$ip"; return 0
        fi
    done
    echo ""
}

if [[ "$CURL_AVAILABLE" -eq 1 || "$WGET_AVAILABLE" -eq 1 ]]; then
    PUBLIC_IP="$(detect_public_ip)"
    if [[ -n "$PUBLIC_IP" ]]; then
        log "Detected public IP: ${PUBLIC_IP}"
    else
        log "WARNING: Could not detect public IP. Server-reflexive candidate will be empty."
    fi
else
    log "WARNING: Neither curl nor wget available. Skipping public IP detection."
    PUBLIC_IP=""
fi

# ---------------------------------------------------------------------------
# 8. NAT profile hints
# ---------------------------------------------------------------------------
log "Gathering NAT profile hints..."

# Determine if this node is behind NAT by comparing first LAN IP to public IP
FIRST_LAN_IP="$(echo "$HOST_CANDIDATES_RAW" | head -n1 | cut -d: -f1)"
BEHIND_NAT="false"
if [[ -n "$PUBLIC_IP" && -n "$FIRST_LAN_IP" && "$PUBLIC_IP" != "$FIRST_LAN_IP" ]]; then
    BEHIND_NAT="true"
fi

# Check if WireGuard port is likely reachable – compare listen port to default
PORT_FORWARDED_HINT="unknown"
if [[ "$BEHIND_NAT" == "true" ]]; then
    PORT_FORWARDED_HINT="assumed_no – node is behind NAT; manual port-forward or relay may be required"
else
    PORT_FORWARDED_HINT="likely_yes – public IP matches local IP (no NAT detected)"
fi

# ---------------------------------------------------------------------------
# 9. WireGuard peers already configured on this node
# ---------------------------------------------------------------------------
log "Collecting existing WireGuard peer list..."

collect_wg_peers() {
    [[ -z "$WG_IFACE" || "$WG_AVAILABLE" -eq 0 ]] && echo "[]" && return

    local wg_dump=""
    if wg show "$WG_IFACE" dump >/dev/null 2>&1; then
        wg_dump="$(wg show "$WG_IFACE" dump 2>/dev/null)"
    elif command -v sudo >/dev/null 2>&1 && sudo -n wg show "$WG_IFACE" dump >/dev/null 2>&1; then
        wg_dump="$(sudo wg show "$WG_IFACE" dump 2>/dev/null)"
    fi

    [[ -z "$wg_dump" ]] && echo "[]" && return

    # wg show <iface> dump:
    #   line 1: own private-key public-key listen-port fwmark
    #   lines 2+: peer-pubkey preshared-key endpoint allowed-ips latest-handshake rx-bytes tx-bytes keepalive
    local peers_json="["
    local first=1
    while IFS=$'\t' read -r pubkey psk endpoint allowed_ips handshake rx tx keepalive; do
        # Skip the first (own interface) line
        [[ "$first" -eq 1 ]] && first=0 && continue

        # Sanitise fields (replace empty/missing with empty string)
        pubkey="${pubkey:-}"
        endpoint="${endpoint:-}"
        allowed_ips="${allowed_ips:-}"
        handshake="${handshake:-0}"
        rx="${rx:-0}"
        tx="${tx:-0}"

        # Skip placeholder "(none)" endpoint
        [[ "$endpoint" == "(none)" ]] && endpoint=""

        [[ "$peers_json" != "[" ]] && peers_json+=","
        peers_json+=$(printf '{"public_key":"%s","endpoint":"%s","allowed_ips":"%s","latest_handshake_unix":%s,"rx_bytes":%s,"tx_bytes":%s}' \
            "$pubkey" "$endpoint" "$allowed_ips" "$handshake" "$rx" "$tx")
    done <<<"$wg_dump"
    peers_json+="]"
    echo "$peers_json"
}

WG_PEERS_JSON="$(collect_wg_peers)"

# ---------------------------------------------------------------------------
# 10. Rustynet artifact inventory
# ---------------------------------------------------------------------------
log "Inventorying Rustynet signed artifacts..."

artifact_entry() {
    local label="$1" path="$2"
    local exists size mtime
    exists="$(file_exists_flag "$path")"
    if [[ "$exists" == "true" ]]; then
        size="$(stat -c%s "$path" 2>/dev/null || echo 0)"
        mtime="$(stat -c%Y "$path" 2>/dev/null || echo 0)"
    else
        size=0; mtime=0
    fi
    printf '"%s":{"path":"%s","exists":%s,"size_bytes":%s,"mtime_unix":%s}' \
        "$label" "$path" "$exists" "$size" "$mtime"
}

# Read the assignment verifier public key (safe – it is a public key, not secret)
ASSIGNMENT_PUB_KEY_B64=""
if [[ -f "$ASSIGNMENT_PUB_KEY" ]]; then
    ASSIGNMENT_PUB_KEY_B64="$(cat "$ASSIGNMENT_PUB_KEY" 2>/dev/null | tr -d '[:space:]')"
fi

TRAVERSAL_PUB_KEY_B64=""
if [[ -f "$TRAVERSAL_PUB_KEY" ]]; then
    TRAVERSAL_PUB_KEY_B64="$(cat "$TRAVERSAL_PUB_KEY" 2>/dev/null | tr -d '[:space:]')"
fi

DNS_ZONE_PUB_KEY_B64=""
if [[ -f "$DNS_ZONE_PUB_KEY" ]]; then
    DNS_ZONE_PUB_KEY_B64="$(cat "$DNS_ZONE_PUB_KEY" 2>/dev/null | tr -d '[:space:]')"
fi

TRUST_PUB_KEY_B64=""
if [[ -f "$TRUST_PUB_KEY" ]]; then
    TRUST_PUB_KEY_B64="$(cat "$TRUST_PUB_KEY" 2>/dev/null | tr -d '[:space:]')"
fi

# ---------------------------------------------------------------------------
# 11. Daemon / service status
# ---------------------------------------------------------------------------
log "Checking rustynetd service status..."

DAEMON_ACTIVE="unknown"
DAEMON_PID=""
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet rustynetd 2>/dev/null; then
        DAEMON_ACTIVE="active"
        DAEMON_PID="$(systemctl show rustynetd --property=MainPID --value 2>/dev/null || echo "")"
    else
        DAEMON_ACTIVE="inactive"
    fi
elif [[ -S "${RUSTYNET_RUN_DIR}/rustynetd.sock" ]]; then
    DAEMON_ACTIVE="socket_present"
fi

# ---------------------------------------------------------------------------
# 12. Build the JSON discovery bundle
# ---------------------------------------------------------------------------
log "Building discovery bundle..."

# Build endpoint candidates JSON array
ENDPOINT_CANDIDATES="["
CANDIDATE_SEP=""

# Host candidates (all non-loopback LAN IPs)
while IFS=: read -r ip prefix; do
    [[ -z "$ip" ]] && continue
    # Assign priority by address class (RFC1918 private get higher priority)
    priority=100
    if [[ "$ip" =~ ^10\. ]]; then priority=110
    elif [[ "$ip" =~ ^192\.168\. ]]; then priority=120
    elif [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; then priority=115
    fi
    ENDPOINT_CANDIDATES+="${CANDIDATE_SEP}"
    ENDPOINT_CANDIDATES+=$(printf '{"type":"host","endpoint":"%s:%s","address":"%s","prefix_len":"%s","priority":%d}' \
        "$ip" "$WG_LISTEN_PORT" "$ip" "$prefix" "$priority")
    CANDIDATE_SEP=","
done <<<"$HOST_CANDIDATES_RAW"

# Server-reflexive candidate (public IP discovered via echo service)
if [[ -n "$PUBLIC_IP" ]]; then
    ENDPOINT_CANDIDATES+="${CANDIDATE_SEP}"
    ENDPOINT_CANDIDATES+=$(printf '{"type":"server_reflexive","endpoint":"%s:%s","address":"%s","priority":200,"note":"public IP detected via HTTP echo; assumes port %s is forwarded through NAT"}' \
        "$PUBLIC_IP" "$WG_LISTEN_PORT" "$PUBLIC_IP" "$WG_LISTEN_PORT")
    CANDIDATE_SEP=","
fi

# Relay placeholder (populated by the control plane, not directly discoverable here)
ENDPOINT_CANDIDATES+="${CANDIDATE_SEP}"
ENDPOINT_CANDIDATES+='{"type":"relay","endpoint":"","priority":50,"note":"relay address is assigned by the Rustynet relay fleet; provision via signed traversal bundle"}'

ENDPOINT_CANDIDATES+="]"

# WireGuard peer stanza (what the remote admin pastes into their wg-quick config)
WG_PEER_STANZA=""
if [[ -n "$WG_PUBLIC_KEY" ]]; then
    WG_PEER_STANZA="[Peer]\n"
    WG_PEER_STANZA+="# Node: ${NODE_ID}  (${HOSTNAME_VAL})\n"
    WG_PEER_STANZA+="PublicKey = ${WG_PUBLIC_KEY}\n"
    if [[ -n "$PUBLIC_IP" ]]; then
        WG_PEER_STANZA+="Endpoint = ${PUBLIC_IP}:${WG_LISTEN_PORT}\n"
    elif [[ -n "$FIRST_LAN_IP" ]]; then
        WG_PEER_STANZA+="Endpoint = ${FIRST_LAN_IP}:${WG_LISTEN_PORT}  # LAN only – no public IP detected\n"
    fi
    WG_PEER_STANZA+="AllowedIPs = <REPLACE_WITH_RUSTYNET_VPN_CIDR>  # e.g. 100.64.0.0/10\n"
    WG_PEER_STANZA+="PersistentKeepalive = 25"
fi

# Final JSON output
# We build it manually to avoid a hard dependency on jq at runtime.
JSON_OUTPUT=$(cat <<JSON
{
  "schema_version": 1,
  "collected_at_unix": ${COLLECTED_AT},
  "collected_at_iso": "${COLLECTED_AT_ISO}",
  "purpose": "cross_network_discovery_bundle",
  "note": "Share this bundle with the remote network administrator. They need the node_identity, wireguard, endpoint_candidates, and verifier_keys sections to configure a signed traversal/assignment bundle pointing at this node.",

  "node_identity": {
    "node_id": "${NODE_ID}",
    "hostname": "${HOSTNAME_VAL}",
    "os": "${OS_FULL}",
    "kernel": "${KERNEL}",
    "arch": "${ARCH}"
  },

  "wireguard": {
    "interface": "${WG_IFACE}",
    "public_key": "${WG_PUBLIC_KEY}",
    "listen_port": ${WG_LISTEN_PORT},
    "interface_addresses": "${WG_IFACE_ADDRESSES}",
    "peer_stanza_template": "$(echo -e "$WG_PEER_STANZA" | sed 's/"/\\"/g' | tr '\n' '|' | sed 's/|/\\n/g')"
  },

  "endpoint_candidates": ${ENDPOINT_CANDIDATES},

  "nat_profile": {
    "behind_nat": ${BEHIND_NAT},
    "first_lan_ip": "${FIRST_LAN_IP}",
    "detected_public_ip": "${PUBLIC_IP}",
    "port_forwarded_hint": "${PORT_FORWARDED_HINT}",
    "recommended_traversal_strategy": "$(
        if [[ "$BEHIND_NAT" == "false" ]]; then
            echo "direct – use server_reflexive or host candidate"
        else
            echo "hole_punch_or_relay – node is behind NAT; provision relay candidate in traversal bundle"
        fi
    )"
  },

  "verifier_keys": {
    "note": "Remote network must trust these public keys to verify signed bundles originating from this network.",
    "assignment_verifier_key_b64": "${ASSIGNMENT_PUB_KEY_B64}",
    "traversal_verifier_key_b64": "${TRAVERSAL_PUB_KEY_B64}",
    "dns_zone_verifier_key_b64": "${DNS_ZONE_PUB_KEY_B64}",
    "trust_evidence_verifier_key_b64": "${TRUST_PUB_KEY_B64}"
  },

  "rustynet_artifacts": {
    $(artifact_entry "assignment_bundle" "$ASSIGNMENT_BUNDLE"),
    $(artifact_entry "traversal_bundle" "$TRAVERSAL_BUNDLE"),
    $(artifact_entry "membership_snapshot" "$MEMBERSHIP_SNAPSHOT"),
    $(artifact_entry "membership_log" "$MEMBERSHIP_LOG"),
    $(artifact_entry "dns_zone_bundle" "$DNS_ZONE_BUNDLE"),
    $(artifact_entry "trust_evidence" "$TRUST_EVIDENCE")
  },

  "daemon_status": {
    "active": "${DAEMON_ACTIVE}",
    "pid": "${DAEMON_PID}",
    "socket_path": "${RUSTYNET_RUN_DIR}/rustynetd.sock",
    "socket_present": $(file_exists_flag "${RUSTYNET_RUN_DIR}/rustynetd.sock")
  },

  "known_peers": ${WG_PEERS_JSON},

  "remote_network_checklist": [
    "1. Add an entry for this node in your network's membership snapshot with node_id and wireguard.public_key.",
    "2. Sign a new assignment bundle that includes this node as a peer with AllowedIPs covering this node's Rustynet VPN address.",
    "3. Create a traversal bundle for your nodes targeting this node using one of the endpoint_candidates (prefer server_reflexive if available, then host, then relay).",
    "4. Distribute the signed assignment and traversal bundles to all nodes on your network that need to reach this node.",
    "5. Verify DNS zone bundle includes a record for this node's hostname if Magic DNS is in use.",
    "6. If this node is behind NAT (nat_profile.behind_nat=true), ensure a relay candidate is provisioned or port-forwarding is configured.",
    "7. Confirm latest-handshake with: sudo wg show <iface> latest-handshakes (expect a recent timestamp after peering).",
    "8. All bundles must be signed with keys trusted by both networks. Exchange verifier_keys.assignment_verifier_key_b64 with the remote CA."
  ]
}
JSON
)

# ---------------------------------------------------------------------------
# 13. Output
# ---------------------------------------------------------------------------
if [[ -n "$OUTPUT_PATH" ]]; then
    # Write to file
    mkdir -p "$(dirname "$OUTPUT_PATH")"
    if [[ "$JQ_AVAILABLE" -eq 1 ]]; then
        echo "$JSON_OUTPUT" | jq '.' > "$OUTPUT_PATH"
    else
        echo "$JSON_OUTPUT" > "$OUTPUT_PATH"
    fi
    log "Discovery bundle written to: ${OUTPUT_PATH}"
    # Print a short summary to stderr for the operator
    echo ""
    echo "=== Cross-Network Discovery Summary ===" >&2
    echo "  Node ID      : ${NODE_ID}" >&2
    echo "  Hostname     : ${HOSTNAME_VAL}" >&2
    echo "  WG Public Key: ${WG_PUBLIC_KEY:-<not found>}" >&2
    echo "  WG Port      : ${WG_LISTEN_PORT}" >&2
    echo "  Public IP    : ${PUBLIC_IP:-<not detected>}" >&2
    echo "  Behind NAT   : ${BEHIND_NAT}" >&2
    echo "  Daemon       : ${DAEMON_ACTIVE}" >&2
    echo "  Output file  : ${OUTPUT_PATH}" >&2
    echo "=======================================" >&2
else
    # Print to stdout (optionally pretty-print with jq)
    if [[ "$JQ_AVAILABLE" -eq 1 ]]; then
        echo "$JSON_OUTPUT" | jq '.'
    else
        echo "$JSON_OUTPUT"
    fi
fi

log "Done."
