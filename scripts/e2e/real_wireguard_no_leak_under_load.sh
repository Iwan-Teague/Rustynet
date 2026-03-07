#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/local/sbin:/usr/sbin:/sbin:${PATH}"
umask 077

REPORT_PATH="${RUSTYNET_NO_LEAK_REPORT_PATH:-artifacts/phase10/no_leak_dataplane_report.json}"
RUNTIME_DIR="${RUSTYNET_NO_LEAK_RUNTIME_DIR:-/tmp/rustynet-no-leak-gate}"
mkdir -p "$(dirname "${REPORT_PATH}")" "${RUNTIME_DIR}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "real_wireguard_no_leak_under_load.sh must run as root" >&2
  exit 1
fi

for cmd in ip wg nft python3 ping timeout tcpdump; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "missing required command: ${cmd}" >&2
    exit 1
  fi
done

NS_CLIENT="rnleak-client-$$"
NS_EXIT="rnleak-exit-$$"
NS_INET="rnleak-inet-$$"

KEY_DIR="${RUNTIME_DIR}/keys-$$"
LOAD_PCAP="${RUNTIME_DIR}/underlay-load-$$.pcap"
DOWN_PCAP="${RUNTIME_DIR}/underlay-down-$$.pcap"
mkdir -p "${KEY_DIR}"

TCPDUMP_LOAD_PID=""
TCPDUMP_DOWN_PID=""

cleanup() {
  set +e
  if [[ -n "${TCPDUMP_LOAD_PID}" ]]; then
    kill "${TCPDUMP_LOAD_PID}" >/dev/null 2>&1 || true
    wait "${TCPDUMP_LOAD_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${TCPDUMP_DOWN_PID}" ]]; then
    kill "${TCPDUMP_DOWN_PID}" >/dev/null 2>&1 || true
    wait "${TCPDUMP_DOWN_PID}" >/dev/null 2>&1 || true
  fi
  ip netns del "${NS_CLIENT}" >/dev/null 2>&1 || true
  ip netns del "${NS_EXIT}" >/dev/null 2>&1 || true
  ip netns del "${NS_INET}" >/dev/null 2>&1 || true
  rm -rf "${KEY_DIR}" "${LOAD_PCAP}" "${DOWN_PCAP}"
}
trap cleanup EXIT

ns() {
  local namespace="$1"
  shift
  ip netns exec "${namespace}" "$@"
}

ip netns add "${NS_CLIENT}"
ip netns add "${NS_EXIT}"
ip netns add "${NS_INET}"

for namespace in "${NS_CLIENT}" "${NS_EXIT}" "${NS_INET}"; do
  ns "${namespace}" ip link set lo up
done

ip link add veth_ce_c type veth peer name veth_ce_e
ip link set veth_ce_c netns "${NS_CLIENT}"
ip link set veth_ce_e netns "${NS_EXIT}"
ns "${NS_CLIENT}" ip addr add 172.16.10.2/24 dev veth_ce_c
ns "${NS_EXIT}" ip addr add 172.16.10.1/24 dev veth_ce_e
ns "${NS_CLIENT}" ip link set veth_ce_c up
ns "${NS_EXIT}" ip link set veth_ce_e up

ip link add veth_ei_e type veth peer name veth_ei_i
ip link set veth_ei_e netns "${NS_EXIT}"
ip link set veth_ei_i netns "${NS_INET}"
ns "${NS_EXIT}" ip addr add 198.18.0.2/24 dev veth_ei_e
ns "${NS_INET}" ip addr add 198.18.0.1/24 dev veth_ei_i
ns "${NS_EXIT}" ip link set veth_ei_e up
ns "${NS_INET}" ip link set veth_ei_i up

ns "${NS_CLIENT}" wg genkey >"${KEY_DIR}/client.key"
ns "${NS_EXIT}" wg genkey >"${KEY_DIR}/exit.key"
ns "${NS_CLIENT}" wg pubkey <"${KEY_DIR}/client.key" >"${KEY_DIR}/client.pub"
ns "${NS_EXIT}" wg pubkey <"${KEY_DIR}/exit.key" >"${KEY_DIR}/exit.pub"
CLIENT_PUB="$(cat "${KEY_DIR}/client.pub")"
EXIT_PUB="$(cat "${KEY_DIR}/exit.pub")"

ns "${NS_EXIT}" ip link add wg0 type wireguard
ns "${NS_EXIT}" ip addr add 100.64.0.1/24 dev wg0
ns "${NS_EXIT}" wg set wg0 private-key "${KEY_DIR}/exit.key" listen-port 51820 peer "${CLIENT_PUB}" allowed-ips 100.64.0.2/32
ns "${NS_EXIT}" ip link set wg0 up

ns "${NS_CLIENT}" ip link add wg0 type wireguard
ns "${NS_CLIENT}" ip addr add 100.64.0.2/32 dev wg0
ns "${NS_CLIENT}" wg set wg0 private-key "${KEY_DIR}/client.key" peer "${EXIT_PUB}" endpoint 172.16.10.1:51820 allowed-ips 0.0.0.0/0 persistent-keepalive 5
ns "${NS_CLIENT}" ip link set wg0 up
ns "${NS_CLIENT}" ip route replace default dev wg0

ns "${NS_EXIT}" sysctl -w net.ipv4.ip_forward=1 >/dev/null
ns "${NS_EXIT}" nft -f - <<'NFT'
table inet rustynet_noleak {
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "wg0" oifname "veth_ei_e" accept
  }
}

table ip rustynet_noleak_nat {
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    oifname "veth_ei_e" ip saddr 100.64.0.0/10 masquerade
  }
}
NFT

TUNNEL_UP_STATUS="fail"
LOAD_PING_STATUS="fail"
TUNNEL_DOWN_BLOCK_STATUS="fail"

if ns "${NS_CLIENT}" ping -c 2 -W 1 198.18.0.1 >/dev/null 2>&1; then
  TUNNEL_UP_STATUS="pass"
fi

ns "${NS_CLIENT}" tcpdump -i veth_ce_c -nn -U -w "${LOAD_PCAP}" "ip and src host 172.16.10.2" >/dev/null 2>&1 &
TCPDUMP_LOAD_PID=$!
sleep 1

if ns "${NS_CLIENT}" timeout 6 ping -i 0.05 -W 1 198.18.0.1 >/dev/null 2>&1; then
  LOAD_PING_STATUS="pass"
fi
ns "${NS_CLIENT}" python3 - <<'PY'
import socket
import time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
end = time.time() + 4.0
while time.time() < end:
    sock.sendto(b"rustynet-load", ("198.18.0.1", 53))
    time.sleep(0.02)
sock.close()
PY

sleep 1
kill "${TCPDUMP_LOAD_PID}" >/dev/null 2>&1 || true
wait "${TCPDUMP_LOAD_PID}" >/dev/null 2>&1 || true
TCPDUMP_LOAD_PID=""

ns "${NS_CLIENT}" ip link set wg0 down

ns "${NS_CLIENT}" tcpdump -i veth_ce_c -nn -U -w "${DOWN_PCAP}" "ip and src host 172.16.10.2" >/dev/null 2>&1 &
TCPDUMP_DOWN_PID=$!
sleep 1

if ! ns "${NS_CLIENT}" timeout 4 ping -i 0.2 -W 1 198.18.0.1 >/dev/null 2>&1; then
  TUNNEL_DOWN_BLOCK_STATUS="pass"
fi

ns "${NS_CLIENT}" python3 - <<'PY' >/dev/null 2>&1 || true
import socket
for _ in range(8):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(b"rustynet-down", ("198.18.0.1", 53))
    finally:
        sock.close()
PY

sleep 1
kill "${TCPDUMP_DOWN_PID}" >/dev/null 2>&1 || true
wait "${TCPDUMP_DOWN_PID}" >/dev/null 2>&1 || true
TCPDUMP_DOWN_PID=""

ENVIRONMENT="${RUSTYNET_NO_LEAK_ENVIRONMENT:-lab-netns}"
python3 - "${LOAD_PCAP}" "${DOWN_PCAP}" "${REPORT_PATH}" "${TUNNEL_UP_STATUS}" "${LOAD_PING_STATUS}" "${TUNNEL_DOWN_BLOCK_STATUS}" "${ENVIRONMENT}" <<'PY'
import json
import subprocess
import sys
from datetime import datetime, timezone

(
    load_pcap,
    down_pcap,
    report_path,
    tunnel_up_status,
    load_ping_status,
    tunnel_down_block_status,
    environment,
) = sys.argv[1:]


def tcpdump_lines(path: str):
    result = subprocess.run(
        ["tcpdump", "-nn", "-r", path],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in (0, 1):
        raise SystemExit(f"tcpdump decode failed for {path}: {result.stderr.strip()}")
    return result.stdout.splitlines()


def count_tunnel_packets(lines):
    return sum(
        1
        for line in lines
        if "IP 172.16.10.2." in line and " > 172.16.10.1.51820: UDP" in line
    )


def count_cleartext_packets(lines):
    return sum(
        1
        for line in lines
        if "IP 172.16.10.2" in line and " > 198.18.0.1" in line
    )


load_lines = tcpdump_lines(load_pcap)
down_lines = tcpdump_lines(down_pcap)

load_tunnel_packets = count_tunnel_packets(load_lines)
load_cleartext_packets = count_cleartext_packets(load_lines)
down_cleartext_packets = count_cleartext_packets(down_lines)

checks = {
    "tunnel_up_connectivity": tunnel_up_status,
    "load_ping_success": load_ping_status,
    "tunnel_transport_observed_under_load": "pass" if load_tunnel_packets > 0 else "fail",
    "no_underlay_cleartext_during_load": "pass" if load_cleartext_packets == 0 else "fail",
    "tunnel_down_fail_closed": tunnel_down_block_status,
    "no_underlay_cleartext_after_tunnel_down": "pass" if down_cleartext_packets == 0 else "fail",
}
overall = "pass" if all(value == "pass" for value in checks.values()) else "fail"

captured_at = datetime.now(timezone.utc)
report = {
    "phase": "phase10",
    "mode": "real_netns_no_leak_under_load",
    "evidence_mode": "measured",
    "environment": environment,
    "captured_at": captured_at.isoformat(),
    "captured_at_unix": int(captured_at.timestamp()),
    "status": overall,
    "checks": checks,
    "metrics": {
        "load_tunnel_packets": load_tunnel_packets,
        "load_cleartext_packets": load_cleartext_packets,
        "down_cleartext_packets": down_cleartext_packets,
    },
    "source_artifacts": [load_pcap, down_pcap],
}

with open(report_path, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2)
    fh.write("\n")

if overall != "pass":
    raise SystemExit("no-leak dataplane gate failed")
PY

echo "No-leak dataplane report written to ${REPORT_PATH}"
