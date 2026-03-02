#!/usr/bin/env bash
set -euo pipefail

REPORT_PATH="${RUSTYNET_E2E_REPORT_PATH:-artifacts/phase10/netns_e2e_report.json}"
RUNTIME_DIR="${RUSTYNET_E2E_RUNTIME_DIR:-/tmp/rustynet-e2e}"
mkdir -p "$(dirname "${REPORT_PATH}")" "${RUNTIME_DIR}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "real_wireguard_exitnode_e2e.sh must run as root" >&2
  exit 1
fi

for cmd in ip wg nft python3 ping timeout; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "missing required command: ${cmd}" >&2
    exit 1
  fi
done

NS_CLIENT="ryn-client-$$"
NS_EXIT="ryn-exit-$$"
NS_INET="ryn-inet-$$"
NS_LAN="ryn-lan-$$"

KEY_DIR="${RUNTIME_DIR}/keys-$$"
DNS_COUNT_FILE="${RUNTIME_DIR}/dns-count-$$.txt"
DNS_SERVER_LOG="${RUNTIME_DIR}/dns-server-$$.log"
mkdir -p "${KEY_DIR}"

DNS_PID=""

cleanup() {
  set +e
  if [[ -n "${DNS_PID}" ]]; then
    kill "${DNS_PID}" >/dev/null 2>&1 || true
    wait "${DNS_PID}" >/dev/null 2>&1 || true
  fi
  ip netns del "${NS_CLIENT}" >/dev/null 2>&1 || true
  ip netns del "${NS_EXIT}" >/dev/null 2>&1 || true
  ip netns del "${NS_INET}" >/dev/null 2>&1 || true
  ip netns del "${NS_LAN}" >/dev/null 2>&1 || true
  rm -rf "${KEY_DIR}" "${DNS_COUNT_FILE}" "${DNS_SERVER_LOG}"
}
trap cleanup EXIT

ns() {
  local namespace="$1"
  shift
  ip netns exec "${namespace}" "$@"
}

run_expect_success() {
  "$@" >/dev/null 2>&1
}

run_expect_failure() {
  if "$@" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

write_json_report() {
  local exit_status="$1"
  local lan_off_status="$2"
  local lan_on_status="$3"
  local dns_up_status="$4"
  local kill_switch_status="$5"
  local dns_down_status="$6"
  local overall="fail"

  if [[ "${exit_status}" == "pass" \
     && "${lan_off_status}" == "pass" \
     && "${lan_on_status}" == "pass" \
     && "${dns_up_status}" == "pass" \
     && "${kill_switch_status}" == "pass" \
     && "${dns_down_status}" == "pass" ]]; then
    overall="pass"
  fi

  local environment="${RUSTYNET_PHASE10_E2E_ENVIRONMENT:-lab-netns}"
  python3 - "$REPORT_PATH" "$overall" "$exit_status" "$lan_off_status" "$lan_on_status" "$dns_up_status" "$kill_switch_status" "$dns_down_status" "$environment" <<'PY'
import json
import sys
from datetime import datetime, timezone

(
    report_path,
    overall,
    exit_status,
    lan_off_status,
    lan_on_status,
    dns_up_status,
    kill_switch_status,
    dns_down_status,
    environment,
) = sys.argv[1:]

captured_at = datetime.now(timezone.utc)
report = {
    "phase": "phase10",
    "mode": "real_netns_wireguard",
    "evidence_mode": "measured",
    "environment": environment,
    "captured_at": captured_at.isoformat(),
    "captured_at_unix": int(captured_at.timestamp()),
    "status": overall,
    "checks": {
        "exit_node_routing": exit_status,
        "lan_toggle_off_blocks": lan_off_status,
        "lan_toggle_on_allows": lan_on_status,
        "dns_reaches_protected_path_when_tunnel_up": dns_up_status,
        "kill_switch_blocks_egress_when_tunnel_down": kill_switch_status,
        "dns_fail_close_when_tunnel_down": dns_down_status,
    },
}

with open(report_path, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2)
    fh.write("\n")
PY

  if [[ "${overall}" != "pass" ]]; then
    return 1
  fi
  return 0
}

# Namespaces and loopback.
ip netns add "${NS_CLIENT}"
ip netns add "${NS_EXIT}"
ip netns add "${NS_INET}"
ip netns add "${NS_LAN}"

for namespace in "${NS_CLIENT}" "${NS_EXIT}" "${NS_INET}" "${NS_LAN}"; do
  ns "${namespace}" ip link set lo up
done

# Underlay between client and exit.
ip link add veth_ce_c type veth peer name veth_ce_e
ip link set veth_ce_c netns "${NS_CLIENT}"
ip link set veth_ce_e netns "${NS_EXIT}"
ns "${NS_CLIENT}" ip addr add 172.16.10.2/24 dev veth_ce_c
ns "${NS_EXIT}" ip addr add 172.16.10.1/24 dev veth_ce_e
ns "${NS_CLIENT}" ip link set veth_ce_c up
ns "${NS_EXIT}" ip link set veth_ce_e up

# Exit egress toward inet namespace.
ip link add veth_ei_e type veth peer name veth_ei_i
ip link set veth_ei_e netns "${NS_EXIT}"
ip link set veth_ei_i netns "${NS_INET}"
ns "${NS_EXIT}" ip addr add 198.18.0.2/24 dev veth_ei_e
ns "${NS_INET}" ip addr add 198.18.0.1/24 dev veth_ei_i
ns "${NS_EXIT}" ip link set veth_ei_e up
ns "${NS_INET}" ip link set veth_ei_i up

# Exit LAN subnet.
ip link add veth_el_e type veth peer name veth_el_l
ip link set veth_el_e netns "${NS_EXIT}"
ip link set veth_el_l netns "${NS_LAN}"
ns "${NS_EXIT}" ip addr add 192.168.50.1/24 dev veth_el_e
ns "${NS_LAN}" ip addr add 192.168.50.2/24 dev veth_el_l
ns "${NS_EXIT}" ip link set veth_el_e up
ns "${NS_LAN}" ip link set veth_el_l up

# Route LAN replies back through exit.
ns "${NS_LAN}" ip route add 100.64.0.0/10 via 192.168.50.1

# Generate key material.
ns "${NS_CLIENT}" wg genkey >"${KEY_DIR}/client.key"
ns "${NS_EXIT}" wg genkey >"${KEY_DIR}/exit.key"
ns "${NS_CLIENT}" wg pubkey <"${KEY_DIR}/client.key" >"${KEY_DIR}/client.pub"
ns "${NS_EXIT}" wg pubkey <"${KEY_DIR}/exit.key" >"${KEY_DIR}/exit.pub"
CLIENT_PUB="$(cat "${KEY_DIR}/client.pub")"
EXIT_PUB="$(cat "${KEY_DIR}/exit.pub")"

# WireGuard interfaces.
ns "${NS_EXIT}" ip link add wg0 type wireguard
ns "${NS_EXIT}" ip addr add 100.64.0.1/24 dev wg0
ns "${NS_EXIT}" wg set wg0 private-key "${KEY_DIR}/exit.key" listen-port 51820 peer "${CLIENT_PUB}" allowed-ips 100.64.0.2/32
ns "${NS_EXIT}" ip link set wg0 up

ns "${NS_CLIENT}" ip link add wg0 type wireguard
ns "${NS_CLIENT}" ip addr add 100.64.0.2/32 dev wg0
ns "${NS_CLIENT}" wg set wg0 private-key "${KEY_DIR}/client.key" peer "${EXIT_PUB}" endpoint 172.16.10.1:51820 allowed-ips 0.0.0.0/0 persistent-keepalive 5
ns "${NS_CLIENT}" ip link set wg0 up
ns "${NS_CLIENT}" ip route replace default dev wg0

# Exit forwarding + NAT with LAN blocked by default.
ns "${NS_EXIT}" sysctl -w net.ipv4.ip_forward=1 >/dev/null
ns "${NS_EXIT}" nft -f - <<'NFT'
table inet rustynet_e2e {
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "wg0" oifname "veth_ei_e" accept
  }
}

table ip rustynet_e2e_nat {
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    oifname "veth_ei_e" ip saddr 100.64.0.0/10 masquerade
  }
}
NFT

# UDP DNS probe sink in inet namespace.
echo 0 >"${DNS_COUNT_FILE}"
ns "${NS_INET}" python3 - "${DNS_COUNT_FILE}" >"${DNS_SERVER_LOG}" 2>&1 <<'PY' &
import pathlib
import socket
import sys

count_file = pathlib.Path(sys.argv[1])
count = 0
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("198.18.0.1", 53))
while True:
    sock.recvfrom(2048)
    count += 1
    count_file.write_text(str(count), encoding="utf-8")
PY
DNS_PID=$!
sleep 1

EXIT_STATUS="fail"
LAN_OFF_STATUS="fail"
LAN_ON_STATUS="fail"
DNS_UP_STATUS="fail"
KILL_SWITCH_STATUS="fail"
DNS_DOWN_STATUS="fail"

if run_expect_success ns "${NS_CLIENT}" ping -c 1 -W 1 198.18.0.1; then
  EXIT_STATUS="pass"
fi

if run_expect_failure ns "${NS_CLIENT}" ping -c 1 -W 1 192.168.50.2; then
  LAN_OFF_STATUS="pass"
fi

ns "${NS_EXIT}" nft add rule inet rustynet_e2e forward iifname "wg0" oifname "veth_el_e" ip daddr 192.168.50.0/24 accept
if run_expect_success ns "${NS_CLIENT}" ping -c 1 -W 1 192.168.50.2; then
  LAN_ON_STATUS="pass"
fi

before_dns="$(cat "${DNS_COUNT_FILE}")"
if run_expect_success ns "${NS_CLIENT}" python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b"dns-probe-up", ("198.18.0.1", 53)); s.close()'; then
  sleep 1
  after_dns="$(cat "${DNS_COUNT_FILE}")"
  if [[ "${after_dns}" -gt "${before_dns}" ]]; then
    DNS_UP_STATUS="pass"
  fi
fi

ns "${NS_CLIENT}" ip link set wg0 down
ns "${NS_CLIENT}" ip route del default dev wg0 >/dev/null 2>&1 || true

if run_expect_failure ns "${NS_CLIENT}" ping -c 1 -W 1 198.18.0.1; then
  KILL_SWITCH_STATUS="pass"
fi

before_dns_down="$(cat "${DNS_COUNT_FILE}")"
if run_expect_failure ns "${NS_CLIENT}" python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b"dns-probe-down", ("198.18.0.1", 53)); s.close()'; then
  sleep 1
  after_dns_down="$(cat "${DNS_COUNT_FILE}")"
  if [[ "${after_dns_down}" -eq "${before_dns_down}" ]]; then
    DNS_DOWN_STATUS="pass"
  fi
fi

write_json_report "${EXIT_STATUS}" "${LAN_OFF_STATUS}" "${LAN_ON_STATUS}" "${DNS_UP_STATUS}" "${KILL_SWITCH_STATUS}" "${DNS_DOWN_STATUS}"
echo "E2E report written to ${REPORT_PATH}"
