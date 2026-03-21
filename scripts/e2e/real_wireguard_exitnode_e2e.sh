#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/local/sbin:/usr/sbin:/sbin:${PATH}"
umask 077

REPORT_PATH="${RUSTYNET_E2E_REPORT_PATH:-artifacts/phase10/netns_e2e_report.json}"
RUNTIME_DIR="${RUSTYNET_E2E_RUNTIME_DIR:-/tmp/rustynet-e2e}"
mkdir -p "$(dirname "${REPORT_PATH}")" "${RUNTIME_DIR}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "real_wireguard_exitnode_e2e.sh must run as root" >&2
  exit 1
fi

for cmd in ip wg nft ping timeout cargo tcpdump; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "missing required command: ${cmd}" >&2
    exit 1
  fi
done

NS_CLIENT="ryn-client-$$"
NS_EXIT="ryn-exit-$$"
NS_INET="ryn-inet-$$"
NS_LAN="ryn-lan-$$"
DNS_SERVER_IP="198.18.0.1"
DNS_SERVER_PORT="53"

KEY_DIR="${RUNTIME_DIR}/keys-$$"
mkdir -p "${KEY_DIR}"

cleanup() {
  set +e
  ip netns del "${NS_CLIENT}" >/dev/null 2>&1 || true
  ip netns del "${NS_EXIT}" >/dev/null 2>&1 || true
  ip netns del "${NS_INET}" >/dev/null 2>&1 || true
  ip netns del "${NS_LAN}" >/dev/null 2>&1 || true
  rm -rf "${KEY_DIR}"
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

send_udp_probe() {
  local namespace="$1"
  local ip="$2"
  local port="$3"
  local payload="$4"
  ns "${namespace}" env RUSTYNET_UDP_PAYLOAD="${payload}" timeout 2 bash -lc "printf '%s' \"\$RUSTYNET_UDP_PAYLOAD\" >/dev/udp/${ip}/${port}"
}

write_json_report() {
  local exit_status="$1"
  local lan_off_status="$2"
  local lan_on_status="$3"
  local dns_up_status="$4"
  local kill_switch_status="$5"
  local dns_down_status="$6"

  local environment="${RUSTYNET_PHASE10_E2E_ENVIRONMENT:-lab-netns}"
  local captured_at_utc
  local captured_at_unix
  local overall
  captured_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  captured_at_unix="$(date -u +%s)"
  overall="$(
    cargo run --quiet -p rustynet-cli -- ops write-real-wireguard-exitnode-e2e-report \
      --report-path "${REPORT_PATH}" \
      --exit-status "${exit_status}" \
      --lan-off-status "${lan_off_status}" \
      --lan-on-status "${lan_on_status}" \
      --dns-up-status "${dns_up_status}" \
      --kill-switch-status "${kill_switch_status}" \
      --dns-down-status "${dns_down_status}" \
      --environment "${environment}" \
      --captured-at-utc "${captured_at_utc}" \
      --captured-at-unix "${captured_at_unix}"
  )"
  [[ "${overall}" == "pass" ]]
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

EXIT_STATUS="fail"
LAN_OFF_STATUS="fail"
LAN_ON_STATUS="fail"
DNS_UP_STATUS="fail"
KILL_SWITCH_STATUS="fail"
DNS_DOWN_STATUS="fail"

if run_expect_success ns "${NS_CLIENT}" ping -c 1 -W 1 "${DNS_SERVER_IP}"; then
  EXIT_STATUS="pass"
fi

if run_expect_failure ns "${NS_CLIENT}" ping -c 1 -W 1 192.168.50.2; then
  LAN_OFF_STATUS="pass"
fi

ns "${NS_EXIT}" nft add rule inet rustynet_e2e forward iifname "wg0" oifname "veth_el_e" ip daddr 192.168.50.0/24 accept
if run_expect_success ns "${NS_CLIENT}" ping -c 1 -W 1 192.168.50.2; then
  LAN_ON_STATUS="pass"
fi

ns "${NS_INET}" timeout 4 tcpdump -ni veth_ei_i -c 1 "udp and dst host ${DNS_SERVER_IP} and dst port ${DNS_SERVER_PORT}" >/dev/null 2>&1 &
dns_up_capture_pid=$!
sleep 0.2
if run_expect_success send_udp_probe "${NS_CLIENT}" "${DNS_SERVER_IP}" "${DNS_SERVER_PORT}" "dns-probe-up"; then
  if wait "${dns_up_capture_pid}"; then
    DNS_UP_STATUS="pass"
  fi
else
  wait "${dns_up_capture_pid}" >/dev/null 2>&1 || true
fi

ns "${NS_CLIENT}" ip link set wg0 down
ns "${NS_CLIENT}" ip route del default dev wg0 >/dev/null 2>&1 || true

if run_expect_failure ns "${NS_CLIENT}" ping -c 1 -W 1 "${DNS_SERVER_IP}"; then
  KILL_SWITCH_STATUS="pass"
fi

ns "${NS_INET}" timeout 3 tcpdump -ni veth_ei_i -c 1 "udp and dst host ${DNS_SERVER_IP} and dst port ${DNS_SERVER_PORT}" >/dev/null 2>&1 &
dns_down_capture_pid=$!
sleep 0.2
dns_down_send_failed=0
if ! send_udp_probe "${NS_CLIENT}" "${DNS_SERVER_IP}" "${DNS_SERVER_PORT}" "dns-probe-down"; then
  dns_down_send_failed=1
fi
if wait "${dns_down_capture_pid}"; then
  :
else
  dns_down_capture_rc=$?
  if [[ "${dns_down_capture_rc}" -eq 124 && "${dns_down_send_failed}" -eq 1 ]]; then
    DNS_DOWN_STATUS="pass"
  fi
fi

write_json_report "${EXIT_STATUS}" "${LAN_OFF_STATUS}" "${LAN_ON_STATUS}" "${DNS_UP_STATUS}" "${KILL_SWITCH_STATUS}" "${DNS_DOWN_STATUS}"
echo "E2E report written to ${REPORT_PATH}"
