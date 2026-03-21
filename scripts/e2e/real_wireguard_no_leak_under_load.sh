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

for cmd in ip wg nft ping timeout tcpdump cargo; do
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

send_udp_probe() {
  local namespace="$1"
  local ip="$2"
  local port="$3"
  local payload="$4"
  ns "${namespace}" env RUSTYNET_UDP_PAYLOAD="${payload}" timeout 2 bash -lc "printf '%s' \"\$RUSTYNET_UDP_PAYLOAD\" >/dev/udp/${ip}/${port}"
}

write_json_report() {
  local tunnel_up_status="$1"
  local load_ping_status="$2"
  local tunnel_down_block_status="$3"

  local environment="${RUSTYNET_NO_LEAK_ENVIRONMENT:-lab-netns}"
  local captured_at_utc
  local captured_at_unix
  local overall
  captured_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  captured_at_unix="$(date -u +%s)"
  overall="$(
    cargo run --quiet -p rustynet-cli -- ops write-real-wireguard-no-leak-under-load-report \
      --report-path "${REPORT_PATH}" \
      --load-pcap "${LOAD_PCAP}" \
      --down-pcap "${DOWN_PCAP}" \
      --tunnel-up-status "${tunnel_up_status}" \
      --load-ping-status "${load_ping_status}" \
      --tunnel-down-block-status "${tunnel_down_block_status}" \
      --environment "${environment}" \
      --captured-at-utc "${captured_at_utc}" \
      --captured-at-unix "${captured_at_unix}"
  )"
  [[ "${overall}" == "pass" ]]
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
load_probe_end=$((SECONDS + 4))
while (( SECONDS < load_probe_end )); do
  send_udp_probe "${NS_CLIENT}" "198.18.0.1" "53" "rustynet-load" >/dev/null 2>&1 || true
  sleep 0.02
done

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

for _ in {1..8}; do
  send_udp_probe "${NS_CLIENT}" "198.18.0.1" "53" "rustynet-down" >/dev/null 2>&1 || true
done

sleep 1
kill "${TCPDUMP_DOWN_PID}" >/dev/null 2>&1 || true
wait "${TCPDUMP_DOWN_PID}" >/dev/null 2>&1 || true
TCPDUMP_DOWN_PID=""

write_json_report "${TUNNEL_UP_STATUS}" "${LOAD_PING_STATUS}" "${TUNNEL_DOWN_BLOCK_STATUS}"
echo "No-leak dataplane report written to ${REPORT_PATH}"
