#!/usr/bin/env bash
# vxlan_tier_b.sh - D5.1 Tier B VXLAN-overlay cross-NAT lab driver.
#
# Builds isolated VXLAN "home LANs" over the flat UTM bridge. The script only
# kills simulator processes it started and recorded by PID. It never pkill's
# rustynetd; daemon setup is delegated to the existing rustynet bootstrap verb.
set -euo pipefail

SSH_BIN="${SSH_BIN:-ssh}"
SSH_USER="${SSH_USER:-debian}"
SSH_IDENTITY="${SSH_IDENTITY:-${HOME}/.ssh/rustynet_lab_ed25519}"
SSH_KNOWN_HOSTS="${SSH_KNOWN_HOSTS:-${HOME}/.ssh/known_hosts}"
REMOTE_REPO="${REMOTE_REPO:-/home/debian/Rustynet}"
STATE_ROOT="${STATE_ROOT:-/tmp/rustynet-tier-b}"
NETWORK_ID="${NETWORK_ID:-tier-b-vxlan}"
PROFILE_A="${PROFILE_A:-port_restricted_cone}"
PROFILE_B="${PROFILE_B:-port_restricted_cone}"
UDP_PORTS_A="${UDP_PORTS_A:-51820-51859}"
UDP_PORTS_B="${UDP_PORTS_B:-51860-51900}"

NODE_A_HOST="${NODE_A_HOST:-192.168.0.200}"      # debian-headless-1
NODE_B_HOST="${NODE_B_HOST:-192.168.0.201}"      # debian-headless-2
SVC_HOST="${SVC_HOST:-192.168.0.202}"            # debian-headless-3
ROUTER_HOST="${ROUTER_HOST:-192.168.0.203}"      # debian-headless-4
WORK_HOST="${WORK_HOST:-192.168.0.204}"          # debian-headless-5

NODE_A_VX="172.16.10.2/24"
NODE_A_GW="172.16.10.1"
NODE_B_VX="172.16.20.2/24"
NODE_B_GW="172.16.20.1"
ROUTER_A_VX="172.16.10.1/24"
ROUTER_B_VX="172.16.20.1/24"
ROUTER_WAN_VX="10.200.0.11/24"
SVC_VX="10.200.0.254/24"
VXLAN_PORT="${VXLAN_PORT:-4789}"
STUN_PORT="${STUN_PORT:-3478}"

ssh_opts() {
  printf '%s\n' \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="${SSH_KNOWN_HOSTS}" \
    -i "${SSH_IDENTITY}"
}

sq() {
  printf "%s" "$1" | sed "s/'/'\\\\''/g"
}

remote() {
  local host="$1" cmd="$2"
  # shellcheck disable=SC2046
  "$SSH_BIN" $(ssh_opts) "${SSH_USER}@${host}" "sudo -n bash -lc '$(sq "$cmd")'"
}

remote_user() {
  local host="$1" cmd="$2"
  # shellcheck disable=SC2046
  "$SSH_BIN" $(ssh_opts) "${SSH_USER}@${host}" "bash -lc '$(sq "$cmd")'"
}

underlay_dev_cmd='ip route get __PEER__ | awk '"'"'{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}'"'"''

vxlan_leaf_cmd() {
  local vni="$1" local_ip="$2" remote_ip="$3" addr="$4" gw="$5" link="$6"
  cat <<EOF
set -euo pipefail
mkdir -p "$STATE_ROOT"
dev=\$(${underlay_dev_cmd/__PEER__/$remote_ip})
ip link del "$link" 2>/dev/null || true
ip route show default > "$STATE_ROOT/default.route.$link" 2>/dev/null || true
ip link add "$link" type vxlan id "$vni" local "$local_ip" remote "$remote_ip" dev "\$dev" dstport "$VXLAN_PORT" nolearning
ip addr replace "$addr" dev "$link"
ip link set "$link" up
ip route replace default via "$gw" dev "$link" metric 500
EOF
}

vxlan_router_cmd() {
  cat <<EOF
set -euo pipefail
mkdir -p "$STATE_ROOT"
dev_a=\$(ip route get "$NODE_A_HOST" | awk '{for (i=1;i<=NF;i++) if (\$i=="dev") {print \$(i+1); exit}}')
dev_b=\$(ip route get "$NODE_B_HOST" | awk '{for (i=1;i<=NF;i++) if (\$i=="dev") {print \$(i+1); exit}}')
dev_s=\$(ip route get "$SVC_HOST" | awk '{for (i=1;i<=NF;i++) if (\$i=="dev") {print \$(i+1); exit}}')
for link in vxlan100 vxlan200 vxlan1; do ip link del "\$link" 2>/dev/null || true; done
ip link add vxlan100 type vxlan id 100 local "$ROUTER_HOST" remote "$NODE_A_HOST" dev "\$dev_a" dstport "$VXLAN_PORT" nolearning
ip addr replace "$ROUTER_A_VX" dev vxlan100
ip link set vxlan100 up
ip link add vxlan200 type vxlan id 200 local "$ROUTER_HOST" remote "$NODE_B_HOST" dev "\$dev_b" dstport "$VXLAN_PORT" nolearning
ip addr replace "$ROUTER_B_VX" dev vxlan200
ip link set vxlan200 up
ip link add vxlan1 type vxlan id 1 local "$ROUTER_HOST" remote "$SVC_HOST" dev "\$dev_s" dstport "$VXLAN_PORT" nolearning
ip addr replace "$ROUTER_WAN_VX" dev vxlan1
ip link set vxlan1 up
sysctl -qw net.ipv4.ip_forward=1
EOF
}

vxlan_svc_cmd() {
  cat <<EOF
set -euo pipefail
mkdir -p "$STATE_ROOT"
dev=\$(ip route get "$ROUTER_HOST" | awk '{for (i=1;i<=NF;i++) if (\$i=="dev") {print \$(i+1); exit}}')
ip link del vxlan1 2>/dev/null || true
ip link add vxlan1 type vxlan id 1 local "$SVC_HOST" remote "$ROUTER_HOST" dev "\$dev" dstport "$VXLAN_PORT" nolearning
ip addr replace "$SVC_VX" dev vxlan1
ip link set vxlan1 up
EOF
}

install_combined_nat_cmd() {
  cat <<EOF
set -euo pipefail
table=rustynet_tier_b_nat
nft delete table ip "\$table" 2>/dev/null || true
nft delete table ip rustynet_natlab 2>/dev/null || true
nft add table ip "\$table"
nft add chain ip "\$table" postrouting '{ type nat hook postrouting priority srcnat; policy accept; }'
case "$PROFILE_A" in
  port_restricted_cone) nft add rule ip "\$table" postrouting oifname vxlan1 ip saddr 172.16.10.0/24 masquerade ;;
  symmetric) nft add rule ip "\$table" postrouting oifname vxlan1 ip saddr 172.16.10.0/24 masquerade random ;;
  full_cone)
    nft add chain ip "\$table" prerouting '{ type nat hook prerouting priority dstnat; policy accept; }' 2>/dev/null || true
    nft add rule ip "\$table" postrouting oifname vxlan1 ip saddr 172.16.10.0/24 masquerade
    nft add rule ip "\$table" prerouting iifname vxlan1 udp dport "$UDP_PORTS_A" dnat to 172.16.10.2
    ;;
  *) echo "unsupported PROFILE_A=$PROFILE_A" >&2; exit 2 ;;
esac
case "$PROFILE_B" in
  port_restricted_cone) nft add rule ip "\$table" postrouting oifname vxlan1 ip saddr 172.16.20.0/24 masquerade ;;
  symmetric) nft add rule ip "\$table" postrouting oifname vxlan1 ip saddr 172.16.20.0/24 masquerade random ;;
  full_cone)
    nft add chain ip "\$table" prerouting '{ type nat hook prerouting priority dstnat; policy accept; }' 2>/dev/null || true
    nft add rule ip "\$table" postrouting oifname vxlan1 ip saddr 172.16.20.0/24 masquerade
    nft add rule ip "\$table" prerouting iifname vxlan1 udp dport "$UDP_PORTS_B" dnat to 172.16.20.2
    ;;
  *) echo "unsupported PROFILE_B=$PROFILE_B" >&2; exit 2 ;;
esac
printf 'profile_a=%s profile_b=%s wan_if=vxlan1 lan_a=vxlan100 lan_b=vxlan200\n' "$PROFILE_A" "$PROFILE_B" > /run/rustynet_tier_b_nat_profile
EOF
}

start_stun_cmd() {
  cat <<EOF
set -euo pipefail
mkdir -p "$STATE_ROOT"
if [ -f "$STATE_ROOT/stun.pid" ]; then
  old=\$(cat "$STATE_ROOT/stun.pid")
  kill "\$old" 2>/dev/null || true
  rm -f "$STATE_ROOT/stun.pid"
fi
nohup python3 "$REMOTE_REPO/scripts/vm_lab/stun_responder.py" --bind 10.200.0.254 --port "$STUN_PORT" >"$STATE_ROOT/stun.log" 2>&1 &
echo \$! > "$STATE_ROOT/stun.pid"
EOF
}

teardown_cmd() {
  cat <<EOF
set -euo pipefail
for pidfile in "$STATE_ROOT/stun.pid" "$STATE_ROOT/node-a/rustynetd.pid" "$STATE_ROOT/node-b/rustynetd.pid"; do
  if [ -f "\$pidfile" ]; then
    pid=\$(cat "\$pidfile")
    kill "\$pid" 2>/dev/null || true
    rm -f "\$pidfile"
  fi
done
nft delete table ip rustynet_tier_b_nat 2>/dev/null || true
nft delete table ip rustynet_natlab 2>/dev/null || true
for link in vxlan100 vxlan200 vxlan1; do ip link del "\$link" 2>/dev/null || true; done
for saved in "$STATE_ROOT"/default.route.vxlan*; do
  [ -s "\$saved" ] || continue
  ip route replace \$(cat "\$saved") 2>/dev/null || true
done
EOF
}

setup() {
  remote "$NODE_A_HOST" "$(vxlan_leaf_cmd 100 "$NODE_A_HOST" "$ROUTER_HOST" "$NODE_A_VX" "$NODE_A_GW" vxlan100)"
  remote "$NODE_B_HOST" "$(vxlan_leaf_cmd 200 "$NODE_B_HOST" "$ROUTER_HOST" "$NODE_B_VX" "$NODE_B_GW" vxlan200)"
  remote "$SVC_HOST" "$(vxlan_svc_cmd)"
  remote "$ROUTER_HOST" "$(vxlan_router_cmd)"

  # Required helper invocations. The helper is single-LAN/table-reset today, so
  # the final active ruleset below combines both LANs after these checks.
  remote "$ROUTER_HOST" "bash '$REMOTE_REPO/scripts/vm_lab/apply_nat_profile.sh' --profile '$PROFILE_A' --wan-if vxlan1 --lan-if vxlan100 --lan-host 172.16.10.2 --wan-udp-ports '$UDP_PORTS_A'"
  remote "$ROUTER_HOST" "bash '$REMOTE_REPO/scripts/vm_lab/apply_nat_profile.sh' --profile '$PROFILE_B' --wan-if vxlan1 --lan-if vxlan200 --lan-host 172.16.20.2 --wan-udp-ports '$UDP_PORTS_B'"
  remote "$ROUTER_HOST" "$(install_combined_nat_cmd)"
  remote "$SVC_HOST" "$(start_stun_cmd)"
  status
}

status() {
  echo "== node A =="
  remote "$NODE_A_HOST" "ip -br addr show vxlan100 2>/dev/null || true; ip route show default"
  echo "== node B =="
  remote "$NODE_B_HOST" "ip -br addr show vxlan200 2>/dev/null || true; ip route show default"
  echo "== router =="
  remote "$ROUTER_HOST" "for link in vxlan100 vxlan200 vxlan1; do ip -br addr show \"\$link\" 2>/dev/null || true; done; cat /run/rustynet_tier_b_nat_profile 2>/dev/null || true"
  echo "== svc =="
  remote "$SVC_HOST" "ip -br addr show vxlan1 2>/dev/null || true; cat '$STATE_ROOT/stun.pid' 2>/dev/null || true"
}

teardown() {
  remote "$NODE_A_HOST" "$(teardown_cmd)" || true
  remote "$NODE_B_HOST" "$(teardown_cmd)" || true
  remote "$SVC_HOST" "$(teardown_cmd)" || true
  remote "$ROUTER_HOST" "$(teardown_cmd)" || true
}

run_daemon_test() {
  setup
  remote "$NODE_A_HOST" "mkdir -p '$STATE_ROOT/node-a'"
  remote "$NODE_B_HOST" "mkdir -p '$STATE_ROOT/node-b'"
  remote "$NODE_A_HOST" "cd '$REMOTE_REPO' && RUSTYNET_INSTALL_SOURCE_ROOT='$REMOTE_REPO' /usr/local/bin/rustynet ops e2e-bootstrap-host --role client --node-id tier-b-a --network-id '$NETWORK_ID' --src-dir '$REMOTE_REPO' --ssh-allow-cidrs 172.16.0.0/12,10.200.0.0/24 --skip-apt"
  remote "$NODE_B_HOST" "cd '$REMOTE_REPO' && RUSTYNET_INSTALL_SOURCE_ROOT='$REMOTE_REPO' /usr/local/bin/rustynet ops e2e-bootstrap-host --role client --node-id tier-b-b --network-id '$NETWORK_ID' --src-dir '$REMOTE_REPO' --ssh-allow-cidrs 172.16.0.0/12,10.200.0.0/24 --skip-apt"
}

usage() {
  cat <<EOF
usage: $0 setup|status|teardown|run-daemon-test

Env overrides:
  NODE_A_HOST=$NODE_A_HOST NODE_B_HOST=$NODE_B_HOST SVC_HOST=$SVC_HOST ROUTER_HOST=$ROUTER_HOST WORK_HOST=$WORK_HOST
  PROFILE_A=$PROFILE_A PROFILE_B=$PROFILE_B REMOTE_REPO=$REMOTE_REPO
EOF
}

cmd="${1:-}"
case "$cmd" in
  setup) setup ;;
  status) status ;;
  teardown) teardown ;;
  run-daemon-test) run_daemon_test ;;
  -h|--help|"") usage ;;
  *) echo "unknown command: $cmd" >&2; usage; exit 2 ;;
esac
