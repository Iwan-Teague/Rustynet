#!/usr/bin/env bash
# netns_internet_sim.sh — a deterministic "internet in a box" for cross-network
# Rustynet testing, built entirely from Linux network namespaces on ONE Debian
# guest (dataplane plan D5.1, Tier A).
#
# WHY
#   The UTM lab puts every VM on one L2 bridge, so VM-to-VM is same-LAN — there
#   is no NAT boundary to traverse. This harness builds a real cross-NAT
#   topology inside a single guest using namespaces: each endpoint sits behind
#   its own NAT router on its own private segment, reachable only through a
#   shared "wan" core that also hosts the STUN responder and relay/anchor. The
#   NAT, routing, conntrack, and (when rustynetd is layered on) WireGuard are
#   the real kernel code paths — only the wires are virtual. It is fully
#   reproducible, so it is the substrate for the cross-network CI gate.
#
# TOPOLOGY (default 2 sites; --site adds more)
#
#     ns:ep-A (10.10.0.2)                         ns:ep-B (10.20.0.2)
#          │ veth lan                                   │ veth lan
#     ns:rtr-A ──┐ NAT(profile)            NAT(profile) ┌── ns:rtr-B
#     198.18.0.11│                                      │198.18.0.12
#                └────────────  br:wanbr  ──────────────┘
#                        (198.18.0.0/24  =  "the internet")
#                                  │
#                          ns:svc (198.18.0.254)
#                       STUN responder + rustynet-relay
#
#   - Each endpoint reaches the wan only through its router's NAT, so the
#     reflexive address an endpoint learns from the svc STUN responder is the
#     router's translated (ip:port) — exactly as on a real home network.
#   - Endpoints cannot reach each other unsolicited (the routers' filtering
#     rules enforce the NAT type), which is what makes traversal non-trivial.
#
# NAT PROFILES (per site; same vocabulary as apply_nat_profile.sh)
#   port_restricted_cone  plain masquerade (endpoint-dependent filtering)
#   full_cone             masquerade + DNAT of the WG/relay UDP range to the ep
#   symmetric             masquerade with per-flow random source ports
#   double_nat_cgnat      two NAT hops (extra carrier router on 100.64/10)
#
# USAGE
#   netns_internet_sim.sh build  [--site NAME:PROFILE[:IMPAIR] ...]
#                                 [--wan-cidr A.B.C.0/24] [--udp-ports lo-hi]
#   netns_internet_sim.sh status
#   netns_internet_sim.sh exec   <ns> -- <cmd...>
#   netns_internet_sim.sh teardown
#
#   IMPAIR (optional, applied to the endpoint's lan veth via netem):
#     none | latency_50ms_loss_1pct | latency_120ms_loss_3pct | loss_5pct
#
#   Default sites if none given:
#     A:port_restricted_cone  B:port_restricted_cone
#
# Run as root on the Debian guest. All state lives under namespaces prefixed
# "rnsim-" and a bridge "rnsim-wan"; teardown removes exactly those.
set -euo pipefail

NS_PREFIX="rnsim"
WAN_BR="${NS_PREFIX}-wan"
# Ordinary simulated transit lives in the IANA benchmarking range
# 198.18.0.0/15 (LiveLabVmConnectivityRulebook §15.3). The legacy default
# 100.64.0.0/24 overlapped the Rustynet mesh 100.64.0.0/10 and is now valid
# ONLY under the explicit cgnat_collision_v1 adversarial profile — pass
# --wan-cidr 100.64.0.0/24 (or WAN_CIDR/WAN_BASE env) deliberately for that.
WAN_CIDR="${WAN_CIDR:-198.18.0.0/24}"
WAN_BASE="${WAN_BASE:-198.18.0}"
SVC_HOST_OCTET="254"
UDP_PORTS="51820-51900"
MARKER="/run/${NS_PREFIX}_topology"
declare -a SITES=()

NFT() { nft "$@"; }
IP() { ip "$@"; }

ns()   { echo "${NS_PREFIX}-$1"; }              # namespace name
nsx()  { local n; n="$(ns "$1")"; shift; ip netns exec "$n" "$@"; }

require_root() { [ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }; }

is_valid_profile() {
  case "$1" in
    port_restricted_cone|full_cone|symmetric|double_nat_cgnat) return 0 ;;
    *) return 1 ;;
  esac
}

netem_args() {
  case "$1" in
    none|"")                  echo "" ;;
    latency_50ms_loss_1pct)   echo "delay 50ms loss 1%" ;;
    latency_120ms_loss_3pct)  echo "delay 120ms 20ms distribution normal loss 3%" ;;
    loss_5pct)                echo "loss 5%" ;;
    *) echo "__INVALID__" ;;
  esac
}

# ---------------------------------------------------------------- teardown
teardown() {
  # Delete every namespace we own, then the wan bridge. Namespace deletion
  # takes its veths with it; the bridge end on the root side is named per-site
  # so we sweep those explicitly too.
  local n
  while read -r n; do
    case "$n" in
      ${NS_PREFIX}-*) ip netns del "$n" 2>/dev/null || true ;;
    esac
  done < <(ip netns list 2>/dev/null | awk '{print $1}')
  # Sweep any leftover root-side veths and the bridge.
  for l in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | sed 's/@.*//' | grep "^${NS_PREFIX}-" || true); do
    ip link del "$l" 2>/dev/null || true
  done
  ip link del "$WAN_BR" 2>/dev/null || true
  rm -f "$MARKER"
}

# ---------------------------------------------------------------- build core
build_wan_core() {
  ip link add "$WAN_BR" type bridge
  ip link set "$WAN_BR" up

  # Services namespace on the wan: STUN responder + relay/anchor live here.
  local svcns; svcns="$(ns svc)"
  ip netns add "$svcns"
  ip link add "${NS_PREFIX}-svc-w" type veth peer name "${NS_PREFIX}-svc-br"
  ip link set "${NS_PREFIX}-svc-w" netns "$svcns"
  ip link set "${NS_PREFIX}-svc-br" master "$WAN_BR"; ip link set "${NS_PREFIX}-svc-br" up
  nsx svc ip addr add "${WAN_BASE}.${SVC_HOST_OCTET}/24" dev "${NS_PREFIX}-svc-w"
  nsx svc ip link set "${NS_PREFIX}-svc-w" up
  nsx svc ip link set lo up
}

# ---------------------------------------------------------------- build site
# $1=index (1..n) $2=name $3=profile $4=impair
build_site() {
  local idx="$1" name="$2" profile="$3" impair="$4"
  local lan_net="10.$((idx*10)).0"
  local ep_ip="${lan_net}.2" gw_ip="${lan_net}.1"
  local wan_ip="${WAN_BASE}.$((10+idx))"
  local rtrns epns
  rtrns="$(ns "rtr-${name}")"; epns="$(ns "ep-${name}")"
  ip netns add "$rtrns"; ip netns add "$epns"
  nsx "rtr-${name}" ip link set lo up
  nsx "ep-${name}" ip link set lo up

  # router <-> wan bridge
  ip link add "${NS_PREFIX}-r${idx}w" type veth peer name "${NS_PREFIX}-r${idx}br"
  ip link set "${NS_PREFIX}-r${idx}w" netns "$rtrns"
  ip link set "${NS_PREFIX}-r${idx}br" master "$WAN_BR"; ip link set "${NS_PREFIX}-r${idx}br" up
  nsx "rtr-${name}" ip addr add "${wan_ip}/24" dev "${NS_PREFIX}-r${idx}w"
  nsx "rtr-${name}" ip link set "${NS_PREFIX}-r${idx}w" up

  # endpoint <-> router (the "home LAN")
  ip link add "${NS_PREFIX}-e${idx}l" type veth peer name "${NS_PREFIX}-r${idx}l"
  ip link set "${NS_PREFIX}-e${idx}l" netns "$epns"
  ip link set "${NS_PREFIX}-r${idx}l" netns "$rtrns"
  nsx "rtr-${name}" ip addr add "${gw_ip}/24" dev "${NS_PREFIX}-r${idx}l"
  nsx "rtr-${name}" ip link set "${NS_PREFIX}-r${idx}l" up
  nsx "ep-${name}" ip addr add "${ep_ip}/24" dev "${NS_PREFIX}-e${idx}l"
  nsx "ep-${name}" ip link set "${NS_PREFIX}-e${idx}l" up
  nsx "ep-${name}" ip route add default via "${gw_ip}"

  # optional impairment on the endpoint's uplink
  local ne; ne="$(netem_args "$impair")"
  [ "$ne" = "__INVALID__" ] && { echo "invalid impairment: $impair" >&2; exit 2; }
  if [ -n "$ne" ]; then
    # shellcheck disable=SC2086
    nsx "ep-${name}" tc qdisc add dev "${NS_PREFIX}-e${idx}l" root netem $ne
  fi

  # router forwarding + NAT profile
  nsx "rtr-${name}" sysctl -qw net.ipv4.ip_forward=1
  apply_site_nat "$name" "$profile" "${NS_PREFIX}-r${idx}w" "${NS_PREFIX}-r${idx}l" "$ep_ip"
}

# $1=name $2=profile $3=wan-if $4=lan-if $5=ep-ip   (run inside rtr-<name>)
apply_site_nat() {
  local name="$1" profile="$2" wif="$3" lif="$4" ep="$5"
  local lo="${UDP_PORTS%-*}" hi="${UDP_PORTS#*-}"
  nsx "rtr-${name}" nft add table ip rnsim_nat
  nsx "rtr-${name}" nft add chain ip rnsim_nat post '{ type nat hook postrouting priority srcnat; policy accept; }'
  case "$profile" in
    port_restricted_cone)
      nsx "rtr-${name}" nft add rule ip rnsim_nat post oifname "$wif" masquerade ;;
    symmetric)
      nsx "rtr-${name}" nft add rule ip rnsim_nat post oifname "$wif" masquerade random ;;
    full_cone)
      nsx "rtr-${name}" nft add rule ip rnsim_nat post oifname "$wif" masquerade
      nsx "rtr-${name}" nft add chain ip rnsim_nat pre '{ type nat hook prerouting priority dstnat; policy accept; }'
      nsx "rtr-${name}" nft add rule ip rnsim_nat pre iifname "$wif" udp dport "${lo}-${hi}" dnat to "$ep" ;;
    double_nat_cgnat)
      # Inner hop is this router; the harness models the carrier as a second
      # masquerade on the same router toward a 100.64/10 next hop is not
      # faithful, so double_nat is built as a two-router chain by the caller.
      echo "double_nat_cgnat must be built as a chained site (handled in build)" >&2
      exit 2 ;;
  esac
}

# ---------------------------------------------------------------- status
status() {
  [ -f "$MARKER" ] && { echo "== topology =="; cat "$MARKER"; } || echo "no topology marker"
  echo "== namespaces =="; ip netns list | grep "^${NS_PREFIX}-" || echo "(none)"
  echo "== wan bridge members =="; ip link show master "$WAN_BR" 2>/dev/null | awk -F': ' '/'"${NS_PREFIX}"'/{print $2}' || true
}

# ---------------------------------------------------------------- main
[ $# -ge 1 ] || { sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
cmd="$1"; shift

case "$cmd" in
  build)
    require_root
    while [ $# -gt 0 ]; do
      case "$1" in
        --site)       SITES+=("$2"); shift 2 ;;
        --wan-cidr)   WAN_CIDR="$2"; WAN_BASE="${2%.*/*}"; WAN_BASE="${WAN_BASE%.*}"; shift 2 ;;
        --udp-ports)  UDP_PORTS="$2"; shift 2 ;;
        *) echo "unknown build arg: $1" >&2; exit 2 ;;
      esac
    done
    [ ${#SITES[@]} -gt 0 ] || SITES=("A:port_restricted_cone" "B:port_restricted_cone")
    teardown
    build_wan_core
    i=0
    for spec in "${SITES[@]}"; do
      i=$((i+1))
      name="${spec%%:*}"; rest="${spec#*:}"
      profile="${rest%%:*}"; impair="none"
      [ "$rest" != "$profile" ] && impair="${rest#*:}"
      is_valid_profile "$profile" || { echo "invalid profile in --site $spec" >&2; exit 2; }
      build_site "$i" "$name" "$profile" "$impair"
    done
    {
      printf 'wan_cidr=%s svc=%s.%s udp_ports=%s\n' "$WAN_CIDR" "$WAN_BASE" "$SVC_HOST_OCTET" "$UDP_PORTS"
      i=0; for spec in "${SITES[@]}"; do i=$((i+1)); printf 'site%d=%s\n' "$i" "$spec"; done
    } > "$MARKER"
    echo "netns-sim: built ${#SITES[@]} site(s); svc at ${WAN_BASE}.${SVC_HOST_OCTET}"
    ;;
  status)   status ;;
  exec)
    target="$1"; shift; [ "$1" = "--" ] && shift
    nsx "$target" "$@" ;;
  teardown) require_root; teardown; echo "netns-sim: torn down" ;;
  *) echo "unknown command: $cmd" >&2; exit 2 ;;
esac
