#!/usr/bin/env bash
# apply_nat_profile.sh — turn a lab router VM into a deterministic NAT
# boundary for cross-network live-lab stages (dataplane plan D5.1).
#
# RUNS ON: a Debian router guest with two NICs (run as root). The
# orchestrator copies this script to the router VM and invokes it over SSH
# before each cross-network stage; it is NOT run on the macOS host.
#
# PROFILES (one ruleset per label; see RustynetDataplaneExecutionPlan §D5.1)
#   port_restricted_cone  plain conntrack masquerade. Netfilter's natural
#                         behaviour: endpoint-independent mapping (source
#                         port preserved when free) with endpoint-dependent
#                         filtering. The common consumer-router shape and
#                         the one that exposes the §4.1.1 cold-contact gap.
#   full_cone             masquerade outbound + DMZ-style DNAT of the
#                         configured WAN UDP port range to the LAN host:
#                         endpoint-independent mapping AND filtering.
#   symmetric             masquerade with forced port randomisation: every
#                         conntrack flow gets a fresh source port, so the
#                         mapping is endpoint-dependent.
#   double_nat_cgnat      two NAT hops: an inner "home router" hop in this
#                         namespace and an outer "carrier" hop in a nested
#                         netns, numbered from 100.64.0.0/10 (RFC 6598),
#                         with NO uPnP at the outer hop. Emulates a CGNAT
#                         ISP (§4.1.3).
#   baseline_lan          plain routing, no NAT (also what --reset leaves).
#
# MODIFIERS (combine with any profile)
#   --enable-upnp         start miniupnpd answering on the LAN side so the
#                         guest's IGD client (D2.3 / D14.a) can obtain a
#                         real mapping. Requires miniupnpd installed on the
#                         router VM. With double_nat_cgnat this serves the
#                         INNER hop only, matching real CGNAT deployments.
#   --enable-v6 <prefix>  advertise <prefix> (e.g. fd77:1::/64) on the LAN
#                         via radvd and route v6 natively (no NAT66), so
#                         v6-bypass claims (§4.1.3, D14.b) are testable
#                         alongside any v4 profile.
#
# IDEMPOTENCE / DETERMINISM
#   Every invocation tears down all prior state first (nft table, nested
#   netns, miniupnpd, radvd) and rebuilds from scratch, so the resulting
#   ruleset is a pure function of the arguments. The applied profile is
#   recorded in /run/rustynet_nat_profile for the orchestrator to verify.
#
# USAGE
#   apply_nat_profile.sh --profile <label> --wan-if <if> --lan-if <if> \
#       [--lan-host <ip>] [--wan-udp-ports <lo-hi>] \
#       [--enable-upnp] [--enable-v6 <prefix>]
#   apply_nat_profile.sh --reset --wan-if <if> --lan-if <if>
#
#   --lan-host is required for full_cone (the DMZ target).
#   --wan-udp-ports defaults to 51820-51900 (WireGuard + relay range).
set -euo pipefail

NFT_TABLE="rustynet_natlab"
CGN_NETNS="rustynet_cgn"
CGN_VETH_HOME="rnl-home"
CGN_VETH_CARRIER="rnl-cgn"
CGN_HOME_ADDR="100.64.10.2/24"   # inner hop's "WAN" address (RFC 6598)
CGN_CARRIER_ADDR="100.64.10.1/24"
MARKER_FILE="/run/rustynet_nat_profile"
MINIUPNPD_CONF="/run/rustynet_natlab_miniupnpd.conf"
RADVD_CONF="/run/rustynet_natlab_radvd.conf"

PROFILE=""
WAN_IF=""
LAN_IF=""
LAN_HOST=""
WAN_UDP_PORTS="51820-51900"
ENABLE_UPNP=0
ENABLE_V6_PREFIX=""
RESET_ONLY=0

usage() {
  sed -n '2,55p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-2}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --profile)        PROFILE="${2:?--profile needs a value}"; shift 2 ;;
    --wan-if)         WAN_IF="${2:?--wan-if needs a value}"; shift 2 ;;
    --lan-if)         LAN_IF="${2:?--lan-if needs a value}"; shift 2 ;;
    --lan-host)       LAN_HOST="${2:?--lan-host needs a value}"; shift 2 ;;
    --wan-udp-ports)  WAN_UDP_PORTS="${2:?--wan-udp-ports needs a value}"; shift 2 ;;
    --enable-upnp)    ENABLE_UPNP=1; shift ;;
    --enable-v6)      ENABLE_V6_PREFIX="${2:?--enable-v6 needs a prefix}"; shift 2 ;;
    --reset)          RESET_ONLY=1; shift ;;
    -h|--help)        usage 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "must run as root on the router VM" >&2; exit 1; }
[ -n "$WAN_IF" ] || { echo "--wan-if is required" >&2; exit 2; }
[ -n "$LAN_IF" ] || { echo "--lan-if is required" >&2; exit 2; }
ip link show "$WAN_IF" >/dev/null 2>&1 || { echo "WAN interface not found: $WAN_IF" >&2; exit 1; }
ip link show "$LAN_IF" >/dev/null 2>&1 || { echo "LAN interface not found: $LAN_IF" >&2; exit 1; }

if [ "$RESET_ONLY" -eq 0 ]; then
  case "$PROFILE" in
    port_restricted_cone|symmetric|double_nat_cgnat|baseline_lan) : ;;
    full_cone)
      [ -n "$LAN_HOST" ] || { echo "full_cone requires --lan-host (DMZ target)" >&2; exit 2; }
      ;;
    "") echo "--profile is required (or use --reset)" >&2; exit 2 ;;
    *)  printf 'unknown profile: %s\n' "$PROFILE" >&2; exit 2 ;;
  esac
fi

# ---------------------------------------------------------------- teardown
teardown() {
  # Stop modifier daemons started by a prior invocation.
  pkill -f "miniupnpd.*${MINIUPNPD_CONF}" 2>/dev/null || true
  pkill -f "radvd.*${RADVD_CONF}" 2>/dev/null || true
  rm -f "$MINIUPNPD_CONF" "$RADVD_CONF"

  # Drop the nested carrier namespace (returns the WAN NIC to this ns
  # automatically when the namespace dies, but move it back explicitly so
  # the interface name and addressing are deterministic).
  if ip netns list 2>/dev/null | grep -q "^${CGN_NETNS}\b"; then
    ip netns exec "$CGN_NETNS" ip link set "$WAN_IF" netns 1 2>/dev/null || true
    ip netns del "$CGN_NETNS" 2>/dev/null || true
  fi
  ip link del "$CGN_VETH_HOME" 2>/dev/null || true

  # WAN NIC back under DHCP in the root namespace (no-op when untouched).
  ip link set "$WAN_IF" up 2>/dev/null || true

  nft delete table inet "$NFT_TABLE" 2>/dev/null || true
  nft delete table ip "$NFT_TABLE" 2>/dev/null || true
  rm -f "$MARKER_FILE"
}
teardown

if [ "$RESET_ONLY" -eq 1 ]; then
  echo "nat-profile: reset complete (plain routing, no NAT table)"
  exit 0
fi

# ---------------------------------------------------------------- sysctls
sysctl -qw net.ipv4.ip_forward=1
if [ -n "$ENABLE_V6_PREFIX" ]; then
  sysctl -qw net.ipv6.conf.all.forwarding=1
fi

port_lo="${WAN_UDP_PORTS%-*}"
port_hi="${WAN_UDP_PORTS#*-}"

# ------------------------------------------------------------- v4 rulesets
apply_masquerade() {
  # $1 = masquerade flags ("" or "random"), $2 = outbound interface
  nft add table ip "$NFT_TABLE"
  nft add chain ip "$NFT_TABLE" postrouting '{ type nat hook postrouting priority srcnat; policy accept; }'
  # shellcheck disable=SC2086 — $1 is an nft keyword, not user data
  nft add rule ip "$NFT_TABLE" postrouting oifname "$2" masquerade $1
}

case "$PROFILE" in
  baseline_lan)
    : # routing only; forwarding sysctl above is all that's needed
    ;;

  port_restricted_cone)
    apply_masquerade "" "$WAN_IF"
    ;;

  symmetric)
    apply_masquerade "random" "$WAN_IF"
    ;;

  full_cone)
    apply_masquerade "" "$WAN_IF"
    nft add chain ip "$NFT_TABLE" prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'
    nft add rule ip "$NFT_TABLE" prerouting iifname "$WAN_IF" udp dport "${port_lo}-${port_hi}" dnat to "$LAN_HOST"
    ;;

  double_nat_cgnat)
    # Inner hop ("home router", this namespace): LAN -> veth, RFC 6598 side.
    # Outer hop ("carrier", nested netns): veth -> physical WAN NIC, with
    # randomised ports — carrier NATs are typically endpoint-dependent.
    ip netns add "$CGN_NETNS"
    ip link add "$CGN_VETH_HOME" type veth peer name "$CGN_VETH_CARRIER"
    ip link set "$CGN_VETH_CARRIER" netns "$CGN_NETNS"
    ip addr add "$CGN_HOME_ADDR" dev "$CGN_VETH_HOME"
    ip link set "$CGN_VETH_HOME" up

    # The physical WAN NIC moves into the carrier namespace; its address
    # is re-acquired there via DHCP (UTM bridge serves it).
    wan_mac=$(cat "/sys/class/net/${WAN_IF}/address")
    ip link set "$WAN_IF" netns "$CGN_NETNS"
    ip netns exec "$CGN_NETNS" ip link set "$WAN_IF" up
    ip netns exec "$CGN_NETNS" ip addr add "$CGN_CARRIER_ADDR" dev "$CGN_VETH_CARRIER" 2>/dev/null || true
    ip netns exec "$CGN_NETNS" ip link set "$CGN_VETH_CARRIER" up
    ip netns exec "$CGN_NETNS" sysctl -qw net.ipv4.ip_forward=1
    if ! ip netns exec "$CGN_NETNS" dhclient -1 "$WAN_IF" 2>/dev/null; then
      echo "carrier-ns DHCP on ${WAN_IF} (mac ${wan_mac}) failed; check the UTM bridge" >&2
      exit 1
    fi

    # Inner hop NAT: LAN traffic masquerades onto the 100.64/10 segment.
    apply_masquerade "" "$CGN_VETH_HOME"
    ip route replace default via "${CGN_CARRIER_ADDR%/*}" dev "$CGN_VETH_HOME"

    # Outer hop NAT: carrier namespace masquerades 100.64/10 onto the WAN.
    ip netns exec "$CGN_NETNS" nft add table ip "$NFT_TABLE"
    ip netns exec "$CGN_NETNS" nft add chain ip "$NFT_TABLE" postrouting '{ type nat hook postrouting priority srcnat; policy accept; }'
    ip netns exec "$CGN_NETNS" nft add rule ip "$NFT_TABLE" postrouting oifname "$WAN_IF" masquerade random
    ;;
esac

# ---------------------------------------------------------------- modifiers
if [ "$ENABLE_UPNP" -eq 1 ]; then
  command -v miniupnpd >/dev/null 2>&1 || { echo "--enable-upnp requires miniupnpd on the router VM" >&2; exit 1; }
  if [ "$PROFILE" = "double_nat_cgnat" ]; then
    upnp_ext_if="$CGN_VETH_HOME"   # inner hop only — carriers don't run uPnP
  else
    upnp_ext_if="$WAN_IF"
  fi
  cat > "$MINIUPNPD_CONF" <<EOF
ext_ifname=${upnp_ext_if}
listening_ip=${LAN_IF}
enable_natpmp=yes
enable_upnp=yes
secure_mode=no
allow ${port_lo}-${port_hi} 0.0.0.0/0 ${port_lo}-${port_hi}
deny 0-65535 0.0.0.0/0 0-65535
EOF
  miniupnpd -f "$MINIUPNPD_CONF"
fi

if [ -n "$ENABLE_V6_PREFIX" ]; then
  command -v radvd >/dev/null 2>&1 || { echo "--enable-v6 requires radvd on the router VM" >&2; exit 1; }
  # Assign ::1 of the prefix to the LAN interface so the router is the
  # on-link gateway, then advertise the prefix.
  lan_v6_addr="${ENABLE_V6_PREFIX%%/*}"
  lan_v6_len="${ENABLE_V6_PREFIX##*/}"
  ip -6 addr replace "${lan_v6_addr}1/${lan_v6_len}" dev "$LAN_IF"
  cat > "$RADVD_CONF" <<EOF
interface ${LAN_IF} {
    AdvSendAdvert on;
    prefix ${ENABLE_V6_PREFIX} {
        AdvOnLink on;
        AdvAutonomous on;
    };
};
EOF
  radvd -C "$RADVD_CONF"
fi

# ---------------------------------------------------------------- marker
{
  printf 'profile=%s\n' "$PROFILE"
  printf 'wan_if=%s lan_if=%s\n' "$WAN_IF" "$LAN_IF"
  printf 'upnp=%s v6_prefix=%s\n' "$ENABLE_UPNP" "${ENABLE_V6_PREFIX:-none}"
  printf 'applied_at_unix=%s\n' "$(date +%s)"
} > "$MARKER_FILE"

echo "nat-profile: applied profile=${PROFILE} wan=${WAN_IF} lan=${LAN_IF} upnp=${ENABLE_UPNP} v6=${ENABLE_V6_PREFIX:-none}"
