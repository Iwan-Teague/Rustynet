#!/usr/bin/env bash
# netns_nat_classify.sh — verify each apply_nat_profile NAT type actually
# produces its intended mapping behaviour, using the netns internet simulator
# (dataplane plan D5.1, Tier A; safe — no rustynetd, pure netns + UDP).
#
# For each profile it builds a one-site topology, runs TWO STUN responders on
# two distinct svc addresses, then from the endpoint (behind that profile's NAT)
# runs nat_probe.py from a single socket against both servers and checks whether
# the NAT mapping is endpoint-independent (cone — hole-punchable) or
# endpoint-dependent (symmetric — relay-forced). A profile fails the gate if its
# observed behaviour does not match the intent the §4.1 matrix relies on:
#
#   port_restricted_cone -> endpoint-independent
#   full_cone            -> endpoint-independent
#   symmetric            -> endpoint-dependent
#
# Run as root on a Debian guest. Does NOT touch host networking (all state is in
# rnsim-* namespaces). Override tool locations with SIM/RESP/PROBE env vars.
set -uo pipefail

SIM="${SIM:-/tmp/netns_internet_sim.sh}"
RESP="${RESP:-/tmp/stun_responder.py}"
PROBE="${PROBE:-/tmp/nat_probe.py}"
SVC_PRIMARY="100.64.0.254"
SVC_SECONDARY="100.64.0.253"
PORT=3478

declare -A EXPECT=(
  [port_restricted_cone]=endpoint-independent
  [full_cone]=endpoint-independent
  [symmetric]=endpoint-dependent
)

run_profile() {
  local profile="$1" expect="$2"
  bash "$SIM" teardown >/dev/null 2>&1
  bash "$SIM" build --site "A:${profile}" >/dev/null || { echo "build failed for $profile"; return 1; }
  # second STUN server address on the svc node (distinct destination)
  ip netns exec rnsim-svc ip addr add "${SVC_SECONDARY}/24" dev rnsim-svc-w 2>/dev/null
  ip netns exec rnsim-svc python3 "$RESP" --bind "$SVC_PRIMARY" --port "$PORT" >/tmp/resp1.log 2>&1 &
  ip netns exec rnsim-svc python3 "$RESP" --bind "$SVC_SECONDARY" --port "$PORT" >/tmp/resp2.log 2>&1 &
  sleep 1
  local out behaviour
  out="$(ip netns exec rnsim-ep-A python3 "$PROBE" --stun "${SVC_PRIMARY}:${PORT}" --stun "${SVC_SECONDARY}:${PORT}" 2>&1)"
  behaviour="$(printf '%s\n' "$out" | sed -n 's/^mapping=//p')"
  pkill -f "stun_responder.py" 2>/dev/null
  bash "$SIM" teardown >/dev/null 2>&1

  printf '  %-22s expected=%-20s observed=%-20s ' "$profile" "$expect" "${behaviour:-<none>}"
  if [ "$behaviour" = "$expect" ]; then
    printf 'PASS\n'; return 0
  else
    printf 'FAIL\n'; printf '%s\n' "$out" | sed 's/^/      /'; return 1
  fi
}

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
echo "== NAT mapping-behaviour classification =="
rc=0
for profile in port_restricted_cone full_cone symmetric; do
  run_profile "$profile" "${EXPECT[$profile]}" || rc=1
done
echo "== $( [ $rc -eq 0 ] && echo "all profiles behave as intended" || echo "one or more profiles MISBEHAVED" ) =="
exit $rc
