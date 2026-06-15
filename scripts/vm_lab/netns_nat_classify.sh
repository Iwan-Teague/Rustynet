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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIM="${SIM:-${SCRIPT_DIR}/netns_internet_sim.sh}"
RESP="${RESP:-${SCRIPT_DIR}/stun_responder.py}"
PROBE="${PROBE:-${SCRIPT_DIR}/nat_probe.py}"
[ -f "$SIM" ] || SIM="/tmp/netns_internet_sim.sh"
[ -f "$RESP" ] || RESP="/tmp/stun_responder.py"
[ -f "$PROBE" ] || PROBE="/tmp/nat_probe.py"
SVC_PRIMARY="100.64.0.254"
SVC_SECONDARY="100.64.0.253"
PORT=3478
TMP_DIR=""
declare -a STUN_PIDS=()

declare -A EXPECT=(
  [port_restricted_cone]=endpoint-independent
  [full_cone]=endpoint-independent
  [symmetric]=endpoint-dependent
)

stop_stun_responders() {
  local pid
  for pid in "${STUN_PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  STUN_PIDS=()
}

cleanup() {
  stop_stun_responders
  bash "$SIM" teardown >/dev/null 2>&1 || true
  if [ -n "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

run_profile() {
  local profile="$1" expect="$2"
  stop_stun_responders
  bash "$SIM" teardown >/dev/null 2>&1
  bash "$SIM" build --site "A:${profile}" >/dev/null || { echo "build failed for $profile"; return 1; }
  # second STUN server address on the svc node (distinct destination)
  ip netns exec rnsim-svc ip addr add "${SVC_SECONDARY}/24" dev rnsim-svc-w 2>/dev/null
  ip netns exec rnsim-svc python3 "$RESP" --bind "$SVC_PRIMARY" --port "$PORT" >"${TMP_DIR}/resp1.log" 2>&1 &
  STUN_PIDS+=("$!")
  ip netns exec rnsim-svc python3 "$RESP" --bind "$SVC_SECONDARY" --port "$PORT" >"${TMP_DIR}/resp2.log" 2>&1 &
  STUN_PIDS+=("$!")
  sleep 1
  local out behaviour
  out="$(ip netns exec rnsim-ep-A python3 "$PROBE" --stun "${SVC_PRIMARY}:${PORT}" --stun "${SVC_SECONDARY}:${PORT}" 2>&1)"
  behaviour="$(printf '%s\n' "$out" | sed -n 's/^mapping=//p')"
  stop_stun_responders
  bash "$SIM" teardown >/dev/null 2>&1

  printf '  %-22s expected=%-20s observed=%-20s ' "$profile" "$expect" "${behaviour:-<none>}"
  if [ "$behaviour" = "$expect" ]; then
    printf 'PASS\n'; return 0
  else
    printf 'FAIL\n'; printf '%s\n' "$out" | sed 's/^/      /'; return 1
  fi
}

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rustynet-nat-classify.XXXXXX")" || exit 1
echo "== NAT mapping-behaviour classification =="
rc=0
for profile in port_restricted_cone full_cone symmetric; do
  run_profile "$profile" "${EXPECT[$profile]}" || rc=1
done
echo "== $( [ $rc -eq 0 ] && echo "all profiles behave as intended" || echo "one or more profiles MISBEHAVED" ) =="
exit $rc
