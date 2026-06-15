#!/usr/bin/env bash
# netns_nat_filter.sh - verify NAT filtering behaviour in the Tier A netns sim.
#
# Pure netns + UDP lab tooling. No rustynetd is started or stopped.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIM="${SIM:-${SCRIPT_DIR}/netns_internet_sim.sh}"
RESP="${RESP:-${SCRIPT_DIR}/stun_responder.py}"
PROBE="${PROBE:-${SCRIPT_DIR}/nat_filter_probe.py}"
[ -f "$SIM" ] || SIM="/tmp/netns_internet_sim.sh"
[ -f "$RESP" ] || RESP="/tmp/stun_responder.py"
[ -f "$PROBE" ] || PROBE="/tmp/nat_filter_probe.py"

SVC_PRIMARY="100.64.0.254"
SVC_SECONDARY="100.64.0.253"
STUN_PORT=3478
EP_WG_PORT=51820
DIFF_PORT=49378
COLD_PORT=49379
TMP_DIR=""
declare -a PIDS=()

cleanup() {
  local pid
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  bash "$SIM" teardown >/dev/null 2>&1 || true
  if [ -n "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

require_root() {
  [ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
}

expect_for() {
  local profile="$1" scenario="$2"
  case "$scenario" in
    RETURN_EXACT) echo "yes" ;;
    UNSOLICITED_DIFF_PORT|COLD_INBOUND)
      [ "$profile" = "full_cone" ] && echo "yes" || echo "no"
      ;;
    *) echo "unknown scenario: $scenario" >&2; return 2 ;;
  esac
}

wait_for_file() {
  local path="$1" i
  for i in $(seq 1 50); do
    [ -s "$path" ] && return 0
    sleep 0.1
  done
  return 1
}

start_stun() {
  ip netns exec rnsim-svc python3 "$RESP" --bind "$SVC_PRIMARY" --port "$STUN_PORT" \
    >"${TMP_DIR}/stun.log" 2>&1 &
  PIDS+=("$!")
  sleep 0.4
}

stop_background() {
  local pid
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  PIDS=()
}

observed_received() {
  local path="$1"
  sed -n 's/.*received=\(yes\|no\).*/\1/p' "$path" | tail -1
}

run_scenario() {
  local profile="$1" scenario="$2" expected mapped init_log probe_log target observed init_pid
  expected="$(expect_for "$profile" "$scenario")" || return 2
  mapped="${TMP_DIR}/${profile}_${scenario}.mapped"
  init_log="${TMP_DIR}/${profile}_${scenario}.init.log"
  probe_log="${TMP_DIR}/${profile}_${scenario}.probe.log"

  stop_background
  bash "$SIM" teardown >/dev/null 2>&1
  bash "$SIM" build --site "A:${profile}" >/dev/null || {
    echo "build failed: profile=${profile} scenario=${scenario}"
    return 1
  }
  ip netns exec rnsim-svc ip addr add "${SVC_SECONDARY}/24" dev rnsim-svc-w 2>/dev/null || true

  case "$scenario" in
    RETURN_EXACT)
      start_stun
      ip netns exec rnsim-ep-A python3 "$PROBE" init \
        --bind-port "$EP_WG_PORT" \
        --stun "${SVC_PRIMARY}:${STUN_PORT}" \
        --mapped-file "$mapped" \
        --listen-secs 0 \
        --count-stun-response \
        >"$init_log" 2>&1
      ;;
    UNSOLICITED_DIFF_PORT)
      start_stun
      ip netns exec rnsim-ep-A python3 "$PROBE" init \
        --bind-port "$EP_WG_PORT" \
        --stun "${SVC_PRIMARY}:${STUN_PORT}" \
        --mapped-file "$mapped" \
        --listen-secs 2 \
        >"$init_log" 2>&1 &
      init_pid="$!"
      PIDS+=("$init_pid")
      wait_for_file "$mapped" || {
        echo "mapped endpoint not written: profile=${profile} scenario=${scenario}"
        return 1
      }
      target="$(tr -d '\r\n' < "$mapped")"
      ip netns exec rnsim-svc python3 "$PROBE" probe \
        --bind "${SVC_SECONDARY}:${DIFF_PORT}" \
        --target "$target" \
        >"$probe_log" 2>&1
      wait "$init_pid" 2>/dev/null || true
      ;;
    COLD_INBOUND)
      ip netns exec rnsim-ep-A python3 "$PROBE" init \
        --bind-port "$EP_WG_PORT" \
        --listen-secs 2 \
        >"$init_log" 2>&1 &
      init_pid="$!"
      PIDS+=("$init_pid")
      sleep 0.3
      ip netns exec rnsim-svc python3 "$PROBE" probe \
        --bind "${SVC_SECONDARY}:${COLD_PORT}" \
        --target "100.64.0.11:${EP_WG_PORT}" \
        >"$probe_log" 2>&1
      wait "$init_pid" 2>/dev/null || true
      ;;
  esac

  observed="$(observed_received "$init_log")"
  printf '  %-22s %-23s expected=%-3s observed=%-3s ' "$profile" "$scenario" "$expected" "${observed:-none}"
  if [ "$observed" = "$expected" ]; then
    printf 'PASS\n'
    return 0
  fi
  printf 'FAIL\n'
  sed 's/^/      init: /' "$init_log"
  [ -f "$probe_log" ] && sed 's/^/      probe: /' "$probe_log"
  return 1
}

require_root
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rustynet-nat-filter.XXXXXX")" || exit 1
rc=0
echo "== NAT filtering-behaviour verification =="
for profile in full_cone port_restricted_cone symmetric; do
  for scenario in RETURN_EXACT UNSOLICITED_DIFF_PORT COLD_INBOUND; do
    run_scenario "$profile" "$scenario" || rc=1
  done
done
echo "== $( [ "$rc" -eq 0 ] && echo "all filtering scenarios behave as intended" || echo "one or more filtering scenarios misbehaved" ) =="
exit "$rc"
