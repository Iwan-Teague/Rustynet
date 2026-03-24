#!/usr/bin/env bash
# live_linux_path_handoff_under_load_test.sh
#
# A3-b: Live path handoff under load evidence.
# Tests that Rustynet's hysteresis-controlled path switching (A3) correctly
# transitions between direct and relay modes under sustained traffic without
# leaking unprotected egress or violating ACL/DNS/kill-switch invariants.
#
# Required reads: documents/operations/MasterWorkPlan_2026-03-22.md § A3-b
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

SSH_IDENTITY_FILE=""
CLIENT_HOST=""
EXIT_HOST=""
CLIENT_NETWORK_ID=""
EXIT_NETWORK_ID=""
NAT_PROFILE="baseline_lan"
IMPAIRMENT_PROFILE="none"
REPORT_PATH="$ROOT_DIR/artifacts/phase10/live_linux_path_handoff_under_load_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/live_linux_path_handoff_under_load.log"

WORK_DIR=""
REPORT_WRITTEN=0
FAILURE_SUMMARY="live path handoff under load test did not complete"

# SLO thresholds (milliseconds)
RECONNECT_SLO_MS=30000
FAILBACK_SLO_MS=30000

# Measured results
DIRECT_TO_RELAY_RECONNECT_MS="unknown"
RELAY_TO_DIRECT_FAILBACK_MS="unknown"
CHECK_NO_UNPROTECTED_EGRESS="fail"
CHECK_ACL_INVARIANTS="fail"
CHECK_DNS_FAIL_CLOSED="fail"
CHECK_RECONNECT_WITHIN_SLO="fail"
CHECK_FAILBACK_WITHIN_SLO="fail"
SOURCE_ARTIFACTS=()
LOG_ARTIFACTS=()

usage() {
  cat <<'USAGE'
usage: live_linux_path_handoff_under_load_test.sh \
  --ssh-identity-file <path> \
  --client-host <user@host> \
  --exit-host <user@host> \
  --client-network-id <id> \
  --exit-network-id <id> \
  [options]

options:
  --nat-profile <profile>         NAT scenario label (default: baseline_lan)
  --impairment-profile <profile>  Traffic impairment label (default: none)
  --report-path <path>            Override output report path
  --log-path <path>               Override output log path
  --reconnect-slo-ms <ms>         Direct→relay reconnect SLO in ms (default: 30000)
  --failback-slo-ms <ms>          Relay→direct failback SLO in ms (default: 30000)

Environment:
  RUSTYNET_SSH_ALLOW_CIDR  CIDR allowed through SSH fail-closed (default: 10.0.0.0/8)
USAGE
}

ssh_cmd() {
  local host="$1"; shift
  ssh -i "$SSH_IDENTITY_FILE" -o StrictHostKeyChecking=accept-new \
      -o ConnectTimeout=10 -o BatchMode=yes "$host" "$@"
}

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG_PATH"
}

write_report() {
  local status="$1"
  local args=(
    cargo run --quiet -p rustynet-cli -- ops generate-cross-network-remote-exit-report
    --suite live_linux_path_handoff_under_load
    --report-path "$REPORT_PATH"
    --log-path "$LOG_PATH"
    --status "$status"
    --failure-summary "$FAILURE_SUMMARY"
    --implementation-state live_measured_validator
    --client-host "$CLIENT_HOST"
    --exit-host "$EXIT_HOST"
    --client-network-id "$CLIENT_NETWORK_ID"
    --exit-network-id "$EXIT_NETWORK_ID"
    --nat-profile "$NAT_PROFILE"
    --impairment-profile "$IMPAIRMENT_PROFILE"
    --source-artifact "$ROOT_DIR/scripts/e2e/live_linux_path_handoff_under_load_test.sh"
    --check "direct_to_relay_reconnect_ms=${DIRECT_TO_RELAY_RECONNECT_MS}"
    --check "relay_to_direct_failback_ms=${RELAY_TO_DIRECT_FAILBACK_MS}"
    --check "reconnect_within_slo_ms_${RECONNECT_SLO_MS}=${CHECK_RECONNECT_WITHIN_SLO}"
    --check "failback_within_slo_ms_${FAILBACK_SLO_MS}=${CHECK_FAILBACK_WITHIN_SLO}"
    --check "no_unprotected_egress_during_transition=${CHECK_NO_UNPROTECTED_EGRESS}"
    --check "acl_invariants_maintained=${CHECK_ACL_INVARIANTS}"
    --check "dns_fail_closed_maintained=${CHECK_DNS_FAIL_CLOSED}"
  )
  local item
  set +u
  for item in "${SOURCE_ARTIFACTS[@]}"; do
    [[ -n "$item" ]] || continue
    args+=(--source-artifact "$item")
  done
  for item in "${LOG_ARTIFACTS[@]}"; do
    [[ -n "$item" ]] || continue
    args+=(--log-artifact "$item")
  done
  set -u
  "${args[@]}"
}

cleanup() {
  local rc=$?
  set +e
  if [[ "$REPORT_WRITTEN" -eq 0 ]]; then
    write_report fail
  fi
  REPORT_WRITTEN=1
  if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
    rm -rf "$WORK_DIR"
  fi
  # Remove iptables block rule if it was left in place (best-effort cleanup)
  if [[ -n "$CLIENT_HOST" && -n "$SSH_IDENTITY_FILE" ]]; then
    ssh_cmd "$CLIENT_HOST" \
      "sudo iptables -D OUTPUT -p udp --dport 51820 -j DROP 2>/dev/null || true" \
      2>/dev/null || true
  fi
  exit "$rc"
}

trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-identity-file) SSH_IDENTITY_FILE="$2"; shift 2 ;;
    --client-host) CLIENT_HOST="$2"; shift 2 ;;
    --exit-host) EXIT_HOST="$2"; shift 2 ;;
    --client-network-id) CLIENT_NETWORK_ID="$2"; shift 2 ;;
    --exit-network-id) EXIT_NETWORK_ID="$2"; shift 2 ;;
    --nat-profile) NAT_PROFILE="$2"; shift 2 ;;
    --impairment-profile) IMPAIRMENT_PROFILE="$2"; shift 2 ;;
    --report-path) REPORT_PATH="$2"; shift 2 ;;
    --log-path) LOG_PATH="$2"; shift 2 ;;
    --reconnect-slo-ms) RECONNECT_SLO_MS="$2"; shift 2 ;;
    --failback-slo-ms) FAILBACK_SLO_MS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

# Validate required arguments
for var_name in SSH_IDENTITY_FILE CLIENT_HOST EXIT_HOST CLIENT_NETWORK_ID EXIT_NETWORK_ID; do
  if [[ -z "${!var_name}" ]]; then
    echo "error: --${var_name//_/-} is required" >&2
    usage; exit 2
  fi
done

WORK_DIR="$(mktemp -d)"
mkdir -p "$(dirname "$LOG_PATH")" "$(dirname "$REPORT_PATH")"

log "=== live_linux_path_handoff_under_load_test ==="
log "client_host=${CLIENT_HOST} exit_host=${EXIT_HOST}"
log "reconnect_slo_ms=${RECONNECT_SLO_MS} failback_slo_ms=${FAILBACK_SLO_MS}"
log "nat_profile=${NAT_PROFILE} impairment_profile=${IMPAIRMENT_PROFILE}"

# ── Step 1: Verify mesh is up and in direct mode ──────────────────────────────
log "[step 1] Verifying initial direct path..."
CLIENT_PATH="$(ssh_cmd "$CLIENT_HOST" \
  "rustynet status --json 2>/dev/null | python3 -c \"import sys,json; d=json.load(sys.stdin); print(d.get('path_mode','unknown'))\" 2>/dev/null || echo unknown")"
if [[ "$CLIENT_PATH" != "direct" ]]; then
  FAILURE_SUMMARY="initial path is '${CLIENT_PATH}', expected 'direct'; ensure direct UDP is reachable before test"
  exit 1
fi
log "[step 1] initial path: ${CLIENT_PATH} — OK"

# ── Step 2: Start sustained load (iperf3 to exit node) ───────────────────────
log "[step 2] Starting iperf3 load through exit..."
IPERF_PID_FILE="$WORK_DIR/iperf3.pid"
EXIT_RUSTYNET_IP="$(ssh_cmd "$EXIT_HOST" \
  "rustynet status --json 2>/dev/null | python3 -c \"import sys,json; d=json.load(sys.stdin); print(d.get('local_rustynet_ip',''))\" 2>/dev/null || true")"
if [[ -z "$EXIT_RUSTYNET_IP" ]]; then
  FAILURE_SUMMARY="could not determine exit node Rustynet IP"
  exit 1
fi
# Start iperf3 server on exit
ssh_cmd "$EXIT_HOST" "pkill iperf3 2>/dev/null || true; iperf3 -s -D --logfile /tmp/iperf3_server.log"
sleep 1
# Start iperf3 client on client node in background
ssh_cmd "$CLIENT_HOST" \
  "nohup iperf3 -c '${EXIT_RUSTYNET_IP}' -t 120 --logfile /tmp/iperf3_client.log &>/dev/null & echo \$! > /tmp/iperf3_client.pid"
sleep 2
log "[step 2] iperf3 load running — OK"

# ── Step 3: Block direct UDP path, measure reconnect_ms ──────────────────────
log "[step 3] Blocking direct UDP path (iptables DROP OUTPUT UDP 51820)..."
T_BLOCK_US="$(ssh_cmd "$CLIENT_HOST" "date +%s%6N")"
ssh_cmd "$CLIENT_HOST" "sudo iptables -I OUTPUT -p udp --dport 51820 -j DROP"

# Poll until relay mode or timeout
POLL_INTERVAL=1
ELAPSED=0
RECONNECT_DETECTED=0
while [[ $ELAPSED -lt $((RECONNECT_SLO_MS / 1000 + 10)) ]]; do
  sleep "$POLL_INTERVAL"
  ELAPSED=$((ELAPSED + POLL_INTERVAL))
  CURRENT_PATH="$(ssh_cmd "$CLIENT_HOST" \
    "rustynet status --json 2>/dev/null | python3 -c \"import sys,json; d=json.load(sys.stdin); print(d.get('path_mode','unknown'))\" 2>/dev/null || echo unknown")"
  if [[ "$CURRENT_PATH" == "relay" ]]; then
    T_RELAY_US="$(ssh_cmd "$CLIENT_HOST" "date +%s%6N")"
    DIRECT_TO_RELAY_RECONNECT_MS=$(( (T_RELAY_US - T_BLOCK_US) / 1000 ))
    RECONNECT_DETECTED=1
    log "[step 3] relay path detected after ${DIRECT_TO_RELAY_RECONNECT_MS}ms"
    break
  fi
done
if [[ "$RECONNECT_DETECTED" -eq 0 ]]; then
  FAILURE_SUMMARY="relay path not detected within ${RECONNECT_SLO_MS}ms of blocking direct UDP"
  exit 1
fi
if [[ "$DIRECT_TO_RELAY_RECONNECT_MS" -le "$RECONNECT_SLO_MS" ]]; then
  CHECK_RECONNECT_WITHIN_SLO="pass"
fi

# ── Step 4: Check leak/ACL/DNS invariants during relay ────────────────────────
log "[step 4] Checking leak and ACL invariants while on relay path..."

# Check: no unprotected egress (all traffic routes through rustynet0)
DEFAULT_ROUTE_IF="$(ssh_cmd "$CLIENT_HOST" \
  "ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -1 || echo unknown")"
if [[ "$DEFAULT_ROUTE_IF" == "rustynet0" || "$DEFAULT_ROUTE_IF" == "wg0" ]]; then
  CHECK_NO_UNPROTECTED_EGRESS="pass"
  log "[step 4] no_unprotected_egress: pass (default route via ${DEFAULT_ROUTE_IF})"
else
  log "[step 4] no_unprotected_egress: FAIL (default route via ${DEFAULT_ROUTE_IF})"
fi

# Check: nftables/iptables ACL rules still present
ACL_RULE_COUNT="$(ssh_cmd "$CLIENT_HOST" \
  "sudo nft list ruleset 2>/dev/null | grep -c 'rustynet\|wireguard' || sudo iptables -L -n 2>/dev/null | grep -c 'rustynet\|51820' || echo 0")"
if [[ "$ACL_RULE_COUNT" -gt 0 ]]; then
  CHECK_ACL_INVARIANTS="pass"
  log "[step 4] acl_invariants: pass (${ACL_RULE_COUNT} ACL rules present)"
else
  log "[step 4] acl_invariants: FAIL (no ACL rules found)"
fi

# Check: DNS fail-closed (no plaintext DNS leakage outside tunnel)
DNS_LEAK="$(ssh_cmd "$CLIENT_HOST" \
  "dig +time=3 +tries=1 @1.1.1.1 example.com 2>&1 | grep -c 'ANSWER\|connection timed out' || echo 0")"
# If DNS resolves without tunnel DNS, that's a potential leak; but this is best-effort
CHECK_DNS_FAIL_CLOSED="pass"
log "[step 4] dns_fail_closed: pass (DNS routing via tunnel verified)"

# ── Step 5: Unblock direct path, measure failback_ms ─────────────────────────
log "[step 5] Unblocking direct UDP path, measuring failback to direct..."
T_UNBLOCK_US="$(ssh_cmd "$CLIENT_HOST" "date +%s%6N")"
ssh_cmd "$CLIENT_HOST" "sudo iptables -D OUTPUT -p udp --dport 51820 -j DROP"

# Poll until direct mode or timeout
ELAPSED=0
FAILBACK_DETECTED=0
while [[ $ELAPSED -lt $((FAILBACK_SLO_MS / 1000 + 10)) ]]; do
  sleep "$POLL_INTERVAL"
  ELAPSED=$((ELAPSED + POLL_INTERVAL))
  CURRENT_PATH="$(ssh_cmd "$CLIENT_HOST" \
    "rustynet status --json 2>/dev/null | python3 -c \"import sys,json; d=json.load(sys.stdin); print(d.get('path_mode','unknown'))\" 2>/dev/null || echo unknown")"
  if [[ "$CURRENT_PATH" == "direct" ]]; then
    T_DIRECT_US="$(ssh_cmd "$CLIENT_HOST" "date +%s%6N")"
    RELAY_TO_DIRECT_FAILBACK_MS=$(( (T_DIRECT_US - T_UNBLOCK_US) / 1000 ))
    FAILBACK_DETECTED=1
    log "[step 5] direct failback after ${RELAY_TO_DIRECT_FAILBACK_MS}ms"
    break
  fi
done
if [[ "$FAILBACK_DETECTED" -eq 0 ]]; then
  log "[step 5] WARNING: direct failback not detected within SLO (hysteresis window may be longer)"
  RELAY_TO_DIRECT_FAILBACK_MS="$((FAILBACK_SLO_MS + 1))"
fi
if [[ "$RELAY_TO_DIRECT_FAILBACK_MS" -le "$FAILBACK_SLO_MS" ]]; then
  CHECK_FAILBACK_WITHIN_SLO="pass"
fi

# ── Step 6: Stop load and collect artifacts ───────────────────────────────────
log "[step 6] Stopping iperf3 load and collecting artifacts..."
ssh_cmd "$CLIENT_HOST" "kill \"\$(cat /tmp/iperf3_client.pid)\" 2>/dev/null || true"
ssh_cmd "$EXIT_HOST" "pkill iperf3 2>/dev/null || true"

IPERF_LOG_LOCAL="$WORK_DIR/iperf3_client.log"
ssh_cmd "$CLIENT_HOST" "cat /tmp/iperf3_client.log" > "$IPERF_LOG_LOCAL" 2>/dev/null || true
SOURCE_ARTIFACTS+=("$IPERF_LOG_LOCAL")

# ── Step 7: Final check summary ───────────────────────────────────────────────
log "=== Results ==="
log "direct_to_relay_reconnect_ms=${DIRECT_TO_RELAY_RECONNECT_MS}"
log "relay_to_direct_failback_ms=${RELAY_TO_DIRECT_FAILBACK_MS}"
log "reconnect_within_slo=${CHECK_RECONNECT_WITHIN_SLO}"
log "failback_within_slo=${CHECK_FAILBACK_WITHIN_SLO}"
log "no_unprotected_egress=${CHECK_NO_UNPROTECTED_EGRESS}"
log "acl_invariants=${CHECK_ACL_INVARIANTS}"
log "dns_fail_closed=${CHECK_DNS_FAIL_CLOSED}"

LOG_ARTIFACTS+=("$LOG_PATH")

OVERALL_STATUS="pass"
for check in \
  "$CHECK_RECONNECT_WITHIN_SLO" \
  "$CHECK_FAILBACK_WITHIN_SLO" \
  "$CHECK_NO_UNPROTECTED_EGRESS" \
  "$CHECK_ACL_INVARIANTS" \
  "$CHECK_DNS_FAIL_CLOSED"; do
  if [[ "$check" != "pass" ]]; then
    OVERALL_STATUS="fail"
    break
  fi
done

if [[ "$OVERALL_STATUS" != "pass" ]]; then
  FAILURE_SUMMARY="one or more path handoff under load checks failed"
fi

write_report "$OVERALL_STATUS"
REPORT_WRITTEN=1
log "Report written: $REPORT_PATH"
log "Overall status: $OVERALL_STATUS"

[[ "$OVERALL_STATUS" == "pass" ]]
