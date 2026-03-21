#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/e2e/live_lab_common.sh"

LIVE_LAB_LOG_PREFIX="exit-handoff"
export LIVE_LAB_LOG_PREFIX

EXIT_A_HOST="debian@192.168.18.49"
EXIT_B_HOST="mint@192.168.18.53"
CLIENT_HOST="debian@192.168.18.65"
EXIT_A_NODE_ID="exit-49"
EXIT_B_NODE_ID="client-53"
CLIENT_NODE_ID="client-65"
SSH_ALLOW_CIDRS="192.168.18.0/24"
SSH_IDENTITY_FILE=""
REPORT_PATH="$ROOT_DIR/artifacts/phase10/live_linux_exit_handoff_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/live_linux_exit_handoff.log"
MONITOR_LOG="$ROOT_DIR/artifacts/phase10/source/live_linux_exit_handoff_monitor.log"
SWITCH_ITERATION=20
MONITOR_ITERATIONS=55
TRAVERSAL_TTL_SECS=120
TRAVERSAL_REFRESH_INTERVAL_SECS=45

usage() {
  cat <<USAGE
usage: $0 --ssh-identity-file <path> [options]

options:
  --exit-a-host <user@host>
  --exit-b-host <user@host>
  --client-host <user@host>
  --exit-a-node-id <id>
  --exit-b-node-id <id>
  --client-node-id <id>
  --ssh-allow-cidrs <cidrs>
  --switch-iteration <n>
  --monitor-iterations <n>
  --traversal-ttl-secs <n>   (1-120)
  --report-path <path>
  --log-path <path>
  --monitor-log <path>
USAGE
}

validate_positive_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value <= 0 )); then
    printf '%s must be a positive integer (got: %s)\n' "$name" "$value" >&2
    exit 2
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-identity-file) SSH_IDENTITY_FILE="$2"; shift 2 ;;
    --exit-a-host) EXIT_A_HOST="$2"; shift 2 ;;
    --exit-b-host) EXIT_B_HOST="$2"; shift 2 ;;
    --client-host) CLIENT_HOST="$2"; shift 2 ;;
    --exit-a-node-id) EXIT_A_NODE_ID="$2"; shift 2 ;;
    --exit-b-node-id) EXIT_B_NODE_ID="$2"; shift 2 ;;
    --client-node-id) CLIENT_NODE_ID="$2"; shift 2 ;;
    --ssh-allow-cidrs) SSH_ALLOW_CIDRS="$2"; shift 2 ;;
    --switch-iteration) SWITCH_ITERATION="$2"; shift 2 ;;
    --monitor-iterations) MONITOR_ITERATIONS="$2"; shift 2 ;;
    --traversal-ttl-secs) TRAVERSAL_TTL_SECS="$2"; shift 2 ;;
    --report-path) REPORT_PATH="$2"; shift 2 ;;
    --log-path) LOG_PATH="$2"; shift 2 ;;
    --monitor-log) MONITOR_LOG="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$SSH_IDENTITY_FILE" ]]; then
  usage >&2
  exit 2
fi

validate_positive_integer "switch iteration" "$SWITCH_ITERATION"
validate_positive_integer "monitor iterations" "$MONITOR_ITERATIONS"
if [[ ! "$TRAVERSAL_TTL_SECS" =~ ^[0-9]+$ ]]; then
  printf 'traversal ttl seconds must be an integer (got: %s)\n' "$TRAVERSAL_TTL_SECS" >&2
  exit 2
fi
if (( TRAVERSAL_TTL_SECS > 120 )); then
  printf 'traversal ttl seconds must be <= 120 (got: %s)\n' "$TRAVERSAL_TTL_SECS" >&2
  exit 2
fi
validate_positive_integer "traversal ttl seconds" "$TRAVERSAL_TTL_SECS"
if (( TRAVERSAL_TTL_SECS <= 30 )); then
  TRAVERSAL_REFRESH_INTERVAL_SECS=10
else
  TRAVERSAL_REFRESH_INTERVAL_SECS=$((TRAVERSAL_TTL_SECS / 2))
fi

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")" "$(dirname "$MONITOR_LOG")"
exec > >(tee "$LOG_PATH") 2>&1

live_lab_init "rustynet-exit-handoff" "$SSH_IDENTITY_FILE"
trap 'live_lab_cleanup' EXIT
live_lab_log "Traversal bundle TTL for handoff stage: ${TRAVERSAL_TTL_SECS}s (refresh every ${TRAVERSAL_REFRESH_INTERVAL_SECS}s)"

ISSUE_ENV="$LIVE_LAB_WORK_DIR/rn_issue_handoff.env"
ASSIGN_PUB_LOCAL="$LIVE_LAB_WORK_DIR/assignment.pub"
EXIT_A_ASSIGNMENT_LOCAL="$LIVE_LAB_WORK_DIR/assignment-exit-a"
EXIT_B_ASSIGNMENT_LOCAL="$LIVE_LAB_WORK_DIR/assignment-exit-b"
CLIENT_ASSIGNMENT_LOCAL="$LIVE_LAB_WORK_DIR/assignment-client"
EXIT_A_REFRESH_LOCAL="$LIVE_LAB_WORK_DIR/assignment-refresh-exit-a.env"
EXIT_B_REFRESH_LOCAL="$LIVE_LAB_WORK_DIR/assignment-refresh-exit-b.env"
CLIENT_REFRESH_LOCAL="$LIVE_LAB_WORK_DIR/assignment-refresh-client.env"
TRAVERSAL_ENV="$LIVE_LAB_WORK_DIR/rn_issue_handoff_traversal.env"
TRAVERSAL_PUB_LOCAL="$LIVE_LAB_WORK_DIR/traversal.pub"
EXIT_A_TRAVERSAL_LOCAL="$LIVE_LAB_WORK_DIR/traversal-exit-a"
EXIT_B_TRAVERSAL_LOCAL="$LIVE_LAB_WORK_DIR/traversal-exit-b"
CLIENT_TRAVERSAL_LOCAL="$LIVE_LAB_WORK_DIR/traversal-client"

for host in "$EXIT_A_HOST" "$EXIT_B_HOST" "$CLIENT_HOST"; do
  live_lab_push_sudo_password "$host"
done

live_lab_log "Collecting WireGuard public keys"
EXIT_A_PUB_HEX="$(live_lab_collect_pubkey_hex "$EXIT_A_HOST")"
EXIT_B_PUB_HEX="$(live_lab_collect_pubkey_hex "$EXIT_B_HOST")"
CLIENT_PUB_HEX="$(live_lab_collect_pubkey_hex "$CLIENT_HOST")"

EXIT_A_ADDR="$(live_lab_target_address "$EXIT_A_HOST")"
EXIT_B_ADDR="$(live_lab_target_address "$EXIT_B_HOST")"
CLIENT_ADDR="$(live_lab_target_address "$CLIENT_HOST")"

NODES_SPEC="${EXIT_A_NODE_ID}|${EXIT_A_ADDR}:51820|${EXIT_A_PUB_HEX};${EXIT_B_NODE_ID}|${EXIT_B_ADDR}:51820|${EXIT_B_PUB_HEX};${CLIENT_NODE_ID}|${CLIENT_ADDR}:51820|${CLIENT_PUB_HEX}"
ALLOW_SPEC="${CLIENT_NODE_ID}|${EXIT_A_NODE_ID};${EXIT_A_NODE_ID}|${CLIENT_NODE_ID};${CLIENT_NODE_ID}|${EXIT_B_NODE_ID};${EXIT_B_NODE_ID}|${CLIENT_NODE_ID}"

: > "$ISSUE_ENV"
live_lab_append_env_assignment "$ISSUE_ENV" "NODES_SPEC" "$NODES_SPEC"
live_lab_append_env_assignment "$ISSUE_ENV" "ALLOW_SPEC" "$ALLOW_SPEC"
live_lab_append_env_assignment "$ISSUE_ENV" "ASSIGNMENTS_SPEC" "${EXIT_A_NODE_ID}|-;${EXIT_B_NODE_ID}|-;${CLIENT_NODE_ID}|${EXIT_A_NODE_ID}"

live_lab_log "Issuing signed handoff assignments on $EXIT_A_HOST"
live_lab_issue_assignment_bundles_from_env "$EXIT_A_HOST" "$ISSUE_ENV" "/tmp/rn_issue_handoff.env"

live_lab_capture_root "$EXIT_A_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment.pub" > "$ASSIGN_PUB_LOCAL"
live_lab_capture_root "$EXIT_A_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$EXIT_A_NODE_ID.assignment" > "$EXIT_A_ASSIGNMENT_LOCAL"
live_lab_capture_root "$EXIT_A_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$EXIT_B_NODE_ID.assignment" > "$EXIT_B_ASSIGNMENT_LOCAL"
live_lab_capture_root "$EXIT_A_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$CLIENT_NODE_ID.assignment" > "$CLIENT_ASSIGNMENT_LOCAL"

live_lab_log "Distributing signed assignments"
live_lab_install_assignment_bundle "$EXIT_A_HOST" "$ASSIGN_PUB_LOCAL" "$EXIT_A_ASSIGNMENT_LOCAL"
live_lab_install_assignment_bundle "$EXIT_B_HOST" "$ASSIGN_PUB_LOCAL" "$EXIT_B_ASSIGNMENT_LOCAL"
live_lab_install_assignment_bundle "$CLIENT_HOST" "$ASSIGN_PUB_LOCAL" "$CLIENT_ASSIGNMENT_LOCAL"

live_lab_write_assignment_refresh_env "$EXIT_A_REFRESH_LOCAL" "$EXIT_A_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC"
live_lab_write_assignment_refresh_env "$EXIT_B_REFRESH_LOCAL" "$EXIT_B_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC"
live_lab_write_assignment_refresh_env "$CLIENT_REFRESH_LOCAL" "$CLIENT_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC" "$EXIT_A_NODE_ID"

live_lab_install_assignment_refresh_env "$EXIT_A_HOST" "$EXIT_A_REFRESH_LOCAL"
live_lab_install_assignment_refresh_env "$EXIT_B_HOST" "$EXIT_B_REFRESH_LOCAL"
live_lab_install_assignment_refresh_env "$CLIENT_HOST" "$CLIENT_REFRESH_LOCAL"

: > "$TRAVERSAL_ENV"
live_lab_append_env_assignment "$TRAVERSAL_ENV" "NODES_SPEC" "$NODES_SPEC"
live_lab_append_env_assignment "$TRAVERSAL_ENV" "ALLOW_SPEC" "$ALLOW_SPEC"
live_lab_append_env_assignment "$TRAVERSAL_ENV" "TRAVERSAL_TTL_SECS" "$TRAVERSAL_TTL_SECS"

install_traversal_bundle() {
  local host="$1"
  local bundle_local="$2"
  live_lab_scp_to "$TRAVERSAL_PUB_LOCAL" "$host" "/tmp/rn-traversal.pub"
  live_lab_scp_to "$bundle_local" "$host" "/tmp/rn-traversal.bundle"
  live_lab_run_root "$host" "root install -m 0644 -o root -g root /tmp/rn-traversal.pub /etc/rustynet/traversal.pub && root install -m 0640 -o root -g rustynetd /tmp/rn-traversal.bundle /var/lib/rustynet/rustynetd.traversal && root rm -f /var/lib/rustynet/rustynetd.traversal.watermark /tmp/rn-traversal.pub /tmp/rn-traversal.bundle"
}

refresh_traversal_bundles() {
  live_lab_log "Issuing signed traversal bundles for handoff topology"
  live_lab_issue_traversal_bundles_from_env "$EXIT_A_HOST" "$TRAVERSAL_ENV" "/tmp/rn_issue_handoff_traversal.env"

  live_lab_capture_root "$EXIT_A_HOST" "root cat /run/rustynet/traversal-issue/rn-traversal.pub" > "$TRAVERSAL_PUB_LOCAL"
  live_lab_capture_root "$EXIT_A_HOST" "root cat /run/rustynet/traversal-issue/rn-traversal-$EXIT_A_NODE_ID.traversal" > "$EXIT_A_TRAVERSAL_LOCAL"
  live_lab_capture_root "$EXIT_A_HOST" "root cat /run/rustynet/traversal-issue/rn-traversal-$EXIT_B_NODE_ID.traversal" > "$EXIT_B_TRAVERSAL_LOCAL"
  live_lab_capture_root "$EXIT_A_HOST" "root cat /run/rustynet/traversal-issue/rn-traversal-$CLIENT_NODE_ID.traversal" > "$CLIENT_TRAVERSAL_LOCAL"

  live_lab_log "Distributing signed traversal bundles"
  install_traversal_bundle "$EXIT_A_HOST" "$EXIT_A_TRAVERSAL_LOCAL"
  install_traversal_bundle "$EXIT_B_HOST" "$EXIT_B_TRAVERSAL_LOCAL"
  install_traversal_bundle "$CLIENT_HOST" "$CLIENT_TRAVERSAL_LOCAL"
}

refresh_traversal_bundles

live_lab_log "Enforcing runtime roles"
live_lab_enforce_host "$EXIT_A_HOST" "admin" "$EXIT_A_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$EXIT_A_HOST")"
live_lab_enforce_host "$EXIT_B_HOST" "admin" "$EXIT_B_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$EXIT_B_HOST")"
live_lab_enforce_host "$CLIENT_HOST" "client" "$CLIENT_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$CLIENT_HOST")"
live_lab_wait_for_daemon_socket "$EXIT_A_HOST"
live_lab_wait_for_daemon_socket "$EXIT_B_HOST"
live_lab_wait_for_daemon_socket "$CLIENT_HOST"

live_lab_log "Advertising default route on both exits"
live_lab_retry_root "$EXIT_A_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 0.0.0.0/0" 10 2
live_lab_retry_root "$EXIT_B_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 0.0.0.0/0" 10 2

sleep 5
: > "$MONITOR_LOG"

switch_ts=0
last_traversal_refresh_ts="$(date +%s)"
for ((i=1; i<=MONITOR_ITERATIONS; i++)); do
  ts="$(date +%s)"
  if (( ts - last_traversal_refresh_ts >= TRAVERSAL_REFRESH_INTERVAL_SECS )); then
    live_lab_log "Refreshing signed traversal bundles during handoff monitor"
    refresh_traversal_bundles
    last_traversal_refresh_ts="$(date +%s)"
    ts="$last_traversal_refresh_ts"
  fi
  status="$(live_lab_status "$CLIENT_HOST" | tr -s ' ' | tr -d '\n')"
  route_line="$(live_lab_capture "$CLIENT_HOST" "ip -4 route get 1.1.1.1 2>/dev/null | head -n1 || true" | tr -s ' ' | tr -d '\n')"
  endpoints="$(live_lab_capture_root "$CLIENT_HOST" "root wg show rustynet0 endpoints 2>/dev/null || true" | tr -s ' ' | tr '\n' ';' | tr -d '\r')"
  if live_lab_ssh "$CLIENT_HOST" "ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1" 30; then
    ping_rc=0
  else
    ping_rc=$?
  fi

  printf '%s|iter=%s|ping_rc=%s|route=%s|status=%s|endpoints=%s\n' \
    "$ts" "$i" "$ping_rc" "$route_line" "$status" "$endpoints" >> "$MONITOR_LOG"

  if (( i == SWITCH_ITERATION )); then
    live_lab_log "Refreshing signed traversal bundles before exit switch"
    refresh_traversal_bundles
    last_traversal_refresh_ts="$(date +%s)"
    switch_ts="$ts"
    live_lab_log "Switching client exit to ${EXIT_B_NODE_ID}"
    live_lab_apply_role_coupling "$CLIENT_HOST" "client" "$EXIT_B_NODE_ID" "false" "/etc/rustynet/assignment-refresh.env"
  fi
  sleep 1
done

CLIENT_STATUS_FINAL="$(live_lab_status "$CLIENT_HOST")"
EXIT_A_STATUS_FINAL="$(live_lab_status "$EXIT_A_HOST")"
EXIT_B_STATUS_FINAL="$(live_lab_status "$EXIT_B_HOST")"
CLIENT_ROUTE_FINAL="$(live_lab_capture "$CLIENT_HOST" "ip -4 route get 1.1.1.1 || true")"
CLIENT_ENDPOINTS_FINAL="$(live_lab_capture_root "$CLIENT_HOST" "root wg show rustynet0 endpoints || true")"
EXIT_A_NFT="$(live_lab_capture_root "$EXIT_A_HOST" "root nft list ruleset || true")"
EXIT_B_NFT="$(live_lab_capture_root "$EXIT_B_HOST" "root nft list ruleset || true")"

live_lab_log "Final client status"
printf '%s\n' "$CLIENT_STATUS_FINAL"
live_lab_log "Final exit A status"
printf '%s\n' "$EXIT_A_STATUS_FINAL"
live_lab_log "Final exit B status"
printf '%s\n' "$EXIT_B_STATUS_FINAL"
live_lab_log "Final client route"
printf '%s\n' "$CLIENT_ROUTE_FINAL"
live_lab_log "Final client endpoints"
printf '%s\n' "$CLIENT_ENDPOINTS_FINAL"

route_leak_count="$(awk -F'|' '$0 !~ /route=.*dev rustynet0/ {c++} END {print c+0}' "$MONITOR_LOG")"
restricted_count="$(awk -F'|' '$0 ~ /status=.*restricted_safe_mode=true/ {c++} END {print c+0}' "$MONITOR_LOG")"
first_switch_ts="$(awk -F'|' -v sw="$switch_ts" -v target="$EXIT_B_NODE_ID" '$1 >= sw && $0 ~ ("status=.*exit_node=" target) {print $1; exit}' "$MONITOR_LOG")"
if [[ -n "$first_switch_ts" && "$switch_ts" -gt 0 ]]; then
  reconvergence_secs=$((first_switch_ts - switch_ts))
else
  reconvergence_secs=-1
fi

check_handoff_reconvergence="fail"
check_no_route_leak="fail"
check_no_restricted_safe_mode="fail"
check_exit_b_endpoint_visible="fail"
check_both_exits_nat="fail"

if [[ "$reconvergence_secs" -ge 0 && "$reconvergence_secs" -le 30 ]]; then
  check_handoff_reconvergence="pass"
fi
if [[ "$route_leak_count" == '0' ]]; then
  check_no_route_leak="pass"
fi
if [[ "$restricted_count" == '0' ]]; then
  check_no_restricted_safe_mode="pass"
fi
if grep -Fq "${EXIT_B_ADDR}:51820" <<<"$CLIENT_ENDPOINTS_FINAL" && grep -Fq "exit_node=${EXIT_B_NODE_ID}" <<<"$CLIENT_STATUS_FINAL"; then
  check_exit_b_endpoint_visible="pass"
fi
if grep -Fq 'masquerade' <<<"$EXIT_A_NFT" && grep -Fq 'masquerade' <<<"$EXIT_B_NFT"; then
  check_both_exits_nat="pass"
fi

overall="pass"
for value in \
  "$check_handoff_reconvergence" \
  "$check_no_route_leak" \
  "$check_no_restricted_safe_mode" \
  "$check_exit_b_endpoint_visible" \
  "$check_both_exits_nat"; do
  if [[ "$value" != 'pass' ]]; then
    overall="fail"
    break
  fi
done

captured_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
captured_at_unix="$(date -u +%s)"
git_commit="${RUSTYNET_EXPECTED_GIT_COMMIT:-$(git rev-parse HEAD)}"
git_commit="$(printf '%s' "$git_commit" | tr '[:upper:]' '[:lower:]')"
cat > "$REPORT_PATH" <<EOF_REPORT
{
  "phase": "phase10",
  "mode": "live_linux_exit_handoff",
  "evidence_mode": "measured",
  "captured_at": "${captured_at_utc}",
  "captured_at_unix": ${captured_at_unix},
  "git_commit": "${git_commit}",
  "status": "${overall}",
  "exit_a_host": "${EXIT_A_HOST}",
  "exit_b_host": "${EXIT_B_HOST}",
  "client_host": "${CLIENT_HOST}",
  "switch_iteration": ${SWITCH_ITERATION},
  "monitor_iterations": ${MONITOR_ITERATIONS},
  "reconvergence_seconds": ${reconvergence_secs},
  "checks": {
    "handoff_reconvergence": "${check_handoff_reconvergence}",
    "no_route_leak_during_handoff": "${check_no_route_leak}",
    "no_restricted_safe_mode": "${check_no_restricted_safe_mode}",
    "exit_b_endpoint_visible": "${check_exit_b_endpoint_visible}",
    "both_exits_nat": "${check_both_exits_nat}"
  },
  "source_artifacts": [
    "${LOG_PATH}",
    "${MONITOR_LOG}"
  ]
}
EOF_REPORT

live_lab_log "Exit handoff report written: $REPORT_PATH"
if [[ "$overall" != 'pass' ]]; then
  exit 1
fi
