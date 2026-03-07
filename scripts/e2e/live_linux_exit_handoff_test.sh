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
CLIENT_HOST="debian@192.168.18.50"
EXIT_A_NODE_ID="exit-49"
EXIT_B_NODE_ID="client-53"
CLIENT_NODE_ID="client-50"
SSH_ALLOW_CIDRS="192.168.18.0/24"
SSH_PASSWORD_FILE=""
SUDO_PASSWORD_FILE=""
REPORT_PATH="$ROOT_DIR/artifacts/phase10/live_linux_exit_handoff_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/live_linux_exit_handoff.log"
MONITOR_LOG="$ROOT_DIR/artifacts/phase10/source/live_linux_exit_handoff_monitor.log"
SWITCH_ITERATION=20
MONITOR_ITERATIONS=55

usage() {
  cat <<USAGE
usage: $0 --ssh-password-file <path> --sudo-password-file <path> [options]

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
  --report-path <path>
  --log-path <path>
  --monitor-log <path>
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-password-file) SSH_PASSWORD_FILE="$2"; shift 2 ;;
    --sudo-password-file) SUDO_PASSWORD_FILE="$2"; shift 2 ;;
    --exit-a-host) EXIT_A_HOST="$2"; shift 2 ;;
    --exit-b-host) EXIT_B_HOST="$2"; shift 2 ;;
    --client-host) CLIENT_HOST="$2"; shift 2 ;;
    --exit-a-node-id) EXIT_A_NODE_ID="$2"; shift 2 ;;
    --exit-b-node-id) EXIT_B_NODE_ID="$2"; shift 2 ;;
    --client-node-id) CLIENT_NODE_ID="$2"; shift 2 ;;
    --ssh-allow-cidrs) SSH_ALLOW_CIDRS="$2"; shift 2 ;;
    --switch-iteration) SWITCH_ITERATION="$2"; shift 2 ;;
    --monitor-iterations) MONITOR_ITERATIONS="$2"; shift 2 ;;
    --report-path) REPORT_PATH="$2"; shift 2 ;;
    --log-path) LOG_PATH="$2"; shift 2 ;;
    --monitor-log) MONITOR_LOG="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$SSH_PASSWORD_FILE" || -z "$SUDO_PASSWORD_FILE" ]]; then
  usage >&2
  exit 2
fi

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")" "$(dirname "$MONITOR_LOG")"
exec > >(tee "$LOG_PATH") 2>&1

live_lab_init "rustynet-exit-handoff" "$SSH_PASSWORD_FILE" "$SUDO_PASSWORD_FILE"
trap 'live_lab_cleanup' EXIT

ISSUE_SCRIPT="$LIVE_LAB_WORK_DIR/rn_issue_handoff.sh"
ISSUE_ENV="$LIVE_LAB_WORK_DIR/rn_issue_handoff.env"
ASSIGN_PUB_LOCAL="$LIVE_LAB_WORK_DIR/assignment.pub"
EXIT_A_ASSIGNMENT_LOCAL="$LIVE_LAB_WORK_DIR/assignment-exit-a"
EXIT_B_ASSIGNMENT_LOCAL="$LIVE_LAB_WORK_DIR/assignment-exit-b"
CLIENT_ASSIGNMENT_LOCAL="$LIVE_LAB_WORK_DIR/assignment-client"
EXIT_A_REFRESH_LOCAL="$LIVE_LAB_WORK_DIR/assignment-refresh-exit-a.env"
EXIT_B_REFRESH_LOCAL="$LIVE_LAB_WORK_DIR/assignment-refresh-exit-b.env"
CLIENT_REFRESH_LOCAL="$LIVE_LAB_WORK_DIR/assignment-refresh-client.env"

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

cat > "$ISSUE_SCRIPT" <<'ISSUEEOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: rn_issue_handoff.sh <env-file>" >&2
  exit 2
fi

source "$1"

root() {
  sudo -S -p '' "$@" < /tmp/rn_sudo.pass
}

PASS_FILE="$(mktemp /tmp/rn-handoff-passphrase.XXXXXX)"
cleanup() {
  if [[ -f "$PASS_FILE" ]]; then
    root rustynet ops secure-remove --path "$PASS_FILE" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

root rustynet ops materialize-signing-passphrase --output "$PASS_FILE"
root chmod 0600 "$PASS_FILE"

ISSUE_DIR="/run/rustynet/assignment-issue"
root rm -rf "$ISSUE_DIR"
root install -d -m 0700 "$ISSUE_DIR"

issue_bundle() {
  local target_node_id="$1"
  local output_name="$2"
  shift 2
  root rustynet assignment issue \
    --target-node-id "$target_node_id" \
    --nodes "$NODES_SPEC" \
    --allow "$ALLOW_SPEC" \
    --signing-secret /etc/rustynet/assignment.signing.secret \
    --signing-secret-passphrase-file "$PASS_FILE" \
    --output "$ISSUE_DIR/$output_name" \
    --verifier-key-output "$ISSUE_DIR/rn-assignment.pub" \
    "$@" \
    --ttl-secs 300
}

issue_bundle "$EXIT_A_NODE_ID" "rn-assignment-$EXIT_A_NODE_ID.assignment"
issue_bundle "$EXIT_B_NODE_ID" "rn-assignment-$EXIT_B_NODE_ID.assignment"
issue_bundle "$CLIENT_NODE_ID" "rn-assignment-$CLIENT_NODE_ID.assignment" --exit-node-id "$EXIT_A_NODE_ID"
ISSUEEOF
chmod 700 "$ISSUE_SCRIPT"

: > "$ISSUE_ENV"
live_lab_append_env_assignment "$ISSUE_ENV" "EXIT_A_NODE_ID" "$EXIT_A_NODE_ID"
live_lab_append_env_assignment "$ISSUE_ENV" "EXIT_B_NODE_ID" "$EXIT_B_NODE_ID"
live_lab_append_env_assignment "$ISSUE_ENV" "CLIENT_NODE_ID" "$CLIENT_NODE_ID"
live_lab_append_env_assignment "$ISSUE_ENV" "NODES_SPEC" "$NODES_SPEC"
live_lab_append_env_assignment "$ISSUE_ENV" "ALLOW_SPEC" "$ALLOW_SPEC"

live_lab_log "Issuing signed handoff assignments on $EXIT_A_HOST"
live_lab_scp_to "$ISSUE_SCRIPT" "$EXIT_A_HOST" "/tmp/rn_issue_handoff.sh"
live_lab_scp_to "$ISSUE_ENV" "$EXIT_A_HOST" "/tmp/rn_issue_handoff.env"
live_lab_run_root "$EXIT_A_HOST" "root chmod 700 /tmp/rn_issue_handoff.sh && root bash /tmp/rn_issue_handoff.sh /tmp/rn_issue_handoff.env"
live_lab_run_root "$EXIT_A_HOST" "root rm -f /tmp/rn_issue_handoff.sh /tmp/rn_issue_handoff.env"

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
for ((i=1; i<=MONITOR_ITERATIONS; i++)); do
  ts="$(date +%s)"
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
git_commit="$(git rev-parse HEAD)"
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
