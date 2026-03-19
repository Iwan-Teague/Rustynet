#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/e2e/live_lab_common.sh"

LIVE_LAB_LOG_PREFIX="cross-network-failback-roaming"
export LIVE_LAB_LOG_PREFIX

SSH_PASSWORD_FILE=""
SUDO_PASSWORD_FILE=""
CLIENT_HOST=""
EXIT_HOST=""
RELAY_HOST=""
CLIENT_NODE_ID=""
EXIT_NODE_ID=""
RELAY_NODE_ID=""
CLIENT_NETWORK_ID=""
EXIT_NETWORK_ID=""
RELAY_NETWORK_ID=""
NAT_PROFILE="baseline_lan"
IMPAIRMENT_PROFILE="none"
SSH_ALLOW_CIDRS="192.168.18.0/24"
REPORT_PATH="$ROOT_DIR/artifacts/phase10/cross_network_failback_roaming_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/cross_network_failback_roaming.log"

WORK_DIR=""
REPORT_WRITTEN=0
FAILURE_SUMMARY="cross-network failback and roaming validator did not complete"
CHECK_RELAY_TO_DIRECT_FAILBACK_SUCCESS="fail"
CHECK_ENDPOINT_ROAM_RECOVERY_SUCCESS="fail"
CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK="fail"
CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="fail"
RELAY_REPORT_PATH=""
RELAY_LOG_PATH=""
BYPASS_REPORT_PATH=""
BYPASS_LOG_PATH=""
FAILBACK_MONITOR_LOG=""
SOURCE_ARTIFACTS=()
LOG_ARTIFACTS=()
CLIENT_ADDR=""
EXIT_ADDR=""
RELAY_ADDR=""
ROAM_ALIAS_IP=""
ROAM_INTERFACE=""
ROAM_PREFIX=""

usage() {
  cat <<'USAGE'
usage: live_linux_cross_network_failback_roaming_test.sh --ssh-password-file <path> --sudo-password-file <path> --client-host <user@host> --exit-host <user@host> --relay-host <user@host> --client-node-id <id> --exit-node-id <id> --relay-node-id <id> --client-network-id <id> --exit-network-id <id> --relay-network-id <id> [options]

options:
  --nat-profile <profile>
  --impairment-profile <profile>
  --ssh-allow-cidrs <cidr[,cidr]>
  --report-path <path>
  --log-path <path>
USAGE
}

write_report() {
  local status="$1"
  local args=(
    python3 "$ROOT_DIR/scripts/e2e/generate_cross_network_remote_exit_report.py"
    --suite cross_network_failback_roaming
    --report-path "$REPORT_PATH"
    --log-path "$LOG_PATH"
    --status "$status"
    --failure-summary "$FAILURE_SUMMARY"
    --implementation-state live_measured_validator
    --client-host "$CLIENT_HOST"
    --exit-host "$EXIT_HOST"
    --relay-host "$RELAY_HOST"
    --client-network-id "$CLIENT_NETWORK_ID"
    --exit-network-id "$EXIT_NETWORK_ID"
    --relay-network-id "$RELAY_NETWORK_ID"
    --nat-profile "$NAT_PROFILE"
    --impairment-profile "$IMPAIRMENT_PROFILE"
    --source-artifact "$ROOT_DIR/scripts/e2e/live_linux_cross_network_failback_roaming_test.sh"
    --check "relay_to_direct_failback_success=${CHECK_RELAY_TO_DIRECT_FAILBACK_SUCCESS}"
    --check "endpoint_roam_recovery_success=${CHECK_ENDPOINT_ROAM_RECOVERY_SUCCESS}"
    --check "remote_exit_no_underlay_leak=${CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK}"
    --check "cross_network_topology_heuristic=${CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC}"
  )
  local item
  for item in "${SOURCE_ARTIFACTS[@]}"; do
    args+=(--source-artifact "$item")
  done
  for item in "${LOG_ARTIFACTS[@]}"; do
    args+=(--log-artifact "$item")
  done
  "${args[@]}"
}

cleanup() {
  local rc=$?
  set +e
  if [[ -n "$ROAM_ALIAS_IP" && -n "$ROAM_INTERFACE" && -n "$ROAM_PREFIX" ]]; then
    live_lab_run_root "$EXIT_HOST" "root ip addr del '${ROAM_ALIAS_IP}/${ROAM_PREFIX}' dev '${ROAM_INTERFACE}' >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
  fi
  if [[ "$REPORT_WRITTEN" -eq 0 ]]; then
    write_report fail
  fi
  REPORT_WRITTEN=1
  if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
    rm -rf "$WORK_DIR"
  fi
  live_lab_cleanup
  exit "$rc"
}

trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-password-file) SSH_PASSWORD_FILE="$2"; shift 2 ;;
    --sudo-password-file) SUDO_PASSWORD_FILE="$2"; shift 2 ;;
    --client-host) CLIENT_HOST="$2"; shift 2 ;;
    --exit-host) EXIT_HOST="$2"; shift 2 ;;
    --relay-host) RELAY_HOST="$2"; shift 2 ;;
    --client-node-id) CLIENT_NODE_ID="$2"; shift 2 ;;
    --exit-node-id) EXIT_NODE_ID="$2"; shift 2 ;;
    --relay-node-id) RELAY_NODE_ID="$2"; shift 2 ;;
    --client-network-id) CLIENT_NETWORK_ID="$2"; shift 2 ;;
    --exit-network-id) EXIT_NETWORK_ID="$2"; shift 2 ;;
    --relay-network-id) RELAY_NETWORK_ID="$2"; shift 2 ;;
    --nat-profile) NAT_PROFILE="$2"; shift 2 ;;
    --impairment-profile) IMPAIRMENT_PROFILE="$2"; shift 2 ;;
    --ssh-allow-cidrs) SSH_ALLOW_CIDRS="$2"; shift 2 ;;
    --report-path) REPORT_PATH="$2"; shift 2 ;;
    --log-path) LOG_PATH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$SSH_PASSWORD_FILE" || -z "$SUDO_PASSWORD_FILE" || -z "$CLIENT_HOST" || -z "$EXIT_HOST" || -z "$RELAY_HOST" || -z "$CLIENT_NODE_ID" || -z "$EXIT_NODE_ID" || -z "$RELAY_NODE_ID" || -z "$CLIENT_NETWORK_ID" || -z "$EXIT_NETWORK_ID" || -z "$RELAY_NETWORK_ID" ]]; then
  usage >&2
  exit 2
fi
if [[ -z "$NAT_PROFILE" || -z "$IMPAIRMENT_PROFILE" ]]; then
  echo "--nat-profile and --impairment-profile must be non-empty" >&2
  exit 2
fi

if [[ "$CLIENT_HOST" == "$EXIT_HOST" || "$CLIENT_HOST" == "$RELAY_HOST" || "$EXIT_HOST" == "$RELAY_HOST" ]]; then
  echo "client, exit, and relay hosts must all differ" >&2
  exit 2
fi

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")"
: > "$LOG_PATH"
exec >> "$LOG_PATH" 2>&1

main() {
  local relay_rc bypass_status
  local switch_ts first_switch_ts reconvergence_secs
  local local_ts
  local client_status client_route client_endpoints
  local issue_script issue_env assign_pub_local exit_assignment_local relay_assignment_local client_assignment_local
  local exit_refresh_local relay_refresh_local client_refresh_local
  local client_status_after_roam client_route_after_roam client_endpoints_after_roam
  local artifact_dir

  FAILURE_SUMMARY="bootstrapping relay remote-exit path before failback"
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rustynet-cross-network-failback-roaming.XXXXXX")"
  artifact_dir="$(dirname "$REPORT_PATH")"
  RELAY_REPORT_PATH="$artifact_dir/cross_network_failback_roaming_relay_stage_report.json"
  RELAY_LOG_PATH="$artifact_dir/cross_network_failback_roaming_relay_stage.log"
  BYPASS_REPORT_PATH="$artifact_dir/cross_network_failback_roaming_server_ip_bypass_report.json"
  BYPASS_LOG_PATH="$artifact_dir/cross_network_failback_roaming_server_ip_bypass.log"
  FAILBACK_MONITOR_LOG="$artifact_dir/cross_network_failback_roaming_monitor.log"
  SOURCE_ARTIFACTS=("$RELAY_REPORT_PATH" "$BYPASS_REPORT_PATH")
  LOG_ARTIFACTS=("$RELAY_LOG_PATH" "$BYPASS_LOG_PATH" "$FAILBACK_MONITOR_LOG")

  if RUSTYNET_EXPECTED_GIT_COMMIT="${RUSTYNET_EXPECTED_GIT_COMMIT:-}" \
    bash "$ROOT_DIR/scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh" \
      --ssh-password-file "$SSH_PASSWORD_FILE" \
      --sudo-password-file "$SUDO_PASSWORD_FILE" \
      --client-host "$CLIENT_HOST" \
      --exit-host "$EXIT_HOST" \
      --relay-host "$RELAY_HOST" \
      --client-node-id "$CLIENT_NODE_ID" \
      --exit-node-id "$EXIT_NODE_ID" \
      --relay-node-id "$RELAY_NODE_ID" \
      --client-network-id "$CLIENT_NETWORK_ID" \
      --exit-network-id "$EXIT_NETWORK_ID" \
      --relay-network-id "$RELAY_NETWORK_ID" \
      --nat-profile "$NAT_PROFILE" \
      --impairment-profile "$IMPAIRMENT_PROFILE" \
      --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
      --report-path "$RELAY_REPORT_PATH" \
      --log-path "$RELAY_LOG_PATH"; then
    relay_rc=0
  else
    relay_rc=$?
  fi

  if [[ ! -f "$RELAY_REPORT_PATH" ]]; then
    FAILURE_SUMMARY="relay bootstrap validator failed before emitting evidence"
    return 1
  fi

  CLIENT_ADDR="$(live_lab_target_address "$CLIENT_HOST")"
  EXIT_ADDR="$(live_lab_target_address "$EXIT_HOST")"
  RELAY_ADDR="$(live_lab_target_address "$RELAY_HOST")"

  if python3 - "$CLIENT_ADDR" "$EXIT_ADDR" <<'PY'
import ipaddress
import sys

client_ip = ipaddress.ip_address(sys.argv[1])
exit_ip = ipaddress.ip_address(sys.argv[2])
prefix = 24 if client_ip.version == 4 else 64
client_net = ipaddress.ip_network(f"{client_ip}/{prefix}", strict=False)
exit_net = ipaddress.ip_network(f"{exit_ip}/{prefix}", strict=False)
raise SystemExit(1 if client_net == exit_net else 0)
PY
  then
    CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="pass"
  else
    CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="fail"
  fi

  FAILURE_SUMMARY="initializing failback and roaming live-lab runtime"
  live_lab_init "rustynet-cross-network-failback-roaming" "$SSH_PASSWORD_FILE" "$SUDO_PASSWORD_FILE"
  live_lab_push_sudo_password "$EXIT_HOST"
  live_lab_push_sudo_password "$RELAY_HOST"
  live_lab_push_sudo_password "$CLIENT_HOST"
  live_lab_wait_for_daemon_socket "$EXIT_HOST"
  live_lab_wait_for_daemon_socket "$RELAY_HOST"
  live_lab_wait_for_daemon_socket "$CLIENT_HOST"

  : > "$FAILBACK_MONITOR_LOG"
  switch_ts="$(date +%s)"
  FAILURE_SUMMARY="switching client from relay exit to direct exit"
  live_lab_apply_role_coupling "$CLIENT_HOST" "client" "$EXIT_NODE_ID" "false" "/etc/rustynet/assignment-refresh.env"

  first_switch_ts=""
  for ((i=1; i<=35; i++)); do
    local_ts="$(date +%s)"
    client_status="$(live_lab_status "$CLIENT_HOST")"
    client_route="$(live_lab_capture "$CLIENT_HOST" "ip -4 route get 1.1.1.1 || true")"
    client_endpoints="$(live_lab_capture_root "$CLIENT_HOST" "root wg show rustynet0 endpoints || true")"
    printf '%s|iter=%s|route=%s|status=%s|endpoints=%s\n' \
      "$local_ts" "$i" \
      "$(printf '%s' "$client_route" | tr -s ' ' | tr '\n' ';')" \
      "$(printf '%s' "$client_status" | tr -s ' ' | tr '\n' ';')" \
      "$(printf '%s' "$client_endpoints" | tr -s ' ' | tr '\n' ';')" >> "$FAILBACK_MONITOR_LOG"
    if [[ -z "$first_switch_ts" ]] && grep -Fq "exit_node=${EXIT_NODE_ID}" <<<"$client_status" && grep -Fq 'dev rustynet0' <<<"$client_route"; then
      first_switch_ts="$local_ts"
    fi
    sleep 1
  done

  if [[ -n "$first_switch_ts" ]]; then
    reconvergence_secs=$((first_switch_ts - switch_ts))
  else
    reconvergence_secs=-1
  fi

  if python3 - "$RELAY_REPORT_PATH" "$reconvergence_secs" "$CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC" <<'PY'
import json
import sys

payload = json.loads(open(sys.argv[1], encoding="utf-8").read())
reconvergence_secs = int(sys.argv[2])
topology_ok = sys.argv[3] == "pass"
relay_ok = payload.get("checks", {}).get("relay_remote_exit_success") == "pass"
if relay_ok and topology_ok and 0 <= reconvergence_secs <= 30:
    raise SystemExit(0)
raise SystemExit(1)
PY
  then
    CHECK_RELAY_TO_DIRECT_FAILBACK_SUCCESS="pass"
  fi

  FAILURE_SUMMARY="computing endpoint roam alias and issuing updated signed assignments"
  mapfile -t roam_values < <(python3 - "$EXIT_ADDR" "$CLIENT_ADDR" "$RELAY_ADDR" <<'PY'
import ipaddress
import sys

exit_ip = ipaddress.ip_address(sys.argv[1])
used = {ipaddress.ip_address(value) for value in sys.argv[1:] if value}
if exit_ip.version == 4:
    prefix = 24
    network = ipaddress.ip_network(f"{exit_ip}/{prefix}", strict=False)
    candidate = None
    for raw in range(int(network.broadcast_address) - 1, int(network.network_address), -1):
        ip = ipaddress.ip_address(raw)
        if ip not in used:
            candidate = ip
            break
else:
    prefix = 64
    candidate = exit_ip + 0x100
    if candidate in used:
        candidate = exit_ip + 0x101
print(str(candidate))
print(prefix)
PY
)
  ROAM_ALIAS_IP="${roam_values[0]}"
  ROAM_PREFIX="${roam_values[1]}"
  ROAM_INTERFACE="$(live_lab_capture "$EXIT_HOST" "ip -4 route get '$CLIENT_ADDR' 2>/dev/null | awk '{for (i=1; i<=NF; i++) if (\$i == \"dev\") {print \$(i+1); exit}}' || true")"
  if [[ -z "$ROAM_INTERFACE" ]]; then
    FAILURE_SUMMARY="failed to determine exit underlay interface for endpoint roam"
    return 1
  fi

  live_lab_run_root "$EXIT_HOST" "root ip addr show dev '$ROAM_INTERFACE' | grep -Fq '${ROAM_ALIAS_IP}/${ROAM_PREFIX}' || root ip addr add '${ROAM_ALIAS_IP}/${ROAM_PREFIX}' dev '$ROAM_INTERFACE'"

  issue_script="$LIVE_LAB_WORK_DIR/rn_issue_cross_network_roam.sh"
  issue_env="$LIVE_LAB_WORK_DIR/rn_issue_cross_network_roam.env"
  assign_pub_local="$LIVE_LAB_WORK_DIR/assignment.pub"
  exit_assignment_local="$LIVE_LAB_WORK_DIR/assignment-exit"
  relay_assignment_local="$LIVE_LAB_WORK_DIR/assignment-relay"
  client_assignment_local="$LIVE_LAB_WORK_DIR/assignment-client"
  exit_refresh_local="$LIVE_LAB_WORK_DIR/assignment-refresh-exit.env"
  relay_refresh_local="$LIVE_LAB_WORK_DIR/assignment-refresh-relay.env"
  client_refresh_local="$LIVE_LAB_WORK_DIR/assignment-refresh-client.env"

  EXIT_PUB_HEX="$(live_lab_collect_pubkey_hex "$EXIT_HOST")"
  RELAY_PUB_HEX="$(live_lab_collect_pubkey_hex "$RELAY_HOST")"
  CLIENT_PUB_HEX="$(live_lab_collect_pubkey_hex "$CLIENT_HOST")"
  NODES_SPEC="${EXIT_NODE_ID}|${ROAM_ALIAS_IP}:51820|${EXIT_PUB_HEX};${RELAY_NODE_ID}|${RELAY_ADDR}:51820|${RELAY_PUB_HEX};${CLIENT_NODE_ID}|${CLIENT_ADDR}:51820|${CLIENT_PUB_HEX}"
  ALLOW_SPEC="${CLIENT_NODE_ID}|${RELAY_NODE_ID};${RELAY_NODE_ID}|${CLIENT_NODE_ID};${CLIENT_NODE_ID}|${EXIT_NODE_ID};${EXIT_NODE_ID}|${CLIENT_NODE_ID};${RELAY_NODE_ID}|${EXIT_NODE_ID};${EXIT_NODE_ID}|${RELAY_NODE_ID}"

  cat > "$issue_script" <<'ISSUEEOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: rn_issue_cross_network_roam.sh <env-file>" >&2
  exit 2
fi

source "$1"

root() {
  sudo -S -p '' "$@" < /tmp/rn_sudo.pass
}

PASS_FILE="$(mktemp /tmp/rn-cross-network-roam-passphrase.XXXXXX)"
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

issue_bundle "$EXIT_NODE_ID" "rn-assignment-$EXIT_NODE_ID.assignment"
issue_bundle "$RELAY_NODE_ID" "rn-assignment-$RELAY_NODE_ID.assignment" --exit-node-id "$EXIT_NODE_ID"
issue_bundle "$CLIENT_NODE_ID" "rn-assignment-$CLIENT_NODE_ID.assignment" --exit-node-id "$EXIT_NODE_ID"
ISSUEEOF
  chmod 700 "$issue_script"

  : > "$issue_env"
  live_lab_append_env_assignment "$issue_env" "EXIT_NODE_ID" "$EXIT_NODE_ID"
  live_lab_append_env_assignment "$issue_env" "RELAY_NODE_ID" "$RELAY_NODE_ID"
  live_lab_append_env_assignment "$issue_env" "CLIENT_NODE_ID" "$CLIENT_NODE_ID"
  live_lab_append_env_assignment "$issue_env" "NODES_SPEC" "$NODES_SPEC"
  live_lab_append_env_assignment "$issue_env" "ALLOW_SPEC" "$ALLOW_SPEC"

  live_lab_scp_to "$issue_script" "$EXIT_HOST" "/tmp/rn_issue_cross_network_roam.sh"
  live_lab_scp_to "$issue_env" "$EXIT_HOST" "/tmp/rn_issue_cross_network_roam.env"
  live_lab_run_root "$EXIT_HOST" "root chmod 700 /tmp/rn_issue_cross_network_roam.sh && root bash /tmp/rn_issue_cross_network_roam.sh /tmp/rn_issue_cross_network_roam.env"
  live_lab_run_root "$EXIT_HOST" "root rm -f /tmp/rn_issue_cross_network_roam.sh /tmp/rn_issue_cross_network_roam.env"

  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment.pub" > "$assign_pub_local"
  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$EXIT_NODE_ID.assignment" > "$exit_assignment_local"
  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$RELAY_NODE_ID.assignment" > "$relay_assignment_local"
  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$CLIENT_NODE_ID.assignment" > "$client_assignment_local"

  live_lab_install_assignment_bundle "$EXIT_HOST" "$assign_pub_local" "$exit_assignment_local"
  live_lab_install_assignment_bundle "$RELAY_HOST" "$assign_pub_local" "$relay_assignment_local"
  live_lab_install_assignment_bundle "$CLIENT_HOST" "$assign_pub_local" "$client_assignment_local"

  live_lab_write_assignment_refresh_env "$exit_refresh_local" "$EXIT_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC"
  live_lab_write_assignment_refresh_env "$relay_refresh_local" "$RELAY_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC" "$EXIT_NODE_ID"
  live_lab_write_assignment_refresh_env "$client_refresh_local" "$CLIENT_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC" "$EXIT_NODE_ID"
  live_lab_install_assignment_refresh_env "$EXIT_HOST" "$exit_refresh_local"
  live_lab_install_assignment_refresh_env "$RELAY_HOST" "$relay_refresh_local"
  live_lab_install_assignment_refresh_env "$CLIENT_HOST" "$client_refresh_local"

  live_lab_enforce_host "$EXIT_HOST" "admin" "$EXIT_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$EXIT_HOST")"
  live_lab_enforce_host "$RELAY_HOST" "admin" "$RELAY_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$RELAY_HOST")"
  live_lab_enforce_host "$CLIENT_HOST" "client" "$CLIENT_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$CLIENT_HOST")"
  live_lab_wait_for_daemon_socket "$EXIT_HOST"
  live_lab_wait_for_daemon_socket "$RELAY_HOST"
  live_lab_wait_for_daemon_socket "$CLIENT_HOST"
  live_lab_retry_root "$EXIT_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 0.0.0.0/0" 10 2
  live_lab_retry_root "$RELAY_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 0.0.0.0/0" 10 2
  sleep 5

  FAILURE_SUMMARY="capturing endpoint roam recovery evidence"
  client_status_after_roam="$(live_lab_status "$CLIENT_HOST")"
  client_route_after_roam="$(live_lab_capture "$CLIENT_HOST" "ip -4 route get 1.1.1.1 || true")"
  client_endpoints_after_roam="$(live_lab_capture_root "$CLIENT_HOST" "root wg show rustynet0 endpoints || true")"
  live_lab_log "Client status after roam"
  printf '%s\n' "$client_status_after_roam"
  live_lab_log "Client route after roam"
  printf '%s\n' "$client_route_after_roam"
  live_lab_log "Client endpoints after roam"
  printf '%s\n' "$client_endpoints_after_roam"

  if grep -Fq "exit_node=${EXIT_NODE_ID}" <<<"$client_status_after_roam" && grep -Fq 'dev rustynet0' <<<"$client_route_after_roam" && grep -Fq "${ROAM_ALIAS_IP}:51820" <<<"$client_endpoints_after_roam"; then
    CHECK_ENDPOINT_ROAM_RECOVERY_SUCCESS="pass"
  fi

  FAILURE_SUMMARY="validating narrow server-IP bypass and leak resistance after endpoint roam"
  if RUSTYNET_EXPECTED_GIT_COMMIT="${RUSTYNET_EXPECTED_GIT_COMMIT:-}" \
    bash "$ROOT_DIR/scripts/e2e/live_linux_server_ip_bypass_test.sh" \
      --ssh-password-file "$SSH_PASSWORD_FILE" \
      --sudo-password-file "$SUDO_PASSWORD_FILE" \
      --client-host "$CLIENT_HOST" \
      --probe-host "$EXIT_HOST" \
      --probe-bind-ip "$ROAM_ALIAS_IP" \
      --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
      --report-path "$BYPASS_REPORT_PATH" \
      --log-path "$BYPASS_LOG_PATH"; then
    bypass_status=0
  else
    bypass_status=$?
  fi

  if [[ "$bypass_status" -ne 0 && ! -f "$BYPASS_REPORT_PATH" ]]; then
    FAILURE_SUMMARY="server-IP bypass validator failed before emitting failback/roaming evidence"
    return 1
  fi

  mapfile -t bypass_results < <(python3 - "$BYPASS_REPORT_PATH" <<'PY'
import json
import sys

payload = json.loads(open(sys.argv[1], encoding="utf-8").read())
checks = payload.get("checks", {})
print(checks.get("internet_route_via_rustynet0", "fail"))
print(checks.get("probe_service_blocked_from_client", "fail"))
PY
)

  if [[ "${bypass_results[0]}" == 'pass' && "${bypass_results[1]}" == 'pass' ]]; then
    CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK="pass"
  fi

  if [[ "$CHECK_RELAY_TO_DIRECT_FAILBACK_SUCCESS" != 'pass' ]]; then
    FAILURE_SUMMARY="relay-to-direct failback did not reconverge securely"
    return 1
  fi
  if [[ "$CHECK_ENDPOINT_ROAM_RECOVERY_SUCCESS" != 'pass' ]]; then
    FAILURE_SUMMARY="client did not recover after signed endpoint roam"
    return 1
  fi
  if [[ "$CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK" != 'pass' ]]; then
    FAILURE_SUMMARY="post-roam path leaked or could not prove leak resistance"
    return 1
  fi

  FAILURE_SUMMARY=""
  [[ "$relay_rc" -eq 0 ]]
}

if main; then
  write_report pass
  REPORT_WRITTEN=1
else
  write_report fail
  REPORT_WRITTEN=1
  exit 1
fi

live_lab_log "Cross-network failback and roaming report written: $REPORT_PATH"
