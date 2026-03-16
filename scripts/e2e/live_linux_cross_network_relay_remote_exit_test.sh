#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/e2e/live_lab_common.sh"

LIVE_LAB_LOG_PREFIX="cross-network-relay-remote-exit"
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
SSH_ALLOW_CIDRS="192.168.18.0/24"
REPORT_PATH="$ROOT_DIR/artifacts/phase10/cross_network_relay_remote_exit_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/cross_network_relay_remote_exit.log"

REPORT_WRITTEN=0
FAILURE_SUMMARY="cross-network relay remote-exit validator did not complete"
CHECK_RELAY_REMOTE_EXIT_SUCCESS="fail"
CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK="fail"
CHECK_REMOTE_EXIT_SERVER_IP_BYPASS_IS_NARROW="fail"
CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="fail"
CHECK_CLIENT_EXIT_IS_RELAY="fail"
CHECK_RELAY_EXIT_IS_FINAL="fail"
CHECK_RELAY_SERVES_EXIT="fail"
CHECK_FINAL_EXIT_SERVES="fail"
CHECK_CLIENT_ROUTE_VIA_RUSTYNET="fail"
CHECK_RELAY_PEER_VISIBILITY="fail"
CHECK_NO_PLAINTEXT_PASSPHRASE_FILES="fail"
CLIENT_ADDR=""
EXIT_ADDR=""
RELAY_ADDR=""
BYPASS_REPORT_PATH=""
BYPASS_LOG_PATH=""
SOURCE_ARTIFACTS=()
LOG_ARTIFACTS=()

usage() {
  cat <<'USAGE'
usage: live_linux_cross_network_relay_remote_exit_test.sh --ssh-password-file <path> --sudo-password-file <path> --client-host <user@host> --exit-host <user@host> --relay-host <user@host> --client-node-id <id> --exit-node-id <id> --relay-node-id <id> --client-network-id <id> --exit-network-id <id> --relay-network-id <id> [options]

options:
  --ssh-allow-cidrs <cidr[,cidr]>
  --report-path <path>
  --log-path <path>
USAGE
}

write_report() {
  local status="$1"
  local args=(
    python3 "$ROOT_DIR/scripts/e2e/generate_cross_network_remote_exit_report.py"
    --suite cross_network_relay_remote_exit
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
    --source-artifact "$ROOT_DIR/scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh"
    --check "relay_remote_exit_success=${CHECK_RELAY_REMOTE_EXIT_SUCCESS}"
    --check "remote_exit_no_underlay_leak=${CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK}"
    --check "remote_exit_server_ip_bypass_is_narrow=${CHECK_REMOTE_EXIT_SERVER_IP_BYPASS_IS_NARROW}"
    --check "cross_network_topology_heuristic=${CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC}"
    --check "client_exit_is_relay=${CHECK_CLIENT_EXIT_IS_RELAY}"
    --check "relay_exit_is_final=${CHECK_RELAY_EXIT_IS_FINAL}"
    --check "relay_serves_exit=${CHECK_RELAY_SERVES_EXIT}"
    --check "final_exit_serves=${CHECK_FINAL_EXIT_SERVES}"
    --check "client_route_via_rustynet0=${CHECK_CLIENT_ROUTE_VIA_RUSTYNET}"
    --check "relay_peer_visibility=${CHECK_RELAY_PEER_VISIBILITY}"
    --check "no_plaintext_passphrase_files=${CHECK_NO_PLAINTEXT_PASSPHRASE_FILES}"
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
  if [[ "$REPORT_WRITTEN" -eq 0 ]]; then
    write_report fail
  fi
  REPORT_WRITTEN=1
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

if [[ "$CLIENT_HOST" == "$EXIT_HOST" || "$CLIENT_HOST" == "$RELAY_HOST" || "$EXIT_HOST" == "$RELAY_HOST" ]]; then
  echo "client, exit, and relay hosts must all differ" >&2
  exit 2
fi

if [[ "$CLIENT_NETWORK_ID" == "$EXIT_NETWORK_ID" || "$CLIENT_NETWORK_ID" == "$RELAY_NETWORK_ID" || "$EXIT_NETWORK_ID" == "$RELAY_NETWORK_ID" ]]; then
  echo "client, exit, and relay network ids must all differ" >&2
  exit 2
fi

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")"
: > "$LOG_PATH"
exec >> "$LOG_PATH" 2>&1

main() {
  local issue_script issue_env assign_pub_local exit_assignment_local relay_assignment_local client_assignment_local
  local exit_refresh_local relay_refresh_local client_refresh_local
  local client_status relay_status exit_status client_route relay_endpoints client_plaintext_check relay_plaintext_check exit_plaintext_check
  local bypass_status
  local artifact_dir

  FAILURE_SUMMARY="initializing relay remote-exit live-lab runtime"
  live_lab_init "rustynet-cross-network-relay-remote-exit" "$SSH_PASSWORD_FILE" "$SUDO_PASSWORD_FILE"

  issue_script="$LIVE_LAB_WORK_DIR/rn_issue_cross_network_relay.sh"
  issue_env="$LIVE_LAB_WORK_DIR/rn_issue_cross_network_relay.env"
  assign_pub_local="$LIVE_LAB_WORK_DIR/assignment.pub"
  exit_assignment_local="$LIVE_LAB_WORK_DIR/assignment-exit"
  relay_assignment_local="$LIVE_LAB_WORK_DIR/assignment-relay"
  client_assignment_local="$LIVE_LAB_WORK_DIR/assignment-client"
  exit_refresh_local="$LIVE_LAB_WORK_DIR/assignment-refresh-exit.env"
  relay_refresh_local="$LIVE_LAB_WORK_DIR/assignment-refresh-relay.env"
  client_refresh_local="$LIVE_LAB_WORK_DIR/assignment-refresh-client.env"
  artifact_dir="$(dirname "$REPORT_PATH")"
  BYPASS_REPORT_PATH="$artifact_dir/cross_network_relay_remote_exit_server_ip_bypass_report.json"
  BYPASS_LOG_PATH="$artifact_dir/cross_network_relay_remote_exit_server_ip_bypass.log"
  SOURCE_ARTIFACTS=("$BYPASS_REPORT_PATH")
  LOG_ARTIFACTS=("$BYPASS_LOG_PATH")

  live_lab_push_sudo_password "$EXIT_HOST"
  live_lab_push_sudo_password "$RELAY_HOST"
  live_lab_push_sudo_password "$CLIENT_HOST"

  live_lab_log "Collecting WireGuard public keys"
  EXIT_PUB_HEX="$(live_lab_collect_pubkey_hex "$EXIT_HOST")"
  RELAY_PUB_HEX="$(live_lab_collect_pubkey_hex "$RELAY_HOST")"
  CLIENT_PUB_HEX="$(live_lab_collect_pubkey_hex "$CLIENT_HOST")"
  EXIT_ADDR="$(live_lab_target_address "$EXIT_HOST")"
  RELAY_ADDR="$(live_lab_target_address "$RELAY_HOST")"
  CLIENT_ADDR="$(live_lab_target_address "$CLIENT_HOST")"

  NODES_SPEC="${EXIT_NODE_ID}|${EXIT_ADDR}:51820|${EXIT_PUB_HEX};${RELAY_NODE_ID}|${RELAY_ADDR}:51820|${RELAY_PUB_HEX};${CLIENT_NODE_ID}|${CLIENT_ADDR}:51820|${CLIENT_PUB_HEX}"
  ALLOW_SPEC="${CLIENT_NODE_ID}|${RELAY_NODE_ID};${RELAY_NODE_ID}|${CLIENT_NODE_ID};${CLIENT_NODE_ID}|${EXIT_NODE_ID};${EXIT_NODE_ID}|${CLIENT_NODE_ID};${RELAY_NODE_ID}|${EXIT_NODE_ID};${EXIT_NODE_ID}|${RELAY_NODE_ID}"

  cat > "$issue_script" <<'ISSUEEOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: rn_issue_cross_network_relay.sh <env-file>" >&2
  exit 2
fi

source "$1"

root() {
  sudo -S -p '' "$@" < /tmp/rn_sudo.pass
}

PASS_FILE="$(mktemp /tmp/rn-cross-network-relay-passphrase.XXXXXX)"
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
issue_bundle "$CLIENT_NODE_ID" "rn-assignment-$CLIENT_NODE_ID.assignment" --exit-node-id "$RELAY_NODE_ID"
ISSUEEOF
  chmod 700 "$issue_script"

  : > "$issue_env"
  live_lab_append_env_assignment "$issue_env" "EXIT_NODE_ID" "$EXIT_NODE_ID"
  live_lab_append_env_assignment "$issue_env" "RELAY_NODE_ID" "$RELAY_NODE_ID"
  live_lab_append_env_assignment "$issue_env" "CLIENT_NODE_ID" "$CLIENT_NODE_ID"
  live_lab_append_env_assignment "$issue_env" "NODES_SPEC" "$NODES_SPEC"
  live_lab_append_env_assignment "$issue_env" "ALLOW_SPEC" "$ALLOW_SPEC"

  live_lab_log "Issuing signed relay remote-exit assignments on $EXIT_HOST"
  live_lab_scp_to "$issue_script" "$EXIT_HOST" "/tmp/rn_issue_cross_network_relay.sh"
  live_lab_scp_to "$issue_env" "$EXIT_HOST" "/tmp/rn_issue_cross_network_relay.env"
  live_lab_run_root "$EXIT_HOST" "root chmod 700 /tmp/rn_issue_cross_network_relay.sh && root bash /tmp/rn_issue_cross_network_relay.sh /tmp/rn_issue_cross_network_relay.env"
  live_lab_run_root "$EXIT_HOST" "root rm -f /tmp/rn_issue_cross_network_relay.sh /tmp/rn_issue_cross_network_relay.env"

  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment.pub" > "$assign_pub_local"
  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$EXIT_NODE_ID.assignment" > "$exit_assignment_local"
  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$RELAY_NODE_ID.assignment" > "$relay_assignment_local"
  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$CLIENT_NODE_ID.assignment" > "$client_assignment_local"

  live_lab_log "Distributing signed assignments"
  live_lab_install_assignment_bundle "$EXIT_HOST" "$assign_pub_local" "$exit_assignment_local"
  live_lab_install_assignment_bundle "$RELAY_HOST" "$assign_pub_local" "$relay_assignment_local"
  live_lab_install_assignment_bundle "$CLIENT_HOST" "$assign_pub_local" "$client_assignment_local"

  live_lab_write_assignment_refresh_env "$exit_refresh_local" "$EXIT_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC"
  live_lab_write_assignment_refresh_env "$relay_refresh_local" "$RELAY_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC" "$EXIT_NODE_ID"
  live_lab_write_assignment_refresh_env "$client_refresh_local" "$CLIENT_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC" "$RELAY_NODE_ID"
  live_lab_install_assignment_refresh_env "$EXIT_HOST" "$exit_refresh_local"
  live_lab_install_assignment_refresh_env "$RELAY_HOST" "$relay_refresh_local"
  live_lab_install_assignment_refresh_env "$CLIENT_HOST" "$client_refresh_local"

  live_lab_log "Enforcing runtime roles"
  live_lab_enforce_host "$EXIT_HOST" "admin" "$EXIT_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$EXIT_HOST")"
  live_lab_enforce_host "$RELAY_HOST" "admin" "$RELAY_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$RELAY_HOST")"
  live_lab_enforce_host "$CLIENT_HOST" "client" "$CLIENT_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$CLIENT_HOST")"
  live_lab_wait_for_daemon_socket "$EXIT_HOST"
  live_lab_wait_for_daemon_socket "$RELAY_HOST"
  live_lab_wait_for_daemon_socket "$CLIENT_HOST"

  live_lab_log "Advertising default route on relay and final exit"
  live_lab_retry_root "$EXIT_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 0.0.0.0/0" 10 2
  live_lab_retry_root "$RELAY_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 0.0.0.0/0" 10 2
  sleep 5

  FAILURE_SUMMARY="capturing relay remote-exit steady-state evidence"
  client_status="$(live_lab_status "$CLIENT_HOST")"
  relay_status="$(live_lab_status "$RELAY_HOST")"
  exit_status="$(live_lab_status "$EXIT_HOST")"
  client_route="$(live_lab_capture "$CLIENT_HOST" "ip -4 route get 1.1.1.1 || true")"
  relay_endpoints="$(live_lab_capture_root "$RELAY_HOST" "root wg show rustynet0 endpoints || true")"
  client_plaintext_check="$(live_lab_no_plaintext_passphrase_check "$CLIENT_HOST")"
  relay_plaintext_check="$(live_lab_no_plaintext_passphrase_check "$RELAY_HOST")"
  exit_plaintext_check="$(live_lab_no_plaintext_passphrase_check "$EXIT_HOST")"

  live_lab_log "Client status"
  printf '%s\n' "$client_status"
  live_lab_log "Relay status"
  printf '%s\n' "$relay_status"
  live_lab_log "Final exit status"
  printf '%s\n' "$exit_status"
  live_lab_log "Client route"
  printf '%s\n' "$client_route"
  live_lab_log "Relay endpoints"
  printf '%s\n' "$relay_endpoints"

  if grep -Fq "exit_node=${RELAY_NODE_ID}" <<<"$client_status" && grep -Fq 'state=ExitActive' <<<"$client_status"; then
    CHECK_CLIENT_EXIT_IS_RELAY="pass"
  fi
  if grep -Fq "exit_node=${EXIT_NODE_ID}" <<<"$relay_status"; then
    CHECK_RELAY_EXIT_IS_FINAL="pass"
  fi
  if grep -Fq 'serving_exit_node=true' <<<"$relay_status"; then
    CHECK_RELAY_SERVES_EXIT="pass"
  fi
  if grep -Fq 'serving_exit_node=true' <<<"$exit_status"; then
    CHECK_FINAL_EXIT_SERVES="pass"
  fi
  if grep -Fq 'dev rustynet0' <<<"$client_route"; then
    CHECK_CLIENT_ROUTE_VIA_RUSTYNET="pass"
  fi
  if grep -Fq "${CLIENT_ADDR}:51820" <<<"$relay_endpoints" && grep -Fq "${EXIT_ADDR}:51820" <<<"$relay_endpoints"; then
    CHECK_RELAY_PEER_VISIBILITY="pass"
  fi
  if [[ "$client_plaintext_check" == 'no-plaintext-passphrase-files' && "$relay_plaintext_check" == 'no-plaintext-passphrase-files' && "$exit_plaintext_check" == 'no-plaintext-passphrase-files' ]]; then
    CHECK_NO_PLAINTEXT_PASSPHRASE_FILES="pass"
  fi

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

  if [[ "$CHECK_CLIENT_EXIT_IS_RELAY" == 'pass' && "$CHECK_RELAY_EXIT_IS_FINAL" == 'pass' && "$CHECK_RELAY_SERVES_EXIT" == 'pass' && "$CHECK_FINAL_EXIT_SERVES" == 'pass' && "$CHECK_CLIENT_ROUTE_VIA_RUSTYNET" == 'pass' && "$CHECK_RELAY_PEER_VISIBILITY" == 'pass' && "$CHECK_NO_PLAINTEXT_PASSPHRASE_FILES" == 'pass' && "$CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC" == 'pass' ]]; then
    CHECK_RELAY_REMOTE_EXIT_SUCCESS="pass"
  fi

  FAILURE_SUMMARY="validating narrow server-IP bypass and leak resistance on relay remote-exit path"
  if RUSTYNET_EXPECTED_GIT_COMMIT="${RUSTYNET_EXPECTED_GIT_COMMIT:-}" \
    bash "$ROOT_DIR/scripts/e2e/live_linux_server_ip_bypass_test.sh" \
      --ssh-password-file "$SSH_PASSWORD_FILE" \
      --sudo-password-file "$SUDO_PASSWORD_FILE" \
      --client-host "$CLIENT_HOST" \
      --probe-host "$EXIT_HOST" \
      --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
      --report-path "$BYPASS_REPORT_PATH" \
      --log-path "$BYPASS_LOG_PATH"; then
    bypass_status=0
  else
    bypass_status=$?
  fi

  if [[ "$bypass_status" -ne 0 && ! -f "$BYPASS_REPORT_PATH" ]]; then
    FAILURE_SUMMARY="server-IP bypass validator failed before emitting relay evidence"
    return 1
  fi

  mapfile -t bypass_results < <(python3 - "$BYPASS_REPORT_PATH" <<'PY'
import json
import sys

payload = json.loads(open(sys.argv[1], encoding="utf-8").read())
checks = payload.get("checks", {})
print(checks.get("internet_route_via_rustynet0", "fail"))
print(checks.get("probe_service_blocked_from_client", "fail"))
print(checks.get("probe_endpoint_route_direct_not_tunnelled", "fail"))
print(checks.get("no_unexpected_bypass_routes", "fail"))
PY
)

  if [[ "${bypass_results[0]}" == 'pass' && "${bypass_results[1]}" == 'pass' ]]; then
    CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK="pass"
  fi
  if [[ "${bypass_results[1]}" == 'pass' && "${bypass_results[2]}" == 'pass' && "${bypass_results[3]}" == 'pass' ]]; then
    CHECK_REMOTE_EXIT_SERVER_IP_BYPASS_IS_NARROW="pass"
  fi

  if [[ "$CHECK_RELAY_REMOTE_EXIT_SUCCESS" != 'pass' ]]; then
    FAILURE_SUMMARY="relay remote-exit steady-state checks did not all pass"
    return 1
  fi
  if [[ "$CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK" != 'pass' ]]; then
    FAILURE_SUMMARY="relay remote-exit path leaked or could not prove leak resistance"
    return 1
  fi
  if [[ "$CHECK_REMOTE_EXIT_SERVER_IP_BYPASS_IS_NARROW" != 'pass' ]]; then
    FAILURE_SUMMARY="server-IP bypass on the relay remote-exit path was broader than allowed"
    return 1
  fi

  FAILURE_SUMMARY=""
}

if main; then
  write_report pass
  REPORT_WRITTEN=1
else
  write_report fail
  REPORT_WRITTEN=1
  exit 1
fi

live_lab_log "Cross-network relay remote-exit report written: $REPORT_PATH"
