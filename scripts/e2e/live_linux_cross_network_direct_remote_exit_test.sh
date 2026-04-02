#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/e2e/live_lab_common.sh"

LIVE_LAB_LOG_PREFIX="cross-network-direct-remote-exit"
export LIVE_LAB_LOG_PREFIX

SSH_IDENTITY_FILE=""
CLIENT_HOST=""
EXIT_HOST=""
CLIENT_NODE_ID=""
EXIT_NODE_ID=""
CLIENT_NETWORK_ID=""
EXIT_NETWORK_ID=""
CLIENT_UNDERLAY_IP="${RUSTYNET_CLIENT_UNDERLAY_IP:-}"
EXIT_UNDERLAY_IP="${RUSTYNET_EXIT_UNDERLAY_IP:-}"
NAT_PROFILE="baseline_lan"
IMPAIRMENT_PROFILE="none"
SSH_ALLOW_CIDRS="192.168.18.0/24"
REPORT_PATH="$ROOT_DIR/artifacts/phase10/cross_network_direct_remote_exit_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/cross_network_direct_remote_exit.log"

REPORT_WRITTEN=0
FAILURE_SUMMARY="cross-network direct remote-exit validator did not complete"
CHECK_DIRECT_REMOTE_EXIT_SUCCESS="fail"
CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK="fail"
CHECK_REMOTE_EXIT_SERVER_IP_BYPASS_IS_NARROW="fail"
CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="fail"
CHECK_CLIENT_EXIT_SELECTED="fail"
CHECK_EXIT_SERVING_ROUTE="fail"
CHECK_CLIENT_ROUTE_VIA_RUSTYNET="fail"
CHECK_EXIT_ENDPOINT_VISIBLE="fail"
CHECK_EXIT_MASQUERADE_PRESENT="fail"
CHECK_NO_PLAINTEXT_PASSPHRASE_FILES="fail"
CLIENT_ADDR=""
EXIT_ADDR=""
BYPASS_REPORT_PATH=""
BYPASS_LOG_PATH=""
CLIENT_STATUS_FILE=""
EXIT_STATUS_FILE=""
CLIENT_INTERNET_ROUTE_FILE=""
CLIENT_ENDPOINTS_FILE=""
EXIT_NFT_FILE=""
CLIENT_PLAINTEXT_FILE=""
EXIT_PLAINTEXT_FILE=""
SOURCE_ARTIFACTS=()
LOG_ARTIFACTS=()
PATH_STATUS_LINE=""

usage() {
  cat <<'USAGE'
usage: live_linux_cross_network_direct_remote_exit_test.sh --ssh-identity-file <path> --client-host <user@host> --exit-host <user@host> --client-node-id <id> --exit-node-id <id> --client-network-id <id> --exit-network-id <id> [options]

options:
  --nat-profile <profile>
  --impairment-profile <profile>
  --ssh-allow-cidrs <cidr[,cidr]>
  --client-underlay-ip <ipv4>
  --exit-underlay-ip <ipv4>
  --report-path <path>
  --log-path <path>
USAGE
}

write_report() {
  local status="$1"
  local args=(
    cargo run --quiet -p rustynet-cli -- ops generate-cross-network-remote-exit-report
    --suite cross_network_direct_remote_exit
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
    --source-artifact "$ROOT_DIR/scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh"
    --check "direct_remote_exit_success=${CHECK_DIRECT_REMOTE_EXIT_SUCCESS}"
    --check "remote_exit_no_underlay_leak=${CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK}"
    --check "remote_exit_server_ip_bypass_is_narrow=${CHECK_REMOTE_EXIT_SERVER_IP_BYPASS_IS_NARROW}"
    --check "cross_network_topology_heuristic=${CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC}"
    --check "client_exit_selected=${CHECK_CLIENT_EXIT_SELECTED}"
    --check "exit_serving_route=${CHECK_EXIT_SERVING_ROUTE}"
    --check "client_route_via_rustynet0=${CHECK_CLIENT_ROUTE_VIA_RUSTYNET}"
    --check "exit_endpoint_visible=${CHECK_EXIT_ENDPOINT_VISIBLE}"
    --check "exit_masquerade_present=${CHECK_EXIT_MASQUERADE_PRESENT}"
    --check "no_plaintext_passphrase_files=${CHECK_NO_PLAINTEXT_PASSPHRASE_FILES}"
  )
  local item
  set +u
  if [[ -n "$PATH_STATUS_LINE" ]]; then
    args+=(--path-status-line "$PATH_STATUS_LINE")
  fi
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
  live_lab_cleanup
  exit "$rc"
}

trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-identity-file) SSH_IDENTITY_FILE="$2"; shift 2 ;;
    --client-host) CLIENT_HOST="$2"; shift 2 ;;
    --exit-host) EXIT_HOST="$2"; shift 2 ;;
    --client-node-id) CLIENT_NODE_ID="$2"; shift 2 ;;
    --exit-node-id) EXIT_NODE_ID="$2"; shift 2 ;;
    --client-network-id) CLIENT_NETWORK_ID="$2"; shift 2 ;;
    --exit-network-id) EXIT_NETWORK_ID="$2"; shift 2 ;;
    --client-underlay-ip) CLIENT_UNDERLAY_IP="$2"; shift 2 ;;
    --exit-underlay-ip) EXIT_UNDERLAY_IP="$2"; shift 2 ;;
    --nat-profile) NAT_PROFILE="$2"; shift 2 ;;
    --impairment-profile) IMPAIRMENT_PROFILE="$2"; shift 2 ;;
    --ssh-allow-cidrs) SSH_ALLOW_CIDRS="$2"; shift 2 ;;
    --report-path) REPORT_PATH="$2"; shift 2 ;;
    --log-path) LOG_PATH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$SSH_IDENTITY_FILE" || -z "$CLIENT_HOST" || -z "$EXIT_HOST" || -z "$CLIENT_NODE_ID" || -z "$EXIT_NODE_ID" || -z "$CLIENT_NETWORK_ID" || -z "$EXIT_NETWORK_ID" ]]; then
  usage >&2
  exit 2
fi
if [[ -z "$NAT_PROFILE" || -z "$IMPAIRMENT_PROFILE" ]]; then
  echo "--nat-profile and --impairment-profile must be non-empty" >&2
  exit 2
fi

if [[ "$CLIENT_HOST" == "$EXIT_HOST" ]]; then
  echo "--client-host and --exit-host must differ" >&2
  exit 2
fi

if [[ "$CLIENT_NETWORK_ID" == "$EXIT_NETWORK_ID" ]]; then
  echo "--client-network-id and --exit-network-id must differ" >&2
  exit 2
fi

if [[ -n "$CLIENT_UNDERLAY_IP" ]]; then
  cargo run --quiet -p rustynet-cli -- ops validate-ipv4-address --ip "$CLIENT_UNDERLAY_IP" >/dev/null
fi
if [[ -n "$EXIT_UNDERLAY_IP" ]]; then
  cargo run --quiet -p rustynet-cli -- ops validate-ipv4-address --ip "$EXIT_UNDERLAY_IP" >/dev/null
fi

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")"
: > "$LOG_PATH"
exec >> "$LOG_PATH" 2>&1

main() {
  local issue_env assign_pub_local exit_assignment_local client_assignment_local
  local exit_refresh_local client_refresh_local
  local traversal_env traversal_pub_local exit_traversal_local client_traversal_local
  local bypass_status client_status client_netcheck exit_status client_internet_route client_endpoints exit_nft
  local client_plaintext_check exit_plaintext_check
  local artifact_dir
  local path_proven_direct signed_state_healthy

  FAILURE_SUMMARY="initializing live-lab runtime"

  live_lab_init "rustynet-cross-network-direct-remote-exit" "$SSH_IDENTITY_FILE"

  issue_env="$LIVE_LAB_WORK_DIR/rn_issue_cross_network_direct.env"
  assign_pub_local="$LIVE_LAB_WORK_DIR/assignment.pub"
  exit_assignment_local="$LIVE_LAB_WORK_DIR/assignment-exit"
  client_assignment_local="$LIVE_LAB_WORK_DIR/assignment-client"
  exit_refresh_local="$LIVE_LAB_WORK_DIR/assignment-refresh-exit.env"
  client_refresh_local="$LIVE_LAB_WORK_DIR/assignment-refresh-client.env"
  traversal_env="$LIVE_LAB_WORK_DIR/rn_issue_cross_network_direct_traversal.env"
  traversal_pub_local="$LIVE_LAB_WORK_DIR/traversal.pub"
  exit_traversal_local="$LIVE_LAB_WORK_DIR/traversal-exit"
  client_traversal_local="$LIVE_LAB_WORK_DIR/traversal-client"
  artifact_dir="$(dirname "$REPORT_PATH")"
  BYPASS_REPORT_PATH="$artifact_dir/cross_network_direct_remote_exit_server_ip_bypass_report.json"
  BYPASS_LOG_PATH="$artifact_dir/cross_network_direct_remote_exit_server_ip_bypass.log"
  SOURCE_ARTIFACTS=("$BYPASS_REPORT_PATH")
  LOG_ARTIFACTS=("$BYPASS_LOG_PATH")
  CLIENT_STATUS_FILE="$LIVE_LAB_WORK_DIR/client_status.txt"
  EXIT_STATUS_FILE="$LIVE_LAB_WORK_DIR/exit_status.txt"
  CLIENT_INTERNET_ROUTE_FILE="$LIVE_LAB_WORK_DIR/client_internet_route.txt"
  CLIENT_ENDPOINTS_FILE="$LIVE_LAB_WORK_DIR/client_endpoints.txt"
  EXIT_NFT_FILE="$LIVE_LAB_WORK_DIR/exit_nft.txt"
  CLIENT_PLAINTEXT_FILE="$LIVE_LAB_WORK_DIR/client_plaintext_check.txt"
  EXIT_PLAINTEXT_FILE="$LIVE_LAB_WORK_DIR/exit_plaintext_check.txt"

  live_lab_push_sudo_password "$EXIT_HOST"
  live_lab_push_sudo_password "$CLIENT_HOST"

  live_lab_log "Collecting WireGuard public keys"
  EXIT_PUB_HEX="$(live_lab_collect_pubkey_hex "$EXIT_HOST")"
  CLIENT_PUB_HEX="$(live_lab_collect_pubkey_hex "$CLIENT_HOST")"
  if [[ -n "$EXIT_UNDERLAY_IP" ]]; then
    EXIT_ADDR="$EXIT_UNDERLAY_IP"
  else
    EXIT_ADDR="$(live_lab_resolved_target_address "$EXIT_HOST")"
  fi
  if [[ -n "$CLIENT_UNDERLAY_IP" ]]; then
    CLIENT_ADDR="$CLIENT_UNDERLAY_IP"
  else
    CLIENT_ADDR="$(live_lab_resolved_target_address "$CLIENT_HOST")"
  fi

  NODES_SPEC="${EXIT_NODE_ID}|${EXIT_ADDR}:51820|${EXIT_PUB_HEX};${CLIENT_NODE_ID}|${CLIENT_ADDR}:51820|${CLIENT_PUB_HEX}"
  ALLOW_SPEC="${CLIENT_NODE_ID}|${EXIT_NODE_ID};${EXIT_NODE_ID}|${CLIENT_NODE_ID}"

  : > "$issue_env"
  live_lab_append_env_assignment "$issue_env" "NODES_SPEC" "$NODES_SPEC"
  live_lab_append_env_assignment "$issue_env" "ALLOW_SPEC" "$ALLOW_SPEC"
  live_lab_append_env_assignment "$issue_env" "ASSIGNMENTS_SPEC" "${EXIT_NODE_ID}|-;${CLIENT_NODE_ID}|${EXIT_NODE_ID}"

  live_lab_log "Issuing signed direct remote-exit assignments on $EXIT_HOST"
  live_lab_issue_assignment_bundles_from_env "$EXIT_HOST" "$issue_env" "/tmp/rn_issue_cross_network_direct.env"

  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment.pub" > "$assign_pub_local"
  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$EXIT_NODE_ID.assignment" > "$exit_assignment_local"
  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$CLIENT_NODE_ID.assignment" > "$client_assignment_local"

  live_lab_log "Distributing signed assignments"
  live_lab_install_assignment_bundle "$EXIT_HOST" "$assign_pub_local" "$exit_assignment_local"
  live_lab_install_assignment_bundle "$CLIENT_HOST" "$assign_pub_local" "$client_assignment_local"

  live_lab_write_assignment_refresh_env "$exit_refresh_local" "$EXIT_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC"
  live_lab_write_assignment_refresh_env "$client_refresh_local" "$CLIENT_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC" "$EXIT_NODE_ID"
  live_lab_install_assignment_refresh_env "$EXIT_HOST" "$exit_refresh_local"
  live_lab_install_assignment_refresh_env "$CLIENT_HOST" "$client_refresh_local"

  : > "$traversal_env"
  live_lab_append_env_assignment "$traversal_env" "NODES_SPEC" "$NODES_SPEC"
  live_lab_append_env_assignment "$traversal_env" "ALLOW_SPEC" "$ALLOW_SPEC"

  live_lab_log "Issuing signed traversal bundles for direct remote-exit topology"
  live_lab_issue_traversal_bundles_from_env "$EXIT_HOST" "$traversal_env" "/tmp/rn_issue_cross_network_direct_traversal.env"

  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/traversal-issue/rn-traversal.pub" > "$traversal_pub_local"
  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/traversal-issue/rn-traversal-$EXIT_NODE_ID.traversal" > "$exit_traversal_local"
  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/traversal-issue/rn-traversal-$CLIENT_NODE_ID.traversal" > "$client_traversal_local"

  install_traversal_bundle() {
    local host="$1"
    local bundle_local="$2"
    live_lab_scp_to "$traversal_pub_local" "$host" "/tmp/rn-traversal.pub"
    live_lab_scp_to "$bundle_local" "$host" "/tmp/rn-traversal.bundle"
    live_lab_run_root "$host" "root install -m 0644 -o root -g root /tmp/rn-traversal.pub /etc/rustynet/traversal.pub && root install -m 0640 -o root -g rustynetd /tmp/rn-traversal.bundle /var/lib/rustynet/rustynetd.traversal && root rm -f /var/lib/rustynet/rustynetd.traversal.watermark /tmp/rn-traversal.pub /tmp/rn-traversal.bundle"
  }

  live_lab_log "Distributing signed traversal bundles"
  install_traversal_bundle "$EXIT_HOST" "$exit_traversal_local"
  install_traversal_bundle "$CLIENT_HOST" "$client_traversal_local"

  live_lab_log "Enforcing runtime roles"
  live_lab_enforce_host "$EXIT_HOST" "admin" "$EXIT_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$EXIT_HOST")"
  live_lab_enforce_host "$CLIENT_HOST" "client" "$CLIENT_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$CLIENT_HOST")"
  live_lab_wait_for_daemon_socket "$EXIT_HOST"
  live_lab_wait_for_daemon_socket "$CLIENT_HOST"

  live_lab_log "Advertising default route on remote exit"
  live_lab_retry_root "$EXIT_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 0.0.0.0/0" 10 2
  sleep 5

  FAILURE_SUMMARY="capturing direct remote-exit steady-state evidence"
  client_status="$(live_lab_status "$CLIENT_HOST")"
  client_netcheck="$(live_lab_capture_root "$CLIENT_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet netcheck")"
  exit_status="$(live_lab_status "$EXIT_HOST")"
  PATH_STATUS_LINE="$client_netcheck"
  client_internet_route="$(live_lab_capture "$CLIENT_HOST" "ip -4 route get 1.1.1.1 || true")"
  client_endpoints="$(live_lab_capture_root "$CLIENT_HOST" "root wg show rustynet0 endpoints || true")"
  exit_nft="$(live_lab_capture_root "$EXIT_HOST" "root nft list ruleset || true")"
  client_plaintext_check="$(live_lab_no_plaintext_passphrase_check "$CLIENT_HOST")"
  exit_plaintext_check="$(live_lab_no_plaintext_passphrase_check "$EXIT_HOST")"

  printf '%s\n' "$client_status" > "$CLIENT_STATUS_FILE"
  printf '%s\n' "$exit_status" > "$EXIT_STATUS_FILE"
  printf '%s\n' "$client_internet_route" > "$CLIENT_INTERNET_ROUTE_FILE"
  printf '%s\n' "$client_endpoints" > "$CLIENT_ENDPOINTS_FILE"
  printf '%s\n' "$exit_nft" > "$EXIT_NFT_FILE"
  printf '%s\n' "$client_plaintext_check" > "$CLIENT_PLAINTEXT_FILE"
  printf '%s\n' "$exit_plaintext_check" > "$EXIT_PLAINTEXT_FILE"

  live_lab_log "Client status"
  printf '%s\n' "$client_status"
  live_lab_log "Exit status"
  printf '%s\n' "$exit_status"
  live_lab_log "Client route to internet"
  printf '%s\n' "$client_internet_route"
  live_lab_log "Client endpoints"
  printf '%s\n' "$client_endpoints"
  live_lab_log "Client netcheck"
  printf '%s\n' "$client_netcheck"

  path_proven_direct=0
  if [[ "$client_netcheck" == *"path_mode=direct_active"* && "$client_netcheck" == *"path_live_proven=true"* ]]; then
    path_proven_direct=1
  fi
  signed_state_healthy=0
  if [[ "$client_netcheck" != *"traversal_alarm_state=critical"* && "$client_netcheck" != *"traversal_alarm_state=error"* && "$client_netcheck" != *"traversal_alarm_state=missing"* && "$client_netcheck" != *"dns_alarm_state=critical"* && "$client_netcheck" != *"dns_alarm_state=error"* && "$client_netcheck" != *"dns_alarm_state=missing"* && "$client_netcheck" == *"traversal_error=none"* ]]; then
    signed_state_healthy=1
  fi

  if (( path_proven_direct == 1 )) && grep -Fq "exit_node=${EXIT_NODE_ID}" <<<"$client_status" && grep -Fq 'state=ExitActive' <<<"$client_status"; then
    CHECK_CLIENT_EXIT_SELECTED="pass"
  fi
  if grep -Fq 'serving_exit_node=true' <<<"$exit_status"; then
    CHECK_EXIT_SERVING_ROUTE="pass"
  fi
  if grep -Fq 'dev rustynet0' <<<"$client_internet_route"; then
    CHECK_CLIENT_ROUTE_VIA_RUSTYNET="pass"
  fi
  if grep -Fq "${EXIT_ADDR}:51820" <<<"$client_endpoints"; then
    CHECK_EXIT_ENDPOINT_VISIBLE="pass"
  fi
  if grep -Fq 'masquerade' <<<"$exit_nft"; then
    CHECK_EXIT_MASQUERADE_PRESENT="pass"
  fi
  if [[ "$client_plaintext_check" == 'no-plaintext-passphrase-files' && "$exit_plaintext_check" == 'no-plaintext-passphrase-files' ]]; then
    CHECK_NO_PLAINTEXT_PASSPHRASE_FILES="pass"
  fi

  topology_result="$(cargo run --quiet -p rustynet-cli -- ops classify-cross-network-topology --ip-a "$CLIENT_ADDR" --ip-b "$EXIT_ADDR")" || return 1
  if [[ "$topology_result" == "pass" ]]; then
    CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="pass"
  else
    CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="fail"
  fi

  if [[ "$CHECK_CLIENT_EXIT_SELECTED" == 'pass' && "$CHECK_EXIT_SERVING_ROUTE" == 'pass' && "$CHECK_CLIENT_ROUTE_VIA_RUSTYNET" == 'pass' && "$CHECK_EXIT_ENDPOINT_VISIBLE" == 'pass' && "$CHECK_EXIT_MASQUERADE_PRESENT" == 'pass' && "$CHECK_NO_PLAINTEXT_PASSPHRASE_FILES" == 'pass' && "$CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC" == 'pass' ]] && (( signed_state_healthy == 1 )); then
    CHECK_DIRECT_REMOTE_EXIT_SUCCESS="pass"
  fi

  FAILURE_SUMMARY="validating narrow server-IP bypass and leak resistance on direct remote-exit path"
  if RUSTYNET_EXPECTED_GIT_COMMIT="${RUSTYNET_EXPECTED_GIT_COMMIT:-}" \
    bash "$ROOT_DIR/scripts/e2e/live_linux_server_ip_bypass_test.sh" \
      --ssh-identity-file "$SSH_IDENTITY_FILE" \
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
    FAILURE_SUMMARY="server-IP bypass validator failed before emitting evidence"
    return 1
  fi

  mapfile -t bypass_results < <(
    cargo run --quiet -p rustynet-cli -- ops read-cross-network-report-fields \
      --report-path "$BYPASS_REPORT_PATH" \
      --check internet_route_via_rustynet0 \
      --check probe_service_blocked_from_client \
      --check probe_endpoint_route_direct_not_tunnelled \
      --check no_unexpected_bypass_routes
  ) || return 1

  if [[ "${bypass_results[0]}" == 'pass' && "${bypass_results[1]}" == 'pass' ]]; then
    CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK="pass"
  fi
  if [[ "${bypass_results[1]}" == 'pass' && "${bypass_results[2]}" == 'pass' && "${bypass_results[3]}" == 'pass' ]]; then
    CHECK_REMOTE_EXIT_SERVER_IP_BYPASS_IS_NARROW="pass"
  fi

  if [[ "$CHECK_DIRECT_REMOTE_EXIT_SUCCESS" != 'pass' ]]; then
    if [[ "$CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC" != 'pass' ]]; then
      FAILURE_SUMMARY="client and exit underlay addresses share the same local prefix; refusing to claim cross-network direct remote exit on same-subnet topology"
    else
      FAILURE_SUMMARY="direct remote-exit steady-state checks did not all pass"
    fi
    return 1
  fi
  if [[ "$CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK" != 'pass' ]]; then
    FAILURE_SUMMARY="direct remote-exit path leaked or could not prove leak resistance"
    return 1
  fi
  if [[ "$CHECK_REMOTE_EXIT_SERVER_IP_BYPASS_IS_NARROW" != 'pass' ]]; then
    FAILURE_SUMMARY="server-IP bypass on the direct remote-exit path was broader than allowed"
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

live_lab_log "Cross-network direct remote-exit report written: $REPORT_PATH"
