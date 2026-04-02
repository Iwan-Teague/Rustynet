#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/e2e/live_lab_common.sh"

LIVE_LAB_LOG_PREFIX="cross-network-failback-roaming"
export LIVE_LAB_LOG_PREFIX

SSH_IDENTITY_FILE=""
CLIENT_HOST=""
EXIT_HOST=""
RELAY_HOST=""
CLIENT_NODE_ID=""
EXIT_NODE_ID=""
RELAY_NODE_ID=""
CLIENT_NETWORK_ID=""
EXIT_NETWORK_ID=""
RELAY_NETWORK_ID=""
CLIENT_UNDERLAY_IP="${RUSTYNET_CLIENT_UNDERLAY_IP:-}"
EXIT_UNDERLAY_IP="${RUSTYNET_EXIT_UNDERLAY_IP:-}"
RELAY_UNDERLAY_IP="${RUSTYNET_RELAY_UNDERLAY_IP:-}"
NAT_PROFILE="baseline_lan"
IMPAIRMENT_PROFILE="none"
SSH_ALLOW_CIDRS="192.168.18.0/24"
FAILBACK_RECOVERY_SLO_SECS=30
FAILBACK_MONITOR_ITERATIONS=35
REPORT_PATH="$ROOT_DIR/artifacts/phase10/cross_network_failback_roaming_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/cross_network_failback_roaming.log"

WORK_DIR=""
REPORT_WRITTEN=0
FAILURE_SUMMARY="cross-network failback and roaming validator did not complete"
CHECK_RELAY_TO_DIRECT_FAILBACK_SUCCESS="fail"
CHECK_ENDPOINT_ROAM_RECOVERY_SUCCESS="fail"
CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK="fail"
CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="fail"
CHECK_FAILBACK_RECOVERY_SLO="fail"
CHECK_NO_UNDERLAY_LEAK_DURING_FAILBACK="fail"
CHECK_SIGNED_STATE_VALID_DURING_FAILBACK="fail"
RELAY_REPORT_PATH=""
RELAY_LOG_PATH=""
BYPASS_REPORT_PATH=""
BYPASS_LOG_PATH=""
FAILBACK_MONITOR_LOG=""
FAILBACK_SLO_SUMMARY_PATH=""
SOURCE_ARTIFACTS=()
LOG_ARTIFACTS=()
PATH_STATUS_LINE=""
CLIENT_ADDR=""
EXIT_ADDR=""
RELAY_ADDR=""
ROAM_ALIAS_IP=""
ROAM_INTERFACE=""
ROAM_PREFIX=""

usage() {
  cat <<'USAGE'
usage: live_linux_cross_network_failback_roaming_test.sh --ssh-identity-file <path> --client-host <user@host> --exit-host <user@host> --relay-host <user@host> --client-node-id <id> --exit-node-id <id> --relay-node-id <id> --client-network-id <id> --exit-network-id <id> --relay-network-id <id> [options]

options:
  --nat-profile <profile>
  --impairment-profile <profile>
  --ssh-allow-cidrs <cidr[,cidr]>
  --client-underlay-ip <ipv4>
  --exit-underlay-ip <ipv4>
  --relay-underlay-ip <ipv4>
  --failback-recovery-slo-secs <seconds>      Default: 30
  --failback-monitor-iterations <count>       Default: 35
  --report-path <path>
  --log-path <path>
USAGE
}

parse_positive_integer() {
  local flag="$1"
  local raw="$2"
  if [[ ! "$raw" =~ ^[0-9]+$ ]] || (( raw <= 0 )); then
    echo "${flag} must be a positive integer (got: ${raw})" >&2
    exit 2
  fi
}

write_report() {
  local status="$1"
  local args=(
    cargo run --quiet -p rustynet-cli -- ops generate-cross-network-remote-exit-report
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
    --check "failback_reconnect_within_slo=${CHECK_FAILBACK_RECOVERY_SLO}"
    --check "no_underlay_leak_while_reconnecting=${CHECK_NO_UNDERLAY_LEAK_DURING_FAILBACK}"
    --check "signed_state_valid_while_reconnecting=${CHECK_SIGNED_STATE_VALID_DURING_FAILBACK}"
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
    --ssh-identity-file) SSH_IDENTITY_FILE="$2"; shift 2 ;;
    --client-host) CLIENT_HOST="$2"; shift 2 ;;
    --exit-host) EXIT_HOST="$2"; shift 2 ;;
    --relay-host) RELAY_HOST="$2"; shift 2 ;;
    --client-node-id) CLIENT_NODE_ID="$2"; shift 2 ;;
    --exit-node-id) EXIT_NODE_ID="$2"; shift 2 ;;
    --relay-node-id) RELAY_NODE_ID="$2"; shift 2 ;;
    --client-network-id) CLIENT_NETWORK_ID="$2"; shift 2 ;;
    --exit-network-id) EXIT_NETWORK_ID="$2"; shift 2 ;;
    --relay-network-id) RELAY_NETWORK_ID="$2"; shift 2 ;;
    --client-underlay-ip) CLIENT_UNDERLAY_IP="$2"; shift 2 ;;
    --exit-underlay-ip) EXIT_UNDERLAY_IP="$2"; shift 2 ;;
    --relay-underlay-ip) RELAY_UNDERLAY_IP="$2"; shift 2 ;;
    --nat-profile) NAT_PROFILE="$2"; shift 2 ;;
    --impairment-profile) IMPAIRMENT_PROFILE="$2"; shift 2 ;;
    --ssh-allow-cidrs) SSH_ALLOW_CIDRS="$2"; shift 2 ;;
    --failback-recovery-slo-secs)
      parse_positive_integer "--failback-recovery-slo-secs" "$2"
      FAILBACK_RECOVERY_SLO_SECS="$2"
      shift 2
      ;;
    --failback-monitor-iterations)
      parse_positive_integer "--failback-monitor-iterations" "$2"
      FAILBACK_MONITOR_ITERATIONS="$2"
      shift 2
      ;;
    --report-path) REPORT_PATH="$2"; shift 2 ;;
    --log-path) LOG_PATH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$SSH_IDENTITY_FILE" || -z "$CLIENT_HOST" || -z "$EXIT_HOST" || -z "$RELAY_HOST" || -z "$CLIENT_NODE_ID" || -z "$EXIT_NODE_ID" || -z "$RELAY_NODE_ID" || -z "$CLIENT_NETWORK_ID" || -z "$EXIT_NETWORK_ID" || -z "$RELAY_NETWORK_ID" ]]; then
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

if [[ -n "$CLIENT_UNDERLAY_IP" ]]; then
  cargo run --quiet -p rustynet-cli -- ops validate-ipv4-address --ip "$CLIENT_UNDERLAY_IP" >/dev/null
fi
if [[ -n "$EXIT_UNDERLAY_IP" ]]; then
  cargo run --quiet -p rustynet-cli -- ops validate-ipv4-address --ip "$EXIT_UNDERLAY_IP" >/dev/null
fi
if [[ -n "$RELAY_UNDERLAY_IP" ]]; then
  cargo run --quiet -p rustynet-cli -- ops validate-ipv4-address --ip "$RELAY_UNDERLAY_IP" >/dev/null
fi

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")"
: > "$LOG_PATH"
exec >> "$LOG_PATH" 2>&1

main() {
  local relay_rc bypass_status
  local switch_ts first_switch_ts reconvergence_secs first_switch_json
  local local_ts
  local client_status client_route client_endpoints client_netcheck
  local issue_env assign_pub_local exit_assignment_local relay_assignment_local client_assignment_local
  local exit_refresh_local relay_refresh_local client_refresh_local
  local client_status_after_roam client_netcheck_after_roam client_route_after_roam client_endpoints_after_roam
  local artifact_dir
  local route_leak_samples signed_state_invalid_samples netcheck_invalid route_has_underlay_dev
  local route_line
  local final_direct_path_live final_signed_state_healthy

  FAILURE_SUMMARY="bootstrapping relay remote-exit path before failback"
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rustynet-cross-network-failback-roaming.XXXXXX")"
  artifact_dir="$(dirname "$REPORT_PATH")"
  RELAY_REPORT_PATH="$artifact_dir/cross_network_failback_roaming_relay_stage_report.json"
  RELAY_LOG_PATH="$artifact_dir/cross_network_failback_roaming_relay_stage.log"
  BYPASS_REPORT_PATH="$artifact_dir/cross_network_failback_roaming_server_ip_bypass_report.json"
  BYPASS_LOG_PATH="$artifact_dir/cross_network_failback_roaming_server_ip_bypass.log"
  FAILBACK_MONITOR_LOG="$artifact_dir/cross_network_failback_roaming_monitor.log"
  FAILBACK_SLO_SUMMARY_PATH="$artifact_dir/cross_network_failback_roaming_slo_summary.json"
  SOURCE_ARTIFACTS=("$RELAY_REPORT_PATH" "$BYPASS_REPORT_PATH" "$FAILBACK_SLO_SUMMARY_PATH")
  LOG_ARTIFACTS=("$RELAY_LOG_PATH" "$BYPASS_LOG_PATH" "$FAILBACK_MONITOR_LOG")

  if RUSTYNET_EXPECTED_GIT_COMMIT="${RUSTYNET_EXPECTED_GIT_COMMIT:-}" \
    bash "$ROOT_DIR/scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh" \
      --ssh-identity-file "$SSH_IDENTITY_FILE" \
      --client-host "$CLIENT_HOST" \
      --exit-host "$EXIT_HOST" \
      --relay-host "$RELAY_HOST" \
      --client-node-id "$CLIENT_NODE_ID" \
      --exit-node-id "$EXIT_NODE_ID" \
      --relay-node-id "$RELAY_NODE_ID" \
      --client-network-id "$CLIENT_NETWORK_ID" \
      --exit-network-id "$EXIT_NETWORK_ID" \
      --relay-network-id "$RELAY_NETWORK_ID" \
      --client-underlay-ip "${CLIENT_UNDERLAY_IP:-}" \
      --exit-underlay-ip "${EXIT_UNDERLAY_IP:-}" \
      --relay-underlay-ip "${RELAY_UNDERLAY_IP:-}" \
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

  if [[ -n "$CLIENT_UNDERLAY_IP" ]]; then
    CLIENT_ADDR="$CLIENT_UNDERLAY_IP"
  else
    CLIENT_ADDR="$(live_lab_target_address "$CLIENT_HOST")"
  fi
  if [[ -n "$EXIT_UNDERLAY_IP" ]]; then
    EXIT_ADDR="$EXIT_UNDERLAY_IP"
  else
    EXIT_ADDR="$(live_lab_target_address "$EXIT_HOST")"
  fi
  if [[ -n "$RELAY_UNDERLAY_IP" ]]; then
    RELAY_ADDR="$RELAY_UNDERLAY_IP"
  else
    RELAY_ADDR="$(live_lab_target_address "$RELAY_HOST")"
  fi

  topology_result="$(cargo run --quiet -p rustynet-cli -- ops classify-cross-network-topology --ip-a "$CLIENT_ADDR" --ip-b "$EXIT_ADDR")" || return 1
  if [[ "$topology_result" == "pass" ]]; then
    CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="pass"
  else
    CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="fail"
  fi

  FAILURE_SUMMARY="initializing failback and roaming live-lab runtime"
  live_lab_init "rustynet-cross-network-failback-roaming" "$SSH_IDENTITY_FILE"
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
  route_leak_samples=0
  signed_state_invalid_samples=0
  for ((i=1; i<=FAILBACK_MONITOR_ITERATIONS; i++)); do
    local_ts="$(date +%s)"
    client_status="$(live_lab_status "$CLIENT_HOST")"
    client_route="$(live_lab_capture "$CLIENT_HOST" "ip -4 route get 1.1.1.1 || true")"
    client_endpoints="$(live_lab_capture_root "$CLIENT_HOST" "root wg show rustynet0 endpoints || true")"
    client_netcheck="$(live_lab_capture_root "$CLIENT_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet netcheck || true")"

    netcheck_invalid=0
    if [[ "$client_netcheck" == *"traversal_alarm_state=critical"* || "$client_netcheck" == *"traversal_alarm_state=error"* || "$client_netcheck" == *"traversal_alarm_state=missing"* ]]; then
      netcheck_invalid=1
    fi
    if [[ "$client_netcheck" != *"traversal_error=none"* ]]; then
      netcheck_invalid=1
    fi
    if (( netcheck_invalid != 0 )); then
      signed_state_invalid_samples=$((signed_state_invalid_samples + 1))
    fi

    route_has_underlay_dev=0
    while IFS= read -r route_line; do
      [[ -n "$route_line" ]] || continue
      if [[ "$route_line" =~ [[:space:]]dev[[:space:]]([^[:space:]]+) ]]; then
        if [[ "${BASH_REMATCH[1]}" != "rustynet0" ]]; then
          route_has_underlay_dev=1
          break
        fi
      fi
    done <<< "$client_route"
    if (( route_has_underlay_dev != 0 )); then
      route_leak_samples=$((route_leak_samples + 1))
    fi

    printf '%s|iter=%s|route=%s|status=%s|endpoints=%s|netcheck=%s\n' \
      "$local_ts" "$i" \
      "$(printf '%s' "$client_route" | tr -s ' ' | tr '\n' ';')" \
      "$(printf '%s' "$client_status" | tr -s ' ' | tr '\n' ';')" \
      "$(printf '%s' "$client_endpoints" | tr -s ' ' | tr '\n' ';')" \
      "$(printf '%s' "$client_netcheck" | tr -s ' ' | tr '\n' ';')" >> "$FAILBACK_MONITOR_LOG"
    if [[ -z "$first_switch_ts" ]] && grep -Fq "exit_node=${EXIT_NODE_ID}" <<<"$client_status" && grep -Fq 'dev rustynet0' <<<"$client_route" && [[ "$client_netcheck" == *"path_mode=direct_active"* ]] && [[ "$client_netcheck" == *"path_live_proven=true"* ]]; then
      first_switch_ts="$local_ts"
    fi
    sleep 1
  done

  if [[ -n "$first_switch_ts" ]]; then
    reconvergence_secs=$((first_switch_ts - switch_ts))
  else
    reconvergence_secs=-1
  fi

  relay_ready_check="$(cargo run --quiet -p rustynet-cli -- ops read-cross-network-report-fields --report-path "$RELAY_REPORT_PATH" --check relay_remote_exit_success)" || return 1
  if [[ "$relay_ready_check" == 'pass' && "$CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC" == 'pass' && "$reconvergence_secs" -ge 0 && "$reconvergence_secs" -le "$FAILBACK_RECOVERY_SLO_SECS" ]]; then
    CHECK_FAILBACK_RECOVERY_SLO="pass"
  fi
  if [[ "$route_leak_samples" -eq 0 ]]; then
    CHECK_NO_UNDERLAY_LEAK_DURING_FAILBACK="pass"
  fi
  if [[ "$signed_state_invalid_samples" -eq 0 ]]; then
    CHECK_SIGNED_STATE_VALID_DURING_FAILBACK="pass"
  fi

  if [[ "$CHECK_FAILBACK_RECOVERY_SLO" == 'pass' && "$CHECK_NO_UNDERLAY_LEAK_DURING_FAILBACK" == 'pass' && "$CHECK_SIGNED_STATE_VALID_DURING_FAILBACK" == 'pass' ]]; then
    CHECK_RELAY_TO_DIRECT_FAILBACK_SUCCESS="pass"
  fi

  first_switch_json="null"
  if [[ -n "$first_switch_ts" ]]; then
    first_switch_json="$first_switch_ts"
  fi
  cat > "$FAILBACK_SLO_SUMMARY_PATH" <<EOF
{
  "switch_unix": $switch_ts,
  "first_direct_unix": $first_switch_json,
  "reconvergence_secs": $reconvergence_secs,
  "recovery_slo_secs": $FAILBACK_RECOVERY_SLO_SECS,
  "monitor_iterations": $FAILBACK_MONITOR_ITERATIONS,
  "underlay_leak_samples": $route_leak_samples,
  "signed_state_invalid_samples": $signed_state_invalid_samples,
  "checks": {
    "failback_reconnect_within_slo": "$CHECK_FAILBACK_RECOVERY_SLO",
    "no_underlay_leak_while_reconnecting": "$CHECK_NO_UNDERLAY_LEAK_DURING_FAILBACK",
    "signed_state_valid_while_reconnecting": "$CHECK_SIGNED_STATE_VALID_DURING_FAILBACK"
  }
}
EOF

  FAILURE_SUMMARY="computing endpoint roam alias and issuing updated signed assignments"
  mapfile -t roam_values < <(
    cargo run --quiet -p rustynet-cli -- ops choose-cross-network-roam-alias \
      --exit-ip "$EXIT_ADDR" \
      --used-ip "$EXIT_ADDR" \
      --used-ip "$CLIENT_ADDR" \
      --used-ip "$RELAY_ADDR"
  ) || return 1
  ROAM_ALIAS_IP="${roam_values[0]}"
  ROAM_PREFIX="${roam_values[1]}"
  ROAM_INTERFACE="$(live_lab_capture "$EXIT_HOST" "ip -4 route get '$CLIENT_ADDR' 2>/dev/null | awk '{for (i=1; i<=NF; i++) if (\$i == \"dev\") {print \$(i+1); exit}}' || true")"
  if [[ -z "$ROAM_INTERFACE" ]]; then
    FAILURE_SUMMARY="failed to determine exit underlay interface for endpoint roam"
    return 1
  fi

  live_lab_run_root "$EXIT_HOST" "root ip addr show dev '$ROAM_INTERFACE' | grep -Fq '${ROAM_ALIAS_IP}/${ROAM_PREFIX}' || root ip addr add '${ROAM_ALIAS_IP}/${ROAM_PREFIX}' dev '$ROAM_INTERFACE'"

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

  : > "$issue_env"
  live_lab_append_env_assignment "$issue_env" "NODES_SPEC" "$NODES_SPEC"
  live_lab_append_env_assignment "$issue_env" "ALLOW_SPEC" "$ALLOW_SPEC"
  live_lab_append_env_assignment "$issue_env" "ASSIGNMENTS_SPEC" "${EXIT_NODE_ID}|-;${RELAY_NODE_ID}|${EXIT_NODE_ID};${CLIENT_NODE_ID}|${EXIT_NODE_ID}"

  live_lab_issue_assignment_bundles_from_env "$EXIT_HOST" "$issue_env" "/tmp/rn_issue_cross_network_roam.env"

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
  client_netcheck_after_roam="$(live_lab_capture_root "$CLIENT_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet netcheck || true")"
  PATH_STATUS_LINE="$client_netcheck_after_roam"
  client_route_after_roam="$(live_lab_capture "$CLIENT_HOST" "ip -4 route get 1.1.1.1 || true")"
  client_endpoints_after_roam="$(live_lab_capture_root "$CLIENT_HOST" "root wg show rustynet0 endpoints || true")"
  live_lab_log "Client status after roam"
  printf '%s\n' "$client_status_after_roam"
  live_lab_log "Client netcheck after roam"
  printf '%s\n' "$client_netcheck_after_roam"
  live_lab_log "Client route after roam"
  printf '%s\n' "$client_route_after_roam"
  live_lab_log "Client endpoints after roam"
  printf '%s\n' "$client_endpoints_after_roam"

  final_direct_path_live=0
  if [[ "$client_netcheck_after_roam" == *"path_mode=direct_active"* && "$client_netcheck_after_roam" == *"path_live_proven=true"* ]]; then
    final_direct_path_live=1
  fi
  final_signed_state_healthy=0
  if [[ "$client_netcheck_after_roam" != *"traversal_alarm_state=critical"* && "$client_netcheck_after_roam" != *"traversal_alarm_state=error"* && "$client_netcheck_after_roam" != *"traversal_alarm_state=missing"* && "$client_netcheck_after_roam" != *"dns_alarm_state=critical"* && "$client_netcheck_after_roam" != *"dns_alarm_state=error"* && "$client_netcheck_after_roam" != *"dns_alarm_state=missing"* && "$client_netcheck_after_roam" == *"traversal_error=none"* ]]; then
    final_signed_state_healthy=1
  fi

  if (( final_direct_path_live == 1 )) && (( final_signed_state_healthy == 1 )) && grep -Fq "exit_node=${EXIT_NODE_ID}" <<<"$client_status_after_roam" && grep -Fq 'dev rustynet0' <<<"$client_route_after_roam" && grep -Fq "${ROAM_ALIAS_IP}:51820" <<<"$client_endpoints_after_roam"; then
    CHECK_ENDPOINT_ROAM_RECOVERY_SUCCESS="pass"
  fi

  FAILURE_SUMMARY="validating narrow server-IP bypass and leak resistance after endpoint roam"
  if RUSTYNET_EXPECTED_GIT_COMMIT="${RUSTYNET_EXPECTED_GIT_COMMIT:-}" \
    bash "$ROOT_DIR/scripts/e2e/live_linux_server_ip_bypass_test.sh" \
      --ssh-identity-file "$SSH_IDENTITY_FILE" \
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

  mapfile -t bypass_results < <(
    cargo run --quiet -p rustynet-cli -- ops read-cross-network-report-fields \
      --report-path "$BYPASS_REPORT_PATH" \
      --check internet_route_via_rustynet0 \
      --check probe_service_blocked_from_client
  ) || return 1

  if [[ "${bypass_results[0]}" == 'pass' && "${bypass_results[1]}" == 'pass' ]]; then
    CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK="pass"
  fi

  if [[ "$CHECK_RELAY_TO_DIRECT_FAILBACK_SUCCESS" != 'pass' ]]; then
    if [[ "$CHECK_FAILBACK_RECOVERY_SLO" != 'pass' ]]; then
      FAILURE_SUMMARY="relay-to-direct failback exceeded reconnect SLO (${FAILBACK_RECOVERY_SLO_SECS}s), measured=${reconvergence_secs}s"
    elif [[ "$CHECK_NO_UNDERLAY_LEAK_DURING_FAILBACK" != 'pass' ]]; then
      FAILURE_SUMMARY="underlay leak detected while reconnecting during relay-to-direct failback"
    elif [[ "$CHECK_SIGNED_STATE_VALID_DURING_FAILBACK" != 'pass' ]]; then
      FAILURE_SUMMARY="signed traversal state became invalid while reconnecting during relay-to-direct failback"
    else
      FAILURE_SUMMARY="relay-to-direct failback did not reconverge securely"
    fi
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
