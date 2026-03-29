#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/e2e/live_lab_common.sh"

LIVE_LAB_LOG_PREFIX="cross-network-remote-exit-soak"
export LIVE_LAB_LOG_PREFIX

SSH_IDENTITY_FILE=""
CLIENT_HOST=""
EXIT_HOST=""
CLIENT_NODE_ID="client-1"
EXIT_NODE_ID="exit-1"
CLIENT_NETWORK_ID=""
EXIT_NETWORK_ID=""
CLIENT_UNDERLAY_IP="${RUSTYNET_CLIENT_UNDERLAY_IP:-}"
EXIT_UNDERLAY_IP="${RUSTYNET_EXIT_UNDERLAY_IP:-}"
NAT_PROFILE="baseline_lan"
IMPAIRMENT_PROFILE="none"
SSH_ALLOW_CIDRS="192.168.18.0/24"
SOAK_DURATION_SECS=120
SOAK_SAMPLE_INTERVAL_SECS=5
SOAK_MAX_CONSECUTIVE_FAILURES=2
SOAK_MAX_FAILING_SAMPLES=2
REPORT_PATH="$ROOT_DIR/artifacts/phase10/cross_network_remote_exit_soak_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/cross_network_remote_exit_soak.log"

REPORT_WRITTEN=0
FAILURE_SUMMARY="cross-network remote-exit soak validator did not complete"
CHECK_LONG_SOAK_STABLE="fail"
CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK="fail"
CHECK_REMOTE_EXIT_SERVER_IP_BYPASS_IS_NARROW="fail"
CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="fail"
CHECK_DIRECT_REMOTE_EXIT_READY="fail"
CHECK_POST_SOAK_BYPASS_READY="fail"
CHECK_NO_PLAINTEXT_PASSPHRASE_FILES="fail"
DIRECT_REPORT_PATH=""
DIRECT_LOG_PATH=""
BYPASS_REPORT_PATH=""
BYPASS_LOG_PATH=""
MONITOR_LOG_PATH=""
MONITOR_SUMMARY_PATH=""
SOURCE_ARTIFACTS=()
LOG_ARTIFACTS=()
PATH_STATUS_LINE=""
CLIENT_ADDR=""
EXIT_ADDR=""
WORK_DIR=""

usage() {
  cat <<'USAGE'
usage: live_linux_cross_network_remote_exit_soak_test.sh --ssh-identity-file <path> --client-host <user@host> --exit-host <user@host> --client-network-id <id> --exit-network-id <id> [options]

options:
  --client-node-id <id>                Default: client-1
  --exit-node-id <id>                  Default: exit-1
  --nat-profile <profile>              Default: baseline_lan
  --impairment-profile <profile>       Default: none
  --ssh-allow-cidrs <cidr[,cidr]>
  --client-underlay-ip <ipv4>
  --exit-underlay-ip <ipv4>
  --soak-duration-secs <secs>          Default: 120
  --sample-interval-secs <secs>        Default: 5
  --max-consecutive-failures <count>   Default: 2
  --max-failing-samples <count>        Default: 2
  --report-path <path>
  --log-path <path>
USAGE
}

validate_positive_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value <= 0 )); then
    echo "$name must be a positive integer (got: $value)" >&2
    return 1
  fi
}

write_report() {
  local status="$1"
  local args=(
    cargo run --quiet -p rustynet-cli -- ops generate-cross-network-remote-exit-report
    --suite cross_network_remote_exit_soak
    --report-path "$REPORT_PATH"
    --log-path "$LOG_PATH"
    --status "$status"
    --failure-summary "$FAILURE_SUMMARY"
    --implementation-state live_measured_validator
    --environment live_linux_cross_network_remote_exit_soak
    --client-host "$CLIENT_HOST"
    --exit-host "$EXIT_HOST"
    --client-network-id "$CLIENT_NETWORK_ID"
    --exit-network-id "$EXIT_NETWORK_ID"
    --nat-profile "$NAT_PROFILE"
    --impairment-profile "$IMPAIRMENT_PROFILE"
    --source-artifact "$ROOT_DIR/scripts/e2e/live_linux_cross_network_remote_exit_soak_test.sh"
    --check "long_soak_stable=${CHECK_LONG_SOAK_STABLE}"
    --check "remote_exit_no_underlay_leak=${CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK}"
    --check "remote_exit_server_ip_bypass_is_narrow=${CHECK_REMOTE_EXIT_SERVER_IP_BYPASS_IS_NARROW}"
    --check "cross_network_topology_heuristic=${CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC}"
    --check "direct_remote_exit_ready=${CHECK_DIRECT_REMOTE_EXIT_READY}"
    --check "post_soak_bypass_ready=${CHECK_POST_SOAK_BYPASS_READY}"
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
    --client-node-id) CLIENT_NODE_ID="$2"; shift 2 ;;
    --exit-node-id) EXIT_NODE_ID="$2"; shift 2 ;;
    --client-network-id) CLIENT_NETWORK_ID="$2"; shift 2 ;;
    --exit-network-id) EXIT_NETWORK_ID="$2"; shift 2 ;;
    --client-underlay-ip) CLIENT_UNDERLAY_IP="$2"; shift 2 ;;
    --exit-underlay-ip) EXIT_UNDERLAY_IP="$2"; shift 2 ;;
    --nat-profile) NAT_PROFILE="$2"; shift 2 ;;
    --impairment-profile) IMPAIRMENT_PROFILE="$2"; shift 2 ;;
    --ssh-allow-cidrs) SSH_ALLOW_CIDRS="$2"; shift 2 ;;
    --soak-duration-secs) SOAK_DURATION_SECS="$2"; shift 2 ;;
    --sample-interval-secs) SOAK_SAMPLE_INTERVAL_SECS="$2"; shift 2 ;;
    --max-consecutive-failures) SOAK_MAX_CONSECUTIVE_FAILURES="$2"; shift 2 ;;
    --max-failing-samples) SOAK_MAX_FAILING_SAMPLES="$2"; shift 2 ;;
    --report-path) REPORT_PATH="$2"; shift 2 ;;
    --log-path) LOG_PATH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$SSH_IDENTITY_FILE" || -z "$CLIENT_HOST" || -z "$EXIT_HOST" || -z "$CLIENT_NETWORK_ID" || -z "$EXIT_NETWORK_ID" ]]; then
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

validate_positive_integer "soak duration seconds" "$SOAK_DURATION_SECS"
validate_positive_integer "sample interval seconds" "$SOAK_SAMPLE_INTERVAL_SECS"
validate_positive_integer "max consecutive failures" "$SOAK_MAX_CONSECUTIVE_FAILURES"
validate_positive_integer "max failing samples" "$SOAK_MAX_FAILING_SAMPLES"

if (( SOAK_SAMPLE_INTERVAL_SECS > SOAK_DURATION_SECS )); then
  echo "sample interval must be <= soak duration" >&2
  exit 2
fi

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")"
: > "$LOG_PATH"
exec >> "$LOG_PATH" 2>&1

main() {
  local artifact_dir direct_rc bypass_rc
  local sample_result sample_reason
  local client_status client_route client_endpoints
  local final_client_status
  local sample_ts start_ts end_ts elapsed_secs deadline
  local samples=0 failing_samples=0 consecutive_failures=0 max_consecutive_observed=0
  local first_failure_reason=""
  local client_plaintext_start exit_plaintext_start client_plaintext_end exit_plaintext_end
  local status_ok route_ok endpoint_ok
  local pre_leak_check="fail" pre_bypass_check="fail"
  local post_leak_check="fail" post_bypass_check="fail"

  FAILURE_SUMMARY="preparing cross-network remote-exit soak artifacts"
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rustynet-cross-network-remote-exit-soak.XXXXXX")"

  artifact_dir="$(dirname "$REPORT_PATH")"
  DIRECT_REPORT_PATH="$artifact_dir/cross_network_remote_exit_soak_direct_remote_exit_report.json"
  DIRECT_LOG_PATH="$artifact_dir/cross_network_remote_exit_soak_direct_remote_exit.log"
  BYPASS_REPORT_PATH="$artifact_dir/cross_network_remote_exit_soak_server_ip_bypass_report.json"
  BYPASS_LOG_PATH="$artifact_dir/cross_network_remote_exit_soak_server_ip_bypass.log"
  MONITOR_LOG_PATH="$artifact_dir/cross_network_remote_exit_soak_monitor.log"
  MONITOR_SUMMARY_PATH="$artifact_dir/cross_network_remote_exit_soak_monitor_summary.json"
  SOURCE_ARTIFACTS=("$DIRECT_REPORT_PATH" "$BYPASS_REPORT_PATH" "$MONITOR_SUMMARY_PATH")
  LOG_ARTIFACTS=("$DIRECT_LOG_PATH" "$BYPASS_LOG_PATH" "$MONITOR_LOG_PATH")

  FAILURE_SUMMARY="bootstrapping secure direct remote-exit baseline for soak validation"
  if RUSTYNET_EXPECTED_GIT_COMMIT="${RUSTYNET_EXPECTED_GIT_COMMIT:-}" \
    bash "$ROOT_DIR/scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh" \
      --ssh-identity-file "$SSH_IDENTITY_FILE" \
      --client-host "$CLIENT_HOST" \
      --exit-host "$EXIT_HOST" \
      --client-node-id "$CLIENT_NODE_ID" \
      --exit-node-id "$EXIT_NODE_ID" \
      --client-network-id "$CLIENT_NETWORK_ID" \
      --exit-network-id "$EXIT_NETWORK_ID" \
      --client-underlay-ip "${CLIENT_UNDERLAY_IP:-}" \
      --exit-underlay-ip "${EXIT_UNDERLAY_IP:-}" \
      --nat-profile "$NAT_PROFILE" \
      --impairment-profile "$IMPAIRMENT_PROFILE" \
      --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
      --report-path "$DIRECT_REPORT_PATH" \
      --log-path "$DIRECT_LOG_PATH"; then
    direct_rc=0
  else
    direct_rc=$?
  fi

  if [[ ! -f "$DIRECT_REPORT_PATH" ]]; then
    FAILURE_SUMMARY="direct remote-exit child validator failed before emitting evidence"
    return 1
  fi

  mapfile -t direct_results < <(
    cargo run --quiet -p rustynet-cli -- ops read-cross-network-report-fields \
      --report-path "$DIRECT_REPORT_PATH" \
      --include-status \
      --check direct_remote_exit_success \
      --check remote_exit_no_underlay_leak \
      --check remote_exit_server_ip_bypass_is_narrow \
      --check cross_network_topology_heuristic
  ) || return 1

  local direct_status="${direct_results[0]:-fail}"
  local direct_success="${direct_results[1]:-fail}"
  local direct_leak_check="${direct_results[2]:-fail}"
  local direct_bypass_check="${direct_results[3]:-fail}"
  local direct_topology_check="${direct_results[4]:-fail}"
  local direct_client_underlay
  local direct_exit_underlay

  if [[ "$direct_status" == 'pass' && "$direct_success" == 'pass' ]]; then
    CHECK_DIRECT_REMOTE_EXIT_READY="pass"
  fi
  if [[ "$direct_leak_check" == 'pass' ]]; then
    pre_leak_check="pass"
  fi
  if [[ "$direct_bypass_check" == 'pass' ]]; then
    pre_bypass_check="pass"
  fi
  if [[ "$direct_topology_check" == 'pass' ]]; then
    CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="pass"
  fi
  if [[ -n "$CLIENT_UNDERLAY_IP" ]]; then
    direct_client_underlay="$CLIENT_UNDERLAY_IP"
  else
    direct_client_underlay="$(live_lab_target_address "$CLIENT_HOST")"
  fi
  if [[ -n "$EXIT_UNDERLAY_IP" ]]; then
    direct_exit_underlay="$EXIT_UNDERLAY_IP"
  else
    direct_exit_underlay="$(live_lab_target_address "$EXIT_HOST")"
  fi
  CLIENT_ADDR="$direct_client_underlay"
  EXIT_ADDR="$direct_exit_underlay"

  if [[ "$direct_rc" -ne 0 || "$CHECK_DIRECT_REMOTE_EXIT_READY" != 'pass' ]]; then
    FAILURE_SUMMARY="direct remote-exit baseline failed; refusing soak claim"
    return 1
  fi
  if [[ "$CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC" != 'pass' ]]; then
    FAILURE_SUMMARY="direct remote-exit baseline did not prove a credible cross-network topology"
    return 1
  fi

  FAILURE_SUMMARY="initializing live runtime monitor for cross-network soak"
  live_lab_init "rustynet-cross-network-remote-exit-soak" "$SSH_IDENTITY_FILE"
  live_lab_push_sudo_password "$EXIT_HOST"
  live_lab_push_sudo_password "$CLIENT_HOST"
  live_lab_wait_for_daemon_socket "$EXIT_HOST"
  live_lab_wait_for_daemon_socket "$CLIENT_HOST"

  client_plaintext_start="$(live_lab_no_plaintext_passphrase_check "$CLIENT_HOST" || true)"
  exit_plaintext_start="$(live_lab_no_plaintext_passphrase_check "$EXIT_HOST" || true)"

  : > "$MONITOR_LOG_PATH"
  start_ts="$(date +%s)"
  deadline=$((start_ts + SOAK_DURATION_SECS))

  while (( $(date +%s) < deadline )); do
    sample_ts="$(date +%s)"
    samples=$((samples + 1))
    sample_result="pass"
    sample_reason=""

    if client_status="$(live_lab_status "$CLIENT_HOST" 2>/dev/null)"; then
      status_ok=1
    else
      client_status="status-command-failed"
      status_ok=0
    fi
    if client_route="$(live_lab_capture "$CLIENT_HOST" "ip -4 route get 1.1.1.1 || true" 2>/dev/null)"; then
      route_ok=1
    else
      client_route="route-command-failed"
      route_ok=0
    fi
    if client_endpoints="$(live_lab_capture_root "$CLIENT_HOST" "root wg show rustynet0 endpoints || true" 2>/dev/null)"; then
      endpoint_ok=1
    else
      client_endpoints="endpoint-command-failed"
      endpoint_ok=0
    fi

    if (( status_ok == 0 )) || ! grep -Fq "exit_node=${EXIT_NODE_ID}" <<<"$client_status" || ! grep -Fq 'state=ExitActive' <<<"$client_status"; then
      sample_result="fail"
      sample_reason+="status_not_exit_active;"
    fi
    if (( route_ok == 0 )) || ! grep -Fq 'dev rustynet0' <<<"$client_route"; then
      sample_result="fail"
      sample_reason+="route_not_tunnelled;"
    fi
    if (( endpoint_ok == 0 )) || ! grep -Fq "${EXIT_ADDR}:51820" <<<"$client_endpoints"; then
      sample_result="fail"
      sample_reason+="exit_endpoint_not_visible;"
    fi

    printf '%s|sample=%s|result=%s|reason=%s|status=%s|route=%s|endpoints=%s\n' \
      "$sample_ts" \
      "$samples" \
      "$sample_result" \
      "${sample_reason:-none}" \
      "$(printf '%s' "$client_status" | tr -s ' ' | tr '\n' ';')" \
      "$(printf '%s' "$client_route" | tr -s ' ' | tr '\n' ';')" \
      "$(printf '%s' "$client_endpoints" | tr -s ' ' | tr '\n' ';')" >> "$MONITOR_LOG_PATH"

    if [[ "$sample_result" == "pass" ]]; then
      consecutive_failures=0
    else
      failing_samples=$((failing_samples + 1))
      consecutive_failures=$((consecutive_failures + 1))
      if [[ -z "$first_failure_reason" ]]; then
        first_failure_reason="${sample_reason:-unknown}"
      fi
      if (( consecutive_failures > max_consecutive_observed )); then
        max_consecutive_observed="$consecutive_failures"
      fi
      if (( consecutive_failures > SOAK_MAX_CONSECUTIVE_FAILURES )); then
        FAILURE_SUMMARY="soak monitor exceeded max consecutive failures (${SOAK_MAX_CONSECUTIVE_FAILURES})"
        break
      fi
    fi

    sleep "$SOAK_SAMPLE_INTERVAL_SECS"
  done

  end_ts="$(date +%s)"
  elapsed_secs=$((end_ts - start_ts))

  client_plaintext_end="$(live_lab_no_plaintext_passphrase_check "$CLIENT_HOST" || true)"
  exit_plaintext_end="$(live_lab_no_plaintext_passphrase_check "$EXIT_HOST" || true)"
  if [[ "$client_plaintext_start" == 'no-plaintext-passphrase-files' && "$exit_plaintext_start" == 'no-plaintext-passphrase-files' && "$client_plaintext_end" == 'no-plaintext-passphrase-files' && "$exit_plaintext_end" == 'no-plaintext-passphrase-files' ]]; then
    CHECK_NO_PLAINTEXT_PASSPHRASE_FILES="pass"
  fi

  FAILURE_SUMMARY="running post-soak leak and bypass verification"
  if RUSTYNET_EXPECTED_GIT_COMMIT="${RUSTYNET_EXPECTED_GIT_COMMIT:-}" \
    bash "$ROOT_DIR/scripts/e2e/live_linux_server_ip_bypass_test.sh" \
      --ssh-identity-file "$SSH_IDENTITY_FILE" \
      --client-host "$CLIENT_HOST" \
      --probe-host "$EXIT_HOST" \
      --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
      --report-path "$BYPASS_REPORT_PATH" \
      --log-path "$BYPASS_LOG_PATH"; then
    bypass_rc=0
  else
    bypass_rc=$?
  fi

  if [[ ! -f "$BYPASS_REPORT_PATH" ]]; then
    FAILURE_SUMMARY="post-soak server-IP bypass validator failed before emitting evidence"
    return 1
  fi

  mapfile -t bypass_results < <(
    cargo run --quiet -p rustynet-cli -- ops read-cross-network-report-fields \
      --report-path "$BYPASS_REPORT_PATH" \
      --include-status \
      --check internet_route_via_rustynet0 \
      --check probe_service_blocked_from_client \
      --check probe_endpoint_route_direct_not_tunnelled \
      --check no_unexpected_bypass_routes
  ) || return 1

  local bypass_status_value="${bypass_results[0]:-fail}"
  local bypass_route_tunnelled="${bypass_results[1]:-fail}"
  local bypass_probe_blocked="${bypass_results[2]:-fail}"
  local bypass_probe_direct="${bypass_results[3]:-fail}"
  local bypass_no_unexpected="${bypass_results[4]:-fail}"

  if [[ "$bypass_status_value" == 'pass' ]]; then
    CHECK_POST_SOAK_BYPASS_READY="pass"
  fi
  if [[ "$bypass_route_tunnelled" == 'pass' && "$bypass_probe_blocked" == 'pass' ]]; then
    post_leak_check="pass"
  fi
  if [[ "$bypass_probe_blocked" == 'pass' && "$bypass_probe_direct" == 'pass' && "$bypass_no_unexpected" == 'pass' ]]; then
    post_bypass_check="pass"
  fi

  if [[ "$pre_leak_check" == 'pass' && "$post_leak_check" == 'pass' ]]; then
    CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK="pass"
  fi
  if [[ "$pre_bypass_check" == 'pass' && "$post_bypass_check" == 'pass' ]]; then
    CHECK_REMOTE_EXIT_SERVER_IP_BYPASS_IS_NARROW="pass"
  fi

  FAILURE_SUMMARY="capturing final live-path evidence after soak"
  final_client_status="$(live_lab_status "$CLIENT_HOST")"
  PATH_STATUS_LINE="$final_client_status"
  live_lab_log "Final client status after soak"
  printf '%s\n' "$final_client_status"

  if (( samples > 0 && elapsed_secs >= SOAK_DURATION_SECS && failing_samples <= SOAK_MAX_FAILING_SAMPLES && max_consecutive_observed <= SOAK_MAX_CONSECUTIVE_FAILURES && bypass_rc == 0 )) && [[ "$CHECK_NO_PLAINTEXT_PASSPHRASE_FILES" == 'pass' ]]; then
    CHECK_LONG_SOAK_STABLE="pass"
  fi

  cargo run --quiet -p rustynet-cli -- ops write-cross-network-soak-monitor-summary \
    --path "$MONITOR_SUMMARY_PATH" \
    --samples "$samples" \
    --failing-samples "$failing_samples" \
    --max-consecutive-failures-observed "$max_consecutive_observed" \
    --elapsed-secs "$elapsed_secs" \
    --required-soak-duration-secs "$SOAK_DURATION_SECS" \
    --allowed-failing-samples "$SOAK_MAX_FAILING_SAMPLES" \
    --allowed-max-consecutive-failures "$SOAK_MAX_CONSECUTIVE_FAILURES" \
    --direct-remote-exit-ready "$CHECK_DIRECT_REMOTE_EXIT_READY" \
    --post-soak-bypass-ready "$CHECK_POST_SOAK_BYPASS_READY" \
    --no-plaintext-passphrase-files "$CHECK_NO_PLAINTEXT_PASSPHRASE_FILES" \
    --first-failure-reason "${first_failure_reason:-none}" \
    --long-soak-stable "$CHECK_LONG_SOAK_STABLE" >/dev/null

  if [[ "$CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC" != 'pass' ]]; then
    FAILURE_SUMMARY="soak path topology did not credibly prove a cross-network claim"
    return 1
  fi
  if [[ "$CHECK_DIRECT_REMOTE_EXIT_READY" != 'pass' ]]; then
    FAILURE_SUMMARY="soak path did not preserve direct remote-exit bootstrap proof"
    return 1
  fi
  if [[ "$CHECK_POST_SOAK_BYPASS_READY" != 'pass' ]]; then
    FAILURE_SUMMARY="soak path did not produce a passing post-soak server-IP bypass report"
    return 1
  fi
  if [[ "$CHECK_NO_PLAINTEXT_PASSPHRASE_FILES" != 'pass' ]]; then
    FAILURE_SUMMARY="soak path detected plaintext passphrase material before or after soak"
    return 1
  fi
  if [[ "$CHECK_LONG_SOAK_STABLE" != 'pass' ]]; then
    FAILURE_SUMMARY="cross-network remote-exit soak stability checks failed (samples=${samples}, failing=${failing_samples}, consecutive=${max_consecutive_observed}, elapsed=${elapsed_secs}s, first_failure=${first_failure_reason:-none})"
    return 1
  fi
  if [[ "$CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK" != 'pass' ]]; then
    FAILURE_SUMMARY="cross-network remote-exit soak could not prove underlay leak resistance before and after soak"
    return 1
  fi
  if [[ "$CHECK_REMOTE_EXIT_SERVER_IP_BYPASS_IS_NARROW" != 'pass' ]]; then
    FAILURE_SUMMARY="cross-network remote-exit soak server-IP bypass scope was broader than allowed"
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

printf 'cross-network remote-exit soak report written: %s\n' "$REPORT_PATH"
