#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/e2e/live_lab_common.sh"

LIVE_LAB_LOG_PREFIX="cross-network-controller-switch"
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
CONTROLLER_OUTAGE_SECS=8
RECONNECT_SLO_SECS=30
REPORT_PATH="$ROOT_DIR/artifacts/phase10/cross_network_controller_switch_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/cross_network_controller_switch.log"

WORK_DIR=""
REPORT_WRITTEN=0
FAILURE_SUMMARY="cross-network controller switch validator did not complete"
CHECK_CONTROLLER_SWITCH_SUCCESS="fail"
CHECK_RELAY_REMOTE_EXIT_READY="fail"
CHECK_CONTROLLER_RECONNECT_WITHIN_SLO="fail"
CHECK_RECONNECT_VIA_PULL_REFRESH="fail"
CHECK_NO_UNDERLAY_LEAK_DURING_RECONNECT="fail"
CHECK_SIGNED_STATE_VALID_DURING_RECONNECT="fail"
CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="fail"
CHECK_NO_PLAINTEXT_PASSPHRASE_FILES="fail"
RELAY_REPORT_PATH=""
RELAY_LOG_PATH=""
MONITOR_LOG_PATH=""
MONITOR_SUMMARY_PATH=""
SOURCE_ARTIFACTS=()
LOG_ARTIFACTS=()
CONTROLLER_IP=""
CLIENT_ADDR=""
EXIT_ADDR=""
RELAY_ADDR=""
CONTROLLER_SWITCH_STARTED_UNIX=0

usage() {
  cat <<'USAGE'
usage: live_linux_cross_network_controller_switch_test.sh --ssh-identity-file <path> --client-host <user@host> --exit-host <user@host> --relay-host <user@host> --client-node-id <id> --exit-node-id <id> --relay-node-id <id> --client-network-id <id> --exit-network-id <id> --relay-network-id <id> [options]

options:
  --nat-profile <profile>
  --impairment-profile <profile>
  --ssh-allow-cidrs <cidr[,cidr]>
  --client-underlay-ip <ipv4>
  --exit-underlay-ip <ipv4>
  --relay-underlay-ip <ipv4>
  --controller-outage-secs <secs>          Default: 8
  --reconnect-slo-secs <secs>              Default: 30
  --report-path <path>
  --log-path <path>
USAGE
}

validate_positive_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value <= 0 )); then
    echo "$name must be a positive integer (got: $value)" >&2
    exit 2
  fi
}

extract_netcheck_value() {
  local netcheck="$1"
  local key="$2"
  printf '%s\n' "$netcheck" | tr ' ' '\n' | awk -F '=' -v key="$key" '$1 == key { print $2; exit }'
}

netcheck_is_valid() {
  local netcheck="$1"
  [[ "$netcheck" == *"traversal_error=none"* ]] || return 1
  [[ "$netcheck" != *"traversal_alarm_state=critical"* ]] || return 1
  [[ "$netcheck" != *"traversal_alarm_state=error"* ]] || return 1
  [[ "$netcheck" != *"traversal_alarm_state=missing"* ]] || return 1
  [[ "$netcheck" != *"dns_alarm_state=critical"* ]] || return 1
  [[ "$netcheck" != *"dns_alarm_state=error"* ]] || return 1
  [[ "$netcheck" != *"dns_alarm_state=missing"* ]] || return 1
  return 0
}

join_existing_artifacts() {
  local joined=""
  local item
  for item in "$@"; do
    [[ -n "$item" && -f "$item" ]] || continue
    if [[ -n "$joined" ]]; then
      joined+=$'\x1f'
    fi
    joined+="$item"
  done
  printf '%s' "$joined"
}

apply_controller_block() {
  local target="$1"
  local controller_ip="$2"
  live_lab_run_root "$target" "
root nft delete table inet rustynet_controller_switch_gate >/dev/null 2>&1 || true
root nft add table inet rustynet_controller_switch_gate
root nft 'add chain inet rustynet_controller_switch_gate input { type filter hook input priority -150; policy accept; }'
root nft 'add chain inet rustynet_controller_switch_gate output { type filter hook output priority -150; policy accept; }'
root nft add rule inet rustynet_controller_switch_gate input ip saddr ${controller_ip} counter drop
root nft add rule inet rustynet_controller_switch_gate output ip daddr ${controller_ip} counter drop
"
}

clear_controller_block() {
  local target="$1"
  live_lab_run_root "$target" "root nft delete table inet rustynet_controller_switch_gate >/dev/null 2>&1 || true"
}

write_summary() {
  local reconnect_secs="$1"
  local route_leak_samples="$2"
  local signed_state_invalid_samples="$3"
  local recovery_status="$4"
  local pull_refresh_status="$5"
  local reconnect_unix="$6"
  local reconnect_unix_json="null"
  if [[ "$reconnect_unix" =~ ^[0-9]+$ ]] && (( reconnect_unix > 0 )); then
    reconnect_unix_json="$reconnect_unix"
  fi
  MONITOR_SUMMARY_PATH="$MONITOR_SUMMARY_PATH" \
  CONTROLLER_SWITCH_STARTED_UNIX="$CONTROLLER_SWITCH_STARTED_UNIX" \
  CONTROLLER_IP="$CONTROLLER_IP" \
  RECONNECT_SECS="$reconnect_secs" \
  ROUTE_LEAK_SAMPLES="$route_leak_samples" \
  SIGNED_STATE_INVALID_SAMPLES="$signed_state_invalid_samples" \
  RECOVERY_STATUS="$recovery_status" \
  PULL_REFRESH_STATUS="$pull_refresh_status" \
  RECONNECT_UNIX_JSON="$reconnect_unix_json" \
  RECONNECT_SLO_SECS="$RECONNECT_SLO_SECS" \
  python - <<'PY'
import json
import os
from pathlib import Path

path = Path(os.environ["MONITOR_SUMMARY_PATH"])
path.parent.mkdir(parents=True, exist_ok=True)

reconnect_unix_raw = os.environ.get("RECONNECT_UNIX_JSON", "null")
try:
    reconnect_unix = int(reconnect_unix_raw)
except ValueError:
    reconnect_unix = None

payload = {
    "controller_switch_started_unix": int(os.environ.get("CONTROLLER_SWITCH_STARTED_UNIX", "0")),
    "controller_ip": os.environ.get("CONTROLLER_IP", ""),
    "reconnect_unix": reconnect_unix,
    "reconnect_secs": int(os.environ.get("RECONNECT_SECS", "-1")),
    "reconnect_slo_secs": int(os.environ.get("RECONNECT_SLO_SECS", "30")),
    "route_leak_samples": int(os.environ.get("ROUTE_LEAK_SAMPLES", "0")),
    "signed_state_invalid_samples": int(os.environ.get("SIGNED_STATE_INVALID_SAMPLES", "0")),
    "checks": {
        "controller_reconnect_within_slo": os.environ.get("RECOVERY_STATUS", "fail"),
        "reconnect_via_pull_refresh": os.environ.get("PULL_REFRESH_STATUS", "fail"),
    },
}

path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
}

write_report() {
  local status="$1"
  local captured_at_unix git_commit failure_summary
  captured_at_unix="$(date +%s)"
  git_commit="${RUSTYNET_EXPECTED_GIT_COMMIT:-$(git rev-parse HEAD)}"
  git_commit="$(printf '%s' "$git_commit" | tr 'A-F' 'a-f')"
  if [[ "$status" == "pass" ]]; then
    failure_summary=""
  else
    failure_summary="$FAILURE_SUMMARY"
  fi
  local source_joined log_joined
  source_joined="$(join_existing_artifacts "${SOURCE_ARTIFACTS[@]}")"
  log_joined="$(join_existing_artifacts "$LOG_PATH" "${LOG_ARTIFACTS[@]}")"

  STATUS_ENV="$status" \
  REPORT_PATH_ENV="$REPORT_PATH" \
  CAPTURED_AT_UNIX_ENV="$captured_at_unix" \
  GIT_COMMIT_ENV="$git_commit" \
  FAILURE_SUMMARY_ENV="$failure_summary" \
  CLIENT_HOST_ENV="$CLIENT_HOST" \
  EXIT_HOST_ENV="$EXIT_HOST" \
  RELAY_HOST_ENV="$RELAY_HOST" \
  CLIENT_NETWORK_ID_ENV="$CLIENT_NETWORK_ID" \
  EXIT_NETWORK_ID_ENV="$EXIT_NETWORK_ID" \
  RELAY_NETWORK_ID_ENV="$RELAY_NETWORK_ID" \
  NAT_PROFILE_ENV="$NAT_PROFILE" \
  IMPAIRMENT_PROFILE_ENV="$IMPAIRMENT_PROFILE" \
  SOURCE_ARTIFACTS_ENV="$source_joined" \
  LOG_ARTIFACTS_ENV="$log_joined" \
  CHECK_CONTROLLER_SWITCH_SUCCESS_ENV="$CHECK_CONTROLLER_SWITCH_SUCCESS" \
  CHECK_RELAY_REMOTE_EXIT_READY_ENV="$CHECK_RELAY_REMOTE_EXIT_READY" \
  CHECK_CONTROLLER_RECONNECT_WITHIN_SLO_ENV="$CHECK_CONTROLLER_RECONNECT_WITHIN_SLO" \
  CHECK_RECONNECT_VIA_PULL_REFRESH_ENV="$CHECK_RECONNECT_VIA_PULL_REFRESH" \
  CHECK_NO_UNDERLAY_LEAK_DURING_RECONNECT_ENV="$CHECK_NO_UNDERLAY_LEAK_DURING_RECONNECT" \
  CHECK_SIGNED_STATE_VALID_DURING_RECONNECT_ENV="$CHECK_SIGNED_STATE_VALID_DURING_RECONNECT" \
  CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC_ENV="$CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC" \
  CHECK_NO_PLAINTEXT_PASSPHRASE_FILES_ENV="$CHECK_NO_PLAINTEXT_PASSPHRASE_FILES" \
  python - <<'PY'
import json
import os
from pathlib import Path

def split_paths(raw: str):
    if not raw:
        return []
    return [entry for entry in raw.split("\x1f") if entry]

report_path = Path(os.environ["REPORT_PATH_ENV"])
report_path.parent.mkdir(parents=True, exist_ok=True)

payload = {
    "schema_version": 1,
    "phase": "phase10",
    "suite": "cross_network_controller_switch",
    "environment": "live_linux_cross_network_controller_switch",
    "evidence_mode": "measured",
    "captured_at_unix": int(os.environ["CAPTURED_AT_UNIX_ENV"]),
    "git_commit": os.environ["GIT_COMMIT_ENV"],
    "status": os.environ["STATUS_ENV"],
    "participants": {
        "client_host": os.environ["CLIENT_HOST_ENV"],
        "exit_host": os.environ["EXIT_HOST_ENV"],
        "relay_host": os.environ["RELAY_HOST_ENV"],
    },
    "network_context": {
        "client_network_id": os.environ["CLIENT_NETWORK_ID_ENV"],
        "exit_network_id": os.environ["EXIT_NETWORK_ID_ENV"],
        "relay_network_id": os.environ["RELAY_NETWORK_ID_ENV"],
        "nat_profile": os.environ["NAT_PROFILE_ENV"],
        "impairment_profile": os.environ["IMPAIRMENT_PROFILE_ENV"],
    },
    "checks": {
        "controller_switch_success": os.environ["CHECK_CONTROLLER_SWITCH_SUCCESS_ENV"],
        "relay_remote_exit_ready": os.environ["CHECK_RELAY_REMOTE_EXIT_READY_ENV"],
        "controller_reconnect_within_slo": os.environ["CHECK_CONTROLLER_RECONNECT_WITHIN_SLO_ENV"],
        "reconnect_via_pull_refresh": os.environ["CHECK_RECONNECT_VIA_PULL_REFRESH_ENV"],
        "no_underlay_leak_during_reconnect": os.environ["CHECK_NO_UNDERLAY_LEAK_DURING_RECONNECT_ENV"],
        "signed_state_valid_during_reconnect": os.environ["CHECK_SIGNED_STATE_VALID_DURING_RECONNECT_ENV"],
        "cross_network_topology_heuristic": os.environ["CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC_ENV"],
        "no_plaintext_passphrase_files": os.environ["CHECK_NO_PLAINTEXT_PASSPHRASE_FILES_ENV"],
    },
    "source_artifacts": split_paths(os.environ.get("SOURCE_ARTIFACTS_ENV", "")),
    "log_artifacts": split_paths(os.environ.get("LOG_ARTIFACTS_ENV", "")),
    "implementation_state": "live_measured_validator",
}

if payload["status"] == "fail":
    payload["failure_summary"] = os.environ.get("FAILURE_SUMMARY_ENV", "").strip()

report_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
}

cleanup() {
  local rc=$?
  set +e
  if [[ -n "$CLIENT_HOST" ]]; then
    clear_controller_block "$CLIENT_HOST" >/dev/null 2>&1 || true
  fi
  if [[ -n "$RELAY_HOST" ]]; then
    clear_controller_block "$RELAY_HOST" >/dev/null 2>&1 || true
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
    --controller-outage-secs) CONTROLLER_OUTAGE_SECS="$2"; shift 2 ;;
    --reconnect-slo-secs) RECONNECT_SLO_SECS="$2"; shift 2 ;;
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

if [[ "$CLIENT_NETWORK_ID" == "$EXIT_NETWORK_ID" || "$CLIENT_NETWORK_ID" == "$RELAY_NETWORK_ID" || "$EXIT_NETWORK_ID" == "$RELAY_NETWORK_ID" ]]; then
  echo "client, exit, and relay network ids must all differ" >&2
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

validate_positive_integer "controller outage seconds" "$CONTROLLER_OUTAGE_SECS"
validate_positive_integer "reconnect slo seconds" "$RECONNECT_SLO_SECS"

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")"
: > "$LOG_PATH"
exec >> "$LOG_PATH" 2>&1

main() {
  local relay_rc
  local route_leak_samples signed_state_invalid_samples
  local client_route client_status client_netcheck relay_netcheck
  local local_ts restore_started_unix reconnect_unix reconnect_secs
  local client_refresh_logs relay_refresh_logs
  local client_refresh_output relay_refresh_output
  local client_plaintext_start relay_plaintext_start exit_plaintext_start
  local client_plaintext_end relay_plaintext_end exit_plaintext_end
  local artifact_dir

  FAILURE_SUMMARY="preparing controller switch artifacts"
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rustynet-cross-network-controller-switch.XXXXXX")"
  artifact_dir="$(dirname "$REPORT_PATH")"
  RELAY_REPORT_PATH="$artifact_dir/cross_network_controller_switch_relay_stage_report.json"
  RELAY_LOG_PATH="$artifact_dir/cross_network_controller_switch_relay_stage.log"
  MONITOR_LOG_PATH="$artifact_dir/cross_network_controller_switch_monitor.log"
  MONITOR_SUMMARY_PATH="$artifact_dir/cross_network_controller_switch_summary.json"
  SOURCE_ARTIFACTS=(
    "$ROOT_DIR/scripts/e2e/live_linux_cross_network_controller_switch_test.sh"
    "$RELAY_REPORT_PATH"
    "$MONITOR_SUMMARY_PATH"
  )
  LOG_ARTIFACTS=(
    "$RELAY_LOG_PATH"
    "$MONITOR_LOG_PATH"
  )

  FAILURE_SUMMARY="bootstrapping relay remote-exit path before controller-switch simulation"
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

  mapfile -t relay_results < <(
    cargo run --quiet -p rustynet-cli -- ops read-cross-network-report-fields \
      --report-path "$RELAY_REPORT_PATH" \
      --include-status \
      --check relay_remote_exit_success \
      --check remote_exit_no_underlay_leak \
      --check cross_network_topology_heuristic
  ) || return 1

  if [[ "${relay_results[0]:-fail}" == 'pass' && "${relay_results[1]:-fail}" == 'pass' && "${relay_results[2]:-fail}" == 'pass' ]]; then
    CHECK_RELAY_REMOTE_EXIT_READY="pass"
  fi
  if [[ "${relay_results[3]:-fail}" == 'pass' ]]; then
    CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="pass"
  fi

  if [[ "$relay_rc" -ne 0 || "$CHECK_RELAY_REMOTE_EXIT_READY" != 'pass' ]]; then
    FAILURE_SUMMARY="relay bootstrap did not produce a secure baseline for controller-switch validation"
    return 1
  fi

  FAILURE_SUMMARY="initializing live-lab runtime for controller-switch validation"
  live_lab_init "rustynet-cross-network-controller-switch" "$SSH_IDENTITY_FILE"
  live_lab_push_sudo_password "$EXIT_HOST"
  live_lab_push_sudo_password "$RELAY_HOST"
  live_lab_push_sudo_password "$CLIENT_HOST"
  live_lab_wait_for_daemon_socket "$EXIT_HOST"
  live_lab_wait_for_daemon_socket "$RELAY_HOST"
  live_lab_wait_for_daemon_socket "$CLIENT_HOST"

  if [[ -n "$CLIENT_UNDERLAY_IP" ]]; then
    CLIENT_ADDR="$CLIENT_UNDERLAY_IP"
  else
    CLIENT_ADDR="$(live_lab_resolved_target_address "$CLIENT_HOST")"
  fi
  if [[ -n "$EXIT_UNDERLAY_IP" ]]; then
    EXIT_ADDR="$EXIT_UNDERLAY_IP"
  else
    EXIT_ADDR="$(live_lab_resolved_target_address "$EXIT_HOST")"
  fi
  if [[ -n "$RELAY_UNDERLAY_IP" ]]; then
    RELAY_ADDR="$RELAY_UNDERLAY_IP"
  else
    RELAY_ADDR="$(live_lab_resolved_target_address "$RELAY_HOST")"
  fi
  CONTROLLER_IP="$EXIT_ADDR"

  client_plaintext_start="$(live_lab_no_plaintext_passphrase_check "$CLIENT_HOST" || true)"
  relay_plaintext_start="$(live_lab_no_plaintext_passphrase_check "$RELAY_HOST" || true)"
  exit_plaintext_start="$(live_lab_no_plaintext_passphrase_check "$EXIT_HOST" || true)"

  FAILURE_SUMMARY="blocking controller underlay path with nftables"
  CONTROLLER_SWITCH_STARTED_UNIX="$(date +%s)"
  apply_controller_block "$CLIENT_HOST" "$CONTROLLER_IP"
  apply_controller_block "$RELAY_HOST" "$CONTROLLER_IP"

  : > "$MONITOR_LOG_PATH"
  route_leak_samples=0
  signed_state_invalid_samples=0

  for ((i=1; i<=CONTROLLER_OUTAGE_SECS; i++)); do
    local_ts="$(date +%s)"
    client_route="$(live_lab_capture "$CLIENT_HOST" "ip -4 route get 1.1.1.1 || true")"
    client_status="$(live_lab_status "$CLIENT_HOST")"
    client_netcheck="$(live_lab_capture_root "$CLIENT_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet netcheck || true")"
    relay_netcheck="$(live_lab_capture_root "$RELAY_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet netcheck || true")"

    if ! grep -Fq 'dev rustynet0' <<<"$client_route"; then
      route_leak_samples=$((route_leak_samples + 1))
    fi
    if ! netcheck_is_valid "$client_netcheck" || ! netcheck_is_valid "$relay_netcheck"; then
      signed_state_invalid_samples=$((signed_state_invalid_samples + 1))
    fi

    printf '%s|phase=blocked|iter=%s|route=%s|status=%s|client_netcheck=%s|relay_netcheck=%s\n' \
      "$local_ts" "$i" \
      "$(printf '%s' "$client_route" | tr -s ' ' | tr '\n' ';')" \
      "$(printf '%s' "$client_status" | tr -s ' ' | tr '\n' ';')" \
      "$(printf '%s' "$client_netcheck" | tr -s ' ' | tr '\n' ';')" \
      "$(printf '%s' "$relay_netcheck" | tr -s ' ' | tr '\n' ';')" >> "$MONITOR_LOG_PATH"

    sleep 1
  done

  FAILURE_SUMMARY="restoring controller underlay path"
  clear_controller_block "$CLIENT_HOST"
  clear_controller_block "$RELAY_HOST"
  restore_started_unix="$(date +%s)"

  reconnect_unix=0
  for ((i=1; i<=RECONNECT_SLO_SECS; i++)); do
    local_ts="$(date +%s)"
    client_status="$(live_lab_status "$CLIENT_HOST")"
    client_route="$(live_lab_capture "$CLIENT_HOST" "ip -4 route get 1.1.1.1 || true")"
    client_netcheck="$(live_lab_capture_root "$CLIENT_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet netcheck || true")"
    relay_netcheck="$(live_lab_capture_root "$RELAY_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet netcheck || true")"

    if ! grep -Fq 'dev rustynet0' <<<"$client_route"; then
      route_leak_samples=$((route_leak_samples + 1))
    fi
    if ! netcheck_is_valid "$client_netcheck" || ! netcheck_is_valid "$relay_netcheck"; then
      signed_state_invalid_samples=$((signed_state_invalid_samples + 1))
    fi

    printf '%s|phase=recovery|iter=%s|route=%s|status=%s|client_netcheck=%s|relay_netcheck=%s\n' \
      "$local_ts" "$i" \
      "$(printf '%s' "$client_route" | tr -s ' ' | tr '\n' ';')" \
      "$(printf '%s' "$client_status" | tr -s ' ' | tr '\n' ';')" \
      "$(printf '%s' "$client_netcheck" | tr -s ' ' | tr '\n' ';')" \
      "$(printf '%s' "$relay_netcheck" | tr -s ' ' | tr '\n' ';')" >> "$MONITOR_LOG_PATH"

    if grep -Fq "exit_node=${RELAY_NODE_ID}" <<<"$client_status" && grep -Fq 'state=ExitActive' <<<"$client_status" && grep -Fq 'dev rustynet0' <<<"$client_route" && netcheck_is_valid "$client_netcheck" && netcheck_is_valid "$relay_netcheck"; then
      reconnect_unix="$local_ts"
      break
    fi
    sleep 1
  done

  reconnect_secs=-1
  if (( reconnect_unix > 0 )); then
    reconnect_secs=$((reconnect_unix - restore_started_unix))
    if (( reconnect_secs >= 0 && reconnect_secs <= RECONNECT_SLO_SECS )); then
      CHECK_CONTROLLER_RECONNECT_WITHIN_SLO="pass"
    fi
  fi

  if (( route_leak_samples == 0 )); then
    CHECK_NO_UNDERLAY_LEAK_DURING_RECONNECT="pass"
  fi
  if (( signed_state_invalid_samples == 0 )); then
    CHECK_SIGNED_STATE_VALID_DURING_RECONNECT="pass"
  fi

  client_refresh_logs="$(live_lab_capture_root "$CLIENT_HOST" "root journalctl -u rustynetd --since '@${CONTROLLER_SWITCH_STARTED_UNIX}' --no-pager 2>/dev/null | grep -F 'signed state refresh completed' || true")"
  relay_refresh_logs="$(live_lab_capture_root "$RELAY_HOST" "root journalctl -u rustynetd --since '@${CONTROLLER_SWITCH_STARTED_UNIX}' --no-pager 2>/dev/null | grep -F 'signed state refresh completed' || true")"
  if [[ -n "$client_refresh_logs" || -n "$relay_refresh_logs" ]]; then
    CHECK_RECONNECT_VIA_PULL_REFRESH="pass"
  fi

  if [[ "$CHECK_RECONNECT_VIA_PULL_REFRESH" != 'pass' ]]; then
    client_refresh_output="$(live_lab_capture_root "$CLIENT_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet state refresh || true")"
    relay_refresh_output="$(live_lab_capture_root "$RELAY_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet state refresh || true")"
    if [[ "$client_refresh_output" == *"signed state refresh completed"* && "$relay_refresh_output" == *"signed state refresh completed"* ]]; then
      CHECK_RECONNECT_VIA_PULL_REFRESH="pass"
    fi
  fi

  client_plaintext_end="$(live_lab_no_plaintext_passphrase_check "$CLIENT_HOST" || true)"
  relay_plaintext_end="$(live_lab_no_plaintext_passphrase_check "$RELAY_HOST" || true)"
  exit_plaintext_end="$(live_lab_no_plaintext_passphrase_check "$EXIT_HOST" || true)"
  if [[ "$client_plaintext_start" == 'no-plaintext-passphrase-files' && "$relay_plaintext_start" == 'no-plaintext-passphrase-files' && "$exit_plaintext_start" == 'no-plaintext-passphrase-files' && "$client_plaintext_end" == 'no-plaintext-passphrase-files' && "$relay_plaintext_end" == 'no-plaintext-passphrase-files' && "$exit_plaintext_end" == 'no-plaintext-passphrase-files' ]]; then
    CHECK_NO_PLAINTEXT_PASSPHRASE_FILES="pass"
  fi

  write_summary \
    "$reconnect_secs" \
    "$route_leak_samples" \
    "$signed_state_invalid_samples" \
    "$CHECK_CONTROLLER_RECONNECT_WITHIN_SLO" \
    "$CHECK_RECONNECT_VIA_PULL_REFRESH" \
    "$reconnect_unix"

  if [[ "$CHECK_RELAY_REMOTE_EXIT_READY" == 'pass' && "$CHECK_CONTROLLER_RECONNECT_WITHIN_SLO" == 'pass' && "$CHECK_RECONNECT_VIA_PULL_REFRESH" == 'pass' && "$CHECK_NO_UNDERLAY_LEAK_DURING_RECONNECT" == 'pass' && "$CHECK_SIGNED_STATE_VALID_DURING_RECONNECT" == 'pass' && "$CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC" == 'pass' && "$CHECK_NO_PLAINTEXT_PASSPHRASE_FILES" == 'pass' ]]; then
    CHECK_CONTROLLER_SWITCH_SUCCESS="pass"
  fi

  if [[ "$CHECK_CONTROLLER_SWITCH_SUCCESS" != 'pass' ]]; then
    if [[ "$CHECK_CONTROLLER_RECONNECT_WITHIN_SLO" != 'pass' ]]; then
      FAILURE_SUMMARY="controller switch reconvergence exceeded reconnect SLO (${RECONNECT_SLO_SECS}s), measured=${reconnect_secs}s"
    elif [[ "$CHECK_RECONNECT_VIA_PULL_REFRESH" != 'pass' ]]; then
      FAILURE_SUMMARY="controller switch did not show signed pull-refresh recovery evidence"
    elif [[ "$CHECK_NO_UNDERLAY_LEAK_DURING_RECONNECT" != 'pass' ]]; then
      FAILURE_SUMMARY="underlay leak detected while controller path was switching"
    elif [[ "$CHECK_SIGNED_STATE_VALID_DURING_RECONNECT" != 'pass' ]]; then
      FAILURE_SUMMARY="signed state became invalid while controller path was switching"
    elif [[ "$CHECK_NO_PLAINTEXT_PASSPHRASE_FILES" != 'pass' ]]; then
      FAILURE_SUMMARY="plaintext passphrase files were detected during controller-switch validation"
    else
      FAILURE_SUMMARY="controller switch validation checks did not all pass"
    fi
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

live_lab_log "Cross-network controller-switch report written: $REPORT_PATH"
