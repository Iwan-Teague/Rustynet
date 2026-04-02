#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/e2e/live_lab_common.sh"

LIVE_LAB_LOG_PREFIX="cross-network-node-network-switch"
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
RECONNECT_SLO_SECS=30
REPORT_PATH="$ROOT_DIR/artifacts/phase10/cross_network_node_network_switch_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/cross_network_node_network_switch.log"

WORK_DIR=""
REPORT_WRITTEN=0
FAILURE_SUMMARY="cross-network node network-switch validator did not complete"
CHECK_NODE_NETWORK_SWITCH_SUCCESS="fail"
CHECK_DIRECT_REMOTE_EXIT_READY="fail"
CHECK_ENDPOINT_CHANGE_DETECTED="fail"
CHECK_TRAVERSAL_REISSUE_TRIGGERED="fail"
CHECK_SESSION_RECONNECT_WITHIN_SLO="fail"
CHECK_PEER_RECEIVED_UPDATED_ENDPOINT_HINT="fail"
CHECK_NO_UNDERLAY_LEAK_DURING_TRANSITION="fail"
CHECK_SIGNED_STATE_VALID_DURING_TRANSITION="fail"
CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="fail"
CHECK_NO_PLAINTEXT_PASSPHRASE_FILES="fail"
DIRECT_REPORT_PATH=""
DIRECT_LOG_PATH=""
MONITOR_LOG_PATH=""
MONITOR_SUMMARY_PATH=""
SOURCE_ARTIFACTS=()
LOG_ARTIFACTS=()
CLIENT_ADDR=""
EXIT_ADDR=""
CLIENT_IFACE=""
ALIAS_IP=""
ALIAS_PREFIX=""
ORIGINAL_ROUTE_SNAPSHOT=""
SWITCH_STARTED_UNIX=0

usage() {
  cat <<'USAGE'
usage: live_linux_cross_network_node_network_switch_test.sh --ssh-identity-file <path> --client-host <user@host> --exit-host <user@host> --client-node-id <id> --exit-node-id <id> --client-network-id <id> --exit-network-id <id> [options]

options:
  --nat-profile <profile>
  --impairment-profile <profile>
  --ssh-allow-cidrs <cidr[,cidr]>
  --client-underlay-ip <ipv4>
  --exit-underlay-ip <ipv4>
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

choose_alias() {
  mapfile -t alias_values < <(
    cargo run --quiet -p rustynet-cli -- ops choose-cross-network-roam-alias \
      --exit-ip "$CLIENT_ADDR" \
      --used-ip "$CLIENT_ADDR" \
      --used-ip "$EXIT_ADDR"
  )
  ALIAS_IP="${alias_values[0]:-}"
  ALIAS_PREFIX="${alias_values[1]:-}"
  if [[ -z "$ALIAS_IP" || -z "$ALIAS_PREFIX" ]]; then
    echo "failed to choose roam alias for client endpoint switch" >&2
    return 1
  fi
}

capture_default_route_iface() {
  local target="$1"
  live_lab_capture "$target" "ip -4 route show default | awk '/^default/ {for (i=1; i<=NF; i++) if (\$i == \"dev\") {print \$(i+1); exit}}' || true"
}

capture_default_route_snapshot() {
  local target="$1"
  live_lab_capture "$target" "ip -4 route show default || true"
}

apply_alias_switch() {
  local target="$1"
  local iface="$2"
  local alias_ip="$3"
  local alias_prefix="$4"
  live_lab_run_root "$target" "
root ip addr show dev '$iface' | grep -Fq '${alias_ip}/${alias_prefix}' || root ip addr add '${alias_ip}/${alias_prefix}' dev '$iface'
root ip route replace default dev '$iface' src '$alias_ip'
"
}

clear_alias_switch() {
  local target="$1"
  local iface="$2"
  local alias_ip="$3"
  local alias_prefix="$4"
  local original_default="$5"
  live_lab_run_root "$target" "
if [[ -n '$original_default' ]]; then
  while IFS= read -r line; do
    [[ -n \"\$line\" ]] || continue
    root ip route replace \$line || true
  done <<< '$original_default'
fi
root ip addr del '${alias_ip}/${alias_prefix}' dev '$iface' >/dev/null 2>&1 || true
" >/dev/null 2>&1 || true
}

write_summary() {
  local reconnect_secs="$1"
  local route_leak_samples="$2"
  local signed_state_invalid_samples="$3"
  local endpoint_detected="$4"
  local traversal_reissue="$5"
  local endpoint_hint="$6"
  local reconnect_unix="$7"
  local reconnect_unix_json="null"
  if [[ "$reconnect_unix" =~ ^[0-9]+$ ]] && (( reconnect_unix > 0 )); then
    reconnect_unix_json="$reconnect_unix"
  fi
  MONITOR_SUMMARY_PATH="$MONITOR_SUMMARY_PATH" \
  SWITCH_STARTED_UNIX="$SWITCH_STARTED_UNIX" \
  ALIAS_IP="$ALIAS_IP" \
  RECONNECT_SECS="$reconnect_secs" \
  ROUTE_LEAK_SAMPLES="$route_leak_samples" \
  SIGNED_STATE_INVALID_SAMPLES="$signed_state_invalid_samples" \
  ENDPOINT_DETECTED="$endpoint_detected" \
  TRAVERSAL_REISSUE="$traversal_reissue" \
  ENDPOINT_HINT="$endpoint_hint" \
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
    "switch_started_unix": int(os.environ.get("SWITCH_STARTED_UNIX", "0")),
    "alias_ip": os.environ.get("ALIAS_IP", ""),
    "reconnect_unix": reconnect_unix,
    "reconnect_secs": int(os.environ.get("RECONNECT_SECS", "-1")),
    "reconnect_slo_secs": int(os.environ.get("RECONNECT_SLO_SECS", "30")),
    "route_leak_samples": int(os.environ.get("ROUTE_LEAK_SAMPLES", "0")),
    "signed_state_invalid_samples": int(os.environ.get("SIGNED_STATE_INVALID_SAMPLES", "0")),
    "checks": {
        "endpoint_change_detected": os.environ.get("ENDPOINT_DETECTED", "fail"),
        "traversal_reissue_triggered": os.environ.get("TRAVERSAL_REISSUE", "fail"),
        "peer_received_updated_endpoint_hint": os.environ.get("ENDPOINT_HINT", "fail"),
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
  CLIENT_NETWORK_ID_ENV="$CLIENT_NETWORK_ID" \
  EXIT_NETWORK_ID_ENV="$EXIT_NETWORK_ID" \
  NAT_PROFILE_ENV="$NAT_PROFILE" \
  IMPAIRMENT_PROFILE_ENV="$IMPAIRMENT_PROFILE" \
  SOURCE_ARTIFACTS_ENV="$source_joined" \
  LOG_ARTIFACTS_ENV="$log_joined" \
  CHECK_NODE_NETWORK_SWITCH_SUCCESS_ENV="$CHECK_NODE_NETWORK_SWITCH_SUCCESS" \
  CHECK_DIRECT_REMOTE_EXIT_READY_ENV="$CHECK_DIRECT_REMOTE_EXIT_READY" \
  CHECK_ENDPOINT_CHANGE_DETECTED_ENV="$CHECK_ENDPOINT_CHANGE_DETECTED" \
  CHECK_TRAVERSAL_REISSUE_TRIGGERED_ENV="$CHECK_TRAVERSAL_REISSUE_TRIGGERED" \
  CHECK_SESSION_RECONNECT_WITHIN_SLO_ENV="$CHECK_SESSION_RECONNECT_WITHIN_SLO" \
  CHECK_PEER_RECEIVED_UPDATED_ENDPOINT_HINT_ENV="$CHECK_PEER_RECEIVED_UPDATED_ENDPOINT_HINT" \
  CHECK_NO_UNDERLAY_LEAK_DURING_TRANSITION_ENV="$CHECK_NO_UNDERLAY_LEAK_DURING_TRANSITION" \
  CHECK_SIGNED_STATE_VALID_DURING_TRANSITION_ENV="$CHECK_SIGNED_STATE_VALID_DURING_TRANSITION" \
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
    "suite": "cross_network_node_network_switch",
    "environment": "live_linux_cross_network_node_network_switch",
    "evidence_mode": "measured",
    "captured_at_unix": int(os.environ["CAPTURED_AT_UNIX_ENV"]),
    "git_commit": os.environ["GIT_COMMIT_ENV"],
    "status": os.environ["STATUS_ENV"],
    "participants": {
        "client_host": os.environ["CLIENT_HOST_ENV"],
        "exit_host": os.environ["EXIT_HOST_ENV"],
    },
    "network_context": {
        "client_network_id": os.environ["CLIENT_NETWORK_ID_ENV"],
        "exit_network_id": os.environ["EXIT_NETWORK_ID_ENV"],
        "nat_profile": os.environ["NAT_PROFILE_ENV"],
        "impairment_profile": os.environ["IMPAIRMENT_PROFILE_ENV"],
    },
    "checks": {
        "node_network_switch_success": os.environ["CHECK_NODE_NETWORK_SWITCH_SUCCESS_ENV"],
        "direct_remote_exit_ready": os.environ["CHECK_DIRECT_REMOTE_EXIT_READY_ENV"],
        "endpoint_change_detected": os.environ["CHECK_ENDPOINT_CHANGE_DETECTED_ENV"],
        "traversal_reissue_triggered": os.environ["CHECK_TRAVERSAL_REISSUE_TRIGGERED_ENV"],
        "session_reconnect_within_slo": os.environ["CHECK_SESSION_RECONNECT_WITHIN_SLO_ENV"],
        "peer_received_updated_endpoint_hint": os.environ["CHECK_PEER_RECEIVED_UPDATED_ENDPOINT_HINT_ENV"],
        "no_underlay_leak_during_transition": os.environ["CHECK_NO_UNDERLAY_LEAK_DURING_TRANSITION_ENV"],
        "signed_state_valid_during_transition": os.environ["CHECK_SIGNED_STATE_VALID_DURING_TRANSITION_ENV"],
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
  if [[ -n "$CLIENT_HOST" && -n "$CLIENT_IFACE" && -n "$ALIAS_IP" && -n "$ALIAS_PREFIX" ]]; then
    clear_alias_switch "$CLIENT_HOST" "$CLIENT_IFACE" "$ALIAS_IP" "$ALIAS_PREFIX" "$ORIGINAL_ROUTE_SNAPSHOT"
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
    --client-node-id) CLIENT_NODE_ID="$2"; shift 2 ;;
    --exit-node-id) EXIT_NODE_ID="$2"; shift 2 ;;
    --client-network-id) CLIENT_NETWORK_ID="$2"; shift 2 ;;
    --exit-network-id) EXIT_NETWORK_ID="$2"; shift 2 ;;
    --client-underlay-ip) CLIENT_UNDERLAY_IP="$2"; shift 2 ;;
    --exit-underlay-ip) EXIT_UNDERLAY_IP="$2"; shift 2 ;;
    --nat-profile) NAT_PROFILE="$2"; shift 2 ;;
    --impairment-profile) IMPAIRMENT_PROFILE="$2"; shift 2 ;;
    --ssh-allow-cidrs) SSH_ALLOW_CIDRS="$2"; shift 2 ;;
    --reconnect-slo-secs) RECONNECT_SLO_SECS="$2"; shift 2 ;;
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

validate_positive_integer "reconnect slo seconds" "$RECONNECT_SLO_SECS"

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")"
: > "$LOG_PATH"
exec >> "$LOG_PATH" 2>&1

main() {
  local direct_rc
  local route_leak_samples signed_state_invalid_samples
  local local_ts reconnect_unix reconnect_secs
  local client_status client_route client_netcheck exit_netcheck client_endpoints exit_endpoints
  local pre_change_fingerprint post_change_fingerprint
  local pre_reissue_events post_reissue_events
  local client_plaintext_start exit_plaintext_start
  local client_plaintext_end exit_plaintext_end
  local alias_apply_rc=0
  local artifact_dir

  FAILURE_SUMMARY="preparing node network-switch artifacts"
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rustynet-cross-network-node-switch.XXXXXX")"
  artifact_dir="$(dirname "$REPORT_PATH")"
  DIRECT_REPORT_PATH="$artifact_dir/cross_network_node_network_switch_direct_stage_report.json"
  DIRECT_LOG_PATH="$artifact_dir/cross_network_node_network_switch_direct_stage.log"
  MONITOR_LOG_PATH="$artifact_dir/cross_network_node_network_switch_monitor.log"
  MONITOR_SUMMARY_PATH="$artifact_dir/cross_network_node_network_switch_summary.json"
  SOURCE_ARTIFACTS=(
    "$ROOT_DIR/scripts/e2e/live_linux_cross_network_node_network_switch_test.sh"
    "$DIRECT_REPORT_PATH"
    "$MONITOR_SUMMARY_PATH"
  )
  LOG_ARTIFACTS=(
    "$DIRECT_LOG_PATH"
    "$MONITOR_LOG_PATH"
  )

  FAILURE_SUMMARY="bootstrapping direct remote-exit path before node network-switch simulation"
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
    FAILURE_SUMMARY="direct baseline validator failed before emitting evidence"
    return 1
  fi

  mapfile -t direct_results < <(
    cargo run --quiet -p rustynet-cli -- ops read-cross-network-report-fields \
      --report-path "$DIRECT_REPORT_PATH" \
      --include-status \
      --check direct_remote_exit_success \
      --check remote_exit_no_underlay_leak \
      --check cross_network_topology_heuristic
  ) || return 1

  if [[ "${direct_results[0]:-fail}" == 'pass' && "${direct_results[1]:-fail}" == 'pass' && "${direct_results[2]:-fail}" == 'pass' ]]; then
    CHECK_DIRECT_REMOTE_EXIT_READY="pass"
  fi
  if [[ "${direct_results[3]:-fail}" == 'pass' ]]; then
    CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="pass"
  fi

  if [[ "$direct_rc" -ne 0 || "$CHECK_DIRECT_REMOTE_EXIT_READY" != 'pass' ]]; then
    FAILURE_SUMMARY="direct baseline did not produce secure readiness for node switch validation"
    return 1
  fi

  FAILURE_SUMMARY="initializing runtime for node underlay switch validation"
  live_lab_init "rustynet-cross-network-node-switch" "$SSH_IDENTITY_FILE"
  live_lab_push_sudo_password "$EXIT_HOST"
  live_lab_push_sudo_password "$CLIENT_HOST"
  live_lab_wait_for_daemon_socket "$EXIT_HOST"
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
  choose_alias || return 1
  CLIENT_IFACE="$(capture_default_route_iface "$CLIENT_HOST" | tr -d '[:space:]')"
  if [[ -z "$CLIENT_IFACE" ]]; then
    FAILURE_SUMMARY="failed to resolve client default underlay interface"
    return 1
  fi
  ORIGINAL_ROUTE_SNAPSHOT="$(capture_default_route_snapshot "$CLIENT_HOST")"

  client_plaintext_start="$(live_lab_no_plaintext_passphrase_check "$CLIENT_HOST" || true)"
  exit_plaintext_start="$(live_lab_no_plaintext_passphrase_check "$EXIT_HOST" || true)"

  pre_change_fingerprint="$(extract_netcheck_value "$(live_lab_capture_root "$CLIENT_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet netcheck || true")" "traversal_endpoint_fingerprint")"
  pre_reissue_events="$(extract_netcheck_value "$(live_lab_capture_root "$CLIENT_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet netcheck || true")" "traversal_preexpiry_refresh_events")"
  if [[ -z "$pre_reissue_events" || ! "$pre_reissue_events" =~ ^[0-9]+$ ]]; then
    pre_reissue_events=0
  fi

  FAILURE_SUMMARY="applying client underlay alias and route switch"
  SWITCH_STARTED_UNIX="$(date +%s)"
  if ! apply_alias_switch "$CLIENT_HOST" "$CLIENT_IFACE" "$ALIAS_IP" "$ALIAS_PREFIX"; then
    alias_apply_rc=1
  fi
  if [[ "$alias_apply_rc" -ne 0 ]]; then
    FAILURE_SUMMARY="failed to apply client alias route switch"
    return 1
  fi

  : > "$MONITOR_LOG_PATH"
  route_leak_samples=0
  signed_state_invalid_samples=0
  reconnect_unix=0

  for ((i=1; i<=RECONNECT_SLO_SECS; i++)); do
    local_ts="$(date +%s)"
    client_status="$(live_lab_status "$CLIENT_HOST")"
    client_route="$(live_lab_capture "$CLIENT_HOST" "ip -4 route get 1.1.1.1 || true")"
    client_netcheck="$(live_lab_capture_root "$CLIENT_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet netcheck || true")"
    exit_netcheck="$(live_lab_capture_root "$EXIT_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet netcheck || true")"
    client_endpoints="$(live_lab_capture_root "$CLIENT_HOST" "root wg show rustynet0 endpoints || true")"
    exit_endpoints="$(live_lab_capture_root "$EXIT_HOST" "root wg show rustynet0 endpoints || true")"

    if ! grep -Fq 'dev rustynet0' <<<"$client_route"; then
      route_leak_samples=$((route_leak_samples + 1))
    fi
    if ! netcheck_is_valid "$client_netcheck" || ! netcheck_is_valid "$exit_netcheck"; then
      signed_state_invalid_samples=$((signed_state_invalid_samples + 1))
    fi

    post_change_fingerprint="$(extract_netcheck_value "$client_netcheck" "traversal_endpoint_fingerprint")"
    post_reissue_events="$(extract_netcheck_value "$client_netcheck" "traversal_preexpiry_refresh_events")"
    if [[ -z "$post_reissue_events" || ! "$post_reissue_events" =~ ^[0-9]+$ ]]; then
      post_reissue_events=0
    fi

    if [[ -n "$pre_change_fingerprint" && -n "$post_change_fingerprint" && "$pre_change_fingerprint" != "$post_change_fingerprint" ]]; then
      CHECK_ENDPOINT_CHANGE_DETECTED="pass"
    fi
    if (( post_reissue_events > pre_reissue_events )); then
      CHECK_TRAVERSAL_REISSUE_TRIGGERED="pass"
    fi
    if grep -Fq "${ALIAS_IP}:51820" <<<"$exit_endpoints" || grep -Fq "${ALIAS_IP}:51820" <<<"$client_endpoints"; then
      CHECK_PEER_RECEIVED_UPDATED_ENDPOINT_HINT="pass"
    fi

    printf '%s|iter=%s|route=%s|status=%s|client_netcheck=%s|exit_netcheck=%s|client_endpoints=%s|exit_endpoints=%s\n' \
      "$local_ts" "$i" \
      "$(printf '%s' "$client_route" | tr -s ' ' | tr '\n' ';')" \
      "$(printf '%s' "$client_status" | tr -s ' ' | tr '\n' ';')" \
      "$(printf '%s' "$client_netcheck" | tr -s ' ' | tr '\n' ';')" \
      "$(printf '%s' "$exit_netcheck" | tr -s ' ' | tr '\n' ';')" \
      "$(printf '%s' "$client_endpoints" | tr -s ' ' | tr '\n' ';')" \
      "$(printf '%s' "$exit_endpoints" | tr -s ' ' | tr '\n' ';')" >> "$MONITOR_LOG_PATH"

    if grep -Fq "exit_node=${EXIT_NODE_ID}" <<<"$client_status" && grep -Fq 'state=ExitActive' <<<"$client_status" && grep -Fq 'dev rustynet0' <<<"$client_route" && netcheck_is_valid "$client_netcheck" && netcheck_is_valid "$exit_netcheck"; then
      reconnect_unix="$local_ts"
      break
    fi

    sleep 1
  done

  reconnect_secs=-1
  if (( reconnect_unix > 0 )); then
    reconnect_secs=$((reconnect_unix - SWITCH_STARTED_UNIX))
    if (( reconnect_secs >= 0 && reconnect_secs <= RECONNECT_SLO_SECS )); then
      CHECK_SESSION_RECONNECT_WITHIN_SLO="pass"
    fi
  fi

  if (( route_leak_samples == 0 )); then
    CHECK_NO_UNDERLAY_LEAK_DURING_TRANSITION="pass"
  fi
  if (( signed_state_invalid_samples == 0 )); then
    CHECK_SIGNED_STATE_VALID_DURING_TRANSITION="pass"
  fi

  client_plaintext_end="$(live_lab_no_plaintext_passphrase_check "$CLIENT_HOST" || true)"
  exit_plaintext_end="$(live_lab_no_plaintext_passphrase_check "$EXIT_HOST" || true)"
  if [[ "$client_plaintext_start" == 'no-plaintext-passphrase-files' && "$exit_plaintext_start" == 'no-plaintext-passphrase-files' && "$client_plaintext_end" == 'no-plaintext-passphrase-files' && "$exit_plaintext_end" == 'no-plaintext-passphrase-files' ]]; then
    CHECK_NO_PLAINTEXT_PASSPHRASE_FILES="pass"
  fi

  write_summary \
    "$reconnect_secs" \
    "$route_leak_samples" \
    "$signed_state_invalid_samples" \
    "$CHECK_ENDPOINT_CHANGE_DETECTED" \
    "$CHECK_TRAVERSAL_REISSUE_TRIGGERED" \
    "$CHECK_PEER_RECEIVED_UPDATED_ENDPOINT_HINT" \
    "$reconnect_unix"

  if [[ "$CHECK_DIRECT_REMOTE_EXIT_READY" == 'pass' && "$CHECK_ENDPOINT_CHANGE_DETECTED" == 'pass' && "$CHECK_TRAVERSAL_REISSUE_TRIGGERED" == 'pass' && "$CHECK_SESSION_RECONNECT_WITHIN_SLO" == 'pass' && "$CHECK_PEER_RECEIVED_UPDATED_ENDPOINT_HINT" == 'pass' && "$CHECK_NO_UNDERLAY_LEAK_DURING_TRANSITION" == 'pass' && "$CHECK_SIGNED_STATE_VALID_DURING_TRANSITION" == 'pass' && "$CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC" == 'pass' && "$CHECK_NO_PLAINTEXT_PASSPHRASE_FILES" == 'pass' ]]; then
    CHECK_NODE_NETWORK_SWITCH_SUCCESS="pass"
  fi

  if [[ "$CHECK_NODE_NETWORK_SWITCH_SUCCESS" != 'pass' ]]; then
    if [[ "$CHECK_ENDPOINT_CHANGE_DETECTED" != 'pass' ]]; then
      FAILURE_SUMMARY="endpoint-change detection did not trigger during node underlay switch"
    elif [[ "$CHECK_TRAVERSAL_REISSUE_TRIGGERED" != 'pass' ]]; then
      FAILURE_SUMMARY="traversal re-issue did not trigger during node underlay switch"
    elif [[ "$CHECK_PEER_RECEIVED_UPDATED_ENDPOINT_HINT" != 'pass' ]]; then
      FAILURE_SUMMARY="peer did not observe updated endpoint hint after node underlay switch"
    elif [[ "$CHECK_SESSION_RECONNECT_WITHIN_SLO" != 'pass' ]]; then
      FAILURE_SUMMARY="session reconvergence exceeded reconnect SLO (${RECONNECT_SLO_SECS}s), measured=${reconnect_secs}s"
    elif [[ "$CHECK_NO_UNDERLAY_LEAK_DURING_TRANSITION" != 'pass' ]]; then
      FAILURE_SUMMARY="underlay leak detected during node underlay switch transition"
    elif [[ "$CHECK_SIGNED_STATE_VALID_DURING_TRANSITION" != 'pass' ]]; then
      FAILURE_SUMMARY="signed state became invalid during node underlay switch transition"
    elif [[ "$CHECK_NO_PLAINTEXT_PASSPHRASE_FILES" != 'pass' ]]; then
      FAILURE_SUMMARY="plaintext passphrase files detected during node network-switch validation"
    else
      FAILURE_SUMMARY="node network-switch validation checks did not all pass"
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

live_lab_log "Cross-network node network-switch report written: $REPORT_PATH"
