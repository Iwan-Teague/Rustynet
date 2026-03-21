#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/e2e/live_lab_common.sh"

LIVE_LAB_LOG_PREFIX="endpoint-hijack"
export LIVE_LAB_LOG_PREFIX

CLIENT_HOST=""
ROGUE_ENDPOINT_IP=""
SSH_IDENTITY_FILE=""
SOCKET_PATH="/run/rustynet/rustynetd.sock"
ASSIGNMENT_PATH="/var/lib/rustynet/rustynetd.assignment"
ASSIGNMENT_WATERMARK_PATH="/var/lib/rustynet/rustynetd.assignment.watermark"
REPORT_PATH="$ROOT_DIR/artifacts/phase10/live_linux_endpoint_hijack_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/live_linux_endpoint_hijack.log"

usage() {
  cat <<'USAGE'
usage: live_linux_endpoint_hijack_test.sh --ssh-identity-file <path> --client-host <user@host> --rogue-endpoint-ip <ipv4> [options]

options:
  --client-host <user@host>
  --rogue-endpoint-ip <ipv4>
  --socket-path <path>
  --assignment-path <path>
  --report-path <path>
  --log-path <path>
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-identity-file) SSH_IDENTITY_FILE="$2"; shift 2 ;;
    --client-host) CLIENT_HOST="$2"; shift 2 ;;
    --rogue-endpoint-ip) ROGUE_ENDPOINT_IP="$2"; shift 2 ;;
    --socket-path) SOCKET_PATH="$2"; shift 2 ;;
    --assignment-path) ASSIGNMENT_PATH="$2"; shift 2 ;;
    --report-path) REPORT_PATH="$2"; shift 2 ;;
    --log-path) LOG_PATH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$SSH_IDENTITY_FILE" || -z "$CLIENT_HOST" || -z "$ROGUE_ENDPOINT_IP" ]]; then
  usage >&2
  exit 2
fi

cargo run --quiet -p rustynet-cli -- ops validate-ipv4-address --ip "$ROGUE_ENDPOINT_IP" >/dev/null

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")"
: > "$LOG_PATH"
exec >> "$LOG_PATH" 2>&1

live_lab_init "rustynet-endpoint-hijack" "$SSH_IDENTITY_FILE"

BACKUP_PATH=""
ASSIGNMENT_TIMER_WAS_ACTIVE=0
cleanup_endpoint_hijack() {
  if [[ -n "$BACKUP_PATH" ]]; then
    live_lab_run_root "$CLIENT_HOST" "root test -f '$BACKUP_PATH' && root cp '$BACKUP_PATH' '$ASSIGNMENT_PATH' || true; root rm -f '$BACKUP_PATH' '$ASSIGNMENT_WATERMARK_PATH'" >/dev/null 2>&1 || true
    live_lab_run_root "$CLIENT_HOST" "root systemctl restart rustynetd.service" >/dev/null 2>&1 || true
    if [[ "$ASSIGNMENT_TIMER_WAS_ACTIVE" -eq 1 ]]; then
      live_lab_run_root "$CLIENT_HOST" "root systemctl start rustynetd-assignment-refresh.timer" >/dev/null 2>&1 || true
    fi
  fi
  live_lab_cleanup
}
trap 'cleanup_endpoint_hijack' EXIT

live_lab_push_sudo_password "$CLIENT_HOST"
live_lab_wait_for_daemon_socket "$CLIENT_HOST"

BASELINE_STATUS_OUTPUT="$(live_lab_capture_root "$CLIENT_HOST" "root env RUSTYNET_DAEMON_SOCKET='${SOCKET_PATH}' rustynet status || true")"
BASELINE_NETCHECK_OUTPUT="$(live_lab_capture_root "$CLIENT_HOST" "root env RUSTYNET_DAEMON_SOCKET='${SOCKET_PATH}' rustynet netcheck || true")"
BASELINE_ENDPOINTS="$(live_lab_capture_root "$CLIENT_HOST" "root wg show rustynet0 endpoints || true")"

if [[ "$BASELINE_STATUS_OUTPUT" == *"state=FailClosed"* ]]; then
  echo "baseline runtime is already fail-closed; refusing endpoint hijack test" >&2
  exit 1
fi

timer_state="$(live_lab_capture_root "$CLIENT_HOST" "root systemctl is-active rustynetd-assignment-refresh.timer || true")"
if [[ "$timer_state" == *"active"* ]]; then
  ASSIGNMENT_TIMER_WAS_ACTIVE=1
fi
live_lab_run_root "$CLIENT_HOST" "root systemctl stop rustynetd-assignment-refresh.timer >/dev/null 2>&1 || true; root systemctl stop rustynetd-assignment-refresh.service >/dev/null 2>&1 || true"

BACKUP_PATH="/var/lib/rustynet/rustynetd.assignment.endpoint-hijack.$(date +%s).bak"
live_lab_run_root "$CLIENT_HOST" "root cp '$ASSIGNMENT_PATH' '$BACKUP_PATH'"
live_lab_run_root "$CLIENT_HOST" "root rustynet ops rewrite-assignment-peer-endpoint-ip --assignment-path '$ASSIGNMENT_PATH' --endpoint-ip '$ROGUE_ENDPOINT_IP'"
live_lab_run_root "$CLIENT_HOST" "root rm -f '$ASSIGNMENT_WATERMARK_PATH'; root systemctl restart rustynetd.service"
sleep 3
live_lab_wait_for_daemon_socket "$CLIENT_HOST" "$SOCKET_PATH" 20 1

STATUS_AFTER_HIJACK="$(live_lab_capture_root "$CLIENT_HOST" "root env RUSTYNET_DAEMON_SOCKET='${SOCKET_PATH}' rustynet status || true")"
NETCHECK_AFTER_HIJACK="$(live_lab_capture_root "$CLIENT_HOST" "root env RUSTYNET_DAEMON_SOCKET='${SOCKET_PATH}' rustynet netcheck || true")"
ENDPOINTS_AFTER_HIJACK="$(live_lab_capture_root "$CLIENT_HOST" "root wg show rustynet0 endpoints || true")"

live_lab_run_root "$CLIENT_HOST" "root cp '$BACKUP_PATH' '$ASSIGNMENT_PATH'; root rm -f '$BACKUP_PATH' '$ASSIGNMENT_WATERMARK_PATH'; root systemctl restart rustynetd.service"
BACKUP_PATH=""
sleep 3
live_lab_wait_for_daemon_socket "$CLIENT_HOST" "$SOCKET_PATH" 20 1
if [[ "$ASSIGNMENT_TIMER_WAS_ACTIVE" -eq 1 ]]; then
  live_lab_run_root "$CLIENT_HOST" "root systemctl start rustynetd-assignment-refresh.timer"
fi

STATUS_AFTER_RECOVERY="$(live_lab_capture_root "$CLIENT_HOST" "root env RUSTYNET_DAEMON_SOCKET='${SOCKET_PATH}' rustynet status || true")"
ENDPOINTS_AFTER_RECOVERY="$(live_lab_capture_root "$CLIENT_HOST" "root wg show rustynet0 endpoints || true")"

captured_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
captured_at_unix="$(date -u +%s)"
report_status="$(
  cargo run --quiet -p rustynet-cli -- ops write-live-linux-endpoint-hijack-report \
    --report-path "$REPORT_PATH" \
    --rogue-endpoint-ip "$ROGUE_ENDPOINT_IP" \
    --baseline-status "$BASELINE_STATUS_OUTPUT" \
    --baseline-netcheck "$BASELINE_NETCHECK_OUTPUT" \
    --baseline-endpoints "$BASELINE_ENDPOINTS" \
    --status-after-hijack "$STATUS_AFTER_HIJACK" \
    --netcheck-after-hijack "$NETCHECK_AFTER_HIJACK" \
    --endpoints-after-hijack "$ENDPOINTS_AFTER_HIJACK" \
    --status-after-recovery "$STATUS_AFTER_RECOVERY" \
    --endpoints-after-recovery "$ENDPOINTS_AFTER_RECOVERY" \
    --captured-at-utc "$captured_at_utc" \
    --captured-at-unix "$captured_at_unix"
)"

if [[ "$report_status" != "pass" ]]; then
  echo "endpoint hijack test failed; see ${REPORT_PATH}" >&2
  exit 1
fi

live_lab_log "Endpoint hijack report written: $REPORT_PATH"
