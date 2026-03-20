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

python3 - "$ROGUE_ENDPOINT_IP" <<'PY'
import ipaddress
import sys
ipaddress.IPv4Address(sys.argv[1])
PY

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
live_lab_run_root "$CLIENT_HOST" "root python3 - '$ASSIGNMENT_PATH' '$ROGUE_ENDPOINT_IP' <<'PY'\nimport pathlib\nimport re\nimport sys\n\nassignment_path = pathlib.Path(sys.argv[1])\nrogue_ip = sys.argv[2]\npattern = re.compile(r'^(peer\\.\\d+\\.endpoint=)([^:\\s]+):(\\d+)\\s*$')\nlines = assignment_path.read_text(encoding='utf-8').splitlines()\nupdated = []\nreplaced = 0\nfor line in lines:\n    match = pattern.match(line)\n    if match:\n        line = f\"{match.group(1)}{rogue_ip}:{match.group(3)}\"\n        replaced += 1\n    updated.append(line)\nif replaced == 0:\n    raise SystemExit('failed to locate peer endpoint fields in assignment bundle')\nassignment_path.write_text('\\n'.join(updated) + '\\n', encoding='utf-8')\nPY"
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

python3 - "$REPORT_PATH" "$ROGUE_ENDPOINT_IP" "$BASELINE_STATUS_OUTPUT" "$BASELINE_NETCHECK_OUTPUT" "$BASELINE_ENDPOINTS" "$STATUS_AFTER_HIJACK" "$NETCHECK_AFTER_HIJACK" "$ENDPOINTS_AFTER_HIJACK" "$STATUS_AFTER_RECOVERY" "$ENDPOINTS_AFTER_RECOVERY" <<'PY'
import json
import sys
from datetime import datetime, timezone

(
    report_path,
    rogue_ip,
    baseline_status,
    baseline_netcheck,
    baseline_endpoints,
    status_after_hijack,
    netcheck_after_hijack,
    endpoints_after_hijack,
    status_after_recovery,
    endpoints_after_recovery,
) = sys.argv[1:]

checks = {
    "baseline_runtime_secure": "pass" if "state=FailClosed" not in baseline_status else "fail",
    "hijack_drives_fail_closed": "pass" if "state=FailClosed" in status_after_hijack else "fail",
    "restricted_safe_mode_engaged": "pass" if "restricted_safe_mode=true" in status_after_hijack else "fail",
    "netcheck_reports_fail_closed": "pass" if "path_mode=fail_closed" in netcheck_after_hijack else "fail",
    "rogue_endpoint_not_adopted": "pass" if rogue_ip not in endpoints_after_hijack else "fail",
    "recovery_restores_secure_runtime": "pass" if "state=FailClosed" not in status_after_recovery and "restricted_safe_mode=false" in status_after_recovery else "fail",
    "recovery_keeps_rogue_endpoint_rejected": "pass" if rogue_ip not in endpoints_after_recovery else "fail",
}

overall = "pass"
for value in checks.values():
    if value != "pass":
        overall = "fail"
        break

captured_at = datetime.now(timezone.utc)
payload = {
    "phase": "phase10",
    "mode": "live_linux_endpoint_hijack",
    "evidence_mode": "measured",
    "captured_at": captured_at.isoformat(),
    "captured_at_unix": int(captured_at.timestamp()),
    "status": overall,
    "rogue_endpoint_ip": rogue_ip,
    "checks": checks,
    "evidence": {
        "baseline_status": baseline_status,
        "baseline_netcheck": baseline_netcheck,
        "baseline_endpoints": baseline_endpoints,
        "status_after_hijack": status_after_hijack,
        "netcheck_after_hijack": netcheck_after_hijack,
        "endpoints_after_hijack": endpoints_after_hijack,
        "status_after_recovery": status_after_recovery,
        "endpoints_after_recovery": endpoints_after_recovery,
    },
}

with open(report_path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2)
    fh.write("\n")
PY

if [[ "$(python3 - "$REPORT_PATH" <<'PY'
import json, sys
print(json.loads(open(sys.argv[1], encoding="utf-8").read())["status"])
PY
)" != "pass" ]]; then
  echo "endpoint hijack test failed; see ${REPORT_PATH}" >&2
  exit 1
fi

live_lab_log "Endpoint hijack report written: $REPORT_PATH"
