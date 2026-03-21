#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/e2e/live_lab_common.sh"

LIVE_LAB_LOG_PREFIX="server-ip-bypass"
export LIVE_LAB_LOG_PREFIX

CLIENT_HOST=""
PROBE_HOST=""
PROBE_BIND_IP=""
SSH_IDENTITY_FILE=""
SSH_ALLOW_CIDRS="192.168.18.0/24"
PROBE_PORT="18080"
REPORT_PATH="$ROOT_DIR/artifacts/phase10/live_linux_server_ip_bypass_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/live_linux_server_ip_bypass.log"

usage() {
  cat <<'USAGE'
usage: live_linux_server_ip_bypass_test.sh --ssh-identity-file <path> --client-host <user@host> --probe-host <user@host> [options]

options:
  --client-host <user@host>
  --probe-host <user@host>         Existing mesh peer whose underlay IP will host the forbidden service probe.
  --probe-bind-ip <ipv4>           Explicit IPv4 to bind on probe host. Default: probe host underlay IP.
  --ssh-allow-cidrs <cidr[,cidr]>  Explicit management bypass CIDRs. Default: 192.168.18.0/24
  --probe-port <port>              Default: 18080
  --report-path <path>
  --log-path <path>
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-identity-file) SSH_IDENTITY_FILE="$2"; shift 2 ;;
    --client-host) CLIENT_HOST="$2"; shift 2 ;;
    --probe-host) PROBE_HOST="$2"; shift 2 ;;
    --probe-bind-ip) PROBE_BIND_IP="$2"; shift 2 ;;
    --ssh-allow-cidrs) SSH_ALLOW_CIDRS="$2"; shift 2 ;;
    --probe-port) PROBE_PORT="$2"; shift 2 ;;
    --report-path) REPORT_PATH="$2"; shift 2 ;;
    --log-path) LOG_PATH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$SSH_IDENTITY_FILE" || -z "$CLIENT_HOST" || -z "$PROBE_HOST" ]]; then
  usage >&2
  exit 2
fi

if [[ "$CLIENT_HOST" == "$PROBE_HOST" ]]; then
  echo "--client-host and --probe-host must differ" >&2
  exit 2
fi

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")"
: > "$LOG_PATH"
exec >> "$LOG_PATH" 2>&1

live_lab_init "rustynet-server-ip-bypass" "$SSH_IDENTITY_FILE"
trap 'live_lab_cleanup' EXIT

if [[ -n "$PROBE_BIND_IP" ]]; then
  cargo run --quiet -p rustynet-cli -- ops validate-ipv4-address --ip "$PROBE_BIND_IP" >/dev/null
  PROBE_IP="$PROBE_BIND_IP"
else
  PROBE_IP="$(live_lab_target_address "$PROBE_HOST")"
fi
PROBE_PID_PATH="/tmp/rn-underlay-http-server.pid"
PROBE_LOG_PATH="/tmp/rn-underlay-http-server.log"

cleanup_probe_server() {
  live_lab_run_root "$PROBE_HOST" "root test -f '$PROBE_PID_PATH' && root kill \"\$(cat '$PROBE_PID_PATH')\" >/dev/null 2>&1 || true; root rm -f '$PROBE_PID_PATH' '$PROBE_LOG_PATH'" >/dev/null 2>&1 || true
}
trap 'cleanup_probe_server; live_lab_cleanup' EXIT

live_lab_push_sudo_password "$CLIENT_HOST"
live_lab_push_sudo_password "$PROBE_HOST"
live_lab_wait_for_daemon_socket "$CLIENT_HOST"
live_lab_wait_for_daemon_socket "$PROBE_HOST"

live_lab_log "Starting underlay HTTP probe service on $PROBE_HOST ($PROBE_IP:$PROBE_PORT)"
live_lab_run_root "$PROBE_HOST" "root rm -f '$PROBE_PID_PATH' '$PROBE_LOG_PATH'; root nohup rustynet ops e2e-http-probe-server --bind-ip '$PROBE_IP' --port '$PROBE_PORT' --response-body 'probe-ok' >'$PROBE_LOG_PATH' 2>&1 </dev/null & echo \$! > '$PROBE_PID_PATH'"
live_lab_retry_root "$PROBE_HOST" "root rustynet ops e2e-http-probe-client --host '$PROBE_IP' --port '$PROBE_PORT' --timeout-ms 2000 --expect-marker probe-ok >/dev/null" 15 1

CLIENT_STATUS="$(live_lab_status "$CLIENT_HOST")"
CLIENT_INTERNET_ROUTE="$(live_lab_capture "$CLIENT_HOST" "ip -4 route get 1.1.1.1 || true")"
CLIENT_PROBE_ROUTE="$(live_lab_capture "$CLIENT_HOST" "ip -4 route get '$PROBE_IP' || true")"
CLIENT_TABLE_51820="$(live_lab_capture "$CLIENT_HOST" "ip -4 route show table 51820 || true")"
CLIENT_ENDPOINTS="$(live_lab_capture_root "$CLIENT_HOST" "root wg show rustynet0 endpoints || true")"
PROBE_SELF_TEST="$(live_lab_capture_root "$PROBE_HOST" "root rustynet ops e2e-http-probe-client --host '$PROBE_IP' --port '$PROBE_PORT' --timeout-ms 2000 --expect-marker probe-ok || true")"
PROBE_FROM_CLIENT_OUTPUT="$(live_lab_capture_root "$CLIENT_HOST" "root rustynet ops e2e-http-probe-client --host '$PROBE_IP' --port '$PROBE_PORT' --timeout-ms 2000 --expect-marker probe-ok || true")"

if live_lab_run_root "$CLIENT_HOST" "root rustynet ops e2e-http-probe-client --host '$PROBE_IP' --port '$PROBE_PORT' --timeout-ms 2000 --expect-marker probe-ok >/dev/null" >/dev/null 2>&1; then
  PROBE_FROM_CLIENT_STATUS="fail"
else
  PROBE_FROM_CLIENT_STATUS="pass"
fi

live_lab_log "Client route to internet"
printf '%s\n' "$CLIENT_INTERNET_ROUTE"
live_lab_log "Client route to probe host underlay IP"
printf '%s\n' "$CLIENT_PROBE_ROUTE"
live_lab_log "Client table 51820"
printf '%s\n' "$CLIENT_TABLE_51820"
live_lab_log "Client endpoints"
printf '%s\n' "$CLIENT_ENDPOINTS"
live_lab_log "Probe host self-test output"
printf '%s\n' "$PROBE_SELF_TEST"
live_lab_log "Client probe output"
printf '%s\n' "$PROBE_FROM_CLIENT_OUTPUT"

captured_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
captured_at_unix="$(date -u +%s)"

report_status="$(
  cargo run --quiet -p rustynet-cli -- ops write-live-linux-server-ip-bypass-report \
    --report-path "$REPORT_PATH" \
    --allowed-management-cidrs "$SSH_ALLOW_CIDRS" \
    --probe-from-client-status "$PROBE_FROM_CLIENT_STATUS" \
    --probe-ip "$PROBE_IP" \
    --probe-port "$PROBE_PORT" \
    --client-internet-route "$CLIENT_INTERNET_ROUTE" \
    --client-probe-route "$CLIENT_PROBE_ROUTE" \
    --client-table-51820 "$CLIENT_TABLE_51820" \
    --client-endpoints "$CLIENT_ENDPOINTS" \
    --probe-self-test "$PROBE_SELF_TEST" \
    --probe-from-client-output "$PROBE_FROM_CLIENT_OUTPUT" \
    --captured-at-utc "$captured_at_utc" \
    --captured-at-unix "$captured_at_unix"
)"

if [[ "$report_status" != "pass" ]]; then
  echo "server-IP bypass test failed; see ${REPORT_PATH}" >&2
  exit 1
fi

live_lab_log "Server-IP bypass report written: $REPORT_PATH"
