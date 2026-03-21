#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/e2e/live_lab_common.sh"

LIVE_LAB_LOG_PREFIX="control-surface"
export LIVE_LAB_LOG_PREFIX

EXIT_HOST=""
CLIENT_HOST=""
ENTRY_HOST=""
AUX_HOST=""
EXTRA_HOST=""
PROBE_HOST=""
SSH_IDENTITY_FILE=""
DNS_BIND_ADDR="127.0.0.1:53535"
REPORT_PATH="$ROOT_DIR/artifacts/phase10/live_linux_control_surface_exposure_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/live_linux_control_surface_exposure.log"

declare -a HOST_LABELS=()
declare -a HOST_TARGETS=()

usage() {
  cat <<'USAGE'
usage: live_linux_control_surface_exposure_test.sh --ssh-identity-file <path> --client-host <user@host> [options]

options:
  --exit-host <user@host>
  --client-host <user@host>
  --entry-host <user@host>
  --aux-host <user@host>
  --extra-host <user@host>
  --probe-host <user@host>          Host used to probe the client's DNS bind over underlay when managed DNS is active.
  --dns-bind-addr <ip:port>         Expected managed DNS bind address. Default: 127.0.0.1:53535
  --report-path <path>
  --log-path <path>
USAGE
}

append_host() {
  local label="$1"
  local target="$2"
  if [[ -n "$target" ]]; then
    HOST_LABELS+=("$label")
    HOST_TARGETS+=("$target")
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-identity-file) SSH_IDENTITY_FILE="$2"; shift 2 ;;
    --exit-host) EXIT_HOST="$2"; shift 2 ;;
    --client-host) CLIENT_HOST="$2"; shift 2 ;;
    --entry-host) ENTRY_HOST="$2"; shift 2 ;;
    --aux-host) AUX_HOST="$2"; shift 2 ;;
    --extra-host) EXTRA_HOST="$2"; shift 2 ;;
    --probe-host) PROBE_HOST="$2"; shift 2 ;;
    --dns-bind-addr) DNS_BIND_ADDR="$2"; shift 2 ;;
    --report-path) REPORT_PATH="$2"; shift 2 ;;
    --log-path) LOG_PATH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$SSH_IDENTITY_FILE" || -z "$CLIENT_HOST" ]]; then
  usage >&2
  exit 2
fi

append_host "exit" "$EXIT_HOST"
append_host "client" "$CLIENT_HOST"
append_host "entry" "$ENTRY_HOST"
append_host "aux" "$AUX_HOST"
append_host "extra" "$EXTRA_HOST"

if [[ "${#HOST_TARGETS[@]}" -eq 0 ]]; then
  echo "at least one target host is required" >&2
  exit 2
fi

if [[ -z "$PROBE_HOST" ]]; then
  if [[ -n "$EXIT_HOST" && "$EXIT_HOST" != "$CLIENT_HOST" ]]; then
    PROBE_HOST="$EXIT_HOST"
  elif [[ -n "$ENTRY_HOST" && "$ENTRY_HOST" != "$CLIENT_HOST" ]]; then
    PROBE_HOST="$ENTRY_HOST"
  elif [[ -n "$AUX_HOST" && "$AUX_HOST" != "$CLIENT_HOST" ]]; then
    PROBE_HOST="$AUX_HOST"
  elif [[ -n "$EXTRA_HOST" && "$EXTRA_HOST" != "$CLIENT_HOST" ]]; then
    PROBE_HOST="$EXTRA_HOST"
  fi
fi

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")"
: > "$LOG_PATH"
exec >> "$LOG_PATH" 2>&1

live_lab_init "rustynet-control-surface" "$SSH_IDENTITY_FILE"
trap 'live_lab_cleanup' EXIT

for target in "${HOST_TARGETS[@]}"; do
  live_lab_push_sudo_password "$target"
  live_lab_wait_for_daemon_socket "$target"
done

for idx in "${!HOST_TARGETS[@]}"; do
  label="${HOST_LABELS[$idx]}"
  target="${HOST_TARGETS[$idx]}"
  daemon_socket_meta="$LIVE_LAB_WORK_DIR/${label}.daemon_socket.txt"
  helper_socket_meta="$LIVE_LAB_WORK_DIR/${label}.helper_socket.txt"
  inet_listeners="$LIVE_LAB_WORK_DIR/${label}.inet_listeners.txt"
  dns_service_state="$LIVE_LAB_WORK_DIR/${label}.managed_dns_state.txt"

  live_lab_log "Inspecting control surfaces on ${label} ${target}"
  live_lab_capture_root "$target" "root stat -Lc '%F|%a|%U|%G' /run/rustynet/rustynetd.sock" > "$daemon_socket_meta"
  live_lab_capture_root "$target" "root stat -Lc '%F|%a|%U|%G' /run/rustynet/rustynetd-privileged.sock" > "$helper_socket_meta"
  live_lab_capture_root "$target" "root ss -H -ltnup || true" > "$inet_listeners"
  live_lab_capture_root "$target" "root systemctl is-active rustynetd-managed-dns.service || true" > "$dns_service_state"
done

REMOTE_DNS_PROBE_STATUS="skip"
REMOTE_DNS_PROBE_OUTPUT="not-applicable"
client_dns_state_file="$LIVE_LAB_WORK_DIR/client.managed_dns_state.txt"
if [[ -n "$PROBE_HOST" && "$PROBE_HOST" != "$CLIENT_HOST" && -f "$client_dns_state_file" ]] && grep -Fqx 'active' "$client_dns_state_file"; then
  DNS_SERVER="${DNS_BIND_ADDR%:*}"
  DNS_PORT="${DNS_BIND_ADDR##*:}"
  CLIENT_ADDR="$(live_lab_target_address "$CLIENT_HOST")"
  if REMOTE_DNS_PROBE_OUTPUT="$(live_lab_capture_root "$PROBE_HOST" "root rustynet ops e2e-dns-query --server '${CLIENT_ADDR}' --port '${DNS_PORT}' --qname blocked-probe.rustynet --timeout-ms 1000 || true")"; then
    :
  fi
  if live_lab_run_root "$PROBE_HOST" "root rustynet ops e2e-dns-query --server '${CLIENT_ADDR}' --port '${DNS_PORT}' --qname blocked-probe.rustynet --timeout-ms 1000 --fail-on-no-response" >/dev/null 2>&1; then
    REMOTE_DNS_PROBE_STATUS="fail"
  else
    REMOTE_DNS_PROBE_STATUS="pass"
  fi
fi

captured_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
captured_at_unix="$(date -u +%s)"
host_label_args=()
for host_label in "${HOST_LABELS[@]}"; do
  host_label_args+=(--host-label "$host_label")
done
report_status="$(
  cargo run --quiet -p rustynet-cli -- ops write-live-linux-control-surface-report \
    --report-path "$REPORT_PATH" \
    --dns-bind-addr "$DNS_BIND_ADDR" \
    --remote-dns-probe-status "$REMOTE_DNS_PROBE_STATUS" \
    --remote-dns-probe-output "$REMOTE_DNS_PROBE_OUTPUT" \
    --work-dir "$LIVE_LAB_WORK_DIR" \
    "${host_label_args[@]}" \
    --captured-at-utc "$captured_at_utc" \
    --captured-at-unix "$captured_at_unix"
)"

if [[ "$report_status" != "pass" ]]; then
  echo "control-surface exposure test failed; see ${REPORT_PATH}" >&2
  exit 1
fi

live_lab_log "Control-surface exposure report written: $REPORT_PATH"
