#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

SSH_PASSWORD_FILE=""
SUDO_PASSWORD_FILE=""
CLIENT_HOST=""
EXIT_HOST=""
CLIENT_NETWORK_ID=""
EXIT_NETWORK_ID=""
REPORT_PATH="$ROOT_DIR/artifacts/phase10/cross_network_remote_exit_soak_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/cross_network_remote_exit_soak.log"

usage() {
  cat <<'USAGE'
usage: live_linux_cross_network_remote_exit_soak_test.sh --ssh-password-file <path> --sudo-password-file <path> --client-host <user@host> --exit-host <user@host> --client-network-id <id> --exit-network-id <id> [options]

options:
  --report-path <path>
  --log-path <path>
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-password-file) SSH_PASSWORD_FILE="$2"; shift 2 ;;
    --sudo-password-file) SUDO_PASSWORD_FILE="$2"; shift 2 ;;
    --client-host) CLIENT_HOST="$2"; shift 2 ;;
    --exit-host) EXIT_HOST="$2"; shift 2 ;;
    --client-network-id) CLIENT_NETWORK_ID="$2"; shift 2 ;;
    --exit-network-id) EXIT_NETWORK_ID="$2"; shift 2 ;;
    --report-path) REPORT_PATH="$2"; shift 2 ;;
    --log-path) LOG_PATH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$SSH_PASSWORD_FILE" || -z "$SUDO_PASSWORD_FILE" || -z "$CLIENT_HOST" || -z "$EXIT_HOST" || -z "$CLIENT_NETWORK_ID" || -z "$EXIT_NETWORK_ID" ]]; then
  usage >&2
  exit 2
fi

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")"
: > "$LOG_PATH"
exec >> "$LOG_PATH" 2>&1

echo "cross-network remote-exit soak validator is not implemented yet"

python3 "$ROOT_DIR/scripts/e2e/generate_cross_network_remote_exit_report.py" \
  --suite cross_network_remote_exit_soak \
  --report-path "$REPORT_PATH" \
  --log-path "$LOG_PATH" \
  --status fail \
  --failure-summary "cross-network remote-exit soak validator is not implemented yet" \
  --client-host "$CLIENT_HOST" \
  --exit-host "$EXIT_HOST" \
  --client-network-id "$CLIENT_NETWORK_ID" \
  --exit-network-id "$EXIT_NETWORK_ID"

exit 1
