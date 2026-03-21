#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

REPORT_PATH="artifacts/phase10/rogue_path_hijack_e2e_report.json"
SOCKET_PATH="/run/rustynet/rustynetd.sock"
ASSIGNMENT_PATH="/var/lib/rustynet/rustynetd.assignment"
ASSIGNMENT_WATERMARK_PATH="/var/lib/rustynet/rustynetd.assignment.watermark"
SSH_PORT="22"
SSH_USER="root"
SSH_IDENTITY=""
SSH_SUDO_MODE="auto"
SSH_KNOWN_HOSTS_FILE="${SSH_KNOWN_HOSTS_FILE:-}"
EXIT_HOST=""
CLIENT_HOST=""
ROGUE_ENDPOINT_IP=""

FORWARD_ARGS=()

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --hijack-report-path)
      [[ "$#" -ge 2 ]] || { echo "missing value for --hijack-report-path" >&2; exit 2; }
      REPORT_PATH="$2"
      shift 2
      ;;
    --rogue-endpoint-ip)
      [[ "$#" -ge 2 ]] || { echo "missing value for --rogue-endpoint-ip" >&2; exit 2; }
      ROGUE_ENDPOINT_IP="$2"
      shift 2
      ;;
    --exit-host)
      [[ "$#" -ge 2 ]] || { echo "missing value for --exit-host" >&2; exit 2; }
      EXIT_HOST="$2"
      FORWARD_ARGS+=("$1" "$2")
      shift 2
      ;;
    --client-host)
      [[ "$#" -ge 2 ]] || { echo "missing value for --client-host" >&2; exit 2; }
      CLIENT_HOST="$2"
      FORWARD_ARGS+=("$1" "$2")
      shift 2
      ;;
    --ssh-user)
      [[ "$#" -ge 2 ]] || { echo "missing value for --ssh-user" >&2; exit 2; }
      SSH_USER="$2"
      FORWARD_ARGS+=("$1" "$2")
      shift 2
      ;;
    --ssh-port)
      [[ "$#" -ge 2 ]] || { echo "missing value for --ssh-port" >&2; exit 2; }
      SSH_PORT="$2"
      FORWARD_ARGS+=("$1" "$2")
      shift 2
      ;;
    --ssh-identity)
      [[ "$#" -ge 2 ]] || { echo "missing value for --ssh-identity" >&2; exit 2; }
      SSH_IDENTITY="$2"
      FORWARD_ARGS+=("$1" "$2")
      shift 2
      ;;
    --ssh-sudo)
      [[ "$#" -ge 2 ]] || { echo "missing value for --ssh-sudo" >&2; exit 2; }
      SSH_SUDO_MODE="$2"
      FORWARD_ARGS+=("$1" "$2")
      shift 2
      ;;
    --ssh-known-hosts-file)
      [[ "$#" -ge 2 ]] || { echo "missing value for --ssh-known-hosts-file" >&2; exit 2; }
      SSH_KNOWN_HOSTS_FILE="$2"
      FORWARD_ARGS+=("$1" "$2")
      shift 2
      ;;
    *)
      FORWARD_ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ -z "${EXIT_HOST}" || -z "${CLIENT_HOST}" ]]; then
  echo "--exit-host and --client-host are required" >&2
  exit 2
fi

if [[ -z "${ROGUE_ENDPOINT_IP}" ]]; then
  echo "--rogue-endpoint-ip is required" >&2
  exit 2
fi

if [[ ! "${SSH_PORT}" =~ ^[0-9]+$ ]]; then
  echo "--ssh-port must be numeric" >&2
  exit 2
fi

if [[ -n "${SSH_IDENTITY}" && ! -f "${SSH_IDENTITY}" ]]; then
  echo "--ssh-identity does not exist: ${SSH_IDENTITY}" >&2
  exit 2
fi

case "${SSH_SUDO_MODE}" in
  auto|always|never) ;;
  *)
    echo "--ssh-sudo must be one of: auto|always|never" >&2
    exit 2
    ;;
esac

if [[ -z "${SSH_KNOWN_HOSTS_FILE}" && -f "${HOME}/.ssh/known_hosts" ]]; then
  SSH_KNOWN_HOSTS_FILE="${HOME}/.ssh/known_hosts"
fi
if [[ -z "${SSH_KNOWN_HOSTS_FILE}" ]]; then
  echo "--ssh-known-hosts-file is required (or pre-populate ~/.ssh/known_hosts)" >&2
  exit 2
fi
if [[ ! -f "${SSH_KNOWN_HOSTS_FILE}" ]]; then
  echo "missing pinned SSH known_hosts file: ${SSH_KNOWN_HOSTS_FILE}" >&2
  exit 2
fi
if [[ -L "${SSH_KNOWN_HOSTS_FILE}" ]]; then
  echo "pinned SSH known_hosts file must not be a symlink: ${SSH_KNOWN_HOSTS_FILE}" >&2
  exit 2
fi
cargo run --quiet -p rustynet-cli -- ops check-local-file-mode \
  --path "${SSH_KNOWN_HOSTS_FILE}" \
  --policy no-group-world-write \
  --label "pinned SSH known_hosts file" >/dev/null

cargo run --quiet -p rustynet-cli -- ops validate-ipv4-address \
  --ip "${ROGUE_ENDPOINT_IP}" >/dev/null

for cmd in ssh ssh-keygen cargo; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "missing required command: ${cmd}" >&2
    exit 1
  fi
done

for host in "${EXIT_HOST}" "${CLIENT_HOST}"; do
  if ! ssh-keygen -F "${host}" -f "${SSH_KNOWN_HOSTS_FILE}" >/dev/null 2>&1; then
    echo "pinned SSH known_hosts file lacks host key for ${host}: ${SSH_KNOWN_HOSTS_FILE}" >&2
    exit 2
  fi
done

mkdir -p "$(dirname "${REPORT_PATH}")"

SSH_BASE=(
  ssh
  -o BatchMode=yes
  -o StrictHostKeyChecking=yes
  -o "UserKnownHostsFile=${SSH_KNOWN_HOSTS_FILE}"
  -o ConnectTimeout=15
  -p "${SSH_PORT}"
)
if [[ -n "${SSH_IDENTITY}" ]]; then
  SSH_BASE+=(-i "${SSH_IDENTITY}")
fi

EXIT_TARGET="${SSH_USER}@${EXIT_HOST}"
CLIENT_TARGET="${SSH_USER}@${CLIENT_HOST}"

needs_sudo() {
  case "${SSH_SUDO_MODE}" in
    never) return 1 ;;
    always) return 0 ;;
    auto)
      [[ "${SSH_USER}" != "root" ]]
      return
      ;;
    *)
      return 1
      ;;
  esac
}

remote_exec() {
  local target="$1"
  shift
  "${SSH_BASE[@]}" "${target}" "$@"
}

remote_exec_root() {
  local target="$1"
  shift
  if needs_sudo; then
    remote_exec "${target}" sudo -n -- "$@"
  else
    remote_exec "${target}" "$@"
  fi
}

capture_remote_root() {
  local target="$1"
  shift
  local output
  if output="$(remote_exec_root "${target}" "$@" 2>&1)"; then
    printf '%s' "${output}"
    return 0
  fi
  printf '%s' "${output}"
  return 1
}

if needs_sudo; then
  if ! remote_exec "${CLIENT_TARGET}" sudo -n true >/dev/null 2>&1; then
    echo "passwordless sudo is required for post-bootstrap hijack operations on ${CLIENT_TARGET}" >&2
    exit 1
  fi
fi

BASELINE_STATUS="fail"
HIJACK_REJECT_STATUS="fail"
FAIL_CLOSED_STATUS="fail"
NETCHECK_FAIL_CLOSED_STATUS="fail"
NO_ROGUE_ENDPOINT_STATUS="fail"
RECOVERY_STATUS="fail"
RECOVERY_ENDPOINT_STATUS="fail"

STATUS_AFTER_HIJACK=""
NETCHECK_AFTER_HIJACK=""
WG_ENDPOINTS_BEFORE=""
WG_ENDPOINTS_AFTER_HIJACK=""
WG_ENDPOINTS_AFTER_RECOVERY=""
STATUS_AFTER_RECOVERY=""
BACKUP_PATH=""
ASSIGNMENT_TIMER_WAS_ACTIVE=0

cleanup() {
  set +e
  if [[ -n "${BACKUP_PATH}" ]]; then
    remote_exec_root "${CLIENT_TARGET}" test -f "${BACKUP_PATH}" &&
      remote_exec_root "${CLIENT_TARGET}" cp "${BACKUP_PATH}" "${ASSIGNMENT_PATH}"
    remote_exec_root "${CLIENT_TARGET}" rm -f "${BACKUP_PATH}" "${ASSIGNMENT_WATERMARK_PATH}"
    remote_exec_root "${CLIENT_TARGET}" systemctl restart rustynetd >/dev/null 2>&1 || true
    if [[ "${ASSIGNMENT_TIMER_WAS_ACTIVE}" -eq 1 ]]; then
      remote_exec_root "${CLIENT_TARGET}" systemctl start rustynetd-assignment-refresh.timer >/dev/null 2>&1 || true
    fi
  fi
}
trap cleanup EXIT

cargo run --quiet -p rustynet-cli -- ops run-debian-two-node-e2e "${FORWARD_ARGS[@]}"
BASELINE_STATUS="pass"

timer_state="$(capture_remote_root "${CLIENT_TARGET}" systemctl is-active rustynetd-assignment-refresh.timer || true)"
if [[ "${timer_state}" == *"active"* ]]; then
  ASSIGNMENT_TIMER_WAS_ACTIVE=1
fi
remote_exec_root "${CLIENT_TARGET}" systemctl stop rustynetd-assignment-refresh.timer >/dev/null 2>&1 || true
remote_exec_root "${CLIENT_TARGET}" systemctl stop rustynetd-assignment-refresh.service >/dev/null 2>&1 || true

WG_ENDPOINTS_BEFORE="$(capture_remote_root "${CLIENT_TARGET}" wg show rustynet0 endpoints || true)"

BACKUP_PATH="/var/lib/rustynet/rustynetd.assignment.securitytest.$(date +%s).bak"
remote_exec_root "${CLIENT_TARGET}" cp "${ASSIGNMENT_PATH}" "${BACKUP_PATH}"

remote_exec_root "${CLIENT_TARGET}" \
  rustynet ops rewrite-assignment-peer-endpoint-ip \
  --assignment-path "${ASSIGNMENT_PATH}" \
  --endpoint-ip "${ROGUE_ENDPOINT_IP}"

remote_exec_root "${CLIENT_TARGET}" rm -f "${ASSIGNMENT_WATERMARK_PATH}"
remote_exec_root "${CLIENT_TARGET}" systemctl restart rustynetd
sleep 3

STATUS_AFTER_HIJACK="$(capture_remote_root "${CLIENT_TARGET}" env "RUSTYNET_DAEMON_SOCKET=${SOCKET_PATH}" rustynet status || true)"
NETCHECK_AFTER_HIJACK="$(capture_remote_root "${CLIENT_TARGET}" env "RUSTYNET_DAEMON_SOCKET=${SOCKET_PATH}" rustynet netcheck || true)"
WG_ENDPOINTS_AFTER_HIJACK="$(capture_remote_root "${CLIENT_TARGET}" wg show rustynet0 endpoints || true)"

if [[ "${STATUS_AFTER_HIJACK}" == *"state=FailClosed"* ]]; then
  HIJACK_REJECT_STATUS="pass"
fi

if [[ "${STATUS_AFTER_HIJACK}" == *"restricted_safe_mode=true"* ]]; then
  FAIL_CLOSED_STATUS="pass"
fi

if [[ "${NETCHECK_AFTER_HIJACK}" == *"path_mode=fail_closed"* ]]; then
  NETCHECK_FAIL_CLOSED_STATUS="pass"
fi

if [[ "${WG_ENDPOINTS_AFTER_HIJACK}" != *"${ROGUE_ENDPOINT_IP}"* ]]; then
  NO_ROGUE_ENDPOINT_STATUS="pass"
fi

remote_exec_root "${CLIENT_TARGET}" cp "${BACKUP_PATH}" "${ASSIGNMENT_PATH}"
remote_exec_root "${CLIENT_TARGET}" rm -f "${ASSIGNMENT_WATERMARK_PATH}" "${BACKUP_PATH}"
BACKUP_PATH=""
remote_exec_root "${CLIENT_TARGET}" systemctl restart rustynetd
sleep 3

if [[ "${ASSIGNMENT_TIMER_WAS_ACTIVE}" -eq 1 ]]; then
  remote_exec_root "${CLIENT_TARGET}" systemctl start rustynetd-assignment-refresh.timer
fi

STATUS_AFTER_RECOVERY="$(capture_remote_root "${CLIENT_TARGET}" env "RUSTYNET_DAEMON_SOCKET=${SOCKET_PATH}" rustynet status || true)"
WG_ENDPOINTS_AFTER_RECOVERY="$(capture_remote_root "${CLIENT_TARGET}" wg show rustynet0 endpoints || true)"

if [[ "${STATUS_AFTER_RECOVERY}" == *"restricted_safe_mode=false"* && "${STATUS_AFTER_RECOVERY}" != *"state=FailClosed"* ]]; then
  RECOVERY_STATUS="pass"
fi

if [[ "${WG_ENDPOINTS_AFTER_RECOVERY}" != *"${ROGUE_ENDPOINT_IP}"* ]]; then
  RECOVERY_ENDPOINT_STATUS="pass"
fi

captured_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
captured_at_unix="$(date -u +%s)"
OVERALL_STATUS="$(
  cargo run --quiet -p rustynet-cli -- ops write-active-network-rogue-path-hijack-report \
    --report-path "${REPORT_PATH}" \
    --baseline-status "${BASELINE_STATUS}" \
    --hijack-reject-status "${HIJACK_REJECT_STATUS}" \
    --fail-closed-status "${FAIL_CLOSED_STATUS}" \
    --netcheck-fail-closed-status "${NETCHECK_FAIL_CLOSED_STATUS}" \
    --no-rogue-endpoint-status "${NO_ROGUE_ENDPOINT_STATUS}" \
    --recovery-status "${RECOVERY_STATUS}" \
    --recovery-endpoint-status "${RECOVERY_ENDPOINT_STATUS}" \
    --rogue-endpoint-ip "${ROGUE_ENDPOINT_IP}" \
    --exit-host "${EXIT_HOST}" \
    --client-host "${CLIENT_HOST}" \
    --endpoints-before "${WG_ENDPOINTS_BEFORE}" \
    --endpoints-after-hijack "${WG_ENDPOINTS_AFTER_HIJACK}" \
    --endpoints-after-recovery "${WG_ENDPOINTS_AFTER_RECOVERY}" \
    --status-after-hijack "${STATUS_AFTER_HIJACK}" \
    --netcheck-after-hijack "${NETCHECK_AFTER_HIJACK}" \
    --status-after-recovery "${STATUS_AFTER_RECOVERY}" \
    --captured-at-utc "${captured_at_utc}" \
    --captured-at-unix "${captured_at_unix}"
)"

if [[ "${OVERALL_STATUS}" != "pass" ]]; then
  echo "rogue-path hijack e2e failed; see ${REPORT_PATH}" >&2
  exit 1
fi

echo "Rogue-path hijack e2e report written to ${REPORT_PATH}"
