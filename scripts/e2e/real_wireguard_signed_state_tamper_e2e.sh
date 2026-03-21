#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

REPORT_PATH="artifacts/phase10/signed_state_tamper_e2e_report.json"
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

FORWARD_ARGS=()

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --tamper-report-path)
      [[ "$#" -ge 2 ]] || { echo "missing value for --tamper-report-path" >&2; exit 2; }
      REPORT_PATH="$2"
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
    echo "passwordless sudo is required for post-bootstrap tamper operations on ${CLIENT_TARGET}" >&2
    exit 1
  fi
fi

BASELINE_STATUS="fail"
TAMPER_REJECT_STATUS="fail"
FAIL_CLOSED_STATUS="fail"
NETCHECK_FAIL_CLOSED_STATUS="fail"
RECOVERY_STATUS="fail"

STATUS_AFTER_TAMPER=""
STATUS_AFTER_RECOVERY=""
NETCHECK_AFTER_TAMPER=""
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

BACKUP_PATH="/var/lib/rustynet/rustynetd.assignment.securitytest.$(date +%s).bak"
remote_exec_root "${CLIENT_TARGET}" cp "${ASSIGNMENT_PATH}" "${BACKUP_PATH}"

CURRENT_MESH_CIDR="$(capture_remote_root "${CLIENT_TARGET}" awk -F= '/^mesh_cidr=/{print $2; exit}' "${ASSIGNMENT_PATH}" || true)"
CURRENT_MESH_CIDR="$(printf '%s' "${CURRENT_MESH_CIDR}" | tr -d '[:space:]')"
TAMPERED_MESH_CIDR="100.128.0.0/10"
if [[ "${CURRENT_MESH_CIDR}" == "100.128.0.0/10" ]]; then
  TAMPERED_MESH_CIDR="100.64.0.0/10"
fi

remote_exec_root "${CLIENT_TARGET}" \
  rustynet ops rewrite-assignment-mesh-cidr \
  --assignment-path "${ASSIGNMENT_PATH}" \
  --mesh-cidr "${TAMPERED_MESH_CIDR}"

remote_exec_root "${CLIENT_TARGET}" rm -f "${ASSIGNMENT_WATERMARK_PATH}"
remote_exec_root "${CLIENT_TARGET}" systemctl restart rustynetd
sleep 3

STATUS_AFTER_TAMPER="$(capture_remote_root "${CLIENT_TARGET}" env "RUSTYNET_DAEMON_SOCKET=${SOCKET_PATH}" rustynet status || true)"
NETCHECK_AFTER_TAMPER="$(capture_remote_root "${CLIENT_TARGET}" env "RUSTYNET_DAEMON_SOCKET=${SOCKET_PATH}" rustynet netcheck || true)"

if [[ "${STATUS_AFTER_TAMPER}" == *"restricted_safe_mode=true"* ]]; then
  FAIL_CLOSED_STATUS="pass"
fi

if [[ "${STATUS_AFTER_TAMPER}" == *"state=FailClosed"* ]]; then
  TAMPER_REJECT_STATUS="pass"
fi

if [[ "${NETCHECK_AFTER_TAMPER}" == *"path_mode=fail_closed"* ]]; then
  NETCHECK_FAIL_CLOSED_STATUS="pass"
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
if [[ "${STATUS_AFTER_RECOVERY}" == *"restricted_safe_mode=false"* && "${STATUS_AFTER_RECOVERY}" != *"state=FailClosed"* ]]; then
  RECOVERY_STATUS="pass"
fi

captured_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
captured_at_unix="$(date -u +%s)"
OVERALL_STATUS="$(
  cargo run --quiet -p rustynet-cli -- ops write-active-network-signed-state-tamper-report \
    --report-path "${REPORT_PATH}" \
    --baseline-status "${BASELINE_STATUS}" \
    --tamper-reject-status "${TAMPER_REJECT_STATUS}" \
    --fail-closed-status "${FAIL_CLOSED_STATUS}" \
    --netcheck-fail-closed-status "${NETCHECK_FAIL_CLOSED_STATUS}" \
    --recovery-status "${RECOVERY_STATUS}" \
    --exit-host "${EXIT_HOST}" \
    --client-host "${CLIENT_HOST}" \
    --status-after-tamper "${STATUS_AFTER_TAMPER}" \
    --netcheck-after-tamper "${NETCHECK_AFTER_TAMPER}" \
    --status-after-recovery "${STATUS_AFTER_RECOVERY}" \
    --captured-at-utc "${captured_at_utc}" \
    --captured-at-unix "${captured_at_unix}"
)"

if [[ "${OVERALL_STATUS}" != "pass" ]]; then
  echo "signed-state tamper e2e failed; see ${REPORT_PATH}" >&2
  exit 1
fi

echo "Signed-state tamper e2e report written to ${REPORT_PATH}"
