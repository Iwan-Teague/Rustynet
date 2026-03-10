#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

is_truthy() {
  local value="${1:-}"
  [[ "${value}" == "1" || "${value}" == "true" || "${value}" == "TRUE" || "${value}" == "yes" || "${value}" == "YES" ]]
}

require_env() {
  local key="$1"
  local value="${!key:-}"
  if [[ -z "${value}" ]]; then
    echo "missing required environment variable: ${key}" >&2
    exit 1
  fi
}

for cmd in python3 cargo ssh; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "missing required command: ${cmd}" >&2
    exit 1
  fi
done

require_env RUSTYNET_ACTIVE_NET_EXIT_HOST
require_env RUSTYNET_ACTIVE_NET_CLIENT_HOST
require_env RUSTYNET_ACTIVE_NET_SSH_ALLOW_CIDRS

ROGUE_ENDPOINT_IP="${RUSTYNET_ACTIVE_NET_ROGUE_ENDPOINT_IP:-203.0.113.250}"
python3 - "${ROGUE_ENDPOINT_IP}" <<'PY'
import ipaddress
import sys

ipaddress.IPv4Address(sys.argv[1])
PY

SSH_USER="${RUSTYNET_ACTIVE_NET_SSH_USER:-root}"
SSH_PORT="${RUSTYNET_ACTIVE_NET_SSH_PORT:-22}"
SSH_IDENTITY="${RUSTYNET_ACTIVE_NET_SSH_IDENTITY:-}"
SSH_KNOWN_HOSTS_FILE="${RUSTYNET_ACTIVE_NET_SSH_KNOWN_HOSTS_FILE:-}"
SSH_SUDO_MODE="${RUSTYNET_ACTIVE_NET_SSH_SUDO_MODE:-auto}"
SUDO_PASSWORD_FILE="${RUSTYNET_ACTIVE_NET_SUDO_PASSWORD_FILE:-}"
SIGNED_REPORT_PATH="${RUSTYNET_ACTIVE_NET_SIGNED_TAMPER_REPORT_PATH:-artifacts/phase10/signed_state_tamper_e2e_report.json}"
HIJACK_REPORT_PATH="${RUSTYNET_ACTIVE_NET_HIJACK_REPORT_PATH:-artifacts/phase10/rogue_path_hijack_e2e_report.json}"

COMMON_ARGS=(
  --exit-host "${RUSTYNET_ACTIVE_NET_EXIT_HOST}"
  --client-host "${RUSTYNET_ACTIVE_NET_CLIENT_HOST}"
  --ssh-user "${SSH_USER}"
  --ssh-port "${SSH_PORT}"
  --ssh-sudo "${SSH_SUDO_MODE}"
  --ssh-allow-cidrs "${RUSTYNET_ACTIVE_NET_SSH_ALLOW_CIDRS}"
)

if [[ -n "${SSH_IDENTITY}" ]]; then
  COMMON_ARGS+=(--ssh-identity "${SSH_IDENTITY}")
fi

if [[ -n "${SSH_KNOWN_HOSTS_FILE}" ]]; then
  COMMON_ARGS+=(--ssh-known-hosts-file "${SSH_KNOWN_HOSTS_FILE}")
fi

if [[ -n "${SUDO_PASSWORD_FILE}" ]]; then
  COMMON_ARGS+=(--sudo-password-file "${SUDO_PASSWORD_FILE}")
fi

if [[ -n "${RUSTYNET_ACTIVE_NET_EXIT_NODE_ID:-}" ]]; then
  COMMON_ARGS+=(--exit-node-id "${RUSTYNET_ACTIVE_NET_EXIT_NODE_ID}")
fi

if [[ -n "${RUSTYNET_ACTIVE_NET_CLIENT_NODE_ID:-}" ]]; then
  COMMON_ARGS+=(--client-node-id "${RUSTYNET_ACTIVE_NET_CLIENT_NODE_ID}")
fi

if [[ -n "${RUSTYNET_ACTIVE_NET_NETWORK_ID:-}" ]]; then
  COMMON_ARGS+=(--network-id "${RUSTYNET_ACTIVE_NET_NETWORK_ID}")
fi

if [[ -n "${RUSTYNET_ACTIVE_NET_REMOTE_ROOT:-}" ]]; then
  COMMON_ARGS+=(--remote-root "${RUSTYNET_ACTIVE_NET_REMOTE_ROOT}")
fi

if [[ -n "${RUSTYNET_ACTIVE_NET_REPO_REF:-}" ]]; then
  COMMON_ARGS+=(--repo-ref "${RUSTYNET_ACTIVE_NET_REPO_REF}")
fi

if [[ -n "${RUSTYNET_ACTIVE_NET_BASELINE_REPORT_PATH:-}" ]]; then
  COMMON_ARGS+=(--report-path "${RUSTYNET_ACTIVE_NET_BASELINE_REPORT_PATH}")
fi

if is_truthy "${RUSTYNET_ACTIVE_NET_SKIP_APT:-0}"; then
  COMMON_ARGS+=(--skip-apt)
fi

./scripts/e2e/real_wireguard_signed_state_tamper_e2e.sh \
  "${COMMON_ARGS[@]}" \
  --tamper-report-path "${SIGNED_REPORT_PATH}"

./scripts/e2e/real_wireguard_rogue_path_hijack_e2e.sh \
  "${COMMON_ARGS[@]}" \
  --rogue-endpoint-ip "${ROGUE_ENDPOINT_IP}" \
  --hijack-report-path "${HIJACK_REPORT_PATH}"

echo "Active network security gates: PASS"
