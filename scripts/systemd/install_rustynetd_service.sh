#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVICE_SRC="${ROOT_DIR}/scripts/systemd/rustynetd.service"
HELPER_SERVICE_SRC="${ROOT_DIR}/scripts/systemd/rustynetd-privileged-helper.service"
SERVICE_DST="/etc/systemd/system/rustynetd.service"
HELPER_SERVICE_DST="/etc/systemd/system/rustynetd-privileged-helper.service"
ENV_DST="/etc/default/rustynetd"

for unit in "${SERVICE_SRC}" "${HELPER_SERVICE_SRC}"; do
  if [[ ! -f "${unit}" ]]; then
    echo "missing service file: ${unit}" >&2
    exit 1
  fi
done

SERVICE_USER="${RUSTYNET_DAEMON_USER:-rustynetd}"
SERVICE_GROUP="${RUSTYNET_DAEMON_GROUP:-rustynetd}"
if ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
  groupadd --system "${SERVICE_GROUP}"
fi
if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --gid "${SERVICE_GROUP}" --home-dir /nonexistent --shell /usr/sbin/nologin "${SERVICE_USER}"
fi
DAEMON_UID="$(id -u "${SERVICE_USER}")"
DAEMON_GID="$(getent group "${SERVICE_GROUP}" | awk -F: '{print $3}')"

install -d -m 0750 -o root -g "${SERVICE_GROUP}" /etc/rustynet
install -d -m 0770 -o root -g "${SERVICE_GROUP}" /run/rustynet
install -d -m 0700 -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" /var/lib/rustynet
install -m 0644 "${SERVICE_SRC}" "${SERVICE_DST}"
install -m 0644 "${HELPER_SERVICE_SRC}" "${HELPER_SERVICE_DST}"

SOCKET_PATH="${RUSTYNET_SOCKET:-/run/rustynet/rustynetd.sock}"
STATE_PATH="${RUSTYNET_STATE:-/var/lib/rustynet/rustynetd.state}"
TRUST_EVIDENCE_PATH="${RUSTYNET_TRUST_EVIDENCE:-/var/lib/rustynet/rustynetd.trust}"
TRUST_VERIFIER_KEY_PATH="${RUSTYNET_TRUST_VERIFIER_KEY:-/etc/rustynet/trust-evidence.pub}"
TRUST_WATERMARK_PATH="${RUSTYNET_TRUST_WATERMARK:-/var/lib/rustynet/rustynetd.trust.watermark}"
MEMBERSHIP_SNAPSHOT_PATH="${RUSTYNET_MEMBERSHIP_SNAPSHOT:-/var/lib/rustynet/membership.snapshot}"
MEMBERSHIP_LOG_PATH="${RUSTYNET_MEMBERSHIP_LOG:-/var/lib/rustynet/membership.log}"
MEMBERSHIP_WATERMARK_PATH="${RUSTYNET_MEMBERSHIP_WATERMARK:-/var/lib/rustynet/membership.watermark}"
AUTO_TUNNEL_ENFORCE="${RUSTYNET_AUTO_TUNNEL_ENFORCE:-true}"
AUTO_TUNNEL_BUNDLE_PATH="${RUSTYNET_AUTO_TUNNEL_BUNDLE:-/var/lib/rustynet/rustynetd.assignment}"
AUTO_TUNNEL_VERIFIER_KEY_PATH="${RUSTYNET_AUTO_TUNNEL_VERIFIER_KEY:-/etc/rustynet/assignment.pub}"
AUTO_TUNNEL_WATERMARK_PATH="${RUSTYNET_AUTO_TUNNEL_WATERMARK:-/var/lib/rustynet/rustynetd.assignment.watermark}"
AUTO_TUNNEL_MAX_AGE_SECS="${RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS:-300}"
NODE_ID="${RUSTYNET_NODE_ID:-$(hostname -s 2>/dev/null || echo daemon-local)}"
NODE_ROLE="${RUSTYNET_NODE_ROLE:-client}"
BACKEND_MODE="${RUSTYNET_BACKEND:-linux-wireguard}"
WG_INTERFACE="${RUSTYNET_WG_INTERFACE:-rustynet0}"
WG_PRIVATE_KEY_PATH="${RUSTYNET_WG_PRIVATE_KEY:-/run/rustynet/wireguard.key}"
WG_ENCRYPTED_PRIVATE_KEY_PATH="${RUSTYNET_WG_ENCRYPTED_PRIVATE_KEY:-/var/lib/rustynet/keys/wireguard.key.enc}"
WG_KEY_PASSPHRASE_PATH="${RUSTYNET_WG_KEY_PASSPHRASE:-/var/lib/rustynet/keys/wireguard.passphrase}"
WG_PUBLIC_KEY_PATH="${RUSTYNET_WG_PUBLIC_KEY:-/var/lib/rustynet/keys/wireguard.pub}"
DATAPLANE_MODE="${RUSTYNET_DATAPLANE_MODE:-hybrid-native}"
PRIVILEGED_HELPER_SOCKET="${RUSTYNET_PRIVILEGED_HELPER_SOCKET:-/run/rustynet/rustynetd-privileged.sock}"
PRIVILEGED_HELPER_TIMEOUT_MS="${RUSTYNET_PRIVILEGED_HELPER_TIMEOUT_MS:-2000}"
RECONCILE_INTERVAL_MS="${RUSTYNET_RECONCILE_INTERVAL_MS:-1000}"
MAX_RECONCILE_FAILURES="${RUSTYNET_MAX_RECONCILE_FAILURES:-5}"
FAIL_CLOSED_SSH_ALLOW="${RUSTYNET_FAIL_CLOSED_SSH_ALLOW:-false}"
FAIL_CLOSED_SSH_ALLOW_CIDRS="${RUSTYNET_FAIL_CLOSED_SSH_ALLOW_CIDRS:-}"

case "${NODE_ROLE}" in
  admin|client) ;;
  *)
    echo "invalid node role: ${NODE_ROLE} (expected admin|client)" >&2
    exit 1
    ;;
esac

case "${FAIL_CLOSED_SSH_ALLOW}" in
  true|false|1|0|yes|no) ;;
  *)
    echo "invalid fail-closed ssh allow value: ${FAIL_CLOSED_SSH_ALLOW} (expected true|false)" >&2
    exit 1
    ;;
esac
if [[ "${FAIL_CLOSED_SSH_ALLOW}" == "true" || "${FAIL_CLOSED_SSH_ALLOW}" == "1" || "${FAIL_CLOSED_SSH_ALLOW}" == "yes" ]]; then
  if [[ -z "${FAIL_CLOSED_SSH_ALLOW_CIDRS// }" ]]; then
    echo "fail-closed ssh allow enabled but no cidrs supplied (RUSTYNET_FAIL_CLOSED_SSH_ALLOW_CIDRS)" >&2
    exit 1
  fi
fi
if ! [[ "${PRIVILEGED_HELPER_TIMEOUT_MS}" =~ ^[0-9]+$ ]] || [[ "${PRIVILEGED_HELPER_TIMEOUT_MS}" == "0" ]]; then
  echo "invalid privileged helper timeout: ${PRIVILEGED_HELPER_TIMEOUT_MS}" >&2
  exit 1
fi

EGRESS_IFACE="${RUSTYNET_EGRESS_INTERFACE:-}"
if [[ -z "${EGRESS_IFACE}" ]]; then
  EGRESS_IFACE="$(ip -o -4 route show to default | awk 'NR==1 { print $5 }')"
fi
if [[ -z "${EGRESS_IFACE}" ]]; then
  echo "unable to detect default egress interface; set RUSTYNET_EGRESS_INTERFACE" >&2
  exit 1
fi
if ! ip link show "${EGRESS_IFACE}" >/dev/null 2>&1; then
  echo "egress interface does not exist: ${EGRESS_IFACE}" >&2
  exit 1
fi

ensure_parent_dir() {
  local target="$1"
  local owner="$2"
  local group="$3"
  local mode="$4"
  local parent
  parent="$(dirname "${target}")"
  if [[ -d "${parent}" ]]; then
    return
  fi
  install -d -m "${mode}" -o "${owner}" -g "${group}" "${parent}"
}

set_owner_mode_if_exists() {
  local target="$1"
  local owner="$2"
  local group="$3"
  local mode="$4"
  if [[ -e "${target}" ]]; then
    chown "${owner}:${group}" "${target}"
    chmod "${mode}" "${target}"
  fi
}

migrate_legacy_key_path_if_needed() {
  local legacy_path="$1"
  local target_path="$2"
  local owner="$3"
  local group="$4"
  local mode="$5"
  if [[ "${legacy_path}" == "${target_path}" ]]; then
    return
  fi
  if [[ -e "${target_path}" || ! -f "${legacy_path}" ]]; then
    return
  fi
  install -m "${mode}" -o "${owner}" -g "${group}" "${legacy_path}" "${target_path}"
  rm -f "${legacy_path}"
}

key_id_for_encrypted_path() {
  local encrypted_path="$1"
  local digest
  digest="$(printf '%s' "${encrypted_path}" | sha256sum | awk '{print $1}')"
  printf 'wg-private-%s' "${digest:0:16}"
}

for mutable_target in \
  "${STATE_PATH}" \
  "${MEMBERSHIP_SNAPSHOT_PATH}" \
  "${MEMBERSHIP_LOG_PATH}" \
  "${TRUST_WATERMARK_PATH}" \
  "${MEMBERSHIP_WATERMARK_PATH}" \
  "${AUTO_TUNNEL_WATERMARK_PATH}" \
  "${WG_PRIVATE_KEY_PATH}"; do
  ensure_parent_dir "${mutable_target}" "${SERVICE_USER}" "${SERVICE_GROUP}" 0750
done
for key_material_target in \
  "${WG_ENCRYPTED_PRIVATE_KEY_PATH}" \
  "${WG_KEY_PASSPHRASE_PATH}" \
  "${WG_PUBLIC_KEY_PATH}"; do
  install -d -m 0700 -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" "$(dirname "${key_material_target}")"
done
ensure_parent_dir "${SOCKET_PATH}" "${SERVICE_USER}" "${SERVICE_GROUP}" 0750
ensure_parent_dir "${PRIVILEGED_HELPER_SOCKET}" root "${SERVICE_GROUP}" 0750

migrate_legacy_key_path_if_needed "/etc/rustynet/wireguard.key.enc" "${WG_ENCRYPTED_PRIVATE_KEY_PATH}" "${SERVICE_USER}" "${SERVICE_GROUP}" 0600
migrate_legacy_key_path_if_needed "/etc/rustynet/wireguard.passphrase" "${WG_KEY_PASSPHRASE_PATH}" "${SERVICE_USER}" "${SERVICE_GROUP}" 0600
migrate_legacy_key_path_if_needed "/etc/rustynet/wireguard.pub" "${WG_PUBLIC_KEY_PATH}" "${SERVICE_USER}" "${SERVICE_GROUP}" 0644

LEGACY_ENCRYPTED_KEY_PATH="/etc/rustynet/wireguard.key.enc"
LEGACY_KEY_ID="$(key_id_for_encrypted_path "${LEGACY_ENCRYPTED_KEY_PATH}")"
TARGET_KEY_ID="$(key_id_for_encrypted_path "${WG_ENCRYPTED_PRIVATE_KEY_PATH}")"
LEGACY_FALLBACK_FILE="$(dirname "${LEGACY_ENCRYPTED_KEY_PATH}")/${LEGACY_KEY_ID}.enc"
TARGET_FALLBACK_FILE="$(dirname "${WG_ENCRYPTED_PRIVATE_KEY_PATH}")/${TARGET_KEY_ID}.enc"
if [[ "${LEGACY_FALLBACK_FILE}" != "${TARGET_FALLBACK_FILE}" && ! -e "${TARGET_FALLBACK_FILE}" && -f "${LEGACY_FALLBACK_FILE}" ]]; then
  install -m 0600 -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" "${LEGACY_FALLBACK_FILE}" "${TARGET_FALLBACK_FILE}"
  rm -f "${LEGACY_FALLBACK_FILE}"
fi

for readonly_target in \
  "${TRUST_EVIDENCE_PATH}" \
  "${TRUST_VERIFIER_KEY_PATH}" \
  "${AUTO_TUNNEL_BUNDLE_PATH}" \
  "${AUTO_TUNNEL_VERIFIER_KEY_PATH}"; do
  ensure_parent_dir "${readonly_target}" root "${SERVICE_GROUP}" 0750
done

set_owner_mode_if_exists "${STATE_PATH}" "${SERVICE_USER}" "${SERVICE_GROUP}" 0600
set_owner_mode_if_exists "${MEMBERSHIP_SNAPSHOT_PATH}" "${SERVICE_USER}" "${SERVICE_GROUP}" 0600
set_owner_mode_if_exists "${MEMBERSHIP_LOG_PATH}" "${SERVICE_USER}" "${SERVICE_GROUP}" 0600
set_owner_mode_if_exists "${TRUST_WATERMARK_PATH}" "${SERVICE_USER}" "${SERVICE_GROUP}" 0600
set_owner_mode_if_exists "${MEMBERSHIP_WATERMARK_PATH}" "${SERVICE_USER}" "${SERVICE_GROUP}" 0600
set_owner_mode_if_exists "${AUTO_TUNNEL_WATERMARK_PATH}" "${SERVICE_USER}" "${SERVICE_GROUP}" 0600
set_owner_mode_if_exists "${WG_PRIVATE_KEY_PATH}" "${SERVICE_USER}" "${SERVICE_GROUP}" 0600
set_owner_mode_if_exists "${WG_ENCRYPTED_PRIVATE_KEY_PATH}" "${SERVICE_USER}" "${SERVICE_GROUP}" 0600
set_owner_mode_if_exists "${WG_KEY_PASSPHRASE_PATH}" "${SERVICE_USER}" "${SERVICE_GROUP}" 0600
set_owner_mode_if_exists "${WG_PUBLIC_KEY_PATH}" "${SERVICE_USER}" "${SERVICE_GROUP}" 0644
set_owner_mode_if_exists "${TARGET_FALLBACK_FILE}" "${SERVICE_USER}" "${SERVICE_GROUP}" 0600

set_owner_mode_if_exists "${TRUST_EVIDENCE_PATH}" root "${SERVICE_GROUP}" 0640
set_owner_mode_if_exists "${AUTO_TUNNEL_BUNDLE_PATH}" root "${SERVICE_GROUP}" 0640
set_owner_mode_if_exists "${TRUST_VERIFIER_KEY_PATH}" root root 0644
set_owner_mode_if_exists "${AUTO_TUNNEL_VERIFIER_KEY_PATH}" root root 0644

cat >"${ENV_DST}" <<EOF_ENV
RUSTYNET_NODE_ID=${NODE_ID}
RUSTYNET_NODE_ROLE=${NODE_ROLE}
RUSTYNET_SOCKET=${SOCKET_PATH}
RUSTYNET_STATE=${STATE_PATH}
RUSTYNET_TRUST_EVIDENCE=${TRUST_EVIDENCE_PATH}
RUSTYNET_TRUST_VERIFIER_KEY=${TRUST_VERIFIER_KEY_PATH}
RUSTYNET_TRUST_WATERMARK=${TRUST_WATERMARK_PATH}
RUSTYNET_AUTO_TUNNEL_ENFORCE=${AUTO_TUNNEL_ENFORCE}
RUSTYNET_AUTO_TUNNEL_BUNDLE=${AUTO_TUNNEL_BUNDLE_PATH}
RUSTYNET_AUTO_TUNNEL_VERIFIER_KEY=${AUTO_TUNNEL_VERIFIER_KEY_PATH}
RUSTYNET_AUTO_TUNNEL_WATERMARK=${AUTO_TUNNEL_WATERMARK_PATH}
RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS=${AUTO_TUNNEL_MAX_AGE_SECS}
RUSTYNET_BACKEND=${BACKEND_MODE}
RUSTYNET_WG_INTERFACE=${WG_INTERFACE}
RUSTYNET_WG_PRIVATE_KEY=${WG_PRIVATE_KEY_PATH}
RUSTYNET_WG_ENCRYPTED_PRIVATE_KEY=${WG_ENCRYPTED_PRIVATE_KEY_PATH}
RUSTYNET_WG_KEY_PASSPHRASE=${WG_KEY_PASSPHRASE_PATH}
RUSTYNET_WG_PUBLIC_KEY=${WG_PUBLIC_KEY_PATH}
RUSTYNET_EGRESS_INTERFACE=${EGRESS_IFACE}
RUSTYNET_DATAPLANE_MODE=${DATAPLANE_MODE}
RUSTYNET_PRIVILEGED_HELPER_SOCKET=${PRIVILEGED_HELPER_SOCKET}
RUSTYNET_PRIVILEGED_HELPER_TIMEOUT_MS=${PRIVILEGED_HELPER_TIMEOUT_MS}
RUSTYNET_PRIVILEGED_HELPER_ALLOWED_UID=${DAEMON_UID}
RUSTYNET_PRIVILEGED_HELPER_ALLOWED_GID=${DAEMON_GID}
RUSTYNET_RECONCILE_INTERVAL_MS=${RECONCILE_INTERVAL_MS}
RUSTYNET_MAX_RECONCILE_FAILURES=${MAX_RECONCILE_FAILURES}
RUSTYNET_FAIL_CLOSED_SSH_ALLOW=${FAIL_CLOSED_SSH_ALLOW}
RUSTYNET_FAIL_CLOSED_SSH_ALLOW_CIDRS=${FAIL_CLOSED_SSH_ALLOW_CIDRS}
EOF_ENV
chmod 0644 "${ENV_DST}"

systemctl daemon-reload
systemctl enable rustynetd-privileged-helper.service
systemctl enable rustynetd.service
systemctl reset-failed rustynetd-privileged-helper.service rustynetd.service || true
systemctl restart rustynetd-privileged-helper.service
systemctl restart rustynetd.service
systemctl --no-pager --full status rustynetd-privileged-helper.service
systemctl --no-pager --full status rustynetd.service
