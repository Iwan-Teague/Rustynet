#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/rustynet"
CONFIG_FILE="${CONFIG_DIR}/wizard.env"
PEERS_FILE="${CONFIG_DIR}/peers.db"
LINUX_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH="/etc/rustynet/credentials/wg_key_passphrase.cred"
LINUX_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH="/etc/rustynet/credentials/signing_key_passphrase.cred"
ASSIGNMENT_REFRESH_ENV_PATH="/etc/rustynet/assignment-refresh.env"

# Defaults aligned with rustynetd/systemd profile.
SOCKET_PATH="/run/rustynet/rustynetd.sock"
STATE_PATH="/var/lib/rustynet/rustynetd.state"
TRUST_EVIDENCE_PATH="/var/lib/rustynet/rustynetd.trust"
TRUST_VERIFIER_KEY_PATH="/etc/rustynet/trust-evidence.pub"
TRUST_WATERMARK_PATH="/var/lib/rustynet/rustynetd.trust.watermark"
AUTO_TUNNEL_ENFORCE="0"
AUTO_TUNNEL_BUNDLE_PATH="/var/lib/rustynet/rustynetd.assignment"
AUTO_TUNNEL_VERIFIER_KEY_PATH="/etc/rustynet/assignment.pub"
AUTO_TUNNEL_WATERMARK_PATH="/var/lib/rustynet/rustynetd.assignment.watermark"
AUTO_TUNNEL_MAX_AGE_SECS="300"
TRAVERSAL_BUNDLE_PATH="/var/lib/rustynet/rustynetd.traversal"
TRAVERSAL_VERIFIER_KEY_PATH="/etc/rustynet/traversal.pub"
TRAVERSAL_WATERMARK_PATH="/var/lib/rustynet/rustynetd.traversal.watermark"
TRAVERSAL_MAX_AGE_SECS="120"
WG_INTERFACE="rustynet0"
WG_LISTEN_PORT="51820"
AUTO_PORT_FORWARD_EXIT="0"
AUTO_PORT_FORWARD_LEASE_SECS="1200"
WG_PRIVATE_KEY_PATH="/run/rustynet/wireguard.key"
WG_ENCRYPTED_PRIVATE_KEY_PATH="/var/lib/rustynet/keys/wireguard.key.enc"
WG_KEY_PASSPHRASE_PATH="/var/lib/rustynet/keys/wireguard.passphrase"
WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH="${LINUX_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}"
SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH="${LINUX_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}"
WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT=""
WG_PUBLIC_KEY_PATH="/var/lib/rustynet/keys/wireguard.pub"
EGRESS_INTERFACE=""
MEMBERSHIP_SNAPSHOT_PATH="/var/lib/rustynet/membership.snapshot"
MEMBERSHIP_LOG_PATH="/var/lib/rustynet/membership.log"
MEMBERSHIP_WATERMARK_PATH="/var/lib/rustynet/membership.watermark"
MEMBERSHIP_OWNER_SIGNING_KEY_PATH="/etc/rustynet/membership.owner.key"
BACKEND_MODE="linux-wireguard"
DATAPLANE_MODE="hybrid-native"
PRIVILEGED_HELPER_SOCKET_PATH="/run/rustynet/rustynetd-privileged.sock"
PRIVILEGED_HELPER_TIMEOUT_MS="2000"
RECONCILE_INTERVAL_MS="1000"
MAX_RECONCILE_FAILURES="5"
FAIL_CLOSED_SSH_ALLOW="0"
FAIL_CLOSED_SSH_ALLOW_CIDRS=""
TRUST_SIGNER_KEY_PATH="/etc/rustynet/trust-evidence.key"
AUTO_REFRESH_TRUST="0"
DEVICE_NODE_ID="$(hostname -s 2>/dev/null || echo rustynet-node)"
SETUP_COMPLETE="0"
NODE_ROLE=""
MANUAL_PEER_OVERRIDE="0"
DEFAULT_LAUNCH_PROFILE="menu"
AUTO_LAUNCH_ON_START="0"
AUTO_LAUNCH_EXIT_NODE_ID=""
AUTO_LAUNCH_LAN_MODE="skip"
EXIT_CHAIN_HOPS="1"
EXIT_CHAIN_ENTRY_NODE_ID=""
EXIT_CHAIN_FINAL_NODE_ID=""
REQUESTED_LAUNCH_PROFILE=""
REQUESTED_EXIT_NODE_ID=""
REQUESTED_LAN_MODE=""
AUTO_ONLY_LAUNCH="0"
RUST_MIN_VERSION="1.85"
CARGO_DENY_VERSION="0.18.3"
CONFIG_LOADED_FROM_FILE="0"
MANUAL_PEER_AUDIT_LOG="/var/log/rustynet/manual-peer-override.log"
MANUAL_OVERRIDE_CONFIRMATION="RUSTYNET_BREAK_GLASS_ACK"
HOST_OS="$(uname -s)"
HOST_PROFILE="unknown"
MACOS_STATE_BASE="${HOME}/Library/Application Support/rustynet"
MACOS_RUNTIME_BASE="${HOME}/Library/Caches/rustynet"
MACOS_LOG_BASE="${HOME}/Library/Logs/rustynet"
MACOS_DAEMON_LOG_PATH="${MACOS_LOG_BASE}/rustynetd.log"
MACOS_HELPER_LOG_PATH="${MACOS_LOG_BASE}/rustynetd-privileged.log"
MACOS_LOCAL_TOOLS_BASE="${HOME}/.local/rustynet-tools"
MACOS_LOCAL_TOOLS_BIN="${MACOS_LOCAL_TOOLS_BASE}/bin"
MACOS_LAUNCHD_DAEMON_LABEL="com.rustynet.rustynetd"
MACOS_LAUNCHD_HELPER_LABEL="com.rustynet.rustynetd-privileged"
MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE="rustynet.wg_passphrase"
MACOS_LAUNCHD_DAEMON_PLIST_PATH="${HOME}/Library/LaunchAgents/${MACOS_LAUNCHD_DAEMON_LABEL}.plist"
MACOS_LAUNCHD_HELPER_PLIST_PATH="/Library/LaunchDaemons/${MACOS_LAUNCHD_HELPER_LABEL}.plist"
export PATH="/usr/local/bin:/usr/local/sbin:/opt/homebrew/bin:/opt/homebrew/sbin:/usr/bin:/usr/sbin:/sbin:${MACOS_LOCAL_TOOLS_BIN}:${MACOS_LOCAL_TOOLS_BASE}/go/bin:${PATH}"

mkdir -p "${CONFIG_DIR}"

print_info() {
  printf '[info] %s\n' "$*"
}

print_warn() {
  printf '[warn] %s\n' "$*" >&2
}

print_err() {
  printf '[error] %s\n' "$*" >&2
}

is_linux_host() {
  [[ "${HOST_OS}" == "Linux" ]]
}

is_macos_host() {
  [[ "${HOST_OS}" == "Darwin" ]]
}

apply_host_profile_defaults() {
  if is_linux_host; then
    HOST_PROFILE="linux"
    WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH="${LINUX_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}"
    SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH="${LINUX_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}"
    return
  fi

  if is_macos_host; then
    HOST_PROFILE="macos"

    SOCKET_PATH="${MACOS_RUNTIME_BASE}/rustynetd.sock"
    STATE_PATH="${MACOS_STATE_BASE}/rustynetd.state"
    TRUST_EVIDENCE_PATH="${MACOS_STATE_BASE}/trust/rustynetd.trust"
    TRUST_VERIFIER_KEY_PATH="${MACOS_STATE_BASE}/trust/trust-evidence.pub"
    TRUST_WATERMARK_PATH="${MACOS_STATE_BASE}/trust/rustynetd.trust.watermark"
    AUTO_TUNNEL_BUNDLE_PATH="${MACOS_STATE_BASE}/assignment/rustynetd.assignment"
    AUTO_TUNNEL_VERIFIER_KEY_PATH="${MACOS_STATE_BASE}/assignment/assignment.pub"
    AUTO_TUNNEL_WATERMARK_PATH="${MACOS_STATE_BASE}/assignment/rustynetd.assignment.watermark"
    TRAVERSAL_BUNDLE_PATH="${MACOS_STATE_BASE}/traversal/rustynetd.traversal"
    TRAVERSAL_VERIFIER_KEY_PATH="${MACOS_STATE_BASE}/traversal/traversal.pub"
    TRAVERSAL_WATERMARK_PATH="${MACOS_STATE_BASE}/traversal/rustynetd.traversal.watermark"
    WG_PRIVATE_KEY_PATH="${MACOS_STATE_BASE}/keys/wireguard.key"
    WG_ENCRYPTED_PRIVATE_KEY_PATH="${MACOS_STATE_BASE}/keys/wireguard.key.enc"
    WG_KEY_PASSPHRASE_PATH="${MACOS_STATE_BASE}/keys/wireguard.passphrase"
    WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH="${MACOS_STATE_BASE}/keys/wg_key_passphrase.cred"
    SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH="${MACOS_STATE_BASE}/keys/signing_key_passphrase.cred"
    WG_PUBLIC_KEY_PATH="${MACOS_STATE_BASE}/keys/wireguard.pub"
    WG_INTERFACE="utun9"
    MEMBERSHIP_SNAPSHOT_PATH="${MACOS_STATE_BASE}/membership/membership.snapshot"
    MEMBERSHIP_LOG_PATH="${MACOS_STATE_BASE}/membership/membership.log"
    MEMBERSHIP_WATERMARK_PATH="${MACOS_STATE_BASE}/membership/membership.watermark"
    MEMBERSHIP_OWNER_SIGNING_KEY_PATH="${MACOS_STATE_BASE}/membership/membership.owner.key"
    TRUST_SIGNER_KEY_PATH="${MACOS_STATE_BASE}/trust/trust-evidence.key"
    PRIVILEGED_HELPER_SOCKET_PATH="${MACOS_RUNTIME_BASE}/rustynetd-privileged.sock"
    MANUAL_PEER_AUDIT_LOG="${MACOS_LOG_BASE}/manual-peer-override.log"
    WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT="$(sanitize_macos_keychain_account "wg-passphrase-${DEVICE_NODE_ID}")"
    MANUAL_PEER_OVERRIDE="0"
    return
  fi

  HOST_PROFILE="unsupported"
}

path_in_linux_runtime_roots() {
  local value="$1"
  [[ "${value}" == /etc/rustynet* ]] \
    || [[ "${value}" == /var/lib/rustynet* ]] \
    || [[ "${value}" == /run/rustynet* ]] \
    || [[ "${value}" == /var/log/rustynet* ]]
}

require_macos_path_var_exact() {
  local var_name="$1"
  local expected="$2"
  local current="${!var_name:-}"
  if [[ -z "${current}" ]]; then
    print_err "Missing required macOS path setting ${var_name}; expected '${expected}'."
    exit 1
  fi
  if [[ "${current}" != "${expected}" ]]; then
    print_err "Non-canonical macOS path for ${var_name}: '${current}' (expected '${expected}')."
    print_info "Update ${CONFIG_FILE} to canonical macOS paths before continuing."
    exit 1
  fi
}

sanitize_macos_keychain_account() {
  local value="$1"
  value="${value//[^A-Za-z0-9._-]/-}"
  value="${value#-}"
  value="${value%-}"
  if [[ -z "${value}" ]]; then
    value="rustynet-passphrase"
  fi
  printf '%s' "${value}"
}

ensure_macos_keychain_passphrase_account() {
  if ! is_macos_host; then
    return 0
  fi
  if [[ -z "${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}" ]]; then
    WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT="$(sanitize_macos_keychain_account "wg-passphrase-${DEVICE_NODE_ID}")"
  else
    WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT="$(sanitize_macos_keychain_account "${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}")"
  fi
}

macos_keychain_passphrase_exists() {
  if ! is_macos_host; then
    return 1
  fi
  if [[ -z "${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}" ]]; then
    return 1
  fi
  security find-generic-password \
    -s "${MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}" \
    -a "${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}" >/dev/null 2>&1
}

enforce_host_storage_policy() {
  if is_linux_host; then
    HOST_PROFILE="linux"
    WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH="${LINUX_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}"
    SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH="${LINUX_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}"
    return
  fi

  if ! is_macos_host; then
    HOST_PROFILE="unsupported"
    return
  fi

  HOST_PROFILE="macos"
  require_macos_path_var_exact SOCKET_PATH "${MACOS_RUNTIME_BASE}/rustynetd.sock"
  require_macos_path_var_exact STATE_PATH "${MACOS_STATE_BASE}/rustynetd.state"
  require_macos_path_var_exact TRUST_EVIDENCE_PATH "${MACOS_STATE_BASE}/trust/rustynetd.trust"
  require_macos_path_var_exact TRUST_VERIFIER_KEY_PATH "${MACOS_STATE_BASE}/trust/trust-evidence.pub"
  require_macos_path_var_exact TRUST_WATERMARK_PATH "${MACOS_STATE_BASE}/trust/rustynetd.trust.watermark"
  require_macos_path_var_exact AUTO_TUNNEL_BUNDLE_PATH "${MACOS_STATE_BASE}/assignment/rustynetd.assignment"
  require_macos_path_var_exact AUTO_TUNNEL_VERIFIER_KEY_PATH "${MACOS_STATE_BASE}/assignment/assignment.pub"
  require_macos_path_var_exact AUTO_TUNNEL_WATERMARK_PATH "${MACOS_STATE_BASE}/assignment/rustynetd.assignment.watermark"
  require_macos_path_var_exact TRAVERSAL_BUNDLE_PATH "${MACOS_STATE_BASE}/traversal/rustynetd.traversal"
  require_macos_path_var_exact TRAVERSAL_VERIFIER_KEY_PATH "${MACOS_STATE_BASE}/traversal/traversal.pub"
  require_macos_path_var_exact TRAVERSAL_WATERMARK_PATH "${MACOS_STATE_BASE}/traversal/rustynetd.traversal.watermark"
  require_macos_path_var_exact WG_PRIVATE_KEY_PATH "${MACOS_STATE_BASE}/keys/wireguard.key"
  require_macos_path_var_exact WG_ENCRYPTED_PRIVATE_KEY_PATH "${MACOS_STATE_BASE}/keys/wireguard.key.enc"
  require_macos_path_var_exact WG_KEY_PASSPHRASE_PATH "${MACOS_STATE_BASE}/keys/wireguard.passphrase"
  require_macos_path_var_exact WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH "${MACOS_STATE_BASE}/keys/wg_key_passphrase.cred"
  require_macos_path_var_exact SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH "${MACOS_STATE_BASE}/keys/signing_key_passphrase.cred"
  require_macos_path_var_exact WG_PUBLIC_KEY_PATH "${MACOS_STATE_BASE}/keys/wireguard.pub"
  require_macos_path_var_exact PRIVILEGED_HELPER_SOCKET_PATH "${MACOS_RUNTIME_BASE}/rustynetd-privileged.sock"
  require_macos_path_var_exact MEMBERSHIP_SNAPSHOT_PATH "${MACOS_STATE_BASE}/membership/membership.snapshot"
  require_macos_path_var_exact MEMBERSHIP_LOG_PATH "${MACOS_STATE_BASE}/membership/membership.log"
  require_macos_path_var_exact MEMBERSHIP_WATERMARK_PATH "${MACOS_STATE_BASE}/membership/membership.watermark"
  require_macos_path_var_exact MEMBERSHIP_OWNER_SIGNING_KEY_PATH "${MACOS_STATE_BASE}/membership/membership.owner.key"
  require_macos_path_var_exact TRUST_SIGNER_KEY_PATH "${MACOS_STATE_BASE}/trust/trust-evidence.key"
  require_macos_path_var_exact MANUAL_PEER_AUDIT_LOG "${MACOS_LOG_BASE}/manual-peer-override.log"
  ensure_macos_keychain_passphrase_account

  if [[ ! "${WG_INTERFACE}" =~ ^utun[0-9]+$ ]]; then
    print_err "WG_INTERFACE '${WG_INTERFACE}' is invalid for macOS; expected pattern utunN."
    exit 1
  fi

  if [[ "${MANUAL_PEER_OVERRIDE}" != "0" ]]; then
    print_err "Manual peer break-glass override is no longer supported."
    print_info "Set MANUAL_PEER_OVERRIDE=0 in ${CONFIG_FILE}."
    exit 1
  fi
}

require_linux_dataplane() {
  local action="$1"
  if is_linux_host; then
    return 0
  fi
  print_err "${action} requires a Linux dataplane host."
  if is_macos_host; then
    print_info "This operation currently has no macOS implementation path in start.sh."
  else
    print_info "Current host OS '${HOST_OS}' is not supported for dataplane/runtime operations."
  fi
  return 1
}

normalize_node_role() {
  if [[ -z "${NODE_ROLE}" ]]; then
    if [[ "${SETUP_COMPLETE}" == "1" ]]; then
      NODE_ROLE="admin"
    else
      NODE_ROLE="client"
    fi
  fi

  case "${NODE_ROLE}" in
    admin|client|blind_exit) ;;
    *)
      print_warn "Invalid NODE_ROLE='${NODE_ROLE}', defaulting to 'client'."
      NODE_ROLE="client"
      ;;
  esac
  if [[ "${NODE_ROLE}" == "blind_exit" ]] && ! is_linux_host; then
    print_warn "blind_exit role is supported only on Linux hosts. Reverting to client role."
    NODE_ROLE="client"
  fi
}

is_admin_role() {
  [[ "${NODE_ROLE}" == "admin" ]]
}

is_client_role() {
  [[ "${NODE_ROLE}" == "client" ]]
}

is_blind_exit_role() {
  [[ "${NODE_ROLE}" == "blind_exit" ]]
}

blind_exit_role_locked() {
  is_blind_exit_role && [[ "${SETUP_COMPLETE}" == "1" ]]
}

print_blind_exit_lock_notice() {
  print_warn "blind_exit role is immutable after setup."
  print_info "To change role, perform a factory reset and provision fresh key material on this device."
}

require_admin_role() {
  local action="$1"
  if is_admin_role; then
    return 0
  fi
  print_err "${action} requires node role 'admin'."
  print_info "This device is configured as role '${NODE_ROLE}'."
  return 1
}

enforce_role_policy_defaults() {
  normalize_node_role
  if is_admin_role; then
    return 0
  fi

  MANUAL_PEER_OVERRIDE="0"
  if [[ "${AUTO_REFRESH_TRUST}" == "1" && ! -f "${TRUST_SIGNER_KEY_PATH}" ]]; then
    print_warn "Trust signer key ${TRUST_SIGNER_KEY_PATH} is unavailable; disabling AUTO_REFRESH_TRUST for role '${NODE_ROLE}'."
    AUTO_REFRESH_TRUST="0"
  fi

  if is_client_role; then
    case "${DEFAULT_LAUNCH_PROFILE}" in
      quick-exit-node|quick-hybrid)
        print_warn "Launch profile '${DEFAULT_LAUNCH_PROFILE}' is admin-only; forcing 'quick-connect' for client role."
        DEFAULT_LAUNCH_PROFILE="quick-connect"
        ;;
    esac
    AUTO_PORT_FORWARD_EXIT="0"
    return 0
  fi

  if is_blind_exit_role; then
    if [[ "${DEFAULT_LAUNCH_PROFILE}" != "quick-exit-node" ]]; then
      print_warn "blind_exit role enforces default launch profile 'quick-exit-node'."
      DEFAULT_LAUNCH_PROFILE="quick-exit-node"
    fi
    EXIT_CHAIN_HOPS="1"
    EXIT_CHAIN_ENTRY_NODE_ID=""
    EXIT_CHAIN_FINAL_NODE_ID=""
    AUTO_LAUNCH_ON_START="1"
    AUTO_LAUNCH_EXIT_NODE_ID=""
    AUTO_LAUNCH_LAN_MODE="off"
    FAIL_CLOSED_SSH_ALLOW="0"
    FAIL_CLOSED_SSH_ALLOW_CIDRS=""
  fi
}

is_allowed_config_key() {
  local key="$1"
  case "${key}" in
    SOCKET_PATH|STATE_PATH|TRUST_EVIDENCE_PATH|TRUST_VERIFIER_KEY_PATH|TRUST_WATERMARK_PATH|AUTO_TUNNEL_ENFORCE|AUTO_TUNNEL_BUNDLE_PATH|AUTO_TUNNEL_VERIFIER_KEY_PATH|AUTO_TUNNEL_WATERMARK_PATH|AUTO_TUNNEL_MAX_AGE_SECS|TRAVERSAL_BUNDLE_PATH|TRAVERSAL_VERIFIER_KEY_PATH|TRAVERSAL_WATERMARK_PATH|TRAVERSAL_MAX_AGE_SECS|WG_INTERFACE|WG_LISTEN_PORT|AUTO_PORT_FORWARD_EXIT|AUTO_PORT_FORWARD_LEASE_SECS|WG_PRIVATE_KEY_PATH|WG_ENCRYPTED_PRIVATE_KEY_PATH|WG_KEY_PASSPHRASE_PATH|WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH|SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH|WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT|WG_PUBLIC_KEY_PATH|EGRESS_INTERFACE|MEMBERSHIP_SNAPSHOT_PATH|MEMBERSHIP_LOG_PATH|MEMBERSHIP_WATERMARK_PATH|MEMBERSHIP_OWNER_SIGNING_KEY_PATH|BACKEND_MODE|DATAPLANE_MODE|PRIVILEGED_HELPER_SOCKET_PATH|PRIVILEGED_HELPER_TIMEOUT_MS|RECONCILE_INTERVAL_MS|MAX_RECONCILE_FAILURES|FAIL_CLOSED_SSH_ALLOW|FAIL_CLOSED_SSH_ALLOW_CIDRS|TRUST_SIGNER_KEY_PATH|AUTO_REFRESH_TRUST|DEVICE_NODE_ID|SETUP_COMPLETE|NODE_ROLE|MANUAL_PEER_OVERRIDE|MANUAL_PEER_AUDIT_LOG|DEFAULT_LAUNCH_PROFILE|AUTO_LAUNCH_ON_START|AUTO_LAUNCH_EXIT_NODE_ID|AUTO_LAUNCH_LAN_MODE|EXIT_CHAIN_HOPS|EXIT_CHAIN_ENTRY_NODE_ID|EXIT_CHAIN_FINAL_NODE_ID|HOST_PROFILE)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

normalize_config_value() {
  local value="$1"
  if [[ "${value}" == "''" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "${value}" =~ ^\'(.*)\'$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return
  fi
  printf '%s' "${value}"
}

validate_config_file_security() {
  [[ -f "${CONFIG_FILE}" ]] || return 0

  if [[ -L "${CONFIG_FILE}" ]]; then
    print_err "Refusing to load symlink config file: ${CONFIG_FILE}"
    exit 1
  fi

  local owner_uid=""
  if stat -c '%u' "${CONFIG_FILE}" >/dev/null 2>&1; then
    owner_uid="$(stat -c '%u' "${CONFIG_FILE}")"
  elif stat -f '%u' "${CONFIG_FILE}" >/dev/null 2>&1; then
    owner_uid="$(stat -f '%u' "${CONFIG_FILE}")"
  fi
  if [[ -n "${owner_uid}" ]]; then
    local current_uid
    current_uid="$(id -u)"
    if [[ "${owner_uid}" != "${current_uid}" && "${owner_uid}" != "0" ]]; then
      print_err "Config file owner is not trusted (${CONFIG_FILE}, uid=${owner_uid})."
      exit 1
    fi
  fi

  local mode=""
  if stat -c '%a' "${CONFIG_FILE}" >/dev/null 2>&1; then
    mode="$(stat -c '%a' "${CONFIG_FILE}")"
  elif stat -f '%OLp' "${CONFIG_FILE}" >/dev/null 2>&1; then
    mode="$(stat -f '%OLp' "${CONFIG_FILE}")"
    mode="${mode#0}"
  fi
  if [[ "${mode}" =~ ^[0-9]{3,4}$ ]]; then
    local mode3="${mode: -3}"
    local group_digit="${mode3:1:1}"
    local other_digit="${mode3:2:1}"
    if (( (10#${group_digit} & 2) != 0 || (10#${other_digit} & 2) != 0 )); then
      print_err "Config file must not be group/world writable: ${CONFIG_FILE} (mode ${mode3})."
      exit 1
    fi
  fi
}

load_config_file() {
  [[ -f "${CONFIG_FILE}" ]] || return 0
  validate_config_file_security
  CONFIG_LOADED_FROM_FILE="1"

  local line
  local key
  local raw_value
  local value
  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]] && continue
    if [[ ! "${line}" =~ ^([A-Z0-9_]+)=(.*)$ ]]; then
      print_warn "Ignoring malformed config line in ${CONFIG_FILE}."
      continue
    fi
    key="${BASH_REMATCH[1]}"
    raw_value="${BASH_REMATCH[2]}"
    if ! is_allowed_config_key "${key}"; then
      print_warn "Ignoring unknown config key '${key}' in ${CONFIG_FILE}."
      continue
    fi
    value="$(normalize_config_value "${raw_value}")"
    value="${value%$'\r'}"
    printf -v "${key}" '%s' "${value}"
  done <"${CONFIG_FILE}"
}

validate_loaded_config_or_die() {
  [[ "${CONFIG_LOADED_FROM_FILE}" == "1" ]] || return 0

  if [[ -n "${NODE_ROLE}" ]]; then
    case "${NODE_ROLE}" in
      admin|client|blind_exit) ;;
      *)
        print_err "Invalid persisted NODE_ROLE='${NODE_ROLE}' in ${CONFIG_FILE}."
        print_info "Set NODE_ROLE to admin, client, or blind_exit."
        exit 1
        ;;
    esac
  fi

  if [[ "${NODE_ROLE}" == "blind_exit" ]] && ! is_linux_host; then
    print_err "Invalid persisted NODE_ROLE='blind_exit' on non-Linux host."
    print_info "Set NODE_ROLE=client in ${CONFIG_FILE} on macOS hosts."
    exit 1
  fi

  if ! is_valid_exit_chain_hops "${EXIT_CHAIN_HOPS}"; then
    print_err "Invalid persisted EXIT_CHAIN_HOPS='${EXIT_CHAIN_HOPS}' in ${CONFIG_FILE}."
    print_info "Allowed values: 1 or 2."
    exit 1
  fi
  if [[ -n "${EXIT_CHAIN_ENTRY_NODE_ID}" ]] && ! is_valid_node_id_value "${EXIT_CHAIN_ENTRY_NODE_ID}"; then
    print_err "Invalid persisted EXIT_CHAIN_ENTRY_NODE_ID='${EXIT_CHAIN_ENTRY_NODE_ID}'."
    exit 1
  fi
  if [[ -n "${EXIT_CHAIN_FINAL_NODE_ID}" ]] && ! is_valid_node_id_value "${EXIT_CHAIN_FINAL_NODE_ID}"; then
    print_err "Invalid persisted EXIT_CHAIN_FINAL_NODE_ID='${EXIT_CHAIN_FINAL_NODE_ID}'."
    exit 1
  fi

  if ! is_valid_launch_profile "${DEFAULT_LAUNCH_PROFILE}"; then
    print_err "Invalid persisted DEFAULT_LAUNCH_PROFILE='${DEFAULT_LAUNCH_PROFILE}' in ${CONFIG_FILE}."
    exit 1
  fi
  if [[ "${AUTO_LAUNCH_ON_START}" != "0" && "${AUTO_LAUNCH_ON_START}" != "1" ]]; then
    print_err "Invalid persisted AUTO_LAUNCH_ON_START='${AUTO_LAUNCH_ON_START}' in ${CONFIG_FILE}."
    exit 1
  fi
  if ! is_valid_lan_mode "${AUTO_LAUNCH_LAN_MODE}"; then
    print_err "Invalid persisted AUTO_LAUNCH_LAN_MODE='${AUTO_LAUNCH_LAN_MODE}' in ${CONFIG_FILE}."
    print_info "Allowed values: skip, on, off."
    exit 1
  fi
  if [[ "${MANUAL_PEER_OVERRIDE}" != "0" ]]; then
    print_err "Invalid persisted MANUAL_PEER_OVERRIDE='${MANUAL_PEER_OVERRIDE}' in ${CONFIG_FILE}."
    print_info "Manual peer break-glass is removed. Set MANUAL_PEER_OVERRIDE=0."
    exit 1
  fi
}

enforce_backend_mode() {
  local expected="linux-wireguard"
  if is_macos_host; then
    expected="macos-wireguard"
  fi
  if [[ "${BACKEND_MODE}" != "${expected}" ]]; then
    print_err "Invalid backend '${BACKEND_MODE}' for host profile ${HOST_PROFILE}; expected '${expected}'."
    exit 1
  fi
}

enforce_auto_tunnel_policy() {
  if [[ "${AUTO_TUNNEL_ENFORCE}" != "1" ]]; then
    print_warn "Unsigned/manual tunnel assignment is not allowed by default; forcing AUTO_TUNNEL_ENFORCE=1."
  fi
  AUTO_TUNNEL_ENFORCE="1"
}

enforce_fail_closed_ssh_policy() {
  if [[ "${FAIL_CLOSED_SSH_ALLOW}" != "1" ]]; then
    FAIL_CLOSED_SSH_ALLOW="0"
    FAIL_CLOSED_SSH_ALLOW_CIDRS=""
    return
  fi

  if [[ -z "${FAIL_CLOSED_SSH_ALLOW_CIDRS// }" ]]; then
    print_err "FAIL_CLOSED_SSH_ALLOW_CIDRS is required when FAIL_CLOSED_SSH_ALLOW=1."
    exit 1
  fi
}

enforce_wg_listen_port_policy() {
  if ! [[ "${WG_LISTEN_PORT}" =~ ^[0-9]+$ ]] || (( WG_LISTEN_PORT < 1 || WG_LISTEN_PORT > 65535 )); then
    print_err "Invalid WG_LISTEN_PORT '${WG_LISTEN_PORT}'. Expected numeric range 1..65535."
    exit 1
  fi
}

enforce_auto_port_forward_policy() {
  if [[ "${AUTO_PORT_FORWARD_EXIT}" != "1" ]]; then
    AUTO_PORT_FORWARD_EXIT="0"
  fi
  if ! [[ "${AUTO_PORT_FORWARD_LEASE_SECS}" =~ ^[0-9]+$ ]] || (( AUTO_PORT_FORWARD_LEASE_SECS < 60 )); then
    print_err "Invalid AUTO_PORT_FORWARD_LEASE_SECS '${AUTO_PORT_FORWARD_LEASE_SECS}'. Expected numeric value >= 60."
    exit 1
  fi
  if ! is_linux_host && [[ "${AUTO_PORT_FORWARD_EXIT}" == "1" ]]; then
    print_warn "Auto port-forward is currently supported only on Linux. Forcing AUTO_PORT_FORWARD_EXIT=0."
    AUTO_PORT_FORWARD_EXIT="0"
  fi
  if ! is_admin_role && ! is_blind_exit_role && [[ "${AUTO_PORT_FORWARD_EXIT}" == "1" ]]; then
    print_warn "Auto port-forward applies only to exit-serving roles. Forcing AUTO_PORT_FORWARD_EXIT=0 for role '${NODE_ROLE}'."
    AUTO_PORT_FORWARD_EXIT="0"
  fi
}

manual_peer_override_enabled() {
  return 1
}

require_manual_peer_override_authorization() {
  local action="$1"
  print_err "Manual peer break-glass operation is disabled: ${action}"
  print_info "Use signed assignment workflows only (rustynet assignment issue + refresh-assignment)."
  return 1
}

run_root() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  else
    if [[ -t 0 && -t 1 ]]; then
      sudo "$@"
      return
    fi

    if sudo -n true >/dev/null 2>&1; then
      sudo -n "$@"
      return
    fi

    print_err "A TTY sudo prompt is unavailable and cached sudo credentials were not found."
    print_info "Run 'sudo -v' in an interactive shell, then rerun this action."
    return 1
  fi
}

run_rustynet_ops_with_scope() {
  if ! command -v rustynet >/dev/null 2>&1; then
    return 127
  fi
  if is_linux_host; then
    run_root rustynet ops "$@"
  else
    rustynet ops "$@"
  fi
}

secure_remove_file_with_scope() {
  local target="$1"
  if [[ ! -f "${target}" && ! -L "${target}" ]]; then
    return 0
  fi

  if ! run_rustynet_ops_with_scope secure-remove --path "${target}" >/dev/null 2>&1; then
    print_err "Secure remove failed for ${target}; cleanup is fail-closed."
    return 1
  fi
  return 0
}

ensure_signing_passphrase_material() {
  if ! command -v rustynet >/dev/null 2>&1; then
    print_err "rustynet CLI is required for signing passphrase custody operations."
    return 1
  fi

  local rust_ops_status=1
  if is_linux_host; then
    run_root env \
      RUSTYNET_HOST_PROFILE="${HOST_PROFILE}" \
      RUSTYNET_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB="${SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" \
      RUSTYNET_MEMBERSHIP_OWNER_SIGNING_KEY="${MEMBERSHIP_OWNER_SIGNING_KEY_PATH}" \
      RUSTYNET_TRUST_SIGNER_KEY="${TRUST_SIGNER_KEY_PATH}" \
      RUSTYNET_ASSIGNMENT_SIGNING_SECRET="/etc/rustynet/assignment.signing.secret" \
      RUSTYNET_MACOS_PASSPHRASE_KEYCHAIN_SERVICE="${MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}" \
      RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT="${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}" \
      rustynet ops ensure-signing-passphrase-material >/dev/null 2>&1 || rust_ops_status=$?
  elif is_macos_host; then
    env \
      RUSTYNET_HOST_PROFILE="${HOST_PROFILE}" \
      RUSTYNET_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB="${SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" \
      RUSTYNET_MEMBERSHIP_OWNER_SIGNING_KEY="${MEMBERSHIP_OWNER_SIGNING_KEY_PATH}" \
      RUSTYNET_TRUST_SIGNER_KEY="${TRUST_SIGNER_KEY_PATH}" \
      RUSTYNET_ASSIGNMENT_SIGNING_SECRET="/etc/rustynet/assignment.signing.secret" \
      RUSTYNET_MACOS_PASSPHRASE_KEYCHAIN_SERVICE="${MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}" \
      RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT="${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}" \
      rustynet ops ensure-signing-passphrase-material >/dev/null 2>&1 || rust_ops_status=$?
  else
    print_err "Unsupported host profile for signing passphrase materialization: ${HOST_PROFILE}"
    return 1
  fi

  if [[ "${rust_ops_status}" != "0" ]]; then
    print_err "Rust-backed signing passphrase ensure flow failed; setup is fail-closed."
    return 1
  fi
  return 0
}

materialize_signing_passphrase_file() {
  local __out_var="$1"
  if ! command -v rustynet >/dev/null 2>&1; then
    print_err "rustynet CLI is required for signing passphrase materialization."
    return 1
  fi
  local tmp_passphrase
  tmp_passphrase="$(mktemp)"
  chmod 600 "${tmp_passphrase}" || {
    print_err "Failed to set secure mode on temporary signing passphrase file."
    secure_remove_file_with_scope "${tmp_passphrase}" || true
    return 1
  }

  local rust_ops_status=1
  if is_linux_host; then
    run_root env \
      RUSTYNET_HOST_PROFILE="${HOST_PROFILE}" \
      RUSTYNET_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB="${SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" \
      RUSTYNET_MEMBERSHIP_OWNER_SIGNING_KEY="${MEMBERSHIP_OWNER_SIGNING_KEY_PATH}" \
      RUSTYNET_TRUST_SIGNER_KEY="${TRUST_SIGNER_KEY_PATH}" \
      RUSTYNET_ASSIGNMENT_SIGNING_SECRET="/etc/rustynet/assignment.signing.secret" \
      RUSTYNET_MACOS_PASSPHRASE_KEYCHAIN_SERVICE="${MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}" \
      RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT="${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}" \
      rustynet ops materialize-signing-passphrase --output "${tmp_passphrase}" >/dev/null 2>&1 || rust_ops_status=$?
  elif is_macos_host; then
    env \
      RUSTYNET_HOST_PROFILE="${HOST_PROFILE}" \
      RUSTYNET_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB="${SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" \
      RUSTYNET_MEMBERSHIP_OWNER_SIGNING_KEY="${MEMBERSHIP_OWNER_SIGNING_KEY_PATH}" \
      RUSTYNET_TRUST_SIGNER_KEY="${TRUST_SIGNER_KEY_PATH}" \
      RUSTYNET_ASSIGNMENT_SIGNING_SECRET="/etc/rustynet/assignment.signing.secret" \
      RUSTYNET_MACOS_PASSPHRASE_KEYCHAIN_SERVICE="${MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}" \
      RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT="${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}" \
      rustynet ops materialize-signing-passphrase --output "${tmp_passphrase}" >/dev/null 2>&1 || rust_ops_status=$?
  else
    secure_remove_file_with_scope "${tmp_passphrase}" || true
    print_err "Unsupported host profile for signing passphrase materialization: ${HOST_PROFILE}"
    return 1
  fi

  if [[ "${rust_ops_status}" != "0" ]]; then
    secure_remove_file_with_scope "${tmp_passphrase}" || true
    print_err "Rust-backed signing passphrase materialization failed; setup is fail-closed."
    return 1
  fi

  if is_linux_host; then
    run_root chown root:root "${tmp_passphrase}" >/dev/null 2>&1 || {
      secure_remove_file_with_scope "${tmp_passphrase}" || true
      print_err "Failed to set signing passphrase file owner to root:root."
      return 1
    }
    run_root chmod 600 "${tmp_passphrase}" >/dev/null 2>&1 || {
      secure_remove_file_with_scope "${tmp_passphrase}" || true
      print_err "Failed to set signing passphrase file mode to 0600."
      return 1
    }
  else
    chmod 600 "${tmp_passphrase}" >/dev/null 2>&1 || {
      secure_remove_file_with_scope "${tmp_passphrase}" || true
      print_err "Failed to set signing passphrase file mode to 0600."
      return 1
    }
  fi

  printf -v "${__out_var}" '%s' "${tmp_passphrase}"
  return 0
}

prompt_default() {
  local __var_name="$1"
  local __prompt="$2"
  local __default="$3"
  local __value
  read -r -p "${__prompt} [${__default}]: " __value
  __value="${__value:-${__default}}"
  printf -v "${__var_name}" '%s' "${__value}"
}

prompt_yes_no() {
  local prompt="$1"
  local default="${2:-y}"
  local value
  local options="y/N"
  if [[ "${default}" == "y" ]]; then
    options="Y/n"
  fi
  read -r -p "${prompt} (${options}): " value
  value="${value:-${default}}"
  [[ "${value}" =~ ^[Yy]$ ]]
}

is_valid_launch_profile() {
  case "$1" in
    menu|quick-connect|quick-exit-node|quick-hybrid) return 0 ;;
    *) return 1 ;;
  esac
}

is_valid_lan_mode() {
  case "$1" in
    skip|on|off) return 0 ;;
    *) return 1 ;;
  esac
}

is_valid_exit_chain_hops() {
  case "$1" in
    1|2) return 0 ;;
    *) return 1 ;;
  esac
}

sanitize_exit_chain_defaults() {
  if ! is_valid_exit_chain_hops "${EXIT_CHAIN_HOPS}"; then
    print_warn "Invalid EXIT_CHAIN_HOPS='${EXIT_CHAIN_HOPS}', reverting to '1'."
    EXIT_CHAIN_HOPS="1"
  fi
  if [[ -n "${EXIT_CHAIN_ENTRY_NODE_ID}" ]] && ! is_valid_node_id_value "${EXIT_CHAIN_ENTRY_NODE_ID}"; then
    print_warn "Invalid EXIT_CHAIN_ENTRY_NODE_ID='${EXIT_CHAIN_ENTRY_NODE_ID}', clearing."
    EXIT_CHAIN_ENTRY_NODE_ID=""
  fi
  if [[ -n "${EXIT_CHAIN_FINAL_NODE_ID}" ]] && ! is_valid_node_id_value "${EXIT_CHAIN_FINAL_NODE_ID}"; then
    print_warn "Invalid EXIT_CHAIN_FINAL_NODE_ID='${EXIT_CHAIN_FINAL_NODE_ID}', clearing."
    EXIT_CHAIN_FINAL_NODE_ID=""
  fi
  if [[ "${EXIT_CHAIN_HOPS}" != "2" ]]; then
    EXIT_CHAIN_FINAL_NODE_ID=""
  fi
  if is_blind_exit_role; then
    EXIT_CHAIN_HOPS="1"
    EXIT_CHAIN_ENTRY_NODE_ID=""
    EXIT_CHAIN_FINAL_NODE_ID=""
  fi
}

sanitize_launch_defaults() {
  enforce_role_policy_defaults
  sanitize_exit_chain_defaults
  if ! is_valid_launch_profile "${DEFAULT_LAUNCH_PROFILE}"; then
    print_warn "Invalid DEFAULT_LAUNCH_PROFILE='${DEFAULT_LAUNCH_PROFILE}', reverting to 'menu'."
    DEFAULT_LAUNCH_PROFILE="menu"
  fi
  if [[ "${AUTO_LAUNCH_ON_START}" != "1" ]]; then
    AUTO_LAUNCH_ON_START="0"
  fi
  if ! is_valid_lan_mode "${AUTO_LAUNCH_LAN_MODE}"; then
    print_warn "Invalid AUTO_LAUNCH_LAN_MODE='${AUTO_LAUNCH_LAN_MODE}', reverting to 'skip'."
    AUTO_LAUNCH_LAN_MODE="skip"
  fi
}

print_start_help() {
  cat <<EOF
Rustynet startup options:
  ./start.sh
    Interactive menu mode.
    Exit-node selection supports 1-hop and 2-hop chain prompts.

  ./start.sh --profile <menu|quick-connect|quick-exit-node|quick-hybrid>
    Apply a launch profile once. Non-menu profiles apply and exit.
    blind_exit role accepts only 'menu' or 'quick-exit-node'.

  ./start.sh --auto
    Apply saved default launch profile once and exit.

  Optional modifiers:
    --exit-node-id <node-id>   Override configured exit node id for this run.
    --lan <skip|on|off>        Override configured LAN mode for this run.
    --help                     Show this help.
EOF
}

parse_start_arguments() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --profile)
        if [[ "$#" -lt 2 ]]; then
          print_err "--profile requires a value."
          exit 1
        fi
        REQUESTED_LAUNCH_PROFILE="$2"
        shift 2
        ;;
      --auto)
        REQUESTED_LAUNCH_PROFILE="auto"
        AUTO_ONLY_LAUNCH="1"
        shift
        ;;
      --exit-node-id)
        if [[ "$#" -lt 2 ]]; then
          print_err "--exit-node-id requires a value."
          exit 1
        fi
        REQUESTED_EXIT_NODE_ID="$2"
        shift 2
        ;;
      --lan)
        if [[ "$#" -lt 2 ]]; then
          print_err "--lan requires a value (skip|on|off)."
          exit 1
        fi
        REQUESTED_LAN_MODE="$2"
        shift 2
        ;;
      --help|-h)
        print_start_help
        exit 0
        ;;
      *)
        print_err "Unknown argument: $1"
        print_start_help
        exit 1
        ;;
    esac
  done

  if [[ -n "${REQUESTED_LAUNCH_PROFILE}" && "${REQUESTED_LAUNCH_PROFILE}" != "auto" ]]; then
    if ! is_valid_launch_profile "${REQUESTED_LAUNCH_PROFILE}"; then
      print_err "Invalid --profile value '${REQUESTED_LAUNCH_PROFILE}'."
      exit 1
    fi
    if [[ "${REQUESTED_LAUNCH_PROFILE}" != "menu" ]]; then
      AUTO_ONLY_LAUNCH="1"
    fi
  fi

  if [[ -n "${REQUESTED_LAN_MODE}" ]] && ! is_valid_lan_mode "${REQUESTED_LAN_MODE}"; then
    print_err "Invalid --lan value '${REQUESTED_LAN_MODE}'. Expected skip|on|off."
    exit 1
  fi
}

save_config() {
  {
    printf 'SOCKET_PATH=%s\n' "${SOCKET_PATH}"
    printf 'STATE_PATH=%s\n' "${STATE_PATH}"
    printf 'TRUST_EVIDENCE_PATH=%s\n' "${TRUST_EVIDENCE_PATH}"
    printf 'TRUST_VERIFIER_KEY_PATH=%s\n' "${TRUST_VERIFIER_KEY_PATH}"
    printf 'TRUST_WATERMARK_PATH=%s\n' "${TRUST_WATERMARK_PATH}"
    printf 'AUTO_TUNNEL_ENFORCE=%s\n' "${AUTO_TUNNEL_ENFORCE}"
    printf 'AUTO_TUNNEL_BUNDLE_PATH=%s\n' "${AUTO_TUNNEL_BUNDLE_PATH}"
    printf 'AUTO_TUNNEL_VERIFIER_KEY_PATH=%s\n' "${AUTO_TUNNEL_VERIFIER_KEY_PATH}"
    printf 'AUTO_TUNNEL_WATERMARK_PATH=%s\n' "${AUTO_TUNNEL_WATERMARK_PATH}"
    printf 'AUTO_TUNNEL_MAX_AGE_SECS=%s\n' "${AUTO_TUNNEL_MAX_AGE_SECS}"
    printf 'TRAVERSAL_BUNDLE_PATH=%s\n' "${TRAVERSAL_BUNDLE_PATH}"
    printf 'TRAVERSAL_VERIFIER_KEY_PATH=%s\n' "${TRAVERSAL_VERIFIER_KEY_PATH}"
    printf 'TRAVERSAL_WATERMARK_PATH=%s\n' "${TRAVERSAL_WATERMARK_PATH}"
    printf 'TRAVERSAL_MAX_AGE_SECS=%s\n' "${TRAVERSAL_MAX_AGE_SECS}"
    printf 'WG_INTERFACE=%s\n' "${WG_INTERFACE}"
    printf 'WG_LISTEN_PORT=%s\n' "${WG_LISTEN_PORT}"
    printf 'AUTO_PORT_FORWARD_EXIT=%s\n' "${AUTO_PORT_FORWARD_EXIT}"
    printf 'AUTO_PORT_FORWARD_LEASE_SECS=%s\n' "${AUTO_PORT_FORWARD_LEASE_SECS}"
    printf 'WG_PRIVATE_KEY_PATH=%s\n' "${WG_PRIVATE_KEY_PATH}"
    printf 'WG_ENCRYPTED_PRIVATE_KEY_PATH=%s\n' "${WG_ENCRYPTED_PRIVATE_KEY_PATH}"
    printf 'WG_KEY_PASSPHRASE_PATH=%s\n' "${WG_KEY_PASSPHRASE_PATH}"
    printf 'WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH=%s\n' "${WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}"
    printf 'SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH=%s\n' "${SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}"
    printf 'WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT=%s\n' "${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}"
    printf 'WG_PUBLIC_KEY_PATH=%s\n' "${WG_PUBLIC_KEY_PATH}"
    printf 'EGRESS_INTERFACE=%s\n' "${EGRESS_INTERFACE}"
    printf 'MEMBERSHIP_SNAPSHOT_PATH=%s\n' "${MEMBERSHIP_SNAPSHOT_PATH}"
    printf 'MEMBERSHIP_LOG_PATH=%s\n' "${MEMBERSHIP_LOG_PATH}"
    printf 'MEMBERSHIP_WATERMARK_PATH=%s\n' "${MEMBERSHIP_WATERMARK_PATH}"
    printf 'MEMBERSHIP_OWNER_SIGNING_KEY_PATH=%s\n' "${MEMBERSHIP_OWNER_SIGNING_KEY_PATH}"
    printf 'BACKEND_MODE=%s\n' "${BACKEND_MODE}"
    printf 'DATAPLANE_MODE=%s\n' "${DATAPLANE_MODE}"
    printf 'PRIVILEGED_HELPER_SOCKET_PATH=%s\n' "${PRIVILEGED_HELPER_SOCKET_PATH}"
    printf 'PRIVILEGED_HELPER_TIMEOUT_MS=%s\n' "${PRIVILEGED_HELPER_TIMEOUT_MS}"
    printf 'RECONCILE_INTERVAL_MS=%s\n' "${RECONCILE_INTERVAL_MS}"
    printf 'MAX_RECONCILE_FAILURES=%s\n' "${MAX_RECONCILE_FAILURES}"
    printf 'FAIL_CLOSED_SSH_ALLOW=%s\n' "${FAIL_CLOSED_SSH_ALLOW}"
    printf 'FAIL_CLOSED_SSH_ALLOW_CIDRS=%s\n' "${FAIL_CLOSED_SSH_ALLOW_CIDRS}"
    printf 'TRUST_SIGNER_KEY_PATH=%s\n' "${TRUST_SIGNER_KEY_PATH}"
    printf 'AUTO_REFRESH_TRUST=%s\n' "${AUTO_REFRESH_TRUST}"
    printf 'DEVICE_NODE_ID=%s\n' "${DEVICE_NODE_ID}"
    printf 'HOST_PROFILE=%s\n' "${HOST_PROFILE}"
    printf 'SETUP_COMPLETE=%s\n' "${SETUP_COMPLETE}"
    printf 'NODE_ROLE=%s\n' "${NODE_ROLE}"
    printf 'MANUAL_PEER_OVERRIDE=%s\n' "${MANUAL_PEER_OVERRIDE}"
    printf 'MANUAL_PEER_AUDIT_LOG=%s\n' "${MANUAL_PEER_AUDIT_LOG}"
    printf 'DEFAULT_LAUNCH_PROFILE=%s\n' "${DEFAULT_LAUNCH_PROFILE}"
    printf 'AUTO_LAUNCH_ON_START=%s\n' "${AUTO_LAUNCH_ON_START}"
    printf 'AUTO_LAUNCH_EXIT_NODE_ID=%s\n' "${AUTO_LAUNCH_EXIT_NODE_ID}"
    printf 'AUTO_LAUNCH_LAN_MODE=%s\n' "${AUTO_LAUNCH_LAN_MODE}"
    printf 'EXIT_CHAIN_HOPS=%s\n' "${EXIT_CHAIN_HOPS}"
    printf 'EXIT_CHAIN_ENTRY_NODE_ID=%s\n' "${EXIT_CHAIN_ENTRY_NODE_ID}"
    printf 'EXIT_CHAIN_FINAL_NODE_ID=%s\n' "${EXIT_CHAIN_FINAL_NODE_ID}"
  } >"${CONFIG_FILE}"
  chmod 600 "${CONFIG_FILE}"
}

detect_default_egress() {
  if is_linux_host; then
    ip -o -4 route show to default 2>/dev/null | awk 'NR==1 { print $5 }'
    return
  fi
  if is_macos_host; then
    route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}'
    return
  fi
}

effective_selected_exit_node_for_egress() {
  if [[ "${EXIT_CHAIN_HOPS}" == "2" && "${EXIT_CHAIN_ENTRY_NODE_ID}" == "${DEVICE_NODE_ID}" ]]; then
    printf '%s' "${EXIT_CHAIN_FINAL_NODE_ID}"
    return
  fi
  printf '%s' "${EXIT_CHAIN_ENTRY_NODE_ID}"
}

endpoint_host_from_value() {
  local endpoint="$1"
  if [[ "${endpoint}" =~ ^\[([0-9A-Fa-f:.]+)\]:[0-9]+$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "${endpoint}" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):[0-9]+$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

route_interface_for_host() {
  local host="$1"
  if [[ -z "${host}" ]]; then
    return 1
  fi
  if [[ "${host}" == *:* ]]; then
    ip -o -6 route get "${host}" 2>/dev/null | awk 'NR==1 { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }'
    return
  fi
  ip -o -4 route get "${host}" 2>/dev/null | awk 'NR==1 { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }'
}

derive_selected_exit_route_egress_interface() {
  local selected_exit record endpoint endpoint_host derived
  selected_exit="$(effective_selected_exit_node_for_egress)"
  if [[ -z "${selected_exit}" ]]; then
    return 1
  fi
  record="$(find_peer_record_by_node_id "${selected_exit}" || true)"
  if [[ -z "${record}" ]]; then
    return 1
  fi
  IFS='|' read -r _name _node_id _public_key endpoint _cidr _role _rest <<<"${record}"
  if [[ -z "${endpoint}" ]]; then
    return 1
  fi
  if ! endpoint_host="$(endpoint_host_from_value "${endpoint}")"; then
    return 1
  fi
  derived="$(route_interface_for_host "${endpoint_host}" || true)"
  if [[ -z "${derived}" ]]; then
    return 1
  fi
  printf '%s' "${derived}"
}

sync_egress_interface_with_selected_exit_route() {
  local selected_exit derived detected_egress
  if ! is_linux_host; then
    return 0
  fi

  selected_exit="$(effective_selected_exit_node_for_egress)"
  if [[ -n "${selected_exit}" ]]; then
    derived="$(derive_selected_exit_route_egress_interface || true)"
    if [[ -z "${derived}" ]]; then
      print_err "Unable to derive egress interface for selected exit node '${selected_exit}'."
      print_info "Verify the selected exit endpoint is present and routable in local peer records."
      return 1
    fi
    if [[ "${EGRESS_INTERFACE}" != "${derived}" ]]; then
      if [[ -n "${EGRESS_INTERFACE}" ]]; then
        print_warn "Overriding configured egress interface '${EGRESS_INTERFACE}' with route-derived '${derived}' for selected exit '${selected_exit}'."
      else
        print_info "Setting egress interface to route-derived '${derived}' for selected exit '${selected_exit}'."
      fi
      EGRESS_INTERFACE="${derived}"
    fi
    return 0
  fi

  if [[ -z "${EGRESS_INTERFACE}" ]]; then
    detected_egress="$(detect_default_egress)"
    if [[ -z "${detected_egress}" ]]; then
      print_err "Unable to detect default egress interface."
      return 1
    fi
    EGRESS_INTERFACE="${detected_egress}"
  fi
  return 0
}

package_manager() {
  if is_macos_host; then
    add_macos_homebrew_to_path
    if command -v brew >/dev/null 2>&1; then
      echo brew
    else
      echo unknown
    fi
    return
  fi
  if command -v apt-get >/dev/null 2>&1; then
    echo apt
    return
  fi
  if command -v dnf >/dev/null 2>&1; then
    echo dnf
    return
  fi
  if command -v pacman >/dev/null 2>&1; then
    echo pacman
    return
  fi
  if command -v zypper >/dev/null 2>&1; then
    echo zypper
    return
  fi
  echo unknown
}

add_macos_homebrew_to_path() {
  if ! is_macos_host; then
    return 0
  fi
  if [[ -x /opt/homebrew/bin/brew ]]; then
    export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:${PATH}"
    return 0
  fi
  if [[ -x /usr/local/bin/brew ]]; then
    export PATH="/usr/local/bin:/usr/local/sbin:${PATH}"
    return 0
  fi
}

is_macos_admin_user() {
  if ! is_macos_host; then
    return 1
  fi
  id -Gn 2>/dev/null | tr ' ' '\n' | grep -qx 'admin'
}

ensure_macos_command_line_tools() {
  if ! is_macos_host; then
    return 0
  fi
  if xcode-select -p >/dev/null 2>&1; then
    return 0
  fi

  print_warn "Xcode Command Line Tools are required on macOS and are not installed."
  if ! prompt_yes_no "Install Command Line Tools now (softwareupdate)?" "y"; then
    print_err "Cannot continue without Xcode Command Line Tools."
    exit 1
  fi

  if ! command -v softwareupdate >/dev/null 2>&1; then
    print_err "softwareupdate is unavailable; cannot automate Command Line Tools install."
    print_info "Run 'xcode-select --install' and rerun ./start.sh."
    exit 1
  fi

  local clt_label=""
  clt_label="$(softwareupdate --list 2>/dev/null | sed -n 's/^\\* Label: //p' | grep '^Command Line Tools for Xcode' | tail -n 1)"
  if [[ -z "${clt_label}" ]]; then
    print_err "No Command Line Tools update label detected via softwareupdate."
    print_info "Install with 'xcode-select --install' and rerun ./start.sh."
    exit 1
  fi

  print_info "Installing '${clt_label}' (this may take several minutes)."
  run_root softwareupdate --install "${clt_label}" --verbose
  if ! xcode-select -p >/dev/null 2>&1; then
    print_err "Command Line Tools installation did not complete successfully."
    exit 1
  fi
}

ensure_macos_homebrew() {
  if ! is_macos_host; then
    return 0
  fi

  add_macos_homebrew_to_path
  if command -v brew >/dev/null 2>&1; then
    return 0
  fi

  print_err "Homebrew is required on macOS for managed dependency installation."
  print_info "Install Homebrew from https://brew.sh using your approved process, then rerun ./start.sh."
  exit 1
}

map_package() {
  local pm="$1"
  local cmd="$2"
  case "${cmd}" in
    wg)
      if [[ "${pm}" == "brew" ]]; then
        echo "wireguard-tools"
      else
        echo "wireguard-tools"
      fi
      ;;
    wireguard-go)
      if [[ "${pm}" == "brew" ]]; then
        echo "wireguard-go"
      else
        echo ""
      fi
      ;;
    ip)
      if [[ "${pm}" == "dnf" ]]; then
        echo "iproute"
      elif [[ "${pm}" == "brew" ]]; then
        echo ""
      else
        echo "iproute2"
      fi
      ;;
    nft)
      if [[ "${pm}" == "brew" ]]; then
        echo ""
      else
        echo "nftables"
      fi
      ;;
    openssl)
      if [[ "${pm}" == "brew" ]]; then
        echo "openssl@3"
      else
        echo "openssl"
      fi
      ;;
    systemctl)
      if [[ "${pm}" == "brew" ]]; then
        echo ""
      else
        echo "systemd"
      fi
      ;;
    xxd)
      if [[ "${pm}" == "brew" ]]; then
        echo "vim"
      elif [[ "${pm}" == "apt" ]]; then
        echo "xxd"
      else
        echo "vim-common"
      fi
      ;;
    rg) echo "ripgrep" ;;
    curl) echo "curl" ;;
    cargo)
      if [[ "${pm}" == "apt" ]]; then
        echo "cargo"
      elif [[ "${pm}" == "dnf" ]]; then
        echo "cargo"
      elif [[ "${pm}" == "brew" ]]; then
        echo "rust"
      elif [[ "${pm}" == "pacman" ]]; then
        echo "rust"
      else
        echo "cargo"
      fi
      ;;
    rustc)
      if [[ "${pm}" == "brew" ]]; then
        echo "rust"
      elif [[ "${pm}" == "pacman" ]]; then
        echo "rust"
      else
        echo "rustc"
      fi
      ;;
    *) echo "" ;;
  esac
}

check_rust_min_version() {
  if ! command -v rustc >/dev/null 2>&1; then
    return 1
  fi
  local installed_ver
  installed_ver="$(rustc --version 2>/dev/null | awk '{print $2}' | cut -d- -f1)"
  # sort -V puts the lower version first; if min <= installed, min comes first (or they're equal)
  [[ "$(printf '%s\n%s\n' "${RUST_MIN_VERSION}" "${installed_ver}" | sort -V | head -1)" == "${RUST_MIN_VERSION}" ]]
}

install_pinned_cargo_deny() {
  print_info "Installing pinned cargo-deny version ${CARGO_DENY_VERSION}."
  cargo install --locked cargo-deny --version "${CARGO_DENY_VERSION}"
}

ensure_rust_components() {
  if ! command -v rustup >/dev/null 2>&1; then
    print_warn "rustup is not available; cannot auto-install rustfmt/clippy components."
    return 0
  fi

  local missing=()
  if ! rustup component list --installed | grep -q '^rustfmt'; then
    missing+=("rustfmt")
  fi
  if ! rustup component list --installed | grep -q '^clippy'; then
    missing+=("clippy")
  fi
  if [[ "${#missing[@]}" -eq 0 ]]; then
    return 0
  fi

  print_info "Installing Rust components: ${missing[*]}"
  rustup component add "${missing[@]}"
}

ensure_ci_security_tools() {
  local missing_bins=()
  if ! command -v cargo-audit >/dev/null 2>&1; then
    missing_bins+=("cargo-audit")
  fi
  if ! command -v cargo-deny >/dev/null 2>&1; then
    missing_bins+=("cargo-deny")
  fi
  if [[ "${#missing_bins[@]}" -eq 0 ]]; then
    return 0
  fi

  print_warn "Missing CI security tools: ${missing_bins[*]}"
  if ! prompt_yes_no "Install missing CI security tools with cargo install --locked?" "y"; then
    print_warn "Skipping CI security tool installation."
    return 0
  fi

  local tool
  for tool in "${missing_bins[@]}"; do
    if [[ "${tool}" == "cargo-deny" ]]; then
      install_pinned_cargo_deny
    else
      cargo install --locked "${tool}"
    fi
  done
}

ensure_rust_toolchain() {
  local need_install=0
  if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
    need_install=1
  elif ! check_rust_min_version; then
    print_warn "Installed Rust $(rustc --version 2>/dev/null | awk '{print $2}') is below the required minimum ${RUST_MIN_VERSION}."
    need_install=1
  fi

  if [[ "${need_install}" -eq 0 ]]; then
    print_info "Rust toolchain $(rustc --version 2>/dev/null) is present and sufficient."
    ensure_rust_components
    return 0
  fi

  print_warn "Rust >= ${RUST_MIN_VERSION} is required to build Rustynet binaries."
  echo "  1) Install via system package manager"
  echo "  2) Skip — I will install Rust manually before building"
  local choice
  read -r -p "Choose Rust install method [1]: " choice
  choice="${choice:-1}"

  case "${choice}" in
    1)
      local pm
      pm="$(package_manager)"
      if [[ "${pm}" == "unknown" ]]; then
        print_err "No supported package manager found. Install Rust manually, then rerun ./start.sh."
        return 1
      fi
      local packages=()
      case "${pm}" in
        brew) packages=(rust) ;;
        pacman) packages=(rust) ;;
        *) packages=(cargo rustc) ;;
      esac
      print_info "Installing Rust via ${pm}: ${packages[*]}"
      case "${pm}" in
        apt)
          run_root apt-get update
          run_root apt-get install -y "${packages[@]}"
          ;;
        dnf)    run_root dnf install -y "${packages[@]}" ;;
        pacman) run_root pacman -Sy --noconfirm "${packages[@]}" ;;
        zypper) run_root zypper --non-interactive install "${packages[@]}" ;;
        brew)   brew install "${packages[@]}" ;;
      esac
      ;;
    2)
      print_warn "Skipping Rust installation. The build step will fail unless Rust >= ${RUST_MIN_VERSION} is installed."
      return 0
      ;;
    *)
      print_err "Invalid choice '${choice}'."
      return 1
      ;;
  esac

  if ! command -v cargo >/dev/null 2>&1; then
    print_err "cargo not found after installation attempt."
    return 1
  fi
  if ! check_rust_min_version; then
    print_warn "Installed Rust $(rustc --version 2>/dev/null | awk '{print $2}') may still be below minimum ${RUST_MIN_VERSION}. Build may fail."
  else
    print_info "Rust toolchain $(rustc --version 2>/dev/null) installed successfully."
  fi
  ensure_rust_components
}

install_runtime_dependencies() {
  if is_macos_host; then
    ensure_macos_command_line_tools
    add_macos_homebrew_to_path
  fi

  local required=(openssl xxd curl awk sed grep rg)
  if is_linux_host; then
    required+=(wg ip nft systemctl)
  elif is_macos_host; then
    required+=(wg wireguard-go)
  fi
  local missing=()
  local cmd
  for cmd in "${required[@]}"; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
      missing+=("${cmd}")
    fi
  done

  if [[ "${#missing[@]}" -eq 0 ]]; then
    return
  fi

  print_warn "Missing commands: ${missing[*]}"
  if ! prompt_yes_no "Install missing runtime dependencies now?" "y"; then
    print_err "Cannot continue without required dependencies."
    exit 1
  fi

  local pm
  pm="$(package_manager)"
  if is_macos_host && [[ "${pm}" == "unknown" ]]; then
    local requires_wireguard_tools=0
    for cmd in "${missing[@]}"; do
      if [[ "${cmd}" == "wg" || "${cmd}" == "wireguard-go" ]]; then
        requires_wireguard_tools=1
      fi
    done

    if [[ "${requires_wireguard_tools}" == "1" ]] && ! is_macos_admin_user; then
      print_err "Homebrew is unavailable and current user is not in the macOS admin group."
      print_info "Admin privileges are required to install root-owned wg/wireguard-go binaries."
      print_info "Ask an admin to install Homebrew and wireguard-tools, then rerun ./start.sh."
      exit 1
    fi

    ensure_macos_homebrew
    pm="$(package_manager)"
  fi
  if [[ "${pm}" == "unknown" ]]; then
    print_err "No supported package manager found. Install manually: ${missing[*]}"
    exit 1
  fi

  local packages=()
  local package
  for cmd in "${missing[@]}"; do
    package="$(map_package "${pm}" "${cmd}")"
    if [[ -n "${package}" ]] && [[ ! " ${packages[*]} " =~ " ${package} " ]]; then
      packages+=("${package}")
    fi
  done

  if [[ "${#packages[@]}" -eq 0 ]]; then
    print_err "Could not map missing commands to installable packages."
    exit 1
  fi

  print_info "Installing packages: ${packages[*]}"
  case "${pm}" in
    apt)
      run_root apt-get update
      run_root apt-get install -y "${packages[@]}"
      ;;
    dnf)
      run_root dnf install -y "${packages[@]}"
      ;;
    pacman)
      run_root pacman -Sy --noconfirm "${packages[@]}"
      ;;
    zypper)
      run_root zypper --non-interactive install "${packages[@]}"
      ;;
    brew)
      brew install "${packages[@]}"
      ;;
  esac
}

ensure_binaries_available() {
  if command -v rustynetd >/dev/null 2>&1 && command -v rustynet >/dev/null 2>&1; then
    return
  fi

  if [[ "${EUID}" -eq 0 ]]; then
    print_err "Refusing to compile Rustynet from a root-owned shell in the repository workspace."
    print_info "Run ./start.sh as a normal user; it will invoke sudo only for privileged installation steps."
    print_info "Set RUSTYNET_ALLOW_ROOT_BUILD=1 to override this guard."
    if [[ "${RUSTYNET_ALLOW_ROOT_BUILD:-0}" != "1" ]]; then
      exit 1
    fi
  fi

  print_warn "rustynet binaries are not installed in PATH."
  if ! command -v cargo >/dev/null 2>&1 || ! check_rust_min_version; then
    ensure_rust_toolchain
  fi

  if ! command -v cargo >/dev/null 2>&1; then
    print_err "cargo is required to build rustynet binaries."
    exit 1
  fi

  if ! prompt_yes_no "Build and install rustynet binaries to /usr/local/bin now?" "y"; then
    print_err "Cannot continue without rustynet binaries."
    exit 1
  fi

  (cd "${ROOT_DIR}" && cargo build --release -p rustynetd -p rustynet-cli)
  local install_dir="/usr/local/bin"
  if is_macos_host && ! test -w "${install_dir}"; then
    if is_macos_admin_user; then
      run_root install -d -m 0755 "${install_dir}"
      run_root install -m 0755 "${ROOT_DIR}/target/release/rustynetd" "${install_dir}/rustynetd"
      run_root install -m 0755 "${ROOT_DIR}/target/release/rustynet-cli" "${install_dir}/rustynet"
      return
    fi
    print_err "No admin write access to /usr/local/bin on macOS."
    print_info "Admin privileges are required so rustynetd can remain root-owned for privileged-helper launchd service."
    exit 1
  fi

  run_root install -d -m 0755 "${install_dir}"
  run_root install -m 0755 "${ROOT_DIR}/target/release/rustynetd" "${install_dir}/rustynetd"
  run_root install -m 0755 "${ROOT_DIR}/target/release/rustynet-cli" "${install_dir}/rustynet"
}

stat_mode() {
  local path="$1"
  stat -c %a "${path}" 2>/dev/null || stat -f %Lp "${path}" 2>/dev/null || true
}

doctor_preflight() {
  local failures=0
  local warnings=0

  doctor_ok() {
    printf '[ok] %s\n' "$1"
  }
  doctor_warn() {
    warnings=$((warnings + 1))
    printf '[warn] %s\n' "$1"
  }
  doctor_fail() {
    failures=$((failures + 1))
    printf '[error] %s\n' "$1" >&2
  }
  doctor_require_cmd() {
    local cmd="$1"
    local label="$2"
    if command -v "${cmd}" >/dev/null 2>&1; then
      doctor_ok "${label}: ${cmd} present"
    else
      doctor_fail "${label}: ${cmd} missing"
    fi
  }
  doctor_check_mode() {
    local path="$1"
    local expected="$2"
    local label="$3"
    if [[ ! -e "${path}" ]]; then
      doctor_fail "${label}: ${path} missing"
      return
    fi
    local mode
    mode="$(stat_mode "${path}")"
    if [[ "${mode}" == "${expected}" ]]; then
      doctor_ok "${label}: ${path} mode ${mode}"
    else
      doctor_fail "${label}: ${path} mode ${mode:-unknown} (expected ${expected})"
    fi
  }
  doctor_check_owner_uid() {
    local path="$1"
    local expected_uid="$2"
    local label="$3"
    if [[ ! -e "${path}" ]]; then
      doctor_fail "${label}: ${path} missing"
      return
    fi
    local owner_uid=""
    if stat -c '%u' "${path}" >/dev/null 2>&1; then
      owner_uid="$(stat -c '%u' "${path}")"
    elif stat -f '%u' "${path}" >/dev/null 2>&1; then
      owner_uid="$(stat -f '%u' "${path}")"
    fi
    if [[ -z "${owner_uid}" ]]; then
      doctor_fail "${label}: unable to determine owner for ${path}"
    elif [[ "${owner_uid}" == "${expected_uid}" ]]; then
      doctor_ok "${label}: ${path} owner uid ${owner_uid}"
    else
      doctor_fail "${label}: ${path} owner uid ${owner_uid} (expected ${expected_uid})"
    fi
  }

  print_info "Running Rustynet preflight doctor..."
  doctor_require_cmd rustynetd "binary"
  doctor_require_cmd rustynet "binary"
  doctor_require_cmd cargo "toolchain"
  doctor_require_cmd openssl "crypto runtime"
  doctor_require_cmd curl "network runtime"
  doctor_require_cmd awk "shell runtime"
  doctor_require_cmd sed "shell runtime"
  doctor_require_cmd grep "shell runtime"
  doctor_require_cmd rg "shell runtime"

  if check_rust_min_version; then
    doctor_ok "rust toolchain >= ${RUST_MIN_VERSION}"
  else
    doctor_fail "rust toolchain < ${RUST_MIN_VERSION}; run first-run bootstrap"
  fi

  if [[ -f "${CONFIG_FILE}" ]]; then
    local cfg_mode
    cfg_mode="$(stat_mode "${CONFIG_FILE}")"
    if [[ "${cfg_mode}" == "600" ]]; then
      doctor_ok "config permissions are strict (${cfg_mode})"
    else
      doctor_fail "config permissions are ${cfg_mode:-unknown}; expected 600"
    fi
  else
    doctor_warn "config file not present yet (${CONFIG_FILE})"
  fi

  if is_linux_host; then
    doctor_require_cmd wg "linux dataplane"
    doctor_require_cmd ip "linux dataplane"
    doctor_require_cmd nft "linux dataplane"
    doctor_require_cmd systemctl "linux service"
    doctor_require_cmd systemd-creds "encrypted credential provisioning"
    doctor_require_cmd python3 "linux e2e/runtime"
    if [[ "${WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" != "${LINUX_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" ]]; then
      doctor_fail "credential blob path must be ${LINUX_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH} on Linux"
    else
      doctor_ok "credential blob path pinned (${WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH})"
    fi
    if [[ "${SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" != "${LINUX_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" ]]; then
      doctor_fail "signing credential blob path must be ${LINUX_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH} on Linux"
    else
      doctor_ok "signing credential blob path pinned (${SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH})"
    fi

    if [[ "${SETUP_COMPLETE}" == "1" ]]; then
      doctor_check_mode "${WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" "600" "encrypted passphrase credential blob"
      doctor_check_mode "${SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" "600" "encrypted signing passphrase credential blob"
      if [[ -f "${WG_KEY_PASSPHRASE_PATH}" ]]; then
        doctor_fail "plaintext passphrase file still present (${WG_KEY_PASSPHRASE_PATH}); remove it"
      else
        doctor_ok "no plaintext passphrase file present"
      fi
      doctor_check_mode "${WG_ENCRYPTED_PRIVATE_KEY_PATH}" "600" "encrypted private key"
      if [[ -f "${WG_PRIVATE_KEY_PATH}" ]]; then
        doctor_check_mode "${WG_PRIVATE_KEY_PATH}" "600" "runtime private key"
      else
        doctor_warn "runtime private key not present (${WG_PRIVATE_KEY_PATH}); it will be derived at daemon startup"
      fi
      if [[ ! -e "${TRUST_EVIDENCE_PATH}" ]]; then
        doctor_fail "trust evidence: ${TRUST_EVIDENCE_PATH} missing"
      else
        local trust_mode trust_group daemon_group
        trust_mode="$(stat_mode "${TRUST_EVIDENCE_PATH}")"
        daemon_group="${RUSTYNET_DAEMON_GROUP:-rustynetd}"
        trust_group=""
        if stat -c '%G' "${TRUST_EVIDENCE_PATH}" >/dev/null 2>&1; then
          trust_group="$(stat -c '%G' "${TRUST_EVIDENCE_PATH}")"
        elif stat -f '%Sg' "${TRUST_EVIDENCE_PATH}" >/dev/null 2>&1; then
          trust_group="$(stat -f '%Sg' "${TRUST_EVIDENCE_PATH}")"
        fi
        if [[ "${trust_mode}" == "600" ]]; then
          doctor_ok "trust evidence: ${TRUST_EVIDENCE_PATH} mode ${trust_mode}"
        elif [[ "${trust_mode}" == "640" && "${trust_group}" == "${daemon_group}" ]]; then
          doctor_ok "trust evidence: ${TRUST_EVIDENCE_PATH} mode ${trust_mode} group ${trust_group}"
        else
          doctor_fail "trust evidence: ${TRUST_EVIDENCE_PATH} mode ${trust_mode:-unknown} group ${trust_group:-unknown} (expected 600 or 640 with group ${daemon_group})"
        fi
      fi
      doctor_check_mode "${TRUST_WATERMARK_PATH}" "600" "trust watermark"
      if [[ -S "${SOCKET_PATH}" ]]; then
        doctor_ok "daemon IPC socket present (${SOCKET_PATH})"
      else
        doctor_warn "daemon IPC socket not present (${SOCKET_PATH}); service may be stopped"
      fi
    else
      doctor_warn "setup not marked complete; run first-run setup"
    fi
  elif is_macos_host; then
    doctor_require_cmd wg "macOS dataplane"
    doctor_require_cmd wireguard-go "macOS dataplane"
    doctor_require_cmd ifconfig "macOS dataplane"
    doctor_require_cmd route "macOS dataplane"
    doctor_require_cmd pfctl "macOS dataplane"
    doctor_require_cmd launchctl "macOS service manager"
    doctor_require_cmd security "macOS keychain custody"
    if command -v brew >/dev/null 2>&1; then
      doctor_ok "homebrew present for macOS dependency management"
    else
      doctor_warn "homebrew missing; dependency upgrades must be managed manually"
    fi
    if path_in_linux_runtime_roots "${SOCKET_PATH}" \
      || path_in_linux_runtime_roots "${STATE_PATH}" \
      || path_in_linux_runtime_roots "${TRUST_EVIDENCE_PATH}" \
      || path_in_linux_runtime_roots "${WG_PRIVATE_KEY_PATH}"; then
      doctor_fail "macOS path policy violation detected (Linux runtime roots in config); rerun setup to normalize paths"
    else
      doctor_ok "macOS path policy enforced (no Linux runtime roots)"
    fi
    if [[ "${SETUP_COMPLETE}" == "1" ]]; then
      if [[ -z "${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}" ]]; then
        doctor_fail "macOS keychain account for passphrase custody is empty"
      elif ! [[ "${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}" =~ ^[A-Za-z0-9._-]+$ ]]; then
        doctor_fail "macOS keychain account has invalid characters (${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT})"
      elif ! macos_keychain_passphrase_exists; then
        doctor_fail "macOS keychain passphrase item missing (service=${MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}, account=${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT})"
      else
        doctor_ok "macOS keychain passphrase source configured (service=${MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}, account=${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT})"
      fi
      if [[ -f "${WG_KEY_PASSPHRASE_PATH}" ]]; then
        doctor_fail "persistent plaintext passphrase file is present on macOS (${WG_KEY_PASSPHRASE_PATH})"
      else
        doctor_ok "no persistent plaintext passphrase file present on macOS"
      fi
      if [[ -f "${MACOS_LAUNCHD_DAEMON_PLIST_PATH}" ]]; then
        doctor_check_mode "${MACOS_LAUNCHD_DAEMON_PLIST_PATH}" "644" "launchd daemon plist"
        doctor_check_owner_uid "${MACOS_LAUNCHD_DAEMON_PLIST_PATH}" "$(id -u)" "launchd daemon plist"
      else
        doctor_warn "launchd daemon plist missing (${MACOS_LAUNCHD_DAEMON_PLIST_PATH}); start will reinstall it"
      fi
      if [[ -f "${MACOS_LAUNCHD_HELPER_PLIST_PATH}" ]]; then
        doctor_check_mode "${MACOS_LAUNCHD_HELPER_PLIST_PATH}" "644" "launchd privileged helper plist"
        doctor_check_owner_uid "${MACOS_LAUNCHD_HELPER_PLIST_PATH}" "0" "launchd privileged helper plist"
      else
        doctor_warn "launchd privileged helper plist missing (${MACOS_LAUNCHD_HELPER_PLIST_PATH}); start will reinstall it"
      fi
      doctor_check_mode "${WG_ENCRYPTED_PRIVATE_KEY_PATH}" "600" "encrypted private key"
      if [[ -f "${WG_PRIVATE_KEY_PATH}" ]]; then
        doctor_check_mode "${WG_PRIVATE_KEY_PATH}" "600" "runtime private key"
      else
        doctor_warn "runtime private key not present (${WG_PRIVATE_KEY_PATH}); it will be derived at daemon startup"
      fi
      doctor_check_mode "${TRUST_EVIDENCE_PATH}" "600" "trust evidence"
      doctor_check_mode "${TRUST_WATERMARK_PATH}" "600" "trust watermark"
      if [[ -S "${SOCKET_PATH}" ]]; then
        doctor_ok "daemon IPC socket present (${SOCKET_PATH})"
      else
        doctor_warn "daemon IPC socket not present (${SOCKET_PATH}); daemon may be stopped"
      fi
    else
      doctor_warn "setup not marked complete; run first-run setup"
    fi
  else
    doctor_fail "unsupported host OS ${HOST_OS}"
  fi

  if (( failures > 0 )); then
    print_err "Preflight doctor failed with ${failures} error(s) and ${warnings} warning(s)."
    return 1
  fi

  print_info "Preflight doctor passed with ${warnings} warning(s)."
  return 0
}

prepare_system_directories() {
  if ! command -v rustynet >/dev/null 2>&1; then
    print_err "rustynet CLI is required for system directory preparation."
    return 1
  fi

  local rust_ops_status=1
  if is_linux_host; then
    run_root env \
      RUSTYNET_HOST_PROFILE="${HOST_PROFILE}" \
      RUSTYNET_STATE="${STATE_PATH}" \
      RUSTYNET_TRUST_EVIDENCE="${TRUST_EVIDENCE_PATH}" \
      RUSTYNET_TRUST_VERIFIER_KEY="${TRUST_VERIFIER_KEY_PATH}" \
      RUSTYNET_TRUST_WATERMARK="${TRUST_WATERMARK_PATH}" \
      RUSTYNET_AUTO_TUNNEL_BUNDLE="${AUTO_TUNNEL_BUNDLE_PATH}" \
      RUSTYNET_AUTO_TUNNEL_VERIFIER_KEY="${AUTO_TUNNEL_VERIFIER_KEY_PATH}" \
      RUSTYNET_AUTO_TUNNEL_WATERMARK="${AUTO_TUNNEL_WATERMARK_PATH}" \
      RUSTYNET_TRAVERSAL_BUNDLE="${TRAVERSAL_BUNDLE_PATH}" \
      RUSTYNET_TRAVERSAL_VERIFIER_KEY="${TRAVERSAL_VERIFIER_KEY_PATH}" \
      RUSTYNET_TRAVERSAL_WATERMARK="${TRAVERSAL_WATERMARK_PATH}" \
      RUSTYNET_WG_PRIVATE_KEY="${WG_PRIVATE_KEY_PATH}" \
      RUSTYNET_WG_ENCRYPTED_PRIVATE_KEY="${WG_ENCRYPTED_PRIVATE_KEY_PATH}" \
      RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB="${WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" \
      RUSTYNET_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB="${SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" \
      RUSTYNET_WG_PUBLIC_KEY="${WG_PUBLIC_KEY_PATH}" \
      RUSTYNET_MEMBERSHIP_SNAPSHOT="${MEMBERSHIP_SNAPSHOT_PATH}" \
      RUSTYNET_MEMBERSHIP_LOG="${MEMBERSHIP_LOG_PATH}" \
      RUSTYNET_MEMBERSHIP_WATERMARK="${MEMBERSHIP_WATERMARK_PATH}" \
      RUSTYNET_MEMBERSHIP_OWNER_SIGNING_KEY="${MEMBERSHIP_OWNER_SIGNING_KEY_PATH}" \
      RUSTYNET_PRIVILEGED_HELPER_SOCKET="${PRIVILEGED_HELPER_SOCKET_PATH}" \
      rustynet ops prepare-system-dirs >/dev/null 2>&1 || rust_ops_status=$?
  elif is_macos_host; then
    env \
      RUSTYNET_HOST_PROFILE="${HOST_PROFILE}" \
      RUSTYNET_MACOS_STATE_BASE="${MACOS_STATE_BASE}" \
      RUSTYNET_MACOS_RUNTIME_BASE="${MACOS_RUNTIME_BASE}" \
      RUSTYNET_MACOS_LOG_BASE="${MACOS_LOG_BASE}" \
      RUSTYNET_STATE="${STATE_PATH}" \
      RUSTYNET_TRUST_EVIDENCE="${TRUST_EVIDENCE_PATH}" \
      RUSTYNET_TRUST_VERIFIER_KEY="${TRUST_VERIFIER_KEY_PATH}" \
      RUSTYNET_TRUST_WATERMARK="${TRUST_WATERMARK_PATH}" \
      RUSTYNET_AUTO_TUNNEL_BUNDLE="${AUTO_TUNNEL_BUNDLE_PATH}" \
      RUSTYNET_AUTO_TUNNEL_VERIFIER_KEY="${AUTO_TUNNEL_VERIFIER_KEY_PATH}" \
      RUSTYNET_AUTO_TUNNEL_WATERMARK="${AUTO_TUNNEL_WATERMARK_PATH}" \
      RUSTYNET_TRAVERSAL_BUNDLE="${TRAVERSAL_BUNDLE_PATH}" \
      RUSTYNET_TRAVERSAL_VERIFIER_KEY="${TRAVERSAL_VERIFIER_KEY_PATH}" \
      RUSTYNET_TRAVERSAL_WATERMARK="${TRAVERSAL_WATERMARK_PATH}" \
      RUSTYNET_WG_PRIVATE_KEY="${WG_PRIVATE_KEY_PATH}" \
      RUSTYNET_WG_ENCRYPTED_PRIVATE_KEY="${WG_ENCRYPTED_PRIVATE_KEY_PATH}" \
      RUSTYNET_WG_KEY_PASSPHRASE="${WG_KEY_PASSPHRASE_PATH}" \
      RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB="${WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" \
      RUSTYNET_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB="${SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" \
      RUSTYNET_WG_PUBLIC_KEY="${WG_PUBLIC_KEY_PATH}" \
      RUSTYNET_MEMBERSHIP_SNAPSHOT="${MEMBERSHIP_SNAPSHOT_PATH}" \
      RUSTYNET_MEMBERSHIP_LOG="${MEMBERSHIP_LOG_PATH}" \
      RUSTYNET_MEMBERSHIP_WATERMARK="${MEMBERSHIP_WATERMARK_PATH}" \
      RUSTYNET_MEMBERSHIP_OWNER_SIGNING_KEY="${MEMBERSHIP_OWNER_SIGNING_KEY_PATH}" \
      RUSTYNET_PRIVILEGED_HELPER_SOCKET="${PRIVILEGED_HELPER_SOCKET_PATH}" \
      rustynet ops prepare-system-dirs >/dev/null 2>&1 || rust_ops_status=$?
  else
    require_linux_dataplane "prepare_system_directories" || return 0
    return 1
  fi

  if [[ "${rust_ops_status}" -ne 0 ]]; then
    print_err "Rust-backed directory preparation failed; setup is fail-closed."
    return 1
  fi
  return 0
}

ensure_wireguard_keys() {
  run_with_scope() {
    if is_linux_host; then
      run_root "$@"
    else
      "$@"
    fi
  }

  local legacy_linux_passphrase_path="/etc/rustynet/wireguard.passphrase"
  local wg_init_prompt_approved="0"
  local wg_init_required="0"

  if is_linux_host; then
    if [[ -f "${WG_ENCRYPTED_PRIVATE_KEY_PATH}" && -f "${WG_PUBLIC_KEY_PATH}" && -f "${WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" ]]; then
      wg_init_required="0"
    elif [[ -f "${WG_ENCRYPTED_PRIVATE_KEY_PATH}" && ! -f "${WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" ]]; then
      wg_init_required="0"
    else
      wg_init_required="1"
    fi
  elif is_macos_host; then
    if [[ -f "${WG_ENCRYPTED_PRIVATE_KEY_PATH}" && -f "${WG_PUBLIC_KEY_PATH}" ]]; then
      wg_init_required="0"
    else
      wg_init_required="1"
    fi
  fi

  if [[ "${wg_init_required}" == "1" ]]; then
    if ! prompt_yes_no "Encrypted WireGuard key material is missing. Initialize now?" "y"; then
      print_err "Encrypted WireGuard key material is required."
      unset -f run_with_scope >/dev/null 2>&1 || true
      exit 1
    fi
    wg_init_prompt_approved="1"
  fi

  if is_macos_host; then
    ensure_macos_keychain_passphrase_account
    if ! command -v security >/dev/null 2>&1; then
      print_err "macOS keychain tooling is missing ('security' command not found)."
      unset -f run_with_scope >/dev/null 2>&1 || true
      exit 1
    fi
  fi

  if ! command -v rustynet >/dev/null 2>&1; then
    print_err "rustynet CLI is required for WireGuard custody bootstrap."
    unset -f run_with_scope >/dev/null 2>&1 || true
    exit 1
  fi

  local rust_wg_bootstrap_output=""
  local rust_allow_init="false"
  if [[ "${wg_init_prompt_approved}" == "1" ]]; then
    rust_allow_init="true"
  fi

  if ! rust_wg_bootstrap_output="$(run_with_scope env \
    RUSTYNET_HOST_PROFILE="${HOST_PROFILE}" \
    RUSTYNET_WG_PRIVATE_KEY="${WG_PRIVATE_KEY_PATH}" \
    RUSTYNET_WG_ENCRYPTED_PRIVATE_KEY="${WG_ENCRYPTED_PRIVATE_KEY_PATH}" \
    RUSTYNET_WG_PUBLIC_KEY="${WG_PUBLIC_KEY_PATH}" \
    RUSTYNET_WG_KEY_PASSPHRASE="${WG_KEY_PASSPHRASE_PATH}" \
    RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB="${WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" \
    RUSTYNET_WG_CUSTODY_ALLOW_INIT="${rust_allow_init}" \
    RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE="${MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}" \
    RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT="${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}" \
    rustynet ops bootstrap-wireguard-custody 2>&1)"; then
    print_err "Rust-backed WireGuard custody bootstrap failed; setup is fail-closed."
    [[ -n "${rust_wg_bootstrap_output}" ]] && print_err "${rust_wg_bootstrap_output}"
    unset -f run_with_scope >/dev/null 2>&1 || true
    exit 1
  fi

  [[ -n "${rust_wg_bootstrap_output}" ]] && print_info "${rust_wg_bootstrap_output}"

  if is_linux_host; then
    secure_remove_file_with_scope "${WG_KEY_PASSPHRASE_PATH}" || {
      unset -f run_with_scope >/dev/null 2>&1 || true
      exit 1
    }
    secure_remove_file_with_scope "${legacy_linux_passphrase_path}" || {
      unset -f run_with_scope >/dev/null 2>&1 || true
      exit 1
    }
  elif is_macos_host; then
    secure_remove_file_with_scope "${WG_KEY_PASSPHRASE_PATH}" || {
      unset -f run_with_scope >/dev/null 2>&1 || true
      exit 1
    }
  fi

  unset -f run_with_scope >/dev/null 2>&1 || true
  return 0
}

ensure_membership_files() {
  if ! command -v rustynet >/dev/null 2>&1; then
    print_err "rustynet CLI is required for membership initialization."
    return 1
  fi

  local rust_ops_status=1
  if is_linux_host; then
    run_root env \
      RUSTYNET_HOST_PROFILE="${HOST_PROFILE}" \
      RUSTYNET_NODE_ROLE="${NODE_ROLE}" \
      RUSTYNET_NODE_ID="${DEVICE_NODE_ID}" \
      RUSTYNET_NETWORK_ID="local-net" \
      RUSTYNET_MEMBERSHIP_SNAPSHOT="${MEMBERSHIP_SNAPSHOT_PATH}" \
      RUSTYNET_MEMBERSHIP_LOG="${MEMBERSHIP_LOG_PATH}" \
      RUSTYNET_MEMBERSHIP_WATERMARK="${MEMBERSHIP_WATERMARK_PATH}" \
      RUSTYNET_MEMBERSHIP_OWNER_SIGNING_KEY="${MEMBERSHIP_OWNER_SIGNING_KEY_PATH}" \
      RUSTYNET_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB="${SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" \
      RUSTYNET_TRUST_SIGNER_KEY="${TRUST_SIGNER_KEY_PATH}" \
      RUSTYNET_ASSIGNMENT_SIGNING_SECRET="/etc/rustynet/assignment.signing.secret" \
      RUSTYNET_MACOS_PASSPHRASE_KEYCHAIN_SERVICE="${MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}" \
      RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT="${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}" \
      rustynet ops init-membership >/dev/null 2>&1 || rust_ops_status=$?
  elif is_macos_host; then
    env \
      RUSTYNET_HOST_PROFILE="${HOST_PROFILE}" \
      RUSTYNET_NODE_ROLE="${NODE_ROLE}" \
      RUSTYNET_NODE_ID="${DEVICE_NODE_ID}" \
      RUSTYNET_NETWORK_ID="local-net" \
      RUSTYNET_MEMBERSHIP_SNAPSHOT="${MEMBERSHIP_SNAPSHOT_PATH}" \
      RUSTYNET_MEMBERSHIP_LOG="${MEMBERSHIP_LOG_PATH}" \
      RUSTYNET_MEMBERSHIP_WATERMARK="${MEMBERSHIP_WATERMARK_PATH}" \
      RUSTYNET_MEMBERSHIP_OWNER_SIGNING_KEY="${MEMBERSHIP_OWNER_SIGNING_KEY_PATH}" \
      RUSTYNET_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB="${SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" \
      RUSTYNET_TRUST_SIGNER_KEY="${TRUST_SIGNER_KEY_PATH}" \
      RUSTYNET_ASSIGNMENT_SIGNING_SECRET="/etc/rustynet/assignment.signing.secret" \
      RUSTYNET_MACOS_PASSPHRASE_KEYCHAIN_SERVICE="${MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}" \
      RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT="${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}" \
      rustynet ops init-membership >/dev/null 2>&1 || rust_ops_status=$?
  else
    print_err "Unsupported host profile for membership initialization: ${HOST_PROFILE}"
    return 1
  fi

  if [[ "${rust_ops_status}" != "0" ]]; then
    print_err "Rust-backed membership initialization failed; setup is fail-closed."
    return 1
  fi

  if is_blind_exit_role && [[ -f "${MEMBERSHIP_OWNER_SIGNING_KEY_PATH}" ]]; then
    secure_remove_file_with_scope "${MEMBERSHIP_OWNER_SIGNING_KEY_PATH}" || return 1
    print_info "Removed local membership owner signing key for blind_exit least-knowledge role."
  fi
  return 0
}

lockdown_blind_exit_local_material() {
  if ! is_blind_exit_role; then
    return 0
  fi
  if ! is_linux_host; then
    return 0
  fi

  if ! command -v rustynet >/dev/null 2>&1; then
    print_err "rustynet CLI is required for blind_exit lockdown."
    return 1
  fi

  local rust_lockdown_output=""
  if ! rust_lockdown_output="$(run_root env \
    RUSTYNET_ASSIGNMENT_SIGNING_SECRET="/etc/rustynet/assignment.signing.secret" \
    RUSTYNET_ASSIGNMENT_REFRESH_ENV_PATH="${ASSIGNMENT_REFRESH_ENV_PATH}" \
    RUSTYNET_SYSTEMD_ENV_PATH="/etc/default/rustynetd" \
    rustynet ops apply-blind-exit-lockdown 2>&1)"; then
    print_err "Rust-backed blind_exit lockdown failed; setup is fail-closed."
    [[ -n "${rust_lockdown_output}" ]] && print_err "${rust_lockdown_output}"
    return 1
  fi
  [[ -n "${rust_lockdown_output}" ]] && print_info "${rust_lockdown_output}"
  return 0
}

generate_verifier_key_from_signer() {
  local signing_passphrase_file="$1"
  run_root rustynet trust export-verifier-key \
    --signing-key "${TRUST_SIGNER_KEY_PATH}" \
    --signing-key-passphrase-file "${signing_passphrase_file}" \
    --output "${TRUST_VERIFIER_KEY_PATH}"
  run_root chmod 0644 "${TRUST_VERIFIER_KEY_PATH}"
  if is_macos_host; then
    run_root chown "$(id -u):$(id -g)" "${TRUST_VERIFIER_KEY_PATH}"
  fi
}

refresh_signed_trust_evidence() {
  if ! is_admin_role && ! is_blind_exit_role; then
    print_err "refresh_signed_trust_evidence requires node role 'admin' or 'blind_exit'."
    print_info "This device is configured as role '${NODE_ROLE}'."
    return 0
  fi
  if [[ ! -f "${TRUST_SIGNER_KEY_PATH}" ]]; then
    print_err "Signer key not found at ${TRUST_SIGNER_KEY_PATH}"
    return 1
  fi

  if ! command -v rustynet >/dev/null 2>&1; then
    print_err "rustynet CLI is required for signed trust refresh."
    return 1
  fi

  local rust_refresh_output=""
  if is_linux_host; then
    if ! rust_refresh_output="$(run_root env \
      RUSTYNET_HOST_PROFILE="${HOST_PROFILE}" \
      RUSTYNET_NODE_ROLE="${NODE_ROLE}" \
      RUSTYNET_TRUST_EVIDENCE="${TRUST_EVIDENCE_PATH}" \
      RUSTYNET_TRUST_SIGNER_KEY="${TRUST_SIGNER_KEY_PATH}" \
      RUSTYNET_DAEMON_GROUP="${RUSTYNET_DAEMON_GROUP:-rustynetd}" \
      RUSTYNET_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB="${SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" \
      RUSTYNET_MEMBERSHIP_OWNER_SIGNING_KEY="${MEMBERSHIP_OWNER_SIGNING_KEY_PATH}" \
      RUSTYNET_ASSIGNMENT_SIGNING_SECRET="/etc/rustynet/assignment.signing.secret" \
      RUSTYNET_MACOS_PASSPHRASE_KEYCHAIN_SERVICE="${MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}" \
      RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT="${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}" \
      rustynet ops refresh-signed-trust 2>&1)"; then
      print_err "Rust-backed signed trust refresh failed; setup is fail-closed."
      [[ -n "${rust_refresh_output}" ]] && print_err "${rust_refresh_output}"
      return 1
    fi
  elif is_macos_host; then
    if ! rust_refresh_output="$(env \
      RUSTYNET_HOST_PROFILE="${HOST_PROFILE}" \
      RUSTYNET_NODE_ROLE="${NODE_ROLE}" \
      RUSTYNET_TRUST_EVIDENCE="${TRUST_EVIDENCE_PATH}" \
      RUSTYNET_TRUST_SIGNER_KEY="${TRUST_SIGNER_KEY_PATH}" \
      RUSTYNET_DAEMON_GROUP="${RUSTYNET_DAEMON_GROUP:-rustynetd}" \
      RUSTYNET_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB="${SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" \
      RUSTYNET_MEMBERSHIP_OWNER_SIGNING_KEY="${MEMBERSHIP_OWNER_SIGNING_KEY_PATH}" \
      RUSTYNET_ASSIGNMENT_SIGNING_SECRET="/etc/rustynet/assignment.signing.secret" \
      RUSTYNET_MACOS_PASSPHRASE_KEYCHAIN_SERVICE="${MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}" \
      RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT="${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}" \
      rustynet ops refresh-signed-trust 2>&1)"; then
      print_err "Rust-backed signed trust refresh failed; setup is fail-closed."
      [[ -n "${rust_refresh_output}" ]] && print_err "${rust_refresh_output}"
      return 1
    fi
  else
    print_err "Unsupported host profile for signed trust refresh: ${HOST_PROFILE}"
    return 1
  fi
  [[ -n "${rust_refresh_output}" ]] && print_info "${rust_refresh_output}"
  print_info "Signed trust evidence refreshed at ${TRUST_EVIDENCE_PATH}"
  return 0
}

configure_trust_material() {
  if is_blind_exit_role; then
    print_info "blind_exit role detected: provisioning local trust material for unattended operation."
    local signing_passphrase_file=""
    if ! materialize_signing_passphrase_file signing_passphrase_file; then
      return 1
    fi
    if [[ ! -f "${TRUST_SIGNER_KEY_PATH}" ]]; then
      run_root rustynet trust keygen \
        --signing-key-output "${TRUST_SIGNER_KEY_PATH}" \
        --signing-key-passphrase-file "${signing_passphrase_file}" \
        --verifier-key-output "${TRUST_VERIFIER_KEY_PATH}" \
        --force
      run_root chmod 0644 "${TRUST_VERIFIER_KEY_PATH}"
      print_warn "Generated local trust signer key at ${TRUST_SIGNER_KEY_PATH} for blind_exit role."
    else
      generate_verifier_key_from_signer "${signing_passphrase_file}"
    fi
    secure_remove_file_with_scope "${signing_passphrase_file}"
    refresh_signed_trust_evidence
    AUTO_REFRESH_TRUST="1"
    return 0
  fi

  if is_client_role; then
    print_info "Client role detected: trust signer operations are disabled."
    local source_verifier
    local source_trust
    prompt_default source_verifier "Path to verifier key (32-byte hex line)" "${TRUST_VERIFIER_KEY_PATH}"
    prompt_default source_trust "Path to signed trust evidence file" "${TRUST_EVIDENCE_PATH}"
    if [[ "${source_verifier}" != "${TRUST_VERIFIER_KEY_PATH}" || ! -f "${TRUST_VERIFIER_KEY_PATH}" ]]; then
      run_root install -m 0644 "${source_verifier}" "${TRUST_VERIFIER_KEY_PATH}"
    fi
    if [[ "${source_trust}" != "${TRUST_EVIDENCE_PATH}" || ! -f "${TRUST_EVIDENCE_PATH}" ]]; then
      local trust_group="root"
      local trust_mode="0600"
      if is_linux_host; then
        trust_mode="0644"
        local daemon_group="${RUSTYNET_DAEMON_GROUP:-rustynetd}"
        if command -v getent >/dev/null 2>&1 && getent group "${daemon_group}" >/dev/null 2>&1; then
          trust_group="${daemon_group}"
          trust_mode="0640"
        fi
      fi
      run_root install -m "${trust_mode}" -o root -g "${trust_group}" "${source_trust}" "${TRUST_EVIDENCE_PATH}"
      if is_macos_host; then
        run_root chown "$(id -u):$(id -g)" "${TRUST_EVIDENCE_PATH}"
      fi
    fi
    AUTO_REFRESH_TRUST="0"
    return 0
  fi
  print_info "Trust material setup:"
  echo "  1) Lab mode (generate local signer key and auto-refresh trust evidence)"
  echo "  2) Bring externally signed trust evidence + verifier key"
  local choice
  read -r -p "Choose mode [1/2, default 2]: " choice
  choice="${choice:-2}"
  if [[ "${choice}" != "1" && "${choice}" != "2" ]]; then
    print_err "Invalid trust mode '${choice}'. Expected 1 or 2."
    return 1
  fi

  if [[ "${choice}" == "1" ]]; then
    local lab_ack
    print_warn "Lab mode reduces trust separation and is intended for local development only."
    read -r -p "Type 'LAB_MODE_ACK' to continue in lab mode: " lab_ack
    if [[ "${lab_ack}" != "LAB_MODE_ACK" ]]; then
      print_err "Lab mode confirmation mismatch."
      return 1
    fi
    local signing_passphrase_file=""
    if ! materialize_signing_passphrase_file signing_passphrase_file; then
      return 1
    fi
    if [[ ! -f "${TRUST_SIGNER_KEY_PATH}" ]]; then
      run_root rustynet trust keygen \
        --signing-key-output "${TRUST_SIGNER_KEY_PATH}" \
        --signing-key-passphrase-file "${signing_passphrase_file}" \
        --verifier-key-output "${TRUST_VERIFIER_KEY_PATH}" \
        --force
      run_root chmod 0644 "${TRUST_VERIFIER_KEY_PATH}"
      print_warn "Generated local signer key at ${TRUST_SIGNER_KEY_PATH} (lab/dev only)."
    else
      generate_verifier_key_from_signer "${signing_passphrase_file}"
    fi
    secure_remove_file_with_scope "${signing_passphrase_file}"
    refresh_signed_trust_evidence
    AUTO_REFRESH_TRUST="1"
    return
  fi

  local source_verifier
  local source_trust
  prompt_default source_verifier "Path to verifier key (32-byte hex line)" "${TRUST_VERIFIER_KEY_PATH}"
  prompt_default source_trust "Path to signed trust evidence file" "${TRUST_EVIDENCE_PATH}"

  if [[ "${source_verifier}" != "${TRUST_VERIFIER_KEY_PATH}" ]]; then
    run_root install -m 0644 "${source_verifier}" "${TRUST_VERIFIER_KEY_PATH}"
  elif [[ ! -f "${TRUST_VERIFIER_KEY_PATH}" ]]; then
    run_root install -m 0644 "${source_verifier}" "${TRUST_VERIFIER_KEY_PATH}"
  fi

  if [[ "${source_trust}" != "${TRUST_EVIDENCE_PATH}" || ! -f "${TRUST_EVIDENCE_PATH}" ]]; then
    local trust_group="root"
    local trust_mode="0600"
    if is_linux_host; then
      trust_mode="0644"
      local daemon_group="${RUSTYNET_DAEMON_GROUP:-rustynetd}"
      if command -v getent >/dev/null 2>&1 && getent group "${daemon_group}" >/dev/null 2>&1; then
        trust_group="${daemon_group}"
        trust_mode="0640"
      fi
    fi
    run_root install -m "${trust_mode}" -o root -g "${trust_group}" "${source_trust}" "${TRUST_EVIDENCE_PATH}"
    if is_macos_host; then
      run_root chown "$(id -u):$(id -g)" "${TRUST_EVIDENCE_PATH}"
    fi
  fi

  if prompt_yes_no "Do you also have signer key access for auto-refresh?" "n"; then
    prompt_default TRUST_SIGNER_KEY_PATH "Signer key path" "${TRUST_SIGNER_KEY_PATH}"
    AUTO_REFRESH_TRUST="1"
  else
    AUTO_REFRESH_TRUST="0"
  fi
}

write_daemon_environment() {
  enforce_role_policy_defaults
  enforce_backend_mode
  enforce_fail_closed_ssh_policy
  enforce_wg_listen_port_policy
  enforce_auto_port_forward_policy
  if is_macos_host; then
    return 0
  fi
  if [[ "${WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" != "${LINUX_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" ]]; then
    print_err "Linux credential blob path must be ${LINUX_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}."
    exit 1
  fi
  if [[ "${SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" != "${LINUX_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" ]]; then
    print_err "Linux signing credential blob path must be ${LINUX_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}."
    exit 1
  fi
  enforce_auto_tunnel_policy
  require_linux_dataplane "write_daemon_environment" || return 0
  if ! sync_egress_interface_with_selected_exit_route; then
    print_err "Failed to derive secure egress interface mapping for current exit selection."
    return 1
  fi

  run_systemd_installer_with_env() {
    run_root env \
      RUSTYNET_NODE_ID="${DEVICE_NODE_ID}" \
      RUSTYNET_NODE_ROLE="${NODE_ROLE}" \
      RUSTYNET_SOCKET="${SOCKET_PATH}" \
      RUSTYNET_STATE="${STATE_PATH}" \
      RUSTYNET_TRUST_EVIDENCE="${TRUST_EVIDENCE_PATH}" \
      RUSTYNET_TRUST_VERIFIER_KEY="${TRUST_VERIFIER_KEY_PATH}" \
      RUSTYNET_TRUST_WATERMARK="${TRUST_WATERMARK_PATH}" \
      RUSTYNET_TRUST_SIGNER_KEY="${TRUST_SIGNER_KEY_PATH}" \
      RUSTYNET_TRUST_AUTO_REFRESH="$( [[ "${AUTO_REFRESH_TRUST}" == "1" ]] && echo true || echo false )" \
      RUSTYNET_MEMBERSHIP_SNAPSHOT="${MEMBERSHIP_SNAPSHOT_PATH}" \
      RUSTYNET_MEMBERSHIP_LOG="${MEMBERSHIP_LOG_PATH}" \
      RUSTYNET_MEMBERSHIP_WATERMARK="${MEMBERSHIP_WATERMARK_PATH}" \
      RUSTYNET_MEMBERSHIP_OWNER_SIGNING_KEY="${MEMBERSHIP_OWNER_SIGNING_KEY_PATH}" \
      RUSTYNET_AUTO_TUNNEL_ENFORCE="$( [[ "${AUTO_TUNNEL_ENFORCE}" == "1" ]] && echo true || echo false )" \
      RUSTYNET_AUTO_TUNNEL_BUNDLE="${AUTO_TUNNEL_BUNDLE_PATH}" \
      RUSTYNET_AUTO_TUNNEL_VERIFIER_KEY="${AUTO_TUNNEL_VERIFIER_KEY_PATH}" \
      RUSTYNET_AUTO_TUNNEL_WATERMARK="${AUTO_TUNNEL_WATERMARK_PATH}" \
      RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS="${AUTO_TUNNEL_MAX_AGE_SECS}" \
      RUSTYNET_TRAVERSAL_BUNDLE="${TRAVERSAL_BUNDLE_PATH}" \
      RUSTYNET_TRAVERSAL_VERIFIER_KEY="${TRAVERSAL_VERIFIER_KEY_PATH}" \
      RUSTYNET_TRAVERSAL_WATERMARK="${TRAVERSAL_WATERMARK_PATH}" \
      RUSTYNET_TRAVERSAL_MAX_AGE_SECS="${TRAVERSAL_MAX_AGE_SECS}" \
      RUSTYNET_BACKEND="${BACKEND_MODE}" \
      RUSTYNET_WG_INTERFACE="${WG_INTERFACE}" \
      RUSTYNET_WG_LISTEN_PORT="${WG_LISTEN_PORT}" \
      RUSTYNET_WG_PRIVATE_KEY="${WG_PRIVATE_KEY_PATH}" \
      RUSTYNET_WG_ENCRYPTED_PRIVATE_KEY="${WG_ENCRYPTED_PRIVATE_KEY_PATH}" \
      RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB="${WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" \
      RUSTYNET_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB="${SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}" \
      RUSTYNET_WG_PUBLIC_KEY="${WG_PUBLIC_KEY_PATH}" \
      RUSTYNET_EGRESS_INTERFACE="${EGRESS_INTERFACE}" \
      RUSTYNET_AUTO_PORT_FORWARD_EXIT="$( [[ "${AUTO_PORT_FORWARD_EXIT}" == "1" ]] && echo true || echo false )" \
      RUSTYNET_AUTO_PORT_FORWARD_LEASE_SECS="${AUTO_PORT_FORWARD_LEASE_SECS}" \
      RUSTYNET_DATAPLANE_MODE="${DATAPLANE_MODE}" \
      RUSTYNET_PRIVILEGED_HELPER_SOCKET="${PRIVILEGED_HELPER_SOCKET_PATH}" \
      RUSTYNET_PRIVILEGED_HELPER_TIMEOUT_MS="${PRIVILEGED_HELPER_TIMEOUT_MS}" \
      RUSTYNET_RECONCILE_INTERVAL_MS="${RECONCILE_INTERVAL_MS}" \
      RUSTYNET_MAX_RECONCILE_FAILURES="${MAX_RECONCILE_FAILURES}" \
      RUSTYNET_FAIL_CLOSED_SSH_ALLOW="$( [[ "${FAIL_CLOSED_SSH_ALLOW}" == "1" ]] && echo true || echo false )" \
      RUSTYNET_FAIL_CLOSED_SSH_ALLOW_CIDRS="${FAIL_CLOSED_SSH_ALLOW_CIDRS}" \
      "$@"
  }

  if ! command -v rustynet >/dev/null 2>&1; then
    print_err "rustynet CLI is required for Linux systemd installer operations."
    unset -f run_systemd_installer_with_env >/dev/null 2>&1 || true
    exit 1
  fi

  if ! run_systemd_installer_with_env \
    RUSTYNET_INSTALL_SOURCE_ROOT="${ROOT_DIR}" \
    rustynet ops install-systemd; then
    print_err "Rust-backed systemd installer invocation failed; setup is fail-closed."
    unset -f run_systemd_installer_with_env >/dev/null 2>&1 || true
    exit 1
  fi
  unset -f run_systemd_installer_with_env >/dev/null 2>&1 || true
  return 0
}

macos_wait_for_socket() {
  local socket_path="$1"
  local attempts=50
  while (( attempts > 0 )); do
    if [[ -S "${socket_path}" ]]; then
      return 0
    fi
    sleep 0.1
    attempts=$((attempts - 1))
  done
  return 1
}

resolve_absolute_command_path() {
  local cmd_name="$1"
  local resolved
  resolved="$(command -v "${cmd_name}" 2>/dev/null || true)"
  if [[ -n "${resolved}" && "${resolved}" != /* ]]; then
    resolved="$(type -P "${cmd_name}" 2>/dev/null || true)"
  fi
  if [[ -z "${resolved}" || "${resolved}" != /* ]]; then
    return 1
  fi
  printf '%s' "${resolved}"
}

require_root_owned_binary_path() {
  local binary_path="$1"
  local label="$2"
  local owner_uid=""
  if stat -c '%u' "${binary_path}" >/dev/null 2>&1; then
    owner_uid="$(stat -c '%u' "${binary_path}")"
  elif stat -f '%u' "${binary_path}" >/dev/null 2>&1; then
    owner_uid="$(stat -f '%u' "${binary_path}")"
  fi
  if [[ -z "${owner_uid}" ]]; then
    print_err "Unable to determine owner for ${label} binary at ${binary_path}"
    return 1
  fi
  if [[ "${owner_uid}" != "0" ]]; then
    print_err "${label} binary must be root-owned for privileged runtime safety: ${binary_path}"
    return 1
  fi
}

validate_macos_passphrase_source_contract() {
  if ! is_macos_host; then
    return 0
  fi
  ensure_macos_keychain_passphrase_account
  if [[ -z "${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}" ]]; then
    print_err "macOS keychain account for passphrase custody is empty."
    return 1
  fi
  if ! [[ "${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}" =~ ^[A-Za-z0-9._-]+$ ]]; then
    print_err "macOS keychain account has invalid characters: ${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}"
    return 1
  fi
  if [[ "${WG_KEY_PASSPHRASE_PATH}" != /* ]]; then
    print_err "macOS passphrase placeholder path must be absolute: ${WG_KEY_PASSPHRASE_PATH}"
    return 1
  fi
  if ! command -v security >/dev/null 2>&1; then
    print_err "macOS keychain tooling is unavailable: security command not found."
    return 1
  fi
  if [[ -f "${WG_KEY_PASSPHRASE_PATH}" ]]; then
    print_err "Persistent plaintext passphrase file is not allowed on macOS: ${WG_KEY_PASSPHRASE_PATH}"
    print_info "Delete the file and rerun setup to keep passphrase custody in Keychain only."
    return 1
  fi
  if ! macos_keychain_passphrase_exists; then
    print_err "macOS keychain passphrase item is missing (service=${MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}, account=${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT})."
    print_info "Run first-run setup to provision Keychain-backed passphrase custody."
    return 1
  fi
  return 0
}

configure_macos_binary_path_env() {
  if ! is_macos_host; then
    return 0
  fi

  add_macos_homebrew_to_path

  local wg_bin wireguard_go_bin ifconfig_bin route_bin pfctl_bin kill_bin rustynetd_bin
  wg_bin="$(resolve_absolute_command_path wg)" || {
    print_err "Unable to resolve absolute path for wg."
    return 1
  }
  wireguard_go_bin="$(resolve_absolute_command_path wireguard-go)" || {
    print_err "Unable to resolve absolute path for wireguard-go."
    return 1
  }
  ifconfig_bin="$(resolve_absolute_command_path ifconfig)" || {
    print_err "Unable to resolve absolute path for ifconfig."
    return 1
  }
  route_bin="$(resolve_absolute_command_path route)" || {
    print_err "Unable to resolve absolute path for route."
    return 1
  }
  pfctl_bin="$(resolve_absolute_command_path pfctl)" || {
    print_err "Unable to resolve absolute path for pfctl."
    return 1
  }
  kill_bin="$(resolve_absolute_command_path kill)" || {
    print_err "Unable to resolve absolute path for kill."
    return 1
  }
  rustynetd_bin="$(resolve_absolute_command_path rustynetd)" || {
    print_err "Unable to resolve absolute path for rustynetd."
    return 1
  }

  require_root_owned_binary_path "${wg_bin}" "wg" || return 1
  require_root_owned_binary_path "${wireguard_go_bin}" "wireguard-go" || return 1
  require_root_owned_binary_path "${ifconfig_bin}" "ifconfig" || return 1
  require_root_owned_binary_path "${route_bin}" "route" || return 1
  require_root_owned_binary_path "${pfctl_bin}" "pfctl" || return 1
  require_root_owned_binary_path "${kill_bin}" "kill" || return 1
  require_root_owned_binary_path "${rustynetd_bin}" "rustynetd" || return 1

  export RUSTYNET_WG_BINARY_PATH="${wg_bin}"
  export RUSTYNET_WIREGUARD_GO_BINARY_PATH="${wireguard_go_bin}"
  export RUSTYNET_IFCONFIG_BINARY_PATH="${ifconfig_bin}"
  export RUSTYNET_ROUTE_BINARY_PATH="${route_bin}"
  export RUSTYNET_PFCTL_BINARY_PATH="${pfctl_bin}"
  export RUSTYNET_KILL_BINARY_PATH="${kill_bin}"
  export RUSTYNET_DAEMON_BINARY_PATH="${rustynetd_bin}"
}

xml_escape() {
  local value="$1"
  value="${value//&/&amp;}"
  value="${value//</&lt;}"
  value="${value//>/&gt;}"
  value="${value//\"/&quot;}"
  value="${value//\'/&apos;}"
  printf '%s' "${value}"
}

macos_launchd_domain() {
  local uid
  uid="$(id -u)"
  if launchctl print "gui/${uid}" >/dev/null 2>&1; then
    printf 'gui/%s' "${uid}"
  else
    printf 'user/%s' "${uid}"
  fi
}

macos_launchd_bootout_unit() {
  local domain="$1"
  local label="$2"
  local plist_path="$3"
  local use_root="${4:-0}"
  local target="${domain}/${label}"
  if [[ "${use_root}" == "1" ]]; then
    if run_root launchctl bootout "${target}" 2>/dev/null; then
      return 0
    fi
    if run_root launchctl bootout "${domain}" "${plist_path}" 2>/dev/null; then
      return 0
    fi
    if ! run_root launchctl print "${target}" >/dev/null 2>&1; then
      return 0
    fi
  else
    if launchctl bootout "${target}" 2>/dev/null; then
      return 0
    fi
    if launchctl bootout "${domain}" "${plist_path}" 2>/dev/null; then
      return 0
    fi
    if ! launchctl print "${target}" >/dev/null 2>&1; then
      return 0
    fi
  fi
  print_err "Failed to unload launchd unit '${target}'."
  return 1
}

macos_install_launchd_units() {
  configure_macos_binary_path_env || return 1
  validate_macos_passphrase_source_contract || return 1

  local uid gid
  uid="$(id -u)"
  gid="$(id -g)"

  run_root install -d -m 0700 "${MACOS_RUNTIME_BASE}" "${MACOS_LOG_BASE}"
  run_root chown "${uid}:${gid}" "${MACOS_RUNTIME_BASE}" "${MACOS_LOG_BASE}"
  install -d -m 0700 "$(dirname "${MACOS_LAUNCHD_DAEMON_PLIST_PATH}")"
  run_root install -d -m 0755 /Library/LaunchDaemons

  local helper_plist_tmp daemon_plist_tmp
  helper_plist_tmp="$(mktemp)"
  daemon_plist_tmp="$(mktemp)"

  local bool_auto_tunnel bool_fail_closed_ssh
  bool_auto_tunnel="$( [[ "${AUTO_TUNNEL_ENFORCE}" == "1" ]] && echo true || echo false )"
  bool_fail_closed_ssh="$( [[ "${FAIL_CLOSED_SSH_ALLOW}" == "1" ]] && echo true || echo false )"

  local esc_rustynetd esc_helper_socket esc_timeout esc_uid esc_gid esc_keychain_account
  local esc_wg_bin esc_wg_go_bin esc_ifconfig_bin esc_route_bin esc_pfctl_bin esc_kill_bin
  esc_rustynetd="$(xml_escape "${RUSTYNET_DAEMON_BINARY_PATH}")"
  esc_helper_socket="$(xml_escape "${PRIVILEGED_HELPER_SOCKET_PATH}")"
  esc_timeout="$(xml_escape "${PRIVILEGED_HELPER_TIMEOUT_MS}")"
  esc_uid="$(xml_escape "${uid}")"
  esc_gid="$(xml_escape "${gid}")"
  esc_wg_bin="$(xml_escape "${RUSTYNET_WG_BINARY_PATH}")"
  esc_wg_go_bin="$(xml_escape "${RUSTYNET_WIREGUARD_GO_BINARY_PATH}")"
  esc_ifconfig_bin="$(xml_escape "${RUSTYNET_IFCONFIG_BINARY_PATH}")"
  esc_route_bin="$(xml_escape "${RUSTYNET_ROUTE_BINARY_PATH}")"
  esc_pfctl_bin="$(xml_escape "${RUSTYNET_PFCTL_BINARY_PATH}")"
  esc_kill_bin="$(xml_escape "${RUSTYNET_KILL_BINARY_PATH}")"
  esc_keychain_account="$(xml_escape "${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}")"

  cat >"${helper_plist_tmp}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${MACOS_LAUNCHD_HELPER_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${esc_rustynetd}</string>
    <string>privileged-helper</string>
    <string>--socket</string>
    <string>${esc_helper_socket}</string>
    <string>--allowed-uid</string>
    <string>${esc_uid}</string>
    <string>--allowed-gid</string>
    <string>${esc_gid}</string>
    <string>--timeout-ms</string>
    <string>${esc_timeout}</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>RUSTYNET_WG_BINARY_PATH</key>
    <string>${esc_wg_bin}</string>
    <key>RUSTYNET_WIREGUARD_GO_BINARY_PATH</key>
    <string>${esc_wg_go_bin}</string>
    <key>RUSTYNET_IFCONFIG_BINARY_PATH</key>
    <string>${esc_ifconfig_bin}</string>
    <key>RUSTYNET_ROUTE_BINARY_PATH</key>
    <string>${esc_route_bin}</string>
    <key>RUSTYNET_PFCTL_BINARY_PATH</key>
    <string>${esc_pfctl_bin}</string>
    <key>RUSTYNET_KILL_BINARY_PATH</key>
    <string>${esc_kill_bin}</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$(xml_escape "${MACOS_HELPER_LOG_PATH}")</string>
  <key>StandardErrorPath</key>
  <string>$(xml_escape "${MACOS_HELPER_LOG_PATH}")</string>
</dict>
</plist>
EOF

  cat >"${daemon_plist_tmp}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${MACOS_LAUNCHD_DAEMON_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${esc_rustynetd}</string>
    <string>daemon</string>
    <string>--node-id</string>
    <string>$(xml_escape "${DEVICE_NODE_ID}")</string>
    <string>--node-role</string>
    <string>$(xml_escape "${NODE_ROLE}")</string>
    <string>--socket</string>
    <string>$(xml_escape "${SOCKET_PATH}")</string>
    <string>--state</string>
    <string>$(xml_escape "${STATE_PATH}")</string>
    <string>--trust-evidence</string>
    <string>$(xml_escape "${TRUST_EVIDENCE_PATH}")</string>
    <string>--trust-verifier-key</string>
    <string>$(xml_escape "${TRUST_VERIFIER_KEY_PATH}")</string>
    <string>--trust-watermark</string>
    <string>$(xml_escape "${TRUST_WATERMARK_PATH}")</string>
    <string>--membership-snapshot</string>
    <string>$(xml_escape "${MEMBERSHIP_SNAPSHOT_PATH}")</string>
    <string>--membership-log</string>
    <string>$(xml_escape "${MEMBERSHIP_LOG_PATH}")</string>
    <string>--membership-watermark</string>
    <string>$(xml_escape "${MEMBERSHIP_WATERMARK_PATH}")</string>
    <string>--auto-tunnel-enforce</string>
    <string>$(xml_escape "${bool_auto_tunnel}")</string>
    <string>--auto-tunnel-bundle</string>
    <string>$(xml_escape "${AUTO_TUNNEL_BUNDLE_PATH}")</string>
    <string>--auto-tunnel-verifier-key</string>
    <string>$(xml_escape "${AUTO_TUNNEL_VERIFIER_KEY_PATH}")</string>
    <string>--auto-tunnel-watermark</string>
    <string>$(xml_escape "${AUTO_TUNNEL_WATERMARK_PATH}")</string>
    <string>--auto-tunnel-max-age-secs</string>
    <string>$(xml_escape "${AUTO_TUNNEL_MAX_AGE_SECS}")</string>
    <string>--traversal-bundle</string>
    <string>$(xml_escape "${TRAVERSAL_BUNDLE_PATH}")</string>
    <string>--traversal-verifier-key</string>
    <string>$(xml_escape "${TRAVERSAL_VERIFIER_KEY_PATH}")</string>
    <string>--traversal-watermark</string>
    <string>$(xml_escape "${TRAVERSAL_WATERMARK_PATH}")</string>
    <string>--traversal-max-age-secs</string>
    <string>$(xml_escape "${TRAVERSAL_MAX_AGE_SECS}")</string>
    <string>--backend</string>
    <string>$(xml_escape "${BACKEND_MODE}")</string>
    <string>--wg-interface</string>
    <string>$(xml_escape "${WG_INTERFACE}")</string>
    <string>--wg-listen-port</string>
    <string>$(xml_escape "${WG_LISTEN_PORT}")</string>
    <string>--wg-private-key</string>
    <string>$(xml_escape "${WG_PRIVATE_KEY_PATH}")</string>
    <string>--wg-encrypted-private-key</string>
    <string>$(xml_escape "${WG_ENCRYPTED_PRIVATE_KEY_PATH}")</string>
    <string>--wg-key-passphrase</string>
    <string>$(xml_escape "${WG_KEY_PASSPHRASE_PATH}")</string>
    <string>--wg-public-key</string>
    <string>$(xml_escape "${WG_PUBLIC_KEY_PATH}")</string>
    <string>--egress-interface</string>
    <string>$(xml_escape "${EGRESS_INTERFACE}")</string>
    <string>--dataplane-mode</string>
    <string>$(xml_escape "${DATAPLANE_MODE}")</string>
    <string>--privileged-helper-socket</string>
    <string>${esc_helper_socket}</string>
    <string>--privileged-helper-timeout-ms</string>
    <string>${esc_timeout}</string>
    <string>--reconcile-interval-ms</string>
    <string>$(xml_escape "${RECONCILE_INTERVAL_MS}")</string>
    <string>--max-reconcile-failures</string>
    <string>$(xml_escape "${MAX_RECONCILE_FAILURES}")</string>
    <string>--fail-closed-ssh-allow</string>
    <string>$(xml_escape "${bool_fail_closed_ssh}")</string>
    <string>--fail-closed-ssh-allow-cidrs</string>
    <string>$(xml_escape "${FAIL_CLOSED_SSH_ALLOW_CIDRS}")</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>RUSTYNET_WG_BINARY_PATH</key>
    <string>${esc_wg_bin}</string>
    <key>RUSTYNET_WIREGUARD_GO_BINARY_PATH</key>
    <string>${esc_wg_go_bin}</string>
    <key>RUSTYNET_IFCONFIG_BINARY_PATH</key>
    <string>${esc_ifconfig_bin}</string>
    <key>RUSTYNET_ROUTE_BINARY_PATH</key>
    <string>${esc_route_bin}</string>
    <key>RUSTYNET_PFCTL_BINARY_PATH</key>
    <string>${esc_pfctl_bin}</string>
    <key>RUSTYNET_KILL_BINARY_PATH</key>
    <string>${esc_kill_bin}</string>
    <key>RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT</key>
    <string>${esc_keychain_account}</string>
    <key>RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH</key>
    <string>$(xml_escape "${WG_KEY_PASSPHRASE_PATH}")</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$(xml_escape "${MACOS_DAEMON_LOG_PATH}")</string>
  <key>StandardErrorPath</key>
  <string>$(xml_escape "${MACOS_DAEMON_LOG_PATH}")</string>
</dict>
</plist>
EOF

  run_root install -m 0644 "${helper_plist_tmp}" "${MACOS_LAUNCHD_HELPER_PLIST_PATH}"
  if ! run_root chown root:wheel "${MACOS_LAUNCHD_HELPER_PLIST_PATH}" 2>/dev/null; then
    run_root chown root:root "${MACOS_LAUNCHD_HELPER_PLIST_PATH}"
  fi
  install -m 0644 "${daemon_plist_tmp}" "${MACOS_LAUNCHD_DAEMON_PLIST_PATH}"

  rm -f "${helper_plist_tmp}" "${daemon_plist_tmp}"
}

macos_start_launchd_services() {
  macos_install_launchd_units || return 1
  local daemon_domain
  daemon_domain="$(macos_launchd_domain)"

  macos_launchd_bootout_unit "system" "${MACOS_LAUNCHD_HELPER_LABEL}" "${MACOS_LAUNCHD_HELPER_PLIST_PATH}" "1" || return 1
  macos_launchd_bootout_unit "${daemon_domain}" "${MACOS_LAUNCHD_DAEMON_LABEL}" "${MACOS_LAUNCHD_DAEMON_PLIST_PATH}" "0" || return 1

  run_root launchctl bootstrap system "${MACOS_LAUNCHD_HELPER_PLIST_PATH}"
  run_root launchctl kickstart -k "system/${MACOS_LAUNCHD_HELPER_LABEL}"
  launchctl bootstrap "${daemon_domain}" "${MACOS_LAUNCHD_DAEMON_PLIST_PATH}"
  launchctl kickstart -k "${daemon_domain}/${MACOS_LAUNCHD_DAEMON_LABEL}"

  if ! macos_wait_for_socket "${PRIVILEGED_HELPER_SOCKET_PATH}"; then
    print_err "Timed out waiting for macOS privileged helper socket at ${PRIVILEGED_HELPER_SOCKET_PATH}."
    return 1
  fi
  if ! macos_wait_for_socket "${SOCKET_PATH}"; then
    print_err "Timed out waiting for rustynetd socket at ${SOCKET_PATH}."
    tail -n 40 "${MACOS_DAEMON_LOG_PATH}" 2>/dev/null || true
    return 1
  fi
}

macos_stop_launchd_services() {
  local daemon_domain
  daemon_domain="$(macos_launchd_domain)"
  macos_launchd_bootout_unit "${daemon_domain}" "${MACOS_LAUNCHD_DAEMON_LABEL}" "${MACOS_LAUNCHD_DAEMON_PLIST_PATH}" "0" || return 1
  macos_launchd_bootout_unit "system" "${MACOS_LAUNCHD_HELPER_LABEL}" "${MACOS_LAUNCHD_HELPER_PLIST_PATH}" "1" || return 1
  rm -f "${SOCKET_PATH}" "${PRIVILEGED_HELPER_SOCKET_PATH}"
  return 0
}

start_or_restart_service() {
  if ! doctor_preflight; then
    print_err "Refusing to start service until preflight doctor passes."
    return 1
  fi
  if is_blind_exit_role; then
    lockdown_blind_exit_local_material || return 1
  fi
  write_daemon_environment
  if [[ "${AUTO_REFRESH_TRUST}" == "1" && -f "${TRUST_SIGNER_KEY_PATH}" ]]; then
    if ! refresh_signed_trust_evidence; then
      print_err "Failed to refresh trust evidence before start; refusing daemon start."
      return 1
    fi
  fi

  if is_linux_host; then
    run_root systemctl daemon-reload
    run_root systemctl enable rustynetd.service
    run_root systemctl restart rustynetd.service
    if ! run_root systemctl --no-pager --full status rustynetd.service; then
      print_warn "Unable to read rustynetd.service status after restart."
    fi
    return
  fi

  if is_macos_host; then
    macos_start_launchd_services
    show_service_status
    return
  fi

  require_linux_dataplane "start_or_restart_service" || return 0
}

stop_service() {
  if is_linux_host; then
    run_root systemctl stop rustynetd.service
    return
  fi
  if is_macos_host; then
    macos_stop_launchd_services
    return
  fi
  require_linux_dataplane "stop_service" || return 0
}

disconnect_vpn() {
  if is_macos_host; then
    local had_error=0
    print_info "Disabling exit-node mode before shutdown..."
    if [[ -S "${SOCKET_PATH}" ]]; then
      if ! run_rustynet_cli exit-node off >/dev/null 2>&1; then
        print_err "Failed to disable exit-node mode before disconnect."
        had_error=1
      fi
    else
      print_info "Daemon socket not present; skipping exit-node disable."
    fi
    print_info "Stopping Rustynet daemon + privileged helper..."
    if ! stop_service; then
      print_err "Failed to stop Rustynet launchd services cleanly."
      had_error=1
    fi
    print_info "Stopping any remaining wireguard-go process for ${WG_INTERFACE}..."
    if run_root pgrep -f "wireguard-go ${WG_INTERFACE}" >/dev/null 2>&1; then
      if ! run_root pkill -f "wireguard-go ${WG_INTERFACE}" 2>/dev/null; then
        print_err "Failed to stop wireguard-go process for ${WG_INTERFACE}."
        had_error=1
      fi
    else
      print_info "No wireguard-go process found for ${WG_INTERFACE}."
    fi
    print_info "Flushing Rustynet PF anchors..."
    local anchors_output=""
    if ! anchors_output="$(run_root pfctl -s Anchors 2>/dev/null)"; then
      print_err "Failed to enumerate PF anchors."
      had_error=1
      anchors_output=""
    fi
    while IFS= read -r anchor; do
      [[ -z "${anchor}" ]] && continue
      if [[ "${anchor}" == com.apple/rustynet_g* ]]; then
        if ! run_root pfctl -a "${anchor}" -F all 2>/dev/null; then
          print_err "Failed to flush PF anchor ${anchor}."
          had_error=1
        fi
      fi
    done <<<"${anchors_output}"
    if [[ "${had_error}" -ne 0 ]]; then
      print_err "Rustynet disconnect completed with residual-state errors."
      return 1
    fi
    print_info "Rustynet VPN disconnected."
    return
  fi

  require_linux_dataplane "disconnect_vpn" || return 0
  local had_error=0
  print_info "Stopping Rustynet service..."
  if run_root systemctl is-active --quiet rustynetd.service 2>/dev/null; then
    if ! run_root systemctl stop rustynetd.service 2>/dev/null; then
      print_err "Rustynet service is active but failed to stop cleanly."
      had_error=1
    fi
  else
    print_info "Rustynet service is already stopped."
  fi

  print_info "Removing WireGuard interface ${WG_INTERFACE}..."
  if run_root ip link show dev "${WG_INTERFACE}" >/dev/null 2>&1; then
    if run_root ip link del dev "${WG_INTERFACE}" 2>/dev/null; then
      print_info "Interface ${WG_INTERFACE} removed (all associated routes cleared)."
    else
      print_err "Failed to remove interface ${WG_INTERFACE}."
      had_error=1
    fi
  else
    print_info "Interface ${WG_INTERFACE} was not present."
  fi

  print_info "Flushing exit-node routing table 51820..."
  local routes_51820=""
  routes_51820="$(run_root ip route show table 51820 2>/dev/null || true)"
  if [[ -n "${routes_51820}" ]]; then
    if ! run_root ip route flush table 51820 2>/dev/null; then
      print_err "Failed to flush routing table 51820."
      had_error=1
    fi
  else
    print_info "No routes present in table 51820."
  fi

  print_info "Removing exit-node IP policy rule (table 51820)..."
  local removed_rule=0
  while run_root ip rule list 2>/dev/null | grep -Eq '(^|[[:space:]])lookup[[:space:]]+51820($|[[:space:]])'; do
    removed_rule=1
    if ! run_root ip rule del table 51820 2>/dev/null; then
      print_err "Failed to remove one or more policy rules for table 51820."
      had_error=1
      break
    fi
  done
  if [[ "${removed_rule}" -eq 0 ]]; then
    print_info "No policy rules found for table 51820."
  fi

  print_info "Removing Rustynet nftables firewall and NAT tables..."
  if command -v nft >/dev/null 2>&1; then
    local tables_output
    if ! tables_output="$(run_root nft list tables 2>/dev/null)"; then
      print_err "Failed to enumerate nftables tables."
      had_error=1
      tables_output=""
    fi
    while IFS= read -r line; do
      case "${line}" in
        "table inet rustynet_g"*)
          local t="${line#table inet }"
          if run_root nft delete table inet "${t}" 2>/dev/null; then
            print_info "Removed nft table: inet ${t}"
          else
            print_err "Failed to remove nft table: inet ${t}"
            had_error=1
          fi
          ;;
        "table ip rustynet_nat_g"*)
          local t="${line#table ip }"
          if run_root nft delete table ip "${t}" 2>/dev/null; then
            print_info "Removed nft table: ip ${t}"
          else
            print_err "Failed to remove nft table: ip ${t}"
            had_error=1
          fi
          ;;
      esac
    done <<< "${tables_output}"
  fi

  print_info "Restoring IPv6 (disabled during VPN operation)..."
  if ! run_root sysctl -w net.ipv6.conf.all.disable_ipv6=0 2>/dev/null; then
    print_err "Failed to restore IPv6 global setting."
    had_error=1
  fi

  if [[ "${had_error}" -ne 0 ]]; then
    print_err "Rustynet disconnect completed with residual-state errors."
    return 1
  fi

  print_info "Rustynet VPN disconnected. Device is now using normal internet connectivity."
}

show_service_status() {
  if is_linux_host; then
    if ! run_root systemctl --no-pager --full status rustynetd.service; then
      print_warn "Unable to read rustynetd.service status."
    fi
    return
  fi
  if is_macos_host; then
    local daemon_domain daemon_target helper_target
    daemon_domain="$(macos_launchd_domain)"
    daemon_target="${daemon_domain}/${MACOS_LAUNCHD_DAEMON_LABEL}"
    helper_target="system/${MACOS_LAUNCHD_HELPER_LABEL}"
    if launchctl print "${daemon_target}" >/dev/null 2>&1; then
      print_info "rustynetd launchd unit loaded (${daemon_target})"
    else
      print_warn "rustynetd launchd unit is not loaded (${daemon_target})."
    fi
    if run_root launchctl print "${helper_target}" >/dev/null 2>&1; then
      print_info "privileged helper launchd unit loaded (${helper_target})"
    else
      print_warn "privileged helper launchd unit is not loaded (${helper_target})."
    fi
    if [[ -S "${SOCKET_PATH}" ]]; then
      print_info "daemon IPC socket present (${SOCKET_PATH})"
    else
      print_warn "daemon IPC socket missing (${SOCKET_PATH})"
    fi
    if [[ -S "${PRIVILEGED_HELPER_SOCKET_PATH}" ]]; then
      print_info "privileged helper socket present (${PRIVILEGED_HELPER_SOCKET_PATH})"
    else
      print_warn "privileged helper socket missing (${PRIVILEGED_HELPER_SOCKET_PATH})"
    fi
    return
  fi
  require_linux_dataplane "show_service_status" || return 0
}

ensure_peer_store() {
  local output=""
  if ! output="$(run_rustynet_cli ops peer-store-validate --config-dir "${CONFIG_DIR}" --peers-file "${PEERS_FILE}" 2>&1)"; then
    print_err "Peer-store validation failed."
    if [[ -n "${output}" ]]; then
      print_err "${output}"
    fi
    return 1
  fi
}

peer_store_list_records() {
  local role_filter="${1:-}"
  local node_id_filter="${2:-}"
  local args=(ops peer-store-list --config-dir "${CONFIG_DIR}" --peers-file "${PEERS_FILE}")
  if [[ -n "${role_filter}" ]]; then
    args+=(--role "${role_filter}")
  fi
  if [[ -n "${node_id_filter}" ]]; then
    args+=(--node-id "${node_id_filter}")
  fi
  run_rustynet_cli "${args[@]}"
}

peer_endpoint_host() {
  local endpoint="$1"
  if [[ -z "${endpoint}" ]]; then
    return 1
  fi
  if [[ "${endpoint}" =~ ^\[([^]]+)\]:[0-9]+$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "${endpoint}" =~ ^([^:]+):[0-9]+$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  printf '%s' "${endpoint}"
}

probe_peer_online_status() {
  local endpoint="$1"
  local host
  if ! host="$(peer_endpoint_host "${endpoint}")"; then
    printf 'unknown'
    return 0
  fi
  if [[ -z "${host}" ]]; then
    printf 'unknown'
    return 0
  fi
  if ! command -v ping >/dev/null 2>&1; then
    printf 'unknown'
    return 0
  fi
  if is_linux_host; then
    if ping -n -c 1 -W 1 "${host}" >/dev/null 2>&1; then
      printf 'online'
    else
      printf 'offline'
    fi
    return 0
  fi
  if is_macos_host; then
    if ping -n -c 1 -W 1000 "${host}" >/dev/null 2>&1; then
      printf 'online'
    else
      printf 'offline'
    fi
    return 0
  fi
  if ping -n -c 1 "${host}" >/dev/null 2>&1; then
    printf 'online'
  else
    printf 'offline'
  fi
}

print_saved_peers() {
  local records_output name node_id public_key endpoint cidr role status
  if ! records_output="$(peer_store_list_records 2>&1)"; then
    print_err "Unable to read peer store."
    print_err "${records_output}"
    return 1
  fi
  while IFS='|' read -r name node_id public_key endpoint cidr role _rest; do
    if [[ "${name}" == \#* || -z "${name}" ]]; then
      continue
    fi
    if [[ -z "${node_id}" || -z "${endpoint}" || -z "${cidr}" ]]; then
      continue
    fi
    if [[ -z "${role}" ]]; then
      role="unknown"
    fi
    status="$(probe_peer_online_status "${endpoint}")"
    printf '  - %s (node=%s endpoint=%s cidr=%s role=%s status=%s)\n' \
      "${name}" "${node_id}" "${endpoint}" "${cidr}" "${role}" "${status}"
  done <<< "${records_output}"
}

print_saved_admin_peers() {
  local records_output name node_id public_key endpoint cidr role
  if ! records_output="$(peer_store_list_records "admin" 2>&1)"; then
    print_err "Unable to read admin peer records."
    print_err "${records_output}"
    return 1
  fi
  while IFS='|' read -r name node_id public_key endpoint cidr role _rest; do
    if [[ -z "${name}" || -z "${node_id}" || -z "${endpoint}" || -z "${cidr}" ]]; then
      continue
    fi
    printf '  - %s (node=%s endpoint=%s cidr=%s)\n' \
      "${name}" "${node_id}" "${endpoint}" "${cidr}"
  done <<< "${records_output}"
}

find_peer_record_by_node_id() {
  local node_id="$1"
  local records_output line
  if [[ -z "${node_id}" ]]; then
    return 0
  fi
  if ! records_output="$(peer_store_list_records "" "${node_id}" 2>/dev/null)"; then
    return 1
  fi
  while IFS= read -r line || [[ -n "${line}" ]]; do
    if [[ -n "${line}" ]]; then
      printf '%s\n' "${line}"
      break
    fi
  done <<< "${records_output}"
}

run_rustynet_cli() {
  if ! command -v rustynet >/dev/null 2>&1; then
    print_err "rustynet CLI not found in PATH."
    return 1
  fi
  RUSTYNET_DAEMON_SOCKET="${SOCKET_PATH}" rustynet "$@"
}

wait_for_daemon_socket_ready() {
  local attempts="${1:-20}"
  if [[ -z "${SOCKET_PATH}" ]]; then
    return 1
  fi
  while (( attempts > 0 )); do
    if [[ -S "${SOCKET_PATH}" ]]; then
      return 0
    fi
    sleep 1
    attempts=$((attempts - 1))
  done
  return 1
}

is_valid_node_id_value() {
  local node_id="$1"
  [[ "${node_id}" =~ ^[A-Za-z0-9._-]+$ ]]
}

local_assignment_refresh_available() {
  if ! is_linux_host; then
    return 1
  fi
  run_root test -f "${ASSIGNMENT_REFRESH_ENV_PATH}" >/dev/null 2>&1 || return 1
  run_root systemctl cat rustynetd-assignment-refresh.service >/dev/null 2>&1 || return 1
  return 0
}

set_local_assignment_refresh_exit_node() {
  local exit_node_id="${1:-}"

  if ! is_linux_host; then
    return 0
  fi
  if ! local_assignment_refresh_available; then
    print_warn "Assignment refresh is not configured locally; skipping persisted exit-node update."
    return 1
  fi
  if [[ -n "${exit_node_id}" ]] && ! is_valid_node_id_value "${exit_node_id}"; then
    print_err "Invalid exit node id '${exit_node_id}'. Allowed characters: letters, numbers, dot, underscore, hyphen."
    return 1
  fi

  if ! command -v rustynet >/dev/null 2>&1; then
    print_err "rustynet CLI is required for assignment refresh env updates."
    return 1
  fi

  if [[ -n "${exit_node_id}" ]]; then
    if ! run_root rustynet ops set-assignment-refresh-exit-node \
      --env-path "${ASSIGNMENT_REFRESH_ENV_PATH}" \
      --exit-node-id "${exit_node_id}" >/dev/null 2>&1; then
      print_err "Rust-backed assignment refresh env update failed; setup is fail-closed."
      return 1
    fi
  else
    if ! run_root rustynet ops set-assignment-refresh-exit-node \
      --env-path "${ASSIGNMENT_REFRESH_ENV_PATH}" >/dev/null 2>&1; then
      print_err "Rust-backed assignment refresh env update failed; setup is fail-closed."
      return 1
    fi
  fi

  if [[ -n "${exit_node_id}" ]]; then
    print_info "Persisted preferred exit node in ${ASSIGNMENT_REFRESH_ENV_PATH}: ${exit_node_id}"
  else
    print_info "Cleared preferred exit node from ${ASSIGNMENT_REFRESH_ENV_PATH}."
  fi
  return 0
}

force_local_assignment_refresh_now() {
  if ! is_linux_host; then
    return 0
  fi
  if ! local_assignment_refresh_available; then
    print_warn "Assignment refresh service is unavailable; skipping forced local assignment refresh."
    return 1
  fi

  print_info "Forcing local assignment bundle refresh (signed) to apply role/exit changes immediately."
  run_root rm -f "${AUTO_TUNNEL_BUNDLE_PATH}" "${AUTO_TUNNEL_WATERMARK_PATH}"
  if ! run_root systemctl start rustynetd-assignment-refresh.service; then
    print_warn "Failed to run rustynetd-assignment-refresh.service."
    return 1
  fi
  if ! run_root systemctl restart rustynetd.service; then
    print_warn "Failed to restart rustynetd.service after forced assignment refresh."
    return 1
  fi
  if ! wait_for_daemon_socket_ready 20; then
    print_warn "Daemon socket did not become ready after assignment refresh restart."
    return 1
  fi
  return 0
}

switch_node_role_mode() {
  local previous_role target_role preferred_exit_node enable_exit_advertise
  local enable_exit_advertise_bool
  local role_confirm_default

  normalize_node_role
  if blind_exit_role_locked; then
    print_blind_exit_lock_notice
    return 1
  fi
  previous_role="${NODE_ROLE}"
  print_info "Current node role: ${previous_role}"
  prompt_default target_role "Target node role (admin|client)" "${NODE_ROLE}"

  case "${target_role}" in
    admin|client) ;;
    *)
      print_err "Unsupported role '${target_role}'. Expected 'admin' or 'client'."
      return 1
      ;;
  esac

  if [[ "${target_role}" == "${previous_role}" ]]; then
    print_info "Node is already configured as '${target_role}'."
    return 0
  fi

  preferred_exit_node=""
  enable_exit_advertise="0"
  if [[ "${target_role}" == "admin" ]]; then
    role_confirm_default="n"
    if [[ "${previous_role}" == "admin" ]]; then
      role_confirm_default="y"
    fi
    if ! prompt_yes_no "Confirm switch to admin role (full control-plane privileges)" "${role_confirm_default}"; then
      print_info "Role switch cancelled."
      return 0
    fi
    if prompt_yes_no "Enable exit serving now (advertise 0.0.0.0/0 after switch)?" "y"; then
      enable_exit_advertise="1"
    fi
  else
    prompt_default preferred_exit_node "Preferred exit node id after switch (blank for none)" ""
    if [[ -n "${preferred_exit_node}" ]] && ! is_valid_node_id_value "${preferred_exit_node}"; then
      print_err "Invalid exit node id '${preferred_exit_node}'. Allowed characters: letters, numbers, dot, underscore, hyphen."
      return 1
    fi
  fi

  NODE_ROLE="${target_role}"
  enforce_role_policy_defaults
  save_config

  if [[ "${SETUP_COMPLETE}" != "1" ]]; then
    print_warn "Setup is not complete; role updated in config only."
    return 0
  fi

  write_daemon_environment
  if ! start_or_restart_service; then
    print_err "Role switch aborted because service restart failed."
    return 1
  fi
  if ! wait_for_daemon_socket_ready 20; then
    print_warn "Daemon socket did not become ready after role switch; deferred actions may fail."
  fi

  if is_linux_host; then
    enable_exit_advertise_bool="false"
    if [[ "${enable_exit_advertise}" == "1" ]]; then
      enable_exit_advertise_bool="true"
    fi
    if ! command -v rustynet >/dev/null 2>&1; then
      print_err "rustynet CLI is required for role-coupling operations."
      return 1
    fi
    local role_coupling_cmd=(rustynet ops apply-role-coupling \
      --target-role "${target_role}" \
      --enable-exit-advertise "${enable_exit_advertise_bool}" \
      --env-path "${ASSIGNMENT_REFRESH_ENV_PATH}")
    if [[ -n "${preferred_exit_node}" ]]; then
      role_coupling_cmd+=(--preferred-exit-node-id "${preferred_exit_node}")
    fi
    if ! run_root env \
      RUSTYNET_SOCKET="${SOCKET_PATH}" \
      RUSTYNET_AUTO_TUNNEL_BUNDLE="${AUTO_TUNNEL_BUNDLE_PATH}" \
      RUSTYNET_AUTO_TUNNEL_WATERMARK="${AUTO_TUNNEL_WATERMARK_PATH}" \
      "${role_coupling_cmd[@]}"; then
      print_err "Rust-backed role coupling failed; setup is fail-closed."
      return 1
    fi
  else
    if [[ "${target_role}" == "client" && -n "${preferred_exit_node}" ]]; then
      if ! run_rustynet_cli exit-node select "${preferred_exit_node}"; then
        print_err "Failed to select exit node '${preferred_exit_node}' during role switch."
        return 1
      fi
    elif [[ "${target_role}" == "admin" && "${enable_exit_advertise}" == "1" ]]; then
      if ! offer_device_as_exit_node; then
        print_err "Failed to advertise device as exit node during role switch."
        return 1
      fi
    fi
  fi

  refresh_menu_runtime_status
  print_info "Node role switched: ${previous_role} -> ${target_role}"
  if [[ "${target_role}" == "admin" ]]; then
    print_warn "Peers can route through this node only when signed assignments include this node and allow rules."
  fi
}

restore_exit_selection() {
  local original_exit_node="$1"
  if [[ -n "${original_exit_node}" && "${original_exit_node}" != "none" ]]; then
    run_rustynet_cli exit-node select "${original_exit_node}" >/dev/null 2>&1 || true
  else
    run_rustynet_cli exit-node off >/dev/null 2>&1 || true
  fi
}

extract_status_field() {
  local status_line="$1"
  local key="$2"
  awk -v key="${key}" '{
    for (i = 1; i <= NF; i++) {
      if (index($i, key "=") == 1) {
        print substr($i, length(key) + 2)
        exit
      }
    }
  }' <<<"${status_line}"
}

current_exit_node_from_status() {
  local status_line
  status_line="$(run_rustynet_cli status 2>/dev/null || true)"
  local current_exit
  current_exit="$(extract_status_field "${status_line}" "exit_node")"
  if [[ "${current_exit}" == "none" ]]; then
    current_exit=""
  fi
  printf '%s' "${current_exit}"
}

wait_for_exit_node_state() {
  local expected_node="$1"
  local attempts="${2:-12}"
  local current
  while (( attempts > 0 )); do
    current="$(current_exit_node_from_status)"
    if [[ "${current}" == "${expected_node}" ]]; then
      return 0
    fi
    sleep 1
    attempts=$((attempts - 1))
  done
  return 1
}

apply_exit_selection_change() {
  local target_node="${1:-}"
  if [[ -n "${target_node}" ]] && ! is_valid_node_id_value "${target_node}"; then
    print_err "Invalid exit node id '${target_node}'. Allowed characters: letters, numbers, dot, underscore, hyphen."
    return 1
  fi

  if is_linux_host && local_assignment_refresh_available; then
    set_local_assignment_refresh_exit_node "${target_node}" || return 1
    force_local_assignment_refresh_now || return 1
    if ! wait_for_exit_node_state "${target_node}" 12; then
      if [[ -n "${target_node}" ]]; then
        print_warn "Daemon did not report exit node '${target_node}' after signed assignment refresh."
      else
        print_warn "Daemon did not report cleared exit selection after signed assignment refresh."
      fi
    fi
    return 0
  fi

  if [[ -n "${target_node}" ]]; then
    run_rustynet_cli exit-node select "${target_node}"
  else
    run_rustynet_cli exit-node off
  fi
}

exit_chain_label() {
  if [[ "${EXIT_CHAIN_HOPS}" == "2" && -n "${EXIT_CHAIN_ENTRY_NODE_ID}" && -n "${EXIT_CHAIN_FINAL_NODE_ID}" ]]; then
    printf '2-hop(%s->%s)' "${EXIT_CHAIN_ENTRY_NODE_ID}" "${EXIT_CHAIN_FINAL_NODE_ID}"
    return
  fi
  if [[ -n "${EXIT_CHAIN_ENTRY_NODE_ID}" ]]; then
    printf '1-hop(%s)' "${EXIT_CHAIN_ENTRY_NODE_ID}"
    return
  fi
  printf 'none'
}

refresh_menu_runtime_status() {
  MENU_NETWORK_STATE="unknown"
  MENU_NETWORK_CONNECTED="unknown"
  MENU_NODE_ROLE="${NODE_ROLE}"
  MENU_EXIT_ROLE="off"
  MENU_EXIT_SELECTED_NODE="none"
  MENU_EXIT_SERVING="false"

  if ! is_linux_host && ! is_macos_host; then
    MENU_NETWORK_STATE="unsupported-host"
    MENU_NETWORK_CONNECTED="n/a"
    MENU_NODE_ROLE="${NODE_ROLE}"
    MENU_EXIT_ROLE="n/a"
    return
  fi

  if ! command -v rustynet >/dev/null 2>&1; then
    MENU_NETWORK_STATE="cli-missing"
    MENU_NETWORK_CONNECTED="no"
    MENU_NODE_ROLE="${NODE_ROLE}"
    MENU_EXIT_ROLE="unknown"
    return
  fi

  local status_line
  if ! status_line="$(RUSTYNET_DAEMON_SOCKET="${SOCKET_PATH}" rustynet status 2>/dev/null)"; then
    MENU_NETWORK_STATE="daemon-unreachable"
    MENU_NETWORK_CONNECTED="no"
    MENU_NODE_ROLE="${NODE_ROLE}"
    MENU_EXIT_ROLE="off"
    return
  fi

  MENU_NODE_ROLE="$(extract_status_field "${status_line}" "node_role")"
  if [[ -z "${MENU_NODE_ROLE}" ]]; then
    MENU_NODE_ROLE="${NODE_ROLE}"
  fi
  MENU_NETWORK_STATE="$(extract_status_field "${status_line}" "state")"
  MENU_EXIT_SELECTED_NODE="$(extract_status_field "${status_line}" "exit_node")"
  MENU_EXIT_SERVING="$(extract_status_field "${status_line}" "serving_exit_node")"

  case "${MENU_NETWORK_STATE}" in
    ControlTrusted|DataplaneApplied|ExitActive) MENU_NETWORK_CONNECTED="yes" ;;
    Init|FailClosed|"") MENU_NETWORK_CONNECTED="no" ;;
    *) MENU_NETWORK_CONNECTED="unknown" ;;
  esac

  if [[ "${MENU_EXIT_SERVING}" == "true" && "${MENU_EXIT_SELECTED_NODE}" != "none" && -n "${MENU_EXIT_SELECTED_NODE}" ]]; then
    MENU_EXIT_ROLE="serving+using(${MENU_EXIT_SELECTED_NODE})"
  elif [[ "${MENU_EXIT_SERVING}" == "true" ]]; then
    MENU_EXIT_ROLE="serving"
  elif [[ "${MENU_EXIT_SELECTED_NODE}" != "none" && -n "${MENU_EXIT_SELECTED_NODE}" ]]; then
    MENU_EXIT_ROLE="using(${MENU_EXIT_SELECTED_NODE})"
  else
    MENU_EXIT_ROLE="off"
  fi
}

print_menu_runtime_header() {
  refresh_menu_runtime_status
  local connected_display
  local node_role_display
  local state_display
  local exit_display
  local chain_display
  connected_display="$(printf '%s' "${MENU_NETWORK_CONNECTED}" | tr '[:lower:]' '[:upper:]')"
  node_role_display="$(printf '%s' "${MENU_NODE_ROLE}" | tr '[:lower:]' '[:upper:]')"
  state_display="$(printf '%s' "${MENU_NETWORK_STATE}" | tr '[:lower:]' '[:upper:]')"
  exit_display="$(printf '%s' "${MENU_EXIT_ROLE}" | tr '[:lower:]' '[:upper:]')"
  chain_display="$(printf '%s' "$(exit_chain_label)" | tr '[:lower:]' '[:upper:]')"
  printf '[status] Node role: %s | Connected: %s (state=%s) | Exit role: %s | Chain: %s\n' \
    "${node_role_display}" \
    "${connected_display}" \
    "${state_display}" \
    "${exit_display}" \
    "${chain_display}"
}

connect_to_device() {
  require_admin_role "connect_to_device" || return 0
  require_linux_dataplane "connect_to_device" || return 0
  print_err "Manual peer add/update is disabled."
  print_info "Use signed assignment issuance and assignment refresh (single hardened path)."
  return 1
}

disconnect_device() {
  require_admin_role "disconnect_device" || return 0
  require_linux_dataplane "disconnect_device" || return 0
  print_err "Manual peer remove is disabled."
  print_info "Use signed assignment updates and assignment refresh (single hardened path)."
  return 1
}

show_connected_devices() {
  echo "Saved peers:"
  print_saved_peers
  echo
  echo "WireGuard live state:"
  run_root wg show "${WG_INTERFACE}" || print_warn "Unable to read live WireGuard state."
}

connect_to_saved_admin_peers() {
  require_admin_role "connect_to_saved_admin_peers" || return 0
  require_linux_dataplane "connect_to_saved_admin_peers" || return 0
  print_err "Manual admin-peer sync is disabled."
  print_info "Use signed assignment workflows only (single hardened path)."
  return 1
}

rotate_local_key() {
  require_admin_role "rotate_local_key" || return 0
  run_rustynet_cli key rotate
}

revoke_local_key() {
  require_admin_role "revoke_local_key" || return 0
  if ! prompt_yes_no "Revoke local key material now? This disables connectivity until reinitialized." "n"; then
    print_info "Revoke cancelled."
    return 0
  fi
  run_rustynet_cli key revoke
}

apply_rotation_bundle() {
  require_admin_role "apply_rotation_bundle" || return 0
  require_linux_dataplane "apply_rotation_bundle" || return 0
  print_err "Manual peer key-rotation apply is disabled."
  print_info "Use signed membership/assignment key-rotation workflows only."
  return 1
}

configure_launch_defaults() {
  local profile_prompt
  if blind_exit_role_locked; then
    print_blind_exit_lock_notice
    print_info "Launch defaults are locked for blind_exit role."
    return 1
  fi
  if is_admin_role; then
    profile_prompt="Default launch profile (menu|quick-connect|quick-exit-node|quick-hybrid)"
  elif is_blind_exit_role; then
    profile_prompt="Default launch profile (menu|quick-exit-node)"
  else
    profile_prompt="Default launch profile (menu|quick-connect)"
  fi
  prompt_default DEFAULT_LAUNCH_PROFILE \
    "${profile_prompt}" \
    "${DEFAULT_LAUNCH_PROFILE}"
  prompt_default AUTO_LAUNCH_ON_START \
    "Auto-apply default launch profile on startup (0/1)" \
    "${AUTO_LAUNCH_ON_START}"
  prompt_default AUTO_LAUNCH_EXIT_NODE_ID \
    "Default exit node id for quick-connect/quick-hybrid (blank for none)" \
    "${AUTO_LAUNCH_EXIT_NODE_ID}"
  prompt_default AUTO_LAUNCH_LAN_MODE \
    "Default LAN mode for quick-exit-node/quick-hybrid (skip|on|off)" \
    "${AUTO_LAUNCH_LAN_MODE}"
  sanitize_launch_defaults
}

configure_values() {
  local detected_egress
  local previous_role selected_role confirm_default role_prompt
  detected_egress="$(detect_default_egress)"
  if [[ -z "${EGRESS_INTERFACE}" ]]; then
    if [[ -z "${detected_egress}" ]]; then
      print_err "Unable to detect default egress interface."
      print_info "Set EGRESS_INTERFACE explicitly in configuration before continuing."
      return 1
    fi
    EGRESS_INTERFACE="${detected_egress}"
  fi

  normalize_node_role
  previous_role="${NODE_ROLE}"
  if blind_exit_role_locked; then
    print_blind_exit_lock_notice
    return 1
  fi
  prompt_default DEVICE_NODE_ID "Local device node id (used for display)" "${DEVICE_NODE_ID}"
  role_prompt="Node role (admin|client)"
  if [[ "${SETUP_COMPLETE}" != "1" ]]; then
    role_prompt="Node role (admin|client|blind_exit)"
  fi
  prompt_default selected_role "${role_prompt}" "${NODE_ROLE}"
  case "${selected_role}" in
    admin|client|blind_exit) ;;
    *)
      print_err "Unsupported node role '${selected_role}'. Expected admin, client, or blind_exit."
      return 1
      ;;
  esac
  if [[ "${selected_role}" == "blind_exit" ]] && ! is_linux_host; then
    print_err "blind_exit role is supported only on Linux hosts."
    return 1
  fi
  if [[ "${SETUP_COMPLETE}" == "1" && "${selected_role}" != "${previous_role}" ]]; then
    if [[ "${selected_role}" == "blind_exit" || "${previous_role}" == "blind_exit" ]]; then
      print_blind_exit_lock_notice
      return 1
    fi
    print_warn "Role changes after setup must use 'Switch node role (guided client/admin transition)'."
    selected_role="${previous_role}"
  fi
  NODE_ROLE="${selected_role}"
  normalize_node_role
  if is_admin_role; then
    confirm_default="n"
    if [[ "${previous_role}" == "admin" ]]; then
      confirm_default="y"
    fi
    if ! prompt_yes_no "Confirm admin role for this node (full control-plane privileges)" "${confirm_default}"; then
      print_warn "Admin role confirmation declined. Reverting to client role."
      NODE_ROLE="client"
    fi
  elif is_blind_exit_role && [[ "${SETUP_COMPLETE}" != "1" ]]; then
    if ! prompt_yes_no "Confirm blind_exit role (immutable after setup; least-knowledge mode)" "n"; then
      print_warn "Blind-exit role confirmation declined. Reverting to client role."
      NODE_ROLE="client"
    fi
  fi

  if is_macos_host; then
    print_info "macOS dataplane profile is active."
    print_info "Runtime paths are user-scoped; Linux system roots (/etc,/var,/run) are rejected."
  fi

  prompt_default SOCKET_PATH "Daemon socket path" "${SOCKET_PATH}"
  prompt_default STATE_PATH "Daemon state path" "${STATE_PATH}"
  prompt_default TRUST_EVIDENCE_PATH "Trust evidence path" "${TRUST_EVIDENCE_PATH}"
  prompt_default TRUST_VERIFIER_KEY_PATH "Trust verifier key path" "${TRUST_VERIFIER_KEY_PATH}"
  prompt_default TRUST_WATERMARK_PATH "Trust watermark path" "${TRUST_WATERMARK_PATH}"
  enforce_auto_tunnel_policy
  print_info "Auto-tunnel enforcement is mandatory. Signed assignment bundles are required."
  prompt_default AUTO_TUNNEL_BUNDLE_PATH "Auto-tunnel bundle path" "${AUTO_TUNNEL_BUNDLE_PATH}"
  prompt_default AUTO_TUNNEL_VERIFIER_KEY_PATH "Auto-tunnel verifier key path" "${AUTO_TUNNEL_VERIFIER_KEY_PATH}"
  prompt_default AUTO_TUNNEL_WATERMARK_PATH "Auto-tunnel watermark path" "${AUTO_TUNNEL_WATERMARK_PATH}"
  prompt_default AUTO_TUNNEL_MAX_AGE_SECS "Auto-tunnel bundle max age (secs)" "${AUTO_TUNNEL_MAX_AGE_SECS}"
  prompt_default TRAVERSAL_BUNDLE_PATH "Traversal bundle path" "${TRAVERSAL_BUNDLE_PATH}"
  prompt_default TRAVERSAL_VERIFIER_KEY_PATH "Traversal verifier key path" "${TRAVERSAL_VERIFIER_KEY_PATH}"
  prompt_default TRAVERSAL_WATERMARK_PATH "Traversal watermark path" "${TRAVERSAL_WATERMARK_PATH}"
  prompt_default TRAVERSAL_MAX_AGE_SECS "Traversal bundle max age (secs)" "${TRAVERSAL_MAX_AGE_SECS}"
  prompt_default WG_INTERFACE "WireGuard interface name" "${WG_INTERFACE}"
  prompt_default WG_LISTEN_PORT "WireGuard listen port (1-65535)" "${WG_LISTEN_PORT}"
  if is_linux_host && ( is_admin_role || is_blind_exit_role ); then
    prompt_default AUTO_PORT_FORWARD_EXIT "Auto port-forward exit endpoint via NAT-PMP (0/1)" "${AUTO_PORT_FORWARD_EXIT}"
    if [[ "${AUTO_PORT_FORWARD_EXIT}" == "1" ]]; then
      prompt_default AUTO_PORT_FORWARD_LEASE_SECS "Auto port-forward lease seconds (>=60)" "${AUTO_PORT_FORWARD_LEASE_SECS}"
    fi
  else
    AUTO_PORT_FORWARD_EXIT="0"
  fi
  prompt_default WG_PRIVATE_KEY_PATH "WireGuard runtime private key path" "${WG_PRIVATE_KEY_PATH}"
  prompt_default WG_ENCRYPTED_PRIVATE_KEY_PATH "WireGuard encrypted private key path" "${WG_ENCRYPTED_PRIVATE_KEY_PATH}"
  if is_linux_host; then
    WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH="${LINUX_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}"
    SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH="${LINUX_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}"
    print_info "Linux passphrase credential blob path is pinned to ${WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}."
    print_info "Linux signing passphrase credential blob path is pinned to ${SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}."
  elif is_macos_host; then
    prompt_default WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT "WireGuard passphrase Keychain account" "${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}"
    ensure_macos_keychain_passphrase_account
    print_info "macOS passphrase custody uses Keychain service '${MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}'."
    print_info "Persistent plaintext passphrase files are disabled by default."
  else
    prompt_default WG_KEY_PASSPHRASE_PATH "WireGuard key passphrase file path" "${WG_KEY_PASSPHRASE_PATH}"
  fi
  prompt_default WG_PUBLIC_KEY_PATH "WireGuard public key path" "${WG_PUBLIC_KEY_PATH}"
  prompt_default EGRESS_INTERFACE "Egress interface" "${EGRESS_INTERFACE}"
  if [[ -z "${EGRESS_INTERFACE}" ]]; then
    print_err "Egress interface is required."
    return 1
  fi
  prompt_default MEMBERSHIP_SNAPSHOT_PATH "Membership snapshot path" "${MEMBERSHIP_SNAPSHOT_PATH}"
  prompt_default MEMBERSHIP_LOG_PATH "Membership log path" "${MEMBERSHIP_LOG_PATH}"
  prompt_default MEMBERSHIP_WATERMARK_PATH "Membership watermark path" "${MEMBERSHIP_WATERMARK_PATH}"
  prompt_default MEMBERSHIP_OWNER_SIGNING_KEY_PATH "Membership owner signing key path" "${MEMBERSHIP_OWNER_SIGNING_KEY_PATH}"
  enforce_backend_mode
  print_info "Backend mode is fixed to ${BACKEND_MODE} for this host profile."
  prompt_default DATAPLANE_MODE "Dataplane mode (shell|hybrid-native)" "${DATAPLANE_MODE}"
  prompt_default PRIVILEGED_HELPER_SOCKET_PATH "Privileged helper socket path" "${PRIVILEGED_HELPER_SOCKET_PATH}"
  prompt_default PRIVILEGED_HELPER_TIMEOUT_MS "Privileged helper timeout (ms)" "${PRIVILEGED_HELPER_TIMEOUT_MS}"
  prompt_default RECONCILE_INTERVAL_MS "Reconcile interval (ms)" "${RECONCILE_INTERVAL_MS}"
  prompt_default MAX_RECONCILE_FAILURES "Max reconcile failures" "${MAX_RECONCILE_FAILURES}"
  prompt_default FAIL_CLOSED_SSH_ALLOW "Allow SSH management during fail-closed mode (0/1)" "${FAIL_CLOSED_SSH_ALLOW}"
  if [[ "${FAIL_CLOSED_SSH_ALLOW}" == "1" ]]; then
    prompt_default FAIL_CLOSED_SSH_ALLOW_CIDRS "Fail-closed SSH allow CIDRs (comma-separated)" "${FAIL_CLOSED_SSH_ALLOW_CIDRS}"
  else
    FAIL_CLOSED_SSH_ALLOW="0"
    FAIL_CLOSED_SSH_ALLOW_CIDRS=""
  fi
  enforce_fail_closed_ssh_policy
  enforce_wg_listen_port_policy
  enforce_auto_port_forward_policy
  prompt_default TRUST_SIGNER_KEY_PATH "Trust signer key path (for auto-refresh)" "${TRUST_SIGNER_KEY_PATH}"

  if [[ "${MANUAL_PEER_OVERRIDE}" != "0" ]]; then
    print_warn "Manual peer break-glass override is removed; forcing MANUAL_PEER_OVERRIDE=0."
  fi
  MANUAL_PEER_OVERRIDE="0"

  enforce_role_policy_defaults
  configure_launch_defaults
  enforce_host_storage_policy
}

first_run_setup() {
  print_info "Starting first-run Rustynet setup wizard."
  if ! configure_values; then
    print_err "First-run setup aborted."
    return 1
  fi
  install_runtime_dependencies
  ensure_rust_toolchain
  ensure_ci_security_tools
  ensure_binaries_available
  prepare_system_directories
  ensure_wireguard_keys
  ensure_signing_passphrase_material
  ensure_membership_files
  configure_trust_material
  write_daemon_environment
  lockdown_blind_exit_local_material
  start_or_restart_service
  SETUP_COMPLETE="1"
  save_config
  if is_blind_exit_role; then
    print_warn "blind_exit role setup complete: this role is now immutable until factory reset."
    print_info "Local control-plane mutation commands are disabled; exit serving is maintained automatically."
  fi
  print_info "First-run setup complete."
}

show_runtime_config() {
  cat <<EOF
Current Rustynet Wizard Configuration
  node_id                 : ${DEVICE_NODE_ID}
  node_role               : ${NODE_ROLE}
  host_profile            : ${HOST_PROFILE}
  socket                  : ${SOCKET_PATH}
  state                   : ${STATE_PATH}
  trust_evidence          : ${TRUST_EVIDENCE_PATH}
  trust_verifier_key      : ${TRUST_VERIFIER_KEY_PATH}
  trust_watermark         : ${TRUST_WATERMARK_PATH}
  auto_tunnel_enforce     : ${AUTO_TUNNEL_ENFORCE}
  auto_tunnel_bundle      : ${AUTO_TUNNEL_BUNDLE_PATH}
  auto_tunnel_verifier_key: ${AUTO_TUNNEL_VERIFIER_KEY_PATH}
  auto_tunnel_watermark   : ${AUTO_TUNNEL_WATERMARK_PATH}
  auto_tunnel_max_age_secs: ${AUTO_TUNNEL_MAX_AGE_SECS}
  traversal_bundle        : ${TRAVERSAL_BUNDLE_PATH}
  traversal_verifier_key  : ${TRAVERSAL_VERIFIER_KEY_PATH}
  traversal_watermark     : ${TRAVERSAL_WATERMARK_PATH}
  traversal_max_age_secs  : ${TRAVERSAL_MAX_AGE_SECS}
  wg_interface            : ${WG_INTERFACE}
  wg_listen_port          : ${WG_LISTEN_PORT}
  auto_port_forward_exit  : ${AUTO_PORT_FORWARD_EXIT}
  auto_port_forward_lease_secs: ${AUTO_PORT_FORWARD_LEASE_SECS}
  wg_runtime_private_key  : ${WG_PRIVATE_KEY_PATH}
  wg_encrypted_private_key: ${WG_ENCRYPTED_PRIVATE_KEY_PATH}
  wg_key_passphrase       : ${WG_KEY_PASSPHRASE_PATH}
  wg_key_passphrase_cred  : ${WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}
  signing_key_passphrase_cred: ${SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}
  wg_key_passphrase_keychain_account: ${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}
  wg_public_key           : ${WG_PUBLIC_KEY_PATH}
  egress_interface        : ${EGRESS_INTERFACE}
  membership_snapshot     : ${MEMBERSHIP_SNAPSHOT_PATH}
  membership_log          : ${MEMBERSHIP_LOG_PATH}
  membership_watermark    : ${MEMBERSHIP_WATERMARK_PATH}
  membership_owner_signing_key: ${MEMBERSHIP_OWNER_SIGNING_KEY_PATH}
  backend                 : ${BACKEND_MODE}
  dataplane_mode          : ${DATAPLANE_MODE}
  privileged_helper_socket: ${PRIVILEGED_HELPER_SOCKET_PATH}
  privileged_helper_timeout_ms: ${PRIVILEGED_HELPER_TIMEOUT_MS}
  reconcile_interval_ms   : ${RECONCILE_INTERVAL_MS}
  max_reconcile_failures  : ${MAX_RECONCILE_FAILURES}
  fail_closed_ssh_allow   : ${FAIL_CLOSED_SSH_ALLOW}
  fail_closed_ssh_cidrs   : ${FAIL_CLOSED_SSH_ALLOW_CIDRS}
  trust_signer_key        : ${TRUST_SIGNER_KEY_PATH}
  auto_refresh_trust      : ${AUTO_REFRESH_TRUST}
  manual_peer_override    : ${MANUAL_PEER_OVERRIDE} (deprecated; must remain 0)
  manual_peer_audit_log   : ${MANUAL_PEER_AUDIT_LOG}
  default_launch_profile  : ${DEFAULT_LAUNCH_PROFILE}
  auto_launch_on_start    : ${AUTO_LAUNCH_ON_START}
  auto_launch_exit_node_id: ${AUTO_LAUNCH_EXIT_NODE_ID}
  auto_launch_lan_mode    : ${AUTO_LAUNCH_LAN_MODE}
  exit_chain_hops         : ${EXIT_CHAIN_HOPS}
  exit_chain_entry_node_id: ${EXIT_CHAIN_ENTRY_NODE_ID}
  exit_chain_final_node_id: ${EXIT_CHAIN_FINAL_NODE_ID}
EOF
}

offer_device_as_exit_node() {
  require_admin_role "offer_device_as_exit_node" || return 0
  print_info "Advertising exit route (0.0.0.0/0)."
  run_rustynet_cli route advertise 0.0.0.0/0
  print_info "This device can now be selected as an exit node by peers (node id: ${DEVICE_NODE_ID})."
}

query_lan_access_status() {
  local status_line selected_exit lan_access
  status_line="$(run_rustynet_cli status 2>/dev/null || true)"
  if [[ -z "${status_line}" ]]; then
    print_err "Unable to query daemon status for LAN access toggle."
    return 1
  fi
  selected_exit="$(extract_status_field "${status_line}" "exit_node")"
  lan_access="$(extract_status_field "${status_line}" "lan_access")"
  case "${lan_access}" in
    on|true) lan_access="on" ;;
    off|false|"") lan_access="off" ;;
    *) lan_access="off" ;;
  esac
  printf '%s|%s\n' "${selected_exit}" "${lan_access}"
}

enable_lan_access_for_selected_exit() {
  local status_pair selected_exit lan_access
  if is_blind_exit_role; then
    print_err "LAN access toggles are disabled for blind_exit role."
    return 1
  fi

  if ! status_pair="$(query_lan_access_status)"; then
    return 1
  fi
  selected_exit="$(cut -d'|' -f1 <<<"${status_pair}")"
  lan_access="$(cut -d'|' -f2 <<<"${status_pair}")"
  if [[ "${lan_access}" == "on" ]]; then
    print_info "LAN access is already enabled."
    return 0
  fi

  if [[ -z "${selected_exit}" || "${selected_exit}" == "none" ]]; then
    print_err "Select an exit node first, then toggle LAN access on."
    return 1
  fi

  print_info "Enabling local LAN access through exit node '${selected_exit}'."
  if ! run_rustynet_cli lan-access on; then
    return 1
  fi
  print_info "LAN access enabled."
  print_info "For non-default LAN CIDRs, use 'Advertise route' with the target subnet."
  return 0
}

toggle_lan_access() {
  local status_pair lan_access
  if ! status_pair="$(query_lan_access_status)"; then
    return 1
  fi
  lan_access="$(cut -d'|' -f2 <<<"${status_pair}")"
  if [[ "${lan_access}" == "on" ]]; then
    print_info "Disabling exit-node local LAN access."
    run_rustynet_cli lan-access off
    return $?
  fi
  enable_lan_access_for_selected_exit
}

enable_lan_access_after_exit_selection() {
  if prompt_yes_no "Enable local LAN access through the selected exit node now?" "n"; then
    if ! enable_lan_access_for_selected_exit; then
      print_warn "Exit selection succeeded, but enabling LAN access failed."
      return 1
    fi
  fi
  return 0
}

probe_selected_exit_tunnel_status() {
  local node_id="$1"
  local peer_public_key="${2:-}"
  local attempt status_line selected state restricted netcheck_line handshake_ts

  for attempt in 1 2 3; do
    status_line="$(run_rustynet_cli status 2>/dev/null || true)"
    selected="$(extract_status_field "${status_line}" "exit_node")"
    state="$(extract_status_field "${status_line}" "state")"
    restricted="$(extract_status_field "${status_line}" "restricted_safe_mode")"
    netcheck_line="$(run_rustynet_cli netcheck 2>/dev/null || true)"

    if [[ "${selected}" != "${node_id}" ]]; then
      sleep 1
      continue
    fi
    if [[ "${state}" != "ExitActive" ]]; then
      sleep 1
      continue
    fi
    if [[ "${restricted}" == "true" ]]; then
      sleep 1
      continue
    fi
    if [[ "${netcheck_line}" == *"path=fail-closed"* ]]; then
      sleep 1
      continue
    fi

    if [[ -n "${peer_public_key}" ]] && command -v wg >/dev/null 2>&1; then
      handshake_ts="$(
        wg show "${WG_INTERFACE}" latest-handshakes 2>/dev/null \
          | awk -v key="${peer_public_key}" '$1 == key { print $2; exit }'
      )"
      if [[ "${handshake_ts}" =~ ^[0-9]+$ ]] && (( handshake_ts > 0 )); then
        printf 'online'
        return 0
      fi
      sleep 1
      continue
    fi

    printf 'online'
    return 0
  done

  printf 'offline'
}

probe_exit_node_readiness() {
  local node_id="$1"
  local peer_public_key="${2:-}"
  local status_line original_exit_node selection_output
  local membership_state="unknown"
  local tunnel_state="offline"
  local readiness="select-failed"

  status_line="$(run_rustynet_cli status 2>/dev/null || true)"
  original_exit_node="$(extract_status_field "${status_line}" "exit_node")"
  if [[ "${original_exit_node}" == "none" ]]; then
    original_exit_node=""
  fi

  if ! selection_output="$(run_rustynet_cli exit-node select "${node_id}" 2>&1)"; then
    if [[ "${selection_output}" == *"not active in membership state"* ]]; then
      membership_state="inactive"
      tunnel_state="skipped"
      readiness="membership-inactive"
    else
      membership_state="unknown"
      tunnel_state="offline"
      readiness="select-failed"
    fi
    restore_exit_selection "${original_exit_node}"
    printf '%s|%s|%s' "${membership_state}" "${tunnel_state}" "${readiness}"
    return 0
  fi

  membership_state="active"
  tunnel_state="$(probe_selected_exit_tunnel_status "${node_id}" "${peer_public_key}")"
  if [[ "${tunnel_state}" == "online" ]]; then
    readiness="ready"
  else
    readiness="selected-but-no-tunnel"
  fi

  restore_exit_selection "${original_exit_node}"
  printf '%s|%s|%s' "${membership_state}" "${tunnel_state}" "${readiness}"
}

print_saved_exit_candidates_with_probe() {
  local records_output name node_id public_key endpoint cidr role probe_result membership_state tunnel_state readiness
  local status_line current_exit_node marker
  if ! records_output="$(peer_store_list_records 2>&1)"; then
    print_err "Unable to read peer store for exit-candidate probe."
    print_err "${records_output}"
    return 1
  fi
  status_line="$(run_rustynet_cli status 2>/dev/null || true)"
  current_exit_node="$(extract_status_field "${status_line}" "exit_node")"
  if [[ "${current_exit_node}" == "none" ]]; then
    current_exit_node=""
  fi
  print_info "Running exit-node readiness probe (membership + tunnel)."
  print_warn "Probe temporarily switches exit selection per candidate, then restores it."
  if [[ -n "${current_exit_node}" ]]; then
    print_info "Current selection: '${current_exit_node}' (marked with '*')."
  else
    print_info "Current selection: none."
  fi
  while IFS='|' read -r name node_id public_key endpoint cidr role _rest; do
    if [[ "${name}" == \#* || -z "${name}" ]]; then
      continue
    fi
    if [[ -z "${node_id}" || -z "${endpoint}" || -z "${cidr}" ]]; then
      continue
    fi
    if [[ -z "${role}" ]]; then
      role="unknown"
    fi

    probe_result="$(probe_exit_node_readiness "${node_id}" "${public_key}")"
    membership_state="$(cut -d'|' -f1 <<<"${probe_result}")"
    tunnel_state="$(cut -d'|' -f2 <<<"${probe_result}")"
    readiness="$(cut -d'|' -f3 <<<"${probe_result}")"
    marker=" "
    if [[ -n "${current_exit_node}" && "${node_id}" == "${current_exit_node}" ]]; then
      marker="*"
    fi
    printf '  %s %s (node=%s endpoint=%s cidr=%s role=%s membership=%s tunnel=%s readiness=%s)\n' \
      "${marker}" "${name}" "${node_id}" "${endpoint}" "${cidr}" "${role}" \
      "${membership_state}" "${tunnel_state}" "${readiness}"
  done <<< "${records_output}"
}

select_exit_node() {
  local hop_count first_hop final_hop status_line current_exit_node
  local known_entry known_final
  if is_blind_exit_role; then
    print_err "Exit node selection is disabled for blind_exit role."
    return 1
  fi

  sanitize_exit_chain_defaults
  print_saved_exit_candidates_with_probe
  status_line="$(run_rustynet_cli status 2>/dev/null || true)"
  current_exit_node="$(extract_status_field "${status_line}" "exit_node")"
  if [[ "${current_exit_node}" == "none" ]]; then
    current_exit_node=""
  fi

  print_info "Current chain mode: $(exit_chain_label)"
  if [[ -n "${current_exit_node}" ]]; then
    print_info "Selecting current exit node '${current_exit_node}' will disconnect and clear selection."
  fi

  prompt_default hop_count "Routing depth (1=one-hop, 2=two-hop)" "${EXIT_CHAIN_HOPS}"
  if ! is_valid_exit_chain_hops "${hop_count}"; then
    print_err "Invalid routing depth '${hop_count}'. Expected 1 or 2."
    return 1
  fi

  if [[ "${hop_count}" == "1" ]]; then
    prompt_default first_hop "Exit node id to select" "${EXIT_CHAIN_ENTRY_NODE_ID}"
    if [[ -z "${first_hop}" ]]; then
      print_err "Exit node id is required."
      return 1
    fi
    if ! is_valid_node_id_value "${first_hop}"; then
      print_err "Invalid exit node id '${first_hop}'. Allowed characters: letters, numbers, dot, underscore, hyphen."
      return 1
    fi

    if [[ -n "${current_exit_node}" && "${first_hop}" == "${current_exit_node}" ]]; then
      if [[ "${EXIT_CHAIN_HOPS}" == "1" && "${EXIT_CHAIN_ENTRY_NODE_ID}" == "${first_hop}" ]]; then
        print_info "Exit node '${first_hop}' is already selected. Disconnecting from exit node."
        if ! apply_exit_selection_change ""; then
          return 1
        fi
        EXIT_CHAIN_HOPS="1"
        EXIT_CHAIN_ENTRY_NODE_ID=""
        EXIT_CHAIN_FINAL_NODE_ID=""
        save_config
        return 0
      fi
      print_info "Exit node '${first_hop}' is already selected. Updating chain mode to one-hop."
    else
      if ! apply_exit_selection_change "${first_hop}"; then
        return 1
      fi
    fi

    EXIT_CHAIN_HOPS="1"
    EXIT_CHAIN_ENTRY_NODE_ID="${first_hop}"
    EXIT_CHAIN_FINAL_NODE_ID=""
    save_config
    print_info "One-hop exit selected: ${first_hop}"
    enable_lan_access_after_exit_selection || true
    return 0
  fi

  prompt_default first_hop "First-hop entry relay node id" "${EXIT_CHAIN_ENTRY_NODE_ID}"
  prompt_default final_hop "Final exit node id" "${EXIT_CHAIN_FINAL_NODE_ID}"
  if [[ -z "${first_hop}" || -z "${final_hop}" ]]; then
    print_err "Both first-hop and final exit node ids are required for two-hop mode."
    return 1
  fi
  if ! is_valid_node_id_value "${first_hop}" || ! is_valid_node_id_value "${final_hop}"; then
    print_err "Invalid node id in two-hop chain. Allowed characters: letters, numbers, dot, underscore, hyphen."
    return 1
  fi
  if [[ "${first_hop}" == "${final_hop}" ]]; then
    print_err "Two-hop chain requires distinct first-hop and final exit nodes."
    return 1
  fi

  known_entry="$(find_peer_record_by_node_id "${first_hop}" || true)"
  known_final="$(find_peer_record_by_node_id "${final_hop}" || true)"
  if [[ -z "${known_entry}" ]]; then
    print_warn "First-hop node '${first_hop}' is not present in local peer records."
  fi
  if [[ -z "${known_final}" ]]; then
    print_warn "Final exit node '${final_hop}' is not present in local peer records."
  fi

  if [[ "${first_hop}" == "${DEVICE_NODE_ID}" ]]; then
    require_admin_role "configure local entry relay chain" || return 1
    print_info "Configuring this node as entry relay with upstream exit '${final_hop}'."
    if ! apply_exit_selection_change "${final_hop}"; then
      return 1
    fi
    if ! run_rustynet_cli route advertise 0.0.0.0/0; then
      print_err "Failed to advertise 0.0.0.0/0 while configuring entry relay mode."
      return 1
    fi
  else
    if [[ -n "${current_exit_node}" \
      && "${current_exit_node}" == "${first_hop}" \
      && "${EXIT_CHAIN_HOPS}" == "2" \
      && "${EXIT_CHAIN_ENTRY_NODE_ID}" == "${first_hop}" \
      && "${EXIT_CHAIN_FINAL_NODE_ID}" == "${final_hop}" ]]; then
      print_info "Two-hop chain '${first_hop} -> ${final_hop}' is already selected. Disconnecting and clearing chain."
      if ! apply_exit_selection_change ""; then
        return 1
      fi
      EXIT_CHAIN_HOPS="1"
      EXIT_CHAIN_ENTRY_NODE_ID=""
      EXIT_CHAIN_FINAL_NODE_ID=""
      save_config
      return 0
    fi

    if [[ "${current_exit_node}" != "${first_hop}" ]]; then
      if ! apply_exit_selection_change "${first_hop}"; then
        return 1
      fi
    else
      print_info "First-hop '${first_hop}' already selected; updating final-hop metadata only."
    fi

    print_warn "Two-hop chain metadata recorded: ${first_hop} -> ${final_hop}."
    print_warn "Ensure entry relay '${first_hop}' is configured to use upstream exit '${final_hop}' and advertises 0.0.0.0/0."
  fi

  EXIT_CHAIN_HOPS="2"
  EXIT_CHAIN_ENTRY_NODE_ID="${first_hop}"
  EXIT_CHAIN_FINAL_NODE_ID="${final_hop}"
  save_config
  print_info "Two-hop chain selection saved: ${first_hop} -> ${final_hop}"
  enable_lan_access_after_exit_selection || true
}

advertise_route() {
  require_admin_role "advertise_route" || return 0
  local cidr
  prompt_default cidr "CIDR to advertise (for LAN/exit routing)" "192.168.1.0/24"
  run_rustynet_cli route advertise "${cidr}"
}

apply_lan_mode_noninteractive() {
  local mode="$1"
  case "${mode}" in
    on|off)
      if run_rustynet_cli lan-access "${mode}"; then
        print_info "LAN access set to '${mode}'."
      else
        print_warn "Failed to set LAN access to '${mode}'."
      fi
      ;;
    skip|"")
      ;;
    *)
      print_warn "Ignoring unsupported LAN mode '${mode}'."
      ;;
  esac
}

apply_launch_profile() {
  local profile="$1"
  local exit_node_id="${2:-}"
  local lan_mode="${3:-skip}"

  if ! is_valid_launch_profile "${profile}"; then
    print_err "Unsupported launch profile '${profile}'."
    return 1
  fi
  if is_blind_exit_role && [[ "${profile}" != "menu" && "${profile}" != "quick-exit-node" ]]; then
    print_err "Launch profile '${profile}' is not permitted for blind_exit role."
    return 1
  fi
  if is_client_role && [[ "${profile}" == "quick-exit-node" || "${profile}" == "quick-hybrid" ]]; then
    print_err "Launch profile '${profile}' is admin-only for serving exit traffic."
    return 1
  fi
  if ! is_valid_lan_mode "${lan_mode}"; then
    print_warn "Invalid LAN mode '${lan_mode}', using 'skip'."
    lan_mode="skip"
  fi

  if [[ "${profile}" == "menu" ]]; then
    return 0
  fi

  print_info "Applying launch profile '${profile}'."
  start_or_restart_service

  case "${profile}" in
    quick-connect)
      if [[ -n "${exit_node_id}" ]]; then
        if run_rustynet_cli exit-node select "${exit_node_id}"; then
          print_info "Exit node selected: ${exit_node_id}"
        else
          print_warn "Failed to select exit node '${exit_node_id}'."
        fi
      fi
      ;;
    quick-exit-node)
      if is_blind_exit_role; then
        print_info "blind_exit role enforces exit-serving mode without exposing manual route mutation."
      else
        if run_rustynet_cli route advertise 0.0.0.0/0; then
          print_info "Exit route advertised (0.0.0.0/0)."
        else
          print_warn "Failed to advertise exit route. Check auto-tunnel policy restrictions."
        fi
        apply_lan_mode_noninteractive "${lan_mode}"
      fi
      ;;
    quick-hybrid)
      if [[ -n "${exit_node_id}" ]]; then
        if run_rustynet_cli exit-node select "${exit_node_id}"; then
          print_info "Exit node selected: ${exit_node_id}"
        else
          print_warn "Failed to select exit node '${exit_node_id}'."
        fi
      fi
      if run_rustynet_cli route advertise 0.0.0.0/0; then
        print_info "Exit route advertised (0.0.0.0/0)."
      else
        print_warn "Failed to advertise exit route. Check auto-tunnel policy restrictions."
      fi
      apply_lan_mode_noninteractive "${lan_mode}"
      ;;
  esac
}

menu_service_setup_operations() {
  while true; do
    print_menu_runtime_header
    cat <<'EOF'

Service Setup & Operations
  1) First-run setup/bootstrap
  2) Reconfigure daemon values
  3) Start/restart Rustynet service
  4) Show service status
  0) Back
EOF
    local choice
    if ! read -r -p "Choose an option: " choice; then
      print_info "Input closed; returning to main menu."
      return
    fi
    case "${choice}" in
      1) first_run_setup ;;
      2)
        if configure_values; then
          save_config
          write_daemon_environment
        fi
        ;;
      3) start_or_restart_service ;;
      4) show_service_status ;;
      0) return ;;
      *) print_warn "Unknown option: ${choice}" ;;
    esac
  done
}

menu_network_information() {
  while true; do
    print_menu_runtime_header
    cat <<'EOF'

Network Information & Diagnostics
  1) Show Rustynet status
  2) Netcheck
  3) Show connected devices
  4) Show current configuration
  5) Preflight doctor (security + prerequisites)
  0) Back
EOF
    local choice
    if ! read -r -p "Choose an option: " choice; then
      print_info "Input closed; returning to main menu."
      return
    fi
    case "${choice}" in
      1) run_rustynet_cli status ;;
      2) run_rustynet_cli netcheck ;;
      3) show_connected_devices ;;
      4) show_runtime_config ;;
      5) doctor_preflight ;;
      0) return ;;
      *) print_warn "Unknown option: ${choice}" ;;
    esac
  done
}

menu_peer_exit_routing() {
  while true; do
    print_menu_runtime_header
    if is_admin_role; then
      cat <<'EOF'

Peer, Exit Node & Routing
  1) Select exit node
  2) Disable exit node
  3) Offer this device as an exit node
  4) Toggle exit local LAN access
  5) Advertise route
  6) Show saved admin peers
  0) Back
EOF
    else
      cat <<'EOF'

Client Connectivity
  1) Select exit node
  2) Disable exit node
  3) Toggle exit local LAN access
  4) Show saved admin peers
  0) Back
EOF
    fi
    local choice
    if ! read -r -p "Choose an option: " choice; then
      print_info "Input closed; returning to main menu."
      return
    fi
    if is_admin_role; then
      case "${choice}" in
        1) select_exit_node ;;
        2) run_rustynet_cli exit-node off ;;
        3) offer_device_as_exit_node ;;
        4) toggle_lan_access ;;
        5) advertise_route ;;
        6)
          echo "Saved admin peers:"
          print_saved_admin_peers
          ;;
        0) return ;;
        *) print_warn "Unknown option: ${choice}" ;;
      esac
    else
      case "${choice}" in
        1) select_exit_node ;;
        2) run_rustynet_cli exit-node off ;;
        3) toggle_lan_access ;;
        4)
          echo "Saved admin peers:"
          print_saved_admin_peers
          ;;
        0) return ;;
        *) print_warn "Unknown option: ${choice}" ;;
      esac
    fi
  done
}

menu_security_key_management() {
  if ! is_admin_role; then
    print_warn "Security & key management menu is available only to admin-role nodes."
    return 0
  fi
  while true; do
    print_menu_runtime_header
    cat <<'EOF'

Security & Key Management
  1) Refresh signed trust evidence now
  2) Rotate local WireGuard key
  3) Revoke local key material
  0) Back
EOF
    local choice
    if ! read -r -p "Choose an option: " choice; then
      print_info "Input closed; returning to main menu."
      return
    fi
    case "${choice}" in
      1) refresh_signed_trust_evidence ;;
      2) rotate_local_key ;;
      3) revoke_local_key ;;
      0) return ;;
      *) print_warn "Unknown option: ${choice}" ;;
    esac
  done
}

menu_emergency_recovery() {
  while true; do
    print_menu_runtime_header
    if is_blind_exit_role; then
      cat <<'EOF'

Emergency & Recovery
  1) Disconnect VPN (stop service + restore normal network)
  2) Reassert blind-exit mode (restart service)
  3) Show service status
  4) Preflight doctor (security + prerequisites)
  0) Back
EOF
    else
      cat <<'EOF'

Emergency & Recovery
  1) Disconnect VPN (stop service + restore normal network)
  2) Disable exit node
  3) Show service status
  4) Preflight doctor (security + prerequisites)
  0) Back
EOF
    fi
    local choice
    if ! read -r -p "Choose an option: " choice; then
      print_info "Input closed; returning to main menu."
      return
    fi
    case "${choice}" in
      1) disconnect_vpn ;;
      2)
        if is_blind_exit_role; then
          start_or_restart_service
        else
          run_rustynet_cli exit-node off
        fi
        ;;
      3) show_service_status ;;
      4) doctor_preflight ;;
      0) return ;;
      *) print_warn "Unknown option: ${choice}" ;;
    esac
  done
}

menu_configuration() {
  while true; do
    print_menu_runtime_header
    if blind_exit_role_locked; then
      cat <<'EOF'

Configuration (Read-Only: blind_exit role lock)
  1) Show current configuration
  2) Show blind-exit lock policy
  0) Back
EOF
    else
      cat <<'EOF'

Configuration
  1) Reconfigure daemon values
  2) Show current configuration
  3) Save configuration now
  4) Configure launch defaults
  5) Apply default launch profile now
  6) Switch node role (guided client/admin transition)
  0) Back
EOF
    fi
    local choice
    if ! read -r -p "Choose an option: " choice; then
      print_info "Input closed; returning to main menu."
      return
    fi
    if blind_exit_role_locked; then
      case "${choice}" in
        1) show_runtime_config ;;
        2) print_blind_exit_lock_notice ;;
        0) return ;;
        *) print_warn "Unknown option: ${choice}" ;;
      esac
      continue
    fi
    case "${choice}" in
      1)
        if configure_values; then
          save_config
          write_daemon_environment
        fi
        ;;
      2) show_runtime_config ;;
      3)
        save_config
        print_info "Configuration saved to ${CONFIG_FILE}."
        ;;
      4)
        configure_launch_defaults
        save_config
        print_info "Launch defaults updated."
        ;;
      5)
        apply_launch_profile "${DEFAULT_LAUNCH_PROFILE}" "${AUTO_LAUNCH_EXIT_NODE_ID}" "${AUTO_LAUNCH_LAN_MODE}"
        ;;
      6) switch_node_role_mode ;;
      0) return ;;
      *) print_warn "Unknown option: ${choice}" ;;
    esac
  done
}

main_connection_action_label() {
  if [[ "${MENU_NETWORK_CONNECTED}" == "yes" ]]; then
    printf '%s' "DISCONNECT FROM NETWORK"
  else
    printf '%s' "CONNECT TO VPN"
  fi
}

toggle_vpn_connection_from_main_menu() {
  refresh_menu_runtime_status
  if [[ "${MENU_NETWORK_CONNECTED}" == "yes" ]]; then
    disconnect_vpn
  else
    start_or_restart_service
  fi
}

main_menu() {
  if is_linux_host || is_macos_host; then
    print_info "Host OS: ${HOST_OS} (full dataplane/runtime mode)."
  else
    print_warn "Host OS: ${HOST_OS} (unsupported dataplane/runtime mode)."
  fi
  while true; do
    print_menu_runtime_header
    local connect_action_label
    connect_action_label="$(main_connection_action_label)"
    if is_admin_role; then
      cat <<EOF

Rustynet Admin Console
  Quick Actions
  1) >>> ${connect_action_label} <<<
  2) >>> SELECT EXIT NODE <<<

  Management Menus
  3) Service setup & operations
  4) Network information & diagnostics
  5) Peer, exit node & routing
  6) Security & key management
  7) Emergency & recovery
  8) Configuration
  0) Exit
EOF
    elif is_blind_exit_role; then
      cat <<EOF

Rustynet Blind Exit Console
  Quick Actions
  1) >>> ${connect_action_label} <<<
  2) >>> SHOW BLIND EXIT STATUS <<<

  Management Menus
  3) Service setup & operations
  4) Network information & diagnostics
  5) Emergency & recovery
  6) Configuration
  0) Exit
EOF
    else
      cat <<EOF

Rustynet Client Console
  Quick Actions
  1) >>> ${connect_action_label} <<<
  2) >>> SELECT EXIT NODE <<<

  Management Menus
  3) Service setup & operations
  4) Network information & diagnostics
  5) Client connectivity
  6) Emergency & recovery
  7) Configuration
  0) Exit
EOF
    fi
    local choice
    if ! read -r -p "Choose an option: " choice; then
      print_info "Input closed; exiting menu."
      break
    fi
    if is_admin_role; then
      case "${choice}" in
        1) toggle_vpn_connection_from_main_menu ;;
        2) select_exit_node ;;
        3) menu_service_setup_operations ;;
        4) menu_network_information ;;
        5) menu_peer_exit_routing ;;
        6) menu_security_key_management ;;
        7) menu_emergency_recovery ;;
        8) menu_configuration ;;
        0) exit 0 ;;
        *) print_warn "Unknown option: ${choice}" ;;
      esac
    elif is_blind_exit_role; then
      case "${choice}" in
        1) toggle_vpn_connection_from_main_menu ;;
        2) run_rustynet_cli status ;;
        3) menu_service_setup_operations ;;
        4) menu_network_information ;;
        5) menu_emergency_recovery ;;
        6) menu_configuration ;;
        0) exit 0 ;;
        *) print_warn "Unknown option: ${choice}" ;;
      esac
    else
      case "${choice}" in
        1) toggle_vpn_connection_from_main_menu ;;
        2) select_exit_node ;;
        3) menu_service_setup_operations ;;
        4) menu_network_information ;;
        5) menu_peer_exit_routing ;;
        6) menu_emergency_recovery ;;
        7) menu_configuration ;;
        0) exit 0 ;;
        *) print_warn "Unknown option: ${choice}" ;;
      esac
    fi
  done
}

parse_start_arguments "$@"
apply_host_profile_defaults
add_macos_homebrew_to_path
load_config_file
validate_loaded_config_or_die
enforce_host_storage_policy
sanitize_launch_defaults
enforce_backend_mode
enforce_wg_listen_port_policy
ensure_peer_store

if [[ "${SETUP_COMPLETE}" != "1" ]]; then
  print_warn "Rustynet is not configured yet."
  if [[ "${AUTO_ONLY_LAUNCH}" == "1" ]]; then
    print_err "Cannot run non-interactive launch profile before first-run setup."
    print_info "Run ./start.sh and complete setup first."
    exit 1
  fi
  if prompt_yes_no "Run first-run setup now?" "y"; then
    first_run_setup
  fi
fi

enforce_host_storage_policy
save_config

launch_profile=""
launch_exit_node_id="${AUTO_LAUNCH_EXIT_NODE_ID}"
launch_lan_mode="${AUTO_LAUNCH_LAN_MODE}"

if [[ -n "${REQUESTED_EXIT_NODE_ID}" ]]; then
  launch_exit_node_id="${REQUESTED_EXIT_NODE_ID}"
fi
if [[ -n "${REQUESTED_LAN_MODE}" ]]; then
  launch_lan_mode="${REQUESTED_LAN_MODE}"
fi

if [[ "${REQUESTED_LAUNCH_PROFILE}" == "auto" ]]; then
  launch_profile="${DEFAULT_LAUNCH_PROFILE}"
elif [[ -n "${REQUESTED_LAUNCH_PROFILE}" ]]; then
  launch_profile="${REQUESTED_LAUNCH_PROFILE}"
elif [[ "${AUTO_LAUNCH_ON_START}" == "1" ]]; then
  launch_profile="${DEFAULT_LAUNCH_PROFILE}"
fi

if [[ -n "${launch_profile}" && "${launch_profile}" != "menu" ]]; then
  if ! apply_launch_profile "${launch_profile}" "${launch_exit_node_id}" "${launch_lan_mode}"; then
    if [[ "${AUTO_ONLY_LAUNCH}" == "1" ]]; then
      exit 1
    fi
  fi
  if [[ "${AUTO_ONLY_LAUNCH}" == "1" ]]; then
    exit 0
  fi
fi

main_menu
