#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/rustynet"
CONFIG_FILE="${CONFIG_DIR}/wizard.env"
PEERS_FILE="${CONFIG_DIR}/peers.db"

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
WG_INTERFACE="rustynet0"
WG_PRIVATE_KEY_PATH="/run/rustynet/wireguard.key"
WG_ENCRYPTED_PRIVATE_KEY_PATH="/var/lib/rustynet/keys/wireguard.key.enc"
WG_KEY_PASSPHRASE_PATH="/var/lib/rustynet/keys/wireguard.passphrase"
WG_PUBLIC_KEY_PATH="/var/lib/rustynet/keys/wireguard.pub"
EGRESS_INTERFACE=""
MEMBERSHIP_SNAPSHOT_PATH="/var/lib/rustynet/membership.snapshot"
MEMBERSHIP_LOG_PATH="/var/lib/rustynet/membership.log"
MEMBERSHIP_WATERMARK_PATH="/var/lib/rustynet/membership.watermark"
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
REQUESTED_LAUNCH_PROFILE=""
REQUESTED_EXIT_NODE_ID=""
REQUESTED_LAN_MODE=""
AUTO_ONLY_LAUNCH="0"
RUST_MIN_VERSION="1.85"
MANUAL_PEER_AUDIT_LOG="/var/log/rustynet/manual-peer-override.log"
MANUAL_OVERRIDE_CONFIRMATION="RUSTYNET_BREAK_GLASS_ACK"
HOST_OS="$(uname -s)"
HOST_PROFILE="unknown"
MACOS_STATE_BASE="${HOME}/Library/Application Support/rustynet"
MACOS_RUNTIME_BASE="${HOME}/Library/Caches/rustynet"
MACOS_LOG_BASE="${HOME}/Library/Logs/rustynet"
MACOS_DAEMON_PID_PATH="${MACOS_RUNTIME_BASE}/rustynetd.pid"
MACOS_HELPER_PID_PATH="${MACOS_RUNTIME_BASE}/rustynetd-privileged.pid"
MACOS_DAEMON_LOG_PATH="${MACOS_LOG_BASE}/rustynetd.log"
MACOS_HELPER_LOG_PATH="${MACOS_LOG_BASE}/rustynetd-privileged.log"
MACOS_LOCAL_TOOLS_BASE="${HOME}/.local/rustynet-tools"
MACOS_LOCAL_TOOLS_BIN="${MACOS_LOCAL_TOOLS_BASE}/bin"
MACOS_LOCAL_GO_VERSION="1.23.1"
MACOS_WIREGUARD_TOOLS_VERSION="1.0.20210914"
export PATH="/usr/local/bin:/usr/local/sbin:/opt/homebrew/bin:/opt/homebrew/sbin:/usr/bin:/usr/sbin:/sbin:${MACOS_LOCAL_TOOLS_BIN}:${MACOS_LOCAL_TOOLS_BASE}/go/bin:${PATH}"

mkdir -p "${CONFIG_DIR}"
touch "${PEERS_FILE}"

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
    return
  fi

  if is_macos_host; then
    HOST_PROFILE="macos"

    SOCKET_PATH="${MACOS_RUNTIME_BASE}/rustynetd.sock"
    STATE_PATH="${MACOS_STATE_BASE}/rustynetd.state"
    TRUST_EVIDENCE_PATH="${MACOS_STATE_BASE}/compat/trust/rustynetd.trust"
    TRUST_VERIFIER_KEY_PATH="${MACOS_STATE_BASE}/compat/trust/trust-evidence.pub"
    TRUST_WATERMARK_PATH="${MACOS_STATE_BASE}/compat/trust/rustynetd.trust.watermark"
    AUTO_TUNNEL_BUNDLE_PATH="${MACOS_STATE_BASE}/compat/assignment/rustynetd.assignment"
    AUTO_TUNNEL_VERIFIER_KEY_PATH="${MACOS_STATE_BASE}/compat/assignment/assignment.pub"
    AUTO_TUNNEL_WATERMARK_PATH="${MACOS_STATE_BASE}/compat/assignment/rustynetd.assignment.watermark"
    WG_PRIVATE_KEY_PATH="${MACOS_STATE_BASE}/compat/keys/wireguard.key"
    WG_ENCRYPTED_PRIVATE_KEY_PATH="${MACOS_STATE_BASE}/compat/keys/wireguard.key.enc"
    WG_KEY_PASSPHRASE_PATH="${MACOS_STATE_BASE}/compat/keys/wireguard.passphrase"
    WG_PUBLIC_KEY_PATH="${MACOS_STATE_BASE}/compat/keys/wireguard.pub"
    WG_INTERFACE="utun9"
    MEMBERSHIP_SNAPSHOT_PATH="${MACOS_STATE_BASE}/compat/membership/membership.snapshot"
    MEMBERSHIP_LOG_PATH="${MACOS_STATE_BASE}/compat/membership/membership.log"
    MEMBERSHIP_WATERMARK_PATH="${MACOS_STATE_BASE}/compat/membership/membership.watermark"
    TRUST_SIGNER_KEY_PATH="${MACOS_STATE_BASE}/compat/trust/trust-evidence.key"
    PRIVILEGED_HELPER_SOCKET_PATH="${MACOS_RUNTIME_BASE}/rustynetd-privileged.sock"
    MANUAL_PEER_AUDIT_LOG="${MACOS_LOG_BASE}/manual-peer-override.log"
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

coerce_macos_path_var() {
  local var_name="$1"
  local fallback="$2"
  local current="${!var_name:-}"

  if [[ -z "${current}" ]]; then
    printf -v "${var_name}" '%s' "${fallback}"
    return
  fi

  if path_in_linux_runtime_roots "${current}"; then
    print_warn "Path '${var_name}' points to Linux runtime storage on macOS; resetting to '${fallback}'."
    printf -v "${var_name}" '%s' "${fallback}"
  fi
}

enforce_host_storage_policy() {
  if is_linux_host; then
    HOST_PROFILE="linux"
    return
  fi

  if ! is_macos_host; then
    HOST_PROFILE="unsupported"
    return
  fi

  HOST_PROFILE="macos"
  coerce_macos_path_var SOCKET_PATH "${MACOS_RUNTIME_BASE}/rustynetd.sock"
  coerce_macos_path_var STATE_PATH "${MACOS_STATE_BASE}/rustynetd.state"
  coerce_macos_path_var TRUST_EVIDENCE_PATH "${MACOS_STATE_BASE}/compat/trust/rustynetd.trust"
  coerce_macos_path_var TRUST_VERIFIER_KEY_PATH "${MACOS_STATE_BASE}/compat/trust/trust-evidence.pub"
  coerce_macos_path_var TRUST_WATERMARK_PATH "${MACOS_STATE_BASE}/compat/trust/rustynetd.trust.watermark"
  coerce_macos_path_var AUTO_TUNNEL_BUNDLE_PATH "${MACOS_STATE_BASE}/compat/assignment/rustynetd.assignment"
  coerce_macos_path_var AUTO_TUNNEL_VERIFIER_KEY_PATH "${MACOS_STATE_BASE}/compat/assignment/assignment.pub"
  coerce_macos_path_var AUTO_TUNNEL_WATERMARK_PATH "${MACOS_STATE_BASE}/compat/assignment/rustynetd.assignment.watermark"
  coerce_macos_path_var WG_PRIVATE_KEY_PATH "${MACOS_STATE_BASE}/compat/keys/wireguard.key"
  coerce_macos_path_var WG_ENCRYPTED_PRIVATE_KEY_PATH "${MACOS_STATE_BASE}/compat/keys/wireguard.key.enc"
  coerce_macos_path_var WG_KEY_PASSPHRASE_PATH "${MACOS_STATE_BASE}/compat/keys/wireguard.passphrase"
  coerce_macos_path_var WG_PUBLIC_KEY_PATH "${MACOS_STATE_BASE}/compat/keys/wireguard.pub"
  coerce_macos_path_var PRIVILEGED_HELPER_SOCKET_PATH "${MACOS_RUNTIME_BASE}/rustynetd-privileged.sock"
  coerce_macos_path_var MEMBERSHIP_SNAPSHOT_PATH "${MACOS_STATE_BASE}/compat/membership/membership.snapshot"
  coerce_macos_path_var MEMBERSHIP_LOG_PATH "${MACOS_STATE_BASE}/compat/membership/membership.log"
  coerce_macos_path_var MEMBERSHIP_WATERMARK_PATH "${MACOS_STATE_BASE}/compat/membership/membership.watermark"
  coerce_macos_path_var TRUST_SIGNER_KEY_PATH "${MACOS_STATE_BASE}/compat/trust/trust-evidence.key"
  coerce_macos_path_var MANUAL_PEER_AUDIT_LOG "${MACOS_LOG_BASE}/manual-peer-override.log"

  if [[ ! "${WG_INTERFACE}" =~ ^utun[0-9]+$ ]]; then
    print_warn "WG_INTERFACE '${WG_INTERFACE}' is not valid on macOS; resetting to 'utun9'."
    WG_INTERFACE="utun9"
  fi

  if [[ "${MANUAL_PEER_OVERRIDE}" != "0" ]]; then
    print_warn "Manual peer break-glass override is disabled on macOS hosts."
    MANUAL_PEER_OVERRIDE="0"
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
    admin|client) ;;
    *)
      print_warn "Invalid NODE_ROLE='${NODE_ROLE}', defaulting to 'client'."
      NODE_ROLE="client"
      ;;
  esac
}

is_admin_role() {
  [[ "${NODE_ROLE}" == "admin" ]]
}

is_client_role() {
  [[ "${NODE_ROLE}" == "client" ]]
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
  if is_client_role; then
    MANUAL_PEER_OVERRIDE="0"
    AUTO_REFRESH_TRUST="0"
    case "${DEFAULT_LAUNCH_PROFILE}" in
      quick-exit-node|quick-hybrid)
        print_warn "Launch profile '${DEFAULT_LAUNCH_PROFILE}' is admin-only; forcing 'quick-connect' for client role."
        DEFAULT_LAUNCH_PROFILE="quick-connect"
        ;;
    esac
  fi
}

is_allowed_config_key() {
  local key="$1"
  case "${key}" in
    SOCKET_PATH|STATE_PATH|TRUST_EVIDENCE_PATH|TRUST_VERIFIER_KEY_PATH|TRUST_WATERMARK_PATH|AUTO_TUNNEL_ENFORCE|AUTO_TUNNEL_BUNDLE_PATH|AUTO_TUNNEL_VERIFIER_KEY_PATH|AUTO_TUNNEL_WATERMARK_PATH|AUTO_TUNNEL_MAX_AGE_SECS|WG_INTERFACE|WG_PRIVATE_KEY_PATH|WG_ENCRYPTED_PRIVATE_KEY_PATH|WG_KEY_PASSPHRASE_PATH|WG_PUBLIC_KEY_PATH|EGRESS_INTERFACE|MEMBERSHIP_SNAPSHOT_PATH|MEMBERSHIP_LOG_PATH|MEMBERSHIP_WATERMARK_PATH|BACKEND_MODE|DATAPLANE_MODE|PRIVILEGED_HELPER_SOCKET_PATH|PRIVILEGED_HELPER_TIMEOUT_MS|RECONCILE_INTERVAL_MS|MAX_RECONCILE_FAILURES|FAIL_CLOSED_SSH_ALLOW|FAIL_CLOSED_SSH_ALLOW_CIDRS|TRUST_SIGNER_KEY_PATH|AUTO_REFRESH_TRUST|DEVICE_NODE_ID|SETUP_COMPLETE|NODE_ROLE|MANUAL_PEER_OVERRIDE|MANUAL_PEER_AUDIT_LOG|DEFAULT_LAUNCH_PROFILE|AUTO_LAUNCH_ON_START|AUTO_LAUNCH_EXIT_NODE_ID|AUTO_LAUNCH_LAN_MODE|HOST_PROFILE)
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

enforce_backend_mode() {
  local expected="linux-wireguard"
  if is_macos_host; then
    expected="macos-wireguard"
  fi
  if [[ "${BACKEND_MODE}" != "${expected}" ]]; then
    print_warn "Unsupported backend '${BACKEND_MODE}' detected for ${HOST_PROFILE}; forcing ${expected}."
  fi
  BACKEND_MODE="${expected}"
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

manual_peer_override_enabled() {
  is_admin_role && [[ "${MANUAL_PEER_OVERRIDE}" == "1" || "${RUSTYNET_MANUAL_PEER_OVERRIDE:-0}" == "1" ]]
}

append_manual_peer_override_audit() {
  local action="$1"
  local timestamp
  local user_name
  local host_name
  local line
  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  user_name="${SUDO_USER:-${USER:-unknown}}"
  host_name="$(hostname -s 2>/dev/null || echo unknown)"
  line="timestamp=${timestamp} action=${action} user=${user_name} host=${host_name}"

  run_root install -d -m 0700 "$(dirname "${MANUAL_PEER_AUDIT_LOG}")"
  printf '%s\n' "${line}" | run_root tee -a "${MANUAL_PEER_AUDIT_LOG}" >/dev/null
  run_root chmod 600 "${MANUAL_PEER_AUDIT_LOG}"
}

require_manual_peer_override_authorization() {
  local action="$1"
  local confirmation
  if ! manual_peer_override_enabled; then
    print_err "Manual peer programming is disabled."
    print_info "Use centrally signed auto-tunnel assignments by default."
    print_info "To invoke break-glass mode, set MANUAL_PEER_OVERRIDE=1 in wizard config."
    return 1
  fi
  print_warn "Break-glass override requested for ${action}."
  read -r -p "Type '${MANUAL_OVERRIDE_CONFIRMATION}' to proceed: " confirmation
  if [[ "${confirmation}" != "${MANUAL_OVERRIDE_CONFIRMATION}" ]]; then
    print_err "Break-glass confirmation mismatch. Operation cancelled."
    return 1
  fi
  append_manual_peer_override_audit "${action}"
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

run_root_background() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@" &
    return 0
  fi

  if [[ -t 0 && -t 1 ]]; then
    sudo -b "$@"
    return
  fi

  if sudo -n true >/dev/null 2>&1; then
    sudo -n -b "$@"
    return
  fi

  print_err "A TTY sudo prompt is unavailable and cached sudo credentials were not found."
  print_info "Run 'sudo -v' in an interactive shell, then rerun this action."
  return 1
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

sanitize_launch_defaults() {
  enforce_role_policy_defaults
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

  ./start.sh --profile <menu|quick-connect|quick-exit-node|quick-hybrid>
    Apply a launch profile once. Non-menu profiles apply and exit.

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
    printf 'WG_INTERFACE=%s\n' "${WG_INTERFACE}"
    printf 'WG_PRIVATE_KEY_PATH=%s\n' "${WG_PRIVATE_KEY_PATH}"
    printf 'WG_ENCRYPTED_PRIVATE_KEY_PATH=%s\n' "${WG_ENCRYPTED_PRIVATE_KEY_PATH}"
    printf 'WG_KEY_PASSPHRASE_PATH=%s\n' "${WG_KEY_PASSPHRASE_PATH}"
    printf 'WG_PUBLIC_KEY_PATH=%s\n' "${WG_PUBLIC_KEY_PATH}"
    printf 'EGRESS_INTERFACE=%s\n' "${EGRESS_INTERFACE}"
    printf 'MEMBERSHIP_SNAPSHOT_PATH=%s\n' "${MEMBERSHIP_SNAPSHOT_PATH}"
    printf 'MEMBERSHIP_LOG_PATH=%s\n' "${MEMBERSHIP_LOG_PATH}"
    printf 'MEMBERSHIP_WATERMARK_PATH=%s\n' "${MEMBERSHIP_WATERMARK_PATH}"
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
  if [[ -d "${MACOS_LOCAL_TOOLS_BIN}" ]]; then
    case ":${PATH}:" in
      *":${MACOS_LOCAL_TOOLS_BIN}:"*) ;;
      *) export PATH="${PATH}:${MACOS_LOCAL_TOOLS_BIN}" ;;
    esac
    case ":${PATH}:" in
      *":${MACOS_LOCAL_TOOLS_BASE}/go/bin:"*) ;;
      *) export PATH="${PATH}:${MACOS_LOCAL_TOOLS_BASE}/go/bin" ;;
    esac
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

ensure_macos_local_go_toolchain() {
  if command -v go >/dev/null 2>&1; then
    return 0
  fi

  local arch go_arch tarball_url tmp_tar
  arch="$(uname -m)"
  case "${arch}" in
    arm64|aarch64) go_arch="arm64" ;;
    x86_64|amd64) go_arch="amd64" ;;
    *)
      print_err "Unsupported macOS architecture for local Go bootstrap: ${arch}"
      return 1
      ;;
  esac

  install -d -m 0700 "${MACOS_LOCAL_TOOLS_BASE}"
  tmp_tar="$(mktemp)"
  tarball_url="https://go.dev/dl/go${MACOS_LOCAL_GO_VERSION}.darwin-${go_arch}.tar.gz"
  print_info "Installing local Go toolchain (${MACOS_LOCAL_GO_VERSION}) to ${MACOS_LOCAL_TOOLS_BASE}/go."
  if ! curl --proto '=https' --tlsv1.2 -fsSL "${tarball_url}" -o "${tmp_tar}"; then
    rm -f "${tmp_tar}"
    print_err "Failed to download Go toolchain from ${tarball_url}"
    return 1
  fi
  rm -rf "${MACOS_LOCAL_TOOLS_BASE}/go"
  tar -xzf "${tmp_tar}" -C "${MACOS_LOCAL_TOOLS_BASE}"
  rm -f "${tmp_tar}"
  export PATH="${MACOS_LOCAL_TOOLS_BASE}/go/bin:${PATH}"
}

install_macos_unprivileged_wireguard_tools() {
  if ! is_macos_host; then
    return 0
  fi

  install -d -m 0700 "${MACOS_LOCAL_TOOLS_BIN}"
  export PATH="${MACOS_LOCAL_TOOLS_BIN}:${MACOS_LOCAL_TOOLS_BASE}/go/bin:${PATH}"

  if [[ ! -x "/usr/local/bin/wireguard-go" ]]; then
    ensure_macos_local_go_toolchain || return 1
    local wg_go_src_dir
    wg_go_src_dir="$(mktemp -d)"
    if command -v git >/dev/null 2>&1; then
      git clone --depth 1 https://git.zx2c4.com/wireguard-go "${wg_go_src_dir}"
    else
      local wg_go_tar
      wg_go_tar="$(mktemp)"
      curl --proto '=https' --tlsv1.2 -fsSL \
        "https://git.zx2c4.com/wireguard-go/snapshot/wireguard-go-master.tar.xz" \
        -o "${wg_go_tar}"
      tar -xf "${wg_go_tar}" -C "${wg_go_src_dir}" --strip-components=1
      rm -f "${wg_go_tar}"
    fi
    make -C "${wg_go_src_dir}"
    if run_root install -d -m 0755 /usr/local/bin \
      && run_root install -m 0755 "${wg_go_src_dir}/wireguard-go" /usr/local/bin/wireguard-go; then
      print_info "Installed wireguard-go to /usr/local/bin/wireguard-go"
    else
      install -m 0755 "${wg_go_src_dir}/wireguard-go" "${MACOS_LOCAL_TOOLS_BIN}/wireguard-go"
      print_warn "Installed fallback wireguard-go at ${MACOS_LOCAL_TOOLS_BIN}/wireguard-go (not root-owned)."
    fi
    rm -rf "${wg_go_src_dir}"
  fi

  if [[ ! -x "/usr/local/bin/wg" ]]; then
    local wg_tools_src_dir wg_tools_tar
    wg_tools_src_dir="$(mktemp -d)"
    wg_tools_tar="$(mktemp)"
    curl --proto '=https' --tlsv1.2 -fsSL \
      "https://git.zx2c4.com/wireguard-tools/snapshot/wireguard-tools-${MACOS_WIREGUARD_TOOLS_VERSION}.tar.xz" \
      -o "${wg_tools_tar}"
    tar -xf "${wg_tools_tar}" -C "${wg_tools_src_dir}" --strip-components=1
    rm -f "${wg_tools_tar}"
    make -C "${wg_tools_src_dir}/src"
    if run_root install -d -m 0755 /usr/local/bin \
      && run_root install -m 0755 "${wg_tools_src_dir}/src/wg" /usr/local/bin/wg; then
      print_info "Installed wg to /usr/local/bin/wg"
    else
      install -m 0755 "${wg_tools_src_dir}/src/wg" "${MACOS_LOCAL_TOOLS_BIN}/wg"
      print_warn "Installed fallback wg at ${MACOS_LOCAL_TOOLS_BIN}/wg (not root-owned)."
    fi
    rm -rf "${wg_tools_src_dir}"
  fi
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

  print_warn "Homebrew is required on macOS for automated dependency installs and is not installed."
  if ! prompt_yes_no "Install Homebrew now (official installer)?" "y"; then
    print_err "Cannot continue without Homebrew on macOS."
    print_info "Install Homebrew from https://brew.sh and rerun ./start.sh."
    exit 1
  fi

  if [[ ! -x /bin/bash ]]; then
    print_err "Cannot find /bin/bash required for Homebrew installer."
    exit 1
  fi
  if ! command -v curl >/dev/null 2>&1; then
    print_err "curl is required for Homebrew installer."
    exit 1
  fi

  print_info "Installing Homebrew via official installer."
  NONINTERACTIVE=1 /bin/bash -c "$(curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  add_macos_homebrew_to_path
  if ! command -v brew >/dev/null 2>&1; then
    print_err "Homebrew install finished but brew is still not in PATH."
    print_info "Open a new shell and rerun ./start.sh."
    exit 1
  fi
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
        echo "vim-common"
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

install_compatible_cargo_deny() {
  local installed_ver=""
  if command -v rustc >/dev/null 2>&1; then
    installed_ver="$(rustc --version 2>/dev/null | awk '{print $2}' | cut -d- -f1)"
  fi

  if [[ -n "${installed_ver}" ]] && [[ "$(printf '%s\n%s\n' "1.88.0" "${installed_ver}" | sort -V | head -1)" != "1.88.0" ]]; then
    print_warn "rustc ${installed_ver} is below 1.88.0; installing cargo-deny 0.18.3 for compatibility."
    cargo install --locked cargo-deny --version 0.18.3
    return
  fi

  cargo install --locked cargo-deny
}

install_rust_via_rustup() {
  print_info "Installing Rust via rustup (latest stable toolchain)."
  if ! command -v curl >/dev/null 2>&1; then
    print_err "curl is required for the rustup installer. Install curl first."
    return 1
  fi
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  # Make cargo available in the current shell session
  # shellcheck disable=SC1091
  source "${HOME}/.cargo/env" 2>/dev/null || export PATH="${HOME}/.cargo/bin:${PATH}"
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
      install_compatible_cargo_deny
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
  echo "  1) Install via rustup (recommended — always gets latest stable)"
  echo "  2) Install via system package manager (may be outdated on some distros)"
  echo "  3) Skip — I will install Rust manually before building"
  local choice
  read -r -p "Choose Rust install method [1]: " choice
  choice="${choice:-1}"

  case "${choice}" in
    1)
      install_rust_via_rustup
      ;;
    2)
      local pm
      pm="$(package_manager)"
      if [[ "${pm}" == "unknown" ]]; then
        print_err "No supported package manager found. Install Rust manually from https://rustup.rs"
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
    3)
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
    print_info "If installed via rustup, open a new terminal or run: source \"\$HOME/.cargo/env\""
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
    local only_rg_missing=1
    local requires_wireguard_tools=0
    for cmd in "${missing[@]}"; do
      if [[ "${cmd}" != "rg" ]]; then
        only_rg_missing=0
      fi
      if [[ "${cmd}" == "wg" || "${cmd}" == "wireguard-go" ]]; then
        requires_wireguard_tools=1
      fi
    done

    if [[ "${only_rg_missing}" == "1" ]]; then
      print_warn "Homebrew is unavailable; falling back to cargo install for ripgrep."
      if ! command -v cargo >/dev/null 2>&1 || ! check_rust_min_version; then
        ensure_rust_toolchain
      fi
      if ! command -v cargo >/dev/null 2>&1; then
        print_err "cargo is required for ripgrep fallback installation."
        exit 1
      fi
      cargo install --locked ripgrep
      export PATH="${HOME}/.cargo/bin:${PATH}"
      if command -v rg >/dev/null 2>&1; then
        print_info "ripgrep installed via cargo fallback."
        return
      fi
      print_err "ripgrep fallback install did not produce an 'rg' binary in PATH."
      exit 1
    fi

    if [[ "${requires_wireguard_tools}" == "1" ]] && ! is_macos_admin_user; then
      print_warn "Homebrew is unavailable and current user is not in the macOS admin group."
      print_info "Falling back to unprivileged local install for wireguard-go and wg."
      install_macos_unprivileged_wireguard_tools
      export PATH="${MACOS_LOCAL_TOOLS_BIN}:${MACOS_LOCAL_TOOLS_BASE}/go/bin:${PATH}"
      missing=()
      for cmd in "${required[@]}"; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
          missing+=("${cmd}")
        fi
      done
      if [[ "${#missing[@]}" -eq 0 ]]; then
        return
      fi
      if [[ "${#missing[@]}" -eq 1 && "${missing[0]}" == "rg" ]]; then
        if ! command -v cargo >/dev/null 2>&1 || ! check_rust_min_version; then
          ensure_rust_toolchain
        fi
        cargo install --locked ripgrep
        export PATH="${HOME}/.cargo/bin:${PATH}"
        if command -v rg >/dev/null 2>&1; then
          return
        fi
      fi
      print_err "Missing commands after unprivileged macOS fallback: ${missing[*]}"
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
    install_dir="${MACOS_LOCAL_TOOLS_BIN}"
    print_warn "No admin write access to /usr/local/bin; installing rustynet binaries to ${install_dir}."
    install -d -m 0700 "${install_dir}"
    install -m 0755 "${ROOT_DIR}/target/release/rustynetd" "${install_dir}/rustynetd"
    install -m 0755 "${ROOT_DIR}/target/release/rustynet-cli" "${install_dir}/rustynet"
    export PATH="${install_dir}:${PATH}"
    return
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
    doctor_require_cmd python3 "linux e2e/runtime"

    if [[ "${SETUP_COMPLETE}" == "1" ]]; then
      doctor_check_mode "${WG_KEY_PASSPHRASE_PATH}" "600" "key custody"
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
      doctor_check_mode "${WG_KEY_PASSPHRASE_PATH}" "600" "key custody"
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
  if is_linux_host; then
    run_root install -d -m 0700 /etc/rustynet /run/rustynet /var/lib/rustynet
    run_root install -d -m 0700 "$(dirname "${STATE_PATH}")"
    run_root install -d -m 0700 "$(dirname "${TRUST_EVIDENCE_PATH}")"
    run_root install -d -m 0700 "$(dirname "${TRUST_WATERMARK_PATH}")"
    run_root install -d -m 0700 "$(dirname "${AUTO_TUNNEL_BUNDLE_PATH}")"
    run_root install -d -m 0700 "$(dirname "${AUTO_TUNNEL_WATERMARK_PATH}")"
    run_root install -d -m 0700 "$(dirname "${AUTO_TUNNEL_VERIFIER_KEY_PATH}")"
    run_root install -d -m 0700 "$(dirname "${WG_PRIVATE_KEY_PATH}")"
    run_root install -d -m 0700 "$(dirname "${WG_ENCRYPTED_PRIVATE_KEY_PATH}")"
    run_root install -d -m 0700 "$(dirname "${WG_KEY_PASSPHRASE_PATH}")"
    run_root install -d -m 0700 "$(dirname "${WG_PUBLIC_KEY_PATH}")"
    run_root install -d -m 0700 "$(dirname "${MEMBERSHIP_WATERMARK_PATH}")"
    run_root install -d -m 0700 "$(dirname "${PRIVILEGED_HELPER_SOCKET_PATH}")"
    return
  fi

  if is_macos_host; then
    install -d -m 0700 "${MACOS_STATE_BASE}" "${MACOS_RUNTIME_BASE}" "${MACOS_LOG_BASE}"
    install -d -m 0700 "$(dirname "${STATE_PATH}")"
    install -d -m 0700 "$(dirname "${TRUST_EVIDENCE_PATH}")"
    install -d -m 0700 "$(dirname "${TRUST_WATERMARK_PATH}")"
    install -d -m 0700 "$(dirname "${AUTO_TUNNEL_BUNDLE_PATH}")"
    install -d -m 0700 "$(dirname "${AUTO_TUNNEL_WATERMARK_PATH}")"
    install -d -m 0700 "$(dirname "${AUTO_TUNNEL_VERIFIER_KEY_PATH}")"
    install -d -m 0700 "$(dirname "${WG_PRIVATE_KEY_PATH}")"
    install -d -m 0700 "$(dirname "${WG_ENCRYPTED_PRIVATE_KEY_PATH}")"
    install -d -m 0700 "$(dirname "${WG_KEY_PASSPHRASE_PATH}")"
    install -d -m 0700 "$(dirname "${WG_PUBLIC_KEY_PATH}")"
    install -d -m 0700 "$(dirname "${MEMBERSHIP_WATERMARK_PATH}")"
    install -d -m 0700 "$(dirname "${PRIVILEGED_HELPER_SOCKET_PATH}")"
    return
  fi

  require_linux_dataplane "prepare_system_directories" || return 0
}

ensure_wireguard_keys() {
  run_with_scope() {
    if is_linux_host; then
      run_root "$@"
    else
      "$@"
    fi
  }

  if [[ -f "${WG_ENCRYPTED_PRIVATE_KEY_PATH}" && -f "${WG_PUBLIC_KEY_PATH}" && -f "${WG_KEY_PASSPHRASE_PATH}" ]]; then
    unset -f run_with_scope >/dev/null 2>&1 || true
    return
  fi

  if ! prompt_yes_no "Encrypted WireGuard key material is missing. Initialize now?" "y"; then
    print_err "Encrypted WireGuard key material is required."
    exit 1
  fi

  if [[ ! -f "${WG_KEY_PASSPHRASE_PATH}" ]]; then
    local tmp_passphrase
    tmp_passphrase="$(mktemp)"
    openssl rand -hex 48 >"${tmp_passphrase}"
    run_with_scope install -m 0600 "${tmp_passphrase}" "${WG_KEY_PASSPHRASE_PATH}"
    rm -f "${tmp_passphrase}"
    print_info "Generated key passphrase file at ${WG_KEY_PASSPHRASE_PATH}"
  fi

  local source_private_key=""
  if [[ -f "${WG_PRIVATE_KEY_PATH}" ]]; then
    source_private_key="${WG_PRIVATE_KEY_PATH}"
  elif [[ -f "/etc/rustynet/wireguard.key" ]]; then
    source_private_key="/etc/rustynet/wireguard.key"
  fi

  if [[ -n "${source_private_key}" ]]; then
    run_with_scope rustynetd key migrate \
      --existing-private-key "${source_private_key}" \
      --runtime-private-key "${WG_PRIVATE_KEY_PATH}" \
      --encrypted-private-key "${WG_ENCRYPTED_PRIVATE_KEY_PATH}" \
      --public-key "${WG_PUBLIC_KEY_PATH}" \
      --passphrase-file "${WG_KEY_PASSPHRASE_PATH}" \
      --force
    if [[ "${source_private_key}" != "${WG_PRIVATE_KEY_PATH}" ]]; then
      run_with_scope rm -f "${source_private_key}"
      print_info "Removed legacy plaintext private key at ${source_private_key}"
    fi
    print_info "Existing key migrated to encrypted storage."
    unset -f run_with_scope >/dev/null 2>&1 || true
    return
  fi

  run_with_scope rustynetd key init \
    --runtime-private-key "${WG_PRIVATE_KEY_PATH}" \
    --encrypted-private-key "${WG_ENCRYPTED_PRIVATE_KEY_PATH}" \
    --public-key "${WG_PUBLIC_KEY_PATH}" \
    --passphrase-file "${WG_KEY_PASSPHRASE_PATH}" \
    --force

  print_info "WireGuard key material initialized (encrypted key: ${WG_ENCRYPTED_PRIVATE_KEY_PATH})"
  unset -f run_with_scope >/dev/null 2>&1 || true
}

ensure_membership_files() {
  run_with_scope() {
    if is_linux_host; then
      run_root "$@"
    else
      "$@"
    fi
  }
  if [[ -f "${MEMBERSHIP_SNAPSHOT_PATH}" && -f "${MEMBERSHIP_LOG_PATH}" ]]; then
    print_info "Membership files already present."
    unset -f run_with_scope >/dev/null 2>&1 || true
    return
  fi
  print_info "Initializing membership files for node '${DEVICE_NODE_ID}'."
  run_with_scope rustynetd membership init \
    --snapshot "${MEMBERSHIP_SNAPSHOT_PATH}" \
    --log "${MEMBERSHIP_LOG_PATH}" \
    --watermark "${MEMBERSHIP_WATERMARK_PATH}" \
    --node-id "${DEVICE_NODE_ID}" \
    --network-id "local-net" \
    --force
  unset -f run_with_scope >/dev/null 2>&1 || true
}

generate_verifier_key_from_signer() {
  local tmp_pub
  tmp_pub="$(mktemp)"
  openssl pkey -in "${TRUST_SIGNER_KEY_PATH}" -pubout -outform DER 2>/dev/null \
    | tail -c 32 \
    | xxd -p -c 32 >"${tmp_pub}"
  run_root install -m 0644 "${tmp_pub}" "${TRUST_VERIFIER_KEY_PATH}"
  rm -f "${tmp_pub}"
}

refresh_signed_trust_evidence() {
  require_admin_role "refresh_signed_trust_evidence" || return 0
  local refresh_script="${ROOT_DIR}/scripts/systemd/refresh_trust_evidence.sh"
  if [[ ! -f "${refresh_script}" ]]; then
    print_err "Missing trust refresh helper: ${refresh_script}"
    return 1
  fi
  if [[ ! -f "${TRUST_SIGNER_KEY_PATH}" ]]; then
    print_err "Signer key not found at ${TRUST_SIGNER_KEY_PATH}"
    return 1
  fi

  run_root env \
    RUSTYNET_TRUST_EVIDENCE="${TRUST_EVIDENCE_PATH}" \
    RUSTYNET_TRUST_SIGNER_KEY="${TRUST_SIGNER_KEY_PATH}" \
    RUSTYNET_DAEMON_GROUP="${RUSTYNET_DAEMON_GROUP:-rustynetd}" \
    RUSTYNET_TRUST_AUTO_REFRESH=true \
    "${refresh_script}"
  if is_macos_host; then
    local current_uid current_gid
    current_uid="$(id -u)"
    current_gid="$(id -g)"
    run_root chown "${current_uid}:${current_gid}" "${TRUST_EVIDENCE_PATH}"
    run_root chmod 600 "${TRUST_EVIDENCE_PATH}"
  fi
  print_info "Signed trust evidence refreshed at ${TRUST_EVIDENCE_PATH}"
}

configure_trust_material() {
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
    if [[ ! -f "${TRUST_SIGNER_KEY_PATH}" ]]; then
      run_root openssl genpkey -algorithm ED25519 -out "${TRUST_SIGNER_KEY_PATH}"
      run_root chmod 600 "${TRUST_SIGNER_KEY_PATH}"
      print_warn "Generated local signer key at ${TRUST_SIGNER_KEY_PATH} (lab/dev only)."
    fi
    generate_verifier_key_from_signer
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
  if is_macos_host; then
    return 0
  fi
  enforce_auto_tunnel_policy
  require_linux_dataplane "write_daemon_environment" || return 0
  local service_installer="${ROOT_DIR}/scripts/systemd/install_rustynetd_service.sh"
  if [[ ! -f "${service_installer}" ]]; then
    print_err "Missing installer script: ${service_installer}"
    exit 1
  fi
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
    RUSTYNET_AUTO_TUNNEL_ENFORCE="$( [[ "${AUTO_TUNNEL_ENFORCE}" == "1" ]] && echo true || echo false )" \
    RUSTYNET_AUTO_TUNNEL_BUNDLE="${AUTO_TUNNEL_BUNDLE_PATH}" \
    RUSTYNET_AUTO_TUNNEL_VERIFIER_KEY="${AUTO_TUNNEL_VERIFIER_KEY_PATH}" \
    RUSTYNET_AUTO_TUNNEL_WATERMARK="${AUTO_TUNNEL_WATERMARK_PATH}" \
    RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS="${AUTO_TUNNEL_MAX_AGE_SECS}" \
    RUSTYNET_BACKEND="${BACKEND_MODE}" \
    RUSTYNET_WG_INTERFACE="${WG_INTERFACE}" \
    RUSTYNET_WG_PRIVATE_KEY="${WG_PRIVATE_KEY_PATH}" \
    RUSTYNET_WG_ENCRYPTED_PRIVATE_KEY="${WG_ENCRYPTED_PRIVATE_KEY_PATH}" \
    RUSTYNET_WG_KEY_PASSPHRASE="${WG_KEY_PASSPHRASE_PATH}" \
    RUSTYNET_WG_PUBLIC_KEY="${WG_PUBLIC_KEY_PATH}" \
    RUSTYNET_EGRESS_INTERFACE="${EGRESS_INTERFACE}" \
    RUSTYNET_DATAPLANE_MODE="${DATAPLANE_MODE}" \
    RUSTYNET_PRIVILEGED_HELPER_SOCKET="${PRIVILEGED_HELPER_SOCKET_PATH}" \
    RUSTYNET_PRIVILEGED_HELPER_TIMEOUT_MS="${PRIVILEGED_HELPER_TIMEOUT_MS}" \
    RUSTYNET_RECONCILE_INTERVAL_MS="${RECONCILE_INTERVAL_MS}" \
    RUSTYNET_MAX_RECONCILE_FAILURES="${MAX_RECONCILE_FAILURES}" \
    RUSTYNET_FAIL_CLOSED_SSH_ALLOW="$( [[ "${FAIL_CLOSED_SSH_ALLOW}" == "1" ]] && echo true || echo false )" \
    RUSTYNET_FAIL_CLOSED_SSH_ALLOW_CIDRS="${FAIL_CLOSED_SSH_ALLOW_CIDRS}" \
    "${service_installer}"
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

configure_macos_binary_path_env() {
  if ! is_macos_host; then
    return 0
  fi

  add_macos_homebrew_to_path
  case ":${PATH}:" in
    *":${MACOS_LOCAL_TOOLS_BIN}:"*) ;;
    *) export PATH="${PATH}:${MACOS_LOCAL_TOOLS_BIN}" ;;
  esac
  case ":${PATH}:" in
    *":${MACOS_LOCAL_TOOLS_BASE}/go/bin:"*) ;;
    *) export PATH="${PATH}:${MACOS_LOCAL_TOOLS_BASE}/go/bin" ;;
  esac

  local wg_bin wireguard_go_bin ifconfig_bin route_bin pfctl_bin kill_bin
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

  require_root_owned_binary_path "${wg_bin}" "wg" || return 1
  require_root_owned_binary_path "${wireguard_go_bin}" "wireguard-go" || return 1
  require_root_owned_binary_path "${ifconfig_bin}" "ifconfig" || return 1
  require_root_owned_binary_path "${route_bin}" "route" || return 1
  require_root_owned_binary_path "${pfctl_bin}" "pfctl" || return 1
  require_root_owned_binary_path "${kill_bin}" "kill" || return 1

  export RUSTYNET_WG_BINARY_PATH="${wg_bin}"
  export RUSTYNET_WIREGUARD_GO_BINARY_PATH="${wireguard_go_bin}"
  export RUSTYNET_IFCONFIG_BINARY_PATH="${ifconfig_bin}"
  export RUSTYNET_ROUTE_BINARY_PATH="${route_bin}"
  export RUSTYNET_PFCTL_BINARY_PATH="${pfctl_bin}"
  export RUSTYNET_KILL_BINARY_PATH="${kill_bin}"
}

macos_stop_daemon_process() {
  if [[ -f "${MACOS_DAEMON_PID_PATH}" ]]; then
    local pid
    pid="$(cat "${MACOS_DAEMON_PID_PATH}" 2>/dev/null || true)"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      sleep 0.5
      if kill -0 "${pid}" 2>/dev/null; then
        kill -9 "${pid}" 2>/dev/null || true
      fi
    fi
    rm -f "${MACOS_DAEMON_PID_PATH}"
  fi
  rm -f "${SOCKET_PATH}"
}

macos_stop_privileged_helper_process() {
  run_root pkill -f "rustynetd privileged-helper --socket ${PRIVILEGED_HELPER_SOCKET_PATH}" 2>/dev/null || true
  rm -f "${PRIVILEGED_HELPER_SOCKET_PATH}"
}

macos_start_privileged_helper_process() {
  macos_stop_privileged_helper_process
  configure_macos_binary_path_env || return 1
  local uid gid
  uid="$(id -u)"
  gid="$(id -g)"
  run_root_background env \
    RUSTYNET_WG_BINARY_PATH="${RUSTYNET_WG_BINARY_PATH}" \
    RUSTYNET_WIREGUARD_GO_BINARY_PATH="${RUSTYNET_WIREGUARD_GO_BINARY_PATH}" \
    RUSTYNET_IFCONFIG_BINARY_PATH="${RUSTYNET_IFCONFIG_BINARY_PATH}" \
    RUSTYNET_ROUTE_BINARY_PATH="${RUSTYNET_ROUTE_BINARY_PATH}" \
    RUSTYNET_PFCTL_BINARY_PATH="${RUSTYNET_PFCTL_BINARY_PATH}" \
    RUSTYNET_KILL_BINARY_PATH="${RUSTYNET_KILL_BINARY_PATH}" \
    rustynetd privileged-helper \
    --socket "${PRIVILEGED_HELPER_SOCKET_PATH}" \
    --allowed-uid "${uid}" \
    --allowed-gid "${gid}" \
    --timeout-ms "${PRIVILEGED_HELPER_TIMEOUT_MS}"
  if ! macos_wait_for_socket "${PRIVILEGED_HELPER_SOCKET_PATH}"; then
    print_err "Timed out waiting for macOS privileged helper socket at ${PRIVILEGED_HELPER_SOCKET_PATH}."
    return 1
  fi
}

macos_start_daemon_process() {
  macos_stop_daemon_process
  configure_macos_binary_path_env || return 1
  local uid gid
  uid="$(id -u)"
  gid="$(id -g)"
  run_root install -d -m 0700 "${MACOS_RUNTIME_BASE}" "${MACOS_LOG_BASE}"
  run_root chown "${uid}:${gid}" "${MACOS_RUNTIME_BASE}" "${MACOS_LOG_BASE}"
  env \
    RUSTYNET_WG_BINARY_PATH="${RUSTYNET_WG_BINARY_PATH}" \
    RUSTYNET_WIREGUARD_GO_BINARY_PATH="${RUSTYNET_WIREGUARD_GO_BINARY_PATH}" \
    RUSTYNET_IFCONFIG_BINARY_PATH="${RUSTYNET_IFCONFIG_BINARY_PATH}" \
    RUSTYNET_ROUTE_BINARY_PATH="${RUSTYNET_ROUTE_BINARY_PATH}" \
    RUSTYNET_PFCTL_BINARY_PATH="${RUSTYNET_PFCTL_BINARY_PATH}" \
    RUSTYNET_KILL_BINARY_PATH="${RUSTYNET_KILL_BINARY_PATH}" \
    rustynetd daemon \
    --node-id "${DEVICE_NODE_ID}" \
    --node-role "${NODE_ROLE}" \
    --socket "${SOCKET_PATH}" \
    --state "${STATE_PATH}" \
    --trust-evidence "${TRUST_EVIDENCE_PATH}" \
    --trust-verifier-key "${TRUST_VERIFIER_KEY_PATH}" \
    --trust-watermark "${TRUST_WATERMARK_PATH}" \
    --membership-snapshot "${MEMBERSHIP_SNAPSHOT_PATH}" \
    --membership-log "${MEMBERSHIP_LOG_PATH}" \
    --membership-watermark "${MEMBERSHIP_WATERMARK_PATH}" \
    --auto-tunnel-enforce "$( [[ "${AUTO_TUNNEL_ENFORCE}" == "1" ]] && echo true || echo false )" \
    --auto-tunnel-bundle "${AUTO_TUNNEL_BUNDLE_PATH}" \
    --auto-tunnel-verifier-key "${AUTO_TUNNEL_VERIFIER_KEY_PATH}" \
    --auto-tunnel-watermark "${AUTO_TUNNEL_WATERMARK_PATH}" \
    --auto-tunnel-max-age-secs "${AUTO_TUNNEL_MAX_AGE_SECS}" \
    --backend "${BACKEND_MODE}" \
    --wg-interface "${WG_INTERFACE}" \
    --wg-private-key "${WG_PRIVATE_KEY_PATH}" \
    --wg-encrypted-private-key "${WG_ENCRYPTED_PRIVATE_KEY_PATH}" \
    --wg-key-passphrase "${WG_KEY_PASSPHRASE_PATH}" \
    --wg-public-key "${WG_PUBLIC_KEY_PATH}" \
    --egress-interface "${EGRESS_INTERFACE}" \
    --dataplane-mode "${DATAPLANE_MODE}" \
    --privileged-helper-socket "${PRIVILEGED_HELPER_SOCKET_PATH}" \
    --privileged-helper-timeout-ms "${PRIVILEGED_HELPER_TIMEOUT_MS}" \
    --reconcile-interval-ms "${RECONCILE_INTERVAL_MS}" \
    --max-reconcile-failures "${MAX_RECONCILE_FAILURES}" \
    --fail-closed-ssh-allow "$( [[ "${FAIL_CLOSED_SSH_ALLOW}" == "1" ]] && echo true || echo false )" \
    --fail-closed-ssh-allow-cidrs "${FAIL_CLOSED_SSH_ALLOW_CIDRS}" \
    >"${MACOS_DAEMON_LOG_PATH}" 2>&1 &
  local daemon_pid=$!
  printf '%s\n' "${daemon_pid}" >"${MACOS_DAEMON_PID_PATH}"
  chmod 600 "${MACOS_DAEMON_PID_PATH}"

  if ! macos_wait_for_socket "${SOCKET_PATH}"; then
    print_err "Timed out waiting for rustynetd socket at ${SOCKET_PATH}."
    tail -n 40 "${MACOS_DAEMON_LOG_PATH}" 2>/dev/null || true
    return 1
  fi
}

start_or_restart_service() {
  if ! doctor_preflight; then
    print_err "Refusing to start service until preflight doctor passes."
    return 1
  fi
  write_daemon_environment
  if [[ "${AUTO_REFRESH_TRUST}" == "1" && -f "${TRUST_SIGNER_KEY_PATH}" ]]; then
    refresh_signed_trust_evidence || print_warn "Failed to refresh trust evidence before start."
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
    macos_start_privileged_helper_process
    macos_start_daemon_process
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
    macos_stop_daemon_process
    macos_stop_privileged_helper_process
    return
  fi
  require_linux_dataplane "stop_service" || return 0
}

disconnect_vpn() {
  if is_macos_host; then
    print_info "Disabling exit-node mode before shutdown..."
    run_rustynet_cli exit-node off >/dev/null 2>&1 || true
    print_info "Stopping Rustynet daemon + privileged helper..."
    stop_service
    print_info "Stopping any remaining wireguard-go process for ${WG_INTERFACE}..."
    run_root pkill -f "wireguard-go ${WG_INTERFACE}" 2>/dev/null || true
    print_info "Flushing Rustynet PF anchors..."
    local anchors_output=""
    anchors_output="$(run_root pfctl -s Anchors 2>/dev/null)" || anchors_output=""
    while IFS= read -r anchor; do
      [[ -z "${anchor}" ]] && continue
      if [[ "${anchor}" == com.apple/rustynet_g* ]]; then
        run_root pfctl -a "${anchor}" -F all 2>/dev/null || true
      fi
    done <<<"${anchors_output}"
    print_info "Rustynet VPN disconnected."
    return
  fi

  require_linux_dataplane "disconnect_vpn" || return 0
  print_info "Stopping Rustynet service..."
  if ! run_root systemctl stop rustynetd.service 2>/dev/null; then
    print_warn "Rustynet service was not running or could not be stopped cleanly."
  fi

  print_info "Removing WireGuard interface ${WG_INTERFACE}..."
  if run_root ip link del dev "${WG_INTERFACE}" 2>/dev/null; then
    print_info "Interface ${WG_INTERFACE} removed (all associated routes cleared)."
  else
    print_info "Interface ${WG_INTERFACE} was not present."
  fi

  print_info "Flushing exit-node routing table 51820..."
  if ! run_root ip route flush table 51820 2>/dev/null; then
    print_warn "No routes found in table 51820 or flush failed."
  fi

  print_info "Removing exit-node IP policy rule (table 51820)..."
  if ! run_root ip rule del table 51820 2>/dev/null; then
    print_warn "No policy rule for table 51820 or delete failed."
  fi

  print_info "Removing Rustynet nftables firewall and NAT tables..."
  if command -v nft >/dev/null 2>&1; then
    local tables_output
    tables_output="$(run_root nft list tables 2>/dev/null)" || tables_output=""
    while IFS= read -r line; do
      case "${line}" in
        "table inet rustynet_g"*)
          local t="${line#table inet }"
          if run_root nft delete table inet "${t}" 2>/dev/null; then
            print_info "Removed nft table: inet ${t}"
          else
            print_warn "Failed to remove nft table: inet ${t}"
          fi
          ;;
        "table ip rustynet_nat_g"*)
          local t="${line#table ip }"
          if run_root nft delete table ip "${t}" 2>/dev/null; then
            print_info "Removed nft table: ip ${t}"
          else
            print_warn "Failed to remove nft table: ip ${t}"
          fi
          ;;
      esac
    done <<< "${tables_output}"
  fi

  print_info "Restoring IPv6 (disabled during VPN operation)..."
  if ! run_root sysctl -w net.ipv6.conf.all.disable_ipv6=0 2>/dev/null; then
    print_warn "Failed to restore IPv6 global setting."
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
    local daemon_pid=""
    daemon_pid="$(cat "${MACOS_DAEMON_PID_PATH}" 2>/dev/null || true)"
    if [[ -n "${daemon_pid}" ]] && kill -0 "${daemon_pid}" 2>/dev/null; then
      print_info "rustynetd running (pid ${daemon_pid})"
    else
      print_warn "rustynetd is not running."
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
  if [[ ! -s "${PEERS_FILE}" ]]; then
    cat >"${PEERS_FILE}" <<'EOF'
# name|node_id|public_key|endpoint|cidr|role
EOF
  fi
}

print_saved_peers() {
  ensure_peer_store
  awk -F'|' '
    $0 !~ /^#/ && NF >= 5 {
      role = (NF >= 6 && $6 != "") ? $6 : "unknown";
      printf "  - %s (node=%s endpoint=%s cidr=%s role=%s)\n", $1, $2, $4, $5, role
    }
  ' "${PEERS_FILE}"
}

print_saved_admin_peers() {
  ensure_peer_store
  awk -F'|' '
    $0 !~ /^#/ && NF >= 5 {
      role = (NF >= 6 && $6 != "") ? $6 : "unknown";
      if (role == "admin") {
        printf "  - %s (node=%s endpoint=%s cidr=%s)\n", $1, $2, $4, $5
      }
    }
  ' "${PEERS_FILE}"
}

upsert_peer() {
  local name="$1"
  local node_id="$2"
  local public_key="$3"
  local endpoint="$4"
  local cidr="$5"
  local role="${6:-unknown}"
  ensure_peer_store
  local tmp
  tmp="$(mktemp)"
  awk -F'|' -v n="${name}" '$0 ~ /^#/ || $1 != n { print }' "${PEERS_FILE}" >"${tmp}"
  printf '%s|%s|%s|%s|%s|%s\n' "${name}" "${node_id}" "${public_key}" "${endpoint}" "${cidr}" "${role}" >>"${tmp}"
  mv "${tmp}" "${PEERS_FILE}"
}

remove_peer_record() {
  local name="$1"
  ensure_peer_store
  local tmp
  tmp="$(mktemp)"
  awk -F'|' -v n="${name}" '$0 ~ /^#/ || $1 != n { print }' "${PEERS_FILE}" >"${tmp}"
  mv "${tmp}" "${PEERS_FILE}"
}

find_peer_record() {
  local name="$1"
  ensure_peer_store
  awk -F'|' -v n="${name}" '$0 !~ /^#/ && NF>=5 && $1 == n { print; exit }' "${PEERS_FILE}"
}

find_peer_record_by_node_id() {
  local node_id="$1"
  ensure_peer_store
  awk -F'|' -v nid="${node_id}" '$0 !~ /^#/ && NF>=5 && $2 == nid { print; exit }' "${PEERS_FILE}"
}

run_rustynet_cli() {
  if ! command -v rustynet >/dev/null 2>&1; then
    print_err "rustynet CLI not found in PATH."
    return 1
  fi
  RUSTYNET_DAEMON_SOCKET="${SOCKET_PATH}" rustynet "$@"
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
  connected_display="$(printf '%s' "${MENU_NETWORK_CONNECTED}" | tr '[:lower:]' '[:upper:]')"
  node_role_display="$(printf '%s' "${MENU_NODE_ROLE}" | tr '[:lower:]' '[:upper:]')"
  state_display="$(printf '%s' "${MENU_NETWORK_STATE}" | tr '[:lower:]' '[:upper:]')"
  exit_display="$(printf '%s' "${MENU_EXIT_ROLE}" | tr '[:lower:]' '[:upper:]')"
  printf '[status] Node role: %s | Connected: %s (state=%s) | Exit role: %s\n' \
    "${node_role_display}" \
    "${connected_display}" \
    "${state_display}" \
    "${exit_display}"
}

connect_to_device() {
  require_admin_role "connect_to_device" || return 0
  require_linux_dataplane "connect_to_device" || return 0
  local name node_id public_key endpoint_ip endpoint_port endpoint cidr peer_role
  prompt_default name "Peer name (local label)" "peer-$(date +%H%M%S)"
  prompt_default node_id "Peer node id" "${name}"
  prompt_default public_key "Peer WireGuard public key (base64)" ""
  prompt_default endpoint_ip "Peer endpoint IP or DNS" ""
  prompt_default endpoint_port "Peer endpoint port" "51820"
  prompt_default cidr "Peer tunnel CIDR" "100.64.0.2/32"
  prompt_default peer_role "Peer role (admin|client)" "client"
  case "${peer_role}" in
    admin|client) ;;
    *)
      print_warn "Unsupported peer role '${peer_role}', storing as client."
      peer_role="client"
      ;;
  esac

  if [[ -z "${public_key}" || -z "${endpoint_ip}" ]]; then
    print_err "Public key and endpoint are required."
    return 1
  fi

  require_manual_peer_override_authorization "manual_peer_connect:${name}:${node_id}" || return 1
  endpoint="${endpoint_ip}:${endpoint_port}"
  run_root wg set "${WG_INTERFACE}" peer "${public_key}" endpoint "${endpoint}" allowed-ips "${cidr}" persistent-keepalive 25
  run_root ip route replace "${cidr}" dev "${WG_INTERFACE}"
  upsert_peer "${name}" "${node_id}" "${public_key}" "${endpoint}" "${cidr}" "${peer_role}"
  print_info "Peer ${name} configured on ${WG_INTERFACE}."
}

disconnect_device() {
  require_admin_role "disconnect_device" || return 0
  require_linux_dataplane "disconnect_device" || return 0
  local name record public_key cidr
  print_saved_peers
  prompt_default name "Peer name to remove" ""
  if [[ -z "${name}" ]]; then
    print_err "Peer name is required."
    return 1
  fi
  record="$(find_peer_record "${name}")"
  if [[ -z "${record}" ]]; then
    print_err "Peer ${name} not found."
    return 1
  fi
  require_manual_peer_override_authorization "manual_peer_disconnect:${name}" || return 1
  public_key="$(echo "${record}" | awk -F'|' '{print $3}')"
  cidr="$(echo "${record}" | awk -F'|' '{print $5}')"
  if ! run_root wg set "${WG_INTERFACE}" peer "${public_key}" remove; then
    print_warn "Peer ${name} was not present in WireGuard runtime state."
  fi
  if ! run_root ip route del "${cidr}" dev "${WG_INTERFACE}"; then
    print_warn "Route ${cidr} was not present on ${WG_INTERFACE}."
  fi
  remove_peer_record "${name}"
  print_info "Peer ${name} removed."
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
  ensure_peer_store
  require_manual_peer_override_authorization "manual_peer_admin_mesh_sync" || return 1

  local configured=0
  local failed=0
  while IFS='|' read -r name node_id public_key endpoint cidr role _rest; do
    [[ -z "${name}" || "${name}" == \#* ]] && continue
    if [[ "${role:-unknown}" != "admin" ]]; then
      continue
    fi

    if run_root wg set "${WG_INTERFACE}" peer "${public_key}" endpoint "${endpoint}" allowed-ips "${cidr}" persistent-keepalive 25 \
      && run_root ip route replace "${cidr}" dev "${WG_INTERFACE}"; then
      configured=$((configured + 1))
    else
      failed=$((failed + 1))
      print_warn "Failed to apply admin peer '${name}' (${node_id})."
    fi
  done <"${PEERS_FILE}"

  print_info "Admin-peer sync complete: configured=${configured} failed=${failed}."
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
  local bundle prefix node_id new_public_key record name old_public endpoint cidr peer_role
  prompt_default bundle "Rotation bundle (format rotation:<node_id>:<public_key>)" ""
  if [[ -z "${bundle}" ]]; then
    print_err "Rotation bundle is required."
    return 1
  fi
  IFS=':' read -r prefix node_id new_public_key <<<"${bundle}"
  if [[ "${prefix}" != "rotation" || -z "${node_id}" || -z "${new_public_key}" ]]; then
    print_err "Invalid rotation bundle format."
    return 1
  fi

  record="$(find_peer_record_by_node_id "${node_id}")"
  if [[ -z "${record}" ]]; then
    print_err "No saved peer found for node id ${node_id}."
    return 1
  fi

  name="$(echo "${record}" | awk -F'|' '{print $1}')"
  old_public="$(echo "${record}" | awk -F'|' '{print $3}')"
  endpoint="$(echo "${record}" | awk -F'|' '{print $4}')"
  cidr="$(echo "${record}" | awk -F'|' '{print $5}')"
  peer_role="$(echo "${record}" | awk -F'|' '{print $6}')"
  if [[ -z "${peer_role}" ]]; then
    peer_role="unknown"
  fi

  if [[ "${old_public}" == "${new_public_key}" ]]; then
    print_info "Peer ${name} already has this key."
    return 0
  fi

  require_manual_peer_override_authorization "manual_peer_rotation_bundle:${name}:${node_id}" || return 1
  if ! run_root wg set "${WG_INTERFACE}" peer "${old_public}" remove; then
    print_warn "Previous peer key was not present in WireGuard runtime state."
  fi
  run_root wg set "${WG_INTERFACE}" peer "${new_public_key}" endpoint "${endpoint}" allowed-ips "${cidr}" persistent-keepalive 25
  upsert_peer "${name}" "${node_id}" "${new_public_key}" "${endpoint}" "${cidr}" "${peer_role}"
  print_info "Updated peer key for ${name} (${node_id}) without changing node identity."
}

configure_launch_defaults() {
  local profile_prompt
  if is_admin_role; then
    profile_prompt="Default launch profile (menu|quick-connect|quick-exit-node|quick-hybrid)"
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
  local fallback_egress="eth0"
  local previous_role selected_role confirm_default
  if is_macos_host; then
    fallback_egress="en0"
  fi
  detected_egress="$(detect_default_egress)"
  if [[ -z "${EGRESS_INTERFACE}" ]]; then
    EGRESS_INTERFACE="${detected_egress:-${fallback_egress}}"
  fi

  normalize_node_role
  previous_role="${NODE_ROLE}"
  prompt_default DEVICE_NODE_ID "Local device node id (used for display)" "${DEVICE_NODE_ID}"
  prompt_default selected_role "Node role (admin|client)" "${NODE_ROLE}"
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
  prompt_default WG_INTERFACE "WireGuard interface name" "${WG_INTERFACE}"
  prompt_default WG_PRIVATE_KEY_PATH "WireGuard runtime private key path" "${WG_PRIVATE_KEY_PATH}"
  prompt_default WG_ENCRYPTED_PRIVATE_KEY_PATH "WireGuard encrypted private key path" "${WG_ENCRYPTED_PRIVATE_KEY_PATH}"
  prompt_default WG_KEY_PASSPHRASE_PATH "WireGuard key passphrase file path" "${WG_KEY_PASSPHRASE_PATH}"
  prompt_default WG_PUBLIC_KEY_PATH "WireGuard public key path" "${WG_PUBLIC_KEY_PATH}"
  prompt_default EGRESS_INTERFACE "Egress interface" "${EGRESS_INTERFACE}"
  prompt_default MEMBERSHIP_SNAPSHOT_PATH "Membership snapshot path" "${MEMBERSHIP_SNAPSHOT_PATH}"
  prompt_default MEMBERSHIP_LOG_PATH "Membership log path" "${MEMBERSHIP_LOG_PATH}"
  prompt_default MEMBERSHIP_WATERMARK_PATH "Membership watermark path" "${MEMBERSHIP_WATERMARK_PATH}"
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
  prompt_default TRUST_SIGNER_KEY_PATH "Trust signer key path (for auto-refresh)" "${TRUST_SIGNER_KEY_PATH}"

  if is_linux_host && is_admin_role; then
    prompt_default MANUAL_PEER_OVERRIDE "Enable manual peer break-glass override (0/1)" "${MANUAL_PEER_OVERRIDE}"
    if [[ "${MANUAL_PEER_OVERRIDE}" != "1" ]]; then
      MANUAL_PEER_OVERRIDE="0"
    else
      print_warn "Manual peer break-glass override is ENABLED. All use is audit logged."
    fi
  else
    MANUAL_PEER_OVERRIDE="0"
  fi

  enforce_role_policy_defaults
  configure_launch_defaults
  enforce_host_storage_policy
}

first_run_setup() {
  print_info "Starting first-run Rustynet setup wizard."
  configure_values
  install_runtime_dependencies
  ensure_rust_toolchain
  ensure_ci_security_tools
  ensure_binaries_available
  prepare_system_directories
  ensure_wireguard_keys
  ensure_membership_files
  configure_trust_material
  write_daemon_environment
  start_or_restart_service
  SETUP_COMPLETE="1"
  save_config
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
  wg_interface            : ${WG_INTERFACE}
  wg_runtime_private_key  : ${WG_PRIVATE_KEY_PATH}
  wg_encrypted_private_key: ${WG_ENCRYPTED_PRIVATE_KEY_PATH}
  wg_key_passphrase       : ${WG_KEY_PASSPHRASE_PATH}
  wg_public_key           : ${WG_PUBLIC_KEY_PATH}
  egress_interface        : ${EGRESS_INTERFACE}
  membership_snapshot     : ${MEMBERSHIP_SNAPSHOT_PATH}
  membership_log          : ${MEMBERSHIP_LOG_PATH}
  membership_watermark    : ${MEMBERSHIP_WATERMARK_PATH}
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
  manual_peer_override    : ${MANUAL_PEER_OVERRIDE}
  manual_peer_audit_log   : ${MANUAL_PEER_AUDIT_LOG}
  default_launch_profile  : ${DEFAULT_LAUNCH_PROFILE}
  auto_launch_on_start    : ${AUTO_LAUNCH_ON_START}
  auto_launch_exit_node_id: ${AUTO_LAUNCH_EXIT_NODE_ID}
  auto_launch_lan_mode    : ${AUTO_LAUNCH_LAN_MODE}
EOF
}

offer_device_as_exit_node() {
  require_admin_role "offer_device_as_exit_node" || return 0
  print_info "Advertising exit route (0.0.0.0/0)."
  run_rustynet_cli route advertise 0.0.0.0/0
  print_info "This device can now be selected as an exit node by peers (node id: ${DEVICE_NODE_ID})."
}

toggle_lan_access() {
  local choice
  read -r -p "LAN access [on/off]: " choice
  case "${choice}" in
    on) run_rustynet_cli lan-access on ;;
    off) run_rustynet_cli lan-access off ;;
    *) print_err "Expected 'on' or 'off'." ;;
  esac
}

select_exit_node() {
  local node
  print_saved_peers
  prompt_default node "Exit node id to select" ""
  if [[ -z "${node}" ]]; then
    print_err "Exit node id is required."
    return 1
  fi
  run_rustynet_cli exit-node select "${node}"
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
      if run_rustynet_cli route advertise 0.0.0.0/0; then
        print_info "Exit route advertised (0.0.0.0/0)."
      else
        print_warn "Failed to advertise exit route. Check auto-tunnel policy restrictions."
      fi
      apply_lan_mode_noninteractive "${lan_mode}"
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
        configure_values
        save_config
        write_daemon_environment
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
  1) Connect to device (break-glass manual peer add/update)
  2) Remove device peer (break-glass manual peer remove)
  3) Select exit node
  4) Disable exit node
  5) Offer this device as an exit node
  6) Toggle LAN access
  7) Advertise route
  8) Apply peer key rotation bundle (break-glass manual path)
  9) Sync all saved admin peers (admin mesh break-glass)
  10) Show saved admin peers
  0) Back
EOF
    else
      cat <<'EOF'

Client Connectivity
  1) Select exit node
  2) Disable exit node
  3) Toggle LAN access
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
        1) connect_to_device ;;
        2) disconnect_device ;;
        3) select_exit_node ;;
        4) run_rustynet_cli exit-node off ;;
        5) offer_device_as_exit_node ;;
        6) toggle_lan_access ;;
        7) advertise_route ;;
        8) apply_rotation_bundle ;;
        9) connect_to_saved_admin_peers ;;
        10)
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
    cat <<'EOF'

Emergency & Recovery
  1) Disconnect VPN (stop service + restore normal network)
  2) Disable exit node
  3) Show service status
  4) Preflight doctor (security + prerequisites)
  0) Back
EOF
    local choice
    if ! read -r -p "Choose an option: " choice; then
      print_info "Input closed; returning to main menu."
      return
    fi
    case "${choice}" in
      1) disconnect_vpn ;;
      2) run_rustynet_cli exit-node off ;;
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
    cat <<'EOF'

Configuration
  1) Reconfigure daemon values
  2) Show current configuration
  3) Save configuration now
  4) Configure launch defaults
  5) Apply default launch profile now
  0) Back
EOF
    local choice
    if ! read -r -p "Choose an option: " choice; then
      print_info "Input closed; returning to main menu."
      return
    fi
    case "${choice}" in
      1)
        configure_values
        save_config
        write_daemon_environment
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
      0) return ;;
      *) print_warn "Unknown option: ${choice}" ;;
    esac
  done
}

main_menu() {
  if is_linux_host || is_macos_host; then
    print_info "Host OS: ${HOST_OS} (full dataplane/runtime mode)."
  else
    print_warn "Host OS: ${HOST_OS} (unsupported dataplane/runtime mode)."
  fi
  while true; do
    print_menu_runtime_header
    if is_admin_role; then
      cat <<'EOF'

Rustynet Admin Console
  1) Service setup & operations
  2) Network information & diagnostics
  3) Peer, exit node & routing
  4) Security & key management
  5) Emergency & recovery
  6) Configuration
  0) Exit
EOF
    else
      cat <<'EOF'

Rustynet Client Console
  1) Service setup & operations
  2) Network information & diagnostics
  3) Client connectivity
  4) Emergency & recovery
  5) Configuration
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
        1) menu_service_setup_operations ;;
        2) menu_network_information ;;
        3) menu_peer_exit_routing ;;
        4) menu_security_key_management ;;
        5) menu_emergency_recovery ;;
        6) menu_configuration ;;
        0) exit 0 ;;
        *) print_warn "Unknown option: ${choice}" ;;
      esac
    else
      case "${choice}" in
        1) menu_service_setup_operations ;;
        2) menu_network_information ;;
        3) menu_peer_exit_routing ;;
        4) menu_emergency_recovery ;;
        5) menu_configuration ;;
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
enforce_host_storage_policy
sanitize_launch_defaults
enforce_backend_mode

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
