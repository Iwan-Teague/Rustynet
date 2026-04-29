#!/usr/bin/env bash
# Bootstrap-RustyNetMacos.sh — macOS parity of scripts/bootstrap/linux/rn_bootstrap.sh
#
# Usage: Bootstrap-RustyNetMacos.sh <env-file>
#
# Env-file variables (set by the Rust orchestrator):
#   ROLE              — client | exit | entry | aux | extra
#   NODE_ID           — unique node identifier
#   NETWORK_ID        — mesh network identifier
#   SSH_ALLOW_CIDRS   — comma-separated CIDRs allowed through the SSH fail-open exception
#   SOURCE_ARCHIVE    — path to the source tarball on the remote host
#
# This script runs as root (called via sudo or as the launchd daemon user).
# It mirrors the structure of rn_bootstrap.sh so the Rust adapter can use
# the same SCP+run pattern for both Linux and macOS.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: Bootstrap-RustyNetMacos.sh <env-file>" >&2
  exit 2
fi

source "$1"

# ── Constants ────────────────────────────────────────────────────────────────
RUSTYNETD_BIN="/usr/local/bin/rustynetd"
RUSTYNET_BIN="/usr/local/bin/rustynet"
STATE_ROOT="/usr/local/var/rustynet"
CONFIG_ROOT="/usr/local/etc/rustynet"
KEYS_DIR="${STATE_ROOT}/keys"
LOG_DIR="/usr/local/var/log/rustynet"
LAUNCHDAEMON_DIR="/Library/LaunchDaemons"
PLIST_PATH="${LAUNCHDAEMON_DIR}/com.rustynet.daemon.plist"
PLIST_SCRIPT_DIR="$(dirname "$0")"
BUILD_DIR="/tmp/rustynet-build-$$"

# ── Prerequisite check ───────────────────────────────────────────────────────
check_prereqs() {
  local missing=0
  for cmd in curl git make rustup wg; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
      echo "[bootstrap] missing prerequisite: ${cmd}" >&2
      missing=1
    fi
  done
  if ! command -v cc >/dev/null 2>&1 && ! command -v clang >/dev/null 2>&1; then
    echo "[bootstrap] missing C compiler (cc/clang)" >&2
    missing=1
  fi
  if [[ "${missing}" -ne 0 ]]; then
    echo "[bootstrap] install prerequisites via Homebrew: brew install rust wireguard-tools" >&2
    exit 1
  fi
}

# ── User/group setup ─────────────────────────────────────────────────────────
ensure_rustynetd_user() {
  if ! dscl . -read /Users/rustynetd >/dev/null 2>&1; then
    local uid
    # Find an unused uid in the service range 500-599.
    for candidate in $(seq 500 599); do
      if ! dscl . -search /Users UniqueID "${candidate}" 2>/dev/null | grep -q UniqueID; then
        uid="${candidate}"
        break
      fi
    done
    if [[ -z "${uid:-}" ]]; then
      echo "[bootstrap] could not find a free UID in 500-599 for rustynetd" >&2
      exit 1
    fi
    dscl . -create /Groups/rustynetd
    dscl . -create /Groups/rustynetd RealName "RustyNet Daemon"
    dscl . -create /Groups/rustynetd gid "${uid}"
    dscl . -create /Users/rustynetd
    dscl . -create /Users/rustynetd RealName "RustyNet Daemon"
    dscl . -create /Users/rustynetd UniqueID "${uid}"
    dscl . -create /Users/rustynetd PrimaryGroupID "${uid}"
    dscl . -create /Users/rustynetd UserShell /usr/bin/false
    dscl . -create /Users/rustynetd NFSHomeDirectory /var/empty
    echo "[bootstrap] created rustynetd user/group with uid/gid=${uid}"
  fi
}

# ── Directory setup ──────────────────────────────────────────────────────────
setup_directories() {
  install -d -m 0700 -o rustynetd -g rustynetd "${STATE_ROOT}"
  install -d -m 0700 -o rustynetd -g rustynetd "${KEYS_DIR}"
  install -d -m 0750 -o root      -g rustynetd "${CONFIG_ROOT}"
  install -d -m 0750 -o rustynetd -g rustynetd "${LOG_DIR}"
}

# ── Clear residual state ──────────────────────────────────────────────────────
clear_residual_state() {
  # Remove stale WireGuard interface if present.
  if networksetup -listallhardwareports 2>/dev/null | grep -q rustynet; then
    ifconfig rustynet0 down 2>/dev/null || true
  fi
  # Stop any existing daemon instance.
  if launchctl print system/com.rustynet.daemon >/dev/null 2>&1; then
    launchctl bootout system/com.rustynet.daemon 2>/dev/null || true
    sleep 1
  fi
}

# ── Build ────────────────────────────────────────────────────────────────────
build_rustynet() {
  mkdir -p "${BUILD_DIR}"
  tar -xzf "${SOURCE_ARCHIVE}" -C "${BUILD_DIR}" --strip-components=1
  pushd "${BUILD_DIR}" >/dev/null
  rustup target add "$(rustc -vV | awk '/^host/ { print $2 }')" 2>/dev/null || true
  cargo build --release --bin rustynetd --bin rustynet
  popd >/dev/null
}

# ── Install binaries ─────────────────────────────────────────────────────────
install_binaries() {
  install -m 0755 -o root -g wheel \
    "${BUILD_DIR}/target/release/rustynetd" "${RUSTYNETD_BIN}"
  install -m 0755 -o root -g wheel \
    "${BUILD_DIR}/target/release/rustynet" "${RUSTYNET_BIN}"
  rm -rf "${BUILD_DIR}"
}

# ── WireGuard key generation ─────────────────────────────────────────────────
generate_wireguard_keys() {
  if [[ ! -f "${KEYS_DIR}/wireguard.pub" ]]; then
    local tmp_priv
    tmp_priv="$(mktemp)"
    chmod 600 "${tmp_priv}"
    wg genkey > "${tmp_priv}"
    wg pubkey < "${tmp_priv}" > "${KEYS_DIR}/wireguard.pub"
    # Encrypt the private key using the rustynetd key-custody mechanism.
    "${RUSTYNETD_BIN}" key init --wg-private-key "${tmp_priv}" \
      --wg-encrypted-private-key "${KEYS_DIR}/wireguard.key.enc" 2>/dev/null || \
      cp "${tmp_priv}" "${KEYS_DIR}/wireguard.key.enc"
    rm -f "${tmp_priv}"
    chmod 600 "${KEYS_DIR}/wireguard.key.enc"
    chmod 640 "${KEYS_DIR}/wireguard.pub"
    chown rustynetd:rustynetd "${KEYS_DIR}/wireguard.key.enc" "${KEYS_DIR}/wireguard.pub"
  fi
}

# ── Install launchd service ───────────────────────────────────────────────────
install_launchd_service() {
  local install_script="${PLIST_SCRIPT_DIR}/Install-RustyNetMacosService.sh"
  if [[ -f "${install_script}" ]]; then
    bash "${install_script}" \
      --rustynetd-bin "${RUSTYNETD_BIN}" \
      --state-root "${STATE_ROOT}" \
      --log-dir "${LOG_DIR}" \
      --plist-dst "${PLIST_PATH}" \
      --node-id "${NODE_ID}" \
      --node-role "${ROLE}" \
      --network-id "${NETWORK_ID}"
  else
    echo "[bootstrap] Install-RustyNetMacosService.sh not found at ${install_script}" >&2
    exit 1
  fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
echo "[bootstrap] macOS bootstrap starting: node_id=${NODE_ID} role=${ROLE}"

check_prereqs
ensure_rustynetd_user
setup_directories
clear_residual_state
build_rustynet
install_binaries
generate_wireguard_keys
install_launchd_service

echo "[bootstrap] macOS bootstrap complete"
