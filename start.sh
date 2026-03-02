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
WG_ENCRYPTED_PRIVATE_KEY_PATH="/etc/rustynet/wireguard.key.enc"
WG_KEY_PASSPHRASE_PATH="/etc/rustynet/wireguard.passphrase"
WG_PUBLIC_KEY_PATH="/etc/rustynet/wireguard.pub"
EGRESS_INTERFACE=""
MEMBERSHIP_SNAPSHOT_PATH="/var/lib/rustynet/membership.snapshot"
MEMBERSHIP_LOG_PATH="/var/lib/rustynet/membership.log"
BACKEND_MODE="linux-wireguard"
DATAPLANE_MODE="hybrid-native"
RECONCILE_INTERVAL_MS="1000"
MAX_RECONCILE_FAILURES="5"
TRUST_SIGNER_KEY_PATH="/etc/rustynet/trust-evidence.key"
AUTO_REFRESH_TRUST="0"
DEVICE_NODE_ID="$(hostname -s 2>/dev/null || echo rustynet-node)"
SETUP_COMPLETE="0"
MANUAL_PEER_OVERRIDE="0"
RUST_MIN_VERSION="1.85"
MANUAL_PEER_AUDIT_LOG="/var/log/rustynet/manual-peer-override.log"
MANUAL_OVERRIDE_CONFIRMATION="RUSTYNET_BREAK_GLASS_ACK"
HOST_OS="$(uname -s)"
export PATH="/usr/local/sbin:/usr/sbin:/sbin:${PATH}"

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

require_linux_dataplane() {
  local action="$1"
  if is_linux_host; then
    return 0
  fi
  print_err "${action} requires a Linux dataplane host."
  if is_macos_host; then
    print_info "On macOS, use this wizard for build/validation and manage a Linux node for dataplane/runtime."
  else
    print_info "Current host OS '${HOST_OS}' is not supported for dataplane/runtime operations."
  fi
  return 1
}

is_allowed_config_key() {
  local key="$1"
  case "${key}" in
    SOCKET_PATH|STATE_PATH|TRUST_EVIDENCE_PATH|TRUST_VERIFIER_KEY_PATH|TRUST_WATERMARK_PATH|AUTO_TUNNEL_ENFORCE|AUTO_TUNNEL_BUNDLE_PATH|AUTO_TUNNEL_VERIFIER_KEY_PATH|AUTO_TUNNEL_WATERMARK_PATH|AUTO_TUNNEL_MAX_AGE_SECS|WG_INTERFACE|WG_PRIVATE_KEY_PATH|WG_ENCRYPTED_PRIVATE_KEY_PATH|WG_KEY_PASSPHRASE_PATH|WG_PUBLIC_KEY_PATH|EGRESS_INTERFACE|MEMBERSHIP_SNAPSHOT_PATH|MEMBERSHIP_LOG_PATH|BACKEND_MODE|DATAPLANE_MODE|RECONCILE_INTERVAL_MS|MAX_RECONCILE_FAILURES|TRUST_SIGNER_KEY_PATH|AUTO_REFRESH_TRUST|DEVICE_NODE_ID|SETUP_COMPLETE|MANUAL_PEER_OVERRIDE|MANUAL_PEER_AUDIT_LOG)
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
  if [[ "${BACKEND_MODE}" != "linux-wireguard" ]]; then
    print_warn "Unsupported backend '${BACKEND_MODE}' detected; forcing linux-wireguard."
  fi
  BACKEND_MODE="linux-wireguard"
}

enforce_auto_tunnel_policy() {
  if [[ "${AUTO_TUNNEL_ENFORCE}" != "1" ]]; then
    print_warn "Unsigned/manual tunnel assignment is not allowed by default; forcing AUTO_TUNNEL_ENFORCE=1."
  fi
  AUTO_TUNNEL_ENFORCE="1"
}

manual_peer_override_enabled() {
  [[ "${MANUAL_PEER_OVERRIDE}" == "1" || "${RUSTYNET_MANUAL_PEER_OVERRIDE:-0}" == "1" ]]
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
    sudo "$@"
  fi
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
    printf 'BACKEND_MODE=%s\n' "${BACKEND_MODE}"
    printf 'DATAPLANE_MODE=%s\n' "${DATAPLANE_MODE}"
    printf 'RECONCILE_INTERVAL_MS=%s\n' "${RECONCILE_INTERVAL_MS}"
    printf 'MAX_RECONCILE_FAILURES=%s\n' "${MAX_RECONCILE_FAILURES}"
    printf 'TRUST_SIGNER_KEY_PATH=%s\n' "${TRUST_SIGNER_KEY_PATH}"
    printf 'AUTO_REFRESH_TRUST=%s\n' "${AUTO_REFRESH_TRUST}"
    printf 'DEVICE_NODE_ID=%s\n' "${DEVICE_NODE_ID}"
    printf 'SETUP_COMPLETE=%s\n' "${SETUP_COMPLETE}"
    printf 'MANUAL_PEER_OVERRIDE=%s\n' "${MANUAL_PEER_OVERRIDE}"
    printf 'MANUAL_PEER_AUDIT_LOG=%s\n' "${MANUAL_PEER_AUDIT_LOG}"
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
    cargo install --locked "${tool}"
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
  local required=(openssl xxd curl awk sed grep rg)
  if is_linux_host; then
    required+=(wg ip nft systemctl)
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
  if is_macos_host && [[ "${pm}" != "brew" ]]; then
    print_err "Homebrew is required on macOS for automated dependency installs."
    print_info "Install Homebrew from https://brew.sh and rerun ./start.sh."
    exit 1
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
  run_root install -m 0755 "${ROOT_DIR}/target/release/rustynetd" /usr/local/bin/rustynetd
  run_root install -m 0755 "${ROOT_DIR}/target/release/rustynet-cli" /usr/local/bin/rustynet
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
      doctor_check_mode "${WG_PRIVATE_KEY_PATH}" "600" "runtime private key"
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
    if command -v brew >/dev/null 2>&1; then
      doctor_ok "homebrew present for macOS dependency management"
    else
      doctor_fail "homebrew missing; install from https://brew.sh"
    fi
    doctor_warn "macOS runs in compatibility mode; Linux host is required for dataplane runtime."
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
  require_linux_dataplane "prepare_system_directories" || return 0
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
}

ensure_wireguard_keys() {
  require_linux_dataplane "ensure_wireguard_keys" || return 0
  if [[ -f "${WG_ENCRYPTED_PRIVATE_KEY_PATH}" && -f "${WG_PUBLIC_KEY_PATH}" && -f "${WG_KEY_PASSPHRASE_PATH}" ]]; then
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
    run_root install -m 0600 "${tmp_passphrase}" "${WG_KEY_PASSPHRASE_PATH}"
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
    run_root rustynetd key migrate \
      --existing-private-key "${source_private_key}" \
      --runtime-private-key "${WG_PRIVATE_KEY_PATH}" \
      --encrypted-private-key "${WG_ENCRYPTED_PRIVATE_KEY_PATH}" \
      --public-key "${WG_PUBLIC_KEY_PATH}" \
      --passphrase-file "${WG_KEY_PASSPHRASE_PATH}" \
      --force
    if [[ "${source_private_key}" != "${WG_PRIVATE_KEY_PATH}" ]]; then
      run_root rm -f "${source_private_key}"
      print_info "Removed legacy plaintext private key at ${source_private_key}"
    fi
    print_info "Existing key migrated to encrypted storage."
    return
  fi

  run_root rustynetd key init \
    --runtime-private-key "${WG_PRIVATE_KEY_PATH}" \
    --encrypted-private-key "${WG_ENCRYPTED_PRIVATE_KEY_PATH}" \
    --public-key "${WG_PUBLIC_KEY_PATH}" \
    --passphrase-file "${WG_KEY_PASSPHRASE_PATH}" \
    --force

  print_info "WireGuard key material initialized (encrypted key: ${WG_ENCRYPTED_PRIVATE_KEY_PATH})"
}

ensure_membership_files() {
  require_linux_dataplane "ensure_membership_files" || return 0
  if [[ -f "${MEMBERSHIP_SNAPSHOT_PATH}" && -f "${MEMBERSHIP_LOG_PATH}" ]]; then
    print_info "Membership files already present."
    return
  fi
  print_info "Initializing membership files for node '${DEVICE_NODE_ID}'."
  run_root rustynetd membership init \
    --snapshot "${MEMBERSHIP_SNAPSHOT_PATH}" \
    --log "${MEMBERSHIP_LOG_PATH}" \
    --node-id "${DEVICE_NODE_ID}" \
    --network-id "local-net" \
    --force
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
  if [[ ! -f "${TRUST_SIGNER_KEY_PATH}" ]]; then
    print_err "Signer key not found at ${TRUST_SIGNER_KEY_PATH}"
    return 1
  fi

  local updated_at
  local nonce
  local payload
  local sig_bin
  local trust_tmp
  local sig_hex
  updated_at="$(date +%s)"
  nonce="$(date +%s%N)"
  payload="$(mktemp)"
  sig_bin="$(mktemp)"
  trust_tmp="$(mktemp)"

  cat >"${payload}" <<EOF
version=2
tls13_valid=true
signed_control_valid=true
signed_data_age_secs=0
clock_skew_secs=0
updated_at_unix=${updated_at}
nonce=${nonce}
EOF

  openssl pkeyutl -sign -inkey "${TRUST_SIGNER_KEY_PATH}" -rawin -in "${payload}" -out "${sig_bin}"
  sig_hex="$(xxd -p -c 200 "${sig_bin}" | tr -d '\n')"
  cat "${payload}" >"${trust_tmp}"
  printf 'signature=%s\n' "${sig_hex}" >>"${trust_tmp}"

  run_root install -m 0600 "${trust_tmp}" "${TRUST_EVIDENCE_PATH}"
  rm -f "${payload}" "${sig_bin}" "${trust_tmp}"
  print_info "Signed trust evidence refreshed at ${TRUST_EVIDENCE_PATH}"
}

configure_trust_material() {
  require_linux_dataplane "configure_trust_material" || return 0
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

  if [[ "${source_trust}" != "${TRUST_EVIDENCE_PATH}" ]]; then
    run_root install -m 0600 "${source_trust}" "${TRUST_EVIDENCE_PATH}"
  elif [[ ! -f "${TRUST_EVIDENCE_PATH}" ]]; then
    run_root install -m 0600 "${source_trust}" "${TRUST_EVIDENCE_PATH}"
  fi

  if prompt_yes_no "Do you also have signer key access for auto-refresh?" "n"; then
    prompt_default TRUST_SIGNER_KEY_PATH "Signer key path" "${TRUST_SIGNER_KEY_PATH}"
    AUTO_REFRESH_TRUST="1"
  else
    AUTO_REFRESH_TRUST="0"
  fi
}

write_daemon_environment() {
  require_linux_dataplane "write_daemon_environment" || return 0
  enforce_backend_mode
  enforce_auto_tunnel_policy
  local service_installer="${ROOT_DIR}/scripts/systemd/install_rustynetd_service.sh"
  if [[ ! -f "${service_installer}" ]]; then
    print_err "Missing installer script: ${service_installer}"
    exit 1
  fi
  run_root env \
    RUSTYNET_NODE_ID="${DEVICE_NODE_ID}" \
    RUSTYNET_SOCKET="${SOCKET_PATH}" \
    RUSTYNET_STATE="${STATE_PATH}" \
    RUSTYNET_TRUST_EVIDENCE="${TRUST_EVIDENCE_PATH}" \
    RUSTYNET_TRUST_VERIFIER_KEY="${TRUST_VERIFIER_KEY_PATH}" \
    RUSTYNET_TRUST_WATERMARK="${TRUST_WATERMARK_PATH}" \
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
    RUSTYNET_RECONCILE_INTERVAL_MS="${RECONCILE_INTERVAL_MS}" \
    RUSTYNET_MAX_RECONCILE_FAILURES="${MAX_RECONCILE_FAILURES}" \
    "${service_installer}"
}

start_or_restart_service() {
  require_linux_dataplane "start_or_restart_service" || return 0
  if ! doctor_preflight; then
    print_err "Refusing to start service until preflight doctor passes."
    return 1
  fi
  write_daemon_environment
  if [[ "${AUTO_REFRESH_TRUST}" == "1" && -f "${TRUST_SIGNER_KEY_PATH}" ]]; then
    refresh_signed_trust_evidence || print_warn "Failed to refresh trust evidence before start."
  fi
  run_root systemctl daemon-reload
  run_root systemctl enable rustynetd.service
  run_root systemctl restart rustynetd.service
  if ! run_root systemctl --no-pager --full status rustynetd.service; then
    print_warn "Unable to read rustynetd.service status after restart."
  fi
}

stop_service() {
  require_linux_dataplane "stop_service" || return 0
  run_root systemctl stop rustynetd.service
}

disconnect_vpn() {
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
  require_linux_dataplane "show_service_status" || return 0
  if ! run_root systemctl --no-pager --full status rustynetd.service; then
    print_warn "Unable to read rustynetd.service status."
  fi
}

ensure_peer_store() {
  if [[ ! -s "${PEERS_FILE}" ]]; then
    cat >"${PEERS_FILE}" <<'EOF'
# name|node_id|public_key|endpoint|cidr
EOF
  fi
}

print_saved_peers() {
  ensure_peer_store
  awk -F'|' 'NF==5 && $0 !~ /^#/ { printf "  - %s (node=%s endpoint=%s cidr=%s)\n", $1, $2, $4, $5 }' "${PEERS_FILE}"
}

upsert_peer() {
  local name="$1"
  local node_id="$2"
  local public_key="$3"
  local endpoint="$4"
  local cidr="$5"
  ensure_peer_store
  local tmp
  tmp="$(mktemp)"
  awk -F'|' -v n="${name}" '$0 ~ /^#/ || $1 != n { print }' "${PEERS_FILE}" >"${tmp}"
  printf '%s|%s|%s|%s|%s\n' "${name}" "${node_id}" "${public_key}" "${endpoint}" "${cidr}" >>"${tmp}"
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
  awk -F'|' -v n="${name}" '$0 !~ /^#/ && NF==5 && $1 == n { print; exit }' "${PEERS_FILE}"
}

find_peer_record_by_node_id() {
  local node_id="$1"
  ensure_peer_store
  awk -F'|' -v nid="${node_id}" '$0 !~ /^#/ && NF==5 && $2 == nid { print; exit }' "${PEERS_FILE}"
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
  MENU_EXIT_ROLE="off"
  MENU_EXIT_SELECTED_NODE="none"
  MENU_EXIT_SERVING="false"

  if ! is_linux_host; then
    MENU_NETWORK_STATE="compatibility-mode"
    MENU_NETWORK_CONNECTED="n/a"
    MENU_EXIT_ROLE="n/a"
    return
  fi

  if ! command -v rustynet >/dev/null 2>&1; then
    MENU_NETWORK_STATE="cli-missing"
    MENU_NETWORK_CONNECTED="no"
    MENU_EXIT_ROLE="unknown"
    return
  fi

  local status_line
  if ! status_line="$(RUSTYNET_DAEMON_SOCKET="${SOCKET_PATH}" rustynet status 2>/dev/null)"; then
    MENU_NETWORK_STATE="daemon-unreachable"
    MENU_NETWORK_CONNECTED="no"
    MENU_EXIT_ROLE="off"
    return
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
  printf '[status] Connected: %s (state=%s) | Exit role: %s\n' \
    "${MENU_NETWORK_CONNECTED}" \
    "${MENU_NETWORK_STATE}" \
    "${MENU_EXIT_ROLE}"
}

connect_to_device() {
  require_linux_dataplane "connect_to_device" || return 0
  local name node_id public_key endpoint_ip endpoint_port endpoint cidr
  prompt_default name "Peer name (local label)" "peer-$(date +%H%M%S)"
  prompt_default node_id "Peer node id" "${name}"
  prompt_default public_key "Peer WireGuard public key (base64)" ""
  prompt_default endpoint_ip "Peer endpoint IP or DNS" ""
  prompt_default endpoint_port "Peer endpoint port" "51820"
  prompt_default cidr "Peer tunnel CIDR" "100.64.0.2/32"

  if [[ -z "${public_key}" || -z "${endpoint_ip}" ]]; then
    print_err "Public key and endpoint are required."
    return 1
  fi

  require_manual_peer_override_authorization "manual_peer_connect:${name}:${node_id}" || return 1
  endpoint="${endpoint_ip}:${endpoint_port}"
  run_root wg set "${WG_INTERFACE}" peer "${public_key}" endpoint "${endpoint}" allowed-ips "${cidr}" persistent-keepalive 25
  run_root ip route replace "${cidr}" dev "${WG_INTERFACE}"
  upsert_peer "${name}" "${node_id}" "${public_key}" "${endpoint}" "${cidr}"
  print_info "Peer ${name} configured on ${WG_INTERFACE}."
}

disconnect_device() {
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
  require_linux_dataplane "show_connected_devices" || return 0
  echo "Saved peers:"
  print_saved_peers
  echo
  echo "WireGuard live state:"
  run_root wg show "${WG_INTERFACE}" || print_warn "Unable to read live WireGuard state."
}

rotate_local_key() {
  require_linux_dataplane "rotate_local_key" || return 0
  run_rustynet_cli key rotate
}

revoke_local_key() {
  require_linux_dataplane "revoke_local_key" || return 0
  if ! prompt_yes_no "Revoke local key material now? This disables connectivity until reinitialized." "n"; then
    print_info "Revoke cancelled."
    return 0
  fi
  run_rustynet_cli key revoke
}

apply_rotation_bundle() {
  require_linux_dataplane "apply_rotation_bundle" || return 0
  local bundle prefix node_id new_public_key record name old_public endpoint cidr
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

  if [[ "${old_public}" == "${new_public_key}" ]]; then
    print_info "Peer ${name} already has this key."
    return 0
  fi

  require_manual_peer_override_authorization "manual_peer_rotation_bundle:${name}:${node_id}" || return 1
  if ! run_root wg set "${WG_INTERFACE}" peer "${old_public}" remove; then
    print_warn "Previous peer key was not present in WireGuard runtime state."
  fi
  run_root wg set "${WG_INTERFACE}" peer "${new_public_key}" endpoint "${endpoint}" allowed-ips "${cidr}" persistent-keepalive 25
  upsert_peer "${name}" "${node_id}" "${new_public_key}" "${endpoint}" "${cidr}"
  print_info "Updated peer key for ${name} (${node_id}) without changing node identity."
}

configure_values() {
  local detected_egress
  local fallback_egress="eth0"
  if is_macos_host; then
    fallback_egress="en0"
  fi
  detected_egress="$(detect_default_egress)"
  if [[ -z "${EGRESS_INTERFACE}" ]]; then
    EGRESS_INTERFACE="${detected_egress:-${fallback_egress}}"
  fi

  prompt_default DEVICE_NODE_ID "Local device node id (used for display)" "${DEVICE_NODE_ID}"
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
  enforce_backend_mode
  print_info "Backend mode is fixed to linux-wireguard for production-safe operation."
  prompt_default DATAPLANE_MODE "Dataplane mode (shell|hybrid-native)" "${DATAPLANE_MODE}"
  prompt_default RECONCILE_INTERVAL_MS "Reconcile interval (ms)" "${RECONCILE_INTERVAL_MS}"
  prompt_default MAX_RECONCILE_FAILURES "Max reconcile failures" "${MAX_RECONCILE_FAILURES}"
  prompt_default TRUST_SIGNER_KEY_PATH "Trust signer key path (for auto-refresh)" "${TRUST_SIGNER_KEY_PATH}"
  prompt_default MANUAL_PEER_OVERRIDE "Enable manual peer break-glass override (0/1)" "${MANUAL_PEER_OVERRIDE}"
  if [[ "${MANUAL_PEER_OVERRIDE}" != "1" ]]; then
    MANUAL_PEER_OVERRIDE="0"
  else
    print_warn "Manual peer break-glass override is ENABLED. All use is audit logged."
  fi
}

first_run_setup() {
  print_info "Starting first-run Rustynet setup wizard."
  configure_values
  install_runtime_dependencies
  ensure_rust_toolchain
  ensure_ci_security_tools
  ensure_binaries_available
  if ! is_linux_host; then
    print_warn "Linux dataplane/runtime provisioning is skipped on ${HOST_OS}."
    print_info "This host is configured for build/validation workflows only."
    print_info "Run runtime dataplane setup on a Debian/Linux node with ./start.sh."
    SETUP_COMPLETE="1"
    save_config
    return 0
  fi
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
  backend                 : ${BACKEND_MODE}
  dataplane_mode          : ${DATAPLANE_MODE}
  reconcile_interval_ms   : ${RECONCILE_INTERVAL_MS}
  max_reconcile_failures  : ${MAX_RECONCILE_FAILURES}
  trust_signer_key        : ${TRUST_SIGNER_KEY_PATH}
  auto_refresh_trust      : ${AUTO_REFRESH_TRUST}
  manual_peer_override    : ${MANUAL_PEER_OVERRIDE}
  manual_peer_audit_log   : ${MANUAL_PEER_AUDIT_LOG}
EOF
}

offer_device_as_exit_node() {
  require_linux_dataplane "offer_device_as_exit_node" || return 0
  print_info "Advertising exit route (0.0.0.0/0)."
  run_rustynet_cli route advertise 0.0.0.0/0
  print_info "This device can now be selected as an exit node by peers (node id: ${DEVICE_NODE_ID})."
}

toggle_lan_access() {
  require_linux_dataplane "toggle_lan_access" || return 0
  local choice
  read -r -p "LAN access [on/off]: " choice
  case "${choice}" in
    on) run_rustynet_cli lan-access on ;;
    off) run_rustynet_cli lan-access off ;;
    *) print_err "Expected 'on' or 'off'." ;;
  esac
}

select_exit_node() {
  require_linux_dataplane "select_exit_node" || return 0
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
  require_linux_dataplane "advertise_route" || return 0
  local cidr
  prompt_default cidr "CIDR to advertise (for LAN/exit routing)" "192.168.1.0/24"
  run_rustynet_cli route advertise "${cidr}"
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
  0) Back
EOF
    local choice
    if ! read -r -p "Choose an option: " choice; then
      print_info "Input closed; returning to main menu."
      return
    fi
    case "${choice}" in
      1) connect_to_device ;;
      2) disconnect_device ;;
      3) select_exit_node ;;
      4) run_rustynet_cli exit-node off ;;
      5) offer_device_as_exit_node ;;
      6) toggle_lan_access ;;
      7) advertise_route ;;
      8) apply_rotation_bundle ;;
      0) return ;;
      *) print_warn "Unknown option: ${choice}" ;;
    esac
  done
}

menu_security_key_management() {
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
      0) return ;;
      *) print_warn "Unknown option: ${choice}" ;;
    esac
  done
}

main_menu() {
  if is_linux_host; then
    print_info "Host OS: ${HOST_OS} (full dataplane/runtime mode)."
  else
    print_warn "Host OS: ${HOST_OS} (compatibility mode: Linux dataplane actions are blocked)."
  fi
  while true; do
    print_menu_runtime_header
    cat <<'EOF'

Rustynet Control Menu
  1) Service setup & operations
  2) Network information & diagnostics
  3) Peer, exit node & routing
  4) Security & key management
  5) Emergency & recovery
  6) Configuration
  0) Exit
EOF
    local choice
    if ! read -r -p "Choose an option: " choice; then
      print_info "Input closed; exiting menu."
      break
    fi
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
  done
}

load_config_file

if [[ "${SETUP_COMPLETE}" != "1" ]]; then
  print_warn "Rustynet is not configured yet."
  if prompt_yes_no "Run first-run setup now?" "y"; then
    first_run_setup
  fi
fi

save_config
main_menu
