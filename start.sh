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
WG_INTERFACE="rustynet0"
WG_PRIVATE_KEY_PATH="/run/rustynet/wireguard.key"
WG_ENCRYPTED_PRIVATE_KEY_PATH="/etc/rustynet/wireguard.key.enc"
WG_KEY_PASSPHRASE_PATH="/etc/rustynet/wireguard.passphrase"
WG_PUBLIC_KEY_PATH="/etc/rustynet/wireguard.pub"
EGRESS_INTERFACE=""
BACKEND_MODE="linux-wireguard"
DATAPLANE_MODE="hybrid-native"
RECONCILE_INTERVAL_MS="1000"
MAX_RECONCILE_FAILURES="5"
TRUST_SIGNER_KEY_PATH="/etc/rustynet/trust-evidence.key"
AUTO_REFRESH_TRUST="0"
DEVICE_NODE_ID="$(hostname -s 2>/dev/null || echo rustynet-node)"
SETUP_COMPLETE="0"

mkdir -p "${CONFIG_DIR}"
touch "${PEERS_FILE}"

if [[ -f "${CONFIG_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${CONFIG_FILE}"
fi

print_info() {
  printf '[info] %s\n' "$*"
}

print_warn() {
  printf '[warn] %s\n' "$*" >&2
}

print_err() {
  printf '[error] %s\n' "$*" >&2
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
    printf 'SOCKET_PATH=%q\n' "${SOCKET_PATH}"
    printf 'STATE_PATH=%q\n' "${STATE_PATH}"
    printf 'TRUST_EVIDENCE_PATH=%q\n' "${TRUST_EVIDENCE_PATH}"
    printf 'TRUST_VERIFIER_KEY_PATH=%q\n' "${TRUST_VERIFIER_KEY_PATH}"
    printf 'TRUST_WATERMARK_PATH=%q\n' "${TRUST_WATERMARK_PATH}"
    printf 'WG_INTERFACE=%q\n' "${WG_INTERFACE}"
    printf 'WG_PRIVATE_KEY_PATH=%q\n' "${WG_PRIVATE_KEY_PATH}"
    printf 'WG_ENCRYPTED_PRIVATE_KEY_PATH=%q\n' "${WG_ENCRYPTED_PRIVATE_KEY_PATH}"
    printf 'WG_KEY_PASSPHRASE_PATH=%q\n' "${WG_KEY_PASSPHRASE_PATH}"
    printf 'WG_PUBLIC_KEY_PATH=%q\n' "${WG_PUBLIC_KEY_PATH}"
    printf 'EGRESS_INTERFACE=%q\n' "${EGRESS_INTERFACE}"
    printf 'BACKEND_MODE=%q\n' "${BACKEND_MODE}"
    printf 'DATAPLANE_MODE=%q\n' "${DATAPLANE_MODE}"
    printf 'RECONCILE_INTERVAL_MS=%q\n' "${RECONCILE_INTERVAL_MS}"
    printf 'MAX_RECONCILE_FAILURES=%q\n' "${MAX_RECONCILE_FAILURES}"
    printf 'TRUST_SIGNER_KEY_PATH=%q\n' "${TRUST_SIGNER_KEY_PATH}"
    printf 'AUTO_REFRESH_TRUST=%q\n' "${AUTO_REFRESH_TRUST}"
    printf 'DEVICE_NODE_ID=%q\n' "${DEVICE_NODE_ID}"
    printf 'SETUP_COMPLETE=%q\n' "${SETUP_COMPLETE}"
  } >"${CONFIG_FILE}"
  chmod 600 "${CONFIG_FILE}"
}

detect_default_egress() {
  ip -o -4 route show to default 2>/dev/null | awk 'NR==1 { print $5 }'
}

package_manager() {
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
    wg) echo "wireguard-tools" ;;
    ip)
      if [[ "${pm}" == "dnf" ]]; then
        echo "iproute"
      else
        echo "iproute2"
      fi
      ;;
    nft) echo "nftables" ;;
    openssl) echo "openssl" ;;
    xxd)
      if [[ "${pm}" == "apt" ]]; then
        echo "xxd"
      else
        echo "vim-common"
      fi
      ;;
    cargo)
      if [[ "${pm}" == "apt" ]]; then
        echo "cargo"
      elif [[ "${pm}" == "dnf" ]]; then
        echo "cargo"
      elif [[ "${pm}" == "pacman" ]]; then
        echo "rust"
      else
        echo "cargo"
      fi
      ;;
    rustc)
      if [[ "${pm}" == "pacman" ]]; then
        echo "rust"
      else
        echo "rustc"
      fi
      ;;
    *) echo "" ;;
  esac
}

install_runtime_dependencies() {
  local required=(wg ip nft openssl xxd systemctl awk sed grep)
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
  esac
}

ensure_binaries_available() {
  if command -v rustynetd >/dev/null 2>&1 && command -v rustynet >/dev/null 2>&1; then
    return
  fi

  print_warn "rustynet binaries are not installed in PATH."
  if ! command -v cargo >/dev/null 2>&1; then
    if prompt_yes_no "Install Rust toolchain package dependency (cargo/rustc)?" "y"; then
      install_runtime_dependencies
    fi
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

prepare_system_directories() {
  run_root install -d -m 0700 /etc/rustynet /run/rustynet /var/lib/rustynet
  run_root install -d -m 0700 "$(dirname "${STATE_PATH}")"
  run_root install -d -m 0700 "$(dirname "${TRUST_EVIDENCE_PATH}")"
  run_root install -d -m 0700 "$(dirname "${TRUST_WATERMARK_PATH}")"
  run_root install -d -m 0700 "$(dirname "${WG_PRIVATE_KEY_PATH}")"
  run_root install -d -m 0700 "$(dirname "${WG_ENCRYPTED_PRIVATE_KEY_PATH}")"
  run_root install -d -m 0700 "$(dirname "${WG_KEY_PASSPHRASE_PATH}")"
  run_root install -d -m 0700 "$(dirname "${WG_PUBLIC_KEY_PATH}")"
}

ensure_wireguard_keys() {
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
  print_info "Trust material setup:"
  echo "  1) Lab mode (generate local signer key and auto-refresh trust evidence)"
  echo "  2) Bring externally signed trust evidence + verifier key"
  local choice
  read -r -p "Choose mode [1/2]: " choice
  choice="${choice:-1}"

  if [[ "${choice}" == "1" ]]; then
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
  if [[ "${AUTO_REFRESH_TRUST}" == "1" && -f "${TRUST_SIGNER_KEY_PATH}" ]]; then
    refresh_signed_trust_evidence || print_warn "Failed to refresh trust evidence before start."
  fi
  run_root systemctl daemon-reload
  run_root systemctl enable rustynetd.service
  run_root systemctl restart rustynetd.service
  run_root systemctl --no-pager --full status rustynetd.service || true
}

stop_service() {
  run_root systemctl stop rustynetd.service
}

show_service_status() {
  run_root systemctl --no-pager --full status rustynetd.service || true
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
  grep -v "^${name}|" "${PEERS_FILE}" >"${tmp}" || true
  printf '%s|%s|%s|%s|%s\n' "${name}" "${node_id}" "${public_key}" "${endpoint}" "${cidr}" >>"${tmp}"
  mv "${tmp}" "${PEERS_FILE}"
}

remove_peer_record() {
  local name="$1"
  ensure_peer_store
  local tmp
  tmp="$(mktemp)"
  grep -v "^${name}|" "${PEERS_FILE}" >"${tmp}" || true
  mv "${tmp}" "${PEERS_FILE}"
}

find_peer_record() {
  local name="$1"
  ensure_peer_store
  grep "^${name}|" "${PEERS_FILE}" || true
}

find_peer_record_by_node_id() {
  local node_id="$1"
  ensure_peer_store
  awk -F'|' -v nid="${node_id}" '$0 !~ /^#/ && NF==5 && $2 == nid { print; exit }' "${PEERS_FILE}" || true
}

run_rustynet_cli() {
  if ! command -v rustynet >/dev/null 2>&1; then
    print_err "rustynet CLI not found in PATH."
    return 1
  fi
  RUSTYNET_DAEMON_SOCKET="${SOCKET_PATH}" rustynet "$@"
}

connect_to_device() {
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

  endpoint="${endpoint_ip}:${endpoint_port}"
  run_root wg set "${WG_INTERFACE}" peer "${public_key}" endpoint "${endpoint}" allowed-ips "${cidr}" persistent-keepalive 25
  run_root ip route replace "${cidr}" dev "${WG_INTERFACE}"
  upsert_peer "${name}" "${node_id}" "${public_key}" "${endpoint}" "${cidr}"
  print_info "Peer ${name} configured on ${WG_INTERFACE}."
}

disconnect_device() {
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
  public_key="$(echo "${record}" | awk -F'|' '{print $3}')"
  cidr="$(echo "${record}" | awk -F'|' '{print $5}')"
  run_root wg set "${WG_INTERFACE}" peer "${public_key}" remove || true
  run_root ip route del "${cidr}" dev "${WG_INTERFACE}" || true
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

rotate_local_key() {
  run_rustynet_cli key rotate
}

revoke_local_key() {
  if ! prompt_yes_no "Revoke local key material now? This disables connectivity until reinitialized." "n"; then
    print_info "Revoke cancelled."
    return 0
  fi
  run_rustynet_cli key revoke
}

apply_rotation_bundle() {
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

  run_root wg set "${WG_INTERFACE}" peer "${old_public}" remove || true
  run_root wg set "${WG_INTERFACE}" peer "${new_public_key}" endpoint "${endpoint}" allowed-ips "${cidr}" persistent-keepalive 25
  upsert_peer "${name}" "${node_id}" "${new_public_key}" "${endpoint}" "${cidr}"
  print_info "Updated peer key for ${name} (${node_id}) without changing node identity."
}

configure_values() {
  local detected_egress
  detected_egress="$(detect_default_egress)"
  if [[ -z "${EGRESS_INTERFACE}" ]]; then
    EGRESS_INTERFACE="${detected_egress:-eth0}"
  fi

  prompt_default DEVICE_NODE_ID "Local device node id (used for display)" "${DEVICE_NODE_ID}"
  prompt_default SOCKET_PATH "Daemon socket path" "${SOCKET_PATH}"
  prompt_default STATE_PATH "Daemon state path" "${STATE_PATH}"
  prompt_default TRUST_EVIDENCE_PATH "Trust evidence path" "${TRUST_EVIDENCE_PATH}"
  prompt_default TRUST_VERIFIER_KEY_PATH "Trust verifier key path" "${TRUST_VERIFIER_KEY_PATH}"
  prompt_default TRUST_WATERMARK_PATH "Trust watermark path" "${TRUST_WATERMARK_PATH}"
  prompt_default WG_INTERFACE "WireGuard interface name" "${WG_INTERFACE}"
  prompt_default WG_PRIVATE_KEY_PATH "WireGuard runtime private key path" "${WG_PRIVATE_KEY_PATH}"
  prompt_default WG_ENCRYPTED_PRIVATE_KEY_PATH "WireGuard encrypted private key path" "${WG_ENCRYPTED_PRIVATE_KEY_PATH}"
  prompt_default WG_KEY_PASSPHRASE_PATH "WireGuard key passphrase file path" "${WG_KEY_PASSPHRASE_PATH}"
  prompt_default WG_PUBLIC_KEY_PATH "WireGuard public key path" "${WG_PUBLIC_KEY_PATH}"
  prompt_default EGRESS_INTERFACE "Egress interface" "${EGRESS_INTERFACE}"
  prompt_default BACKEND_MODE "Backend mode (in-memory|linux-wireguard)" "${BACKEND_MODE}"
  prompt_default DATAPLANE_MODE "Dataplane mode (shell|hybrid-native)" "${DATAPLANE_MODE}"
  prompt_default RECONCILE_INTERVAL_MS "Reconcile interval (ms)" "${RECONCILE_INTERVAL_MS}"
  prompt_default MAX_RECONCILE_FAILURES "Max reconcile failures" "${MAX_RECONCILE_FAILURES}"
  prompt_default TRUST_SIGNER_KEY_PATH "Trust signer key path (for auto-refresh)" "${TRUST_SIGNER_KEY_PATH}"
}

first_run_setup() {
  print_info "Starting first-run Rustynet setup wizard."
  configure_values
  install_runtime_dependencies
  ensure_binaries_available
  prepare_system_directories
  ensure_wireguard_keys
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
EOF
}

offer_device_as_exit_node() {
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
  local cidr
  prompt_default cidr "CIDR to advertise (for LAN/exit routing)" "192.168.1.0/24"
  run_rustynet_cli route advertise "${cidr}"
}

main_menu() {
  while true; do
    cat <<'EOF'

Rustynet Control Menu
  1) First-run setup/bootstrap
  2) Reconfigure daemon values
  3) Start/restart Rustynet service
  4) Stop Rustynet service
  5) Show service status
  6) Show Rustynet status
  7) Netcheck
  8) Show connected devices
  9) Connect to device (add/update peer)
 10) Remove device peer
 11) Select exit node
 12) Disable exit node
 13) Offer this device as an exit node
 14) Toggle LAN access
 15) Advertise route
 16) Refresh signed trust evidence now
 17) Rotate local WireGuard key
 18) Revoke local key material
 19) Apply peer key rotation bundle
 20) Show current configuration
  0) Exit
EOF
    local choice
    read -r -p "Choose an option: " choice
    case "${choice}" in
      1) first_run_setup ;;
      2)
        configure_values
        save_config
        write_daemon_environment
        ;;
      3) start_or_restart_service ;;
      4) stop_service ;;
      5) show_service_status ;;
      6) run_rustynet_cli status ;;
      7) run_rustynet_cli netcheck ;;
      8) show_connected_devices ;;
      9) connect_to_device ;;
      10) disconnect_device ;;
      11) select_exit_node ;;
      12) run_rustynet_cli exit-node off ;;
      13) offer_device_as_exit_node ;;
      14) toggle_lan_access ;;
      15) advertise_route ;;
      16) refresh_signed_trust_evidence ;;
      17) rotate_local_key ;;
      18) revoke_local_key ;;
      19) apply_rotation_bundle ;;
      20) show_runtime_config ;;
      0) exit 0 ;;
      *) print_warn "Unknown option: ${choice}" ;;
    esac
  done
}

if [[ "${SETUP_COMPLETE}" != "1" ]]; then
  print_warn "Rustynet is not configured yet."
  if prompt_yes_no "Run first-run setup now?" "y"; then
    first_run_setup
  fi
fi

save_config
main_menu
