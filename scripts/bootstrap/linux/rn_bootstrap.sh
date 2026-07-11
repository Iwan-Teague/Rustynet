#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: rn_bootstrap.sh <env-file>" >&2
  exit 2
fi

source "$1"
export PATH="${HOME}/.cargo/bin:${PATH}"

run_root() {
  sudo -n "$@"
}

run_root_timed() {
  local timeout_secs="$1"
  shift
  sudo -n timeout --kill-after=5 "$timeout_secs" "$@"
}

run_local_timed() {
  local timeout_secs="$1"
  shift
  timeout "$timeout_secs" "$@"
}

clear_residual_rustynet_state() {
  run_root_timed 30 ip link set rustynet0 down >/dev/null 2>&1 || true
  run_root_timed 30 ip link delete rustynet0 >/dev/null 2>&1 || true
  run_root_timed 30 ip route flush table 51820 >/dev/null 2>&1 || true
  run_root_timed 30 ip -6 route flush table 51820 >/dev/null 2>&1 || true
  if command -v nft >/dev/null 2>&1; then
    for _attempt in $(seq 1 3); do
      while read -r family table_name; do
        [[ -n "${family}" && -n "${table_name}" ]] || continue
        run_root_timed 30 nft flush table "${family}" "${table_name}" >/dev/null 2>&1 || true
        run_root_timed 30 nft delete table "${family}" "${table_name}" >/dev/null 2>&1 || true
      done < <(run_root_timed 30 nft list tables 2>/dev/null | awk '/^table / && $3 ~ /^rustynet/ { print $2 " " $3 }' | tr -d '\r')
      if ! run_root_timed 30 nft list tables 2>/dev/null | grep -qE '^table [^[:space:]]+ rustynet'; then
        break
      fi
      sleep 1
    done
    if run_root_timed 30 nft list tables 2>/dev/null | grep -qE '^table [^[:space:]]+ rustynet'; then
      echo "residual rustynet nftables state remained before bootstrap" >&2
      exit 1
    fi
  fi
}

wait_for_package_manager_idle() {
  local pattern="$1"
  local label="$2"
  local attempt
  for attempt in $(seq 1 60); do
    if ! pgrep -f "$pattern" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "${label} remained busy after waiting for prior lab processes to exit" >&2
  pgrep -af "$pattern" >&2 || true
  exit 1
}

build_bootstrap_prereqs_present() {
  local PATH="${HOME}/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"
  local missing=0
  local cmd
  local llvm_found=0
  local ca_bundle_found=0
  for cmd in curl git make pkg-config clang nft wg rustup tar gzip tcpdump ping; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
      echo "[bootstrap] missing prerequisite command: ${cmd}" >&2
      missing=1
    fi
  done
  if ! command -v gcc >/dev/null 2>&1 && ! command -v cc >/dev/null 2>&1; then
    echo "[bootstrap] missing C compiler command (gcc/cc)" >&2
    missing=1
  fi
  if ! command -v g++ >/dev/null 2>&1 && ! command -v c++ >/dev/null 2>&1; then
    echo "[bootstrap] missing C++ compiler command (g++/c++)" >&2
    missing=1
  fi
  if command -v llvm-config >/dev/null 2>&1; then
    llvm_found=1
  else
    for cmd in /usr/bin/llvm-config-* /usr/local/bin/llvm-config-*; do
      [[ -x "${cmd}" ]] || continue
      llvm_found=1
      break
    done
  fi
  if [[ "${llvm_found}" -eq 0 ]]; then
    echo "[bootstrap] missing llvm-config command" >&2
    missing=1
  fi
  if command -v pkg-config >/dev/null 2>&1; then
    if ! pkg-config --exists openssl >/dev/null 2>&1; then
      echo "[bootstrap] missing pkg-config openssl development metadata" >&2
      missing=1
    fi
    if ! pkg-config --exists sqlite3 >/dev/null 2>&1; then
      echo "[bootstrap] missing pkg-config sqlite3 development metadata" >&2
      missing=1
    fi
  fi
  for cmd in \
    /etc/ssl/certs/ca-certificates.crt \
    /etc/pki/tls/certs/ca-bundle.crt \
    /etc/ssl/ca-bundle.pem; do
    if [[ -r "${cmd}" ]]; then
      ca_bundle_found=1
      break
    fi
  done
  if [[ "${ca_bundle_found}" -eq 0 ]]; then
    echo "[bootstrap] missing readable CA certificate bundle (checked Debian, Fedora/RHEL, and SUSE paths)" >&2
    missing=1
  fi
  [[ "${missing}" -eq 0 ]]
}

install_rustup_hardened() {
  export PATH="${HOME}/.cargo/bin:${PATH}"
  command -v rustup >/dev/null 2>&1 && return 0

  local target
  case "$(uname -m)" in
    aarch64|arm64) target="aarch64-unknown-linux-gnu" ;;
    x86_64|amd64) target="x86_64-unknown-linux-gnu" ;;
    *)
      echo "unsupported architecture for rustup bootstrap: $(uname -m)" >&2
      return 1
      ;;
  esac

  local tmp_dir
  local base_url="https://static.rust-lang.org/rustup/dist/${target}"
  local attempt
  tmp_dir="$(mktemp -d /tmp/rn-rustup-init.XXXXXX)"
  for attempt in $(seq 1 3); do
    if run_local_timed 300 curl --proto '=https' --tlsv1.2 --fail --location \
      --silent --show-error "${base_url}/rustup-init" -o "${tmp_dir}/rustup-init" \
      && run_local_timed 300 curl --proto '=https' --tlsv1.2 --fail --location \
        --silent --show-error "${base_url}/rustup-init.sha256" -o "${tmp_dir}/rustup-init.sha256" \
      && (cd "${tmp_dir}" && sha256sum -c rustup-init.sha256); then
      chmod 0700 "${tmp_dir}/rustup-init"
      "${tmp_dir}/rustup-init" -y --profile minimal --no-modify-path --default-toolchain none
      rm -rf "${tmp_dir}"
      export PATH="${HOME}/.cargo/bin:${PATH}"
      command -v rustup >/dev/null 2>&1
      return
    fi
    if [[ "${attempt}" -lt 3 ]]; then
      echo "[bootstrap] rustup-init download attempt ${attempt} failed; repairing DNS" >&2
      repair_bootstrap_dns_state
      sleep 2
    fi
  done
  rm -rf "${tmp_dir}"
  echo "[bootstrap] checksum-verified rustup-init download failed" >&2
  return 1
}

install_prereqs() {
  local os_id=""
  local os_like=""
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    os_id="${ID:-}"
    os_like="${ID_LIKE:-}"
  fi
  if build_bootstrap_prereqs_present; then
    echo "[bootstrap] prerequisite toolchain already present; skipping package manager mutation" >&2
    return 0
  fi
  if [[ "${os_id}" == "fedora" || "${os_like}" == *"fedora"* || "${os_like}" == *"rhel"* ]]; then
    wait_for_package_manager_idle 'dnf|rpm' 'dnf/rpm'
    run_root_timed 1800 dnf install -y \
      ca-certificates curl git gcc gcc-c++ make pkgconf-pkg-config openssl-devel \
      sqlite-devel clang llvm llvm-devel nftables wireguard-tools tar gzip tcpdump iputils
  elif [[ "${os_id}" == "debian" || "${os_id}" == "ubuntu" || "${os_id}" == "linuxmint" || "${os_like}" == *"debian"* ]] || command -v apt-get >/dev/null 2>&1; then
    run_apt_update_hardened
    run_apt_install_hardened \
      ca-certificates curl git build-essential pkg-config libssl-dev libsqlite3-dev \
      clang llvm nftables wireguard-tools openssl systemd-resolved libnss-resolve tar gzip \
      tcpdump iputils-ping
  else
    echo "unsupported package manager; expected apt-get or dnf" >&2
    exit 1
  fi
  install_rustup_hardened
  if ! build_bootstrap_prereqs_present; then
    echo "[bootstrap] prerequisite verification failed after package installation" >&2
    exit 1
  fi
}

ensure_llvm_config_alias() {
  if command -v llvm-config >/dev/null 2>&1; then
    return 0
  fi
  local candidate=""
  for candidate in /usr/bin/llvm-config-* /usr/local/bin/llvm-config-*; do
    [[ -x "${candidate}" ]] || continue
    run_root ln -sf "${candidate}" /usr/local/bin/llvm-config
    return 0
  done
  echo "[bootstrap] unable to locate versioned llvm-config binary" >&2
  return 1
}

run_apt_update_hardened() {
  local attempt
  local apt_log
  local -a apt_network_opts
  apt_network_opts=(
    -o Acquire::Retries=3
    -o Acquire::ForceIPv4=true
    -o Acquire::http::Timeout=60
    -o Acquire::https::Timeout=60
    -o Dpkg::Use-Pty=0
  )
  for attempt in $(seq 1 3); do
    wait_for_package_manager_idle 'apt-get|/usr/lib/apt/methods/|dpkg' 'apt/dpkg'
    apt_log="$(mktemp /tmp/rn-apt-update.XXXXXX.log)"
    if run_root_timed 240 env DEBIAN_FRONTEND=noninteractive apt-get \
      "${apt_network_opts[@]}" \
      update 2>&1 | tee "${apt_log}"; then
      if ! grep -Eiq '(^W: Failed to fetch|Temporary failure resolving|Some index files failed to download)' "${apt_log}"; then
        rm -f "${apt_log}"
        return 0
      fi
      echo "[bootstrap] apt-get update reported fetch warnings; treating as failure" >&2
    fi
    rm -f "${apt_log}"
    if [[ "${attempt}" -lt 3 ]]; then
      echo "[bootstrap] apt-get update attempt ${attempt} failed; retrying after DNS repair" >&2
      run_root_timed 120 env DEBIAN_FRONTEND=noninteractive apt-get clean >/dev/null 2>&1 || true
      repair_bootstrap_dns_state
      sleep 2
    fi
  done
  echo "[bootstrap] apt-get update failed after retries" >&2
  emit_bootstrap_network_diagnostics "deb.debian.org"
  return 1
}

run_apt_install_hardened() {
  local attempt
  local -a apt_network_opts
  apt_network_opts=(
    -o Acquire::Retries=3
    -o Acquire::ForceIPv4=true
    -o Acquire::http::Timeout=60
    -o Acquire::https::Timeout=60
    -o Dpkg::Use-Pty=0
  )
  if [[ "$#" -eq 0 ]]; then
    echo "run_apt_install_hardened requires package names" >&2
    return 2
  fi
  for attempt in $(seq 1 3); do
    if run_root_timed 5400 env DEBIAN_FRONTEND=noninteractive apt-get \
      "${apt_network_opts[@]}" \
      install -y --no-install-recommends "$@"; then
      return 0
    fi
    if [[ "${attempt}" -lt 3 ]]; then
      echo "[bootstrap] apt-get install attempt ${attempt} failed; retrying after DNS repair" >&2
      run_root_timed 120 env DEBIAN_FRONTEND=noninteractive apt-get clean >/dev/null 2>&1 || true
      repair_bootstrap_dns_state
      sleep 2
    fi
  done
  echo "[bootstrap] apt-get install failed after retries" >&2
  emit_bootstrap_network_diagnostics "deb.debian.org"
  return 1
}

repair_managed_dns_prereqs() {
  local os_id=""
  local os_like=""
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    os_id="${ID:-}"
    os_like="${ID_LIKE:-}"
  fi
  if [[ "${os_id}" != "debian" && "${os_id}" != "ubuntu" && "${os_id}" != "linuxmint" && "${os_like}" != *"debian"* ]]; then
    return 0
  fi
  if ! command -v resolvectl >/dev/null 2>&1; then
    echo "managed DNS routing requires resolvectl on Debian-like hosts" >&2
    exit 1
  fi
  run_root systemctl enable --now systemd-resolved.service
  if ! run_root resolvectl status >/dev/null 2>&1; then
    run_root systemctl reload dbus
    run_root systemctl restart systemd-resolved.service
    run_root resolvectl status >/dev/null 2>&1 || {
      echo "managed DNS control plane remained unhealthy after dbus reload and systemd-resolved restart" >&2
      exit 1
    }
  fi
}

repair_local_hostname_resolution() {
  local current_hostname=""
  current_hostname="$(hostname)"
  [[ -n "${current_hostname}" ]] || return 0
  if grep -Eq "(^|[[:space:]])${current_hostname}([[:space:]]|$)" /etc/hosts; then
    return 0
  fi
  run_root sh -c 'printf "\n127.0.1.1\t%s\n" "$1" >> /etc/hosts' sh "${current_hostname}"
}

repair_rustup_toolchain_state() {
  local channel="$1"
  rustup toolchain uninstall "$channel" >/dev/null 2>&1 || true
  rm -rf "$HOME/.rustup/tmp"
  mkdir -p "$HOME/.rustup/downloads" "$HOME/.rustup/toolchains"
  find "$HOME/.rustup/downloads" -maxdepth 1 -type f -delete 2>/dev/null || true
  rm -rf "$HOME/.rustup/toolchains/${channel}" "$HOME/.rustup/toolchains/${channel}.tmp"*
}

repair_bootstrap_dns_state() {
  local default_iface=""
  local default_gateway=""
  default_iface="$(ip -4 route show default 2>/dev/null | awk '/default/ { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
  default_gateway="$(ip -4 route show default 2>/dev/null | awk '/default/ { print $3; exit }')"

  if command -v systemctl >/dev/null 2>&1; then
    run_root_timed 30 systemctl reload dbus >/dev/null 2>&1 || true
    run_root_timed 30 systemctl enable --now systemd-resolved.service >/dev/null 2>&1 || true
    run_root_timed 30 systemctl restart systemd-resolved.service >/dev/null 2>&1 || true
  fi
  if [[ -e /run/systemd/resolve/stub-resolv.conf ]]; then
    run_root_timed 30 ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf >/dev/null 2>&1 || true
  fi
  if command -v resolvectl >/dev/null 2>&1; then
    if [[ -n "${default_iface}" ]]; then
      run_root_timed 30 resolvectl revert "${default_iface}" >/dev/null 2>&1 || true
      if [[ -n "${default_gateway}" ]]; then
        run_root_timed 30 resolvectl dns "${default_iface}" "${default_gateway}" >/dev/null 2>&1 || true
      fi
      run_root_timed 30 resolvectl domain "${default_iface}" "~." >/dev/null 2>&1 || true
      run_root_timed 30 resolvectl default-route "${default_iface}" yes >/dev/null 2>&1 || true
    fi
    run_root_timed 30 resolvectl flush-caches >/dev/null 2>&1 || true
  elif [[ -n "${default_gateway}" ]]; then
    run_root sh -c 'printf "nameserver %s\noptions timeout:2 attempts:2\n" "$1" > /etc/resolv.conf' sh "${default_gateway}"
  fi

  # Validate that DNS is actually responding after the repair. The stub at
  # 127.0.0.53 can enter a broken state (socket bound but no responses) that
  # persists across systemd-resolved restarts. Give it a brief moment to
  # initialize, then verify. If broken, fall back to a working nameserver so
  # cargo build can reach the registry.
  sleep 2
  if ! timeout 6 getent ahosts index.crates.io >/dev/null 2>&1; then
    echo "[bootstrap] DNS unresponsive after repair; switching to direct nameservers" >&2
    # First try the upstream resolv.conf from systemd-resolved (bypasses the stub).
    # Break the symlink before writing so systemd-resolved can't regenerate it.
    if [[ -e /run/systemd/resolve/resolv.conf ]] && \
       grep -q '^nameserver' /run/systemd/resolve/resolv.conf 2>/dev/null; then
      run_root bash -c 'rm -f /etc/resolv.conf; cp /run/systemd/resolve/resolv.conf /etc/resolv.conf' 2>/dev/null || true
    fi
    # If still broken, hardcode public resolvers as last resort.
    # Break the symlink first so systemd-resolved cannot regenerate
    # stub-resolv.conf and revert our change.
    if ! timeout 6 getent ahosts index.crates.io >/dev/null 2>&1; then
      run_root bash -c 'rm -f /etc/resolv.conf; printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions timeout:2 attempts:2\n" > /etc/resolv.conf'
    fi
  fi
}

# Linux protected-mode DNS enforcement writes /etc/resolv.conf in place with
# O_NOFOLLOW. Keep that security boundary intact: replace distro-managed
# symlinks ourselves, then verify the leaf is a regular file before rustynetd
# starts. NetworkManager/systemd-resolved may recreate the symlink during a long
# cargo build, so callers must pin once for build egress and again immediately
# before service installation/startup.
pin_regular_resolv_conf() {
  local primary_nameserver="$1"
  local secondary_nameserver="${2:-}"
  local secondary_line=""

  if [[ -n "${secondary_nameserver}" ]]; then
    secondary_line="nameserver ${secondary_nameserver}\\n"
  fi
  run_root bash -c \
    'rm -f /etc/resolv.conf; printf "nameserver %s\\n%boptions timeout:2 attempts:2\\n" "$1" "$2" > /etc/resolv.conf; chmod 0644 /etc/resolv.conf' \
    bash "${primary_nameserver}" "${secondary_line}"
  if [[ -L /etc/resolv.conf || ! -f /etc/resolv.conf ]]; then
    echo "failed to pin /etc/resolv.conf as a regular file" >&2
    exit 1
  fi
}

# Fedora/RHEL-family guests commonly run firewalld with only SSH admitted.
# Preserve that firewall and open only Rustynet's reviewed WireGuard UDP port;
# without this, peers can reach the node only after it initiates outbound first,
# violating the live-lab any-node-to-any-node contract. This bootstrap is lab
# scoped; production packaging owns its separate host-firewall policy.
configure_lab_wireguard_firewall() {
  if ! command -v systemctl >/dev/null 2>&1 \
    || ! systemctl is-active --quiet firewalld.service 2>/dev/null; then
    return 0
  fi
  if ! command -v firewall-cmd >/dev/null 2>&1; then
    echo "firewalld is active but firewall-cmd is unavailable" >&2
    exit 1
  fi
  run_root firewall-cmd --permanent --add-port=51820/udp >/dev/null
  run_root firewall-cmd --add-port=51820/udp >/dev/null
}

emit_bootstrap_network_diagnostics() {
  local host="$1"
  echo "[bootstrap] network diagnostics for host=${host}" >&2
  echo "--- /etc/resolv.conf ---" >&2
  cat /etc/resolv.conf >&2 || true
  echo "--- ip -4 route ---" >&2
  ip -4 route >&2 || true
  echo "--- ip -4 addr ---" >&2
  ip -4 addr >&2 || true
  if command -v resolvectl >/dev/null 2>&1; then
    echo "--- resolvectl status ---" >&2
    run_root_timed 30 resolvectl status >&2 || true
    echo "--- resolvectl query ${host} ---" >&2
    run_root_timed 30 resolvectl query "${host}" >&2 || true
  fi
  echo "--- getent ahosts ${host} ---" >&2
  timeout 10 getent ahosts "${host}" >&2 || true
}

wait_for_cargo_registry_endpoint() {
  local endpoint="https://index.crates.io/"
  local attempt
  local max_attempts="${RUSTYNET_BOOTSTRAP_REGISTRY_ATTEMPTS:-8}"
  for attempt in $(seq 1 "${max_attempts}"); do
    if run_local_timed 15 curl --ipv4 --fail --silent --head "${endpoint}" >/dev/null 2>&1; then
      return 0
    fi
    echo "[bootstrap] cargo registry unreachable (attempt ${attempt}/${max_attempts}); repairing DNS" >&2
    repair_bootstrap_dns_state
    sleep 2
  done
  echo "[bootstrap] failed to reach cargo registry: ${endpoint}" >&2
  emit_bootstrap_network_diagnostics "index.crates.io"
  return 1
}

wait_for_bootstrap_rustup_endpoint() {
  local channel="$1"
  local endpoint="https://static.rust-lang.org/dist/channel-rust-${channel}.toml.sha256"
  local attempt
  for attempt in $(seq 1 8); do
    if run_local_timed 60 curl --ipv4 --fail --silent --show-error --head "${endpoint}" >/dev/null 2>&1; then
      return 0
    fi
    repair_bootstrap_dns_state
    sleep 2
  done
  echo "[bootstrap] failed to reach Rust toolchain endpoint: ${endpoint}" >&2
  emit_bootstrap_network_diagnostics "static.rust-lang.org"
  return 1
}

install_rust_toolchain_hardened() {
  local channel="$1"
  local attempt
  wait_for_bootstrap_rustup_endpoint "${channel}" || return 1
  for attempt in $(seq 1 3); do
    if run_local_timed 3600 env \
      RUSTUP_DOWNLOAD_TIMEOUT=600 \
      RUSTUP_CONCURRENT_DOWNLOADS=1 \
      rustup toolchain install "${channel}" --profile minimal; then
      return 0
    fi
    if [[ "${attempt}" -lt 3 ]]; then
      echo "[bootstrap] rustup install attempt ${attempt} failed; retrying after DNS repair" >&2
      repair_bootstrap_dns_state
      wait_for_bootstrap_rustup_endpoint "${channel}" || true
      sleep 2
    fi
  done
  echo "[bootstrap] rustup toolchain install failed after retries for channel ${channel}" >&2
  emit_bootstrap_network_diagnostics "static.rust-lang.org"
  return 1
}

clear_residual_rustynet_state
repair_local_hostname_resolution
install_prereqs
ensure_llvm_config_alias
repair_managed_dns_prereqs
if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup is required on test hosts; missing after prerequisite install" >&2
  exit 1
fi

rm -rf "${HOME}/Rustynet"
mkdir -p "${HOME}/Rustynet"
tar -xzf "${SOURCE_ARCHIVE}" -C "${HOME}/Rustynet"
cd "${HOME}/Rustynet"

RUST_TOOLCHAIN_CHANNEL="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' rust-toolchain.toml 2>/dev/null | head -n 1)"
if [[ -z "${RUST_TOOLCHAIN_CHANNEL}" ]]; then
  echo "failed to determine required Rust toolchain from rust-toolchain.toml" >&2
  exit 1
fi

export PATH="${HOME}/.cargo/bin:${PATH}"
rustup set profile minimal
if ! rustup run "${RUST_TOOLCHAIN_CHANNEL}" rustc --version >/dev/null 2>&1 || ! rustup run "${RUST_TOOLCHAIN_CHANNEL}" cargo --version >/dev/null 2>&1; then
  repair_rustup_toolchain_state "${RUST_TOOLCHAIN_CHANNEL}"
  install_rust_toolchain_hardened "${RUST_TOOLCHAIN_CHANNEL}"
fi
rustup default "${RUST_TOOLCHAIN_CHANNEL}"

# Break the /etc/resolv.conf symlink unconditionally before cargo so that
# systemd-resolved regenerating stub-resolv.conf mid-build cannot race us
# and revert nameservers to the broken 127.0.0.53 stub.
echo "[bootstrap] pinning nameservers for cargo build" >&2
pin_regular_resolv_conf 1.1.1.1 8.8.8.8
# Build rustynetd + rustynet-cli. Prefer an online build against a fresh
# registry, but fall back to an offline build from the cargo cache when the
# registry is unreachable. A node with a warm ${HOME}/.cargo cache — e.g. a lab
# guest whose mesh underlay works bridge-local but whose internet egress does
# not, or a deliberately air-gapped host — can still bootstrap. The offline
# fallback is accepted ONLY if it actually succeeds: cargo --offline errors
# during dependency resolution on a cache miss, so the bootstrap still fails
# loudly for a genuine network problem and never silently builds stale/partial
# state. Mirrors the macOS bootstrap's existing `cargo build --offline` path.
if wait_for_cargo_registry_endpoint; then
  run_local_timed 7200 rustup run "${RUST_TOOLCHAIN_CHANNEL}" cargo build --release -p rustynetd
  run_local_timed 7200 rustup run "${RUST_TOOLCHAIN_CHANNEL}" cargo build --release -p rustynet-cli --bin rustynet-cli
  # rustynet-relay is a separate binary whose bin target requires the `daemon`
  # feature, so it builds as its own invocation. Built on every node (cheap —
  # its deps are already compiled for rustynetd) so a node assigned, or later
  # role-switched, to the relay/anchor preset always has the binary; the relay
  # *service* is only enabled on Relay nodes by the orchestrator's
  # DeployRelayService stage. Built here while the registry is reachable —
  # later stages run behind the killswitch where a cargo build cannot.
  run_local_timed 7200 rustup run "${RUST_TOOLCHAIN_CHANNEL}" cargo build --release -p rustynet-relay --features daemon
else
  echo "[bootstrap] cargo registry unreachable; falling back to offline build from cargo cache" >&2
  run_local_timed 7200 rustup run "${RUST_TOOLCHAIN_CHANNEL}" cargo build --release --offline -p rustynetd
  run_local_timed 7200 rustup run "${RUST_TOOLCHAIN_CHANNEL}" cargo build --release --offline -p rustynet-cli --bin rustynet-cli
  run_local_timed 7200 rustup run "${RUST_TOOLCHAIN_CHANNEL}" cargo build --release --offline -p rustynet-relay --features daemon
fi
run_root install -m 0755 target/release/rustynetd /usr/local/bin/rustynetd
run_root install -m 0755 target/release/rustynet-cli /usr/local/bin/rustynet
run_root install -m 0755 target/release/rustynet-relay /usr/local/bin/rustynet-relay
# Re-pin after the potentially long build. Distro DNS managers can recreate a
# stub-resolver symlink while cargo runs; rustynetd must start from a regular
# fail-closed file because its privileged helper deliberately refuses symlinks.
echo "[bootstrap] pinning regular fail-closed resolver before daemon start" >&2
pin_regular_resolv_conf 127.0.0.1
configure_lab_wireguard_firewall
backend_env=()
if [[ -n "${RUSTYNET_BACKEND:-}" ]]; then
  backend_env+=(RUSTYNET_BACKEND="${RUSTYNET_BACKEND}")
fi
# Lab bootstrap uses the relaxed 86400s freshness window (parity with macOS
# Bootstrap-RustyNetMacos.sh and the Windows installer) so a Linux node is not
# left enforcing the strict 300s/120s window if the later enforce pass is
# interrupted. e2e-bootstrap-host forwards these into `ops install-systemd`,
# which bakes them into the unit file. Production deployments leave these unset.
run_root env RUSTYNET_INSTALL_SOURCE_ROOT="${HOME}/Rustynet" \
  PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin \
  RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS=86400 \
  RUSTYNET_TRAVERSAL_MAX_AGE_SECS=86400 \
  RUSTYNET_DNS_ZONE_MAX_AGE_SECS=86400 \
  "${backend_env[@]}" \
  /usr/local/bin/rustynet ops e2e-bootstrap-host \
  --role "${ROLE}" \
  --node-id "${NODE_ID}" \
  --network-id "${NETWORK_ID}" \
  --src-dir "${HOME}/Rustynet" \
  --ssh-allow-cidrs "${SSH_ALLOW_CIDRS}" \
  --skip-apt
