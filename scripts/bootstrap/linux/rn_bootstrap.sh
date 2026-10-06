#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: rn_bootstrap.sh <env-file>" >&2
  exit 2
fi

# RSA-0068: this script runs with root privileges (sudo -n throughout), so
# loading the env-file argument with `source` made every shell metacharacter
# in it a root code-execution sink. The file is now parsed as strict
# KEY=VALUE over a fixed allowlist of the keys the script actually reads
# (the set written by the orchestrator's build_bootstrap_env plus the
# host-cross prebuilt flags). One KEY=VALUE per line; comment lines and
# blank lines are allowed; unknown keys, duplicate keys, lines without '=',
# and values containing '$' or a backtick are refused with a non-zero exit
# before the script performs any other action. Values are bound with
# printf -v and never evaluated. The file must be owned by the effective
# user (root, when the script itself runs as root) and must not be
# group- or world-writable.
RN_BOOTSTRAP_ENV_KEYS=(
  ROLE
  NODE_ID
  NETWORK_ID
  SSH_ALLOW_CIDRS
  SOURCE_ARCHIVE
  RUSTYNET_BOOTSTRAP_REGISTRY_ATTEMPTS
  RUSTYNET_LAB_STUN_SERVERS
  RUSTYNET_BACKEND
  RN_PREBUILT_BINARIES
  RN_PREBUILT_DIR
  RN_LAB_SUBSTRATE
)

load_bootstrap_env() {
  local env_file="$1"
  local line key value
  local key_allowed allowed seen_keys required_key

  if [[ ! -r "${env_file}" ]]; then
    echo "[bootstrap] env file not readable: ${env_file}" >&2
    exit 2
  fi
  # Ownership: accept only a file owned by the effective user — root-owned
  # when this script runs as root, the invoking admin's own file when the
  # orchestrator stages it over SSH as a non-root sudoer. Anything owned by
  # a third local user is refused.
  if [[ ! -O "${env_file}" ]]; then
    echo "[bootstrap] refusing env file not owned by root or the invoking user: ${env_file}" >&2
    exit 1
  fi
  # Group- or world-writable is refused: parse the symbolic mode off `ls -l`
  # (10-char type+perm prefix, identical for GNU and BSD ls) so the check
  # does not depend on stat's platform-specific flags.
  local env_mode
  # shellcheck disable=SC2012
  env_mode="$(ls -ld -- "${env_file}")"
  env_mode="${env_mode:0:10}"
  if [[ "${env_mode:5:1}" == "w" || "${env_mode:8:1}" == "w" ]]; then
    echo "[bootstrap] refusing group- or world-writable env file (mode ${env_mode}): ${env_file}" >&2
    exit 1
  fi

  seen_keys="|"
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line%$'\r'}"
    [[ -z "${line//[[:space:]]/}" ]] && continue
    if [[ "${line}" =~ ^[[:space:]]*# ]]; then
      continue
    fi
    if [[ "${line}" != *=* ]]; then
      echo "[bootstrap] refusing env line without '=': ${line}" >&2
      exit 1
    fi
    key="${line%%=*}"
    value="${line#*=}"
    if [[ ! "${key}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      echo "[bootstrap] refusing env line with malformed key: ${line}" >&2
      exit 1
    fi
    allowed=0
    for key_allowed in "${RN_BOOTSTRAP_ENV_KEYS[@]}"; do
      if [[ "${key}" == "${key_allowed}" ]]; then
        allowed=1
        break
      fi
    done
    if [[ "${allowed}" -ne 1 ]]; then
      echo "[bootstrap] refusing unknown env key: ${key}" >&2
      exit 1
    fi
    if [[ "${seen_keys}" == *"|${key}|"* ]]; then
      echo "[bootstrap] refusing duplicate env key: ${key}" >&2
      exit 1
    fi
    seen_keys="${seen_keys}${key}|"
    case "${value}" in
      *'$'*|*'`'*)
        echo "[bootstrap] refusing env value with a command-substitution metacharacter for key: ${key}" >&2
        exit 1
        ;;
    esac
    printf -v "${key}" '%s' "${value}"
  done < "${env_file}"

  for required_key in ROLE NODE_ID NETWORK_ID SSH_ALLOW_CIDRS SOURCE_ARCHIVE; do
    if [[ -z "${!required_key+x}" ]]; then
      echo "[bootstrap] refusing env file missing required key: ${required_key}" >&2
      exit 1
    fi
  done
}

load_bootstrap_env "$1"
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
  # Bounded wait: 60 attempts x 2s (120s) unless the caller overrides it.
  # The apt install path passes 300 (10 min) because it genuinely needs the
  # dpkg lock and unattended-upgrades can hold it for many minutes on a slow
  # uplink (rz1-r2, linux-x86-client-1: held ~2h by pid 3515).
  local max_attempts="${3:-60}"
  local attempt
  for attempt in $(seq 1 "${max_attempts}"); do
    if ! pgrep -f "$pattern" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "${label} remained busy after waiting $((max_attempts * 2))s for the package manager to go idle; current holder(s):" >&2
  pgrep -af "$pattern" >&2 || true
  exit 1
}

# Detects apt/dpkg lock-contention failures in one attempt's captured log
# (rz1-r2, linux-x86-client-1: unattended-upgrades held the dpkg frontend
# lock and three install attempts seconds apart were mislabelled as DNS
# failures). Deliberately narrow — only the two lock shapes apt-get emits —
# so genuine network failures keep the DNS-repair treatment.
apt_attempt_failed_on_package_lock() {
  local apt_log="$1"
  grep -Eq '^E: (Could not get lock|Unable to acquire the dpkg frontend lock)' "${apt_log}" 2>/dev/null
}

# Lock diagnostics: name the holder of the apt/dpkg locks. A lock error is
# not a network error, so on the lock path this REPLACES — never accompanies
# — repair_bootstrap_dns_state and emit_bootstrap_network_diagnostics.
emit_bootstrap_package_lock_diagnostics() {
  local lock_file
  echo "[bootstrap] package-lock diagnostics: an apt/dpkg lock is held by another process" >&2
  pgrep -af 'apt-get|apt|dpkg|unattended-upgr|packagekitd' >&2 \
    || echo "[bootstrap] no apt/dpkg/unattended-upgrade process is running now" >&2
  if command -v fuser >/dev/null 2>&1; then
    for lock_file in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock; do
      [[ -e "${lock_file}" ]] || continue
      echo "--- fuser -v ${lock_file} ---" >&2
      run_root_timed 30 fuser -v "${lock_file}" >&2 || true
    done
  fi
}

# EL detection for the dnf family branch: Fedora shares dnf with the EL
# distros (Rocky/AlmaLinux/CentOS Stream/RHEL/Oracle Linux, matched on ID
# or on an ID_LIKE of rhel/centos) but keeps carrying packages the EL base
# repositories lack — libfaketime above all. ID=fedora always wins over any
# ID_LIKE, so Fedora can never be classed as EL. Takes the parsed
# os-release ID and ID_LIKE as arguments so the vm_lab pin harness can
# extract and run it under bash.
is_el_linux() {
  local os_id="${1:-}"
  local os_like="${2:-}"
  if [[ "${os_id}" == "fedora" ]]; then
    return 1
  fi
  case "${os_id}" in
    rocky|almalinux|centos|rhel|ol|redhat*)
      return 0
      ;;
  esac
  case "${os_like}" in
    *rhel*|*centos*)
      return 0
      ;;
  esac
  return 1
}

build_bootstrap_prereqs_present() {
  local PATH="${HOME}/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"
  local os_id=""
  local os_like=""
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    os_id="${ID:-}"
    os_like="${ID_LIKE:-}"
  fi
  local missing=0
  local cmd
  local llvm_found=0
  local ca_bundle_found=0
  for cmd in curl git make pkg-config clang nft wg rustup tar gzip tcpdump ping ip tc; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
      echo "[bootstrap] missing prerequisite command: ${cmd}" >&2
      missing=1
    fi
  done
  # libfaketime is a shared object, not a command: the command loop above
  # cannot see it, so an already-provisioned guest never gained it (katana,
  # 2026-09-11 — chaos_clock_attack reported faketime_lib_present=false).
  # b30 (live 2026-09-27, rocky-utm-1, Rocky Linux 10 aarch64): the EL base
  # repositories do not carry libfaketime (it is EPEL-only, and EPEL is
  # deliberately NOT enabled here per ADR-027), so on EL it is OPTIONAL —
  # treated as satisfied so the guest does not loop through install_prereqs
  # on every run, but reported loudly: the chaos clock-attack stage is the
  # ONLY consumer and must report faketime_lib_present=false (precondition
  # skip) on such a guest. On Fedora and Debian/Ubuntu it stays REQUIRED.
  faketime_found=0
  for cand in /usr/lib/*/faketime/libfaketime.so.1 /usr/lib64/faketime/libfaketime.so.1 /usr/lib/faketime/libfaketime.so.1; do
    if [ -r "$cand" ]; then faketime_found=1; break; fi
  done
  if [ "$faketime_found" = 1 ] || ldconfig -p 2>/dev/null | grep libfaketime >/dev/null; then
    printf "  %-12s ok\n" libfaketime
  elif is_el_linux "${os_id}" "${os_like}"; then
    printf "  %-12s optional (EL: not installed)\n" libfaketime
    echo "[bootstrap] WARN: libfaketime is unavailable from the base repositories of this EL distro (EPEL-only; deliberately not enabled, ADR-027). Only the chaos clock-attack stage consumes it: that stage will report faketime_lib_present=false and skip as a precondition failure instead of injecting." >&2
  else
    echo "  libfaketime  MISSING"; missing=1
  fi
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
    wait_for_package_manager_idle 'dnf|rpm|packagekitd' 'dnf/rpm'
    # b30: the core transaction deliberately EXCLUDES libfaketime. On EL the
    # base repositories lack it (EPEL-only; not enabled per ADR-027) and dnf
    # refuses the WHOLE transaction when any one name is unresolvable (live
    # 2026-09-27, rocky-utm-1, Rocky Linux 10: "Error: Unable to find a
    # match: libfaketime" — all other packages resolved). iproute-tc is
    # named explicitly: on Fedora/EL the tc binary ships in the separate
    # iproute-tc package, not iproute (live 2026-09-27, fedora-utm-1,
    # Fedora 44: prerequisite verification failed on the missing tc command
    # after every listed package had installed).
    run_root_timed 1800 dnf install -y \
      ca-certificates curl git gcc gcc-c++ make pkgconf-pkg-config openssl-devel \
      sqlite-devel clang llvm llvm-devel nftables wireguard-tools tar gzip tcpdump iputils \
      iproute iproute-tc
    # libfaketime runs as its OWN transaction so it can never fail the core
    # prerequisites: on Fedora this succeeds and the strict post-install
    # verification below keeps it REQUIRED there; on EL it may fail, which
    # is tolerated loudly (the WARN in build_bootstrap_prereqs_present
    # fires and the chaos clock-attack stage skips).
    if ! run_root_timed 600 dnf install -y libfaketime; then
      if is_el_linux "${os_id}" "${os_like}"; then
        echo "[bootstrap] WARN: optional libfaketime install failed on this EL distro (EPEL-only; deliberately not enabled, ADR-027). Only the chaos clock-attack stage consumes it and will skip (faketime_lib_present=false)." >&2
      else
        echo "[bootstrap] libfaketime install failed on ${os_id:-unknown}; prerequisite verification below stays strict for it" >&2
      fi
    fi
  elif [[ "${os_id}" == "debian" || "${os_id}" == "ubuntu" || "${os_id}" == "linuxmint" || "${os_like}" == *"debian"* ]] || command -v apt-get >/dev/null 2>&1; then
    run_apt_update_hardened
    run_apt_install_hardened \
      ca-certificates curl git build-essential pkg-config libssl-dev libsqlite3-dev \
      clang llvm nftables wireguard-tools openssl systemd-resolved libnss-resolve tar gzip \
      tcpdump iputils-ping iproute2 libfaketime
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
  local lock_failure=false
  local -a apt_network_opts
  apt_network_opts=(
    -o Acquire::Retries=3
    -o Acquire::ForceIPv4=true
    -o Acquire::http::Timeout=60
    -o Acquire::https::Timeout=60
    -o Dpkg::Use-Pty=0
  )
  for attempt in $(seq 1 3); do
    wait_for_package_manager_idle 'apt-get|/usr/lib/apt/methods/|dpkg|unattended-upgr' 'apt/dpkg'
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
    if apt_attempt_failed_on_package_lock "${apt_log}"; then
      lock_failure=true
      emit_bootstrap_package_lock_diagnostics
    else
      lock_failure=false
    fi
    rm -f "${apt_log}"
    if [[ "${attempt}" -lt 3 ]]; then
      if [[ "${lock_failure}" == true ]]; then
        echo "[bootstrap] apt-get update attempt ${attempt} failed: the apt/dpkg lock is held by another process; NOT repairing DNS" >&2
      else
        echo "[bootstrap] apt-get update attempt ${attempt} failed; retrying after DNS repair" >&2
        run_root_timed 120 env DEBIAN_FRONTEND=noninteractive apt-get clean >/dev/null 2>&1 || true
        repair_bootstrap_dns_state
      fi
      sleep 2
    fi
  done
  if [[ "${lock_failure}" == true ]]; then
    echo "[bootstrap] apt-get update failed after retries: the apt/dpkg lock stayed held by another process (holders named above); this is not a DNS/network problem" >&2
    return 1
  fi
  echo "[bootstrap] apt-get update failed after retries" >&2
  emit_bootstrap_network_diagnostics "deb.debian.org"
  return 1
}

run_apt_install_hardened() {
  local attempt
  local apt_log
  local lock_failure=false
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
    # The install needs the dpkg lock itself (the update does not), so wait
    # bounded before EVERY attempt, covering the unattended-upgrade python
    # parent that holds the lock between phases. rz1-r2 proved the gap.
    wait_for_package_manager_idle 'apt-get|/usr/lib/apt/methods/|dpkg|unattended-upgr' 'apt/dpkg' 300
    apt_log="$(mktemp /tmp/rn-apt-install.XXXXXX.log)"
    if run_root_timed 5400 env DEBIAN_FRONTEND=noninteractive apt-get \
      "${apt_network_opts[@]}" \
      install -y --no-install-recommends "$@" 2>&1 | tee "${apt_log}"; then
      rm -f "${apt_log}"
      return 0
    fi
    if apt_attempt_failed_on_package_lock "${apt_log}"; then
      lock_failure=true
      emit_bootstrap_package_lock_diagnostics
    else
      lock_failure=false
    fi
    rm -f "${apt_log}"
    if [[ "${attempt}" -lt 3 ]]; then
      if [[ "${lock_failure}" == true ]]; then
        echo "[bootstrap] apt-get install attempt ${attempt} failed: the apt/dpkg lock is held by another process; NOT repairing DNS" >&2
        sleep 2
      else
        echo "[bootstrap] apt-get install attempt ${attempt} failed; retrying after DNS repair" >&2
        run_root_timed 120 env DEBIAN_FRONTEND=noninteractive apt-get clean >/dev/null 2>&1 || true
        repair_bootstrap_dns_state
        sleep 2
      fi
    fi
  done
  if [[ "${lock_failure}" == true ]]; then
    echo "[bootstrap] apt-get install failed after retries: the apt/dpkg lock stayed held by another process (holders named above); this is not a DNS/network problem" >&2
    return 1
  fi
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
# RN_LAB_SUBSTRATE=1 (set by the orchestrator for vxlan-substrate runs) builds
# the daemon with the `lab-substrate` cargo feature; every other run keeps the
# default-off daemon build.
rn_daemon_features=""
if [[ "${RN_LAB_SUBSTRATE:-0}" == "1" ]]; then
  rn_daemon_features="--features lab-substrate"
fi
if [[ "${RN_PREBUILT_BINARIES:-0}" == "1" ]]; then
  # host-cross-binary mode: the orchestrator cross-built the node binaries on the
  # host and scp'd them here, so install those and SKIP the guest build entirely
  # (this is where the reclaimed build time lands). Fail closed: a missing
  # prebuilt binary aborts the bootstrap rather than silently falling through to
  # a guest build, which would defeat the whole point and hide a transfer bug.
  rn_prebuilt_dir="${RN_PREBUILT_DIR:-/tmp/rn_prebuilt}"
  echo "[bootstrap] host-cross: staging prebuilt binaries from ${rn_prebuilt_dir} into target/release, skipping guest build" >&2
  for rn_b in rustynetd rustynet-cli rustynet-relay; do
    if [[ ! -f "${rn_prebuilt_dir}/${rn_b}" ]]; then
      echo "[bootstrap] FATAL: RN_PREBUILT_BINARIES=1 but prebuilt '${rn_b}' is missing in ${rn_prebuilt_dir}" >&2
      exit 1
    fi
  done
  # Stage into target/release so BOTH the install below AND the downstream
  # `ops e2e-bootstrap-host` step find them: ops_e2e installs from
  # <src-dir>/target/release and, because the lab passes --skip-apt, does not
  # rebuild — so placing the prebuilt binaries there is all that is needed to
  # skip every guest build while leaving the rest of bootstrap unchanged.
  mkdir -p target/release
  install -m 0755 "${rn_prebuilt_dir}/rustynetd" target/release/rustynetd
  install -m 0755 "${rn_prebuilt_dir}/rustynet-cli" target/release/rustynet-cli
  install -m 0755 "${rn_prebuilt_dir}/rustynet-relay" target/release/rustynet-relay
  rn_bin_src="target/release"
elif wait_for_cargo_registry_endpoint; then
  rn_bin_src="target/release"
  run_local_timed 7200 rustup run "${RUST_TOOLCHAIN_CHANNEL}" cargo build --release -p rustynetd $rn_daemon_features
  run_local_timed 7200 rustup run "${RUST_TOOLCHAIN_CHANNEL}" cargo build --release -p rustynet-cli --features vm-lab --bin rustynet-cli
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
  rn_bin_src="target/release"
  run_local_timed 7200 rustup run "${RUST_TOOLCHAIN_CHANNEL}" cargo build --release --offline -p rustynetd $rn_daemon_features
  run_local_timed 7200 rustup run "${RUST_TOOLCHAIN_CHANNEL}" cargo build --release --offline -p rustynet-cli --features vm-lab --bin rustynet-cli
  run_local_timed 7200 rustup run "${RUST_TOOLCHAIN_CHANNEL}" cargo build --release --offline -p rustynet-relay --features daemon
fi
run_root install -m 0755 "${rn_bin_src}/rustynetd" /usr/local/bin/rustynetd
run_root install -m 0755 "${rn_bin_src}/rustynet-cli" /usr/local/bin/rustynet
run_root install -m 0755 "${rn_bin_src}/rustynet-relay" /usr/local/bin/rustynet-relay
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
# Lab STUN endpoint: an empty RUSTYNET_TRAVERSAL_STUN_SERVERS disables srflx
# candidate gathering entirely, so the lab threads a non-empty default — the
# guest's default gateway on 3478 (the UTM host as seen from this subnet). A
# live responder there is optional: gathering fails soft on a bounded timeout
# and same-LAN validation rides host candidates either way. The value must be
# ip:port CSV (the daemon parses socket addresses, not hostnames), which the
# gateway address satisfies; RUSTYNET_LAB_STUN_SERVERS in the bootstrap env
# overrides. Production deployments never run this script.
lab_stun_servers="${RUSTYNET_LAB_STUN_SERVERS:-}"
if [[ -z "${lab_stun_servers}" ]]; then
  default_gw="$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')"
  if [[ -n "${default_gw}" ]]; then
    lab_stun_servers="${default_gw}:3478"
  fi
fi
stun_env=()
if [[ -n "${lab_stun_servers}" ]]; then
  stun_env+=(RUSTYNET_TRAVERSAL_STUN_SERVERS="${lab_stun_servers}")
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
  "${stun_env[@]}" \
  /usr/local/bin/rustynet ops e2e-bootstrap-host \
  --role "${ROLE}" \
  --node-id "${NODE_ID}" \
  --network-id "${NETWORK_ID}" \
  --src-dir "${HOME}/Rustynet" \
  --ssh-allow-cidrs "${SSH_ALLOW_CIDRS}" \
  --skip-apt
