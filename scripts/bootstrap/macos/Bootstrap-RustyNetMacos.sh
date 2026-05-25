#!/usr/bin/env bash
# Bootstrap-RustyNetMacos.sh — macOS full-install wizard for Rustynet.
#
# Takes a bare macOS installation to a running rustynetd daemon in one pass:
#   1. Xcode Command Line Tools
#   2. Homebrew
#   3. wireguard-go, wireguard-tools, rustup-init  (via brew)
#   4. Rust stable toolchain
#   5. Build rustynet from source tarball
#   6. Install binaries + launchd service
#
# Usage (must run as root):
#   sudo bash Bootstrap-RustyNetMacos.sh <env-file>
#
# Env-file variables (written by the Rust orchestrator or filled in manually):
#   ROLE              — client | exit | entry | aux | extra
#   NODE_ID           — unique node identifier
#   NETWORK_ID        — mesh network identifier
#   SSH_ALLOW_CIDRS   — comma-separated CIDRs allowed through SSH fail-open rule
#   SOURCE_ARCHIVE    — path to the source tarball on this host
#   WG_INTERFACE      — utun<N> (default utun9; orchestrator passes the
#                       node-derived value via macos_install.rs's
#                       utun_name_for_node_id helper so the first plist
#                       install already targets the correct device)
#
# Design:
#   - Idempotent: safe to re-run; each phase skips if already satisfied.
#   - Fail-closed: set -euo pipefail; every step is verified before proceeding.
#   - No interactive prompts: NONINTERACTIVE=1 for brew; -y for rustup-init.
#   - Mirrors the structure of scripts/bootstrap/linux/rn_bootstrap.sh so the
#     Rust adapter (macos_install.rs) can use the same SCP+run pattern.

set -euo pipefail

# Prevent Homebrew from trying to auto-update or phone home.
# Required when the VM has no internet access (lab/UTM environments).
export HOMEBREW_NO_AUTO_UPDATE=1
export HOMEBREW_NO_ANALYTICS=1
export HOMEBREW_NO_INSTALL_FROM_API=1
export NONINTERACTIVE=1

# ── Arg check ─────────────────────────────────────────────────────────────────
if [[ $# -ne 1 ]]; then
  echo "usage: sudo bash Bootstrap-RustyNetMacos.sh <env-file>" >&2
  exit 2
fi
source "$1"

# ── Constants ─────────────────────────────────────────────────────────────────
readonly RUSTYNETD_BIN="/usr/local/bin/rustynetd"
readonly RUSTYNET_BIN="/usr/local/bin/rustynet"
readonly STATE_ROOT="/usr/local/var/rustynet"
readonly CONFIG_ROOT="/usr/local/etc/rustynet"
readonly KEYS_DIR="${STATE_ROOT}/keys"
readonly LOG_DIR="/usr/local/var/log/rustynet"
readonly LAUNCHDAEMON_DIR="/Library/LaunchDaemons"
readonly PLIST_PATH="${LAUNCHDAEMON_DIR}/com.rustynet.daemon.plist"
readonly PLIST_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly BUILD_DIR="/tmp/rustynet-build-$$"

# On Apple Silicon brew lives at /opt/homebrew; on Intel at /usr/local.
BREW_PREFIX=""

# ── Privilege separation ───────────────────────────────────────────────────────
# Homebrew and the Rust toolchain refuse to run as root. When invoked via
# `sudo bash`, $SUDO_USER holds the original unprivileged user.
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || whoami)}"
REAL_HOME="$(eval echo "~${REAL_USER}")"

# Run a command as the real (non-root) user with the current PATH exported.
as_user() {
  sudo -u "${REAL_USER}" env \
    HOME="${REAL_HOME}" \
    PATH="${PATH}" \
    HOMEBREW_NO_AUTO_UPDATE=1 \
    HOMEBREW_NO_ANALYTICS=1 \
    HOMEBREW_NO_INSTALL_FROM_API=0 \
    NONINTERACTIVE=1 \
    "$@"
}

# ── PATH bootstrap ────────────────────────────────────────────────────────────
# Sudo strips PATH to a minimal set. Re-add Homebrew and Cargo directories
# so subsequent commands can find brew, wg, wireguard-go, rustup, cargo.
setup_bootstrap_path() {
  for prefix in /opt/homebrew /usr/local; do
    if [[ -x "${prefix}/bin/brew" ]]; then
      BREW_PREFIX="${prefix}"
      eval "$(as_user "${prefix}/bin/brew" shellenv)"
      break
    fi
  done
  # Source cargo env from the real user's home, not root's.
  for cargo_env in "${REAL_HOME}/.cargo/env" "${HOME}/.cargo/env" /var/root/.cargo/env; do
    # shellcheck disable=SC1090
    [[ -f "${cargo_env}" ]] && source "${cargo_env}" && break
  done
  export PATH="${REAL_HOME}/.cargo/bin:/usr/local/bin:/opt/homebrew/opt/rustup/bin:/opt/homebrew/bin:/opt/homebrew/sbin:${PATH}"
}

# ── 1. Xcode Command Line Tools ───────────────────────────────────────────────
# git, clang, make, and cc all require the CLT on a bare macOS install.
ensure_xcode_clt() {
  if xcode-select -p &>/dev/null 2>&1; then
    echo "[prereqs] Xcode Command Line Tools already present at $(xcode-select -p)"
    return 0
  fi

  echo "[prereqs] Xcode Command Line Tools not found; installing via softwareupdate..."

  # The touch file signals softwareupdate to list the CLT package.
  touch /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress

  local label=""
  local attempt
  for attempt in $(seq 1 12); do
    label=$(softwareupdate -l 2>/dev/null \
      | grep 'Label:' | grep 'Command Line Tools' \
      | sed 's/.*Label: //' \
      | sort -rV | head -1 | xargs 2>/dev/null || true)
    if [[ -n "${label}" ]]; then
      break
    fi
    echo "[prereqs] waiting for CLT to appear in softwareupdate catalog (${attempt}/12)..." >&2
    sleep 10
  done

  if [[ -z "${label}" ]]; then
    rm -f /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress
    cat >&2 <<EOF
[prereqs] Command Line Tools not found in softwareupdate catalog.
[prereqs] Manual fallback:
[prereqs]   sudo xcode-select --install
[prereqs] Then re-run this script once the dialog completes.
EOF
    exit 1
  fi

  echo "[prereqs] Installing: ${label}"
  # Keep the trigger file in place until install completes — removing it first
  # causes softwareupdate to report "No such update" for the CLT package.
  softwareupdate -i "${label}" --verbose
  rm -f /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress

  if ! xcode-select -p &>/dev/null 2>&1; then
    echo "[prereqs] CLT reported as installed but xcode-select still reports failure." >&2
    exit 1
  fi
  echo "[prereqs] Xcode Command Line Tools installed at $(xcode-select -p)"
}

# ── 2. Homebrew ───────────────────────────────────────────────────────────────
ensure_homebrew() {
  for prefix in /opt/homebrew /usr/local; do
    if [[ -x "${prefix}/bin/brew" ]]; then
      BREW_PREFIX="${prefix}"
      eval "$(as_user "${prefix}/bin/brew" shellenv)"
      echo "[prereqs] Homebrew already present at ${prefix}"
      return 0
    fi
  done

  echo "[prereqs] Installing Homebrew as ${REAL_USER} (Homebrew refuses root)..."
  # Pre-create /opt/homebrew (Apple Silicon) owned by the real user so the
  # Homebrew installer does not need to call sudo internally.
  if [[ "$(uname -m)" == "arm64" ]] && [[ ! -d /opt/homebrew ]]; then
    mkdir -p /opt/homebrew
    chown -R "${REAL_USER}:staff" /opt/homebrew
  fi
  # Grant temporary NOPASSWD sudo so Homebrew's sudo-access check passes
  # without a TTY. This file is removed immediately after install.
  local sudoers_tmp="/etc/sudoers.d/rustynet-bootstrap-tmp"
  echo "${REAL_USER} ALL=(ALL) NOPASSWD: ALL" > "${sudoers_tmp}"
  chmod 0440 "${sudoers_tmp}"
  as_user env NONINTERACTIVE=1 /bin/bash -c \
    "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  rm -f "${sudoers_tmp}"

  for prefix in /opt/homebrew /usr/local; do
    if [[ -x "${prefix}/bin/brew" ]]; then
      BREW_PREFIX="${prefix}"
      eval "$(as_user "${prefix}/bin/brew" shellenv)"
      echo "[prereqs] Homebrew installed at ${prefix}"
      return 0
    fi
  done

  echo "[prereqs] Homebrew install failed — brew binary not found at expected locations." >&2
  exit 1
}

# ── 3. Homebrew packages ──────────────────────────────────────────────────────
# wireguard-go   — userspace WireGuard tunnel process (required by rustynetd macOS backend)
# wireguard-tools — provides the 'wg' command for key generation and peer config
# rustup-init    — Rust toolchain installer/manager
install_brew_packages() {
  local pkg
  # Note: Homebrew renamed the formula from rustup-init to rustup (keg-only).
  for pkg in wireguard-go wireguard-tools rustup; do
    if as_user "${BREW_PREFIX}/bin/brew" list --formula "${pkg}" &>/dev/null 2>&1; then
      echo "[prereqs] ${pkg}: already installed"
    else
      echo "[prereqs] Installing ${pkg}..."
      as_user "${BREW_PREFIX}/bin/brew" install "${pkg}"
    fi
  done

  # wireguard-go must be reachable from the daemon's restricted PATH
  # (/usr/local/bin is always in launchd's default PATH).
  if [[ ! -f /usr/local/bin/wireguard-go ]]; then
    local wg_go_bin="${BREW_PREFIX}/bin/wireguard-go"
    if [[ -x "${wg_go_bin}" ]]; then
      echo "[prereqs] Symlinking wireguard-go to /usr/local/bin for daemon PATH"
      mkdir -p /usr/local/bin
      ln -sf "${wg_go_bin}" /usr/local/bin/wireguard-go
    else
      echo "[prereqs] wireguard-go not found after brew install" >&2
      exit 1
    fi
  fi
}

# ── 4. Rust toolchain ─────────────────────────────────────────────────────────
install_rust_toolchain_hardened() {
  # With brew's keg-only rustup formula, rustup lives at opt/rustup/bin/rustup.
  # It does NOT create ~/.cargo/bin/ shims — toolchain bins live in ~/.rustup/toolchains/.
  # We use `rustup run stable <cmd>` everywhere rather than relying on shim paths.
  local brew_rustup="${BREW_PREFIX}/opt/rustup/bin/rustup"
  if [[ ! -x "${brew_rustup}" ]]; then
    echo "[prereqs] rustup not found at ${brew_rustup}" >&2
    exit 1
  fi

  # Check if stable toolchain already installed.
  if as_user "${brew_rustup}" toolchain list 2>/dev/null | grep -q "stable-.*apple-darwin"; then
    echo "[prereqs] Rust stable toolchain already present (skipping update; offline-safe)"
  else
    echo "[prereqs] Installing Rust stable toolchain as ${REAL_USER}..."
    as_user "${brew_rustup}" toolchain install stable --profile minimal
  fi
  as_user "${brew_rustup}" default stable 2>&1 | tail -3 || true

  local rustc_ver
  rustc_ver="$(as_user "${brew_rustup}" run stable rustc --version 2>/dev/null)"
  if [[ -z "${rustc_ver}" ]]; then
    echo "[prereqs] rustc not found via 'rustup run stable rustc' after install" >&2
    exit 1
  fi
  echo "[prereqs] Rust toolchain: ${rustc_ver}"
}

# ── 5. Final prerequisite verification ───────────────────────────────────────
verify_prereqs() {
  local missing=0
  # System tools (available to root).
  local cmd
  for cmd in curl git make clang; do
    if ! command -v "${cmd}" &>/dev/null; then
      echo "[prereqs] still missing: ${cmd}" >&2
      missing=1
    fi
  done
  # Homebrew tools (installed to BREW_PREFIX, now on PATH via setup_bootstrap_path).
  for cmd in wg wireguard-go; do
    if ! command -v "${cmd}" &>/dev/null; then
      echo "[prereqs] still missing: ${cmd}" >&2
      missing=1
    fi
  done
  # Rust toolchain via brew's keg-only rustup (no ~/.cargo/bin shims).
  local brew_rustup="${BREW_PREFIX}/opt/rustup/bin/rustup"
  if [[ ! -x "${brew_rustup}" ]]; then
    echo "[prereqs] still missing: ${brew_rustup}" >&2
    missing=1
  elif ! as_user "${brew_rustup}" run stable rustc --version &>/dev/null; then
    echo "[prereqs] rustup present but stable toolchain not runnable" >&2
    missing=1
  elif ! as_user "${brew_rustup}" run stable cargo --version &>/dev/null; then
    echo "[prereqs] rustup present but cargo not runnable" >&2
    missing=1
  fi
  if [[ "${missing}" -ne 0 ]]; then
    echo "[prereqs] prerequisite verification failed — review errors above." >&2
    exit 1
  fi
  echo "[prereqs] all prerequisites satisfied"
}

# ── Install prerequisites (phases 1-5 above) ─────────────────────────────────
install_prereqs() {
  setup_bootstrap_path
  ensure_xcode_clt
  setup_bootstrap_path        # re-run: CLT now provides git/clang
  ensure_homebrew
  setup_bootstrap_path        # re-run: brew shellenv now resolvable
  install_brew_packages
  install_rust_toolchain_hardened
  setup_bootstrap_path        # re-run: cargo bin now in PATH
  verify_prereqs
}

# ── User/group setup ──────────────────────────────────────────────────────────
ensure_rustynetd_user() {
  if dscl . -read /Users/rustynetd &>/dev/null 2>&1; then
    echo "[bootstrap] rustynetd user already exists"
    return 0
  fi
  local uid=""
  local candidate
  for candidate in $(seq 500 599); do
    if ! dscl . -search /Users UniqueID "${candidate}" 2>/dev/null | grep -q UniqueID; then
      uid="${candidate}"
      break
    fi
  done
  if [[ -z "${uid}" ]]; then
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
  echo "[bootstrap] created rustynetd user/group (uid/gid=${uid})"
}

# ── Directory setup ───────────────────────────────────────────────────────────
setup_directories() {
  install -d -m 0700 -o rustynetd -g rustynetd "${STATE_ROOT}"
  install -d -m 0700 -o rustynetd -g rustynetd "${KEYS_DIR}"
  install -d -m 0700 -o rustynetd -g rustynetd "${STATE_ROOT}/membership"
  install -d -m 0700 -o rustynetd -g rustynetd "${STATE_ROOT}/secrets"
  install -d -m 0700 -o rustynetd -g rustynetd "${STATE_ROOT}/trust"
  install -d -m 0750 -o root      -g rustynetd "${CONFIG_ROOT}"
  install -d -m 0750 -o rustynetd -g rustynetd "${LOG_DIR}"
}

# ── Enrollment secret provisioning ───────────────────────────────────────────
# Generates a 32-byte random enrollment HMAC secret for the daemon.
# The file is raw binary (not hex or base64) — exactly what load_secret()
# expects in rustynetd/src/enrollment_token.rs.
# Idempotent: if the file already exists at the canonical path it is left
# untouched.
# Fail-closed: if generation or the permission/ownership steps fail, the
# script exits immediately via set -euo pipefail.
#
# Atomic write protocol (HIGH 1 + 2 reviewer fold-in):
#   1. Create unique tmpfile inside the keys/ directory (same filesystem as
#      the final secret path, so the final mv is an atomic rename, not a
#      cross-device copy).
#   2. chmod 0600 the tmpfile BEFORE writing any secret bytes into it —
#      this closes the brief race window in which `openssl rand -out`
#      would otherwise create the file under the process umask (typically
#      0022 → mode 0644) and only later have chmod tighten it.
#   3. Write exactly 32 bytes of entropy into the tmpfile via openssl rand.
#   4. Verify the tmpfile is exactly 32 bytes before promoting it. This
#      catches truncated/short writes from a signal-killed openssl. The
#      previous non-atomic pattern left a partial enrollment.secret on
#      disk; the next bootstrap saw `if [ -f ]` as true, skipped
#      regeneration, then size-checked and exited 1 → install stuck
#      until an operator deleted the partial file by hand.
#   5. chown to rustynetd:rustynetd, then atomic mv into the final path.
#   6. EXIT trap removes the tmpfile if any step before the rename
#      failed, so a re-run is always a clean fresh write.
provision_enrollment_secret() {
  local secret_path="${KEYS_DIR}/enrollment.secret"
  if [ -f "${secret_path}" ]; then
    # Hard verify the existing file is exactly 32 bytes before declaring
    # it good. A pre-existing zero-byte or truncated secret is a fail-
    # closed condition — the daemon would reject the HMAC key and the
    # install would silently regress.
    local existing_size
    existing_size="$(wc -c < "${secret_path}" | tr -d ' ')"
    if [ "${existing_size}" -ne 32 ]; then
      echo "[bootstrap] existing enrollment.secret has invalid size ${existing_size} (expected 32); refusing to overwrite — delete it manually and re-run" >&2
      exit 1
    fi
    echo "[bootstrap] enrollment.secret already present (32 bytes); skipping generation"
    return 0
  fi

  local tmp=""
  # EXIT trap covers SIGTERM, SIGHUP, hard `exit` paths, and the
  # set -e abort case. If the rename below succeeds, $tmp will no
  # longer name an existing file and `rm -f` is a no-op.
  # shellcheck disable=SC2064
  trap 'rm -f "${tmp}"' EXIT
  tmp="$(mktemp "${KEYS_DIR}/enrollment.secret.tmp.XXXXXX")"
  if [ -z "${tmp}" ] || [ ! -f "${tmp}" ]; then
    echo "[bootstrap] failed to create enrollment.secret tmpfile under ${KEYS_DIR}" >&2
    exit 1
  fi
  # chmod-first: lock the tmpfile down BEFORE any secret material lands in it.
  chmod 0600 "${tmp}"
  # Write exactly 32 raw binary bytes via openssl (available on all macOS versions).
  openssl rand -out "${tmp}" 32
  # Defend against truncated openssl output (signal-killed, disk full, etc.).
  local size
  size="$(wc -c < "${tmp}" | tr -d ' ')"
  if [ "${size}" -ne 32 ]; then
    echo "[bootstrap] openssl wrote ${size} bytes to tmpfile; expected 32" >&2
    exit 1
  fi
  chown rustynetd:rustynetd "${tmp}"
  # Atomic rename within the same filesystem. The final secret path
  # only ever appears with full contents + correct mode + correct owner.
  mv "${tmp}" "${secret_path}"
  # Disarm the trap; the tmpfile name no longer exists.
  trap - EXIT
  echo "[bootstrap] enrollment.secret generated at ${secret_path}"
}

# ── Clear residual state ──────────────────────────────────────────────────────
clear_residual_state() {
  if networksetup -listallhardwareports 2>/dev/null | grep -q rustynet; then
    ifconfig rustynet0 down 2>/dev/null || true
  fi
  if launchctl print system/com.rustynet.daemon &>/dev/null 2>&1; then
    launchctl bootout system/com.rustynet.daemon 2>/dev/null || true
    sleep 1
  fi
}

# ── Build from source ─────────────────────────────────────────────────────────
build_rustynet() {
  # Skip build ONLY when SKIP_BUILD=1 is explicitly set.  The previous
  # behaviour (auto-skip when the binary already existed) silently kept
  # stale binaries across orchestrator re-runs: the source archive on
  # disk would be the fresh one but `/usr/local/bin/rustynetd` would
  # still be from an earlier build, which is invisible to the operator
  # and breaks any fix that has not yet propagated.  Always rebuilding
  # is the correct default in an orchestrator-driven environment where
  # this script only runs as part of a deliberate (re)deploy.
  if [[ "${SKIP_BUILD:-0}" == "1" ]]; then
    if [[ -x "${RUSTYNETD_BIN}" ]]; then
      echo "[bootstrap] SKIP_BUILD=1: keeping existing ${RUSTYNETD_BIN}"
    else
      echo "[bootstrap] SKIP_BUILD=1 set but ${RUSTYNETD_BIN} not found — cannot skip build" >&2
      exit 1
    fi
    return 0
  fi
  mkdir -p "${BUILD_DIR}"
  # Give the real user ownership so cargo can write the target directory.
  chown -R "${REAL_USER}" "${BUILD_DIR}"
  tar -xzf "${SOURCE_ARCHIVE}" -C "${BUILD_DIR}"

  pushd "${BUILD_DIR}" >/dev/null

  local brew_rustup="${BREW_PREFIX}/opt/rustup/bin/rustup"
  local host_target
  host_target="$(as_user "${brew_rustup}" run stable rustc -vV | awk '/^host/ { print $2 }')"

  # Add the native target for this host (arm64-apple-darwin / x86_64-apple-darwin).
  as_user "${brew_rustup}" target add "${host_target}" 2>/dev/null || true

  # macOS system SQLite is sufficient; no Homebrew sqlite needed.
  # No OpenSSL dep in rustynetd. Build is clean with just the system SDK.
  # Build by package, not by bin name — the cli package is `rustynet-cli`
  # (no `rustynet` bin exists at the workspace level), and `cargo build
  # --bin rustynet` fails with "no bin target named `rustynet`" against
  # the current workspace.  `-p rustynet-cli` builds the rustynet-cli
  # binary at target/release/rustynet-cli, which install_binaries below
  # renames to /usr/local/bin/rustynet on the way out.
  as_user "${brew_rustup}" run stable cargo build --release -p rustynetd -p rustynet-cli

  popd >/dev/null
}

# ── Install binaries ──────────────────────────────────────────────────────────
install_binaries() {
  # Skip when SKIP_BUILD=1 was set (caller explicitly kept the existing
  # binaries).  Otherwise always reinstall — the freshly built binaries
  # at ${BUILD_DIR}/target/release must replace any stale copies in
  # /usr/local/bin so the next launchctl restart picks up the new code.
  if [[ "${SKIP_BUILD:-0}" == "1" ]]; then
    echo "[bootstrap] SKIP_BUILD=1: keeping existing ${RUSTYNETD_BIN} (skipping reinstall)"
    return 0
  fi
  if [[ ! -d "${BUILD_DIR}" ]]; then
    echo "[bootstrap] install_binaries: BUILD_DIR=${BUILD_DIR} is missing — build must run before install" >&2
    exit 1
  fi
  install -m 0755 -o root -g wheel \
    "${BUILD_DIR}/target/release/rustynetd" "${RUSTYNETD_BIN}"
  # The CLI bin is built as `rustynet-cli` by the rustynet-cli package and
  # installed system-wide as `rustynet` (the launchd plist and operator
  # documentation expect the short name).
  install -m 0755 -o root -g wheel \
    "${BUILD_DIR}/target/release/rustynet-cli" "${RUSTYNET_BIN}"
  rm -rf "${BUILD_DIR}"
}

# ── WireGuard key generation ──────────────────────────────────────────────────
generate_wireguard_keys() {
  if [[ -f "${KEYS_DIR}/wireguard.pub" ]]; then
    echo "[bootstrap] WireGuard keys already present; skipping key generation"
    return 0
  fi
  local tmp_priv
  tmp_priv="$(mktemp)"
  chmod 600 "${tmp_priv}"
  wg genkey > "${tmp_priv}"
  wg pubkey < "${tmp_priv}" > "${KEYS_DIR}/wireguard.pub"
  # Encrypt using rustynetd key-custody; plain copy as fallback.
  "${RUSTYNETD_BIN}" key init \
    --wg-private-key "${tmp_priv}" \
    --wg-encrypted-private-key "${KEYS_DIR}/wireguard.key.enc" 2>/dev/null \
    || cp "${tmp_priv}" "${KEYS_DIR}/wireguard.key.enc"
  rm -f "${tmp_priv}"
  chmod 600 "${KEYS_DIR}/wireguard.key.enc"
  chmod 640 "${KEYS_DIR}/wireguard.pub"
  chown rustynetd:rustynetd \
    "${KEYS_DIR}/wireguard.key.enc" \
    "${KEYS_DIR}/wireguard.pub"
  echo "[bootstrap] WireGuard keys generated"
}

# ── Trust evidence seeding ───────────────────────────────────────────────────
# Generates a local trust signing key and issues initial trust evidence.
# The daemon requires trust evidence at startup; this must run before the
# launchd plist is installed and the daemon attempts to start.
# Idempotent: skips if trust evidence already exists.
seed_trust_evidence() {
  local trust_dir="${STATE_ROOT}/trust"
  local signing_key="${CONFIG_ROOT}/trust-evidence.key"
  local verifier_key="${trust_dir}/trust-evidence.pub"
  local trust_evidence="${trust_dir}/rustynetd.trust"
  local passphrase_file

  if [[ -f "${trust_evidence}" ]]; then
    echo "[bootstrap] trust evidence already present; skipping seed"
    return 0
  fi

  # HIGH 3 reviewer fold-in: match setup_directories perms exactly
  # (0700 owner rustynetd:rustynetd). Earlier code used 0755 root:rustynetd
  # which left the trust directory world-traversable. Files inside
  # (signing_key, trust_evidence, verifier_key) are individually chowned
  # below to root:rustynetd; rustynetd traverses through the dir because
  # the dir itself is rustynetd-owned.
  install -d -m 0700 -o rustynetd -g rustynetd "${trust_dir}"

  passphrase_file="$(mktemp)"
  chmod 600 "${passphrase_file}"
  # Generate a random 32-char hex passphrase for the signing key.
  od -A n -t x1 -N 16 /dev/urandom | tr -d ' \n' > "${passphrase_file}"

  # Generate the trust signing+verifier key pair.
  "${RUSTYNET_BIN}" trust keygen \
    --signing-key-output "${signing_key}" \
    --signing-key-passphrase-file "${passphrase_file}" \
    --verifier-key-output "${verifier_key}" \
    --force

  # Issue the initial trust evidence signed by the new key.
  "${RUSTYNET_BIN}" trust issue \
    --signing-key "${signing_key}" \
    --signing-key-passphrase-file "${passphrase_file}" \
    --output "${trust_evidence}"

  rm -f "${passphrase_file}"

  # Secure the signing key (root-owned, group-read for rustynetd).
  chown root:rustynetd "${signing_key}"
  chmod 0640 "${signing_key}"
  # Trust evidence: root:rustynetd 0640.
  chown root:rustynetd "${trust_evidence}"
  chmod 0640 "${trust_evidence}"
  # Verifier key: world-readable.
  chown root:rustynetd "${verifier_key}"
  chmod 0644 "${verifier_key}"

  echo "[bootstrap] trust evidence seeded at ${trust_evidence}"
}

# ── Launchd service installation ──────────────────────────────────────────────
install_launchd_service() {
  local install_script="${PLIST_SCRIPT_DIR}/Install-RustyNetMacosService.sh"
  local daemon_node_role="${DAEMON_NODE_ROLE:-}"
  case "${daemon_node_role}" in
    admin|client|blind_exit) ;;
    *)
      echo "[bootstrap] DAEMON_NODE_ROLE must be admin, client, or blind_exit" >&2
      exit 2
      ;;
  esac
  if [[ ! -f "${install_script}" ]]; then
    echo "[bootstrap] Install-RustyNetMacosService.sh not found at ${install_script}" >&2
    exit 1
  fi
  local ssh_allow_flag="false"
  if [[ -n "${SSH_ALLOW_CIDRS:-}" ]]; then
    ssh_allow_flag="true"
  fi

  # auto_tunnel_enforce defaults false during bootstrap so the daemon can start
  # without a signed assignment bundle. The orchestrator's enforce_runtime phase
  # re-invokes Install-RustyNetMacosService.sh with --auto-tunnel-enforce true
  # after all bundles are deployed (mirroring Linux e2e-enforce-host behaviour).
  # trust_max_age_secs: macOS has no periodic trust-evidence refresh timer
  # (the Linux unit ships a rustynetd-trust-refresh.timer; macOS does not).
  # The bootstrap-time trust evidence may be a few minutes old by the time
  # launchd actually invokes the daemon, and the 300 s daemon default trips
  # "trust evidence is stale" → exit 65 → daemon never opens its socket →
  # orchestrator's collect_pubkeys stage hangs and aborts.  Use 86400 s here
  # to match what enforce_daemon already sets, so the very first invocation
  # also stays within the freshness window.
  # WG_INTERFACE is the per-node utun device name derived from NODE_ID by
  # the Rust orchestrator (utun_name_for_node_id in macos_install.rs). Fall
  # back to utun9 so a manual operator-run install (without the env var)
  # still produces a usable plist; the install-script regex validation
  # (^utun[0-9]+$) rejects anything malformed before plist rendering.
  local wg_interface="${WG_INTERFACE:-utun9}"
  if [[ ! "${wg_interface}" =~ ^utun[0-9]+$ ]]; then
    echo "[bootstrap] WG_INTERFACE='${wg_interface}' must match ^utun[0-9]+\$" >&2
    exit 2
  fi
  bash "${install_script}" \
    --rustynetd-bin "${RUSTYNETD_BIN}" \
    --state-root "${STATE_ROOT}" \
    --log-dir "${LOG_DIR}" \
    --plist-dst "${PLIST_PATH}" \
    --node-id "${NODE_ID}" \
    --node-role "${daemon_node_role}" \
    --network-id "${NETWORK_ID}" \
    --brew-prefix "${BREW_PREFIX:-/opt/homebrew}" \
    --auto-tunnel-enforce "false" \
    --trust-max-age-secs 86400 \
    --wg-interface "${wg_interface}" \
    --fail-closed-ssh-allow "${ssh_allow_flag}" \
    --fail-closed-ssh-allow-cidrs "${SSH_ALLOW_CIDRS:-}"
}

# ── Main ──────────────────────────────────────────────────────────────────────
echo "[bootstrap] macOS Rustynet install starting"
echo "[bootstrap]   macOS:   $(sw_vers -productName) $(sw_vers -productVersion)"
echo "[bootstrap]   arch:    $(uname -m)"
echo "[bootstrap]   node_id: ${NODE_ID}"
echo "[bootstrap]   role:    ${ROLE}"

if [[ "${SKIP_BUILD:-0}" == "1" ]]; then
  # Binary already installed — skip prereqs, build, and binary install.
  # Only run the steps needed to keep the service config current.
  echo "[bootstrap] SKIP_BUILD=1: skipping prereqs and build phases"
  ensure_rustynetd_user
  setup_directories
  generate_wireguard_keys
  provision_enrollment_secret
  seed_trust_evidence
  install_launchd_service
else
  install_prereqs
  ensure_rustynetd_user
  setup_directories
  clear_residual_state
  build_rustynet
  install_binaries
  generate_wireguard_keys
  provision_enrollment_secret
  seed_trust_evidence
  install_launchd_service
fi

echo "[bootstrap] macOS Rustynet install complete"
echo "[bootstrap]   rustynetd: ${RUSTYNETD_BIN} ($(${RUSTYNETD_BIN} --version 2>/dev/null || echo 'version unavailable'))"
echo "[bootstrap]   service:   launchctl print system/com.rustynet.daemon"
