#!/usr/bin/env bash
# Bootstrap-RustyNetMacos.sh — macOS full-install wizard for Rustynet.
#
# Takes a bare macOS installation to a running rustynetd daemon in one pass:
#   1. Xcode Command Line Tools
#   2. Homebrew — MUST ALREADY BE INSTALLED (verified, never installed here)
#   3. wireguard-go, wireguard-tools, rustup-init  (via the existing brew)
#   4. Rust stable toolchain
#   5. Build rustynet from a SIGNED + VERIFIED source archive (or stage
#      host-cross prebuilt binaries only after the same verification)
#   6. Install binaries + launchd service
#
# Usage (must run as root):
#   sudo bash Bootstrap-RustyNetMacos.sh <env-file>
#
# AQ-11 / R-SEC-10 hardening contract (fail closed, no downgrade path):
#   - This script never widens its own privileges. It grants itself no
#     passwordless sudo rule and never edits the system sudo policy — not
#     even temporarily. sudo is only exercised as `sudo -u <real-user>` to
#     DROP privileges for brew/rustup; any elevation is supplied by the
#     caller (operator or rn_bootstrap_macos.sh).
#   - Homebrew is a prerequisite. Missing brew = exit 1 with operator
#     instructions; the Homebrew installer is never fetched or executed here.
#   - Nothing downloaded is executed or installed until it verifies against a
#     signed release manifest (Ed25519, pinned verifier key) AND the artifact
#     sha256+size digest, via Verify-RustyNetRelease.sh (next to this script)
#     driving `rustynet ops verify-release-manifest`. The exact files about
#     to be consumed are required BY NAME (--require-artifact), and the
#     payload is first copied to a PRIVATE temp dir; the copy is what
#     verifies and the copy is what gets consumed (no verify-to-use race).
#     Verification covers:
#       * SOURCE_ARCHIVE (a private copy of it), before tar extraction
#         (build-from-source path)
#       * the co-located manifest in RN_PREBUILT_DIR, before staging
#         prebuilt binaries into target/release
#     A missing manifest/key/verifier-CLI is a hard failure, not a warning.
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
# Release-verification variables (AQ-11; required for the build phases):
#   RUSTYNET_VERIFY_CLI       — absolute path to a TRUSTED `rustynet` binary
#                               used for `ops verify-release-manifest`. It
#                               must be provisioned out-of-band (a
#                               previously installed rustynet or an
#                               operator-staged copy) and must never be part
#                               of the payload it verifies. Default when
#                               unset: the already-installed ${RUSTYNET_BIN}
#                               (itself built from previously-verified
#                               source); with neither available the
#                               bootstrap builds `rustynet-cli` from the
#                               LOCAL source checkout this script itself
#                               runs from (never from the downloaded
#                               payload — AQ-11 F4 provenance refusal
#                               still applies) and uses that build as the
#                               verifier BEFORE any download is trusted.
#                               That build fails closed on failure.
#   RUSTYNET_RELEASE_MANIFEST — signed release-manifest.json covering
#                               SOURCE_ARCHIVE. The archive is verified BY
#                               NAME (`--require-artifact <basename>`): the
#                               manifest must list the archive's exact
#                               basename, or verification fails (AQ-11 F3 —
#                               a signed manifest that does not list the
#                               file being consumed is not acceptance of
#                               that file).
#   RUSTYNET_RELEASE_PINNED_KEY_HEX | RUSTYNET_RELEASE_PINNED_KEY_FILE
#                             — pinned Ed25519 verifier key (exactly one).
#                               OPTIONAL: with neither set the bootstrap
#                               pins its embedded DEFAULT release verifier
#                               key (RUSTYNET_DEFAULT_RELEASE_VERIFIER_
#                               KEY_HEX below — the owner-generated public
#                               key accepted by owner decision OI-47,
#                               2026-09-25). An explicit hex/file always
#                               wins over the default. The verifier CLI +
#                               pinned key are REFUSED if they resolve
#                               inside any payload directory (artifacts
#                               dir / RN_PREBUILT_DIR / BUILD_DIR): the
#                               payload can never vouch for itself
#                               (AQ-11 F4).
#   RN_PREBUILT_BINARIES=1 + RN_PREBUILT_DIR
#                             — host-cross staging; requires a co-located
#                               release-manifest.json inside RN_PREBUILT_DIR
#                               (override: RN_PREBUILT_RELEASE_MANIFEST).
#                               Each staged binary (rustynetd, rustynet-cli,
#                               rustynet-relay) is required BY NAME in the
#                               signed manifest, and the payload is verified
#                               as a PRIVATE COPY before use (AQ-11 F3+F5).
#
# Optional:
#   RUSTYNET_BREW_PREFIX      — explicit Homebrew prefix pin; when set it is
#                               the ONLY accepted location (no silent
#                               fallback to the canonical prefixes).
#   RUSTYNET_BOOTSTRAP_PREREQ_CHECK_ONLY=1
#                             — read-only dry run: resolve the prerequisite
#                               phases (PATH + Homebrew detection) and exit
#                               before any system change.
#
# Design:
#   - Idempotent: safe to re-run; each phase skips if already satisfied.
#   - Fail-closed: set -euo pipefail; every step is verified before proceeding.
#   - Verify-before-execute: downloaded payload verifies or the run dies.
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
readonly RUSTYNET_RELAY_BIN="/usr/local/bin/rustynet-relay"
readonly STATE_ROOT="/usr/local/var/rustynet"
readonly CONFIG_ROOT="/usr/local/etc/rustynet"
readonly KEYS_DIR="${STATE_ROOT}/keys"
# Bootstrap-time credential directory. Exists outside keys/ so the
# macos-key-custody-check (which only scans keys/) does not flag its contents
# as plaintext key material at rest. The wireguard passphrase lives here rather
# than in keys/ — it is a bootstrap artifact needed for cdhash re-bind on each
# rebuild, not key material the daemon accesses at runtime (the daemon reads
# the passphrase from the System.keychain, not from disk).
readonly BOOTSTRAP_DIR="${STATE_ROOT}/bootstrap"
readonly LOG_DIR="/usr/local/var/log/rustynet"
readonly LAUNCHDAEMON_DIR="/Library/LaunchDaemons"
readonly PLIST_PATH="${LAUNCHDAEMON_DIR}/com.rustynet.daemon.plist"
readonly PLIST_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly BUILD_DIR="/private/var/tmp/rustynet-build-$$"

# AQ-247 / OI-47 (accepted 2026-09-25): the owner-generated Ed25519 PUBLIC
# release verifier key, embedded as the DEFAULT pin for every payload-
# verification path below. An explicit RUSTYNET_RELEASE_PINNED_KEY_HEX /
# RUSTYNET_RELEASE_PINNED_KEY_FILE always overrides it. The matching PRIVATE
# signing seed is held by the owner only and never appears in this tree.
readonly RUSTYNET_DEFAULT_RELEASE_VERIFIER_KEY_HEX="7bb5f1629b7b9eb48bdb94633d092e796a2a8ba69903cc3e432e1a33c05016fe"

# On Apple Silicon brew lives at /opt/homebrew; on Intel at /usr/local.
BREW_PREFIX=""

# ── Secure removal of key/passphrase artifacts ─────────────────────────────────
# Shell counterpart of rustynetd's key_material::remove_file_if_present, for the
# same reason: `rm -f` on a secret is two separate hazards.
#
#   1. Path/type confusion. `rm -f "$f"` will happily unlink whatever $f names.
#      If an attacker who can write the parent directory plants a symlink there,
#      a naive scrub-then-delete would zero the symlink's TARGET. We therefore
#      stat WITHOUT following (`-L` before `-f`), unlink a symlink as a symlink
#      and never write through it, and fail closed on anything that is not a
#      regular file rather than guessing.
#   2. Content remanence. Unlink only drops the directory entry; the bytes stay
#      until reused. We overwrite with zeros first.
#
# The zero-fill is BEST-EFFORT and deliberately not advertised as more: on
# APFS/SSD (copy-on-write, wear levelling, snapshots) an in-place overwrite may
# land on fresh blocks and leave the originals readable. macOS dropped `srm` and
# deprecated `rm -P` for exactly this reason. The load-bearing protection here is
# (1); the scrub is defence in depth. This matches what the Rust helper does, so
# the two sides of the codebase make the same promise.
secure_remove_file() {
  local target="${1:-}"

  # Empty is a no-op, NOT an error. This is load-bearing for the EXIT trap that
  # guards the passphrase tmpfile: the trap is armed BEFORE mktemp assigns the
  # variable, so it can legitimately fire with an empty path if mktemp fails.
  # `rm -f ""` exits 0 silently, so erroring here would turn a clean failure exit
  # into a confusing trap error under `set -e`.
  if [[ -z "${target}" ]]; then
    return 0
  fi

  # Absent is success — callers use this for "remove if present" cleanup.
  # -e is false for a dangling symlink, hence the explicit -L.
  if [[ ! -e "${target}" && ! -L "${target}" ]]; then
    return 0
  fi

  # -L first: a symlink must be unlinked as a symlink, never scrubbed through.
  if [[ -L "${target}" ]]; then
    rm -f -- "${target}"
    return 0
  fi

  if [[ ! -f "${target}" ]]; then
    echo "[bootstrap] secure remove requires a regular file: ${target}" >&2
    return 1
  fi

  local size
  size="$(stat -f %z "${target}" 2>/dev/null || echo 0)"
  # Overwrite EXACTLY the file's length: bs=<size> count=1 writes size bytes and
  # conv=notrunc keeps dd from truncating first. Rounding up to a block instead
  # (bs=8192 count=ceil) would EXTEND a short file — a 32-byte passphrase became
  # 8192 bytes — allocating blocks we are about to unlink anyway. Safe as a single
  # buffer because every caller here passes a key/passphrase file (tens of bytes).
  if [[ "${size}" -gt 0 ]]; then
    dd if=/dev/zero of="${target}" bs="${size}" count=1 conv=notrunc 2>/dev/null || true
    sync
  fi
  rm -f -- "${target}"
}

# ── Privilege separation ───────────────────────────────────────────────────────
# Homebrew and the Rust toolchain refuse to run as root. When invoked via
# `sudo bash`, $SUDO_USER holds the original unprivileged user.
#
# Phase 24 follow-up (Gap E): the orchestrator wrapper rn_bootstrap_macos.sh
# already runs us under `sudo -n bash`, so we are launched with SUDO_USER
# pointing at the wrapper's effective user. When the wrapper itself was
# already invoked via sudo (the orchestrator's `live_lab_run_root` pattern),
# SUDO_USER inside this script is `root` rather than the human/desktop
# account that owns Homebrew. Falling back blindly to `${SUDO_USER:-...}`
# would then make as_user run brew as root, which Homebrew refuses
# ("Running Homebrew as root is extremely dangerous"). Prefer logname
# (which tracks the original login session uid) and only fall back to
# SUDO_USER when logname is unavailable AND SUDO_USER is not root.
resolve_non_root_bootstrap_user() {
  local candidate=""
  local prefix owner
  for candidate in "${RUSTYNET_MACOS_BOOTSTRAP_USER:-}" \
                   "$(logname 2>/dev/null || true)" \
                   "${SUDO_USER:-}"; do
    if [[ -n "${candidate}" && "${candidate}" != "root" ]] &&
       id -u "${candidate}" >/dev/null 2>&1; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done

  for prefix in /opt/homebrew /usr/local; do
    if [[ -x "${prefix}/bin/brew" ]]; then
      owner="$(stat -f '%Su' "${prefix}" 2>/dev/null || true)"
      if [[ -n "${owner}" && "${owner}" != "root" ]] &&
         id -u "${owner}" >/dev/null 2>&1; then
        printf '%s\n' "${owner}"
        return 0
      fi
      owner="$(stat -f '%Su' "${prefix}/bin/brew" 2>/dev/null || true)"
      if [[ -n "${owner}" && "${owner}" != "root" ]] &&
         id -u "${owner}" >/dev/null 2>&1; then
        printf '%s\n' "${owner}"
        return 0
      fi
    fi
  done

  owner="$(stat -f '%Su' /dev/console 2>/dev/null || true)"
  if [[ -n "${owner}" && "${owner}" != "root" ]] &&
     id -u "${owner}" >/dev/null 2>&1; then
    printf '%s\n' "${owner}"
    return 0
  fi

  return 1
}

REAL_USER="$(resolve_non_root_bootstrap_user)" || {
  cat >&2 <<'EOF'
[bootstrap] could not resolve a non-root macOS bootstrap user.
[bootstrap] Refusing to run Homebrew/Rust toolchain as root.
[bootstrap] Re-run from an admin user session or set RUSTYNET_MACOS_BOOTSTRAP_USER to a valid non-root account.
EOF
  exit 1
}
REAL_HOME="$(dscl . -read "/Users/${REAL_USER}" NFSHomeDirectory 2>/dev/null | awk '{print $2}' || true)"
if [[ -z "${REAL_HOME}" || ! -d "${REAL_HOME}" ]]; then
  REAL_HOME="$(eval echo "~${REAL_USER}")"
fi
if [[ -z "${REAL_HOME}" || ! -d "${REAL_HOME}" ]]; then
  echo "[bootstrap] could not resolve home directory for ${REAL_USER}" >&2
  exit 1
fi

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
  # RUSTYNET_BREW_PREFIX is authoritative when set (see ensure_homebrew).
  local -a brew_candidates
  if [[ -n "${RUSTYNET_BREW_PREFIX:-}" ]]; then
    brew_candidates=("${RUSTYNET_BREW_PREFIX}")
  else
    brew_candidates=(/opt/homebrew /usr/local)
  fi
  local prefix
  for prefix in "${brew_candidates[@]}"; do
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

# ── 2. Homebrew (prerequisite — never installed by this script) ──────────────
# AQ-11 / R-SEC-10: Homebrew must be provisioned by the operator BEFORE this
# bootstrap runs. The previous flow self-granted the bootstrap user a
# temporary passwordless-root sudo rule (a /etc policy-file write that
# outlived its purpose on any missed cleanup path — local
# privilege-escalation residue) and piped the Homebrew installer straight
# off the network into a shell (unverified remote code execution). Both are
# removed: a bootstrap never widens its own privileges and never executes
# downloaded code unverified. Missing brew = exit 1 with operator
# instructions.
ensure_homebrew() {
  # RUSTYNET_BREW_PREFIX is authoritative when set: it is the only accepted
  # location, with NO silent fallback to the canonical prefixes (fail closed).
  local -a brew_candidates
  if [[ -n "${RUSTYNET_BREW_PREFIX:-}" ]]; then
    brew_candidates=("${RUSTYNET_BREW_PREFIX}")
  else
    brew_candidates=(/opt/homebrew /usr/local)
  fi
  local prefix
  for prefix in "${brew_candidates[@]}"; do
    if [[ -x "${prefix}/bin/brew" ]]; then
      BREW_PREFIX="${prefix}"
      eval "$(as_user "${prefix}/bin/brew" shellenv)"
      echo "[prereqs] Homebrew present at ${prefix}"
      return 0
    fi
  done

  cat >&2 <<'EOF'
[prereqs] FATAL: Homebrew is not installed, and this bootstrap does not
[prereqs] install it (AQ-11: never download-and-execute an installer, never
[prereqs] self-grant elevated privileges).
[prereqs] Install Homebrew yourself as an admin user (you will be prompted
[prereqs] for YOUR password), then re-run this bootstrap:
[prereqs]   1. follow https://brew.sh from an admin account (NOT as root)
[prereqs]   2. verify:  /opt/homebrew/bin/brew --version   (Apple Silicon)
[prereqs]      or:      /usr/local/bin/brew --version     (Intel)
[prereqs]   3. re-run:  sudo bash Bootstrap-RustyNetMacos.sh <env-file>
EOF
  exit 1
}

# ── 3. Homebrew packages ──────────────────────────────────────────────────────
# wireguard-go   — userspace WireGuard tunnel process (required by rustynetd macOS backend)
# wireguard-tools — provides the 'wg' command for key generation and peer config
# rustup-init    — Rust toolchain installer/manager
install_brew_packages() {
  local pkg
  # Note: Homebrew renamed the formula from rustup-init to rustup (keg-only).
  #
  # Phase 24 follow-up (Gap D): coreutils provides `gtimeout`, which we
  # symlink into /usr/local/bin/timeout below so the orchestrator's
  # `timeout 15 sudo -n -k true` preflight (Linux-style, see
  # scripts/e2e/live_lab_common.sh::live_lab_verify_sudo) resolves to a
  # working `timeout` binary on stock macOS (which ships only BSD `time`,
  # no GNU `timeout`). Without this the orchestrator's prime_remote_access
  # stage fails for the aux/macos label with rc=127.
  for pkg in wireguard-go wireguard-tools rustup; do
    if as_user "${BREW_PREFIX}/bin/brew" list --formula "${pkg}" &>/dev/null 2>&1; then
      echo "[prereqs] ${pkg}: already installed"
    else
      echo "[prereqs] Installing ${pkg}..."
      as_user "${BREW_PREFIX}/bin/brew" install "${pkg}"
    fi
  done

  if command -v timeout &>/dev/null || [[ -x /usr/local/bin/timeout ]]; then
    echo "[prereqs] timeout: already available; skipping coreutils install"
  elif as_user "${BREW_PREFIX}/bin/brew" list --formula coreutils &>/dev/null 2>&1; then
    echo "[prereqs] coreutils: already installed"
  else
    echo "[prereqs] Installing coreutils for gtimeout..."
    as_user "${BREW_PREFIX}/bin/brew" install coreutils
  fi

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

  # Phase 24 follow-up (Gap D): expose GNU timeout at /usr/local/bin/timeout
  # so the orchestrator's preflight finds it on ssh non-login shells (whose
  # PATH does NOT include /opt/homebrew/bin even when /etc/paths lists it).
  if [[ ! -e /usr/local/bin/timeout ]]; then
    local gtimeout_bin="${BREW_PREFIX}/bin/gtimeout"
    if [[ -x "${gtimeout_bin}" ]]; then
      echo "[prereqs] Symlinking gtimeout to /usr/local/bin/timeout for orchestrator PATH"
      mkdir -p /usr/local/bin
      ln -sf "${gtimeout_bin}" /usr/local/bin/timeout
    else
      echo "[prereqs] gtimeout not found after brew install coreutils" >&2
      exit 1
    fi
  fi
}

# ── 4. Rust toolchain ─────────────────────────────────────────────────────────
install_rust_toolchain_hardened() {
  # Brew's keg-only rustup formula lives at opt/rustup/bin/rustup and does NOT
  # create the ~/.cargo/bin/ proxy shims. We invoke it as `rustup run stable
  # <cmd>`, but that alone is NOT sufficient for `cargo build`: with
  # RUSTUP_TOOLCHAIN set, the toolchain cargo invokes `rustc` through the rustup
  # PROXY (resolved on PATH, where ${REAL_HOME}/.cargo/bin is first — see
  # setup_bootstrap_path), not the toolchain's own bin. With no shim the build
  # dies with "could not execute process `rustc -vV` ... No such file or
  # directory" even though `rustup run stable rustc --version` works. So we must
  # ensure the shims exist (offline-safe: a shim is just the rustup multi-call
  # binary under each tool name, dispatching via argv[0] — no download).
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

  # Ensure the ~/.cargo/bin shims the build path depends on, pointing them
  # DIRECTLY at the stable toolchain's own binaries (resolved via `rustup
  # which`), NOT at the brew rustup wrapper. brew's keg-only
  # opt/rustup/bin/rustup is a thin wrapper that does NOT multi-call dispatch on
  # argv[0] — invoked as `rustc` it prints rustup's own version instead of
  # compiling — so a shim pointing at it would never run the compiler. A direct
  # link is robust to that and matches the force-stable build below. Idempotent
  # (ln -sf), so it also repairs a guest whose shims went missing (the failure
  # mode that surfaced live: the toolchain rustc was intact but cargo could not
  # exec a `rustc` proxy, dying with "could not execute process `rustc -vV`").
  local cargo_bin="${REAL_HOME}/.cargo/bin"
  as_user mkdir -p "${cargo_bin}"
  local real_rustc real_cargo
  real_rustc="$(as_user "${brew_rustup}" which --toolchain stable rustc 2>/dev/null)"
  real_cargo="$(as_user "${brew_rustup}" which --toolchain stable cargo 2>/dev/null)"
  if [[ -z "${real_rustc}" || -z "${real_cargo}" ]]; then
    echo "[prereqs] could not resolve stable toolchain rustc/cargo via 'rustup which'" >&2
    exit 1
  fi
  as_user ln -sf "${real_rustc}" "${cargo_bin}/rustc"
  as_user ln -sf "${real_cargo}" "${cargo_bin}/cargo"

  local rustc_ver
  rustc_ver="$(as_user "${brew_rustup}" run stable rustc --version 2>/dev/null)"
  if [[ -z "${rustc_ver}" ]]; then
    echo "[prereqs] rustc not found via 'rustup run stable rustc' after install" >&2
    exit 1
  fi
  # Verify the path `cargo build` actually takes: a bare `rustc` resolved through
  # the ~/.cargo/bin shim on PATH (first entry per setup_bootstrap_path), which
  # is what previously failed despite the direct-toolchain check above passing.
  if ! as_user env "PATH=${cargo_bin}:${PATH}" rustc --version &>/dev/null; then
    echo "[prereqs] shim rustc invocation (cargo build path) failed after ensuring ~/.cargo/bin shims" >&2
    exit 1
  fi
  echo "[prereqs] Rust toolchain: ${rustc_ver} (shims ensured at ${cargo_bin})"
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
  # Rust toolchain via brew's keg-only rustup, with the ~/.cargo/bin proxy shims
  # ensured by install_rust_toolchain_hardened (the build path needs them).
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
# AQ-11 F7 (deliberate ordering, documented): the Homebrew-absent refusal
# inside ensure_homebrew fires AFTER ensure_xcode_clt. That is intentional,
# not an ordering bug: on a brew-less Mac the CLT provides git/clang — the
# out-of-band toolchain the verify-before-execute path relies on (AQ-11 F4) — and
# installing CLT is required to install Homebrew at all. The refusal is the
# TERMINAL state of that path ("CLT present, brew still absent → exit 1 with
# operator instructions"), so no untrusted installer is ever fetched.
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

# ── System.keychain unlock ──────────────────────────────────────────────────
# `rustynetd key init` writes the WireGuard runtime passphrase + (later) the
# trust signing-key passphrase into the macOS System.keychain via
# `store_macos_generic_password_system_keychain` in rustynet-crypto.
# The legacy `SecKeychain` API fails closed with `OsStoreUnavailable` when
# the keychain is locked, even for root. macOS auto-locks System.keychain on
# sleep / on a per-keychain idle timeout (default 300 s). Without an explicit
# unlock pass here the bootstrap fails with `encrypt key failed: os secure
# store unavailable` whenever the VM has been idle long enough for the lock
# timer to fire (Phase 24 live-lab retry15 hit this).
#
# Set the timeout to no auto-lock and run an unlock pass. The default fresh
# macOS System.keychain password is empty, so the unlock typically succeeds
# without operator input. Both steps are best-effort — they emit a clear
# log line and continue so a locked-keychain failure surfaces at `key init`
# (fail-closed) rather than being masked.
ensure_system_keychain_unlocked() {
  local keychain_path="/Library/Keychains/System.keychain"
  if [[ ! -f "${keychain_path}" ]]; then
    echo "[bootstrap] System.keychain missing at ${keychain_path}; key init will fail" >&2
    return 0
  fi
  if security set-keychain-settings "${keychain_path}" >/dev/null 2>&1; then
    echo "[bootstrap] System.keychain auto-lock disabled (no-timeout)"
  else
    echo "[bootstrap] failed to disable System.keychain auto-lock (continuing)" >&2
  fi
  if security unlock-keychain -p "" "${keychain_path}" >/dev/null 2>&1; then
    echo "[bootstrap] System.keychain unlocked (default empty password)"
  else
    # Already unlocked or a custom password is set; key init will surface
    # the real error if write still fails.
    echo "[bootstrap] System.keychain unlock-keychain returned non-zero (likely already unlocked or custom password)"
  fi
}

# ── Directory setup ───────────────────────────────────────────────────────────
setup_directories() {
  install -d -m 0700 -o rustynetd -g rustynetd "${STATE_ROOT}"
  install -d -m 0700 -o rustynetd -g rustynetd "${KEYS_DIR}"
  install -d -m 0700 -o rustynetd -g rustynetd "${STATE_ROOT}/membership"
  install -d -m 0700 -o rustynetd -g rustynetd "${STATE_ROOT}/secrets"
  install -d -m 0700 -o rustynetd -g rustynetd "${STATE_ROOT}/trust"
  # Membership signing credential-workspace parent (parity with the Linux
  # systemd install adapter, which provisions /var/lib/rustynet/credentials-workspace
  # root:rustynetd 0700): only root ops verbs write per-invocation 0700 leaves
  # here via mkdir(2); the daemon never opens this parent on macOS.
  install -d -m 0700 -o root      -g rustynetd "${STATE_ROOT}/credentials-workspace"
  install -d -m 0750 -o root      -g rustynetd "${CONFIG_ROOT}"
  install -d -m 0750 -o rustynetd -g rustynetd "${LOG_DIR}"
  # Bootstrap credential dir: 0700 root:rustynetd so only root (bootstrap) and
  # rustynetd can traverse. Holds wireguard.passphrase outside the keys/ dir so
  # macos-key-custody-check does not flag it as forbidden plaintext key material.
  install -d -m 0700 -o root -g rustynetd "${BOOTSTRAP_DIR}"
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

# ── DNS repair and cargo registry connectivity ────────────────────────────────

# Ensure an IPv4 default route exists. Cleanup can leave the route missing when
# ipconfig getpacket fails (no DHCP lease data). Derive the gateway using three
# fallbacks: DHCP lease router option → any UGH host route with an IPv4 gateway
# → .1 of the host's primary address on en0.
ensure_ipv4_default_route_macos() {
  netstat -rn -f inet 2>/dev/null | grep '^default' >/dev/null && return 0
  local gw=""
  # 1. networksetup Router field — works for Manual (static) and DHCP configs
  gw="$(networksetup -getinfo "Ethernet" 2>/dev/null | awk '/^Router:/{print $2; exit}')" || true
  # 2. DHCP lease router option (DHCP-only fallback)
  if [[ -z "$gw" ]]; then
    gw="$(ipconfig getpacket en0 2>/dev/null | awk '/^router /{gsub(/[{}]/, "", $3); print $3; exit}')" || true
  fi
  # 3. Any existing host route that already carries an IPv4 gateway
  if [[ -z "$gw" ]]; then
    gw="$(netstat -rn -f inet 2>/dev/null \
          | awk '$2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $3 ~ /G/ {print $2; exit}')" || true
  fi
  # 4. Assume .1 of the host's primary IPv4 address on en0
  if [[ -z "$gw" ]]; then
    local host_ip
    host_ip="$(ipconfig getifaddr en0 2>/dev/null)" || true
    [[ -n "$host_ip" ]] && gw="${host_ip%.*}.1"
  fi
  if [[ -n "$gw" ]]; then
    route add default "$gw" 2>/dev/null \
      || route change default "$gw" 2>/dev/null \
      || true
    echo "[bootstrap] IPv4 default route added via ${gw}" >&2
  else
    echo "[bootstrap] warning: IPv4 default route missing; could not determine gateway" >&2
  fi
}

repair_bootstrap_dns_state_macos() {
  # Override DNS on every network service with a known-good public resolver.
  # The lab router's DNS (from DHCP) may be broken or unreachable; if cargo
  # cannot resolve index.crates.io the build hangs silently for minutes.
  local service
  while IFS= read -r service; do
    [[ -n "${service}" ]] || continue
    networksetup -setdnsservers "${service}" 1.1.1.1 8.8.8.8 2>/dev/null || true
  done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)
  dscacheutil -flushcache 2>/dev/null || true
  killall -HUP mDNSResponder 2>/dev/null || true
  # Give mDNSResponder time to apply the new nameserver settings before any
  # caller checks connectivity.
  sleep 3
}

wait_for_cargo_registry_endpoint() {
  local endpoint="https://index.crates.io/"
  # Ensure IPv4 default route exists before any connectivity check. Cleanup can
  # silently drop the route when ipconfig getpacket has no lease data.
  ensure_ipv4_default_route_macos
  # Always repair DNS before the first check to ensure 1.1.1.1 is the active
  # resolver. Without this, curl may pass on a stale cache entry but cargo's
  # fresh resolution fails because mDNSResponder still has broken DHCP DNS.
  repair_bootstrap_dns_state_macos
  local attempt
  for attempt in $(seq 1 8); do
    if curl --ipv4 --fail --silent --head --connect-timeout 10 --max-time 15 \
         "${endpoint}" >/dev/null 2>&1; then
      return 0
    fi
    echo "[bootstrap] cargo registry unreachable (attempt ${attempt}/8); repairing DNS" >&2
    repair_bootstrap_dns_state_macos
    sleep 2
  done
  echo "[bootstrap] failed to reach cargo registry: ${endpoint}" >&2
  return 1
}

# ── Clear residual state ──────────────────────────────────────────────────────
clear_residual_state() {
  if networksetup -listallhardwareports 2>/dev/null | grep -q rustynet; then
    ifconfig rustynet0 down 2>/dev/null || true
  fi
  # Boot out daemon first (depends on helper socket); helper second so its
  # SCM_RIGHTS socket survives until the daemon has detached. Matches the
  # systemd Requires=rustynetd-privileged-helper.service teardown order.
  if launchctl print system/com.rustynet.daemon &>/dev/null 2>&1; then
    launchctl bootout system/com.rustynet.daemon 2>/dev/null || true
    # Wait (bounded, <= 10 s: launchd's 5 s SIGTERM->SIGKILL ceiling + margin)
    # for the daemon job to report no pid before stopping the helper. `bootout`
    # returns at SIGTERM delivery, not at job exit, and the daemon's shutdown
    # rollback dials the privileged-helper socket — the helper must outlive the
    # daemon (plan M2, MacosHelperShutdownOrderingImplementationPlan_2026-09-02).
    for _attempt in $(seq 1 20); do
      if ! launchctl print system/com.rustynet.daemon 2>/dev/null | grep 'pid = ' >/dev/null; then
        break
      fi
      sleep 0.5
    done
  fi
  if launchctl print system/com.rustynet.privileged-helper &>/dev/null 2>&1; then
    launchctl bootout system/com.rustynet.privileged-helper 2>/dev/null || true
    sleep 1
  fi

  # Clear residual distributed signed-state + anti-replay watermarks from any
  # prior enrollment. This is the macOS analogue of the Linux cleanup's
  # `rm -rf /var/lib/rustynet`: a fresh (re)enrollment must not inherit a stale
  # trust epoch watermark, or the daemon rejects the fresh genesis bundle
  # as a replay/rollback ("membership replay/rollback detected by
  # watermark") and fail-closes (observed live: macOS stuck state=FailClosed,
  # reconcile_failures, membership_active_nodes=none). Key custody (keys/,
  # bootstrap/, secrets/) is deliberately preserved — only the trust/
  # signed-state plus the top-level session state are removed, and only
  # here on an operator-driven fresh bootstrap (the running daemon's
  # anti-rollback protection between enrollments is unchanged).
  # `seed_trust_evidence` re-seeds trust/, the orchestrator re-distributes
  # the signed bundles, and the daemon rebuilds its watermarks from the
  # fresh genesis.
  #
  # MAC-D10: the membership/ wipe deliberately does NOT live here. Wiping
  # membership/ in a general cleanup pass leaves a destructive window where
  # any bootstrap (re)entry that fails between the wipe and the re-genesis —
  # or re-runs the cleanup after genesis — strands the node with NO signed
  # state while the orchestrator's membership stage is mid-flight (observed
  # live: genesis seeded by bootstrap, membership/ empty by the time the
  # stage's read-back ran). The wipe now lives inside `seed_membership_genesis`,
  # immediately before `membership init` re-seeds the state, so the deleting
  # write can never execute without the re-seed following it in the same
  # function.
  local _residual_dir
  for _residual_dir in trust; do
    if [[ -d "${STATE_ROOT}/${_residual_dir}" ]]; then
      find "${STATE_ROOT}/${_residual_dir}" -mindepth 1 -maxdepth 1 \
        -exec rm -rf {} + 2>/dev/null || true
    fi
  done
  rm -f "${STATE_ROOT}/rustynetd.state" "${STATE_ROOT}/rustynetd.state.lock" \
    "${STATE_ROOT}/rustynetd.state.shutdown-residue.json" \
    "${STATE_ROOT}/rustynetd.state.networksetup-dns.failclosed.bak" 2>/dev/null || true
}

# ── AQ-11: signed-release verification of downloaded payload ────────────────
# Single enforcement point for "nothing downloaded is executed or installed
# unverified": Verify-RustyNetRelease.sh (which drives
# `rustynet ops verify-release-manifest` with the PINNED verifier key) must
# accept the manifest signature AND every artifact digest BEFORE the caller
# extracts or stages the payload. Missing manifest/key/verifier-CLI or any
# digest mismatch exits non-zero here (fail closed; no warning-and-continue).
#
# AQ-11 rework additions (all fail closed):
#   F3 — callers pass the exact filenames they are about to consume as extra
#        arguments; each is forwarded as `--require-artifact <name>` and must
#        be listed in the signed manifest. A validly-signed manifest that
#        merely does NOT list the consumed file is not acceptance of it.
#   F4 — the verifier CLI and the pinned key are resolved HERE and passed to
#        the helper as explicit flags, so ambient environment (including the
#        env-file sourced at the top of this script) can never supply a
#        payload-chosen verifier or key. Either one resolving inside a payload
#        directory is refused: the payload can never vouch for itself.
#   F5 — call sites verify a PRIVATE COPY of the payload (staged into a 0700
#        temp dir) and consume only that copy; world-writable payload
#        directories are refused outright.

# Canonical absolute path of an EXISTING file/dir without BSD/GNU stat or
# readlink -f portability traps: canonicalize the parent with cd/pwd -P and
# re-attach the final component. The final component's own symlink is not
# resolved — conservative for the provenance check (a symlink PLACED in a
# payload directory still has its dirname inside the payload directory).
canonicalize_existing_path() {
  local p="$1"
  local dir base
  dir="$(cd -- "$(dirname -- "${p}")" && pwd -P)" || return 1
  base="$(basename -- "${p}")"
  printf '%s/%s\n' "${dir}" "${base}"
}

refuse_world_writable_dir() {
  local dir="$1"
  local label="$2"
  # -perm -0002 is mode-AND-0002 != 0: portable across BSD/GNU find, unlike
  # parsing `ls -l` or `stat -f/-c` output. The match list (not find's exit
  # status — find exits 0 whether or not anything matched) decides.
  if [[ -n "$(find "${dir}" -maxdepth 0 -perm -0002 2>/dev/null)" ]]; then
    echo "[bootstrap] FATAL: ${label} is world-writable: ${dir}" >&2
    echo "[bootstrap]        a co-located attacker could swap the payload between verification and use; chmod the directory private and re-run" >&2
    exit 1
  fi
}

# F4: refuse a verifier CLI or pinned key that resolves inside any directory
# holding payload content. If the verifier (or the key that authorizes it)
# came from the payload, signature verification is self-vouching.
refuse_payload_provenance() {
  local path="$1"
  local label="$2"
  shift 2
  local canonical payload_dir
  canonical="$(canonicalize_existing_path "${path}")" || {
    echo "[bootstrap] FATAL: cannot canonicalize ${label}: ${path}" >&2
    exit 1
  }
  local -a payload_dirs=()
  local d
  payload_dirs+=("${BUILD_DIR}")
  payload_dirs+=("${RN_PREBUILT_DIR:-/tmp/rn_prebuilt}")
  payload_dirs+=("$@")
  for d in ${payload_dirs[@]+"${payload_dirs[@]}"}; do
    [[ -n "${d}" ]] || continue
    payload_dir="$(canonicalize_existing_path "${d}")" || continue
    case "${canonical}/" in
      "${payload_dir}"/*)
        echo "[bootstrap] FATAL: ${label} resolves inside a payload directory (${payload_dir}): ${canonical}" >&2
        echo "[bootstrap]        the verifier and pinned key must be provisioned out-of-band (AQ-11 F4); the payload can never vouch for itself" >&2
        exit 1
        ;;
    esac
  done
}

# AQ-247 / OI-47: verifier-from-source fallback. When neither an explicit
# RUSTYNET_VERIFY_CLI nor the already-installed ${RUSTYNET_BIN} is usable,
# build `rustynet-cli` from the LOCAL source checkout this bootstrap script
# itself runs from (PLIST_SCRIPT_DIR/../../..) — never from the downloaded
# payload — with the Rust toolchain the bootstrap already requires, running
# as the non-root real user, and use that binary as the verifier BEFORE any
# download is trusted. Every failure here is a named hard failure: the
# bootstrap never falls back to an unverified extract.
rn_build_local_verifier_cli() {
  local artifacts_dir="$1"
  local checkout="${PLIST_SCRIPT_DIR}/../../.."
  checkout="$(cd "${checkout}" && pwd)" || {
    echo "[bootstrap] FATAL: cannot resolve the local source checkout below ${PLIST_SCRIPT_DIR}" >&2
    return 1
  }
  if [[ ! -f "${checkout}/Cargo.toml" || ! -d "${checkout}/crates/rustynet-cli" ]]; then
    echo "[bootstrap] FATAL: no out-of-band verifier CLI available and ${checkout} is not a rustynet source checkout (missing Cargo.toml or crates/rustynet-cli)" >&2
    echo "[bootstrap]        provision a trusted verifier (export RUSTYNET_VERIFY_CLI=<absolute-path>) and retry" >&2
    return 1
  fi
  # AQ-11 F4: a checkout that IS the payload (or lives inside it) can never
  # vouch for itself. The provenance refusal must precede the build: building
  # executes the checkout's own build scripts, so refusing only the finished
  # binary would already have run payload-chosen code.
  refuse_payload_provenance "${checkout}/Cargo.toml" "verifier source checkout" "${artifacts_dir}" || return 1
  local brew_rustup="${BREW_PREFIX}/opt/rustup/bin/rustup"
  if [[ ! -x "${brew_rustup}" ]]; then
    echo "[bootstrap] FATAL: cannot build the verifier from source: rustup not found at ${brew_rustup} (the prerequisite phase must run first)" >&2
    return 1
  fi
  echo "[bootstrap] no out-of-band verifier CLI available; building rustynet-cli from the local checkout ${checkout} (AQ-247/OI-47)" >&2
  if ! as_user "${brew_rustup}" run stable cargo build --release --locked -p rustynet-cli --manifest-path "${checkout}/Cargo.toml"; then
    echo "[bootstrap] FATAL: verifier build from local source failed — refusing to verify or extract any download (fail closed)" >&2
    return 1
  fi
  local built="${checkout}/target/release/rustynet-cli"
  if [[ ! -x "${built}" ]]; then
    echo "[bootstrap] FATAL: verifier build produced no binary at ${built}" >&2
    return 1
  fi
  refuse_payload_provenance "${built}" "built verifier CLI" "${artifacts_dir}" || return 1
  printf '%s' "${built}"
}

verify_downloaded_payload() {
  local label="$1"
  local manifest="$2"
  local artifacts_dir="$3"
  shift 3
  # Remaining args: exact filenames the caller will consume (AQ-11 F3).

  local helper="${PLIST_SCRIPT_DIR}/Verify-RustyNetRelease.sh"
  if [[ ! -x "${helper}" ]]; then
    echo "[bootstrap] FATAL: release verifier helper not executable: ${helper}" >&2
    exit 1
  fi

  # F4: resolve the verifier CLI out-of-band. Explicit env wins; the
  # default is the ALREADY-INSTALLED rustynet (built from previously-verified
  # source); with neither available the verifier is BUILT from the local
  # source checkout this script runs from (AQ-247/OI-47), never from the
  # payload. No verifier at all is a hard failure, never a fallback into the
  # payload.
  local rn_verify_cli="${RUSTYNET_VERIFY_CLI:-${RUSTYNET_BIN}}"
  if [[ "${rn_verify_cli}" != /* ]]; then
    echo "[bootstrap] FATAL: verifier CLI must be an absolute path: ${rn_verify_cli}" >&2
    exit 1
  fi
  if [[ ! -x "${rn_verify_cli}" ]]; then
    rn_verify_cli="$(rn_build_local_verifier_cli "${artifacts_dir}")" || {
      echo "[bootstrap] FATAL: no out-of-band verifier CLI available and no verifier could be built from the local source checkout" >&2
      exit 1
    }
  fi

  # F4: resolve the pinned key. Explicit env (hex or file), exactly one,
  # wins; with neither set the bootstrap pins its embedded DEFAULT release
  # verifier key (AQ-247/OI-47: the owner-generated Ed25519 public key). The
  # resolved key is passed as an explicit flag so the helper's environment
  # fallback can never be fed by the env-file sourced at the top of this
  # script (a payload-chosen key would make verification self-vouching).
  local rn_key_hex="${RUSTYNET_RELEASE_PINNED_KEY_HEX:-}"
  local rn_key_file="${RUSTYNET_RELEASE_PINNED_KEY_FILE:-}"
  if [[ -n "${rn_key_hex}" && -n "${rn_key_file}" ]]; then
    echo "[bootstrap] FATAL: both RUSTYNET_RELEASE_PINNED_KEY_HEX and RUSTYNET_RELEASE_PINNED_KEY_FILE set; provide exactly one" >&2
    exit 1
  fi
  local -a rn_key_args=()
  if [[ -n "${rn_key_hex}" ]]; then
    rn_key_args=(--pinned-key-hex "${rn_key_hex}")
  elif [[ -n "${rn_key_file}" ]]; then
    [[ -f "${rn_key_file}" ]] || {
      echo "[bootstrap] FATAL: pinned key file not found: ${rn_key_file}" >&2
      exit 1
    }
    refuse_payload_provenance "${rn_key_file}" "pinned key file" "${artifacts_dir}" || exit 1
    rn_key_args=(--pinned-key-file "${rn_key_file}")
  else
    rn_key_hex="${RUSTYNET_DEFAULT_RELEASE_VERIFIER_KEY_HEX}"
    echo "[bootstrap] no explicit release verifier key given; pinning the embedded default release key (AQ-247/OI-47)" >&2
    rn_key_args=(--pinned-key-hex "${rn_key_hex}")
  fi

  refuse_payload_provenance "${rn_verify_cli}" "verifier CLI" "${artifacts_dir}" || exit 1
  refuse_world_writable_dir "${artifacts_dir}" "payload artifacts dir"

  echo "[bootstrap] verifying ${label} (signed manifest + artifact digests, required by name: ${*:-none})..."
  # Explicit status check, not set -e alone: a security gate must not depend
  # on its call context (set -e is void inside `if`/`&&`/`||` contexts).
  local -a rn_verify_cmd=("${helper}" --verifier-cli "${rn_verify_cli}" --manifest "${manifest}" --artifacts-dir "${artifacts_dir}" "${rn_key_args[@]}")
  local rn_required
  for rn_required in "$@"; do
    rn_verify_cmd+=(--require-artifact "${rn_required}")
  done
  if ! "${rn_verify_cmd[@]}"; then
    echo "[bootstrap] FATAL: ${label} FAILED signed-release verification — refusing to extract or execute it (AQ-11: verify-before-execute)" >&2
    exit 1
  fi
  echo "[bootstrap] ${label}: manifest signature + digests verified (required artifacts bound)"
}

# ── AQ-11 F5: private verification staging ───────────────────────────────────
# Payload is COPIED into a private (0700) temp dir; the copy is what verifies
# and the copy is what gets consumed, closing the verify-to-use window on a
# shared or world-writable directory. The safety EXIT cleanup is armed only
# when no EXIT trap exists (the later passphrase-tmpfile traps own their own;
# see the trap-ends-rc-0 note at the top of this file — the trailing
# assignment keeps the trap's exit status clean).
RN_VERIFY_STAGE=""
RN_VERIFY_STAGE_TRAP_ARMED=0
rn_stage_begin() {
  local stage
  stage="$(mktemp -d "${TMPDIR:-/private/var/tmp}/rn-verify-XXXXXXXX")" || {
    echo "[bootstrap] FATAL: cannot create private verification staging dir" >&2
    exit 1
  }
  chmod 0700 "${stage}"
  RN_VERIFY_STAGE="${stage}"
  if [[ -z "$(trap -p EXIT)" ]]; then
    trap '[[ -n "${RN_VERIFY_STAGE:-}" ]] && rm -rf "${RN_VERIFY_STAGE}"; RN_VERIFY_STAGE=""' EXIT
    RN_VERIFY_STAGE_TRAP_ARMED=1
  fi
}
rn_stage_end() {
  if [[ -n "${RN_VERIFY_STAGE:-}" ]]; then
    rm -rf "${RN_VERIFY_STAGE}"
    RN_VERIFY_STAGE=""
  fi
  if [[ "${RN_VERIFY_STAGE_TRAP_ARMED:-0}" == "1" ]]; then
    trap - EXIT
    RN_VERIFY_STAGE_TRAP_ARMED=0
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
  # AQ-11 / R-SEC-10: verify BEFORE extracting. The source archive is
  # downloaded content — building it executes vendored build scripts and the
  # resulting binaries get installed, so the signed-manifest + digest gate
  # must pass before tar touches disk. The archive is required BY NAME in the
  # signed manifest (`--require-artifact <basename>` — a signed manifest that
  # does not list it is not acceptance of it), and the archive is verified as
  # a PRIVATE COPY which is also what tar consumes (AQ-11 F3+F5: no
  # verify-to-use window on a shared directory such as /private/var/tmp).
  local rn_archive_name rn_verify_stage
  rn_archive_name="$(basename "${SOURCE_ARCHIVE}")"
  rn_stage_begin
  rn_verify_stage="${RN_VERIFY_STAGE}"
  if [[ ! -f "${SOURCE_ARCHIVE}" ]]; then
    echo "[bootstrap] FATAL: source archive not found: ${SOURCE_ARCHIVE}" >&2
    rn_stage_end
    exit 1
  fi
  cp "${SOURCE_ARCHIVE}" "${rn_verify_stage}/${rn_archive_name}" || {
    echo "[bootstrap] FATAL: cannot copy source archive into private staging dir" >&2
    rn_stage_end
    exit 1
  }
  verify_downloaded_payload \
    "source archive ${rn_archive_name} (private staging copy)" \
    "${RUSTYNET_RELEASE_MANIFEST:-}" \
    "${rn_verify_stage}" \
    "${rn_archive_name}"
  tar -xzf "${rn_verify_stage}/${rn_archive_name}" -C "${BUILD_DIR}"
  rn_stage_end

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
  # Offline-first build. When the dependency cache is already warm (an
  # orchestrator re-run on a previously-bootstrapped VM, or a relocated VM that
  # kept its ~/.cargo cache but lost upstream internet — e.g. moved to a LAN
  # segment with no gateway), build straight from the local cache with no
  # network. `cargo build --offline` fails fast during dependency resolution if
  # anything is missing, so a genuinely cold cache / newly-added dependency
  # falls through to the online path, which requires the registry and fetches.
  # This keeps fresh-VM provisioning working while no longer making a transient
  # or absent upstream route a hard bootstrap failure when the cache suffices.
  if [[ "${RN_PREBUILT_BINARIES:-0}" == "1" ]]; then
    # host-cross: the orchestrator cross-built the node binaries on the host
    # (same aarch64-apple-darwin triple) and scp'd them here; stage them into
    # target/release so install_binaries picks them up, and skip the guest build.
    # Fail closed on a missing prebuilt binary AND on unverified content
    # (AQ-11): the co-located signed release-manifest.json must verify against
    # the pinned key + digests BEFORE any binary is staged into target/release.
    # Each binary is required BY NAME in the manifest, and the binaries are
    # verified as a PRIVATE COPY which is also what gets installed
    # (AQ-11 F3+F5). A world-writable prebuilt directory is refused outright:
    # unlike the source-archive path there is no signed container, so any
    # co-located writer inside the staging window is a hard failure.
    rn_prebuilt_dir="${RN_PREBUILT_DIR:-/tmp/rn_prebuilt}"
    if [[ ! -d "${rn_prebuilt_dir}" ]]; then
      echo "[bootstrap] FATAL: RN_PREBUILT_BINARIES=1 but prebuilt dir is missing: ${rn_prebuilt_dir}" >&2
      exit 1
    fi
    refuse_world_writable_dir "${rn_prebuilt_dir}" "RN_PREBUILT_DIR"
    local rn_prebuilt_manifest rn_prebuilt_stage rn_b
    rn_prebuilt_manifest="${RN_PREBUILT_RELEASE_MANIFEST:-${rn_prebuilt_dir}/release-manifest.json}"
    if [[ ! -f "${rn_prebuilt_manifest}" ]]; then
      echo "[bootstrap] FATAL: prebuilt release manifest not found: ${rn_prebuilt_manifest}" >&2
      exit 1
    fi
    for rn_b in rustynetd rustynet-cli rustynet-relay; do
      if [[ ! -f "${rn_prebuilt_dir}/${rn_b}" ]]; then
        echo "[bootstrap] FATAL: RN_PREBUILT_BINARIES=1 but prebuilt '${rn_b}' is missing in ${rn_prebuilt_dir}" >&2
        exit 1
      fi
    done
    rn_stage_begin
    rn_prebuilt_stage="${RN_VERIFY_STAGE}"
    cp "${rn_prebuilt_manifest}" "${rn_prebuilt_stage}/release-manifest.json" || {
      echo "[bootstrap] FATAL: cannot copy prebuilt manifest into private staging dir" >&2
      rn_stage_end
      exit 1
    }
    for rn_b in rustynetd rustynet-cli rustynet-relay; do
      cp "${rn_prebuilt_dir}/${rn_b}" "${rn_prebuilt_stage}/${rn_b}" || {
        echo "[bootstrap] FATAL: cannot copy prebuilt '${rn_b}' into private staging dir" >&2
        rn_stage_end
        exit 1
      }
    done
    verify_downloaded_payload \
      "prebuilt binaries (private staging copy)" \
      "${rn_prebuilt_stage}/release-manifest.json" \
      "${rn_prebuilt_stage}" \
      rustynetd rustynet-cli rustynet-relay
    echo "[bootstrap] host-cross: staging verified prebuilt binaries into target/release, skipping guest build" >&2
    mkdir -p target/release
    install -m 0755 "${rn_prebuilt_stage}/rustynetd" target/release/rustynetd
    install -m 0755 "${rn_prebuilt_stage}/rustynet-cli" target/release/rustynet-cli
    install -m 0755 "${rn_prebuilt_stage}/rustynet-relay" target/release/rustynet-relay
    rn_stage_end
  elif as_user "${brew_rustup}" run stable cargo build --release --offline -p rustynetd -p rustynet-cli --features rustynet-cli/vm-lab; then
    echo "[bootstrap] built rustynetd + rustynet-cli from warm cargo cache (offline)"
  else
    echo "[bootstrap] offline build unavailable (cold cache or new dependency); fetching from registry" >&2
    wait_for_cargo_registry_endpoint || exit 1
    as_user "${brew_rustup}" run stable cargo build --release -p rustynetd -p rustynet-cli --features rustynet-cli/vm-lab
  fi

  # rustynet-relay (sibling relay datapath binary) needs the `daemon` feature
  # for its service runtime, and is built as a separate invocation because
  # `--features` does not fan out across multiple `-p` packages. A Relay-role
  # node needs this binary present for DeployRelayServiceStage to enable the
  # launchd com.rustynet.relay service; building it on every node also keeps a
  # later role-switch to Relay possible without a re-bootstrap. Same offline-
  # first fallback as the daemon/cli build above.
  # host-cross staged rustynet-relay above (with the daemon/cli), so only build
  # it in the normal (non-prebuilt) path.
  if [[ "${RN_PREBUILT_BINARIES:-0}" != "1" ]]; then
    if as_user "${brew_rustup}" run stable cargo build --release --offline -p rustynet-relay --features daemon; then
      echo "[bootstrap] built rustynet-relay from warm cargo cache (offline)"
    else
      echo "[bootstrap] offline rustynet-relay build unavailable (cold cache or new dependency); fetching from registry" >&2
      wait_for_cargo_registry_endpoint || exit 1
      as_user "${brew_rustup}" run stable cargo build --release -p rustynet-relay --features daemon
    fi
  fi

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
  # Re-sign rustynetd with a *proper* ad-hoc signature. The Rust toolchain emits
  # a "linker-signed" ad-hoc signature (codesign flags 0x20002); macOS does NOT
  # treat linker-signed binaries as having a stable code identity for keychain
  # ACLs across processes. As a result an item stored by `rustynetd key
  # store-passphrase` (owned-identity System-keychain path) is unreadable by the
  # daemon at startup — "os secure store unavailable" -> wg key decrypt failed ->
  # launchd exit 65 crash-loop. A real ad-hoc signature (`codesign --force -s -`,
  # flags 0x2) gives a stable cdhash that the owned-item ACL honors, so the same
  # rustynetd binary that stores the WG passphrase reads it back at startup.
  # Verified live on macOS 26.5: under the linker signature both the launchd
  # daemon and a `sudo -u rustynetd` run fail the keychain read; after
  # `codesign --force -s -` + re-store both reach "runtime key material
  # prepared". Must run before `key store-passphrase` so the keychain item is
  # owned by the re-signed identity. (rustynet-cli is not re-signed: it only
  # reads the trust passphrase via the allow-any-app `-A` path, which is not
  # bound to the reader's code identity.)
  codesign --force -s - "${RUSTYNETD_BIN}"
  # The CLI bin is built as `rustynet-cli` by the rustynet-cli package and
  # installed system-wide as `rustynet` (the launchd plist and operator
  # documentation expect the short name).
  install -m 0755 -o root -g wheel \
    "${BUILD_DIR}/target/release/rustynet-cli" "${RUSTYNET_BIN}"
  # rustynet-relay: the sibling relay datapath binary. Installed on every node
  # so a Relay-role assignment (or later role-switch to Relay) can be activated
  # by DeployRelayServiceStage without a re-bootstrap. Not re-signed — unlike
  # rustynetd it never performs a keychain `key store-passphrase`; it loads its
  # ed25519 verifier key from a file (--verifier-key) and serves the datapath.
  install -m 0755 -o root -g wheel \
    "${BUILD_DIR}/target/release/rustynet-relay" "${RUSTYNET_RELAY_BIN}"
  rm -rf "${BUILD_DIR}"
}

# ── WireGuard key generation ──────────────────────────────────────────────────
#
# Mirrors the Linux key-custody pipeline so the macOS daemon's runtime
# key material is identical in shape to systemd hosts:
#   - ${KEYS_DIR}/wireguard.key.enc   — passphrase-encrypted blob (mode 0600, AT REST)
#   - ${KEYS_DIR}/wireguard.pub       — public key (mode 0640, AT REST)
#   - ${KEYS_DIR}/wireguard.passphrase — passphrase credential (mode 0600, AT REST)
#   - /private/var/run/rustynet/wireguard.key — plaintext runtime key, EPHEMERAL
#       (daemon-written each start; deliberately NOT in keys/ — custody note below)
#
# Custody (macos_key_custody / Phase E encrypted-at-rest): the plaintext runtime
# key must NOT persist in the at-rest keys/ dir. `key init` writes it under keys/
# transiently (root can create there), then generate_wireguard_keys removes it.
# The daemon re-derives it from wireguard.key.enc + the keychain passphrase into
# the EPHEMERAL runtime dir (/private/var/run/rustynet/wireguard.key, the
# `--wg-private-key` plist arg) at every startup (see
# `prepare_runtime_wireguard_key_material` in crates/rustynetd/src/daemon.rs).
# The macOS userspace-shared backend re-reads that runtime key on boringtun
# worker recovery (`retains_runtime_key_at_rest` is true), so it persists in the
# runtime dir for the daemon's lifetime but is GC'd between reboots — matching
# Linux's /run/rustynet/wireguard.key. The privileged-helper plist recreates
# /private/var/run/rustynet (root:0o770) each boot so the rustynetd group can
# write the runtime key there.
#
# After `key init` we push the passphrase into the macOS keychain via
# `rustynetd key store-passphrase`. The launchd plist exports
# `RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT`, so at runtime
# `read_passphrase_file` resolves the passphrase from Security framework
# instead of disk; the on-disk passphrase file remains only as the
# bootstrap-time material for `key init` and to satisfy the launchd plist
# file-path argument.
#
# Fail-closed: no fallback. If `key init` returns non-zero the install must
# stop here rather than silently leaving plaintext key bytes at
# `wireguard.key.enc` (the prior `|| cp` branch did exactly that, which
# Phase 19+20 live-val surfaced as a daemon "decrypt encrypted key failed"
# loop on first start).
generate_wireguard_keys() {
  local runtime_key="${KEYS_DIR}/wireguard.key"
  local encrypted_key="${KEYS_DIR}/wireguard.key.enc"
  local public_key="${KEYS_DIR}/wireguard.pub"
  # Phase E: the passphrase is a bootstrap artifact, not key material. It now
  # lives in BOOTSTRAP_DIR (outside keys/) so macos-key-custody-check does not
  # flag it as "forbidden plaintext key material at rest in keys/". The daemon
  # never reads it from disk at runtime — it reads from the System.keychain.
  local passphrase_file="${BOOTSTRAP_DIR}/wireguard.passphrase"
  local keychain_account="wg-passphrase-${NODE_ID}"

  # Migrate any pre-Phase-E passphrase file from keys/ to bootstrap/.
  # Guests bootstrapped before this change kept wireguard.passphrase in
  # keys/, which the macos-key-custody-check correctly flags as forbidden.
  # Move it once, preserving the existing passphrase so the cdhash re-bind
  # below continues to work without generating a fresh key.
  if [[ -f "${KEYS_DIR}/wireguard.passphrase" && ! -f "${passphrase_file}" ]]; then
    mv "${KEYS_DIR}/wireguard.passphrase" "${passphrase_file}"
    chown root:rustynetd "${passphrase_file}"
    chmod 0600 "${passphrase_file}"
    echo "[bootstrap] migrated wireguard.passphrase from keys/ to bootstrap/ (Phase E)"
  elif [[ -f "${KEYS_DIR}/wireguard.passphrase" && -f "${passphrase_file}" ]]; then
    # Both exist (edge case: partial prior migration). Remove the stale keys/ copy.
    secure_remove_file "${KEYS_DIR}/wireguard.passphrase"
    echo "[bootstrap] removed stale wireguard.passphrase from keys/ (Phase E cleanup)"
  fi

  # Detect existing key material via the PERSISTENT artifacts only (encrypted
  # blob + public key). The passphrase is now in BOOTSTRAP_DIR (not keys/) and
  # the plaintext runtime key is intentionally NOT a sentinel: it is removed from
  # keys/ after init (see below) and re-derived by the daemon into the ephemeral
  # runtime dir on each start. Its absence must NOT trigger a re-key.
  if [[ -f "${public_key}" && -f "${encrypted_key}" && -f "${passphrase_file}" ]]; then
    echo "[bootstrap] WireGuard key material already present; skipping key generation"
    # Re-store the passphrase into the keychain even on the skip path.
    # install_binaries re-signs rustynetd on EVERY bootstrap, and macOS ad-hoc
    # signatures are NON-DETERMINISTIC: `codesign --force -s -` yields a fresh
    # cdhash each run (verified live — re-signing the same bytes twice produced
    # different CDHashes). The owned System-keychain item's read ACL is bound to
    # the storing binary's cdhash, so a rebuild that keeps the existing WG key
    # (cleanup_runtime_state preserves it) but re-signs the binary leaves the
    # item bound to a PREVIOUS build's cdhash -> the freshly-signed daemon hits
    # "os secure store unavailable" -> wg decrypt fails -> launchd exit 65
    # crash-loop (observed live: item cdhash 89dd09… vs daemon cdhash e28b76…).
    # Re-binding here keeps the stable WG identity while making the passphrase
    # readable by the current binary. The store reader runs as root and the
    # daemon's secret-file guard requires owner==reader, so present the
    # passphrase file root-owned for the store, then restore daemon ownership.
    chown root:wheel "${passphrase_file}"
    if ! sudo "${RUSTYNETD_BIN}" key store-passphrase \
        --passphrase-file "${passphrase_file}" \
        --keychain-account "${keychain_account}"; then
      echo "[bootstrap] rustynetd key store-passphrase (cdhash re-bind) failed; daemon cannot resolve passphrase from keychain" >&2
      exit 1
    fi
    chown root:rustynetd "${passphrase_file}"
    chmod 0600 "${passphrase_file}"
    echo "[bootstrap] WireGuard passphrase re-stored in macOS keychain (account=${keychain_account}) to rebind to the current rustynetd cdhash"
    return 0
  fi

  # Atomic passphrase write: chmod the tmpfile BEFORE writing entropy so the
  # secret bytes never appear under the default umask (0644) even briefly.
  # Same protocol as provision_enrollment_secret above.
  local passphrase_tmp=""
  # shellcheck disable=SC2064
  trap 'secure_remove_file "${passphrase_tmp}"' EXIT
  passphrase_tmp="$(mktemp "${BOOTSTRAP_DIR}/wireguard.passphrase.tmp.XXXXXX")"
  if [[ -z "${passphrase_tmp}" || ! -f "${passphrase_tmp}" ]]; then
    echo "[bootstrap] failed to create wireguard.passphrase tmpfile under ${BOOTSTRAP_DIR}" >&2
    exit 1
  fi
  chmod 0600 "${passphrase_tmp}"
  # 32 raw bytes -> 64 hex chars (>= 16-char minimum enforced by parse_passphrase_bytes).
  od -A n -t x1 -N 32 /dev/urandom | tr -d ' \n' > "${passphrase_tmp}"
  local passphrase_size
  passphrase_size="$(wc -c < "${passphrase_tmp}" | tr -d ' ')"
  if [[ "${passphrase_size}" -ne 64 ]]; then
    echo "[bootstrap] wireguard passphrase generation produced ${passphrase_size} bytes; expected 64" >&2
    exit 1
  fi
  # Keep the bootstrap passphrase root-owned until the privileged `key init`
  # and `key store-passphrase` calls finish. The daemon's Unix secret-file
  # guard requires the file owner to match the effective reader UID; root is
  # the reader during these two System.keychain provisioning steps.
  chown root:wheel "${passphrase_tmp}"
  mv "${passphrase_tmp}" "${passphrase_file}"
  trap - EXIT

  # `rustynetd key init` reads `--passphrase-file` via the explicit
  # (non-keychain) reader on macOS — see read_passphrase_file_explicit in
  # crates/rustynetd/src/key_material.rs — so this works even before the
  # passphrase is in the keychain.
  #
  # `--force` is required so a re-run after a partial install (e.g. crash
  # between `mv` of the passphrase file and the first key-init invocation)
  # cleanly overwrites the stale material.
  #
  # Run the key-init custody write as root, then chown the material back to
  # rustynetd below. The macOS service account can read System.keychain items
  # but cannot create them ("Write permissions error"), so running this command
  # as rustynetd fails closed at PlatformOsSecureStore before any usable daemon
  # key material exists. Root is the single privileged bootstrap writer; the
  # daemon remains the runtime reader through Security.framework/System.keychain.
  # Phase 24 follow-up (Gap F): rustynetd's resolve_wireguard_binary_path()
  # defaults to /usr/bin/wg, which does not exist on macOS. Homebrew installs
  # wg at ${BREW_PREFIX}/bin/wg (the launchd plist already exports
  # RUSTYNET_WG_BINARY_PATH for the daemon's runtime invocations). For the
  # bootstrap-time `key init` call we must export the same path explicitly;
  # sudo scrubs the caller environment unless the variable is passed in argv.
  if ! sudo RUSTYNET_WG_BINARY_PATH="${BREW_PREFIX}/bin/wg" \
      "${RUSTYNETD_BIN}" key init \
      --runtime-private-key "${runtime_key}" \
      --encrypted-private-key "${encrypted_key}" \
      --public-key "${public_key}" \
      --passphrase-file "${passphrase_file}" \
      --force; then
    echo "[bootstrap] rustynetd key init failed; refusing to leave plaintext key in encrypted slot" >&2
    exit 1
  fi

  # Push the passphrase into the macOS System keychain so the daemon resolves
  # it at startup (per RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT in the launchd
  # plist). The account is per-node (`wg-passphrase-${NODE_ID}`) so co-tenant
  # nodes cannot cross-read. Runs as root because the service account may not
  # create System.keychain items.
  #
  # NO --keychain-allow-any-app here. The passphrase is stored AND read by the
  # same binary: rustynetd (`key store-passphrase` as root at bootstrap, then the
  # LaunchDaemon at startup as the uid-500 service account). `key store-passphrase`
  # therefore custodies it via the owned-identity System-keychain path
  # (`SecItemAdd`), which binds read access to rustynetd's own code-signing
  # identity (Rust binaries are ad-hoc linker-signed on macOS arm64 -> stable
  # cdhash across both invocations). The same signed binary reads it back across
  # the login-session boundary, as any uid; nothing else can — not even
  # `/usr/bin/security`.
  #
  # This replaces the previous `-A` (allow-any-app) CLI path, which was the
  # actual root cause of the daemon crash-loop: on macOS 26 the `-A` item's
  # secret is gated by a code-signing partition list and is unreadable
  # cross-session even by root (observed live: `os secure store unavailable` ->
  # wg key decrypt failed -> daemon exit 65, keepalive crash-loop). The owned
  # path is strictly tighter than `-A` AND actually readable by the daemon.
  # Per-node-scoped by account (`wg-passphrase-${NODE_ID}`); OS-secure keychain
  # storage preserved — a tighter read-ACL, not a downgrade to a plaintext file.
  # (keychain_account is set at the top of this function.)
  if ! sudo "${RUSTYNETD_BIN}" key store-passphrase \
      --passphrase-file "${passphrase_file}" \
      --keychain-account "${keychain_account}"; then
    echo "[bootstrap] rustynetd key store-passphrase failed; daemon cannot resolve passphrase from keychain" >&2
    exit 1
  fi

  # Final ownership/perms tightening — defence in depth against any race
  # between key init's atomic write and a concurrent process.
  chown rustynetd:rustynetd "${encrypted_key}" "${public_key}"
  chmod 0600 "${encrypted_key}"
  chmod 0640 "${public_key}"
  # Passphrase is a bootstrap artifact in BOOTSTRAP_DIR (root:rustynetd, 0600).
  # Keep it root-owned: the cdhash re-bind path runs as root and requires
  # owner==reader for the daemon's secret-file guard.
  chown root:rustynetd "${passphrase_file}"
  chmod 0600 "${passphrase_file}"

  # Custody: remove the plaintext runtime key from the PERSISTENT keys/ dir.
  # `key init` wrote it there (root can create files under keys/), but
  # macos_key_custody forbids a plaintext private key at rest (Phase E
  # encrypted-at-rest), mirroring Linux which keeps its runtime key on tmpfs
  # (/run/rustynet/wireguard.key). The daemon re-derives the runtime key from
  # wireguard.key.enc + the keychain passphrase into the ephemeral runtime dir
  # (/private/var/run/rustynet/wireguard.key, the --wg-private-key plist arg) on
  # every start, so the at-rest copy is unnecessary and must not linger.
  secure_remove_file "${runtime_key}"

  echo "[bootstrap] WireGuard keys generated (encrypted=${encrypted_key} public=${public_key}); runtime key re-derived by daemon into the ephemeral runtime dir"
  echo "[bootstrap] WireGuard passphrase stored in macOS keychain (account=${keychain_account})"
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

  # Persist the trust signing-key passphrase into the System.keychain so the
  # daemon can re-sign trust evidence after a role switch to admin/blind_exit.
  # macOS has no Linux-style systemd-credential custody for the signing key;
  # without this the passphrase would be discarded with the temp file below and
  # `rustynet ops refresh-signed-trust` would fail closed ("macOS keychain
  # account is required"). Stored under the signing-passphrase service that
  # refresh-signed-trust resolves (matches DEFAULT_MACOS_PASSPHRASE_KEYCHAIN_SERVICE
  # in rustynet-cli), keyed per node so co-tenant nodes cannot cross-read. Runs
  # as root because the service account may not create System.keychain items.
  # --keychain-allow-any-app: the trust passphrase is stored by rustynetd but
  # read back by a different binary (`rustynet ops refresh-signed-trust` via
  # `/usr/bin/security -w`); the allow-any-application ACL lets the cross-binary
  # reader access it (the default framework ACL binds to the storing binary's
  # identity). Single-tenant service-account install layout.
  if ! sudo "${RUSTYNETD_BIN}" key store-passphrase \
      --passphrase-file "${passphrase_file}" \
      --keychain-service "rustynet.signing_passphrase" \
      --keychain-account "trust-passphrase-${NODE_ID}" \
      --keychain-allow-any-app; then
    echo "[bootstrap] rustynetd key store-passphrase (trust signing) failed; node cannot re-sign trust evidence after a role switch" >&2
    exit 1
  fi

  secure_remove_file "${passphrase_file}"

  # Secure the signing key owner-only (0600). `rustynet ops refresh-signed-trust`
  # (run as root to re-sign trust evidence after a role switch) requires the
  # signer key to be owner-only and fails closed on a group-readable key. The
  # macOS daemon never reads the signer key directly (its launchd plist carries
  # only the trust evidence + verifier key, not the signer), so dropping group
  # read does not affect daemon startup.
  chown root:rustynetd "${signing_key}"
  chmod 0600 "${signing_key}"
  # Trust evidence: root:rustynetd 0640.
  chown root:rustynetd "${trust_evidence}"
  chmod 0640 "${trust_evidence}"
  # Verifier key: world-readable.
  chown root:rustynetd "${verifier_key}"
  chmod 0644 "${verifier_key}"

  echo "[bootstrap] trust evidence seeded at ${trust_evidence}"
}

# ── Membership genesis (MAC-D4) ───────────────────────────────────────────────
# Seeds the membership owner keypair at the canonical macOS genesis location
# so the MAC-D2 fail-loud owner-pubkey read path
# (${CONFIG_ROOT}/membership.owner.key.pub, pinned by test to
# `ops_e2e::MACOS_OWNER_SIGNING_KEY_PATH`) has install provenance. The Linux
# bootstrap runs `rustynet ops e2e-bootstrap-host`, whose membership-init step
# re-seeds /etc/rustynet/membership.owner.key(.pub) on every install; the
# macOS bootstrap previously had no genesis step at all, so a fresh deploy
# could never hold an owner key and the orchestrator's membership_init stage
# failed on every macOS exit run (MAC-D4, MacCellsHarvest_2026-08-28 §8.3).
#
# Custody (mirrors the reviewed genesis drivers; nothing weakened):
#   - the owner SIGNING (private) key is written by `rustynetd membership
#     init` itself, passphrase-ENCRYPTED at rest (Argon2+XChaCha20 envelope,
#     mode 0600; the writer refuses symlinks and tightens the directory to
#     0700) — never plaintext private key material;
#   - the passphrase is generated as a bootstrap artifact in BOOTSTRAP_DIR
#     (outside keys/, so macos-key-custody-check does not flag it; 0600
#     root-owned; same atomic-write protocol as the wireguard passphrase)
#     AND is provisioned into the System.keychain under the canonical
#     membership-mutation unwrap descriptor (service
#     "signing_key_passphrase", account "membership-owner-signing-key")
#     with the same idempotent delete-then-add provisioning
#     `execute_ops_e2e_bootstrap_macos` performs;
#   - only the PUBLIC half (.pub) is world-readable — exactly the file the
#     orchestrator's membership_init stage reads back via `sudo -n cat`;
#   - the genesis snapshot/log are chowned to the daemon service account
#     after genesis (the same ownership restore
#     ops_e2e::set_membership_state_permissions_for applies after every
#     root-run membership mutation) so the launchd daemon, which runs as the
#     rustynetd service account, can persist membership log/snapshot/watermark
#     updates at runtime (the watermark itself is deliberately absent at
#     genesis and is created by the daemon on first start);
#   - fail-closed: `set -euo pipefail` aborts the whole bootstrap if any
#     genesis step fails — a node must never ship without a seeded owner key.
#
# Re-genesis per bootstrap is deliberate and mirrors Linux:
# `seed_membership_genesis` wipes the membership/ signed state immediately
# before re-seeding it (a stale epoch watermark makes the daemon reject the
# fresh genesis bundle as a replay/rollback), so the owner keypair must be
# regenerated with it,
# and `macos_install.rs`'s wholesale uninstall wipe of CONFIG_ROOT is
# repaired by the very next bootstrap rather than a one-time manual fix.
seed_membership_genesis() {
  local membership_dir="${STATE_ROOT}/membership"
  local owner_key="${CONFIG_ROOT}/membership.owner.key"
  local passphrase_file="${BOOTSTRAP_DIR}/membership-owner.passphrase"

  # Atomic passphrase write: chmod the tmpfile BEFORE writing entropy so the
  # secret bytes never appear under the default umask (same protocol as
  # generate_wireguard_keys). 32 raw bytes -> 64 hex chars, no trailing
  # newline (the keychain item must round-trip exactly the genesis bytes).
  local passphrase_tmp=""
  # shellcheck disable=SC2064
  trap 'secure_remove_file "${passphrase_tmp}"' EXIT
  passphrase_tmp="$(mktemp "${BOOTSTRAP_DIR}/membership-owner.passphrase.tmp.XXXXXX")"
  if [[ -z "${passphrase_tmp}" || ! -f "${passphrase_tmp}" ]]; then
    echo "[bootstrap] failed to create membership-owner passphrase tmpfile under ${BOOTSTRAP_DIR}" >&2
    exit 1
  fi
  chmod 0600 "${passphrase_tmp}"
  od -A n -t x1 -N 32 /dev/urandom | tr -d ' \n' > "${passphrase_tmp}"
  local passphrase_size
  passphrase_size="$(wc -c < "${passphrase_tmp}" | tr -d ' ')"
  if [[ "${passphrase_size}" -ne 64 ]]; then
    echo "[bootstrap] membership owner passphrase generation produced ${passphrase_size} bytes; expected 64" >&2
    exit 1
  fi
  chown root:wheel "${passphrase_tmp}"
  mv "${passphrase_tmp}" "${passphrase_file}"
  trap - EXIT

  # Genesis. `rustynetd membership init` generates the owner keypair,
  # persists the encrypted private half at ${owner_key} (0600) and the
  # public half at ${owner_key}.pub, and mints the single-node genesis
  # snapshot (full bootstrap capability set) the daemon starts from.
  # Fail-closed via set -e: a failed genesis aborts the install.
  #
  # MAC-D10: the stale signed-state wipe is pinned HERE — immediately before
  # `membership init` re-seeds the state — not in `clear_residual_state`.
  # A fresh (re)enrollment must not inherit a stale membership/epoch
  # watermark (the daemon rejects the fresh genesis bundle as a
  # replay/rollback and fail-closes), but a general cleanup pass that wipes
  # membership/ can strand the node with NO signed state if it ever runs
  # without the re-genesis immediately following it (observed live:
  # membership/ empty while the orchestrator's membership stage was
  # mid-flight). Pinning the wipe inside the same function that re-seeds
  # keeps the anti-rollback guarantee while making the deletion inseparable
  # from the replacement. This also clears the daemon's gossip watermark
  # spool, which lives in the same directory.
  if [[ -d "${membership_dir}" ]]; then
    find "${membership_dir}" -mindepth 1 -maxdepth 1 \
      -exec rm -rf {} + 2>/dev/null || true
  fi
  "${RUSTYNETD_BIN}" membership init \
    --snapshot "${membership_dir}/membership.snapshot" \
    --log "${membership_dir}/membership.log" \
    --watermark "${membership_dir}/membership.watermark" \
    --owner-signing-key "${owner_key}" \
    --owner-signing-key-passphrase-file "${passphrase_file}" \
    --node-id "${NODE_ID}" \
    --network-id "${NETWORK_ID}" \
    --force

  # Restore daemon-service ownership of the genesis signed state (the same
  # restore the CLI ops path applies after every root-run membership
  # mutation): the launchd daemon runs as the rustynetd service account and
  # rewrites snapshot/log/watermark as membership updates are applied.
  chown rustynetd:rustynetd \
    "${membership_dir}/membership.snapshot" \
    "${membership_dir}/membership.log"

  # Provision the canonical System.keychain item for the membership-mutation
  # unwrap path — the same provisioning contract as
  # execute_ops_e2e_bootstrap_macos's provisioner (idempotent
  # delete-then-add, argv-only, System.keychain so the item survives across
  # sessions and is reachable by root-run membership ops). The service/
  # account pair MUST match the canonical
  # rustynet_control::credential_unwrap
  # ::membership_signing_key_passphrase_descriptor.
  local passphrase_text
  passphrase_text="$(cat "${passphrase_file}")"
  /usr/bin/security delete-generic-password \
    -a membership-owner-signing-key \
    -s signing_key_passphrase \
    /Library/Keychains/System.keychain >/dev/null 2>&1 || true
  /usr/bin/security add-generic-password \
    -a membership-owner-signing-key \
    -s signing_key_passphrase \
    -w "${passphrase_text}" \
    /Library/Keychains/System.keychain
  unset passphrase_text

  # The passphrase file stays as a bootstrap artifact in BOOTSTRAP_DIR (0600,
  # root-owned — same posture as the wireguard passphrase): it is the
  # bootstrap-time material for re-provisioning the keychain item after a
  # rebuild; the daemon and the ops unwrap path resolve the passphrase from
  # the keychain descriptor, not from disk.
  chown root:rustynetd "${passphrase_file}"
  chmod 0600 "${passphrase_file}"

  # MAC-D13 parity on the orchestrator bootstrap path: seed the encrypted
  # assignment-signing secret at the macOS canonical config root so the
  # signed-bundle issuance verbs the orchestrator drives over SSH
  # (`e2e-issue-assignment-bundles-from-env` and the traversal issuer) find
  # it at genesis. This mirrors BOTH the Linux host bootstrap (whose
  # rn_bootstrap.sh runs `rustynet ops e2e-bootstrap-host`, which seeds
  # /etc/rustynet/assignment.signing.secret) and the MAC-D13 step inside
  # execute_ops_e2e_bootstrap_macos — which the Rust --node orchestrator
  # never invokes for macOS, leaving the secret unseeded and
  # distribute_assignments failing closed with "assignment signing secret
  # missing (/usr/local/etc/rustynet/assignment.signing.secret)" even on a
  # freshly rebuilt node. The secret is minted from OS randomness and
  # encrypted at rest under the same owner passphrase this genesis just
  # provisioned into System.keychain — exactly the credential the issuers
  # unwrap via MacosKeychainBackend. Custody is enforced by the verb itself
  # (persist_encrypted_secret_material: file 0600 root-owned, config root
  # 0750, ownership and modes validated before returning); --force matches
  # the per-bootstrap re-genesis above so the secret never outlives the
  # owner keypair it is bound to. Fail-closed via set -e: a failed seed
  # aborts the bootstrap, and an issuer on a node where genesis never
  # seeded the secret still errors loudly rather than skipping signing.
  "${RUSTYNET_BIN}" assignment init-signing-secret \
    --output "${CONFIG_ROOT}/assignment.signing.secret" \
    --signing-secret-passphrase-file "${passphrase_file}" \
    --force

  # The public half is the MAC-D2 read target: pin deterministic ownership
  # and mode (membership init writes it under the process umask).
  chown root:rustynetd "${owner_key}.pub"
  chmod 0644 "${owner_key}.pub"

  echo "[bootstrap] membership genesis seeded: owner key ${owner_key} (.pub published at ${owner_key}.pub), snapshot ${membership_dir}/membership.snapshot"
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
  # Lab STUN endpoint (C-STUN, BashOrchestratorRetirementProgram): an empty
  # --traversal-stun-servers disables srflx candidate gathering, so the lab
  # bootstrap threads the guest's default gateway on 3478 (the UTM host as
  # seen from this guest's subnet — a valid ip:port, which is all the daemon
  # parses). A live responder there is optional: gathering fails soft on a
  # bounded timeout. RUSTYNET_LAB_STUN_SERVERS in the bootstrap env overrides;
  # detection failure leaves the flag off, preserving prior behaviour.
  local lab_stun_servers="${RUSTYNET_LAB_STUN_SERVERS:-}"
  if [[ -z "${lab_stun_servers}" ]]; then
    local default_gw
    default_gw="$(route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}')"
    if [[ "${default_gw}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
      lab_stun_servers="${default_gw}:3478"
    fi
  fi
  local stun_flags=()
  if [[ -n "${lab_stun_servers}" ]]; then
    stun_flags=(--traversal-stun-servers "${lab_stun_servers}")
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
    --auto-tunnel-max-age-secs 86400 \
    --traversal-max-age-secs 86400 \
    --dns-zone-max-age-secs 86400 \
    ${stun_flags[@]+"${stun_flags[@]}"} \
    --wg-interface "${wg_interface}" \
    --fail-closed-ssh-allow "${ssh_allow_flag}" \
    --fail-closed-ssh-allow-cidrs "${SSH_ALLOW_CIDRS:-}"
}

# ── Read-only prerequisite dry run (AQ-11 testability hook) ──────────────────
# RUSTYNET_BOOTSTRAP_PREREQ_CHECK_ONLY=1 resolves the prerequisite phases
# (PATH + Homebrew detection — both read-only when brew is absent) and exits
# BEFORE any system change. Used by operators/orchestrators to pre-flight a
# host, and by the AQ-11 witnesses to prove the Homebrew-absent refusal
# without running a real install.
#
# AQ-11 F6 (scope note, not a mitigation): this check runs AFTER the env-file
# is sourced above, so an env file is arbitrary shell executed as root even
# in this dry run — PREREQ_CHECK_ONLY narrows what the run DOES, not what the
# env file can do. The env file must be provisioned with the same care as the
# payload (it arrives over the same orchestrator channel).
if [[ "${RUSTYNET_BOOTSTRAP_PREREQ_CHECK_ONLY:-0}" == "1" ]]; then
  echo "[bootstrap] PREREQ_CHECK_ONLY=1: read-only prerequisite check; no system changes will be made"
  setup_bootstrap_path
  ensure_homebrew
  echo "[bootstrap] PREREQ_CHECK_ONLY: prerequisites resolvable (Homebrew at ${BREW_PREFIX})"
  exit 0
fi

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
  # Phase 24 follow-up (Gap G): generate_wireguard_keys and the install
  # script both reference ${BREW_PREFIX}; without setup_bootstrap_path the
  # variable is empty and `${BREW_PREFIX}/bin/wg` collapses to `/bin/wg`,
  # which does not exist on macOS. Resolve BREW_PREFIX here so the SKIP_BUILD
  # path runs with the same brew_prefix the full-install path would.
  for _bp in /opt/homebrew /usr/local; do
    if [[ -x "${_bp}/bin/brew" ]]; then
      BREW_PREFIX="${_bp}"
      break
    fi
  done
  if [[ -z "${BREW_PREFIX}" ]]; then
    echo "[bootstrap] SKIP_BUILD=1: brew not found at /opt/homebrew or /usr/local" >&2
    exit 1
  fi
  ensure_rustynetd_user
  setup_directories
  clear_residual_state
  ensure_system_keychain_unlocked
  generate_wireguard_keys
  provision_enrollment_secret
  seed_trust_evidence
  seed_membership_genesis
  install_launchd_service
else
  install_prereqs
  ensure_rustynetd_user
  setup_directories
  clear_residual_state
  build_rustynet
  install_binaries
  ensure_system_keychain_unlocked
  generate_wireguard_keys
  provision_enrollment_secret
  seed_trust_evidence
  seed_membership_genesis
  install_launchd_service
fi

echo "[bootstrap] macOS Rustynet install complete"
echo "[bootstrap]   rustynetd: ${RUSTYNETD_BIN} ($(${RUSTYNETD_BIN} --version 2>/dev/null || echo 'version unavailable'))"
echo "[bootstrap]   service:   launchctl print system/com.rustynet.daemon"
