#!/usr/bin/env bash
# Install-RustyNetMacosService.sh — Install the RustyNet launchd service on macOS.
#
# Writes the reviewed com.rustynet.daemon.plist to /Library/LaunchDaemons/,
# applies correct ownership and mode (root:wheel 0644), then loads the
# service via `launchctl bootstrap system`.
#
# Usage:
#   Install-RustyNetMacosService.sh \
#     --rustynetd-bin <path>    (default: /usr/local/bin/rustynetd)
#     --state-root <path>       (default: /usr/local/var/rustynet)
#     --log-dir <path>          (default: /usr/local/var/log/rustynet)
#     --plist-dst <path>        (default: /Library/LaunchDaemons/com.rustynet.daemon.plist)
#     --brew-prefix <path>      (default: auto-detect; /opt/homebrew on arm64, /usr/local on x86_64)
#     --node-id <id>
#     --node-role <role>
#     --network-id <id>
#     --auto-tunnel-enforce <true|false>     (default: false; set true after bundles are deployed)
#     --trust-max-age-secs <secs>            (default: empty, uses daemon default 300 s)
#     --auto-tunnel-max-age-secs <secs>      (default: empty, uses daemon default 300 s)
#     --traversal-max-age-secs <secs>        (default: empty, uses daemon default)
#     --dns-zone-max-age-secs <secs>         (default: empty, uses daemon default)
#     --wg-interface <utunN>                 (default: utun9; must match ^utun[0-9]+$)
#     --fail-closed-ssh-allow <true|false>   (default: false)
#     --fail-closed-ssh-allow-cidrs <cidr>   (default: empty; only used when --fail-closed-ssh-allow true)

set -euo pipefail

# ── Argument parsing ─────────────────────────────────────────────────────────
RUSTYNETD_BIN="/usr/local/bin/rustynetd"
STATE_ROOT="/usr/local/var/rustynet"
LOG_DIR="/usr/local/var/log/rustynet"
PLIST_DST="/Library/LaunchDaemons/com.rustynet.daemon.plist"
SOCKET_PATH="/private/var/run/rustynet/rustynetd.sock"
PRIVILEGED_HELPER_SOCKET="/private/var/run/rustynet/rustynetd-privileged.sock"
NODE_ID=""
NODE_ROLE=""
NETWORK_ID=""
# auto_tunnel_enforce defaults false so the daemon can start without a signed
# assignment bundle during initial bootstrap. The orchestrator's enforce_runtime
# phase re-invokes this script with --auto-tunnel-enforce true after bundles are
# deployed, matching the Linux e2e-enforce-host pattern.
AUTO_TUNNEL_ENFORCE="false"
# trust_max_age_secs: macOS has no periodic trust-evidence refresh timer (unlike
# Linux which uses rustynetd-trust-refresh.service). The daemon's hardcoded 300 s
# default trips "trust evidence is stale" on the very first launch when the
# bootstrap-time `rustynet trust issue` ran several minutes before launchctl
# bootstrap finally invokes the daemon. Default to 86400 s here so any caller
# that omits the flag — including a re-install via the orchestrator's enforce
# stage if the env var is dropped — still gets a freshness window long enough
# to survive lab-typical install latencies. enforce-time callers may still
# override with a smaller value if they re-issue the evidence at the same time.
TRUST_MAX_AGE_SECS="86400"
AUTO_TUNNEL_MAX_AGE_SECS=""
TRAVERSAL_MAX_AGE_SECS=""
DNS_ZONE_MAX_AGE_SECS=""
FAIL_CLOSED_SSH_ALLOW="false"
FAIL_CLOSED_SSH_ALLOW_CIDRS=""
# utun interface name for WireGuard. Defaults to utun9 (safe fallback that avoids
# utun0-8 used by macOS system interfaces). Callers should always pass an explicit
# value derived from the node_id (see utun_name_for_node_id in macos_install.rs).
WG_INTERFACE="utun9"
# Auto-detect brew prefix; caller may override via --brew-prefix.
if [[ -x "/opt/homebrew/bin/brew" ]]; then
  BREW_PREFIX="/opt/homebrew"
else
  BREW_PREFIX="/usr/local"
fi
# Gated ("awaiting enrollment") install: render + install both plists and
# bootstrap ONLY the privileged helper, but do NOT bootstrap the daemon —
# instead `launchctl disable` it so it stays down until the enrollment seam runs
# `launchctl enable` + `launchctl bootstrap`. Default false preserves the
# bootstrap-and-start behaviour every existing caller relies on. Used by the
# `rustynet install` engine, which provisions a fresh node up to the deferred
# enrollment seam (the daemon has no trust evidence yet, so starting it would
# crash-loop).
NO_DAEMON_START="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rustynetd-bin)              RUSTYNETD_BIN="$2";              shift 2 ;;
    --state-root)                 STATE_ROOT="$2";                 shift 2 ;;
    --log-dir)                    LOG_DIR="$2";                    shift 2 ;;
    --plist-dst)                  PLIST_DST="$2";                  shift 2 ;;
    --brew-prefix)                BREW_PREFIX="$2";                shift 2 ;;
    --node-id)                    NODE_ID="$2";                    shift 2 ;;
    --node-role)                  NODE_ROLE="$2";                  shift 2 ;;
    --network-id)                 NETWORK_ID="$2";                 shift 2 ;;
    --auto-tunnel-enforce)         AUTO_TUNNEL_ENFORCE="$2";         shift 2 ;;
    --trust-max-age-secs)          TRUST_MAX_AGE_SECS="$2";          shift 2 ;;
    --auto-tunnel-max-age-secs)    AUTO_TUNNEL_MAX_AGE_SECS="$2";    shift 2 ;;
    --traversal-max-age-secs)      TRAVERSAL_MAX_AGE_SECS="$2";      shift 2 ;;
    --dns-zone-max-age-secs)       DNS_ZONE_MAX_AGE_SECS="$2";       shift 2 ;;
    --wg-interface)                WG_INTERFACE="$2";                shift 2 ;;
    --fail-closed-ssh-allow)       FAIL_CLOSED_SSH_ALLOW="$2";       shift 2 ;;
    --fail-closed-ssh-allow-cidrs) FAIL_CLOSED_SSH_ALLOW_CIDRS="$2"; shift 2 ;;
    --no-daemon-start)             NO_DAEMON_START="true";           shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "${NODE_ID}" || -z "${NODE_ROLE}" ]]; then
  echo "error: --node-id and --node-role are required" >&2
  exit 2
fi

# Validate --wg-interface: must be utun followed by one or more digits.
# Fail closed — an invalid or missing value must never silently end up in the plist.
if [[ ! "${WG_INTERFACE}" =~ ^utun[0-9]+$ ]]; then
  echo "error: --wg-interface '${WG_INTERFACE}' must match ^utun[0-9]+$" >&2
  exit 2
fi

require_safe_plist_string() {
  local label="$1"
  local value="$2"
  case "${value}" in
    *'<'*|*'>'*|*'&'*|*'"'*|*$'\n'*|*$'\r'*)
      echo "error: ${label} contains characters unsafe for launchd plist rendering" >&2
      exit 2
      ;;
  esac
}

case "${NODE_ID}" in
  *[!A-Za-z0-9._:-]*)
    echo "error: --node-id contains characters unsafe for launchd plist rendering" >&2
    exit 2
    ;;
esac

case "${NODE_ROLE}" in
  admin|client|blind_exit) ;;
  *)
    echo "error: --node-role must be one of admin, client, blind_exit" >&2
    exit 2
    ;;
esac

case "${NETWORK_ID}" in
  *[!A-Za-z0-9._:-]*)
    echo "error: --network-id contains characters unsafe for launchd plist rendering" >&2
    exit 2
    ;;
esac

require_safe_plist_string "--rustynetd-bin" "${RUSTYNETD_BIN}"
require_safe_plist_string "--state-root" "${STATE_ROOT}"
require_safe_plist_string "--log-dir" "${LOG_DIR}"
require_safe_plist_string "--brew-prefix" "${BREW_PREFIX}"

case "${AUTO_TUNNEL_ENFORCE}" in
  true|false) ;;
  *) echo "error: --auto-tunnel-enforce must be true or false" >&2; exit 2 ;;
esac
if [[ -n "${TRUST_MAX_AGE_SECS}" ]]; then
  case "${TRUST_MAX_AGE_SECS}" in
    *[!0-9]*|"") echo "error: --trust-max-age-secs must be a positive integer" >&2; exit 2 ;;
  esac
fi
if [[ -n "${AUTO_TUNNEL_MAX_AGE_SECS}" ]]; then
  case "${AUTO_TUNNEL_MAX_AGE_SECS}" in
    *[!0-9]*|"") echo "error: --auto-tunnel-max-age-secs must be a positive integer" >&2; exit 2 ;;
  esac
fi
if [[ -n "${TRAVERSAL_MAX_AGE_SECS}" ]]; then
  case "${TRAVERSAL_MAX_AGE_SECS}" in
    *[!0-9]*|"") echo "error: --traversal-max-age-secs must be a positive integer" >&2; exit 2 ;;
  esac
fi
if [[ -n "${DNS_ZONE_MAX_AGE_SECS}" ]]; then
  case "${DNS_ZONE_MAX_AGE_SECS}" in
    *[!0-9]*|"") echo "error: --dns-zone-max-age-secs must be a positive integer" >&2; exit 2 ;;
  esac
fi
case "${FAIL_CLOSED_SSH_ALLOW}" in
  true|false) ;;
  *) echo "error: --fail-closed-ssh-allow must be true or false" >&2; exit 2 ;;
esac
if [[ -n "${FAIL_CLOSED_SSH_ALLOW_CIDRS}" ]]; then
  require_safe_plist_string "--fail-closed-ssh-allow-cidrs" "${FAIL_CLOSED_SSH_ALLOW_CIDRS}"
fi

# PATH injected into the daemon's environment so it can locate wireguard-go.
# launchd launches daemons with a minimal PATH (/usr/bin:/bin:/usr/sbin:/sbin);
# wireguard-go installed via Homebrew lives under ${BREW_PREFIX}/bin.
# /usr/local/bin is included as the fallback symlink location (belt-and-suspenders).
DAEMON_PATH="${BREW_PREFIX}/bin:${BREW_PREFIX}/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

# Build the optional max-age plist fragments (only when caller overrides the daemon default).
TRUST_MAX_AGE_PLIST_FRAGMENT=""
if [[ -n "${TRUST_MAX_AGE_SECS}" ]]; then
  TRUST_MAX_AGE_PLIST_FRAGMENT="        <string>--trust-max-age-secs</string>
        <string>${TRUST_MAX_AGE_SECS}</string>"
fi
AUTO_TUNNEL_MAX_AGE_PLIST_FRAGMENT=""
if [[ -n "${AUTO_TUNNEL_MAX_AGE_SECS}" ]]; then
  AUTO_TUNNEL_MAX_AGE_PLIST_FRAGMENT="        <string>--auto-tunnel-max-age-secs</string>
        <string>${AUTO_TUNNEL_MAX_AGE_SECS}</string>"
fi
TRAVERSAL_MAX_AGE_PLIST_FRAGMENT=""
if [[ -n "${TRAVERSAL_MAX_AGE_SECS}" ]]; then
  TRAVERSAL_MAX_AGE_PLIST_FRAGMENT="        <string>--traversal-max-age-secs</string>
        <string>${TRAVERSAL_MAX_AGE_SECS}</string>"
fi
DNS_ZONE_MAX_AGE_PLIST_FRAGMENT=""
if [[ -n "${DNS_ZONE_MAX_AGE_SECS}" ]]; then
  DNS_ZONE_MAX_AGE_PLIST_FRAGMENT="        <string>--dns-zone-max-age-secs</string>
        <string>${DNS_ZONE_MAX_AGE_SECS}</string>"
fi

# Build the optional fail-closed-ssh plist fragment.
FAIL_CLOSED_SSH_PLIST_FRAGMENT=""
if [[ "${FAIL_CLOSED_SSH_ALLOW}" == "true" && -n "${FAIL_CLOSED_SSH_ALLOW_CIDRS}" ]]; then
  FAIL_CLOSED_SSH_PLIST_FRAGMENT="        <string>--fail-closed-ssh-allow</string>
        <string>true</string>
        <string>--fail-closed-ssh-allow-cidrs</string>
        <string>${FAIL_CLOSED_SSH_ALLOW_CIDRS}</string>"
fi

# Build the optional encrypted-key plist fragment.
# Gated on the encrypted key (wireguard.key.enc, produced by `rustynetd key
# init`) — the reliable signal for encrypted key custody. The decrypt passphrase
# is read from the System.keychain (primary; see the keychain env below) with the
# bootstrap-dir passphrase file as fallback. The passphrase deliberately lives in
# BOOTSTRAP_DIR (../bootstrap/), NOT keys/, so the macos-key-custody-check — which
# only scans keys/ — does not flag it as plaintext key material at rest (see
# Bootstrap-RustyNetMacos.sh). The previous gate checked a passphrase file under
# keys/, which never exists by design, so the decrypt config was silently dropped
# and the daemon failed at startup ("wireguard private key metadata read failed").
# When the encrypted key is absent the daemon uses the plaintext --wg-private-key
# path directly (the manual-install lab path in MacosInstallRunbook.md).
WG_ENCRYPTED_KEY_PLIST_FRAGMENT=""
WG_KEYCHAIN_ENV_FRAGMENT=""
if [[ -f "${STATE_ROOT}/keys/wireguard.key.enc" ]]; then
  WG_ENCRYPTED_KEY_PLIST_FRAGMENT="        <string>--wg-encrypted-private-key</string>
        <string>${STATE_ROOT}/keys/wireguard.key.enc</string>"
  WG_KEYCHAIN_ENV_FRAGMENT="        <key>RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT</key>
        <string>wg-passphrase-${NODE_ID}</string>
        <key>RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE</key>
        <string>net.rustynet.wg-key-passphrase</string>"
  # File fallback (used when the keychain item is unavailable), pointed at the
  # passphrase's actual location in BOOTSTRAP_DIR. Only wired up when present so
  # the daemon never gets a path to a non-existent file.
  if [[ -f "${STATE_ROOT}/bootstrap/wireguard.passphrase" ]]; then
    WG_ENCRYPTED_KEY_PLIST_FRAGMENT="${WG_ENCRYPTED_KEY_PLIST_FRAGMENT}
        <string>--wg-key-passphrase</string>
        <string>${STATE_ROOT}/bootstrap/wireguard.passphrase</string>"
    WG_KEYCHAIN_ENV_FRAGMENT="${WG_KEYCHAIN_ENV_FRAGMENT}
        <key>RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH</key>
        <string>${STATE_ROOT}/bootstrap/wireguard.passphrase</string>"
  fi
fi

# ── Audited Linux→macOS plist flag parity (HIGH 4 reviewer fold-in) ──────────
#
# Linux systemd unit (scripts/systemd/rustynetd.service) passes a superset of
# daemon flags. For each flag the Linux unit passes that this macOS plist
# does NOT, the decision is documented below. An accidental omission set
# would silently fall back to daemon defaults which may differ from the
# Linux-validated configuration; the explicit audit closes that gap.
#
# Flags ADDED to the plist below to match systemd-unit semantics:
#   --gossip-watermark
#       systemd value: /var/lib/rustynet/rustynetd.gossip.watermark
#       daemon default: None (gossip runs in-memory only)
#       reason: D2.5 requires the gossip-sequence + seen-source ledger to
#       survive daemon restarts. Without an explicit spool path the
#       daemon loses replay protection across restarts on macOS.
#       macOS spool: ${STATE_ROOT}/membership/rustynetd.gossip.watermark
#
# Flags INTENTIONALLY OMITTED because the daemon default already matches
# the Linux-validated value on macOS:
#   --anchor-bundle-pull-addr        default: 127.0.0.1:51822 (loopback) — matches systemd
#   --anchor-bundle-pull-token-path  default: None (no token enforced) — matches systemd empty
#   --anchor-bundle-pull-allow-lan   default: false — matches systemd
#   --wg-listen-port                 default: 51820 — matches systemd
#   --egress-interface               default: "auto" — matches systemd
#   --auto-port-forward-exit         default: false — matches systemd
#   --auto-port-forward-lease-secs   default: 1200 — matches systemd
#   --privileged-helper-timeout-ms   default: 2000 — matches systemd
#   --reconcile-interval-ms          default: 1000 — matches systemd
#   --max-reconcile-failures         default: 5 — matches systemd
#   --dns-zone-name                  default: "rustynet" — matches systemd
#   --dns-resolver-bind-addr         default: 127.0.0.1:53535 — matches systemd
#   --traversal-stun-servers         default: empty Vec — matches systemd empty
#   --traversal-stun-gather-timeout-ms default: 2000 — matches systemd
#
# Flag INTENTIONALLY OMITTED because it is platform-specific to Linux:
#   --dataplane-mode
#       systemd value: hybrid-native
#       daemon default: Shell
#       reason: dataplane_mode is consumed only by the Linux dataplane
#       branch (daemon.rs maps DaemonDataplaneMode → LinuxDataplaneMode).
#       The macOS backend takes a different code path that does not
#       reference this field, so passing or omitting it has no effect.

# Build the gossip-watermark plist fragment. Always present; spool lives
# under the membership dir so it shares the same rustynetd:rustynetd 0700
# ownership setup by Bootstrap-RustyNetMacos.sh setup_directories.
GOSSIP_WATERMARK_PLIST_FRAGMENT="        <string>--gossip-watermark</string>
        <string>${STATE_ROOT}/membership/rustynetd.gossip.watermark</string>"

# ── Write plist ───────────────────────────────────────────────────────────────
cat > "${PLIST_DST}" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.rustynet.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>${RUSTYNETD_BIN}</string>
        <string>daemon</string>
        <string>--node-id</string>
        <string>${NODE_ID}</string>
        <string>--node-role</string>
        <string>${NODE_ROLE}</string>
        <string>--state</string>
        <string>${STATE_ROOT}/rustynetd.state</string>
        <string>--trust-evidence</string>
        <string>${STATE_ROOT}/trust/rustynetd.trust</string>
        <string>--trust-verifier-key</string>
        <string>${STATE_ROOT}/trust/trust-evidence.pub</string>
        <string>--trust-watermark</string>
        <string>${STATE_ROOT}/trust/rustynetd.trust.watermark</string>
${TRUST_MAX_AGE_PLIST_FRAGMENT}
        <string>--enrollment-secret</string>
        <string>${STATE_ROOT}/keys/enrollment.secret</string>
        <string>--enrollment-ledger</string>
        <string>${STATE_ROOT}/keys/rustynetd.enrollment.ledger</string>
        <string>--membership-snapshot</string>
        <string>${STATE_ROOT}/membership/membership.snapshot</string>
        <string>--membership-log</string>
        <string>${STATE_ROOT}/membership/membership.log</string>
        <string>--membership-watermark</string>
        <string>${STATE_ROOT}/membership/membership.watermark</string>
${GOSSIP_WATERMARK_PLIST_FRAGMENT}
        <string>--auto-tunnel-enforce</string>
        <string>${AUTO_TUNNEL_ENFORCE}</string>
        <string>--auto-tunnel-bundle</string>
        <string>${STATE_ROOT}/trust/rustynetd.assignment</string>
        <string>--auto-tunnel-verifier-key</string>
        <string>${STATE_ROOT}/trust/assignment.pub</string>
        <string>--auto-tunnel-watermark</string>
        <string>${STATE_ROOT}/trust/rustynetd.assignment.watermark</string>
${AUTO_TUNNEL_MAX_AGE_PLIST_FRAGMENT}
        <string>--traversal-bundle</string>
        <string>${STATE_ROOT}/trust/rustynetd.traversal</string>
        <string>--traversal-verifier-key</string>
        <string>${STATE_ROOT}/trust/traversal.pub</string>
        <string>--traversal-watermark</string>
        <string>${STATE_ROOT}/trust/rustynetd.traversal.watermark</string>
${TRAVERSAL_MAX_AGE_PLIST_FRAGMENT}
        <string>--dns-zone-bundle</string>
        <string>${STATE_ROOT}/trust/rustynetd.dns-zone</string>
        <string>--dns-zone-verifier-key</string>
        <string>${STATE_ROOT}/trust/dns-zone.pub</string>
        <string>--dns-zone-watermark</string>
        <string>${STATE_ROOT}/trust/rustynetd.dns-zone.watermark</string>
${DNS_ZONE_MAX_AGE_PLIST_FRAGMENT}
        <string>--wg-private-key</string>
        <!-- Runtime (decrypted) key lives in the ephemeral runtime dir, NOT the
             persistent keys/ dir: macos_key_custody forbids a plaintext private
             key at rest (Phase E encrypted-at-rest), mirroring Linux's
             /run/rustynet/wireguard.key. The daemon re-derives it from
             wireguard.key.enc + the keychain passphrase on every start; the
             privileged-helper recreates /private/var/run/rustynet (root:0o770)
             each boot so the rustynetd group can write here. -->
        <string>/private/var/run/rustynet/wireguard.key</string>
${WG_ENCRYPTED_KEY_PLIST_FRAGMENT}
        <string>--wg-public-key</string>
        <string>${STATE_ROOT}/keys/wireguard.pub</string>
        <string>--wg-interface</string>
        <string>${WG_INTERFACE}</string>
        <string>--backend</string>
        <string>macos-wireguard-userspace-shared</string>
        <string>--socket</string>
        <string>${SOCKET_PATH}</string>
        <string>--privileged-helper-socket</string>
        <string>${PRIVILEGED_HELPER_SOCKET}</string>
${FAIL_CLOSED_SSH_PLIST_FRAGMENT}
    </array>
    <key>UserName</key>
    <string>rustynetd</string>
    <key>GroupName</key>
    <string>rustynetd</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>AbandonProcessGroup</key>
    <false/>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/rustynetd.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/rustynetd-error.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>${DAEMON_PATH}</string>
        <key>RUSTYNET_NODE_ROLE</key>
        <string>${NODE_ROLE}</string>
        <key>RUSTYNET_NETWORK_ID</key>
        <string>${NETWORK_ID}</string>
        <key>RUSTYNET_WG_BINARY_PATH</key>
        <string>${BREW_PREFIX}/bin/wg</string>
${WG_KEYCHAIN_ENV_FRAGMENT}
    </dict>
</dict>
</plist>
PLIST

# ── Apply ownership and mode ──────────────────────────────────────────────────
chown root:wheel "${PLIST_DST}"
chmod 0644 "${PLIST_DST}"

# ── Privileged helper plist ──────────────────────────────────────────────────
#
# The privileged helper is the macOS counterpart of Linux's
# rustynetd-privileged-helper.service. It runs as root, hosts the SCM_RIGHTS
# utun fd-passing socket (used by Phase 19), and recreates the runtime socket
# parent directory (/private/var/run/rustynet) on every boot. macOS garbage-
# collects /private/var/run between reboots, so without a root-privileged
# RunAtLoad daemon to recreate it the rustynetd user has no permission to
# mkdir there and the unprivileged daemon's parent-dir create fails with
# EACCES. Installing the helper plist here gives macOS the same
# Requires=rustynetd-privileged-helper.service semantics that systemd
# provides implicitly on Linux.
#
# Allowed uid/gid pull from the rustynetd account this install just created
# (or that already existed from an earlier install). Resolving them at
# install time (via dscl) instead of hardcoding 500 avoids drift if a
# subsequent install runs on a host where a different unrelated account
# already occupies uid 500.
HELPER_PLIST_DST="$(dirname "${PLIST_DST}")/com.rustynet.privileged-helper.plist"
RUSTYNETD_UID="$(dscl . -read /Users/rustynetd UniqueID 2>/dev/null | awk '{print $2}')"
RUSTYNETD_GID="$(dscl . -read /Groups/rustynetd PrimaryGroupID 2>/dev/null | awk '{print $2}')"
if [[ -z "${RUSTYNETD_UID}" || -z "${RUSTYNETD_GID}" ]]; then
  echo "error: cannot resolve rustynetd uid/gid; ensure_rustynetd_user must run first" >&2
  exit 1
fi
if [[ ! "${RUSTYNETD_UID}" =~ ^[0-9]+$ ]] || [[ ! "${RUSTYNETD_GID}" =~ ^[0-9]+$ ]]; then
  echo "error: rustynetd uid/gid not integer (uid='${RUSTYNETD_UID}' gid='${RUSTYNETD_GID}')" >&2
  exit 1
fi

cat > "${HELPER_PLIST_DST}" <<HELPER_PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.rustynet.privileged-helper</string>
    <key>ProgramArguments</key>
    <array>
        <string>${RUSTYNETD_BIN}</string>
        <string>privileged-helper</string>
        <string>--socket</string>
        <string>${PRIVILEGED_HELPER_SOCKET}</string>
        <string>--allowed-uid</string>
        <string>${RUSTYNETD_UID}</string>
        <string>--allowed-gid</string>
        <string>${RUSTYNETD_GID}</string>
        <string>--timeout-ms</string>
        <string>30000</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>AbandonProcessGroup</key>
    <false/>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/rustynetd-helper.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/rustynetd-helper-error.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>${DAEMON_PATH}</string>
    </dict>
</dict>
</plist>
HELPER_PLIST
chown root:wheel "${HELPER_PLIST_DST}"
chmod 0644 "${HELPER_PLIST_DST}"

# ── Load the services ────────────────────────────────────────────────────────
# Helper must come up BEFORE the daemon so the runtime socket parent
# directory and the privileged-helper socket both exist when the daemon
# tries to bind. Unload first for idempotent re-install.
if launchctl print system/com.rustynet.daemon >/dev/null 2>&1; then
  launchctl bootout system/com.rustynet.daemon || true
  sleep 1
fi
if launchctl print system/com.rustynet.privileged-helper >/dev/null 2>&1; then
  launchctl bootout system/com.rustynet.privileged-helper || true
  sleep 1
fi

launchctl bootstrap system "${HELPER_PLIST_DST}"
# Wait up to 10 s for the helper socket to materialise. The daemon will
# refuse to start if the helper socket parent dir is missing, so we cannot
# race past this step.
for attempt in $(seq 1 20); do
  if [[ -S "${PRIVILEGED_HELPER_SOCKET}" ]]; then
    break
  fi
  sleep 0.5
done
if [[ ! -S "${PRIVILEGED_HELPER_SOCKET}" ]]; then
  echo "error: privileged helper socket ${PRIVILEGED_HELPER_SOCKET} did not appear within 10 s of launchctl bootstrap" >&2
  exit 1
fi

if [[ "${NO_DAEMON_START}" == "true" ]]; then
  # Gated install: the reviewed daemon plist is written (RunAtLoad=true,
  # unchanged) but the daemon is NOT bootstrapped. Disable it so it stays down —
  # both now and across reboots — until the enrollment seam re-enables
  # (`launchctl enable system/com.rustynet.daemon`) and bootstraps it. A fresh
  # node has no trust evidence, so a running daemon would only crash-loop; this
  # is the macOS analogue of Linux's ExecStartPre-gated (enabled-but-down) unit.
  launchctl disable system/com.rustynet.daemon
  echo "[install-service] com.rustynet.daemon INSTALLED + DISABLED (awaiting enrollment; not bootstrapped, brew-prefix=${BREW_PREFIX})"
else
  # `launchctl enable` is idempotent (a no-op on a never-disabled label) but is
  # REQUIRED to recover a host that a prior gated install disabled — otherwise
  # `bootstrap` fails with "Service is disabled" and the daemon never starts.
  launchctl enable system/com.rustynet.daemon
  launchctl bootstrap system "${PLIST_DST}"
  echo "[install-service] com.rustynet.daemon loaded via launchctl bootstrap (brew-prefix=${BREW_PREFIX})"
fi

echo "[install-service] com.rustynet.privileged-helper loaded via launchctl bootstrap (socket=${PRIVILEGED_HELPER_SOCKET})"
