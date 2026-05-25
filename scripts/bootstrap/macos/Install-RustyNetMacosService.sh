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
# Linux which uses rustynetd-trust-refresh.service).  Bootstrap-phase and initial
# invocations should use a short value; enforce_runtime should pass 86400 so the
# once-issued lab evidence stays valid for the duration of the run.
TRUST_MAX_AGE_SECS=""
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
# Only included when wireguard.passphrase exists (produced by `rustynetd key init`).
# When absent the daemon uses the plaintext --wg-private-key path directly;
# this is expected on nodes bootstrapped without full key-custody setup (e.g.
# the manual-install lab path in MacosInstallRunbook.md).
WG_ENCRYPTED_KEY_PLIST_FRAGMENT=""
WG_KEYCHAIN_ENV_FRAGMENT=""
if [[ -f "${STATE_ROOT}/keys/wireguard.passphrase" ]]; then
  WG_ENCRYPTED_KEY_PLIST_FRAGMENT="        <string>--wg-encrypted-private-key</string>
        <string>${STATE_ROOT}/keys/wireguard.key.enc</string>
        <string>--wg-key-passphrase</string>
        <string>${STATE_ROOT}/keys/wireguard.passphrase</string>"
  WG_KEYCHAIN_ENV_FRAGMENT="        <key>RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT</key>
        <string>wg-passphrase-${NODE_ID}</string>
        <key>RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE</key>
        <string>net.rustynet.wg-key-passphrase</string>
        <key>RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH</key>
        <string>${STATE_ROOT}/keys/wireguard.passphrase</string>"
fi

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
        <string>${STATE_ROOT}/keys/wireguard.key</string>
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

# ── Load the service ──────────────────────────────────────────────────────────
# Unload first if already registered (idempotent re-install).
if launchctl print system/com.rustynet.daemon >/dev/null 2>&1; then
  launchctl bootout system/com.rustynet.daemon || true
  sleep 1
fi

launchctl bootstrap system "${PLIST_DST}"

echo "[install-service] com.rustynet.daemon loaded via launchctl bootstrap (brew-prefix=${BREW_PREFIX})"
