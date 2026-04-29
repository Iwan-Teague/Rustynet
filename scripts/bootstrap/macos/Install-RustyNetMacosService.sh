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
#     --node-id <id>
#     --node-role <role>
#     --network-id <id>

set -euo pipefail

# ── Argument parsing ─────────────────────────────────────────────────────────
RUSTYNETD_BIN="/usr/local/bin/rustynetd"
STATE_ROOT="/usr/local/var/rustynet"
LOG_DIR="/usr/local/var/log/rustynet"
PLIST_DST="/Library/LaunchDaemons/com.rustynet.daemon.plist"
NODE_ID=""
NODE_ROLE=""
NETWORK_ID=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rustynetd-bin) RUSTYNETD_BIN="$2"; shift 2 ;;
    --state-root)    STATE_ROOT="$2";    shift 2 ;;
    --log-dir)       LOG_DIR="$2";       shift 2 ;;
    --plist-dst)     PLIST_DST="$2";     shift 2 ;;
    --node-id)       NODE_ID="$2";       shift 2 ;;
    --node-role)     NODE_ROLE="$2";     shift 2 ;;
    --network-id)    NETWORK_ID="$2";    shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "${NODE_ID}" || -z "${NODE_ROLE}" ]]; then
  echo "error: --node-id and --node-role are required" >&2
  exit 2
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
        <string>--wg-encrypted-private-key</string>
        <string>${STATE_ROOT}/keys/wireguard.key.enc</string>
        <string>--wg-public-key</string>
        <string>${STATE_ROOT}/keys/wireguard.pub</string>
        <string>--backend</string>
        <string>macos-wireguard</string>
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
        <key>RUSTYNET_NODE_ROLE</key>
        <string>${NODE_ROLE}</string>
        <key>RUSTYNET_NETWORK_ID</key>
        <string>${NETWORK_ID}</string>
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

echo "[install-service] com.rustynet.daemon loaded via launchctl bootstrap"
