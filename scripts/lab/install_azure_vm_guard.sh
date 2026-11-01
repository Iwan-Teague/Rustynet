#!/usr/bin/env bash
# Install (or refresh) the hourly Azure lab VM guard as a macOS user LaunchAgent.
#
# launchd jobs cannot read ~/Desktop (macOS privacy protection), so the runnable
# copies live in ~/rustysuite-fleet/bin; this script is the tracked source of
# truth and re-running it after any edit refreshes them. Remove the job with:
#   launchctl bootout gui/$(id -u)/com.rustysuite.azure-vm-guard
#   rm ~/Library/LaunchAgents/com.rustysuite.azure-vm-guard.plist
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/rustysuite-fleet/bin"
STATE="$HOME/rustysuite-fleet/state"
LABEL="com.rustysuite.azure-vm-guard"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
mkdir -p "$DEST" "$STATE"
for f in azure_vm_guard.sh azure_vm_up.sh azure_vm_down.sh; do
  cp "$HERE/$f" "$DEST/$f.new" && chmod 755 "$DEST/$f.new" && mv -f "$DEST/$f.new" "$DEST/$f"
done
cat > "$PLIST" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>/bin/bash</string><string>$DEST/azure_vm_guard.sh</string></array>
  <key>StartInterval</key><integer>3600</integer>
  <key>RunAtLoad</key><true/>
  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
  <key>StandardOutPath</key><string>$STATE/azure-guard.launchd.out</string>
  <key>StandardErrorPath</key><string>$STATE/azure-guard.launchd.err</string>
</dict>
</plist>
PL
plutil -lint "$PLIST" >/dev/null
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "installed: hourly guard ($LABEL); scripts in $DEST; log $STATE/azure-guard.log"
