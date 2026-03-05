# macOS `launchd` Service Management

This document defines the hardened macOS service lifecycle for Rustynet runtime processes.

## Labels and Plists

- Daemon label: `com.rustynet.rustynetd`
- Helper label: `com.rustynet.rustynetd-privileged`
- Daemon plist path: `~/Library/LaunchAgents/com.rustynet.rustynetd.plist`
- Helper plist path: `/Library/LaunchDaemons/com.rustynet.rustynetd-privileged.plist`

`start.sh` generates and installs both plists with fixed `ProgramArguments` and explicit environment variables for binary paths and passphrase-source contract.

## Security Properties

- Privileged helper runs as root via LaunchDaemon.
- Helper command path (`rustynetd`) and all privileged tool binaries (`wg`, `wireguard-go`, `ifconfig`, `route`, `pfctl`, `kill`) are validated as:
  - absolute path
  - root-owned
  - executable
- Daemon passphrase source is explicit through:
  - `RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH=<configured macOS path>`
- No manual `sudo -b` background process orchestration is used in the normal start/stop path.

## Lifecycle Commands

Start/restart flow (used by `./start.sh`):

1. Install/update launchd plist files.
2. `launchctl bootout` old units.
3. `launchctl bootstrap` helper in `system` domain.
4. `launchctl bootstrap` daemon in user domain (`gui/<uid>` or fallback `user/<uid>`).
5. `launchctl kickstart -k` each unit.

Stop flow:

1. `launchctl bootout` daemon unit.
2. `launchctl bootout` helper unit.
3. Remove stale socket paths.

## Verification

From a user shell:

```bash
launchctl print "gui/$(id -u)/com.rustynet.rustynetd" || launchctl print "user/$(id -u)/com.rustynet.rustynetd"
sudo launchctl print system/com.rustynet.rustynetd-privileged
```

Socket checks:

```bash
test -S "${HOME}/Library/Caches/rustynet/rustynetd.sock"
test -S "${HOME}/Library/Caches/rustynet/rustynetd-privileged.sock"
```
