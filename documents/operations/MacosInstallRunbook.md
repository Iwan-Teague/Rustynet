# macOS `rustynetd` Manual Install Runbook

Captured from live install on `macos-client-1` (macOS 26.5, Apple Silicon, UTM VM)
on 2026-05-21/22. Use this when the bootstrap wizard is unavailable or when
debugging a failed wizard run.

---

## Prerequisites

Install via Homebrew (as the real non-root user):

```bash
brew install wireguard-go wireguard-tools
```

Install Rust (if not present):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
rustup default stable
```

Confirm:

```bash
wg --version
wireguard-go --version
rustc --version
```

---

## Build

Build from the repository root on the host (cross-compile or native):

```bash
cargo build --release -p rustynetd
```

The output binary is `target/release/rustynetd` (~3–4 MB stripped ARM64).

---

## Passwordless Sudo

The orchestrator runs bootstrap commands over SSH without a tty. The SSH user
(`mac`) must have passwordless sudo configured:

```bash
echo 'mac ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/mac-nopasswd
sudo chmod 440 /etc/sudoers.d/mac-nopasswd
```

Verify: `sudo -n true && echo OK`

---

## System User

Create the `rustynetd` system user and group (run as root):

```bash
sudo dscl . -create /Users/rustynetd
sudo dscl . -create /Users/rustynetd UserShell /usr/bin/false
sudo dscl . -create /Users/rustynetd RealName "Rustynet Daemon"
sudo dscl . -create /Users/rustynetd UniqueID 500
sudo dscl . -create /Users/rustynetd PrimaryGroupID 500
sudo dscl . -create /Users/rustynetd NFSHomeDirectory /var/empty
sudo dscl . -create /Groups/rustynetd
sudo dscl . -create /Groups/rustynetd PrimaryGroupID 500
sudo dscl . -append /Groups/rustynetd GroupMembership rustynetd
```

Skip if the user already exists (`id rustynetd` returns without error).

---

## Directories

```bash
sudo mkdir -p /usr/local/bin
sudo mkdir -p /usr/local/var/rustynet/keys
sudo mkdir -p /usr/local/var/log/rustynet
sudo mkdir -p /private/var/run/rustynet

sudo chown rustynetd:rustynetd /usr/local/var/rustynet
sudo chown rustynetd:rustynetd /usr/local/var/rustynet/keys
sudo chmod 700 /usr/local/var/rustynet
sudo chmod 700 /usr/local/var/rustynet/keys

sudo chown root:rustynetd /private/var/run/rustynet
sudo chmod 770 /private/var/run/rustynet
```

---

## Binary

Copy the built binary (from host to VM, then install):

```bash
# From host:
scp target/release/rustynetd mac@192.168.65.2:/tmp/rustynetd-new

# On VM (as root):
sudo cp /tmp/rustynetd-new /usr/local/bin/rustynetd
sudo chown root:wheel /usr/local/bin/rustynetd
sudo chmod 755 /usr/local/bin/rustynetd
```

---

## WireGuard Keys

Generate keys as `rustynetd` user:

```bash
sudo -u rustynetd sh -c '
  wg genkey | tee /usr/local/var/rustynet/keys/wireguard.key \
    | wg pubkey > /usr/local/var/rustynet/keys/wireguard.pub
  chmod 600 /usr/local/var/rustynet/keys/wireguard.key
  chmod 644 /usr/local/var/rustynet/keys/wireguard.pub
'
```

For production: generate a passphrase-protected encrypted copy. The install script
(`Install-RustyNetMacosService.sh`) automatically detects whether
`wireguard.passphrase` exists and includes `--wg-encrypted-private-key` in the
plist only when it does. Without a passphrase file the daemon uses the plaintext
`wireguard.key` directly (lab-safe; use encrypted key for production).

```bash
# Generate passphrase and encrypt key (production).
# rustynetd key init handles passphrase generation and encryption atomically:
sudo -u rustynetd /usr/local/bin/rustynetd key init \
  --runtime-private-key /usr/local/var/rustynet/keys/wireguard.key \
  --encrypted-private-key /usr/local/var/rustynet/keys/wireguard.key.enc \
  --public-key /usr/local/var/rustynet/keys/wireguard.pub \
  --passphrase-file /usr/local/var/rustynet/keys/wireguard.passphrase
```

---

## Launchd Plist

Write `/Library/LaunchDaemons/com.rustynet.daemon.plist` (as root).

Key points discovered during live install:

- **`--socket` must be explicit** — the compiled-in default is
  `/private/var/run/rustynet/rustynetd.sock` (macOS) but the plist should
  pin it explicitly.
- **`--privileged-helper-socket`** is required; the helper creates
  `/private/var/run/rustynet/` on first run.
- **`--fail-closed-ssh-allow true --fail-closed-ssh-allow-cidrs <CIDR>`**
  must be present or SSH will be blocked when the pf killswitch fires.
  Use the management network CIDR (e.g. `192.168.65.0/24` for UTM NAT).

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.rustynet.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/rustynetd</string>
        <string>daemon</string>
        <string>--node-id</string>
        <string>NODE_ID_HERE</string>
        <string>--node-role</string>
        <string>client</string>
        <string>--state</string>
        <string>/usr/local/var/rustynet/rustynetd.state</string>
        <string>--wg-private-key</string>
        <string>/usr/local/var/rustynet/keys/wireguard.key</string>
        <string>--wg-encrypted-private-key</string>
        <string>/usr/local/var/rustynet/keys/wireguard.key.enc</string>
        <string>--wg-key-passphrase</string>
        <string>/usr/local/var/rustynet/keys/wireguard.passphrase</string>
        <string>--wg-public-key</string>
        <string>/usr/local/var/rustynet/keys/wireguard.pub</string>
        <string>--backend</string>
        <string>macos-wireguard-userspace-shared</string>
        <string>--socket</string>
        <string>/private/var/run/rustynet/rustynetd.sock</string>
        <string>--privileged-helper-socket</string>
        <string>/private/var/run/rustynet/rustynetd-privileged.sock</string>
        <string>--trust-max-age-secs</string>
        <string>315360000</string>
        <string>--auto-tunnel-enforce</string>
        <string>false</string>
        <string>--fail-closed-ssh-allow</string>
        <string>true</string>
        <string>--fail-closed-ssh-allow-cidrs</string>
        <string>192.168.65.0/24</string>
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
    <string>/usr/local/var/log/rustynet/rustynetd.log</string>
    <key>StandardErrorPath</key>
    <string>/usr/local/var/log/rustynet/rustynetd-error.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>RUSTYNET_NODE_ROLE</key>
        <string>client</string>
        <key>RUSTYNET_NETWORK_ID</key>
        <string>NETWORK_ID_HERE</string>
        <key>RUSTYNET_WG_BINARY_PATH</key>
        <string>/opt/homebrew/bin/wg</string>
        <key>RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT</key>
        <string>wg-passphrase-NODE_ID_HERE</string>
        <key>RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE</key>
        <string>net.rustynet.wg-key-passphrase</string>
        <key>RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH</key>
        <string>/usr/local/var/rustynet/keys/wireguard.passphrase</string>
    </dict>
</dict>
</plist>
```

Apply ownership:

```bash
sudo chown root:wheel /Library/LaunchDaemons/com.rustynet.daemon.plist
sudo chmod 644 /Library/LaunchDaemons/com.rustynet.daemon.plist
```

---

## Load the Service

```bash
sudo launchctl bootstrap system /Library/LaunchDaemons/com.rustynet.daemon.plist
```

Verify running (PID > 0, exit code 0):

```bash
sudo launchctl list | grep rustynet
```

Check pf killswitch is active with the SSH allow rule:

```bash
sudo pfctl -a 'com.apple/rustynet_g0' -s rules
# Expected:
# pass in quick inet proto tcp from 192.168.65.0/24 to any port = 22 flags S/SA keep state
# pass out quick inet proto tcp from any to 192.168.65.0/24 port = 22 flags S/SA keep state
# block drop out quick all
```

---

## Stop / Unload

```bash
sudo launchctl bootout system/com.rustynet.daemon
```

---

## Logs

```bash
sudo tail -f /usr/local/var/log/rustynet/rustynetd-error.log
sudo tail -f /usr/local/var/log/rustynet/rustynetd.log
```

Expected on a fresh (unenrolled) node: `restrict_recoverable: membership snapshot
is missing` and eventual `restrict_permanent: reconcile failure threshold exceeded`.
This is normal — the daemon is running but restricted until membership state is
provisioned. The pf killswitch is still active.

---

## Known Issues / Gotchas

### pf killswitch blocks SSH unless `--fail-closed-ssh-allow` is set

The daemon's pf anchor (`com.apple/rustynet_g0`) installs `block drop out quick all`.
Without the `--fail-closed-ssh-allow true --fail-closed-ssh-allow-cidrs <CIDR>` flags,
all outbound TCP is blocked including SSH replies. The `pass in ... keep state`
rule (not `pass out`) is what allows SSH through: stateful tracking lets the
outbound SYN-ACK reply pass automatically.

### `/run` does not exist on macOS — use `/private/var/run/`

The daemon's compiled-in default for `--socket` was previously `/run/rustynet/rustynetd.sock`
(Linux path). macOS seals the root volume, so `fs::create_dir_all("/run/rustynet")`
returns EROFS (errno 30). Fixed in `daemon.rs` — macOS default is now
`/private/var/run/rustynet/rustynetd.sock`. Always pin `--socket` explicitly in
the plist regardless.

### Disk space

The build tarball (`rustynet-src.tar.gz`) is ~15 GB when uncompressed build
artifacts are included. A 45 Gi VM data volume fills up quickly. Clean
`/tmp/rustynet-build-*` and the source tarball after a successful install.

### Source tarball must include `third_party/boringtun/`

The `rustynet-backend-wireguard` crate depends on `boringtun` as a path
dependency from `third_party/boringtun/`. A tarball that omits git submodules
will fail the build with `failed to read .../third_party/boringtun/Cargo.toml`.
Ensure `git archive` or the tarball generation includes submodules.

### UTM console keyboard (Irish layout)

When SSH is blocked and recovery requires the UTM console:
- `/` is intercepted by UTM — use `$'\57'` (zsh ANSI-C octal, ASCII 47)
- `_` via shift+minus gives `-` — use `$'\137'` (ASCII 95)
- `type` tool uses clipboard (blocked by VM isolation) — use `key` tool instead
