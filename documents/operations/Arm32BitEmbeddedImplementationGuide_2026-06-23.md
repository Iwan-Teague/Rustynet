# 32-Bit ARM Embedded Implementation Guide

**Status: open items — work needed before 32-bit ARM can be called supported**

Companion to
[Arm32BitEmbeddedSupportReference_2026-06-23.md](./Arm32BitEmbeddedSupportReference_2026-06-23.md)
(Part 1 — background, risk ratings, and the §28 Known Open Items table).

This document turns every row in the §28 table into a developer task with
exact file paths, before/after code blocks, and implementation notes drawn
from both the Rustynet codebase and patterns used by comparable Rust network
daemons.  Complete the tasks in the order listed; tasks 4 and 6 are coupled
and must land together.

---

## Quick Index

| § | Item | Severity | Files touched |
|---|---|---|---|
| [1](#1-binary-size-profilerelease) | Binary size: `[profile.release]` | Build | `Cargo.toml` |
| [2](#2-cross-compilation-toolchain-cargoconfigtoml) | Cross-compile toolchain | Setup | `.cargo/config.toml` (local only; not committed) |
| [3](#3-wireguard-interface-mtu) | WireGuard interface MTU | Operational | `crates/rustynet-backend-wireguard/src/linux_command.rs` |
| [4](#4-rustynetdservice-hardening) | `rustynetd.service` hardening | Operational | `scripts/systemd/rustynetd.service` |
| [5](#5-rustynet-relayservice-hardening) | `rustynet-relay.service` hardening | Operational | `scripts/systemd/rustynet-relay.service` |
| [6](#6-sd_notify-watchdog-in-the-daemon) | `sd_notify` watchdog in daemon | Operational | `crates/rustynetd/Cargo.toml`, `crates/rustynetd/src/daemon.rs` |
| [7](#7-udp-socket-buffers-on-relay-sockets) | UDP socket buffers on relay | Operational | `crates/rustynet-relay/Cargo.toml`, `crates/rustynet-relay/src/main.rs` |
| [8](#8-relay-tokio-thread-stack-size) | Relay tokio thread stack size | Operational | `crates/rustynet-relay/src/main.rs` |
| [9](#9-relay-socket-re-bind-on-ip-change) | Relay socket re-bind on IP change | Operational | dhcpcd exit-hook (operational); code fix future work |
| [10](#10-ci-gate-for-armv7-cross-compile) | CI gate for armv7 | CI | `.github/workflows/cross-platform-ci.yml` |
| [11](#11-platformsupportmatrixmd-language) | `PlatformSupportMatrix.md` language | Documentation | `documents/operations/PlatformSupportMatrix.md` |
| [12](#12-log-rotation-and-journald-config) | Log rotation / journald config | Operational | journald dropin |
| [13](#13-udp-receive-buffer-sysctl) | UDP receive buffer sysctl | Operational | `/etc/sysctl.d/` |
| [14](#14-live-lab-evidence-row) | Live-lab evidence row | Evidence | `documents/operations/live_lab_run_matrix.csv` |

**Coupling note:** tasks 4 and 6 must land in the same deploy.  Changing
`rustynetd.service` to `Type=notify` without the daemon sending `READY=1`
causes systemd to hang at startup until `TimeoutStartSec` expires.

---

## 1. Binary Size: `[profile.release]`

**File:** `Cargo.toml` (workspace root), lines 49–50.

### Current

```toml
[profile.release]
lto = "thin"
```

### Change to

```toml
[profile.release]
lto = "thin"
strip = true       # drops debug symbols; saves 25–40% binary size on ARM
panic = "abort"    # removes unwind tables; saves 5–15%; correct for a hardened daemon
```

`strip = true` removes DWARF debug sections from the release binary.  Zero
runtime-performance impact.  Expected result: `rustynetd` drops from ~20 MB
to ~10–12 MB on armv7.  This is a general improvement, not ARM-specific; it
benefits all platforms.

`panic = "abort"` replaces unwinding with an immediate `abort(3)` on panic.
For a security daemon that must never silently continue after an unexpected
panic, this is the correct behaviour.  The process exits, systemd restarts it,
and the watchdog (task 6) bounds the silent-hang window.  Implications:

- `std::panic::catch_unwind` degrades to abort — no callers in Rustynet use
  it (confirmed by grep; there are zero `catch_unwind` calls across all crates).
- FFI boundaries: under `unwind`, a Rust panic crossing into a C frame is
  undefined behaviour; `abort` makes it well-defined.  Rustynet has no
  Rust→C callbacks in production paths.
- All crates in the workspace compile with the same panic strategy.  None of
  the current dependencies rely on unwinding semantics.

**Do not** add `opt-level = "z"` at the workspace level.  It degrades
`boringtun`'s crypto throughput.  If binary size reduction beyond `strip` +
`panic = "abort"` is needed, add per-crate overrides:

```toml
[profile.release.package.rustynetd]
opt-level = "z"
codegen-units = 1

[profile.release.package.boringtun]
opt-level = 3     # override back to speed-optimised
```

---

## 2. Cross-Compilation Toolchain: `.cargo/config.toml`

**Do not commit this file.**  It contains host-local paths that differ
between machines.  Add it to `.gitignore` or keep it outside the working
tree.  CI uses `cross` (task 10) which needs no `.cargo/config.toml`.

### Local developer config (create on the dev machine, not in the repo)

```toml
# .cargo/config.toml — NOT committed to the repo
[target.armv7-unknown-linux-gnueabihf]
linker = "arm-linux-gnueabihf-gcc"
```

### Installing the cross-linker

**On a Debian/Ubuntu host:**

```sh
sudo apt-get install gcc-arm-linux-gnueabihf
rustup target add armv7-unknown-linux-gnueabihf
```

**On macOS (Homebrew):**

```sh
brew tap messense/macos-cross-toolchains
brew install armv7-unknown-linux-gnueabihf
# linker path: /opt/homebrew/bin/arm-unknown-linux-gnueabihf-gcc
# Update .cargo/config.toml to match
```

### Verify the cross-compile (fast check, no binary produced)

```sh
cargo check --target armv7-unknown-linux-gnueabihf -p rustynetd
cargo check --target armv7-unknown-linux-gnueabihf -p rustynet-relay
```

### Full release build (produces the deployment binary)

```sh
cargo build --release --target armv7-unknown-linux-gnueabihf -p rustynetd
# Output: target/armv7-unknown-linux-gnueabihf/release/rustynetd

cargo build --release --target armv7-unknown-linux-gnueabihf -p rustynet-relay
# Output: target/armv7-unknown-linux-gnueabihf/release/rustynet-relay
```

---

## 3. WireGuard Interface MTU

**File:** `crates/rustynet-backend-wireguard/src/linux_command.rs`

**Function:** `configure_interface()` — line 138.

The function runs four commands in sequence: `ip link add`, `wg set`,
`ip address add`, `ip link set up`.  It never sets MTU.  The WireGuard
interface inherits the parent interface MTU (1500 for Ethernet/WiFi at L2).
With ~60–80 bytes of WireGuard overhead, packets near 1500 bytes trigger
fragmentation.  The correct value is **1420 bytes** (1500 − 80, the widest
WireGuard encapsulation for IPv6 outer headers).

This is the same default used by `wg-quick` and `wireguard-go`.

### Change

Add the following block **after line 191** (the closing `}` of the
`ip link set up` error guard) and **before** `Ok(())` at line 192:

**Before (end of function, lines 179–193):**

```rust
        if let Err(err) = self.runner.run(
            "ip",
            &[
                "link".to_owned(),
                "set".to_owned(),
                "up".to_owned(),
                "dev".to_owned(),
                self.interface_name.clone(),
            ],
        ) {
            let _ = self.remove_interface();
            return Err(err);
        }
        Ok(())
    }
```

**After:**

```rust
        if let Err(err) = self.runner.run(
            "ip",
            &[
                "link".to_owned(),
                "set".to_owned(),
                "up".to_owned(),
                "dev".to_owned(),
                self.interface_name.clone(),
            ],
        ) {
            let _ = self.remove_interface();
            return Err(err);
        }
        // 1420 = 1500 (standard Ethernet) minus 80 bytes (WireGuard + IPv6 + UDP headers).
        // Matches wg-quick and wireguard-go defaults.  Prevents fragmentation on WiFi.
        if let Err(err) = self.runner.run(
            "ip",
            &[
                "link".to_owned(),
                "set".to_owned(),
                "mtu".to_owned(),
                "1420".to_owned(),
                "dev".to_owned(),
                self.interface_name.clone(),
            ],
        ) {
            let _ = self.remove_interface();
            return Err(err);
        }
        Ok(())
    }
```

### Verify

```sh
ip link show rustynet0 | grep mtu
# Expected output contains: ... mtu 1420 ...
```

### Future improvement

Make MTU configurable via `RUSTYNET_WG_MTU` env var.  Pattern: add a
`wg_mtu: u16` field to the interface config struct, thread it through
`LinuxWireGuardBackend::new()`, and substitute it for the `"1420"` literal
in `configure_interface()`.

---

## 4. `rustynetd.service` Hardening

**File:** `scripts/systemd/rustynetd.service`

**Prerequisite:** task 6 (`sd_notify` watchdog) must be implemented first.
Setting `Type=notify` before the daemon sends `READY=1` causes systemd to
wait until `TimeoutStartSec` (default 90 s) expires before marking the
service failed.  Deploy tasks 4 and 6 together.  Consider adding
`TimeoutStartSec=30s` to the `[Service]` section to bound a failed start
to 30 seconds rather than the 90-second default.

### 4a. Service type, watchdog, and notify access

**Current `[Service]` opening line:**

```ini
[Service]
Type=simple
```

**Change to:**

```ini
[Service]
Type=notify
NotifyAccess=main
WatchdogSec=30s
```

`Type=notify` — systemd waits for `READY=1` from the daemon before
marking the service started and allowing dependent services to start.
This prevents races where, for example, a local service that dials the
Unix socket tries to connect before the socket exists.

`NotifyAccess=main` — restricts sd_notify delivery to the main daemon
process only.  The privileged helper subprocess must not be able to send
notifications.

`WatchdogSec=30s` — systemd kills and restarts the daemon if it fails to
send `WATCHDOG=1` within 30 seconds.  The reconcile loop runs every ~1
second (`RUSTYNET_RECONCILE_INTERVAL_MS=1000`), giving a 30× margin.
On a lightly loaded Pi Zero 2 W the margin is comfortably large; STUN
gather and gossip ingest complete in tens of milliseconds.

### 4b. Time-sync dependency (Pi Zero 2 W: no RTC)

**Current `[Unit]` ordering:**

```ini
After=network-online.target
Wants=network-online.target
```

**Change to:**

```ini
After=network-online.target
After=time-sync.target
Wants=network-online.target
```

The Pi Zero 2 W has no battery-backed RTC.  The clock starts at epoch
(1970-01-01) on every power cycle until NTP synchronises.  The gossip
bundle freshness checks in `accept_bundle_with_now()` compare bundle
timestamps against `unix_now()`.  A pre-NTP boot makes all bundles appear
to be from the far future, failing freshness checks and blocking startup.

`time-sync.target` is satisfied by `systemd-timesyncd` (installed by default
on Pi OS) after the first successful clock sync.  On subsequent boots,
`fake-hwclock` saves the last-known time to SD card so `timesyncd` syncs
within a few seconds even before the first NTP response.

### 4c. OOM adjustment

Add inside `[Service]`, adjacent to `User=rustynetd`:

```ini
OOMScoreAdjust=-500
```

Instructs the OOM killer to prefer other processes over the daemon when
memory is scarce.  −500 is a reasonable midpoint between the default (0)
and the maximum protection (−1000).  The privileged helper should be set
to −900 in `rustynetd-privileged-helper.service` (not covered here).

### 4d. Startup retry limits

**Current `[Unit]` section:**

```ini
StartLimitBurst=5
StartLimitIntervalSec=60
```

**Change to:**

```ini
StartLimitBurst=10
StartLimitIntervalSec=300
```

Five restarts in 60 seconds is too tight for a node that may lose WiFi
during the initial NTP + traversal convergence window.  Ten restarts over
5 minutes matches the expected cold-boot window on a Pi Zero 2 W.

---

## 5. `rustynet-relay.service` Hardening

**File:** `scripts/systemd/rustynet-relay.service`

Three changes; no code changes required.

### 5a. File descriptor limit

Add inside `[Service]`:

```ini
LimitNOFILE=8192
```

The default `NOFILE` limit is 1024.  The relay holds two file descriptors
per session (one socket per port) plus the control socket.  At
`RUSTYNET_RELAY_MAX_TOTAL_SESSIONS=4096` the relay needs 8193 fds.  Without
this limit, session allocation fails silently once the fd table fills.

For Pi Zero 2 W deployments with `RUSTYNET_RELAY_MAX_TOTAL_SESSIONS=32`
(see §16 of the reference doc), the system default is technically sufficient,
but set `LimitNOFILE=8192` for consistency.

### 5b. OOM adjustment

```ini
OOMScoreAdjust=-500
```

Same rationale as the daemon (task 4c).

### 5c. Startup retry limits

**Current `[Unit]`:**

```ini
StartLimitBurst=5
StartLimitIntervalSec=60
```

**Change to:**

```ini
StartLimitBurst=10
StartLimitIntervalSec=300
```

---

## 6. `sd_notify` Watchdog in the Daemon

Two files change: the crate `Cargo.toml` and `daemon.rs`.

How other projects do this: Kanidm (identity management daemon), `sshd`
replacement `russh`, and Cloudflare's `boringtun` service wrapper all follow
the same pattern — a `cfg(unix)` dependency on `sd-notify`, a `READY=1` call
at the end of initialisation, and a `WATCHDOG=1` call in the main loop.

### 6a. Add `sd-notify` dependency

**File:** `crates/rustynetd/Cargo.toml`

The crate already has `signal-hook` under `[target.'cfg(unix)'.dependencies]`.
Add `sd-notify` in the same block:

**Current:**

```toml
[target.'cfg(unix)'.dependencies]
signal-hook = { version = "0.3", default-features = false }
```

**Change to:**

```toml
[target.'cfg(unix)'.dependencies]
signal-hook = { version = "0.3", default-features = false }
sd-notify = { version = "0.4", default-features = false }
```

`default-features = false` drops the optional `log` crate integration inside
`sd-notify` itself (Rustynet uses `log` directly; no duplication concern, but
the feature is not needed).

The `sd-notify` crate is pure Rust and MIT-licensed — it passes the
`deny.toml` license gate without any additional allow entry.  It reads
`NOTIFY_SOCKET` and `WATCHDOG_USEC` environment variables set by systemd
and sends messages over a Unix datagram socket.  When systemd is absent
(e.g., macOS, Windows, developer desktop), the env vars are not set and
`notify()` returns `Ok(false)` — it is a safe no-op.

**Run `cargo deny check bans licenses sources advisories` after adding the
dependency** to confirm the new crate passes all gates.

### 6b. Send `READY=1` and `WATCHDOG=1`

**File:** `crates/rustynetd/src/daemon.rs`

The daemon's main loop function is `pub fn run_daemon(config: DaemonConfig)`.
The main `loop {}` starts at line 9316.

**Step 1 — import** (add near the existing `use` declarations):

```rust
#[cfg(unix)]
use sd_notify::NotifyState;
```

**Step 2 — send `READY=1` just before the main loop** (add between the
`log::info!("rustynetd startup: ... entering reconcile loop")` at line 9307
and the `loop {` at line 9316 — the setup variables `processed`, `reconcile_interval`,
`next_reconcile`, and `dns_buffer` are declared between these points, so place
the `notify` call after line 9314):

```rust
// Tell systemd the daemon has finished initialising and is ready to serve.
// Required when rustynetd.service uses Type=notify (see task 4a).
// Returns Ok(false) when NOTIFY_SOCKET is unset; safe to discard.
#[cfg(unix)]
let _ = sd_notify::notify(false, &[NotifyState::Ready]);

loop {  // line 9316 — main reconcile loop starts here
```

**Step 3 — kick the watchdog on every reconcile** (add after line 9408):

```rust
        if now >= next_reconcile {
            runtime.reconcile();               // line 9408
            next_reconcile = now + reconcile_interval;
            // Watchdog ping.  If the reconcile loop stops making progress
            // (deadlock, infinite block in poll_stun_results, etc.), this
            // ping stops and systemd restarts the daemon within WatchdogSec.
            #[cfg(unix)]
            let _ = sd_notify::notify(false, &[NotifyState::Watchdog]);
        }
```

**Why the reconcile block, not the sleep block?**  Kicking the watchdog only
on reconcile (every `RUSTYNET_RECONCILE_INTERVAL_MS`, default 1 s) rather
than on every loop iteration (every ≤25 ms) means: if `runtime.reconcile()`
itself blocks indefinitely, the watchdog fires correctly.  Kicking in the
sleep block would hide a blocked reconcile.

### 6c. Verify the integration

After deploying the updated binary and service file:

```sh
systemctl status rustynetd.service
# Look for "Type: notify" in the service description
# and a non-empty "Watchdog" timestamp once the daemon is running

systemctl show rustynetd.service --property WatchdogTimestamp
# Returns the last time a WATCHDOG=1 was received
```

Simulate a hung daemon to confirm watchdog recovery:

```sh
# In a test environment only — sends SIGSTOP to freeze the daemon
kill -STOP $(pgrep rustynetd)
# Expect systemd to restart it after WatchdogSec=30s
journalctl -u rustynetd.service --since "1 min ago" | grep -i watchdog
```

---

## 7. UDP Socket Buffers on Relay Sockets

Two files change: the relay's `Cargo.toml` and `main.rs`.

Pattern followed by other Rust relay projects (`udp-relay-core`, `rstun`,
AWS SDK relay tests): create the socket via `socket2`, set buffer sizes
before binding, convert to `std::net::UdpSocket`, then into
`tokio::net::UdpSocket`.  The conversion chain is:

```
socket2::Socket → std::net::UdpSocket::from(s) → tokio::net::UdpSocket::from_std(std_s)
```

`set_recv_buffer_size` must be called **before** `bind` to take effect on
Linux.  Linux doubles the requested value internally for bookkeeping; the
actual kernel allocation is 2× the requested size.  The OS silently clamps
requests to `net.core.rmem_max` (see task 13 for raising the limit).

### 7a. Add `socket2` dependency

**File:** `crates/rustynet-relay/Cargo.toml`

`rustynet-mcp` and `rustynet-cli` already use `socket2 = "0.6"`, so the
crate is already in the dependency tree — `cargo deny check` will not flag
a new crate, and no `deny.toml` change is needed.  Add it to
`rustynet-relay` as an optional dependency gated on the `daemon` feature.

**Current (relevant section):**

```toml
[dependencies]
tokio = { version = "1", features = [...], optional = true }
...

[features]
default = []
daemon = ["tokio", "tracing", "serde", "serde_json"]
```

**Change to:**

```toml
[dependencies]
tokio = { version = "1", features = [...], optional = true }
socket2 = { version = "0.6", optional = true }
...

[features]
default = []
daemon = ["tokio", "tracing", "serde", "serde_json", "socket2"]
```

### 7b. Refactor control socket creation

**File:** `crates/rustynet-relay/src/main.rs`

**Current (lines 262–264):**

```rust
let control_socket = UdpSocket::bind(config.bind_addr)
    .await
    .map_err(|e| format!("failed to bind control socket: {e}"))?;
```

**Replace with:**

```rust
let control_socket = {
    use socket2::{Domain, Socket, Type};
    let s = Socket::new(Domain::for_address(config.bind_addr), Type::DGRAM, None)
        .map_err(|e| format!("create control socket: {e}"))?;
    // Set buffers before binding.  Linux doubles the value internally;
    // 4 MB request yields ~8 MB actual kernel allocation.
    // Clamped to net.core.rmem_max — see sysctl task 13.
    s.set_recv_buffer_size(4 * 1024 * 1024).ok();
    s.set_send_buffer_size(4 * 1024 * 1024).ok();
    s.bind(&socket2::SockAddr::from(config.bind_addr))
        .map_err(|e| format!("failed to bind control socket: {e}"))?;
    s.set_nonblocking(true)
        .map_err(|e| format!("set nonblocking on control socket: {e}"))?;
    UdpSocket::from_std(std::net::UdpSocket::from(s))
        .map_err(|e| format!("convert control socket: {e}"))?
};
```

### 7c. Raise socket buffers on per-session sockets

**File:** `crates/rustynet-relay/src/main.rs`

**Current session socket allocation inside `allocate_port()` (lines 314–322):**

```rust
        // Try to bind
        let addr = SocketAddr::new(self.config.bind_addr.ip(), port);
        match UdpSocket::bind(addr).await {
            Ok(socket) => return Ok((port, socket)),
            Err(_) => {
                attempts += 1;
                continue;
            }
        }
```

**Replace with:**

```rust
        let addr = SocketAddr::new(self.config.bind_addr.ip(), port);
        let socket_result: Result<UdpSocket, String> = (|| {
            use socket2::{Domain, Socket, Type};
            let s = Socket::new(Domain::for_address(addr), Type::DGRAM, None)
                .map_err(|e| e.to_string())?;
            // 1 MB per session; adequate for WireGuard-sized datagrams (≤1500 bytes).
            s.set_recv_buffer_size(1024 * 1024).ok();
            s.set_send_buffer_size(1024 * 1024).ok();
            s.bind(&socket2::SockAddr::from(addr))
                .map_err(|e| e.to_string())?;
            s.set_nonblocking(true).map_err(|e| e.to_string())?;
            UdpSocket::from_std(std::net::UdpSocket::from(s))
                .map_err(|e| e.to_string())
        })();
        match socket_result {
            Ok(socket) => return Ok((port, socket)),
            Err(_) => {
                attempts += 1;
                continue;
            }
        }
```

**Memory budget note for Pi Zero 2 W:** With 32 max sessions
(`RUSTYNET_RELAY_MAX_TOTAL_SESSIONS=32`), per-session buffer allocation is
32 × 2 MB (Linux doubles) = 64 MB, plus the 8 MB control socket.  This fits
the 512 MB total RAM budget (see §14 of the reference doc).  If memory is
constrained after other resident costs, reduce the per-session request to
`256 * 1024` (256 KB requested → 512 KB actual).

---

## 8. Relay Tokio Thread Stack Size

**Critical context before making this change:** The tokio runtime builder at
line 2264 is inside `run_windows_relay_service_host()` — a function that only
runs on the Windows SCM path.  On Linux (including armv7), the relay enters
via `#[tokio::main]` at line 3519, which calls `run_relay_from_args().await`
directly.  That path has no explicit builder, so the line 2264 change has no
effect on Linux.

Two options — choose based on how invasive a change is acceptable:

### Option A: Service file env var (no code change, Linux only)

Add to `scripts/systemd/rustynet-relay.service` `[Service]` section:

```ini
Environment=RUST_MIN_STACK=524288
```

`RUST_MIN_STACK` is the Rust standard library env var checked when
`std::thread::Builder` spawns threads without an explicit `.stack_size()`.
Tokio spawns its worker threads through `std::thread::Builder`, so setting
this env var reduces the worker stack from the OS default (8 MB) to 512 KB.
Effect: saves ~(worker-count × 7.5 MB) of virtual address space and
reduces the chance of stack memory staying resident in physical RAM.

No code change; no recompile needed.  Verify after deploy:

```sh
# Check the actual stack reservation per tokio worker thread
cat /proc/$(pgrep rustynet-relay)/smaps | grep -A1 "stack"
```

### Option B: Explicit runtime builder (code change, affects all platforms)

**File:** `crates/rustynet-relay/src/main.rs`, line 3519.

Replace `#[tokio::main]` with an explicit builder.  This is the clean
long-term fix, but is more invasive.

**Before:**

```rust
#[cfg(feature = "daemon")]
#[tokio::main]
async fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let result = match daemon::select_relay_host_entry(&args) {
        Ok(daemon::RelayHostEntrySelection::RelayArgs(args)) => {
            daemon::run_relay_from_args(args).await
        }
        // ... Windows and other arms
    };
```

**After:**

```rust
#[cfg(feature = "daemon")]
fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let result = match daemon::select_relay_host_entry(&args) {
        Ok(daemon::RelayHostEntrySelection::RelayArgs(relay_args)) => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(512 * 1024)
                .build()
                .expect("build relay runtime");
            runtime.block_on(daemon::run_relay_from_args(relay_args))
        }
        Ok(daemon::RelayHostEntrySelection::WindowsService(options)) => {
            // Windows service creates its own runtime internally (line 2264)
            daemon::run_windows_relay_service_host(options)
        }
        Ok(daemon::RelayHostEntrySelection::WindowsServiceHardeningCheck { fail_on_drift }) => {
            daemon::run_windows_relay_service_hardening_check(fail_on_drift)
        }
        Err(err) => Err(err),
    };
    // ... existing error handling
```

Note: `main()` becomes synchronous (remove `async`).  The Windows service
path already creates its own runtime at line 2264, so removing `#[tokio::main]`
does not affect Windows.  Also add the same `.thread_stack_size(512 * 1024)`
call in the Windows builder at line 2264 for consistency.

The relay's tokio tasks have shallow call stacks: receive a UDP datagram,
look up the session map, forward.  The 8 MB default stack per thread is
designed for synchronous Rust with deep recursion; it wastes ~6 MB per
worker thread on a 512 MB system.  512 KB is conservative (Embassy targets
4–32 KB; 512 KB is generous for async I/O tasks).

---

## 9. Relay Socket Re-Bind on IP Change

**Background:** `allocate_port()` at line 315 binds each session socket to
`SocketAddr::new(self.config.bind_addr.ip(), port)`.  When the host IP
changes (WiFi reconnect with new DHCP address), all existing sockets remain
bound to the old IP.  Incoming datagrams addressed to the new IP are not
delivered to the old sockets; all relay sessions silently stall.

### 9a. Operational workaround (Pi OS with dhcpcd)

Install a dhcpcd exit-hook that restarts the relay on IP change.  dhcpcd
calls exit-hooks in `/etc/dhcpcd.exit-hook` after each DHCP event, passing
the event reason in `$reason`.

**Create `/etc/dhcpcd.exit-hook`** (or append if the file already exists):

```sh
#!/bin/sh
# Restart rustynet-relay on IP change so relay sockets re-bind to the
# current interface address.  dhcpcd sets $reason before calling this hook.
case "$reason" in
    BOUND|REBIND)
        # BOUND = new lease assigned; REBIND = rebind after lease expiry.
        # --no-block: do not wait for restart to complete (avoids DHCP timeout).
        systemctl --no-block restart rustynet-relay.service 2>/dev/null || true
        ;;
esac
```

```sh
chmod 755 /etc/dhcpcd.exit-hook
```

**Where this file should live in the repo:** Add it to
`scripts/systemd/dhcpcd.exit-hook` and extend the `rustynet ops
install-systemd-relay` subcommand to copy it to `/etc/dhcpcd.exit-hook`
during Pi OS relay installation.

**Verify:**

```sh
journalctl -fu rustynet-relay.service &
# Simulate a rebind:
sudo dhcpcd --rebind wlan0
# Expect "Started Rustynet Relay" to appear in the journal within seconds
```

### 9b. Code-level fix (future work)

A robust fix requires the relay to monitor IP address changes via netlink and
re-bind gracefully.  Outline of the approach:

1. Open a `NETLINK_ROUTE` socket subscribed to `RTMGRP_IPV4_IFADDR` (and
   `RTMGRP_IPV6_IFADDR` for dual-stack).
2. Run a background tokio task that loops on `recv` from the netlink socket.
3. On `RTM_NEWADDR` or `RTM_DELADDR` for the interface matching
   `config.bind_addr.ip()`, signal the relay's main loop via a
   `tokio::sync::watch::Sender<Option<IpAddr>>`.
4. In the main `select!` loop (around line 382), watch the channel.  On
   change: drain all active sessions (send a `SessionTerminated` to each
   peer pair), drop all allocated sockets, re-bind the control socket to
   the new address, reset the session table.

The appropriate crate is `rtnetlink` (`0.14`).  It is not currently a
dependency of `rustynet-relay`.  This is a non-trivial change; the dhcpcd
hook is the correct short-term path.

---

## 10. CI Gate for armv7 Cross-Compile

**File:** `.github/workflows/cross-platform-ci.yml`

Add the following job after the existing `linux_e2e` job.  Use `cross`
(the `cross-rs` project) which wraps the compiler in a Docker container that
includes the ARM sysroot and linker; this is the standard approach used by
`aws-lc-rs`, `quinn`, `tokio`, and most Rust network projects for armv7 CI.

```yaml
  armv7_cross:
    name: armv7 cross-compile check
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Install Rust stable + armv7 target
        run: |
          rustup toolchain install stable --profile minimal
          rustup target add armv7-unknown-linux-gnueabihf
      - name: Install cross
        run: cargo install cross --version 0.2.5 --locked
      - name: Cross-check rustynetd
        run: >
          cross check
          --target armv7-unknown-linux-gnueabihf
          -p rustynetd
          --locked
      - name: Cross-check rustynet-relay
        run: >
          cross check
          --target armv7-unknown-linux-gnueabihf
          -p rustynet-relay
          --locked
      - name: Cross-check rustynet-cli
        run: >
          cross check
          --target armv7-unknown-linux-gnueabihf
          -p rustynet-cli
          --locked
```

### Design decisions

**`cross check` instead of `cross build --release`.**  `cross check`
validates that the code type-checks and all imports resolve in under
2 minutes per crate.  A full `cross build --release` on a 2-core CI runner
takes 15–25 minutes and is only needed when producing deployment binaries.
A separate nightly or tag-triggered job can run the full build.

**`ubuntu-22.04` not `ubuntu-latest`.**  `cross` images are tied to specific
Ubuntu base versions.  The `ubuntu-latest` label tracks the newest LTS and
can cause Docker version mismatches.  `ubuntu-22.04` is the tested runner
version for `cross 0.2.5`.

**Pin a specific `cross` version.**  The `0.2.5` version shown above was
current in early 2024; verify the latest stable release on
`https://crates.io/crates/cross` at implementation time and pin that version.
Unpinned `cargo install cross` installs head, which can break CI on upstream
changes.  Update intentionally with a dedicated commit and note.

**Crates included:**  `rustynetd`, `rustynet-relay`, and `rustynet-cli` are
the three crates that run on the Pi.  `rustynet-backend-wireguard` is
included implicitly via `rustynetd`.

**Do not add `--all-features` yet.**  Confirm each crate's feature set
compiles cleanly on armv7 before enabling all features in CI.

**Known exclusions:**
- `rustynet-windows-native` — Windows-only FFI; excluded by `cfg(windows)`,
  will fail to cross-check on Linux/armv7.
- `rustynet-tun` — macOS-only; excluded by `cfg(target_os = "macos")`.

---

## 11. `PlatformSupportMatrix.md` Language

**File:** `documents/operations/PlatformSupportMatrix.md`

After the first green run of the CI job from task 10:

1. Find the `armv7-unknown-linux-gnueabihf` row (or add one if absent).
2. Remove "compile blocker" or "unsupported" language.
3. Set status to `compile-verified, lab-pending`.
4. Add a note that live-lab evidence is required before "supported" is
   claimed (task 14).
5. Reference this document and the companion reference doc.

After task 14 (live-lab evidence row complete), update again to:

```
supported (limited: relay / exit / client; lab-proven on Pi Zero 2 W,
Pi OS Bookworm 6.6.x, armv7 userland)
```

Do not claim "supported" status until live-lab evidence exists.

---

## 12. Log Rotation and journald Config

**No code change required.**  The daemon logs to the systemd journal when
started via the service file.

### Recommended embedded journald config

Create `/etc/systemd/journald.conf.d/rustynet-embedded.conf`:

```ini
[Journal]
Storage=volatile       # keep logs in RAM (/run/log/journal); do not write to SD card
RuntimeMaxUse=32M      # cap RAM usage at 32 MB
RuntimeMaxFileSize=8M  # rotate individual files at 8 MB
RuntimeMaxFiles=4      # retain at most 4 journal files
```

`Storage=volatile` is the most important setting for SD card longevity.
Journal writes are frequent; on a relay under load they can amount to
several MB per hour.  Losing logs on reboot is acceptable for relay/exit
nodes: incidents are diagnosed from the daemon's state at restart, not from
pre-crash logs.

If persistent logs across reboots are needed:

```ini
[Journal]
Storage=persistent
SystemMaxUse=64M
SystemMaxFileSize=16M
SystemMaxFiles=4
```

Apply the config without rebooting:

```sh
systemctl restart systemd-journald
```

### Operator note

Include this journald config in the `rustynet ops install-systemd-relay`
flow for Pi OS deployments, or document it in the relay install runbook.

---

## 13. UDP Receive Buffer Sysctl

The relay's `SO_RCVBUF` request (task 7) is silently clamped to
`net.core.rmem_max`.  Linux defaults this to ~208 KB.  Raise it to allow
the code-level buffer requests to take effect.

Create `/etc/sysctl.d/30-rustynet-relay.conf`:

```ini
# Allow rustynet-relay to request up to 16 MB UDP socket buffers.
# Without this, set_recv_buffer_size() is clamped to ~208 KB.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
```

Apply immediately without rebooting:

```sh
sudo sysctl --system
```

**Pi Zero 2 W embedded note:** For `RUSTYNET_RELAY_MAX_TOTAL_SESSIONS=32`
(the recommended cap for a 512 MB board), the default 208 KB kernel
maximum is sufficient.  The relay will run correctly with the clamped
buffers; they just will not reach the 4 MB requested in task 7.  Apply
the sysctl change anyway to match the server-deployment config and avoid
configuration drift.

---

## 14. Live-Lab Evidence Row

**File:** `documents/operations/live_lab_run_matrix.csv`

32-bit ARM cannot be called "supported" until a live-lab evidence row exists.

### Minimum evidence run

1. Flash Pi OS Lite (64-bit kernel, 32-bit userland) to a Pi Zero 2 W
   microSD card.
2. Install the `rustynetd` and `rustynet-relay` binaries cross-compiled from
   task 10 (or local cross-compile from task 2).
3. Install service files with all changes from tasks 3–6 applied.
4. Join the Pi to a test mesh as a `relay` node (or `client` as a minimum
   smoke test).
5. Verify: tunnel interface up, `ip link show rustynet0` MTU = 1420, gossip
   sync completes within 120 seconds, at least one peer reachable through
   the overlay.

### CSV row format

See `LiveLabRunMatrix.md` for the full column definitions.  At minimum populate:

```csv
<date>,<commit>,clean,<report_dir>,armv7_relay,pass,<node_id>,none
```

Record in the report directory:
- Pi OS version (`cat /etc/os-release`)
- Kernel and architecture (`uname -rm`)
- `rustynetd` version string (`rustynetd --version`)
- `ip link show rustynet0` output confirming MTU = 1420
- Systemd service status (`systemctl status rustynetd rustynet-relay`)

### After the evidence row exists

Update `PlatformSupportMatrix.md` per task 11, changing status from
`compile-verified, lab-pending` to `supported (limited)`.
