# Rustynet 32-bit ARM Embedded Support Reference

Date: 2026-06-23  
Status: **Evergreen reference** — not an active work plan. See `PlatformSupportMatrix.md`
(ARM Architecture Support section) for current support status and the fix checklist.
See `Requirements.md` (ARM architecture support bullet) and
`operations/active/MasterWorkPlan_2026-03-22.md` (post-parity backlog) for where
this sits in the roadmap.

## Purpose

This document is the developer reference for running Rustynet on 32-bit ARM Linux
embedded boards (`armv7-unknown-linux-gnueabihf`). It covers every pitfall, constraint,
and configuration decision a developer needs to understand before attempting a port or
deployment on boards such as the Raspberry Pi Zero 2 W.

Primary use case: low-power relay and exit/blind_exit nodes serving 1–3 peers. At
that scale, the daemon's CPU and memory budgets are comfortable; the work is mostly
toolchain setup and a small number of codebase adjustments.

---

## 1. Headline Finding: No Hard Compile Blockers

The codebase will cross-compile for `armv7-unknown-linux-gnueabihf` today without
any code changes to production binaries (`rustynetd`, `rustynet-relay`). The items
previously documented as "compile blockers" in `PlatformSupportMatrix.md` are
actually soft concerns:

- **`AtomicU64`** — Rust compiles this on 32-bit ARM via a mutex-backed fallback.
  `is_lock_free()` returns false, but correctness is preserved. The performance cost
  is negligible: the affected sites are the WireGuard handshake rate-limiter nonce
  counter (`third_party/boringtun/src/noise/rate_limiter.rs:45,50`) and the key
  rotation drain counter (`crates/rustynetd/src/key_rotation.rs:387`), neither of
  which is on the per-packet hot path. The `AtomicU64` in
  `third_party/rustynet-alloc-meter/src/lib.rs:17-18` is dev/bench-only and never
  compiled into a released binary.

- **`u128` / `i128`** — Rust compiles these on 32-bit ARM via software emulation
  provided by the compiler. There are nine production sites, all in control-plane
  paths (IPv6 subnet math, gossip timestamp drift). None are on the per-packet path.
  The overhead is a few extra instructions per call.

- **No `#[cfg(target_arch)]` or `#[cfg(target_pointer_width = "64")]` exclusions
  exist anywhere in the codebase.** All conditional compilation gates use
  `target_os` only. There are no 64-bit-only code paths that would exclude armv7.

- **`TUNSETIFF` ioctl constant** (`third_party/rustynet-tun/src/lib.rs:12`) is
  `0x400454ca`. This value is correct on both 32-bit and 64-bit Linux ARM. The
  constant is typed as `libc::c_ulong` which is 32 bits on armv7; the value fits
  within 32 bits and the `libc::ioctl` ABI is correct.

The `PlatformSupportMatrix.md` entry should be updated after a successful
cross-compile attempt confirms this; the current matrix text overstates the severity.

---

## 2. Correct Cross-Compilation Target

Use **`armv7-unknown-linux-gnueabihf`** (hard-float VFPv3).

- **Do not use `arm-unknown-linux-gnueabihf`** — this targets ARMv6 soft-float, which
  is wrong for Pi Zero 2 W and any Debian armhf board.
- **Do not use `armel`** — Debian `armel` is ARMv4T with soft-float, for very old
  hardware only.
- **`armv7-unknown-linux-musleabihf`** works if a musl build is desired. All
  crypto is pure Rust and all syscall wrappers via `nix` support musl. The main
  unknown is `getrandom` on musl, which uses the `getrandom(2)` syscall (Linux
  3.17+) — fully available on any Debian Bookworm kernel.

The Raspberry Pi Zero 2 W's Cortex-A53 CPU is a 64-bit core but runs 32-bit
Raspberry Pi OS in ARMv8-A compat mode, which is backward-compatible with ARMv7.

---

## 3. Cross-Compilation Toolchain Setup

No `.cargo/config.toml` exists in the repository. Create one at the repo root before
cross-compiling:

```toml
[target.armv7-unknown-linux-gnueabihf]
linker = "arm-linux-gnueabihf-gcc"
```

Install the cross-compiler and sysroot headers on a Debian/Ubuntu host:

```sh
sudo apt-get install gcc-arm-linux-gnueabihf libc6-dev-armhf-cross
rustup target add armv7-unknown-linux-gnueabihf
```

Build the relay binary:

```sh
cargo build --release --target armv7-unknown-linux-gnueabihf -p rustynet-relay
```

Build the daemon:

```sh
cargo build --release --target armv7-unknown-linux-gnueabihf -p rustynetd
```

**There are no C library dependencies beyond `libc`** (used in `rustynet-tun` for
`ioctl`, `read`, `write`, `fcntl`). The entire crypto stack is pure Rust:
ed25519-dalek, chacha20poly1305, x25519-dalek, blake2, sha2, argon2. The `ring`
crate is not present. No OpenSSL. Cross-compilation does not require a full sysroot
beyond `libc6-dev-armhf-cross`.

**Crate-specific notes:**

| Crate | 32-bit status | Note |
|---|---|---|
| `argon2 = "0.5"` | Fine | Default params: 19 MiB memory, t=2, p=1. Allocates ~19 MB transiently at each key decrypt/encrypt. Released immediately. Acceptable on 512 MB. |
| `ed25519-dalek = "2"` | Fine | Uses pure-Rust curve25519 backend on armv7; no assembly. |
| `getrandom` | Fine | Uses `getrandom(2)` syscall on Linux. Available since kernel 3.17. No feature flags needed for Linux targets. |
| `tokio = "1"` | Fine | No known cross-compile issues for armv7. |
| `parking_lot = "0.12"` | Fine | Full 32-bit support; uses futex on Linux regardless of pointer width. |
| `nix = "0.29"` | Fine | Pure Rust wrappers over POSIX syscalls. No 32-bit issues. |

---

## 4. Runtime Architecture: What Is and Is Not Async

**The `rustynetd` daemon is synchronous, not async.** It runs a single-threaded
blocking event loop (`loop {}` with `std::thread::sleep`) backed by `std::sync::mpsc`
channels and `UnixListener::accept()`. There is no `tokio` in the daemon's main code
path. The boringtun userspace engine spawns its own OS threads and uses
`mpsc::recv_timeout`. This means the daemon's memory footprint from thread overhead
is minimal: a small number of fixed OS threads, not a thread pool.

**The `rustynet-relay` is async (tokio).** It uses `#[tokio::main]` with the
multi-thread runtime (default: one worker thread per CPU core). On a Pi Zero 2 W
(4 cores), this spawns 4 worker threads. Default tokio thread stack size is 2 MB per
thread: 4 × 2 MB = 8 MB for the relay thread pool, which is fine on 512 MB.

If RAM is genuinely constrained, add `.thread_stack_size(524288)` (512 KB) to the
tokio runtime builder in `crates/rustynet-relay/src/main.rs` (the
`Builder::new_multi_thread()` call near line 2264 in the Windows service path, and
the `#[tokio::main]` macro invocation for the normal path). This would save ~6 MB.

Per-session tokio tasks are heap-allocated coroutines, not OS threads. At 100
active relay sessions, the tokio overhead beyond the thread pool itself is
approximately 20-30 MB total for session state plus task futures.

---

## 5. Backend Selection: Kernel vs Userspace WireGuard

Rustynet has two Linux WireGuard backends:

**`linux-wireguard` (default):**  
Calls `ip link add dev rustynet0 type wireguard` via subprocess
(`crates/rustynet-backend-wireguard/src/linux_command.rs:140-147`). Requires
`wireguard.ko` to be loaded. On Raspberry Pi OS (Debian Bookworm, kernel 6.6.x LTS),
WireGuard is built as a module (`CONFIG_WIREGUARD=m`) and loads automatically when
`ip link add type wireguard` is called. On vanilla Debian Bookworm armhf, install
`wireguard-tools` and ensure `linux-image-armmp` is used.

**`linux-wireguard-userspace-shared` (recommended for embedded):**  
Runs the boringtun WireGuard implementation in pure userspace via `/dev/net/tun`
(`CONFIG_TUN` kernel option). Does **not** require `wireguard.ko`. This is the
correct choice for boards where kernel module availability is uncertain or for
maximum portability. The backend constant is defined at
`crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs:30`.

Set the backend in the daemon environment file:

```sh
RUSTYNET_BACKEND=linux-wireguard-userspace-shared
```

`/dev/net/tun` is available on all Raspberry Pi OS and Debian Bookworm kernels.

---

## 6. systemd Dependency and the Plaintext Fallback

Rustynet has deep systemd integration. On Raspberry Pi OS and Debian Bookworm, systemd
is the init system and all features work. The following items depend on systemd:

- **`LoadCredentialEncrypted`** in `scripts/systemd/rustynetd.service:66` — uses
  systemd 250+ encrypted credentials. Requires systemd 252 (Debian Bookworm ships
  252).
- **`systemd-creds decrypt`** binary — called by `LinuxSystemdCredsBackend`
  (`crates/rustynet-control/src/credential_unwrap.rs:138,222`) for membership signing
  and trust operations. Fails closed with an explicit error if the binary is absent.
- **`AmbientCapabilities`**, `ProtectSystem=strict`, `NoNewPrivileges` — systemd
  sandboxing directives in the service files. Not replicable without systemd.
- **`RuntimeDirectory=rustynet`**, `StateDirectory=rustynet` — systemd-managed
  directory creation.

**For non-systemd embedded images (OpenRC, SysV init):**
The daemon can run with a plaintext key bypass. Set `RUSTYNET_WG_KEY_PASSPHRASE`
to point at a plaintext passphrase file, or provision the runtime key directly at
`/run/rustynet/wireguard.key`. The daemon checks this path before attempting the
`systemd-creds` path. Create runtime directories manually in a pre-start script.
The security sandboxing (protect-system, no-new-privileges, capability bounding set)
will be absent — document this as an accepted degradation for the specific deployment.

The `systemd-creds` encrypted credential path is only required for full operator
key management workflows (`ops trust-refresh`, membership signing). A relay or
exit node that is provisioned once and runs unattended does not need this flow.

---

## 7. nftables Requirement

Rustynet requires nftables exclusively. There is no iptables detection or fallback.
At startup, the prerequisite check (`crates/rustynetd/src/phase10.rs:1803`) runs
`ip -V` to verify that iproute2 is present and fails closed if absent. The `nft`
binary itself is not checked at startup — it is invoked only when exit/blind_exit
NAT rules are applied. If `nft` is missing, the daemon starts but applying exit
NAT rules will fail at that point.

The nft commands used are standard syntax compatible with nftables 0.9.x+. Debian
Bookworm ships nftables 1.0.6 at `/usr/sbin/nft` (the correct hardcoded path).
On boards without nftables pre-installed:

```sh
apt-get install nftables
```

Boards running older Raspberry Pi OS images with iptables-legacy only will also
need nftables installed. There is no iptables-nft compatibility shim used by
Rustynet — the `nft` binary is invoked directly.

**Required kernel configuration for nftables exit/blind_exit operation:**

```
CONFIG_NF_TABLES=y
CONFIG_NF_TABLES_INET=y
CONFIG_NF_CONNTRACK=m
CONFIG_NFT_MASQ=m          # exit role NAT masquerade (available since kernel 4.3)
CONFIG_NFT_REDIR=m         # DNS protected-mode redirect (available since kernel 4.1)
CONFIG_NFT_NAT=m
```

Minimum kernel version for all features: **Linux 4.3**. Debian Bookworm armhf
ships kernel 6.1 (LTS). All requirements are satisfied.

---

## 8. Minimum Kernel Version Summary

| Feature | Minimum kernel | Notes |
|---|---|---|
| WireGuard kernel module | 5.6 | Or use userspace backend to bypass entirely |
| nftables inet tables | 3.13 | All Pi OS and Debian Bookworm kernels |
| nftables masquerade | 4.3 | Required for exit role NAT |
| nftables redirect | 4.1 | Required for DNS protected mode |
| `getrandom(2)` syscall | 3.17 | Required for Rust crypto RNG |
| `/dev/net/tun` | 2.6 | `CONFIG_TUN=m` |
| `SO_PEERCRED` (IPC auth) | 2.2 | Always present |
| `clock_gettime64` (glibc 2.36+) | 5.1 | Transparent via glibc; no action needed |

**Practical minimum: Linux 4.3** for exit/blind_exit. Linux 3.17 for relay-only
deployment. Raspberry Pi OS Bookworm ships kernel 6.6.x LTS and all requirements
are met.

---

## 9. The 2038 Problem: Not an Issue

Rustynet does not use `libc::time_t`, `chrono`, or the `time` crate anywhere.
All timestamps are derived from `std::time::SystemTime::duration_since(UNIX_EPOCH)
.as_secs()` which returns `u64`. All timestamp fields on disk and wire are declared
as `u64` (e.g., `expires_unix_seconds: u64`, `timestamp_unix: u64`).

On Debian Bookworm armhf, glibc 2.36 transparently routes `clock_gettime` through
the `clock_gettime64` syscall on 32-bit ARM. Rust's `std::time::SystemTime` inherits
this routing. There is no 2038 exposure in the daemon, relay, or any library in use.

The `nix = "0.25"` dependency pulled by the boringtun fork (`features = ["time"]`)
also uses glibc's 64-bit time wrappers on Bookworm. Pre-glibc-2.34 systems (older
than Debian Bullseye) would be at risk, but Bookworm is safe.

---

## 10. File Descriptor Limits

The relay allocates one UDP socket per active session. At the default
`--max-total-sessions 4096`, approximately 4130 file descriptors are needed. The
system default `ulimit -n 1024` is insufficient.

**Add to `rustynet-relay.service`:**

```ini
LimitNOFILE=8192
```

For embedded deployments serving 1–3 peers, reduce `--max-total-sessions` to a
realistic value:

```sh
--max-total-sessions 32   # 1-3 peers, ~60 fds needed
```

The daemon itself uses fewer than 50 file descriptors and is fine at the default limit.

---

## 11. Memory Budget on 512 MB

Realistic RSS breakdown for a combined relay + exit node at 1–3 peers:

| Component | RSS |
|---|---|
| Linux kernel + system daemons (ssh, udev) | ~50 MB |
| `rustynetd` daemon (exit role, idle) | ~15–25 MB |
| `rustynet-relay` (32 active sessions) | ~20–30 MB |
| Argon2id key decrypt at startup (transient) | ~19 MB peak, released |
| Kernel conntrack table (32768 max entries) | ~10–12 MB |
| **Total at 1–3 peers** | **~95–130 MB** |
| **Available headroom** | **~370–415 MB** |

At 1–3 peers the memory profile is very comfortable. The dominant variables are
conntrack table size (tunable) and relay session count (configurable).

**Conntrack tuning for 512 MB:** The default `nf_conntrack_max` on a 512 MB system
is typically 65536 entries (~20–25 MB). For a lightly-loaded exit node, reduce to
conserve memory:

```sh
echo 8192 > /sys/module/nf_conntrack/parameters/hashsize
sysctl -w net.netfilter.nf_conntrack_max=32768
```

Persist in `/etc/sysctl.d/rustynet-conntrack.conf`.

**Swap:** Configure 256–512 MB of swap, preferably zram (compressed RAM swap) rather
than an SD card swap partition to avoid wear:

```sh
# Install zram-tools (Debian)
apt-get install zram-tools
# /etc/default/zramswap: PERCENT=50 ALGO=zstd
```

Set `vm.swappiness=10` to minimise swap usage under normal conditions.

---

## 12. Memory Fragmentation (Long-Running Relay)

The relay has continuous session churn (sessions open and close). Over days or weeks,
glibc malloc can accumulate heap fragmentation. To cause glibc to return memory to
the OS more aggressively, set in the relay's environment file (`/etc/default/rustynet-relay`
or the systemd service `Environment=` stanza):

```sh
MALLOC_TRIM_THRESHOLD_=131072
MALLOC_MMAP_THRESHOLD_=131072
```

This has no effect on correctness. It trades minor allocation overhead for a smaller
long-term RSS footprint.

---

## 13. SD Card Wear

On boards using SD card storage, excessive disk writes cause wear. The Rustynet write
patterns at 1–3 peers:

| Write source | Frequency | Per-write size |
|---|---|---|
| Gossip watermark | Once per 30s per active peer | ~100 bytes |
| Daemon state file | Only on actual state changes | ~1–10 KB |
| Session snapshot | Only on state changes | < 1 KB |
| Log file (`rustynetd.log`) | Continuously (unbounded) | Line by line |

At 3 peers, gossip watermarks produce approximately 6 writes/minute or ~8,640
writes/day — well within the endurance of any modern SD card (TBW >> 10 GB),
but meaningful over years of continuous operation.

**Mitigations:**

1. **Redirect state paths to tmpfs.** All runtime paths are configurable via flags
   or environment variables. In `rustynetd.service`, override:
   ```ini
   Environment=RUSTYNET_STATE_ROOT=/run/rustynet/state
   ```
   and mount `/run/rustynet/state` as tmpfs. Periodically rsync to a persistent
   store if needed.

2. **Log to journal only.** When running under systemd, `rustynetd` logs to stderr
   which is captured by the journal. The log file at
   `/var/lib/rustynet/logs/rustynetd.log` is supplementary and grows without bound
   (no rotation is implemented). Disable it or redirect to `/dev/null` for embedded
   deployments. Configure the journal to use volatile storage:
   ```ini
   # /etc/systemd/journald.conf
   [Journal]
   Storage=volatile
   ```

3. **`noatime` mount option.** Add `noatime` to the root filesystem entry in
   `/etc/fstab` to eliminate access-time update writes on every file read.

4. **Use a USB drive for state.** For long-running deployments, redirect
   `/var/lib/rustynet` to a USB drive, which has dramatically higher TBW than
   a microSD card.

---

## 14. Network Interface Auto-Detection

Rustynet does not depend on predictable interface names (`eth0` vs `enp2s0`) and
does not depend on udev for interface discovery. When
`RUSTYNET_EGRESS_INTERFACE=auto` (the default), the daemon runs
`ip -o route show to default` and parses the `dev` field from the kernel routing
table. This works correctly regardless of interface naming convention.

On minimal embedded images without udev, the physical NIC will typically be named
`eth0` or `wlan0` by the kernel — both are discovered correctly by the routing
table lookup.

Ensure `iproute2` is installed:

```sh
apt-get install iproute2
```

Without it, auto-detection fails closed at daemon startup.

---

## 15. Floating Point ABI

`armv7-unknown-linux-gnueabihf` uses hard-float (VFPv3-D16). All `f64` operations
in Rustynet map to hardware VFP instructions. There is no soft-float emulation
overhead. The production `f64` uses are:

- Relay rate limiter (`crates/rustynet-relay/src/rate_limit.rs:65-66`) — token
  bucket calculations. Fast VFP instructions.
- Daemon CPU metrics (`crates/rustynetd/src/perf.rs:9,24`) — monitoring only,
  not on any data path.

**ABI mismatch risk:** Linking a hard-float Rustynet binary against a soft-float
system library produces a link-time error (incompatible ELF ABI flags), not a
silent runtime bug. Debian Bookworm armhf ships exclusively hard-float libraries.
No risk on a correctly-configured Debian Bookworm armhf system.

---

## 16. Deployment Configuration Summary

Minimum configuration for a relay node on Raspberry Pi Zero 2 W (32-bit Debian
Bookworm):

```sh
# /etc/default/rustynet-relay
RUSTYNET_RELAY_MAX_TOTAL_SESSIONS=32
RUSTYNET_RELAY_PORT_RANGE_START=40000
RUSTYNET_RELAY_PORT_RANGE_END=40031
MALLOC_TRIM_THRESHOLD_=131072
MALLOC_MMAP_THRESHOLD_=131072
```

```ini
# addition to rustynet-relay.service [Service] section
LimitNOFILE=256
```

For an exit/blind_exit node, additionally:

```sh
RUSTYNET_BACKEND=linux-wireguard-userspace-shared
```

```sh
# /etc/sysctl.d/rustynet-conntrack.conf
net.netfilter.nf_conntrack_max=32768
```

---

## 17. Pi Zero 2 W Hardware Specifics

These apply specifically to the Raspberry Pi Zero 2 W and are not covered by the
general armv7 porting work above.

### NTP is a Hard Operational Dependency

The Pi Zero 2 W has **no battery-backed real-time clock**. On cold boot the hardware
clock starts at the Linux epoch (or a saved firmware timestamp). Until NTP
synchronises, `SystemTime::now()` may return a time that is months or years in the
past or future.

Rustynet's anti-replay windows and Ed25519-signed gossip bundle freshness checks are
both time-sensitive. A node that starts before NTP has synced will either reject all
inbound bundles as "from the future" or emit bundles with stale timestamps that peers
reject.

**Required:** ensure `systemd-timesyncd` or `chrony` is running and the system clock
is synchronised before `rustynetd` starts. Add the following to `rustynetd.service`:

```ini
After=network-online.target time-sync.target
Wants=network-online.target
```

For an always-on relay with no guaranteed internet access at boot, configure `chrony`
with `makestep 1 -1` so it corrects large clock jumps immediately rather than
slewing slowly.

### ARMv8 Crypto Extensions Are Unavailable in 32-bit Mode

The Cortex-A53 supports AES hardware acceleration (ARMv8 Crypto Extensions) only in
AArch64 mode. Running 32-bit Raspberry Pi OS disables these extensions. AES
operations fall back to software.

This is not a problem for Rustynet. **WireGuard uses ChaCha20-Poly1305**, not AES.
The `boringtun` implementation in `third_party/boringtun/` is pure Rust and has no
AES dependency. ChaCha20-Poly1305 performs excellently on ARMv7 with NEON (which
*is* available in 32-bit mode on the Cortex-A53). This is the correct cipher choice
for this target architecture and is already what boringtun selects.

If a developer adds any feature that introduces AES (e.g., AES-GCM for a new
transport), be aware that on this hardware in 32-bit mode it will be significantly
slower than on 64-bit or x86.

### WiFi and Bluetooth Radio Sharing (CYW43438)

The Pi Zero 2 W uses a single CYW43438 combo chip that shares one antenna between
**2.4 GHz 802.11n WiFi** and **Bluetooth 4.1**. When Bluetooth is active
(BT keyboard, serial console, BT audio), the WiFi subsystem is time-multiplexed with
the BT radio. This causes periodic gaps in WiFi transmission, which manifests as
latency spikes and packet loss bursts on the WireGuard UDP path.

For a relay or exit node, these bursts can trigger spurious WireGuard session
keepalive timeouts and relay session expiry under light load.

**Disable Bluetooth on relay/exit deployments:**

```sh
# /boot/firmware/config.txt
dtoverlay=disable-bt
```

This frees the full WiFi radio budget to WireGuard UDP and eliminates the
time-multiplexing interference.

### WiFi-Only Networking — No Onboard Ethernet

The Pi Zero 2 W has no onboard ethernet port. All WireGuard, relay, and gossip
traffic travels over the single 2.4 GHz WiFi interface (`wlan0`). There is no USB
ethernet built into the SoC; wired connectivity requires a USB OTG adapter.

### Single USB OTG Port

The Pi Zero 2 W has one micro-USB OTG port for data (separate from the power port).
If a USB OTG ethernet adapter is used for wired connectivity, the data port is
occupied and USB serial console access is unavailable simultaneously. For
production relay deployments, plan remote administration over WiFi SSH. Do not
rely on USB serial console as the primary access path on a live relay node.

---

## 19. CI Requirements Before Claiming 32-bit ARM Support

Per `PlatformSupportMatrix.md` and `Requirements.md`, 32-bit ARM support is a
finished-product requirement and must be gate-verified before being called supported.
The minimum CI additions required:

1. Add `armv7-unknown-linux-gnueabihf` target to `.github/workflows/cross-platform-ci.yml`
   using `cross` (`cross build --target armv7-unknown-linux-gnueabihf`) or a native
   QEMU-based runner.
2. Run `cargo check --target armv7-unknown-linux-gnueabihf` at minimum; ideally
   `cargo build --release` for the relay and daemon binaries.
3. Verify the `AtomicU64`/`u128` soft-concern sites with `--target armv7-unknown-linux-gnueabihf`
   and confirm no link errors.
4. Record a live-lab evidence run on ARM hardware (Pi Zero 2 W or equivalent) for
   relay role and exit role, following the standard live-lab runbook.
5. Append a row to `documents/operations/live_lab_run_matrix.csv` for each evidence run.

This work is not release-blocking for the current Linux/macOS/Windows role parity
mandate. Do not pick it up until that mandate is complete.

---

## 20. Known Open Items (At Time of Writing)

| Item | Severity | Notes |
|---|---|---|
| `PlatformSupportMatrix.md` "compile blocker" language overstates severity | Documentation | Update after first successful cross-compile confirms no hard blockers |
| No `.cargo/config.toml` in repo | Setup | Must be created before cross-compilation; do not commit host-specific paths |
| `LimitNOFILE` missing from `rustynet-relay.service` | Operational | Add before any deployment; default 1024 is insufficient at >512 sessions |
| `rustynetd.service` missing `After=time-sync.target` | Operational | Required on Pi Zero 2 W (no RTC); clock must be synced before daemon starts |
| Log file has no rotation | Operational | Mitigate by redirecting to `/dev/null` or using journal-only on embedded |
| No CI gate for armv7 target | CI | Required before 32-bit ARM can be called supported |
| No live-lab evidence row for ARM | Evidence | Required before 32-bit ARM can be called supported |
