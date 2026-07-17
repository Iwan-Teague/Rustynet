# Dedicated Linux VM-Host Plan (2026-07-14)

**Status: DRAFT / PROPOSAL — awaiting owner ratification.** This is net-new
direction. No prior plan for a dedicated Linux machine that hosts the lab VMs
exists in the repo; the entire live-lab + parity program to date assumes a
single macOS + UTM host ("iwan's MacBook Pro"). This ledger scopes standing up a
dedicated x86-64 Linux box as a second, larger VM host and integrating it with
the existing node/live-lab orchestrator.

**Operating contract.** `AGENTS.md` / `CLAUDE.md` are mandatory
(security-first, fail-closed, default-deny, no custom crypto, one hardened path,
evidence-before-claims, Rust-first). Everything below assumes them.

---

## 1. Motivation — why a dedicated Linux VM host is worth it

Four independent reasons, strongest first:

1. **Unblocks the one role cell the Mac lab structurally cannot prove.**
   Apple-Silicon UTM/QEMU does **not** expose nested virtualization to guests, so
   Windows **WinNAT / Hyper-V** cannot run in a UTM Windows guest — which parks
   the Windows **exit** and **blind_exit** dataplane cells indefinitely (see
   `RustNodeOrchestratorCompletionBrief_2026-07-12.md §8.1`,
   `WindowsExitNodeRunbook_2026-06-04.md`, `CrossPlatformRoleParityPlan_2026-06-21.md §3`).
   The documented workarounds are a physical Windows device or an Azure Dv5/Ev5
   cloud VM. **An x86-64 Linux host with KVM does nested virt natively**, so a
   Windows-on-x86 guest on this box can finally run WinNAT — closing a
   release-blocking parity gap the current host cannot.

2. **Capacity.** ~64 GB RAM + a 12-thread CPU comfortably hosts ~10 concurrent
   Linux guests (≈4–6 GB each), which the parity/efficiency plans repeatedly gate
   on host headroom (`LiveLabExecutionEfficiencyPlan_2026-06-20.md §7`,
   `CrossPlatformRoleParityRoadmap_2026-06-22.md §8.3`). Today concurrency is
   bounded by the Mac's CPU/disk. A second host relieves that ceiling and lets the
   Mac and Linux labs run concurrently.

3. **Reduces common-mode risk toward the higher test tiers.**
   `LiveLabVmConnectivityRulebook.md` §6 notes a single-host tier "does not prove
   resistance to hypervisor compromise or common-host failure; only remote tiers
   reduce that common-mode risk." A second physical host on genuinely distinct
   networks is a concrete step toward Tier 3 (`dedicated_physical_lab_v1`) and
   Tier 4 (`remote_wild_v1`).

4. **x86-64 native guests.** The Mac lab is aarch64-only (all guests are arm64).
   An x86-64 host adds real amd64 coverage for every OS — closer to the machines
   most operators actually run.

> **Hardware note — confirm before density planning.** The stated spec is
> "~64 GB graphics, 12-thread CPU." This plan assumes **64 GB of system RAM**
> (the binding constraint for VM density). A GPU/VRAM figure is irrelevant to
> headless VM hosting unless GPU passthrough is wanted for the `llm` role. If the
> 64 GB is actually VRAM and system RAM is smaller, revise the ~10-VM target down.

---

## 2. Current-state architecture (what we are integrating with)

The orchestrator has **two independent planes**. This split is the crux of the
whole readiness picture:

### 2.1 Guest-orchestration plane — host-agnostic, Linux-ready TODAY
The actual live-lab work — clean-up, ship source, bootstrap + launch the real
`rustynetd` node, collect pubkeys, distribute signed membership/DNS/traversal
bundles, deploy relay/anchor, run per-role + live + cross-network + chaos
validators, cleanup — runs over **plain OpenSSH to a guest IP** and does not care
what hypervisor hosts the guest.

Flow (per the discovery pass, verify symbols before editing):
- `vm_lab_inventory.json` lists each guest `{alias, ssh_target/last_known_ip,
  platform, ssh creds, optional controller}`.
- Operator declares topology with repeated `--node <alias>:<role>` flags;
  `role_assignment.rs::parse_node_role_arg` → `NodeRoleAssignment{alias, role}`.
- `orchestrator/native.rs::execute_rust_native_orchestration` matches each alias
  to its inventory entry and builds `NodeConnection::Ssh(host = last_known_ip ||
  ssh_target, …)` with `StrictHostKeyChecking=yes`.
- `adapter/factory.rs::node_adapter_for(platform, connection)` builds the per-OS
  `NodeAdapter` (`linux.rs` / `macos.rs` / `windows.rs`), stored per-alias in
  `OrchestrationContext.adapters` (`context.rs`).
- `plan.rs::PlanBuilder` + `runner.rs::StateMachineRunner` drive ~50
  `OrchestrationStage` impls in dependency order with skip-cascade.

Engine selection is **by invocation** (`vm_lab/mod.rs:9176`): `--node …` →
Rust `--node` engine; legacy `--exit-vm`/`--client-vm` → bash engine. The whole
lab robot compiles only under the default-off `vm-lab` cargo feature (RNQ-17).

`NodeConnection::Ssh` is already valid for Linux/Windows/macOS guests and targets
whatever IP it is given — **it does not care what hypervisor hosts the guest.**

### 2.2 VM-lifecycle plane — HARDCODED to macOS/UTM
Power on/off, live-IP discovery, and host→guest file push/pull/exec all go
through UTM `utmctl` (macOS-only). The controller is a **single-variant enum**:

```rust
// crates/rustynet-cli/src/vm_lab/mod.rs (≈:1601 — grep `enum VmController`)
pub(crate) enum VmController {
    LocalUtm { utm_name: String, bundle_path: PathBuf },
}
```

- `utmctl` path is hardcoded (`mod.rs:44 DEFAULT_UTMCTL_PATH =
  "/Applications/UTM.app/Contents/MacOS/utmctl"`, overridable only via an optional
  config field; `default_utmctl_path()` ≈`mod.rs:2312`).
- Power = `utmctl start|stop <name>` (`transition_local_utm_vm` ≈`mod.rs:31967`),
  reconciled against the local `ps` table.
- Live-IP discovery = `utmctl ip-address <name>`, with a host-side fallback that
  reads the guest MAC from the UTM bundle's `config.plist` and greps the Mac's
  `arp -a`.
- File transfer/exec = `utmctl file push|pull` / `utmctl exec`.
- `resolve_start_targets` **hard-fails** any entry without a `LocalUtm`
  controller: *"only local UTM-backed entries can be started here"*
  (≈`mod.rs:28045`).

There is **no** libvirt / virsh / qemu-system / VBoxManage anywhere in `vm_lab`
(grep: zero hits). VM creation is not automated — guests are hand-built in UTM
then registered in the JSON. The inventory models **guests only**; the host is
implied by `controller.bundle_path` + a free-text `parent_device`. There is no
first-class host record.

> Line numbers above are indicative (as of the 2026-07-14 discovery pass) and can
> drift — grep the named symbol, do not trust the number.

---

## 3. Readiness verdict

| Plane | State on a Linux host | Work required |
| --- | --- | --- |
| Guest orchestration (SSH) | **Ready today** | None — SSH-only inventory entry, `debian-lan-11` pattern |
| VM lifecycle (power/create/IP/file) | **Blocked** — hardcoded to `LocalUtm`/`utmctl` | New `VmController` variant + discovery + transfer (net-new) |

**Bottom line:** a Linux-hosted guest can join the lab and run the full stage
pipeline **immediately, with zero code changes**, as long as it is already
powered on and SSH-reachable. What the tool cannot yet do on a Linux host is
power/create/clone/restart VMs or auto-discover their IPs — that needs a net-new
lifecycle backend behind an abstraction that does not exist today.

---

## 4. Adoption in two tiers

### Tier 1 — SSH-only integration (ZERO code; use immediately)
The inventory schema already supports off-host guests as controller-less,
SSH-reachable entries (documented in `UTMVirtualMachineInventory_2026-03-31.md`;
`debian-lan-11` is the live example). Steps:

1. Flash + set up the Linux host (§6), install a hypervisor, create the guests.
2. Bridge the guests onto a LAN the Mac can reach (§7) so they get routable IPs.
3. Set each guest to **autostart** on the host (so "the tool can't power them" is
   moot — they're always up).
4. Add each as an inventory entry **without a `controller` block**, e.g.:

```jsonc
{
  "alias": "linux-x86-exit-1",
  "include_in_all": false,
  "last_known_ip": "192.168.0.50",
  "last_known_network": "192.168.0.0/24",
  "network_group": "lan-192.168.0.0/24",
  "os": "Debian/Linux (x86_64)",
  "parent_device": "Linux VM host (x86_64, KVM)",
  "platform": "linux",
  "rustynet_src_dir": "/home/debian/Rustynet",
  "ssh_user": "debian",
  "ssh_target": "linux-x86-exit-1",   // or the IP
  "ssh_password": "…"                  // prefer key-auth; see §5
}
```

5. `ops vm-lab-sync-repo` / `vm-lab-run` / `vm-lab-bootstrap` and the full
   `--node <alias>:<role>` pipeline then work over SSH.

**This is the fastest path to value and is enough if the fleet is long-lived and
manually managed.** It does not give the orchestrator power/create control.

### Tier 2 — First-class Linux lifecycle backend (net-new implementation)
Only needed if the orchestrator itself must power/create/clone/restart guests and
auto-discover their IPs on the Linux host (e.g. for `--rebuild-nodes` keep-warm
loops, or overnight-march branch isolation). Scope:

1. **Abstract the controller.** Turn `VmController` from a single-variant enum
   into a trait (or add variants) with a driver interface:
   `start / stop / restart / status / discover_ip / push_file / pull_file / exec`.
   Keep `LocalUtm` as one impl; behaviour on macOS is unchanged (one hardened
   path — do not fork the UTM path).
2. **Add a Linux driver.** Two shapes — pick one in §8:
   - `Libvirt` (drive `virsh` on the host: `virsh start|shutdown|reboot|domstate`,
     `virsh domifaddr` for IP discovery, `scp`/`ssh` for file transfer), or
   - `Proxmox` (drive the Proxmox REST API / `qm` for lifecycle + snapshots +
     clone from templates).
3. **Hypervisor-neutral IP discovery.** Replace the UTM `config.plist` + local
   `arp -a` fallback with a driver-provided path (`virsh domifaddr` / DHCP lease /
   qemu-guest-agent). The SSH plane already tolerates a supplied IP; this only
   feeds the discovery step.
4. **Local vs remote host execution** (§8): if the orchestrator runs **on** the
   Linux box, the driver shells out locally; if it runs on the Mac and reaches
   the Linux host **over SSH** to run `virsh`, the driver wraps every command in
   an SSH hop. This choice sets the abstraction shape — decide first.
5. **First-class host record (optional but recommended).** Extend the inventory
   schema with a `hosts[]` section (`{host_id, kind: local_utm|libvirt|proxmox,
   endpoint, …}`) and reference it by id from each guest's `controller`, so a
   multi-host / cross-machine fleet has a real representation instead of the
   implied `bundle_path` + `parent_device`.
6. **VM provisioning (optional).** `virt-install` / cloud-init (or Proxmox
   templates + clone) to create guests programmatically instead of by hand.

Rough effort: the abstraction refactor + a `virsh`-over-SSH driver is a
**medium** task (one enum → trait, ~3 code paths, IP-discovery + transfer). SSH-only
Tier 1 is zero code.

---

## 5. Security considerations (§4 baseline)

- **SSH custody.** Prefer key-auth over the lab's shared `tempo`/`password`
  convention for a new, potentially internet-adjacent host; keep
  `StrictHostKeyChecking=yes` (the Rust engine already sets it) and pin
  `known_hosts`. Never log credentials.
- **No control weakening.** The Linux driver must not introduce a second/weaker
  apply path; reuse the single verified stage pipeline. Lifecycle commands are
  argv-only exec (`virsh …` as argv, never a shell string with untrusted values)
  — same rule as the UTM path and the privileged-helper boundary.
- **Fail closed.** Unknown host state, unreachable host, or a driver command that
  cannot be verified → error, never "assume up / assume clean." The existing
  residue/cleanup asserts (RNQ, Pair-1 P1-2) must run identically on Linux-hosted
  guests.
- **Network isolation.** Bridge guests onto a controlled segment, not a
  trust-sensitive LAN by default (aligns with the dual-plane
  `network_profile.rs` / `LiveLabVmConnectivityImplementation_2026-07-10.md`
  rulebook — a Linux host is a natural place to build the Tier-3 dedicated lab
  network).
- **WinNAT guest.** The x86 Windows guest that motivates this host (§1.1) must
  still meet the `SecurityMinimumBar` for the exit role — this host only unblocks
  *proving* it, it does not lower the bar.

---

## 6. OS recommendation + host setup runbook

**Priority: as lightweight as possible, headless, good at managing ~10 VMs,
integrates with an SSH-driven orchestrator.**

### Primary: Debian (stable) minimal — netinst, no desktop + libvirt/QEMU/KVM
Why:
- Leanest option that is still batteries-included for KVM; smallest resident
  footprint leaves the most RAM/CPU for guests.
- **Matches the existing Debian lab guests** — same tooling and muscle memory,
  same `apt` workflow, same distro the orchestrator already exercises.
- Rock-solid KVM; drive VMs with `virsh` / `virt-install` / cloud-init.
- Closest fit to the Tier-1 SSH-only pattern and the natural target for a future
  `virsh-over-SSH` `VmController` (Tier 2).

Setup sketch:
```bash
# Debian netinst, "SSH server" + "standard system utilities" only (no DE).
sudo apt install -y qemu-kvm libvirt-daemon-system virtinst \
                    bridge-utils cpu-checker
kvm-ok                       # confirm hardware virt + (for Windows) nested virt
sudo usermod -aG libvirt "$USER"
# create guests with virt-install / import qcow2; set autostart:
sudo virsh autostart <domain>
# nested virt for the x86 Windows/WinNAT guest (Intel shown; AMD = kvm_amd):
echo 'options kvm_intel nested=1' | sudo tee /etc/modprobe.d/kvm-nested.conf
```

### Alternative: Proxmox VE 8 — if you want a management UI/API out of the box
Why: Debian-based (so barely heavier at the host layer), boots headless, gives a
**web UI + REST API + `qm`/`pct` CLI**, snapshots, templates, clone, cloud-init —
a materially better story for a human juggling many VMs, and a clean API target
for a `VmController::Proxmox`. Downside: opinionated, pulls in ZFS/cluster bits
you may not use; slightly less minimal than bare Debian.

**Avoid:** Ubuntu Server (snap overhead, heavier for no gain here), any desktop
distro, ESXi (licensing + fussy hardware).

**Lead recommendation:** the operator stressed *lightweight* → **Debian minimal +
KVM**. Trade a little weight for a management UI/API → **Proxmox**.

### Flashing (the immediate operator action)
1. From the current Windows boot, write the chosen ISO to a USB (Rufus / balena
   Etcher / `dd`).
2. Boot the target drive from USB; install headless (Debian: deselect all
   desktop tasks, keep only SSH server + standard utils).
3. Confirm virt support post-install: `kvm-ok` and, for Windows guests,
   `cat /sys/module/kvm_intel/parameters/nested` (or `kvm_amd`) → `Y`.
4. Bridge networking (§7), create guests, register per §4 Tier 1.

> This does **not** require wiping the Windows install if a spare/second drive is
> available — a dual-boot to a dedicated Linux drive is enough. Confirm whether
> the Windows install must be preserved before flashing.

### 6.1 As-built host record + disk-scope HARD RULE (2026-07-16)

The host is stood up and live. As-built, verified on the box:

| Property | Value |
| --- | --- |
| CPU | AMD Ryzen 7 7700X, 8C/16T, `svm` present |
| RAM | 61 GiB (closes §8 #6) |
| Nested virt | **`kvm_amd nested = 1` — already on by default** (§1.1 unblocked) |
| OS | Ubuntu 24.04 LTS, headless, `multi-user.target` |
| Root | `/dev/sdb2` ext4 464.8 G (427 G free), ESP `/dev/sdb1` 1 G, 4 G swapfile |
| Network | WiFi `wlp7s0` up (DHCP 10.230.76.5); wired `eno1` **DOWN / NO-CARRIER** |

**DISK SCOPE — HARD RULE (closes §8 #7, non-negotiable):**

| Disk | Device | Contents | Rule |
| --- | --- | --- | --- |
| 0 | Samsung 860 EVO 500G | NTFS data | **OFF LIMITS** |
| 1 | Samsung 870 EVO 500G | `/dev/sdb` — this Ubuntu VM host | **only writable target** |
| 2 | Samsung 980 NVMe 932G | **Windows 11 boot** | **NEVER TOUCH** |

Enforcement:
- Every destructive disk op (`dd`/`mkfs`/`parted`/`sgdisk`/`wipefs`, installer
  targets, libvirt storage pools) targets **`/dev/sdb` only**.
- **Verify by model/serial, never a bare device letter** — SATA enumeration can
  shift across boots. Check `lsblk -o NAME,SIZE,MODEL,SERIAL` (expect
  `Samsung SSD 870 EVO`) or pin via `/dev/disk/by-id/` before writing.
- libvirt's default pool `/var/lib/libvirt/images` is on sdb → compliant by
  default. Do **not** add pools on Disk 0 or the NVMe.
- Never propose reclaiming Disk 0 or the NVMe for VM capacity; if space runs
  short, ask. Windows must remain bootable from the UEFI boot menu.

**Deviation from the §6 lead recommendation — logged, accepted:** the host runs
**Ubuntu 24.04**, not the recommended Debian minimal, and §6 lists "Avoid: Ubuntu
Server (snap overhead)". The build is a minimal debootstrap with **no `snapd`
installed** and no desktop, so the stated objection does not apply — it is
functionally the Debian-minimal profile §6 asked for (same `apt` workflow, same
KVM stack). Recorded here rather than silently diverging; revisit only if snap or
footprint problems actually materialize.

**As-installed (2026-07-16) — §6's `apt` line does NOT work verbatim on Ubuntu
24.04.** `qemu-kvm` has **no candidate** on noble (it was a transitional stub and
is gone); the real package is `qemu-system-x86`. Actually installed and verified:

```bash
sudo apt install -y qemu-system-x86 qemu-utils libvirt-daemon-system \
  libvirt-clients virtinst bridge-utils cpu-checker ovmf swtpm swtpm-tools \
  dnsmasq-base cloud-image-utils git build-essential pkg-config libssl-dev curl
sudo usermod -aG libvirt,kvm "$USER"      # re-login to take effect
# Rust (run-on-host build; distro rustc 1.75 is too old for edition 2024):
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
  sh -s -- -y --profile minimal --default-toolchain 1.88.0 -c rustfmt -c clippy
```

Beyond §6's list, `ovmf` (UEFI, incl. `OVMF_CODE_4M.secboot.fd`) and `swtpm`
(TPM 2.0) are **required for the Windows 11 guest** that motivates this host
(§1.1) — Win11 will not install without UEFI + TPM 2.0. `cloud-image-utils`
supports the §4 Tier-2.6 cloud-init provisioning path.

Verified state: QEMU 8.2.2 / libvirt 10.0.0 / virt-install 4.1.0; `kvm-ok` →
"KVM acceleration can be used"; `domcapabilities` → `<domain>kvm</domain>` (real
KVM, not TCG); `virsh` works **unprivileged** as `ubuntu-server` (libvirt group);
`libvirtd` enabled+active; net `default` active+autostart; Rust 1.88.0 matching
`rust-toolchain.toml`, host triple **`x86_64-unknown-linux-gnu`** (so a plain
`cargo check` on the box *is* increment 0/6's target build).

**Storage pool:** Ubuntu's libvirt ships the default *network* but **no default
*pool*** — it was defined manually as `default` → `/var/lib/libvirt/images`,
built/started/autostart. Verified on-rule: that path resolves to `/dev/sdb2` →
`Samsung SSD 870 EVO 500GB`.

**Pool write access — group-writable, no stored credential (2026-07-17).** The
pool shipped `drwx--x--x root root`, so staging an image needed `sudo`, and
`sudo -n` on this box needs a password. Rather than store a sudo password (this
repo is public — see the secrets sidecar in `CLAUDE.md` §12.3), the pool is
group-owned by `kvm`:

```
sudo chgrp kvm /var/lib/libvirt/images
sudo chmod 2771 /var/lib/libvirt/images     # -> drwxrws--x root kvm
```

`ubuntu-server` **and** `libvirt-qemu` are both already in `kvm` (gid 993), so the
writer and qemu's reader are both covered by the group, and `2771` leaves the
world bits at `--x` — **identical to the original `711`**, not the looser `2775`.
The setgid bit makes new images inherit group `kvm` so qemu can read them without
a chown. One privileged command, once; every image fetch after it is unprivileged.
`vm-lab-fetch-image` tries the unprivileged `install` first, falls back to
`sudo -n`, and prints this exact remediation if both fail.

**Image integrity.** `vm-lab-fetch-image` takes an optional `--sha256 <hex>`,
verified on the host **before** the image is installed into the pool and
re-verified against an image already in the pool (the `.done` marker records that
some past run finished; it is not evidence the bytes are still right). A mismatch
refuses and does not overwrite. The 64-hex validation is also the shell-injection
boundary, since the value is interpolated into the host script.

Caveat worth knowing before pinning: **Fedora publishes no digest for
`virtio-win.iso`** — the `CHECKSUM` file beside it covers only the four RPMs, in
MD5. So a pin for that ISO is trust-on-first-use: it detects drift or corruption
after the first fetch but cannot establish first-fetch authenticity. The transport
is sound (verified: one connection, `:443`, TLS 1.3, `scheme=HTTPS`; the
`Location: http://` hops it advertises are followed on the *existing* TLS socket,
and `--proto-redir =https` provably refuses a real cross-host downgrade with
`Protocol "http" not supported or disabled in libcurl`).

Installed 2026-07-17: `virtio-win.iso`, 789645312 bytes,
`sha256 e14cf2b94492c3e925f0070ba7fdfedeb2048c91eea9c5a5afb30232a3976331`
(virtio-win-0.1.285), `ubuntu-server:kvm 0644`.

### 6.2 Guest provisioning — cloud-image + cloud-init (works; one hard gotcha)

Guests are provisioned from Debian cloud images + cloud-init (§4 Tier-2.6), not
interactive ISO installs: `qemu-img` overlay on a shared read-only base +
`cloud-localds` seed ISO + `virt-install --import`. Fast, headless, repeatable.
Script: `provision_guest.sh <name> [ram] [vcpus] [disk]` (carries a hard-rule
guard that aborts unless the pool's backing disk model is the 870 EVO).

> **GOTCHA — `virt-install --graphics none` creates a VM with NO video device,
> and that makes Debian 13 cloud images boot-loop forever.** The image's GRUB is
> built with `GRUB_TERMINAL_OUTPUT="gfxterm serial"`; **gfxterm requires a video
> device**. With no VGA, gfxterm init fails, the menuentry aborts *before*
> reaching `linux`/`initrd`, GRUB re-renders and auto-boots again — an endless
> ``Booting `Debian GNU/Linux'`` loop, **no kernel output at all** (not even
> `earlyprintk`), and the qcow2 overlay stays frozen at ~197 KB.
>
> **Fix: add `--video vga`** (stays headless — no display is exported; it just
> gives GRUB a framebuffer to init against).
>
> Diagnosis notes for next time — the symptom points at everything except the
> real cause. Ruled out by bisection: image is valid (`qemu-img check` clean),
> q35 is fine (boots under plain QEMU), the 40 G-over-3 G overlay is fine, the
> seed CDROM is fine, 4 GiB RAM is fine, AppArmor is not even confining libvirt.
> Reproduce the fault on demand with plain QEMU by adding **`-vga none`**; note
> `-nographic` alone does **not** reproduce it (it still leaves a VGA device
> attached). Also: a running domain holds a write-lock on its qcow2, so a plain
> `qemu-system-x86_64` test against a live domain's disk silently produces no
> output — `virsh destroy` first or the test is meaningless.

Proven live 2026-07-16 on guest `linux-x86-client-1` (Debian 13 trixie,
6.12.95+deb13-cloud-amd64): `domstate` → running (incr 2), **`virsh domifaddr` →
192.168.122.137 (incr 3 ladder rung 1)**, cloud-init `status: done`, host→guest
SSH via key auth OK, passwordless sudo OK, and **`svm` visible inside the guest**
(nested virt reaches the guest via `--cpu host-passthrough`) — the §1.1
Windows/WinNAT prerequisite.

**Networking — bridging is NOT required for the box-local milestone.** §7's `br0`
**cannot run over WiFi** (802.11 station mode will not forward the 4-address
frames a bridge needs), and `eno1` currently has **no carrier**. But under the
ratified **run-on-host** architecture the orchestrator lives *on this box*, and
the host is the gateway for libvirt's NAT `default` net (192.168.122.0/24) — so
it can SSH NAT'd guests, and guests can mesh with each other, **without a
bridge**. That is enough for increment 0/6's build check + a box-local `--node`
run.

A wired `br0` is still required for: the **Mac** reaching these guests directly
(Tier-1 `debian-lan-11` pattern, Mac-side MCP/lab tooling) and any
**cross-host mesh** with the macOS/UTM fleet. **Plug `eno1` into the LAN** before
those. Wired would also cure the intermittent SSH auth flake seen over `wlp7s0`.

---

## 6.8 MCP surface — increment 5 re-scoped (2026-07-16)

**Yes, there is an MCP server: `rustynet-mcp-lab-state`** (`crates/rustynet-mcp/src/bin/lab_state.rs`).
It is how an agent drives the lab without memorising CLI flags. It was **UTM-only**
while the CLI became multi-host, so the two had drifted.

### 6.8.1 ✅ DONE — the multi-host tools are exposed

Three tools added, mirroring the §6.7.4a pipeline so an agent calls functions
instead of remembering an order:

| Tool | Wraps | Notes |
| --- | --- | --- |
| `host_preflight` | `ops vm-lab-host-preflight` | **START HERE** for any multi-machine run. Ordered gates, GO/NO-GO, each failure names its fix. |
| `sync_host` | `ops vm-lab-sync-host` | Pins a host to a commit and proves it by read-back. |
| `discover_hosts` | `ops vm-lab-discover-hosts` | What VMs each machine has, and which are ready. |

Each **delegates to the CLI** via the existing `run_ops` helper — no logic is
re-implemented in the MCP.

### 6.8.1b `provision_guest` — creating VMs is now a command (2026-07-16)

`ops vm-lab-provision-guest --host <id> --name <guest> --image <base.qcow2>
[--ram-mb 4096] [--vcpus 2] [--disk-gb 40] [--pool <path>] [--dry-run]
[--format table|json]`, exposed as the MCP tool **`provision_guest`** (delegating,
per §6.8.2). Creating a VM was a scratchpad shell script; now it is a function,
and the hard-won details are compiled in rather than remembered:

- **`--video vga` is not optional.** `virt-install --graphics none` attaches **no
  video device**, and Debian cloud images ship `GRUB_TERMINAL_OUTPUT="gfxterm
  serial"`. gfxterm needs a framebuffer, so with none GRUB aborts the menuentry
  **before** loading the kernel and re-loops forever — no kernel output at all,
  not even `earlyprintk`, and the overlay frozen at ~197 KB. Cost hours to find
  (§6.2). Still headless: no display is exported.
- **`--cpu host-passthrough`** so the guest inherits `svm` and nested virt reaches
  *inside* it — §1.1's entire purpose.
- **backing-file overlay** so N guests share one read-only base image.

**The operator hard rule is now inventory DATA, not prose:** `hosts[].pool_disk_model`
(e.g. `"Samsung SSD 870 EVO 500GB"`). Before writing anything, provisioning
resolves the pool's backing disk and compares the **model** — never the device
letter, because `/dev/sdb` is not stable across boots and a letter is not a safe
guard. Mismatch ⇒ refuse, nothing written. `--dry-run` states plainly whether the
guard is **armed** or **SKIPPED (no pool_disk_model declared)**, so an inert guard
can never be mistaken for a passing one.

Input validation is deliberately allow-list, because a guest name becomes a
libvirt domain name **and** a pool filename **and** argv to `virsh`/`qemu-img`:
ASCII alphanumeric / `-` / `_`, 1..=60, no leading `-`. Images must be **bare
filenames** (no `/`, no `..`) so they cannot escape the pool. `local_utm` hosts are
refused (UTM guests are made in the UTM app). Tests cover
`evil;rm -rf /`, `../escape`, `-flag`, quotes/backticks/`$`/newlines, over-length,
and `../../etc/passwd`.

> **UNVERIFIED — deliberate guard.** The execution path was written while the lab
> host was **offline**, so after the pre-flight checks it **returns an error
> rather than provisioning**, printing the plan. `--dry-run` is fully usable now.
> **Remove that guard only once it is proven live on `ubuntu-kvm-1`** — shipping an
> unproven VM-creating path as if it worked is exactly the "dry-run-as-pass"
> failure the parity roadmap forbids.

### 6.8.1a MCP coverage matrix — what already works on the box (audited 2026-07-16)

**Most VM-lifecycle tools already work on `ubuntu-kvm-1` and needed no work.** The
rule is simply *which path the tool takes*: tools that shell out to the CLI inherit
increment 2's controller dispatch for free; tools that call `utmctl` directly are
macOS-only. Audited, not assumed:

| Tool | Path | Works on the box? |
| --- | --- | --- |
| `power_on_vm` | → `ops vm-lab-start` | **✅ yes** (CLI dispatches per controller) |
| `power_off_vm` | → `ops vm-lab-stop` | **✅ yes** |
| `restart_vm` | → `ops vm-lab-restart` | **✅ yes** |
| `get_vm_diagnostics` | → `ops vm-lab-status` | **✅ yes** |
| `sync_repo_to_vm` | → `ops vm-lab-sync-repo` | **✅ yes** |
| `bootstrap_vm` | → `ops …` | **✅ yes** |
| `discover_hosts` / `sync_host` / `host_preflight` | → `ops …` (new, §6.8.1) | **✅ yes** |
| `get_vm_power_state` | `utmctl list` | ❌ **UTM only** — superseded by `discover_hosts` |
| `get_vm_network_info` | `utmctl` | ❌ UTM only |
| `reset_vm_network` | `utmctl`/plist | ❌ UTM only (ADR-004 makes network mutation a UTM-only transaction anyway — §6.5.4) |
| `host_disk_status` | local `df` | ❌ **THIS machine only** — never a remote host's disk |
| `recover_stuck_vms` | → `ops …`, but UTM/`arp`-shaped internally | ⚠️ unverified on libvirt |

So "turn VMs on/off on the box" **already works**; the real gap was **listing and
status**, which `discover_hosts` now covers for both host kinds uniformly.

**🚩 The dangerous one — fixed.** `get_vm_power_state` is *the* "show me all VMs"
tool and it answers from `utmctl list`, so once a second host exists it **silently
omitted every guest on the box** — a confident, complete-looking answer missing half
the lab. A partial answer that looks total is worse than an error. It now appends a
scope footer naming the uncovered host(s) and pointing at `discover_hosts`, and the
UTM-only tools carry an explicit `SCOPE:` in their descriptions. Tests:
`utm_scope_note_names_uncovered_hosts_and_is_silent_when_single_host` (silent on a
single-host lab, names the host once a second is declared, no panic when `hosts[]`
is absent).

### 6.8.2 🚩 The original increment-5 scope was wrong — do NOT build it

The tracker said: *"branch `lab_state.rs` … on controller kind (virsh `domstate` +
a virsh recover)"*. **That would add a THIRD implementation of power control.**
Verified 2026-07-16:

- The **CLI is already controller-aware** (increment 2). `execute_ops_vm_lab_start`:
  ```rust
  // utmctl is only required when at least one selected target is UTM-backed; a
  // libvirt-only selection is powered via virsh and needs no utmctl.
  if targets.iter().any(|target| target.local_utm().is_some()) && !utmctl_path.is_file() {
  ```
  So `ops vm-lab-start|stop|restart` already dispatch per controller.
- The **MCP bypasses that** and shells out to `utmctl` **directly at 5 sites**:
  `get_vm_power_state`, `utm_power_status`, `reset_vm_network`,
  `get_vm_network_info`, `utm_status_map`. That duplication **is** the defect —
  a second, weaker path (§3: one hardened execution path per workflow).

**Re-scoped increment 5 = DELEGATION, not duplication:** make those five tools
call the controller-aware CLI instead of `utmctl`. libvirt support then arrives
for free, the duplicate path disappears, and there is nothing new to keep in sync.
Adding virsh to the MCP would make the drift permanent.

### 6.8.3 ✅ DONE — a misleading error that would have cost real time

`alias_to_utm` returns `None` **both** when an alias is absent **and** when it is
present but non-UTM-backed (a libvirt controller has no `utm_name`). All five
callers reported the same thing:

```rust
return tool_error(&format!("Unknown alias '{alias}' (not in inventory)"));   // a LIE for libvirt guests
```

A libvirt guest **is** in the inventory, so this sends an operator hunting a
phantom inventory bug. Added `utm_resolution_error()`, which distinguishes the two
and, for a non-UTM alias, names the controller kind + `host_id` and points at the
controller-aware CLI. All 5 call sites updated; test
`utm_resolution_error_distinguishes_absent_from_non_utm_backed` asserts it never
claims a present alias is missing. **Fail-loud, not fail-silent.**

**Remaining (needs the box to verify):** the §6.8.2 delegation refactor, and
`recover_stuck_vms` (currently UTM/`arp`-shaped).

---

## 6.7 Parallel per-machine labs + the commit-sync mechanic (DESIGN, 2026-07-16)

**Status: SPEC, NOT IMPLEMENTED.** Owner idea 2026-07-16, assessed and accepted.

### 6.7.1 Two capabilities, deliberately separated

| | What | Needs | Status |
| --- | --- | --- | --- |
| **A. Parallel per-machine labs** | Each machine runs a **self-contained** lab; one agent drives both | commit-sync + per-machine guests | **available once §6.7.3 lands** |
| **B. One lab spanning machines** | Guests on *different* hosts mesh with each other | guest↔guest reachability, dual-NIC, ADR-004 scenario plane, the §6.5.2 collision | **blocked on §6.5** |

**A is not a stepping stone to B.** It is a separate win, and critically **A needs
none of §6.5's unsolved networking**: no mesh, no subnet routes, no dual-NIC, no
Tailscale dependency. In A the only things crossing machines are the **commit**
(in), the **results** (out), and the agent's **SSH**. Bank A now; leave B parked.

### 6.7.2 The machine split is forced by hardware, not chosen

- **Windows / WinNAT-exit needs x86 nested virt** → only `ubuntu-kvm-1`
  (`kvm_amd nested=1`, §6.1). Apple Silicon structurally cannot — that is §1.1's
  entire motivation.
- **macOS guests need Apple hardware** → only `mac-utm-1`.

The hosts are **complementary and non-substitutable**, so "Windows-focused run on
the box, macOS run on the Mac, concurrently" is the only assignment physics
allows — not load balancing. Each side also carries its own Linux arch (x86-64 on
the box, aarch64 on the Mac), which is extra coverage, not duplication.

### 6.7.3 ✅ BUILT — `ops vm-lab-sync-host` (implemented + live-proven 2026-07-16)

```
rustynet ops vm-lab-sync-host --host <host_id> [--inventory <path>]
    [--commit <ref|sha>] [--allow-dirty] [--verify-only]
    [--ssh-identity-file <path>] [--known-hosts-file <path>]
    [--timeout-secs <n>] [--format table|json]
```

Live-proven against `ubuntu-kvm-1`, every guard rail firing:

| Behaviour | Observed |
| --- | --- |
| Read-back verify catches divergence | `VERIFY FAILED — HEAD is b8304a1…, expected 18ad7b11…; the host is NOT on the requested commit` |
| Sync + verify | `{commit: b8304a1…, branch: main, dirty: false, verified: true, action: synced}` |
| Dirty gate (default) | `refusing to sync … a dirty tree is not reproducible from a SHA` |
| Local host never moved | `this command will not move your working tree` |
| Unpushed SHA | git's `upload-pack: not our ref` → `push it first — this command deliberately syncs only commits that exist on the shared remote` |

Design decisions, each with the reason (do not "simplify" these away):
- **Verify by read-back, never by assertion.** The tool runs `git rev-parse HEAD`
  *on the host* and requires equality. Reporting success from the sending side is
  precisely how two machines run different code while both rows claim one commit.
- **Refuse a dirty tree by default** — not reproducible from a SHA.
- **Resolve the SHA once, locally, and pin it.** "Sync both to main" can land two
  *different* commits: this repo has concurrent sessions committing (local HEAD
  moved mid-session on 2026-07-16 and sat 6 commits ahead of `origin/main`).
- **`reset --hard`, never `git clean -xdff`** — clean would delete the untracked
  `target/` cache (925 M on the box) and make every run a cold build.
- **`--ssh-identity-file` is overridable.** `default_lab_ssh_identity_path()` is
  `~/.ssh/rustynet_lab_ed25519`, which does **not exist** on this Mac; with
  `IdentitiesOnly=yes` a hardcoded default simply fails. Argv-only exec,
  `StrictHostKeyChecking=yes`, pinned `known_hosts` (§5).
- **SSH endpoint is DERIVED** from `connect_uri` (`LabHost::ssh_endpoint()`), not
  configured separately — one source of truth, so a re-pointed host cannot keep a
  stale address.

**Transport = fetch from the PUBLIC GitHub origin** (`https://github.com/Iwan-Teague/Rustynet.git`,
verified public: unauthenticated API → 200). **No credentials, no deploy key, no
secrets on any host.** Consequence, by design: **only pushed commits can be
synced** — a host's evidence then refers to a commit anyone can fetch. For an
unpushed tight loop, push first (matches the repo's direct-to-main convention).

**New `hosts[]` field:** `repo_dir` (absolute, validated).

### 6.7.3.1 Host readiness — `ubuntu-kvm-1` (2026-07-16)

| Item | State |
| --- | --- |
| Toolchain | rustup, cargo/rustc **1.88.0** (matches `rust-toolchain.toml`), clippy **0.1.88** (the pinned one this Mac cannot produce) |
| Repo | **real git checkout** at `/home/ubuntu-server/Rustynet`, `origin` = public GitHub, **shallow** (`.git` = 6.7 M vs 2.7 G full) |
| Provenance | `git_commit=b8304a1…`, `git_branch=main`, `git_dirty_state=clean` ✅ |
| Binary | `cargo build -p rustynet-cli --features vm-lab` → **BUILD_EXIT=0**, 162 MB |
| Build cache | `target/` 925 M preserved across syncs |

> **GOTCHA — macOS `tar` poisons provenance with AppleDouble.** The earlier
> `tar -cf - … | ssh 'tar x'` sync from the Mac created `._main.rs`,
> `._mod.rs`, `._vm_lab_inventory.json` on the box. They are **untracked**, so
> `git status --porcelain` was non-empty and **every run's `git_dirty_state`
> would have read DIRTY** for reasons unrelated to the code. Purged. This is a
> repeat offender in this repo (see the historical "AppleDouble Windows brick").
> **Use `vm-lab-sync-host` (git) — never `tar` from macOS.** If tar is
> unavoidable, `COPYFILE_DISABLE=1 tar …`.

### 6.7.3.2 Original spec (retained for rationale)

**Why it is mandatory, not convenience (verified):** run provenance is computed by
**shelling out to git at run time** — `live_lab_run_matrix.rs:1267`
`git_stdout(["rev-parse","HEAD"])`, and `vm_lab/mod.rs:2669` which *errors* when
`rev-parse` fails. The box's `~/Rustynet` is currently a **`git archive` tar with
no `.git`** (`fatal: not a git repository`), so a box-side run **cannot produce
attributable evidence**. Two runs are only comparable if both rows carry a real
`git_commit`, and each host must compute that **from its own checkout** rather
than have the syncing agent assert it.

```
rustynet ops vm-lab-sync-host \
  --inventory <path> --host <host_id> \
  [--commit <ref|sha>]   # default HEAD; resolved ONCE locally, pinned for all hosts
  [--allow-dirty]        # default: refuse
  [--verify-only]        # assert host state; change nothing
  [--format table|json]
```

Steps, each fail-closed:
1. **Resolve locally** — `git rev-parse <ref>` → full 40-char SHA. Unresolvable ref → error.
2. **Dirty gate** — local tree dirty and no `--allow-dirty` → **refuse**. A dirty
   tree cannot be reproduced on another machine from a SHA; syncing it would let
   the two hosts silently diverge while both claim the same commit.
3. **Ensure host repo** — `git init` at the host's `repo_dir` if absent.
4. **Transport** — `git bundle create` for the SHA, stream over the existing SSH
   channel, `git bundle unbundle` host-side. Chosen over `git fetch` from GitHub
   because it needs **no credentials on the host**, works for **unpushed** commits
   (the tight loop tests before pushing), and rides the key auth we already have.
5. **Checkout** — `git checkout --detach <sha>` + `git reset --hard <sha>`.
   **Do NOT `git clean -xdff`** — it would delete the untracked `target/` build
   cache (~42 G on the Mac) and turn every run into a cold build. `reset --hard`
   already fixes tracked files and leaves build output alone.
6. **VERIFY — mandatory, the whole point.** Read back the host's
   `git rev-parse HEAD` and assert it **equals** the requested SHA; assert
   `git status --porcelain` is empty (unless `--allow-dirty`). **Mismatch → error.**
   Never report "synced" from the sending side: unverified sync is exactly how two
   machines silently diverge while the evidence claims they agree.
7. **Record** — emit `{host_id, commit, branch, dirty, synced_at, verified}`;
   `--format json` for callers.

**Pin the SHA, never "latest main".** This repo has **concurrent sessions
committing** (an interleaved stash was hit on 2026-07-16); "sync both hosts to
main" can land two *different* commits and produce two run-matrix rows that look
comparable and are not. Resolve once, pin everywhere.

**New `hosts[]` field:** `repo_dir` (absolute) — where the orchestrator source
lives on that host. `mac-utm-1` → the working repo; `ubuntu-kvm-1` →
`/home/ubuntu-server/Rustynet`.

### 6.7.4a ✅ THE PIPELINE — call these, in this order. Do not improvise.

**Nothing here is the agent's to remember.** Each step is a command that verifies
its own preconditions and **fails closed with the exact next command**. If you
find yourself relying on memory or on prose in this document, that is a bug in
the tooling — fix the tooling.

```
1.  git push origin HEAD:main                      # hosts fetch from the shared origin
2.  rustynet ops vm-lab-sync-host   --host <id> --commit <sha>   # per host; verifies by read-back
3.  rustynet ops vm-lab-host-preflight --commit <sha>            # ordered gates; must say GO
4.  rustynet ops vm-lab-preflight   --select-all                 # per-GUEST readiness (pre-existing)
5.  <launch the per-OS runs>                                     # only after GO
6.  <BOTH runs finish>  → read both run-matrix rows (same git_commit)
7.  patch → commit → push → back to 1
```

`ops vm-lab-host-preflight [--inventory <p>] [--hosts <id,id>] [--commit <ref|sha>]
[--allow-dirty] [--ssh-identity-file <p>] [--timeout-secs <n>] [--format table|json]`

Gates run **in order and stop at the first failure** (mirroring `xtask gates`),
because a later gate's answer is meaningless once an earlier invariant is broken.
Skipped gates report **`not_run`** — never silently omitted, never assumed green.

| # | Gate | Fails when | It tells you |
| --- | --- | --- | --- |
| 1 | `inventory` | hosts[] missing / no `repo_dir` | declare `repo_dir` |
| 2 | `commit_pinned` | ref does not resolve | check the ref |
| 3 | `local_clean` | dev tree dirty | `commit your changes (or --allow-dirty)` |
| 4 | `commit_pushed` | SHA not on origin | **`git push origin HEAD:main`** |
| 5 | `hosts_on_commit` | any host off-commit/dirty | `vm-lab-sync-host --host <id> --commit <sha>` |
| 6 | `hosts_agree` | hosts on different commits | sync all to one pinned SHA |
| 7 | `guests_ready` | a host has 0 ready guests | `vm-lab-discover-hosts` |

Verdict is `GO` / `NO-GO`; `--format json` for a calling pipeline.

Live-proven 2026-07-16, each gate catching a real condition:

```
[3/7] local_clean      FAIL  local worktree is dirty; its evidence would not match the commit it claims
        next: commit your changes (or re-run with --allow-dirty)
[4/7] commit_pushed    FAIL  18ad7b11… is not on origin; hosts cannot fetch it
        next: git push origin HEAD:main
[5/7] hosts_on_commit  FAIL  off-commit: mac-utm-1=18ad7b11
        next: rustynet ops vm-lab-sync-host --host <id> --commit b8304a1ae…
…and with a pushed SHA:  VERDICT: GO — hosts agree on one commit and have ready guests.
```

**Gate 4 is the cheapest win:** an unpushed commit is caught in ~1 s instead of
failing minutes into a sync. **Gate 6 is the one the whole parallel-lab
comparison rests on** — it is asserted explicitly rather than inferred from gate 5,
because "both rows say the same commit" is the claim the evidence makes.

> **NAMING — two different preflights, both real:**
> `vm-lab-preflight` (pre-existing) gates **guests**: reachable, SSH-auth, platform
> identity, required commands, free space. `vm-lab-host-preflight` (new) gates
> **machines**: pinned commit, host agreement, ready-guest rollup. They **compose**
> — hosts first, then guests (steps 3 then 4). Do not merge them.

### 6.7.4 The loop, and the discipline that makes it valid

```
resolve SHA  →  sync+verify both hosts  →  launch both runs (async)
             →  BOTH complete  →  read both run-matrix rows (same git_commit)
             →  patch + commit  →  new SHA  →  repeat
```

**You cannot patch while either run is live.** Editing orchestrator source mid-run
trips the setup-manifest provenance check and fails the run, and it dirties
`git_dirty_state` on any row still being written. The agent genuinely idles while
runs are in flight — that is correct, not waste. Patch on the **dev machine**,
commit, then sync; never hand-patch a host's checkout (it would desync from the
SHA its evidence claims, and step 6 would catch it — which is the point).

**Accepted risk:** a patch that fixes Windows can regress macOS. Re-running both
from the new SHA is what catches it — that is the argument *for* the loop.

### 6.7.4e Self-review of the multi-host commands (2026-07-16)

Reviewed the six commands built this session against each other. Findings, all fixed:

| # | Finding | Fix |
| --- | --- | --- |
| 1 | 🚨 **`sync-host` destroyed box-side evidence.** `reset --hard` ran *before* any host dirty check, and the ledgers are tracked → a run's rows were reverted, then the post-reset check reported `clean` because it had just deleted what made it dirty. | Read host status **first**; refuse a dirty host with its diff; name evidence ledgers explicitly; `--discard-host-changes` to opt in (§6.7.4c). |
| 2 | 🚩 **Compare's commit match was unbounded.** `!recorded.is_empty() && target.starts_with(recorded)` — a truncated/corrupt `git_commit` like `"ab"` would match many commits and pull a **foreign run** into a comparison. Evidence attributed by coincidence. | `commit_matches()`: require ≥ 7 hex chars (git's own minimum abbreviation) on **both** sides, reject non-hex. Tested against `"2"`…`"2c0047"` and garbage. |
| 3 | 🚩 **The SSH invocation was duplicated.** `run_host_git` and `run_host_cmd` each rebuilt the same transport options — the second-weaker-path problem this plan argues against at the MCP (§6.8.2), committed here. That is how one copy quietly loses a hardening flag the other keeps. | `run_host_git` now delegates to `run_host_cmd`. One builder. |
| 4 | Compare/status could not answer "how did *this* stage do?" | `--stage <substring>` on both. **One filter, not ~36 per-stage wrappers**: the stage set changes, so a wrapper each would be near-identical code drifting from the catalogue the moment a stage is added. A filter over the generic reader cannot drift. Fails closed listing the run's real stages if nothing matches, so a typo never reads as "nothing wrong". |

Live on real data: `--stage two_hop` at `2c004782` → `linux 0 pass / 5 fail / 0 no-verdict`,
naming exactly the five nodes.

### 6.7.4c 🚨 EACH MACHINE KEEPS ITS OWN EVIDENCE — and that nearly ate it

**The evidence ledgers are per-host.** A run writes to
`<repo_dir>/documents/operations/live_lab_node_stage_results.csv` **on the machine
that ran it**. The Mac's ledger therefore **cannot see the box's runs**, and vice
versa. Two consequences, both load-bearing:

**1. `vm-lab-run-matrix-compare` only sees the ledger it is pointed at — CLOSED
2026-07-16 via `--include-hosts`.** Each machine writes to its own ledger, so
without fetching the remote one a "two-machine comparison" would silently examine
**one** machine: a confident verdict over half the evidence, which is the worst
failure this command could have. `--include-hosts <id,id>` (MCP: `include_hosts`)
fetches each named host's ledger over SSH and merges it, deduping identical rows.

Fail-closed, verified: an unknown host errors; naming the **local** host errors
(`its ledger is already the one being read` — a mistake, not a no-op); and a host
that **cannot be read** errors rather than comparing without it —
*"a verdict over half the evidence is worse than no verdict."* Observed live with
the box offline.

**Until a run is launched on the box, this is untested end-to-end** — the merge
path itself is proven only by its failure modes.

**2. 🚨 `vm-lab-sync-host` was silently destroying that evidence — FIXED
2026-07-16.** The ledgers are **git-tracked**, so a box-side run leaves the box's
worktree dirty. `sync_remote_host` ran `git reset --hard <sha>` **before** any
dirty check on the host, which reverted the tracked ledgers and **deleted the
run's results** — then the post-reset check reported `clean`, because it had just
deleted the thing that made it dirty. Run a lab on the box, sync to the next
commit, evidence gone, no message.

Fixed: the host's `git status --porcelain` is now read **before** anything is
touched, and a dirty host is **refused** with its actual diff. If any dirty path
looks like an evidence ledger the error says so explicitly and tells you to fetch
it first. Discarding requires `--discard-host-changes`, because losing evidence
must be a decision rather than a default.

### 6.7.4d ✅ BUILT — `ops vm-lab-host-run-status` (MCP: `host_run_status`)

```
rustynet ops vm-lab-host-run-status --host <host_id> [--run-id <id>]
    [--ssh-identity-file <p>] [--format table|json]
```

Ask a remote host what it is doing and what its last run found, without going
there. Read-only.

- **Is a run in flight?** `pgrep -af vm-lab-orchestrate-live-lab` on the host.
  A non-zero exit means *nothing matched* — a legitimate answer, not an error, so
  it is not reported as "cannot tell".
- **Which stages passed / failed**, read from that host's **own** ledger over SSH,
  with `alias` and `error_detail` per failure.
- The **commit + dirty state** the run recorded, and its **report_dir**, so you can
  drill into the failing area.
- `--format json` carries the full `error_detail` per failed stage.

Local hosts are refused (`read its ledger directly`) rather than pretending to SSH
to themselves.

### 6.7.4b ✅ BUILT — `ops vm-lab-run-matrix-compare` (step 6; MCP: `compare_runs_at_commit`)

```
rustynet ops vm-lab-run-matrix-compare [--commit <ref|sha>] [--inventory <p>]
    [--stage-results <p>] [--expect-runs <n>] [--allow-dirty] [--format table|json]
```

Collapses every run recorded at one commit into **one verdict**, so step 6 stops
requiring an agent to read two report trees. Built on the **normalised stage
ledger** + the **`alias → host_id` inventory join** — no schema change (see the
revision note below).

Live-proven against real recorded data (a run landed at `2c004782`):

```
=== run compare — commit 2c004782 — 1 run(s) ===
  run livelab-1784213609-2c004782fb2f  host(s): mac-utm-1
PER-PLATFORM
  PLATFORM   PASS  FAIL  NO-VERDICT  FAILING STAGES
  linux      129   5     45          live_two_hop_validation (debian-headless-2), … ×5 nodes
CONFLICTS  (none)
VERDICT: FAIL
```

179 stage rows → one line, correctly attributed to `mac-utm-1`, naming the known
client↔client full-mesh failure.

Load-bearing rules, each with a test:
- **Absent is NEVER pass.** `{skip, skipped, not_run, reused, unknown, ""}` count
  as *no verdict*, reusing the recorder's own grouping rather than inventing a
  parallel one. All-absent ⇒ verdict **`NO-VERDICT`**, never `PASS`. This is *the*
  safety property: a two-machine split leaves the other OS's cells absent, so a
  union that promoted absent→pass would manufacture parity that was never tested.
- **Conflicts are shouted, not resolved.** Same node+stage answering differently
  across runs at one commit ⇒ verdict `CONFLICT`. That is nondeterminism or a
  misconfigured overlap; picking a winner would launder it.
- **Dirty evidence is refused** by default — a run recorded from a dirty tree does
  not correspond to the commit it names. (This fired on the very first live run.)
- **One run is not a comparison** — `--expect-runs` defaults to 2.
- **Attribution never guesses.** A `local_utm` entry predates `hosts[]` and names
  no host, so it is attributed to the *sole* declared UTM host — and only when
  exactly one exists; with two Macs it is left unattributed. A controller-less
  entry (`debian-lan-11`) is `<unattributed>`, never bucketed under a machine it
  does not belong to.

### 6.7.4b-spec — original spec (retained for rationale)

**Purpose:** collapse the driving agent's job from "read two report trees and
work out what differs" to "read one verdict". Today step 6 is the only step still
requiring judgement; this removes it.

> **⚠️ REVISED 2026-07-16 — there is NO schema gap; build on the STAGE ledger.**
> The section below was written against `live_lab_node_run_matrix.csv` (266 cols,
> per-**run** rows, no host column). But the sibling ledger
> **`live_lab_node_stage_results.csv` is already normalised**:
> ```
> run_id, run_started_utc, run_finished_utc, git_commit, git_dirty_state, report_dir,
> alias, node_id, platform, os_family, os_version, role, stage, stage_scope, status,
> evidence_path, error_detail
> ```
> One row per **stage per node**, carrying `alias`, `platform`, `role`, `stage`,
> `status`. And **`alias` → `host_id` is a join through the inventory**
> (`entries[].controller.host_id`; aliases are uniqueness-enforced by
> `load_inventory`), so a stage result **can already be attributed to a machine**.
>
> **Therefore: do NOT add `runner_hostname`/`host_id` columns.** Besides being
> unnecessary, `live_lab_run_matrix.rs:801` enforces an exact header
> (`if header != NODE_STAGE_COLUMNS.join(",")`), so widening the schema would
> invalidate every existing file. Build compare on the stage ledger + the inventory
> join, and leave both schemas untouched.
>
> Caveat: a controller-less entry (e.g. `debian-lan-11`, the SSH-only off-host
> guest) joins to **no host** — report it as `host=<unattributed>`, never silently
> bucket it under a machine it does not belong to.

#### The schema gap that must be closed first (SUPERSEDED — see the note above)

Verified 2026-07-16 against `live_lab_node_run_matrix.csv`:

- **266 columns**, and every stage is already a per-OS **triple** —
  `linux_stage_<name>` / `macos_stage_<name>` / `windows_stage_<name>` — all in
  **one row**. The schema assumes **one orchestrator drives every OS**.
- **There is NO host/machine column.** `operator` is a *username* (`iwan`), not a
  machine. So with two machines writing rows, **a row cannot be attributed to the
  host that produced it**.

**Required schema addition (do this first):**
- `runner_hostname` — from `hostname` on the machine writing the row. Always
  available, needs no config, so it can never be silently absent.
- `host_id` — optional, from a new `--host-id <id>` on the run command, mapping
  the row to `hosts[]`. Optional because a row must never be *unwritable* just
  because someone forgot a flag; `runner_hostname` is the fallback identity.

Append-only: existing rows keep the columns blank (the run matrix already
tolerates blank legacy columns — see ADR-004 Consequences).

#### The command

```
rustynet ops vm-lab-run-matrix-compare --commit <sha>
    [--matrix <path>]        # default: the node engine's matrix
    [--expect-hosts <n>]     # default 2; fail if fewer rows than this
    [--format table|json]
```

Behaviour:
1. Select rows where `git_commit == <sha>`. **Fewer than `--expect-hosts` → error**,
   never a green: "only one machine reported" must not read as agreement.
2. Refuse to compare rows whose `git_dirty_state` is dirty (their evidence does
   not correspond to the commit they name).
3. For each stage triple, **merge across rows per OS**, then report:
   - the OS/stage results that actually ran,
   - **conflicts**: the same OS+stage with **different** results in two rows from
     one commit — reported **loudly** as a finding. That is nondeterminism or a
     misconfigured overlap, and it invalidates the comparison; the tool must not
     silently pick a winner.
4. Report `first_failed_stage` per row, plus each row's `report_dir` so the agent
   can drill in without hunting.
5. Verdict: per-OS pass/fail rollup + the merged parity view.

**Vocabulary rule (ADR-004 §6):** the statuses are
`pass` / `fail` / `not_run` / `not_supported` / `expected_fail`. **`not_run` is not
`pass`.** A merge must never promote an absent result to a passing one — that is
exactly how a two-machine split would manufacture false parity (host A skips
Windows, host B skips macOS, and a naive merge shows everything green).

> **The REAL vocabulary is narrower than ADR-004's, and compare must use the
> implemented one.** Measured on the newest `live_lab_node_run_matrix.csv` row: of
> 110 stage cells, **`not_run`×77, `pass`×19, `skip`×13, `fail`×1**.
>
> ADR-004 §6 names `pass`/`fail`/`not_run`/`not_supported`/`expected_fail` and says
> `skipped` is internal-only. The engine, however, implements only:
> ```rust
> pub(crate) enum VmLabStageStatus { Pass, Fail, Skipped }   // mod.rs:2295
> ```
> and the recorder deliberately normalises it:
> ```rust
> "skipped" | "skip" => "skip"                        // live_lab_run_matrix.rs:1995
> "skip" | "not_run" | "reused" | "unknown"           // grouped, :2039
> ```
> So `skip` in the matrix is **designed behaviour, not a leak** — and crucially the
> recorder **already groups `skip` with `not_run`, never with `pass`**.
> (An earlier revision of this section called it a defect; that was wrong and is
> retracted. `not_supported` / `expected_fail` are simply **not implemented** —
> that documentation-vs-implementation gap is worth closing, but it is not a bug
> in the recorder.)
>
> **Rule for compare:** reuse the recorder's existing grouping —
> `{skip, not_run, reused, unknown}` = **"produced no verdict"**, never `pass`.
> Do not invent a second, parallel notion of "didn't run"; align with :2039.
>
> The `not_run`×77 count also **confirms the merge design**: a single-host run
> already leaves the other OSes' triples `not_run`, so two focused runs populate
> **disjoint** columns and the merge is mostly a union.

**Why this is the right shape:** because the schema already carries per-OS triples,
two focused runs (box = `--windows-only`-ish, Mac = macOS) naturally populate
**disjoint** columns. The merge is then mostly a union, and the *only* interesting
case is the overlap — which is precisely what conflict detection surfaces.

Depends on: the `runner_hostname` / `host_id` columns above. Without them the
compare works (rows are keyed by commit) but cannot say **which machine** produced
a result — so it can report *what* differs, not *where*. Close the schema gap first.

### 6.7.4f Remaining gaps in the agent-facing surface (2026-07-16)

Audited against the pipeline. What an agent still cannot do by calling a function:

| Gap | Why it matters | Status |
| --- | --- | --- |
| **Launch a run ON a remote host** (step 5) | `start_live_lab_run` / `vm-lab-orchestrate-live-lab` run **locally only** — none takes a `--host`. So the parallel-lab loop's central action is still a manual SSH. **This is the biggest remaining hole.** Needs: detached launch on the host (own process group, log file, survives the SSH dropping — the pattern already used for `nohup setsid` runs), returning a run_id to poll with `host_run_status`. | **NOT BUILT** |
| **Fetch a report artifact from a host** | `host_run_status` hands back a `report_dir` on the box, but nothing can read files out of it, so drilling into a failure still means logging in. | **NOT BUILT** |
| **Stop a runaway remote run** | No way to cancel a hung box-side run. | **NOT BUILT** |
| `host_disk_status --host <id>` | Always reports **this** machine's disk (§6.8.1a). With six images + qcow2 overlays accruing, "how much room is left on the 870?" is a real question. | **NOT BUILT** |
| `sync_host --all` | Pipeline step 2 is per-host; syncing every declared host in one call is a small ergonomic win. | **NOT BUILT** |

Deliberately **not** doing: a function per stage (~36 wrappers that drift from the
catalogue — `--stage` covers it, §6.7.4e), and a libvirt `recover_stuck_vms`
(§6.8.2's delegation would subsume it — do not build it twice).

### 6.7.5 Prerequisites before A can run

- **`vm-lab-sync-host`** (§6.7.3) + `hosts[].repo_dir` — not built.
- **Box guests**: Windows 11 guest (ISO needs owner registration, §6.2) + the
  x86 Linux images (downloading 2026-07-16: Ubuntu 24.04 ✅, Rocky 10, Fedora 42,
  openSUSE Leap 16.0, Arch, virtio-win).
- **Mac audit failure** (§6.6.3) must clear before any macOS **enforced-profile**
  evidence run.
- Per-OS run selectors already exist (`--windows-only`, `--exit-platform`,
  `--relay-platform`, `--anchor-platform`, `--admin-platform`,
  `--blind-exit-platform`, `--macos-promote-exit`, `--skip-linux-live-suite`) —
  no new scoping work needed.

---

## 6.6 Transport exit plan — how to drop Tailscale WITHOUT touching the engine

**Owner decision 2026-07-16: stay on LAN for now.** Cross-network is deferred, the
ZeroTier swap is parked (§6.5.2 keeps it priced), and Tailscale stays as the
current transport. This section exists so that decision stays cheap to reverse.

### 6.6.1 The engine is already transport-agnostic — verified

`grep -rni "tailscale|tailnet|magicdns" crates/ --include=*.rs` → **zero transport
code**. (The only hits are an unrelated `rustynet-dns-zone` test name about
100.64/10 *address format*, and CVE/project strings in the security auditor.)

The transport is expressed entirely as **data**:

| What | Where | Today's value |
| --- | --- | --- |
| Host endpoint | `hosts[].connect_uri` | `qemu+ssh://ubuntu-server@ubuntu-headless/system` |
| Guest address | entry `ssh_target` / `last_known_ip`, or resolved live by the incr-3 ladder | `192.168.121.137` |

Only the hostname `ubuntu-headless` (Tailscale MagicDNS) is Tailscale-specific.
Everything else is a plain URI/IP. **Dropping Tailscale is a network-config
change, not a code change** — no `--node` engine rewrite, by construction. Keep it
that way: never let a transport name reach a Rust constant; it belongs in
`hosts[]`.

### 6.6.2 The exit is TWO parts, not one (measured)

An earlier claim that the swap is "one string" was **wrong**. Measured on the Mac:

```
route -n get 10.230.76.5      → interface: en0      ← host: LAN-reachable ✅
route -n get 192.168.121.137  → interface: utun10   ← guest: TAILSCALE ONLY ❌
```

1. **Host endpoint — trivial.** `connect_uri` host part
   `ubuntu-headless` → `10.230.76.5`. One string in one record; the LAN already
   carries it. Re-pointing every guest on that machine is this single edit,
   because `host_id` resolves to `connect_uri` at parse time (§6.4).
2. **Guest-subnet reach — the real work.** `192.168.121.0/24` lives behind the
   box's libvirt NAT and is **not** LAN-reachable. The Mac reaches it *solely*
   via Tailscale's approved subnet route. Drop Tailscale and Mac→guest dies,
   which kills the `--node` SSH plane for libvirt guests.

Replacements for part 2, cheapest first:
- **(a) Static route on the Mac** — `route add 192.168.121.0/24 10.230.76.5` plus
  a forward/MASQUERADE rule on the box (libvirt's default rules do not accept
  inbound forwarding from `wlp7s0`). No VPN at all. Cheap, but it is ambient host
  routing state — the exact class ADR-004 dislikes.
- **(b) Bridge guests onto the LAN** (the unplugged `eno1` + a libvirt bridged
  network) — guests get real `10.230.76.x` addresses, the Mac reaches them
  directly, no routes and no VPN. **This is the real exit**, and it also moves
  toward ADR-004's scenario plane (§6.5.3) instead of away from it.
- **(c) Run the orchestrator on the box** — guest reach becomes local (`virbr0`);
  no Mac→guest path needed. Works only for a Linux-guests-only run, since
  `utmctl` is local-only.

**Therefore: the `eno1` cable is the strategic exit from Tailscale**, not just a
performance nicety — it removes the VPN dependency for guest reach *and* is a
prerequisite for the dual-NIC scenario plane. Prioritise it over any transport
swap.

### 6.6.3 Known accepted state while on LAN

Tailscale remains **up on the Mac**, so `vm-lab-network-audit` reports
`overall_status=fail` with the §6.5.2 `host_route_collision` errors. This blocks
**enforced-profile** runs. Accepted for now because the libvirt guest is not yet a
dataplane-evidence node (§6.5.3) — there is no enforced-profile run to block.
**Before the first enforced-profile / dataplane-evidence run on the Mac, this must
be resolved** (`tailscale down`, or the ZeroTier swap). Do not let it become
ambient: it is a live audit failure, recorded here on purpose.

---

## 6.5 Cross-host networking — VERIFIED design findings (2026-07-16)

**Status: DESIGN, NOT IMPLEMENTED.** Owner directive 2026-07-16: nail and verify
the design before implementing further. Scope is **Linux + macOS hosts only**; a
Windows *host* driver is out of scope (Windows stays a lab **guest**). Everything
below was checked against the code/live hosts, not assumed. **Read this before
touching cross-host networking.**

### 6.5.1 The governing authority is ADR-004, not this plan

`documents/operations/adr/ADR-004-dual-plane-live-lab-network.md` (Accepted,
2026-07-10) already decides the lab's network architecture. §7 of this plan
predates it and is **superseded** where they disagree. Load-bearing points:

1. **Four planes, never conflated** — `management_ip` / `scenario_ip` /
   `mesh_ip` / `observed_egress_ip`. **"Management reachability is never
   dataplane proof."**
2. **Dual-NIC target** — NIC 0 = narrow management/recovery plane (Shared or
   Host-Only; **no Rustynet endpoint advertisement**; no default internet route
   in security-evidence stages). NIC 1 = controlled scenario plane carrying all
   Rustynet traffic on a lab-owned subnet.
3. **Evidence ladder** — Tier 0 pure Rust → Tier 1 `crossnet_netns_v1` → **Tier 2
   `isolated_multivm_v1` (routine default)** → Tier 3 `dedicated_physical_lab_v1`
   → Tier 4 `remote_wild_v1`. **No lower tier may be promoted into a higher
   tier's claim.**
4. **Mutation boundary** — attachments change ONLY via the typed
   `vm-lab-network-prepare` / `-restore` transaction (`--approve-reconfigure`,
   atomic lease, stopped-VM-only, verified rollback).
5. **Address plan** — mesh overlay `100.64.0.0/10`; scenario sites
   `172.20.0.0/16`; simulated transit `198.18.0.0/15`. Underlay use of
   `100.64.0.0/10` is **reserved for the deliberate `cgnat_collision_v1`
   adversarial profile with its own oracle**. Never auto-bridge to `en0`.

ADR-004's Context names the exact failure mode this plan must not reintroduce:
run meaning depending on *"the selected VM, the current physical LAN, **host VPN
state**, and prior MCP actions."*

### 6.5.2 🚨 VERIFIED DEFECT — Tailscale collides with the Rustynet overlay

**Tailscale hands out `100.64.0.0/10` addresses — byte-for-byte the Rustynet mesh
overlay.** Enabling it on the macOS host (done 2026-07-16, §6.3) put the
orchestrator host into the `cgnat_collision_v1` condition **by accident**.

Verified live on the macOS host:

```
$ netstat -rn -f inet | grep 100.64
100.64/10          link#43        UCS       utun10        ← Tailscale claims the WHOLE /10
$ route -n get 100.64.0.2         → interface: utun10     ← debian-headless-2's MESH IP
$ rustynet ops vm-lab-network-audit --skip-guests
overall_status=fail reason="8 error finding(s)"
  [ERROR] host_route_collision (utun10): host route 100.64.0.0/10 via utun10 (VPN) overlaps mesh (100.64.0.0/10)
  [ERROR] host_route_collision (utun10): host route 100.86.234.84/32  via utun10 (VPN) overlaps mesh
  [ERROR] host_route_collision (utun10): host route 100.100.100.100/32 via utun10 (VPN) overlaps mesh
  [ERROR] host_route_collision (utun10): host route 100.123.146.3/32  via utun10 (VPN) overlaps mesh
```

The guardrail already existed and worked: `network_audit.rs`
`detect_host_route_findings` protects `mesh_overlay_cidr()` and emits an
**error**, even annotating `(VPN)` — someone anticipated this. **Consequence: the
network audit now FAILS on the macOS host, so enforced-profile runs are blocked
there until this is resolved.** This is a live regression introduced by adopting
Tailscale, not a theoretical one.

Nuance worth keeping: guest↔guest mesh traffic is WireGuard **encapsulated to
underlay endpoints** (`192.168.64.x`), so a host route for `100.64/10` does not
obviously hijack it — the practical blast radius may be small. But ADR-004 makes
it an **error by design**, the audit fails closed, and "probably harmless" is
exactly the ambient-state reasoning the ADR exists to kill. Treat it as blocking.

#### macOS ↔ Linux asymmetry (verified 2026-07-16) — severity differs enormously

The collision is **not** symmetric across the two supported host OSes:

| Host | What Tailscale installs | Rustynet mesh IP `100.64.0.2` resolves to | Practical hijack |
| --- | --- | --- | --- |
| **macOS** | one blanket route: `100.64/10 → utun10` | `route -n get 100.64.0.2` → **`utun10`** | **Total** — every mesh address on the host is swallowed |
| **Linux** | per-node `/32`s only, in table 52 (`100.86.234.84 dev tailscale0`, …) | `ip route get 100.64.0.2` → **`via 10.230.76.157 dev wlp7s0`** (normal) | **None**, unless a tailnet node is assigned an address that *exactly equals* a live mesh IP |

Both still fail the audit — a `/32` mathematically overlaps the `/10`, so
`detect_host_route_findings` flags it — but the real-world danger is very
different. On the **Linux** host the finding is close to pedantic; on **macOS**
it is a genuine hijack. Do not treat the two hosts as equally affected.

#### Why it is an ERROR and not a warning

For a security product a host whose routing table hijacks the range under test
makes evidence **ambiguous**. The case that matters: a killswitch/leak stage where
an *untunneled* mesh packet MUST be dropped. If the host silently swallows it into
Tailscale instead, "correctly blocked" and "leaked into a VPN" are
indistinguishable and a green result is unearned. ADR-004 therefore reserves the
condition for `cgnat_collision_v1` — legitimate to test, but *chosen*, not ambient.

#### Escape routes — priced, with two dead ends (researched 2026-07-16)

**❌ DEAD END — Headscale (and NetBird-on-Tailscale-clients).** Swapping the
control server does **not** help, because the **Tailscale clients hardcode the
range**. `headscale`'s own `config-example.yaml` says verbatim:

> *"WARNING: These prefixes MUST be subsets of the standard Tailscale ranges: —
> IPv4: 100.64.0.0/10 (CGNAT range) — IPv6: fd7a:115c:a1e0::/48 (Tailscale ULA
> range)"* … *"Using ranges OUTSIDE of CGNAT/ULA is NOT supported and will cause
> undefined behaviour."*

Headscale replaces the control plane, not the client → same hardcoded `/10` route
→ same collision. **An earlier revision of this section recommended Headscale;
that recommendation was wrong and is retracted.**

**❌ DEAD END — Tailscale "IP Pool".** Restricting assigned addresses to a subset
does *not* narrow the installed route.
[tailscale/tailscale#12828](https://github.com/tailscale/tailscale/issues/12828)
("Tailscale adds a hardcoded route encompassing the whole space, even if a subset
of IPs has been defined using the IP Pool feature") — reported 2024-07-16, **still
open, no fix, no workaround**. This is exactly the blanket `100.64/10 → utun10`
route measured on the Mac.

| Option | Cost | Collision? | Notes |
| --- | --- | --- | --- |
| **ZeroTier** (leading candidate) | **£0** — free tier: **10 devices, 1 network, hosted controller included** | **None** — you choose the IPv4 auto-assign range (`Advanced → Managed Routes and IP Assignment`); nothing is hardcoded | Only **hosts** join the overlay (2 today), so 10 devices is ample. Different client/UX from Tailscale. Pick a range avoiding the whole ADR-004 plan **and** the lab LANs: not `100.64/10`, `172.20.0.0/16`, `198.18.0.0/15`, `192.168.121.0/24`, `192.168.64/65.x`, `10.230.76.0/24` — e.g. `10.99.0.0/24` |
| **Tailscale IPv6-only** (`disable-ipv4` node attr, tailnet-wide or per-tag) | £0 | Probably none — no IPv4 addressing at all | **UNVERIFIED on two counts:** (1) whether the hardcoded `/10` route disappears when IPv4 is off (#12828 suggests it may be unconditional); (2) whether **IPv4 subnet routing survives** — advertising `192.168.121.0/24` is our entire guest-reach mechanism, and Tailscale's docs do not address subnet routers with IPv4 disabled. **Test before trusting.** |
| **Toggle Tailscale** (`tailscale down` before evidence runs) | £0 | Removed while down | Zero setup — and exactly the ambient host-VPN-state trap ADR-004 exists to kill. The audit catches a forgotten toggle, but only if the audit is run. |
| **Nebula** | VPS for the lighthouse (~£4–5/mo; Oracle free tier possible) | None — CIDR fully yours | Lightweight, but a lighthouse needs a public endpoint and it is more assembly |
| **Plain WireGuard hub** | VPS (~£4–5/mo) | None | Total control, no NAT-traversal service, most manual |
| **No overlay — LAN only** | £0 | None | Mac reaches the box at `10.230.76.5`; loses the cross-network property entirely |

**Recommendation: ZeroTier free tier.** It is the only option that is £0, needs no
self-hosted server, and lets you actually choose a non-colliding range. Second
choice: keep Tailscale but **only on the Linux box** (where the collision is
`/32`-only) and reach it over the LAN from the Mac, accepting no cross-network
reach from the Mac.

**OWNER DECISION REQUIRED.** Do not implement cross-host runs until settled —
every run on the Mac currently audits `fail`.

### 6.5.3 The provisioned guest violates the dual-NIC target

`linux-x86-client-1` has **one NIC** on libvirt NAT (`192.168.121.137`), serving
as management *and* would-be scenario plane. ADR-004 §2 requires NIC 0
management + NIC 1 scenario-on-a-lab-owned-subnet, and `192.168.121.0/24` is
**not in the address plan** (scenario sites are `172.20.0.0/16`). So the current
guest is a valid *management-plane* node and **not** a valid dataplane-evidence
node. `provision_guest.sh` must grow a second NIC on a `172.20.0.0/16` site
subnet before any dataplane claim.

### 6.5.4 Corrections to earlier assumptions (checked, not assumed)

- **Bootstrap is NOT same-LAN-only.** `RustynetDataplaneExecutionPlan` §2.5: a
  new device bootstraps *"from any network where the home server is reachable …
  any network that has cone-type NAT and outbound UDP allowed."* Same-LAN is the
  **fallback** when both ends are symmetric-NAT. So Mac-NAT ↔ libvirt-NAT guests
  meshing is a **supported, and more realistic, topology** — not a blocker.
- **Cross-host is an asset, not a problem.** Today's single-host fleet is all on
  `192.168.64.x` (one L2 segment, no NAT boundary). Mac-NAT ↔ Ubuntu-NAT is a
  genuine two-NAT hole-punching topology — closer to what D2–D13 wants to prove.
  It needs a mutually-reachable anchor for gossip/rendezvous.
- **`full_tunnel_vpn_suspected` is TRUE on this Mac** (`utun0…utun10`), contrary
  to a split-tunnel prediction — but it is a **warning**, not an error, and does
  not by itself stop a run.
- **The mutation boundary has no Linux implementation.** `network_prepare` /
  `_restore` **fail closed on non-macOS** (increment 4: "use virsh/domain XML").
  So ADR-004's approval-gated attachment transaction — the *only* sanctioned way
  to change a VM's network — **does not exist for libvirt hosts**. Any dual-NIC
  work on `ubuntu-kvm-1` needs a libvirt arm of that transaction first, or it
  bypasses the ratified boundary. **This is the biggest unimplemented gap.**

### 6.5.5 Pre-existing findings surfaced (not caused here)

`stale_network_group` errors for `debian-headless-4` (`lan-192.168.0.0/24` vs
recorded `192.168.64.10`), `fedora-utm-1` (`lan-10.230.76.0/24` vs
`192.168.64.20`), `macos-utm-1` (`lan-192.168.0.0/24` vs `192.168.65.101`) — the
Bridged→Shared migration left stale labels. Also 4 `unmanaged_utm_vm` (CentOS,
Rocky, Windows XP, Windows XP Harness) known to UTM but absent from inventory.

---

## 7. Networking model

> **SUPERSEDED in part by ADR-004 and §6.5.** This section predates the
> dual-plane decision; where they disagree, ADR-004 governs.

For the orchestrator (running on the Mac, or on the Linux box) to reach guests
over SSH, guests need routable IPs:

- **Bridged (`br0`)** on the Linux host so each guest gets a LAN IP the Mac can
  SSH directly — the simplest Tier-1 fit; mirror the `debian-lan-11` /
  `lan-192.168.0.0/24` pattern already in the inventory.
- Or a **routed/NAT libvirt network** with host port-forwards / a jump host if
  the guests should stay off the main LAN — better isolation, more setup.
- This host is also the natural place to build the **Tier-3 dedicated lab
  network** (VLAN/router-appliance) from `LiveLabVmConnectivityRulebook.md` and
  the dual-plane `network_profile` program — a follow-on, not required for
  Tier 1.

---

### 6.3 Cross-machine transport — Tailscale (proven 2026-07-16)

The multi-host vision ("point the orchestrator at any host, get its ready VMs,
orchestrate across machines, across networks") needs a transport. **Ratified:
Tailscale**, carrying the **control plane only**.

**Rejected: Rustynet itself.** It is the system under test; a control plane that
rides it dies exactly when the lab breaks it (killswitch, DNS fail-closed, exit
NAT teardown, chaos stages). Precedent: the G9 killswitch lockout runbook and
`probe_and_recover_local_utm.sh` already exist for guests that fenced themselves
off. The harness must survive the failure of what it tests. Dogfooding is fine —
not for the channel you need most when Rustynet is down.

**Control plane vs data plane — do not blur.** Tailscale carries orchestration
(Mac→host `virsh`; Mac→guest SSH). Rustynet's guest-to-guest mesh must **not**
ride the tailnet: guests reachable only via a SNAT'd WireGuard overlay make every
path look like a well-behaved NAT'd LAN, so STUN/ICE/traversal/relay results
(D2–D13, `CrossNetworkSubstrateIntegrationSpec`) would be measuring Rustynet over
a VPN and prove nothing. Real topology stays on the data plane.

Proven live from the macOS host, 2026-07-16:

| Step | Result |
| --- | --- |
| Host on tailnet | `ubuntu-kvm-1` / MagicDNS `ubuntu-headless.tail3413b7.ts.net` @ `100.117.1.47` |
| Path | `active; direct 10.230.76.5:41641` (direct WireGuard, not DERP); `netcheck` UDP:true |
| Subnet route | `192.168.121.0/24` advertised **and approved** → guests reachable tailnet-wide |
| Mac → guest | `REACHED: linux-x86-client-1` @ `192.168.121.137` from the Mac, across the tailnet |
| Mac → host virsh | `virsh list --all` + `domifaddr` driven remotely over SSH, unattended |

**Guest subnet renumbered per host.** Every libvirt host ships the same default
`192.168.122.0/24`, which collides the moment two hosts advertise routes to one
tailnet. This host is now **`192.168.121.0/24`** (`host_id: ubuntu-kvm-1`); record
`guest_subnet` per host in `hosts[]` and allocate a distinct /24 to each new host.

> **GOTCHA — Tailscale SSH is incompatible with unattended orchestration.**
> `tailscale set --ssh` makes tailscaled intercept **port 22 for all tailnet
> traffic**, so key-auth never reaches real `sshd`. With the default policy rule
> (`action: "check"`) every session demands an interactive browser re-auth —
> an orchestrator hangs forever on a check nobody clicks. Proven on the box:
> `nc 10.230.76.5 22` → `SSH-2.0-OpenSSH_9.6p1 Ubuntu` but `nc 100.117.1.47 22`
> → `SSH-2.0-Tailscale`. **Resolution: Tailscale SSH OFF** (`tailscale set
> --ssh=false`); tailnet `:22` falls through to real `sshd`, and key auth works
> cross-network — which is what §5 mandates anyway (key-auth,
> `StrictHostKeyChecking=yes`, pinned `known_hosts`). Tailscale supplies
> *addressing*, not authentication. (`action: "accept"` would also unblock it,
> at the cost of pinning Tailscale's host key instead of sshd's and making lab
> SSH depend on the policy file.)

**Known network defect (not ours):** this network blackholes
**`pkgs.tailscale.com`** — TCP connects and TLS verifies, but zero bytes return
on every CloudFront edge, over HTTP and HTTPS. `tailscale.com`,
`login.tailscale.com`, `controlplane.tailscale.com`, GitHub, Google and the
Debian/Ubuntu mirrors are all fine, and both the Mac and the box are affected
identically → it is the shared gateway `10.230.76.157`, not the host. Tailscale
was therefore **built from upstream source** (`GOTOOLCHAIN=auto go install
tailscale.com/cmd/tailscale{,d}@latest`, checksum-verified via `sum.golang.org`).
Consequence: **this install does not auto-update via `apt`**. A deliberate
anti-VPN policy would have blocked `controlplane.tailscale.com` (the endpoint
that makes Tailscale work), so this reads as a broken CDN route, not a rule.

**DEFERRED RISK — tailnet ACLs are allow-all.** The lab host joined an existing
personal tailnet shared with other (owner-trusted, non-technical) devices, and
Tailscale defaults to allow-all between nodes; the approved subnet route now also
exposes **lab guests**. Owner accepted this 2026-07-16 on the basis that the
tailnet is private and trusted. Revisit (`tag:lab` + a restricting ACL, or a
separate lab tailnet) before the lab carries anything sensitive — a host that
deliberately enters broken security states is a poor neighbour. Also recommended:
**disable key expiry** on the headless node, or its node key expires (~180 days)
and a keyboard-less host silently drops off the tailnet.

---

### 6.4 `hosts[]` + host discovery — implemented 2026-07-16

The multi-host surface is command-driven, not operator-driven: a second machine
joins the lab by editing one record and calling one command.

**Inventory `hosts[]`** (optional; absent ⇒ every pre-existing inventory still
loads unchanged):

```jsonc
"hosts": [
  { "host_id": "mac-utm-1",    "kind": "local_utm" },
  { "host_id": "ubuntu-kvm-1", "kind": "libvirt",
    "connect_uri": "qemu+ssh://ubuntu-server@ubuntu-headless/system",
    "guest_subnet": "192.168.121.0/24" }
],
"entries": [
  { "alias": "linux-x86-client-1", "ssh_target": "192.168.121.137",
    "controller": { "type": "libvirt", "domain": "linux-x86-client-1",
                    "host_id": "ubuntu-kvm-1" } }
]
```

`host_id` resolves to `connect_uri` **at parse time**
(`load_inventory_with_hosts` → `parse_hosts` → `parse_controller`), so the
runtime `VmController::Libvirt { domain, connect_uri }` is unchanged and no
downstream call site was touched. Re-pointing a host (LAN IP → tailnet name,
local → remote) is now a **one-record edit**, not a per-guest edit.

Fail-closed rules, each with a test:
- unknown `host_id` → error (never a silent fall back to `qemu:///system`, which
  would drive the **wrong machine**)
- `host_id` naming a `local_utm` host from a libvirt controller → error
- both `host_id` and inline `connect_uri` → error (ambiguous precedence)
- duplicate `host_id` → error; malformed `guest_subnet` → error (a typo must not
  silently overlap another host's subnet)

**Discovery:** `ops vm-lab-discover-hosts [--inventory <path>] [--host <host_id>]
[--virsh-path <path>] [--timeout-secs <n>] [--format table|json] [--report-dir <path>]`

Read-only. Per declared host it runs a **capability probe** (`virsh version` →
the hypervisor identity, verifying the *declared* kind rather than sniffing the
OS), then `virsh list --all --name`, then per domain `domstate` and — only when
running — the existing increment-3 IP ladder. Output joins each domain to its
inventory alias; unregistered domains are **reported, not hidden** (you cannot
adopt what you cannot see). `ready = running && ip.is_some()` — running-without-IP
is deliberately not ready, because the SSH plane would have nowhere to connect.
An unreachable/wrong-kind host reports `probe=FAILED` and contributes no guests,
rather than a silent empty list ("no VMs" must not look like "could not ask").
`--format json` and `--report-dir` make it machine-consumable.

**macOS is a first-class host kind, not a stub.** `local_utm` hosts **delegate**
to `execute_ops_vm_lab_discover_local_utm` and normalise its report into the same
cross-host shape — one hardened macOS path (§3), no second/weaker scan. So one
command answers "what VMs does this machine have, and which are ready" for **both**
supported host OSes identically. Scope is Linux + macOS by owner decision
(2026-07-16); a Windows *host* driver is explicitly out of scope (Windows remains
a lab **guest**).

`utm_documents_roots` is a **list**, because the Mac fleet is split across roots:
`Windows11.utm` lives under the UTM container path while the rest live under
`~/Desktop/OS_images/UTM images`. Scanning one root silently loses the other
(observed: 9 domains vs 10, `windows-utm-1` invisible). Every declared root is
scanned and merged, deduped by domain; if **no** root scans cleanly the host
fails closed, and a partial failure is surfaced as `[PARTIAL: …]` rather than
swallowed. Declaring the roots here also retires the recurring
`--utm-documents-root` footgun — forgetting that flag made a run discover almost
nothing *and look like it worked*.

Both kinds apply the same **IP-gated-on-running** rule: a stale ARP / last-known
address for a stopped VM is never reported as live (observed and fixed: `macOS`
was showing `192.168.65.101` while shut off).

Proven live — one command, both machines:

```
host mac-utm-1 kind=local_utm endpoint=/Users/iwan/Desktop/OS_images/UTM images,
     /Users/iwan/Library/Containers/com.utmapp.UTM/Data/Documents probe=ok (UTM bundle scan)
  DOMAIN               STATE      IP                ALIAS               READY
  CentOS               shut off   -                 (unregistered)      no
  Fedora               running    192.168.64.20     fedora-utm-1        yes
  Windows11            shut off   -                 windows-utm-1       no
  debian-headless-2    running    192.168.64.4      debian-headless-2   yes
  …
  10 domain(s), 5 ready
host ubuntu-kvm-1 kind=libvirt endpoint=qemu+ssh://ubuntu-server@ubuntu-headless/system
                  guest_subnet=192.168.121.0/24 probe=ok (QEMU 8.2.2)
  DOMAIN               STATE     IP                ALIAS               READY
  linux-x86-client-1   running   192.168.121.137   linux-x86-client-1  yes
  1 domain(s), 1 ready
```

> **GOTCHA — `--json` is swallowed globally.** `extract_json_flag` strips `--json`
> from argv before any `ops` parser sees it, and only `status`/`netcheck` honour
> it (it converts `key=value` daemon lines). So `ops <anything> --json` is a
> silent no-op across the whole ops surface. This command therefore uses
> **`--format table|json`**, which the interceptor does not touch.

Gates: `fmt` clean; 9 new unit tests (host resolution + every fail-closed path +
the `virsh list` parser + the ready rule); **1959 tests pass, 0 fail**. Clippy
must be run with the **pinned** toolchain — see the toolchain note below.

> **TOOLCHAIN — local clippy cannot gate this repo.** `rust-toolchain.toml` pins
> 1.88.0, but Homebrew's cargo/clippy (1.97) shadows rustup in `PATH`, and even
> `rustup run 1.88.0 cargo clippy` reports **clippy 0.1.97** — the documented
> "clippy poison". 1.97 invents an `unused_imports` error in
> `live_lab_run_matrix.rs` that **pinned clippy 0.1.88 does not flag** (verified),
> so "fixing" it would have been wrong. **The Ubuntu host has a clean rustup
> 1.88.0 with clippy 0.1.88** and is now the authoritative local gate runner —
> a concrete payoff of the second host. Under it, this increment adds **zero**
> clippy errors; the 11 `uninlined_format_args` errors it reports are all
> pre-existing on `HEAD` in files this change never touched.

---

## 8. Open decisions (owner-decision queue)

1. **Is a dedicated Linux VM host actually the goal, or is the real need just a
   WinNAT-capable Windows environment?** (A physical Windows device / Azure VM
   also solves §1.1. The Linux host additionally gives capacity + x86 + a second
   host, which the alternatives do not.)
2. **Hypervisor stack for the Tier-2 driver:** libvirt/QEMU/KVM via `virsh`, or
   Proxmox (REST/`qm`)? Sets what `VmController::*` targets.
3. ~~**Execution locus:** orchestrator runs **on** the Linux box (driver shells out
   locally) or **on the Mac** SSHing to the Linux host to run `virsh` (driver
   wraps every command in an SSH hop)? Decide before writing the abstraction.~~
   **DISSOLVED 2026-07-16 — this was a false fork.** Every libvirt call is built
   as `virsh -c <connect_uri> …` (`mod.rs` `run_virsh_capture` /
   `libvirt_domain_running` / `transition_libvirt_vm`), and `connect_uri` is a
   free-form string on the controller. `qemu:///system` drives the local daemon;
   `qemu+ssh://user@host/system` drives a remote one over libvirt's **native**
   remote transport — no SSH-wrapping layer, no second code path. **Locus is a
   config value, not an architecture**, so the driver is locus-agnostic and the
   decision reduces to "where do you run the binary today". Proven live from the
   macOS host against `ubuntu-kvm-1` over the tailnet (§6.3). Run-on-host remains
   valid; it is no longer a constraint.
4. **Is lifecycle management needed at all,** or is SSH-only orchestration of
   already-running guests (Tier 1, `debian-lan-11` pattern) sufficient for the
   intended use? If Tier 1 suffices, Tier 2 can be deferred indefinitely.
5. ~~**First-class host record** in the inventory schema (§4 Tier 2.5) — adopt now,
   or keep implying the host via `parent_device`?~~
   **RESOLVED 2026-07-16 — ADOPTED and implemented (§6.4).** Guests reference a
   machine by `host_id`, resolved to a `connect_uri` **at parse time**, so the
   runtime `VmController` shape is unchanged and all 12 existing match sites, the
   power layer and the discovery ladder needed no edits.
6. ~~**Confirm the RAM figure** (§1 hardware note) before committing to ~10 VMs.~~
   **RESOLVED 2026-07-16 — 61 GiB system RAM** measured on the live host
   (AMD Ryzen 7 7700X, 8C/16T). Comfortable for the ~10-guest target.
7. ~~**Preserve the existing Windows install** (dual-boot to a spare drive) or wipe?~~
   **RESOLVED 2026-07-16 — PRESERVE. This is a HARD RULE, not a preference:**
   the Windows 11 install (Samsung 980 NVMe, Disk 2) is **never** to be wiped,
   reinstalled, repartitioned, or otherwise modified. The Samsung 860 EVO
   (Disk 0, NTFS data) is likewise **out of scope**. **All VM hosting is
   confined to the Samsung 870 EVO (Disk 1, `/dev/sdb`)** — the drive that
   already held the prior Debian install and now runs the Ubuntu VM host.
   Nothing outside that disk. This decision is **closed**; do not re-open it or
   offer "wipe" as an option. See §6.1 for the enforcement rules.

---

## 9. Definition of Done

Scoped to whichever tier is ratified:

- **Tier 1 DoD:** Linux host stood up headless with KVM; ≥1 x86 guest per target
  OS created, autostarted, LAN-reachable; registered as SSH-only inventory
  entries; a `--node <alias>:<role>` run reaches the guests and produces a
  `live_lab_run_matrix.csv` row (§10.9). The x86 **Windows/WinNAT exit** cell runs
  live (the §1.1 unblock) — the headline evidence deliverable.
- **Tier 2 DoD (if pursued):** `VmController` abstracted with `LocalUtm`
  unchanged + a Linux driver; power/status/IP-discovery/file-transfer work on the
  Linux host; gates green (§7 CLAUDE.md); no second/weaker apply path; residue
  asserts run identically; a live run proves lifecycle control end-to-end. Docs +
  `CODE_MAP.md` + this ledger updated in the same change.

No OS may become a capability limiter (parity mandate) — this host exists to
*remove* the Apple-Silicon nested-virt limiter, not to add a Linux-only one.

---

## 10. Provenance

Authored 2026-07-14 from a repo-wide discovery pass (no dedicated-Linux-host plan
found pre-existing) + the current inventory + orchestrator source. All code
line references are indicative as of that date — grep the named symbol before
editing. This ledger is a proposal; implementation status is tracked in §11.

---

## 11. Implementation progress

Owner ratified **Tier 2 (full UTM-parity lifecycle)** with the **run-on-host**
architecture: the orchestrator runs on the Linux box, drives **local libvirt via
`virsh`** for power + IP discovery, and SSHes to bridged guests for
ship→compile→launch (which is already SSH-throughout). Hypervisor = libvirt/
QEMU/KVM (Proxmox parked). Landed in gated increments (each: targeted `cargo
check`/`test` + `fmt` + `clippy -D warnings` on `rustynet-cli --features vm-lab`;
the full §7 gate list + a live run before any release claim).

Key scope-shrinking finding from the code map: the go-forward `--node`
orchestrator uses `utmctl` **only** in a pre-orchestration readiness gate
(power-on + resolve live IP → inventory); everything downstream is SSH. So the
libvirt work is confined to that power+discovery gate, and **Linux guests that
autostart sshd with the automation key pre-seeded need no guest-agent channel at
all** — pure scp/ssh reaches parity. A qemu-guest-agent channel is only needed
to match the UTM tree's **Windows** pre-SSH bootstrap + WireGuard-flap fallback,
and can be sidestepped with out-of-band (cloud-init/unattend) provisioning.

| # | Scope | Status |
| --- | --- | --- |
| 1 | `VmController::Libvirt { domain, connect_uri }` variant + `parse_controller` `"libvirt"` arm (default `connect_uri = qemu:///system`) + Libvirt arms on all 12 compiler-flagged match sites (display echoes the domain; UTM-reconcile closures skip Libvirt; power/IP gates fail closed) + unit tests | **DONE** — `f3352b0` |
| 2 | virsh **power control**: `transition_libvirt_vm` (`virsh start`/`shutdown` + `domstate` poll; fails closed when state is unreadable; graceful shutdown — force/`destroy` escalation is a small follow-up) + `LibvirtPowerAction`. `StartTarget` now carries the real `VmController` (not the flattened UTM `utm_name`/`bundle_path`) with `display_name()`/`local_utm()` accessors; `resolve_start_targets` resolves libvirt targets; `execute_ops_vm_lab_start`/`_stop` dispatch per controller and only require `utmctl` when a UTM target is present. IP-resolution + readiness still fail closed for libvirt → increment 3. +3 unit tests | **DONE** — `check --all-targets`/`fmt`/`clippy -D warnings`/tests green |
| 3 | virsh **IP discovery + readiness observation**: `resolve_libvirt_live_host` three-rung ladder — `virsh domifaddr` (lease) → `domifaddr --source arp` (bridged) → `domiflist` MACs × `ip neigh show` — candidates through the shared `select_preferred_live_ssh_ip` selector (viability, mesh-IP exclusion, last-known preference). Entry resolver generalized (`resolve_local_utm_live_host` → `resolve_controller_live_host`) so `resolved_inventory_ssh_target*` rewrites SSH hosts for libvirt entries; `observe_local_utm_target_ready` observes libvirt via `virsh domstate` + the ladder (IP deliberately gated on domain-running to keep stale neigh-cache IPs out of ready states/inventory persistence), making `--wait-ready` restart recovery work for libvirt targets. +3 parser tests. NOTE: the `execute_ops_vm_lab_discover_local_utm` bundle-scan remains UTM-only — libvirt entries rely on per-run/per-target resolution (a `virsh list --all` discovery analogue is optional follow-up). Live proof on the box pending (§ 0/6) | **DONE (code)** — gates green |
| 4 | **runtime-OS-dispatch the host network observers** so the launch audit (which the `--node` orchestrator runs at `native.rs:1095`, host-only, and which hard-stops an *enforced*-profile run) produces real evidence on the Linux host instead of empty+`plutil`/`ifconfig`-not-found noise. `observe_host` now branches on `std::env::consts::OS`: `observe_host_macos` keeps the existing BSD-tool collectors byte-identical; new `observe_host_linux` uses iproute2 JSON (`ip -j addr`/`ip -j route`) via new pure parsers `parse_ip_json_addr`/`parse_ip_json_route` (private-IP kept, public redacted, best-effort empty on bad input) + a `linux_ip_binary()` PATH-safe resolver (guards the non-login `/usr/sbin` gap). The UTM-bundle-mutating `network_prepare`/`_restore` fail closed on non-macOS via `ensure_utm_host_for_network_mutation` (clear "use virsh/domain XML" error, not a missing-`plutil` crash; `--list` still works anywhere). +2 parser tests. KNOWN GAP: the `vpn_utun_interfaces`/`full_tunnel_vpn_suspected` heuristic stays utun-specific (won't flag a Linux WireGuard full-tunnel) — a follow-up refinement | **DONE (code)** — gates green |
| 5 | MCP surface (`rustynet-mcp-lab-state`) | **PARTIAL 2026-07-16 — and the original scope was WRONG; see §6.8** |
| 0 / 6 | Linux-host build check (`cargo check … --target x86_64-unknown-linux-gnu` on the box) + interim `--trust-inventory-ready` run; then a full live `--node` run driving libvirt guests → `live_lab_run_matrix.csv` row (**the DoD**) | **UNBLOCKED 2026-07-16 — NEXT.** Host is live and verified (§6.1): Ryzen 7700X, 61 GiB, `kvm_amd nested = 1` already on, 427 G free on `/dev/sdb`. Not yet installed on the box: the §6 virt stack (`qemu-kvm`/`libvirt-daemon-system`/`virtinst`/`bridge-utils`/`cpu-checker`) and a Rust toolchain (run-on-host needs `cargo` to build `rustynet-cli --features vm-lab`). Gated on the §6.1 bridging blocker (`eno1` has no carrier — WiFi cannot bridge) |

Increment 1 (`f3352b0`) touched `mod.rs` (enum + const `DEFAULT_LIBVIRT_CONNECT_URI`
+ parser + fail-closed arms) plus the `network_audit.rs`/`network_prepare.rs`
Libvirt arms (landed in the concurrent `e5ba1b1`) and `topology.rs`. Increment 2
is `mod.rs`-only (the virsh power layer + `StartTarget` generalization +
start/stop dispatch + 3 tests). **`LocalUtm` behaviour is byte-identical** across
both (one hardened path, §3); a libvirt VM can now be powered on/off via `virsh`,
but IP discovery + readiness still fail closed until increment 3.

**Intersection watch:** all of this lives in the 49k-line `vm_lab/mod.rs`, which
RNQ-15 is extracting and RNQ-17 is splitting out. Keep the libvirt code cohesive
so it moves wholesale; cross-reference in the RNQ ledger when increment 2 lands.

---

## 12. THE CHECKLIST — make the MCP actually usable against `ubuntu-kvm-1`

**Owner ask (2026-07-17):** *"a usable MCP that can run and do other useful things
like setup and resets, on/off, etc on the ubuntu server."* This section is the
live, ordered execution checklist for that. It lives **here**, in the owning
ledger, rather than in a new doc, because §6.7.4f (agent-surface gaps), §6.8.2
(the delegation refactor) and §11 (increments) already track the same items — a
second document would diverge from them within a day (AGENTS/CLAUDE §5: no
parallel checklist that drifts from repository state). Those sections stay the
rationale; this is the state.

**Mark items here as they land, in the same change that lands them.**

### 12.1 Verified working — measured live 2026-07-17, not read off the code

Everything below was exercised against the running box, because §6.8.1a's matrix
was compiled by *reading* the code path and two of its "✅ yes" rows turned out to
hide real defects (§12.3). Re-verify rather than trust this table once it ages.

| Capability | Evidence |
| --- | --- |
| Power **off/on** a box guest from the Mac | `ops vm-lab-stop`/`-start` on `linux-x86-exit-1`: `running → shut off → running`, exit 0, `via libvirt domain=… connect_uri=qemu+ssh://…` |
| **Status/diagnostics** on box guests | `ops vm-lab-status` resolved both guests through the libvirt ladder (`192.168.121.137`/`.26`), SSHed in, returned hostname/ip/service state |
| `virsh` over `qemu+ssh` **from the Mac** | `virsh -c qemu+ssh://ubuntu-server@ubuntu-headless/system list --all` → both guests running (Mac has virsh via homebrew) |
| **Toolchain on the box** | rustc/cargo **1.88.0** (pinned), clippy, rustfmt — reachable over a *non-login* SSH after §12.2's shim fix; `cargo check -p rustynet-cli --features vm-lab` → exit 0 |
| **Image fetch** into the pool | `virtio-win.iso` (754M) installed unprivileged; sha256 pin verified/refused/rejected (§6.1) |
| CLI multi-host surface | `discover_hosts`, `sync_host`, `host_preflight`, `compare`, `host_run_status`, `host_net_status`, `provision-toolchain` all run **from the CLI** |

**Guest reachability rides Tailscale.** `route -n get 192.168.121.137` → `utun10`.
The Mac reaches the box's NAT subnet only because the box advertises
`192.168.121.0/24` as a tailnet subnet route — i.e. the same Tailscale that
collides with the Rustynet overlay (§6.5.2). Removing Tailscale (§6.6) removes
this path too; plan for it.

### 12.2 ✅ DONE — box toolchain (2026-07-17)

- [x] Rust on the box. **The premise was wrong:** rust was installed 2026-07-16
      09:18 and had already built `rustynet-cli --features vm-lab` at 12:58 that
      day (7.2G `target/`, real x86-64 ELF with the vm-lab subcommands). It looked
      absent because `command -v cargo` over SSH returns nothing — the non-login
      PATH is `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:…`
      with **no `~/.cargo/bin`**. That is the documented sbin/PATH trap wearing a
      different hat. **The tracker's §11 increment 0/6 "Linux-host build check"
      was therefore already satisfied; only the PATH hid it.**
- [x] Shims linked into `/usr/local/bin` (one sudo; same approach as
      `GUEST_TOOLCHAIN_SCRIPT`, keeping rustup so `rust-toolchain.toml`'s 1.88.0
      pin still governs). Proven over a fresh non-login SSH.
- [x] **No apt/build-deps needed.** `clang`/`libclang`/`libsqlite3-dev` are all
      absent from the box and none are required: `rusqlite = { features =
      ["bundled"] }` vendors SQLite (proof: a compiled `sqlite3.o` under
      `target/debug/build/libsqlite3-sys-*/out/`). The guest script installs them
      because it targets `rn_bootstrap`'s **node** prerequisites; a host is not a
      node. Do not copy the guest script wholesale onto a host.

### 12.3 Step 0 — rebuild the MCP binary (minutes; unblocks 8 tools)

**This is why the MCP feels broken. The capability is built; it is not loaded.**
`bin/rustynet-mcp-lab-state` is dated **2026-07-09 00:36**; `lab_state.rs` is from
**2026-07-17**. Every multi-host tool added on the 16th–17th exists in source and
is **absent from the running server**: `discover_hosts`, `sync_host`,
`host_preflight`, `provision_guest`, `compare_runs_at_commit`, `host_run_status`,
`host_net_status`, `provision_guest_toolchain`.

Live proof of the staleness: `check_vm_reachable("linux-x86-client-1")` returns
`Unknown alias … (not in inventory)` — it **is** in the inventory. That is exactly
the lie §6.8.3 records as fixed by `utm_resolution_error()`; the running binary
predates the fix.

- [x] `cargo build --release --bin rustynet-mcp-lab-state` (2026-07-17)
- [x] Install with an **atomic `mv`, never `cp`** — the client keeps the running
      binary mmap'd, so `cp` truncates it in place and corrupts it (symptom: the
      server starts and emits nothing). `cp … bin/x.new && mv -f bin/x.new bin/x`.
      Done; installed sha256 matches the build output byte-for-byte.
- [x] **All three servers were stale, not just this one** — a systemic problem with
      hand-built binaries in `bin/`, since nothing rebuilds them:
      `gate-runner` bin 2026-06-12 vs src 2026-06-26; `repo-context` bin 2026-06-12
      vs src **2026-07-12** (a month). All rebuilt + installed 2026-07-17.
      **Worth a follow-up:** a staleness check (bin mtime vs src, or a `--version`
      the client asserts) so this cannot rot silently again.
- [x] Verified over **stdio** (`state/mcp_call.sh`, which needs no client
      reconnect): all 8 tools present in the new binary and absent from the old;
      `discover_hosts` probes **both** hosts for real —
      `mac-utm-1 probe=ok, 10 domains/5 ready` (real utmctl state, live IPs) and
      `ubuntu-kvm-1 probe=ok (QEMU 8.2.2)` with both guests + IPs. And the §6.8.3
      fix is live: `check_vm_reachable` on a libvirt guest now says *"IS in the
      inventory but is not UTM-backed (controller.type=libvirt,
      host_id=ubuntu-kvm-1)"* and points at the controller-aware CLI, instead of
      the old binary's flat lie that the alias was absent.
- [x] **Client reconnected** (owner, 2026-07-17) — the 8 tools are live.
- [x] **Re-verified through the client, not just over stdio.** `discover_hosts` via
      the Desktop-spawned server: `ubuntu-kvm-1 probe=ok (QEMU 8.2.2)`, both guests
      + IPs. **Step 0 is complete.**

### 12.4 Step 1 — close the fail-opens

These make every other result untrustworthy, so they come before new features.

- [x] **DONE 2026-07-17.** `ops <unknown-subcommand>` exited 0 and printed usage,
      so the MCP's `format_lab_outcome` (which trusts the exit code) reported
      **`✅ PASSED` for a command that never ran** — hit live via
      `get_vm_diagnostics`. Root cause was **23 sites** of
      `Err(_) => CliCommand::Help`: every subcommand parser's error was *discarded*
      (`Err(_)`, underscore) and turned into a usage dump at exit 0. Not just `ops`
      — `role set <invalid>` did it too, printing generic help instead of
      `RoleCliError::user_message()`'s explanation, at exit 0.
      Fixed with a `CliCommand::UsageError(String)` variant that carries the
      parser's own message and executes as `Err`, so `classify_cli_error` gives it a
      real exit code. `classify` also had to widen: it matched the literal
      `"unknown subcommand"`, which `"unknown ops subcommand"` does **not** contain,
      so even a propagated error would have been misclassified. Top-level
      fallthrough split so bare `rustynet` / `help` / `--help` / `-h` stay exit-0
      help while an unknown command is a usage error.
      Now: `ops <unknown>` → **64**, unknown top-level → **64**,
      `role set not-a-role` → 1 *with the real message*, help paths → 0,
      real vm-lab commands → 0. 6 new tests; full bin suite 2427 passed / 0 failed.
      **Two existing tests had to be fixed, and both are instructive:**
      `parse_reboot_recovery_report_requires_dns_refresh_checks` **asserted
      `Help`** for a missing required option — the fail-open was entrenched enough
      to have a test enforcing it; it now asserts the message names the option and
      classifies as BadArgs. And `bootstrap_script_uses_root_for_system_keychain_writes_only`
      pinned `rm -f "${runtime_key}"`, which RSA-0080's fix (02deff8) had changed to
      `secure_remove_file` — that commit landed with the break because only targeted
      tests + the gate were run, not the full suite (AGENTS/CLAUDE §13.1 says run it
      before landing). The assertion is now the stronger one: secure removal, and
      *no* plain `rm -f` on that path.
- [x] **DONE 2026-07-17.** `discover_hosts` failed open off-macOS: on the box it
      reported `host mac-utm-1 … probe=ok` and listed the Mac's 7 domains as
      **"shut off"**. Root cause: the bundle scan **tolerates a missing root** and
      falls back to entries read from the *inventory*, so the existing
      `if scanned.is_empty()` fail-closed guard never fired — utmctl and the roots
      do not exist on the box and nothing was ever contacted. Fixed with
      `ensure_local_utm_host_is_this_machine` (a `local_utm` host IS this machine:
      refuse off-macOS, and refuse when utmctl is absent) plus a per-root existence
      check so a typo'd root on macOS cannot fabricate either.
      Proven on the box: `mac-utm-1 probe=FAILED (… this machine is linux …
      Reporting VM states from here would be a fabrication, not an observation.)`
      with **zero guests**, and the Mac's own output unchanged. 3 tests (the
      off-macOS one is `cfg(not(target_os = "macos"))`, so it runs on the box/CI —
      where the bug actually lived).

### 12.5 Step 2 — locality: let the box drive itself (blocks run-on-host)

- [ ] On the box, the inventory's `qemu+ssh://ubuntu-server@ubuntu-headless/system`
      is an **SSH loopback to itself** → `Host key verification failed` →
      `probe=FAILED`. Local `qemu:///system` works fine (both guests listed). The
      `connect_uri` is written from the **Mac's** viewpoint and the code has no
      notion of "this host is me". Run-on-host (§11's ratified architecture) cannot
      work until it does.
- [ ] **Open design decision.** Hostname-match is automatic but collision-prone,
      and a false match would point the orchestrator at the **wrong machine's
      libvirt** — the dangerous direction. An explicit marker
      (`RUSTYNET_LAB_HOST_ID` env or an inventory field) is unambiguous and fails
      safe: unset simply degrades to today's loud self-SSH failure. Recommend
      explicit, with hostname as a convenience fallback only if it cannot
      false-positive.

### 12.6 Step 3 — §6.8.2 delegation refactor (kill the second, weaker path)

- [ ] Route the 5 `utmctl`-direct tools through the controller-aware CLI:
      `get_vm_power_state`, `get_vm_network_info`, `reset_vm_network`,
      `utm_power_status`, `utm_status_map`. libvirt support arrives for free and
      the duplicate path disappears (§3: one hardened execution path).
- [ ] `recover_stuck_vms` — UTM/`arp`-shaped internally; unverified on libvirt.
- [ ] `host_disk_status --host <id>` — always reports **this** machine's disk. With
      11G of images already on the 870, "how much room is left" is a real question
      it cannot answer.

### 12.7 Step 4 — run labs on the box (the point of the whole program)

- [ ] **`--host` on `orchestrate-live-lab` / `start_live_lab_run`** — detached
      launch (own process group, log file, survives the SSH dropping — the
      `nohup setsid` pattern already used elsewhere), returning a run_id to poll
      with `host_run_status`. **The biggest hole**; today this is a manual SSH.
- [ ] Fetch a report artifact off a host (`host_run_status` returns a `report_dir`
      and nothing can read it).
- [ ] Stop a runaway remote run.
- [ ] `sync_host --all`.

### 12.8 Step 5 — setup / reset

- [ ] **`provision_guest`'s create steps are not implemented** — only validation and
      guards exist. Clean route: `virsh vol-create-as` + `vol-upload` +
      `virt-install --connect` (no sudo, now that the pool is group-writable).
- [ ] Its cloud-init seeds the **box's** key, not the fleet's lab key
      (`~/.ssh/rustynet_lab_ed25519`) — the root fix that removes the
      `authorize_*.sh` scratchpad workarounds.
- [ ] Port `renumber_net.sh` (per-host subnet collision avoidance).
- [ ] Both guests have `mesh_ip` unset and `include_in_all: false` — present in the
      inventory, in no run's topology. Config, not code.

### 12.9 Prerequisites that will bite

- [ ] **Push the commits.** `sync_remote_host` runs `git fetch --depth=1 origin
      <sha>` **on the box**, so it physically cannot advance a host to an unpushed
      SHA. As of 2026-07-17 the box is pinned at `49f5f9f` while `2c306b4`,
      `02deff8`, `5b814c3`, `3d950d1` are local-only. This is deliberate (evidence
      must name a commit others can fetch), not a bug — but it gates §12.7.
- [x] **SETTLED 2026-07-17 — the sandbox is NOT blocking anything, and §12.3.1 was
      stale.** This mattered more than a checklist tick: §12.3.1 told every agent to
      do reachability/SSH from Bash rather than the MCP, and a whole session was
      driven that way before it was re-tested. Four probes through the
      Desktop-spawned server say otherwise — `check_vm_reachable` → `192.168.64.20:22`
      **in-process TCP** `reachable: true`; `host_net_status` → LAN `172.23.56.5`
      reachable; `discover_hosts` → `qemu+ssh` `probe=ok`; `validate_inventory`'s
      only failure is `connection timed out` against a **powered-off** VM, which is
      the correct answer. The `EHOSTUNREACH` / "No route to host (os error 65)"
      signature appears nowhere. Both halves work — in-process sockets AND
      shelled-out children, over LAN AND Tailscale. No launchd workaround needed.
      **CLAUDE.md/AGENTS.md §12.3.1 rewritten** (mirrored per §14) to lead with
      "use the MCP", keeping the original finding as a recurrence guide — Local
      Network Privacy is a *permission*, so it can be revoked as easily as granted;
      `EHOSTUNREACH` against a private-range IP is the tell that it is back.
- [ ] `eno1` is `NO-CARRIER` (box is on WiFi; WiFi cannot bridge), so guests are
      NAT-only behind `virbr0` — fine for a box-local lab, but it violates ADR-004's
      dual-NIC target (§6.5.3) and keeps cross-machine on Tailscale.
