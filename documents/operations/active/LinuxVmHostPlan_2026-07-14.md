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

---

## 7. Networking model

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

## 8. Open decisions (owner-decision queue)

1. **Is a dedicated Linux VM host actually the goal, or is the real need just a
   WinNAT-capable Windows environment?** (A physical Windows device / Azure VM
   also solves §1.1. The Linux host additionally gives capacity + x86 + a second
   host, which the alternatives do not.)
2. **Hypervisor stack for the Tier-2 driver:** libvirt/QEMU/KVM via `virsh`, or
   Proxmox (REST/`qm`)? Sets what `VmController::*` targets.
3. **Execution locus:** orchestrator runs **on** the Linux box (driver shells out
   locally) or **on the Mac** SSHing to the Linux host to run `virsh` (driver
   wraps every command in an SSH hop)? Decide before writing the abstraction.
4. **Is lifecycle management needed at all,** or is SSH-only orchestration of
   already-running guests (Tier 1, `debian-lan-11` pattern) sufficient for the
   intended use? If Tier 1 suffices, Tier 2 can be deferred indefinitely.
5. **First-class host record** in the inventory schema (§4 Tier 2.5) — adopt now,
   or keep implying the host via `parent_device`?
6. **Confirm the RAM figure** (§1 hardware note) before committing to ~10 VMs.
7. **Preserve the existing Windows install** (dual-boot to a spare drive) or wipe?

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
| 3 | virsh discovery + IP resolution (`virsh domifaddr` + MAC-from-domain-XML + `ip neigh` fallback) wired into `readiness.rs` restart-recovery + `observe_local_utm_target_ready` (libvirt currently fails closed as not-ready there) | TODO (live part needs the box) |
| 4 | cfg-isolate the macOS-only host observers (`plutil`/`scutil`/`ifconfig`/`netstat`/`arp`) in `network_audit.rs`/`network_prepare.rs` so those stages skip/adapt on Linux instead of failing | TODO |
| 5 | MCP surface: branch `lab_state.rs` `alias_to_utm`/`utm_power_status`/power tools/`recover_stuck_vms` on controller kind (virsh `domstate` + a virsh recover) | TODO |
| 0 / 6 | Linux-host build check (`cargo check … --target x86_64-unknown-linux-gnu` on the box) + interim `--trust-inventory-ready` run; then a full live `--node` run driving libvirt guests → `live_lab_run_matrix.csv` row (**the DoD**) | BLOCKED on hardware |

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
