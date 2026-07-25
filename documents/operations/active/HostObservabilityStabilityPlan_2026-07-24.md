# Host Observability, Stability & Fleet-Onboarding Plan (2026-07-24)

Status: ACTIVE. Owner track: lab infrastructure (extends
`LinuxVmHostPlan_2026-07-14.md`). Trigger: `ubuntu-kvm-1` rebooted ≥2× on
2026-07-24 under nested-virt load; the box is currently **un-diagnosable** — see
the memory `ubuntu_kvm1_reboot_investigation_2026-07-24`.

**Scope has two coupled halves:** (1) the observability/stability layers that make
a host self-diagnosable (§1–§6, Layer 0 done + fable-reviewed), and (2) a
**first-class fleet-onboarding architecture** so those layers — and the whole
add/subtract-a-box flow — scale horizontally across Ubuntu + macOS hosts (§7,
hardened by four independent adversarial reviews). The observability layers are
steps *inside* onboarding, which is why they share one doc.

## 0) Problem statement

The host cannot see its own failures, and the agent tooling cannot read what
little the host does capture:

- `ubuntu-server` (the agent SSH identity) is in `sudo,libvirt,kvm` but **not**
  `systemd-journal`/`adm`, and has **no passwordless sudo** → `journalctl -k`,
  `/sys/fs/pstore`, `/var/crash`, `dmesg` (dmesg_restrict=1) are all unreadable
  without an interactive password.
- No `lm-sensors` (no thermal history), no `mcelog` (no machine-check capture),
  no pstore/ramoops/serial console (nothing survives a reset), `quiet splash`.
- `kernel.panic=0` → a panic **hangs**, it does not reboot. The box *did*
  reboot (~2.5 min power-cycle gap), so the mechanism was a **hardware reset /
  power event**, not a software panic. That class of fault is precisely what the
  OS logs least about — making instrumentation the only path forward.

## 1) Objective & non-negotiables

Make `ubuntu-kvm-1` self-diagnosable and **agent-readable without an interactive
password**, WITHOUT broadening the host's attack surface beyond a minimal,
read-only diagnostic capability. This is a security-sensitive change on a
tailnet-reachable box, so it inherits `SecurityMinimumBar.md` and AGENTS.md §4:

- **Least privilege.** Grant the narrowest capability that achieves the read.
  Prefer a group membership (bounded, auditable) over sudo; where root is
  unavoidable, a single fixed-argv root-owned wrapper, never blanket sudo.
- **Argv-only, no shell construction with untrusted values.** No caller argument
  is ever interpolated into a command.
- **Fail closed.** An unrecognized request does nothing and exits non-zero.
- **Read-only in Layer 0.** No install, no sysctl write, no state change here —
  those are Layer 2, separately designed and reviewed.
- **No weakening of existing hardening.** `dmesg_restrict` stays `1` (kernel
  messages are reached via the journal group instead). `kernel.panic` change is
  deferred to Layer 2, not slipped in here.

## 2) The four layers (program shape)

| Layer | What | Automatable as MCP? | Depends on |
|---|---|---|---|
| **0** | Journal-read enablement: add `ubuntu-server` to `systemd-journal` + assert persistent journal. **No wrapper, no sudoers** (see §3 — the adversarial review collapsed it to this) | No — one group grant + a config assert | — |
| **1** | Read-only MCP tools over the now-readable journal: `host_stability_report` (boot cadence/gap-analysis, prev-boot kernel tail, panic/watchdog state), `host_thermal_status` (hwmon, no root) | Yes (read-only, grounded) | Layer 0 |
| **2** | **Install → C1/operator, NOT an agent MCP tool** (operational-review F1): `host_install_diagnostics` (lm-sensors/mcelog/pstore-ramoops/`kernel.panic=10`) is one-time privileged stand-up that folds into the first-boot bootstrap. What stays an agent MCP tool is **`host_crash_forensics` as a pure UNPRIVILEGED read** — C1 enables `systemd-pstore` (auto-archives `/sys/fs/pstore` → group-readable) + dumps `dmidecode` once to a group-readable file + `mcelog`→journal (covered by the Layer-0 group), so no Layer-2 tool needs root. `host_thermal_stress_probe` (reproduce under load) | Yes — read-only agent tool over C1-provisioned sinks | Layer 0 + C1 |
| **3** | Physical/firmware checklist: PSU headroom, UPS, reseat, wired eno1, **BIOS hardware-event log** (UEFI UI — consumer AM5 board exposes no SMBIOS Type-15 SEL) | No — human hands + firmware UI | independent |

Sequencing: **plan → adversarial fable review → implement, one layer at a
time**, 0→1→2→3. Layers 1/2 call the exact surface Layer 0 defines, so Layer 0
is finalized and reviewed first. Layer 3 is a checklist, not code.

---

## 3) LAYER 0 — detailed design (post-review: collapsed to a group grant)

The first draft added a root-owned `NOPASSWD` diagnostic wrapper for pstore/
dmidecode/mcelog. The adversarial fable review (§5) killed that: one arm
(`journalctl` under sudo) was a **root-shell escape** via the pager, the other
arms **yield nothing at Layer 0** (no mcelog daemon yet; consumer AM5 board has
no SMBIOS Type-15 SEL — empirically confirmed; pstore can't survive a power
cut), and the whole sudoers apparatus carried a host-wide **sudo-brick** risk.
The only durable Layer-0 win is the group grant. So Layer 0 is now **exactly
one capability change plus an assert** — no wrapper, no sudoers, no new root-run
code, which erases the critical hole and every sudoers/priv-esc finding at once.

### 3.1 The one change — `systemd-journal` group membership

Add `ubuntu-server` to **`systemd-journal`**. Confirmed against this box: the
`/var/log/journal` ACL grants `group:systemd-journal r-x`, and the identity
currently reads **0** kernel lines — so this grant is exactly what unblocks
`journalctl -k -b -1` and `journalctl -b -1 _PID=1` (the abrupt-cut vs
throttle-then-die discriminator), with **zero sudo**. Do NOT add `adm` (broader
— `/var/log` flat files incl. `auth.log`); `systemd-journal` is the tighter
grant and the journal is all Layer 1 reads.

### 3.2 Assert, don't assume, persistent journal

The previous-boot read (`-b -1`) only survives a reboot if journald storage is
persistent. **Confirmed present on this box** (`/var/log/journal` exists;
`--list-boots` reaches 2026-07-16). Setup still *asserts* it and stops if it's
ever volatile — turning journald persistent is a write and would belong in
Layer 2, so Layer 0 must not silently depend on it.

### 3.3 Scope honesty — what the grant really exposes

`systemd-journal` grants read of the **entire** journal, not just kernel lines:
every unit's stdout/stderr and any secret a service logged. This repo has a
history of secrets reaching logs (WireGuard keys, tokens). Two reasons this is
acceptable here, stated plainly rather than hidden: (a) the identity is
**already non-interactively root** via its existing `libvirt` group membership
(a libvirt member can define a domain with an attacker-chosen disk /
`qemu:commandline` and run qemu as root), so it can already read the whole
journal — this grant adds **no** capability it lacks; (b) the standing repo rule
(AGENTS.md §4) that no rustynetd/daemon logs secrets to the journal is the real
control, and holds regardless of this grant. Net: the incremental exposure is
nil; the pre-existing `libvirt` root-equivalence is the thing actually worth
hardening, tracked as a follow-up (§6).

### 3.4 One-time crash check — you run it now, no persistent grant

For the immediate "did the last reset leave anything," run these **once**, with
your own sudo (you have the password; no wrapper/sudoers needed for a one-shot):

```
sudo ls -la /sys/fs/pstore/ ; sudo cat /sys/fs/pstore/* 2>/dev/null | head -200
sudo dmidecode -t 0 -t 1        # BIOS version + board (Type-15 SEL absent here)
```

Ongoing pstore/mcelog/thermal access is Layer 2 (it installs mcelog + configures
ramoops, and can add a properly-reviewed access path *then*, alongside tooling
that actually produces data).

### 3.5 Verification (setup asserts these; fail-closed)

Run as `ubuntu-server` after the group grant + a fresh login:

1. `id -nG | grep -qw systemd-journal` → present.
2. `journalctl -k -b -1 | head` → **non-empty** kernel lines (was `-- No entries --`).
3. `journalctl -b -1 _PID=1 | tail` → returns PID-1's shutdown sequence (or its
   absence — either way, now *readable*).
4. `test -d /var/log/journal` → persistent journal confirmed.
5. `sudo -n true` → still **fails** (Layer 0 granted no sudo at all).

### 3.6 Rollback

```
sudo gpasswd -d ubuntu-server systemd-journal   # effective next login
```
That is the entire footprint — no files, no sudoers, nothing else to undo.

### 3.7 Threat model note

Added surface = **one group membership**, no new root-run code, no sudoers.
`systemd-journal` is a standard auditable Linux capability that (per §3.3) the
identity already effectively holds via `libvirt`. There is no wrapper to defeat
and no sudo grant to escalate. The residual real risk on this box is the
**pre-existing** `libvirt`/`kvm` root-equivalence, not anything Layer 0 adds.

---

## 5) Adversarial fable review — disposition

Review run 2026-07-24 (fable model). Findings and resolution:

- **[CRITICAL] `journalctl` wrapper arm = root pager (`less !sh`) escape.**
  ACCEPTED. Root cause was the wrapper existing at all for something the group
  already covers. Resolution: **wrapper removed entirely** (§3).
- **[HIGH] `-b -1` needs persistent journald, unverified.** ACCEPTED; verified
  present on this box and now an explicit assert (§3.2).
- **[HIGH] identity already root-equivalent via `libvirt`; §3.7 misleading.**
  ACCEPTED; stated plainly (§3.3/§3.7) and raised as the real follow-up (§6).
- **[MED] `systemd-journal` = full-journal (all secrets) read.** ACCEPTED;
  documented (§3.3); mitigated by no-secrets-in-logs rule + libvirt-already-root.
- **[MED] sudoers install can brick host sudo.** MOOTED — no sudoers file any
  more.
- **[MED] dmi-sel/mce/pstore arms yield nothing at L0.** ACCEPTED; matches the
  empirical probe (no Type-15 SEL, mcelog absent); moved to Layer 2/3 (§2, §3.4).
- **[LOW–MED] for a power/reset event, L0's only real yield is the prev-boot
  kernel tail.** ACCEPTED; L0 is honestly scoped to exactly that + priority
  shifted to Layer 2 (persistent journal already ✓, ramoops, mcelog,
  `kernel.panic=10`) and Layer 3 (PSU/BIOS), where a power event is diagnosed.
- **[LOW] info-disclosure / shell nits.** MOOTED with the wrapper.

## 6) Follow-up surfaced by review (not Layer 0)

`ubuntu-server`'s `libvirt`+`kvm` group membership is non-interactive
root-equivalent. The "no passwordless sudo" posture is therefore partly
illusory. If the agent identity should be genuinely sub-root, that requires
separating the libvirt-driving identity from a lower-privilege one — a larger
change, tracked here, out of scope for the observability layers.

---

# FLEET ONBOARDING ARCHITECTURE (first-class requirement)

The observability layers above must not be per-box manual work. They fold into a
repeatable **add/subtract a box** flow so the fleet scales horizontally
(Ubuntu + macOS). This section is the design, hardened by **four independent
adversarial fable reviews** (architecture / security / teardown / macOS). Design
v1 is superseded; below is v2 (what survived).

## 7.1 What already exists (reuse; do NOT rebuild)
Host registry `hosts[]` (`kind ∈ {local_utm, libvirt}`, parse-time `VmController`
resolution, fail-closed validation — b689cd6 on main); idempotent guest lifecycle
(`fetch-image` sha256-pinned, `provision-guest`, `provision-toolchain`,
`discover-hosts`, power, `sync-host`, host+guest preflight); node OS bring-up
`e2e-bootstrap-host`; two-plane split (host-agnostic SSH orchestration vs
kind-specific VM lifecycle); SSH secrets sidecar. The four gaps to close: host
**stand-up** automation, composed **add-box**, **teardown/offboarding** (none
exists today), macOS asymmetry + portability.

## 7.2 Design principle (review-decided)
**Idempotent composed verbs over declarative catalogs, PLUS the safe half of
reconcile — never destructive reconcile.** Rejecting a full desired-state control
loop is correct for a pets-not-cattle lab (a config-diff must never `undefine` a
VM). But pure verbs leave drift invisible at N hosts, so add read-only
`fleet-status` (declared-vs-actual drift report) + **additive-only**
`fleet-converge` (= run the idempotent `onboard-host` across all hosts; never
deletes). Every verb: check-then-act, three-outcome per step
(**confirmed-absent / confirmed-done / error** — never the repo's `|| true`
"absent==error" idiom), verify-by-readback, fail-closed on transport error.

## 7.3 The verbs (hardening baked in)

**`onboard-host --new --ssh <user@ip>`** — probes the fresh box, **auto-allocates
+ writes** its `hosts[]` entry (host_id, guest_subnet from a fleet allocator,
repo_dir by convention — no hand-edited JSON, which was the fiddliest surviving
step), records an **onboard manifest** of exactly what it changed, then runs the
stand-up (KVM stack, `usermod -aG`, rustup pin, PATH shims, pool + `chmod 2771`,
observability §7.6) and host-preflight. It must NOT blindly compose the
destructive `e2e-bootstrap-host` against a **live** box: that clears the nft
killswitch + trust anchor before recreating (`ops_e2e.rs:339-346` — a verified
**fail-OPEN** window). Gate it behind a "no protected traffic" assertion and keep
a standalone default-deny killswitch in force across the recreate.

**`add-guest --host H --image <catalog-name> --role R`** — fetch-image (catalog,
sha256) → **arch gate** (`catalog.arch == host uname -m`, fail closed, else an
amd64 image silently defines on an ARM host and dies as an opaque SSH timeout) →
provision-guest → wait-for-SSH → auto-write `entries[]` (non-secret) + sidecar
(secret, mode-600, **proven-by-test** it never lands in the public tracked file) →
toolchain → cache-seed + repo-sync + `--features vm-lab` build + known_hosts pin.
**Per-stage verify-then-skip** (domain exists AND SSH answers AND cloud-init
finished = skip; exists-but-unhealthy = explicit `--adopt`/`--recreate`) — because
`provision-guest` refuses an existing domain/overlay, so a naive re-run of a
half-done add hard-fails and orphans a VM. **Done-ness contract:** "guest passes
preflight AND is selectable by a `--node` run with zero further steps" — same
contract across all host kinds.

**`remove-guest --alias A` | `--host H --domain D`** (reality-keyed, so a
half-provisioned orphan with no inventory record is still removable) — three
outcomes per step; delete storage **only** from `virsh domblklist` read back
*before* undefine, pool-prefixed, and only files whose `qemu-img info` shows a
**backing file** (proves overlay, never the shared base image). **Drop
`--remove-all-storage`** (zero repo precedent; the existing rollback uses plain
`undefine` + targeted `rm`). Unreachable guest (the modal removal target — daemon
uninstall needs SSH into it): powered-off → auto-skip; powered-on-unreachable →
`--force-unreachable`, recording that trust cleanup was skipped. Emit membership
`RemoveNode`/`RevokeNode` **before** dropping the record; prune the host's
`known_hosts` entries (else a future box reusing the IP fails with a key-mismatch);
leave run-matrix rows untouched (evidence). `--yes`/dry-run default-plan. UTM:
`utmctl stop` → `utmctl delete` (verified to exist) → deregister, not `rm -rf`
the bundle.

**`offboard-host`** — offboard its guests (refuse if any remain without
`--offboard-guests`), deregister, prune known_hosts. `--revert-privileged` is
**cut from v1** (YAGNI + it strips the human's own access, since `agent_identity`
== the human account on ubuntu-kvm-1); if ever added, drive it from the onboard
manifest (replay-in-reverse of recorded additive changes only) and hard-refuse
while a run is active.

**Inventory writes** (all verbs): advisory `flock` + re-verify target still
matches before write + preserve key order/formatting + **refuse while a lab run is
active on the host** (the documented provenance dirty-check already failed runs
once). Secrets always to the mode-600 sidecar, never the tracked file.

## 7.4 Trust & connection model (security-review must-fixes)
- **No `curl | sudo bash`.** SecurityMinimumBar §6.B forbids TLS-only trust
  transfer. First-boot bootstrap is delivered image-baked (Ubuntu autoinstall /
  cloud-init user-data) or console/sneakernet with an **operator-verified
  sha256**; the transport is untrusted, the pasted hash is the trust root.
- **Agent pubkey carried in-band** in that pinned bootstrap, fingerprint verified
  once (like the §6.B owner pubkey) — never fetched from a URL.
- **Per-host distinct credentials** (or distinct authorized principal) — one key
  across N boxes is a fleet skeleton key. Private keys live only on the driving
  workstation; prefer short-lived SSH certs.
- **Privilege = narrow standing polkit capabilities, no agent sudo (FINAL, §7.10).**
  Superseded the earlier "time-bounded sudo" framing after two adversarial reviews
  converged on polkit capability-narrowing. The agent identity gets **no sudo at
  all** (C1 strips `sudo` from it and creates a distinct operator account); steady
  state runs on a fixed set of per-action polkit grants baked in C1 (libvirt API
  narrowed to sub-root + libvirtd/virtqemud-restart + reboot). Full rationale and
  must-fixes in §7.10.
- **Remote management path must be named and NOT the overlay-being-removed.**
  "LAN-first, tailnet-fallback" is not separable for a non-LAN box (the Rustynet
  overlay isn't up on a box you're onboarding — chicken-and-egg). v1 scope:
  onboarding requires a pre-existing reachable transport — LAN SSH to a pinned
  host key, or a bastion/jump host, or image-baked cloud-init phoning a fixed
  pinned endpoint. State plainly that remote onboarding needs one of these.

## 7.5 macOS reality (premise corrected — SPIKE RUN 2026-07-24: E-opt-0 CHOSEN)

**Spike result (run on the Mac, this machine):** headless AppleScript→UTM works
end-to-end under macOS Automation TCC with **no prompt and no GUI** — proven:
read-only query (VM list, exit 0); `make new virtual machine {backend:qemu,
configuration:{name, architecture:"aarch64", memory}}` created a VM from scratch;
`update configuration … {network interfaces:{{index:0, address:"52:54:00:…"}}}`
**set the MAC and read it back** (this MOOTS the reviewer's unverified
clone-MAC-regen risk — the MAC is set explicitly, never inherited); `utmctl
delete` removed it. The sdef `qemu drive configuration` has a **`source` = "An
existing file to use as the source image"** property, so a CoW overlay + seed ISO
attach exactly like libvirt. **Decision: adopt E-opt-0 (full programmatic parity),
NOT semi-manual.** The macOS guest path mirrors the libvirt flow: `qemu-img` CoW
overlay + `cloud-localds` seed + AppleScript `make` with drive `source`s + explicit
MAC. Two caveats stay open: (i) NOT yet validated end-to-end is an actual ARM
cloud-image + seed → boot → cloud-init first-boot → SSH-up (API capability proven;
guest bring-up is the next validation, needs a real image); (ii) TCC Automation
permission is currently granted but **revocable** (cf. the Local-Network-Privacy
caveat) — onboarding must detect an AppleScript `-1743` and surface it, not hang.

The three options as originally framed (kept for the record; E-opt-0 won):
- **E-opt-0 (real parity):** `qemu-img` CoW overlay + fresh cloud-localds seed +
  AppleScript `make` — mirrors the libvirt flow.
- **E-opt-1 (clone):** `utmctl clone` exists but has **zero reconfig knobs** →
  a byte-duplicate (same machine-id/host-keys/hostname; dup machine-id can grab
  the same DHCP lease even with a new MAC). Only viable as: cloud-init template +
  AppleScript `update configuration` to set a generated MAC + attach a fresh seed
  with a new instance-id; netplan matched by interface name, never MAC.
- **E-opt-2 (semi-manual):** register + toolchain + bootstrap a GUI-made VM.
- **Hard ceiling to STATE:** `local_utm` means *this machine* (`mod.rs:7736`
  refuses driving a remote Mac; no `remote_utm` kind). So multi-Mac scaling is
  impossible today — v1 is **Ubuntu fully-auto + exactly one Mac**; a
  `remote_utm` kind (SSH → run `utmctl`/`osascript` on the Mac) or run-on-host is
  the deferred path for Mac #2. Honesty requires stating this, not implying
  flow parity.

## 7.6 Observability fold-in (profile-driven, per-step outcomes)
Layer 0/2 are steps in `onboard-host`, driven by the host's `onboard_profile` /
`observability` field, each recording **applied / skipped-unsupported / failed**
— Layer 0 (journal group) mandatory; Layer 2 warn-by-default (`mcelog` is
x86-only → skipped-unsupported on ARM; `kernel.panic=10` is a behaviour change a
lean onboard shouldn't silently force). Observability absence must never block
using a box, and a silent skip is equally wrong — recorded-skip is the middle.
Layer 1 MCP tools stay host-agnostic (work on any onboarded box, zero new code).

## 7.7 Decisions I made (per "you decide") — two are reversible, flagged
1. **Privilege = narrow standing polkit, no agent sudo** (FINALIZED post-review —
   see §7.10; supersedes the earlier "time-bounded + reverted" call). Both
   adversarial reviews converged: capability-narrowing beats time-bounding against
   the real threat (a confused-deputy agent misusing its own valid credentials).
   *No longer flagged reversible — the two-review convergence settled it.*
2. **macOS = E-opt-0 full parity** (UPDATED post-spike — the AppleScript-headless
   spike passed, §7.5, so semi-manual is no longer the v1 fallback). Still **one
   Mac** until a `remote_utm` kind exists (`local_utm` = this-machine-only). The
   remaining macOS validation is a real end-to-end guest boot (cloud-init→SSH),
   not a design question. *Reversible:* if you want Mac-scaling (Mac #2) sooner,
   we prioritise `remote_utm`.
3. **Reconcile = idempotent verbs + additive `fleet-converge` + `fleet-status`
   drift report.** No destructive reconcile. (Not reversing this — every review
   agreed.)

## 7.8 Four-review disposition (condensed)
- **Architecture (sound-with-changes):** false idempotency → per-stage
  verify/adopt/journal ✓; hand-authored `hosts[]` survives → `onboard-host --new`
  ✓; "in inventory ≠ usable" → done-ness contract ✓; add `fleet-status`/
  `fleet-converge` ✓; cut `--revert-privileged` ✓.
- **Security (unsafe→acceptable-with-changes):** kill `curl|sudo bash` ✓;
  privilege → polkit-narrowed sub-root, no agent sudo (§7.10, replaced time-bound)
  ✓; per-host keys ✓; in-band pubkey ✓; secrets→sidecar proven-by-test ✓;
  fail-open recreate window gated ✓; remote path named ✓.
- **Privilege (2nd-round, two reviews — see §7.10):** security review refuted
  "libvirt-root immovable" (polkit narrowing → genuinely sub-root) ✓; operational
  review confirmed no shipped steady-state op needs host root, found 3 stand-up
  gaps folded to C1 (Layer-2 sinks, GRUB pin, operator account) + 1 genuine narrow
  standing grant (service-restart) ✓.
- **Teardown (safe-with-changes):** three-outcome/`|| true` trap ✓; backing-file
  check, drop `--remove-all-storage` ✓; unreachable-guest policy ✓; inventory
  flock ✓; prune known_hosts, mesh RemoveNode first, evidence untouched ✓;
  dry-run/`--yes` ✓.
- **macOS (sound-with-changes):** corrected UTM premise ✓; E-opt-1 stall fixed /
  E-opt-0 surfaced ✓; state one-Mac ceiling ✓; arch gate ✓; portability
  (resolvable connect_uri, scrub tailnet literals, second-operator note) ✓.

## 7.9 Implementation ordering
0. **Spike (macOS) — DONE 2026-07-24, PASSED (§7.5):** headless AppleScript
   `make`/`update configuration` under TCC works, MAC settable, drive `source`
   attach available → E-opt-0 chosen. Remaining: one end-to-end guest-boot
   validation (real ARM cloud image + seed → cloud-init → SSH) during step 3.
1. **Image catalog + arch gate — DONE 2026-07-25 (code), LIVE-PROVEN. Catalog
   *content* is seeded with placeholder digests (see below).**
   `documents/operations/active/lab_image_catalog.json` (schema v1) +
   `crates/rustynet-cli/src/vm_lab/image_catalog.rs` +
   `ops vm-lab-image-catalog`. Detail in §7.11.
2. `onboard-host --new` (entry authoring + allocator + manifest + observability
   fold-in) — Ubuntu path. C1 provisioning per §7.10: polkit rules (libvirt
   narrowed + service-restart), strip agent `sudo` + operator account, GRUB
   pin-by-id + `apt-mark hold`, Layer-2 sinks, privilege-shape readback assert.
3. `add-guest` (per-stage verify + done-ness contract + sidecar-proven secrets).
4. `remove-guest` + `offboard-host` (backing-file-safe teardown, `--yes`/dry-run).
5. `fleet-status` + additive `fleet-converge`.
6. Layer 1 MCP tools (`host_stability_report`, `host_thermal_status`) — host-agnostic.
7. Portability scrub (resolvable connect_uri, tailnet literals, hardcoded paths).
Each step: plan → adversarial review → implement, per the standing method.

## 7.9.1 Step 1 delivered — image catalog + arch gate (2026-07-25)

**Status: the code is DONE and live-proven; the catalog's digests are
placeholders.** Split deliberately, because those are different claims.

**What landed.** `crates/rustynet-cli/src/vm_lab/image_catalog.rs` (new
`vm_lab` submodule, so it reuses the parent's private validators —
`ensure_provision_image_name`, `ensure_script_safe_value`, `run_guest_script`,
`load_inventory_with_hosts` — with no visibility bumps, following the
`topology.rs` precedent), the tracked catalog
`documents/operations/active/lab_image_catalog.json`, and
`ops vm-lab-image-catalog` wired at the three mandatory
`#[cfg(feature = "vm-lab")]` sites in `main.rs`.

**Schema v1** is `serde(deny_unknown_fields)` per entry and at top level:
`name`, `os`, `os_version`, `arch`, `kind`, `filename`, `url`, `sha256`,
`digest_provenance`, optional `notes`. Two fields exist because the fleet's real
images demanded them, not for symmetry:
- **`kind`** (`cloud_image_qcow2` | `iso`) — `provision-guest` uses its base
  image as a qcow2 backing file (`qemu-img create -F qcow2 -b …`), so an ISO
  fails at runtime, not at validation. `windows-x86-1` is a libvirt guest
  installed from an ISO, so the ISO case is real and must be representable and
  refusable, not excluded.
- **`digest_provenance`** (`upstream_published` | `local_tofu`) — Fedora
  publishes no digest for `virtio-win.iso` (the adjacent `CHECKSUM` covers only
  the four RPMs, in MD5), so any pin for it is trust-on-first-use. §7.4 says the
  pasted hash is the trust root; a TOFU digest that is byte-identical in the file
  to a vendor-attested one launders TLS-only trust into something that looks
  authoritative forever. Making the distinction mandatory is what prevents that.

**Fail-closed rules, each with a test.** Non-object root; missing/non-1
`version`; empty `images`; any required field missing or whitespace-only; unknown
key at either level; duplicate JSON key (the derive path errors where a
`serde_json::Value` walk silently keeps the last — on a digest field that is a
supply-chain hazard, and it is the reason this module does not follow the
inventory loader's hand-rolled style); duplicate `name` case-insensitively; one
`filename` described two ways; non-https `url`; `sha256` not 64 hex; `filename`
failing the consumer's own validator; `arch` outside the closed accept-list.

**The arch gate.** `LabArch` is a closed two-variant enum with no fallback arm.
Two parsers, because the two sides have opposite needs: `parse_catalog_arch`
demands canonical spelling (a tracked file must not accumulate four spellings of
one architecture), while `parse_probed_arch` is lenient because the fleet really
does report `x86_64`, `aarch64`, `arm64` and — on Windows — `AMD64`. Folding is
ASCII-only, so non-ASCII lookalikes fail closed instead of folding onto a real
token. `assert_image_runnable_on` takes a `CatalogImage` and a `ProbedHostArch`
rather than two strings, which makes "arch matched" unreachable without both
sides parsed and binds the verdict to the entry that was actually checked.
`ProbedHostArch` is constructible only by a real probe or by the deliberately
greppable `assumed_by_operator`, and carries that provenance into every message.

Two holes found by adversarial review and closed here:
- **A lying `arch` field** passed every other rule: `"arch": "amd64"` on
  `debian-13-generic-arm64.qcow2` parses cleanly and then reports a green gate,
  defeating the exact failure the gate exists to prevent. The declared value is
  now cross-checked against arch tokens in the filename and the URL's final
  segment. Only the final segment, so a mirror directory naming an unrelated
  architecture does not false-fail.
- **Mode selection by flag *presence*** would have exited 0 with the gate never
  run: the ops option parser demotes a value-less `--foo` to a flag and rejects
  no unknown options. Mode is now chosen by an explicit flag, a value-less
  gate option is a hard error, and every run prints `GATE: RAN` or
  `GATE: NOT RUN`. For a command whose purpose is to be a gate, "not run" must
  never be mistakable for "passed".

**Live proof (2026-07-25).** The gate reads the real host, not a constant —
verdicts invert across two hosts of different architectures:

| Host | Probe | `debian-13-arm64` | `debian-13-amd64` |
| --- | --- | --- | --- |
| `mac-utm-1` (aarch64) | `[measured]`, local | PASS, exit 0 | **fail-closed, exit 78** |
| `ubuntu-kvm-1` (x86-64) | `[measured]`, `uname -m` over SSH | **fail-closed, exit 78** | PASS, exit 0 |

A mismatch exits **78 `policy_reject`** ("DO NOT retry without operator
review"), not 70 `transient_failure`. That is deliberate: `classify_cli_error`
is a substring heuristic, so the message avoids every transient-sounding word —
a CI wrapper must never retry an architecture mismatch. An unusable probe also
exits 78 (verified), never falling back to a declared or guessed value.

**Placeholder digests — precise scope of what is NOT done.** All three entries
carry `sha256` of 64 zeros. This is safe by construction rather than a latent
bypass: `HOST_FETCH_IMAGE_SCRIPT` verifies the pin and refuses on mismatch, so a
zeros digest guarantees refusal. The arch gate and every other schema rule are
enforced independently of digest *value*, which is why the gate is claimed as
done and the catalog content is not. **Owed before the catalog is used to fetch
anything:** real digests from Debian's signed `SHA256SUMS` for the two cloud
images, and an adopted local-fetch digest for `virtio-win.iso`.

**Still owed from the reviews, deliberately not folded in here** (they belong to
the increment that authors the call site, and the ledger should not imply
otherwise): `fetch-image` still accepts no digest at all
(`sha256: Option<String>`), and `provision-guest` verifies only that its base
image *exists* (`[ -f "$BASE" ]`) with no digest field. Until those close, the
catalog's mandatory digest is a data-quality guarantee, **not** an integrity
control over the bytes a guest boots. The pool is group-`kvm`-writable
(`chmod 2771`) and the agent identity is in `kvm`, so a pool overwrite needs no
privilege — §7.10's confused-deputy threat exactly. Closing it needs both:
provenance-or-digest mandatory on `fetch-image` (no silent skip), and
re-verification at consumption in `add-guest` (step 3).

## 7.9.2 Prerequisite hardening — shell injection in `provision-guest` (fixed 2026-07-25)

Found while mapping step 3's call site; fixed here because `add-guest` wraps
`provision-guest`, so onboarding cannot be built on it as it stood.

**Grade: MAJOR** — privileged-boundary defect plus a false safety comment. Not
critical: the input is operator/tool-supplied, not remote-attacker-supplied, so
this is not remote RCE. It is squarely §7.10's confused-deputy case, because the
lab-state MCP exposes an `image` parameter and lab data an agent reads is
untrusted.

`HOST_PROVISION_GUEST_SCRIPT` interpolates `POOL='…'`, `NAME='…'`, `IMAGE='…'`
into single-quoted shell literals, and its doc comment asserted that "the caller
forbids a literal single quote, so the quoting cannot be escaped." **That was
false for two of the three.** `pool` was interpolated with no validation at all,
and `ensure_provision_image_name` was a deny-list that rejected `/`, `..` and
control characters but permitted `'` — and had no length bound, unlike
`ensure_provision_guest_name`'s `1..=60`. So `--image "x'; id; '"` or a `--pool`
carrying the same closed the literal and ran the remainder as shell source on the
lab host, as the lab identity (groups `libvirt`, `kvm`; write access to the
group-writable pool). `name` was already safe.

The hardened pattern already existed in the same file: `host-disk-status` calls
`ensure_script_safe_value` **and** rejects `'` explicitly. This was a missing
guard, not a missing rule.

Fix: `ensure_single_quoted_script_value` composes `ensure_script_safe_value` with
the `'` rejection, so the two halves of the rule cannot drift apart per call site
(§3, one hardened path); `provision-guest` now applies it to `pool`;
`ensure_provision_image_name` became a strict ASCII allow-list
(`[A-Za-z0-9._-]`, no leading `-`/`.`, `1..=128`) which is safe under *both*
quoting styles, since that value is also used double-quoted in
`HOST_FETCH_IMAGE_SCRIPT`; and the doc comment now states what is enforced and
where, plus the fact that the comment is not the control. `host-disk-status` was
refactored onto the shared helper — semantics-preserving, and it removes the
second copy of the rule rather than implying that path was ever broken.

Verification (§4 requires an enforcement point *and* a test): negative tests
prove `'`, shell metacharacters, whitespace, a non-ASCII homoglyph, a leading
`-`/`.`, and an over-long value are each rejected for `image`, and that `'` plus
every `ensure_script_safe_value` metacharacter and the empty/whitespace cases are
rejected for `pool`. `Rocky-10-GenericCloud.latest.x86_64.qcow2`,
`virtio-win.iso` and the real pool path stay valid, so the allow-list is not
retroactively breaking the fleet.

## 7.10 Privilege model — FINAL (decided after two adversarial reviews)

**The question posed:** for the lab-driving agent identity, is *time-bounded*
privilege (onboard installs a temp sudoers, does the privileged phase, reverts it)
or *standing* privilege the better long-term model? Both a security-axis and an
operational-axis adversarial review were run. **They converged, and the answer is
neither of those two framings — it is narrow, standing, per-action polkit
capabilities with no agent sudo at any point.**

### The decision
1. **The agent identity holds no sudo — ever.** Not standing, not time-bounded.
   C1 (the first-boot, image-baked/console bootstrap — never the agent) does all
   one-time privileged stand-up, and C1 **strips the `sudo` group from the agent
   identity** and creates a **distinct operator account** (password + sudo, for the
   rare human console maintenance). "No standing agent sudo" is false today —
   `ubuntu-server` is in `sudo,libvirt,kvm` — so this strip is a required C1 step,
   not a description of the status quo.
2. **Steady-state agent privilege = a fixed set of narrow polkit rules baked in C1**
   (auditable, per-action, not shell-reachable — unlike any sudoers entry):
   - **libvirt API narrowed** via `org.libvirt.api.*`: allow
     `domain.start/stop/getattr/read` + guest `undefine`; **deny**
     `domain.define`-with-host-disk / `save` / `core-dump`. This is what makes the
     agent **genuinely sub-root** — it removes the domain-define-arbitrary-disk path
     that is the libvirt-group root-equivalence. (Requires C1 to flip
     `auth_unix_rw` from `"none"` to `"polkit"` — verified: the box currently runs
     `auth_unix_rw = "none"`, polkit 124 + granular `org.libvirt.api.domain.*`
     actions are present.)
   - **service-restart + reboot** via `org.freedesktop.systemd1.manage-units`
     scoped to `libvirtd`/`virtqemud`, plus optionally `org.freedesktop.login1.reboot`
     — the genuinely-needed standing grant for the hypervisor-wedge recovery class
     (proven to happen: the 16-min UTM VM-reset hang has a libvirt equivalent).
     Never resurrect `run_host_reboot`'s `sudo -n systemctl reboot`.
3. **The one escalation — `add-guest` needs `domain.define`** — is isolated as a
   single broker-mediated / vetted-template-only define, not a general capability.

### Why this beats both original framings (the load-bearing argument)
The **dominant threat for an AI-agent identity is not credential theft — it is the
confused deputy**: prompt-injection reaches the agent through the very lab data it
reads (guest logs, journal text, stage reports — all attacker-influenceable from
inside a guest), or plain agent error, causing it to act destructively with its
own **valid** credentials. Against that, per-host keys, SSH-cert TTLs, and a
time-bounded sudo window are all irrelevant — the confused deputy never needs a
stolen credential, and a full-root time-window is a full-root window whether or not
it is short. **Only shrinking the capability surface bounds a confused deputy**, and
that is exactly what the polkit narrowing does and what time-bounding does not.
Time-bounding also adds a revert step that can *fail* — leaving standing sudo, the
worst outcome — whereas a rule set once in C1 has nothing to revert.

### Must-fixes folded in (from the two reviews)
- **Layer-2 forensics must not need agent root** (operational F1): C1 provisions the
  sinks (`systemd-pstore` archive + group-readable ACL, one-shot `dmidecode` dump,
  `mcelog`→journal) so `host_crash_forensics` is a pure unprivileged read.
  `host_install_diagnostics` is reclassified from an agent MCP tool to C1/operator
  (§2 table updated) — the two were contradictory before.
- **GRUB kernel-pin time bomb** (operational F4): C1 pins by menu-entry id (or
  `GRUB_DEFAULT=saved` + `grub-set-default`) and `apt-mark hold`s kernels / disables
  unattended kernel upgrades — the index-drift strand is a *dead host*, not a stall.
- **Privilege-shape readback assertion** (security F7): `onboard-host` finalization
  reads back `id <agent>` and `sudo -ln` and **fails closed** if groups ≠ the
  intended set or any sudo is reachable — the sha256-pin authenticates C1's bytes,
  not the correctness of the privilege they provision.
- **Stop counting SSH certs as a current control** (security F4): none exist in-repo;
  they are future work, not part of today's posture.
- **Delete the `fetch-image` `sudo -n` fallback** (operational F5) once this lands —
  on a C1-correct host the unprivileged pool write always succeeds; the fallback is
  dead code that only rewards keeping passwordless sudo around.
- **Name the residual concentrations** (security F1/F6): the driving workstation is
  the concentrated trust root (holds all per-host keys / any future CA); the broker
  is the only control that bounds even a workstation-origin confused deputy.

### Observed ground truth on `ubuntu-kvm-1` (probed 2026-07-25)

Measured, not inferred. Recorded because C1 is written against this host and
three of these facts change how a step must be written or verified. Where an item
merely *confirms* what §7.10 already says, it is labelled as confirmation — the
decision above is not being reopened.

```
whoami: ubuntu-server  uid=1000  groups=1000(ubuntu-server),27(sudo),107(libvirt),993(kvm)
sudo -n true            → "sudo: a password is required"      (no PASSWORDLESS sudo)
sudo -n -l              → password required (cannot even enumerate)
/etc/sudoers.d/         → root-only README; no drop-ins
/etc/polkit-1/rules.d/  → Permission denied (UNREADABLE to the agent identity)
netdev group            → EMPTY;  /etc/netplan/*.yaml → root-only 0600
/run/wpa_supplicant/    → Permission denied; wpa_cli → Permission denied
net stack               → systemd-networkd + wpa_supplicant ACTIVE;
                          NetworkManager INACTIVE; iwd INACTIVE; nmcli ABSENT
tools present           → iw, wpa_cli, wpa_passphrase, wpa_supplicant, netplan, rfkill
libvirt                 → qemu:///system reachable; default `virsh uri` = qemu:///session (EMPTY)
```

1. **This host is netplan + `systemd-networkd` + `wpa_supplicant`, and `nmcli`
   and `iwctl` are ABSENT.** New constraint, not a correction — the plan named no
   network manager either way. Any C1 network step written against
   NetworkManager/`nmcli` simply will not run here.
2. **The agent identity is in group `sudo` today.** Confirms §7.10's stated
   position (it already says "'No standing agent sudo' is false today"). The
   consequence worth stating: the privilege-shape readback assert would FAIL
   against the box as it stands, which is the correct answer. Note the assert runs
   at `onboard-host` *finalization*, i.e. after C1 has stripped `sudo` — it is not
   a precondition of onboarding, or this box could never be onboarded.
3. **`sudo -n true` failing proves no *passwordless* sudo, not no sudo** — and
   `sudo -n -l` cannot even enumerate. So the assert must key on `id` group
   membership (must not contain `sudo`) **and** on `sudo -n true` failing.
   Treating the `sudo -n` failure alone as compliance would read today's
   non-compliant box as compliant.
4. **`/etc/polkit-1/rules.d/` is unreadable to the agent**, so the polkit half of
   the privilege shape cannot be verified by reading files. §7.10's Scope
   paragraph already specifies the right check (behavioural: `virsh define
   <host-disk-xml>` denied while `start`/`stop`/`getattr` work) — this is a note
   on *how* to run it safely, not a new requirement. **That probe mutates on the
   failure path:** if the rule is misconfigured to allow, the `define` SUCCEEDS
   and has just defined a domain with a raw host disk attached. So specify:
   success of the negative probe is a hard gate FAIL, `undefine` immediately, and
   use a harmless disk path.
5. **The agent has no network-reconfiguration capability at all** (`netdev`
   empty, netplan root-only 0600, `wpa_supplicant` socket unreadable) and §7.10
   grants it none — consistent. Consequence: uplink/router work on this box cannot
   be agent-assisted and must be done by the operator at the console.
6. **`virsh uri` defaults to `qemu:///session`, which is EMPTY.** The shipped code
   is already correct here — every `virsh` call in `HOST_PROVISION_GUEST_SCRIPT`
   and `HOST_GUEST_CONSOLE_SCRIPT` passes `-c qemu:///system` explicitly. The risk
   is a *new* C1 validation forgetting it and reading "no domains" as "all clear",
   which is a fail-open in the validation itself.
7. **The box rebooted 2026-07-25 14:12 and unexplained reboots recur.**
   Reinforces the already-agreed C1 Layer-2 sinks (`systemd-pstore` + ACL,
   one-shot `dmidecode` dump, `mcelog`→journal) and the reboot grant.

### Scope (why this is not routed through SecurityMinimumBar §2 paperwork)
This identity is **lab/orchestrator scope, not shipped-product surface** — it lives
behind the `vm-lab` cargo feature (RNQ-17), compiled out of every released binary;
CI gates run `--all-features` but the shipped release carries none of it. So the
residual accepted risk (the `add-guest` define escalation; workstation-as-trust-root)
sits **outside the product release gate**, and is documented here rather than filed
as a SecurityMinimumBar §2 High-control risk-acceptance. The narrowing above is
nonetheless applied because it is cheap at C1 build time and bounds the confused
deputy regardless of scope. **Pre-implementation validation owed on `ubuntu-kvm-1`:**
define the polkit rule, confirm `virsh start/stop/destroy` + the lab's bridge/pool
ops still work while `virsh define <host-disk-xml>` is denied without a password, and
grep the vm-lab orchestrator's libvirt call sites to confirm no allowed steady-state
op secretly needs a define/save-class API.
