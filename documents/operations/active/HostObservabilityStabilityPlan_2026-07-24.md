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
1. Image catalog (`lab_image_catalog.json`, name→url+sha256+os+arch) + arch gate.
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
