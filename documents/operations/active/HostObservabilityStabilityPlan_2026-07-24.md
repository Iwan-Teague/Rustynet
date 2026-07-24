# Host Observability & Stability Plan — ubuntu-kvm-1 (2026-07-24)

Status: ACTIVE. Owner track: lab infrastructure (extends
`LinuxVmHostPlan_2026-07-14.md`). Trigger: `ubuntu-kvm-1` rebooted ≥2× on
2026-07-24 under nested-virt load; the box is currently **un-diagnosable** — see
the memory `ubuntu_kvm1_reboot_investigation_2026-07-24`.

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
| **2** | Active MCP tools: `host_install_diagnostics` (lm-sensors/mcelog/pstore-ramoops/`kernel.panic=10`) + `host_crash_forensics` (pstore/dmidecode read — needs the reviewed root path deferred from L0) + `host_thermal_stress_probe` (reproduce under load) | Yes (state-changing) | Layer 0 |
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
