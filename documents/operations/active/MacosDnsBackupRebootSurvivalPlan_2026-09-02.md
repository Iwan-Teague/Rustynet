# macOS DNS Backup Reboot-Survival Plan (2026-09-02)

**Status:** plan only — no code, no gate, no lab run. Needs an adversarial refute pass (§5) before any implementation.
**Trigger:** live-lab run `livelab-1788324188-fb8e58290cce`, 2026-09-02, macOS guest `macos-utm-1`.

## 0) Decision summary

The M1 macOS DNS-fail-closed feature writes its pre-enforcement backup document to
`/private/var/run/rustynet/networksetup-dns.failclosed.bak` — a **volatile** path that macOS
clears at boot — while the System Configuration DNS posture it protects against **persists**
across reboot. Any reboot while protection is active therefore strands the host: SC DNS is
loopback, the resolver behind that loopback is dead, the backup is gone, and the daemon's own
startup guard (correctly, fail-closed) refuses to start. Only a manual
`networksetup -setdnsservers <svc> Empty` recovers the node. This structurally breaks the macOS
`live_reboot_recovery` stage and any unattended macOS node that reboots.

**Recommendation: Option A** — move the backup document to the durable state dir, derived as a
sibling of the daemon state file exactly the way QH-40's shutdown-residue marker is derived
(`shutdown_residue.rs::marker_path`, `SHUTDOWN_RESIDUE_MARKER_SUFFIX`), keeping 0600 mode and the
existing fail-closed "unreadable = present = refuse" semantics. The volatile path is **not** read
as a fallback on startup (see §3, invariant 5). Option C (set-DNS-Empty without a backup) is
rejected as a default because it discards the operator's pre-protection DNS; a narrow,
proof-gated variant is recorded as a possible future last resort, and the code today cannot
produce the required proof. The recommendation never weakens the fail-closed guard: missing
durable backup + loopback residue still refuses startup loudly.

## 1) Current behaviour

### 1.1 The observed failure

Run `livelab-1788324188-fb8e58290cce` (2026-09-02, `macos-utm-1`): the guest was rebooted while
DNS protection was active. `rustynetd` refused to start with:

```
RustyNet DNS fail-closed residue detected at startup: System Configuration DNS is still loopback but no RustyNet DNS protection is running and the backup document is missing or unreadable (/private/var/run/rustynet/networksetup-dns.failclosed.bak). Host DNS resolution will stay broken until the manual fix is applied:
Then restart rustynetd.
```

That string is the daemon's own loud refusal — `startup_recovery_manual_restore_message`
(`crates/rustynetd/src/macos_dns_sc_protect.rs:763`, template at `:770`) — reached through
`run_startup_dns_recovery` (`:796`, backup read at `:816`, decision at `:818`).

### 1.2 The asymmetry that causes it

The module documents the asymmetry itself. `crates/rustynetd/src/macos_dns_sc_protect.rs:20-30`:
"SC DNS persists across reboot; a crash without teardown would otherwise strand host DNS on the
dead loopback port". And `:505-512`: "The loopback posture itself is M1's durable residue marker:
it persists across reboot (unlike pf anchors, which launchd's boot-time `pfctl -F` clears)".

But the backup that would repair the strand is written to a boot-cleared path:

```rust
// crates/rustynetd/src/macos_dns_sc_protect.rs:301-307
pub const NETWORKSETUP_DNS_BACKUP_PATH: &str = if cfg!(target_os = "macos") {
    "/private/var/run/rustynet/networksetup-dns.failclosed.bak"
} else if cfg!(target_os = "linux") {
    "/run/rustynet/networksetup-dns.failclosed.bak"
} else {
    "/tmp/rustynet-networksetup-dns.failclosed.bak"
};
```

The runtime dir itself is recreated per boot by the root helper — the installer says so
explicitly (`scripts/bootstrap/macos/Install-RustyNetMacosService.sh:533-536`): "macOS garbage-
collects /private/var/run between reboots, so without a root-privileged RunAtLoad daemon to
recreate it the rustynetd user has no permission to mkdir there". So after a reboot the backup
file is *gone*, not merely unreadable.

### 1.3 The recovery decision

```rust
// crates/rustynetd/src/macos_dns_sc_protect.rs:514-530
pub fn decide_startup_recovery(
    residue_evidence: bool,
    dns_protection_running: bool,
    backup_readable: bool,
) -> StartupRecoveryDecision {
    if !residue_evidence || dns_protection_running {
        return StartupRecoveryDecision::NoAction;
    }
    if backup_readable {
        StartupRecoveryDecision::RestoreFromBackup
    } else {
        StartupRecoveryDecision::FailLoudManualRestoreRequired
    }
}
```

The backup reader is already fail-closed about *present-but-broken* documents
(`read_networksetup_dns_backup`, `:441-478`): missing → `Ok(None)` (caller decides), but present
and unparsable, foreign-schema, empty, or carrying invalid service names → hard `Err`. The
guard's own semantics treat an unreadable document as residue, not absence ("an unreadable marker
is not an absent marker" — the same principle QH-40 states at `shutdown_residue.rs:38`).

### 1.4 Where the backup is written and by whom

The macOS apply path (`MacosCommandSystem::apply_dns_protection`,
`crates/rustynetd/src/phase10.rs:4587`) enumerates services, resolves the per-service baseline
against any prior backup (M1 capture guard, `:4624-4648` — a present-but-unreadable prior backup
refuses the apply; loopback residue with no prior entry refuses loudly), then:

```rust
// crates/rustynetd/src/phase10.rs:4657-4664
// The backup is written BEFORE the first mutation: a crash mid-apply
// leaves the host in a state the startup-recovery guard (daemon.rs)
// can fully restore from.
let backup = crate::macos_dns_sc_protect::build_networksetup_dns_backup(backup_entries)
    .map_err(SystemError::DnsApplyFailed)?;
crate::macos_dns_sc_protect::write_networksetup_dns_backup(
    std::path::Path::new(crate::macos_dns_sc_protect::NETWORKSETUP_DNS_BACKUP_PATH),
    &backup,
)
```

The writer (`write_networksetup_dns_backup`, `macos_dns_sc_protect.rs:405-437`) creates the
parent dir, serializes, writes, and chmods `0o600` ("the document reveals which resolvers the
host used"). It is a plain in-process `std::fs` write by the **daemon process itself**, which on
macOS runs as the dedicated service user: the launchd plist sets
`UserName=rustynetd`, `GroupName=rustynetd` (`Install-RustyNetMacosService.sh:491-494`). The
`/private/var/run/rustynet` directory it lands in is created per boot **as root** by the
privileged helper plist (installer `:533-536`; socket dir is root-owned `0o770` per the plist
fragment comment at `:473`), with group access for the daemon — which is how the unprivileged
daemon can write inside it today.

### 1.5 The privileged helper's role

The helper is **not** on the backup path. Its `networksetup` allowlist constrains the restore's
*argv only* — program `/usr/sbin/networksetup` (`NETWORKSETUP_BINARY_PATH`,
`macos_dns_sc_protect.rs:44-46`), argv shapes validated by
`validate_networksetup_args` (`crates/rustynetd/src/privileged_helper.rs:2936-2955`), which
admits `-setdnsservers <validated-service> Empty` and `-setdnsservers <validated-service>
<validated server list>` via `is_valid_networksetup_service_name` /
`is_valid_networksetup_dns_server_list`. No helper program takes or returns the backup
*document*; there is no path argument in the allowlist, so **no helper allowlist change is needed
for Option A** — only the constant (and its test pins) move. (The helper does have a separate
`DnsFailclosedFile` builtin, `privileged_helper.rs:248`, `:292`, `:1961`
`validate_dns_failclosed_file_args`, used by `phase10.rs` for other fail-closed files —
irrelevant here unless the implementer chooses to route the backup through it; not required.)

### 1.6 The durable state dir precedent (QH-40)

QH-40's shutdown-residue marker is the in-tree pattern for a durable, reboot-surviving residue
marker:

```rust
// crates/rustynetd/src/shutdown_residue.rs:56-59
/// Suffix appended to the daemon state file name to derive the marker path.
pub const SHUTDOWN_RESIDUE_MARKER_SUFFIX: &str = ".shutdown-residue.json";

// :176-187  "Derive the marker path from the daemon state path."
//           "The marker is a sibling of the state file so it inherits the state
//            file's ownership and permissions."
pub fn marker_path(state_path: &Path) -> PathBuf { ... }
```

The daemon's durable state root on macOS is `/usr/local/var/rustynet`
(`daemon.rs:171`, `DEFAULT_STATE_PATH = "/usr/local/var/rustynet/rustynetd.state"` at
`daemon.rs:177`; installer `STATE_ROOT` default at `Install-RustyNetMacosService.sh:31`), owned
by the `rustynetd` service account — the trust/membership/keys files under it
(`daemon.rs:200-492`) are all written by the daemon, so a backup document placed beside the
state file lands on the same durable volume, survives reboot, and inherits the daemon's own
ownership.

### 1.7 The Linux twin

`crates/rustynetd/src/linux_dns_protect.rs:248`:
`RESOLV_CONF_FAILCLOSED_BACKUP_PATH = "/run/rustynet/resolv.conf.failclosed.bak"` (Linux branch;
the same const also has a **macOS branch** at `:250-251` — `/private/var/run/rustynet/resolv.conf.failclosed.bak`,
see §6 — and a `/tmp` fallback at `:253`). On Linux `/run` is typically a `RuntimeDirectory=` tmpfs cleared
at boot, so **the same volatility defect class applies on Linux**: a reboot while
resolv.conf/systemd-resolved protection is active can strand host DNS with the backup gone. The
startup-refusal behaviour differs by platform plumbing (Linux does not have this exact SC guard),
but Option A's derivation pattern should be applied to the Linux constant in the same change or
immediately after; §6 scopes this plan to the macOS fix, with the Linux twin recorded as the
known follow-up.

### 1.8 The stage that proves it

The `live_reboot_recovery` stage exists in the `--node` registry
(`crates/rustynet-cli/src/live_lab_stage_registry.rs:2049`, with
`live_reboot_recovery_validation` at `:1979`; column mapping at `live_lab_run_matrix.rs:4886`),
implemented by the reboot-recovery test binary
(`crates/rustynet-cli/src/bin/live_linux_reboot_recovery_test.rs:629`). As the binary name says,
its proven path is Linux; the macOS reboot-with-protection-active scenario is exactly what
`livelab-1788324188-fb8e58290cce` ran into and could not survive.

## 2) Options

Ranked by the decision lens (serves core goals → most secure → best long-term).

### Option A (RECOMMENDED) — durable backup beside the daemon state file

Move the backup document to the durable state root, derived the QH-40 way: a sibling of
`DEFAULT_STATE_PATH` with a new suffix, e.g.
`/usr/local/var/rustynet/rustynetd.state.networksetup-dns.failclosed.bak`
(`SHUTDOWN_RESIDUE_MARKER_SUFFIX` derivation pattern from `shutdown_residue.rs:182-187`).

* Serves core goals: the strand case becomes fully automatic again — reboot, daemon starts,
  guard sees loopback residue + readable backup + no protection running → restore from backup.
  `live_reboot_recovery` on macOS becomes passable.
* Most secure: same 0600 writer; the state dir is daemon-owned (not world-traversable tmpfs);
  no new privileged surface; unreadable-still-refuses is preserved unchanged.
* Best long-term: one derivation pattern (`sibling-of-state-file + suffix`) now owns both
  durable residue documents (QH-40 marker, DNS backup), which is the same shape the Linux twin
  needs.

Cost: the constant stops being a bare path and becomes a derivation from the state path (a
function plus a const suffix); every site that names `NETWORKSETUP_DNS_BACKUP_PATH`
(`macos_dns_sc_protect.rs:770`, `:816`, `:830`, `:838`, `:847`, `:884`, `:909`, `:869-:913`
messages — `:884`/`:909` are the two post-restore `remove_networksetup_dns_backup` calls, which
must move with everything else or a successful startup restore leaves the volatile file behind
while the durable one is gone, a phantom residue document; `phase10.rs:4629`, `:4660-4661`) must
take the derived path; test pins move
(`macos_dns_sc_protect.rs:1243` neighbourhood, `manual_restore_message_names_the_fix_per_service`
at `:1267` which asserts the substring `networksetup-dns.failclosed.bak` — the filename survives,
only the directory changes).

### Option B — keep `/var/run`, re-derive at startup from a persisted copy

Keep the volatile live backup but mirror it to the durable dir at write time and, at startup,
re-derive the document from the persisted copy when the volatile one is missing.

* Rejected: it is Option A plus a redundant second write and a second read path. Two documents
  means two places to disagree (which copy is authoritative during a crash window?), and the
  volatile copy serves no purpose once the durable copy exists — every consumer
  (`phase10.rs:4629` prior-backup read, `:816` startup read) can read the durable one directly.

### Option C — restore-without-backup (set `Empty` on loopback residue)

Make `decide_startup_recovery` return a new "clear to Empty" action when residue is present, no
backup exists, and protection is not running.

* Why it is attractive: it would have auto-recovered `livelab-1788324188-fb8e58290cce` with no
  backup at all, and `networksetup -setdnsservers <svc> Empty` is the documented
  restore-to-none keyword the code already uses (`NETWORKSETUP_EMPTY_DNS_KEYWORD`,
  `macos_dns_sc_protect.rs:56-58`).
* Why it is **not fail-closed as a default**: the operator may have had static DNS configured
  before M1 ever ran. The backup document is the *only* record of that. `Empty` discards it
  permanently and silently — a data-loss action taken without evidence of what was there.
  The current code's refusal (`FailLoudManualRestoreRequired`) is deliberate: "the startup
  decision only ever restores from a readable backup and otherwise demands an explicit operator
  fix" (`macos_dns_sc_protect.rs:29-30`).
* A last-resort variant could be acceptable ONLY if the daemon can prove the loopback posture is
  RustyNet's own (not an attacker or another tool pinning loopback) — e.g. a signed or
  content-bound marker written at apply time next to the backup. **The code cannot do this
  today**: residue detection (`residue_evidence_from_observation`, S4 per-service observation)
  proves only "some service is loopback-only", not who pinned it. Until such proof exists, C
  must not ship, even gated. If it is ever built, it must be strictly ordered after A and must
  never fire when a backup exists.

### Decision

Option A. It is the only option that restores automatic recovery without inventing new trust
assumptions, reuses a proven in-tree pattern, and needs no helper allowlist change.

## 3) Invariants, enforcement points, tests

| # | Invariant | Enforcement point | Test |
| --- | --- | --- | --- |
| 1 | Backup survives reboot | Path derived from the durable state root (`sibling-of-state-file` derivation, `shutdown_residue.rs:182-187` pattern) — not under `/var/run` | Unit: derived path is under the state dir and changes with `--state-root`; live: macOS `live_reboot_recovery` with protection active (§4) |
| 2 | Backup written BEFORE the first SC mutation | Existing ordering in `phase10.rs::apply_dns_protection` (`:4657-4664` comment + write-before-loop) — preserved verbatim, only the path changes | Existing ordering coverage; add: a failed `networksetup` set mid-apply leaves the *durable* backup readable (rollback can use it) |
| 3 | Backup readable only by root/daemon | `write_networksetup_dns_backup` keeps `0o600` (`macos_dns_sc_protect.rs:427-433`); durable dir is daemon-owned by construction | Unit: mode assertion after write (follows existing style); file lands beside state file → inherits dir ownership |
| 4 | Startup restore uses the durable path | `run_startup_dns_recovery` reads the derived path (`:816` — constant swap); messages name the new path (`:770`, `:816`, `:830`, `:838`, `:847`, `:884`, `:909`, `:869-:913` — the `:884`/`:909` post-restore `remove_networksetup_dns_backup` calls included) | Update `startup_guard_restores_from_readable_backup_only` neighbourhood (`:1243`) and `manual_restore_message_names_the_fix_per_service` (`:1267`) to the derived path |
| 5 | The old volatile path is NOT read as a fallback | Startup and apply read ONLY the derived path; no fallback branch exists (the reader takes one path argument). Fail-closed answer: no fallback read; old path ignored entirely | Unit: a backup written to the old volatile path is ignored by `run_startup_dns_recovery` (§4 tests-first list, item 3) |
| 6 | The durable backup's parent directory exists before the startup guard reads it, or the guard treats "parent missing" the same as "backup missing" | The startup DNS guard (`daemon.rs:11773` → `run_startup_dns_recovery`) runs BEFORE `run_preflight_checks` (call `daemon.rs:11781` → def `:13534`, `create_dir_all(state_path.parent())` at `:13536`), so the guard cannot rely on preflight having created the state dir. Safe today, and must stay safe: reboot case — the durable dir already exists; fresh-install case — a missing dir reads as missing backup (`Ok(None)`) → strand message (correct); apply-time writes are covered by the writer's own `create_dir_all` (`macos_dns_sc_protect.rs:410-412`) plus preflight having run by then. The implementation must keep one of the two guards explicit: parent created before the guard reads, or parent-missing ≡ backup-missing | Unit: a derived-path read with the state dir absent behaves as missing backup (strand path), never as a write-side surprise or a fallback read |

Under Option A the backup's directory is daemon-writable by design, so the old `/var/run`
reasoning ("planting requires root") no longer holds and must not be relied on. The honest
model: the backup's author gains exactly the `networksetup -setdnsservers <svc> <IP-list>` power
the daemon already holds through the helper allowlist (`privileged_helper.rs:2936-2955` admits
the same argv from the daemon at any time), so a planted backup is **not** a privilege
escalation. The residual risk is *stale or foreign content* — a document vouching for the wrong
pre-protection baseline across reboot, snapshot restore, or a second install — which the
no-fallback-read rule and the M1 capture guard (prior entries win only for services whose
current DNS is loopback, `phase10.rs:4624-4648`) answer. Helper-side validation of restored DNS
*values* beyond IP syntax is deliberately not added; it would restrict only the daemon, which
retains unrestricted legitimate use of the same argv.

Invariant 5's trust reasoning is stated here so the refute pass can attack it explicitly rather
than discovering it implicitly: the danger of a fallback is not privilege escalation, it is
*silent restoration of a stale or foreign baseline* — which fails the "signed/verifiable state
before mutation" bar (AGENTS.md §4) even if every directory ACL holds.

## 4) Migration

1. **Path change.** Add `NETWORKSETUP_DNS_BACKUP_SUFFIX` (name TBD in review) and derive
   `networksetup_dns_backup_path(state_path) -> PathBuf` in `macos_dns_sc_protect.rs`,
   mirroring `shutdown_residue::marker_path`. Replace every `NETWORKSETUP_DNS_BACKUP_PATH`
   use site (`:770`, `:816`, `:830`, `:838`, `:847`, `:884`, `:909`, `:869-:913`;
   `phase10.rs:4629`,
   `:4660-4661`) — the two post-restore `remove_networksetup_dns_backup` calls at `:884`/`:909`
   must move with everything else, or a successful startup restore leaves the volatile file
   behind while the durable one is gone (a phantom residue document). The bare-path const is
   deleted, not deprecated (§3 "no runtime fallback"
   — a dangling const invites a fallback read).
2. **Helper allowlist:** no change (§1.5 — the helper never sees the backup document).
3. **Tests-first list (fail-closed first) — the following is copied verbatim from the
   adversarial review §V ("Fail-closed tests the implementation MUST write first") and is the
   authoritative list; the earlier draft items above it are subsumed by it:**

   1. **Truth table preserved (path-agnostic):** `decide_startup_recovery(true, false, false) == FailLoudManualRestoreRequired`, `…(true, false, true) == RestoreFromBackup`, `…(true, true, _) == NoAction`, `…(false, _, _) == NoAction` — the existing `startup_guard_restores_from_readable_backup_only` (`:1243`) must pass unmodified against the derived-path plumbing.
   2. **Present-but-unreadable durable backup is residue, not absence:** corrupt/truncated/foreign-schema document at the derived path → `read_networksetup_dns_backup` hard-`Err` → strand refusal, backup retained (reader semantics `:439-478` unchanged).
   3. **No volatile fallback:** a valid backup planted at the old `/private/var/run` path is ignored by `run_startup_dns_recovery`; recovery decisions consult only the derived path (negative test pinning invariant 5).
   4. **Derivation:** `networksetup_dns_backup_path(state_path)` is a sibling of the state file (`with_file_name`), moves with a `--state-root` override, and has the degenerate-path fallback `marker_path` has (`shutdown_residue.rs:182-192`); every `NETWORKSETUP_DNS_BACKUP_PATH` use site listed in A1 takes the derived value (a compile-time grep gate or a test that the const is gone — the bare const is deleted, not deprecated).
   5. **Restore writes argv the helper admits:** for every backup entry shape (`None` → `Empty`; `Some(list)` → exact list), `startup_restore_argv_for_entry` output passes `validate_networksetup_args` (`privileged_helper.rs:2936`) — pins the backup→helper contract before any path moves.
   6. **Unverified restore retains the backup (A5):** observation-unavailable after restore → backup still on disk + loud warn (this test pins the amended behavior, and fails until A5 is implemented).
   7. **Cleanup compatibility (A4):** the macOS cleanup command list includes the derived backup path (or `assert_node_clean` includes an SC-DNS probe) — a stage-level test on `macos_traffic::cleanup_runtime_state`'s command set.
   8. **Message pins:** `manual_restore_message_names_the_fix_per_service` (`:1267`) updated to the derived path; the `:830` no-socket, `:868` restore-failed, and `:875` retained-backup messages all interpolate the derived path (grep-gate: no remaining `NETWORKSETUP_DNS_BACKUP_PATH` identifier).
   9. **Apply ordering preserved:** a mocked write failure before the first `networksetup` set aborts with the prior backup intact and zero mutation argvs issued (invariant 2, now against the derived path).
4. **Live-lab proof (blocked on new stage work):** `live_reboot_recovery` is Linux-only today
   (`PlatformRule::LinuxOnly` via `DEFAULT_SPEC`, `live_lab_stage_registry.rs:485-506` —
   `platform_rule: PlatformRule::LinuxOnly` at `:495`; `enable: EnableRule::LinuxLiveSuite`,
   `:2049-2052`) and its binary (`live_linux_reboot_recovery_test.rs`) contains no macOS
   DNS-protection code — **there is no macOS reboot cell to include in a stage set**. The
   deliverable therefore includes: (a) a macOS reboot-with-protection-active stage (registry
   entry + implementation that applies protection, reboots `macos-utm-1`, and asserts the daemon
   started, restored from the durable backup, and post-restore observation is clean), or (b) an
   explicit fallback acceptance: the standalone test binary run focused on `macos-utm-1` with
   its transcript archived as the report artifact. Until one exists, this plan cannot reach its
   Definition of Done and no matrix row may claim it. The acceptance outcome itself is: reboot
   `macos-utm-1` under protection → daemon starts → guard observes residue + durable backup →
   automatic restore from backup → post-restore DNS observation clean via the **verified**
   branch (`survivors.is_empty()`, `macos_dns_sc_protect.rs:882-890`). The `:905-917` degrade
   path — observation unavailable → backup retired + `Ok` (warn at `:913`) — is a fail-open
   seam: an unverified restore must **retain** the backup (retiring it converts an unverifiable
   recovery into a guaranteed no-backup strand at next start). The implementation must change
   that path to retain-and-warn, with a test pinning it (tests-first item 6). The failure
   transcript in §1.1 must be unreproducible. Verify the appended
   `live_lab_node_run_matrix.csv` row (`documents/operations/live_lab_node_run_matrix.csv`) and
   take the pass claim from the stage's own report artifact, not the column alone.
5. **cleanup_hosts and uninstall must not strand the bootstrap.** The macOS cleanup's explicit
   rm list (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_traffic.rs:466-483`)
   stops the daemon mid-protection (no teardown), leaves SC loopback residue in place, and does
   not remove the durable backup — so the next run's daemon startup auto-restores (or, on
   service-set drift, refuses to start and fails `bootstrap_hosts`). Add the derived backup path
   to the cleanup rm list (alongside the already-missed
   `rustynetd.state.shutdown-residue.json`), or extend `assert_node_clean` (`:498`) with an
   SC-DNS-clean probe; the same removal belongs in the uninstall path. Record which in this plan
   before implementation.

## 5) Risks and open questions (for the adversarial review)

1. **Does the state root exist before first apply?** The volatile write created its own parent
   (`create_dir_all`, `:410-412`). The durable dir is created by the daemon at startup for the
   state file — confirm the ordering (state-file dir creation precedes any DNS apply) and that
   the writer's `create_dir_all` remains harmless there. **Resolved by the review (§B.4
   "Guard-vs-state-dir ordering"):** the startup guard (`daemon.rs:11773`) runs *before*
   `run_preflight_checks` (call `:11781` → def `:13534`, `create_dir_all` at `:13536`), which is
   safe in the safe direction — folded as §3 invariant 6 (parent must exist before the guard
   reads, or the guard treats parent-missing the same as backup-missing).
2. **Windows branch of the const.** The `else` branch (`/tmp/...`) exists for non-mac/non-linux
   test hosts. Derivation must keep a deterministic test-host answer (state-path sibling on every
   branch) or tests pinning the tmp path break. What is the Windows story — is DNS protection
   even reachable there (it is a different mechanism)? The refute pass should confirm scope.
3. **`--state-root` installs.** The lab may run the daemon with a non-default state root;
   deriving from the daemon's *actual* state path (not the hardcoded `/usr/local/var/...`) is
   required, and the installer's `--state-root` must stay the single source of that value.
4. **Multi-backup collision.** Two applies in one protection session overwrite the backup by
   design (with the M1 capture guard preserving prior entries). On the durable path this now
   *persists* across sessions — is teardown correctly unlinking the durable backup
   (`remove_networksetup_dns_backup`, `:480+`)? A stale backup surviving into a *later*
   protection session is harmless only because of the capture guard — the refute pass should
   attack that claim.
5. **The Linux twin** (`linux_dns_protect.rs:248`, `/run` tmpfs): same defect class, different
   startup-refusal plumbing. In or out of scope for the same change? This plan scopes it out
   (§6) but it should not be forgotten — it is the identical reboot-strand on every Linux
   unattended node.
6. **Snapshot/restore of macOS VMs** (the lab reverts guests): a durable backup could then
   disagree with the actual SC state. Does the capture guard's prior-entry logic fully close
   that, or can a snapshot-reverted SC posture plus a *newer* durable backup restore a wrong
   baseline?
7. **Option C's proof gap** (§2): confirm the refute pass agrees no in-tree primitive today
   binds loopback residue to RustyNet authorship, so C remains unshippable even as a fallback.

## 6) Out of scope

* The **macOS branch** of `RESOLV_CONF_FAILCLOSED_BACKUP_PATH` (`linux_dns_protect.rs:250-251`,
  `/private/var/run/...`) — written best-effort by the same apply (`phase10.rs:4674-4695`, the
  `DnsFailclosedFile` `RESOLV_APPLY` call at `:4691-4692`) and never read by the startup guard;
  macOS regenerates `resolv.conf` from restored SC state, and the durable
  `/etc/resolver/rustynet` artifact (`phase10.rs:4698-4712`, `*.rustynet`-scoped; restored
  best-effort at teardown, `:4779`) persists un-restored across reboot. This plan accepts those
  bounds explicitly and records them; the Linux `/run` branch (`linux_dns_protect.rs:248`)
  remains the follow-up fix, same derivation pattern — so a reader does not conclude the plan
  relocated *all* macOS volatile DNS artifacts when it relocates one of three.
* Option C's authorship-proof primitive (signed residue binding) — future design, strictly
  after this plan.
* Changes to the privileged helper's allowlist or the `DnsFailclosedFile` builtin.
* Any change to `decide_startup_recovery`'s truth table — Option A deliberately preserves it.
* The Windows DNS protection mechanism.

## 7) Review disposition

Adversarial review: `MacosDnsBackupRebootSurvivalPlanAdversarialReview_2026-09-02.md` (§V, READY-WITH-AMENDMENTS). All six amendments folded in place:

- A1: folded — completed the `NETWORKSETUP_DNS_BACKUP_PATH` use-site list with the two post-restore `remove_networksetup_dns_backup` calls (`:884`/`:909`) in §2 (Option A cost), §3 invariant 4, and §4 step 1; without them a successful startup restore leaves the volatile file behind while the durable one is gone.
- A2: folded — §3 invariant 5's threat model restated for the durable path: the backup's directory is daemon-writable by design, a planted backup is not a privilege escalation (the daemon already holds the same `networksetup -setdnsservers` argv power via `privileged_helper.rs:2936-2955`), and the residual risk is stale/foreign content, answered by the no-fallback-read rule and the M1 capture guard (`phase10.rs:4624-4648`).
- A3: folded — §4 step 4 rewritten: `live_reboot_recovery` is Linux-only (`PlatformRule::LinuxOnly` via `DEFAULT_SPEC`; `EnableRule::LinuxLiveSuite`), its binary contains no macOS DNS-protection code, so no macOS reboot cell exists to include; building the macOS reboot-with-protection stage (or naming the focused standalone-proof fallback) is now part of the deliverable, and no matrix row may claim done until it exists.
- A4: folded — new §4 step 5: `cleanup_hosts` (and uninstall) must remove the derived backup path (alongside the already-missed `rustynetd.state.shutdown-residue.json`) or `assert_node_clean` grows an SC-DNS-clean probe; the choice must be recorded in this plan before implementation.
- A5: folded — §4 step 4 acceptance now requires the verified restore branch (`survivors.is_empty()`, `macos_dns_sc_protect.rs:882-890`); the `:905-917` observation-unavailable path (backup retired + `Ok`) is named a fail-open seam and must become retain-and-warn, pinned by tests-first item 6.
- A6: folded — §6 reframed from "Linux twin" to "macOS branch + Linux twin": the macOS branch of `RESOLV_CONF_FAILCLOSED_BACKUP_PATH` (`linux_dns_protect.rs:250-251`) and the durable `/etc/resolver/rustynet` artifact (`phase10.rs:4698-4712`) are recorded with their explicitly accepted bounds; only the Linux `/run` branch remains the follow-up.

The review's guard-vs-state-dir ordering finding (§B.4) is folded as §3 invariant 6 and resolves former §5 open question 1; its fail-closed tests list is folded verbatim as the authoritative §4 step 3 list.

Status: implemented on branch 2026-09-02. §4 step 5 choice recorded per the amendment: the derived backup path (`rustynetd.state.networksetup-dns.failclosed.bak`) and the already-missed QH-40 marker were added to the existing `cleanup_runtime_state` rm batch in `macos_traffic.rs` (literal list, no new shell shape) and to `Bootstrap-RustyNetMacos.sh`'s state-file rm line; `assert_node_clean` was left probe-free. The §4 step 4 live-proof (macOS reboot-with-protection stage) remains open as the plan states — no matrix row claims it.
