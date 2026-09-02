# macOS DNS Backup Durable-Path Implementation Review (2026-09-02)

**Status:** post-merge adversarial review of merge commit `2e120bbd` on `main` ("persist the
macOS DNS fail-closed backup beside the daemon state file"). Verdict: **ACCEPT** — no
security defect found; the implementation is faithful to the amended plan
(`MacosDnsBackupRebootSurvivalPlan_2026-09-02.md`, with all six review amendments folded) and
the one deliberately open item (the macOS reboot-with-protection live proof, plan §4 step 4)
remains honestly open and is restated in §8 below with the exact procedure a proof must run.

## 1) Method

Every claim below was verified against the merged code itself, not against the plan's
descriptions: `git show 2e120bbd:<path>`, `git grep <pattern> 2e120bbd`, and
`git diff 3f812a49 2e120bbd` (the merge's first parent) were used to read the post-merge
sources and pin each anchor. Line numbers in this document are post-merge line numbers in the
files as of `2e120bbd`. The review was performed in the isolated worktree
`state/edit-worktrees/edit-1788330687945-80280-0` (branch `ai-edit/edit-1788330687945-80280-0`).

## 2) Attack dimension 1 — ownership and permissions of the durable backup

The concern: the daemon runs as the unprivileged `rustynetd` service user
(`Install-RustyNetMacosService.sh` plist `UserName`/`GroupName`), while the installer's
`STATE_ROOT` is created by root during installation. If the durable state root were root-owned
and daemon-unwritable, `write_networksetup_dns_backup` would fail on every real node and the
apply would abort — a functional, not security, failure, but one that would make the feature
dead-on-arrival.

Findings:

* The writer creates the parent directory itself and sets the mode explicitly:
  `write_networksetup_dns_backup` (`crates/rustynetd/src/macos_dns_sc_protect.rs:431`) runs
  `create_dir_all(parent)` on the derived path's parent (`:437`, error string
  "backup dir create failed") and `set_permissions(path, 0o600)` after the write (`:452`).
  This satisfies plan invariant 3 (0600 mode) and keeps the plan's own threat model: the
  document reveals which resolvers the host used, so it is readable only by the daemon.
* The bootstrap script does **not** `mkdir`/`chown` the state root
  (`scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh` contains no such lines), so the
  durable root is created by the daemon's own preflight running as the daemon user — the
  backup's write fate is exactly the state file's write fate. This is write-parity by
  construction, which is the right answer: if the daemon cannot write beside its state file,
  it cannot write the state file either, and the node is broken at a much earlier and louder
  point.
* The launchd path is unaffected: the installer resolves the daemon's uid/gid via `dscl`
  (`Install-RustyNetMacosService.sh:547-548`) and the helper plist recreates only the
  `/private/var/run/rustynet` runtime dir per boot (`:536`), which no longer participates in
  the backup path at all.

Conclusion: no real-node write failure is introduced; the backup inherits the state file's
ownership model exactly as the plan's §1.6 reasoning requires.

## 3) Attack dimension 2 — one-path agreement across apply, rollback, guard, and restore

The concern: if any production construction site of `MacosCommandSystem` kept a
default-derived path while the daemon actually runs with `--state`, apply and recovery would
consult two different documents and the guarantee collapses.

Findings:

* The derivation itself is the QH-40 pattern: `NETWORKSETUP_DNS_BACKUP_SUFFIX`
  (`.networksetup-dns.failclosed.bak`, `macos_dns_sc_protect.rs:310`) and
  `networksetup_dns_backup_path(state_path)` (`:324`), which is a sibling of the state file
  via `with_file_name` (`:327`) with the same degenerate-path fallback `marker_path` has
  (`:329`). The doc comments at `:300`/`:313` cite `shutdown_residue::marker_path` explicitly.
* `NETWORKSETUP_DNS_BACKUP_PATH` (the old bare-path constant) has **zero remaining
  identifiers repo-wide** at `2e120bbd` — verified by `git grep NETWORKSETUP_DNS_BACKUP_PATH
  2e120bbd` returning nothing. The constant was deleted, not deprecated, per plan §4 step 1.
* The single production construction site is `daemon.rs:11588`, chained with
  `.with_dns_backup_path(networksetup_dns_backup_path(config.state_path))` at `:11603` — so
  the path always follows the daemon's *actual* state path, including `--state` overrides
  (plan §5.3). The remaining default constructor (`phase10.rs:3612`) uses
  `daemon::default_state_path()` (`daemon.rs:177-193`: macOS `/usr/local/var/rustynet/
  rustynetd.state`, Linux and Windows branches at `:179`/`:181`) and is test-only;
  `with_dns_backup_path` (setter, `phase10.rs:3627`) and the `dns_backup_path` field
  (`:3568`) route everything through one field.
* All consumers read that one field: rollback `restore_networksetup_dns_from_backup`
  (`phase10.rs:4278`), the apply's prior-backup read and pre-mutation write (`:4653`,
  `:4678-4685` — written before the first `networksetup` mutation with abort-on-error `?`,
  plan invariant 2), and the startup guard `run_startup_dns_recovery`
  (`macos_dns_sc_protect.rs:833`), which derives `backup_path` from its `state_path`
  parameter (`:838`).

Conclusion: one derivation function, one field, one path at every consumption point. The
phantom-residue hazard the plan flagged for the old `:884`/`:909` removal calls is closed by
construction because removal, read, and write all take the same derived path.

## 4) Attack dimension 3 — the guard runs before preflight creates the state dir

Plan invariant 6 requires either "parent exists before the guard reads" or "parent-missing
reads as backup-missing", because the startup DNS guard precedes
`run_preflight_checks`' `create_dir_all(state_path.parent())`.

Findings (post-merge `daemon.rs`; lines shifted ~+9 from the plan's citations):

* `run_daemon`'s macOS block calls the guard at `daemon.rs:11787`, and
  `run_preflight_checks` is called afterward at `:11796`.
* `run_preflight_checks` is defined at `:13543` with its `create_dir_all(state_path.parent())`
  at `:13545`.
* The reader's contract makes parent-missing ≡ backup-missing:
  `read_networksetup_dns_backup` (`macos_dns_sc_protect.rs:463`) returns `Ok(None)` for a
  missing file, and the guard's decision table (`decide_startup_recovery`, `:538-549`)
  turns residue + unreadable into the loud `FailLoudManualRestoreRequired` refusal rather
  than any write attempt. No early `create_dir_all` exists on the guard path, so the guard
  cannot change a root-owned directory's ownership by creating it early.

Conclusion: invariant 6 holds in code, in the fail-closed direction.

## 5) Attack dimension 4 — A5 semantics: retain-and-refuse is not a self-DoS

The plan's amendment A5 (§4 step 4, tests-first item 6) required the observation-unavailable
path to **retain** the backup and refuse startup, retiring the old "backup retired + `Ok`"
behavior, which the plan named a fail-open seam (retiring the only recovery document converts
an unverifiable recovery into a guaranteed no-backup strand at the next start).

Findings:

* `verify_and_retire_backup` (`macos_dns_sc_protect.rs:951-1000`) implements exactly three
  arms: observed-and-clean (`survivors.is_empty()`, `:976-977`) → retire the backup with an
  info log; observed-with-survivors → `Err`, backup retained, manual
  `sudo networksetup -setdnsservers … Empty` fix named (`:987`, surfaced at `:930` in the
  restore-failed message with "backup retained at {}"); observation-unavailable → backup
  retained **and startup refused**. The doc comment (`:965`) states the recovery property
  this preserves: a retained backup means the next start re-runs the guard and re-restores.
* The old fail-open seam is gone: the post-merge code contains no arm that retires the backup
  on an unverified observation, and the doc explicitly records the former retire-`Ok` shape as
  the rejected behavior. Tests pin it: `unverified_restore_retains_backup_and_refuses_startup`
  (`:1569`, which reads the retained backup back at `:1597`) and the survivors fail-loud test
  (`:1621`).
* The pre-existing test `observation_unavailable_degrades_without_stranding` (`:1897`) is not
  in conflict: it covers the *residue-evidence* semantics (a scutil-clean host with the helper
  unavailable ⇒ no refusal; scutil-loopback residue still refuses; the
  "per-service DNS observation unavailable" warning strings) — it never touches backup
  retirement.
* Self-DoS analysis (the strictest-secure-default question): can this refusal loop forever if
  the helper is unobservable? No unrecoverable loop exists. If the helper is unavailable
  because the daemon cannot reach it, the restore itself also cannot have run, SC DNS is
  unchanged, and the retained backup is exactly the document the operator (or a fixed helper)
  needs; once the helper answers, the guard re-runs and either restores-then-retires (clean)
  or refuses with the manual fix named. The retained backup never *causes* the refusal — the
  refusal is caused by unverifiable host state, and the alternative (retire on
  unverified) was the verified defect. This is the correct fail-closed trade: a bounded
  operator-visible refusal beats an unbounded silent loss of the only baseline record.

## 6) Attack dimension 5 — bootstrap's `clear_residual_state` removes the backup

The QH-40 marker contract is "never cleared automatically — only by explicit operator
acknowledgement". The merge adds the derived backup file to the bootstrap's residual-state
clear (`scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh`, `clear_residual_state`, `:796-805`)
and to the lab cleanup batch (`macos_traffic.rs`, below).

Assessment: this is acceptable and consistent with the contract. Running the bootstrap script
is itself an explicit operator act, and the same script already deletes the entire state
directory — the state file, the trust/membership/keys documents, and the QH-40 marker. A
re-bootstrap therefore already destroys every durable record the daemon owns; excluding the
backup from that deletion would not protect anything (SC state, not the backup, is what
survives) and would leave the next install starting with a stale pre-protection baseline from
a previous identity. The deletion is honest: it is the same act as deleting the state file,
performed by the same operator invocation. It must not, however, be described as an
"automatic cleanup" — it is operator-acknowledged destruction of state, and this review
records it as such.

The lab cleanup batch (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_traffic.rs`)
adds both durable siblings to the existing rm list (`:488-496` rationale comment, `:512-516`
the `rustynetd.state.shutdown-residue.json` and `rustynetd.state.networksetup-dns.failclosed.bak`
entries, single-quoted literal list, no new shell shape), with a source-pin test
`cleanup_rm_batch_includes_durable_state_sibling_markers` (`:823-856`, `include_str!`-based).
This closes plan §4 step 5 (A4) with the recorded choice: rm-list extension,
`assert_node_clean` left probe-free.

## 7) Attack dimension 6 — the Windows/Linux arms and scope discipline

* `linux_dns_protect.rs` is untouched by the merge: its `RESOLV_CONF_FAILCLOSED_BACKUP_PATH`
  constants keep their `/run` (Linux), `/private/var/run` (macOS branch), and `/tmp` shapes.
  The Linux twin reboot-strand therefore remains open exactly as the plan scopes it (§6) —
  recorded follow-up, not a defect of this merge.
* The derivation function is platform-agnostic (it is a pure `Path` computation), and the new
  tests pin non-macOS paths explicitly (`:1423`, `:1432` in the derivation-test block
  `:1354-1434`), so the Windows test-host answer stays deterministic per plan §5.2.
* The macOS-only guard remains behind its `cfg(target_os = "macos")` arm in `daemon.rs`; the
  non-macOS arms still compile and refuse, and the merge did not touch them.
* The privileged helper gained **no new operation** — the only change in
  `privileged_helper.rs` is the contract test `restore_argv_contract_with_helper_validator`
  (`:6115-6141`), pinning `startup_restore_argv_for_entry` output (`None` → `Empty`,
  `Some(list)` → exact list) against `validate_networksetup_args`. This is plan
  tests-first item 5, satisfied.

## 8) Attack dimension 7 — the live proof is still OPEN (and what a proof must run)

The merge does not claim the live proof, and correctly so:
`live_reboot_recovery` is still Linux-only (`live_lab_stage_registry.rs` — `DEFAULT_SPEC`
sets `platform_rule: PlatformRule::LinuxOnly` at `:495`, and the `live_reboot_recovery`
spec at `:2048-2053` inherits it with `EnableRule::LinuxLiveSuite`), so there is no macOS
reboot cell to include in a stage set, and no matrix row may claim the plan done. This is the
plan's own declared open item (§4 step 4 / amendment A3), not a merge defect — but it is the
release-blocking remainder of this plan, and the required proof is:

1. On `macos-utm-1`, apply DNS protection (phase 10 apply) and verify the durable backup
   exists at `<state-root>/rustynetd.state.networksetup-dns.failclosed.bak` with mode 0600.
2. Reboot the guest.
3. Verify the daemon starts, the startup guard observes loopback residue plus the readable
   durable backup, and the automatic restore runs.
4. Verify the restore through the **verified** branch: post-restore observation clean,
   `survivors.is_empty()`, and the backup retired by that clean verification
   (`macos_dns_sc_protect.rs:976-984`) — the §5 retain-and-refuse arm must not fire.
5. Record the run in `documents/operations/live_lab_node_run_matrix.csv` and take the pass
   claim from the stage's own report artifact (its `status` plus data block), never from the
   CSV column alone. Until a macOS reboot stage exists, the plan's recorded fallback
   acceptance is a focused standalone run with its transcript archived as the report artifact.

## 9) Verdict and notes

**Verdict: ACCEPT.** All six amended-plan invariants are enforced in code at the points the
plan names, the test pins the plan listed are present (truth table `:1451`/`:1488`;
unreadable-retained `:1503`; no-volatile-fallback `:1535-1559`; 0600 `:1685`; argv→validator
`macos_dns_sc_protect.rs:1709` and `privileged_helper.rs:6115-6141`; message pin asserting
the derived filename `:1361`; derivation/degenerate `:1354-1434`; A5 retain-and-refuse
`:1569-1597`), and no remaining reader of the volatile path, no fallback read, and no
remaining `NETWORKSETUP_DNS_BACKUP_PATH` identifier exists anywhere in the tree.

Numbered notes (no MUST-fixes; the first two are SHOULD):

1. **SHOULD — source-pin test brittleness.** `cleanup_rm_batch_includes_durable_state_sibling_markers`
   (`macos_traffic.rs:823-856`) asserts by slicing the whole file text via `include_str!`;
   an innocuous edit above the rm list shifts the slice and fails the test with no semantic
   cause. Prefer anchoring on the literal line(s) under test, not whole-file offsets.
2. **SHOULD — document the bootstrap clear as operator acknowledgement.** The bootstrap's
   `clear_residual_state` now deletes the durable backup. This is correct (§6) but should be
   commented in the script as an explicit operator-acknowledged destruction of the recovery
   document, so a future reader does not mistake it for an automatic cleanup path.
3. **MUST (before any "plan done" claim) — the live proof of §8.** No matrix row may claim
   the macOS reboot-survival proven until the §8 procedure passes on `macos-utm-1` and the
   run's report artifact shows it. The merge correctly does not make that claim.
4. **Reminder — the Linux twin.** `RESOLV_CONF_FAILCLOSED_BACKUP_PATH` on Linux still lives
   on boot-cleared `/run` tmpfs; the same defect class this merge fixed for macOS persists
   for unattended Linux nodes. Same derivation pattern applies when that follow-up lands.
