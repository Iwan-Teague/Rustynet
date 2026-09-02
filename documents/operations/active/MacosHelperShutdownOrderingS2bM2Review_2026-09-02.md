# Post-Merge Adversarial Review — S2b/M2 Helper-Ordering Changes (2026-09-02)

Target: merge `687d67d5` on main (+ compile fix `d2695632`), implementing **S2b** (helper-liveness restore before macOS daemon restarts) and **M2** (helper booted out only after bounded daemon exit) of
[`MacosHelperShutdownOrderingImplementationPlan_2026-09-02.md`](./MacosHelperShutdownOrderingImplementationPlan_2026-09-02.md) (amended).

Method: refute pass on the merged code. Every anchor below was verified against the merge result on this tree with `git show`/read of the named file at the cited line. Line numbers are current-tree, not pre-merge.

## 1. S2b probe: job-present-but-process-dead is not distinguished — CONFIRMED GAP

`probe_privileged_helper_job` (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs:578-582`) reduces to `run_validated(...).is_ok()` and **discards stdout**. `launchctl print system/com.rustynet.privileged-helper` exits 0 for a *loaded* job whose process has exited (KeepAlive respawn pending, throttled, or crashed-with-retry). In exactly that state:

- the helper process is dead, so the socket it binds (`/private/var/run/rustynet/rustynetd-privileged.sock`, `MACOS_PRIVILEGED_HELPER_SOCKET`, `macos_install.rs:35-36`) may be gone (launchd removes per-job sockets at job exit; here the socket is created by the helper itself, so it is removed/stale when the process dies);
- `drive_restart_with_helper_liveness` (`macos_install.rs:544-559`) takes the `HelperPresent` branch, restores nothing, and issues the daemon stop/start anyway (`:556-557`);
- the restart proceeds into the very failure S2b exists to prevent — the daemon's shutdown rollback dials a dead socket, loses its rollback, and `record_shutdown_rollback_residue` writes the QH-40 marker.

So the merge message's claim "refuses the restart loudly if the helper cannot be restored" holds only for the **job-absent** case. The job-present-process-dead case sails through. This is the same hole shape the plan's Q-1 analysis could not decide from logs ("helper liveness at that instant is undetermined") — S2b as merged leaves it undetermined too.

**Required check (exact form):** when the job probe succeeds, the driver must additionally require, before taking the `HelperPresent` no-op branch:

1. **socket presence**: `sudo -n test -S /private/var/run/rustynet/rustynetd-privileged.sock` (same validated shape as `wait_for_privileged_helper_socket`, `macos_install.rs:628-638`), and/or
2. **a live pid**: capture the print stdout (change `probe_privileged_helper_job` from `is_ok()` to returning the captured output) and require a `pid = ` line — the same predicate `macos_daemon_job_reported_exit` (`crates/rustynet-cli/src/install/uninstall.rs:201-203`) already uses in the opposite direction.

If either fails, the job is *present but dead*: the restore path must first `launchctl bootout system/com.rustynet.privileged-helper || true` (a `launchctl bootstrap` of an already-bootstrapped job fails with "already bootstrapped" — naive re-bootstrap would false-fail), then the existing `restore_privileged_helper` (`macos_install.rs:603-621`) bootstrap + bounded socket wait runs unchanged. Concretely: `probe_helper_job` becomes a tri-state (Absent / PresentAlive / PresentDead) or the driver, on `HelperPresent`, runs the socket probe and demotes to restore on failure.

## 2. Bounded waits vs the 5 s ceilings — sound, with one mis-priced and one conflated wait

- **10 s helper-socket wait** (`wait_for_privileged_helper_socket`, `macos_install.rs:639-646`, 20 × 0.5 s): the wait follows a fresh `launchctl bootstrap` — a start, not a stop; launchd's 5 s SIGTERM→SIGKILL ceiling does not apply. 10 s is generous and expiry is a loud refusal. Correct.
- **10 s daemon-exit wait** in the product paths (`wait_for_macos_daemon_exit`, `uninstall.rs:180-197`; installer stop regions `Install-RustyNetMacosService.sh:612-617` and `Bootstrap-RustyNetMacos.sh:764-770`): ≥ launchd's measured 5 s kill ceiling plus the daemon's rollback dial time, and the daemon's own exit budget (`MACOS_LAUNCHD_EXIT_TIMEOUT_MS = 5_000`, `crates/rustynetd/src/privileged_helper.rs:102`, enforced as an upper bound on client timeouts at `:153-156`) is a *helper-side* budget that does not extend the daemon's shutdown. 10 s covers both. Expiry falls through to the helper bootout (documented, `uninstall.rs:177-179`) — but by expiry launchd's own SIGKILL (≈5 s post-SIGTERM) has already fired *while the helper was still up*, so the residual race is bounded to a process that survives SIGKILL (D-state). Acceptable; correctly documented rather than papered over.
- **Mis-priced and conflated: the `MACOS_LAUNCHD_STOP_COMMAND` poll** (`macos_traffic.rs:71-77` and the post-KILL poll `:84-89`). Two defects, one root:
  1. **Process-name conflation.** The privileged helper is `/usr/local/bin/rustynetd …privileged-helper` (the command's own `-f` pattern at `:79`/`:82` says so), so `pgrep -x rustynetd` matches **the helper too**. While the helper lives — which it does until its bootout at `:78`, i.e. after the poll — the poll can never see "all clear" and always spins its full 60 × 0.5 s = **30 s**. The doc comment's claim (`:49-51`) that the poll "observes the daemon PROCESS exiting, which is the stronger form" is false whenever the helper is up. Functionally the wait degenerates to a bounded sleep — better than the old bare sleep, but not the predicate M2 specified.
  2. **Collateral TERM to the helper.** `pkill -TERM -x rustynetd` (`:69`) TERMs the helper process as well. KeepAlive respawns it (job still bootstrapped until `:78` — the exact reasoning the comment at `:47-49` gives for the helper `-f` pkill), but the respawn gap lands precisely inside the window where the dying daemon's rollback dials the socket — a second, self-inflicted instance of the incident being fixed.
  **Fix:** make the poll job-scoped, matching the installer/uninstaller form: loop `launchctl print system/com.rustynet.daemon 2>/dev/null | grep -q 'pid = '` (absence ⇒ exit), and keep the pgrep/pkill backstops but accept (or filter) the helper collision explicitly in the comment. 60 iterations can drop to 20 (10 s) once the predicate is job-scoped, aligning with the other M2 sites.

## 3. M2 stop chain: the KILL fallback is inverted — CONFIRMED

In `MACOS_LAUNCHD_STOP_COMMAND` the order after the wait is:

- `:78` helper bootout, `:79` helper TERM fallback, `:80` anchor bootout, **then** `:81` `pkill -KILL -x rustynetd`, `:82` helper KILL, `:83` relay KILL.

So yes: a daemon wedged hard enough to ignore SIGTERM (both the bootout's SIGTERM at `:60-61` and the TERM pkill at `:69`) — and, per §2(1), one that also kept the 30 s poll spinning — is **SIGKILLed at `:81` after the helper was booted out at `:78`**. That is exactly the residue this fix targets: rollback lost, helper socket gone, QH-40 marker written. The same inversion applies to a wedged anchor (booted out at `:80`, KILLed at `:81`).

Mitigation, stated honestly: launchd's own bootout SIGKILL (≈5 s post-SIGTERM) usually kills even a TERM-ignoring daemon *before* `:78`, so the inverted window requires a process that survived launchd's SIGKILL. But the whole point of the explicit KILL backstop is the case launchd's kill missed, and in that case it fires on the wrong side of the helper stop.

**Correct order for the KILL fallback:** kill the wedged *workload* processes **before** removing the helper:

```
… daemon-exit wait …
sudo -n pkill -KILL -x rustynetd          (moved up — before the helper bootout)
sudo -n pkill -KILL -x rustynet-relay     (moved up)
sudo -n launchctl bootout system/com.rustynet.anchor …
sudo -n launchctl bootout system/com.rustynet.privileged-helper   (unchanged position)
sudo -n pkill -TERM -f '…privileged-helper' …                     (unchanged: after bootout)
sudo -n pkill -KILL -f '…privileged-helper' …                     (last — helper dies last)
```

Rationale: the helper must be the **last** RustyNet process to die, full stop — TERM, KILL, bootout, everything else ordered before it. The only exception is the helper's own TERM-after-bootout (KeepAlive would respawn a TERMed helper whose job is bootstrapped), which already sits correctly.

## 4. Product-path changes (uninstaller/installer): no security-posture change; `pid = ` edge noted

- `uninstall_macos` (`uninstall.rs:81-89`) and both installer stop regions (`Install-RustyNetMacosService.sh:605-618`, `Bootstrap-RustyNetMacos.sh:757-771`) change **ordering predicates only**: same bootout commands, same root/launchctl privileges, no new exec surface, no secret handling, `bootout`-then-wait order preserved (daemon first, helper second). `wait_for_macos_daemon_exit` polls locally via `launchctl print`; `command()` argv usage is unchanged. **No security posture change.** The product paths are also where the lease (design §3) does not reach, so the bounded poll is the entire protection there — which is why the expiry fall-through must stay loud in logs (see tests, §8).
- **The bare-`sleep 1` removal and the `pid = ` predicate.** `launchctl print` for a loaded, *running* job prints a `pid = <n>` line in the job's state block; a loaded-but-*not-running* job prints no `pid = ` line. Hence `macos_daemon_job_reported_exit` (`uninstall.rs:201-203`: `!print_ok || !print_stdout.contains("pid = ")`) and the scripts' `grep -q 'pid = '` are correct for both terminal states. The residual edge: if a future macOS printed a running job **without** `pid = ` (format drift), the poll would conclude "exited" early and proceed to the helper bootout while the daemon still runs — i.e. it fails open to exactly the pre-fix `sleep 1` behaviour, bounded, not worse. The scripts' `for` loops likewise. This is an accepted, documented degradation, not a regression; no change required, but the predicate should be covered by a test pinning the `pid = `-present ⇒ wait behaviour (exists: `macos_daemon_job_reported_exit_matrix`, `uninstall.rs:223-233`).

## 5. Scanner tightening: raw interpolation can hide behind `.as_str()` — CONFIRMED, must close before Step 4d

`count_raw_sink_call_sites` (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/validated_args.rs:619-647`) excludes a `run_remote*(` call when **any** line in the 4-line window (`:635-638`) merely *contains* `.as_str()`. Two hide paths:

1. **Direct:** `ssh::run_remote(conn, format!("sudo {x}").as_str(), t)` — the argument is an unvalidated, interpolated `String` seam-lowered by hand, yet the window contains `.as_str()`, so the site is excluded from the very count that exists to catch raw interpolation at the sink. The QH-01 pin (`raw_sink_call_site_count_must_only_go_down`, `:663-676`, baseline 140 at `:524`) then reads green while the injection surface grew.
2. **Adjacent:** a raw call on line *i* plus an unrelated legitimate `.as_str()` on lines *i+1..i+3* (rustfmt wrapping) also suppresses the count — rarer, but the same substring test causes it.

**Precise refinement:** exclude only when a window line is a *plain-binding* seam lower — anchored, no constructor, no `format!`:

```rust
let seam_lowered = lines[i..window_end].iter().any(|candidate| {
    let t = candidate.trim_start();
    let t = t.strip_suffix(',').unwrap_or(t).trim_end();
    // bare `<binding>.as_str()` only: receiver is a plain identifier,
    // so `format!(...).as_str()` / `x.to_string().as_str()` still count.
    t.ends_with(".as_str()")
        && t[..t.len() - ".as_str()".len()]
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
});
```

(A regex equivalent: `^\s*[a-z_][a-z0-9_]*\.as_str\(\),?\s*$`.) `format!(…).as_str()` starts with `format!(` and fails the all-identifier receiver test, so it counts as raw. For full precision the receiver could additionally be required to be a `RemoteCommand`/`PowerShellScript` binding, but that needs scope analysis a line scanner should not grow; the anchored plain-binding form is the right cost/precision point, and the existing per-site construction tests (`RemoteCommand::from_args` only via `ValidatedArg`) carry the rest.

**Must it land before Step 4d? Yes.** Per `Qh01TemplateInjectionEliminationPlan_2026-09-02.md` §10 (lines ~138-144), Step 4d is where the raw sink-call count *moves* (sink-signature flip) and where the remaining shell-shaped `format!` sites are dispositioned. An under-counting pin at 4d silently blesses hidden raw sites as "already migrated"; the baseline ratchet from 158 → 140 was computed *with* the loose exclusion, so tightening may raise the measured count above 140 — in that case the baseline must be re-measured and re-ratcheted **upward once, with the diff named**, not silently (the pin's MUST-ONLY-GO-DOWN contract stays intact for raw sites).

## 6. Live proof: what must be inspected on the rank-1 macOS-client run

The intended proof is a `--node`-engine live-lab run with `macos-utm-1` as the macOS client at commit ≥ `d2695632`. To **confirm** (not assume) S2b fired and no residue was written:

1. **S2b execution line.** The stage log of the stage that drives the daemon restart — `enforce_baseline_runtime` is the `restart_daemon` call site (plan Q-1; the path is `restart_daemon`, `macos_install.rs:668-677`, via `adapter/macos.rs:148`). Its log must contain the `eprintln!` at `macos_install.rs:675`: `[macos daemon restart] privileged helper liveness:` followed by either `job present (probe-gated no-op)` (`:526-528`) or `job absent; re-bootstrapped from /Library/LaunchDaemons/com.rustynet.privileged-helper.plist and socket appeared after N poll(s)` (`:529-533`). A run whose log lacks this line has **not** exercised S2b. (If the §1 fix lands first, the log should additionally distinguish the present-but-dead demotion.)
2. **No refusal fired:** the same log must not contain `did not appear within` (the `wait_for_privileged_helper_socket` expiry text, `macos_install.rs:647-654`). Presence = the loud-refusal negative path triggered; that is a valid *negative*-path proof but not a clean pass.
3. **No residue:** grep the run's report dir for `shutdown_rollback_residue_detected` (`crates/rustynetd/src/shutdown_residue.rs:72`) — zero hits — and assert the QH-40 marker file (`<state>.shutdown-residue.json`, suffix at `shutdown_residue.rs:59`) is absent on the guest.
4. **M2's traffic-adapter site:** `traffic_test_matrix` must have **run, not skipped** — it was skipped in the incident run, which is why `MACOS_LAUNCHD_STOP_COMMAND` was never exercised there. Its stage output must show the stop completing and no residue marker afterwards.
5. **Ledger:** the appended row in `documents/operations/live_lab_node_run_matrix.csv` must name this commit, a clean tree, and `macos-utm-1` — and per AGENTS.md §12.3 the pass/fail claim comes from the stage's own report artifact, not the column alone.

A single clean pass proves the happy path only; the plan's §5 N ≥ 20-trial chained-bootout requirement stays the deterministic proof for M2.

## Verdict: ACCEPT-WITH-FIXES

The merge strictly narrows every race it touches and the M2 product paths are sound; it does not regress. But S2b's core claim ("refuses the restart if the helper cannot be restored") is false for job-present-process-dead (§1), and the stop chain retains a KILL-after-helper-gone inversion plus an ineffective, conflated wait predicate (§2, §3). Fixes 1-3 are required before S2b/M2 are claimed done in the parity/plan ledgers; 4-5 before Step 4d.

### Fixes

1. **S2b tri-state probe** — `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs:578-582`: capture the print stdout; treat "print ok AND `pid = ` present AND `sudo -n test -S /private/var/run/rustynet/rustynetd-privileged.sock` ok" as `HelperPresent`; anything else enters the restore path, which for a still-bootstrapped dead job must `launchctl bootout system/com.rustynet.privileged-helper || true` **before** the `bootstrap` at `macos_install.rs:608-619` (bootstrap of an already-bootstrapped job errors).
2. **KILL order** — `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_traffic.rs:78-83`: move `sudo -n pkill -KILL -x rustynetd` (`:81`) and `sudo -n pkill -KILL -x rustynet-relay` (`:83`) **above** the helper bootout (`:78`), leaving the helper's own bootout/TERM/KILL (`:78`, `:79`, `:82`) as the final three RustyNet stops. Update the pin tests (`macos_traffic.rs:~915-970`) to assert the KILL lines precede the helper bootout, not merely their presence.
3. **Job-scoped wait predicate** — `macos_traffic.rs:71-77` (and `:84-89`): replace `pgrep -x rustynetd || pgrep -x rustynet-relay` with `launchctl print system/com.rustynet.daemon 2>/dev/null | grep -q 'pid = '` (relay: its own label), 20 × 0.5 s; or, if pgrep is kept for orphan coverage, document the helper-name conflation and its 30 s worst case at `:49-51` and fix the comment's false "stronger form" claim.
4. **Scanner anchor** — `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/validated_args.rs:635-638`: replace the `.contains(".as_str()")` window test with the anchored plain-binding receiver test (§5), plus re-measure `BASELINE_RAW_SINK_CALL_SITES` (`:524`) if the tightened count exceeds 140, naming the delta in the commit message.
5. **Comment truthing** — `macos_traffic.rs:49-51`: correct the wait-predicate claim once fix 3 lands (or immediately if 3 is deferred).

### Tests that MUST be added

1. `macos_install.rs` driver tests (`drive_restart_with_helper_liveness`, existing blocks at `:2940`, `:2974`, `:3011`): **present-but-dead** — job probe succeeds, socket probe fails ⇒ restore closure invoked (and, after fix 1, bootout-before-bootstrap asserted); present-alive ⇒ no restore call; absent ⇒ restore call. The currently-dropped-then-restored 4c test block (`d2695632`) must stay intact.
2. `macos_install.rs`: re-bootstrap of an already-bootstrapped job — restore path issues bootout first (closure-order assertion).
3. `validated_args.rs`: `count_raw_sink_call_sites` counts `run_remote(conn, format!("x {y}").as_str(), t)` as **raw** (currently it would be excluded); still excludes a bare `command.as_str(),` line. One rejection + one acceptance, matching the per-class pattern.
4. `macos_traffic.rs` pin tests: index of `pkill -KILL -x rustynetd` < index of `launchctl bootout system/com.rustynet.privileged-helper` (absence-of-inversion, per plan A8's "assert the absence, not merely the order of present commands" standard); poll predicate is `launchctl print`-shaped after fix 3.
5. `uninstall.rs`: expiry fall-through is already best-effort by design — pin the 10 s bound symbolically (20 × 500 ms constant) so it cannot silently shrink below the 5 s launchd ceiling.

## Anchors verified

| Anchor | Command |
| --- | --- |
| Merge stat + message | `git show 687d67d5 --stat` |
| Compile fix | `git show d2695632 --stat` |
| `drive_restart_with_helper_liveness` `:544-559`, `probe_privileged_helper_job` `:578-582`, `restore_privileged_helper` `:603-621`, `wait_for_privileged_helper_socket` `:628-655`, `restart_daemon` `:668-677`, consts `:30-36`, `SHORT_TIMEOUT` `:77`, driver tests `:2940/:2974/:3011` | read `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs` (offsets 30, 520-709) + `grep -n` |
| `MACOS_LAUNCHD_STOP_COMMAND` `:60-89`, ordering doc `:40-59`, stop call `:465`, pin tests `:915-970` | read `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_traffic.rs` (offset 15) + `grep -n` |
| `restart_daemon` adapter call site | `grep -rn restart_daemon crates/rustynet-cli/src/vm_lab/orchestrator` → `adapter/macos.rs:148` |
| `wait_for_macos_daemon_exit` `:180-197`, `macos_daemon_job_reported_exit` `:201-203`, order test `:210-220`, matrix test `:223-233` | read `crates/rustynet-cli/src/install/uninstall.rs` (offset 70) |
| Installer stop region `:605-622`, socket wait `:628-630` | read `scripts/bootstrap/macos/Install-RustyNetMacosService.sh` (offset 603) |
| `clear_residual_state` `:751-777` | read + `grep -n` `scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh` |
| Scanner `:511-524`, `:619-647`, pin `:663-676` | read `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/validated_args.rs` (offsets 505, 634) |
| `MACOS_LAUNCHD_EXIT_TIMEOUT_MS = 5_000` + client-timeout guard | `grep -rn MACOS_LAUNCHD_EXIT_TIMEOUT_MS crates/rustynetd/src/` → `privileged_helper.rs:102,153-156` |
| QH-40 token + marker suffix | `grep -n … crates/rustynetd/src/shutdown_residue.rs` → `:59,:72` |
| Step 4d disposition + pin-ratchet context | `grep -n "4d" documents/operations/active/Qh01TemplateInjectionEliminationPlan_2026-09-02.md` → `:138-144,180` |
| Plan S2b/M2/Q-1 text and status rows | `grep -n "S2b\|M2\|Q-1\|status tracker"` on `MacosHelperShutdownOrderingImplementationPlan_2026-09-02.md` → `:115,:121,:190,:200,:215,:218` |
