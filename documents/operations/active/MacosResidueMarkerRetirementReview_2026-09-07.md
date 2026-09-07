# QH-40 Residue-Marker Retirement After Reboot — Adversarial Review

Branch: `ai-edit/edit-1788779072494-38689-0`, commit `6f332a6d` ("Retire the QH-40 residue marker after a proven reboot and fix the reboot cell's recovery-line probe").
Scope reviewed: `git diff merge-staging..HEAD -- crates/` (3 files: `crates/rustynetd/src/shutdown_residue.rs`, `crates/rustynetd/src/daemon.rs`, `crates/rustynet-cli/src/vm_lab/mod.rs`). No files outside the intended area were touched.

## What the change does (one paragraph, factual)

`shutdown_residue.rs` adds `decide_marker_retirement` (pure: present marker + known boot time strictly later than `recorded_unix` + `guard_ok`), `boot_time_unix()` (`/usr/sbin/sysctl -n kern.boottime`, macOS only; `None` elsewhere), `parse_sysctl_boottime` (extracts the `sec` field), and `retire_marker_after_reboot` (deletes via the pre-existing `acknowledge_marker`, logs `shutdown_rollback_residue_retired_after_reboot` with the original rollback error). `daemon.rs` calls this at startup, inside the macOS `#[cfg]` block, immediately after the M1 startup DNS guard's `?`. `vm_lab/mod.rs` changes the reboot cell's post-reboot probe from an unprivileged zsh glob (`grep ... /usr/local/var/log/rustynet/*.log`) to `sudo -n find ... -exec grep -hF -e <M1 line> -e <retired token> {} +`, and adds a source-grep test pinning both forms.

## Findings

### F1 — A same-boot clock step can forge a "reboot" and auto-erase a live marker — should-fix

`shutdown_residue.rs::decide_marker_retirement` retires when `boot > marker.recorded_unix` using `kern.boottime` read *now*. On XNU, `kern.boottime` is adjusted when the wall clock is stepped (uptime = now − boottime is kept consistent across `settimeofday`), so a large backward NTP/RTC-correction step *within the same boot* moves `boottime` backward past an already-written marker.

Failure scenario: host boots at wall 2026-09-08 10:00 (RTC one day fast; real 09-07 10:00) → marker recorded at wall 10:05 → NTP steps the clock −24 h → daemon restarts (no reboot). `boot` now reads 2026-09-07 10:00 < `recorded_unix` (2026-09-08 10:05) → decision `RetireRebooted` → `acknowledge_marker` deletes the only durable evidence of *live, uncleaned* residue, logging a false "host booted after the failed rollback". This is precisely the evidence-erasure class QH-40 exists to prevent, reached without any reboot.

Mitigating: needs a backward step larger than boot age, and `guard_ok` still requires the DNS guard to have completed. But the retirement decision then rests on a value (`kern.boottime`) that is not a monotonic reboot witness.

Fix (one line): persist `boot_time_unix()` inside the marker at record time and retire only when `current_boot > stored_boot && current_boot > recorded` (a genuine reboot yields a later boottime; a same-boot step yields an earlier one → Keep, fail-safe).

### F2 — `guard_ok` is hardcoded `true`; correctness hangs on block placement — should-fix

`daemon.rs:11949`: `let decision = crate::shutdown_residue::decide_marker_retirement(&scan, boot, true);`

The `true` is only sound because this block sits after `run_startup_dns_recovery(...)?` inside the same `#[cfg(target_os = "macos")]` scope — any guard failure propagates and never reaches retirement. Nothing structurally enforces that coupling: the pure function advertises a `guard_ok` input that the only production caller fakes. If the block is ever moved, or the guard's error path is softened (e.g. to a logged warning), retirement silently proceeds with `guard_ok == true` while the DNS-pin residue class the comment claims was "just handled" was not.

Fix (one line): have `run_startup_dns_recovery` return a completion flag (or bind `let guard_ok = /* actual outcome */;`) and pass it, so the dependency is data, not source layout.

### F3 — Retirement deletes the only durable evidence based on an assumption set — nit

`retire_marker_after_reboot` → `acknowledge_marker` unlinks the marker. If the assumption "no residue class survives reboot except DNS pins, and the guard handled DNS" is wrong for some class (e.g. a stray launchd plist, a saved-state file, a pf anchor reloaded from a persisted anchor file at boot), the evidence is unrecoverable. The `log::warn!` names the original error, but log files rotate.

Fix (one line): archive instead of unlink — rename the marker to `<path>.retired-<boot>` so a wrong assumption is reversible.

### F4 — `sysctl` invocation has no timeout — nit

`boot_time_unix()` (`shutdown_residue.rs`, macOS cfg) does `Command::new("/usr/sbin/sysctl").args(["-n","kern.boottime"]).output()` with no deadline. Absent/binary-error is handled (`output().ok()?` → `None` → Keep; fail-closed, correct). A hung `sysctl` would block daemon startup indefinitely — theoretical (the fixed absolute path and constant argv are otherwise right; no untrusted input reaches argv).

Fix (one line): wrap in `wait_timeout`/spawn-with-deadline, or accept the risk with a comment.

### F5 — Parser accepts a digit-prefix of a malformed value — nit

`parse_sysctl_boottime`: `take_while(char::is_ascii_digit)` on the value means `sec = 1e9` yields `Some(1)`, and `sec = 12abc` yields `Some(12)`. Downstream this is benign (a wrong-but-positive boot time just feeds the F1 comparison), negatives (`-5`), empty digits, overflow, `sec = 0`, missing `sec`, and `usec`-collision are all correctly rejected (tests cover them). No injection surface: the value never leaves the pure function; nothing reaches shell/argv from it.

Fix (one line, optional): require the remainder after digits to be empty or whitespace/comma, else `None`.

### F6 — The lab-stage token is a duplicated literal, not a compile-time pin — nit

`vm_lab/mod.rs:15126-15127` copies `"shutdown_rollback_residue_retired_after_reboot"` with the comment "Byte-pinned to `rustynetd::shutdown_residue::SHUTDOWN_RESIDUE_RETIRED_AFTER_REBOOT_LOG_TOKEN`". Nothing enforces that: if the rustynetd constant changes, the probe greps for a dead string and the new test (`macos_reboot_post_probe_enumerates_logs_as_root_and_accepts_both_recovery_lines`) still passes because it only asserts the *local* source text. The test is a source canary (it validates the fn body contains the new `find`/`-exec` forms and the old glob is gone — appropriate for a shell-string builder, but it proves presence, not behavior).

Fix (one line): add a comment-gated cross-check test that greps `crates/rustynetd/src/shutdown_residue.rs` for the same literal (or generate the const into a shared crate).

### F7 — Delete-before-log window — nit

`retire_marker_after_reboot` runs `let removed = acknowledge_marker(state_path)?;` then `log::warn!(...)`. A crash between the two leaves the marker gone with no retirement log line. The unlink itself is the durable trace, so impact is minimal; the ordering cannot be made atomic.

Fix (one line): log first (with "retiring"), then delete, then a completion line.

## Direct answers to the review questions

- **Could residue that survives a reboot be erased?** The change never touches residue state — only the marker file. The erasure risk is evidentiary (F1, F3): a live marker can be auto-deleted on a same-boot clock step (F1), and deletion is unrecoverable if the "only DNS survives reboot" premise has an unlisted exception (F3). The DNS-pins premise is handled by the M1 guard running immediately before, whose Err path refuses startup and therefore never reaches retirement — sound as written (but see F2 on how fragile that ordering is).
- **Could a wrong/forged boot time retire a live marker?** Forging `kern.boottime` requires root on the host, so the practical vector is the clock-step one (F1). `recorded_unix` in the future is safe: `boot <= recorded` → Keep. A backward-corrected clock after a genuinely wrong RTC makes retirement *keep* (boot < recorded) — fail-safe direction. Boot time unknown/unreadable → Keep.
- **Is the sysctl parsing safe on every shape?** Yes for security purposes: pure function, no allocation of unbounded input beyond the digit run of one field, `sec` matched as an exact key so `usec` cannot collide, non-positive/overflow/garbage → `None` → Keep (fail closed). Only the digit-prefix laxity (F5), which is harmless.
- **Does the daemon behave sanely when sysctl is absent?** Yes: `.output().ok()?` and non-zero status both yield `None`; non-macOS builds hardwire `None`; `decide_marker_retirement(None, _)` is Keep. Marker stays on the operator-acknowledgement path. Startup is not blocked.
- **Is QH-40 'report, not refuse' preserved?** Yes. The original report block (`daemon.rs:11887-11901`) runs first and still emits `SHUTDOWN_RESIDUE_DETECTED_LOG_TOKEN` with the marker path; retirement failure is logged (`log::error!`) and does not abort startup; a same-boot marker, an unreadable marker, or an unknown boot time keeps the explicit `shutdown-residue-check --acknowledge` path as the only removal route. The comment contract in the old doc-comment of `acknowledge_marker` was updated, not weakened.

## Scope, hygiene, semantics

- Files touched: only the three intended ones. No `unwrap()`/`expect()`/panic added outside `#[cfg(test)]`. No new input reaches argv or shell: `sysctl` gets a constant argv; the vm_lab probe's interpolated strings (`RECOVERY_LOG_LINE`, `RETIRED_LOG_TOKEN`) are compile-time constants without single quotes, safely single-quoted into the `find -exec grep -F` command.
- Pass/fail semantics: the reboot cell now accepts two evidence lines instead of one. That is a deliberate widening, and the retirement token is only ever emitted after the M1 guard completed, so "either" does not admit a weaker proof. The root-owned-dir glob fix is real (zsh "no matches found" would abort under `set -eu` before grep ran); `find`'s non-zero exit on a missing dir is inside the `if` condition, so `set -eu` is not tripped.
- Test gaps: the retirement tests are good on the pure function (same-boot keep, unknown-boot keep, guard-fail keep, clean/unreadable keep, garbage parse). Missing: a test for the clock-step-forge shape (marker recorded after a *simulated* boot that is later moved earlier — impossible to express while the decision takes only `(boot, recorded)`, which is itself the F1 argument for storing boottime in the marker), and no test covers `daemon.rs` wiring (the `guard_ok=true` literal is untested by construction — F2).

## Verdict

MERGE-WITH-FIXES — F1: the reboot proof rests on a wall-clock-derived value that a same-boot clock step can move behind an existing marker, auto-erasing the only durable evidence of live residue; persist boottime in the marker and require it to advance.

## Disposition (managing session, commit 33faa08a on `owner/macos-boot-reapply`)

- F1 — FIXED: the marker now records `boot_time_unix` at write time and retirement requires the current boot to be later than BOTH the recorded boot and the recorded time (`decide_marker_retirement`); test `a_same_boot_clock_step_cannot_forge_a_reboot`.
- F2 — FIXED: `guard_ok` is derived from the startup DNS guard's actual result in `daemon.rs`; a guard failure aborts startup before retirement is considered.
- F3 — FIXED: retirement archives the marker to `<marker>.retired-<boot>` instead of deleting it; test `retired_marker_is_archived_not_deleted`.
- F4 — FIXED: the `sysctl` child runs under a 3 s deadline via `recv_timeout`; timeout → boot time unknown → marker kept.
- F5 — FIXED: the parser matches the `sec` key exactly and requires an all-digit value; test on garbage input.
- F6 — FIXED: the lab stage's `RETIRED_LOG_TOKEN` is pinned to `rustynetd`'s constant by a source-inclusion test (`include_str!`), so drift fails the build's test stage.
- F7 — FIXED: the daemon logs the retirement intent before the rename and the completion after it.
