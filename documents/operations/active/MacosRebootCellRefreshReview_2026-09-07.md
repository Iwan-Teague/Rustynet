# macOS Reboot-Recovery Cell Refresh — Adversarial Security Review (2026-09-07)

Scope reviewed: `git diff 1efc8376..HEAD -- crates/` (commit `29776167`, "Redistribute fresh signed bundles to the rebooted macOS node before the pin probe"). Files touched: `crates/rustynet-cli/src/vm_lab/mod.rs`, `vm_lab/orchestrator/plan.rs`, `vm_lab/orchestrator/role_validation/blind_exit.rs`, `vm_lab/orchestrator/stage/distribute_assignments.rs`, `vm_lab/orchestrator/stage/macos_reboot_recovery_validation.rs`. All in the intended area; `blind_exit.rs` only widens two helpers to `pub(crate)` (`rustynet_program`, `daemon_socket_path`) for reuse by the poll — minimal, justified.

Reviewer ran on this branch: `cargo fmt --all -- --check` exit 0; `cargo check -p rustynet-cli --all-targets --all-features` clean; `cargo test -p rustynet-cli --all-features --lib macos_reboot_recovery` → **15 passed, 0 failed**.

---

## Findings

### F1 — Recovery criterion negates a single state token instead of allowlisting healthy states — **should-fix**

`macos_reboot_recovery_validation.rs:267-269`:

```rust
pub(crate) fn node_has_recovered_generation(observation: &RecoveryStatusObservation) -> bool {
    observation.state.as_deref() != Some(FAILCLOSED_STATE) && observation.programmed_peer_count >= 1
}
```

Any state token other than the exact string `FailClosed` — including a missing `state=` field, a renamed token, or a future fielded variant — counts as "left FailClosed", provided `path_programmed_peer_count >= 1`. The daemon prints `state={:?}` of `DataplaneState` (`crates/rustynetd/src/daemon.rs:9259`), a five-unit-variant enum `{ Init, ControlTrusted, DataplaneApplied, ExitActive, FailClosed }` (`crates/rustynetd/src/phase10.rs:322-328`), so today the exact-match parse is correct and `state=FailClosed` is never misread as not-fail-closed (there is no regex anywhere; `parse_status_field`, `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/ssh.rs:1161-1168`, is an exact `key=` prefix match over whitespace-delimited tokens).

Failure scenario: a future daemon change turns `FailClosed` into a tuple variant (Debug prints `state=FailClosedSomeDetail(...)`) or a partial-token family (`FailClosedDegraded`); the token no longer equals `"FailClosed"`, the first half passes, and if `path_programmed_peer_count` reports a stale/pre-apply count ≥ 1 the poll declares recovery while the node is still fail-closed. The subsequent pin probe still gates the stage, so this is defense-in-depth, not an open hole today.

Fix: allowlist the healthy terminal states — `matches!(observation.state.as_deref(), Some("DataplaneApplied") | Some("ExitActive"))` — instead of `!= Some("FailClosed")`.

### F2 — Order contract is pinned by source-text grep, not by behavior; one test name overstates what it proves — **should-fix**

`macos_reboot_recovery_validation.rs:878-903` (`source_pins_redistribution_before_the_pin_probe`) asserts ordering by `str::find` over the raw source of `mod.rs` and this file:

```rust
let seam = mod_rs.find("post_daemon_live(&node_id)") ...
assert!(seam < pin_probe, ...)
```

This proves seam-before-`post_script` textually, but proves nothing at runtime: no test invokes `exercise_macos_reboot_recovery_with_recovery_actions` (`mod.rs:15126`) with a recording hook, so "the hook runs exactly once, AFTER the daemon-live probe, with the parseable node id" is unverified by any test. Additionally, `redistribution_invoked_once_per_kind_after_daemon_live_probe` (`:801`) calls `redistribute_fresh_bundles_and_await_generation` directly and never involves the daemon-live probe — the `_after_daemon_live_probe` half of its name is not what it tests.

Failure scenario: a refactor moves the `post_daemon_live(&node_id)` call after the post-probe is built (or introduces a second string occurrence earlier in `mod.rs`, e.g. in a doc comment, which `.find()` would hit first) and the source-grep test keeps passing for the wrong reason.

Fix: rename the behavioral test to what it checks (`..._redistributes_once_per_kind_and_polls`), and add a seam-behavioral test with a spy hook if the exercise fn can be made testable without SSH; otherwise keep the source-pin test but also assert `seam > daemon_live_marker` textually (e.g. locate the `daemon-live` wait loop) so the full three-point order is pinned.

### F3 — `KINDS` catch-all maps any label to `DnsZone` — **nit**

`macos_reboot_recovery_validation.rs:184-187`:

```rust
let kind = match label {
    "traversal" => BundleKind::Traversal,
    _ => BundleKind::DnsZone,
};
```

Adding a third kind tuple or typo'ing `"traversal"` silently issues and installs a second dns_zone generation instead of failing. Fix: put `BundleKind` in the tuple (`[(BundleKind, &str, &str); 2]`) and drop the string round-trip.

### F4 — Stale comment: verifier-key barrier "to EVERY node" — **nit**

`distribute_assignments.rs:315` — "Verify and distribute the verifier key to EVERY node before ANY signed bundle is installed." In scoped mode the barrier (correctly) covers only the scoped alias: the filtered `aliases` list (`:293-300`) feeds `run_verifier_barrier` (`:330`), so in a redistribution only the rebooted node receives the verifier key + bundle. The comment now overstates scope. Fix: "to every in-scope node".

### F5 — Success log line contains a run of stray spaces — **nit**

`macos_reboot_recovery_validation.rs:231` — `"re-applied a programmed              generation after fresh bundle redistribution"` (14 spaces). Cosmetic; lands in the stage log evidence. Fix: single space.

### F6 — Doc drift: renamed function still referenced by two active ledgers — **nit**

`exercise_macos_reboot_recovery_live` no longer exists (renamed to `exercise_macos_reboot_recovery_with_recovery_actions`, `mod.rs:15126`), but `documents/operations/active/MacosDnsBackupRebootSurvivalPlan_2026-09-02.md` and `documents/operations/active/MacosRebootRecoveryStageImplementationReview_2026-09-02.md` still cite the old name. Fix: update the references (this reviewer may not write those files).

---

## Verified-good (answers to the specific review questions)

- **Can the stage pass without the pins actually present?** No via the poll: the recovery criterion requires `path_programmed_peer_count >= 1` parsed fail-closed (`unwrap_or(0)`, `:255-258`) — an empty, non-zero-exit, or transport-erroring status observation can never read as recovered (`poll_generation_recovery`, `:279-327`; empty-success is recorded as `"rustynet status exited 0 with empty output"`). The pins themselves are still proven only by the unchanged post-probe `LOOPBACK_PIN_CHECK` after the seam.
- **Redistribution silently skipped on error?** No. Both `StageOutcome::Failed` and any non-`Passed` outcome from `distribute_bundle_kind_scoped` become `Err` (`:188-207`), the hook error fails the exercise (`mod.rs:15283-15285`, "failed before the pin probe"), and a scoped alias with no node_id fails closed (`distribute_assignments.rs:306-310`).
- **Same verifier-key barrier as setup?** Yes — byte-identical path: fresh full-mesh issuance from the exit adapter (`issue_bundles_to_dir`, `:278-289`), `validated_verifier_key_sha256` on the issued `.pub` before any install (`:318-325`), then the two-phase `run_verifier_barrier` (verify-all → install-any, `:330-369`). Bundles are freshly issued, not reused setup artifacts; only the install is scoped, so no unsigned/stale bundle is introduced by this change.
- **Bounded poll fails closed on timeout with the exact status line?** Yes — exhaustion returns `Err` carrying the last observation verbatim (`:317-327`), whether that is a status line, an exit code, or a transport error; test `poll_fails_with_exact_status_text_when_stuck_in_failclosed` (`:752-770`) asserts the exact line appears.
- **`unwrap`/`expect`/`panic` in non-test code?** None — every `expect`/`unimplemented!` in the diff sits at line ≥ 436, inside `mod tests` (non-test file body ends ~line 350).
- **Split keeps boottime-changed + residue-marker checks intact?** Yes — the seam is a pure insertion at `mod.rs:15277-15285`, before `let post_script = format!(`; the unchanged post-probe still errors on `post_boottime == pre_boottime` and on `shutdown_residue_marker=present` (`mod.rs:15340-15352`).
- **`FailClosed` regex false-negative?** No regex exists; parse is exact-token (`ssh.rs:1161-1168`) and `DataplaneState` is unit-variant-only today (see F1 for the drift risk).
- Scope: no files touched outside `crates/rustynet-cli/src/vm_lab/`; no argv/shell construction from untrusted values added (status query is `run_argv` with static program + socket path).

---

VERDICT: MERGE-WITH-FIXES — the seam, barrier reuse, and fail-closed poll are sound and tested, but F1's negate-one-token recovery criterion silently inverts to fail-open on any future daemon state-token drift and should be an allowlist before this becomes load-bearing in more cells.

---

## Disposition (edit job edit-1788781850025-90987-0)

All six findings fixed on branch `ai-edit/edit-1788781850025-90987-0`; the review doc itself
committed verbatim first (`05cd36a9`), code fixes in `1290f68f`.

- **F1 — FIXED.** `node_has_recovered_generation` now allowlists the healthy terminal states:
  `matches!(observation.state.as_deref(), Some(RECOVERED_STATE_DATAPLANE_APPLIED) | Some(RECOVERED_STATE_EXIT_ACTIVE))`
  AND `programmed_peer_count >= 1`. Variant names confirmed against
  `crates/rustynetd/src/phase10.rs` `pub enum DataplaneState { Init, ControlTrusted, DataplaneApplied, ExitActive, FailClosed }`
  (all unit variants; `daemon.rs` prints `state={:?}` of `controller.state()`), and pinned by
  `recovered_state_names_are_pinned_to_the_daemon_enum` (`include_str!` of the defining file,
  exact unit-variant line match). A missing `state` field is NOT recovered. New tests:
  `recovery_criterion_is_an_allowlist_of_healthy_terminal_states` (missing state; `FailClosedDegraded`
  drift token; `Init`/`ControlTrusted` non-terminal tokens; each allowlisted state with peers ≥ 1;
  allowlisted state with 0 peers) and `recovery_criterion_requires_allowlisted_state_and_programmed_generation`
  (renamed from the negation phrasing). Test fixtures updated from the fictional `state=Applied`
  token (which the old criterion accepted — exactly the fail-open F1 describes) to
  `state=DataplaneApplied`.
- **F2 — FIXED (source-slice route; runtime recorder infeasible).** The exercise fn requires a real
  SSH inventory target, so a runtime recording hook is not reachable from unit tests. Instead
  `source_pins_redistribution_before_the_pin_probe` now slices `mod.rs` to the body of
  `exercise_macos_reboot_recovery_with_recovery_actions` (bounded by `fn parse_macos_boottime_line`)
  and requires the seam expression `post_daemon_live(&node_id)` to occur EXACTLY ONCE inside that
  body, before `let post_script = format!(` — a doc-comment occurrence can no longer satisfy the
  pin. The stage-side half is likewise sliced to the body of
  `redistribute_fresh_bundles_and_await_generation` for redistribute-before-poll. The behavioral
  test is renamed to what it proves: `redistributes_once_per_kind_and_polls_generation` (it drives
  the seam implementation directly; the probe-order claim is the source pin's).
- **F3 — FIXED.** `KINDS` is now `[(BundleKind, &str, &str, &str); 2]` carrying the kind in the
  tuple; the string-label round trip with its `DnsZone` catch-all is removed (a typo or a future
  third kind fails to compile instead of silently issuing a second dns_zone generation).
- **F4 — FIXED.** The barrier comment in `distribute_assignments.rs` now reads "to every in-scope
  node", noting scoped mode covers exactly the scoped alias.
- **F5 — FIXED.** The success log line's stray-space run collapsed to single spaces.
- **F6 — FIXED.** Both ledgers updated: `MacosDnsBackupRebootSurvivalPlan_2026-09-02.md` (Step 2
  renamed-split wording corrected to rename; Step 3 poll criterion restated as the F1 allowlist)
  and `MacosRebootRecoveryStageImplementationReview_2026-09-02.md` (helper named with its rename).

Gates (toolchain 1.88.0 per `rust-toolchain.toml`, `CARGO_TARGET_DIR=/Users/iwan/Desktop/Rustynet/target-pinned-j4`):
`cargo fmt --all -- --check` clean; `cargo clippy -p rustynet-cli --all-targets --all-features -- -D warnings`
clean; `cargo test -p rustynet-cli --lib --all-features -- macos_reboot` → **17 passed, 0 failed**.
Note: a Homebrew cargo 1.97.0 shadowed rustup in this worktree's PATH and flags three
`collapsible_if` lints in `crates/rustynetd/src/phase10.rs` (untouched files, out of scope);
under the pinned 1.88.0 clippy they do not fire — no rustynetd change was made.
