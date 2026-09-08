# MeshStatus QH-70 Follow-Up — Adversarial Review (2026-09-08)

Scope: `git diff main..HEAD` on branch `ai-edit/edit-1788827035347-82167-0`
(commits `e5a8f71b`, `d944c700`, `dee283aa`): the QH-70 follow-up in
`crates/rustynet-cli` — (a) the `mesh_status_validation` live-handshake check
must leave a per-node evidence data block in its stage artifact; (b) a passed
`MeshStatus` validator record with an empty `expected_peer_ids` must fail
rather than pass. Method: every claim below was checked against the current
files in this worktree, not the diff alone; every consumer of the MeshStatus
verdict was opened.

## Answers to the review brief

**1. Does the stage artifact now contain the per-node numbers, through the
shared helper?** Yes — this half is done correctly.

- `LiveHandshakeObservation` (`role_validation/mesh_status.rs:169-183`)
  carries `alias`, `path_live_peer_count`, `expected_live_peers`,
  `path_latest_live_handshake_unix`, `guest_now_unix`,
  `handshake_age_seconds`, `serde::Serialize`.
- The stage writes one JSON line per accepted observation into
  `logs/mesh_status_validation.log` via
  `append_stage_evidence_line(&ctx.report_dir, "mesh_status_validation", …)`
  (`stage/mesh_status_validation.rs:112-131`). That is the same helper the
  sibling stage uses (`stage/membership_init.rs:135`, stage name
  `membership_init`), not a new ad-hoc format. The stage-name argument matches
  the stage's own `name()` (`stage/mesh_status_validation.rs:53-55`) and the
  recorder's log path `<report_dir>/logs/<stage>.log`
  (`orchestrator/evidence.rs:180-182`), so the rows land in the stage's own
  artifact above the terminal verdict, inside the recorder's
  truncate-at-start contract (`evidence.rs:505-512`).
- The values are guest-reported, not host-side: `now_unix` comes from
  `parse_guest_now_unix(&status)` of the status line the guest returned
  (`stage/mesh_status_validation.rs:165-171`); the poll never consults the
  orchestrator clock.
- A serialization or write failure is pushed into `failures`, which fails the
  stage (`stage/mesh_status_validation.rs:113-130`) — evidence cannot silently
  go missing.
- Evidence rows are only produced on acceptance: `poll_live_handshake` returns
  `Ok(observation)` only from an accepted `evaluate_live_handshake_status`
  (`stage/mesh_status_validation.rs:177-178`; doc at 147-149). The check
  cannot be skipped while its evidence is written.

**2. Can the evidence be written while the check did not run, or from host
values?** No for both (see above). Two deliberate non-runs pass without
evidence and are pre-existing, documented behavior: an empty alias list
(`stage/mesh_status_validation.rs:68-70`) and non-Linux reported-skips
(written to `mesh_status_validation.reported_skips.json`, never silent).

**3. Does the empty-expectation failure fire for every consumer of the
MeshStatus verdict?** No — it fires in exactly one of three consumer classes.

- **Patched:** `ValidateBaselineRuntimeStage` — the only production caller of
  `run_validator(DaemonProbeOp::MeshStatus, …)`
  (`stage/validate_runtime.rs:212`; the vacuous computation at 264-269 and the
  failure push at 286-288).
- **Not patched:** the legacy per-OS focused runners. `run_validate_linux_mesh_status_stage_with_overrides`
  (`vm_lab/mod.rs:25508`) hands the raw report to
  `evaluate_linux_mesh_status_report` (`mod.rs:23631-23656`), which judges
  only `overall_ok` and `drift_reasons` consistency — a report with
  `expected_peer_ids: []` and `overall_ok: true` is accepted, and that
  acceptance is pinned by the consumer's own tests
  (`mod.rs:50377-50401`, `evaluate_linux_mesh_status_report_accepts_clean_report`
  feeds `"expected_peer_ids": []`). The macOS analog
  `evaluate_macos_mesh_status_report` (`mod.rs:23543+`) likewise never checks
  `expected_peer_ids` (it proves peer visibility differently, via strict
  verified `member_node_ids`); Windows follows the same shape (`mod.rs:22166`).
  The QH-70 vacuous-pass class therefore still reads as a pass on those
  surfaces.
- **Structurally safe:** `MeshStatusValidationStage` (the live-handshake poll)
  derives its expectation from the topology (`assignments.len() - 1`,
  `stage/mesh_status_validation.rs:74`), so it cannot be vacuous on a
  multi-node run, and its single-node zero-expectation path still parses and
  records evidence.

**4. Could the rule wrongly fail a legitimate single-node topology?** No.
`mesh_status_expectation_vacuous` returns false when `assignments_len <= 1`
(`stage/validate_runtime.rs:103`), and `ctx.assignments` is the full run
topology in this stage (`validate_runtime.rs:198` — the same source the
live-handshake stage uses). Single-node exemption is tested
(`validate_runtime.rs`, `single_node_topology_is_never_vacuous`) and the live
stage's single-node pass-with-evidence is tested end-to-end
(`stage/mesh_status_validation.rs`, `execute_writes_per_node_observation_rows_to_stage_log`).

**5. Do the new tests still fail if the fix is reverted?**
- `mesh_status_validation` side: yes. Reverting
  `poll_live_handshake` to `Result<(), String>` breaks compilation of
  `poll_live_handshake_returns_accepted_observation`; deleting only the
  evidence loop fails `execute_writes_per_node_observation_rows_to_stage_log`.
  Verified green on this branch: `cargo test -p rustynet-cli --lib
  --all-features -- mesh_status vacuous` → 54 passed, 0 failed.
- `validate_runtime` side: **no** — see Finding F2.

## Findings

### F1 — BLOCKER: the empty-expectation rule is unsatisfiable by construction; every multi-node run now fails at a T0 stage

`probe_expectations(DaemonProbeOp::MeshStatus)` emits only
`--max-age-seconds` (`stage/validate_runtime.rs:64-68`) — the same file
documents why no expectation is ever passed (`validate_runtime.rs:54-59`:
the daemon's `peer_ids` are advertised route CIDRs, "no node id can ever
match one", emitting expectations "would red every node in the run … a
separate daemon-side defect"). The adapters forward extras verbatim
(`adapter/linux.rs:216-224`, `adapter/macos.rs:236-241`), and all three
daemon collectors echo the CLI options into the report
(`rustynetd/src/linux_mesh_status.rs:87`, `macos_mesh_status.rs:223`,
`windows_mesh_status.rs:99`). Therefore `report.expected_peer_ids` is `[]` on
**every** stage-path MeshStatus record, on every platform.

Concrete failure scenario: any run with ≥ 2 nodes. MeshStatus passes vacuously
exactly as before, `mesh_status_expectation_vacuous(>1, true, …)` is
unconditionally true (`validate_runtime.rs:106-115` — present, well-formed,
empty array → vacuous), `errors.push` fires (`validate_runtime.rs:286-288`),
the stage returns `Failed` (`validate_runtime.rs:314-318`). Since
`ValidateBaselineRuntime` is a Setup/T0Core stage
(`stage/mod.rs:199`) and `deploy_relay` (`deploy_relay.rs:72`),
`traffic_test_matrix` (`traffic_test_matrix.rs:17`),
`security_audit_validation` (`security_audit_validation.rs:60`),
`macos_anchor_profile_deploy` (`macos_anchor_profile_deploy.rs:27`),
`macos_role_transition_validation` (`macos_role_transition_validation.rs:41`),
and `macos_reboot_recovery_validation`
(`macos_reboot_recovery_validation.rs:92`) all declare it a dependency, every
multi-node `--node` run — including the owner-scheduled live proof of the
evidence rows that the ledger promises — will now stop red at setup. The
check has been converted from a false green into a guaranteed red, not into a
meaningful check; nothing on this branch can ever make it pass again on a
multi-node topology. Fail-closed is the correct direction and the brief
mandates it, but a rule that no achievable input satisfies is a pipeline
freeze, and the ledger text ("Both halves of the gap above are closed")
does not disclose it.

Suggested fix (either): emit a positively-provable expectation on the stage
path — the macOS report already carries the right primitive
(`expected_node_ids` / verified `member_node_ids`,
`rustynetd/src/macos_mesh_status.rs:105-112`, and the focused runner's strict
`member_node_ids` proof at `mod.rs:23575+` shows the pattern works live) — or
keep the rejection and record in the QualityHardeningTodo ledger, in this same
change, that `validate_baseline_runtime` is red-by-design on multi-node runs
until the daemon-side expectation emission lands, so the run-matrix red is
readable as intentional.

### F2 — should-fix: the vacuous-rejection wiring has no execute-level test; reverting the wiring leaves every new test green

All six new tests in `stage/validate_runtime.rs:587+` call
`mesh_status_expectation_vacuous` / `mesh_status_vacuous_failure` directly.
None drives a vacuous `MeshStatus` record through
`ValidateBaselineRuntimeStage::execute` to assert `StageOutcome::Failed`.
If the wiring at `validate_runtime.rs:264-269` / `286-288` were deleted (or
the `matches!(op, …MeshStatus)` guard dropped, or the `errors.push` moved
after the `errors.is_empty()` check), the suite stays green. This is exactly
the "tests assert the code's own shape" failure class. Suggested fix: one
execute-level regression test with an adapter double returning a `passed`
MeshStatus `ValidatorReport` whose report is
`{"expected_peer_ids": []}` on a 2-node ctx, asserting the stage fails with
the vacuous message.

### F3 — should-fix: the kept evidence record still says `passed: true` for a rejected vacuous pass

The vacuous detection runs before the record is built
(`validate_runtime.rs:259-269`) but the record keeps `passed` unchanged
(`validate_runtime.rs:270-275`), and `build_validator_evidence` serializes it
verbatim (`validate_runtime.rs:147-167`) into
`logs/validate_baseline_runtime.validator-evidence.json`. A reader of the
artifact alone — the standard this change sets for itself — sees a green
`MeshStatus` entry while the stage failed. Suggested fix: mark the record
(e.g. `summary: "vacuous expectation rejected"` or a `rejected: true` field)
so the artifact and the verdict agree.

### F4 — should-fix (doc): the stage's own doc comment now contradicts its behavior

`stage/validate_runtime.rs:54-59` still says expectations are deliberately
"NOT emitted" because passing them "would red every node in the run" and
"asserting peer visibility has to wait for" the daemon-side fix. After this
branch, every multi-node run is red anyway via the vacuous rejection. The
paragraph reads as if the design chose green-now/red-later; the code now
chooses red-now. Suggested fix: update the comment to state the new posture
and point at the vacuous rejection, so the next reader does not re-derive the
old one.

### F5 — should-fix (scope): the legacy `validate_linux_mesh_status` consumer still accepts the vacuous pass

As detailed in brief-answer 3: `evaluate_linux_mesh_status_report`
(`mod.rs:23631-23656`) accepts `overall_ok: true` with an empty
`expected_peer_ids`, pinned by its own tests (`mod.rs:50377-50401`), and the
macOS/Windows focused-runner equivalents never check the field. If the QH-70
class is "an empty expectation proves nothing", the rule should hold on this
surface too, or the ledger should say explicitly that the legacy runners are
out of scope for this fix. (Note the macOS runner's strict
`member_node_ids` proof already covers peer visibility there — the Linux
focused runner has no equivalent.)

### F6 — nit: `handshake_age_seconds` can be misleading on the single-node evidence path

`handshake_age_seconds: now_unix.saturating_sub(handshake)`
(`role_validation/mesh_status.rs:221`) clamps a future-dated handshake to 0.
The future-dated gate (`mesh_status.rs:241-246`) only runs when
`expected_live_peers > 0`, so a single-node acceptance can record
`handshake_age_seconds: 0` in evidence for a status whose handshake is in the
guest's future. Evidence cosmetics only (the field is not used for gating);
noting it so the artifact is not read as "fresh" when it is "skewed".

## Verified clean

- No `unwrap()`/`expect()`/panic in the new non-test code (matches on
  `serde_json::to_string`, `Result` propagation throughout).
- No shell/argv construction from untrusted values; the shared evidence
  helper refuses embedded newlines/empty lines (`evidence.rs:207-213`), and
  the line content is orchestrator-generated.
- No fail-open path found in either change: write failure fails the stage,
  non-acceptance produces no evidence, missing/malformed reports are treated
  as vacuous (`validate_runtime.rs:106-115`, tested at
  `missing_or_malformed_expectation_fails_closed`).
- Artifact format is the shared sibling helper, not an ad-hoc one; the stage
  name argument is consistent with the recorder's log naming
  (`stage/mod.rs:209`).
- Scoped gates pass on this branch: `cargo test -p rustynet-cli --lib
  --all-features -- mesh_status vacuous` → 54 passed / 0 failed.

## Verdict

VERDICT: MERGE-WITH-FIXES — the evidence half is correctly built through the shared sibling helper with guest-reported values and fail-closed writes, and the single-node topology is safe, but the empty-expectation rejection is unsatisfiable by construction today (guaranteeing a red T0 stage on every multi-node run with no code path to green) and that consequence is neither disclosed in the ledger nor reflected in the stage's own doc comment, while the new validate_runtime tests never exercise the wiring they claim to protect.
