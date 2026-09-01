# Live-Lab Stage Design: Signed-State Epoch Rollback at the Apply Layer (GAP-5)

**Date:** 2026-09-01
**Status:** DESIGN ONLY — no code has been changed for this stage. The stage work described here is pending (a) a separate adversarial review of this design, and (b) live-lab availability (the lab VMs are currently down, so live proving cannot be scheduled yet).
**Scope:** A new live-lab orchestration stage that drives a previous-epoch, previously-valid signed membership bundle at a **running** daemon **through the normal bundle distribution path**, and asserts fail-closed rejection plus unchanged replay watermark and unchanged membership view.

---

## 1. Grounding Verdict: PARTIAL

The GAP-5 fault class — "old-but-valid epoch signed-state rollback driven through the dataplane apply path on a running mesh" — is **named** in the existing chaos taxonomy but is **not exercised live anywhere** in the current engine of record (the Rust `--node` orchestrator). Verdict: **PARTIAL**. The enforcement points exist and are correct; the adversarial corpus names the fault; but no stage replays a previously-valid old-epoch bundle at a running daemon over the wire. The evidence, from a direct read of the code (not from the coverage-gap-hunt document):

### 1.1 The `security_audit` stage is an offline in-daemon self-audit, not a live wire replay

`crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/security_audit.rs` folds eight Tier-0 adversarial daemon self-audits into a standard `OrchestrationStage`. Its doc comment (`:4-13`) states each audit runs `rustynetd <check>-audit --no-fail-on-drift` over the hardened RemoteShellHost seam and is accepted only by the same typed evaluators the live suite applies, which fail closed on an empty corpus, a vacuous result, or a too-thin battery. The audit table (`:42-83`) covers membership revocation, revoked-peer denial, signature forgery, privileged-helper allowlisting, policy default-deny, gossip revoked-readmit, enrollment replay, and blind-exit reversal. None of the eight audits replays a previous-epoch bundle through the live distribution path; they are daemon-side self-examinations of an already-persisted state. The `AuditVerdict` enum (`:113-118`) distinguishes `Blocked` (control never exercised) from `Failed` — both fail the stage, which is the fail-loud convention this design follows.

### 1.2 The enforcement points GAP-5 would exercise (verified, with exact rejection sites)

`crates/rustynet-control/src/membership.rs`, `apply_signed_update` (`:1032-1076`) validates in this order:

1. `state.validate()` (`:1038`).
2. Network-id match (`:1041-1045`) — `InvalidTransition: "network id mismatch in membership update"`.
3. Expiry (`:1046-1048`) — `MembershipError::Expired`.
4. Future-dated guard (`:1049-1051`) — `FutureDated`, bounded by `MEMBERSHIP_CLOCK_SKEW_SECS`.
5. Previous-state-root link (`:1052-1054`) — `PrevStateRootMismatch` when `record.prev_state_root != state.state_root_hex()`.
6. **Epoch chain** (`:1055-1059`) — `InvalidTransition: "epoch chain mismatch for membership update"` unless `record.epoch_prev == state.epoch && record.epoch_new == state.epoch.saturating_add(1)`. This is the primary rejection point for an old-epoch bundle.
7. Signature verification (`:1061`).
8. Deterministic re-reduce root match (`:1066-1072`) — `NewStateRootMismatch`.
9. Replay-cache observation (`:1073`) — `replay_cache.observe(&record.update_id, record.epoch_new)`.

The replay cache (`MembershipReplayCache`, `:728-752`) independently rejects `epoch_new <= self.max_epoch` (`:740`) — the monotonic-epoch watermark guard — and reports `MembershipError::EpochRegression` (`:796-868`) with the message `"membership epoch regression: offered epoch {offered_epoch} is below prior verified epoch {prior_epoch}"`, including fork detection (`"membership fork detected at epoch {epoch}: prior verified state root {prior_root} != offered state root {offered_root}"`). The comment at `:718-722` is explicit that *"epoch watermark alone still blocks rollback replays for evicted ids (apply_signed_update enforces the strict epoch chain)"* — i.e. both layers must hold. The snapshot identity pair is `(epoch, state_root_hex)` per FIS-0020 (`:1248`), with prior-identity epoch monotonicity enforced at `:1510-1526` and replay classification at `:1563-1565` (`incoming.epoch < previous.epoch`, or equal epoch with a differing state root).

### 1.3 The chaos corpus names the fault but only as offline fixtures

`StageId::ChaosSignedStateAdversarial` (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs:291-302`, mapped to `"chaos_signed_state_adversarial"` under Chaos / T4Security, with the comment "Clock rollback vs freshness/anti-replay protection — adversarial") is wired in `plan.rs:497-498` and registered in `chaos.rs:125-128` with runner binary `live_chaos_signed_state_adversarial_test` and target class **`ChaosTargets::Offline`** with `--scenario all` (`chaos.rs:129-131`). Reading that binary (`crates/rustynet-cli/src/bin/live_chaos_signed_state_adversarial_test.rs`) shows it is a **fixture generator and in-process validator, not a live test**: `run()` (`:128-163`) generates a fixture manifest to disk, validates it in-process via `generate_manifest`/`validate_manifest`, and writes a JSON report whose own self-description is `"offline signed-state adversarial fixtures generated and pinned to fail-closed expectations"` (`:179`) with security invariants `"offline_only": true`, `"production_state_mutation": false` (`:186-194`). It never contacts a daemon. Notably, its declared stage list **does include** `chaos_replay_old_membership` (`:21-26`): fault *"inject older validly-signed membership update with stale watermark"*, pass criterion *"replay rejected and daemon stays on current snapshot"* — the exact GAP-5 fault class, but realized only as a fixture record, never as a wire-level replay.

### 1.4 The negative-control stages check a different verifier, also offline

`crates/rustynet-cli/src/vm_lab/orchestrator/stage/negative_control.rs` (forgery taxonomy test module `:1533-1706`) mirrors the `live_signed_state_chaos` corpus, but against the **assignment** verifier (`verify_signed_assignment_state_artifact`), not the membership apply path, and in-process. Its `ForgeryKind::Replay` (`:1663-1665`) is *"a genuine, current bundle presented against a strictly-newer persisted watermark"* — a different shape from a previous-epoch bundle. Its own comment (`:1670-1676`) states quorum fault classes are adjudicated on the membership path via *"the offline `chaos_signed_state_adversarial` corpus + the `validate_linux_membership_signature_forgery` audit"* — confirming that path is understood as offline. A repository-wide search found **no stage** that delivers a previous-epoch, previously-valid membership bundle to a running daemon through the normal distribution path with assertions on rejection reason, watermark immutability, and membership-view immutability.

### 1.5 Conclusion of the grounding step

The guards are real and tested at the validator level; the fault is catalogued as an offline fixture; the live cell — the adversarial delivery over the wire to a running mesh node — is genuinely uncovered. A new stage is justified. (Had the verdict been REFUTED, this document would instead record why no stage is needed.)

---

## 2. Stage Design: `live_signed_state_rollback_replay`

### 2.1 Objective

Prove, on a running mesh, that a signed membership bundle from a **previous epoch that was genuinely valid when issued** (correct threshold signatures, correct chain link at its time, never tampered) is rejected by a daemon already holding a strictly newer epoch, that the rejection comes from the epoch-chain / replay-watermark enforcement point specifically, and that the daemon's persisted watermark and observable membership view are **byte-identical** before and after the attempt.

### 2.2 Prerequisites and capture model

The stage runs **after** the standard live membership setup has driven the mesh through at least two real epochs, so that an applied previous-epoch bundle exists. During setup, before the epoch E-1 → E transition is distributed, the stage's runner captures and retains:

- The complete epoch E-1 bundle exactly as the distribution path delivered it (serialized bytes as received, so the replay is not a re-forged artifact but the genuine wire object).
- The post-transition epoch E bundle, delivered first, so the daemon's watermark is freshly advanced.

Capturing the E-1 bundle from the live path matters: an offline re-serialization could accidentally invalidate signatures or alter canonical bytes, which would turn the test into a malformed-input test instead of a rollback test.

### 2.3 Execution sequence

1. **Advance:** distribute the current epoch E bundle through the normal distribution path. Assert acceptance: the daemon reports the applied update, and its snapshot identity is `(epoch = E, state_root = R_E)` (FIS-0020 pair).
2. **Snapshot:** record the pre-replay membership view: epoch, state root, attestation identity set, and the persisted replay watermark as exposed by the daemon's status/inspection surface.
3. **Replay:** submit the captured epoch E-1 bundle through the **same normal distribution path** (the gossip/bundle distribution channel a legitimate peer would use — not a hand-crafted IPC poke, not a fixture file drop).
4. **Assert, all mandatory (fail loud):**
   - **Rejection at the enforcement point.** The daemon's structured rejection names the epoch chain / replay watermark guard — matching `"epoch chain mismatch for membership update"` (`membership.rs:1055-1059`) or the watermark regression (`"membership epoch regression"`, `membership.rs:796-868`). A rejection for any other reason (malformed, signature, network-id) is a **failure**, not a pass: it would mean the bundle was corrupted in transit and the rollback protection was never exercised.
   - **Watermark unchanged.** The persisted replay watermark still reads `(max_epoch = E, state_root = R_E)`. Any advance, regression, or state-root change is a failure.
   - **Membership view unchanged.** The post-replay view equals the pre-replay snapshot exactly: same epoch, same state root, same attestation identity set. Any drift is a failure.
5. **Report:** a per-assertion report artifact (status, expected reason substring, actual rejection text, before/after view digests), written to the run's report directory, fail-loud on any miss — including a distinct `Blocked` verdict if the capture or distribution plumbing could not run, so a blocked run can never be read as a pass.

### 2.4 Placement in the orchestrator

- New `StageId` (e.g. `LiveSignedStateRollbackReplay`), name `live_signed_state_rollback_replay`, category Security / T4Security, target class the membership node under test (not `Offline`).
- Registration follows the existing pattern: `stage/mod.rs` id-to-name mapping, `plan.rs` stage-box construction, and a runner binary `live_signed_state_rollback_replay_test` alongside the other `live_*` binaries in `crates/rustynet-cli/src/bin/`.
- Dependency: runs after the live membership validation stage (the mesh must be at epoch ≥ 2 with the capture from §2.2 available); ordered before soak/cleanup.
- The runner shells to the target over the hardened RemoteShellHost seam like other live stages, uses the captured bundle bytes, and grades only on the §2.3 assertions.

### 2.5 Offline validator unit tests (implementable now; lab VMs are down)

These tests require no lab and pin the enforcement contract the live stage will exercise:

- Build a `MembershipState` at epoch E. Re-submit a genuinely valid epoch E-1 update through `apply_signed_update` and assert `MembershipError::InvalidTransition` with `"epoch chain mismatch"` (`membership.rs:1055-1059`).
- Same shape against the replay cache directly: `observe(update_id, E-1)` after `observe(_, E)` asserts the monotonic guard (`:740`) and surfaces `EpochRegression` (`:796-868`).
- Assert the watermark and view are untouched after each rejected apply (the validator-level analogue of §2.3 assertions 2-4).
- Negative-as-positive check: a re-signed bundle at the correct epoch still applies, proving the rejection is epoch-selective, not a blanket refusal.

These tests are the offline half of the deliverable; the live stage remains gated on the preconditions below.

---

## 3. Preconditions Before Implementation Proceeds

1. **Adversarial review of this design** by a separate reviewer, specifically attacking: capture fidelity (could the captured bundle be silently mangled?), distribution-path purity (is the replay path truly identical to the legitimate path?), false-pass routes (could a wrong-reason rejection be graded as success?), and report-forgery resistance.
2. **Lab availability.** The live cell cannot be proven while the lab VMs are down. Per the live-lab rules, a stage pass is only ever claimed from the stage's own report artifact in the run's report directory, recorded in `documents/operations/live_lab_node_run_matrix.csv` (the `--node` engine's ledger), never from a dry run.

---

## 4. Explicit Non-Goals

- No change to `membership.rs` guards — they are verified correct and are the system under test, not the fix.
- No weakening of the existing chaos fixture corpus — it stays as the offline taxonomy record; this stage adds the live delivery dimension it deliberately does not cover.
- No legacy/fallback delivery path for the replay: one hardened execution path (the normal distribution path), per the repo's single-path rule.
