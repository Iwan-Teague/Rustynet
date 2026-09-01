# Live-Lab Stage Design: Signed-State Epoch Rollback at the Apply Layer (GAP-5)

**Date:** 2026-09-01
**Status:** DESIGN ONLY — no code has been changed for this stage. An adversarial review of this design has completed (READY-WITH-AMENDMENTS); its five required amendments were folded into this document on 2026-09-01. Implementation remains **owner-gated and lab-pending**: the lab VMs are currently down, so live proving cannot be scheduled yet, and no stage pass exists in the run-matrix ledger.

**Adversarial-review amendments folded (2026-09-01):** amendments 1–5 of `LiveLabSignedStateRollbackApplyLayerStageAdversarialReview_2026-09-01.md` — (1) expected-rejection set corrected to the code-accurate ordered set with `PrevStateRootMismatch` first and `EpochRegression` dropped from the apply path; (2) replay mechanism pinned to the local IPC `membership apply` surface (admin-role), snapshot-file-drop explicitly forbidden; (3) capture model moved to the mint point with SHA-256 pinning and a `Blocked`-graded validity-window guard; (4) concrete observability surfaces named with byte digests across three artifact classes; (5) fail-loud wiring inherited verbatim from the `AuditVerdict` precedent (`Blocked`/`Failed`/`Skipped` semantics, status_rank, missing-artifact-is-failure).

**Scope:** A new live-lab orchestration stage that drives a previous-epoch, previously-valid signed membership bundle at a **running** daemon **through the daemon's legitimate membership-apply ingestion entry — the local IPC `membership apply` surface, driven with the admin-role credential** — and asserts fail-closed rejection plus unchanged replay watermark and unchanged membership view.

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
5. Previous-state-root link (`:1052-1054`) — `PrevStateRootMismatch` when `record.prev_state_root != state.state_root_hex()`. **This fires FIRST, before the epoch-chain guard** — so a genuine old-epoch bundle whose `prev_state_root` no longer matches the daemon's current state is rejected here, not at the epoch-chain check (amendment 1).
6. **Epoch chain** (`:1055-1059`) — `InvalidTransition: "epoch chain mismatch for membership update"` unless `record.epoch_prev == state.epoch && record.epoch_new == state.epoch.saturating_add(1)`. This guard is reachable only by an input that already carries the **current** previous-state root (e.g. a root-forged shape); the genuine-old-bundle shape is rejected at step 5 first.
7. Signature verification (`:1061`).
8. Deterministic re-reduce root match (`:1066-1072`) — `NewStateRootMismatch`.
9. Replay-cache observation (`:1073`) — `replay_cache.observe(&record.update_id, record.epoch_new)`, which rejects a duplicate id with `MembershipError::ReplayDetected` (`"membership replay detected"`, `membership.rs:737-742`).

**Apply-path note (amendment 1):** `MembershipError::EpochRegression` is constructed only in `verify_attested_snapshot` (`membership.rs:1513`) — the snapshot-pull verification surface, a different path from `apply_signed_update`. The live stage's expected-rejection set therefore never asserts `EpochRegression`; asserting it on the apply path would grade a correct daemon as failed.

The replay cache (`MembershipReplayCache`, `:728-752`) independently rejects a duplicate `update_id` with `MembershipError::ReplayDetected` (`:737-742`) — the id-dedup layer — and the snapshot-pull verifier separately classifies stale snapshots, constructing `EpochRegression` only there (`verify_attested_snapshot`, `:1513`; prior-identity epoch monotonicity `:1510-1526`, replay classification `:1563-1565`). The comment at `:718-722` is explicit that *"epoch watermark alone still blocks rollback replays for evicted ids (apply_signed_update enforces the strict epoch chain)"* — i.e. both layers must hold. The snapshot identity pair is `(epoch, state_root_hex)` per FIS-0020 (`:1248`); the parsed persisted field is `state_root`, not `max_epoch` (`membership.rs:1546-1549`) (amendment 4).

### 1.3 The chaos corpus names the fault but only as offline fixtures

`StageId::ChaosSignedStateAdversarial` (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs:291-302`, mapped to `"chaos_signed_state_adversarial"` under Chaos / T4Security, with the comment "Clock rollback vs freshness/anti-replay protection — adversarial") is wired in `plan.rs:497-498` and registered in `chaos.rs:125-128` with runner binary `live_chaos_signed_state_adversarial_test` and target class **`ChaosTargets::Offline`** with `--scenario all` (`chaos.rs:129-131`). Reading that binary (`crates/rustynet-cli/src/bin/live_chaos_signed_state_adversarial_test.rs`) shows it is a **fixture generator and in-process validator, not a live test**: `run()` (`:128-163`) generates a fixture manifest to disk, validates it in-process via `generate_manifest`/`validate_manifest`, and writes a JSON report whose own self-description is `"offline signed-state adversarial fixtures generated and pinned to fail-closed expectations"` (`:179`) with security invariants `"offline_only": true`, `"production_state_mutation": false` (`:186-194`). It never contacts a daemon. Notably, its declared stage list **does include** `chaos_replay_old_membership` (`:21-26`): fault *"inject older validly-signed membership update with stale watermark"*, pass criterion *"replay rejected and daemon stays on current snapshot"* — the exact GAP-5 fault class, but realized only as a fixture record, never as a wire-level replay.

### 1.4 The negative-control stages check a different verifier, also offline

`crates/rustynet-cli/src/vm_lab/orchestrator/stage/negative_control.rs` (forgery taxonomy test module `:1533-1706`) mirrors the `live_signed_state_chaos` corpus, but against the **assignment** verifier (`verify_signed_assignment_state_artifact`), not the membership apply path, and in-process. Its `ForgeryKind::Replay` (`:1663-1665`) is *"a genuine, current bundle presented against a strictly-newer persisted watermark"* — a different shape from a previous-epoch bundle. Its own comment (`:1670-1676`) states quorum fault classes are adjudicated on the membership path via *"the offline `chaos_signed_state_adversarial` corpus + the `validate_linux_membership_signature_forgery` audit"* — confirming that path is understood as offline. A repository-wide search found **no stage** that delivers a previous-epoch, previously-valid membership bundle to a running daemon through the normal distribution path with assertions on rejection reason, watermark immutability, and membership-view immutability.

### 1.5 Conclusion of the grounding step

The guards are real and tested at the validator level; the fault is catalogued as an offline fixture; the live cell — the adversarial delivery over the wire to a running mesh node — is genuinely uncovered. A new stage is justified. (Had the verdict been REFUTED, this document would instead record why no stage is needed.)

---

## 2. Stage Design: `live_signed_state_rollback_replay`

### 2.1 Objective

Prove, on a running mesh, that a signed membership bundle from a **previous epoch that was genuinely valid when issued** (correct threshold signatures, correct chain link at its time, never tampered) is rejected by a daemon already holding a strictly newer epoch, that the rejection comes from the ordered membership-apply guard set specifically (primary: `PrevStateRootMismatch`; see §2.3 step 4), and that the daemon's persisted watermark and observable membership view are **byte-identical** before and after the attempt.

### 2.2 Prerequisites and capture model (amendment 3)

The stage runs **after** the standard live membership setup has driven the mesh through at least two real epochs, so that an applied previous-epoch bundle exists. The capture point is the **mint point**: the envelope bytes are captured at the moment the controller mints the epoch E-1 bundle for distribution — the lab distribution path delivers snapshot *files* to nodes, not envelopes (`adapter/linux_membership.rs:136` et al.), so a capture taken at the node would not be the wire object this stage needs. During setup, before the epoch E-1 → E transition is distributed, the stage's runner captures and retains:

- The complete epoch E-1 envelope exactly as minted (serialized bytes at the mint point, so the replay is not a re-forged artifact but the genuine object), pinned with a **SHA-256 digest** recorded in the report artifact. The digest is re-verified immediately before the replay is submitted; a digest mismatch grades `Blocked` (capture corruption says nothing about the control under test).
- As a precondition of the replay step, an **offline decode + signature sanity check** of the captured envelope against the epoch E-2 state must pass (the envelope must decode and its signature must verify against the state it was minted against), proving the capture is a genuinely valid old bundle rather than a malformed-input test.
- A **validity-window guard**: the runner records the envelope's `expires_at_unix` and only submits the replay while `now < expires_at_unix`. An expired envelope is graded `Blocked` (the control was never exercised), never `Failed`.
- The post-transition epoch E bundle, delivered first, so the daemon's watermark is freshly advanced.

Capturing the E-1 envelope at the mint point matters: the distribution path persists snapshot files, and an offline re-serialization could accidentally invalidate signatures or alter canonical bytes, which would turn the test into a malformed-input test instead of a rollback test.

### 2.3 Execution sequence

1. **Advance:** distribute the current epoch E bundle through the normal distribution path. Assert acceptance: the daemon reports the applied update, and its snapshot identity is `(epoch = E, state_root = R_E)` (FIS-0020 pair).
2. **Snapshot:** record the pre-replay membership view: epoch, state root, attestation identity set, and the persisted replay watermark as exposed by the daemon's status/inspection surface. Record **byte digests** of all observability artifacts listed in §2.3 step 5, not only parsed fields.
3. **Replay:** submit the captured epoch E-1 envelope through the daemon's legitimate membership-apply ingestion entry — **local IPC `membership apply`** (`ipc.rs:92-94`, dispatch `daemon.rs:9758`), driven with the **admin-role credential** (role gate `daemon.rs:36873-36883`) so the request passes the documented dual gate (`daemon.rs:9739-9744`). This IPC surface **is** the legitimate apply path; the amendment explicitly **forbids** the snapshot-file-drop mechanism (dropping a crafted snapshot file into the daemon's state directory), which is a different, unauthorized surface (amendment 2).
4. **Assert, all mandatory (fail loud), against the ordered expected-rejection set (amendment 1):**
   - **Rejection at the enforcement point.** The daemon's structured rejection (the IPC response string, `"membership apply rejected: …"`, `daemon.rs:9808`) names one of, in code order:
     1. **Primary:** `PrevStateRootMismatch` — `"previous state root mismatch"` (`membership.rs:1052-1054`). A genuine old-epoch bundle carries the E-1-era `prev_state_root`, which no longer matches the daemon's current state, so **this guard fires first**; it is the expected rejection for the genuine-old-bundle shape.
     2. **Defensive:** `InvalidTransition: "epoch chain mismatch for membership update"` (`membership.rs:1055-1059`) — reachable only by a shape that already carries the current previous-state root (see the §2.5 root-forged offline test).
     3. **Id-dedup:** `ReplayDetected` — `"membership replay detected"` (`membership.rs:737-742`), when the same `update_id` has already been observed.
   - **`EpochRegression` is NOT in the expected set.** It is constructed only in `verify_attested_snapshot` (`membership.rs:1513`), the snapshot-pull surface; the apply path can never produce it. Asserting it would grade a correct daemon as failed.
   - **Wrong-reason rejections.** A rejection for decode failure, invalid signature (`SignatureInvalid`), or expiry (`Expired`) is **`Blocked`, not `Failed`** (amendment 3): the capture or validity plumbing failed and says nothing about the rollback control. A rejection for network-id mismatch remains a **failure** (it means the wrong bundle was submitted).
   - **Watermark unchanged.** The persisted replay watermark still reads `(epoch = E, state_root = R_E)`. Any advance, regression, or state-root change is a failure.
   - **Membership view unchanged.** The post-replay view equals the pre-replay snapshot exactly: same epoch, same state root, same attestation identity set — compared by **byte digest** in addition to the parsed fields. Any drift is a failure.
5. **Report (observability surfaces, amendment 4):** a per-assertion report artifact written to the run's report directory, fail-loud on any miss. The artifact records, per OS, **before/after byte digests of all three artifact classes** in addition to parsed `(epoch, state_root)` fields:
   - the IPC response string (the rejection text itself);
   - the persisted membership snapshot file — Linux `/var/lib/rustynet/…`, macOS `/usr/local/var/rustynet/membership/…`, Windows `C:\ProgramData\RustyNet\membership\…`;
   - the daemon's watermark/log artifacts at the same per-OS locations.
   The parsed persisted field is `state_root`, not `max_epoch` (`membership.rs:1546-1549`).
6. **Fail-loud wiring (amendment 5):** the stage inherits the `AuditVerdict` precedent verbatim (`security_audit.rs:104-125`): `Blocked` is a distinct verdict from `Failed`, and **both fail the stage**; `"blocked"` outranks skip/pass in the run-matrix `status_rank` so a blocked stage can never be read as a pass in the ledger; any node reported as skipped forces the stage verdict `Skipped` **with the node named on disk** (`:89-96`); a **missing report artifact is a failure**, never a pass.

### 2.4 Placement in the orchestrator

- New `StageId` (e.g. `LiveSignedStateRollbackReplay`), name `live_signed_state_rollback_replay`, category Security / T4Security, target class the membership node under test (not `Offline`).
- Registration follows the existing pattern: `stage/mod.rs` id-to-name mapping, `plan.rs` stage-box construction, and a runner binary `live_signed_state_rollback_replay_test` alongside the other `live_*` binaries in `crates/rustynet-cli/src/bin/`.
- Dependency: runs after the live membership validation stage (the mesh must be at epoch ≥ 2 with the capture from §2.2 available); ordered before soak/cleanup.
- The runner shells to the target over the hardened RemoteShellHost seam like other live stages, uses the captured envelope bytes (digest-verified per §2.2), and grades only on the §2.3 assertions.

### 2.5 Offline validator unit tests (implementable now; lab VMs are down)

These tests require no lab and pin the enforcement contract the live stage will exercise:

- Build a `MembershipState` at epoch E. Re-submit a **genuinely valid epoch E-1 update** through `apply_signed_update` and assert `MembershipError::PrevStateRootMismatch` (the `"previous state root mismatch"` guard, `membership.rs:1052-1054`), because the old bundle's `prev_state_root` no longer matches the current state and **that guard fires before the epoch-chain guard** (amendment 1).
- Add a **root-forged shape**: take the epoch E-1 update but set its `prev_state_root` to the daemon's **current** state root, so the prev-root guard passes and the apply reaches the epoch-chain check — assert `InvalidTransition` with `"epoch chain mismatch for membership update"` (`membership.rs:1055-1059`). This is the only shape that reaches the epoch-chain guard on the apply path.
- Same shape against the replay cache directly: `observe` a duplicate `update_id` after `observe(_, E)` asserts the id-dedup layer and surfaces `ReplayDetected` (`membership.rs:737-742`). (`EpochRegression` is out of scope here — it lives on the `verify_attested_snapshot` surface, not the apply path.)
- Assert the watermark and view are untouched after each rejected apply (the validator-level analogue of §2.3 assertions 2-4), comparing byte digests as well as parsed fields.
- Negative-as-positive check: a re-signed bundle at the correct epoch still applies, proving the rejection is epoch-selective, not a blanket refusal.

These tests are the offline half of the deliverable; the live stage remains gated on the preconditions below.

---

## 3. Preconditions Before Implementation Proceeds

1. **Adversarial review of this design** — **complete (2026-09-01).** `LiveLabSignedStateRollbackApplyLayerStageAdversarialReview_2026-09-01.md` returned READY-WITH-AMENDMENTS (5 required); all five amendments are folded into this document (see the note at the top). The review's original attack concerns — capture fidelity, delivery-path purity, false-pass routes, report-forgery resistance — are addressed by amendments 3, 2, 1, and 5 respectively.
2. **Lab availability.** The live cell cannot be proven while the lab VMs are down. Per the live-lab rules, a stage pass is only ever claimed from the stage's own report artifact in the run's report directory, recorded in `documents/operations/live_lab_node_run_matrix.csv` (the `--node` engine's ledger), never from a dry run.

---

## 4. Explicit Non-Goals

- No change to `membership.rs` guards — they are verified correct and are the system under test, not the fix.
- No weakening of the existing chaos fixture corpus — it stays as the offline taxonomy record; this stage adds the live delivery dimension it deliberately does not cover.
- No legacy/fallback delivery path for the replay: one hardened execution path (the daemon's legitimate membership-apply ingestion entry — local IPC `membership apply` with the admin-role credential), per the repo's single-path rule. The snapshot-file-drop mechanism is explicitly forbidden (§2.3 step 3).
