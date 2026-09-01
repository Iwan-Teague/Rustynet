# Live-Lab Stage Design: Role-Transition Side-Effect Ordering Validation (GAP-1)

**Status: DESIGN ONLY — no code changed.** The adversarial review is **COMPLETE** (verdict: READY-WITH-AMENDMENTS, `LiveLabTransitionOrderingStageAdversarialReview_2026-09-01.md`); this document has been amended in place per its findings and is implementation-ready. Implementation remains **owner-gated and lab-pending** (the lab VMs were down on the design/review dates), so every live assertion is *specified but unproven*; the offline unit tests in §4 are runnable today without any VM.

> **Adversarial-review amendments folded (2026-09-01)** — per `GapStageDesignsAmendmentFoldChecklist_2026-09-01.md` §GAP-1 (review §9 numbering):
> - **A1 — rename blast-radius checklist:** every name-keyed reader of `role_switch_matrix` / `live_role_switch_matrix` enumerated (§3.5) to move in the same change as the rename; anchor-capability disambiguation added to §1.1.
> - **A2 — audit-assertion scope pinned to the public-CLI drive path:** all four transition kinds driven via the public CLI per node; assertion (c) scoped to CLI-driven transitions; pre-registered wiring fact (zero `append_role_audit_entry` call sites in `rustynetd`; sole executor `execute_role_plan`) recorded in §2.5 with an offline source-scanning test pinning it (§4 test 7).
> - **A3 — state-based fallback anchor:** every fallback ordering acceptance must anchor liveness to an effect the transition itself performed (fresh process identity, or first-ever observation against a pre-transition absent-service snapshot); unanchored acceptance is a failure (§2 preamble).
> - **A4 — sampling-window honesty:** §2.1(b) gains a trailing stability check (two spaced probes with process-identity equality) and states its semantics as bounded-window liveness evidence, not continuous availability (§2.1).

**Grounding provenance.** This design implements GAP-1 from `LiveLabCoverageGapHuntIndependent_2026-08-31.md` (§2, lines 36–42), which **CONFIRMED** the gap as HIGH severity. The gap-hunt's GAP-2 (failed-deploy negative-residue stage) was **REFUTED** in the same pass and is explicitly out of scope here; nothing in this document proposes building it.

**Decree under test.** `AGENTS.md` §10.7, mirrored by `documents/SecurityMinimumBar.md` §6.D (line 478):

> Adding serves_relay: deploy service BEFORE emitting signed bundle
> Removing serves_relay: undeploy service BEFORE revocation bundle
> Exit NAT: tear down BEFORE removing capability (residue = release-blocker)
> blind_exit is irreversible — requires factory reset
> All transitions emit append-only audit log entries

---

## 1. Problem and Scope

### 1.1 The gap

No live-lab stage asserts the §10.7 ordering invariants. The existing role-switch stage, `crates/rustynet-cli/src/vm_lab/orchestrator/stage/role_switch_matrix.rs`, verifies only that tunnels are alive after role distribution: `RoleSwitchMatrixStage::execute` iterates assignments, calls `adapter.collect_active_tunnels()` on each, and passes each list to `verify_tunnels_active()`, which fails closed on the `wg-not-installed` sentinel ("cannot verify active tunnels: WireGuard enumeration tool not present on node") and on an empty list ("daemon reports no active WireGuard tunnels after role distribution"). That is tunnel liveness — it says nothing about *when* side effects completed relative to bundle/revocation emission, whether the audit log grew, or whether NAT residue was left behind.

Two structural facts sharpen the gap. First, `RoleSwitchMatrixStage::applies_to_roles()` returns `&[]` — the stage applies to no role specifically, so it runs as an unconditional liveness sweep rather than a transition assertion. Second, the stage carries the `#![allow(dead_code)]` suppression and exhibits the GAP-7 naming hazard flagged in the gap hunt: the name "role_switch_matrix" oversells a body that is a matrix of nothing — one directed check (tunnels alive), not a switch matrix at all. Any reader of the stage name would wrongly conclude the §10.7 matrix is proven live.

### 1.2 Why it matters (risk, from the gap hunt, lines 38–41)

An ordering bug is invisible to tunnel liveness. Two concrete failure modes:

- **Relay black hole.** A client→relay transition emits the signed bundle advertising `serves_relay` *before* the relay service is deployed and verified. Peers then route relay frames at a node that answers nothing. Tunnels are alive; the stage passes; the mesh is degraded.
- **Exit residue release-blocker.** An exit→client demotion revokes the exit capability *before* NAT teardown. The NAT table outlives the capability — exactly the "residue = release-blocker" case §10.7 names.

### 1.3 Why existing stages do not cover it

The orchestrator already has three transition-adjacent stages, each proving **one directed side-effect**, never ordering or atomicity across a transition, and none asserting an audit entry:

| Stage | What it proves | Why it is not GAP-1 |
|---|---|---|
| `exit_nat_lifecycle_validation.rs` (191 lines) | NAT table present during active exit service, absent after daemon stop (two-phase snapshot→stop→snapshot); restart + re-assert serving afterward. | Stops a daemon; it does not drive a signed role transition, so there is no bundle/revocation emission to order against. No audit assertion. |
| `exit_demotion_residue_validation.rs` (206 lines) | Demoting a Linux exit to client via the public CLI leaves no residue (NAT torn down, forwarding restored, daemon still running), with an anti-vacuous "was serving exit" pre-capture. | Asserts the *end state* of demotion, not the ordering of teardown vs revocation, and not audit growth. |
| `blind_exit_dataplane_validation.rs` (235 lines) | Per-node nft ruleset self-check with five hardened subchecks, accepted only on explicit `overall_ok:true`. | Static dataplane posture of the blind_exit role; no transition is driven. |

The gap hunt's sweep for §10.7 ordering terms found only comments (`deploy_relay.rs:276`, `macos_anchor_profile_deploy.rs:5`) — the ordering rules exist in prose and in the transition planner, but nothing observes them live.

**Scope disambiguation (review A1):** this stage asserts `serves_relay` bundle-emission ordering — the signed membership bundle advertising the relay capability. It does not concern the *anchor* bundle-pull path, where an anchor node pulls (rather than is pushed) membership state: the two mechanisms both move signed state but play no role in this design's ordering assertions. The stage name and its evidence must never be read as covering anchor capability advertisement.

### 1.4 Scope

In scope: a new (or renamed/extended) `--node` orchestrator stage that drives the four transition kinds listed in §2 and asserts ordering, advertisement-before-verification, audit growth, and residue-free demotion. Out of scope: GAP-2 (REFUTED), the Windows/macOS role-parity cells (own track), and any change to `rustynet-control` transition semantics — this stage *observes* the decree, it does not re-implement it.

---

## 2. What the Stage Asserts, Per Transition Kind

The stage drives each transition on the live mesh **through the public CLI, per node** (review A2: the drive mechanism is pinned to the same public control path §2.4(a) already uses, matching what an operator runs), and asserts four invariant families (a)–(d). "Observable ordering" in the `--node` orchestrator means: evidence artifacts carry wall-clock timestamps captured at each step (side-effect completion, signed-bundle/revocation emission, audit append), and the stage compares them. Where a timestamp alone is ambiguous (same-second events), the stage falls back to state-at-observation — e.g. "the signed bundle containing capability X was already distributed when service Y was first observed live" is a strictly ordered pair regardless of clock granularity — **under the fallback anchor rule (review A3):** a fallback acceptance is valid only when the liveness/absence observation is anchored to an effect the transition itself performed — either (i) a post-transition deploy/restart acknowledgment with a **fresh process identity** (fresh PID / boot-id / start-time relative to a pre-transition capture), or (ii) a **first-ever observation** of the service's state against a pre-transition snapshot that recorded the opposite state (e.g. service absent in the pre-transition snapshot, present for the first time post-transition). Every fallback acceptance records its anchor in the evidence artifact; an **unanchored fallback acceptance is a failure, never a pass**. Every assertion names its evidence artifact in the run's report directory; a missing artifact is a failure, never a pass.

### 2.1 client → relay (adding `serves_relay`)

- **(a) Ordering.** Relay service deployed AND verified live (health observed from the driving node) strictly before the signed bundle advertising `serves_relay` for that node is emitted, and therefore before it can reach any peer. Timestamp of first successful relay liveness probe < timestamp of bundle emission record.
- **(b) Advertisement gate (bounded-window, review A4).** At no observation point does a distributed signed bundle advertise `serves_relay` for the node while the relay service fails a liveness check. The stage samples: after bundle distribution, immediately probe the relay; failure fails the stage. Because point-in-time liveness cannot rule out a deploy-then-crash between samples, the gate closes with a **trailing stability check**: two liveness probes spaced by a fixed settle interval (the interval is recorded in the evidence artifact) with **process-identity equality across them** (same PID/boot-id/start-time — the crash-and-restart case changes identity and fails the check). **Semantics are stated honestly:** this is *bounded-window liveness evidence*, not continuous availability; the residual crash-after-window risk is documented as **out of the stage's claim**.
- **(c) Audit.** The node's role audit log grows by an append-only entry for the transition, with the expected event kind (a preset transition to `relay` that is `SignedMembership` per `TransitionKind`, `crates/rustynet-control/src/role_presets.rs:496`,706-713) and outcome `succeeded` per `RoleTransitionOutcome` (`crates/rustynet-control/src/role_audit.rs:42`). Chain integrity is re-verified with `verify_role_audit_chain` (`role_audit.rs:413`).
- **(d)** Not applicable to this direction.

### 2.2 relay → client (removing `serves_relay`)

- **(a) Ordering.** Relay service stopped/undeployed and verified absent before the signed revocation bundle removing `serves_relay` is emitted. Timestamp of confirmed service absence < timestamp of revocation emission record.
- **(b) Advertisement gate.** After revocation is distributed, no signed state in circulation advertises `serves_relay` for the node (post-revocation membership snapshot check), and the relay port no longer accepts frames.
- **(c) Audit.** As §2.1(c), expected kind `SignedMembership` with the removal direction.
- **(d)** Not applicable.

### 2.3 exit NAT (exit activation / demotion)

- **(a) Ordering, demotion direction (the release-blocker).** NAT teardown completed before the revocation bundle removes the exit capability. The stage reuses the two-phase snapshot discipline of `exit_nat_lifecycle_validation.rs` but anchors both snapshots to transition events, not to a daemon stop.
- **(d) Residue.** After demotion completes, residue == none: NAT table empty of exit rules, forwarding restored, daemon still running — the same residue checklist `exit_demotion_residue_validation.rs` proves for the daemon-stop path, now proven across the *signed revocation* path.
- **(b)** Activation direction: the signed bundle advertising exit capability is emitted only after NAT activation is observed (fail-closed per `SecurityMinimumBar.md` §6.D control 7, line 529: "Exit-serving NAT activation is fail-closed on revocation").
- **(c)** Audit entry as above, expected kind `SignedMembership`.

### 2.4 blind_exit irreversibility

- **(a) Blocked-before-side-effect.** Any attempt to transition *away from* `blind_exit` is rejected by the transition matrix before any side effect executes: `transition_plan` returns `Blocked("blind_exit is immutable; factory reset + fresh key provisioning required to change role")` (`role_presets.rs:624-638`). The stage drives the attempt **via the public CLI per node** (§2.5 pinned drive path) and asserts (i) the CLI fails closed, (ii) role state is unchanged, (iii) no service/undeploy side effects ran (observable via unchanged service inventory), and (iv) an audit entry with outcome `blocked` was appended (`RoleTransitionOutcome::Blocked`, `role_audit.rs:42`).
- **(b) Entering.** Becoming `blind_exit` yields kind `Irreversible("becoming blind_exit wipes node identity and re-enrolls fresh; this cannot be undone without another factory reset")` (`role_presets.rs:706-709`). The live stage does NOT repeatedly wipe the mesh node; see §5 (open question on cost) — the assertion set for entering is planned as: identity wipe + fresh enrollment observable, prior identity absent from membership, audit entry kind `Irreversible`. On the current lab this is exercised only when a blind_exit re-enrollment is already scheduled, not gratuitously.
- **(c)** Audit as above — for the blocked attempt this is the critical observation: §6.D control 6 (`SecurityMinimumBar.md:522`) requires *every* transition (successful/failed/aborted) to emit an entry.
- **(d)** Not applicable (blind_exit forbids NAT by construction; `blind_exit_dataplane_validation.rs` already proves no-NAT posture).

### 2.5 Audit-assertion scope (rewritten per review A2 — the wiring fact is pinned, not deferred)

All four transition kinds are driven **via the public CLI, per node** (§2 preamble), and **assertion (c) is scoped to these CLI-driven transitions**. The review verified the production wiring this scope depends on, and the design pre-registers that verified fact instead of treating audit wiring as an open question:

- **There are zero `append_role_audit_entry` call sites in `rustynetd` today.** Daemon-side bundle application emits no audit entries.
- The **sole production executor** that appends role-audit entries is the CLI-side `execute_role_plan` (`crates/rustynet-cli/src/main.rs:19546`), calling the appender at `main.rs:19633` / `:19636`.
- Consequence: an audit entry exists **if and only if** the transition was driven through the CLI path — which is exactly why the drive mechanism is pinned above. Scoping (c) to CLI-driven transitions makes the assertion testable today rather than unprovable.
- **Offline guard:** a **source-scanning unit test** (§4 test 7) pins this wiring fact — it fails if a `rustynetd` call site for `append_role_audit_entry` appears, so a future daemon-side emitter flips the stage's expectation **deliberately** (the test forces whoever adds the emitter to update the stage's expected-rejection model in the same change).

What the tamper-evident machinery provides (unchanged): `append_role_audit_entry` (`role_audit.rs:241`, atomic single-write append, 0o640 on create, hash-chained to the previous entry), `read_role_audit_log` (`:299`, fail-closed byte cap), `verify_role_audit_chain` (`:413`), and the `TransitionPlan` that prescribes `service_deploys`/`service_undeploys` ordering (`role_presets.rs:555,560`). The stage reads the node's audit log over the existing adapter/SSH plane and verifies the chain off-node (§3.3).

---

## 3. Mechanism

### 3.1 Extend `role_switch_matrix` vs new stage — decision: rename + extend in place

**Chosen:** fold GAP-1 into the existing stage file, renaming it so the name matches the body (this simultaneously resolves the GAP-7 naming hazard, §1.1).

- New id: `RoleTransitionOrderingValidation`; new name string: `live_role_transition_ordering_validation`. The old `role_switch_matrix` name is retired, not aliased — a stale name in the catalog or the run matrix would invite reading old rows as coverage for the new assertions (the run matrix is per-stage-name; §12.3 of `AGENTS.md` warns that a name on a row is not proof of what ran).
- Rationale for extending rather than adding a parallel stage: both the liveness sweep and the ordering assertions share one precondition — a mesh with role assignments distributed — and the transition kinds under test need the tunnel-liveness result as a baseline ("after transition, tunnels still alive"). One stage, one placement in the dependency chain, no duplicated setup. The tunnel-liveness check is retained as a *sub-assertion* (post-transition liveness), which is what the old body actually delivered.
- The `#![allow(dead_code)]` suppression and the empty `applies_to_roles() = &[]` are revisited during implementation: the extended stage declares `applies_to_roles()` covering the roles it actively transitions (exit, relay-capable), so fanout skips on topologies lacking them instead of passing vacuously.

### 3.2 StageSuite placement

Registration goes in the `define_stage_catalog` macro in `crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs` (the current `RoleSwitchMatrix => "role_switch_matrix" @ Live / T1Role` entry at line 219 becomes the renamed entry), keeping the `Live` suite and `T1Role` tier. Dependencies: `[StageId::TrafficTestMatrix]` is retained as the liveness baseline dependency; the transition-driving body additionally requires the membership/bundle machinery proven by the setup stages, which precede TrafficTestMatrix anyway. Downstream consumers: `exit_handoff` currently depends on `StageId::RoleSwitchMatrix`; the rename updates that dependency edge. `orchestrator/plan.rs` construction (match at ~404-417) and the planned-chain ordering test (~883-889) gain the renamed stage at the same chain position — before the exit-chain stages (`ExitDnsFailclosedValidation` → `ExitNatLifecycleValidation` → `ExitDemotionResidueValidation` → `BlindExitDataplaneValidation`) run their directed checks, so a broken ordering fails early with the richest live context.

### 3.3 Reuse

- `OrchestrationContext` assignment/adapter access and the fail-closed "no adapter for '{alias}'" pattern (`role_switch_matrix.rs` execute loop).
- The `OrchestrationContext` literal-construction test pattern from `exit_demotion_residue_validation.rs::no_exit_assignment_fails_closed` for offline tests (§4).
- The two-phase snapshot discipline from `exit_nat_lifecycle_validation.rs` for (d).
- The reported-skips JSON convention (`<stage>.reported_skips.json`, reason string "reported-skipped (named, never a silent pass)") and the `outcome_for(failures, reported_skips)` aggregation from `exit_nat_lifecycle_validation.rs`.
- `verify_role_audit_chain` / `read_role_audit_log` from `rustynet-control::role_audit` for (c) — the stage reads the node's audit log over the existing adapter/SSH plane and verifies the chain off-node.
- `TransitionPlan` (via `transition_plan`, `role_presets.rs:603`) as the *expected* ordering oracle: the stage computes the plan for each driven transition and asserts observed reality matches the plan's `service_deploys`/`service_undeploys` sequencing.

### 3.4 FAIL-LOUD discipline

Per the fail-LOUD live-stage spec: a live result is the stage status; a dry-run never counts as a pass. Concretely: platform/runtime gates write named reported-skips notes and yield `Skipped` — never `Passed` — when nothing executed ("no node executed this validation; N node(s) reported a runtime skip"); a topology with no eligible node skips loudly (the `blind_exit_dataplane_validation.rs` empty-assignment rule: evidence must not promise a check that never ran); every assertion names its evidence artifact, and a missing artifact is a failure.

### 3.5 Rename blast-radius checklist (review A1 — every reader moves in ONE change)

The rename (§3.1) retires `role_switch_matrix` / `live_role_switch_matrix`. A stage name is read by far more tooling than the stage registry; the implementation change MUST update **all** of the following name-keyed readers in the **same change**, or evidence integrity silently degrades (old rows read as coverage of the new stage, or new runs invisible to tooling):

| Reader | Location |
|---|---|
| Stage spec `name` + `logical` fields | `crates/rustynet-cli/src/live_lab_stage_registry.rs:996,1956` |
| Failure digest stage-name keying | `crates/rustynet-cli/src/ops_live_lab_failure_digest.rs:335` |
| Evidence verifier name matching | `crates/rustynet-cli/src/live_lab_evidence_verifier.rs:448,1395-1407` |
| Lab-monitor TUI coverage column construction | `crates/rustynet-lab-monitor/src/data/run_matrix.rs:984` (standalone crate — gate with `./scripts/ci/lab_monitor_gates.sh`) |
| MCP lab-state binary stage tables | `crates/rustynet-mcp/src/bin/lab_state.rs:68,89,110,7357` |
| MCP repo-context binary stage references | `crates/rustynet-mcp/src/bin/repo_context.rs:2115` |
| MCP ai-agent binary stage references | `crates/rustynet-mcp/src/bin/ai_agent.rs:6121,10839` |
| e2e wrappers + their bin target | `scripts/e2e/live_*_role_switch_matrix_test.sh` family |
| Live ledger column family | `documents/operations/live_lab_node_run_matrix.csv` (historical rows stay attributed to the retired name — never re-read as coverage of the new stage; see §5 open question 1) |
| Prompt-doc stage references | `rustynet_live_lab_loop_prompt.md:1256` |

The one-time old-name→new-name ledger note (§5 open question 1's recommendation) is part of this same change: record it in the parity Refresh doc at implementation time.

---

## 4. Offline Validator Unit Tests (runnable now, no VMs)

The lab VMs are currently down, so live-proving is pending lab availability. The following pure/offline tests run today and pin the stage's decision logic without any guest:

1. **Ordering comparator.** Given synthetic (side_effect_ts, bundle_ts) evidence pairs, the comparator accepts deploy-before-advertise and revocation-after-undeploy, rejects both inversions, and rejects equal-timestamp pairs by requiring the state-based fallback. Table-driven, no context needed.
2. **Plan-vs-observed sequencer.** For each of the four transition kinds, `transition_plan(...)` (`role_presets.rs:603`) output is fed as the expected sequence against hand-built observed sequences; mismatch → the exact failure string naming the out-of-order step.
3. **Audit growth verifier.** Build a temp-dir audit log with `append_role_audit_entry` (three chained entries), assert the verifier accepts; then assert: missing entry for a transition kind → failure naming the expected kind; tampered payload → `verify_role_audit_chain` rejects (already unit-tested in `role_audit.rs`, but the stage-level wrapper's mapping of "chain invalid" → stage failure needs its own test).
4. **Empty-assignment fail-loud.** The `exit_demotion_residue_validation.rs` context-literal pattern: empty assignments → `Skipped` with the naming message, not `Passed`; no adapter for an eligible alias → `Failed` "no adapter for …".
5. **Outcome aggregation.** `outcome_for` semantics: any failure → `Failed`; skips only → `Skipped` naming the count; clean → `Passed` (mirrors the `exit_nat_lifecycle_validation.rs` test set).
6. **Blind-exit blocked assertion logic.** Given a synthetic "attempt rejected" CLI result plus unchanged-state evidence, the assertion accepts; a rejected attempt with mutated state evidence is rejected (that combination means the block happened after a side effect — precisely the hazard).
7. **Audit-wiring source scan (review A2).** A source-scanning test that asserts `append_role_audit_entry` has **zero call sites under `crates/rustynetd/src/`** and that the sole production executor remains `execute_role_plan` (`crates/rustynet-cli/src/main.rs:19546`, appender `:19633`/`:19636`). Fails the moment a daemon-side emitter appears, so §2.5's expected model is flipped deliberately, never silently.

Live-proving of §2 (a)–(d) on the real mesh is **pending lab availability** and is the explicit acceptance gate; until a `--node` run records this stage as passed in `live_lab_node_run_matrix.csv` at a pinned commit, GAP-1 remains open regardless of offline test results.

---

## 5. Open Questions and Adversarial-Review Checklist

### Open questions for reviewers

1. **Renaming vs. evidence continuity.** Retiring the `role_switch_matrix` name orphans its historical run-matrix rows (they stay attributed to a name nothing produces anymore). Is that acceptable, or does the rename need a one-time ledger note mapping old name → new? (Recommendation: yes, note it in the parity Refresh doc at implementation time.)
2. **Blind-exit entry cost.** §2.4(b) wiping a mesh node's identity is expensive and disruptive. Should entering-blind_exit be proven only opportunistically (when a re-enrollment is already planned), or does the stage need a dedicated throwaway node? The current lab may not have a spare.
3. **Timestamp trust.** Evidence timestamps come from heterogeneous nodes (Linux/macOS/Windows guests). The design prefers state-based ordering pairs over raw clock comparison wherever an event is observable as a state; reviewers should challenge any remaining raw-timestamp comparisons for clock-skew tolerance.
4. **Audit-log location per platform.** Where each daemon writes the role audit log on macOS/Windows vs Linux was not pinned in this pass; the stage's reader path needs that per-platform answer before implementation.
5. **Scope of "relay verified live".** Minimum viable liveness for the relay service (TCP accept? a control-plane ping? frame round-trip?) should be fixed during implementation and kept consistent with what `rustynet-relay` can self-report.
6. **Cross-OS staging.** Linux first (the done reference per the parity mandate), then macOS/Windows cells — confirm the ordering assertions do not depend on Linux-only observability (e.g. `nft` presence) without a per-platform gate like the existing `*_runtime_implemented` gates.

### Adversarial-review checklist (review COMPLETED 2026-09-01 — verdict READY-WITH-AMENDMENTS; amendments A1–A4 folded into this document, see the header note)

- [ ] Refute the claim that no existing stage covers ordering (re-sweep the stage tree for anything reading bundle-emission timestamps).
- [ ] Refute the extend-in-place decision: does folding liveness + ordering into one stage mask a liveness regression behind an ordering failure (or vice versa)?
- [ ] Attack assertion (c) as unprovable if audit wiring is absent — is "stage fails, failure is the finding" the right disposition, or does it conflate a product bug with a lab-stage bug?
- [ ] Attack the state-based ordering fallback: construct a scenario where both orderings produce the same observable states (false pass).
- [ ] Attack (b) sampling: a bundle distributed and relay-deployed-then-crashed between samples — does the stage catch a capability advertised for a now-dead service?
- [ ] Verify the rename does not silently re-attribute old `role_switch_matrix` rows as coverage of the new stage in any tooling that reads the run matrix.
- [ ] Verify FAIL-LOUD: no code path in the design lets `Skipped`, `dry_run`, or an empty topology read as `Passed`.
- [ ] Confirm GAP-2 remains out of scope and nothing in the mechanism smuggles it back in.
- [ ] Confirm the offline tests (§4) genuinely run without VMs and fail loudly if the production API they pin changes.
- [ ] Confirm the design never weakens §6.D/§10.7 (observation only; no new acceptance path for any transition).
