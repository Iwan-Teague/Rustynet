# Adversarial Review — GAP-1 Live Stage Design (`LiveLabTransitionOrderingStageDesign_2026-09-01`)

- **Date:** 2026-09-01
- **Scope:** Independent adversarial review of the GAP-1 stage design in `documents/operations/active/LiveLabTransitionOrderingStageDesign_2026-09-01.md` (the "design"). Docs-only; no implementation, no code change, no lab run accompanied this review.
- **Method:** Every design citation was re-verified against the working tree at this commit, and each of the eight mandated attacks was answered with either CONFIRMED-SAFE (closing mechanism cited) or RISK (concrete failure scenario + required amendment). Line references below were read from the live files, not copied from the design.
- **Confidence:** Under-claimed by intent. This is a design read plus source verification; no live reproduction was performed (lab VMs were not available). Where a verdict depends on runtime behavior that only a live `--node` run can show, that dependence is stated.

---

## 0) Citation re-verification summary

All load-bearing citations in the design were checked and stand, with three minor line drifts:

| Design claim | Verified at | Result |
| --- | --- | --- |
| `role_switch_matrix.rs` liveness-only body, `wg-not-installed` sentinel, empty-tunnel sentinel, `#![allow(dead_code)]`, `applies_to_roles() -> &[]`, dep on `TrafficTestMatrix` | `crates/rustynet-cli/src/vm_lab/orchestrator/stage/role_switch_matrix.rs:1,11-15,23,38-43,55` | Confirmed |
| Catalog entry `RoleSwitchMatrix => "role_switch_matrix" @ Live / T1Role` | `crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs:219` | Confirmed |
| `exit_handoff` depends on `StageId::RoleSwitchMatrix` | `crates/rustynet-cli/src/vm_lab/orchestrator/stage/exit_handoff.rs:17` | Confirmed |
| Plan construction + planned-chain position | `crates/rustynet-cli/src/vm_lab/orchestrator/plan.rs:404,883` | Confirmed |
| Sibling stage line counts 191 / 206 / 235 | `wc -l` on the three files | Confirmed exactly |
| `outcome_for(failures, reported_skips)` aggregation | `exit_nat_lifecycle_validation.rs:109` | Confirmed |
| Reported-skips JSON convention (`<stage>.reported_skips.json`, "never a silent pass") | `exit_nat_lifecycle_validation.rs:15`, `exit_demotion_residue_validation.rs:15,109,126`, `blind_exit_dataplane_validation.rs:15,25-27,126,142` | Confirmed |
| Context-literal fail-closed test pattern | `exit_demotion_residue_validation.rs:182` (`no_exit_assignment_fails_closed`) | Confirmed |
| Accepted only on explicit `overall_ok: true` | `blind_exit_dataplane_validation.rs:25-27` | Confirmed |
| `TransitionKind::SignedMembership` | `crates/rustynet-control/src/role_presets.rs:507` | Confirmed (design said :496; actual :507 — drift, not substance) |
| `TransitionPlan.service_deploys` / `service_undeploys` | `role_presets.rs:555,560` | Confirmed |
| `pub fn transition_plan` | `role_presets.rs:603` | Confirmed |
| `Blocked("blind_exit is immutable; factory reset + fresh key provisioning required to change role")` | `role_presets.rs:624-638` (string at :629) | Confirmed |
| `Irreversible("becoming blind_exit wipes node identity and re-enrolls fresh; this cannot be undone without another factory reset")` | `role_presets.rs:706-713` (string at :708) | Confirmed |
| `RoleTransitionOutcome` enum incl. `Blocked` | `crates/rustynet-control/src/role_audit.rs:42` (`Blocked` at :48, `as_str "blocked"` at :59) | Confirmed |
| `append_role_audit_entry` (atomic append, `0o640`, hash-chained) | `role_audit.rs:241` (`0o640` at :279) | Confirmed |
| `read_role_audit_log` fail-closed / `verify_role_audit_chain` | `role_audit.rs:299,413` | Confirmed |
| SecurityMinimumBar §6.D heading and decree | `documents/SecurityMinimumBar.md:478` (§6.D), controls 4–5 at ~:508-519 ("Service deploy precedes capability advertisement", "Service undeploy precedes capability revocation"), control 6 at ~:520-523 (tamper-evident audit for **every** transition), control 7 at ~:528-531 (NAT fail-closed on revocation) | Confirmed |

One design claim was checked beyond the design's own list and materially changes two verdicts below: the **production audit wiring is CLI-side only** (Attack 3), and the **`role_switch_matrix` name is read by far more tooling than the design's §3.2 downstream list** (Attack 2).

---

## 1) Attack 1 — Re-sweep: does any existing stage already cover §10.7 ordering?

**Verdict: CONFIRMED-SAFE.** The re-sweep found no stage that reads bundle-emission timestamps, asserts deploy-before-advertise ordering, or asserts role-audit-log growth.

Evidence:

- A case-insensitive sweep of `crates/rustynet-cli/src/vm_lab/orchestrator/stage/` for `timestamp|emitted|emission|advertise|ordering|audit` returns only unrelated hits: `preflight.rs:52` (remote clock readout for harness sync, not evidence ordering), `negative_control.rs:148,197,2347` ("scenario.v1 emission" = control-scenario JSON construction), `anchor_validation.rs:7,58,197,358,569` (`capability_advertisement` = anchor bundle-pull scope label, a different concept from §10.7 capability advertisement), and the `cross_network/scenario/*` route-advertisement helpers (`advertise_default_route`, `POST_ADVERTISE_SETTLE` — kernel route propagation for traversal scenarios, not membership-bundle advertisement). The `audit` term produced **zero** hits in the stage tree.
- The three sibling stages the design characterizes match that characterization exactly (line counts 191/206/235; mechanisms as tabulated in §0). None drives a transition, and none reads an audit log.
- The GAP-2 misread lesson is respected: nothing in the sweep turns on a name or comment; every candidate was opened and its mechanism read. No stage covers ordering, advertisement-before-verification, or audit growth.

The design's §1.1–§1.3 gap claim therefore holds on an independent re-sweep. One adjacent stage worth naming in the design's §1.1 for completeness: `anchor_validation.rs` advertises a *capability pull* check whose wording ("capability_advertisement") superficially resembles §10.7 advertisement; the design should preempt that confusion with one sentence distinguishing anchor bundle-pull from serves_relay bundle emission.

---

## 2) Attack 2 — Extend-in-place rename of `role_switch_matrix`

**Verdict: RISK — confirmed, and wider than the design states.** The design's core rename reasoning (retire the name, never alias it, because per-stage-name ledger attribution would read old rows as coverage of the new assertions) is correct and matches how the ledger actually works: the run-matrix CSVs attribute per-stage results by literal column/stage name, and AGENTS.md §12.3 warns that a name on a row is not proof of a stage's content. But §3.2's downstream-impact list (catalog entry in `stage/mod.rs`, `plan.rs` construction and chain, the `exit_handoff` dependency edge) is **incomplete**. The name is hard-coded in at least the following live readers, none of which the design mentions:

- `crates/rustynet-cli/src/live_lab_stage_registry.rs:996-999` and `:1956-1957` — both the `role_switch_matrix` and `live_role_switch_matrix` specs carry `logical: Some("role_switch_matrix")`; the logical-name mapping must move with the rename or registry-driven tooling keeps resolving the old logical id.
- `crates/rustynet-cli/src/ops_live_lab_failure_digest.rs:335-336` — failure-digest message mapping keyed on `("live_role_switch_matrix", pass|fail)`; an unknown new name silently degrades to a generic digest line.
- `crates/rustynet-cli/src/live_lab_evidence_verifier.rs:448,1395-1407` — chronology evidence and its fixtures/comment key on `live_role_switch_matrix`.
- `crates/rustynet-lab-monitor/src/data/run_matrix.rs:984` — per-role ledger coverage maps `Role::Admin => vec![format!("{prefix}_stage_role_switch_matrix")]`; the TUI's coverage matrix reads ledger **column names** built from this string, so after a rename the column vanishes from the parity dashboard rather than erroring.
- `crates/rustynet-mcp/src/bin/lab_state.rs:68,89,110,7357` — stage aliases and the stage-explain table (`owning: ".../role_switch_matrix.rs"`) used by `explain_stage`; `repo_context.rs:2115,2314` stage table; `ai_agent.rs:6121,10839` stage-name lists.
- `scripts/e2e/live_linux_role_switch_matrix_test.sh` and the windows/macos wrappers (which exec `--bin live_linux_role_switch_matrix_test`) — a focused-stage entry point that would silently keep driving the old name.
- The live ledger `documents/operations/live_lab_node_run_matrix.csv` (per-OS `<os>_stage_role_switch_matrix` column family, same shape as the bash archive header) and prose references (`rustynet_live_lab_loop_prompt.md:1256`, `QualityHardeningTodo_2026-07-25.md:630,6243`).

Failure scenario if the amendment is skipped: the rename lands, the orchestrator and its ledger column adopt `live_role_transition_ordering_validation`, and every reader above keeps looking for `role_switch_matrix` — the lab monitor's per-role coverage silently drops a column, `explain_stage` returns "unknown stage" for the renamed stage, the failure digest loses its message mapping, and the e2e wrapper errors or (worse) a stale cached build keeps exercising the old stage while the ledger records the new one. None of these are unsafe in the security sense, but all of them are silent evidence-integrity degradations — exactly the class of failure this repo's ledger discipline exists to prevent.

**Required amendment (A1):** the design must add a rename checklist enumerating every name-keyed reader above (registry `name` + `logical`, failure-digest mapping, evidence-verifier chronology references, lab-monitor `run_matrix.rs` column construction, the three MCP binaries' stage tables/aliases, the e2e wrapper scripts and bin target, and the loop-prompt doc reference), each updated in the same change as the rename. Historical ledger rows stay attributed to the old names (frozen bash archive is read-only history; the live node ledger's old rows remain historical) — the one-time old→new ledger note the design already recommends in §5.1 should name this checklist as its precondition.

The regression-masking half of the attack (does folding ordering assertions into the liveness stage let an ordering regression hide behind a liveness pass, or vice versa?) is handled by the design's own structure: the tunnel-liveness check is retained explicitly as a *sub-assertion*, and the new ordering assertions fail the stage independently with named artifacts. With A1 applied, CONFIRMED-SAFE on masking; without it, RISK on attribution.

---

## 3) Attack 3 — Audit-entry assertion (c): "stage fails, failure is the finding"

**Verdict: RISK — the forcing-function disposition is right, but only for CLI-driven transitions, and the design does not pin the drive mechanism.**

Verified wiring (this is the decisive fact):

- The audit appender has exactly three production call sites outside `role_audit.rs` itself: `crates/rustynet-cli/src/main.rs:19636` (via `emit_role_audit`, `main.rs:19633`, called from `execute_role_plan`, `main.rs:19546`), `crates/rustynet-cli/src/bin/rustynet-windows-trust-cli.rs:654`, and `crates/rustynet-cli/src/ops_e2e.rs:2717`.
- `execute_role_plan`'s own doc comment (`main.rs:19540-19545`) states it is "the only place that touches the filesystem or sends IPC for role transitions" and that every outcome (blocked, succeeded, failed-mid-execution) emits a tamper-evident audit entry — D12.e.
- **The `rustynetd` crate contains zero `append_role_audit_entry` call sites.** Signed-bundle application on the daemon side has no audit emission today.

Consequences:

- If the stage drives each transition through the node's public CLI (the same plane the design already uses for the blind_exit blocked attempt in §2.4(a)), assertion (c) is satisfiable today: `execute_role_plan` guarantees an entry for every outcome, and the stage's expected-kind/outcome/chain checks (`SignedMembership` per `role_presets.rs:507`, outcomes per `role_audit.rs:42,59`, chain per `role_audit.rs:413`) map onto real, emitted data.
- If the stage instead drives transitions by distributing signed bundles and letting the daemon apply them (arguably the more production-realistic path, and the one `TransitionPlan`'s `service_deploys` ordering presumes), assertion (c) **fails on every transition today** — not because the product violates §6.D control 6 in spirit, but because that control's emission point was never wired into the daemon's bundle-application path. The stage would then report a legitimate product finding *and* an unresolvable stage failure in the same signal, with no way to distinguish them from inside the run.

The design's §2.5 honest-wiring note acknowledges exactly this uncertainty, and its disposition ("the stage fails; that failure is the finding") is the right *epistemics* — an observability forcing function, not an assumption of completeness. But the design as written conflates two different failure causes behind one red stage: (i) product bug — a transition genuinely emitted no audit entry; (ii) harness mismatch — the stage drove the transition through a path that has no emitter. These need different dispositions, and the mandated question ("does it conflate a product bug with a lab-stage bug?") is answered: **it does, unless the drive mechanism is pinned.**

**Required amendment (A2):** pin the transition drive mechanism to the public CLI per node (matching §2.4(a)'s blind_exit approach) for all four transition kinds, and state in §2.5 that (c) is scoped to CLI-driven transitions. Add one sentence pre-registering the expected product finding: daemon-side bundle application currently emits no `RoleTransitionEvent` audit entries (no call sites in `rustynetd`), so a *bundle-driven* variant of (c) — if ever added — must be understood as probing a known-open product gap, and an offline test should pin this wiring fact (e.g., asserting the call-site inventory via a source-scanning test, consistent with the repo's existing boundary-check gates) so a future daemon-side emitter flips the stage's expectation deliberately rather than accidentally.

With A2, the "legit transitions emit no audit entry today" hazard is closed by construction: every CLI-driven transition emits, by the documented and verified single-path guarantee of `execute_role_plan`.

---

## 4) Attack 4 — State-based ordering fallback on timestamp ties: false-pass construction

**Verdict: RISK — a concrete false pass is constructible against the fallback as written.**

The design's fallback: when the deploy-side and advertise-side timestamps tie (or clocks are untrustworthy), accept the strictly-ordered pair "the signed bundle containing X was already distributed when service Y was first observed live." Wait — read carefully, the fallback as worded in §2 asserts *service live at a time when the bundle was already distributed*, which establishes only **overlap**, not order. Two false passes:

1. **Stale-episode pass.** The node previously served relay in an earlier stage or an earlier transition attempt; the relay service was never fully undeployed (or the same service unit is still resident). The stage now drives client→relay, distributes the bundle, probes, and finds the relay live. The fallback's state condition is satisfied — bundle distributed, service observed live — while the *deployment step the transition should have performed* never happened in this episode. The ordering assertion passes against a service instance that predates the transition.
2. **Wrong-instance pass.** The liveness probe (scope deliberately open in §5.5 — TCP accept vs control ping vs frame round-trip) succeeds against a different relay process or a neighbor on a shared port, and the artifact records a live observation that is not evidence about this node's deployment.

The wall-clock primary path has the mirror-image weakness the design already concedes in §5.3 (heterogeneous guest clocks), which is exactly why the fallback exists — so the fallback must be *stronger* than the thing it replaces, not a looser second door.

**Required amendment (A3):** the state-based fallback must anchor its liveness observation to an effect the transition itself performed: acceptable anchors are a service restart/deploy acknowledgment observed after the transition window opened (fresh PID, boot-id, or process start-time recorded in the evidence artifact), or a first-observation-ever of the service on a node where the pre-transition snapshot (the two-phase discipline the design already reuses from `exit_nat_lifecycle_validation.rs`) recorded the service absent. In both forms the fallback becomes "service became live *inside this episode*, after deploy, while the bundle was already distributed" — a genuine order witness. Additionally, every fallback acceptance must record which anchor it used in the named evidence artifact; a fallback acceptance with no anchor recorded is a failure, never a pass.

With A3, the fallback is conservative (it can only accept when the transition demonstrably caused the liveness), and the residual clock-skew concern in §5.3 shrinks to the primary path only.

---

## 5) Attack 5 — Advertisement-gate sampling blind spot (§2.1(b))

**Verdict: RISK — bounded.** The design samples at each observation point after bundle distribution and probes relay liveness immediately. The blind spot: deployment passes the probe, then the relay **crashes after the last sample**. The stage records a pass; the "at no observation point does the distributed bundle advertise serves_relay while the relay fails liveness" invariant was true at every sample and false in the interval after them. Sampling can never close this interval — the best achievable semantics is a *bounded observation window*, and the design should say so rather than imply continuous coverage.

**Required amendment (A4):** (a) require a trailing stability check before accepting (b): two spaced liveness probes (separated by a fixed settle interval recorded in the artifact) plus process-identity equality (same PID/boot-id) across them — this detects the deploy-crash-restart pattern that a single probe misses; (b) state the semantics honestly in §2.1: (b) proves liveness at sampled points across a named window, not continuous availability, and the residual crash-after-window risk is documented as out of the stage's claim. This is consistent with the design's own fail-loud philosophy: an assertion should promise exactly what its evidence can show.

---

## 6) Attack 6 — blind_exit blocked-attempt observability

**Verdict: CONFIRMED-SAFE.** The blocked path is observable end-to-end today, with the exact evidence the design plans to assert:

- `transition_plan` rejects any transition *away from* blind_exit with `Blocked("blind_exit is immutable; factory reset + fresh key provisioning required to change role")` (`crates/rustynet-control/src/role_presets.rs:624-638`, string at :629) — the pre-side-effect gate the design relies on for "blocked before side effect."
- The CLI single-path executor emits an audit entry for blocked attempts: `execute_role_plan`'s `RoleSetPlan::Blocked` arm constructs `RoleTransitionOutcome::Blocked` and calls `emit_role_audit` (`crates/rustynet-cli/src/main.rs:19552-19562`, appender at :19636), with an explicit comment that a blocked transition applied no side effects. `RoleTransitionOutcome::Blocked` serializes as `"blocked"` (`role_audit.rs:59`).
- The stage's four planned assertions (CLI fails closed; role state unchanged; service inventory unchanged; audit entry with outcome `blocked`) therefore all have live, reachable evidence sources, and the entry-vs-state cross-check is exactly the tamper-evident pairing §6.D control 6 wants.

One scoping note carried over from Attack 3: this holds because the blocked attempt is driven through the public CLI. The same amendment (A2) that pins the drive mechanism for (c) covers this cell automatically.

---

## 7) Attack 7 — FAIL-LOUD completeness: nothing reads as Passed that did not run

**Verdict: CONFIRMED-SAFE, with one sharp edge to keep.** The design's §3.4 rules (live result = stage status; dry-run never passes; platform/runtime gates write named reported-skips and yield `Skipped`, never `Passed`; empty eligible-topology skips loudly; every assertion names an evidence artifact; missing artifact = failure) map one-to-one onto proven sibling mechanisms: the reported-skips convention and `outcome_for` aggregation exist and are exercised in `exit_nat_lifecycle_validation.rs:15,109`, `exit_demotion_residue_validation.rs:15,109,126,182`, and `blind_exit_dataplane_validation.rs:15,25-27,126,142` — the latter's "accepted only on an explicit `overall_ok: true` … never a silent pass" doc comment is the exact precedent. The planned offline tests (§4 items 4 and 5: empty-assignment → Skipped-naming-message; any failure → Failed) verify the aggregation itself, so a future edit that lets skips collapse into a pass fails in CI, not in the lab.

The sharp edge: `Skipped` is loud *inside the stage*, but its meaning downstream depends on the run-matrix recording skip as distinctly-not-pass — which it does (`not_run`/`skip` are recorded statuses and AGENTS.md §12.3 already instructs that a row's pass/fail claim must be read from the stage's own report artifact, never the column). The design should cite that convention in §3.4 so the skip path's end-to-end loudness (stage artifact → matrix row → report artifact) is explicit. No amendment required; this is a documentation addition to the design, foldable into the A1 rename note since both touch how ledger rows are read.

---

## 8) Attack 8 — Does the design weaken §10.7 / SecurityMinimumBar §6.D anywhere?

**Verdict: CONFIRMED-SAFE.** The design is observational by construction: it re-uses `transition_plan` (`role_presets.rs:603`) as the expected-ordering oracle rather than re-implementing transition semantics, asserts against artifacts, and introduces no new acceptance path — a stage pass adds evidence; a stage fail removes none of the decree's force. The decree's text is accurately quoted: deploy-before-advertise and undeploy-before-revocation are controls 4 and 5 of §6.D (`SecurityMinimumBar.md` ~:508-519), the every-transition audit mandate is control 6 (~:520-523), NAT fail-closed on revocation is control 7 (~:528-531), and the §10.7 mirror in AGENTS.md matches.

Two places deserved scrutiny and pass it:

- The state-based fallback (§2) is the only mechanism that could read as "a second way to accept ordering." As written it *is* weaker than raw timestamp comparison; with amendment A3 it becomes strictly evidence-typed and conservative, so no acceptance path is weakened.
- §2.4(b)'s "exercised only when blind_exit re-enrollment is already scheduled, not gratuitously" could be misread as a standing excuse to skip the irreversible-entry cell. It is not an acceptance path: the design's own §3.4 requires the unexecuted cell to surface as a named skip, which keeps the gap visible in every run where it is not exercised. Keep the wording "named skip, never a silent pass" attached to this cell explicitly when implementing.

Nothing in the design re-implements, relaxes, or re-routes any §6.D control; GAP-2 stays out of scope as claimed.

---

## 9) Overall verdict

**READY-WITH-AMENDMENTS.** The design's gap analysis is independently re-confirmed (no existing stage covers §10.7 ordering, advertisement-gating, or audit growth); its citations are accurate to the code with only trivial line drift (`SignedMembership` at `role_presets.rs:507`, not :496; the Blocked string at :629; `as_str "blocked"` at `role_audit.rs:59`); its FAIL-LOUD machinery reuses proven sibling mechanisms; and the blind_exit blocked cell is fully observable today. Four amendments are required before implementation:

1. **A1 (rename blast radius):** add a checklist covering every name-keyed reader of `role_switch_matrix` / `live_role_switch_matrix` — `live_lab_stage_registry.rs:996,1956` (name + `logical`), `ops_live_lab_failure_digest.rs:335`, `live_lab_evidence_verifier.rs:448,1395-1407`, `rustynet-lab-monitor/src/data/run_matrix.rs:984`, `rustynet-mcp` `lab_state.rs:68,89,110,7357` / `repo_context.rs:2115` / `ai_agent.rs:6121,10839`, the `scripts/e2e/live_*_role_switch_matrix_test.sh` wrappers and their bin target, the live ledger column family, and `rustynet_live_lab_loop_prompt.md:1256` — all updated in the same change; also add the one-sentence anchor-capability-advertisement disambiguation from §1 above to §1.1.
2. **A2 (audit wiring scope):** pin all four transition kinds to the public-CLI drive path, scope assertion (c) to CLI-driven transitions, and pre-register the verified fact that daemon-side bundle application emits no audit entries today (zero `append_role_audit_entry` call sites in `rustynetd`; sole production executor `execute_role_plan`, `main.rs:19546`, appender :19633/:19636) — so a (c) failure means a broken CLI path, never a silently-unwired daemon path, and a bundle-driven (c) variant is understood as probing a known-open product gap.
3. **A3 (fallback anchor):** the state-based ordering fallback must anchor liveness to an effect the transition itself performed (post-transition deploy/restart acknowledgment with fresh process identity, or first-ever observation against a pre-transition snapshot recording the service absent); every fallback acceptance records its anchor in the evidence artifact, and an unanchored fallback acceptance is a failure.
4. **A4 (sampling window):** §2.1(b) requires two spaced probes with process-identity equality (trailing stability check) before acceptance, and states its semantics as bounded-window liveness evidence rather than continuous availability.

With A1–A4 folded into the design, implementation can proceed; the live-proving acceptance gate (a recorded pass in `live_lab_node_run_matrix.csv` at a pinned commit) remains the design's own stated condition for closing GAP-1, unchanged by this review.
