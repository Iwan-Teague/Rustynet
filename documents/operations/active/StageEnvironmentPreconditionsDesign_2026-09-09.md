# Stage Environment Preconditions — `requires()` / `provisions()` (design)

Status: DESIGN ONLY — docs-only, no code changed. Counterpart to `NodeEngineAuditConsolidation_2026-09-08.md` §2-B, `LiveLabExtensibilityAssessment_2026-09-08.md` §8 rank 1 / §9 item 6, and `LiveLabModularisationProposalReview_2026-09-08.md` (which redesigns this as "grammar-forced `requires()` + producer-side post-conditions"). Precedent to mirror: QH-83 evidence-on-pass (`EvidenceOnPassDesign_2026-09-08.md`, merged `0e7ab8c4`), whose declarations live in the `define_stage_catalog!` macro as a compile-forced fifth column — not a trait method with a default. Every claim below was verified by opening the cited file at the cited line on the tree at the design date.

## 1) Problem

The `--node` engine validates a plan's *structural* health (duplicate ids, missing dependencies, cycles — `runner.rs:410-441`) but nothing validates a plan's *environmental* health: whether the lab supplies the preconditions each stage silently assumes. The consequences are on record:

- **QH-80** — `relay_forwards_frame_validation` was wired, catalogued, and documented, then went unexecuted for its entire life because no lab path ever minted a relay traversal candidate or distributed relay session material. Every lab bundle mint carries `relay_id: None`: `ops_e2e.rs:3770-3775` (exit bundle Host candidate), `ops_e2e.rs:3789-3794` (client bundle), `ops_e2e.rs:3943-3948` and `ops_e2e.rs:3950-3955` (`traversal_candidates_for_target`). The daemon consumer `load_relay_client` (`rustynetd/src/daemon.rs:4983`) returns `None` without that material, and the stage's own pre-checks (`relay_forwards_frame_validation.rs:83-164`) all pass — the missing facts live *below* the stage layer, invisible to it. Discovered 2026-09-08 on the first-ever execution, three months after the stage was added.
- **Hard-required roles are undeclared.** Seven stages fail at runtime with `"no Exit node in assignments"` (or stage-specific variants) when the topology lacks an Exit: `membership_init.rs:36-40`, `distribute_assignments.rs:283-285` (Setup), `exit_handoff.rs:27-29`, `active_exit.rs:58-61`, `exit_dns_failclosed_validation.rs:45-49`, `exit_nat_lifecycle_validation.rs:41-45`, `exit_demotion_residue_validation.rs:46-50` (Live). The audit consolidated this as "three setup stages hard-require an Exit"; on the tree today the Setup count is two (`membership_init`, `distribute_assignments`) — the remaining five are Live-suite exit stages. None of this is knowable from the plan.
- **Skips swallow holes.** `live_two_hop_validation.rs:43-62` returns `Skipped` when the topology lacks an entry node or second client, and `deploy_relay.rs:93-97` / `admin_issue.rs:33-38` do the same for their roles. `Skipped` is non-blocking (`error.rs:304-309`), so an environment hole becomes a non-event — the exact hazard the extensibility assessment names: "a stage that returns `Skipped` for a condition that should be `NotProven` converts a hole into a non-event."
- **Advertised capability ≠ deployed runtime.** Before `deploy_relay.rs` existed, the orchestrator advertised `relay_host` in signed membership but never installed the relay runtime (`deploy_relay.rs:13-18` doc) — the same class of gap, closed then only by adding a stage, not by a general check.

What is missing is a typed, declarative vocabulary for these preconditions, validated at the two seams that already exist: plan construction (`StateMachineRunner::new` → `validate_plan`, `runner.rs:56-64`) and the run loop (`run_with_observer_and_pre_cleanup_hook`, `runner.rs:115-208`) — the same seams QH-83 used.

## 2) Fact vocabulary

Two classes of facts, because they have two different truth sources and two different failure modes:

**Topology-declared facts** — computable at plan time from the resolved node assignments and plan-builder elections the run already carries. No stage provisions them; the plan itself is the producer. Absence is a property of the requested run, not a defect.

**Produced facts** — artifacts of the run itself, minted by a producer stage at the verified production point. Absence when a requirer is planned is a plan defect (nothing supplies it) or a producer defect (it passed without producing).

Proposed closed enum (grow by adding variants; the gates below force every new variant to be reckoned with):

```rust
pub enum EnvFact {
    // Topology-declared: evaluated at plan construction from
    // PlanBuilder output (resolved assignments + election flags).
    ExitNodePresent,        // requirers: membership_init, distribute_assignments,
                            //   exit_handoff, active_exit, exit_dns_failclosed_validation,
                            //   exit_nat_lifecycle_validation, exit_demotion_residue_validation
    AdminNodePresent,       // requirer: admin_issue (today: runtime Skipped, admin_issue.rs:33-38)
    AnchorNodePresent,      // requirer: anchor_validation (phase 2, after audit)
    RelayNodePresent,       // requirers: deploy_relay, relay_validation,
                            //   relay_forwards_frame_validation (chain root)
    EntryNodePresent,       // requirer: live_two_hop_validation (alias_matching_label, :233-238)
    SecondClientPresent,    // requirer: live_two_hop_validation (ssh_params_for_second_client, :268-275)
    BlindExitNodePresent,   // requirer: blind_exit, blind_exit_dataplane_validation (phase 2)
    MacosAnchorValidatorsElected,   // requirers: the 3 MacosAnchor* stages
    MacosRoleTransitionElected,     // requirer: macos_role_transition
    MacosRebootRecoveryElected,     // requirer: macos_reboot_recovery
    SecondUnderlayPresent,          // requirers: cross-network stages; source: substrate_record

    // Produced: recorded by the named producer at the verified production point.
    MembershipSnapshotIssued,       // producer: membership_init (bundle content)
    AssignmentsDistributed,         // producer: distribute_assignments
    TraversalBundlesDistributed,    // producer: distribute_traversal
    DnsZoneDistributed,             // producer: distribute_dns_zone
    RelayServiceDeployed,           // producer: deploy_relay (per-node systemd unit active)
    RefreshedSignedBundlesIssued,   // producer: refresh_signed_bundles
    SubstrateConfigured,            // producer: cross_network_substrate_setup
    RelayCandidateMinted,           // producer: NONE today — the QH-80 hole, made explicit
    RelaySessionMaterialDistributed,// producer: NONE today — the QH-80 hole, made explicit
}
```

`RelayCandidateMinted` and `RelaySessionMaterialDistributed` having no producer is the point: the plan gate (§3.2) turns that from a three-month runtime surprise into a day-one offline refusal. The future producer is named by `RelayElectionPolicyDesign_2026-09-08.md` (standing relay candidate in every admitted pair's signed traversal bundle; the mint site is the same bundle path `ops_e2e.rs:3763-3799` already exercises) — when that lands, `distribute_traversal` gains the provision and the Disruptive cell becomes plannable.

Vocabulary is deliberately *capabilities-of-the-environment*, not outcomes-of-stages: `RelayServiceDeployed` is a fact because a later stage (`relay_forwards_frame_validation`) composes with it; `TrafficTestMatrixPassed` would not be a fact — stage ordering already covers result dependencies.

## 3) Mechanism

### 3.1 Catalog columns (compile-forced, mirroring `StageEvidence`)

The QH-83 review (`LabInfrastructureDesignsReview_2026-09-08.md`) established why this is a catalog column and not a trait method: macro-generated stage families (`cross_network.rs`, `chaos.rs`) share one struct body, so a defaulted trait method would let one default decide for ~20 stages silently. The catalog macro (`stage/mod.rs:229-274`) already forces a fifth `Evidence` column per row; add a sixth and seventh:

```rust
// stage/mod.rs
pub const NO_ENV_REQUIREMENTS: &[EnvFact] = &[];
pub const NO_ENV_PROVISIONS: &[EnvFact] = &[];

// define_stage_catalog! row shape becomes:
//   Variant => "wire_name" @ Suite / Tier / Evidence / Requires / Provisions
// generating, by the same total-match construction as evidence() (stage/mod.rs:269-271):
//   pub fn requires(&self) -> &'static [EnvFact]
//   pub fn provisions(&self) -> &'static [EnvFact]
```

A row without both columns does not parse; "nothing" must be spelled `NO_ENV_REQUIREMENTS` / `NO_ENV_PROVISIONS`, exactly as QH-83 made "no witness" be spelled `None { reason: PHASE1_EVIDENCE_PENDING }`. The 82nd stage forces its own conscious declaration with the compiler as the totality gate.

Phase-1 rows that matter:

```rust
MembershipInit => ... / &[EnvFact::ExitNodePresent] /
    &[EnvFact::MembershipSnapshotIssued],
DistributeAssignments => ... / &[EnvFact::ExitNodePresent, EnvFact::MembershipSnapshotIssued] /
    &[EnvFact::AssignmentsDistributed],
RelayForwardsFrameValidation => ... /
    &[EnvFact::RelayNodePresent, EnvFact::RelayCandidateMinted,
      EnvFact::RelaySessionMaterialDistributed] / NO_ENV_PROVISIONS,
LiveTwoHopValidation => ... / &[EnvFact::EntryNodePresent, EnvFact::SecondClientPresent] /
    NO_ENV_PROVISIONS,
DeployRelayService => ... / &[EnvFact::RelayNodePresent] / &[EnvFact::RelayServiceDeployed],
```

All remaining stages carry `NO_ENV_REQUIREMENTS` initially — the honest "self-guarded, audit pending" state, mirroring `PHASE1_EVIDENCE_PENDING`, to be filled per-suite batches with a live re-verify per batch (the QH-83 landing order).

### 3.2 Plan-construction gate (offline)

Extend `validate_plan` (`runner.rs:410-441`), which QH-83 already extended for malformed `File` evidence paths (`:425-427`). New pass after the existing dependency checks:

```rust
// For each planned stage s, for each fact f in s.requires():
//   if topology_satisfies(resolved_plan, f) { continue; }        // topology-declared fact
//   let providers: Vec<_> = planned.iter()
//       .filter(|p| p.provisions().contains(&f)).collect();
//   match providers.as_slice() {
//     [p] if reaches_via_dependencies(s, *p) => (),              // exactly one provider,
//     [] | [_] | [..] => return Err(format!(                     // and the requirer actually
//       "stage `{s}` requires env fact {f:?} that no planned stage provisions \
//        (or its provider is not a transitive dependency)")),    // depends on it
//   }
// Duplicate providers of the same produced fact across the plan => Err.
```

`reaches_via_dependencies` walks only real `dependencies()` edges — `ordering_after` edges are ordering-only and silently ignored for missing stages (`runner.rs:448+`, documented in the extensibility assessment §3), so they must not count as supply. A provider the requirer does not depend on is refused because topological order does not guarantee it ran *before* the requirer.

Refusal is offline — the plan never launches. QH-80 dies here on day one: `--enable-relay-forwarding-validation` with no producer of `RelayCandidateMinted` refuses at plan construction, naming the fact, instead of failing 90 s into the first-ever live run three months later.

### 3.3 Runner gate (pre-execute) and provisions check (post-Passed)

Two checks in the run loop, at the seams QH-83 established:

- **Pre-execute, blocking, never `Skipped`:** in `run_with_observer_and_pre_cleanup_hook`, after `skip_decision` (`runner.rs:147`) and before `observer.stage_started` (`:157`) — if any `id.requires()` fact is not satisfied (not topology-satisfied and not in the produced-fact ledger), the stage does not execute; the outcome is `NotProven { reason: RequiredCapabilityAbsent, detail }`. `RequiredCapabilityAbsent` already exists and already means exactly this (`error.rs:240-243`: "the release cell DOES claim it and it is missing"); `NotProven` is blocking (`:304-309`) and cascades through the existing dependency cascade. This is the fail-closed form the audit specified: a missing fact must never degrade to `Skipped`.
- **Post-Passed, declaration-lies catch:** extend the QH-83 seam (`runner.rs:186-196`, `if matches!(outcome, Passed)`), sequencing after `verify_declared_evidence`: if the stage passed but a declared provision is absent from the ledger (the producer never recorded it), demote to `NotProven`. A stage that claims to provision something it did not record is lying in its declaration; the run says so instead of green-lighting dependents into the pre-execute refusal.

### 3.4 Fact recording (content-keyed, wrong-party-refused)

`OrchestrationContext` (context.rs:185) gains `record_env_fact(&mut self, stage: StageId, fact: EnvFact, witness: &str) -> Result<(), String>`:

- **Recorder validated against the catalog**: `stage.provisions().contains(&fact)` or refuse — a stage cannot mint facts it does not declare (wrong-party refusal). This also makes the provisions column load-bearing in the direction that matters: a producer whose declaration is missing fails its own post-Passed check.
- **Witness is content, never outcome**: the recorder is called at the verified production point with a content-derived witness — bundle bytes just written and verified, per-node systemd unit state confirmed, substrate record digest — not "because the stage returned `Passed`". `RelayServiceDeployed` is recorded by `deploy_relay` after `adapter.deploy_relay_service()` confirms the unit per node (`deploy_relay.rs:107-126`), not from `outcome_for`.
- Produced facts live for the run (ledger in `OrchestrationContext`, serialized into the report state like `stage_outcomes`).

### 3.5 Visibility: `planned_out` in `node_stage_plan.json`

Topology facts are evaluated at plan time, so absence is knowable before the run: for each planned stage whose topology-declared requirement is unsatisfied by the requested topology, the plan artifact records `planned_out: [<fact>, ...]` beside the existing additive `evidence` field. This is additive; `schema_version` stays 1 (QH-83 §5 precedent — the consumer `write_node_stage_result_ledgers` pins v1). This answers decision (g) honestly: `live_two_hop_validation` on a 2-node Linux run is *declared out of plan scope* — visible in the artifact before the run, non-blocking because the run legitimately does not claim that scenario — instead of surfacing as a mid-run `Skipped` that reads as a non-event. The runtime skip guards remain as belt-and-braces and become unreachable on plans that passed the gate.

## 4) Fail-closed analysis

| Input | Behavior |
| --- | --- |
| Required fact absent (topology) | Plan records `planned_out` (stage does not claim the scenario); if the stage is also dependency-supplied it still runs guarded. Never silently green. |
| Required fact absent (produced, no provider planned) | Plan refused offline at `StateMachineRunner::new`, naming stage + fact (the QH-80 mutation). |
| Required fact absent at runtime (provider ran, did not record) | Pre-execute gate: `NotProven{RequiredCapabilityAbsent}`, blocking, cascades to dependents. Never `Skipped`. |
| Provider planned but not a dependency of the requirer | Plan refused — ordering between them is not guaranteed. |
| Duplicate providers of one fact | Plan refused — one producer per fact, ambiguity is a defect. |
| Provider passed but never recorded its provision | Post-Passed check demotes to `NotProven` (declaration lie caught at the producer, not at the victim). |
| Wrong-party recording (`record_env_fact` from a stage that doesn't declare the provision) | Refused with an error; the fact is not minted. |
| Declaration lies the other way (requires omitted, stage assumes anyway) | Not caught by the gates — same residual as QH-83: declarations are trusted once written. Mitigated by the audit batches (§5) and by the compile-forced column making omission an explicit `NO_ENV_REQUIREMENTS` someone wrote on purpose. |
| Stale produced fact (recorded in an earlier run) | Ledger is per-run state in `OrchestrationContext`; no cross-run carry-over exists, so staleness cannot arise. Cross-run reuse of stage results remains the existing `Reused{digest}` mechanism, untouched. |
| `EnvFact` enum grows | Compiler forces the plan gate's match and any exhaustive consumers to reckon with the new variant; catalog rows re-totaled (same construction as `evidence()`). |

## 5) Flag-day analysis

81 catalog stages; default plan 66 (`plan.rs:614-618`). Phase-1 declarations and their effect on the two reference plans:

| Stage (suite) | Phase-1 `requires()` | Default 66-plan | 2-node Linux run (exit+client) | vs today |
| --- | --- | --- | --- | --- |
| membership_init, distribute_assignments (Setup) | `ExitNodePresent` | Satisfied (engine's own topology requires an exit) | Satisfied | Outcome-identical: exit-less topologies already `Failed` at `membership_init.rs:40` / `distribute_assignments.rs:285`; refusal just moves earlier, offline. |
| 5 Live exit stages (exit_handoff, active_exit, exit_dns/nat/demotion) | `ExitNodePresent` | Satisfied | Satisfied | No new refusals possible: any exit-less plan is already refused by the Setup requirers above. Pure declaration value. |
| live_two_hop_validation (Live) | `EntryNodePresent`, `SecondClientPresent` | `planned_out` on topologies lacking them (default full topology may carry them; 2-node does not) | `planned_out` recorded pre-run; runtime skip (`live_two_hop_validation.rs:43-62`) becomes unreachable | Visibility upgrade only: same non-blocking posture, now declared in the plan artifact instead of a mid-run skip. |
| deploy_relay, relay_validation (Live) | `RelayNodePresent` | `planned_out` on relay-less topologies (the default) | `planned_out`; today's `Skipped("no node ... assigned the relay role")` (`deploy_relay.rs:93-97`) becomes unreachable | Visibility upgrade: skip-noop → run `Partial` semantics preserved via plan artifact. |
| relay_forwards_frame_validation (Disruptive, opt-in `--enable-relay-forwarding-validation`) | `RelayNodePresent`, `RelayCandidateMinted`, `RelaySessionMaterialDistributed` | Not in default plan; when opted in: **plan refused offline** (no producer of the two produced facts exists) | Same refusal | **The one deliberate behavior change.** Strictly better: the alternative today is a runtime `Failed` 90 s in (QH-80's exact discovery), or a false green if the guard were ever softened. |
| All other 71 stages | `NO_ENV_REQUIREMENTS` | — | — | No change. |

The QH-83 flag-day precedent is the working hazard model: its gate would have demoted every Linux-exit run because `membership_init`'s only stage-log append was macOS-exit-specific. The phase-1 set above avoids the equivalent by declaring only facts whose satisfaction is already enforced (or already skipped) at runtime — every phase-1 row is either outcome-identical, a visibility upgrade, or the intended refusal.

Honest phase-1 default: framework + the table above; 71 of 81 rows carry `NO_ENV_REQUIREMENTS` = "self-guarded, audit pending", filled in per-suite batches (Setup first, then Live exit family, then macOS-elected, then CrossNetwork/Chaos/NegativeControl) with a live re-verify after each batch, the QH-83 landing order.

## 6) Test plan (each test names the mutation it catches)

1. `catalog_columns_compile_forced` — delete the Requires column from one row → the macro fails to parse (catches: a stage sneaking in undeclared; mirrors the QH-83 test).
2. `plan_refuses_unprovisioned_fact` — request `--enable-relay-forwarding-validation` with no producer of `RelayCandidateMinted` → plan refused offline naming stage + fact (catches: the QH-80 mutation — a stage assuming an environment no stage mints).
3. `plan_refuses_unreachable_provider` — provider planned but not a transitive dependency of the requirer → refused (catches: supply-by-coincidence-of-ordering).
4. `plan_refuses_duplicate_provider` — two stages declare the same provision → refused (catches: ambiguous provenance).
5. `runner_blocks_missing_produced_fact` — provider executed but did not record; requirer's pre-execute gate returns `NotProven{RequiredCapabilityAbsent}` and never calls `execute` (catches: Skipped-shaped hole, the `live_two_hop` hazard class).
6. `not_proven_cascades` — dependents of the blocked stage get the dependency-cascade skip with `mark_blocked` (catches: a dependent running against an unsupplied environment).
7. `record_env_fact_refuses_wrong_party` — a stage not declaring the provision calls `record_env_fact` → `Err`, fact not minted (catches: minting by whoever feels like it).
8. `provisions_recorded_from_content_not_outcome` — producer records with a content witness; a `Passed` outcome with no recorded provision demotes via the post-Passed check (catches: declaration lies, green without production).
9. `planned_out_recorded_for_topology_absence` — 2-node plan: `live_two_hop_validation` row in `node_stage_plan.json` carries `planned_out: [EntryNodePresent, SecondClientPresent]`, `schema_version` still 1 (catches: the skip-as-non-event invisibility; catches schema drift).
10. `topology_fact_satisfied_passes_silently` — full topology: no `planned_out`, stages run unguarded-by-the-gate (catches: false blocking — the gate must not fire on satisfied facts).

## 7) Effort

- Framework: `EnvFact` enum, two catalog columns + codegen, `validate_plan` extension, run-loop pre-execute gate, post-Passed provisions check, `record_env_fact`, `planned_out` serialization — ~2–2.5 d (the QH-83 seams are already open; the gates are small additions at both).
- Vocabulary audit: open all 81 stage files, classify assumptions into facts, write declarations per suite — ~3–4 d (judgment-heavy; the extensibility assessment's stage reads are the head start).
- Phase-1 declarations + tests + live re-verify per batch — ~1–1.5 d.
- Total ≈ 6.5–8 d.

Sequencing dependency: lands *after* QH-83 (merged `0e7ab8c4`) — same runner seam, and this doc's post-Passed check extends the QH-83 check. Independent of the `RelayElectionPolicyDesign` producer work; that design removes the refusal in §5's last row when it lands.

## 8) Owner decisions

1. **Two fact classes and `planned_out` semantics** — topology-declared facts evaluate at plan time and absent ones are recorded as `planned_out` (visible, non-blocking: the run does not claim that scenario); produced facts are ledger-recorded and absent ones block. This adopts "honest topology declaration" over converting `live_two_hop_validation`'s skip into `NotProven` (decision (g)) — a 2-node run is not defective for lacking an entry node, but it must say so in the artifact.
2. **Offline refusal for unprovisionable cells** — a planned stage whose produced facts nothing supplies refuses the whole plan rather than running to a runtime `NotProven` (decision (d)); the runtime gate remains as the producer-defect backstop.
3. **Phase-1 `NO_ENV_REQUIREMENTS` mass** — 71 of 81 rows declare nothing initially; is the minimal phase-1 exception set (§5 table) accepted as the flag-day-safe v1, with per-suite audit batches to follow?
4. **One producer per fact** — duplicate providers refused at plan construction rather than "last writer wins"; accept the rigidity (refactoring a mint between stages requires moving the declaration in the same change).
5. **Content-keyed recording with wrong-party refusal** — `record_env_fact` validates the recorder against the catalog `provisions()` column and requires a content witness; confirm this is the right seam (versus, e.g., deriving provisions from report artifacts post-hoc, which reintroduces outcome-keyed trust).
