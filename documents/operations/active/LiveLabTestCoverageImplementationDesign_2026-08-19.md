# Live-Lab Test-Coverage Implementation Design — 2026-08-19

Status: **DESIGN ONLY.** No test code, product code, build, VM action, or benchmark action was performed. A second, source-verified adversarial pass (2026-08-19, §8) confirmed every original citation and found three items that blocked starting L0: TUI-launcher disposition, native TSV v2 compatibility, and two pre-existing defects (`runner.rs:130` cleanup-skip ordering; unenforced single-writer contract) L0 would otherwise silently build on. **All three are now resolved at the design level** (2026-08-19, inlined at §3.1.1/§3.2/§3.4, summarized in §9) — still no code written; one narrow confirmation pass on the three resolutions is recommended before implementation starts.

Parent discovery: [LiveLabCoverageGapDiscovery_2026-08-19.md](./LiveLabCoverageGapDiscovery_2026-08-19.md).

This is the implementation route for the missing live-lab coverage. It is deliberately strict: a stage passes only after it has obtained all required evidence for its exact claim. It must never pass because a command returned zero, a service bound a port, a state file parsed, an old handshake exists, an unavailable platform was silently skipped, or another less-specific scenario happened to work.

Every slice below needs adversarial review before code. This document does not authorize changing any product security contract merely to make a test runnable.

## 1. Binding constraints

| source | binding effect |
| --- | --- |
| Requirements §6.2 | Direct P2P, relay fallback, automatic failback, signed/fresh endpoint hints, and protected-mode failure are product behaviors, not optional lab features. |
| Requirements §6.3 | Backend capability must be explicit. A WireGuard-specific result never certifies another backend. |
| SecurityMinimumBar §3.8 | Direct/relay transitions preserve authenticated, replay-protected, freshness-bounded state. Failover/failback cannot bypass ACL, trust, or leak controls. |
| SecurityMinimumBar §§4–6 | Relay faults, negative abuse tests, leak tests, traversal integrity, protocol-filter tests, audit evidence, and privileged-boundary checks are quality obligations. |
| NodeEngineAcceptanceSpec §§3–5 | T5 proves the engine creates the correct RED. Skip, not-run, reuse, timeout, and abort are never GREEN. Evidence is independently recomputed. |
| CrossNetworkSubstrateIntegrationSpec §0 | Cross-network scenarios use its substrate/scenario seam. Do not build a second harness or retain a cargo-run/shell fallback path. |
| repository operating contract | Rust-first, argv-only privileged work, default deny, fail closed, no security downgrade, no secrets in artifacts. |

Current resource constraint: no compilation, live lab, benchmark, or load-generating test was run. Later execution uses one focused disposable scenario at a time. Soak/capacity work gets an explicit resource window and never runs beside the user's benchmarks.

## 2. Non-negotiable test semantics

### 2.1 Pass is a proof certificate, not an exit code

Every new live scenario uses one shared ScenarioAssessment. A test body cannot directly return Passed.

    admission
      -> fresh baseline witness
      -> verified action/fault witness
      -> security witness(es)
      -> functional witness(es)
      -> cleanup witness
      -> independent evidence verifier
      -> PassCertificate -> Passed

PassCertificate is constructed only by a private evaluator when all required witnesses are present, validate, name the intended node identity, and bind to raw evidence. Missing, stale, ambiguous, contradictory, or unreadable evidence is non-pass. No best-effort branch, fallback oracle, or warn-then-pass path exists.

Implementation: add a Rust-native vm_lab/orchestrator/scenario module. New stages call its evaluator rather than open-coding success logic. This is additive; old stages are migrated only when their own contract is reviewed.

### 2.2 Outcome meanings

Current Rust `StageOutcome` cannot emit the active ledger's established `not_proven` state. Add `StageOutcome::NotProven(ReasonCode)` before adding evidence-heavy scenarios. `ReasonCode` is typed and recorded; a free-form string is supporting detail, never the classification.

| terminal outcome | permitted meaning | coverage/release meaning |
| --- | --- | --- |
| Passed | every required proof item validated | counts only for this exact stage/cell |
| Failed | product/test invariant disproved, security bypass, or cleanup failed | hard failure |
| NotProven | required observation missing or unattributable | blocking non-pass; never converted to skip/pass |
| Skipped(AdmissionSkip) | typed admission proves scenario is outside this selected profile | visible non-GREEN; never counts |
| NotRun / Reused | omitted or prior evidence only | visible non-GREEN; never fresh proof |

A required capability absent in a release-selected cell is NotProven or Failed, never Skipped. Skipped is only for a profile that does not claim the scenario, for example Linux-only tc/netem when the selected profile is a macOS lifecycle cell. The manifest records the precise reason.

L0 defines one exhaustive, lossless outcome mapping across `StageOutcome`, runner blocking, realtime TSV, node JSON, `VmLabStageStatus`, run-matrix CSV, report output, evidence verifier, and monitor. No non-pass may collapse into generic `Skipped` or `Pass`. `NotProven`, `Skipped`, `NotRun`, `Reused`, `TimedOut`, `Aborted`, malformed/unknown status, and missing current-generation cleanup never satisfy a truth prerequisite or release claim. A runtime `Passed` may satisfy an in-run prerequisite only after its `PassCertificate`; only an independently verified current-generation pass can support a release claim.

**Source-verified 2026-08-19 — the four enums cited are confirmed independent, non-`From`-derived taxonomies, and the collapse risk is not hypothetical: it is already shipped twice.** `StageOutcome` (`orchestrator/error.rs:211`, 5 variants, no `NotProven`), the recorder's status match (`evidence.rs:422`, exhaustive, no wildcard — adding a variant is a compile error until updated, which is the good case), `VmLabStageStatus` (`vm_lab/mod.rs:2601-2607`, only `Pass|Fail|Skipped`, built independently at ~40 call sites, not derived from `StageOutcome`), and `StageOutcomeRecord` (`orchestrator/report.rs:33`, only `Passed|Failed|Skipped`) are four genuinely separate enums today. But `orchestrator/parity.rs:73-81` (exhaustive match, no wildcard) **already collapses** `StageOutcome::Skipped`, `NotRun`, and `Reused` all into the single `StageOutcomeRecord::Skipped` when building a `StageReport` — the mapping table this section requires must explicitly cover this file, or a developer adding `NotProven` has a ready precedent to fold it into `Skipped` here exactly as `Reused`/`NotRun` already were, rather than growing `StageOutcomeRecord`. Separately and independently, `live_lab_run_matrix.rs:2273-2278` **already has** a self-admitted "Known latent gap" comment where an unrecognized status string falls through `normalize_status` to `unknown` — a second, already-shipped instance of precisely the collapse failure mode this section is written to prevent, in a module this section's file list does not name. **The exhaustive mapping table must explicitly enumerate `orchestrator/parity.rs`'s `StageOutcome → StageOutcomeRecord` match and `live_lab_run_matrix.rs::normalize_status` as required conversion points**, or "exhaustive" is not true of the mapping actually delivered.

### 2.3 T5 deliberate inversion

A T5 control stage passes only if its named target operation produces the specified rejection and the normal operation passes after cleanup.

| record | required state |
| --- | --- |
| control stage | pass |
| targeted operation | non-pass with exact expected rejection code |
| normal recovery operation | pass |
| cleanup | pass |

Any error is insufficient. Wrong reason, timeout that hides the fault, unverified injection, or unproven recovery fails the control. This is a meta-pass proving adjudication; it is not a product-green target stage.

### 2.4 Independent witnesses

Target-daemon status is one witness, never the only witness. Require the appropriate independent combination:

- relay: both clients report route mode, relay forwarding counter delta, and filtered relay capture;
- cross-network: router/WAN capture proves path class, plus client payload witnesses;
- route/leak: OS-native route/firewall output plus a marked payload;
- TCP/UDP: independent client and receiver marker/hash transcripts;
- DNS: OS-authoritative resolver observation and real loopback query.

The existing evidence verifier is extended with an independently implemented, versioned `ScenarioContractRegistry`, keyed by stage ID and contract version/digest. It does not trust an assertion list or boolean inside `scenario.v1`. It validates the scenario contract, target identities, artifact paths/digests, and terminal semantics; it recomputes each required typed assertion from raw independent witnesses. A report that merely says an assertion passed is rejected without bound raw evidence.

Every referenced artifact path is canonicalised beneath the report root before opening; absolute paths, `..` escape, symlink escape, duplicate aliases, unsupported types, and over-budget artifact sizes are rejected. Each artifact binds to the current run instance, stage, assertion ID, and SHA-256. Scenario JSON, daemon self-report, and a file that hashes its own claim are metadata only, never evidence.

### 2.5 Fault injection boundary

Never add generic daemon debug IPC, arbitrary shell endpoint, or unauthenticated production control for test convenience. A future LabFaultController is vm-lab-gated and accepts a closed Rust enum only. Each variant declares:

- exact role/platform/capability admission;
- argv-only setup and cleanup;
- independent proof that the fault took effect;
- bounded lease;
- always-run cleanup;
- residual-state check.

No arbitrary command string, port, destination, or shell fragment reaches it. Unverified fault application is NotProven. Failed cleanup fails the scenario and taints the run.

In-process authoritative-UDP worker death is explicitly outside this controller until a reviewed diagnostic seam and recovery contract exist. Whole-daemon kill is a different fault and cannot substitute.

## 3. Architecture changes

### 3.1 Separate selection, prerequisite, ordering, and capability

Current OrchestrationStage::dependencies controls ordering and skip cascade together. Keep fail-closed dependency handling, but split its meanings.

| field | meaning | effect |
| --- | --- | --- |
| selection | standard, focused, T5, chaos, cross-network | controls the manifest's planned set |
| truth_prerequisites | earlier proof this scenario genuinely needs | only these skip-cascade |
| ordering_after | destructive/shared-resource serialisation | topological order only; does not require pass |
| admission | roles, platform, capabilities, topology | typed pre-mutation verdict |

The runner topologically sorts the union of truth and ordering edges, but blocks only on failed truth prerequisites. It retains always-run cleanup. Unit tests pin both cases: true dependent still blocks; independent scenario still runs after an ordering-only predecessor fails.

Admission runs before mutation. Empty participant sets never pass a stage intended to exercise participants.

### 3.1.1 Native run-instance boundary

A report directory can be reused for resume/rerun today, while `stages.tsv` upsert retains old rows. Source-verified 2026-08-19: this is narrower than "any rerun" — a genuinely fresh invocation cannot silently reuse a populated report dir (`ensure_report_dir_fresh`, `vm_lab/mod.rs:3175`, called from both `native.rs:135` and the bash-wrapper entry points, hard-fails on a non-empty dir). The exposure is real but scoped to the explicitly-opted-in continuation paths — `--run-only`, `--resume-from`, `--rerun-stage` — where a stale terminal row from a prior invocation is indistinguishable from a fresh one because `stages.tsv` has no run/generation column at all (`live_lab_stage_recorder.rs` `StageRow`, 8 fields, confirmed no run-id field) and the verifier matches purely by bare stage name (`live_lab_evidence_verifier.rs:615-619`, `strip_alias_prefix` strips only a `node::` prefix; `manifest.generated_at_unix` is parsed but never used to bound row acceptance).

L0 must therefore bind every claimed witness to one fresh native invocation. Before any stage starts, the native engine obtains an exclusive report-dir run lease and creates a CSPRNG 128-bit `run_instance_id`. It atomically publishes the native manifest and resolved plan for that ID, then replaces prior generation state. Failure to acquire the lease or prove the reset completed aborts before mutation.

**Aggravating factor, not previously scoped:** there is no filesystem lock/pid/mutex anywhere in `vm_lab/orchestrator/` today (grepped `flock`/pidfile/advisory-lock — zero hits). `upsert_row`'s own doc comment asserts a "SINGLE-WRITER contract: exactly one process/thread records a given run's `stages.tsv`" — asserted, not enforced. Two concurrent `--run-only`/`--resume-from` invocations against the same `report_dir` can race the read-modify-write in `upsert_row` independent of the staleness issue above. **The "exclusive report-dir run lease" in this section must be a real OS-level advisory lock with a liveness/pid check, not a documented convention** — the codebase's own precedent for this pattern already exists and should be reused rather than reinvented: `ensure_orchestration_network_profile_record` (`native.rs:987-1017`) digest-verifies a record against on-repo manifests on resume, which is the shape of binding this section needs for `stages.tsv` and does not yet have.

**Resolved 2026-08-19 — concrete lock primitive.** `<report_dir>/state/.orchestrator.lock`, opened `O_CREAT`, held via `flock(fd, LOCK_EX | LOCK_NB)` for the orchestrator process's lifetime, released on exit (including panic-unwind, via a `Drop` guard) or explicit `LOCK_UN`. On acquisition, the file is overwritten with the holder's pid and `run_instance_id`. On `LOCK_NB` failure: read the existing holder's recorded pid and probe liveness with `kill(pid, 0)`; a live holder aborts the new invocation before any mutation with a named error naming the holder pid, its `run_instance_id`, and its recorded start time; a dead holder's lock is reclaimed — logged as a warning, since a dead holder without a clean exit is itself a signal worth surfacing — and the new invocation proceeds. **The CSPRNG `run_instance_id` is generated only after the lock is confirmed held** — the lock is the gate, the ID is what gets stamped once through it, so "obtains an exclusive report-dir run lease" in the first paragraph of this section names this mechanism, not a second one to design separately. Required test: two invocations racing the same `report_dir` — the second observes the named "run already in progress" error, never a corrupted or interleaved `stages.tsv`; a lock file naming a dead pid is reclaimed with a logged warning, not treated as a live conflict.

For a native-schema run, every record carries the same `run_instance_id`:

- manifest, resolved node-stage plan, and plan digest;
- each `state/stages.tsv` row (native schema adds a required ninth column, `run_instance_id`; legacy eight-column rows are invalid for this dialect — **resolved 2026-08-19: extend the shared file, do not fork a parallel one.** `live_lab_stage_recorder.rs:18-29` records that a `#schema_version=2` marker line was already tried and deliberately dropped because legacy bash-side readers don't skip `#`-prefixed lines, and confirms the recorder has **one shared writer path** (`upsert_row`, one `StageRow` struct, no mode/dialect branch) used by both orchestrators — only the *manifest* builder branches by dialect (`live_lab_stage_manifest.rs:141-186`), not the recorder. But the actual parse code on both sides is already column-count tolerant, not fixed-width: `StageRow::parse` (`live_lab_stage_recorder.rs:78-97`) reads every field via `cols.get(idx).copied().unwrap_or("")` and rejects only `cols.len() < 3`, by its own comment "matching the monitor's own tolerance"; `rustynet-lab-monitor/src/data/stage_reader.rs:342-343` independently re-implements the same `cols.len() < 3` gate (it must — the monitor is workspace-excluded and cannot share the recorder's type, per `stage_manifest.rs:5-8`). A 9th trailing column is therefore already safe for both existing readers, before any code changes — not the landmine it looked like. Concrete change: add `run_instance_id: Option<String>` as `StageRow`'s 9th field, empty string meaning absent — i.e. a legacy/bash-dialect row, by construction, no separate marker line needed; `record_stage_start`/`record_stage_finish` (`live_lab_stage_recorder.rs:163,189`, the only two `StageRow`-constructing call sites) each gain a `run_instance_id: Option<&str>` parameter, `Some(&id)` from the native in-process caller and `None` from the bash-facing `ops record-stage-*` subcommand wrapper; `to_tsv()` appends the field through the existing `sanitize()` used for the other seven. `rustynet-lab-monitor/src/data/stage_reader.rs` needs the identical field added to its own independent parser so the monitor can read it for §3.4's generation filtering. The one existing test pinning the format (`assert_eq!(cols.len(), 8, ...)`, `live_lab_stage_recorder.rs:413`) is expected to become 9 as part of this change, not a regression to avoid. This keeps exactly one writer, one file — matching §3.5's "one evidence channel" — instead of a parallel `stages_v2.tsv` needing its own join-key and duplicated lease/generation logic.);
- `scenario.v1` plus each referenced raw artifact;
- `orchestrate_result.json`, report-state marker, report-local matrix row, and ledger row;
- candidate and final verifier verdicts.

The recorder, verifier, and monitor reject mixed, absent, stale, duplicate, or foreign-generation records. A current manifest plus an old terminal row is never current evidence. Legacy/wrapper artifacts remain separately labelled historical dialect data; they cannot certify a native `--node` release claim.

### 3.1.2 Candidate verification and final promotion

The start-time manifest is immutable plan data. It does **not** carry a mutable `evidence_verifier` flag. That would permit a stale or self-written status to appear authoritative.

Use two ordered verifier phases instead:

    immutable native manifest + current-generation raw records/scenarios
      -> independent candidate verifier
      -> state/evidence_verdict.v1.json
      -> matrix row + report-state final marker promotion
      -> independent final-binding verifier

`evidence_verdict.v1.json` is atomically written by the independent candidate verifier for every terminal invocation, including rejection. It contains its own schema version, run ID, plan/contract digests, exact raw-artifact digest map, verdict (`passed | rejected | unavailable`), reason codes, and writer identity/version. Candidate verification deliberately does not require the matrix row or final marker, removing the current circular ordering.

The native finalizer reads only this completed candidate verdict; it never recomputes or overrides it. A release-pass matrix row and `run_passed=true` marker require an exact `passed` verdict bound to the same run ID and artifact hashes. Non-pass/rejected evidence still records a non-pass final result. The final-binding verifier then validates marker/ledger promotion against that verdict. The monitor checks that current artifacts still match the verdict digests; changed/missing verdict input is stale and non-green.

**Source-verified 2026-08-19 — this is worse than "wrong ordering."** `live_lab_evidence_verifier::verify()` is called from **nowhere** in `native.rs` or `evidence.rs` today (grep of `crates/rustynet-cli/src` for callers finds only its own module declaration, doc-comment mentions, and its standalone CLI shell at `src/bin/live_lab_evidence_verifier.rs`). The finalizer (`evidence.rs:1093-1120`, `finalize_rust_native_run`) writes the matrix row (`matrix_finalize`) then the commit marker with **no verifier gate of any kind in between** — not a misordered gate, an absent one. Today's evidence-verifier binary is a wholly separate tool run manually or by CI after the fact.

This means the candidate-verdict/final-binding split above is necessary but not sufficient: it must be **wired synchronously into `finalize_rust_native_run` such that `matrix_finalize`/marker-write cannot be reached without a passed `CandidateVerdict` value in hand** — ideally enforced at the type level (e.g. `matrix_finalize` takes a `&CandidateVerdict` parameter, not just a file the finalizer happens to have written) rather than as a file-presence check the finalizer could skip calling. A file-based "candidate verdict exists" convention has the same failure mode as the current file-based "matrix row exists" convention: nothing forces the caller to check it.

### 3.1.3 Exact resolved-plan contract

`PlanSelection` is input, not proof. A `ResolvedPlan` is produced before mutation, has a stable digest, and contains the selected target IDs, transitive truth-prerequisite closure, included cleanup, admitted topology/capabilities, and explicit omitted IDs/reason codes. The manifest and `node_stage_plan.json` must equal this resolved plan exactly.

The independent verifier separately derives the expected native plan from canonical `StageId::ALL`, `PlanSelection`, node assignments, and serialized run options. It rejects unknown, duplicate, missing, or unexplained disabled IDs; a self-authored manifest cannot shrink the claim. It then requires exact set equality among this independent plan, manifest-enabled rows, and node-stage plan before accepting any stage result.

**Source-verified 2026-08-19.** Confirmed exploitable today: `native.rs:524-529` derives `plan_names` from whatever `stages` the runner already decided to dispatch — no independent source. `live_lab_stage_manifest.rs:180-186` (Rust-plan branch) labels any omitted stage `"not part of the Rust state-machine plan for this run"` with a benign `skip_reason` and never rejects an unknown/missing name against an independently derived expected set (contrast the bash-dialect branch at line 166, which does re-resolve `TargetSelectors.resolves(...)`). The verifier's §4.1-equivalent check (`live_lab_evidence_verifier.rs:~620-645`) only compares the manifest's own enabled rows against `stages.tsv`/`orchestrate_result.json` — internal self-consistency, not independent reconstruction (`grep -n "TargetSelectors|resolves(|StageId::ALL" live_lab_evidence_verifier.rs` returns nothing). A dropped stage — bug, injected fault, or tampering — is recorded as a clean, unremarkable non-selection today.

**This constrains the fix, not just motivates it.** "The independent verifier separately derives the expected native plan" is only independent if its inputs are immune from the same self-authoring problem. If the derivation reuses the `PlanSelection` value `native.rs` already built (the same value that produced the shrunk `stages` vec in the first place), the verifier is re-deriving from a value the thing under test already computed — still self-referential. The independent plan must be derived from `StageId::ALL` plus the **raw CLI/config selectors** (the untouched input, before the runner's own resolution step), not from any `PlanSelection`/`ResolvedPlan` value the native runner already constructed.

### 3.2 Standard, focused, and adjudication plans

Add a closed PlanSelection:

- Standard: current selected normal suites.
- Focused { targets }: target stages, true prerequisites, required setup, and always-run cleanup only.
- Adjudication: selected T5 controls, their true baseline if required, and cleanup only.

Focused plans never claim full-suite/release evidence. The manifest says exactly what was planned and why omitted stages are absent. Skip-stage/reuse cannot omit a selected target or its truth prerequisite. This enables resource-safe fault work without hiding a scenario behind unrelated linear dependencies.

Resolver rules are closed and tested before code:

1. Reject unknown/duplicate targets before mutation.
2. Add every transitive `truth_prerequisite`; a non-pass prerequisite blocks its dependent with the named ID.
3. Add an `ordering_after` edge only when both endpoints are already selected. An omitted ordering predecessor does not become an implicit requirement; a stage that cannot safely run without it must declare a truth prerequisite instead.
4. Add final and scenario-specific cleanup unconditionally. Fresh cleanup cannot be explicitly skipped or reused. The resolver rejects a plan missing it, and the verifier requires current-generation cleanup plus residual-state proof.
5. Refuse an explicit skip/reuse of a selected target, its truth closure, or any cleanup. A selected admission failure becomes typed NotProven/Failed, never an omitted stage.
6. A Standard plan may be release-candidate only after all selected release-cell requirements are present. Focused and Adjudication plans are exact-stage-only even when every included stage verifies.

**Source-verified 2026-08-19 — rule 3 rewrites a load-bearing trait method with no interim semantics for un-migrated stages.** Today, `OrchestrationStage::dependencies()` (`stage/mod.rs:311-313`) is the *only* edge type and is used for both topological ordering and skip-cascade (`runner.rs:152-158`); no `ordering_after`/`truth_prerequisite` distinction exists anywhere in the tree (repo-wide grep: zero hits outside this document and test-function names like `skip_cascade_blocks_dependents_of_failing_stage`). `PlanBuilder::build` (`plan.rs:226-261`) filters `StageId::ALL` by `StageSuite` tag only — there is no arbitrary-target-closure computation today. Splitting this cleanly requires touching every stage's `dependencies()` call site, which conflicts with §2.1's framing of this work as additive ("new stages call its evaluator... old stages migrated only when reviewed"): a stage not yet migrated still has one undifferentiated edge, so during migration a mixed plan has unequal semantics per stage. State the interim rule explicitly — e.g. un-migrated stages treat every `dependencies()` edge as a truth prerequisite (the current, conservative behavior) until migrated, never as ordering-only by default.

**Rule 4 has a live counter-example the resolver must not regress.** `runner.rs:130` evaluates `explicit_skips.contains(&id)` unconditionally, **before** the `always_run()` exemption checked at lines 160-165 (cascade) and 183 (shutdown-flag) — those two paths correctly exempt cleanup; the explicit-skip path does not. Concrete live trigger: `native.rs:626-632`, `--rerun-stage X` marks every stage positioned after X in `plan_stage_ids` as an explicit skip, which includes any trailing always-run cleanup stage. That cleanup stage is skipped (`StageOutcome::NotRun`), never runs, and no existing test catches it — the only `always_run`-related tests (`runner.rs:462, 501, 589`) exercise the dependency-cascade and shutdown-flag branches, not the explicit-skip branch. This is a **present-day fail-open on residue/cleanup evidence** (killswitch/NAT/route residue — see CLAUDE.md §4/§10.1 and NodeEngineAcceptanceSpec §4.3, "cleanup GREEN, proven by T5 residue injection") reachable via a real, already-shipped CLI flag, not a hypothetical the resolver merely needs to prevent going forward. **L0 must fix `runner.rs:130` to check `always_run()` before `explicit_skips` as a prerequisite of this section, not as a side effect of it.**

**Resolved 2026-08-19 — the correction is a unification, not a reordering of one `if`.** Moving the `always_run()` check earlier at just line 130 would fix this one instance but leaves the root cause: three independent call sites decide whether to skip a stage today — explicit-skip (line 130), dependency-cascade (line ~165), and shutdown-flag (line ~183) — and each one separately has to remember to exempt `always_run()`. Two remembered; one didn't. Patching line 130 alone leaves the same class of bug available to a fourth future skip source (e.g. a resource-budget skip, or the Adjudication-plan skip logic this document adds in §3.2 itself). Replace all three with one function — `fn skip_decision(stage: &dyn OrchestrationStage, ctx: &RunContext) -> Option<SkipReason>` — that checks `stage.always_run()` first and unconditionally returns `None` (never skip) when true, before evaluating explicit-skip, cascade-blocked, or shutdown-flag in any order convenient internally. All current and future skip sources in `runner.rs` route through this one function; none may independently re-implement the exemption. Required test: parameterize the existing `always_run_stage_runs_even_when_dependency_failed`-style test over all three (and any new) skip sources, so a future skip source added without routing through `skip_decision` fails the same test the cascade/shutdown-flag paths already pass.

### 3.3 One scenario evidence schema

Every new scenario writes scenario.v1.json under its report directory. It contains no secret material and references raw artifacts by relative path plus SHA-256.

    schema_version, scenario_id, stage_id, contract_digest, run_identity
    selected_targets[alias,node_id,role,platform,os_version]
    admission[requirement,result,evidence]
    baseline[assertion,result,evidence]
    fault[kind,scope,applied,verified,evidence]
    assertions[id,class,required,result,evidence]
    cleanup[action,result,residual_check,evidence]
    limitations
    terminal_outcome

Assertion class is identity, security, functional, liveness, performance_measurement, or cleanup. Contract metadata fixes required assertion IDs and cardinality.

The independent verifier rejects unknown schema/contract versions, missing required assertion, swapped node ID, missing/mismatched artifact digest, contradictory witnesses, a pass without cleanup, a T5 pass without exact target rejection plus recovery, or security proof based only on daemon self-report.

### 3.4 TUI / live-monitor truth presentation

The TUI is part of this change. It is an observer, not an alternate engine or a control channel: the `--node` runner emits `StageObserver` events to the canonical `state/stages.tsv` recorder; it emits the resolved `orchestration/stage_manifest.json` before dispatch; the monitor reads those two artifacts. It must not infer success from daemon logs, poll the active ledger for current-stage truth, invoke a fault, or mutate a run.

**Source-verified 2026-08-19 — this claim is false against the code that ships today, and this document must resolve the discrepancy rather than assume it away.** `rustynet-lab-monitor/src/app.rs:2317` calls `control::launcher::spawn_orchestrator` (`rustynet-lab-monitor/src/control/launcher.rs:210`), which spawns a real child process (`build_loop_args` assembles the full `start <area> ...` argv) that launches and thereby mutates a live-lab run — VM/lab state changes as a direct result of TUI action. This is not a theoretical risk L0 needs to guard against; it is a shipped capability in `rustynet-lab-monitor` today. "There is no second status protocol and no TUI-to-daemon testing path" (below) is accurate for *status*, but the monitor is not purely an observer of *runs* — it already has a launch/mutate path for them.

This is not automatically wrong to have — launching a run from the monitor's own process is a different, more defensible thing than a TUI having a control channel into the daemon-under-test, and an operator convenience for starting a run from the same screen that watches it is reasonable.

**Resolved 2026-08-19 — retained, scoped, and re-labeled together.** `spawn_orchestrator` stays. The corrected invariant this section states is: *the monitor observes stage truth and may launch a fresh run as an operator convenience; a launched run carries no elevated trust and is evaluated by exactly the same pipeline as any other invocation; the monitor is not a control channel into the daemon under test or into an in-progress run.* Concretely, all of the following hold simultaneously — this is not a choice between the three options an earlier draft of this section posed, because they compose rather than compete:
1. **No special evidence path.** A monitor-launched run acquires its own report-dir lease and `run_instance_id` exactly as a CLI-launched run does (§3.1.1) — `spawn_orchestrator` gets no bypass, fast path, or pre-trusted status for anything it starts. The child process is, from the evidence pipeline's point of view, indistinguishable from one a human started at a terminal.
2. **Launch-time bookkeeping only.** The monitor's in-memory knowledge of "I just started job X, report_dir Y, pid Z" (`SpawnedOrchestrator`) is used solely for UI purposes — which run to tail, spinner/progress state, where to point the stage grid — never as a substitute for reading the on-disk manifest, `stages.tsv`, or verdict artifacts, and never to mark anything `Passed`/`VerifiedPass` ahead of what those artifacts show.
3. **"No TUI-to-daemon control path" is scoped precisely.** It means: the monitor cannot invoke a fault, cannot alter an in-progress run's parameters, and cannot reach into `rustynetd` (the product daemon under test) directly. It does not mean the monitor cannot start a brand-new, arm's-length orchestrator child process that is subsequently observed under the same rules as any other run — that capability is retained.
4. **Prose corrected.** "It is an observer, not an alternate engine or a control channel" (opening paragraph of this section) is read together with this note rather than read as "the monitor cannot start a run" — the accurate claim is "observer of stage truth, permitted launcher of arm's-length runs," and this document's own text is the correction, not a future rewrite.

No functionality is removed; the gap this review found (the claim being false as originally worded, with no stated scope) is closed by making the scope explicit rather than by cutting the capability.

L0 changes the producer and monitor together. Native `stage_manifest.json` moves to a reviewed schema version with required, not defaulted, run fields:

    execution_dialect: native_node_v1
    run_instance_id
    plan_kind: standard | focused | adjudication
    resolved_plan_digest
    selected_stage_ids, omitted_stage_ids_with_reason_codes
    required_cleanup_stage_ids

Candidate verification is published separately in `state/evidence_verdict.v1.json`, never by editing the immutable manifest. The CLI and `rustynet-lab-monitor` fixture update atomically. The monitor accepts only exact supported native schema versions and required fields; a future/unknown version, a legacy dialect presented as native, or absent required field is a producer/version error, never a plausible green run.

**Source-verified 2026-08-19 — this reverses a documented, deliberate, currently-shipped decision; the tradeoff must be stated, not silently overridden.** `stage_manifest.rs:5-11` (monitor side) states explicitly: *"Deserialization is tolerant (serde defaults, unknown fields ignored) so a newer emitter never breaks an older monitor."* Every field, including `schema_version`, carries `#[serde(default)]`; there is no `#[serde(deny_unknown_fields)]`; `schema_version` is parsed but never read/compared anywhere in the file (confirmed decorative); the tolerant behavior is deliberately pinned by test (`manifest_parses_the_emitter_shape_and_tolerates_unknowns`, which includes an unrecognized field on purpose). This is a real, working forward-compatibility guarantee for operators running an older monitor against a newer orchestrator build — the rewrite above trades it for release-truth correctness, which is the right call for anything feeding a release decision, but it is a **breaking operational change** (an old monitor binary will now hard-error against a new-schema run instead of degrading), and this document should say so explicitly rather than let an implementer discover the regression later. Recommend: keep tolerant parsing for **display-only, non-authoritative reads**, but require the strict/exact-version gate specifically at the point where a stage/run is evaluated for `VerifiedPass` or release-candidate presentation — i.e. tolerant enough to show something is running, strict before calling it proof.

`VerifiedPass` is a monitor aggregate predicate, not a new raw stage status: current-generation raw `pass`, exact manifest/plan row, required current-generation cleanup, matching accepted candidate verdict with current artifact hashes, and final-promotion binding. Any absent predicate makes the stage/run non-green.

Required presentation rules:

1. Add canonical `not_proven` to monitor `StageStatus`; terminal, failure-ranked, visibly distinct from `fail`, and never green. Unknown/malformed, Skipped, NotRun, Reused, TimedOut, and Aborted are likewise never pass, satisfied, or group-green.

   **Source-verified 2026-08-19 — this bug is live today, not a future risk.** `stage_grid.rs`'s `all_enabled_complete = enabled > 0 && failed == 0 && completed >= enabled` gates group-green, where `completed` uses `is_terminal()` and `failed` uses `is_failure()` (`stage_reader.rs`). Both `is_terminal()` and the "not a failure" side treat `Reused`, `Skipped`, and `NotRun` identically to `Pass`. A group where every enabled stage is `Reused` (zero freshly executed, zero freshly passed) renders fully green in the shipped monitor right now — this is the most operationally dangerous finding in this review, because `rustynet-lab-monitor` is meant to be read-only observability and an operator could read that green as release evidence, which is exactly the harm this repo's own `run_matrix.rs` (lines ~590-610) already warns about for the CLI-side matrix aggregation. **`VerifiedPass` must replace `all_enabled_complete` outright at its call site, not be added beside it** — if the old predicate remains reachable anywhere in the render path, the false-green path survives L0.
2. Render stages from the emitted manifest, including every newly added `StageId`; no new monitor-side hard-coded catalog or name matcher. A manifest row/outcome mismatch, generation mismatch, duplicate row, or missing selected row is a visible non-green producer fault. No implicit synthetic `skipped` state may make a selected stage look complete; use explicit manifest exclusion only for a genuinely unselected/non-applicable row.
3. Stage detail may show a safe scenario summary: contract ID/digest, assertion IDs and result classes, artifact path/digest, exact `NotProven` reason, fault cleanup result, and verifier verdict. It never renders secrets, packet contents, private keys, arbitrary command text, or unverified raw output as a success claim.
4. Header and stage-grid verdicts distinguish settled execution from verified evidence. A raw `Passed` remains **verification pending** until a matching candidate verdict accepts its `scenario.v1` contract and final promotion binds it. `rejected`, `unavailable`, missing, stale, hash-mismatched, or foreign-generation verification blocks green.
5. `Focused` and `Adjudication` runs show an explicit scope banner. They can prove their named stage/control only; they never render as a full-suite or release-green run. T5 success is labelled “control proved”, not “product healthy”.
6. The monitor remains live by reading current-generation `stages.tsv`; it must show `running`, cleanup, and terminal transitions from that stream without waiting for the historical CSV ledger. The CSV remains history, not current-run authority.

This preserves one evidence channel: runner -> current-generation recorder/immutable manifest -> candidate verifier verdict -> final promotion/final verifier -> monitor. There is no second status protocol and no TUI-to-daemon testing path.

### 3.5 Ownership and source-change targets

| concern | planned owner | intended change |
| --- | --- | --- |
| terminal semantics | orchestrator error/evidence, vm_lab status, run matrix | typed NotProven, failure rank, summary/recorder/CSV support |
| run incarnation | native orchestrator, stage recorder, manifest, node plan, result/marker/ledger writers | one run ID, report-dir lease/reset, generation-bound raw records; reject mixed legacy/native evidence |
| contract metadata | stage/mod.rs and live_lab_stage_registry.rs | total StageContract, admission/evidence metadata |
| plan and runner | plan.rs, runner.rs, manifest writer, verifier plan resolver | resolved-plan digest, focused closure, prerequisite/order split, target-omission refusal and independent set equality |
| common scenario work | new stage/scenario module | admission, pass certificate, artifact writer, witnesses |
| fault boundary | stage/scenario/fault.rs plus adapters | closed enum, verified reversible argv-only operations |
| evidence gate | live_lab_evidence_verifier plus native finalizer | independent contract/witness recomputation, candidate verdict, promotion binding, final verification |
| monitor contract | rustynet-lab-monitor stage_reader, stage_manifest, run_matrix, stage_grid, stage_detail_overlay, control/launcher | new status/schema parsing, proof-aware verdicts, scope banner, safe detail display, 9th-column `run_instance_id` in the monitor's own TSV parser (§3.1.1); `control/launcher::spawn_orchestrator` retained per the resolved §3.4 disposition — no evidence-path change needed there beyond ensuring it never bypasses the lease/manifest pipeline |
| cross-network | existing cross_network path | consume shared contract; no parallel harness |

These are targets, not modifications made by this document.

## 4. Test portfolio and exact pass contracts

### 4.1 P0 — mesh and DNS oracle repair

Evolve mesh_status_validation. Add resolver_liveness_validation only once its contract is implemented.

Admission: supported OS probe and at least one expected remote peer. A zero-peer local-only profile is a distinct scenario and cannot reuse this name.

Pass requires all:

1. intended daemon identity alive on intended control endpoint;
2. every expected peer present and current under a source valid for the persistence model;
3. independently initiated marked peer payload succeeds;
4. OS-native resolver observation and actual loopback resolver query agree in protected mode;
5. daemon absent, expected peer absent, stale/invalid state, wrong resolver, and no listener each fail with named evidence.

No-easy-pass: parsed state, own-node identity, or resolv.conf alone cannot pass. Do not add arbitrary state-age bounds until the product guarantees snapshot freshness.

Linux, macOS, and Windows need native adapter implementations. Unsupported is visible but never proves the release cell.

### 4.2 P0 — minimal mixed-platform baseline

New T3 stage: mixed_platform_mesh_baseline. Retain existing live_mixed_topology_validation until the scopes are deliberately reconciled.

Participants: one Linux, one macOS, one Windows; distinct node IDs; verified signed membership on all.

Pass requires all:

1. exact platform/node/role identity challenge per node;
2. same verified membership root and epoch on all nodes;
3. fresh authenticated handshakes for each expected directed relation;
4. marked payload receipt for all six ordered platform pairs;
5. default-deny negative probe per origin after baseline peer traffic;
6. no marker, listener, route, firewall rule, or role residue after cleanup.

Missing platform is a typed non-GREEN admission result. Duplicate ID, mismatch root, stale evidence, blocked pair, or cleanup failure is non-pass.

Current vmnet isolation remains an infrastructure block. This design does not bridge interfaces, relax private-relay policy, or manufacture evidence to pass.

### 4.3 P0 — T5 and selected chaos

The four negative_control stages already exist and have no truth dependencies. Their zero active coverage is scheduling/evidence work, not a reason to reimplement them. Nine chaos stages need accurate admission instead of universal mixed-topology dependency.

Implementation order:

1. Convert all four T5 controls to scenario.v1: injection, target operation, exact classifier, normal recovery, cleanup.
2. Add Adjudication focused selection; execute one low-blast-radius control per run.
3. Classify chaos:
   - offline crypto/membership: no topology dependency;
   - Linux tc/nft/systemd: Linux capability;
   - cross-platform: actual three-platform topology;
   - resource exhaustion: dedicated isolated resource profile.
4. Move only stages whose real inputs permit it. Preserve ordering and cleanup.

T5 passes only when plant/applied proof, exact rejection, recovery, and cleanup all exist.

### 4.4 P1 — active relay forwarding

New T1 stage: relay_frame_forward_validation. It remains distinct from relay_validation lifecycle.

Refactor and reuse the legacy exercise_linux_relay_forwards_frame helper. Do not clone its firewall/cleanup logic.

Admission: relay plus two distinct peer nodes; fault-driver/capture capability; direct UDP block can be narrow.

Pass requires all:

1. both peers prove direct baseline traffic;
2. direct UDP blocks exist on intended peers and only target each other;
3. both clients independently report relay routing;
4. marked traffic arrives;
5. relay forwarded-frame and byte counters both increase;
6. relay-side filtered capture lacks plaintext marker;
7. blocks are removed and normal baseline returns.

Direct still usable, absent path evidence, unchanged counters, plaintext marker, or unverified cleanup fails. Health/port binding are supporting evidence only.

Linux is first because the harness exists. macOS/Windows need native proof before their role cells may claim the same capability.

### 4.5 P1 — transport path fault matrix

Do not add one network_flap_v2 umbrella where one good subcase hides another. Each is a first-class stage/artifact; matrix is a scheduler convenience only.

| scenario | first target | minimum pass proof | forbidden false green |
| --- | --- | --- | --- |
| transport_direct_outbound_blackhole | Linux then OS-native driver | verified direct block and marked recovery | stale handshake or command exit |
| transport_direct_inbound_blackhole | Linux | no data during verified inbound block; recovery after removal | outbound-only rule |
| transport_asymmetric_impairment | Linux netem | sequenced UDP evidence and bounded contract recovery | ping-only or unmeasured impairment |
| transport_direct_to_relay | Linux | both client relay mode, relay counter delta, marked payload | relay health or parseable ACK |
| transport_relay_restart_recovery | Linux relay | confirmed session, controlled restart, fresh registration/allocation, payload | local UDP send success / old allocation |
| transport_stun_outage_relay_continuity | Linux | usable relay plus separate STUN re-probe | relay re-registration blocked on STUN |
| transport_endpoint_rebind_recovery | shared backend after contract | old overlay invalidated, new incarnation/overlay, new payload | same port treated as same transport |

All record before/during/after path mode, selected peer, session/overlay ID where available, candidate age, endpoint source, and marked payload. Trusted relay live needs current authenticated WireGuard evidence bound to selected session/overlay. ACK correlation alone is not authentication.

### 4.6 P1 — cross-network direct, relay, and failback

Adopt the CrossNetworkSubstrateIntegrationSpec design: substrate declares where topology runs; common scenario declares what is proved.

| scenario | substrate target | pass contract |
| --- | --- | --- |
| NAT classification/matrix | Netns first | configured profile independently applied/classified; unsupported named |
| direct remote path | Netns then Vxlan | candidate/path proof, marked payload, router capture direct ciphertext, no tunnel-CIDR cleartext |
| relay remote path | symmetric Netns then Vxlan | expected direct failure, both clients relay-active, capture/counter relay proof, no direct peer WG |
| failback/roaming | Vxlan/Slirp when available | old path invalidated, new authorized path, payload recovery, no stale endpoint/leak |
| remote exit DNS | substrate-specific | only authorized DNS/exit succeeds; denied query/route fails closed |
| traversal adversarial | deterministic Netns | unsigned/stale/replayed/wrong-scope candidate never programs a peer endpoint |

Netns is deterministic substrate proof, not cross-OS proof. Vxlan/Slirp remain typed non-GREEN with exact reason until topology exists. No silent fallback between substrate names.

### 4.7 P1 — service traffic and existing-flow transition

New stages: mesh_tcp_payload_validation, mesh_udp_payload_validation, mesh_path_mtu_validation, exit_handoff_existing_flow_validation. Keep them separate from traffic_test_matrix, which proves ICMP reachability/default deny.

Payload harness: lab-only Rust client/server with per-run marker, byte count, SHA-256 transcript digest, UDP sequence accounting, and bounded MTU ladder. It binds expected node IDs, carries no secrets, exposes no LAN/public listener, and is not a shipped product service.

Existing-flow handoff: establish marked TCP and UDP through authorized exit. During role/NAT change, observe client result plus platform-native flow/NAT state. Afterwards require owner-defined continuity through new authorized path, or explicit break plus fresh authorized reconnection. Traffic through demoted exit, protected-route leak, or unauthorized retained NAT state fails.

This is blocked on an owner decision about intended existing-flow behavior. Do not turn a test expectation into a policy decision or flush conntrack merely to satisfy a test.

### 4.8 P2 — authoritative shared-UDP recovery

Future T2 stage: authoritative_transport_recovery_validation, only after shared-UDP product design is accepted.

Its future pass contract is already fixed:

1. healthy I0 transport and firewall/bypass baseline;
2. typed unavailable transition, no stale traversal operation or peer egress during quarantine;
3. explicit recovery makes I1 distinct from I0 even if address/port repeats;
4. baseline peers replay without old relay endpoint overlay;
5. firewall/bypass barrier proven before I1 peer egress;
6. STUN and relay reconcile independently;
7. fresh authenticated I1 data-path evidence;
8. diagnostic mechanism leaves no live production hook.

Daemon-kill chaos cannot substitute. This remains unproven until a reviewed safe diagnostic seam exists.

## 5. Implementation slices

Every slice lands with closest unit, mutation, and negative tests. No slice claims live proof until a separately scheduled live run creates an independently verified artifact and active-ledger row.

### L0 — truth-preserving framework

1. Add the typed outcome taxonomy and exhaustive mapping table. Complete runner blocking, recorder, JSON, matrix, report, candidate verifier, final verifier, and monitor handling without any non-pass collapse.
2. Add run-instance creation, exclusive lease, atomic reset, native manifest/TSV schema, and generation checks before any scenario code. Native rerun/resume cannot read an old row as fresh proof.
3. Add StageContract, typed AdmissionContract, ScenarioEvidenceContract, and totality tests; give the verifier its independent versioned contract registry and raw-witness parsers.
4. Split prerequisite/order graph; add `PlanSelection`, `ResolvedPlan`, closure algorithm, cleanup inclusion/refusal rules, manifest/node-plan digest, and independent verifier plan recomputation.
5. Add safe `scenario.v1`, PassCertificate, path/artifact validation, and candidate-verdict publication. Refactor verification into candidate-before-promotion and final-binding phases.
6. Make final matrix/marker promotion require the exact candidate verdict; keep a rejected/non-pass run recordable but non-green.
7. Update the monitor in this same slice: native schema/fixture, generation filtering, `not_proven`, strict aggregate verdict, no implicit completion, proof-verdict display, and focused/adjudication scope banner.

Required mutations: remove witness; alter digest; change exact T5 reason; fail cleanup; fail ordering-only predecessor; reuse an old report row; mix run IDs; mutate manifest plan; omit a required target/cleanup; mark a raw pass while verifier is pending/rejected; feed a new/unknown manifest status; use an escaped/symlink artifact path. Every mutation creates non-pass or verifier rejection; the monitor may not render green.

### L1 — oracle repair and T5 evidence

1. Repair mesh/DNS liveness through negative fixtures first.
2. Emit full scenario evidence from existing T5 controls.
3. Add focused adjudication plans and one isolated live control per scheduled resource window.

Gate: daemonless host, absent peer, wrong resolver/listener, forged bundle, wrong node, planted residue, and daemon kill all produce named expected non-pass. Normal clean path then passes.

### L2 — baseline proof and relay forwarding

1. Add mixed-platform admission/contract without LAN-toggle prerequisite.
2. Promote Linux HP-3 forwarding stage.
3. Add payload helper only after no-public-listener and identity-binding tests.

Gate: no empty-participant pass; direct route during relay-only scenario fails; missing counter/capture fails; substituted node identity fails.

### L3 — path faults and cross-network

1. Refactor direct outage into explicit contract.
2. Add inbound/asymmetric/direct-to-relay under LabFaultController.
3. Implement approved CrossNetworkSubstrateIntegrationSpec increments; consume shared contract.
4. Add relay restart/STUN continuity only after session evidence distinguishes fresh allocation from stale belief.

Gate: fault must prove application; security holds during it; cleanup returns baseline. Requested but unapplied profile/fault is NotProven.

### L4 — role flow and UDP recovery

1. Obtain existing-flow owner decision; add OS-native flow evidence.
2. Finish/review shared-UDP recovery product contract.
3. Add recovery diagnostic stage only then; validate Linux and macOS separately.

Gate: stale endpoint/overlay, unauthorized retained flow, missing route barrier, or retry ambiguity cannot pass.

### L5 — stability and performance

Use Node Engine Acceptance N-of-N clean-commit windows: default 3-of-3, 5-of-5 for recorded flakes. Schedule 24-hour release soak and performance budgets separately; they are never a background side effect of a focused functional run.

## 6. Framework tests required before live claims

1. Selected stage cannot pass with zero participants.
2. Focused plan includes truth prerequisites and cleanup, not unrelated hidden gates.
3. Ordering-only failure does not hide valid independent stage.
4. Truth prerequisite failure blocks dependent stage with named ID.
5. Missing/ambiguous witness maps to NotProven, never Passed/Skipped.
6. Forged scenario artifact, swapped node ID, missing digest, stale contract, or manifest/row mismatch is independently rejected.
7. Fault controller rejects unknown variant, arbitrary argv, wrong role, unsupported platform, unverified application, and cleanup failure.
8. Each T5 control rejects wrong reason and target success; exact rejection plus recovery only.
9. Platform admission never lets Skip satisfy release-cell accounting.
10. Removing required predicate from a scenario evaluator breaks a behavioral mutation test.
11. Monitor fixture emitted by the real `--node` manifest writer parses; unknown schema/status and manifest/TSV mismatch cannot produce group/run green.
12. `NotProven`, verifier-pending/rejected, Focused, and Adjudication each display their exact non-release semantics; only a verified Standard plan can present release-candidate green.
13. Rerun in the same report directory: previous terminal rows, scenario files, verdict, marker, and local ledger row cannot satisfy the new run; mixed/foreign run IDs fail before verdict.
14. Candidate verifier runs before matrix/marker promotion; a missing/rejected/stale candidate verdict cannot produce `run_passed=true` or a release-pass ledger row. Final-binding verifier catches any later swap.
15. Independent plan resolver rejects a manifest that disables a required stage, adds unknown/duplicate IDs, or differs from `node_stage_plan.json`; a selected target's complete truth closure is present.
16. Explicit skip/reuse of selected target, truth prerequisite, final cleanup, or scenario cleanup is rejected. Current-generation cleanup/residual evidence is mandatory for verified pass.
17. Scenario artifact rejects absolute/escaping/symlink paths, duplicate aliases, wrong run ID, oversized/unsupported file, self-authored assertion boolean, missing typed witness, and artifact hash replacement.
18. All-settled/all-skipped/all-not-run/all-reused monitor group remains non-green. Only every required current-generation VerifiedPass plus matching candidate verdict and final promotion can render green.

## 7. Non-goals and blocked decisions

- No weakening signed-candidate, freshness, ACL, DNS, firewall, protected-route, or private-relay controls.
- No generic privileged executor or raw fault IPC.
- No Linux result claimed as macOS/Windows parity.
- No cross-network label for same-host Netns evidence.
- No unbounded exhaustion/soak during ordinary developer work.
- No existing-flow expectation without owner decision.
- No worker-recovery live test without product recovery contract and safe diagnostic mechanism.

## 8. Adversarial L0 review record — 2026-08-19

Review was read-only: no source edits, compilation, live-lab run, or load test. Findings are source-grounded implementation requirements, not facts to take on trust without code-level validation.

**Second pass, same day: every citation below independently re-verified against the current main-worktree source** (not `.claude/worktrees/*` or `state/edit-worktrees/*` copies, which are stale/unrelated) by five parallel read-only investigations, one per cluster (run-instance/generation binding; verdict-promotion/plan-shrink; outcome-taxonomy/TUI-aggregate-green; plan-closure/cleanup-skip/scenario-JSON; TSV-schema/dialect/T5-coverage). Every citation in the original table below was CONFIRMED as quoted. Corrections, severity changes, and net-new findings from that pass are folded inline into §2–§3 above and appended as new rows below rather than kept in a separate document, so this table reflects the current understood state, not the original draft's.

**Also confirmed sound, unchanged:** the T5 negative-control claim in §4.3 is accurate as written — all 4 stages (`negative_control_signed_bundle_rejection`, `negative_control_planted_residue`, `negative_control_wrong_node_substitution`, `negative_control_daemon_kill_mid_stage`) exist, are correctly tagged `Tier::T5NegativeControl` with a registry invariant test enforcing it, and have zero active coverage purely because they sit behind an explicit `--enable-negative-control`/`--negative-control-suite` opt-in never set by the Standard/default plan — "scheduling work, not brokenness" is the right diagnosis, not an excuse.

| rank | finding | source evidence | required correction |
| --- | --- | --- | --- |
| P0 | reused report directory can show old terminal proof as a new run | native manifest is replaced on rerun (`live_lab_stage_manifest.rs:293`); TSV upsert retains rows (`live_lab_stage_recorder.rs:124`); verifier accepts terminal rows by bare name (`live_lab_evidence_verifier.rs:615`); monitor prefers live TSV (`rustynet-lab-monitor/src/data/stage_reader.rs:104`) | §3.1.1 generation binding, lease/reset, ninth native TSV field, and foreign/mixed-row rejection |
| P0 | verifier verdict has no valid current promotion point | manifest is pre-dispatch (`orchestrator/native.rs:580`); verifier only returns a report (`live_lab_evidence_verifier.rs:319`); finalizer writes matrix before marker (`orchestrator/evidence.rs:1097`); verifier cross-checks both (`live_lab_evidence_verifier.rs:649`) | §3.1.2 candidate verdict before promotion, then final-binding verifier; never mutable manifest status |
| P0 | self-authored manifest can shrink selected plan | native plan names come from runner (`orchestrator/native.rs:528`); manifest maps registry rows but does not reject unknown active-plan names (`live_lab_stage_manifest.rs:154`); verifier checks manifest internal consistency only (`live_lab_evidence_verifier.rs:501,527`) | §3.1.3 independent plan resolver plus exact equality with manifest/node-stage plan |
| P0 | new `NotProven` would be lost by existing mapping | runner blocking is incomplete (`orchestrator/error.rs:240`); recorder has only current variants (`orchestrator/evidence.rs:422`); node status is Pass/Fail/Skipped only (`vm_lab/mod.rs:2601`); report has same loss (`orchestrator/report.rs:33`) | §2.2 exhaustive lossless taxonomy/mapping and no non-pass collapse |
| P1 | monitor group can green reused/skipped/not-run work | Reused is satisfied (`stage_reader.rs:67`); any terminal is completed (`app.rs:642`); group green means completed and no `is_failure` (`ui/stage_grid.rs:325`) | §3.4 strict aggregate `VerifiedPass`, separate settled/progress display, and no implicit skipped completion |
| P1 | newer schema silently downgrades in older monitor | monitor intentionally defaults missing fields and ignores unknown fields (`data/stage_manifest.rs:5,28,84`) | §3.4 exact native schema/version gate; unknown/missing required field is producer error |
| P1 | focused plan closure not specified enough for current runner | one `dependencies()` set is both validation and skip cascade (`runner.rs:152,239`); PlanBuilder filters suites, not arbitrary target closure (`plan.rs:240`) | §3.1/§3.2 resolver rules: transitive truth closure, conditional ordering edges, target/cleanup refusal |
| **P0 (resolved 2026-08-19)** | cleanup can be skipped despite always-run label — **and this has a concrete live trigger** | `explicit_skips.contains` at `runner.rs:130` runs before the `always_run()` exemption at 160-165/183; `--rerun-stage X` (`native.rs:626-632`) marks every stage after X — including trailing cleanup — as an explicit skip, reachable via a shipped CLI flag today, not merely a design risk | §3.2 resolution: unify all skip sources behind one `skip_decision()` function that exempts `always_run()` first, closing the bug class rather than patching line 130 alone; this is a present-day fail-open on residue evidence (killswitch/NAT/route), not only a future gap |
| P1 | scenario JSON could be self-authored proof | current verifier hashes fixed report artifacts only (`live_lab_evidence_verifier.rs:404`) and has no `scenario.v1` parser — **source-verified: zero hits repo-wide for `scenario.v1`/`ScenarioEvidence` outside this document, so today this is unrealized risk, not an active forgery path** (nothing exists yet to forge) | §2.4 independent contract registry/raw parsers, containment/symlink/size/type/run-ID checks |
| P2 | legacy and native writer dialects remain mixed | **corrected 2026-08-19:** true for the *manifest* (`live_lab_stage_manifest.rs:141-186`, two live dialect branches, confirmed by tests) but the *recorder* citation is weak/stale — `live_lab_stage_recorder.rs` has one shared writer path with no mode branch; the recorder unifies output rather than mixing it. Cite the manifest only. | §3.1.1 dialect field on the manifest specifically; native release verifier rejects legacy/mixed evidence rather than falling back; see also the 9th-TSV-column compatibility note added to §3.1.1 |
| **P0 (new, 2026-08-19)** | no verifier gate exists in the promotion path at all — worse than "wrong ordering" | `live_lab_evidence_verifier::verify()` has zero callers in `native.rs`/`evidence.rs`; it is a standalone binary run manually/by CI, never wired into `finalize_rust_native_run` (`evidence.rs:1093-1120`) | §3.1.2 candidate verdict must be enforced at the type level (e.g. `matrix_finalize` requires a `&CandidateVerdict`), not merely written as another file the finalizer might not check |
| **P0 (new, 2026-08-19)** | independent plan resolver risks re-deriving from the runner's own already-computed `PlanSelection`, which is not independent | `native.rs:524-529` plan set is runner-authored; manifest (`live_lab_stage_manifest.rs:180-186`) labels omissions as benign; verifier checks manifest self-consistency only (`live_lab_evidence_verifier.rs:~620-645`, no `TargetSelectors`/`StageId::ALL` reconstruction found) | §3.1.3's resolver must derive from `StageId::ALL` + raw CLI/config selectors, never from any `PlanSelection`/`ResolvedPlan` the native runner already built |
| **P0 (new, 2026-08-19)** | monitor group-green already renders true today with zero freshly-passed stages | `stage_grid.rs`'s `all_enabled_complete` uses `is_terminal()`/`is_failure()` (`stage_reader.rs`), both of which treat `Reused`/`Skipped`/`NotRun` as "complete" and never as "failure" — an all-`Reused` group renders green in the shipped monitor now | §3.4 rule 1's `VerifiedPass` must **replace** `all_enabled_complete` at its call site, not sit beside it, or the false-green path survives L0 |
| **P0 (resolved 2026-08-19)** | design's TUI-observer claim ("must not... mutate a run") was false against shipped code, undisclosed | `rustynet-lab-monitor/src/app.rs:2317` calls `control::launcher::spawn_orchestrator` (`control/launcher.rs:210`), which launches a real orchestrator child process from the TUI | §3.4 resolution: retained, scoped — a monitor-launched run gets zero evidence-path privilege, "no TUI-to-daemon control path" is scoped to fault-injection/in-progress-mutation/direct-daemon-reach, not to launching a new arm's-length run |
| P1 (new, 2026-08-19) | `NotProven` collapse risk is not hypothetical — it is already shipped twice | `orchestrator/parity.rs:73-81` already folds `Skipped`/`NotRun`/`Reused` into one `StageOutcomeRecord::Skipped`; `live_lab_run_matrix.rs:2273-2278` already has an admitted "Known latent gap" falling through `normalize_status` to `unknown` | §2.2's exhaustive mapping table must explicitly name both files as required conversion points |
| P1 (resolved 2026-08-19) | no enforced concurrent-run protection | no flock/pidfile/mutex anywhere in `vm_lab/orchestrator/`; `upsert_row`'s "single-writer contract" is a code comment, not a lock | §3.1.1 resolution: `flock(LOCK_EX \| LOCK_NB)` on `<report_dir>/state/.orchestrator.lock`, pid-liveness reclaim of dead locks, `run_instance_id` generated only after the lock is held |

## 9. Next action

**All three L0 blockers are now resolved at the design level (2026-08-19); no code, test, build, or live-lab action has been taken.** This section previously listed them as open; each is now a concrete, source-grounded decision inlined at its owning section, summarized here for traceability:

1. **§3.4 TUI-launcher disposition — resolved: retained, scoped, and re-labeled together.** `spawn_orchestrator` stays. A monitor-launched run gets no evidence-path privilege — same lease, same manifest, same candidate/final verdict pipeline as any CLI-launched run; the monitor's launch-time bookkeeping is UI-only. "No TUI-to-daemon control path" is scoped to mean no fault injection, no in-progress-run mutation, and no direct reach into `rustynetd` — not "cannot start a new arm's-length run." See §3.4 for the four concurrently-held rules.
2. **§3.1.1 native TSV 9th-column compatibility — resolved: extend the shared file.** Both existing parsers (`live_lab_stage_recorder.rs`'s `StageRow::parse` and the monitor's independent re-implementation in `stage_reader.rs`) already tolerate a variable column count by construction (`cols.get(idx).unwrap_or("")`, minimum-length gate only) — verified by reading the parse code, not assumed. A 9th `run_instance_id` column is safe to add to the one shared writer; no parallel file, no writer-side dialect branch. See §3.1.1 for the exact field/signature changes and the one test that must move from 8 to 9.
3. **§3.2/§3.1.1 pre-existing defects — resolved: unify skip decisions, and name the lock as the same mechanism §3.1.1 already required.** The `runner.rs:130` fail-open is corrected by replacing three independently-guarded skip sites with one `skip_decision()` function that exempts `always_run()` first, closing the bug class rather than the one instance. The unenforced single-writer contract is closed by a concrete `flock`-based lease on `<report_dir>/state/.orchestrator.lock` with pid-liveness reclaim, generating `run_instance_id` only once the lock is confirmed held — this is what "exclusive report-dir run lease" in §3.1.1 concretely means, not a second mechanism. See §3.1.1 and §3.2 for the exact designs and required tests.

**Recommended before code:** one narrow confirmation pass specifically on these three resolutions (not a full re-review of the whole document) — each introduces new required tests (§3.1.1's race test, §3.2's parameterized skip-source test, §3.1.1's 9th-column round-trip test) that should be checked for completeness against §6's framework-test list before L0 implementation starts. This is a lighter check than the original second-pass review, not a repeat of it.
