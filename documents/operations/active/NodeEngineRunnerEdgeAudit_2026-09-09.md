# Orchestrator runner edge-semantics audit — 2026-09-09 (GLM-5.3-flash, grounded, trusted input)

Probe W7. Verified-correct edges recorded first; F1–F3 dispatched as an edit job the same morning.

# Rust `--node` orchestrator — runner edge-semantics audit

Scope read in full: `orchestrator/runner.rs`, `error.rs`, the runner seams in `native.rs`/`evidence.rs` (producers of runner inputs), `stage/mod.rs` catalog/trait, plus the 2026-09-08/09 ledgers. plan.rs is the PlanBuilder (catalog-ordered instantiation, `plan.rs:2-33`); it contributes no edge semantics — the runner re-validates whatever it builds (`runner.rs:410-441`).

## 1. Findings

### Verified-correct edges (no finding; quoted for the record)

- **ordering_after vs dependency** — topo order is the *union* of both edge kinds (`runner.rs:470-475`: `for edge in stage.dependencies().iter().chain(stage.ordering_after())`), but skip-cascade reads **only** `dependencies` (`runner.rs:259-276`), and an `ordering_after` edge to a stage not in the plan is silently ignored (`runner.rs:471-474`; test `runner.rs:752`). So a stage runs **after** a Reused/Skipped/Failed ordering-predecessor in time but is never cascade-blocked by it — pinned by `ordering_after_does_not_skip_cascade_on_a_failed_predecessor` (`runner.rs:698`). A dependent of a Reused **dependency** also executes, but never *before* it (topo edge forces order), and that is intended: `validated_reused_skip_does_not_cascade_or_claim_fresh_pass` (`runner.rs:1253`).
- **mark_blocked cascade** — blocking set = `Failed | NotRun | NotProven` (`error.rs:388-394`); cascade-`Skipped` also blocks via `mark_blocked: true` (`runner.rs:268-272`); `Reused` and shutdown-`Skipped` do **not** (`runner.rs:247-253`, `:274-283`). `NotProven` demonstrably cascades (`unwitnessed_pass_blocks_dependents`, `runner.rs:1618`).
- **Panic** — `catch_unwind(AssertUnwindSafe(...))` converts a panic into `Failed("stage 'x' panicked during execute")` (`runner.rs:156-166`), which is blocking and cascades; the run survives and cleanup runs (`runner.rs:985` test). No `panic = "abort"` anywhere in `Cargo.toml` (grep: zero matches), so unwind semantics hold in release.
- **Pre-cleanup hook** — fires before the first `always_run` stage *executes* (`runner.rs:130-138`), its failure never skips cleanup and is folded into that stage's outcome as `Failed` even when cleanup passed (`runner.rs:177-186`; test `runner.rs:1012`).
- **always_run under failure** — the exemption is checked ahead of every skip source (`runner.rs:227-233`); runs under failed dependency (`:808`), explicit skip (`:834`), shutdown (`:897`), panic (`:985`).
- **Observer/recorder vs `verify_declared_evidence`** — the demotion runs after `catch_unwind`/hook fold and **before** `stage_finished` (`runner.rs:189-196`), so it reads the log the recorder truncated at `stage_started` (`evidence.rs:521-542`) and before the verdict echo is appended (`evidence.rs:626-643`); pinned by `demotion_fires_before_observer_appends_verdict` (`runner.rs:1566`). Skip paths fire `stage_finished` without `stage_started`, and the recorder replaces (not appends) the log in that case (`evidence.rs:631-643`) — no stale-log pass-through.
- **Plan validation** — duplicate ids, missing deps, cycles all rejected before execution (`runner.rs:414-419`, `:429-438`, `:492-501`; tests `:1287/:1299/:1311`).

### F1 — HIGH, fail-open: a `File`-evidence witness from a *prior invocation* can back this run's `Passed`

`verify_evidence_file_at` (`runner.rs:330-380`) accepts any existing, non-empty, non-symlink file as the witness. It checks existence, not generation. The recorder clears only `logs/<id>.log` at stage start (`evidence.rs:521-542`); a declared `StageEvidence::File` artifact is never cleared. Input path: `--run-only` / `--resume-from S` / `--rerun-stage S` *require an existing report dir* (`native.rs:129-150`) while a fresh run gets `ensure_report_dir_fresh` (`native.rs:~151`) — i.e. the reuse paths are exactly where a prior generation's artifact is still on disk. The only two `File` rows on main are the Live-suite stages those flags target: `TrafficTestMatrix => File("logs/traffic_test_matrix.pair_results.log")` (`stage/mod.rs:327`) and `ActiveExit => File("active_exit.egress_evidence.json")` (`stage/mod.rs:338`). Failing input: rerun `traffic_test_matrix` in a completed report dir with an `execute()` that (regression or bug) writes nothing — `verify_declared_evidence` finds generation-N's `pair_results.log`, the `Passed` stands, and run N+1's `stages.tsv` row says `pass` on evidence it never produced. `ReasonCode::StaleEvidence` exists for exactly this (`error.rs:230`) but the runner never emits it (grep: used only in `scenario/pass_certificate.rs`). The in-code contract — "no witness written during execute" (`runner.rs:186-189`) — is unenforceable for the `File` arm today.

### F2 — MEDIUM: `Reused` is unauthenticated at the runner boundary

`with_reused_skips(skips, evidence_sha256: String)` (`runner.rs:73-84`) accepts any string for any stage ids; `skip_decision` branch 1 (`runner.rs:241-253`) asserts nothing — no digest shape, no prior-report check — and mints terminal `Reused{evidence_sha256}` rows that are non-blocking and recorded as `"reused"` with summary `"validated prior pass sha256=..."` (`evidence.rs:575-578`). The existing runner test itself passes `"abc123"` (`runner.rs:1266`), demonstrating the forgery. The only real defense is call-site discipline: `native.rs:925-927` feeds it `validate_rust_native_reuse_evidence` output (which does check run state, manifest-enablement, prior `pass|reused` status, and the 64-hex seal — `evidence.rs:287-335`). Ledger risk: any future caller (or reordered wiring) silently writes ledger rows claiming "validated prior pass" with no validation behind them, and dependents execute on that basis.

### F3 — MEDIUM: the reuse seal never covers `File` witnesses

`rust_native_reuse_evidence_digest` hashes exactly: `stage_manifest.json`, `stages.tsv`, `state/orchestration_context.json`, plus each record's **stage log** `record.log_path` (`evidence.rs:231-263`; tamper test `vm_lab/mod.rs:53528-53535` proves the log is covered). It does **not** hash the `File`-declared artifacts (`pair_results.log`, `egress_evidence.json`). Input path: after a passing run, delete/replace `active_exit.egress_evidence.json`, then `--run-only` — `validate_rust_native_reuse_evidence` (`evidence.rs:283-336`) still returns `Ok(digest)`, and the reused row asserts a prior pass whose on-disk backing is gone. (Within the prior run the witness was checked at pass time; post-finalize it is unprotected.)

### F4 — LOW/M (doc-code conflict that guards a fixed fail-open): the trait doc contradicts the runner

`stage/mod.rs:521-524`: "An `always_run` stage … is still honored by an explicit `--skip-stage`". The runner deliberately does the opposite (`runner.rs:227-233`, rationale at `:213-221`, pinned by `runner.rs:834`). Blame: the doc is `9c1c90898` (2026-07-04); the runner's always-run-first exemption is `0b952060a` (2026-08-20) — the doc predates and contradicts the fix, and would steer a maintainer to reintroduce the release-blocker residue fail-open.

### F5 — LOW: dead disjunct in `mark_blocked`

`runner.rs:247-248`: `outcome.is_blocking() || matches!(outcome, StageOutcome::Skipped(..))` — branch 1 can only produce `NotRun` or `Reused`, so the `Skipped` disjunct is unreachable. Harmless, but it signals the author believed this branch could emit `Skipped`; a future arm that does would flip cascade semantics silently.

### F6 — LOW: pre-cleanup diagnostics ignore non-`Failed` blockers

`native.rs:948-953` triggers diagnostics only on `StageOutcome::Failed(_)`. A run demoted entirely to `NotProven` (QH-83 unwitnessed passes — the *expected* failure mode of the new gate) or tail-`NotRun` collects no failure diagnostics. Diagnostics-only; verdicts unaffected.

Also noted (task premise check): the two live runs under the gate are recorded at `NodeEngineAuditConsolidation_2026-09-08.md` §3b — `livelab-1788916793` @ `3bfc99e6` 34/1/62 (`key_custody_validation` pattern-G false drift, fixed `36c7017f`) and `livelab-1788919346` @ `36c7017f` **39 pass / 0 fail / 54 skip** — consistent with the matrix rows for `run-2026-09-09-qh83-linux2d` (fail) / `-2e` (partial) this tool returned. See §5 for a count discrepancy I could not reconcile.

## 2. Patches and red tests

**F1 — clear the declared `File` witness before execute (single choke point, mirrors the recorder's own truncate-at-start semantics).** In `run_with_observer_and_pre_cleanup_hook`, after the skip `continue` and before `observer.stage_started(&id)`:

```rust
// QH-83 freshness: a File witness must be produced by THIS execute, never
// inherited from a prior invocation in the same report dir (--run-only /
// --resume-from / --rerun-stage reuse the directory). Same rule the recorder
// applies to logs/<id>.log at stage_started.
if let StageEvidence::File(relative) = id.evidence() {
    let witness = ctx.report_dir.join(relative);
    if let Err(err) = std::fs::remove_file(&witness) {
        if err.kind() != std::io::ErrorKind::NotFound {
            let outcome = StageOutcome::Failed(format!(
                "stage '{}': could not clear stale witness '{}' before execute: {err}",
                id.as_str(),
                witness.display()
            ));
            observer.stage_finished(&id, &outcome);
            ctx.record_outcome(id.clone(), outcome.clone());
            results.push((id, outcome));
            continue;
        }
    }
}
```

(`StageEvidence::File` carries `&'static str`, `stage/mod.rs:210`.) Red test, in `runner.rs` tests reusing the existing fixture machinery (`write_witness: false`, `runner.rs:640`):

```rust
#[test]
fn stale_file_witness_from_a_prior_invocation_cannot_back_a_pass() {
    let (mut ctx, _dir) = tempdir_ctx();
    let witness = ctx.report_dir.join("logs/traffic_test_matrix.pair_results.log");
    std::fs::create_dir_all(witness.parent().unwrap()).unwrap();
    std::fs::write(&witness, b"generation-N artifact").unwrap();
    let stages: Vec<Box<dyn OrchestrationStage>> =
        vec![witnessed_pass_stage(StageId::TrafficTestMatrix, vec![]).with_witness_writing(false)];
    let results = StateMachineRunner::new(stages).expect("valid plan").run(&mut ctx).expect("run");
    assert!(matches!(
        &results[0].1,
        StageOutcome::NotProven { reason: ReasonCode::MissingWitness, .. }
    ));
}
```

Mutation caught: **revert-pre-execute-witness-clearing** — delete the inserted block; the stale file then upholds `Passed` and the test goes red. (Alternative rejected: mtime/generation comparison — racy and weaker than removal; `StaleEvidence` classification kept in reserve for the finer-grained design.)

**F2 — make the digest unforgeable at the type level.**

```rust
pub struct ReuseDigest(String);
impl ReuseDigest {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        if raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(Self(raw.to_owned()))
        } else {
            Err(format!("reuse digest must be 64 hex chars, got {raw:?}"))
        }
    }
    pub fn as_str(&self) -> &str { &self.0 }
}
```

`with_reused_skips` takes `ReuseDigest`; the caller at `native.rs:926` is unchanged in behavior (`validate_rust_native_reuse_evidence` already returns a 64-hex string, `evidence.rs:326-335` — wrap it). Red test: `reuse_digest_parse_rejects_short_or_non_hex` asserting `ReuseDigest::parse("abc123").is_err()`; the existing `runner.rs:1266` test stops compiling with a raw `String` — the mutation is **revert-digest-newtype** (accept `String` again), which re-opens forgery and the parse test pins the validation.

**F3 — reuse validation must witness-check each reused stage.** Split `verify_declared_evidence` into `declared_witness_path(id, report_dir) -> PathBuf` + the existing `verify_evidence_file_at`, then in `validate_rust_native_reuse_evidence`'s loop after the status check (`evidence.rs:309-314`):

```rust
let path = super::runner::declared_witness_path(id, report_dir);
if let StageEvidence::File(_) | StageEvidence::StageLog = id.evidence() {
    // same fail-closed predicate the runner applies to a live pass
    if super::runner::witness_state(&path).is_err() {
        return Err(format!("cannot reuse stage '{name}': its declared witness is absent or empty"));
    }
}
```

Red test (next to the tamper test at `vm_lab/mod.rs:53528`): seal a passing run, delete `active_exit.egress_evidence.json`, assert `validate_rust_native_reuse_evidence(&dir, &[StageId::ActiveExit])` errs. Mutation: **drop-reuse-witness-check**.

**F4 — fix the stale trait doc** (`stage/mod.rs:521-524`), code is authoritative:

```rust
/// Teardown stages that MUST run even when an earlier stage failed — exempt
/// from dependency skip-cascade AND from explicit skips (`--skip-stage`, the
/// `--rerun-stage` tail) and from the shutdown flag, so this run's own
/// killswitch / exit-NAT residue is always removed from the guests (leaving
/// residue is a release-blocker per the operating contract). The runner checks
/// `always_run` ahead of every skip source (`runner::skip_decision`).
```

Red "test": the existing `always_run_cleanup_runs_even_when_explicitly_skipped` (`runner.rs:834`) is the pin; mutation **honor-explicit-skip-for-always_run** (move the explicit-skip branch above the exemption) turns it red.

**F5 — replace the dead disjunct** (`runner.rs:247-248`):

```rust
debug_assert!(matches!(outcome, StageOutcome::NotRun | StageOutcome::Reused { .. }));
let mark_blocked = outcome.is_blocking();
```

Mutation: **add-a-Skipped-arm-to-branch-1** — the debug_assert fires in tests instead of silently changing cascade polarity.

**F6 — widen the diagnostics trigger** (`native.rs:948-953`):

```rust
if !prior.iter().any(|(_, o)| matches!(o, StageOutcome::Failed(_) | StageOutcome::NotProven { .. })) {
    return Ok(());
}
```

Red test at the closure's level: prior `[NotProven{..}]` must invoke `collect_failure_diagnostics`; mutation **diagnostics-ignore-notproven**.

## 3. Gate that kills the class

**Witness-generation gate**, two layers, cheapest first:

1. **Artifact verifier cross-check (S/M):** extend the run-artifact validator to re-derive, per `pass` row, that the stage's declared witness exists, is non-empty, and is newer than the run's `run_started_unix` stamp — stamping `witness: stale` into the verifier output otherwise. This makes F1 and F3 visible from artifacts alone, without reading source, exactly the ledger cross-check pattern proposed for F1 in `NodeEngineSkipSemanticsReview_2026-09-09.md` §3.
2. **Runner invariant test (S):** one property-style test over the fixture catalog asserting the equivalence "terminal `Passed` ⇒ this-execute witness" for both `StageEvidence` kinds and "terminal `Reused` ⇒ 64-hex digest minted only by `validate_rust_native_reuse_evidence`" — any future skip-source or witness path added to the runner must extend this test or the gate fails.

## 4. Effort

F1 **S** (one block + one test). F2 **S** (newtype + parse test + one call-site). F3 **S/M** (refactor shared witness predicate + loop check + test). F4 **S** (doc). F5, F6 **S**. Gate layer 1 **M**, layer 2 **S**. No runner change alters the happy path of livelab-1788919346 (all passes were witnessed per consolidation §3b, and fresh-run report dirs have no stale witnesses).

## 5. What I could not verify

- The `livelab-1788919346` report dir lives on lenovo-bot (`/home/ubuntu/Rustynet/artifacts/live_lab/run-2026-09-09-qh83-linux2e`); `lab_run_detail` refuses non-repo paths, so I read its outcome only through the matrix tool (commit `36c7017f`, overall `partial`) and the consolidation doc. The skip count is unreconciled: consolidation §3b says 54 skip, while `NodeEngineSetupWitnessAudit_2026-09-09.md` §2 quotes `live_lab_node_run_matrix.csv:340` as `passed=39 failed=0 skipped=27 over 66 stages` — 66 ≠ 93 stage-rows, likely stage-rows vs node-stage-rows accounting, unverified.
- Whether any stage writes its declared `File` witness through a path alias (hardlink/bind) that pre-execute `remove_file` would not clear.
- Whether `OrchestrationContext` contains locks a caught panic could poison (subsequent stages would then fail closed with lock-poison errors — safe, but I did not audit `context.rs` fields).
- The `docs` named in the task brief as `EvidenceOnPassDesign_2026-09-08.md` and a `StageEnvironmentPreconditionsDesign_2026-09-09.md` — I found the former; I did not locate the latter in `documents/operations/active/` (the skip-semantics review quotes its § numbers, and the setup-witness audit states "zero matches for `EnvFact`/`fn requires`/`fn provisions` in `crates/rustynet-cli/src`", consistent with designed-not-built).
- I did not re-verify the sibling probes' own findings (vacuous-pass F1 of the skip-semantics review, the 16 unwitnessed Setup rows) — they are carried from `NodeEngineSkipSemanticsReview_2026-09-09.md` and `NodeEngineSetupWitnessAudit_2026-09-09.md`, not re-read line-by-line here.

## Tools used (56 call(s) over 34 step(s))

## 6. Implementation status (2026-09-09, delegated-edit branch `ai-edit/edit-1788948550870-17439-0`)

F1–F4 are IMPLEMENTED and GATED on this branch. Commits (this branch): `30f94393` (WIP checkpoint: F1 pre-execute witness clear + F4 trait-doc fix + F1 test retargets), `8e9d0a42` (F2 `ReuseDigest` boundary + F3 witness-in-seal + validation witness check), `aa6825b4` (F3 reuse-validation tests).

| Finding | Status | Enforcement point | Verification tests (mutation in parens) |
| --- | --- | --- | --- |
| F1 | DONE | `runner.rs` pre-execute clear after `stage_started` (declared `File` witness removed; non-NotFound removal error ⇒ blocking `NotProven{StaleEvidence}`) | `file_witness_from_a_prior_generation_is_not_accepted`, `witnessed_file_evidence_replaces_a_prior_generations_artifact` (mutation: skip the clear) |
| F2 | DONE | `evidence.rs::ReuseDigest` (private field, `parse` sole constructor: trim + 64-hex); `validate_rust_native_reuse_evidence` returns it; `with_reused_skips`/`skip_decision` accept only the newtype; `native.rs` binding typed | `reuse_digest_parse_rejects_short_and_non_hex_input` (mutation: accept a raw String); `validated_reused_skip_does_not_cascade_or_claim_fresh_pass` updated off `"abc123"` |
| F3 | DONE | `evidence.rs::declared_witness_path` (same witness set the runner demands); digest hashes every PLANNED stage's declared witness; validation requires present + non-empty witness per reused id | `tampering_a_declared_file_witness_fails_reuse_validation` (mutation: drop artifacts from digest); `reuse_validation_rejects_missing_or_empty_declared_witness` (mutation: drop presence/emptiness check) |
| F4 | DONE | `stage/mod.rs` trait doc matches runner (`always_run` NOT skippable by `--skip-stage`) | doc-only |
| F5 | NOT DONE (remainder) | dead disjunct `runner.rs` `mark_blocked` (`outcome.is_blocking() \|\| matches!(..Skipped(..))` — branch 1 can only yield NotRun/Reused) — LOW, left as-is | — |
| F6 | NOT DONE (remainder) | diagnostics trigger in `native.rs` should include `NotProven` in prior outcomes | — |
| §3 gate | NOT DONE (remainder) | witness-generation gate layers 1+2 from §3 | — |

Gate evidence on this branch (CARGO_TARGET_DIR=/Users/iwan/Desktop/Rustynet/target-glm-w7):
- `cargo fmt --all -- --check`: exit 0.
- `cargo test -p rustynet-cli --all-features --lib -- vm_lab`: 2758 passed / 0 failed.
- `cargo check -p rustynet-cli --all-targets --all-features`: exit 0.
- `cargo clippy -p rustynet-cli --all-targets --all-features --locked --no-deps -- -D warnings`: exit 0 ONLY with `-A clippy::collapsible_if -A clippy::cloned_ref_to_slice_refs -A clippy::unnecessary_sort_by` — these three rust-1.97 lints fire on code this branch never touched (e.g. `rustynet-cli/src/vm_lab/mod.rs:7924`, `stage/preflight.rs:553`, `workspace_root.rs:239`), byte-identical to base `30f94393`.
- BLOCKER (pre-existing, out of allowlist): `cargo clippy` with deps lints `rustynetd` and fails on 3 `collapsible_if` (`rustynetd/src/phase10.rs:4301/:4911/:4955`); `rustynetd` is byte-identical to base (0 diff lines) — toolchain-drift lint, not this branch's regression, and outside the permitted edit paths. Fix belongs to a rustynetd-scoped change: collapse the three `if`s.
