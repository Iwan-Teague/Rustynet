# Setup-suite witness audit (QH-83 phase-1 remainder) — 2026-09-09 (GLM-5.3-flash, grounded, trusted input)

Probe W1: per-stage table of what a Setup `Passed` measures, what it writes, and the StageEvidence row it should declare. Feeds the SETUP witness batch edit job together with the provenance audit below.

[glm/glm-5.3-flash | AGENT | budget=40 | briefed]

# Setup-suite witness audit — QH-83 phase-1 remainder

## 1. Root cause

The evidence-on-pass mechanism is correctly built and correctly checked, but the Setup catalog rows were never upgraded: of the 17 Setup stages, **16 still declare `StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING }`** and only `MembershipInit` declares `StageLog` (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs:283-306`). For a `None` row the runner's check is an explicit pass-through (`runner.rs:301-302`), so in livelab-1788919346 every green Setup cell except `membership_init` is a pass with **zero on-disk witness**. The consolidation doc itself records this state: "Only 3 of 81 stages are witnessed at landing; the 76 PHASE1_EVIDENCE_PENDING rows are the honest remainder" (`NodeEngineAuditConsolidation_2026-09-08.md` §3 item 3), and the design ordered Setup first in the per-suite batches (`EvidenceOnPassDesign_2026-09-08.md` §6.2) — that batch has not landed. This is the finding; everything below is the batch.

Severity framing is ledger integrity throughout, per the task.

## 2. Mechanism (verified, load-bearing)

- Check point: after `catch_unwind`, before `stage_finished` — `runner.rs:194-196` (`if matches!(outcome, StageOutcome::Passed) { outcome = verify_declared_evidence(&id, ctx, outcome); }`). Correct placement: the recorder truncates `logs/<id>.log` at `stage_started` and appends the verdict at `stage_finished`, so the log at this instant contains only what `execute` wrote. Pinned by `demotion_fires_before_observer_appends_verdict` (`runner.rs:1566`).
- Demotion is blocking end-to-end: `NotProven` → `VmLabStageStatus::NotProven` (`evidence.rs:351`), and a NotProven leaf can never reach `run_passed=true` (`evidence.rs:1265-1276`, test at `evidence.rs:2105`).
- The opt-out is already machine-visible per run: `node_stage_plan.json` carries `"evidence":{"kind":"none","reason":...}` per stage (`evidence.rs:410-424`), schema pinned at 1 because `write_node_stage_result_ledgers` (`live_lab_run_matrix.rs`) still pins `schema_version == 1` (`evidence.rs:427-434`).
- Mechanism tests already present: `stage_log_witness_upholds_pass` (`runner.rs:1328`), `witnessed_file_evidence_upholds_pass` (`:1510`), `evidence_opt_out_stages_pass_without_witness` (`:1526`), `evidence_declaration_validation_rejects_malformed_paths` (`:1545`).

Live-run grounding: run `livelab-1788919346` @ `36c7017f` is `partial`, `passed=39 failed=0 skipped=27` over 66 stages (`documents/operations/live_lab_node_run_matrix.csv:340`); per-node pass rows for all Setup stages at `documents/operations/live_lab_node_stage_results.csv:47705-47717` — every row points at a `logs/<stage>.log` that, for the 16 unwitnessed stages, contained only the recorder's verdict echo, no execute-time content.

## 3. Findings

**F1 (HIGH — ledger integrity): 16 of 17 Setup verdicts are unwitnessed.** `stage/mod.rs:283-306`; the pass-through is `runner.rs:302`. Failing input: any of the 16 stages returning `Passed` — including a future regression that passes vacuously — writes nothing and stands as green. Why no input fails today: there is no input that can fail a `None` row's witness check, by construction.

**F2 (MEDIUM — pass paths that write nothing even by intention):**

**F3 (LOW — vacuous passes visible only as missing counts):** empty-assignment topologies pass `verify_ssh_reachability`, `cleanup_hosts`, `enforce_baseline_runtime`, `validate_baseline_runtime` (tests literally named `empty_assignments_passes`, e.g. `verify_ssh.rs:96`, `enforce_runtime.rs:278`), and exit-only topologies pass `distribute_membership` (`no_non_exit_nodes_passes_trivially`, `distribute_membership.rs:113`). The `requires()`/`provisions()` design (`StageEnvironmentPreconditionsDesign_2026-09-09.md`) is **not built** — zero matches for `EnvFact`/`fn requires`/`fn provisions` in `crates/rustynet-cli/src`. Witness lines naming node counts make vacuousness auditable without changing skip semantics.

## 4. Per-stage audit

| Stage | What `Passed` measures | Artifact today | Should declare | Pass path writing nothing? |
|---|---|---|---|---|
| preflight | report_dir writable, profile-record immutability, ssh binary, per-node clock skew ≤90 s, cross-bridge /24 probes fail-closed (`preflight.rs:327-499`, `:637-695`, `:833-840`) | `logs/cross_bridge_preflight.txt` (`:823`) | `File("logs/cross_bridge_preflight.txt")` + make write failure fatal | only on silent write failure (`:829`) |
| prepare_source_archive | tarball built + validated; provenance pinned (`source_archive.rs:239-297`, fail-closed provenance `:278-289`, `:300-306`) | `state/source_archive_provenance.json` (fresh path only) | `File("state/source_archive_provenance.json")` + write provenance on the reuse path | yes, `:240-242` |
| verify_ssh_reachability | `check_ssh_reachable()` per assigned node (`verify_ssh.rs:26-49`) | none | `StageLog` + append | always |
| cleanup_hosts | `cleanup_runtime_state().and_then(assert_node_clean)` per in-set node; no-adapter fails closed (`cleanup.rs:63-79`) | none | `StageLog` + append | always |
| bootstrap_hosts | `install_daemon` per in-set node; `validate_reused_daemon` (node_id+pubkey probes) for reused (`install.rs:63-113`, `:116-135`) | none found in stage | `StageLog` + append | stage itself, yes (adapter writes unverified — see §8) |
| cross_network_substrate_setup | no-overlay: record/request match; overlay: `provider.setup` (`substrate.rs:2060-2110`, `:2016-2027`) | none on no-overlay path | `StageLog` + append both pass paths | yes on no-overlay (`:2063-2072`) |
| collect_pubkeys | per-node pubkey + gossip identity + node_id (+STUN rules) collected fail-closed (`collect_pubkeys.rs:32-200`) | none (ctx-only; pubkey eprintln temp diagnostic) | `StageLog` + append (pubkeys are public, already printed) | always |
| membership_init | owner key + signed snapshot minted on exit; macOS exact-set assert | stage log lines on every pass (`membership_init.rs` snapshot_evidence_line + F1 line, append failure = Failed) | `StageLog` — **already correct** (reference pattern) | no |
| distribute_membership | membership snapshot distributed to every non-exit node (`distribute_membership.rs:26-68`) | none in report_dir (tmp file in `env::temp_dir`, removed) | `StageLog` + append (snapshot bytes count) | always |
| anchor_validation | per-anchor capability advertisement + bundle-pull runtime substages (`anchor_validation.rs:137-257`) | `anchor_validation.reported_skips.json` (`:254`) | `File("anchor_validation.reported_skips.json")` + fatal write | only on silent write failure (`:396`) |
| admin_issue | `node_role=admin` in status (≤4 tries) + peer-list exit 0 (`admin_issue.rs:44-70`, `role_validation/admin_issue.rs:11-53`) | none | `StageLog` + append | always |
| distribute_assignments | verifier-key sha validated, verifier barrier, signed bundle installed per node (`distribute_assignments.rs:229-301`) | none in report_dir | `StageLog` + append (verifier key sha256) | always |
| distribute_traversal | same shared fn, `BundleKind::Traversal` (`distribute_traversal.rs:44-54`) | none | `StageLog

## Tools used (63 call(s); step budget of 40 reached)

## Review disposition (2026-09-09, GLM-flash, MERGE-SAFE with two should-fixes → merged)

The Setup batch landed on the `--node` engine: preflight and
prepare_source_archive declare the files they already write
(`File("logs/cross_bridge_preflight.txt")`,
`File("state/source_archive_provenance.json")`), verify_ssh_reachability /
cleanup_hosts / bootstrap_hosts / cross_network_substrate_setup /
collect_pubkeys / admin_issue / enforce_baseline_runtime declare `StageLog`
and append a count-bearing witness line on every pass path (write failure =
`Failed`), and the four distribute rows declare their per-alias
`bundle_evidence.json` witnesses (F1b, `stage/bundle_evidence.rs`). The
reviewer enumerated every `Passed` return site in the flipped stages and
found each witnessed; F2 (prepare_source_archive reuse path) and F3 (vacuous
passes now read as `nodes=0` in the stage log) are closed by construction.

Fixes applied before merge:
- preflight kept walking the fleet after a remediated clock instead of
  returning `Passed` from inside the loop (which skipped the cross-bridge
  check and the witness), and its report write is now fatal.
- prepare_source_archive's early pass for an archive already in context now
  fails when the provenance pin is absent (the runner clears File witnesses
  at stage start), instead of returning an unwitnessed `Passed`.
- `refresh_signed_bundles` shared `distribute_traversal`'s witness path, so
  the runner's clear-at-start for the refresh stage erased the Setup-phase
  record and a failed refresh left the run unsealable. Witness paths now
  carry a `BundleWitnessScope` (Setup / Refresh / Scoped{alias}); the refresh
  row declares `logs/refresh_signed_bundles.traversal.bundle_evidence.json`
  and the single-alias reboot-recovery redistribution writes an
  alias-qualified file rather than overwriting the fleet generation.
- Runner tests shared one `/tmp/test-report` dir across nextest's
  concurrent processes; stale witnesses from other tests had been masking
  unwitnessed fixtures. Every test now gets its own report dir and the
  fixtures that assert a Setup pass write the declared witness.

Second half (same day, job `edit-1788967408531-2246-0`, flash review
MERGE-SAFE, one NIT applied — anchor_validation grades first and witnesses
exactly the `Passed` verdict): anchor_validation now appends one
`anchor_validated=yes alias=… validated=…` line per validated anchor (its
reported-skips note write is fatal too) and validate_baseline_runtime appends
`validated_nodes=N (aliases)`. Every Setup row now declares a real witness;
none is left on `PHASE1_EVIDENCE_PENDING`. Reviewer's blast-radius note: the
reuse seal now binds the two new stage logs, so report dirs sealed by a
pre-batch binary are refused for `--run-only`/`--resume-from`/`--rerun-stage`
— fail-closed; start a fresh run. Flag-day check: a live 2-node Linux run on
lenovo-bot after each merge, before any evidence claim is made against the
new declarations.
