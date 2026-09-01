# Investigation: the residual macOS `anchor_validation` skip — the posture gate is NOT the cause; `--skip-linux-live-suite` drops the validator set the stage delegates to

Date: 2026-08-31
Run investigated: `livelab-1788165016205-17194-3` (macOS anchor cell rerun, commit `5db953ad`, `macos-utm-1` as anchor, `--anchor-platform macos --skip-linux-live-suite`)
Scope: read-only investigation of the `anchor_validation` stage skip emission on the Rust `--node` orchestrator. No code changed.

## Summary

The prior note in `CrossPlatformRoleParityRefresh_2026-07-23.md` (anchor row, line 100) attributes the residual `anchor_validation` skip to "a separate, still-open bundle-pull `is_supported_for_platform` posture-gate issue". **That attribution is wrong — verifiably so.** The `is_supported_for_platform` posture gate is deliberately never consulted by this stage (that de-circularisation *is* MAC-D1, commit `8ec851a9`). The actual mechanism, confirmed end-to-end in code and in the run's own artifacts:

1. The run was launched with `--anchor-platform macos --skip-linux-live-suite` (job record `state/deepseek-mcp-jobs/labrun-1788165016205-17194-3.json`, `request_args`: `anchor_platform: "macos"`, `skip_linux_live_suite: true`).
2. `--skip-linux-live-suite` drops **every** `StageSuite::Live` stage from the plan (`crates/rustynet-cli/src/vm_lab/orchestrator/plan.rs:264-267`, `StageSuite::Live => !skip_live_suite`). The three macOS anchor validator-set stages are tagged `@ Live` (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs:226-228`: `deploy_macos_anchor_profile`, `validate_macos_anchor_bundle_pull`, `validate_macos_anchor_port_mapping_authority`, all `@ Live / T1Role`), so they never entered this run's plan. Confirmed in the run's `state/stages.tsv`: no rows exist for the three stages; `anchor_validation` is `skipped` with the exact string "no node executed this validation; 1 node(s) reported a runtime skip".
3. MAC-D3's tightening (`native.rs:376-383`) then does exactly what it was built to do: `macos_anchor_validators_elected` stays `true` only when all three validator-stage IDs are present in `plan_stage_ids`. They are not, so the election flag is set `false`.
4. `anchor_validation`'s per-node coverage decision (`anchor_validation.rs:290-307`) falls to its fourth arm — macOS *without* validator election → `ReportedSkip` — the node lands in `runtime_skips` (`anchor_validation.rs:242-244`), and `outcome_for` (`anchor_validation.rs:327-338`, skip string at :331-334) emits the observed skip message.

So the skip emission itself is **fail-closed by design** (MAC-D1 + MAC-D3 working as built). The **bug** is upstream: the Live-suite filter is suite-tag-granular, not election-aware, so the documented fast path for mac/win cells (`--anchor-platform macos` + `--skip-linux-live-suite`) makes the macOS anchor cell *unprovable* — the three stages that ARE the cell are swept out by a filter documented as dropping the *Linux* suite, the run still reports overall PASS, and the skip gets misdiagnosed in the parity ledger as a posture-gate issue.

## (a) Exact skip-emission site

`crates/rustynet-cli/src/vm_lab/orchestrator/stage/anchor_validation.rs:331-334`, inside `outcome_for(failures, runtime_skips)` (:327-338): if any hard failure → `Failed`; else if `runtime_skips` is non-empty → `StageOutcome::Skipped("no node executed this validation; {n} node(s) reported a runtime skip")`; else `Passed`. `runtime_skips` is populated only by the `ReportedSkip` arm of the per-node coverage decision at `anchor_validation.rs:290-307` (collected at :242-244). The run's `state/stages.tsv` records this stage as `skipped` with that exact message, so at least one anchor node (macos-utm-1) produced `ReportedSkip`.

## (b) The gate that actually fired (and the gate that did not)

**Not the posture gate.** `NodeRole::is_supported_for_platform` is defined at `crates/rustynet-cli/src/vm_lab/orchestrator/role.rs:75`, but `anchor_validation` deliberately never calls it — doc comments at `anchor_validation.rs:37-41` ("NEVER `NodeRole::Anchor::is_supported_for_platform`"), :106-108, :203-209, :260-264, and `role_validation/anchor.rs:291-299` all state the de-circularisation rationale (gating a stage on the same predicate whose promotion requires the stage's own green run is circular — MAC-D1, `MacCellsHarvest_2026-08-28.md` §2.2). `anchor_lab_runtime_implemented` (`role_validation/anchor.rs:322-324`) returns `true` for Linux **and** macOS, so the platform-implemented check did not fire either.

**What fired:** `runtime_coverage`'s third/fourth arms (`anchor_validation.rs:290-307`). For macOS the coverage is `DelegatedToMacosValidators` only when `ctx.macos_anchor_validators_elected == true`; otherwise `ReportedSkip`. That flag is initialized in `orchestrator/context.rs:228` (default `false`, :261/:388), preset at `orchestrator/native.rs:261` from `config.anchor_platform.as_deref() == Some("macos")`, and then **tightened** at `native.rs:376-383` (MAC-D3): it remains `true` only when `StageId::MacosAnchorProfileDeploy`, `MacosAnchorBundlePullValidation`, and `MacosAnchorPortMappingAuthorityValidation` are all present in the built plan. Because `--skip-linux-live-suite` filters every `StageSuite::Live` stage out of the plan (`plan.rs:264-267`; suite tags at `stage/mod.rs:226-228`), the three stages were absent, the flag fell back to `false`, and the skip was emitted. The run artifacts corroborate each link: launch args (`labrun-1788165016205-17194-3.json`), missing stage rows + skip message (`state/stages.tsv`), and the parity doc's own note that `live_anchor` was not dispatched.

## (c) Assessment: by-design or bug?

**Both, at different layers. Confidence: high (~90%) on the mechanism — every link verified in code and in the run's artifacts; ~85% on the verdict.**

- **By design (correct, keep):** the skip emission and MAC-D3's tightening. A stage must never grade delegated evidence when the delegation did not dispatch, and a macOS anchor without its validator set must be a *named* reported skip, never a silent pass (`anchor_validation.rs:13-117` design chain; evidence artifacts `anchor_validation.reported_skips.json`, :76 and :344-400). This is fail-closed in the right direction.
- **Bug (the filter granularity):** `plan.rs:264-267` drops the three macOS anchor validator stages under `--skip-linux-live-suite` even when the same invocation explicitly elects `--anchor-platform macos`. The documented fast-path contract (AGENTS.md §12.5, `ai_lab_run` `skip_linux_live_suite`: skip the ~30–45 min **Linux** live-validation suite and "run ONLY setup + the targeted mac/win cell … the mac/win stages … stay fully exercised") is violated for the anchor cell: the "targeted mac/win cell" *is* those three stages, and the filter removes them. Consequences: (1) the macOS anchor cell can never be exercised on the fast path, so `anchor_validation` will reported-skip every such run forever; (2) the run still reports overall PASS (16 pass / 0 fail / 3 skip) even though the run's own stated purpose — verify the MAC-D1 fix clears the `anchor_validation` skip — went unmet, because a skip is not a failure; (3) the residual skip invites exactly the wrong diagnosis the parity doc then recorded (a "posture-gate issue" that the code proves cannot exist on this path).

## (d) Fix (description only, no code)

Single-point fix in the plan builder; no `anchor_validation` change is needed because the MAC-D3 handshake downstream reacts automatically once the stages survive planning:

- In `PlanBuilder::build` (`crates/rustynet-cli/src/vm_lab/orchestrator/plan.rs:244-269`), make the `include` closure election-aware: when the run elected `--anchor-platform macos` (thread the same `config.anchor_platform.as_deref() == Some("macos")` condition used at `native.rs:261`/`:376` into `PlanBuilder`, e.g. as a new builder field set next to `with_skip_live_suite` at :204-207), retain `StageId::MacosAnchorProfileDeploy`, `MacosAnchorBundlePullValidation`, and `MacosAnchorPortMappingAuthorityValidation` even under `skip_live_suite`. With the three stages back in the plan, `native.rs:376-383` keeps the election `true`, the stages dispatch, and `anchor_validation` grades delegated evidence instead of skipping.
- Alternative with the same effect: move the three stages out of `StageSuite::Live` (their suite tags live at `stage/mod.rs:226-228`) so they are governed by the anchor election rather than the Linux-suite flag. The builder-field approach is narrower; re-suiteing changes the stage catalog semantics for every reader of the suite tags and should be weighed against RNQ-16's suite-inclusion authority (`plan.rs:259-263`).
- Guardrails: update the `with_skip_live_suite` plan tests (`plan.rs:506`, :594, :609, :651) to cover the election interaction, and note that the "dropped stages ⇒ flag false" property tested around `native.rs:376-383` must keep holding for runs that drop the stages for other reasons (setup-only mode, resume) — the fix must add an exception only for the explicit anchor election.
- Docs: correct the anchor row of `CrossPlatformRoleParityRefresh_2026-07-23.md` (line 100) — the "separate, still-open bundle-pull `is_supported_for_platform` posture-gate issue" attribution should be replaced with this mechanism (Live-suite filter drops the delegated validator set; posture gate not consulted), and AGENTS.md §12.5's `skip_linux_live_suite` contract description is accurate only once this fix lands.

## (e) If treated as by-design instead: what the docs must then say

If the project chooses to keep the current behaviour (fast path does not exercise the macOS anchor cell), that choice must be stated explicitly rather than left to be rediscovered per run: (1) `anchor_validation`'s skip message should distinguish "platform runtime not implemented / no election" from "elected but the validator set was dropped by `--skip-linux-live-suite`" — the current single message (:331-334) is accurate but hides the operator-fixable cause; (2) `ai_lab_run`'s `skip_linux_live_suite` documentation (AGENTS.md §12.5) must drop its claim that the elected mac/win cell "stays fully exercised" for the anchor role, or name anchor as the exception; (3) the parity refresh doc must record the macOS anchor bundle-pull cell as *blocked on the fast path* (provable only via a full run without `--skip-linux-live-suite`) instead of as an open posture-gate defect. The by-design reading is inferior: it makes a release-blocking parity cell (CrossPlatformRoleParityPlan mandate) unprovable on the standard iteration path for no security benefit, while the fail-closed property the current design protects is fully preserved by the MAC-D3 handshake once the stages survive planning.

## Evidence index

| Claim | Source |
| --- | --- |
| Launch args `anchor_platform=macos`, `skip_linux_live_suite=true` | `state/deepseek-mcp-jobs/labrun-1788165016205-17194-3.json` `request_args` |
| Three validator stages absent from plan; skip message verbatim | run `state/stages.tsv` (anchor_validation row) |
| Live-suite filter drops all `@ Live` stages | `plan.rs:264-267` (suite authority :259-263) |
| Validator stages tagged `@ Live / T1Role` | `stage/mod.rs:226-228` |
| MAC-D3 tightening: flag true only if all three in plan | `native.rs:376-383`; preset :261; context default `context.rs:228` |
| Coverage decision + skip emission | `anchor_validation.rs:290-307`, :242-244, :327-338 (string :331-334) |
| Posture gate not consulted (de-circularisation) | `anchor_validation.rs:37-41`, :106-108, :203-209, :260-264; `role_validation/anchor.rs:291-299`, :322-324; `role.rs:75` |
| Prior (incorrect) attribution in parity ledger | `CrossPlatformRoleParityRefresh_2026-07-23.md` line 100 (anchor row) |
