# Live-Lab Stage Contract Plan — 2026-07-03

Owning ledger for the live-lab stage-contract program: the implementation of
the ten findings recorded in [LiveLabFindings_2026-07-03.md](LiveLabFindings_2026-07-03.md)
(end-to-end analysis of both orchestrators, the monitor TUI, the run matrix,
job/state plumbing, security-control coverage, and timers).

**Core idea (Finding 1):** the stage vocabulary gets ONE owner — a data
registry in `rustynet-cli` — and every run states its plan as a run-scoped
manifest artifact that downstream consumers read instead of hand-copying
catalogs. Everything else (row ownership, terminal states, coverage-as-code,
budgets, header math) builds on that contract.

## Architecture landed

| Piece | Where | What |
|---|---|---|
| Stage registry | `crates/rustynet-cli/src/live_lab_stage_registry.rs` | Every stage as data: canonical name, aliases (phantom heal), group, platform stream, CSV column mappings (direct/logical/role/cross-os/special), platform rule, enablement rule + `TargetSelectors`, budget, severity, `proves` control-IDs, synthetic + conditional-dispatch markers. The four historical match tables in the CSV writer are now lookups; their original bodies survive as test oracles with equivalence tests over the full recorded vocabulary. |
| Stage manifest | `crates/rustynet-cli/src/live_lab_stage_manifest.rs` | `<report_dir>/orchestration/stage_manifest.json`, emitted at run start (wrapper with full selector fidelity; bash best-effort via `ops emit-stage-manifest`; idempotent first-writer-wins). Carries `run_mode` (full/setup_only/validate_only/dry_run), per-stage enabled/skip_reason/budget/severity/synthetic/barrier_exempt, and the selector snapshot. |
| Status taxonomy | registry `StageStatus` | Closed enum (pending running pass fail skipped not_applicable timed_out aborted) + dialect-absorbing parse. Wrapper converters emit "skipped" (canonical); matrix normalizer accepts both dialects and knows aborted/timed_out. |
| Row ownership | `live_lab_run_matrix.rs` | Upsert-by-run-key (report_dir, run_started_utc) + `row_role` interim/final column. Bash EXIT trap = interim (crash visibility, never clobbers); supervisor/focused wrappers = final (replaces). Degenerate keys fall back to append. |
| Conclusion barrier | `live_lab_run_matrix.rs` | On full-mode runs, manifest-enabled non-synthetic non-exempt stages with no recorded outcome get explicit `aborted` rows; `overall_result` demotes such runs. Unregistered recorded names surface as `unregistered_stages:` in notes. |
| Drift gate | registry tests | Bash stage literals (run_stage/run_setup_stage/record_stage_skip extraction) and `StageId::ALL` must all resolve in the registry — always-on cargo tests. |

## Status per finding

| # | Finding | Status |
|---|---|---|
| 1A | Stage registry (collapse 4 CSV match tables) | **DONE** 75f2b7a |
| 1B | Run-scoped stage manifest at run start | **DONE** 5127804 (+ run_mode in 8c006a4) |
| 1C | Recorder validates stage names | **PARTIAL** — unregistered names surface in the matrix row's notes (8c006a4); per-stage recorder validation moves with Finding 4 |
| 1D | Drift gate | **DONE** 86449e6 + monitor half (reads the monitor's fallback-catalog source as text; passes after the e510246 phantom heal) |
| 2 | Run-matrix upsert + interim/final row roles | **DONE** 6cb6940 |
| 3 | Terminal-state taxonomy + conclusion barrier | **DONE** 8c006a4 (cli) + 1404135/e648ec4 + 2026-07-10 monitor hardening: dead-PID runs render CRASHED; one parser now handles every closed terminal status including `not_run`/`reused`; terminal outcomes advance active-stage inference and render distinctly. `blocked_pending_review` job state remains deferred to Finding 4's recorder. |
| 4 | Shared recorder (`ops record-stage-start/finish`) | **PARTIAL** (831a32a; earlier half 844175f) — the "every planned enabled stage ends with a terminal outcome" invariant + the first realtime recorder now hold. (a) The never-dispatched bash-path Rust dialect (13 `state_machine_only` stages) is emitted `enabled:false` + `"inactive orchestrator dialect …"` skip_reason; `reconcile_barrier_exempt_outcomes` (in `finalize_vm_lab_orchestration_result`) backfills explicit `skipped` rows for enabled non-synthetic barrier-exempt stages that recorded nothing (job pseudo-stages, conditional infra) — verdict-neutral (after overall_result + CSV). (b) **Recorder module `live_lab_stage_recorder.rs`** owns `state/stages.tsv`: `record_stage_start` upserts a `running` row, `record_stage_finish` replaces it with the terminal outcome (atomic tmp+rename, 8-col v1 layout + `#schema_version=2` marker, single-writer). (c) **The Rust `--node` path emits the full contract** (831a32a): `build_stage_manifest` gained an `active_plan` override; `StateMachineRunner::run_with_observer` + `StageObserver` drives realtime rows; finalization writes JSON + one matrix row. **2026-07-10 monitor consumption is DONE:** active jobs prefer `stages.tsv` over stale final JSON, read `running` directly, expose source age/errors, and rerun/run-only Rust manifests replace the prior invocation's manifest in reused report dirs. Still OPEN: bash per-stage recorder calls, `report_state` job_state/heartbeat, and per-stage recorder validation (Finding 1C/10). |
| 5 | Coverage-as-code (`proves` × run-matrix evidence gate) | **v1 DONE** bf3640e — `ops live-lab-coverage-report` joins registry claims against latest non-interim matrix evidence (all six audit-control families live-proven on all 3 OSes as of 2026-07-03); gate enforcement with reviewed exceptions still open |
| 6 | Timer budgets (P90-of-all-terminal, manifest-carried) | **DONE** 1404135 — P90 over all terminal outcomes x1.2 slack, floored by the manifest budget (falls back to hand-tuned defaults) |
| 7 | Header math (ran/planned/NA from manifest snapshot) | **DONE** e648ec4 + 2026-07-10 — grid + enablement derive from the run manifest; schema v2 emits `counts_as_check`, so header separates settled stages, run-local tests, and history-wide coverage. Schema-v1 reports show `n/a`, never inferred counts. Pruned reports show labelled CSV-only counts, not a fabricated PRE total. |
| 8 | `area` string demoted to display-only | **DONE** d91dac3 — client_platform structured selector; wants_macos/wants_windows/current_target_cell read structured fields only |
| 9 | `disabled_stages` validation | **DONE** d91dac3 — unknown names pruned with a warning on every config load, prune persisted |
| 10 | Evidence contract | OPEN — registry has the field surface; enforcement belongs to Finding 4's recorder |
| — | Seeded monitor fixes (idle-log catch-up, ACTIVITY column removal) | **DONE** bad117f |
| — | macOS anchor/daemon plist passphrase-path drift (found en route) | **DONE** 7f2dab7 |

## Known deliberate gaps / hazards

- **Healed vs preserved drift:** the registry preserves the historical
  behavior byte-for-byte (test oracles) except the alias heal
  (`distribute_windows_bundles` → `distribute_windows_membership`). The
  `issue_and_distribute_traversal`/`_dns_zone` logical-column gap is
  documented in place and deliberately NOT healed yet — healing changes CSV
  column population and needs its own tested change.
- **Barrier fidelity:** stages whose dispatch is runtime-gated beyond the
  selectors (per-OS audit families, standalone linux validators,
  cross-network auto mode) are `conditional_dispatch` and barrier-exempt —
  a missing outcome for them is not evidence of abnormal termination. As
  dispatch becomes selector-visible (Finding 4's recorder), entries can
  graduate to barrier-eligible.
- **Bash standalone manifest fidelity:** a bash-only run emits selectors
  from what bash knows (exit/relay platform, chaos, soak, gates, run mode);
  wrapper-launched runs get full fidelity. Cross-network flags are omitted
  from the bash emit (auto mode).
- **Monitor consumption (landed e648ec4/e510246; hardened 2026-07-10):** an
  active or held report never substitutes the fallback catalog. Missing data
  renders `WAITING FOR MANIFEST`; invalid data renders `DATA ERROR`. The local
  catalog is labelled `LEGACY PREVIEW` and used only when no report is selected.
- **`role_transition` column gap (healed):** `validate_macos_role_transition`
  and `validate_windows_role_transition` were registered stages with no
  `direct_platform` mapping — a real pass/fail never landed in any run-matrix
  column, so coverage queries over stage history (e.g. `find_untested_work`)
  had no visibility into either direction for this stage. Fixed by mapping
  both to `("<os>", "role_transition")` → `<os>_stage_role_transition`,
  updating the registry-equivalence oracle in lockstep (`registry_matches_
  historical_direct_platform_stage`), and adding both new columns to
  `DEFAULT_MATRIX_COLUMNS` (self-migrates the on-disk CSV header via
  `ensure_matrix_schema` on the next append — no manual file surgery). Found
  while investigating why the Windows role-transition live-lab proof
  (`CrossOsRoleSwitchPlan_2026-06-24.md`) wouldn't show up in automated
  coverage once re-run.

## Verification

- Registry/manifest/upsert/barrier/drift tests are inline in the three
  modules; the full `rustynet-cli` suite (1882) is green at 86449e6.
- Live-lab validation of the manifest + interim/final rows requires the next
  standard orchestrate run: verify `orchestration/stage_manifest.json`
  exists in the report dir and the run matrix gains exactly one final row
  for the run (interim replaced), with `row_role` populated.
- 2026-07-10 monitor proof: 184 monitor tests + clippy `-D warnings` green;
  12 focused `rustynet-cli` manifest tests + scoped CLI check green. See
  `LiveLabMonitorTUIAccuracyImprovements_2026-07-10.md`.
