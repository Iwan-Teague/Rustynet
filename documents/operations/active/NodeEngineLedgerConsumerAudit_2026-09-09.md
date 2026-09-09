# Run-ledger consumer integrity audit — 2026-09-09 (GLM-5.3-flash, grounded, trusted input)

Probe W6 (second, read-budgeted attempt). QH-07 column contamination closed for registered stages; CSV writers quote-safe; scenario layer re-derives from artifacts; D1–D3 (crash-time row loss, non-atomic ledger rewrites) dispatched as an edit job; D4 (File witnesses outside the reuse seal) is handled by the runner-edge job.

# Rust `--node` run-ledger consumer integrity — findings

## (1) Can a stage verdict reach the ledgers without its evidence artifact on disk?

**For `StageEvidence::File` / `StageLog`: not past the runner's single choke point — but only checked once, at finish.** The run loop intercepts every `Passed` outcome *before* the recorder observer fires and demotes to `NotProven { MissingWitness }` when the declared witness is absent/empty/unreadable: `runner.rs:194-196` (`outcome = verify_declared_evidence(&id, ctx, outcome)`), dispatch at `runner.rs:301-323` (`StageLog` → `rust_native_stage_log_path`, `File(relative)` → `report_dir.join(relative)`). Because the demotion happens before `observer.stage_finished` (`runner.rs:202`), the `stages.tsv` row — the sole input to the matrix via `read_stage_evidence` (`live_lab_run_matrix.rs:1583-1596`) — records the demoted verdict. Pinned by `pass_without_stage_log_witness_is_demoted_to_not_proven` (`runner.rs:1345`) and `pass_without_declared_file_witness_is_demoted_to_not_proven` (`runner.rs:1399`), whose doc comments name the exact mutations they catch.

**For `StageEvidence::None`: nothing is checked, plainly.** `runner.rs:302` returns the outcome unchanged; the doc at `runner.rs:291-294` says these "carry a recorded opt-out reason and pass through unchanged", and `evidence_opt_out_stages_pass_without_witness` (`runner.rs:1526`) pins that they pass *without any on-disk witness*. A `None` row's `pass` therefore reaches both ledgers with no artifact, by design.

**Residual gap (defect D4):** the witness is checked for *existence at finish time only* — no digest is pinned, and the reuse seal (`evidence.rs::rust_native_reuse_evidence_digest`) hashes only `stage_manifest.json`, `stages.tsv`, `orchestration_context.json`, and the per-stage *logs* — declared `File` artifacts are **not** covered. A pass can stand on a witness deleted or mutated after finish; nothing in the ledger write path (`write_node_stage_result_ledgers`, gated on `Final` at `live_lab_run_matrix.rs:490-492`) re-stats it.

## (2) QH-07 column contamination

**Closed for registered `--node` stages.** The mapping is registry data, not a match table: `live_lab_run_matrix.rs:2202-2204` (`logical_stage_name` → `crate::live_lab_stage_registry::logical_stage_name`) and `:2194-2196` (`direct_platform_stage` → `find_stage(stage)?.direct_platform`). The production source of truth, quoted:

- The other `two_hop` mapper, `live_two_hop` (`live_lab_stage_registry.rs:1960-1961`, `logical: Some("two_hop")`), is a bash-dialect spec (`EnableRule::LinuxLiveSuite`, no `StageId`) and cannot write a `--node` row — same conclusion at `live_lab_run_matrix.rs:443-452`.

**Residual vectors (narrow):** (a) alias-qualified ids are stripped before classification (`registry.rs:2481` `strip_node_alias`; `run_matrix.rs:1900-1902`) — fixed, previously a silent `not_run`; (b) `logical_stage_name` retains *prefix fallbacks* (`chaos_*`, `*reboot*`) for names the registry does not know (`registry.rs:2477-2485`) — an unregistered future stage id matching a fallback can still contaminate a column; drift is gated by `every_registry_stage_column_reference_exists_in_the_csv_schema` (`run_matrix.rs:3182`) but the fallback path itself is the open class. The run-scoped fan-out bug of the same class (`preflight` → all three `{platform}_stage_bootstrap`) is suppressed at `run_matrix.rs:1914-1927` (W-FIX-3), pinned by `a_run_scoped_preflight_failure_leaves_every_per_os_bootstrap_column_never_reached` (`:3630`).

## (3) CSV quote safety

**Quote-safe; one shared serializer, no raw concatenation found in the audited writers.** `csv_escape` (`live_lab_run_matrix.rs:2792-2799`) quotes on `,` `"` `\n` `\r` and doubles embedded quotes; `neutralize_csv_formula` (`:2807-2812`) prefixes formula-leading cells (RSA-0055). Every cell of both ledgers flows through it: per-run node CSV `render_named_csv_row` (`:777-783`), run matrix `render_csv_row` (`:2746-2756`), report-local row (`:2736`, values still via `render_csv_row`; only the constant header is joined raw). Migration re-renders through a quote-aware parser: `migrate_node_stage_row` → `parse_csv_record` (`:839-847`, `:2904+`). Headers are constant joins (`:768`, `:917`), never field data. Pinned by `csv_render_escapes_quotes_and_commas` (`:4453`) and `rsa0055_csv_escape_neutralizes_formula_injection` (`:4274`). Scope caveat: I audited this file's writers only, not the failure-digest/run-summary writers.

## (4) Re-derivation from artifacts vs in-memory trust

**Scenario layer: artifacts, strictly.** `pass_certificate::evaluate` is the sole `PassCertificate` minter (no public constructor); it re-verifies contract digest, run-generation binding, per-artifact containment + SHA-256 against the file on disk, and an independent recomputer — self-reported `result` fields are never consulted; empty required-assertion sets and missing recomputers are `NotProven`, never pass (`pass_certificate.rs`, `evaluate`). `finalize::evaluate_wired_scenarios` re-derives every present wired scenario from raw witnesses, demotes the run on any non-pass, and treats an unresolvable/tampered contract as an `Err` (fail closed) (`finalize.rs`, `wired_scenarios` + tests `a_tampered_contract_digest_is_an_integrity_error`, `a_wrong_generation_is_not_a_pass`).

**Run/matrix finalizer: recorded verdicts, not re-derivation.** `build_live_lab_run_matrix_values` reads `stages.tsv` (`:1583`), `orchestrate_result.json` (`:1598`), and the caller's in-memory `extra_stage_outcomes` (`:361`) as `StageEvidence`, then `overall_result` (`:2474-2493`) trusts `report_state.run_passed` unless a terminal failure or the conclusion barrier's `aborted`/incomplete demotion fires. That is the intended division of labor (QH-83 at the runner, scenario re-derivation at the finalizer), but it means the ledger layer itself performs zero artifact re-checks — see D4.

## (5) Crash mid-run — what exists

- Write atomicity of the shared ledger is fine on the row path: `upsert_csv_row` rewrites under an append lock via tmp+rename (`:2629-2631`, `:2706-2712`), and the aggregate node-stage matrix likewise (`:926-941`). Two writers are **not** atomic: the per-run node CSV (`fs::write`, `:773`) and — worst — the **shared-ledger schema-upgrade rewrite** (`fs::write(path, upgraded_body)`, `:1000`).

### Defects, patches, tests

| # | Defect | Severity (ledger integrity) | Effort |
|---|---|---|---|
| D1 | Crashed `--node` run leaves **no** run-matrix row (Interim never emitted; `run_matrix.rs:483-486`) | **High** — silent loss of a run from the committed evidence ledger | M |
| D2 | Shared-ledger schema upgrade is a plain in-place `fs::write` (`:1000`), unlike the row path's tmp+rename (`:2706-2712`); crash mid-upgrade truncates/corrupts the committed history | **High** (rare window, destroys prior rows) | S |
| D3 | Per-run node-stage CSV written non-atomically (`:773`) and *before* the matrix upsert (`:490-493`): crash window leaves refreshed node CSVs with no ledger row, or a torn per-run file | Medium (self-heals on next `Final`, single-run file) | S |
| D4 | `StageEvidence::File` witnesses: existence-only check at finish, no digest pin, not covered by the reuse seal; ledger writers never re-stat (`:1583-1596`, `:490-492`) — a `pass` stands on a vanished/mutated witness | **High** | S/M |

**D1 patch** — in the runner's abort/crash path (where the conclusion barrier already synthesizes `aborted`), before process exit:

```rust
// vm_lab orchestrator abort/finalize path
append_live_lab_run_matrix_row(LiveLabRunMatrixAppendConfig {
    // …same fields as the Final append…
    notes: Some("run aborted before finalization; row_role=interim".into()),
    row_role: LiveLabRunMatrixRowRole::Interim,
})?;
```
`upsert_csv_row` already refuses to clobber an owned key (`:2683-2687`). Test: `an_aborted_rust_node_run_writes_an_interim_ledger_row_for_its_run_key` — mutation: delete the Interim append from the abort path → red.

**D2 patch** — factor the tmp+rename from `upsert_csv_row:2706-2712` into one helper (or reuse `orchestrator::context::atomic_write_fsync`, already used for `report_state.json` in `evidence.rs::write_report_state_durable`) and route `ensure_matrix_schema`'s upgrade write (`:1000`, and inits `:865`, `:968`) through it. Test: `a_failed_schema_upgrade_leaves_the_committed_ledger_untouched` (force the tmp write to fail; assert original bytes intact) — mutation: revert to in-place `fs::write` → red.

**D3 patch** — same helper for `write_node_stage_csv` (`:773`). Existing coverage: `an_existing_per_run_file_with_an_old_header_is_rewritten_canonical`; add `node_stage_csv_write_is_replace_by_rename` (assert no `.tmp` residue after write) — mutation: revert to `fs::write` → red.

**D4 patch** — two halves: (a) extend `rust_native_reuse_evidence_digest` to hash each registered `StageEvidence::File` path's bytes (missing file ⇒ `Err`, fail closed); (b) in `write_node_stage_result_ledgers`, stat each `pass` row's declared witness and demote `pass` → `not_proven` with an explanatory cell when absent (§2 verify-before-apply; no new runtime fallback path). Tests: `a_tampered_declared_file_witness_breaks_the_reuse_seal` and `a_pass_row_whose_declared_witness_vanished_never_reaches_the_node_ledger_as_pass` — mutations: drop the artifact bytes from the digest / drop the stat check → red.

## Why this and not alternatives

Persisting in-memory outcomes instead of the runner-side demotion would duplicate QH-83 in a second place and violate one-hardened-path-per-workflow; demoting at the *reader* instead of the writer would leave `stages.tsv` (consumed by the monitor and reuse validation) lying. Re-aliasing `traffic_test_matrix` to a new column is rejected in-source as a schema migration against hundreds of pre-existing rows (`registry.rs:993-995`) — tracked separately; leaving `logical: None` is the conservative, already-chosen option. Signing/hash-pinning every ledger row is disproportionate: the reuse seal plus D4(a) covers the replay/tamper class without new crypto.

## Blast radius / re-test

D1 touches the runner exit path — re-run a live `--node` suite end-to-end and confirm the Final row still replaces the Interim (existing tests at `run_matrix.rs:5336-5390` pin Interim-then-Final and Final-then-suppressed-Interim). D2/D3 are write-plumbing only; rerun `append_csv_row_serializes_concurrent_appends` (`:4358`) and the header-migration tests. D4(b) changes ledger cell values only in the witness-missing case (fail-closed); rerun the coverage-cell suite (`rust_native_stage_outcomes_populate_matrix_coverage_cells`, `:4567`) and the QH-07 pin `traffic_test_matrix_feeds_no_two_hop_rollup_but_keeps_cross_os` (`registry.rs:991`).

## What I could NOT verify

- No `cargo_test` was run (budget); all test names above are cited from source, not executed.
- The current callers of `append_live_lab_run_matrix_row` (the Final append site in the `--node` finalizer) were not located — the caller grep was truncated; D1's patch point is therefore named by role ("runner abort/finalize path"), not by exact `file:line`.
- Historical contamination counts (35/94 rows, commit `9cdd660f`) are quoted from the doc comments (`run_matrix.rs:454-461`, `registry.rs:961-968`), not re-counted from the CSV.

## Tools used (19 call(s) over 11 step(s))
