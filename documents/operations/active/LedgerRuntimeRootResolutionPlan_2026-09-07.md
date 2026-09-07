<!-- Drafted 2026-09-07 by a glm-5.3-flash grounded read-only agent at the owner's request (owner decision 3, QH-74); reviewed and placed by the managing Claude session. Status: PLAN — implementation tracked in OwnerDecisions_2026-09-07.md. Line references are against main at 2a5c4e1d unless stated. -->

# QH-74 — Runtime workspace-root resolution for the vm-lab orchestrator

## Goal

Stop the live-lab orchestrator from resolving evidence paths via `env!("CARGO_MANIFEST_DIR")`. Rows must land in the tree the binary *runs* in, derived from `--inventory` (walk up to a dir containing both `Cargo.toml` and `documents/operations`), then cwd, with the compiled-in path as validated last-resort fallback.

## Existing state

- **Two identical compiled-in definitions**: `crates/rustynet-cli/src/live_lab_run_matrix.rs:950-956` and `crates/rustynet-cli/src/vm_lab/mod.rs:2704-2710` — both `PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().and_then(parent)` + `expect` (production-path `expect`, itself a §2 violation).
- **Verified 40 grep matches** for `workspace_root_path` in `crates/rustynet-cli/src` (~42 incl. defs/imports). Categories:
  1. **Ledger append**: `default_live_lab_run_matrix_path` (`live_lab_run_matrix.rs:431`, read-only bash archive), `default_live_lab_node_run_matrix_path` (`:477`, the live `--node` ledger per W5.7 comment at `:483-486`), `default_live_lab_node_stage_matrix_path` (`:510`); consumed by `append_live_lab_run_matrix_row` (`:480`) and `write_node_stage_result_ledgers` (`:513`).
  2. **Triage gate read**: `vm_lab/orchestrator/native.rs:774-778` builds the ledger path via `workspace_root_path()` before `enforce_launch_gate` (`live_lab_stage_triage.rs:464-468`); the auto-stub writer resolves it identically (`live_lab_run_matrix.rs:658`). The doc at `live_lab_run_matrix.rs:945-949` makes gate/writer sharing one derivation a hard invariant; `live_lab_stage_triage.rs:134-141` documents the build-time defect and defers the fix to this work (ref: `FleetEvidenceCollectionPlan_2026-07-28.md`).
  3. **Provenance**: `HostSyncRecord.repo_dir` (`vm_lab/mod.rs:6191`); `git_stdout` runs `git` with `current_dir(workspace_root_path())` (`live_lab_run_matrix.rs:1469`; also `vm_lab/mod.rs:2811, 5951, 6392-6433`) — so commit/dirty columns describe the *build* tree.
  4. **Reviewed static assets**: relay plist `vm_lab/mod.rs:13575` (fail-closed missing-file check at `:13576-13581`), bootstrap/capture scripts (`:11265, 11289, 13331-13339, 15652`), wrapper source `:2873`, `rust-toolchain.toml` `:3208, 39345`, Windows helpers `:2251-2259`, image catalog `image_catalog.rs:61`, lock dir `run_exclusion.rs:182`, overnight report root `overnight/mod.rs:228, 237`.
- `--inventory` defaults are themselves build-tree-derived: `default_inventory_path` (`vm_lab/mod.rs:2712-2713`) used at parse time (`main.rs:3615, 3622, 4204`, etc.).

**Discrepancy:** `documents/operations/active/QualityHardeningTodo_2026-07-25.md` exists (470 KB) but contains no `QH-74` entry (grepped `QH-?74`/`QH.?74`: zero matches repo-wide). The technical description above is nonetheless fully verified in code; treat the ID as unconfirmed.

## Design

1. **New module** `crates/rustynet-cli/src/workspace_root.rs`:
```rust
pub(crate) fn is_workspace_root(p: &Path) -> bool {
    p.join("Cargo.toml").is_file() && p.join("documents/operations").is_dir()
}
pub(crate) fn resolve_workspace_root(
    inventory: Option<&Path>, cwd: &Path,
) -> Result<PathBuf, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(inv) = inventory {
        let start = if inv.is_absolute() { inv.to_path_buf() }
            else { cwd.join(inv) };
        if let Some(dir) = start.parent() { candidates.push(dir.to_path_buf()); }
    }
    candidates.push(cwd.to_path_buf());
    for start in &candidates {
        for dir in start.ancestors() {
            if is_workspace_root(dir) { return Ok(dir.to_path_buf()); }
        }
    }
    let compiled = compiled_in_root()?; // current env! body, expect → ok_or_else
    if is_workspace_root(&compiled) { Ok(compiled) }
    else { Err("no workspace root with Cargo.toml + documents/operations found from \
                --inventory or cwd; compiled-in root is also invalid".to_owned()) }
}
static RESOLVED_ROOT: OnceLock<Result<PathBuf, String>> = OnceLock::new();
pub(crate) fn init_workspace_root(inventory: Option<&Path>) -> Result<(), String> { /* set once */ }
pub(crate) fn workspace_root_path() -> PathBuf { /* RESOLVED_ROOT or lazy resolve(None, cwd) */ }
```
Pure `resolve_workspace_root` is directly testable; the `OnceLock` only caches. Fail closed: no marker anywhere → hard error, never `create_dir_all` into an arbitrary root. When the resolved root differs from the compiled-in root, `eprintln!` both paths once at init (transparency; no secrets).

2. **Delete both old definitions** (`live_lab_run_matrix.rs:950-956`, `vm_lab/mod.rs:2704-2710`); re-export the shared one. The `pub(crate)` gate/stub invariant at `:945-949` is *strengthened*: single derivation by construction.
3. **Init call**: in `main.rs` at the vm-lab/orchestrator verb parse sites, after `--inventory` is parsed (e.g. near `main.rs:4204`), call `init_workspace_root(inventory_arg)` before any config is consumed; error propagates as today's parse errors do. `enforce_launch_gate` itself is unchanged (takes `ledger_path`); only the caller's path source changes (`native.rs:774-776`).
4. **Call-site category effects** (no signature changes): (1) append paths now write beside the running tree; (2) gate + auto-stub read/write the same runtime ledger; (3) `repo_dir`/git operations describe the running tree; (4) reviewed plist/scripts resolve from the runtime tree — existing `is_file()` guards (e.g. `:13576`) turn a wrong root into a loud stage failure, which is the desired fail-closed behavior; (5) locks/overnight roots follow the runtime tree.

## Security analysis

Fail-closed preserved: no markers → error, not a guess; compile-time fallback is validated against the same markers before use; append/create paths still go through `append_lock`. New trust consideration: cwd-derived resolution lets a run attribute evidence to *any* ancestor dir carrying the markers — mitigated by preferring the explicit `--inventory` root and printing the chosen root (and any divergence from the build tree) on every run. This is operator-facing tooling, not a data-plane trust boundary; no key material involved. Risk: an operator who runs from the wrong copy now *successfully* records into the wrong tree — that is today's behavior made consistent and visible, not new exposure.

## Tests

- Unit (`workspace_root.rs`): marker detection; inventory-walk wins over cwd; cwd walk; no markers → compiled fallback; compiled root without markers → error; second-init is idempotent.
- **Pinning test** (`live_lab_run_matrix.rs` tests, temp-dir style of `:4174`): copy a minimal tree (`Cargo.toml`, `documents/operations/`, `state/`) to tmp; `init_workspace_root(Some(copy_inventory))`; call `append_live_lab_run_matrix_row`; assert `copy/documents/operations/live_lab_node_run_matrix.csv` gained the row and the compiled-in tree's ledger was not touched. A second test pins the gate: `enforce_launch_gate` reading the copy's triage ledger sees stubs written there.
- Live proof: no existing stage covers this; validation is one supervised `--node` run launched from a copied tree whose matrix row (report_dir, commit) matches the copy — cross-checkable via `lab_run_status` on the node ledger.

## Effort

~1 day: module + 2 deletions + 1 init site (~80 LOC), ~150 LOC tests, one verification run.

## Implementation log

- 2026-09-07 — Step 1+3 combined (so every commit stays lint-green): created `crates/rustynet-cli/src/workspace_root.rs` (marker check, pure `resolve_workspace_root`, validated compiled-in fallback, `OnceLock` cache + `init_workspace_root`/`workspace_root_path`, cfg(test) forced-root hook for the pinning test); deleted both compiled-in definitions and re-exported the shared one at the two former sites. **Deviation (structural, logged):** `mod workspace_root;` declared in BOTH crate roots (`lib.rs` and `main.rs`) — the binary target compiles its own module tree, so without the one-line `main.rs` declaration the shared definition cannot resolve there and the two-definitions defect QH-74 kills would simply reappear. This extends the "init call only" `main.rs` rule by one structural line; no other `main.rs` change in this step.
- 2026-09-07 — Step 2: the `vm-lab-orchestrate-live-lab` parse arm (`main.rs`, the orchestrator verb; the arm body became a block) now parses `--inventory` once, calls `workspace_root::init_workspace_root(Some(inventory_path.as_path()))?`, and passes the parsed path into the config — error propagates exactly like a parse error. Chose the SINGLE orchestrator site (the only verb whose run writes the run-matrix/stage/triage evidence QH-74 is about) over sprinkling init calls at every read-only `vm-lab-*` verb; other verbs keep the lazy cwd fallback, which preserves their old behavior. `init_workspace_root` is `pub` + the lib declares `pub mod workspace_root;` so the lib build has no dead-code warning. Commits: `6588bb79` (step 1+3), `bafc3b2f` (step 2).
- 2026-09-07 — Step 4 pinning tests (`live_lab_run_matrix.rs`, `conclusion_barrier_tests` module): `append_lands_in_runtime_resolved_workspace_root` builds a minimal workspace COPY (Cargo.toml marker, documents/operations/, inventory) plus a full `--node` report fixture, forces the resolved root to the copy via the cfg(test) hook under the crate-wide serializer, appends a Final row, and asserts the row landed beside the COPY while the build tree's `live_lab_node_run_matrix.csv` is byte-identical before/after. `launch_gate_reads_stubs_written_to_the_copied_root` runs the same append (planned stage failed) and asserts the triage stub appears in the copy's `documents/operations/live_lab_stage_triage.jsonl` and `enforce_launch_gate` refuses the launch naming `live_two_hop_validation`. Fixture note: a node-scope `fail` needs an alias-attributed summary (`exit: …`) or `attributable_node_status` downgrades it to `not_proven` and no stub is opened. Commit: `75337040`.
- 2026-09-07 — Gates (pinned toolchain 1.88.0, dedicated `CARGO_TARGET_DIR`): `cargo fmt --all -- --check` pass; `cargo clippy -p rustynet-cli --all-targets --all-features --features vm-lab -- -D warnings` pass; `cargo test -p rustynet-cli --all-targets --all-features --features vm-lab` — 93 test binaries, 0 failures (includes the 10 `workspace_root` unit tests + 2 pinning tests). Live `--node` proof from a copied tree deliberately NOT run here (no lab access from this branch task); the plan's live-proof step remains for a supervised lab session.

## Open questions

1. RESOLVED before implementation: the QH-74 entry exists in `documents/operations/active/QualityHardeningTodo_2026-07-25.md` (filed by manager session 7, 2026-09-07); its disposition is updated to FIXED-IN-BRANCH by this work.
2. DECISION: kept minimal — NO `--workspace-root` flag. The orchestrator init takes the root from the explicit `--inventory` path first, so the ambiguity the flag would resolve is already removed for the evidence-writing verb; adding a flag now would widen the CLI surface without a demonstrated need. Revisit if an operator hits a real mis-resolution.
3. Out of scope here: the MCP `engine=bash_archive` reader reads the FROZEN legacy-bash ledger, whose compiled-path assumption is harmless for read-only history; the live `--node` ledger reader drives the same runtime resolution once this lands.

## STATUS 2026-09-07T11:16:31Z

DONE (code + tests + gates complete on branch `ai-edit/edit-1788775555939-73909-0`, commits `6588bb79`, `bafc3b2f`, `75337040`): shared runtime `workspace_root` module replaces both compiled-in definitions; orchestrator init at the `vm-lab-orchestrate-live-lab` parse site; 10 unit tests + 2 pinning tests; fmt/clippy/full-crate-test green. NOT done (needs a supervised lab session, per task constraints): the live `--node` validation run launched from a copied tree. NEXT: merge review of the branch, then one supervised live proof run.

## STATUS 2026-09-07 (review fixes applied, edit job edit-1788781503196-77676-0)

The independent adversarial review (`LedgerRuntimeRootResolutionReview_2026-09-07.md`) found the branch's central mechanism dead in production: the eager `vm_lab::default_inventory_path()` argument initialized the `OnceLock` from cwd before `init_workspace_root` ran, so the `--inventory` hint was silently discarded (F1, BLOCKER). All six findings are fixed on branch `ai-edit/edit-1788781503196-77676-0` (commit `b3d4a5b0`; per-finding dispositions in the review doc): parse site consults optional `--inventory` first and only then derives the default; divergent re-initialization is a hard error; the winning root is canonicalized and ownership/writability validated (F3 strict option); pinning test for init-vs-conflicting-cwd plus a divergent-init refusal test (F2, fresh-cell/explcit-cwd adaptation documented in the disposition); stale triage doc corrected (F4); `Some("")` parent treated as cwd (F5); unconditional fixture cleanup via Drop guard (F6). Gates green on the pinned 1.88.0 toolchain: fmt, `clippy -p rustynet-cli --all-targets --all-features -- -D warnings`, and the scoped `cargo test -p rustynet-cli --lib --all-features` selection (122 passed). Still outstanding from the prior STATUS: the supervised live `--node` validation run launched from a copied tree.
