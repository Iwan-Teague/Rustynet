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

## Open questions

1. Where is QH-74 actually recorded? The cited ledger has no such ID — confirm numbering before implementation.
2. Should the cwd walk be opt-in (`--workspace-root` override) to remove ambiguity? Conservative default: yes, add the explicit flag; inventory-walk > flag > cwd > compiled fallback.
3. Does the MCP `engine=bash_archive` reader (`lab_run_status`) assume the compiled-in ledger path? If so it needs the same resolution or an explicit path.
