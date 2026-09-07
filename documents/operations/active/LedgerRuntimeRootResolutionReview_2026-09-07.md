# QH-74 Review — Runtime Workspace-Root Resolution

Scope: `git diff 1efc8376..HEAD -- crates/` (commits 6588bb79, bafc3b2f, 75337040, 82133801). Files touched: `crates/rustynet-cli/src/{workspace_root.rs (new), main.rs, lib.rs, live_lab_run_matrix.rs, vm_lab/mod.rs}`. No files outside `crates/` were changed in this range; scope is clean.

## F1 — BLOCKER: `init_workspace_root` is dead at its only call site; the inventory-ancestors ordering is unreachable in production

`crates/rustynet-cli/src/main.rs:4415-4417`:

```rust
let inventory_path =
    parser.path_or_default("--inventory", vm_lab::default_inventory_path());
workspace_root::init_workspace_root(Some(inventory_path.as_path()))?;
```

`path_or_default` takes the default **by value** (`fn path_or_default(&self, key: &str, default: PathBuf)`, main.rs:16891), so `vm_lab::default_inventory_path()` is evaluated **eagerly, on every parse, even when `--inventory` is supplied**. `default_inventory_path()` is `workspace_root_path().join(...)` (vm_lab/mod.rs:2712-2714), and `workspace_root_path()` is `RESOLVED_ROOT.get_or_init(...)` with **no inventory** (workspace_root.rs:167-175). The `OnceLock` is therefore initialized — cached from `cwd` only — **before** `init_workspace_root` runs. `init_workspace_root` itself uses `RESOLVED_ROOT.get_or_init(...)` (workspace_root.rs:133), so its closure, including the inventory parameter and the runtime-vs-compiled `eprintln!` transparency branch, **never executes** in the CLI path.

Failure scenario: operator runs `rustynet ops vm-lab-orchestrate-live-lab --inventory /copy/inventory.json …` with cwd inside a *different* marked tree. The module doc (workspace_root.rs:8-17) promises inventory ancestors win (step 1); instead the cwd resolution cached by the eager default wins, and the `--inventory` hint is silently discarded. Evidence lands in the cwd tree regardless of the inventory pin. The whole point of step 2 of the branch ("resolve at verb-parse time" from the run's `--inventory`) is not delivered; the pure-core test `inventory_ancestors_win_over_cwd` covers only the unreachable path.

Fix: derive the default inventory without touching the `OnceLock` (e.g. `parser.optional_path("--inventory")` first, call `init_workspace_root` with it, and only then fall back to a default that itself uses the post-init root), or change the eager argument into a closure/`Option` consulted after init.

## F2 — should-fix: the pinning test exercises the append path but bypasses resolution entirely, masking F1

`append_lands_in_runtime_resolved_workspace_root` (live_lab_run_matrix.rs:6475-6510) forces the root via `Qh74RootGuard::force(&copy_root)` → `set_workspace_root_for_tests(Some(...))` (workspace_root.rs:198-205), which short-circuits `workspace_root_path()` **before** `RESOLVED_ROOT` is consulted (workspace_root.rs:163-166). So the test proves the append writer calls `workspace_root_path()` — but never exercises `resolve_workspace_root` or `init_workspace_root` end-to-end. Combined with F1, no test in the branch drives `init_workspace_root(Some(inv))` against a copied tree; a regression that makes init a complete no-op (which F1 already is) stays green. Same for `launch_gate_reads_stubs_written_to_the_copied_root` (live_lab_run_matrix.rs:6519-6547): good gate↔writer same-root proof, same resolution bypass.

Fix: add one test that, holding `TEST_SERIALIZER`, calls `init_workspace_root(Some(&copy_inventory))` from a process cwd pointing at a *different* marked tree and asserts `workspace_root_path()` == the inventory-side root. (Note this test will fail today — correctly — because of F1.)

## F3 — should-fix (accepted-risk call needed): planted markers in a writable cwd/ancestor redirect evidence **and** the launch gate

Resolution accepts any ancestor dir containing `Cargo.toml` **file** + `documents/operations` **dir** (workspace_root.rs:29-31) — two easily planted markers. An attacker (or a stray repo) with write access to the invocation cwd or any ancestor gets the resolver to choose their directory, and every consumer follows the same runtime root: the run-matrix ledger append (`ensure_matrix_schema` writes `documents/operations/live_lab_node_run_matrix.csv` under it, live_lab_run_matrix.rs:958-968), triage stubs, and — critically — `enforce_launch_gate`, whose production path reads `default_triage_ledger_path(workspace_root_path())` (live_lab_stage_triage.rs:118, 136). A planted/edited triage ledger in the attacker's root can mark a genuinely failed stage as deferred/filled, turning the fail-closed launch refusal (the gate that "must refuse the launch") into a pass. No symlink resolution/canonicalization anywhere in the walk (lexical `ancestors()`, workspace_root.rs:59-67), so a symlinked inventory path resolves against its lexical parent chain — same trust domain, same redirect.

This is local-trust-domain (attacker needs write access to the invocation directory chain), and the plan document accepts cwd-derived resolution, but the gate-read side makes it more than cosmetic: evidence **integrity** and a fail-closed check both hang on the chosen root.

Fix: canonicalize the winning root and require it to be owned by the current user (or refuse roots where `Cargo.toml`/`documents/operations` are world-writable), or prefer the validated compiled-in root whenever inventory and cwd disagree with different owners.

## F4 — nit: stale doc re-asserts the old derivation

`live_lab_stage_triage.rs:136-137` still documents the root as "`env!(\"CARGO_MANIFEST_DIR\")` — build-time-derived", contradicting QH-74's one-derivation invariant this branch establishes. Fix: update the doc comment.

## F5 — nit: empty-parent edge in the inventory walk

For a bare-filename inventory (`--inventory inv.json` relative to cwd), `start.parent()` yields `Some("")` (workspace_root.rs:51-54); `is_workspace_root(Path::new(""))` then probes `Cargo.toml` relative to the **process** cwd. Harmless today (duplicate of the explicit cwd candidate) but accidental. Fix: skip empty parents.

## F6 — nit: fixture cleanup is success-only

`write_qh74_copied_workspace` copies live under `std::env::temp_dir()` with a nanosecond stamp (live_lab_run_matrix.rs:6393-6399); both tests remove the copy only after the asserts pass (`let _ = fs::remove_dir_all(...)` at 6509 and 6547), so any assertion failure leaks the tree. Fix: wrap in a Drop guard.

## Direct answers to the review questions

- **Redirect to attacker-chosen dir?** Yes — see F3 (planted markers in cwd/ancestor chain; symlinked inventory path follows the same lexical chain). F1 additionally means the operator's `--inventory` pin is ignored in favor of cwd.
- **Does the fallback create dirs or write into an unvalidated root?** No. The resolver is read-only (`is_file`/`is_dir` only, workspace_root.rs:29-31, 59-77); the compiled-in fallback is marker-validated before use (workspace_root.rs:79-85). The only `create_dir_all` in the append path (`ensure_matrix_schema`, live_lab_run_matrix.rs:960-962) runs inside a directory that already passed the marker check.
- **Is the OnceLock initialized before every reader; any reader caching the compile-time path?** No reader caches the compile-time path anymore — both former `env!("CARGO_MANIFEST_DIR")` definitions are replaced by re-exports (`pub(crate) use crate::workspace_root::workspace_root_path`, live_lab_run_matrix.rs:958; `use crate::workspace_root::workspace_root_path`, vm_lab/mod.rs:2708-2712), and the lazy fallback resolves from cwd at first use, so a pre-init reader caches a cwd result, not a compile-time one. But init itself never wins the race at the only init site (F1), and non-orchestrate verbs (e.g. the `append-live-lab-matrix-row` arm, main.rs:9422) never init at all — they rely on the lazy cwd fallback, which is a deliberate behavior change: a binary run from a stripped copied tree now panics (fail-closed) where it previously silently wrote into the build tree. That tightening is the patch's intent and is correct in direction.
- **main.rs content beyond declaration + init?** `mod workspace_root;` (main.rs:86-88) and the init call (main.rs:4417) plus one mechanical reorder: `inventory_path` is now bound before the config struct so it can be passed to init (main.rs:4415-4416). Nothing else; the ~200-line diff of the orchestrate arm is pure re-indentation of the same parser calls.
- **unwrap/expect in non-test code?** None added. `workspace_root.rs` production code has no unwrap/expect; `workspace_root_path` panics on an unresolvable root (workspace_root.rs:178-179) — a documented, single-choke-point fail-closed panic replacing two per-call-site `.expect(...)`s, an acceptable like-for-like under §10.2. All `expect`s elsewhere in the diff are inside `#[cfg(test)]`; `Qh74RootGuard` even uses `unwrap_or_else(|poisoned| poisoned.into_inner())` for the test mutex.
- **Does the pinning test really exercise the append path?** Yes for the writer/gate (it calls the real `append_live_lab_run_matrix_row` and asserts the row + triage stub land in the copy while the build tree's ledger is byte-identical — a genuinely good anti-regression assertion), but not for the resolver/init (F2).

## Behavior/semantics check

No fail-open path introduced: unresolvable root → `Err` at init (main.rs:4417 `?`) or loud panic at the accessor. Pass/fail semantics of the launch gate are unchanged; the gate reads a ledger whose location is now runtime-dependent (F3). Test-only globals are `#[cfg(test)]`-gated and serialized; no production surface.

`VERDICT: MERGE-WITH-FIXES` — F1 must be fixed first: the branch's central mechanism (init at parse time from `--inventory`) never executes because the eager `default_inventory_path()` argument initializes the `OnceLock` from cwd before init runs.
