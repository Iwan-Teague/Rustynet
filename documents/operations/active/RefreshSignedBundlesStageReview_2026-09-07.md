# Review: `refresh_signed_bundles` stage + `TRAVERSAL_TTL_SECS` hard error

- Diff range: `1efc8376..HEAD -- crates/` (commits `87f23584`, `e31333f5`, `4cf4e260`, `4707a663`, `1e29a9e5`)
- Reviewer: GLM flash, read-only adversarial security review, 2026-09-07
- Findings only; no diff summary.

## Findings

### F1 — should-fix — HP-3 does not depend on the refresh stage; ordering is positional only

`crates/rustynet-cli/src/vm_lab/orchestrator/stage/relay_forwards_frame_validation.rs:254-257`:

```rust
stage.dependencies() == &[StageId::DeployRelayService, StageId::RelayValidation]
```

`RefreshSignedBundlesStage` (new, `refresh_signed_bundles.rs`) declares the *same* dependency list. The invariant that matters — bundles are re-minted immediately before HP-3 validates relay forwarding — is enforced only by `plan.rs` position test (`refresh_pos == hp3_pos - 1`) and catalog insertion order, not by any dependency edge. Failure scenario: a future plan/ordering refactor reorders T1Role stages (catalog sort, dedup, or a new inserted stage) → HP-3 runs against the setup-time bundles, which may be older than the relay service the daemon now runs, and the position test fails only as a broken test rather than preventing the run. One-line fix: add `StageId::RefreshSignedBundles` to `RelayForwardsFrameValidationStage::dependencies()` so adjacency is dependency-driven.

### F2 — nit — hard-error string contains multi-space runs from source line-wrap

`crates/rustynet-cli/src/vm_lab/ops_e2e.rs` (~line 3565, `issue_traversal_bundles_locally`): the `TRAVERSAL_TTL_SECS` missing error literal contains runs like `must be                  configured explicitly` and `the orchestrator's                  build_bundle_env`. Cosmetic only; message is still greppable for `TRAVERSAL_TTL_SECS`. Fix: re-wrap the literal to single spaces.

### F3 — nit — stale comment claims TTL=120 is "the hard cap"

`scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1:719` comment: `with TRAVERSAL_TTL_SECS=120 (the hard cap enforced by ops_e2e)`. The mint now rejects a *missing* TTL rather than defaulting to 120; the comment describes superseded semantics. Fix: update the comment to say the TTL must be configured explicitly. (File outside `crates/`; flagged, not modified.)

### F4 — nit — dead `Skipped` branch on the dns_zone leg

`refresh_signed_bundles.rs`: `distribute_bundle_kind` can only return `Passed` or `Failed` (no Exit node → `Failed`; it never returns `Skipped`), so the `if Skipped → return` after the `DnsZone` leg is unreachable defensive code. Harmless; also means the stage's final returned `traversal` outcome can only be `Passed`/`Failed`. Fix: drop the branch or leave with a comment that it is defensive.

## Task questions — answers

1. **Gated + honest Skip**: yes. `execute()` returns `Skipped("relay forwarding validation not enabled for this run")` when `!ctx.relay_forwarding_validation_elected`; `native.rs:468-473` tightens the flag to `enable_relay_forwarding_validation && plan_stage_ids.contains(&StageId::RefreshSignedBundles)` after plan build (interim loose assignment overwritten before any stage executes; resume path forces `false`). The flag is true only when the stage is genuinely in the run's plan and the CLI flag was passed.
2. **Stale epoch / verifier barrier**: no. Re-mint reuses `distribute_bundle_kind`, which mints a *fresh* keypair on the exit guest per call and preserves the phase1-verifier-key → phase2-signed-bundle ordering (`node_adapter.rs:236-246` documents the barrier contract), so no bundle is ever applied without its matching verifier and no old signing epoch is replayed.
3. **Anti-shrink**: no stage dropped. Every count pin moved exactly +1 (relay plan 67→68, chaos 76→77, stacked 80→81, registry `("t1_role", 23→24)`); all pins are upward, and the registry-equivalence and repo_context expected-order tests both list the new stage.
4. **TTL hard error breakage**: none found. The single production caller is `adapter/windows.rs:316`, fed by `build_bundle_env` which always pins `TRAVERSAL_TTL_SECS=86400` (new pin test `traversal_env_always_pins_the_traversal_ttl_explicitly`); all other producers (`vm_lab/mod.rs:37627-37640`, `live_linux_exit_handoff_test.rs:435-440`, `main.rs:14516-14518`) write it explicitly; the optional `config.traversal_ttl_secs` at `vm_lab/mod.rs:8573-8579` feeds the guest daemon env, not the mint env.
5. **35 files / StageId arms**: premise false. ~30 touched files are mechanical `#[cfg(test)]` `OrchestrationContext` literal additions of `relay_forwarding_validation_elected: false,` from the new context field; `StageId` matches are centralized in `plan.rs` (compile-enforced). Catalog/registry arm is consistent: `Disruptive` / `T1Role` / `AllPlatforms` / `EnableRule::RelayForwardingValidation`, identical to HP-3.
6. **unwrap/expect**: none in non-test code of any new/changed file.

VERDICT: MERGE-WITH-FIXES — no blocker, but F1 leaves the refresh-before-HP-3 invariant positional rather than structural, one refactor away from silently validating stale bundles.
