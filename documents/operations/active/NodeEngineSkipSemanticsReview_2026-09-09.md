# `--node` engine skip-semantics sweep — 2026-09-09 (GLM-5.3-flash, grounded, trusted input)

Probe W2 of the correctness pass. Findings F1/F2 dispatched as an edit job the same morning.

# Rust `--node` engine — skip-site correctness review

Grounding: every site below was read in this tree; latest live ledger row confirms the context run (`36c7017f` 2026-09-09T01:26Z, overall `partial`, `two_hop=skip`, `relay_svc=skip` — `lab_run_status`, the livelab-1788919346 39/0/54 run). All `StageOutcome::Skipped` constructors live in `orchestrator/stage/**`; `role_validation/**` constructs none (only `RollbackVerdict::Skipped`, `role_validation/signed_state_rollback_eval.rs:149`, forced by a node-reported skip at `:229`, mapped to matrix status `"skip"` at `:161`/`:580`, pinned by tests `:635-641`). The I4 fix holds: no skip strings remain in `role_validation/anchor.rs` (grep "Skipped" over role_validation: 13 hits, none in anchor.rs).

## (1) Findings

### F1 — (b) FAIL-OPEN: nine validators return `Passed` when they validated zero nodes. Severity for ledger integrity: **HIGH (latent)**

The (b) class in this tree is not a skip — it is a **vacuous pass** sitting next to honest skips in the same helper family. Every stage that iterates *all* assignments guards emptiness with `Passed`:

| Site | Condition (verbatim) |
|---|---|
| `stage/security_audit_validation.rs:71-73` | `if aliases.is_empty() { return StageOutcome::Passed; }` — doc `:49` sanctions it: "A run with no nodes is a skip-noop pass." |
| `stage/authenticode_validation.rs:44-47` | same |
| `stage/key_custody_validation.rs:42-45` | same |
| `stage/mesh_status_validation.rs:67-70` | same |
| `stage/runtime_acls_validation.rs:41-44` | same |
| `stage/gossip_convergence_validation.rs:44-47` | same |
| `stage/ipv6_leak_validation.rs:50-53` | same |
| `stage/dns_failclosed_validation.rs:41-44` | `if ctx.assignments.is_empty() { return StageOutcome::Passed; }` |
| `stage/service_hardening_validation.rs:40-44` | same |

Why QH-83 cannot catch it: these rows' catalog evidence is the bulk `None { reason: PHASE1_EVIDENCE_PENDING }` (ledger §3: "only 3 of 81 stages are witnessed"), and `verify_declared_evidence` (`runner.rs:163-166` implementation `:526-560`) passes `None`-declared stages through unchanged. A green ledger row for a control assertion that ran on no node is exactly the pattern-B "pass by construction" the audit closed elsewhere (`run_logged_test` N≥1), surviving inside the new engine. Input path: `ctx.assignments` comes from the persisted/launched orchestration context; the resume path refuses an empty one (`native.rs:218-223`), the fresh-launch path's guard I did **not** find (see §5) — so today latent, not live. The role-scoped siblings get this right and return `Skipped` (`blind_exit.rs:39-43`, `blind_exit_dataplane_validation.rs:61-67`, `relay_validation.rs:68-72`, `anchor_validation.rs:150-154`, `admin_issue.rs:35-39`, `deploy_relay.rs:93-97`, `live_hello_limiter_flood_validation.rs:35-39`, `relay_forwards_frame_validation.rs:83-87`), each with the comment "not Passed … a false-green Pass would mask the gap".

### F2 — (b) MEDIUM: an operator-elected proof silently skips when the topology cannot supply it

`stage/relay_forwards_frame_validation.rs:83-87`: condition `if relay_aliases.is_empty() { return StageOutcome::Skipped("no node in this topology is assigned the relay role") }`. This stage is opt-in (`--enable-relay-forwarding-validation`, module doc `:9-20`) — the operator explicitly elected the disruption, and the stage's own in-file rule says a topology that cannot supply the proof "FAILS the stage — it is never a skip, because the operator explicitly asked for this disruption" (`:116-124`, implemented at `:126-135` for the peer-election case). The no-relay case violates its own rule: the election dissolves into a non-blocking skip (run goes Partial and the Disruptive cell stays silently unexercised — the exact QH-80 shape: three months unexecuted, discovered on first run). Everything below the relay check already fails closed (no inventory `:105-112`, no adapter `:118-124`, non-Linux relay `:126-130`, unformable topology `:148-158`).

### F3 — (a) classification: the topology/role skips are honest and correctly non-`Passed`, but undeclared

Verified conditions, all returning `Skipped` (non-blocking, run Partial), all computable at plan time:

| Site | Condition | EnvFact (design §2 name, or new) |
|---|---|---|
| `live_two_hop_validation.rs:51-61` | no `entry` role / no `extra`\|`aux` | `EntryNodePresent`, `SecondClientPresent` (both named in design) |
| `admin_issue.rs:35-39` | no `Admin` assignment | `AdminNodePresent` (named) |
| `deploy_relay.rs:93-97`, `relay_validation.rs:68-72`, `relay_forwards_frame_validation.rs:83-87`, `live_hello_limiter_flood_validation.rs:35-39` | no `Relay` | `RelayNodePresent` (named) |
| `anchor_validation.rs:150-154` | no `Anchor` | `AnchorNodePresent` (named) |
| `blind_exit.rs:39-43`, `blind_exit_dataplane_validation.rs:61-67`, `live_lan_toggle_validation.rs:46-53` | no `BlindExit` | `BlindExitNodePresent` (named) |
| `live_anchor.rs:41-43` | no `entry` | `EntryNodePresent` |
| `live_anchor.rs:49-52` | no `aux` | **new** `AuxNodePresent` |
| `live_anchor.rs:58-61` | no `extra` | **new** `ExtraEnrolleePresent` |
| `live_enrollment_restart_validation.rs:35-39` | no `aux` | **new** `AuxNodePresent` |
| `live_extended_soak_validation.rs:41-49` | `["exit","client","entry","aux"]` not all present, or no second client | `ExitNodePresent+ClientPresent+EntryNodePresent+AuxNodePresent+SecondClientPresent` |
| `live_mixed_topology_validation.rs:49-53` | "not every platform in the matrix is assigned a node" | **new** `PlatformMatrixComplete` |
| `cross_network.rs:526-531` | `TopologyError::MissingRole` (relay/probe from `entry`\|`aux`, `:963-966`) | `AuxNodePresent` (or Entry) |
| `cross_network.rs:520-523` | substrate ≠ vxlan | **new** `CrossNetworkSubstrateSelected(Vxlan)` |
| `cross_network.rs:283-286` | `!options.enable_suite` | **new** election fact `CrossNetworkSuiteElected` |
| `refresh_signed_bundles.rs:55-59` | `!ctx.relay_forwarding_validation_elected` | **new** `RelayForwardingValidationElected` |
| `macos_role_transition_validation.rs:57-62` | `!ctx.macos_role_transition_elected` | `MacosRoleTransitionElected` (named) |
| `macos_reboot_recovery_validation.rs:109-114` | `!ctx.macos_reboot_recovery_elected` | `MacosRebootRecoveryElected` (named) |
| `macos_anchor_profile_deploy.rs:43-48`, `macos_anchor_bundle_pull_validation.rs:39-48`, `macos_anchor_port_mapping_authority_validation.rs:54-58` | not elected (`--anchor-platform macos`), or no macOS anchor node | `MacosAnchorValidatorsElected` (named) + `AnchorNodePresent` |

Note the design vocabulary itself has gaps this table exposes: there is **no platform/capability or election fact** in §2's enum, yet four honest skip classes are exactly that (platform gate + election + matrix). They need `ValidatorImplementedForPlatform(...)` / `Elected(...)` variants or the `PlatformCapabilities`-on-`NodeAdapter` table from ledger item C.

### F4 — (c) correct: reported-skip-with-artifact family

The shared `outcome_for(failures, reported_skips)` ("no node executed this validation; N node(s) reported a runtime skip") + `write_reported_skips_note` pattern is correct ledger behavior: failures win → `Failed`; all-skipped → `Skipped` **with** `<stage>.reported_skips.json` on disk. Producer output verified verbatim (`runtime_acls_validation.rs:89-99`): `{"stage":"runtime_acls_validation","reported_skipped_runtime_acls":[{"alias":…,"platform":…}],"reason":"…reported-skipped (named, never a silent pass)"}`. Sites: `mesh_status_validation.rs:196`, `runtime_acls_validation.rs:80`, `authenticode_validation.rs:83`, `gossip_convergence_validation.rs:87` (doc `:81-82` "an all-non-Linux topology must not read as gossip having converged", test `:126-131`), `dns_failclosed_validation.rs:123`, `ipv6_leak_validation.rs:102`, `security_audit_validation.rs:148`, `key_custody_validation.rs:81`, `service_hardening_validation.rs:82`, `exit_nat_lifecycle_validation.rs:151`, `exit_dns_failclosed_validation.rs:158`, `exit_demotion_residue_validation.rs:134`, `blind_exit.rs:89`, `blind_exit_dataplane_validation.rs:117`, `anchor_validation.rs:331`, `relay_validation.rs:139`, `deploy_relay.rs:161`, `role_transition_ordering_eval.rs:248` (`aggregate_outcome`, module header `:5-9`: evaluator is offline, stage wiring explicitly not landed). Platform-gate skips with the same artifact: `exit_nat_lifecycle_validation.rs:58-64`, `exit_dns_failclosed_validation.rs:75-81`, `exit_demotion_residue_validation.rs:63-69`, `active_exit.rs:193-197`. `active_exit.rs:115-133` is the (c) exemplar — exit-only topology skips with a fail-closed artifact write (`MISSING_CLIENT_FILENAME`, write failure → `Failed`), the B4 fix. `negative_control.rs:2923` is a test fixture, not production.

## (2) Patches + red tests

**F1 (×9, identical shape)** — e.g. `security_audit_validation.rs:71-73`:

```rust
if aliases.is_empty() {
    return StageOutcome::Skipped(
        "no node assignments in this topology; nothing was validated".to_owned(),
    );
}
```

Also correct the doc line `security_audit_validation.rs:49` ("skip-noop pass" → skip). Interim severity note: `Skipped` matches the role-scoped siblings and keeps the run Partial; when `requires()`/`provisions()` lands (design §3.3), the runner gate upgrades any unsatisfied fact to blocking `NotProven { RequiredCapabilityAbsent }` — never `Skipped` — which is the terminal form.

Red test per stage (one shown; nine total):

```rust
#[test]
fn empty_assignments_is_skipped_never_passed() {
    let mut ctx = empty_ctx(); // zero assignments
    assert!(matches!(
        SecurityAuditValidationStage.execute(&mut ctx),
        StageOutcome::Skipped(_)
    ));
}
```

Mutation that turns it red: revert any one of the nine arms to `return StageOutcome::Passed;` — that stage's `empty_assignments_is_skipped_never_passed` fails. Name: the `empty-assignments-vacuous-pass` mutation.

**F2** — `relay_forwards_frame_validation.rs:83-87`:

```rust
if relay_aliases.is_empty() {
    return StageOutcome::Failed(
        "relay forwarding validation was elected (--enable-relay-forwarding-validation) \
         but no node in this topology is assigned the relay role"
            .to_owned(),
    );
}
```

Red test: `elected_frame_forwarding_without_relay_node_fails_never_skips` (empty-assignments ctx with `relay_forwarding_validation_elected: true`; assert `Failed`). Mutation: revert to `Skipped` → red. Check whether an existing test pins the `Skipped` outcome for this arm (file truncated at 12/16 KB; if present, that pin is the test to flip).

## (3) Gate that kills the class

Three layers, cheapest first:

1. **CI source tripwire (S, lands today):** recursive scan of `orchestrator/stage/**` rejecting the pattern `is_empty()` guard whose body returns `StageOutcome::Passed` (zero allowlist; fail closed on unreadable files, exactly as the B2 feature-guard was hardened). Mirrors the QH-82 tripwire-in-CI precedent.
2. **Ledger cross-check (M):** in `live_lab_run_matrix.rs`, a `pass` stage row whose stage log contains zero per-node verdict lines for a per-node validator is stamped `unwitnessed` in the matrix — makes F1 visible from artifacts without reading source.
3. **The real kill (L):** `requires()`/`provisions()` as compile-forced catalog columns (design §3.1-3.3, extended with the §F3 `Elected(...)`/platform variants): plan-construction refusal for unsatisfiable facts, runner conversion of runtime absence into `NotProven { RequiredCapabilityAbsent }` (blocking, cascading — `error.rs` NotProven is blocking), `planned_out` in `node_stage_plan.json` for visibility. This converts every (a) row above into an offline declaration and makes both F1 and F2 structurally impossible.

## (4) Effort

F1: **S** (9 one-line patches + 9 tests; +1 for tripwire ⇒ M). F2: **S**. F3 declarations + gate: **L** (design exists; per-suite batches with live re-verify each, per the QH-83 landing method).

## (5) What I could not verify

- **Reachability of F1's input:** I found the empty-assignments refusal only on the resume path (`native.rs:218-223`). I did not trace the fresh-launch context construction to a minimum-node guard, so F1 may be unreachable from the live launcher today. Static severity stays HIGH because the guard is one typo away and the ledger row would be green either way.
- **Catalog evidence values for the nine F1 stages** (whether each is `None { PHASE1_EVIDENCE_PENDING }`) — taken from the consolidation ledger §3 ("only 3 of 81 stages are witnessed"), not re-read from the `define_stage_catalog!` table in `stage/mod.rs`.
- **`cross_network.rs:347` exact condition** — inferred from `run_nat_matrix` (`:473-476`) and the test comment at `:1842` ("a netns run skips the gate"); I did not read `:340-350` verbatim.
- **`role_transition_ordering_eval.rs:611`** — the enclosing function of that `Skipped(message)` arm; the module header states the stage wiring has not landed, so the arm is currently test-only.
- **Existing skip-pinning tests in `relay_forwards_frame_validation.rs`** (file read truncated at 12,000 of 15,981 bytes).
- **No commands were executed against the code** (no `cargo_test` for the proposed tests — they do not exist yet); all findings are static reads at the cited lines.

## Tools used (41 call(s) over 26 step(s))
