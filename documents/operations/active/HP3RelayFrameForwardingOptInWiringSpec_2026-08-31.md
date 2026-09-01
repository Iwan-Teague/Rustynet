# HP-3 Relay Frame-Forwarding — Opt-In `--node` Wiring Spec

**Date:** 2026-08-31
**Status:** SPEC ONLY — no code changed. A later task implements from this document.
**Owner decision (binding):** the HP-3 validator is wired in as an **OPT-IN stage, never default-on**. It injects nft blocks and restarts daemons mid-run (disruptive) and interacts with the QH-64 gossip trust-restart race (§6). This supersedes the *default-plan* recommendation in `NeverDispatchedLinuxStagesTriage_2026-08-27.md` §6 D-1 and `OwnerDecisionDigest_2026-08-27.md` §5 (both recommended "wire it into the default Live plan"; the mechanism they proposed is rejected here, the goal — prove HP-3 on the engine of record — is unchanged).
**Grounding:** every `file:line` is against this tree at HEAD (`ai-edit/edit-1788260113251-15328-8` worktree). Line numbers of large files drift; the implementer should re-grep the named symbols before editing.

---

## 1. The validator as it exists today

### 1.1 Identity and current line

The digest and triage cite `vm_lab/mod.rs:13841`; **that cite is stale** — the function has moved. Current anchor at HEAD:

- `crates/rustynet-cli/src/vm_lab/mod.rs:14071` — `fn exercise_linux_relay_forwards_frame(linux_alias, inventory_path, ssh_identity_file, known_hosts_path) -> Result<String, String>` (body `:14071-14350`).

Supporting symbols (all `vm_lab/mod.rs` unless noted):

| Symbol | Line | Role |
|---|---|---|
| `RELAY_FORWARD_TEST_CAPTURE_SECS` | `:13742` | 15 s tcpdump window |
| `RELAY_FORWARD_TEST_MARKER_LEN` | `:13743` | 8-char random ASCII marker |
| `struct RelayForwardTestTopology` | `:13749-13755` | relay + 2 peers + mesh IPs |
| `select_relay_forward_test_topology` | `:13761-13816` | topology resolution, fails closed |
| `relay_forward_test_peer_rank` | `:13818-13824` | deterministic peer order: `aux` < `extra` < other |
| `generate_relay_forward_test_marker` | `:13829-13835` | random per-run marker (stale capture can't masquerade) |
| `relay_forward_test_marker_hex` | `:13841` | the line the old cite pointed at (helper, not the fn) |
| `run_relay_forward_test_script` | `:13977` | SSH-direct script runner |
| `wait_for_relay_forward_test_relay_routing` | `:14001` | polls both peers' own `rustynet status` |
| `cleanup_relay_forward_test` | `:14358-14384` | unconditional best-effort teardown |

### 1.2 What it does, step by step (all cites `vm_lab/mod.rs`)

1. **Resolve topology** `:14077-14078` → `select_relay_forward_test_topology` `:13761-13816`:
   - relay = first Linux entry with `relay_capable == Some(true)` `:13768-13772`;
   - peers = Linux entries that are **not** the relay, **not** `exit_capable`, **not** `relay_capable` `:13774-13780`; needs ≥2 or hard `Err` (fail closed, not a silent skip) `:13790-13795`;
   - both peers must have a `mesh_ip` in inventory `:13798-13807`;
   - deterministic peer pick so repeated runs select the same pair `:13784-13788, :13818-13824`.
2. **Platform gate:** all three targets must be Linux or `Err` `:14099-14107`. Linux-only today; no mac/win counterpart exists (`LiveLabStageCoverageGapPlan_2026-08-10.md:298`).
3. **Provision relay** `:14113-14131`: systemd unit active (`HP3_RELAY_UNIT_STATE=active`) + `/healthz` ok (`"status":"ok"`). Durable setup, explicitly safe to early-return before anything is firewalled (comment `:14109-14112`).
4. **Before-counters** `:14135-14151`: parses `rustynet_relay_frames_forwarded_total` / `rustynet_relay_bytes_forwarded_total` from the relay's metrics (`rustynet-relay/src/main.rs::ForwardStats`/`record_forward` is the counter source — `repo_context.rs:2186`).
5. **Disruptive block (inside the cleanup-guaranteed closure `:14161`):**
   - **nft-inject 2 UDP-drop rules on the sender** (blocking its direct path to the receiver) and assert `HP3_NFT_RULE_COUNT=2` `:14163-14175`;
   - **nft-inject 2 UDP-drop rules on the receiver** (blocking its direct path to the sender), same assertion `:14176-14188`;
   - **restart `rustynetd` on BOTH peers** via systemd, asserting `HP3_DAEMON_STATE=active` `:14192-14206`;
   - poll both peers' own status until each **independently** reports relay-routed (`path_live_relay_peers` / `relay_session_established_peers`) `:14208-14213, :14320-14335`;
   - start a **tcpdump capture on the relay's own wire** `:14217-14229`; send a **marked ICMP ping** (random 8-byte payload) sender→receiver over the mesh `:14231-14241`; poll until the capture self-terminates (15 s + slack, `:14246-14260`); fetch it `:14262-14268`;
   - assert ping exit 0 `:14270-14275`; assert the **plaintext marker is ABSENT from the relay capture** (ciphertext-only / zero-ingress property) `:14276-14281`;
   - after-counters `:14284-14302`; assert frames AND bytes strictly increased `:14304-14313`.
6. **Guaranteed cleanup** `:14339-14349` → `cleanup_relay_forward_test` `:14358-14384`: on every exit path (pass, assertion failure, SSH error) removes the nft block and **restarts both daemons again**, best-effort; cleanup failures go to stderr and never mask the verdict (comment `:14352-14357`).

### 1.3 Why it is disruptive (the concrete list)

Per invocation: **4 nft rules injected** (2 per peer), **4 daemon restarts** (2 in-test + 2 in cleanup) across the two peer nodes, a **15 s+ live capture** on the relay, and two peers forced off their direct path for the duration. This is exactly the mid-run restart + dataplane-mutation profile the owner ruled must not be default-on.

### 1.4 Why it never dispatches today

- No `StageId` variant → not in `StageId::ALL` (`stage/mod.rs:161+` catalog) → the plan (`plan.rs:306-308`: `StageId::ALL.iter().filter(include)`) cannot contain it (`NeverDispatchedLinuxStagesTriage_2026-08-27.md:112-113`).
- Only execution path is the standalone `ops vm-lab-validate-linux-security` chainer: dry-run branch `vm_lab/mod.rs:24955-24967`, real call `:24968-24990`, outcome assembled `:25013` (`main.rs:4551` entry) — which appends **no ledger row**.
- Bash-dialect registry row: `live_lab_stage_registry.rs:1891-1893` (`name: "validate_linux_relay_forwards_frame"`, `special: Some("linux_relay_forwards_frame")`); column mapping keyed on that bash name: `live_lab_run_matrix.rs:4870`; column exists in the ledger header: `live_lab_run_matrix.rs:229`.
- Result: `linux_relay_forwards_frame` = `not_run` in 178/178 ledger rows (triage `:117-118`).
- Nothing else proves it: `relay_validation` is lifecycle-only and says so in-source (`role_validation/relay.rs` via triage `:122-127`): service up, ports bound, `/healthz` ok — never a forwarded frame, never ciphertext-only.

---

## 2. The opt-in plumbing pattern to mirror: `enable_chaos_suite` end to end

The chaos suite is the exact precedent for "stage exists, is real, but must never run unless explicitly asked". Full chain at HEAD:

**(a) CLI flag → config.**
`crates/rustynet-cli/src/main.rs:4459` — `enable_chaos_suite: parser.has_flag("--enable-chaos-suite")` inside the `vm-lab-orchestrate-live-lab` options struct literal. Config field: `crates/rustynet-cli/src/vm_lab/mod.rs:1271` — `pub enable_chaos_suite: bool` (the sibling `enable_negative_control` at `:1275` documents the same opt-in contract: "out of the default plan").

**(b) Config → native.rs.**
`crates/rustynet-cli/src/vm_lab/orchestrator/native.rs`:
- `:47` — `let enable_chaos_suite = config.enable_chaos_suite;` (scalar captured while `config` is intact);
- `:326-342` — passed positionally into `build_rust_native_orchestration_stages(...)` (chaos at `:336`);
- `:561` — recorded into the run manifest selectors: `chaos_suite: enable_chaos_suite && !skip_live_suite` (the `&& !skip_live_suite` is what makes `--skip-linux-live-suite` drop an enabled suite);
- `:912-938` — `build_rust_native_orchestration_stages` takes `enable_chaos_suite: bool` `:918` and calls `.with_enable_chaos_suite(enable_chaos_suite)` `:931`.

**(c) PlanBuilder.**
`crates/rustynet-cli/src/vm_lab/orchestrator/plan.rs`:
- field `:134` (`enable_chaos_suite: bool`, doc `:132-133` "append the opt-in chaos stages… outside the default plan");
- builder method `:223-226` (`with_enable_chaos_suite`);
- destructured in `build()` `:265`;
- consumed by the include closure `:298` — `StageSuite::Chaos => !skip_live_suite && enable_chaos_suite`.

**(d) plan.rs include closure — CURRENT form (post-`e3297391`).**
The closure is **stage-id-aware**, not suite-only: it takes `&StageId` (`plan.rs:282`), first applies a named-variant exception for the three macOS anchor validator stages (`:283-292`, retained when `anchor_platform_macos` even under `skip_live_suite` — the MAC-D3 fast path), **then** matches `id.suite()` (`:293-300`). Suite arms:
```rust
StageSuite::Setup | StageSuite::Cleanup => true,                    // :294
StageSuite::Live => !skip_live_suite,                               // :295
StageSuite::Soak => !skip_live_suite && !skip_soak,                 // :296
StageSuite::CrossNetwork => !skip_live_suite && cross_network.enable_suite, // :297
StageSuite::Chaos => !skip_live_suite && enable_chaos_suite,        // :298
StageSuite::NegativeControl => !skip_live_suite && enable_negative_control, // :299
```
Instantiation is a compiler-enforced exhaustive match over `StageId::ALL` (`:303-309`, one `Box::new` arm per variant — a new variant fails to compile until it gets an arm).

**(e) Suite authority.**
`crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs`: `StageSuite` enum `:95-120` (`Chaos` at `:110`); `define_stage_catalog!` macro `:122-155` generates `StageId`, `ALL`, `as_str`, **`suite()` — "the plan-inclusion authority" (RNQ-16, `:88-93`, `:137-140`)** — and `tier()`; rows are `Variant => "wire_name" @ Suite / Tier` (`:161+`; e.g. `RelayValidation => "relay_validation" @ Live / T1Role` at `:205`).

**(f) Downstream consumers that must stay consistent.**
- Manifest reconstruction: `resolved_plan.rs:350-360` rebuilds the expected plan from recorded selectors — `.with_enable_chaos_suite(selectors.chaos_suite)` at `:356`; its test helper `:839-845` mirrors it (`:841`).
- Evidence: `evidence.rs:160` records `chaos_suite: config.enable_chaos_suite`.
- Exclusion lint: `run_exclusion.rs:417` matches the config field.
- Tests pin plan sizes: default **64** (`plan.rs:505-508`), chaos-enabled **73** (`:566-584`), negative-control **68** (`:587-622`), stacked **77** (`:625-635`), skip-live drops opt-in suites (`:638-652`). (The triage's "61/70/72" (`:153-154`) is stale; current HEAD is 64/73/77.)
- MCP `ai_lab_run` has **no chaos selector today** — the lab-state server forwards only `--skip-soak`-style flags (`lab_state.rs:6406`, `:6529`; `ai_agent.rs:6401`, `:9242`). Chaos can only be enabled via the CLI today.

**(g) Role-election selector flow (the alternative shape).**
`exit_platform`/`relay_platform`/`anchor_platform`/… are string config fields defaulted empty in the manifest selectors (`native.rs:554-558`), and the plan-level effect is a derived boolean: `config.anchor_platform.as_deref() == Some("macos")` at `native.rs:335` → PlanBuilder `anchor_platform_macos` → the include-closure exception at `plan.rs:283-292`. This shape elects a role AND adjusts plan membership in one flag. It fits when the flag's meaning is "which node plays this role"; it does not, by itself, express "run a disruptive validator".

---

## 3. Design decision: which opt-in mechanism

Options considered:

**(i) Reuse `StageSuite::Chaos`.** Rejected. Chaos has a defined semantic — fault injection (`stage/chaos.rs`, nine stages delegated to `live_chaos_*` binaries; `repo_context.rs:2145-2153`). HP-3 is a *positive* security proof, not a fault injector; folding it in would (a) make `--enable-chaos-suite` silently carry a disruptive firewall/daemon-restart stage under a flag whose contract says "fault injection", (b) break the `chaos_suite_opt_in_appends_9_fault_stages` count test (`plan.rs:566-584`) and the `chaos_suite_stages()` id-list (`plan.rs:162-164`), and (c) conflate the `linux_stage_chaos` ledger column family with `linux_relay_forwards_frame`.

**(ii) New dedicated `StageSuite` gated by a new selector.** **RECOMMENDED.** Add `StageSuite::Disruptive` (naming below) with exactly one row, gated by a dedicated boolean `--enable-relay-forwarding-validation`, via an include arm that is a byte-for-byte structural copy of the chaos arm (`plan.rs:298`). Reasons:
- **Default-exclusion is structural, not conventional.** RNQ-16 makes the suite tag *the* plan-inclusion authority (`stage/mod.rs:88-93`). A stage whose suite arm evaluates `false` without the flag cannot appear in a default plan, and the compiler-enforced exhaustive closure means there is no code path that admits it accidentally. The owner's guarantee ("never in a default run") is enforced by the same mechanism that keeps chaos and negative-control out — both precedents (`plan.rs:298-299`) show the pattern scales to a second and third opt-in suite.
- No inverted special-case in the include closure. The macOS-anchor exception (`:283-292`) is *additive* (it rescues already-Live stages under skip); putting a `Live`-tagged stage behind a default-off flag would need the opposite — a *subtractive* exception on a `Live` row — which no current arm expresses and which every future reader would read as a bug against the RNQ-16 invariant.
- Downstream machinery already exists per-suite: `resolved_plan.rs:356` reconstruction, `evidence.rs:160` recording, `run_exclusion.rs:417`, and a ledger column (`linux_relay_forwards_frame`, `live_lab_run_matrix.rs:229`) that already exists and is currently dead.

**(iii) New `StageId` in an existing suite gated by a dedicated boolean.** Rejected for the same reason as the subtractive exception above if the suite is `Live` (default arm `:295` would admit it unconditionally — direct violation of the mandate), and equivalent to (ii) in everything but naming if the "existing suite" were Chaos (see (i)). The task brief lists it as an option; the honest analysis is that *any* correct version of (iii) collapses into (ii) once the suite arm must consult the flag.

**Chosen: (ii).**

- Suite name: `StageSuite::Disruptive` — doc comment: stages that mutate guest dataplane/security state mid-run (nft rules, daemon restarts) and are therefore opt-in only. (Alternative names considered: `Intrusive`, `Hp3`; `Disruptive` states the reason for the gate, matching how the `Chaos` and `NegativeControl` doc comments state *their* reasons at `stage/mod.rs:108-116`.)
- Catalog row: `RelayForwardsFrameValidation => "relay_forwards_frame_validation" @ Disruptive / T1Role` (wire name per triage §1d `:144`).
- Flag: `--enable-relay-forwarding-validation` (names the proof, not the mechanism, mirroring `--enable-negative-control` naming style at `main.rs:4460`).
- Tier: `T1Role` — it is a relay-role capability proof (`RelayValidation` at `stage/mod.rs:205` is the same tier).

**Exactly how the current filter enforces never-default-on:** `plan.rs:306-308` iterates `StageId::ALL` filtered by the include closure; the new arm `StageSuite::Disruptive => !skip_live_suite && enable_relay_forwarding_validation` (inserted after `:299`) evaluates `false` whenever the flag is absent — which is the default (`main.rs` `has_flag` → `false`; `PlanBuilder::default()` field `false`). `PlanBuilder::new()` therefore cannot emit the stage, and neither can `resolved_plan.rs:350-360`'s reconstruction unless the recorded manifest selector says the run opted in.

---

## 4. Exact implementation steps (ordered checklist)

All line anchors at HEAD; re-grep symbols before editing.

1. **`stage/mod.rs` — suite variant.** Add `Disruptive` to `StageSuite` (`:95-120`, after `NegativeControl` `:116`, before `Cleanup` `:119`) with a doc comment in the house style of `:108-116` ("opt-in via `--enable-relay-forwarding-validation` (and dropped by `--skip-linux-live-suite`); stays OUT of the default plan because it injects nft blocks and restarts daemons mid-run").
2. **`stage/mod.rs` — catalog row.** Add to `define_stage_catalog!` at the **END of the Live-suite block** (after the last `@ Live` row — canonical order = plan order, and placing it last minimizes how many live stages run *after* its mid-run restarts; see §6): `RelayForwardsFrameValidation => "relay_forwards_frame_validation" @ Disruptive / T1Role,` with a one-line judgment comment on the row (tier convention, `stage/mod.rs:157-160`).
3. **New file `stage/relay_forwards_frame_validation.rs`** implementing `OrchestrationStage` (structure mirrored from `relay_validation.rs:38-53`):
   - `id()` → `StageId::RelayForwardsFrameValidation`; `name()` → `"relay_forwards_frame_validation"`.
   - `dependencies()` → `&[StageId::DeployRelayService, StageId::RelayValidation]` (the relay must be deployed and lifecycle-validated first; pattern: `relay_validation.rs:45-47`, `live_hello_limiter_flood_validation.rs:19`).
   - `applies_to_roles()` → `&[NodeRole::Relay]` — **with a comment that this stage is topology-scoped, not per-node**: it drives the relay *plus two spare peers* chosen from the inventory (`vm_lab/mod.rs:13761-13816`).
   - `fanout()` → `StageFanout::Once` (one whole-topology action), **not** `PerNode` — contrast `relay_validation.rs:51-53`.
   - `execute()`:
     - If no node is assigned `NodeRole::Relay` → `StageOutcome::Skipped(...)` (never `Passed`) — the false-green guard at `relay_validation.rs:64-72`.
     - Because the stage is opt-in, a *requested-but-impossible* topology is a failure, not a skip: if the relay-role node exists but `select_relay_forward_test_topology` cannot find two spare Linux peers (`vm_lab/mod.rs:13790-13795`), surface the `Err` as a stage failure (the operator explicitly asked for this proof; failing closed is the honest verdict).
     - Drive the existing logic. The eight script-builder functions (`build_relay_forward_test_*` in `vm_lab/mod.rs`) are pure string builders and the assertion/cleanup skeleton (`:14161-14349`) is sound — **reuse them; do not clone the firewall/cleanup logic** (same instruction as `LiveLabTestCoverageImplementationDesign_2026-08-19.md:334`). The seam decision: the current impl is SSH-direct via `run_relay_forward_test_script` (`:13977`) + `resolve_remote_targets` (`:14080`), needing `inventory_path`/`ssh_identity_file`/`known_hosts`. Preferred: re-home the body into the stage and execute each script through the stage's `OrchestrationContext` adapter shell-exec seam (`ctx.adapters[alias]`, as `relay_validation.rs:79-86` fetches adapters) so it inherits the orchestrator's SSH plumbing; the triage's original note (`:148-149`) recommended the same seam. Minimal alternative if the adapter seam cannot express the multi-host scripts in this pass: keep the SSH-direct helpers and pass them the orchestrator's inventory/identity paths from ctx — acceptable because this is lab tooling, but record the deviation in the stage's doc comment.
     - Emit the same rich success string as `:14315-14336` (aliases, counter deltas, ciphertext-only confirmation, both peers' relay-routed status fields) — that string is the evidence a human reads in the report.
4. **`stage/mod.rs` — module declaration:** `pub mod relay_forwards_frame_validation;` alongside `:85-86`.
5. **`plan.rs` — PlanBuilder:**
   - field `enable_relay_forwarding_validation: bool` next to `:134-138` with the opt-in doc comment;
   - `with_enable_relay_forwarding_validation(...)` next to `:223-232`;
   - destructure next to `:265-266`;
   - include arm after `:299`: `StageSuite::Disruptive => !skip_live_suite && enable_relay_forwarding_validation,`;
   - instantiation arm in the exhaustive match (`:310+`): `StageId::RelayForwardsFrameValidation => Box::new(RelayForwardsFrameValidationStage),` + `use` import (the compiler will name this spot).
6. **`native.rs` — threading:**
   - capture next to `:48`: `let enable_relay_forwarding_validation = config.enable_relay_forwarding_validation;`
   - pass into `build_rust_native_orchestration_stages(...)` next to `:336-337`;
   - manifest selector next to `:561`: `relay_forwarding_validation: enable_relay_forwarding_validation && !skip_live_suite,` (same `&& !skip_live_suite` discipline as chaos);
   - `build_rust_native_orchestration_stages` param next to `:918` + `.with_enable_relay_forwarding_validation(...)` next to `:931` (the fn is already `#[allow(clippy::too_many_arguments)]` `:911`).
7. **`vm_lab/mod.rs` — config field:** `pub enable_relay_forwarding_validation: bool` next to `:1271-1275`, doc comment mirroring `:1272-1274` ("opt-in … out of the default plan; injects nft blocks and restarts two peer daemons mid-run — see HP3RelayFrameForwardingOptInWiringSpec_2026-08-31.md").
8. **`main.rs` — flag:** next to `:4459-4460`: `enable_relay_forwarding_validation: parser.has_flag("--enable-relay-forwarding-validation"),`.
9. **`resolved_plan.rs` — reconstruction:** `.with_enable_relay_forwarding_validation(selectors.relay_forwarding_validation)` next to `:356`; extend the test helper signature (`:828-832`) and call (`:841`) likewise — the reconstruction MUST reproduce the exact plan membership or recorded-plan verification fails for opted-in runs.
10. **`evidence.rs`:** record `relay_forwarding_validation: config.enable_relay_forwarding_validation` next to `:160`.
11. **`run_exclusion.rs`:** extend the field match at `:417` for the new config field.
12. **`live_lab_run_matrix.rs` — ledger column mapping:** next to the bash-name arm `:4870`, add `"relay_forwards_frame_validation" => Some("linux_relay_forwards_frame")` so `--node` rows finally populate the existing column (`:229`). Parse caveats per AGENTS.md §12.3: quote-aware reader; the column flipping from permanent `not_run` to real pass/fail is the point (QH-37/G3 mirror-image, `LiveLabStageCoverageGapPlan_2026-08-10.md:135-136`).
13. **`live_lab_stage_registry.rs`:** keep the bash-dialect row `:1891-1893` as-is; verify the registry's `--node`-name handling admits `"relay_forwards_frame_validation"` the way the chaos rows do (the triage's "registry row with `state_machine_only: true`" guidance, `:151-152`, applies to whichever registry field gates bash-dialect `special:` rows out of `--node` dispatch — mirror the `chaos_*` rows' shape, `repo_context.rs:2145-2153`).
14. **Topology/roles a run must elect for the stage to execute:**
    - a Linux node assigned the **relay** role (`--node <alias>:relay` / equivalent election) — the stage Skips without one;
    - ≥2 additional Linux nodes that are **not** exit- and **not** relay-capable, each with a `mesh_ip` in inventory (`vm_lab/mod.rs:13774-13807`) — the standard 5-node lab (exit/client/relay/aux/extra) satisfies this (`:13760`);
    - the run must NOT pass `--skip-linux-live-suite` (the suite arm `plan.rs` new `:300` requires `!skip_live_suite`);
    - if a Linux exit node is also present it is *excluded* from peer selection by design (`:13778`) — do not "fix" that; forcing the exit through the relay would break the exit cell.
15. **Tests to add (`plan.rs` `#[cfg(test)] mod tests`, `:500+`)** — mirror the chaos/negative-control tests:
    - `relay_forwarding_validation_absent_from_default_plan`: `PlanBuilder::new().build()` must NOT contain `StageId::RelayForwardsFrameValidation` (the ABSENT-by-default guarantee; same shape as the negative-control default check `:606-612`). The existing `build_returns_64_stages` (`:505-508`) must stay at 64 — that is itself the absence pin.
    - `relay_forwarding_validation_opt_in_appends_1_stage`: with `.with_enable_relay_forwarding_validation(true)` the plan is **65** stages, contains the stage, its position is after `StageId::RelayValidation` (dependency order), and `ids.last() == Some(&StageId::Cleanup)` (mirror `:566-584`).
    - `skip_live_suite_drops_relay_forwarding_validation`: flag + `with_skip_live_suite(true)` → absent (mirror `:638-652`).
    - stacking counts: chaos + this flag = 74; chaos + negative-control + this flag = 78 (mirror `:625-635`).
    - uniqueness under the flag (mirror `chaos_stage_ids_are_unique_when_enabled` `:880-886`).
    - stage-level tests in the new `relay_forwards_frame_validation.rs`: no-relay-assignment → `Skipped` not `Passed` (pattern: `relay_validation.rs:209+` tests); topology-resolution failure surfaces as stage failure.
16. **Optional follow-up (separate change, not required to land this): MCP `ai_lab_run` selector.** The lab-state server currently forwards only a fixed flag set (`lab_state.rs:6406`, `:6529`; `ai_agent.rs:6401`) and has no chaos selector either. Adding `("­--enable-relay-forwarding-validation", "relay_forwarding_validation")` to both flag-pair lists plus a `json_schema_boolean` next to `skip_soak` (`lab_state.rs:4869`) would make the stage drivable from the MCP loop. Until then: CLI-driven runs only.
17. **Docs/index:** update `documents/operations/active/README.md` (index entry for the stage + this spec), `documents/CODE_MAP.md` (new stage module), and append the HP-3 row to the parity status matrices as "provable on demand, opt-in" — per AGENTS.md §6/§13.4. `FullTodoInventory_2026-07-28.md:428` and the triage/coverage-gap docs' HP-3 entries should gain a one-line "wired opt-in on <date>" pointer.
18. **Gates:** `cargo fmt --all -- --check`; scoped `cargo check -p rustynet-cli --all-targets --all-features`; `cargo clippy` and `cargo test` with the same scope (AGENTS.md §13.1 — the flags are mandatory); then the full §7 list before landing. The exhaustive `StageId` match arms mean an incomplete step 3/5 fails the build loudly rather than silently under-dispatching.

---

## 5. Verification runs (what "done" looks like)

- Unit: all new plan-membership tests green; `build_returns_64_stages` still 64.
- Live: one CLI orchestrate run on the Linux topology with `--enable-relay-forwarding-validation` where the stage dispatches (not skips), passes, and its report artifact shows the counter-delta + ciphertext-only evidence string (`:14315-14336`); the appended `live_lab_node_run_matrix.csv` row shows `linux_relay_forwards_frame` ≠ `not_run` for the first time ever (178/178 streak broken intentionally). Verify the row exists and attribute the pass to the stage's own report artifact, not the column alone (AGENTS.md §12.3).
- Negative: one default run (no flag) confirming the stage is absent from the recorded plan manifest (the `resolved_plan.rs` reconstruction must agree — if it doesn't, step 9 was missed).

## 6. The QH-64 interaction (ordering hazard)

QH-64 (`QH64GossipTrustRaceDesignInvestigation_2026-08-31.md`) is **open**. Mechanism, condensed from its §0: a `rustynetd` restart whose trust-evidence file fails to load makes the reconcile loop return early **before membership is ever loaded** (`daemon.rs:10260-10267`), and `sync_gossip_data_plane` early-returns when `membership_state` is `None` (`daemon.rs:6464-6469`) — the gossip transport is never bound and the node goes gossip-silent (`gossip_accepted_total=0`). Self-heal exists only via a later *successful* reconcile tick (`daemon.rs:10557`); nothing mid-run forces it (`:8843` is reachable only via a full signed-bootstrap apply, which no orchestrator step re-runs mid-run).

This stage restarts **two peer daemons, twice each** (test `vm_lab/mod.rs:14192-14206` + cleanup `:14374-14382`) — exactly the "two-actor restart storm" shape QH-64 §0.3 names as a live-cause candidate. Consequences for a run that enables this stage:

1. **Any gossip-dependent or traffic stage that runs AFTER the HP-3 stage in the same run may fail or skip spuriously** with QH-64 symptoms, through no defect of its own. This is the reason the catalog row belongs at the **end of the Live block** (step 2): canonical order = plan order, so placement minimizes the population of post-restart stages. Note `gossip_convergence_validation` sits *before* the relay stages in `StageId::ALL` (`stage/mod.rs:199` vs `:205`), so it is naturally safe with this placement; `traffic_test_matrix` (`:206`) and everything after the relay rows are the exposed set.
2. **Recommendation: do not combine this stage with `gossip_convergence_validation`-class assertions in the same run until QH-64 is resolved.** Concretely: when enabling the flag, either accept that a downstream gossip/traffic failure is *presumed* QH-64 until disproven (re-run once without the flag to attribute), or run the HP-3 cell focused (Linux-only `nodes` topology, `skip_soak`) so the exposed tail is small.
3. Any triage of a failed opted-in run MUST check the daemon journals of the two restarted peers for the QH-64 signature (reconcile early-return / unbound gossip transport) before blaming the peer's own stages; cite the QH-64 doc §0.2/§3.4 probes.

---

## 7. Non-goals

- No mac/win port of the proof (Linux-only today; `LiveLabStageCoverageGapPlan_2026-08-10.md:298` tracks the counterparts).
- No change to the standalone `ops vm-lab-validate-linux-security` chainer (`vm_lab/mod.rs:24955-25013`) — it keeps working unchanged.
- No change to chaos/negative-control semantics; their arms (`plan.rs:298-299`) are untouched.
- This spec implements nothing; `BashRetirementDispositions_2026-08-22.md` B5 stays "parked" until the implementing task lands and a live run proves the stage.
