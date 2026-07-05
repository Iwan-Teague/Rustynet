# Rust-Native Multi-Platform Orchestrator Replacement Plan (W5)

Date opened: 2026-04-28
Owner: AI implementation agent (per `CLAUDE.md`)
Supersedes the bash orchestrator's monopoly on the live-lab install path.
Sister doc: `OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md` (W1-W4 deliverables this plan builds on top of).

> **Status (2026-04-29): partial implementation; live evidence pending.**
>
> Code-only slices have shipped. Every slice that requires live evidence
> against a real VM lab remains unchecked because the lab is not
> reachable from CI yet.
>
> | Slice | Code | Unit gates | Live evidence | Commits |
> |---|---|---|---|---|
> | W5.0 Foundation | ✓ | ✓ (26 tests) | n/a (foundation) | `ca84aeb` |
> | W5.1 LinuxNodeAdapter | ✓ | ✓ | ⛔ blocked-by: real Linux lab | `8c255c8`, `81749e4` (hardening: real node IDs + 64-char pubkeys for membership init) |
> | W5.2 WindowsNodeAdapter | ✓ | ✓ | ⛔ blocked-by: Windows UTM VM | `76df3c4`, `81749e4` (hardening: collected pubkeys for non-Exit; Exit still fail-closed) |
> | W5.3 MacosNodeAdapter + 6 macos-*-check subcommands | ✓ | ✓ | ⛔ blocked-by: macOS UTM VM (W5.4 keeps Exit fail-closed if absent) | `f4a0076`, `81749e4` |
> | W5.4 Windows/macOS-as-Exit (membership-owner cross-OS) | ✓ (impl ships); fail-closed in code per `NodeRole::is_supported_for_platform` | ✓ | ⛔ blocked-by: heterogeneous mesh with non-Linux Exit | `04cf7fd`, `81749e4` (matrix tightening) |
> | W5.5a 17 stages + PlanBuilder | ✓ | ✓ | ✅ Linux live-proven 2026-07-04 (`42afa4b`): full pipeline ran, all Rust-dialect stages PASS through `deploy_relay_service`; only `traffic_test_matrix` client↔client failed (known downstream dataplane gap, not migration) — report `state/rust-native-linux-1783185441` | `c63084b`, `81749e4` (single-source-of-truth via `build_rust_native_orchestration_stages` + `FinalCleanupStage`) |
> | W5.5b parity-diff harness + `vm-lab-diff-orchestrator-parity` subcommand | ✓ | ✓ (11 tests) | 🟡 Rust `parity_input.json` now emitted live (2026-07-04); bash emitter still absent AND the mechanical `overall_parity_pass` gate is unsatisfiable bash↔Rust (divergent stage IDs — see parity-gate finding above); gate needs redefinition | `b530e85` |
> | W5.6 CLI surface (--legacy-bash-orchestrator, deprecation translation) | ✓ | ✓ (13 tests) | n/a (CLI wiring); default-flip ⛔ blocked-by: **redefined** functional-parity gate (mechanical stage-ID parity is unsatisfiable by construction — see parity-gate finding) | `b530e85` |
> | W5.7 Live-evidence campaign + bash removal | ✗ | ✗ | ⛔ blocked-by: all live-evidence scenarios | — |
>
> **Observability parity (2026-07-04, `831a32a`):** the `--node` path now
> emits the SAME live-lab recording artifacts as the wrapper — a run-scoped
> `stage_manifest.json` reflecting the Rust `StageId` plan (dialect enabled +
> barrier-eligible), realtime `state/stages.tsv` `running`/terminal rows via a
> new shared recorder (`live_lab_stage_recorder.rs`) threaded through
> `StateMachineRunner::run_with_observer`, and `orchestrate_result.json` +
> barrier-exempt reconcile + a single run-matrix row via `finalize`. A `--node`
> run therefore renders in the live-lab monitor with no monitor change. This is
> Fable5 Finding 4 recorder-first (see `LiveLabStageContractPlan_2026-07-03.md`)
> and makes the eventual W5.7 default-flip a no-op for every downstream
> consumer. It does NOT flip the default or assert parity.
>
> **First live Linux `--node` run (2026-07-04, HEAD `42afa4b`) — W5.5a/W5.5b
> unblocked for Linux.** `ops vm-lab-orchestrate-live-lab --node
> debian-headless-1:exit --node debian-headless-2:client --node
> debian-headless-3:client --source-mode working-tree` executed the full
> `PlanBuilder` pipeline against the real 3-node Debian lab (report dir
> `state/rust-native-linux-1783185441`, run-matrix row
> `livelab-1783187272-42afa4bd910a`). Result: **15 of 21 stages PASS**, covering
> **every Rust-dialect stage** — `membership_init`, `distribute_membership`,
> `anchor_validation`, `distribute_assignments`/`traversal`/`dns_zone`,
> `enforce_baseline_runtime`, **`validate_baseline_runtime` (mesh functionally
> validated)**, and `deploy_relay_service`/`relay_validation`. The bootstrap's
> retry+DNS-repair recovered all three flaky-egress nodes live. The state-machine
> runner emitted every recording artifact and they were verified: the run-scoped
> `stage_manifest.json` (166-entry catalog, 21 enabled = the Rust plan,
> `membership_init` enabled / `membership_setup` disabled), realtime `stages.tsv`
> (clean `running`→terminal per stage, no dup rows), `orchestrate_result.json`,
> and `parity_input.json` (21-stage `LiveLabRunReport`, `overall_status: failed`,
> 3 `node_statuses`). The single failure is `traffic_test_matrix` — the all-pairs
> mesh ping failed **only** on the client↔client pair (`debian-headless-2 ↔
> debian-headless-3`); client↔exit passed. Every orchestration *setup* stage
> passed, so this is a dataplane/mesh-reachability issue **downstream of
> orchestration** (the known, separately-tracked Linux traffic-test gap), not a
> migration defect — the bash orchestrator would fail the same client↔client pair
> on the same topology. `role_switch_matrix`/`exit_handoff`/`active_exit`/`cleanup`
> then fail-closed skipped, which is correct.
>
> **Parity-gate design finding (2026-07-04) — the W5.6 default-flip gate as
> written is unsatisfiable bash↔Rust and must be redefined.** The plan's parity
> definition (§4.W5.5, "identical set of stage IDs executed") and
> `diff_live_lab_reports`'s `overall_parity_pass` require `stages_match_all`
> (empty `stages_only_in_left`/`right`). But the two orchestrators use
> **divergent stage IDs by design** — the bash dialect
> (`membership_setup`, `distribute_membership_state`, `issue_and_distribute_*`,
> `prime_remote_access`) vs the Rust dialect (`membership_init`,
> `distribute_membership`, `distribute_assignments`/`traversal`/`dns_zone`,
> `anchor_validation`, `deploy_relay_service`, …). Only 8 stage IDs overlap
> (`preflight`, `prepare_source_archive`, `verify_ssh_reachability`,
> `cleanup_hosts`, `bootstrap_hosts`, `collect_pubkeys`,
> `enforce_baseline_runtime`, `validate_baseline_runtime`). So a mechanical
> bash↔Rust diff can **never** produce `overall_parity_pass=true`, and the bash
> `parity_input.json` emitter was never built (W5.5b, below). The recorder-first
> convergence (`831a32a`) unifies the **consumer contract**
> (`stage_manifest.json` + `stages.tsv` + `orchestrate_result.json` the monitor
> reads), **not** the stage-ID sets. **Recommendation:** redefine the W5.6 flip
> gate as **functional/outcome parity** — both dialects reach mesh setup +
> `validate_baseline_runtime` PASS + equal validator pass/total counts on the
> same topology — and/or restrict the mechanical `diff_live_lab_reports` to the
> shared-ID stages or a bash→Rust `StageId` remap. Until that gate is redefined
> and met, **the default stays on bash** (flipping now would violate the DoD:
> flip only after genuine parity proof). W5.7 (bash removal) remains gated on the
> cross-OS live-evidence campaign.
>
> **Loop-readiness increment (2026-07-04) — functional-parity gate + cleanup
> release-blocker fix landed.** Two of the three prerequisites for running the
> live-lab loop on the Rust engine are now addressed in code:
> - **Functional/outcome parity mode (`a88ce75`).** `canonical_stage_id` +
>   `diff_live_lab_reports_functional` + `FunctionalParityDiff`, exposed as
>   `vm-lab-diff-orchestrator-parity --mode strict|functional` (default
>   `strict`, byte-compatible). Functional mode normalizes the bash/Rust
>   stage-ID dialects (the 5 known aliases → canonical) and compares the shared
>   logical work + overall status + node count; **fail-closed on zero overlap**;
>   validator counts reported-but-informational. This is the satisfiable
>   redefinition the parity-gate finding called for. 6 unit tests.
> - **Cleanup residue release-blocker FIXED (`9c1c908`).** The first live
>   `--node` run reproduced it: `FinalCleanupStage` lists `ExitHandoff` as a
>   dependency only for ordering, but the runner's skip-cascade also gated on
>   it, so a `traffic_test_matrix` failure skip-cascaded cleanup and left this
>   run's killswitch + exit-NAT residue on the guests. Fix: new
>   `OrchestrationStage::always_run()` (cleanup overrides `true`) exempts
>   teardown stages from the skip-cascade (still ordered last, still honored by
>   `--skip-stage`), plus a `catch_unwind` panic guard around `execute` so a
>   panicking stage becomes `Failed` rather than aborting past cleanup. 578
>   orchestrator tests green.
>
> **Remaining loop-readiness work (planned, grounded):** (prereq 1) port the
> bash-only validators into the Rust `PlanBuilder` — RANK-0 is a report-mapping
> win (the 6 daemon-probe results `ValidateBaselineRuntimeStage` already
> computes → the `linux_runtime_acls/service_hardening/key_custody/mesh_status`
> columns), RANK-1 is a new `SecurityAuditValidationStage` wrapping the 8
> adversarial audit checks (logic exists in `evaluate_*_report` /
> `run_validate_linux_*_stage`; needs an adapter-seam stage + `StageId`/registry/
> `PlanBuilder` count bump); (prereq 2) an opt-in `rust_engine` param on
> `deepseek_lab_run` that synthesizes `--node` from selectors + inventory
> (`build_orchestrator_args`, needs an MCP rebuild). Tracked gap-hunt follow-ups
> (non-blocking): `--node` path emits no `run_summary.json` so the run-matrix
> `run_note` is dropped; `traffic_test_matrix` assumes all-pairs mesh
> reachability (may be the correct mesh contract — do NOT weaken without a
> topology-model decision); dead `applies_to_roles`/`fanout` trait methods;
> best-effort parity/manifest writes.
>
> **The role-platform matrix in §3.4 is not yet validated end-to-end for
> any non-Linux Exit deployment.** Windows-as-Exit and macOS-as-Exit
> are now fail-closed in code (`NodeRole::is_supported_for_platform`
> returns false for `(Exit, Windows)` and `(Exit, macOS)`); flipping
> them to ✓ requires live evidence per §4.W5.4 / §4.W5.7. Default
> routing in `vm-lab-orchestrate-live-lab` still goes to the bash
> orchestrator; the Rust orchestrator is opt-in via repeated
> `--node <alias>:<role>` flags. The default flips only after W5.5
> parity evidence (`parity_diff.overall_parity_pass=true`) exists at
> a documented artifact path.
>
> Per-slice commit summaries (kept here for traceability):
> - W5.0 Foundation (`ca84aeb`): NodeAdapter + OrchestrationStage traits, stubs, 26 unit tests. All gates green.
> - W5.1 LinuxNodeAdapter (`8c255c8`): full impl + `--node` flag opt-in. Security invariants: shell_safe_arg, validate_ip_arg, key-exclusion (collect_artifacts). `rn_bootstrap.sh` extracted + embedded via `include_str!()`. `execute_rust_native_orchestration` routes --node traffic to the NodeAdapter pipeline.
> - W5.2 WindowsNodeAdapter (`76df3c4`): full impl. Files: windows_install.rs (PS encoding, install lifecycle, 3 embedded scripts), windows_traffic.rs (WG key, node_id, ping/probe, tunnels, artifacts, key-exclusion zip verify), windows_membership.rs (distribute_signed_bundle staging+atomic-move; issue_membership_owner_key / init_membership_snapshot return UnsupportedPlatform pre-W5.4), windows.rs (full delegation, workdir field, run_validator via WindowsDaemonProbe). Security invariants: ps_quote NUL/CR/LF rejection, validate_ip_arg, key-exclusion (verify_no_key_material_zip), membership-owner gating via UnsupportedPlatform.
> - W5.3 MacosNodeAdapter + macos-*-check subcommands (`f4a0076`): adapter + 6 daemon validator stubs (runtime-acls, mesh-status, key-custody, authenticode, service-hardening, dns-failclosed). MacosDaemonProbe wired through `daemon_probe_for(VmGuestPlatform::Macos)`.
> - W5.4 Windows/macOS-as-Exit (`04cf7fd`): membership-owner key issuance + signed-snapshot init implemented for Windows and macOS adapters. Operationally fail-closed in `81749e4`: `NodeRole::is_supported_for_platform` returns false for `(Exit, Windows)` and `(Exit, macOS)`, and `execute_rust_native_orchestration` enforces this at adapter construction. Flipping requires live evidence.
> - W5.5a 17 stage execute() + PlanBuilder::build() (`c63084b`): every bash-orchestrator stage from §2.1 ported to a `OrchestrationStage` impl; `PlanBuilder` walks role assignments and produces the runner stage list in dependency order. Hardening (`81749e4`) consolidates the live CLI entry point and `PlanBuilder` so a single `build_rust_native_orchestration_stages()` function is the only source of the stage list, includes `FinalCleanupStage`, and is unit-pinned.
> - W5.5b parity harness (`b530e85`): cross-orchestrator diff module + `vm-lab-diff-orchestrator-parity` subcommand; Rust orchestrator now writes `<report-dir>/parity_input.json` at end-of-run. 11 unit tests cover every drift dimension, 2 integration tests cover the executor end-to-end.
> - W5.6 CLI surface (`b530e85`): `--legacy-bash-orchestrator` parser flag, `validate_orchestrate_live_lab_config` mutual-exclusion check, `translate_legacy_role_flags` mapping legacy `--*-vm` flags onto `--node` semantics, `legacy_role_flags_deprecation_warnings` emitted on stderr. 13 unit tests cover translation pin against `--node` equivalents, validator coverage, and warning silence/trigger combinations.
> - W5.1-W5.5 hardening (`81749e4`): `NodeMembershipPeer` value type with `is_valid_public_key_hex` (64 ASCII hex chars), `build_membership_peers(ctx)` reads node IDs from `ctx.node_ids` and pubkeys from `ctx.collected_pubkeys`, and the role-platform matrix in `role.rs` enforces fail-closed for Windows/macOS Exit until W5.4 live evidence lands.
> - Security-evidence hardening (2026-05-29, branch `bughunt/orchestrator-pass2`): a sweep to ensure the orchestrator produces **trustworthy** security evidence — i.e. it must never report a security control as verified when it was not (a fake-pass here would be a false assurance about RustyNet itself). Changes, all fail-closed:
>   - **Validator verdict reads the real field.** Daemon `*-check` commands emit `overall_ok`, never `passed`. The adapters previously parsed `"passed"`, so the verdict was meaningless: the original `!contains("passed": false)` heuristic fake-passed every check (field absent ⇒ "not false"), and an interim fix requiring `"passed": true` made `validate_baseline_runtime` fail on every node (field never present — this is the state on `main` at `ca5127c`). Replaced with `ssh::validator_report_ok` reading `overall_ok` (requires `overall_ok: true`, absent `overall_ok: false`), tolerant of stderr-merged / multi-line / log-prefixed output, fail-closed on anything else. Unit-tested.
>   - **Default-deny negative test no longer fake-passes** (`traffic_test_matrix`): a blocked/errored probe to the TEST-NET-2 sentinel only counts as "default-deny verified" once the node has proven baseline mesh reachability in the same stage; probe errors and a missing adapter are inconclusive and fail closed.
>   - **Thin verification stages now verify** their stated claim: `role_switch_matrix` and `exit_handoff` require at least one active WireGuard tunnel (empty list or an absent enumeration tool fail closed rather than passing on a daemon that merely answered).
>   - **Daemon-restart readiness race closed** (macOS `enforce_daemon` now waits for the control socket before `validate` probes it), **Windows artifact key-exclusion fails closed** on an unreadable zip listing (parity with Linux/macOS tar), **macOS verifier-key install no longer flips the shared `{state}/trust` dir to `0755 root:wheel`**, **membership-snapshot read is guarded** with `test -s` + zero-byte check (no silent empty snapshot), and **Windows `membership add-peer` uses the membership signing passphrase**, not the WireGuard key passphrase (bootstrap stores them separately and fails closed if they collide).
>   - **Cleanup fails closed** when an assigned node has no adapter (was a silent pass that could leave a default-deny killswitch in place), and **single-quote escaping** was added to `node_id`/`network_id`/`ssh_allow_cidrs` interpolated into the Linux/macOS enforce shell args (defence-in-depth).
>   - **Evidence completeness:** `validate_baseline_runtime` now records per-node, per-op results to `<report-dir>/validator_results.json`, and `build_live_lab_run_report` reads them into `node_statuses.validator_results` (previously always empty, which also made the parity validator comparison a vacuous 0-vs-0 match).
>   - **Efficiency (no security trade-off):** SSH `ControlMaster` connection reuse (per-process control dir, mode 0700; `StrictHostKeyChecking=yes` still enforced on master establishment).

## 0) TL;DR

Replace `scripts/e2e/live_linux_lab_orchestrator.sh` (~3000 LOC POSIX-bash, Linux-only) with a Rust-native orchestrator that:

1. Drives **N** nodes through a fixed list of orchestration stages.
2. Per-stage dispatch goes through a single `NodeAdapter` trait.
3. Per-OS knowledge lives **only** in adapter implementations (`LinuxNodeAdapter`, `WindowsNodeAdapter`, `MacosNodeAdapter`, future iOS/Android stubs).
4. Role assignment is OS-agnostic — `--node <alias>:<role>` accepts any combination.
5. Bash + PowerShell scripts that ship today are **kept** as thin per-OS workers the adapters shell out to where shell-out is the cheapest correct answer.

The end-state allows a single command:

```sh
ops vm-lab-orchestrate-live-lab \
  --node debian-headless-1:exit \
  --node windows-utm-1:client \
  --node macos-mini-1:entry \
  --node debian-headless-2:aux \
  --node debian-headless-3:extra
```

…to spin up a heterogeneous mesh and validate it end-to-end. Adding a fourth OS = ship one new adapter impl. Adding a new orchestration stage = ship one new `OrchestrationStage` impl.

## 0.5) Full-Replacement Definition of Done (2026-07-04)

**Mandate (operator, 2026-07-04):** this is a *replacement*, not an alternative
engine. It cannot be called done until the Rust `--node` engine **and its whole
tooling stack** carry EVERY capability the bash orchestrator + tooling carry
today — the autonomous live-lab loop, next-available-stage selection, all MCP
lab-state + DeepSeek functions, agent/overnight configs, the terminal monitor,
and every evidence artifact — all driving the new engine and proven live. Only
then does bash get removed (W5.7).

This DoD is grounded in a 5-surface inventory (workflow `weme66cwa`, 2026-07-04)
of the old orchestrator's complete feature/integration surface mapped to the
Rust engine.

### Already at parity (the recorder-first convergence pays off — DONE/verified)
- **MCP `lab-state`:** 18/19 tools already work on a Rust `--node` run — both
  engines share ONE evidence contract (`stage_manifest.json`, `state/stages.tsv`,
  `parity_input.json`, the fixed-schema `live_lab_run_matrix.csv`) and ONE
  stage-vocabulary owner (`live_lab_stage_registry`) mapping both dialects into
  the same `{os}_stage_*` columns. `start_live_lab_run` **already drives the Rust
  engine today** — passing `nodes` → `--node` selects `execute_rust_native_orchestration`.
- **MCP `deepseek` loop:** an engine-agnostic *client* of the orchestrator CLI;
  the loop / `next_live_lab_target` / reconcile / triage already work against Rust
  runs via the shared evidence contract.
- **Monitor stage grid + per-run counts:** manifest-driven and **render Rust
  `--node` runs correctly today** — the Rust path emits `orchestration/stage_manifest.json`
  and the monitor reads it from the identical path (verified 2026-07-04; an
  inventory agent's "no manifest" claim was false). Regression-guard only.
- **Foundation shipped this session:** functional-parity gate (`a88ce75`),
  cleanup-residue release-blocker fix proven live (`9c1c908`, run
  `livelab-1783193071`), recorder-first observability (`831a32a`).

### Gap buckets — the real remaining replacement work

**BUCKET 1 — Orchestrator stage / mode / flag parity (largest).** The Rust
engine runs ONLY the 21-stage `PlanBuilder`. Missing / bash-routed:
- **Stage families:** the Linux live **security suite** (~13 hard validators:
  two_hop, managed_dns, network_flap, reboot_recovery, secrets_not_in_logs,
  key_custody, enrollment_restart, lan_toggle, mixed_topology, membership-revoke /
  signature-forgery / privileged-helper-allowlist / policy-default-deny /
  gossip-revoked-readmit / enrollment-replay / hello-limiter-flood); the
  **mac/win role-election + validator stages** (~20 macOS, ~25 Windows — these
  ALREADY EXIST as Rust helper stages but are only reachable from the bash-router
  arm; wire them into the Rust plan / `--node` role dispatch); the **chaos** suite
  (9 stages) and **cross-network** suite (~10 families per NAT profile) —
  implement Rust-native OR explicitly scope out of the parity claim with a
  documented blocker.
- **Recovery / readiness gate:** `restart_unready_vms` / `rediscover_local_utm` /
  probe-and-recover + the `--trust-inventory-ready` opt-out. **Code landed
  2026-07-05 for the Rust `--node` path:** it discovers selected aliases,
  restarts probed-unready VMs, rediscover-validates readiness, and honors
  `--trust-inventory-ready` as an explicit skip of the restart gate. Live proof
  is pending lab-free confirmation.
- **Modes:** setup-only / run-only-against-profile / iterate (resume_from/rerun_stage). **Code landed
  2026-07-05 for all three:** `--setup-only` runs through
  `validate_baseline_runtime`, persists
  `state/orchestration_context.json`, and leaves the mesh up on success while
  still running cleanup on failure; `--run-only` reloads that state, reconstructs
  adapters from inventory, injects setup dependencies as `Passed`, and runs the
  live suite against the existing mesh. Iterate remains open.
- **Flags:** `--skip-linux-live-suite`, `--enable-chaos-suite`,
  `--skip-cross-network`, `--collect-artifacts-on-failure`,
  `--skip-diagnose-on-failure`, the platform selectors
  (`--exit/relay/anchor/admin/blind_exit-platform`, `--macos-promote-exit`,
  `--topology-profile`) which currently take effect ONLY in the bash-router arm,
  and honoring `--repo-ref` in the Rust archive stage.

**BUCKET 2 — Evidence parity.** The Rust finalize path writes
`orchestrate_result.json` + `parity_input.json` but NOT `run_summary.json` /
`run_summary.md`, so `validate_live_lab_run_artifacts` and the run-matrix
`run_note` are dropped for Rust runs. Emit them; carry `run_note` through
finalize (stop hardcoding `notes: None`).

**BUCKET 3 — Monitor.** Add a headless `--snapshot`/`--once` mode (grid + counts
+ VM roles to stdout/JSON, no TUI) so Rust-run rendering is verifiable in scripts
and CI. (Grid/counts already render — see above.)

**BUCKET 4 — Loop / next-target dialect-awareness.** `key_for_stage_or_cell`
(deepseek.rs) only maps a cell when the name contains `macos`/`windows`; a Rust
`first_failed_stage` recorded as a raw Linux `StageId` (e.g. `traffic_test_matrix`,
`distribute_traversal`) is a next-target blind spot. Make next-target recognize
Rust-dialect stage IDs; add the `rust_engine` opt-in on `deepseek_lab_run` (and
`start_live_lab_run` role-platform selectors) that synthesizes `--node` from
selectors + inventory.

**BUCKET 5 — MCP lab-state.** `diagnose_live_lab_failure` auto-resolves a
bash-style profile from the matrix row; make it work on a profile-less Rust
`--node` report dir (or document the grep_report/get_stage_log path). Expose the
role-platform / promote-exit / skip-linux-live-suite selectors on
`start_live_lab_run`.

> **DONE.** `diagnose_live_lab_failure` now diagnoses profile-less Rust `--node`
> runs directly from report-dir evidence artifacts (orchestrate_result.json +
> stages.tsv + failure_digest.json), returning a useful failure summary with log
> pointers. Fail-closed on empty/no-evidence dirs. `start_live_lab_run` already
> exposed all Rust-honored selectors (exit/relay/anchor/admin/blind_exit_platform,
> macos_promote_exit, skip_linux_live_suite) as pass-through CLI flags with
> mutually-exclusive validation against `nodes`. 6 tests added.

**BUCKET 6 — Overnight driver.** **Route it to the Rust engine:** the executor
(`verify_cell`, executor.rs:369) invokes `vm-lab-orchestrate-live-lab` with
`--{role}-platform` selectors but **no `--node`**, so it currently routes to
BASH — emit `--node` (synthesized from the cell) so the overnight oracle drives
the Rust engine. Run the live path (`run_loop` + `LiveExecutor`)
end-to-end against the real lab at least once (only `--dry-run`/mocks have run);
give the spawned agent a real `--mcp-config`/`--allowedTools`; enforce
`agent_timeout_secs`; wire run-matrix auto-seeding, the adversarial second-review
agent, and `--auto-merge-safe-cells` (or scope them out). blind_exit cells never
scheduled/merged.

**BUCKET 7 — Parity proof.** `vm-lab-diff-orchestrator-parity --mode functional`
passes (shared logical work + overall status + node count) between a bash run and
the equivalent Rust `--node` run on the same topology, captured as run-matrix
evidence — the redefined W5.6 flip gate.

**BUCKET 8 — Removal (W5.7).** Only after Buckets 1–7 are green and Rust is the
routing default: remove `scripts/e2e/live_linux_lab_orchestrator.sh` and the
mac/win helper functions from the bash-router arm.

### Ordered execution (incremental, prove-as-you-go)
1. Evidence + observability parity (Buckets 2, 3, 4-observability) — cheap, unblocks
   clean monitor/loop verification. 2. Security-suite stages (Bucket 1) — port the
   8 audit checks (RANK-1) + surface the 6 already-computed daemon probes (RANK-0),
   security-first. 3. mac/win role-election stages into the Rust plan (Bucket 1) —
   they exist; wire them. 4. Recovery/readiness gate + modes + flags (Bucket 1).
   5. Loop routing + next-target dialect-awareness + MCP selectors (Buckets 4, 5).
   6. Overnight live path (Bucket 6). 7. Functional-parity proof (Bucket 7).
   8. Chaos/cross-network decision. 9. Removal (Bucket 8). Each stage/bucket is
   proven live and recorded in `live_lab_run_matrix.csv` before the next.

### Progress — 2026-07-05 session (verified)

Grounded in the exhaustive bucket map (workflow `wf_ee06d0be-054`, 2026-07-05),
which is the authoritative file-by-file remaining-work reference for B1/B6/B7/B8.

- **Bucket 1 — security suite: `SecurityAuditValidationStage` LANDED + LIVE-PROVEN.**
  Folds the 8 Tier-0 `rustynetd` daemon self-audits (membership-revoke,
  revoked-peer-denied, membership-signature, privileged-helper-allowlist,
  policy-default-deny, gossip-revoked-readmit, enrollment-replay,
  blind-exit-reversal — the exact set `rustynetd/src/main.rs` dispatches; fail-closed
  on any non-`overall_ok:true`) into the Rust plan as stage 15/22. Proven PASS on
  the 3-node Linux `--node` run **`livelab-1783214166`** (all 8 audits × 3 nodes
  green). Commits `1dde13d`, `a29cc3f`, `05b2a06` (subcommand ground-truth fix),
  `07781bd` (drift-gate + oracle).
- **Bucket 1 — security-audit anti-vacuity depth: LANDED + LIVE-PROVEN** (`051f44a`).
  Resolves the depth-parity follow-up: `validate_linux_security_audits` now
  dispatches each of the 8 audits to the SAME typed evaluator the bash live-suite
  applies (`crate::vm_lab::evaluate_*`, now `pub(crate)`) instead of accepting the
  daemon's `overall_ok:true` alone, so a stripped/vacuous audit (empty corpus,
  reject-all baseline, too-thin battery, or an `overall_ok`/`violations`
  inconsistency) now fails the Rust engine exactly as it fails bash. Live-proven:
  `security_audit_validation` = pass on the 3-node `--node` run
  **`state/rust-rank0-proof-1783249849`** (run-matrix row
  `livelab-1783251676-d2e4968f29f0`; all 8 audits × 3 nodes green under the stricter
  evaluators; live-safe because the audit subcommands take no corpus-size args, so
  the daemon-baked corpus is invocation-independent). The same run re-confirmed the
  always-run cleanup exemption: `cleanup` = pass despite `traffic_test_matrix`
  failing on the known client↔client gap and the downstream stages skip-cascading.
- **Bucket 1 — `--skip-linux-live-suite` now HONORED by `PlanBuilder`** (`19e5e49`):
  drops the 7 post-baseline live stages (security_audit / deploy_relay /
  relay_validation / traffic / role_switch / exit_handoff / active_exit), keeping
  setup → baseline → the always-run cleanup. Previously the Rust plan ignored it
  and the MCP loop's fast inner loop was a no-op.
- **Correctness — Rust-path manifest evidence-integrity fixed** (`19e5e49`):
  `execute_rust_native_orchestration` used to stamp the run manifest with the
  bash-arm suite selectors (`cross_network_suite = !skip_cross_network` → TRUE by
  default, plus chaos / macos_promote_exit / `*_platform`) that `PlanBuilder` never
  runs — a green `--node` run advertised suites that never executed. Now the
  manifest selectors are built from the resolved `--node` topology + only the
  flags the plan honors; every un-honored suite is stamped inactive.
- **Correctness — macOS Exit `active_exit` no longer hard-fails** (`53a837c`): a
  macOS node elected Exit via `--node` hit the trait fail-closed default and turned
  the whole run RED. Now reported-skipped (`active_exit.reported_skips.json`, run
  goes Partial) gated on `active_exit_runtime_implemented` (Linux + Windows). Full
  macOS enforce-time pf blind_exit NAT assertion is the tracked follow-up.
- **Monitor — VM roles now render from the run's own emitted topology** (`d8db72d`):
  the Rust path records `node_assignments` in `stage_manifest.json`; the monitor
  prefers them over the previous finalized run's roles (emit-don't-infer).
- **Extensibility — the 7-place "add a Rust plan stage" checklist** is documented
  at the top of `orchestrator/plan.rs` (`8cbbcdb`).
- **Bucket 7 — engine-agnostic `parity_input.json` converter: LANDED** (`420b900`,
  `1f52a13`). Removes what the plan called the single hard blocker (the bash
  orchestrator never emitted `parity_input.json`):
  `orchestrator::parity::live_lab_run_report_from_report_dir` reconstructs a
  `LiveLabRunReport` from ANY completed run's on-disk evidence, exposed via
  `ops vm-lab-emit-parity-input` + `scripts/e2e/orchestrator_parity_diff.sh`. v2
  (`1f52a13`) reads the authoritative `orchestration/orchestrate_result.json` (the
  full-run record both engines write) rather than `state/stages.tsv` — the bash arm
  records only the SETUP stages there and collapses the live suite into one
  `orchestrate_result` outcome, so a bash run that failed its live suite was reading
  as `pass` from `stages.tsv`/`run_summary.json` (a false-green the converter now
  avoids). Proven on real artifacts. The remaining Bucket-7 item is the live
  bash-vs-Rust functional-parity *run*, not the tooling.
- **Bucket 1 — iterate mode (`--resume-from` / `--rerun-stage`): LANDED** (`78ec843`).
  Both flags accepted by the Rust `--node` path. `resume_from` loads prior context,
  builds the full 24-stage plan, marks all earlier stages as explicit-skips-recorded-
  as-passed, runs remaining. `rerun_stage` marks all-but-target as skips. Either
  requires a prior report dir with valid context + stages.tsv. Mutually exclusive
  with each other and with `--run-only`. Stage names validated against `StageId::ALL`
  via `TryFrom<&str>`. 5 validation tests; 645 orchestrator tests pass.
- **Validation — orchestrator subsystem test audit: VERIFIED** (`ed7e1e1`, 2026-07-05).
  Comprehensive test-audit of 157 orchestrator tests across 10 subsystems: 16 state
  machine (runner 8 + plan 8), 1 context, 14 --node parsing + role assignment, 18
  NodeRole matrix, 22 parity diff, 68 stage implementations, 18 overnight executor.
  156 pass (1 pre-existing source_archive snapshot). Smoke evidence `rust-rank0-proof`
  confirms full 22-stage pipeline with correct skip-cascade + always_run cleanup,
  manifest selectors match stages, parity converter reads orchestrate_result.json.
  Gaps documented (dry-run readiness-gate probes real VMs — pre-existing; overnight
  executor routes to BASH — Bucket 6; no failure_digest.json emission — low severity
   with diagnose fallback).
- **Bucket 1.5 — Admin + BlindExit as first-class `--node` roles: LANDED** (`dbb41c8`,
   2026-07-05). `NodeRole::Admin` + `NodeRole::BlindExit` with full platform gating
   (Admin Linux-only; BlindExit Linux+macOS, Windows blocked-by-design), daemon mapping
   (admin/blind_exit), product capabilities, and parsing. Full 7-place stage plumbing:
   `StageId::AdminIssue` + `StageId::BlindExit` (24 stages), no-op plan stages, oracle
   + registry + MCP tables (deepseek `is_rust_native_stage`, repo-context stage table).
   Overnight `march_role_to_node_role` returns `Some` for both. 662 orchestrator tests
   pass (629 CLI + 33 MCP). Admin/BlindExit removed from B1 still-open list.

**Still open per bucket (map `wf_ee06d0be-054`):** B1 — Windows-relay deploy
adapter, mac/win security-audit + anchor-bundle-pull runtime (all reported-skip →
live, each gated on a live mac/win run before flipping `is_supported_for_platform`);
chaos/cross-network stages. Setup/run modes + the Rust-path recovery
gate are code-landed but
still need coordinated live proof once the shared lab is free.
B6 — code landed locally 2026-07-05 for the overnight driver route/gate:
`verify_cell` synthesizes full `--node <alias>:<role>` assignments from
inventory, keeps `admin`/`blind_exit` out of the Rust path until first-class
roles exist, runs preflight/recover plus `build-release` cargo-cache warm before
the oracle, seeds the per-cell run-matrix scaffold, launches the adversarial
second-review agent with MCP/tool scope, and gates `--auto-merge-safe-cells` on live green + safe review +
non-denylisted diff + non-main target branch. Agent timeout was already enforced
(`041549d`). Still pending: coordinated live `run_loop` + `LiveExecutor` proof
on an isolated branch after the human confirms the shared lab is free.
B7 — the converter + `orchestrator_parity_diff.sh` wrapper are LANDED (`420b900`,
`1f52a13`); the remaining item is a CLEAN coordinated live bash-vs-Rust run pair on
a matching topology → `overall_functional_parity_pass`. Two run-time cautions found
2026-07-05: the bash orchestrate path's live-suite (`vm_lab_run_live_lab`)
provenance-checks the WORKING-TREE orchestrator source even under
`--source-mode local-head` (do NOT edit orchestrator source during a bash run), and
a bash run auto-expands `--exit-vm/--client-vm/--entry-vm` to a 5-node topology
(match the Rust `--node` side's node count). Then the router flip. B8 — gated on
1–7; `run_{windows,linux}_orchestration_stages`
+ `run_validate_{windows,linux}_security` are SHARED (not removable), and deleting
the `.sh` breaks `cargo test` compilation via `macos_install.rs` `include_str!`.
**Known blockers:** client↔client traffic (`traffic_test_matrix`) fails in an
all-clients topology — needs a product call (hub-spoke by design vs a real
peering bug) + daemon-level investigation; Windows Exit needs a WinNAT/HNS-capable
guest (current lab guest lacks `MSFT_NetNat`).

### Full bash→Rust stage migration tracker (2026-07-05)

**Operator mandate (2026-07-05):** *everything the bash orchestrator offers must be
runnable in the Rust engine — every stage, on Linux AND macOS AND Windows — but
improved (the Rust engine has more control + information). Deferral is fine;
nothing is permanently scoped out. Everything migrates eventually.*

Grounded in the `live_lab_stage_registry` catalog (167 stage names) vs. the 22-stage
Rust `--node` plan. The migration is **not** "145 stages to add" — the Rust engine
consolidates by design (one role×adapter stage covers many discrete bash cells). It
decomposes into three kinds of work:

1. **Already consolidated (done).** The bash setup/bootstrap/membership/distribute/
   baseline dialects (`membership_setup`, `bootstrap_macos_host`,
   `distribute_*_bundles`, …) collapse into the 22 role×adapter stages. ~38 core +
   the mac/win *setup* cells are covered here.
2. **Adapter promotion (code partly there; live-proof deferred).** mac/win role
   behaviors (exit / relay / anchor / security-audit) run *inside* the existing 22
   stages via the per-OS `NodeAdapter`; they are reported-skip on mac/win today and
   flip to live only after a live mac/win run proves each (§ promotion-follows-
   evidence). ~70 mac/win cells map here — no new `StageId`s, just adapter runtime +
   the reported-skip→live flip.
3. **Genuinely new Rust stages (the real remaining port, ~50).** Behaviors the 22 do
   not cover:
   - **chaos ×9** (`chaos_daemon_fault`, `_sigstop_sigcont`, `_clock_attack`,
     `_signed_state_adversarial`, `_crash_recovery`, `_resource_exhaustion`,
     `_network_impairment`, `_membership_adversarial`, `_privileged_boundary`) —
     opt-in (`--enable-chaos-suite`), self-contained.
   - **cross-network ~14** (`cross_network_nat_classification`/`_matrix`/
     `_controller_switch`/`_direct_remote_exit`/`_failback_roaming`, +
     `validate_{linux,macos,windows}_exit_nat_lifecycle`).
   - **rich Linux validators ~28** not consolidated (`live_two_hop`,
     `live_managed_dns`, `validate_linux_ipv6_leak`, `_dns_failclosed`,
     `_network_flap`, `_reboot_recovery`, `_lan_toggle`, `_mixed_topology`,
     `_exit_demotion_residue`, `_blind_exit_dataplane`, `_secrets_not_in_logs`,
     `_enrollment_restart`, the daemon validators, …). Most already have the logic
     as bash-arm Rust functions (`run_validate_linux_*`), so each port is
     "wrap the existing evaluator in an `OrchestrationStage` + the 7-place
     checklist" — the `SecurityAuditValidationStage` pattern.

**Suggested port order (deferral OK):** rich Linux validators (reuse existing
evaluators, cheapest) → chaos ×9 (self-contained, opt-in) → cross-network (needs the
substrate) → mac/win adapter promotion (needs coordinated live proof). Live proof of
each new/promoted cell **follows** the code (reported-skip until a live run proves it
+ a run-matrix row exists; strictest-secure default).

**Coordination rule — stage-adding is SERIALIZED.** Adding a `StageId` touches the
count/drift gates (`build_returns_N`, `rust_native_cli_stage_ids_match_plan_builder`,
the registry extensibility gate, `oracle_is_rust_native`, repo-context
`ORCHESTRATOR_STAGES`). Two agents adding stages at once collide on those asserts.
Assign disjoint *batches* and land them one at a time; always run the FULL
`cargo test --workspace` before claiming a stage batch landed.

## 1) Motivation

### 1.1 Problem statement

The bash orchestrator is the production live-lab path for Linux nodes. It is:

- ~3000 LOC of POSIX bash (plus ~3000 LOC of `live_lab_common.sh` shared helpers).
- Hard-codes `apt`, `systemctl`, `/var/lib/rustynet`, POSIX `chmod` / `chown`, `dpkg`, kernel WireGuard.
- Hard-codes 5 specific role names (exit / client / entry / aux / extra) and the SSH-into-`debian@<ip>` pattern.

Pointing it at a Windows node fails at the first `sudo apt`. Pointing it at macOS fails at `systemctl`. The "Linux required" rows in the current `--exit-vm` / `--client-vm` / etc. flag table are the bash script's POSIX assumptions, not anything intrinsic to the role.

W1-W4 has been quietly building the OS-agnostic *contract*:

- Per-OS verifier modules (`linux_*.rs`, `windows_*.rs`) — same JSON schema across platforms.
- Adapter traits (`RuntimePaths`, `ServiceManager`, `RemoteExec`, `DaemonProbe`) with Linux + Windows + macOS-stub impls behind a `for_(platform)` factory.
- Per-OS install helpers (Linux bash bootstrap, Windows `Bootstrap-RustyNetWindows.ps1` + `Install-RustyNetWindowsService.ps1`).
- OS-agnostic distribute pipeline (W4.x followups: pull-from-Linux-exit + push-to-Windows).

What W1-W4 **deliberately did not touch**: replacing the bash orchestrator's install / membership / traffic-test logic with Rust calls through those traits. That is W5.

### 1.2 Why now (operator goals captured 2026-04-28)

Quote: "I want any os role assignment […] These orchestrators and tests will be run 1000s of times. I want to do it right now, no half/quick jobs."

Quote: "In the wild rustynet will be deployed on multiple devices with varying OS. I want to make sure they interact correctly."

The operator goal is bug-discovery velocity. Multi-platform role assignment is the harness that makes cross-OS interop bugs surface in CI rather than in production. Quick-win shortcuts (e.g., `--auto-distribute-from-linux-exit` flag on the existing orchestrator) deliver one-shot evidence but do not give the operator a sustainable test surface for adding the next OS.

### 1.3 Non-goals

- **Not** rewriting bash + PowerShell scripts that already exist + work. Adapters shell out to those scripts where shell-out is the cheapest correct answer.
- **Not** changing the daemon's wire format, signed-bundle schemas, or membership-owner cryptography. The orchestrator only changes how nodes get installed / configured / verified, not what they verify.
- **Not** removing existing CLI subcommands that operators depend on. Old subcommands keep working in parallel during the transition.
- **Not** rewriting the daemon validators (W3.2-followup-1..6 stays as-is). The new orchestrator dispatches to them via the existing `DaemonProbe` trait.

## 2) Current state (what exists today)

### 2.1 Bash orchestrator stages (the thing being replaced)

`scripts/e2e/live_linux_lab_orchestrator.sh` runs these stages, in order, on Linux peers only:

| Stage | What it does |
|---|---|
| `preflight` | Local prerequisites (cargo, ssh, etc.) |
| `prepare_source_archive` | Tar the working tree → `state/rustynet-source.tar.gz` |
| `verify_ssh_reachability` | Confirm SSH works to each role-assigned node |
| `prime_remote_access` | Bootstrap sudo + authorized_keys on each node |
| `cleanup_hosts` | Wipe prior daemon state on each node |
| `bootstrap_hosts` | scp source → cargo build --release → install daemon → systemd unit |
| `collect_pubkeys` | SSH each peer + read its WireGuard public key |
| `membership_setup` | Exit signs initial membership snapshot |
| `distribute_membership_state` | scp membership snapshot to every non-exit peer |
| `issue_and_distribute_assignments` | Exit signs assignments, distributes to peers |
| `issue_and_distribute_traversal` | Exit signs traversal hints, distributes |
| `issue_and_distribute_dns_zone` | Exit signs DNS zone, distributes |
| `enforce_baseline_runtime` | systemctl start rustynetd on each peer |
| `validate_baseline_runtime` | Each peer's daemon ingests state, reports peer count |
| `live_role_switch_matrix` | Validate runtime role transitions |
| `live_exit_handoff` | Validate exit-node handoff |
| (cleanup) | Optional teardown |

Each stage emits a per-stage log file under `<report-dir>/logs/`. The final `failure_digest.md` aggregates per-stage status. Exit code 0 = all passed.

### 2.2 Rust orchestrator surface today

`crates/rustynet-cli/src/vm_lab/mod.rs` (~26k lines) hosts:

- `execute_ops_vm_lab_orchestrate_live_lab` — top-level entry. Calls bash orchestrator for Linux nodes, then optionally:
  - `run_windows_orchestration_stages_with_options` — Windows post-validate (8 stages).
  - `run_linux_daemon_validators_for_aliases` — Linux validators against every selected Linux alias.
- W3.x adapter traits: `RuntimePaths`, `ServiceManager`, `RemoteExec`, `DaemonProbe` + per-OS impls + `for_(platform)` factories.
- `LinuxBashOrchestrator` — wraps the bash script invocation.
- `RustOrchestrator` — selects between strategies (today: Linux-bash-only or Windows-rust-only; reject heterogeneous mid-run).
- `StageOrchestrator` trait — single-method `execute_live_lab(inputs) -> LiveLabRunReport`.

### 2.3 Per-OS install helpers

| OS | Helper | What it does |
|---|---|---|
| Linux | `scripts/e2e/live_linux_lab_orchestrator.sh` (bootstrap_hosts stage) | apt + git + cargo + systemd unit install |
| Linux | `scripts/systemd/rustynetd.service` | reviewed unit file |
| Windows | `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1` | winget install (WireGuard, Rust, Git, VS Build Tools) + git clone |
| Windows | `scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1` | cargo build → copy to install root → New-Service → ACLs → start |
| Windows | `scripts/bootstrap/windows/Uninstall-RustyNetWindowsService.ps1` | symmetric uninstall |
| Windows | `scripts/bootstrap/windows/Verify-RustyNetWindowsBootstrap.ps1` | post-install verification |
| Windows | `scripts/bootstrap/windows/Smoke-RustyNetWindowsServiceHost.ps1` | smoke test |
| Windows | `scripts/bootstrap/windows/Collect-RustyNetWindowsDiagnostics.ps1` | diag bundle |
| macOS | (none yet) | — |

### 2.4 Daemon-side validators (already cross-platform via W3.2-followup-1..6)

| Op | Linux subcommand | Windows subcommand |
|---|---|---|
| `RuntimeAcls` | `linux-runtime-acls-check` | `windows-runtime-acls-check` |
| `MeshStatus` | `linux-mesh-status-check` | `windows-mesh-status-check` |
| `KeyCustody` | `linux-key-custody-check` | `windows-key-custody-check` |
| `Authenticode` | `linux-authenticode-check` (N/A stub, returns `applicable: false`) | `windows-authenticode-check` |
| `ServiceHardening` | `linux-service-hardening-check` | `windows-service-hardening-check` |
| `DnsFailclosed` | `linux-dns-failclosed-check` | `windows-dns-failclosed-check` |

`LinuxDaemonProbe::build_argv` and `WindowsDaemonProbe::build_argv` already produce per-op argv. **W5 reuses these as-is** through `NodeAdapter::run_validator`.

## 3) Target architecture

### 3.1 Two new traits

**`NodeConnection`** — transport injected at adapter construction time. `NodeAdapter` methods carry no connection argument; the transport is baked in by the factory. This is the key design decision that enables true OS-agnosticism: iOS (MDM), Android (ADB), and any future platform can implement the same trait surface without receiving an SSH struct they cannot use.

```rust
/// Transport injected at adapter construction by `node_adapter_for`.
/// NodeAdapter methods take no connection argument — connection details
/// live here, not on every call site.
pub enum NodeConnection {
    /// SSH to a POSIX or PowerShell-capable host (Linux, Windows, macOS).
    Ssh {
        host: String,
        port: u16,
        user: Option<String>,
        identity_file: PathBuf,
        /// Required. `StrictHostKeyChecking=yes` enforced at SSH layer.
        /// Absent file or key mismatch = hard fail at construction, not a warning.
        known_hosts: PathBuf,
    },
    /// Android Debug Bridge (future AndroidNodeAdapter — lab-only).
    Adb { device_serial: String },
    /// Apple MDM / Network Extension management channel (future IosNodeAdapter).
    Mdm { enrollment_id: String },
}
```

**`NodeAdapter`** — captures everything that's per-node + per-OS for the orchestration path. One impl per OS. Connection details live in `NodeConnection`, injected at construction; no `RemoteTarget` threading through every call.

```rust
pub trait NodeAdapter: Send + Sync {
    fn platform(&self) -> VmGuestPlatform;

    // ── Install lifecycle ─────────────────────────────────────────
    fn install_daemon(
        &self,
        source: &SourceArchive,
        ctx: &OrchestrationContext,
    ) -> Result<InstallReport, AdapterError>;

    fn start_daemon(&self) -> Result<(), AdapterError>;
    fn stop_daemon(&self) -> Result<(), AdapterError>;
    fn restart_daemon(&self) -> Result<(), AdapterError>;
    fn uninstall_daemon(&self) -> Result<(), AdapterError>;

    // ── Membership owner (exit role only) ─────────────────────────
    fn issue_membership_owner_key(
        &self,
    ) -> Result<MembershipOwnerKey, AdapterError>;

    fn init_membership_snapshot(
        &self,
        owner_key: &MembershipOwnerKey,
        peers: &[NodeRoleAssignment],
    ) -> Result<MembershipSnapshot, AdapterError>;

    // ── Per-node identity + key collection ────────────────────────
    fn collect_wireguard_public_key(
        &self,
    ) -> Result<WireguardPublicKey, AdapterError>;

    fn collect_node_id(&self) -> Result<NodeId, AdapterError>;

    // ── Bundle distribution (any non-exit role) ───────────────────
    fn distribute_signed_bundle(
        &self,
        kind: BundleKind,
        bundle_path: &Path,
    ) -> Result<(), AdapterError>;

    // ── Validators (delegates to existing W3.x DaemonProbe) ───────
    fn run_validator(
        &self,
        op: DaemonProbeOp,
    ) -> Result<ValidatorReport, AdapterError>;

    // ── Traffic test ──────────────────────────────────────────────
    /// Positive connectivity: confirm this node reaches peer_mesh_ip via tunnel.
    fn ping_mesh_peer(
        &self,
        peer_mesh_ip: &str,
    ) -> Result<TrafficTestResult, AdapterError>;

    /// Negative ACL test: confirm default-deny blocks traffic to a non-mesh IP.
    /// Must return `TrafficTestResult::Blocked` for the stage to pass.
    /// A `Reachable` result is a security failure and fails the stage.
    fn probe_denied_peer(
        &self,
        denied_ip: &str,
    ) -> Result<TrafficTestResult, AdapterError>;

    fn collect_active_tunnels(
        &self,
    ) -> Result<TunnelsList, AdapterError>;

    // ── Diagnostics + cleanup ─────────────────────────────────────
    /// Collect diagnostic artifacts to dst.
    /// Key material MUST be excluded: `*/keys/*`, `*.priv`, `*.pem` paths
    /// must never appear in the archive. Implementations must test this invariant.
    fn collect_artifacts(
        &self,
        dst: &Path,
    ) -> Result<(), AdapterError>;

    fn cleanup_runtime_state(&self) -> Result<(), AdapterError>;
}
```

The factory signature reflects the connection-injection pattern:

```rust
/// Build an adapter for `platform` using `conn` as its transport.
/// Returns `Err(AdapterError::UnsupportedPlatform { .. })` for platforms
/// not yet implemented (iOS, Android). The error message names the specific
/// security barriers that block the platform (see §11).
/// Returns `Err(AdapterError::ConnectionPlatformMismatch { .. })` if the
/// connection type is not valid for the platform (e.g. Adb for Linux).
pub fn node_adapter_for(
    platform: VmGuestPlatform,
    conn: NodeConnection,
) -> Result<Box<dyn NodeAdapter>, AdapterError>;
```

**`OrchestrationStage`** — captures the orchestrator's behavior. One impl per stage.

```rust
pub trait OrchestrationStage: Send + Sync {
    fn id(&self) -> StageId;
    fn name(&self) -> &str;

    /// Stages that must pass before this one runs (skip-cascade).
    fn dependencies(&self) -> &[StageId];

    /// Which roles this stage operates on. Empty = "all roles".
    fn applies_to_roles(&self) -> &[NodeRole];

    /// Some stages run once (eg membership-init on exit only); others
    /// fan out per role-matched node.
    fn fanout(&self) -> StageFanout;

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome;
}
```

### 3.2 OS-agnostic role definitions

```rust
pub enum NodeRole {
    Exit,        // membership owner; signs all bundles
    Client,      // primary client peer
    Entry,       // entry/relay peer
    Aux,         // auxiliary peer
    Extra,       // 5th node (fifth-client)
    // Future-proofing for non-5-node topologies:
    Custom(String),
}
```

The 5 named roles match the bash orchestrator's existing role names so the membership / traffic-test / role-switch logic stays semantically identical. `Custom("…")` allows future N-node topologies.

### 3.3 New module structure

```
crates/rustynet-cli/src/vm_lab/
├── mod.rs                                 (existing — gradually shrinks as logic moves out)
├── orchestrator/                          (NEW module)
│   ├── mod.rs                             (re-exports)
│   ├── error.rs                           (AdapterError, StageError)
│   ├── role.rs                            (NodeRole enum + role-platform matrix)
│   ├── role_assignment.rs                 (NodeRoleAssignment + parser for `<alias>:<role>`)
│   ├── source_archive.rs                  (SourceArchive: tar of working tree, scp helpers)
│   ├── adapter/
│   │   ├── mod.rs                         (trait def + re-exports)
│   │   ├── node_adapter.rs                (the NodeAdapter trait)
│   │   ├── linux.rs                       (LinuxNodeAdapter)
│   │   ├── windows.rs                     (WindowsNodeAdapter)
│   │   ├── macos.rs                       (MacosNodeAdapter)
│   │   ├── ios.rs                         (IosNodeAdapter — UnsupportedOp stub)
│   │   ├── android.rs                     (AndroidNodeAdapter — UnsupportedOp stub)
│   │   └── factory.rs                     (node_adapter_for(VmGuestPlatform) -> Box<dyn NodeAdapter>)
│   ├── stage/
│   │   ├── mod.rs                         (trait def + StageId enum)
│   │   ├── preflight.rs
│   │   ├── source_archive.rs              (PrepareSourceArchiveStage)
│   │   ├── verify_ssh.rs
│   │   ├── cleanup.rs
│   │   ├── install.rs                     (BootstrapHostsStage — calls adapter.install_daemon)
│   │   ├── collect_pubkeys.rs
│   │   ├── membership_init.rs             (Exit role only)
│   │   ├── distribute_membership.rs       (all non-exit)
│   │   ├── distribute_assignments.rs
│   │   ├── distribute_traversal.rs
│   │   ├── distribute_dns_zone.rs
│   │   ├── enforce_runtime.rs             (start daemon)
│   │   ├── validate_runtime.rs            (run all 6 daemon validators)
│   │   ├── traffic_test_matrix.rs         (N×N peer-to-peer connectivity)
│   │   ├── role_switch_matrix.rs
│   │   └── exit_handoff.rs
│   ├── plan.rs                            (PlanBuilder: walks role assignments + builds stage list + dependency graph)
│   ├── runner.rs                          (StateMachineRunner: drives stages in dep order, handles skip-cascade)
│   ├── context.rs                         (OrchestrationContext: holds NodeRoleAssignments, source archive path,
│   │                                       per-node adapter handles, collected pubkeys / signed bundles, report state)
│   └── report.rs                          (typed JSON output schema + writer)
└── (existing modules unchanged)
```

The bash orchestrator script stays in place. It is invoked by the legacy code path **only** (new code path never calls it). Phase W5.7 deletes the legacy code path + bash script together.

### 3.4 Role-platform matrix (target end state)

|  | Linux | Windows | macOS | iOS | Android |
|---|---|---|---|---|---|
| `Exit` | ✓ | ✓ (after W5.4) | ✓ (after W5.4) | ✗ | ✗ |
| `Client` | ✓ | ✓ | ✓ | ✗ | ✗ |
| `Entry` | ✓ | ✓ | ✓ | ✗ | ✗ |
| `Aux` | ✓ | ✓ | ✓ | ✗ | ✗ |
| `Extra` | ✓ | ✓ | ✓ | ✗ | ✗ |

iOS / Android adapters ship as `UnsupportedOp` stubs that fail closed with **security-specific rejection messages**. The message must name the concrete security barriers — not just "not yet implemented." Required text elements: (1) no daemon validator coverage (service hardening, key custody, DNS fail-closed not implemented for the platform); (2) no reviewed key custody model (Secure Enclave / Android Keystore integration undesigned); (3) connection model (MDM/ADB) not reviewed against security minimum bar. A test asserts each stub's error string contains "security minimum bar". See §11 for what a future W6 track would need.

### 3.5 CLI surface (target end state)

The new CLI shape:

```sh
ops vm-lab-orchestrate-live-lab \
  --inventory <path> \
  --report-dir <path> \
  --ssh-identity-file <path> \
  --known-hosts-file <path> \           # required; StrictHostKeyChecking=yes enforced
  --node <alias>:<role> [--node <alias>:<role>]... \
  [--source-mode working-tree|local-head|origin-main|ref] \
  [--require-min-nodes <n>] \
  [--skip-stage <stage-id>] [--skip-stage <stage-id>]... \
  [--rerun-stage <stage-id>] [--rerun-stage <stage-id>]... \
  [--legacy-bash-orchestrator]   # transitional, deprecated by W5.7
```

`--known-hosts-file` is **required** (not optional). The SSH layer enforces `StrictHostKeyChecking=yes` against the provided file. Absent file, absent host entry, or key mismatch = hard fail at connection construction; the orchestrator does not continue with an unverified host. This applies to every SSH session including the initial bootstrap — a MITM at `install_daemon` time could substitute a malicious daemon binary.

The 6 named flags (`--exit-vm`, `--client-vm`, `--entry-vm`, `--aux-vm`, `--extra-vm`, `--windows-vm`) keep working as deprecation aliases for the duration of W5; they translate internally into `--node <alias>:<role>` pairs. W5.7 removes them.

## 4) Phase plan

Each W5.x slice is a self-contained mergeable commit with passing gates + live evidence where it touches behavior. No half-finished commits. If a session has to pause mid-slice, the codebase remains shippable.

### W5.0 — Foundation (1 session)

**Deliverable:** `NodeAdapter` + `OrchestrationStage` traits exist, compile, are unit-tested with a stub adapter + stub stage. No behavior change to the existing orchestrator.

**Files added:**
- `crates/rustynet-cli/src/vm_lab/orchestrator/mod.rs`
- `crates/rustynet-cli/src/vm_lab/orchestrator/error.rs` (`AdapterError` incl. `UnsupportedPlatform` + `ConnectionPlatformMismatch` variants, `StageError`, `StageOutcome`)
- `crates/rustynet-cli/src/vm_lab/orchestrator/role.rs` (`NodeRole`)
- `crates/rustynet-cli/src/vm_lab/orchestrator/role_assignment.rs` (`NodeRoleAssignment` + `parse_node_role_arg(&str) -> Result<…>`)
- `crates/rustynet-cli/src/vm_lab/orchestrator/source_archive.rs` (`SourceArchive` type)
- `crates/rustynet-cli/src/vm_lab/orchestrator/connection.rs` (`NodeConnection` enum — `Ssh`, `Adb`, `Mdm` variants; `Ssh` validates `known_hosts` path at construction)
- `crates/rustynet-cli/src/vm_lab/orchestrator/context.rs` (`OrchestrationContext`)
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/mod.rs`
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/node_adapter.rs` (trait def — no `RemoteTarget` in method signatures)
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/factory.rs` (`node_adapter_for(VmGuestPlatform, NodeConnection) -> Result<Box<dyn NodeAdapter>, AdapterError>`)
- `crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs` (the trait def + `StageId` enum)
- `crates/rustynet-cli/src/vm_lab/orchestrator/plan.rs` (`PlanBuilder` — empty for now)
- `crates/rustynet-cli/src/vm_lab/orchestrator/runner.rs` (`StateMachineRunner` skeleton)
- `crates/rustynet-cli/src/vm_lab/orchestrator/report.rs` (typed JSON schema)

**Files modified:**
- `crates/rustynet-cli/src/vm_lab/mod.rs` — add `mod orchestrator;` declaration. No other changes.

**Tests:**
- `parse_node_role_arg` accepts `alias:exit` / `alias:client` / `alias:entry` / `alias:aux` / `alias:extra` / `alias:custom-foo`.
- `parse_node_role_arg` rejects empty, malformed, unknown roles (including typos like `exti`).
- `NodeRole::is_unique_per_lab()` returns true for `Exit`, false for others (exactly one Exit per lab).
- `node_adapter_for` returns the right concrete type for Linux/Windows/macOS (using stub impls).
- `node_adapter_for(VmGuestPlatform::Ios, _)` and `node_adapter_for(VmGuestPlatform::Android, _)` return `Err(AdapterError::UnsupportedPlatform)` whose message contains "security minimum bar".
- `node_adapter_for` returns `Err(AdapterError::ConnectionPlatformMismatch)` for mismatched pairs (e.g. `Adb` + Linux, `Ssh` + iOS).
- `NodeConnection::Ssh` construction returns `Err` if `known_hosts` path does not exist (validated at construction, not at first use).
- `StateMachineRunner` honors skip-cascade for a stub 3-stage plan with one failing stage.
- `StateMachineRunner` executes stages in dependency order (not insertion order) for a 3-stage plan where C depends on A but not B.

**Acceptance criteria:**
- `cargo fmt --all -- --check` clean.
- `cargo clippy --workspace --all-features -- -D warnings` clean.
- `cargo test --workspace --all-features` clean (~15-20 new tests).
- No behavior change to `vm-lab-orchestrate-live-lab` or any existing subcommand.
- New module compiles + is reachable via `pub mod orchestrator;` from `vm_lab/mod.rs`.
- iOS + Android `UnsupportedPlatform` error strings verified by test to contain "security minimum bar".
- `NodeConnection::Ssh` path-validation test passes.

**Estimated LOC:** 800-1200 (most is type definitions + trait scaffolding + tests).

### W5.1 — `LinuxNodeAdapter` (3-4 sessions)

**Deliverable:** Full `NodeAdapter` impl for Linux that's behaviorally equivalent to the bash orchestrator's per-node operations. Shells out to existing bash where shell-out is the cheapest correct answer.

**Files added:**
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/linux.rs` (~400-600 LOC)
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/linux_install.rs` (factored install logic, ~200-300 LOC)
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/linux_membership.rs` (membership-init + bundle distribution, ~200-300 LOC)
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/linux_traffic.rs` (ping + tunnels query, ~150-200 LOC)
- `tests/orchestrator_linux_adapter_smoke.rs` (integration test, gated on `RUSTYNET_LIVE_LINUX_LAB=1` env)

**Files modified:**
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/factory.rs` — wire `LinuxNodeAdapter`.

**Per-method strategy:**
| Method | Strategy |
|---|---|
| `install_daemon` | scp `SourceArchive`, run `cargo build --release` over SSH, `install` daemon binary + systemd unit. Currently a bash-helper invocation; can be re-implemented in Rust over SSH later without changing the trait surface. |
| `start_daemon` / `stop_daemon` / `restart_daemon` | `systemctl <action> rustynetd` over SSH. |
| `issue_membership_owner_key` | `rustynet membership init …` over SSH on the target (Rust CLI runs on Linux). |
| `init_membership_snapshot` | `rustynet membership init` flow with peers. |
| `collect_wireguard_public_key` | `cat /var/lib/rustynet/keys/wireguard.pub` over SSH. |
| `collect_node_id` | `rustynet status` over SSH + parse JSON. |
| `distribute_signed_bundle` | scp + atomic install (mirroring W4.x distribute pattern). |
| `run_validator` | `rustynetd linux-<op>-check` over SSH (delegates to `LinuxDaemonProbe::build_argv`). |
| `ping_mesh_peer` | `ping -c 3 <peer-mesh-ip>` over SSH + parse output. |
| `collect_active_tunnels` | `wg show <iface>` over SSH + parse. |
| `collect_artifacts` | `tar -czf - /var/lib/rustynet/ /var/log/rustynet/ <log paths> --exclude='*/keys/*' --exclude='*.priv' --exclude='*.pem'` piped to local file. Key material must never appear in collected artifacts; see §3.1 `NodeAdapter` contract. |
| `cleanup_runtime_state` | `systemctl stop rustynetd && rm -rf /var/lib/rustynet/*` (preserves keys directory shape). |

**CLI surface (opt-in, added in W5.1):** `--node <alias>:<role>` and `--known-hosts-file <path>` are wired to the CLI parser in W5.1 as opt-in flags alongside the existing `--exit-vm / --client-vm / …` flags. W5.2–W5.5 are developed and tested using `--node`. W5.6 promotes `--node` to the default and removes the old flags.

**Files modified (W5.1, in addition to adapter files):**
- `crates/rustynet-cli/src/main.rs` — add `--node`, `--known-hosts-file` flags as opt-in.
- `crates/rustynet-cli/src/vm_lab/mod.rs` — route to new adapter code path when `--node` is present.

**Tests:**
- Unit tests for argv-building helpers (e.g., `build_systemctl_action_invocation("start", "rustynetd")`).
- Integration test (gated env) that drives `LinuxNodeAdapter` against one live Debian VM and confirms each method works.
- Snapshot test: byte-for-byte parity check of `LinuxNodeAdapter::install_daemon` vs bash orchestrator's `bootstrap_hosts` stage. Both produce a daemon at `/usr/local/bin/rustynetd` with the same systemd unit.
- Key-exclusion invariant: `collect_artifacts` output archive must not contain any path containing `keys/`, `.priv`, or `.pem`. Test creates a mock remote tree with a fake `wireguard.priv` file and asserts its absence in the tarball.

**Acceptance criteria:**
- All gates pass.
- `--node` opt-in flag works end-to-end against a Debian VM using `LinuxNodeAdapter`.
- Live evidence: drive the new adapter against one Debian VM, install daemon, run validators, distribute a fake bundle. Capture as `documents/operations/active/W5_LinuxAdapter_LiveEvidence_2026-XX-XX.md`.
- Bash orchestrator unchanged — operators continue to use it through `--legacy-bash-orchestrator` (default for W5.1-5.4).

**Estimated LOC:** 1500-2000 + tests.

### W5.2 — `WindowsNodeAdapter` (3-4 sessions)

**Deliverable:** Full `NodeAdapter` impl for Windows that shells out to the existing PowerShell scripts (`Bootstrap-RustyNetWindows.ps1`, `Install-RustyNetWindowsService.ps1`, etc.).

**Files added:**
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows.rs` (~400-600 LOC)
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_install.rs` (factored install logic, ~200-300 LOC)
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_membership.rs` (membership-init blocked until W5.4; placeholder return UnsupportedOp)
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_traffic.rs`
- `tests/orchestrator_windows_adapter_smoke.rs` (gated on `RUSTYNET_LIVE_WINDOWS_LAB=1`)

**Files modified:**
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/factory.rs` — wire `WindowsNodeAdapter`.

**Per-method strategy:** mirrors W5.1 but using PowerShell-encoded SSH dispatch + the existing PS bootstrap scripts.

**Per-method:**
| Method | Strategy |
|---|---|
| `install_daemon` | scp source, run `Bootstrap-RustyNetWindows.ps1` (winget + git clone) + `Install-RustyNetWindowsService.ps1` over SSH. |
| `start_daemon` etc. | `Get-Service RustyNet \| Start-Service` etc. over SSH. |
| `issue_membership_owner_key` | **Returns UnsupportedOp** until W5.4 (Windows-as-exit). |
| `init_membership_snapshot` | UnsupportedOp until W5.4. |
| `collect_wireguard_public_key` | `Get-Content "C:\ProgramData\RustyNet\keys\wireguard.pub"` over PS-encoded SSH. |
| `collect_node_id` | Read from daemon state. |
| `distribute_signed_bundle` | Reuses W4.2-followup-2 `run_distribute_windows_bundle_stage` logic. |
| `run_validator` | `rustynetd windows-<op>-check` (delegates to `WindowsDaemonProbe::build_argv`). |
| `ping_mesh_peer` | `Test-Connection <peer-mesh-ip> -Count 3` over PS-encoded SSH. |
| `collect_active_tunnels` | `wg show <iface>` via wireguard.exe over PS-encoded SSH. |
| `collect_artifacts` | scp `C:\ProgramData\RustyNet\logs\` to local, explicitly excluding `C:\ProgramData\RustyNet\keys\*`. Key material must never appear in collected artifacts. |
| `cleanup_runtime_state` | `Uninstall-RustyNetWindowsService.ps1 -PurgeStateRoot` (existing helper). |

**Tests:** parallel structure to W5.1.

**Acceptance criteria:**
- All gates pass.
- Live evidence: drive against `windows-utm-1`. Install + 6 validators + ping a Linux mesh IP all PASS.
- Bash orchestrator + W4.x validate-windows-security path remain unchanged.

**Estimated LOC:** 1500-2000.

### W5.3 — `MacosNodeAdapter` (3-4 sessions)

**Deliverable:** Full `NodeAdapter` impl for macOS. Uses Homebrew + `launchd` as the per-OS analogues of apt + systemd / winget + SCM.

**Current 2026-04-29 hardening state:** compile/unit-ready. `MacosNodeAdapter` delegates install/start/stop/restart/uninstall to `macos_install`, membership/bundles to `macos_membership`, traffic/artifacts/cleanup to `macos_traffic`, and validators through `MacosDaemonProbe`. Reviewed bootstrap + launchd assets exist. Live evidence is deferred because the active inventory has no macOS VM.

**Files added:**
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos.rs`
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs`
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_membership.rs`
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_traffic.rs`
- **NEW** `scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh` (parallel to Linux `live_linux_lab_orchestrator.sh`'s install-stage logic)
- **NEW** `scripts/bootstrap/macos/Install-RustyNetMacosService.sh` (launchd plist + chown/chmod + start)
- **NEW** `scripts/launchd/com.rustynet.daemon.plist` (reviewed launchd unit)
- **NEW** `crates/rustynetd/src/macos_*.rs` (per-OS validators mirroring `linux_*.rs` + `windows_*.rs`):
  - `macos_runtime_acls.rs`
  - `macos_service_hardening.rs`
  - `macos_key_custody.rs`
  - `macos_authenticode.rs` (likely N/A stub like Linux)
  - `macos_dns_failclosed.rs`
  - `macos_mesh_status.rs`
- `crates/rustynetd/src/main.rs` — 6 new `macos-*-check` subcommands.
- `crates/rustynet-cli/src/vm_lab/mod.rs` — `MacosDaemonProbe` impl + `daemon_probe_for(VmGuestPlatform::Macos)` factory updated.

**Files modified:**
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/factory.rs` — wire `MacosNodeAdapter`.
- `crates/rustynetd/src/lib.rs` — `pub mod macos_*` for each new validator.

**Per-method strategy:**
| Method | Strategy |
|---|---|
| `install_daemon` | scp source, `brew install rust git`, cargo build, install binary to `/usr/local/bin/`, install launchd plist to `/Library/LaunchDaemons/`, `launchctl load` over SSH. |
| `start_daemon` etc. | `launchctl bootstrap` / `bootout` system/com.rustynet.daemon over SSH. |
| `issue_membership_owner_key` | `rustynet membership init` (Rust CLI runs on macOS). |
| `init_membership_snapshot` | `rustynet membership init` flow. |
| `collect_wireguard_public_key` | macOS uses kernel WireGuard module via wireguard-go OR userspace boringtun — pick based on installed package. Cat `/usr/local/var/rustynet/keys/wireguard.pub` over SSH. |
| `collect_node_id` | `rustynet status`. |
| `distribute_signed_bundle` | scp + atomic install (same pattern as Linux). |
| `run_validator` | `rustynetd macos-<op>-check` over SSH (new `MacosDaemonProbe::build_argv`). |
| `ping_mesh_peer` | `ping -c 3 <peer-mesh-ip>` over SSH (POSIX, same as Linux). |
| `collect_active_tunnels` | `wg show <iface>` via wireguard tools over SSH. |
| `collect_artifacts` | `tar -czf - /usr/local/var/rustynet /var/log/rustynet … --exclude='*/keys/*' --exclude='*.priv' --exclude='*.pem'` over SSH. Key material excluded per §3.1 contract. |
| `cleanup_runtime_state` | `launchctl bootout system/com.rustynet.daemon && rm -rf /usr/local/var/rustynet/*`. |

**Tests:** parallel structure to W5.1.

**Acceptance criteria:**
- All gates pass.
- Live evidence: drive against a macOS UTM VM (operator provides — see §8 Open Questions). If no macOS VM available at this slice, fall back to off-platform `applicable: false` reports for validators + acceptance criterion is "compile + unit tests + dry-run path works".

**Estimated LOC:** 2000-2500 (includes 6 new validator modules in rustynetd).

### W5.4 — Windows-as-exit + macOS-as-exit (membership-owner cross-OS) (2-3 sessions)

**Deliverable:** Remove the "exit must be Linux" constraint. `WindowsNodeAdapter::issue_membership_owner_key` + `init_membership_snapshot` + `MacosNodeAdapter` equivalents stop returning UnsupportedOp.

**Current 2026-04-29 hardening state:** non-Linux Exit is not yet enabled. The Windows/macOS membership code paths now pass collected peer node IDs and 64-char WireGuard public keys into `ops e2e-membership-add`, but `NodeRole::Exit` remains fail-closed on Windows/macOS until live evidence proves membership-owner key custody, init, signed bundle issuance, and validators on those platforms. This is intentional: exposing Windows/macOS Exit without W5.4 live evidence would violate the security minimum bar.

**Files modified:**
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_membership.rs` — full impl using `rustynet membership init` over PS-encoded SSH.
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_membership.rs` — full impl.
- Role-platform matrix in `role.rs` updated.

**Tests:**
- Unit tests for the new Windows membership-init dispatch.
- Live evidence: spin up a heterogeneous lab where the EXIT is `windows-utm-1` and clients are Linux. Mesh up + validators pass.

**Acceptance criteria:** the role-platform matrix end-state in §3.4 is achieved.

**Status (2026-04-29):** code shipped (`04cf7fd`); live evidence ⛔ blocked. Membership-init implementations exist for both Windows and macOS adapters, but until live mesh-with-non-Linux-Exit evidence is captured the role-platform matrix in §3.4 is **not** flipped to ✓ for the Windows/macOS Exit cells in operational practice. Operators should treat Windows-as-Exit and macOS-as-Exit as fail-closed until §4.W5.7 produces the artifacts.

**Estimated LOC:** 800-1200.

### W5.5 — Stage implementations (4-6 sessions)

**Deliverable:** All 17 stages from §2.1 ported from bash to Rust as `OrchestrationStage` impls. Each stage is its own file under `orchestrator/stage/`, calls `NodeAdapter` methods, and emits typed `StageOutcome`.

**Current 2026-04-29 hardening state:** all 17 stage files are present and `execute_rust_native_orchestration` now builds its runtime stage vector from `PlanBuilder`, so the CLI path includes `FinalCleanupStage` and cannot drift from the plan list. A unit test pins exact stage-ID parity with `PlanBuilder`. The live parity runner/evidence remains pending, so W5.5 is not fully closed.

**Files added:** 17 stage files under `crates/rustynet-cli/src/vm_lab/orchestrator/stage/`.

**Tests per stage:** unit test of the stage's logic with a mocked `NodeAdapter`. Integration test (gated) drives the stage against a live VM.

**Acceptance criteria:**
- Side-by-side parity run: invoke `vm-lab-orchestrate-live-lab` once with `--legacy-bash-orchestrator` and once with the new code path against the same lab. **Parity was originally defined as:** (a) identical set of stage IDs executed; (b) identical pass/fail status for every stage; (c) identical overall exit code; (d) per-stage JSON `outcome` field values match exactly; (e) numeric peer counts and validator counts within ±0. **⚠️ SUPERSEDED (2026-07-04):** criterion (a) — and therefore the mechanical `overall_parity_pass` — is **unsatisfiable** because the bash and Rust dialects use divergent stage IDs by design (only 8 of ~21 overlap; see the parity-gate finding at the top of this doc). The redefined gate is **functional/outcome parity**: both dialects reach mesh setup + `validate_baseline_runtime` PASS with equal validator pass/total counts on the same topology, optionally with a mechanical diff restricted to the shared-ID stages. Capture diff + summary as evidence.
- `TrafficTestMatrix` stage includes both **positive probes** (mesh peers reachable via tunnel — N×N) and **negative probes** (default-deny ACL blocks a non-mesh probe IP from each node). Stage result is PASS only when all positive probes succeed AND all negative probes return `Blocked`. A `Reachable` result on any negative probe is a security failure that fails the stage and blocks phase progression. Both probe sets are documented in per-stage evidence.
- All gates pass.

**Status (2026-04-29):**
- W5.5a — 17 stage execute() impls + `PlanBuilder::build()` shipped in `c63084b`. Stages walk in dep order, emit typed `StageOutcome`, route through `NodeAdapter`. Unit tests on the runner / plan / per-stage logic with mocked adapters.
- W5.5b — parity-diff harness shipped in `85e786d`. Rust orchestrator now writes `<report-dir>/parity_input.json` (a `LiveLabRunReport`) at end-of-run. New `vm-lab-diff-orchestrator-parity --left <bash.json> --right <rust.json> --output <diff.json>` subcommand emits `ParityDiff` covering every dimension above (stage list, per-stage outcome, overall status, node count, validator pass/total counts). 11 unit tests cover the diff function + every drift dimension; 2 tests cover the executor end-to-end. Returns Err on drift so CI can gate.
- 🟡 **Rust-side live parity evidence CAPTURED (2026-07-04, `42afa4b`).** The Rust orchestrator wrote a live `parity_input.json` (`state/rust-native-linux-1783185441`, 21-stage `LiveLabRunReport`) from a real 3-node Linux run — all Rust-dialect stages PASS through `deploy_relay_service`; only the downstream `traffic_test_matrix` client↔client pair failed (known dataplane gap, not migration). The **bash** side still emits no `parity_input.json`, and — critically — even if it did, the mechanical `overall_parity_pass` cannot go green bash↔Rust because the two dialects' stage-ID sets differ by design (parity-gate finding, top of doc). Next: redefine the gate to functional/outcome parity (or shared-ID-only diff), then a paired bash↔Rust run on an all-pairs-reachable topology.

**Estimated LOC:** 3000-4000 across 17 stage files + per-stage tests.

### W5.6 — Promote `--node` to default + deprecate old flags (1 session)

**Deliverable:** `--node` (opt-in since W5.1) becomes the default code path. Old flags (`--exit-vm`, `--client-vm`, `--entry-vm`, `--aux-vm`, `--extra-vm`, `--windows-vm`) keep working as deprecated translation aliases. `--legacy-bash-orchestrator` remains available until W5.7.

**Files modified:**
- `crates/rustynet-cli/src/main.rs` — mark old flags deprecated; new path is default.
- `crates/rustynet-cli/src/vm_lab/mod.rs` — flip the router default: new path unless `--legacy-bash-orchestrator`.

**Tests:**
- Pin test: `--exit-vm A --client-vm B --entry-vm C --aux-vm D --extra-vm E` produces the same role assignments as `--node A:exit --node B:client --node C:entry --node D:aux --node E:extra`.
- Deprecation warning emitted when old flags are used.

**Acceptance criteria:**
- Existing CI invocations of `vm-lab-orchestrate-live-lab` keep working unchanged (old flags still translate correctly).
- New path is default; operators who have already adopted `--node` since W5.1 see no change.
- All gates pass.

**Status (2026-04-29):** CLI surface shipped in `85e786d`.
- `--legacy-bash-orchestrator` flag wired (parser + config field).
- `validate_orchestrate_live_lab_config` enforces mutual exclusion with `--node`; called from the executor before dispatch.
- `translate_legacy_role_flags` in `role_assignment.rs` maps the legacy `--exit-vm` / `--client-vm` / `--entry-vm` / `--aux-vm` / `--extra-vm` / `--fifth-client-vm` / `--windows-vm` flag set to a `Vec<NodeRoleAssignment>` matching the bash orchestrator's role semantics. Pin test asserts equality with the equivalent repeated `--node A:exit ...` form.
- `legacy_role_flags_deprecation_warnings` returns the warning lines emitted to stderr when the legacy flag set is used without `--node` and without `--legacy-bash-orchestrator`.
- 13 unit tests cover translation correctness (every legacy → role mapping, fifth-client/windows-vm both → second Client, blank/missing alias handling, whitespace trimming), validator mutual-exclusion (4 cases), and deprecation-warning silence vs. trigger (5 cases).
- ⛔ **Default routing is NOT yet flipped.** The bash orchestrator remains the default; the Rust path is opt-in via repeated `--node`. Flipping the default is a one-line change in `execute_ops_vm_lab_orchestrate_live_lab`. **Gate update (2026-07-04):** the original `parity_diff.overall_parity_pass=true` gate is unsatisfiable bash↔Rust (divergent dialect stage IDs — parity-gate finding, top of doc), so the flip is now blocked on the **redefined functional/outcome-parity gate** (both dialects reach `validate_baseline_runtime` PASS with equal validator counts on an all-pairs-reachable topology). The Rust path is Linux live-proven through relay deploy (`42afa4b`); the flip additionally stays gated on the cross-OS (macOS/Windows) live-evidence campaign per W5.7.

**Estimated LOC:** 200-300 (most work already done in W5.1).

### W5.7 — Live-evidence campaign + bash orchestrator removal (2-3 sessions)

**Deliverable:** Live evidence runs across multiple OS combinations:

1. **5 Linux** — match bash orchestrator output exactly.
2. **4 Linux + 1 Windows** — Windows in client/entry/aux/extra role.
3. **4 Linux + 1 macOS** — macOS in client/entry/aux/extra role.
4. **3 Linux + 1 Windows + 1 macOS** — three OSes in one mesh.
5. **1 Windows-as-exit + 4 Linux** — Windows owns membership.
6. **1 macOS-as-exit + 2 Linux + 2 Windows** — macOS owns membership.

Each captures a JSON evidence artifact + markdown summary under `documents/operations/active/W5_LiveEvidence_<scenario>_<date>.md`.

**Files removed (W5.7):**
- `scripts/e2e/live_linux_lab_orchestrator.sh` (the bash orchestrator).
- `scripts/e2e/live_lab_common.sh` (helpers — only if no other consumer exists; audit first).
- The `--legacy-bash-orchestrator` flag.
- Legacy code path in `execute_ops_vm_lab_orchestrate_live_lab` that called the bash orchestrator.

**Files modified:**
- `documents/operations/LiveLinuxLabOrchestrator.md` — rewrite to point at the Rust orchestrator.
- `documents/operations/HeterogeneousLiveLabRunbook.md` — update for `--node` flag.
- `documents/operations/active/MasterWorkPlan_2026-03-22.md` — close the W5 track.
- `.github/workflows/*.yml` — replace bash-orchestrator CI invocations with Rust-orchestrator invocations.

**Acceptance criteria:**
- All 6 live-evidence scenarios produce PASS reports.
- Bash orchestrator removed; no remaining references in code or docs.
- All gates pass on a clean rebuild.

**Status (2026-04-29):** ⛔ NOT STARTED. The entire slice is gated on a real VM lab being reachable. None of the six scenario evidence files exist; the bash orchestrator and `--legacy-bash-orchestrator` flag are intentionally retained.

**Estimated LOC:** -3000 (net removal) + ~500 evidence + ~300 doc updates.

## 5) Migration strategy (how old + new coexist)

During W5.0 → W5.6, both code paths coexist. Operators can choose:

```sh
# Legacy bash path (default during transition)
ops vm-lab-orchestrate-live-lab --exit-vm a --client-vm b … --legacy-bash-orchestrator

# New Rust path (opt-in during transition, default after W5.7)
ops vm-lab-orchestrate-live-lab --node a:exit --node b:client …
```

Risk mitigation:
1. **CI keeps invoking the legacy path** until W5.7 ships. No CI-breaking change midway through.
2. **Side-by-side parity check** at every major milestone: same lab → both paths → byte-for-byte stage-outcome comparison.
3. **Bash script remains in place** until W5.7. If the new path regresses on a non-test-covered scenario, operators flip back to legacy without a rollback commit.
4. **Per-slice mergeability** — each W5.x is a clean commit with passing gates. Pause-resume safe.

## 6) Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Rust orchestrator regresses behavior the bash path silently relied on | High | High | Side-by-side parity runs at end of W5.5 with machine-readable JSON diff. Bash path stays callable until W5.7. Daemon-side validators (W3.2-followup) provide cross-check. |
| SSH MITM during `install_daemon` → attacker substitutes malicious daemon binary | Medium | Critical | `StrictHostKeyChecking=yes` + required `--known-hosts-file` enforced at `NodeConnection::Ssh` construction. Orchestrator hard-fails on absent file or key mismatch. Pre-populate known-hosts before first orchestrator run via key-exchange ceremony documented in runbook. |
| `collect_artifacts` captures key material → private key exfiltration via artifact archive | Low | Critical | Key dirs excluded at the `tar` invocation level (`--exclude='*/keys/*' --exclude='*.priv' --exclude='*.pem'`). Key-exclusion invariant tested: mock tarball must not contain `wireguard.priv`. |
| `cargo build --release` over SSH on a UTM Linux VM is too slow (>20 min) → CI timeouts | Medium | Medium | Add binary-cache mode: build once on the macOS host (cross-compile), scp the binary, skip remote cargo. Optional flag, falls back to remote-build if cross-compile not configured. |
| macOS adapter blocked by no available macOS VM during W5.3 | High | Medium | macOS adapter compiles + has unit tests. Live evidence runs deferred to when a Mac mini / macOS UTM VM is available. Marked as "compile + unit ready, live evidence pending". |
| WireGuard for Windows install via winget unreliable in CI | Medium | High | Add a `--require-wireguard-preinstalled` flag that skips winget. CI runners pre-install via base-image automation. |
| Membership-owner key handling differs subtly per-OS (key-custody, signature scheme) | Medium | High | Validate via the existing `key-custody-check` validator after every install. Cross-OS membership-init is gated on validator PASS. |
| Multi-OS testing surfaces a pile of cross-OS interop bugs simultaneously | High | Medium | Each scenario in W5.7 evidence campaign is its own slice. We fix bugs as they surface, one slice at a time. The orchestrator's drift-reasons list is designed to surface multiple issues per run, not stop on first. |
| Bash orchestrator removal breaks an out-of-tree consumer | Low | Medium | grep entire repo + docs + CI configs for `live_linux_lab_orchestrator.sh` references at W5.7. Audit before removal. |
| The "PowerShell-encoded SSH" dispatch path on Windows has known quirks (CLIXML on stderr, etc.) | Medium | Medium | Already partially debugged in W4.x. Add a `$ProgressPreference = "SilentlyContinue"` wrapper to all encoded PS scripts. Drain stderr separately from stdout in the Rust SSH layer. |

## 7) Acceptance criteria for "W5 complete"

Code gates met for the slices that have shipped. Live-evidence and CI-side
items remain unchecked because they require a real VM lab.

- [ ] All 7 phases (W5.0 → W5.7) have shipped commits + passing gates. *(W5.0–W5.6 shipped; W5.7 not started.)*
- [x] `vm-lab-orchestrate-live-lab` accepts `--node <alias>:<role>` and works for any OS-role combination in §3.4's matrix. *(CLI surface accepts every role/platform combination; live execution still requires the per-OS adapter to succeed against a real VM.)*
- [ ] Live evidence exists for ≥5 of the 6 scenarios in W5.7. *(blocked-by: real VM lab.)*
- [ ] Bash orchestrator removed from the codebase. *(intentionally retained until W5.7 live evidence passes.)*
- [ ] CI exclusively uses the new Rust orchestrator. *(blocked-by: W5.5 parity proof + W5.7 evidence.)*
- [ ] Documentation reflects the new architecture; no doc references the bash orchestrator as the production path. *(W5.7 doc rewrite pending.)*
- [ ] `cargo audit --deny warnings` + `cargo deny check bans licenses sources advisories` clean. *(re-run at the W5.7 cut.)*
- [ ] No new TODOs / FIXMEs in completed deliverables. *(re-audit at the W5.7 cut.)*
- [ ] `MasterWorkPlan_2026-03-22.md` updated to reference W5 track + close it. *(deferred to W5.7.)*

## 8) Architecture decisions made before W5.0

The following decisions were made during plan review (2026-04-28) and are now closed. They are recorded here as decisions, not open questions.

**D1 — `NodeAdapter` connection-injection pattern (P0, blocking W5.0):**
`NodeAdapter` methods carry no `RemoteTarget` / connection argument. Connection details live in `NodeConnection`, injected at adapter construction by `node_adapter_for(platform, conn)`. Rationale: SSH-centric `RemoteTarget` in every method signature blocks iOS (MDM) and Android (ADB) from ever implementing the trait without a hack.

**D2 — SSH known-hosts enforcement (P1, security):**
`--known-hosts-file <path>` is a required CLI flag. `NodeConnection::Ssh` validates the path at construction. `StrictHostKeyChecking=yes` is non-negotiable at the SSH layer. Rationale: MITM during `install_daemon` allows daemon binary substitution.

**D3 — Negative traffic tests mandatory in `TrafficTestMatrix` (P1, security):**
`probe_denied_peer` is a required `NodeAdapter` method. `TrafficTestMatrix` stage PASS requires all negative probes return `Blocked`. Rationale: positive-only connectivity test gives false assurance for default-deny ACL verification.

**D4 — `collect_artifacts` key-exclusion required (P1, security):**
`*/keys/*`, `*.priv`, `*.pem` excluded from artifact archives at the `tar` invocation level. Exclusion tested with an invariant test. Rationale: `SecurityMinimumBar.md §3.4` prohibits logging/leaking key material.

**D5 — iOS/Android blocker messages name security barriers (P1, security):**
Error strings from `node_adapter_for(Ios|Android, _)` must contain "security minimum bar". Rationale: operator needs to know the rejection is a security decision, not a missing feature, and what future work is required to unblock it.

**D6 — `--node` opt-in flag ships in W5.1, not W5.6 (P2, plan quality):**
W5.1 wires `--node` and `--known-hosts-file` as opt-in flags. W5.2–W5.5 are developed and tested using `--node`. W5.6 promotes to default + deprecates old flags. Rationale: first test of the new path should not be after all 17 stages are already implemented.

**D7 — W5.5 parity defined as machine-readable JSON diff (P2, plan quality):**
Parity = same stage IDs, same pass/fail, same exit code, same `outcome` field values, numeric counts ±0. CI asserts zero diff on a machine-readable JSON diff artifact. See §4 W5.5 acceptance criteria for full definition.

**D8 — macOS in scope (W5.3), Android/iOS deferred to W6+ (P2):**
macOS is included in W5 as specified. iOS and Android require a different connection model (MDM/ADB), different validator coverage, and a reviewed key custody model. They are W6+ work. See §11 for the full forward roadmap.

**Remaining open questions (operator input needed):**

1. **macOS VM availability:** does the operator have a macOS UTM VM for W5.3 live evidence? If not, W5.3 ships as "compile + unit complete, live evidence deferred".
2. **Cross-compile vs remote-build:** confirmed remote-build (matching bash orchestrator) for W5.1. Cross-compile opt-in flag in a later slice.
3. **`live_lab_common.sh` retention:** audit at W5.7; keep only if another consumer exists.
4. **`Custom(String)` role gating:** ship enum with `Custom(String)` from W5.0 but gate behind `--allow-custom-roles` flag to prevent silent typo promotion.
5. **Stage gating language:** ship `--skip-stage` + `--rerun-stage` as direct ports of bash semantics in W5.6. No new gating language until operators request it.

## 9) Files-to-touch summary

For quick orientation. Per-phase details in §4.

### Files added (across all phases)

```
crates/rustynet-cli/src/vm_lab/orchestrator/                   (new module, ~32 files)
  ├── mod.rs
  ├── error.rs                  (AdapterError incl. UnsupportedPlatform, ConnectionPlatformMismatch)
  ├── role.rs
  ├── role_assignment.rs
  ├── source_archive.rs
  ├── connection.rs             (NodeConnection: Ssh/Adb/Mdm; known_hosts validated at construction)
  ├── context.rs
  ├── plan.rs
  ├── runner.rs
  ├── report.rs
  ├── adapter/
  │   ├── mod.rs
  │   ├── node_adapter.rs       (trait def — no RemoteTarget in method signatures)
  │   ├── linux.rs              (W5.1)
  │   ├── linux_install.rs      (W5.1)
  │   ├── linux_membership.rs   (W5.1)
  │   ├── linux_traffic.rs      (W5.1)
  │   ├── windows.rs            (W5.2)
  │   ├── windows_install.rs    (W5.2)
  │   ├── windows_membership.rs (W5.2 + W5.4)
  │   ├── windows_traffic.rs    (W5.2)
  │   ├── macos.rs              (W5.3)
  │   ├── macos_install.rs      (W5.3)
  │   ├── macos_membership.rs   (W5.3 + W5.4)
  │   ├── macos_traffic.rs      (W5.3)
  │   ├── ios.rs                (UnsupportedOp stub)
  │   ├── android.rs            (UnsupportedOp stub)
  │   └── factory.rs
  └── stage/                    (~17 files, W5.5)
      ├── mod.rs
      ├── preflight.rs
      ├── source_archive.rs
      ├── verify_ssh.rs
      ├── cleanup.rs
      ├── install.rs
      ├── collect_pubkeys.rs
      ├── membership_init.rs
      ├── distribute_membership.rs
      ├── distribute_assignments.rs
      ├── distribute_traversal.rs
      ├── distribute_dns_zone.rs
      ├── enforce_runtime.rs
      ├── validate_runtime.rs
      ├── traffic_test_matrix.rs
      ├── role_switch_matrix.rs
      └── exit_handoff.rs

crates/rustynetd/src/macos_*.rs                                (W5.3, 6 new validator modules)

scripts/bootstrap/macos/                                       (W5.3, new dir)
  ├── Bootstrap-RustyNetMacos.sh
  └── Install-RustyNetMacosService.sh

scripts/launchd/com.rustynet.daemon.plist                      (W5.3)

documents/operations/active/W5_*_LiveEvidence_<date>.md        (W5.1-7, one per scenario)

tests/orchestrator_*_smoke.rs                                  (W5.1-3, gated integration tests)
```

### Files modified (across all phases)

```
crates/rustynet-cli/src/vm_lab/mod.rs           (add `mod orchestrator;` W5.0; gradually shrink as logic moves out W5.5-7)
crates/rustynet-cli/src/main.rs                 (--node + --known-hosts-file opt-in W5.1; promote to default W5.6)
crates/rustynetd/src/lib.rs                     (W5.3: `pub mod macos_*` for new validators)
crates/rustynetd/src/main.rs                    (W5.3: 6 new `macos-*-check` subcommands)
documents/operations/LiveLinuxLabOrchestrator.md   (W5.7 rewrite)
documents/operations/HeterogeneousLiveLabRunbook.md (W5.6 update)
documents/operations/active/MasterWorkPlan_2026-03-22.md (W5.7 close track)
.github/workflows/*.yml                         (W5.7 replace bash orchestrator invocations)
```

### Files removed (W5.7)

```
scripts/e2e/live_linux_lab_orchestrator.sh
scripts/e2e/live_lab_common.sh                  (if no other consumer found in audit)
```

## 10) How this plan fits the broader roadmap

W5 is the natural sequel to W1-W4 (`OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md`):

- W1-W4 built the OS-agnostic *contract* (verifier shapes, adapter traits, distribute pipeline).
- W5 builds the OS-agnostic *orchestration* (uses those contracts to drive any-OS install + mesh + validate).

After W5 is complete:

- Adding a new OS = ship one new `NodeAdapter` impl + per-OS validator modules. Estimated 2-3 weeks per OS (roughly the same as the current Windows track's effort, minus the contract design work that's now done).
- Adding a new orchestration stage = ship one new `OrchestrationStage` impl. Days, not weeks.
- Bug-discovery velocity for cross-OS interop is gated by VM availability + CI capacity, not by orchestrator code work.

This positions the project for the operator's stated goal: "in the wild rustynet will be deployed on multiple devices with varying OS. I want to make sure they interact correctly." After W5, every CI run can spin up a heterogeneous mesh of arbitrary OS combinations + validate them end-to-end. That's the bug-finding harness the project needs to ship reliably.

## 11) iOS / Android — What a Future W6 Track Requires

W5 ships iOS and Android as `UnsupportedOp` stubs that fail closed with security-specific rejection messages. This is the correct default: these platforms cannot be added to a production mesh until each of the following barriers is cleared. This section exists so the W6 track owner has a concrete target.

### 11.1 Connection model (blocking)

- **iOS** has no SSH daemon. The `NodeConnection::Mdm` variant is the forward slot. Filling it in requires either Apple MDM enrollment (enterprise / supervised device) or a custom in-app management socket exposed by the Rustynet iOS Network Extension. Neither is designed yet.
- **Android** can use ADB for lab-only bootstrapping (`NodeConnection::Adb`), but production Android nodes run as a VPN-service app, not a system service. Production Android requires an app-layer management channel distinct from ADB. The `Adb` variant is explicitly a lab escape hatch, not a production path.

Both paths require explicit security review of the channel authentication model before the `UnsupportedPlatform` guard is lifted.

### 11.2 Daemon validator coverage (blocking)

All 6 W3.2-followup validators must be ported before live evidence is accepted:

| Validator | iOS target | Android target |
|---|---|---|
| `service-hardening-check` | iOS app sandbox + Network Extension entitlements | SELinux policy + VpnService permissions |
| `key-custody-check` | Secure Enclave-backed WireGuard key | Android Keystore hardware-backed key |
| `dns-failclosed-check` | iOS VPN profile DNS configuration | Android VPN DNS configuration |
| `runtime-acls-check` | App container file ACLs | App-private storage ACLs |
| `mesh-status-check` | Daemon reachable via in-app IPC | Daemon reachable via in-app IPC |
| `authenticode-check` | App Store / TestFlight signing | APK signing + Play Protect status |

### 11.3 Key custody model (blocking)

- **iOS:** WireGuard private key stored in Secure Enclave where available; Keychain fallback with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` as minimum. Explicit threat model for the case where the device is lost/stolen while unlocked.
- **Android:** WireGuard private key stored in Android Keystore with `StrongBox` hardware-backed protection where available. Threat model for rooted devices documented and fail-closed behavior specified.

### 11.4 Service hardening (blocking)

- **iOS:** App cannot be killed by other apps; runs with minimum entitlements; Network Extension restart behavior on crash is defined; background execution constraints documented.
- **Android:** SELinux `vpn` domain applied; `BIND_VPN_SERVICE` permission is system-only; app signing enforced; background execution restrictions documented.

### 11.5 Estimated effort

- iOS: 5-8 weeks. Apple's Network Extension and Secure Enclave APIs are constrained; App Store review adds latency. ADB connection model is not applicable; MDM enrollment or custom socket is required from day one.
- Android: 4-6 weeks for ADB-backed lab path; 6-8 weeks for production Play Store app-layer path (separate from the lab path).
- Both tracks can proceed in parallel after W5 ships. Neither blocks W5.
