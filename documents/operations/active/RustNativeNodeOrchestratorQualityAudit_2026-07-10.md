# Rust-Native `--node` Orchestrator Quality Audit — 2026-07-10

Status: implementation in progress; core hardening landed locally, structural split remains  
Audit baseline: repository rooted at `b775156`, with unrelated working-tree changes preserved  
Scope: `crates/rustynet-cli/src/vm_lab/`, especially the Rust-native orchestrator engine, evidence conversion, native paths in `vm_lab/mod.rs`, topology/capability helpers, and overnight executor  
Out of scope: feature-completeness claims, new live role-cell proof, bash-orchestrator implementation, and daemon internals except where the engine depends on them

## 1. Purpose and security rule

This document records the 2026-07-10 quality audit of the Rust `--node`
live-lab orchestrator. It is an implementation backlog, not live-lab evidence.
No finding below authorizes weakening fail-closed behavior, default-deny policy,
signed-state provenance, or verify-before-apply ordering. Security-sensitive
fixes require both an enforcement point and a negative verification test under
`documents/SecurityMinimumBar.md`.

Ranking considers risk, confidence, and expected implementation cost. Findings
are ordered by recommended execution priority.

## 1.1 Implementation update — 2026-07-10

This table is the honest post-implementation ledger. “Code complete” means the
enforcement point and scoped unit tests are present in the working tree; it does
not claim a new live-lab role-cell result.

| Finding | Status | Implemented / remaining |
|---|---|---|
| RNQ-01 | Code complete | Verifier files are mandatory and validated; every node installs and fingerprint-checks its verifier before the two-phase barrier admits any bundle. Missing/malformed and call-order tests added. |
| RNQ-02 | Code complete; **fail-open fixed 2026-07-13 (`20bca19`)**; live negative proof now partially done | Final cleanup calls `assert_node_clean` after cleanup. Linux/macOS include daemon + relay + interface + firewall/NAT probes; Windows includes daemon service + relay service + adapter + firewall + NAT. **Live residue fixture (Linux) surfaced a real FAIL-OPEN:** the Linux clean probe + nft reset gated on `command -v nft` in the SSH user's PATH, which omits `/usr/sbin` (where nft lives) — so the probe reported `nft=-` (clean) and the reset skipped its delete loop while a fail-closed `rustynet_boot` killswitch table persisted (Pair-1 finding P1-2). Fixed: sbin-inclusive PATH + the probe now fails CLOSED on an unqueryable-but-present tool (`nft=unknown` → dirty). Live-proven detect→remove→clean on debian-headless-2. Remaining: macOS/Windows live residue fixtures. |
| RNQ-03 | Code complete | Added `NotRun` and hash-bound `Reused`; focused modes validate the prior manifest, terminal rows, logs, bound context, passing report state, and sealed aggregate digest before readiness or evidence overwrite. Modified-log test fails closed. |
| RNQ-04 | Code complete | Baseline no longer paints role cells green. Role cells now map only from their canonical role-proof stages; regression test pins baseline-only behavior. |
| RNQ-05 | Substantially implemented; fsync transaction + fault-injection pending | Recorder/manifest/summary/parity/report-state/artifact/finalizer errors now block pass, and matrix append failure is fatal. Existing manifest/stage/context writers are atomic (context.rs does temp+fsync+dir-fsync). **2026-07-12 fix (`0cbf98d`):** a fully-green fresh full `--node` run failed finalization and appended NO matrix row — the reuse-evidence seal (attempted only when `candidate_pass`) digests `state/orchestration_context.json`, which a fresh full run never persisted (only `--setup-only` did; `--run-only` loaded it), so it failed `No such file or directory`; a *failing* run skipped the seal and therefore DID record a row, so only failing runs ever appeared in the matrix. Now the full-run path persists the context (atomic+fsync) before the seal; failure demotes via `evidence_errors`. Live-proven by a green run appending its row. Remaining: reorder so `report_state.json` run_passed=true is the LAST fsync'd write (single commit marker) + exhaustive per-writer fault injection. |
| RNQ-06 | Code complete | Failure dominates contradictory report state; corrupt manifests and unknown terminal stages block proof; incomplete/reused/not-run conclusions are partial. Negative fixtures added. |
| RNQ-07 | Code complete (2026-07-13) | Real cancellable process-isolated per-stage deadlines landed in the Rust `--node` engine. Each stage runs on a scoped worker thread with a wall-clock watchdog; on expiry the stage's live subprocess tree is reaped (`ps` ppid-walk + `kill -KILL`, argv-only, pid≤1 fail-closed guard) so the never-detached worker unblocks and returns — no detached thread that keeps mutating after the runner moves on. A timeout is FAIL-CLOSED: the terminal outcome is `Failed`, recorded with the closed-taxonomy `timed_out` status (rc 124) through the existing recorder, so the run fails, skip-cascade blocks dependents, and always-run cleanup still executes. `--stage-timeout-secs=0` leaves the plan untouched (no deadline). SIGTERM/SIGINT fatal-signal handling is unchanged (deadlines are additive). Scoped unit tests prove over-deadline→cancelled+reaped+`timed_out`+run-fails (with always-run cleanup), under-deadline unaffected, timeout=0 unchanged, and the pure kill-set/exclusion/pid-guard logic. Not yet live-lab-proven. |
| RNQ-08 | Code complete | Runner construction rejects duplicates, missing dependencies, and cycles before execution. Negative graph tests added. |
| RNQ-09 | Code complete; subprocess signal proof pending | Fatal SIGTERM/SIGINT registration now precedes readiness/inventory mutation. Injectable registration-failure test proves following readiness work is not entered. A real subprocess SIGTERM cleanup test remains. |
| RNQ-10 | Code complete | Context schema v3 uses deterministic payloads, SHA-256 binding, inventory/source/repo/report provenance, atomic mode-0600 write + fsync, permission validation, and tamper/binding tests. |
| RNQ-11 | Code complete | Parity `NodeStatus` carries real target and node ID; matrix finalization cross-checks target/node ID/role against `nodes.tsv`. Exact-match and mismatch tests added. |
| RNQ-12 | Code complete | Failure diagnostics and optional per-node artifact archives run before cleanup; diagnostic failure is combined with cleanup outcome and cannot suppress cleanup. Hook-order/failure test added. |
| RNQ-13 | Code complete | Bootstrap, enforce, baseline validation, and signed-state distribution use deterministic bounded fanout. `--max-parallel-node-workers` is honored; cancellation stops admitting later batches. Cap, speedup, ordering, and cancellation tests added. |
| RNQ-14 | Code complete | Custom roles are not lab-assignable; daemon-role/capability mapping is validated before readiness; Linux/macOS bootstrap env builders return `Result` instead of panicking. |
| RNQ-15 | Code complete (2026-07-12) | Readiness, diagnostics, and bounded fanout were already extracted. The remaining native engine moved out of `vm_lab/mod.rs`: `orchestrator/native.rs` (executor `execute_rust_native_orchestration`, mode filtering, platform-selector election, network-profile record — ~1,090 lines) and `orchestrator/evidence.rs` (stage recorder, run summary, failure digest, report-state writers, reuse seal/validation, manifest selectors — ~700 lines). `vm_lab/mod.rs` shrank 49,731 → 47,972 lines. Behavior-preserving: dispatcher + legacy in-file tests compile against `use` re-exports; full `rustynet-cli` suite 2,321/2,321 green. The shared `build_allow_spec` stays in `mod.rs` while the bash path still consumes it (migrates at W5.7). |
| RNQ-16 | Code complete (2026-07-12) | The stage catalog macro (`define_stage_catalog!`) now owns variant, canonical pipeline order, wire name, AND suite tag per row. `PlanBuilder::build` derives membership+order from `StageId::ALL` filtered by suite with a compiler-enforced exhaustive instantiation match (the four hand-kept suite const arrays became derived fns); `--setup-only`/`--run-only` mode filtering derives from suite tags; the registry's `rust_native` flag was deleted and `is_rust_native_stage_name` derives from `StageId::try_from` (+ historical prefix fallback); the run-matrix oracle derives the same way, with a new characterization test pinning StageId⊆rust-native + bash-only negatives. En route the catalog's claimed "canonical order" was corrected to the TRUE build order (3 divergences found: exit-validator trio, extended_soak position, blind_exit position — the security-order pin caught the third) and the MCP doc table was aligned. Residual by design: registry per-entry metadata (severity/columns/budget) is registry-owned single-copy data, and the MCP `ORCHESTRATOR_STAGES` doc remains a cross-crate string drift-gate. Six posture stages dispatch through typed `RoleValidatorKind` behind `NodeAdapter`. |
| RNQ-17 | Open — scoped 2026-07-12 | Surface analysis done. The shipped product binary is `rustynet-cli --bin rustynet-cli` (release.yml builds only rustynetd + this + rustynet-relay). Its lab attack surface = `mod vm_lab;` + the interleaved lab-`ops` dispatch in `main.rs` (ops_live_lab_orchestrator 97 refs, ops_e2e 36, ops_cross_network_* 29, ops_fresh_install_os_matrix 12, live_lab_* 10, vm_lab). The ~94 `src/bin/live_*`/`*_gates`/`phase*`/`check_*` binaries are SELF-CONTAINED (mod live_lab_support + #[path]; only `rustynet-windows-trust-cli` uses the lib) and are NOT in the shipped binary, so moving them is build-cost/package-surface cleanup, NOT the security tentpole. **The tentpole (remove the lab surface from the shipped binary) is achievable two ways:** (a) feature-gate `vm-lab` (default-off; conditional-compile `mod vm_lab;` + the lab-`ops` enum variants/parser/dispatch arms; make tar/zip optional; release build already scopes no features → surface absent; gates run `--all-features` → still compiled+tested) — bounded, no cross-crate move, but the ~15 lab bins that `cargo run -p rustynet-cli -- ops write-live-*-report` need `--features vm-lab`; or (b) the full `rustynet-lab` crate split the brief prefers — larger, untangles the shared lib boundary. Either achieves the same shipped-binary property, verified by `rustynet --help` (no vm-lab commands) + `cargo tree`/SBOM diff (no lab-only deps). Not yet landed. |

Verification run in this working tree: scoped `cargo check`, strict scoped
Clippy, 697 Rust-orchestrator tests, and the full 2,219-test CLI binary suite.
The first full-suite run exposed one stale taxonomy expectation after adding
`NotRun` plus one transient coverage-test result; both targeted reruns passed,
the taxonomy expectation was corrected, and the final full-suite rerun passed
2,219/2,219. Final workspace gates also passed: format check, workspace check,
workspace Clippy with warnings denied, workspace tests, `cargo audit --deny
warnings`, and `cargo deny check bans licenses sources advisories` (the deny
gate reported only its configured duplicate-dependency warnings).

## 1.2 Live-iteration findings — 2026-07-10

Focused three-node execution added three grounded findings after the static
audit. These findings are kept here, in the dated audit, rather than in a
separate private checklist.

| Finding | Status | Evidence / resolution |
|---|---|---|
| RNQ-18 | Code + focused bootstrap proof complete | Parallel bootstrap workers used PID-only local temp paths, so workers overwrote one another's node-specific env. Run `rust-node-fullmesh-focus-20260710-4` proved the defect: the Debian2 bootstrap log ended with Debian4's node ID. All Linux/macOS/Windows installer temp payloads now use the shared collision-free, mode-0600 `write_secure_temp_file`; a parallel regression test verifies unique paths and preserved contents. Run `-5` passed bootstrap and confirmed distinct Debian2 exit, Debian4 client, and macOS client identities with one network ID. |
| RNQ-19 | Code complete; live cleanup passed | Diagnostics rejected an archive containing only the empty `var/lib/rustynet/keys/` directory entry, despite excluding every key payload. Verification now permits directory metadata but still rejects any file below `keys/` and all `.priv`, `.pem`, and `.key` payloads. Three positive/negative tests pass; interrupted run `-4` completed final cleanup successfully with artifact collection enabled. |
| RNQ-20 | Code complete; Fedora live bootstrap pending | The Linux bootstrap assumed Debian CA layout and omitted Fedora's `llvm-devel`. It now resolves common Debian, Fedora/RHEL, and SUSE CA bundles and installs `llvm-devel` on Fedora-family guests. The embedded-script regression test passes. Fedora live proof remains pending because its current lab account does not have the required passwordless-sudo precondition; no persistent sudo-policy change was made. |
| RNQ-21 | Code complete; live negative observed | Preflight did not compare guest clocks with the orchestrator. Run `-5` reached traffic with a macOS VM about 90 minutes behind; signed assignments were future-dated to that guest and its daemon exited fail-closed. Preflight now probes each guest using platform-native argv, rejects malformed/unavailable time, and blocks skew beyond the 90-second signed-state tolerance before bootstrap or bundle issuance. Parser and boundary tests pass. |

Operational discovery during these runs: `working-tree` archives intentionally
include only Git-tracked/staged content. Runs must stage new Rust modules before
guest deployment; arbitrary untracked files remain excluded. Run `-2` failed
closed when three new orchestrator modules were not yet staged, and archive
listing plus nine source-archive tests verified their inclusion after staging.

Run `rust-node-fullmesh-focus-20260710-5` reached `traffic_test_matrix` with all
21 preceding applicable stages passing. Its topology was not a valid same-LAN
proof: Debian2 (`192.168.64.4`), Debian4 (`10.230.76.58`), and macOS
(`192.168.65.2`) were on isolated UTM underlays, and direct guest-to-guest probes
confirmed their advertised assignment endpoints were unreachable. The stage
correctly failed all-pairs reachability and final cleanup passed. A replacement
same-underlay evidence run remains required; do not promote run `-5` as a
functional mesh result.

## 2. Ranked findings

### RNQ-01 — Verifier keys deploy after bundles, and missing keys silently pass

- **Dimension:** fail-closed, security, ordering
- **Location:** `crates/rustynet-cli/src/vm_lab/orchestrator/stage/distribute_assignments.rs:189`, `:209-228`
- **Severity:** release-blocker
- **Why it matters:** Signed bundles are installed before their verifier keys.
  A running daemon can observe a new bundle before it has the matching key. If
  `rn-{kind}.pub` is absent, the code returns an empty verifier-result list and
  the stage can pass without deploying any verifier key.
- **Proposed fix:** Require a present, non-empty verifier-key file. Install and
  fingerprint-check the key on every target before installing any bundle. Any
  missing key or per-node failure aborts bundle deployment. Prefer one adapter
  transaction: stage key, verify fingerprint, then atomically install bundle.
- **Effort:** M
- **Verification:** Negative tests for missing/empty key, wrong fingerprint,
  and partial-node failure. A call-order test must prove no
  `distribute_signed_bundle` call occurs before every verifier-key precondition
  passes.

### RNQ-02 — Final cleanup trusts best-effort commands without checking residue

- **Dimension:** fail-closed, idempotency
- **Location:** `crates/rustynet-cli/src/vm_lab/orchestrator/stage/final_cleanup.rs:49-78`, `crates/rustynet-cli/src/vm_lab/orchestrator/stage/cleanup.rs:58-67`, `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/linux_traffic.rs:551`, `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_traffic.rs:377`, `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_traffic.rs:326`
- **Severity:** release-blocker
- **Why it matters:** Pre-bootstrap cleanup correctly chains
  `cleanup_runtime_state().and_then(assert_node_clean)`. Final cleanup only
  calls `cleanup_runtime_state`. OS adapters deliberately ignore multiple
  stop/firewall/interface-reset errors, so final cleanup can pass while daemon,
  NAT, killswitch, relay-service, DNS, or tunnel residue remains.
- **Proposed fix:** Apply the same postcondition assertion during final cleanup.
  Extend each OS assertion to cover daemon, relay sibling, tunnel interface,
  killswitch, managed-DNS residue, and exit NAT.
- **Effort:** S-M
- **Verification:** Mock cleanup returns `Ok` while the assertion fails; the
  stage must fail. Live negative fixtures should leave one residue type per OS
  and prove cleanup detects it.

### RNQ-03 — `--rerun-stage` and `--resume-from` record unexecuted stages as passed

- **Dimension:** correctness, evidence integrity
- **Location:** `crates/rustynet-cli/src/vm_lab/mod.rs:8329-8357`, `crates/rustynet-cli/src/vm_lab/orchestrator/runner.rs:65-72`, `crates/rustynet-cli/src/vm_lab/orchestrator/runner.rs:109-117`
- **Severity:** release-blocker
- **Why it matters:** Both iteration modes use
  `with_explicit_skips_recorded_as_passed`. A stage not executed by the current
  invocation becomes a terminal `Passed` outcome. A focused rerun can therefore
  erase prior failure or not-run truth.
- **Proposed fix:** Add distinct `NotRun` and `Reused` outcomes. `Reused` must
  name the prior run and bind to its manifest and artifact hashes. Missing,
  stale, failed, or modified prior evidence must block dependency reuse.
- **Effort:** M-L
- **Verification:** A prior failed stage followed by an unrelated rerun must
  never yield overall pass. Missing or modified prior evidence must fail before
  target execution.

### RNQ-04 — Baseline success falsely marks every assigned role as passing

- **Dimension:** evidence integrity
- **Location:** `crates/rustynet-cli/src/live_lab_run_matrix.rs:1305-1326`
- **Severity:** release-blocker
- **Why it matters:** `bootstrap_hosts` and `validate_baseline_runtime` call
  `set_target_role_statuses(... |_| true)`. An assigned relay can therefore
  produce `linux_relay=pass` when relay deployment and validation never ran.
- **Proposed fix:** Baseline stages populate baseline columns only. Each role
  result cell must map to one canonical role-proof stage, or a declared
  conjunction of terminal role-specific stages.
- **Effort:** M
- **Verification:** Relay topology with baseline pass and relay lifecycle not
  run must produce `linux_relay=not_run`. Repeat for exit, anchor, admin, and
  blind-exit roles. Failure must dominate pass.

### RNQ-05 — Evidence failures are warnings, yet the run may finalize as passed

- **Dimension:** evidence integrity, observability
- **Location:** `crates/rustynet-cli/src/vm_lab/mod.rs:8257-8272`, `:8425-8485`, `:8513-8545`, `:7546-7607`
- **Severity:** release-blocker
- **Why it matters:** Manifest, stage rows, stage logs, summary, parity input,
  artifact-completeness validation, and final report-state failures are mostly
  warnings. Final report state uses `failed == 0`, ignoring finalizer or
  completeness failure. Incomplete or contradictory evidence can claim pass.
- **Proposed fix:** Introduce a mandatory evidence-finalization transaction. A
  pass requires manifest, terminal rows, logs, summary, report state, parity
  snapshot, report-local matrix row, and consistency validation. Use atomic
  temp-write, sync, and rename. Evidence failure changes verdict to fail or
  aborted.
- **Effort:** M
- **Verification:** Fault-inject every writer. No failure may leave
  `run_passed=true` or `overall_result=pass`.

### RNQ-06 — Matrix reconciliation fails open on contradictory or unreadable evidence

- **Dimension:** evidence integrity
- **Location:** `crates/rustynet-cli/src/live_lab_run_matrix.rs:746-777`, `:779-795`, `:1581-1605`
- **Severity:** release-blocker
- **Why it matters:** An unreadable manifest makes the conclusion barrier
  silently return. Unknown stages become a note rather than a failed proof.
  `run_complete=true` plus `run_passed=true` returns pass without first checking
  for recorded failed stages.
- **Proposed fix:** Make contradiction resolution failure-dominant. Any failed,
  timed-out, or aborted stage overrides report-state pass. An unreadable
  full-run manifest or unknown terminal stage prevents proof.
- **Effort:** S-M
- **Verification:** Fixtures for corrupt manifest, unknown stage, missing
  planned stage, and `report_state=pass` plus `stages.tsv=fail` must all result
  in fail or aborted.

### RNQ-07 — `--stage-timeout-secs` is accepted but does nothing

- **Dimension:** robustness, ergonomics
- **Location:** `crates/rustynet-cli/src/vm_lab/orchestrator/runner.rs:36-47`, `:75-79`, `crates/rustynet-cli/src/vm_lab/mod.rs:8317-8327`
- **Severity:** high
- **Why it matters:** The value is stored but never read during execution. A
  hung in-process stage can block final cleanup indefinitely.
- **Proposed fix:** Reject nonzero values until real cancellation exists. Then
  implement cancellable stage execution. Do not use a detached timed-out thread
  that can continue privileged mutation after the runner returns.
- **Effort:** S for immediate rejection; L for full cancellation
- **Verification:** Current CLI test rejects nonzero timeout. Future sleeping
  mock stage must time out, stop work, and still execute always-run cleanup.
- **Resolution (2026-07-13):** Full cancellation implemented. The infrastructure
  lives in `crates/rustynet-cli/src/vm_lab/orchestrator/diagnostics.rs`
  (`DeadlineEnforcedStage` + the `run_stage_with_deadline` scoped-thread
  watchdog, the `SubprocessTreeControl` seam with the production `ps`/`kill`
  tree, the shared `StageTimeoutLedger`, and the `TimeoutAwareStageRecorder`
  that emits the `timed_out` terminal row through the existing recorder), wired
  in `crates/rustynet-cli/src/vm_lab/orchestrator/native.rs` where the former
  nonzero rejection is replaced by `apply_stage_deadlines` (and
  `stage_timeout_secs == 0` stays a no-op). The design explicitly avoids a
  detached timed-out thread: cancellation reaps the stage's subprocess tree so
  the never-detached worker returns before the runner advances. The sleeping
  mock-stage test (over-deadline → cancelled → subprocess reaped → terminal
  `timed_out` → run fails, with always-run cleanup still executed), the
  under-deadline and timeout=0 cases, and the pure kill-set logic all pass under
  `cargo test -p rustynet-cli`. Live-lab proof still pending.

### RNQ-08 — Invalid dependency graphs execute instead of failing

- **Dimension:** ordering, correctness
- **Location:** `crates/rustynet-cli/src/vm_lab/orchestrator/runner.rs:182-229`
- **Severity:** high
- **Why it matters:** Duplicate stage IDs overwrite map entries, unknown
  dependencies are ignored, and cyclic stages are appended in insertion order.
  Security-sensitive ordering can silently break.
- **Proposed fix:** Add `validate_plan()` that rejects duplicate IDs, missing
  dependencies, and cycles before readiness or node mutation. Make runner
  construction or execution return `Result`.
- **Effort:** S-M
- **Verification:** Three negative graph tests must assert zero stages execute.
  Canonical 58-stage and 67-stage plans must validate.

### RNQ-09 — Signal cleanup registers late, and registration failure is nonfatal

- **Dimension:** race, cleanup
- **Location:** `crates/rustynet-cli/src/vm_lab/mod.rs:8053-8058`, `:8302-8316`
- **Severity:** high
- **Why it matters:** Readiness can update inventory or restart VMs before
  handlers exist. Registration failure only warns. Default SIGTERM handling can
  then bypass always-run cleanup.
- **Proposed fix:** Register shutdown handling before any lab mutation. Treat
  registration failure as fatal. Use an injectable shutdown controller for
  unit and subprocess testing.
- **Effort:** S-M
- **Verification:** Injected registration failure must produce zero readiness
  and stage calls. A subprocess SIGTERM test must prove final cleanup executes.

### RNQ-10 — Persisted run-only context is unbound and non-atomic

- **Dimension:** provenance, fail-closed
- **Location:** `crates/rustynet-cli/src/vm_lab/orchestrator/context.rs:33-47`, `:118-180`, `crates/rustynet-cli/src/vm_lab/mod.rs:7976-7991`
- **Severity:** high
- **Why it matters:** Context contains roles, node IDs, public keys, membership
  snapshot, endpoints, mesh IPs, and network ID. Load checks only JSON schema
  version. No content digest, source/inventory binding, permissions check, or
  atomic write exists.
- **Proposed fix:** Use atomic mode-0600 writes. Bind context digest into report
  and setup manifests. Validate inventory digest, source provenance,
  assignments, report directory, and platforms before reconstructing adapters.
- **Effort:** M
- **Verification:** Tamper each persisted field, permissions, digest, or
  inventory. Load must fail before any VM mutation.

### RNQ-11 — `--node` topology evidence drops real target and node identity

- **Dimension:** evidence integrity
- **Location:** `crates/rustynet-cli/src/vm_lab/orchestrator/report.rs:41-47`, `crates/rustynet-cli/src/live_lab_run_matrix.rs:1075-1119`, `crates/rustynet-cli/src/vm_lab/mod.rs:7637-7664`
- **Severity:** high
- **Why it matters:** `nodes.tsv` contains real target and node ID, but
  `NodeStatus` does not. Parity fallback sets target empty and can substitute
  alias for node ID. `topology_summary` exists but may contain degraded
  identity.
- **Proposed fix:** Add target and node ID to `NodeStatus`, or build target
  evidence directly from `nodes.tsv`. Cross-check parity report, stage manifest,
  inventory, and nodes TSV before pass.
- **Effort:** S-M
- **Verification:** A real-shaped `--node` fixture must preserve exact target
  and node ID. Any source mismatch blocks evidence finalization.

### RNQ-12 — Failure-diagnostic flags are ignored by the Rust path

- **Dimension:** observability, ergonomics
- **Location:** `crates/rustynet-cli/src/vm_lab/mod.rs:880-881`, `:7858-8546`, `:9481-9505`, `:9762-9783`
- **Severity:** medium
- **Why it matters:** `collect_artifacts_on_failure` and
  `skip_diagnose_on_failure` are parsed, but only consumed by the later bash
  path. Rust failures omit diagnostics operators explicitly requested.
- **Proposed fix:** Add a pre-cleanup failure hook: collect diagnostics and
  requested artifacts, record their outcome, then execute always-run cleanup.
  Reject unsupported combinations instead of silently ignoring them.
- **Effort:** M
- **Verification:** A failing mock stage with collection enabled must call every
  selected adapter before cleanup and emit indexed artifacts.

### RNQ-13 — Per-node execution is serialized; advertised worker limit is unused

- **Dimension:** concurrency, performance
- **Location:** `crates/rustynet-cli/src/vm_lab/mod.rs:866`, `crates/rustynet-cli/src/vm_lab/orchestrator/stage/install.rs:59-85`, `crates/rustynet-cli/src/vm_lab/orchestrator/stage/validate_runtime.rs:38-56`, `crates/rustynet-cli/src/vm_lab/orchestrator/stage/enforce_runtime.rs:27-47`, `crates/rustynet-cli/src/vm_lab/orchestrator/stage/distribute_assignments.rs:189-225`
- **Severity:** medium
- **Why it matters:** `StageFanout::PerNode` is descriptive only. Per-node loops
  run synchronously. `--max-parallel-node-workers` is not consumed by the
  native executor.
- **Proposed fix:** Add a bounded per-node executor. Make adapters safely
  `Send + Sync`, preserve stage barriers, sort aggregate errors deterministically,
  and stop scheduling new mutation after cancellation.
- **Effort:** L
- **Verification:** Sleeping mocks prove concurrency cap and speedup. Race
  tests prove deterministic output and no unsafe shared-context mutation.

### RNQ-14 — Custom roles pass preflight, then Linux/macOS panic during bootstrap

- **Dimension:** error handling, validation
- **Location:** `crates/rustynet-cli/src/vm_lab/orchestrator/role.rs:88-92`, `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/linux_install.rs:361-364`, `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs:600-604`
- **Severity:** medium
- **Why it matters:** Every desktop role is reported lab-assignable, including
  `Custom`, but Linux and macOS bootstrap call `expect()` on the absent daemon
  role mapping. Runner catches the panic, but readiness may already have
  mutated the lab.
- **Proposed fix:** Validate daemon-role and product-capability mappings before
  readiness. Make bootstrap environment builders return `Result`.
- **Effort:** S
- **Verification:** `--node x:custom-foo` must return a clear error with zero
  readiness or SSH calls. Add Linux, macOS, and Windows mapping parity tests.

### RNQ-15 — About 1,285 native-engine lines remain in the 49,258-line mega-file

- **Dimension:** maintainability
- **Location:** `crates/rustynet-cli/src/vm_lab/mod.rs:2859-2930`, `:7526-7608`, `:7618-7855`, `:7858-8546`, `:8654-8845`, `:35541-35551`
- **Severity:** medium
- **Why it matters:** Native execution, readiness, recording/finalization,
  summaries, failure digest, and topology helpers remain interleaved with
  legacy routing and unrelated VM-lab code.
- **Proposed fix:** Perform a behavior-preserving extraction before changing
  behavior:
  - `orchestrator/native.rs`: executor and router glue, about 689 lines.
  - `orchestrator/readiness.rs`: about 192 lines.
  - `orchestrator/evidence.rs` or `finalize.rs`: report state, recorder,
    summary, and digest, about 390 lines.
  - `orchestrator/topology_evidence.rs`: allow-spec and related helpers.
- **Effort:** L
- **Verification:** Existing 58/67 count tests, CLI-plan equality,
  registry/oracle/repo-context drift gates, and full workspace tests must remain
  green. Update `documents/CODE_MAP.md` and this ledger when modules move.

### RNQ-16 — Platform dispatch and stage metadata still have multiple authorities

- **Dimension:** extensibility, cross-OS abstraction
- **Location:** `crates/rustynet-cli/src/vm_lab/orchestrator/plan.rs:2-30`, `crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs:59-225`, `crates/rustynet-cli/src/vm_lab/orchestrator/stage/authenticode_validation.rs:79-95`, `crates/rustynet-cli/src/vm_lab/orchestrator/stage/runtime_acls_validation.rs:76-92`
- **Severity:** medium
- **Why it matters:** Adding one stage still touches seven surfaces. Multiple
  validators repeat platform path selection, implementation predicates, and
  dispatch arms.
- **Proposed fix:** Use one declarative stage catalog to generate
  `StageId::ALL`, names, registry metadata, plan inclusion, and oracle mapping.
  Move validator dispatch behind a typed adapter method such as
  `run_role_validator(ValidatorKind)`. Keep OS-specific policy inside adapters.
- **Effort:** L
- **Verification:** Generated-set equality, canonical order/count tests,
  registry/oracle gates, repo-context gate, and per-platform negative validator
  tests.

### RNQ-17 — Lab robot code ships inside the product CLI

- **Dimension:** product/test separation
- **Location:** `crates/rustynet-cli/src/main.rs:36`, `crates/rustynet-cli/Cargo.toml:9-19`, `.github/workflows/release.yml:73-85`
- **Severity:** medium
- **Why it matters:** Released `rustynet` contains UTM, SSH, SCP, PowerShell,
  topology, overnight-agent, and lab-orchestration surfaces. This increases
  product attack surface and build cost.
- **Proposed fix:** Create a separate `rustynet-lab` crate or binary. Move lab
  CLI parsing and engine there. Keep only genuinely shared, stable operations in
  a small library crate. Do not combine this move with behavior changes.
- **Effort:** L
- **Verification:** Shipping `rustynet --help` exposes no VM-lab commands;
  release dependency tree and SBOM exclude lab-only dependencies;
  `rustynet-lab` retains all engine tests.

## 3. Considered, no change needed

- **Any-node communication:** Full-mesh allow policy is already generated by
  `orchestrator/stage/distribute_assignments.rs:67-85` and
  `vm_lab/mod.rs:35541-35550`: every distinct ordered node pair is included.
  Keep this contract. Do not narrow it to hub-and-spoke.
- **SSH connection reuse:** `orchestrator/adapter/ssh.rs:48-77` already uses
  secure `ControlMaster=auto`, short `ControlPersist`, a mode-0700 local socket
  directory, and pinned strict host-key checking.
- **Raw panic count:** Most `unwrap`/`expect` occurrences are test-only. The SSH
  pipe `expect()` calls follow locally proven `Stdio::piped()` setup. The
  reachable custom-role panic is retained as RNQ-14.
- **Dry-run VM mutation:** `vm_lab/mod.rs:8670-8685` exits before discovery,
  probing, inventory update, or restart.
- **Empty topology summary:** Refuted literally; the matrix populates
  `topology_summary`. Identity quality remains defective and is RNQ-11.
- **`--legacy-bash-orchestrator` no-op:** The field is discarded only after it
  has selected the bash route. Transitional routing behavior is internally
  consistent.
- **Overnight reviewer/oracle:** Malformed or missing review verdicts fail
  closed. A green oracle result without a durable commit is not accepted.
- **Backend-boundary leakage:** No production WireGuard adapter type was found
  leaking from this engine into transport-agnostic product crates.

## 4. Recommended implementation order

1. RNQ-01, RNQ-02: signed-state ordering and cleanup postconditions.
2. RNQ-03 through RNQ-06: eliminate false evidence and contradiction paths.
3. RNQ-07 through RNQ-11: timeout, graph, signals, persisted context, identity.
4. RNQ-12 through RNQ-14: diagnostics, bounded concurrency, early role errors.
5. RNQ-15 through RNQ-17: behavior-preserving structure and product separation.

Each behavioral fix should land separately from module extraction. Every
security-sensitive fix requires its negative test before status changes from
open. Full gates before landing remain those in `AGENTS.md` section 7.

## 5. Audit limitations

- Static source audit only; no code was changed by the audit itself.
- No unit, workspace, or live-lab gates were run for the audit.
- DeepSeek MCP tooling was unavailable; every retained claim was verified
  directly against source.
- Line numbers reflect the 2026-07-10 workspace and may move as open work lands.
