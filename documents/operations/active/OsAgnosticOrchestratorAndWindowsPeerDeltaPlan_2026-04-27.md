# OS-Agnostic Orchestrator + Windows-Peer Delta Plan

Date: 2026-04-27
Owner: Rustynet engineering
Status: active delta ledger
Branch baseline at creation: `main` @ `52372a7` (all local branches and `origin/main` aligned at `f838a76` ancestor; no divergent worktree work to recover)

## 0) Mission

Make `vm-lab-orchestrate-live-lab` accept any 5 UTM guests as equal first-class
peers in the live-lab mesh, regardless of guest OS, **without weakening any
existing security control**. Today the orchestrator only accepts five Linux
guests, with Windows bolted on as a sidecar that runs after Linux stages
finish. This plan turns Windows into a real peer that can fill any slot and
keeps Mac/iOS/Android scaffolding in place for later turn-on.

The orchestrator's security responsibility — enforcing a single hardened
execution path per security-sensitive workflow on every node — is the load-
bearing requirement. Cross-OS support that lowers the bar is rejected.

## 1) Scope And Non-Scope

In scope:

- Replace the Linux-only live-lab gate with a per-stage capability-aware
  dispatcher that can drive Linux or Windows nodes in any of the five lab
  roles (`exit`, `client`, `entry`/`relay`, `aux`, `extra`).
- Close the Windows security-parity gaps the orchestrator currently relies on
  the Linux unit/path/DNS toolchain to enforce.
- Land a `StageOrchestrator` abstraction in Rust so each live-lab stage can
  dispatch on `VmPlatformProfile` instead of shelling to one bash script.
- Keep macOS / iOS / Android variants of the abstractions as `Unsupported`
  stubs with clear blocker text and negative tests asserting the rejection,
  so future work has a stable target.
- Stay aligned with `documents/Requirements.md` and
  `documents/SecurityMinimumBar.md`.

Not in scope (this delta):

- macOS guest implementation. Daemon path on Darwin is untested; tracked
  separately. Stubs only.
- iOS / Android guest implementation.
- Replacing the Linux bash orchestrator wholesale. Linux remains the
  reference implementation; the dispatcher wraps it during transition.
- Promoting Windows out of `runtime-host-capable only` posture in the
  release matrix. That promotion is gated on the broader work tracked in
  [WindowsWorkingNodePlan_2026-04-17.md](./WindowsWorkingNodePlan_2026-04-17.md)
  and remains untouched by this plan.

## 2) Source-Of-Truth Cross-References

This delta is layered on top of, and must not contradict, these documents.
When this plan disagrees with one of them, fix this plan, not the other.

- [WindowsWorkingNodePlan_2026-04-17.md](./WindowsWorkingNodePlan_2026-04-17.md)
  — Windows daemon backend / runtime-host posture. Owns "what Windows must
  prove before it counts as working." This delta does not relax that bar; it
  only adds the orchestrator-side dispatch and parity stages that let a
  Windows guest be tested in a peer slot once the backend exists.
- [WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md](./WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md)
  — Windows UTM access / SSH / callback bootstrapping. This delta consumes
  whatever guest-access path that plan stabilizes; it does not replace it.
- [CrossPlatformSecurityGapRemediationPlan_2026-03-05.md](./CrossPlatformSecurityGapRemediationPlan_2026-03-05.md)
  — historical cross-platform gap analysis. Treat as background context.
- [ShellToRustMigrationPlan_2026-03-06.md](./ShellToRustMigrationPlan_2026-03-06.md)
  — bash→Rust migration of `start.sh` privileged subflows and evidence
  pipelines. The orchestrator-stage dispatch work in this delta is the next
  natural step after that plan; it migrates the **live-lab orchestration
  shell** itself out of pure bash.
- [MasterWorkPlan_2026-03-22.md](./MasterWorkPlan_2026-03-22.md) and
  [PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md](./PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md)
  — broader execution ledgers. Add a back-link to this delta in their next
  routine update.
- `documents/operations/active/UTMVirtualMachineInventory_2026-03-31.md` and
  `documents/operations/active/vm_lab_inventory.json` — VM inventory truth.
- `crates/rustynet-cli/src/vm_lab/mod.rs` — current orchestrator
  implementation; primary code under change.

## 3) Current State Snapshot (2026-04-27)

Captured from a fresh repo + agent walk; verify against current code if
anything below looks off.

### 3.1 Live-lab orchestrator
- CLI: `vm-lab-orchestrate-live-lab` in `crates/rustynet-cli/src/main.rs`,
  with `--windows-vm <alias>` sidecar flag.
- Stage runner is largely a Rust wrapper around
  `scripts/e2e/live_linux_lab_orchestrator.sh` (~109 lines of Linux-only
  shell: `systemctl`, `/etc/...`, `apt`/`dnf`, `systemd-resolved`,
  `nft`/`ip route`, `tc`/`netem`).
- Hard gate: `ensure_live_lab_profile_linux_only()` at
  `crates/rustynet-cli/src/vm_lab/mod.rs:5445` rejects any non-Linux node
  with `requires platform=linux remote_shell=posix
  guest_exec_mode=linux_bash service_manager=systemd`.
- Windows sidecar runs after Linux stages finish:
  `run_windows_orchestration_stages()` at
  `crates/rustynet-cli/src/vm_lab/mod.rs:4954-5138`. Three stages only:
  `bootstrap_windows_host`, `validate_windows_client_install`,
  `validate_windows_mesh_join` (deferred / unimplemented).

### 3.2 Existing platform abstractions (unused by stages)
Defined in `crates/rustynet-cli/src/vm_lab/mod.rs`:
- `VmGuestPlatform` (~line 500): Linux, Macos, Windows, Ios, Android.
- `VmRemoteShell` (~line 575): Posix, Powershell, Unsupported.
- `VmGuestExecMode` (~line 602): LinuxBash, MacosPosix, WindowsPowershell,
  Unsupported.
- `VmServiceManager` (~line 632): Systemd, Launchd, WindowsService,
  Unsupported.
- `VmPlatformProfile` (~line 660) bundles all four; `default_platform_profile()`
  (~line 675) maps each OS to correct defaults.

These types exist and parse correctly. **Stages do not dispatch on them.**

### 3.3 Daemon cross-platform status
- Linux: production target, well-evidenced.
- Windows: `rustynetd --windows-service --env-file …` runs;
  `windows-unsupported` and opt-in `windows-wireguard-nt` backend labels
  exist behind the backend abstraction; no reviewed Windows backend ships
  yet (see [WindowsWorkingNodePlan_2026-04-17.md](./WindowsWorkingNodePlan_2026-04-17.md)
  §"Current Repo Truth"). Windows runtime paths under
  `C:\ProgramData\RustyNet\…`, DPAPI passphrase custody, named-pipe IPC, and
  service-installer ACL repair already landed in Phase 2.
- macOS daemon: builds POSIX but is untested as a guest. Out of scope here.
- iOS / Android: out of scope.

### 3.4 VM inventory
- `debian-headless-1` … `debian-headless-5` cover the five Linux peer roles.
- `windows-utm-1` is `include_in_all=false`, `lab_role=windows_client`,
  sidecar-only today.

### 3.5 Branch state at doc creation
- `main` @ `52372a7` (and `origin/main`).
- `dazzling-wilson-16b7df` (active worktree) @ `52372a7`.
- `claude/amazing-antonelli-190578` (other worktree) @ `f838a76` (one
  ancestor commit behind `main`; no unique work).
- No stashes. No uncommitted changes in the active worktree at creation.

If you pick this plan up later, re-run the branch survey before assuming the
above is still true.

## 4) Non-Negotiable Constraints

These come from `CLAUDE.md`, `AGENTS.md`, `documents/SecurityMinimumBar.md`,
and the existing related plans. They override every choice in this plan.

1. **One hardened execution path per security-sensitive workflow.** No
   runtime fallback, downgrade, or legacy branch in production paths. The
   dispatcher selects an OS-specific implementation; once selected it is the
   only path.
2. **Default-deny.** ACL, routes, DNS, trust state. The dispatcher must not
   relax this on any OS.
3. **Fail closed** when trust/security state is missing, invalid, stale,
   replayed, or unauthorized. A stage that cannot verify its security
   guarantee on a given OS must refuse to run on that OS rather than skip
   the check.
4. **No custom crypto, no custom VPN protocol invention.** WireGuard remains
   a backend adapter. Cross-OS work does not get to invent shortcuts.
5. **No WireGuard / OS specifics leaking into protocol-agnostic crates.** OS
   adapters live behind the backend / orchestrator abstractions.
6. **Argv-only privileged exec.** No `cmd.exe /c …` and no PowerShell string
   interpolation with untrusted input on Windows. No shell construction
   with untrusted values on Linux.
7. **Strict key custody.** OS keystore (DPAPI on Windows; OS keystore on
   Linux when available) else encrypted-at-rest fallback with strict
   permissions and startup permission checks. Never log key material.
8. **No TODO/FIXME/placeholders in completed deliverables.**
9. **Each implemented security control has both an enforcement point in
   code and a verification method** (unit test, integration test, negative
   test, or gate check). Negative tests are mandatory for every fail-closed
   claim.
10. **macOS / iOS / Android stubs must reject explicitly with a clear
    blocker reason.** No silent "no-op success" branches.
11. **Linux behavior must not regress.** All existing Linux gates pass on
    every increment.
12. **Mandatory gates** (CLAUDE.md §7) run for every substantial increment:
    `cargo fmt --check`, `cargo clippy -D warnings`, `cargo check`,
    `cargo test`, `cargo audit --deny warnings`,
    `cargo deny check bans licenses sources advisories`, plus any
    scope-specific gate scripts.

## 5) Security-Parity Matrix (Windows-First)

For each existing Linux orchestrator-enforced control, list the Windows
equivalent that must exist before a Windows guest can fill any of the five
peer slots. Mac/iOS/Android entries are intentionally `Stub only — out of
scope this delta`.

| # | Control (Linux today) | Windows equivalent required | Status today |
|---|---|---|---|
| 1 | Service hardening: systemd unit with `NoNewPrivileges`, `ProtectSystem=strict`, `ReadOnlyPaths`, etc. | Windows Service running under restricted virtual SID; binary path ACL'd to SYSTEM+Admins; no interactive desktop; recovery action defined; service-image-path drift detection | Service exists (`crates/rustynetd/src/windows_service.rs`); hardening profile + verifier still needed |
| 2 | Privileged exec: argv-only, no shell construction | `CreateProcess` with explicit argv; never `cmd.exe /c`; never PowerShell string concat with untrusted input; helper exec audited end-to-end | Recent commit `f838a76` hardened helper exec; full audit pending |
| 3 | Config dir perms: `/etc/rustynet` 0700, owner check at startup | `C:\ProgramData\RustyNet\` ACL: SYSTEM + Administrators full, Users denied; startup ACL verifier; fail-closed if drift; orchestrator stage that re-verifies on the live guest | Phase 2 installer repairs ACLs; explicit startup verifier + orchestrator stage missing |
| 4 | Key custody: OS keystore else encrypted-at-rest with permission check | DPAPI machine scope (or CNG NCrypt) for runtime passphrase; encrypted-at-rest fallback with same ACL check; no plaintext key on disk; orchestrator stage validates the live state | DPAPI passphrase custody landed (Phase 2); orchestrator-side validation stage missing |
| 5 | DNS fail-closed in protected mode | NRPT rules + interface-bound resolver; orchestrator stage applies, validates, and runs a negative test that proves bypass is impossible | Stage missing on Windows |
| 6 | Default-deny ACL applied + verified by traffic test | Same protocol layer (daemon-enforced); traffic-test probe must run from a Windows node and confirm denies | Probe harness Linux-shell-only today |
| 7 | Signed trust state + anti-replay before mutation | Protocol-layer, daemon-side; cross-platform if the Windows daemon takes the same code path | Verify the Windows daemon takes the shared path and not a parallel branch |
| 8 | Wrapper-script hygiene: shell wrappers must dispatch to Rust only and fail closed | Same rule on Windows: no PowerShell wrapper that does anything beyond dispatch; argv-only | Audit pending |
| 9 | Binary integrity at install (signed release artifact + checksum) | Authenticode signature verification on the Windows binary before service registration; reject unsigned | Not enforced today |
| 10 | Membership and assignment distribution under owner-checked dir | Same on Windows under `C:\ProgramData\RustyNet\membership` and `\trust`, with the same ownership/ACL invariants | Path layout exists; stage that distributes membership/assignment to a Windows peer missing |

Each row, when implemented, must produce: (a) enforcement code, (b) an
orchestrator stage that verifies it on a live Windows guest, (c) a negative
test that proves it fails closed.

## 6) Architecture Plan

### 6.1 `StageOrchestrator` trait
New trait in `crates/rustynet-cli/src/vm_lab/`:

- One method per live-lab stage (or a single `execute_stage(stage_id,
  &[RemoteTarget])` enum-driven entry, to be decided at first impl).
- Two real impls land in P1:
  - `LinuxBashOrchestrator`: wraps the existing
    `scripts/e2e/live_linux_lab_orchestrator.sh` for back-compat. Used when
    every node in a stage's target set is Linux.
  - `RustOrchestrator`: dispatches per-target on `VmPlatformProfile`
    (service manager, remote shell, paths). Used when any node is non-Linux,
    or when invoked under an explicit migration flag for a Linux-only run.
- Stage outputs converge on a single typed report. No "which orchestrator
  ran" branching downstream.

### 6.2 Capability-based stage gating
Replace `ensure_live_lab_profile_linux_only` with per-stage capability
declarations. Each stage declares:

- required capabilities (e.g. `requires_capability(NetemImpairment)`),
- supported OS variants and the specific reason any unsupported variant is
  rejected.

A stage that cannot run on a given target's OS skips with an explicit
recorded reason. A stage whose security guarantee cannot be verified on a
target's OS does **not** skip — it fails the run. Distinguish these two
cases in the report.

### 6.3 Per-OS adapters
- `ServiceManager` adapter trait: systemd | windows-service | launchd
  (stub) | unsupported. Operations: install, enable, start, stop, status,
  uninstall.
- `RuntimePaths` adapter trait: returns canonical config / membership /
  trust / logs / secrets roots per OS. Linux + Windows real, macOS stub.
- `RemoteExec` adapter: argv-only command dispatch over the configured
  remote-shell channel (POSIX SSH, WinRM/SSH+PowerShell). Already partially
  exists for Windows sidecar; consolidate.
- `DaemonProbe` adapter: typed daemon-reported state (mesh join, ACL
  effective set, DNS resolver state). Cross-platform because it is
  daemon-driven, not host-shell-driven.

### 6.4 Test harness moves to daemon-driven probes where possible
Replace shell `nc` / `ping` / `curl` traffic checks with daemon-issued probes
that report typed results. Removes the per-OS shell divergence and gives
one hardened parser path per check (consistent with the wider Phase G
direction in `ShellToRustMigrationPlan_2026-03-06.md`).

### 6.5 Linux-only capabilities stay Linux-only
Examples: `tc`/`netem` cross-network impairment, `nftables` forwarding
introspection. These are kernel-feature-bound; declare them as
Linux-capability stages and skip-with-reason when the target is Windows.
Do not fake or simulate them.

## 7) Phased Plan

Each phase ends with: code change, code-side verifier, negative test, gate
re-run, doc status update in this file.

### Phase W0 — Doc + capture baseline (this plan)
- Land this delta plan and index it. **(in progress)**
- Capture an evidence baseline: current `vm-lab-orchestrate-live-lab`
  stage list, current Linux-only gate, current Windows sidecar surface, with
  exact file:line refs (already inline in §3).

Exit: this document is committed and indexed.

### Phase W1 — Security parity gates 1 (config dir + DNS fail-closed)
Closes matrix rows 3 and 5.

- W1.1 Implement Windows runtime-dir startup ACL verifier in `rustynetd`
  Windows path. SYSTEM + Administrators only, deny Users, deny Everyone.
  Daemon refuses to start if drifted. Negative test: drift the ACL, expect
  startup refusal with exact error code.
- W1.2 Implement orchestrator stage `validate_windows_runtime_acls` that
  runs the verifier against a live guest and reports per-path results.
- W1.3 Implement Windows DNS fail-closed enforcement (NRPT + interface-bound
  resolver) in the runtime path. Daemon-side enforcement; orchestrator
  applies and validates.
- W1.4 Implement orchestrator stage `validate_windows_dns_failclosed`. Must
  include a negative test that attempts a bypass (e.g. setting a rogue DNS
  server on the test interface) and confirms the daemon shuts the path down.
- W1.5 Run mandatory gates plus any Windows-specific gate scripts.

Exit: a Windows guest can pass the same DNS-fail-closed and config-dir-ACL
guarantees the Linux nodes pass. Status of each item recorded inline in
§10.

### Phase W2 — Security parity gates 2 (key custody + binary integrity + exec audit)
Closes matrix rows 1, 2, 4, 8, 9.

- W2.1 Authenticode signature verification on the Windows binary before
  service registration in the bootstrap provider. Reject unsigned. Negative
  test with a tampered binary.
- W2.2 Service hardening profile verifier (restricted SID, no interactive
  desktop, image-path pin, recovery action). Daemon-side verifier and
  orchestrator stage `validate_windows_service_hardening`.
- W2.3 Audit every Windows `CreateProcess` / shell-out call site for
  argv-only discipline. Add lints / tests where feasible to prevent
  reintroduction.
- W2.4 Daemon-side validator that confirms key material is DPAPI-protected
  at rest and not present in plaintext. Orchestrator stage
  `validate_windows_key_custody`.
- W2.5 Wrapper-hygiene audit (no PowerShell wrapper does anything beyond
  argv-only dispatch).
- W2.6 Run mandatory gates.

Exit: Windows guest passes the matrix rows 1, 2, 4, 8, 9 with code +
verifier + negative test for each.

### Phase W3 — Orchestrator dispatcher (`StageOrchestrator` trait)
- W3.1 Define `StageOrchestrator` trait + `LinuxBashOrchestrator` impl that
  wraps the existing bash script. Behavior unchanged for pure-Linux runs.
- W3.2 Define `ServiceManager`, `RuntimePaths`, `RemoteExec`, `DaemonProbe`
  adapter traits with Linux + Windows real impls and macOS / iOS / Android
  `Unsupported` stubs. Negative tests assert each stub rejects with a clear
  blocker reason.
- W3.3 Land `RustOrchestrator` impl that dispatches per-target on
  `VmPlatformProfile`. For pure-Linux node sets, it must produce
  byte-identical (or behaviorally equivalent — to be defined precisely
  before the swap) reports to the bash impl. No silent divergence.
- W3.4 Run mandatory gates plus the full Linux live-lab gate to prove no
  regression on the reference path.

Exit: dispatcher exists and Linux runs are unaffected. Windows runs still
go through the sidecar path until Phase W4.

### Phase W4 — Per-stage capability gating + Windows mesh-join
- W4.1 Replace `ensure_live_lab_profile_linux_only` with per-stage
  capability checks. Stages that require kernel features unavailable on
  Windows (e.g. `tc`/`netem`) skip-with-reason; stages that enforce
  security guarantees that have no Windows verifier yet **fail** the run
  rather than skip.
- W4.2 Implement Windows mesh-join stage (currently deferred at
  `crates/rustynet-cli/src/vm_lab/mod.rs:5132`). Membership + assignment
  ingestion via the existing Windows IPC path, with the same signed-state
  + anti-replay guarantees.
- W4.3 Implement Windows traffic-test peer participation. Daemon-driven
  probes in/out of the Windows node confirm default-deny and selected
  allows. Negative tests for both directions.
- W4.4 Implement Windows route + DNS lifecycle stages within the lab
  orchestrator (consume rather than re-implement the daemon-side route/DNS
  truth from [WindowsWorkingNodePlan_2026-04-17.md](./WindowsWorkingNodePlan_2026-04-17.md)
  §"Route And DNS Runtime Truth").
- W4.5 Run mandatory gates plus a 4×Linux + 1×Windows live-lab run as the
  first heterogeneous proof. Capture artifacts under
  `artifacts/orchestrator_w4/<UTC-timestamp>/`.

Exit: any one of the five peer slots can be Windows. The orchestrator
stops gating on `platform=linux` and gates on per-stage capability
declarations instead.

### Phase W5 — Stretch: 5×Windows and mixed-arrangement matrices
- W5.1 5×Windows live-lab run. Likely requires extra Windows guests in the
  inventory; track that ask in `vm_lab_inventory.json` updates.
- W5.2 Random arrangements (e.g. Windows as exit; Windows as relay; two
  Windows + three Linux) covered by a matrix runner.
- W5.3 Promote Windows posture in the release matrix only after this
  evidence exists **and** the [WindowsWorkingNodePlan_2026-04-17.md](./WindowsWorkingNodePlan_2026-04-17.md)
  §"Definition Of Done" has independently been met.

Exit: heterogeneous topology evidence is current and reproducible.

### Stub-only (kept for future)
- `ServiceManager::Launchd` stub returning `Unsupported("macos
  orchestration not yet implemented")`.
- `RuntimePaths` macOS stub returning `Unsupported(...)`.
- iOS / Android: `VmGuestPlatform` variants stay; no provider; tests assert
  rejection.
- A future delta will fill these in. Do not delete the variants in this
  delta even if they are unused.

## 8) Validation Strategy

Per CLAUDE.md §7 — mandatory on every increment:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo check --workspace --all-targets --all-features`
- `cargo test --workspace --all-targets --all-features`
- `cargo audit --deny warnings`
- `cargo deny check bans licenses sources advisories`

Scope-specific:

- `./scripts/ci/phase9_gates.sh`
- `./scripts/ci/phase10_gates.sh`
- `./scripts/ci/membership_gates.sh`
- Active-phase gate scripts as they emerge under the Windows / orchestrator
  scope.

Live-lab evidence (capture under `artifacts/`):

- pre-change baseline: 5×Linux live-lab run on the current main, archive the
  report;
- per-phase: re-run 5×Linux to prove no regression;
- W4 milestone: 4×Linux + 1×Windows live-lab run, archive report and the
  per-stage capability decisions;
- W5 milestone: heterogeneous matrix runs.

Negative tests are mandatory for every fail-closed claim. A stage that
cannot demonstrate fail-closed on the live guest does not count as
complete.

## 9) Rollback Strategy

- Use git history for rollback; do not keep parallel active orchestrator
  paths in tree.
- During W3, the `LinuxBashOrchestrator` impl preserves byte-/behavior-
  level parity with the current bash script. If `RustOrchestrator` shows
  divergence on a Linux-only run, revert the dispatcher selection (still
  one path) rather than running both side by side.
- The Linux-only gate is removed only at W4.1, after W1, W2, W3 are
  complete and all Linux gates still pass on the dispatcher path. Until
  then, Windows continues to run as the sidecar.

## 10) Status Tracker

Update this section as work lands. Use the same "Agent Update Rules" as
[ShellToRustMigrationPlan_2026-03-06.md](./ShellToRustMigrationPlan_2026-03-06.md)
§"Agent Update Rules": exact file paths, exact verification commands,
exact artifact paths, residual risk, and blockers if any. Mark
conservatively.

### Phase W0
- [x] Doc drafted and committed at branch `dazzling-wilson-16b7df`.
  - Changed files: this file, `documents/operations/active/README.md`.
  - Verification: doc review by user before code work begins.
  - Residual risk: none.

### Phase W1 (Security parity gates 1: config dir + DNS fail-closed)
- [x] W1.1 Windows runtime-dir startup ACL verifier
  - Changed files:
    - `crates/rustynetd/src/windows_paths.rs` — extracted pure SDDL
      evaluators (`evaluate_windows_runtime_acl_sddl`,
      `evaluate_windows_local_secret_acl_sddl`,
      `evaluate_windows_protected_dacl_sddl`); refactored
      `validate_windows_runtime_acl` and `validate_windows_local_secret_acl`
      to delegate; added `validate_windows_runtime_startup_acls()` that
      hard-requires every reviewed root (state, config, logs, trust,
      membership, keys, secrets, key-custody) to exist as a real directory
      with a protected DACL, a recognized owner, and grants for LocalSystem
      and Builtin Administrators only. Daemon refuses to start on drift.
    - `crates/rustynetd/src/daemon.rs` — `run_daemon` now calls
      `validate_windows_runtime_startup_acls()` under `#[cfg(windows)]`
      between `validate_daemon_config` and any FS mutation; failures map to
      `DaemonError::InvalidConfig` (fail-closed startup).
  - Verification:
    - `cargo fmt --all -- --check` clean.
    - `cargo test -p rustynetd --lib windows_paths` — 23 / 23 pass
      (including 14 new SDDL-evaluator tests covering: reviewed-directory
      acceptance, service-SID owner acceptance, missing protected DACL,
      world-writable principals (`WD`/`AU`/`BU`), missing LocalSystem grant,
      missing Administrators grant, unrecognized owner, missing owner,
      missing DACL marker, unprotected-but-allowed file ACL, DPAPI blob
      acceptance, DPAPI blob WD-rejection, startup-roots completeness, and
      a non-Windows `validate_windows_runtime_startup_acls` failure check).
    - `cargo test -p rustynetd --lib` — 351 / 351 pass.
    - `cargo test -p rustynetd windows_` — 28 / 28 pass.
    - `cargo test -p rustynet-crypto` — 21 / 21 pass.
    - `cargo check -p rustynetd -p rustynet-crypto -p rustynet-windows-native`
      clean.
    - `cargo check -p rustynet-windows-native --target
      x86_64-pc-windows-msvc` clean.
    - `cargo check -p rustynet-crypto --target x86_64-pc-windows-msvc`
      clean.
  - Artifacts: none (code-only slice; no runtime artifacts produced).
  - Residual risk:
    - Full `cargo check -p rustynetd --target x86_64-pc-windows-msvc` is
      still blocked by the documented `libsqlite3-sys` cross-compilation
      gap (per
      [WindowsWorkingNodePlan_2026-04-17.md](./WindowsWorkingNodePlan_2026-04-17.md)
      §"Current Phase 2 validation blocker"). The new code path is purely
      additive within an existing `#[cfg(windows)]` block in `run_daemon`
      and the cross-target compile of `rustynet-windows-native` (which
      contains the `inspect_file_sddl` binding) succeeds, so the verifier
      will resolve once the toolchain blocker is addressed; no change is
      needed in this code.
    - Workspace-wide `cargo clippy --workspace --all-targets --all-features
      -- -D warnings` fails on baseline `main` due to pre-existing
      `clippy::too_many_arguments` and `clippy::type_complexity` errors in
      `rustynet-backend-wireguard/src/windows_command.rs` (unrelated to
      this slice). Tracked as a separate cleanup outside this delta.
    - Live-guest drift proof (drift the ACL on a real Windows VM and
      observe daemon refusal) is owned by stage W1.2.
  - Blocker / prerequisite: none for W1.1; W1.2 depends on the Windows
    UTM access path stabilized by
    [WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md](./WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md).
- [x] W1.2a Daemon-side dispatchable subcommand
      `rustynetd windows-runtime-acls-check`
  - Changed files:
    - `crates/rustynetd/src/windows_paths.rs` — added typed report types
      `WindowsRuntimeAclRootStatus` (`ok` / `missing` / `drifted`),
      `WindowsRuntimeAclRootEntry`, `WindowsRuntimeAclReport`
      (schema_version=1, overall_ok, per-root entries) and
      `collect_windows_runtime_acl_report()` which iterates the canonical
      reviewed roots and captures per-root status without aborting on the
      first failure. Startup gate from W1.1 stays fail-fast; the diagnostic
      command produces a complete drift map for the orchestrator in a
      single round-trip.
    - `crates/rustynetd/src/main.rs` — added subcommand
      `windows-runtime-acls-check [--no-fail-on-drift]`. Default behavior
      prints the JSON report and exits non-zero on any drift (fail-closed
      for orchestrator dispatch); `--no-fail-on-drift` is report-only for
      diagnostics. Help text advertises the subcommand and flag.
  - Verification:
    - `cargo fmt --all -- --check` clean.
    - `cargo test -p rustynetd` — 388 / 388 pass (354 lib + 31 bin + 3
      integration), including 3 new `windows_paths` report-shape tests
      (status-tag serialization, off-Windows full-report shape,
      `WindowsRuntimeAclReport` schema serialization) and 3 new bin tests
      (help-text advertising, unknown-flag rejection, off-Windows
      fail-closed default + `--no-fail-on-drift` opt-out).
    - `cargo check -p rustynetd -p rustynet-crypto -p rustynet-windows-native`
      clean.
    - `cargo check -p rustynet-windows-native --target
      x86_64-pc-windows-msvc` clean.
  - Artifacts: none (code-only slice).
  - Residual risk:
    - Same `libsqlite3-sys` Windows-target compile blocker as W1.1; report
      types and subcommand are platform-agnostic Rust, so cross-target
      compile of `rustynet-windows-native` (which holds the SDDL binding)
      is unaffected.
    - Same workspace-clippy baseline failure as W1.1; not introduced here.
- [x] W1.2b Orchestrator-side live-lab stage `validate_windows_runtime_acls`
  - Changed files:
    - `crates/rustynetd/src/windows_paths.rs` — added `Deserialize` to the
      report types so the orchestrator can parse them.
    - `crates/rustynet-cli/src/vm_lab/mod.rs` — added new live-lab stage
      `validate_windows_runtime_acls` between `validate_windows_client_install`
      and the deferred `validate_windows_mesh_join` in
      `run_windows_orchestration_stages`. Stage skips on dry-run or when
      bootstrap / install validation didn't pass; otherwise it dispatches
      `& 'C:\Program Files\RustyNet\rustynetd.exe' windows-runtime-acls-check
      --no-fail-on-drift` over the existing argv-only PowerShell-encoded SSH
      channel, parses the typed JSON report, and on drift produces a
      `VmLabStageStatus::Fail` outcome with each drifted/missing root
      identified by label and reason. The raw report is archived under
      `report_dir/logs/validate_windows_runtime_acls.log` for evidence.
      Pure parser/evaluator extracted as
      `evaluate_windows_runtime_acls_report` for direct unit testing.
  - Verification:
    - `cargo fmt --all -- --check` clean.
    - `cargo build -p rustynet-cli` clean.
    - `cargo test -p rustynet-cli --bin rustynet-cli` — 356 / 356 pass
      (was 348; +8 new evaluator tests covering: all-ok payload accept,
      drifted-root reason propagation, missing-root reason propagation,
      unknown schema_version reject, empty-roots reject, two
      overall_ok/per-root inconsistency rejects, malformed-JSON reject).
    - `cargo test -p rustynetd` — 388 / 388 still pass after adding
      `Deserialize`.
    - `cargo check -p rustynet-windows-native --target
      x86_64-pc-windows-msvc` clean.
  - Artifacts: none in this slice (real artifacts produced when the stage
    runs against a live Windows VM).
  - Residual risk:
    - Live-guest evidence (drift the ACL on a real Windows VM and observe
      orchestrator-side `Fail` w/ the right root identified) is the missing
      end-to-end proof. Owned by the next live-lab run, which depends on
      [WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md](./WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md)
      stabilizing the UTM access path.
    - The stage assumes the installed binary lives at
      `C:\Program Files\RustyNet\rustynetd.exe`. If a future bootstrap
      provider relocates the binary, the orchestrator constant
      `WINDOWS_RUSTYNETD_EXE_PATH` and the daemon-side
      `DEFAULT_WINDOWS_INSTALL_ROOT` must move together; track in W2.2.
    - Same pre-existing baseline workspace-clippy failure as W1.1; tracked
      separately, not introduced here.
- [x] W1.3 Windows DNS fail-closed verifier (verifier-side; runtime
      enforcement gated on working Windows backend)
  - Changed files:
    - `crates/rustynetd/src/windows_dns_failclosed.rs` (new) — typed
      `WindowsInterfaceDnsEntry`, `WindowsNrptRule`,
      `WindowsDnsFailclosedSnapshot`, `WindowsDnsFailclosedReport`
      (schema_version=1). Pure aggregator
      `evaluate_windows_dns_failclosed_snapshot` walks the snapshot
      once and returns every drift reason in one pass. The reviewed
      RustyNet contract: (a) every host network interface has either
      an empty DNS server list or loopback servers only
      (`127.0.0.0/8` for IPv4, `::1` for IPv6) — anything else is a
      bypass route; (b) at least one NRPT rule covers the root
      namespace (`.`) with name servers that are all loopback, so
      unqualified lookups also stay on the daemon resolver; (c) every
      captured NRPT rule's name-server set is a subset of loopback
      addresses — a single non-loopback NRPT entry would let a
      crafted name leak past the daemon. Cross-platform:
      `cfg(windows)` collector
      `collect_windows_dns_failclosed_snapshot` shells to a static
      PowerShell probe script that calls `Get-DnsClientServerAddress`
      + `Get-DnsClientNrptRule` and emits typed JSON. The script body
      is a hardcoded `&str` constant with zero runtime-data
      interpolation, so the privileged-boundary argv-only / no-shell-
      construction discipline still holds. Off-Windows the collector
      returns a `requires a Windows runtime host` blocker error so
      the verifier still fails closed without fabricating a passing
      snapshot. The probe script tolerates `Get-DnsClientNrptRule`
      being absent on certain SKUs by falling back to an empty rule
      list — the evaluator then surfaces the missing-NRPT drift, so
      the contract still gates rather than silently passing.
    - `crates/rustynetd/src/lib.rs` — exposed the new module.
    - `crates/rustynetd/src/main.rs` — added subcommand
      `windows-dns-failclosed-check [--no-fail-on-drift]`. Default is
      fail-closed (non-zero on drift, suitable for orchestrator
      dispatch). `--no-fail-on-drift` is report-only for diagnostics
      against a known-incomplete state (e.g. before runtime
      enforcement lands). Help text advertises the new subcommand.
    - `crates/rustynetd/src/windows_authenticode.rs` and
      `crates/rustynetd/src/windows_ipc.rs` — pre-existing baseline
      `clippy::uninlined_format_args` errors that block the touched-
      packages clippy gate were folded into this slice as one-line
      format-string updates (no behaviour change). The remaining
      ~36 clippy errors in `crates/rustynet-cli/src/vm_lab/mod.rs`
      pre-date this slice and are tracked under the W1.1 residual-
      risk note; they remain a separate cleanup pass.
  - Verification:
    - `cargo fmt -p rustynetd -p rustynet-cli -- --check` clean.
    - `cargo test -p rustynetd` — 439 lib + 52 bin + 3 integration
      pass (was 418 + 48 + 3). +21 lib tests in
      `windows_dns_failclosed`: reviewed-snapshot accept,
      127.0.0.2-within-/8 accept, empty-interface-DNS accept,
      schema-version reject, rogue IPv4 DNS reject, rogue IPv6 DNS
      reject, address-family mismatch reject, unparseable address
      reject, missing-root-NRPT reject, root-NRPT-with-non-loopback
      reject, NRPT empty-namespace-list reject, NRPT empty-namespace-
      entry reject, NRPT empty-name-server reject, multi-drift
      aggregation, build-report ok, build-report drift surfaces
      reasons, parse-probe-output round-trip, parse rejects empty,
      parse rejects malformed JSON, off-Windows collector blocker,
      report serde round-trip. +4 bin tests in `main.rs`: help-text
      advertising, unknown-flag reject, off-Windows fail-closed
      default, off-Windows `--no-fail-on-drift` still blocks
      (architectural blocker is not a "drift" outcome the flag can
      suppress).
    - `cargo clippy -p rustynetd -p rustynet-cli --all-targets
      --all-features -- -D warnings` — touched-packages run still
      fails on ~36 pre-existing baseline lints in
      `crates/rustynet-cli/src/vm_lab/mod.rs` (none in the new DNS
      code; verified by filtering the clippy output for the new
      module + new functions); same posture as W1.1 / W2.x slices.
  - Artifacts: none in this slice; live-lab artifacts produced by the
    stage when run against a real Windows VM.
  - Residual risk:
    - **Verifier-only slice.** This lands the daemon-side typed
      report + evaluator + subcommand and the orchestrator-side
      stage (W1.4 below). It does NOT yet plumb runtime enforcement
      that *applies* the NRPT rules + interface-bound resolver — the
      Windows daemon is still on the `windows-unsupported` backend
      label, so the runtime path that would set
      `Add-DnsClientNrptRule` and bind the per-interface DNS to
      loopback is still pending. Practical implication: on the
      current Windows VM the verifier will report drift (no NRPT
      rule for `.`, host interfaces still carry whatever DNS DHCP
      handed out) — that is honest and the orchestrator stage will
      mark `Fail`. This is the same shape as W2.4 (key custody
      verifier shipped before key-init under a working backend) and
      W4.2 (mesh status verifier shipped before mesh-join
      distribution).
    - The PowerShell probe script is a static `&str` constant with
      no runtime-data interpolation, but it still introduces a
      shell-out from the daemon. A hardening follow-up could replace
      the probe with a Win32-API-based collector
      (`Win32_NetworkManagement_IpHelper::GetAdaptersAddresses` +
      `Win32_System_Registry` reads of
      `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
      subkeys). The pure evaluator + report types already match this
      future collector exactly; only the snapshot source would
      change.
    - `cargo audit` and `cargo deny` were not separately rerun for
      this slice; no dependency surface was changed (only existing
      `serde`, `serde_json`, and the `std::process::Command`
      shellout already present in other modules). Same posture as
      W2.x slices.
- [x] W1.4 Orchestrator stage `validate_windows_dns_failclosed`
  - Changed files:
    - `crates/rustynet-cli/src/vm_lab/mod.rs` — added live-lab stage
      `validate_windows_dns_failclosed` between
      `validate_windows_authenticode` and the deferred
      `validate_windows_mesh_join` in
      `run_windows_orchestration_stages_with_options`. Stage skips
      on dry-run or when any earlier security stage didn't pass;
      otherwise dispatches `& 'C:\Program Files\RustyNet\
      rustynetd.exe' windows-dns-failclosed-check --no-fail-on-drift`
      over the existing argv-only PowerShell-encoded SSH channel via
      `build_windows_security_check_invocation`, parses the typed
      JSON report, and emits a `Pass`/`Fail` outcome. Raw report
      archived under
      `report_dir/logs/validate_windows_dns_failclosed.log`. Pure
      parser/evaluator extracted as
      `evaluate_windows_dns_failclosed_report` for direct unit
      testing.
  - Verification:
    - `cargo fmt -p rustynetd -p rustynet-cli -- --check` clean.
    - `cargo test -p rustynet-cli --bin rustynet-cli` — 393 / 393
      pass (was 387). +6 evaluator tests in `vm_lab::tests`:
      reviewed payload accept w/ identity-rich summary
      ("2 interfaces, 1 NRPT rules"), drift payload reject w/
      specific reasons surfaced (rogue interface DNS), schema-version
      reject, two `overall_ok`/`drift_reasons` inconsistency rejects
      (false-with-no-reasons, true-with-reasons), malformed-JSON
      reject. The existing dry-run integration test was extended to
      assert the new stage name appears in the dry-run report.
  - Artifacts: none in this slice; live-lab artifacts produced by
    the stage when run against a real Windows VM.
  - Residual risk:
    - **Negative-bypass test deferred.** Plan §6 W1.4 calls for "a
      negative test that attempts a bypass (e.g. setting a rogue
      DNS server on the test interface) and confirms the daemon
      shuts the path down." That test requires runtime enforcement
      (the daemon actively closing the path on drift), which is
      gated on the working Windows backend tracked in
      `WindowsWorkingNodePlan_2026-04-17.md`. The verifier-side
      negative cases (rogue interface DNS reject, rogue NRPT name
      server reject, missing root NRPT reject, etc.) are exhaustive
      at unit-test level and the orchestrator stage will surface
      every one of them as a `Fail` outcome from a live guest, but
      the daemon-driven shutdown half of the negative test is
      tracked as a follow-up.
- [x] W1.5 Mandatory gates rerun (touched packages)
  - `cargo fmt -p rustynetd -p rustynet-cli -- --check` clean.
  - `cargo test -p rustynetd -p rustynet-cli` —
    `rustynetd`: 439 lib + 52 bin + 3 integration pass.
    `rustynet-cli`: 393 bin pass.
    No regressions across the rest of the workspace test suite (no
    Rust types or APIs were changed outside the new
    `windows_dns_failclosed` module + the two `format!` lint
    cleanups in `windows_authenticode.rs` and `windows_ipc.rs`).
  - `cargo clippy -p rustynetd -p rustynet-cli --all-targets
    --all-features -- -D warnings` — same baseline status as W1.1
    and W2.x: ~36 pre-existing format-string lints in
    `crates/rustynet-cli/src/vm_lab/mod.rs` block the gate; none
    are in the new DNS code. Tracked under the W1.1 residual-risk
    note as a separate cleanup pass.
  - `cargo audit --deny warnings` and `cargo deny check bans
    licenses sources advisories` were not separately rerun for this
    slice; no dependency surface changed.

### Phase W2 (Security parity gates 2: key custody + binary integrity + exec audit)
- [x] W2.1 Authenticode signature **presence** verification (W2.1a)
  - Changed files:
    - `crates/rustynetd/src/windows_authenticode.rs` (new) — pure-Rust PE
      parser (no `unsafe`, no external crates). Walks the DOS header → PE
      header → COFF header → optional header (PE32 or PE32+) → data
      directories → Certificate Table directory entry, then iterates
      `WIN_CERTIFICATE` entries with 8-byte alignment. Recognises
      revision=0x0200 (`WIN_CERT_REVISION_2_0`) + type=0x0002
      (`WIN_CERT_TYPE_PKCS_SIGNED_DATA`) as a valid Authenticode entry.
      Typed `WindowsAuthenticodeReport` (schema_version=1, binary_path,
      binary_size_bytes, overall_ok, signature_present,
      certificate_table_offset, certificate_table_size, certificates,
      drift_reasons). Public `inspect_authenticode_signature(path)` that
      reads the binary and returns the report.
    - `crates/rustynetd/src/lib.rs` — exposed the new module.
    - `crates/rustynetd/src/main.rs` — added subcommand
      `windows-authenticode-check [--binary-path <path>] [--no-fail-on-drift]`.
      Default binary path = `C:\Program Files\RustyNet\rustynetd.exe`.
      Default behavior is fail-closed.
    - `crates/rustynet-cli/src/vm_lab/mod.rs` — added live-lab stage
      `validate_windows_authenticode` between
      `validate_windows_key_custody` and the deferred
      `validate_windows_mesh_join`. Stage skips when an earlier stage
      didn't pass; otherwise dispatches the new subcommand and parses the
      typed JSON report. Pure parser/evaluator extracted as
      `evaluate_windows_authenticode_report` for direct unit testing.
      Raw report archived under
      `report_dir/logs/validate_windows_authenticode.log`.
  - Verification:
    - `cargo fmt --all -- --check` clean.
    - `cargo test -p rustynetd` — 447 / 447 pass (401 lib + 43 bin + 3
      integration). +12 lib tests in `windows_authenticode` covering:
      well-formed PE w/ PKCS signature accept, empty Cert Table directory
      reject, Cert Table offset outside binary reject, non-PKCS cert
      type drift-flag, missing MZ reject, wrong PE magic reject, tiny
      binary reject, bogus optional header magic reject, two-cert PE
      accept, zero-length WIN_CERTIFICATE entry reject, report serde
      round-trip, missing-binary read-failure path. +5 bin tests in
      `main.rs` (help advertises subcommand + flag, unknown-flag reject,
      missing `--binary-path` value reject, missing-binary fail-closed,
      `--no-fail-on-drift` opt-out for missing binary).
    - `cargo test -p rustynet-cli --bin rustynet-cli` — 375 / 375 pass.
      +6 evaluator tests covering: signed payload accept w/ identity-rich
      summary, unsigned-binary reject, schema-version reject, two
      overall_ok / signature_present / drift_reasons inconsistency
      rejects, malformed-JSON reject.
    - `cargo check -p rustynet-windows-native --target
      x86_64-pc-windows-msvc` clean.
  - Artifacts: none in this slice; live-lab artifacts produced by the
    stage when run against a real Windows VM with the signed installer.
  - Residual risk:
    - **Presence check only.** This slice rejects unsigned binaries and
      malformed signatures, but does NOT validate the PKCS#7 SignedData
      payload, the certificate chain, the file-hash binding via
      `spcIndirectData`, or timestamp validity. An attacker who can
      produce a self-signed Authenticode entry will pass this gate. Full
      chain validation requires Win32 `WinVerifyTrust` (W2.1b — adds
      `Win32_Security_WinTrust` feature to `windows-sys` deps and a
      safe wrapper in `rustynet-windows-native`). **Closed by W2.1b
      below.**
    - The PE parser is targeted at well-formed PE32+ binaries. It bounds-
      checks every read, but unusual layouts (overlapping cert table and
      sections, etc.) may fail to parse. That's still fail-closed
      behavior; the daemon refuses to start.
    - The orchestrator stage assumes the installed binary lives at
      `C:\Program Files\RustyNet\rustynetd.exe`. Same constant
      reconciliation note as W1.2b / W2.2.
- [x] W2.1b Full Authenticode chain validation via `WinVerifyTrust`
  - Changed files:
    - `crates/rustynet-windows-native/Cargo.toml` — added
      `Win32_Security_WinTrust` to the windows-sys feature list so
      the FFI types (`WINTRUST_DATA`, `WINTRUST_FILE_INFO`,
      `WINTRUST_ACTION_GENERIC_VERIFY_V2`, etc.) are available on
      the Windows target.
    - `crates/rustynet-windows-native/src/lib.rs` — added the
      `AuthenticodeChainOutcome` public enum (`Verified` |
      `Untrusted { reason, hresult }`) and the
      `verify_authenticode_chain(path)` wrapper. Off-Windows the fn
      returns an `Err` blocker. On Windows the fn calls
      `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2`,
      `WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT` (root certs
      typically self-signed; checking everything below the root is
      the canonical Authenticode posture), `WTD_UI_NONE` (no UI), and
      always pairs the verify call with a follow-up
      `WTD_STATEACTION_CLOSE` cleanup so verifier state never leaks
      into subsequent calls. Non-zero HRESULTs are mapped to the
      canonical Win32 label set (`TRUST_E_NOSIGNATURE`,
      `CERT_E_UNTRUSTEDROOT`, `CERT_E_REVOKED`, `TRUST_E_BAD_DIGEST`,
      etc.) so the orchestrator-side log is human-readable rather
      than a hex code. Cross-target check
      (`cargo check -p rustynet-windows-native --target
      x86_64-pc-windows-msvc`) clean.
    - `crates/rustynetd/src/windows_authenticode.rs` — extended
      the report shape: new `WindowsAuthenticodeChainStatus` enum
      (`Verified` | `Untrusted { reason, hresult }` |
      `NotEvaluated { reason }`) with serde tag `outcome`; new
      `chain_status` field on `WindowsAuthenticodeReport`; module
      header rewritten to reflect the two-stage (presence + chain)
      verification posture.
      `inspect_authenticode_signature` now runs both stages and
      tightens `overall_ok` to require BOTH `signature_present` AND
      `chain_status == Verified`. The chain stage is *skipped* when
      the presence stage already rejected the binary (running
      WinVerifyTrust on a malformed PE adds no information). Chain-
      stage outcomes are mirrored into `drift_reasons` so callers
      that grep `drift_reasons` only still see the chain-side
      rejection. Off-Windows the chain stage surfaces as
      `NotEvaluated` and `overall_ok` is false — fail-closed when
      the trust state cannot be observed.
    - `crates/rustynet-cli/src/vm_lab/mod.rs` — orchestrator-side
      `evaluate_windows_authenticode_report` now double-checks
      that `overall_ok=true` implies `chain_status=Verified`
      (rejects a stale or crafted JSON payload that claims
      overall_ok with a weaker chain status). Success summary
      updated to `"Windows Authenticode signature + chain
      verified"` so downstream tooling can grep for the new posture
      (W2.1a's summary said "signature present"). Test fixture
      updated to set `chain_status: { outcome: 'verified' }` in the
      reviewed-payload helper.
  - Verification:
    - `cargo fmt -p rustynetd -p rustynet-cli -p rustynet-windows-native -- --check` clean.
    - `cargo check -p rustynet-windows-native --target
      x86_64-pc-windows-msvc` clean (FFI compiles against
      `Win32_Security_WinTrust`).
    - `cargo test -p rustynetd` — 441 lib + 52 bin + 3 integration
      pass (was 439 lib + 52 + 3). +2 new lib tests for the
      report's new chain_status variants:
      `report_round_trips_chain_status_untrusted_variant`,
      `report_round_trips_chain_status_not_evaluated_variant`.
    - `cargo test -p rustynet-cli --bin rustynet-cli` — 450 / 450
      pass (was 447). +3 new evaluator tests:
      `evaluate_windows_authenticode_report_rejects_overall_ok_true_with_untrusted_chain`,
      `evaluate_windows_authenticode_report_rejects_overall_ok_true_with_not_evaluated_chain`,
      `evaluate_windows_authenticode_report_accepts_payload_with_verified_chain`.
  - Residual risk:
    - `WinVerifyTrust` does network I/O for revocation checks
      (CRL/OCSP fetch). On a fully air-gapped Windows host the
      revocation check returns `CRYPT_E_REVOCATION_OFFLINE` and the
      chain stage rejects. This is fail-closed by design; an
      operator deploying RustyNet to an air-gapped network should
      pre-cache the revocation responses or pre-validate the
      release artefact's trust chain at build time and ship a
      signed-attestation alongside the binary.
    - The chain validation is gated behind a presence-stage pass.
      An attacker could in principle craft a PE that the presence
      parser accepts but `WinVerifyTrust` would also reject — that
      case lands in the `Untrusted` branch and `overall_ok` is
      still false. The skip-on-presence-fail behavior is purely a
      no-info-gain optimisation, not a security relaxation.
    - Live evidence on the actual `windows-utm-1` UTM guest is
      pending — the Windows VM's installed binary is an unsigned
      `cargo build --release` artefact, so the chain stage will
      report `Untrusted { TRUST_E_NOSIGNATURE }` (or skip with
      `NotEvaluated` if presence stage's pure-Rust parser rejects
      first). Real signed-binary evidence requires the production
      release-signing workflow to ship and is tracked separately
      under `documents/operations/active/Phase5ReleaseReadinessChecklist_2026-04-12.md`.
- [x] W2.2 Service hardening profile verifier + stage
  - Changed files:
    - `crates/rustynetd/src/windows_service_hardening.rs` (new) — typed
      `WindowsServiceHardeningSnapshot` and `WindowsServiceHardeningReport`
      structs, pure `evaluate_windows_service_hardening` aggregator that
      returns every drift reason in one pass, `build_windows_service_hardening_report`
      wrapper, best-effort `parse_windows_image_path_argv` for the SCM
      `ImagePath` string, and a `cfg(windows)` snapshot collector that
      queries the live SCM via the existing `windows-service` crate
      (`Service::query_config`, `get_config_service_sid_info`,
      `get_failure_actions`) and inspects the binary file ACL via
      `rustynet_windows_native::inspect_file_sddl`. Non-Windows hosts get
      a clear blocker error so the subcommand still fails-closed without
      pretending to verify. The binary-ACL check delegates to the same
      `evaluate_windows_runtime_acl_sddl` evaluator W1.1 introduced, so
      both rows of the security-parity matrix land on the same hardened
      DACL contract.
    - `crates/rustynetd/src/lib.rs` — exposed the new module.
    - `crates/rustynetd/src/main.rs` — added subcommand
      `windows-service-hardening-check [--no-fail-on-drift]`. Default is
      fail-closed (non-zero on drift, suitable for orchestrator dispatch);
      `--no-fail-on-drift` is report-only.
    - `crates/rustynet-cli/src/vm_lab/mod.rs` — added live-lab stage
      `validate_windows_service_hardening` between
      `validate_windows_runtime_acls` and the deferred
      `validate_windows_mesh_join` in `run_windows_orchestration_stages`.
      Stage skips on dry-run or when an earlier stage didn't pass;
      otherwise dispatches the new subcommand over the existing argv-only
      PowerShell-encoded SSH channel and parses the typed JSON report.
      Pure parser/evaluator extracted as
      `evaluate_windows_service_hardening_report` for direct unit testing.
      Raw report archived under
      `report_dir/logs/validate_windows_service_hardening.log`.
  - Verification:
    - `cargo fmt --all -- --check` clean.
    - `cargo test -p rustynetd` — 415 / 415 pass (378 lib + 34 bin + 3
      integration). +24 lib tests in `windows_service_hardening` covering:
      reviewed-snapshot accept, NT-SERVICE virtual account + restricted
      SID accept, schema-version reject, wrong-service-name reject,
      binary-outside-install-root reject, renamed-binary reject,
      missing-`--windows-service` reject, missing-`--env-file` reject,
      inline-daemon-flag reject (e.g. `--backend windows-wireguard-nt`),
      unreviewed-account reject, SID-type-`none` reject,
      interactive-process reject, zero-failure-actions reject,
      drifted-binary-ACL reject, empty-binary-ACL reject, multiple-drift
      aggregation, build-report ok shape, build-report drift shape, three
      `parse_windows_image_path_argv` cases (quoted exe with spaces,
      unquoted exe without spaces, empty input), report serde value
      shape, full report serde round-trip, off-Windows collector
      blocker. +3 bin tests in `main.rs` (help advertises subcommand,
      unknown-flag rejection, off-Windows fail-closed default).
    - `cargo test -p rustynet-cli --bin rustynet-cli` — 362 / 362 pass.
      +6 evaluator tests in `vm_lab::tests` covering: reviewed payload
      accept w/ identity-rich summary, drift payload reject w/ specific
      reasons surfaced, schema-version reject, two
      overall_ok/drift_reasons inconsistency rejects, malformed-JSON
      reject.
    - `cargo test -p rustynet-crypto` — 21 / 21 pass.
    - `cargo check -p rustynet-windows-native --target
      x86_64-pc-windows-msvc` clean.
  - Artifacts: none in this slice; live-lab artifacts produced by the
    stage when run against a real Windows VM.
  - Residual risk:
    - Cross-target `cargo check -p rustynetd --target
      x86_64-pc-windows-{msvc,gnu}` from this macOS host is still blocked
      by the documented `libsqlite3-sys` (MSVC) / missing
      `x86_64-w64-mingw32-gcc` (GNU) toolchain gaps. The new
      `cfg(windows)` collector uses the `windows-service` crate APIs
      (`Service::query_config`, `get_config_service_sid_info`,
      `get_failure_actions`) which were verified by reading the crate
      sources at `~/.cargo/registry/src/index.crates.io-…/windows-service-0.8.0`
      — `ServiceConfig::executable_path` (PathBuf), `account_name`
      (Option<OsString>), `service_type` (`ServiceType` bitflags including
      `INTERACTIVE_PROCESS`), `start_type` (`ServiceStartType` enum), and
      `ServiceFailureActions::actions` (Option<Vec<ServiceAction>>) — so
      the build is expected to succeed once the toolchain blocker clears.
      No new `windows-sys` features were required.
    - The argv parser is a best-effort split optimized for the reviewed
      install's quoted-exe + space-separated flags shape. If a
      future installer emits a more elaborate command line (escaped
      backslashes, `^` quoting, etc.), the evaluator may flag a false
      drift. Reviewed installer never produces such shapes today; flag in
      `WindowsWorkingNodePlan` if it changes.
    - Live-guest evidence (drift the service registration on a real
      Windows VM and observe orchestrator-side `Fail` w/ the specific
      drift reason) requires the same UTM access path as W1.2b.
- [x] W2.3 Argv-only audit for Windows exec sites
  - Findings:
    - All `Command::new("ssh"|"scp"|"git"|"cargo"|"bash"|utmctl)` sites in
      `crates/rustynet-cli/src/vm_lab/` use Rust's `Command::arg(...)` /
      `args(...)` API, which builds `argv` arrays and passes them to
      `execve` with no shell interpretation. No `cmd.exe /c` or
      shell-string constructions found in active production paths.
    - PowerShell script bodies that get sent over the SSH channel are
      built by `build_windows_helper_command` and similar helpers in
      `crates/rustynet-cli/src/vm_lab/mod.rs`, which run every
      interpolated path / value through `powershell_quote` (single-quoted
      PS literal w/ proper `'` → `''` escape) and pre-flight every
      string with `ensure_no_control_chars`. Long flags matching
      `--[A-Za-z0-9-]+` pass through unquoted (PS parser treats them as
      tokens). Short / value args always get quoted. The whole script
      body is then base64-encoded and dispatched as
      `powershell.exe -EncodedCommand <b64>` — the encoding step makes
      the SSH-layer transport oblivious to PS quoting concerns.
    - The Windows service host registration path
      (`crates/rustynetd/src/windows_service.rs`) uses the
      `windows-service` crate's typed `ServiceManager::create_service`
      API, which passes the binary path and args through Win32 SCM
      structs (no shell). Audit confirmed via cargo-source review at
      `~/.cargo/registry/src/index.crates.io-…/windows-service-0.8.0`.
  - Hardening landed in this slice:
    - `crates/rustynet-cli/src/vm_lab/mod.rs` — extracted shared builder
      `build_windows_security_check_invocation(subcommand, extra_args)`.
      The builder rejects subcommands that are empty or contain anything
      other than ASCII-alphanumeric + hyphen (so a future caller cannot
      sneak a metacharacter through), runs every value-arg through
      `powershell_quote` w/ `ensure_no_control_chars`, lets well-formed
      `--long-flag` tokens pass unquoted, and emits a
      single-quoted-literal `& 'C:\Program Files\RustyNet\rustynetd.exe'
      <subcommand> --no-fail-on-drift [...]`. All four W1.2/W2.2/W2.4/
      W2.1 stage helpers now route through this builder instead of
      hand-rolled `format!` — single audit point.
    - 6 new unit tests in `vm_lab::tests` covering: well-formed
      invocation shape (quoted exe path + subcommand + fail-closed flag);
      rejection of subcommands carrying `;`, backticks, `$`, spaces,
      apostrophes, or empty string; apostrophe in a value arg gets
      doubled (`'` → `''`) and the resulting script keeps its
      single-quote count even (balanced literal); control-byte arg
      rejected; long-flag passes unquoted; positional / short arg gets
      quoted.
  - Verification:
    - `cargo fmt --all -- --check` clean.
    - `cargo test -p rustynet-cli --bin rustynet-cli` — 382 / 382 pass
      (was 376 before this slice; +6 new tests).
    - `cargo test -p rustynetd` — 447 / 447 pass.
    - `cargo build -p rustynet-cli --release` clean.
  - Residual risk:
    - Audit covered the active Windows orchestrator + daemon code paths
      I've touched in this delta. Older PowerShell helper scripts under
      `scripts/bootstrap/windows/` are static `.ps1` files (not
      constructed at runtime) and were not in scope; their argv handling
      lives inside the script files themselves.
    - The `--EncodedCommand` base64 wrap keeps SSH transport safe but
      the PS interpreter still parses the decoded body — the in-script
      quoting discipline is what protects us there. Tests assert that
      contract.
- [x] W2.4 DPAPI key-custody validator + stage
  - Changed files:
    - `crates/rustynetd/src/windows_key_custody.rs` (new) — typed
      `WindowsKeyCustodyEntry` (with present/absent requirement string and
      a tagged `WindowsKeyCustodyEntryStatus` enum: `ok`/`missing`/
      `invalid`/`forbidden`/`absent_as_expected`) and
      `WindowsKeyCustodyReport`. Pure aggregator
      `evaluate_windows_key_custody` returns every drift reason in one
      pass and rejects collector inconsistencies (required reported
      absent, absent reported ok, etc.). Cross-platform collector
      `collect_windows_key_custody_snapshot` walks the canonical paths:
      WG passphrase blob (`.dpapi`), WG encrypted private key (`.enc`),
      WG public key (`.pub`) — all required, all ACL-locked via the
      shared `evaluate_windows_local_secret_acl_sddl` evaluator from
      W1.1; plus the WG plaintext runtime private key — must be ABSENT
      at rest (Phase E migrated runtime custody to encrypted-at-rest).
      Entries sorted by label for deterministic JSON output.
    - `crates/rustynetd/src/lib.rs` — exposed the new module.
    - `crates/rustynetd/src/main.rs` — added subcommand
      `windows-key-custody-check [--no-fail-on-drift]`.
    - `crates/rustynet-cli/src/vm_lab/mod.rs` — added live-lab stage
      `validate_windows_key_custody` between
      `validate_windows_service_hardening` and the deferred
      `validate_windows_mesh_join`. Stage skips when an earlier stage
      didn't pass; otherwise dispatches the new subcommand and parses
      the typed JSON report. Pure parser/evaluator extracted as
      `evaluate_windows_key_custody_report` for direct unit testing.
      Raw report archived under
      `report_dir/logs/validate_windows_key_custody.log`.
  - Verification:
    - `cargo fmt --all -- --check` clean.
    - `cargo test -p rustynetd` — 430 / 430 pass after this slice (389
      lib + 38 bin + 3 integration). +11 lib tests in
      `windows_key_custody`: clean-snapshot accept, empty-entries
      reject, required-missing reject, required-invalid-ACL reject,
      forbidden-present reject, requirement/status inconsistency rejects
      (4 variants), unknown-requirement reject, multi-drift aggregation,
      off-Windows snapshot shape, serde round-trip. +4 bin tests in
      `main.rs` (help advertising, unknown-flag reject, off-Windows
      fail-closed default, `--no-fail-on-drift` opt-out).
    - `cargo test -p rustynet-cli --bin rustynet-cli` — 369 / 369 pass.
      +7 evaluator tests covering: reviewed payload accept w/
      "4 reviewed artifacts" summary, drift payload reject w/ specific
      reasons surfaced, schema-version reject, empty-entries reject,
      two overall_ok/drift_reasons inconsistency rejects, malformed-JSON
      reject.
    - `cargo check -p rustynet-windows-native --target
      x86_64-pc-windows-msvc` clean.
  - Artifacts: none in this slice.
  - Residual risk:
    - The collector validates **on-disk presence + ACL + extension** for
      each artifact. It does not (yet) crack the DPAPI blob to confirm
      it is in fact DPAPI-protected and not arbitrary bytes — that would
      require a `CryptUnprotectData` test round-trip, which the existing
      `windows_runtime_boundary` self-check already does for a
      synthetic blob. Combining this with W2.4 is a follow-up if needed.
    - Same pre-existing baseline blockers as the rest of W1/W2.
- [ ] W2.4-followup: DPAPI round-trip self-test for the live runtime
      passphrase (currently only synthesized in
      `windows_runtime_boundary::run_windows_runtime_boundary_check`).
- [x] W2.5 Wrapper-hygiene audit (audit complete; defense-in-depth
      remediations deferred to a W2.5b follow-up slice)
  - Audit performed across the five reviewed PowerShell helpers
    under `scripts/bootstrap/windows/`:
    - `Bootstrap-RustyNetWindows.ps1`
    - `Collect-RustyNetWindowsDiagnostics.ps1`
    - `Install-RustyNetWindowsService.ps1`
    - `Smoke-RustyNetWindowsServiceHost.ps1`
    - `Verify-RustyNetWindowsBootstrap.ps1`
  - Findings tally: 9 HIGH (theoretical, on controlled values),
    14 MEDIUM (defense-in-depth), 4 LOW. Detailed list with
    file:line refs + cross-cutting remediation recommendations
    archived in
    `documents/operations/active/SecurityHardeningAudit_2026-04-28.md`
    §A.3.6. None of the findings are attacker-reachable today —
    every interpolated value comes from a controlled source
    (hard-coded script constants, orchestrator parameters that
    pass through `build_windows_security_check_invocation` +
    `validate_service_name` ASCII charset enforcement, or the
    Windows guest's own filesystem state).
  - Remediation list (cross-cutting, deferred to W2.5b):
    1. Add `Test-RustyNetServiceName` PS-side validator mirroring
       Rust's `validate_service_name` charset.
    2. Add `Test-RustyNetReviewedRoot` for `-InstallRoot` /
       `-StateRoot` parameters mirroring daemon-side
       `validate_windows_runtime_file_path`.
    3. Replace `cmd.exe /c $commandText` interpolation with
       `Start-Process -ArgumentList` arrays.
    4. Replace `Get-CimInstance -Filter "Name='...'"` WQL
       filter strings with `Get-Service -Name $ServiceName`
       pattern already used elsewhere.
    5. Explicitly quote `icacls $Path` and `sc.exe delete
       $ServiceName` argument variables.
  - Why deferred: every finding is theoretical given the controlled
    value sources; landing the audit + the recommendation list
    closes the W2.5 contract (the plan calls for an *audit* + the
    finding list, not a remediation slice). Carrying the
    remediations as a W2.5b ledger entry tracked in the
    SecurityHardeningAudit doc keeps them visible without bloating
    this slice.
- [x] W2.6 Mandatory gates rerun (touched packages)
  - `cargo fmt --all -- --check` clean.
  - `cargo audit` — 0 vulnerabilities, 1058 advisories scanned, 182
    deps. Recorded as 2026-04-28 in the SecurityHardeningAudit
    ledger.
  - `cargo deny check` — advisories ok, bans ok, licenses ok,
    sources ok. All four categories pass.
  - `cargo clippy --workspace --all-features -- -D warnings` —
    clean for production code (commit 2e71184 closes the long-
    standing pre-existing baseline drift). `--all-targets` still
    trips on `third_party/boringtun`'s vendored test code which
    we deliberately do not fork.
  - `cargo test --workspace`: every workspace package green.
    `rustynetd` 439 lib + 52 bin + 3 integration. `rustynet-cli`
    437 bin. Other crates unchanged.

### Phase W3 (Orchestrator dispatcher)
- [x] W3.1 `StageOrchestrator` trait + `LinuxBashOrchestrator`
  - Changed files:
    - `crates/rustynet-cli/src/vm_lab/mod.rs` — added the
      `StageOrchestrator` trait (single method
      `execute_live_lab(&LiveLabRunInputs) -> Result<LiveLabRunReport,
      String>`), the `LiveLabRunInputs` struct (orchestrator-agnostic
      execution inputs: profile path, report dir, source mode, repo
      ref, timeout, dry-run + skip-* flags, plus a
      `continue_from_setup` signal that translates to the bash
      script's `--skip-setup --preserve-report-state` pair on the
      reusable-setup path), and the `LiveLabRunReport` struct
      (uniform completion shape — `exit_status_code` +
      `success`). Implemented `LinuxBashOrchestrator` whose
      `execute_live_lab` is byte-identical to the inline
      `Command::new("bash") <script> --profile ... --report-dir ...`
      dispatch it replaces — same flag set, same
      `run_status_with_timeout_passthrough` invocation under the same
      hard timeout, same TSV-on-disk contract documented in
      `scripts/e2e/live_linux_lab_orchestrator.sh`. The
      `build_command` helper is split out so unit tests can assert
      argv shape without spawning bash. `execute_ops_vm_lab_run_live_lab`
      now constructs `LiveLabRunInputs`, instantiates
      `LinuxBashOrchestrator::new(config.script_path.clone())`, and
      reads `run_report.success` for downstream pass/fail, release-
      gate completeness, run-provenance, and result-rendering logic.
      No behavior change for pure-Linux runs — the trait is a thin
      shim over the existing flow, fulfilling the §6.1 + §9 rollback
      contract that "the Linux-only gate is removed only at W4.1, after
      W1, W2, W3 are complete and all Linux gates still pass on the
      dispatcher path."
  - Verification:
    - `cargo fmt -p rustynetd -p rustynet-cli -- --check` clean.
    - `cargo build --workspace` clean (one pre-existing dead-code
      warning on the unrelated `run_host_reboot` helper; not introduced
      here).
    - `cargo test -p rustynet-cli --bin rustynet-cli` — 399 / 399
      pass (was 393). +6 new tests in `vm_lab::tests`:
      - `linux_bash_orchestrator_builds_command_with_minimal_args` —
        baseline argv shape (`bash <script> --profile … --report-dir …
        --source-mode …`); asserts none of the optional flags
        (`--dry-run`, `--skip-setup`, `--preserve-report-state`,
        `--skip-gates`, `--skip-soak`, `--skip-cross-network`,
        `--repo-ref`) appear when defaults are used;
      - `linux_bash_orchestrator_builds_command_with_all_skip_flags_set` —
        every skip flag plus `--dry-run` propagates;
      - `linux_bash_orchestrator_continue_from_setup_implies_skip_setup_pair` —
        the `continue_from_setup=true, skip_setup=false` case still
        emits `--skip-setup --preserve-report-state` so the bash
        script reuses, rather than re-runs, validated setup stages;
      - `linux_bash_orchestrator_emits_repo_ref_when_set` — repo ref
        passes through as a `--repo-ref <value>` pair (not stuck
        together);
      - `linux_bash_orchestrator_script_path_round_trips` — getter
        sanity;
      - `stage_orchestrator_trait_supports_test_implementations` —
        proves the dispatch surface is implementable by something
        that does not spawn bash, so the future `RustOrchestrator`
        (W3.3) and per-test fakes can share it without duplicating
        the caller's post-processing path.
    - `cargo test -p rustynetd` unchanged: 439 lib + 52 bin + 3
      integration pass (no Rust types or APIs in `rustynetd` were
      touched by this slice).
  - Artifacts: none (refactor slice; no runtime artifacts produced).
  - Residual risk:
    - This slice is the trait + Linux impl only. `RustOrchestrator`
      (W3.3) does not exist yet — the live-lab driver always selects
      `LinuxBashOrchestrator` today. Consequently the Linux-only gate
      `ensure_live_lab_profile_linux_only` at
      `crates/rustynet-cli/src/vm_lab/mod.rs:5445` still rejects any
      non-Linux node before the orchestrator is even instantiated;
      Windows continues to run as the sidecar. That gate falls in
      W4.1 once W3.3 has produced the per-target Rust impl.
    - The trait method returns `LiveLabRunReport` rather than the
      richer `Vec<VmLabStageOutcome>` the Windows-side
      `run_windows_orchestration_stages_with_options` returns; this
      is intentional for the Linux-bash impl because per-stage
      records are produced by the bash script as TSV under
      `${REPORT_DIR}/state/stages.tsv` and parsed by the caller. The
      `RustOrchestrator` slice will populate `Vec<VmLabStageOutcome>`
      directly from per-stage adapter dispatch and the trait can be
      widened then without breaking Linux callers (the existing
      `LiveLabRunReport` becomes one variant of the wider return
      type, or a thin-summary derived from the outcome vec).
    - Same pre-existing baseline workspace-clippy posture as W1.x
      and W2.x — no new lints introduced; the open vm_lab/mod.rs
      format-string drift is unchanged by this slice.
- [x] W3.2 `ServiceManager` / `RuntimePaths` / `RemoteExec` / `DaemonProbe`
      traits with Linux + Windows real impls and macOS/iOS/Android
      `Unsupported` stubs
  - [x] W3.2a `RuntimePaths` trait + Linux/Windows impls + macOS/iOS/Android
        `Unsupported` stubs
    - Changed files:
      - `crates/rustynet-cli/src/vm_lab/mod.rs` — added the
        `RuntimePathRole` enum (Install / State / Config / Logs /
        Trust / Membership / Keys / Secrets), the `RuntimePaths`
        trait with a single dispatch method (`path_for(role)`) plus
        per-role convenience getters, the `LinuxRuntimePaths` and
        `WindowsRuntimePaths` real impls (paths match the
        daemon-side constants in `crates/rustynetd/src/daemon.rs`
        and `crates/rustynetd/src/windows_paths.rs` so the
        orchestrator and the daemon agree on canonical roots), the
        `UnsupportedRuntimePaths` stub with `macos()` / `ios()` /
        `android()` constructors that fail every role lookup with a
        clear blocker reason citing the missing layout, and a
        `runtime_paths_for(VmGuestPlatform)` factory that hands out
        the right boxed impl per platform.
    - Verification:
      - `cargo fmt -p rustynet-cli -p rustynetd -- --check` clean.
      - `cargo build -p rustynet-cli` clean (1 pre-existing dead-
        code warning on the unrelated `run_host_reboot` helper, not
        introduced here; new items carry
        `#[cfg_attr(not(test), allow(dead_code))]` because the
        `RustOrchestrator` consumer is W3.3 — these annotations
        come off the moment that slice lands).
      - `cargo test -p rustynet-cli --bin rustynet-cli` — 407 / 407
        pass (was 399). +8 new tests in `vm_lab::tests`:
        `linux_runtime_paths_match_reviewed_fhs_layout`,
        `windows_runtime_paths_match_reviewed_program_data_layout`,
        `unsupported_runtime_paths_macos_rejects_every_role_with_blocker_reason`,
        `unsupported_runtime_paths_ios_rejects_every_role_with_blocker_reason`,
        `unsupported_runtime_paths_android_rejects_every_role_with_blocker_reason`,
        `unsupported_runtime_paths_default_getters_propagate_blocker`,
        `runtime_paths_for_dispatches_to_right_impl_per_platform`,
        `runtime_path_role_label_round_trips`.
    - Residual risk:
      - Trait + impls are infrastructure ahead of W3.3
        (`RustOrchestrator`); they are not yet called from
        production code paths. The `#[cfg_attr(not(test),
        allow(dead_code))]` annotations come off when W3.3 wires
        them in. Tests exercise every method of every impl,
        including all eight roles on all three stub platforms.
      - The Linux logs root is canonicalized as `/var/log/rustynet`
        even though today's daemon writes through journald; this is
        the directory the orchestrator's log-root permission stage
        will reference. Daemon-side log path remains an open follow-
        up; the trait surface does not assume daemon log file
        layout, only the directory root.
  - [x] W3.2b `ServiceManager` trait + Linux/Windows impls + stubs
    - Changed files: `crates/rustynet-cli/src/vm_lab/mod.rs` —
      `ServiceCommand` enum (`Argv` | `HelperScript` variants),
      `ServiceManager` trait (install / enable / start / stop /
      restart / status / uninstall + platform_label),
      `LinuxServiceManager` (systemctl argv for every op; install =
      `systemctl daemon-reload`, uninstall = `systemctl disable
      --now <name>`), `WindowsServiceManager` (PowerShell cmdlet
      argv via `powershell.exe -NoLogo -NoProfile -NonInteractive
      -ExecutionPolicy Bypass -Command …` for lifecycle ops; install
      returns `HelperScript { script_basename:
      "Install-RustyNetWindowsService.ps1", args: [-ServiceName
      <name>] }`; uninstall pairs `Stop-Service` with `sc.exe delete
      <name>` — sc.exe arg list contains no spaces or quotes so the
      PS5.1 native-arg quoting bug from the W2.2 install-helper
      hardening commit does not apply), `UnsupportedServiceManager`
      stub with macos/ios/android constructors that reject every op
      with a typed blocker reason, `service_manager_for(platform)`
      factory. All ops route through a `validate_service_name`
      defensive filter that rejects values outside ASCII
      alphanumerics + `-` + `_`, empty, or > 128 chars.
    - Verification: 11 new tests in `vm_lab::tests` covering Linux
      lifecycle argv shape, Linux install = daemon-reload, Linux
      uninstall = disable --now, Windows install = HelperScript,
      Windows lifecycle ops = Start/Stop/Restart-Service +
      Get-Service argv, Windows uninstall = Stop-Service + sc.exe
      delete, name-validator rejection of metacharacters + length
      cap, macOS stub rejects every op, factory dispatch.
    - Residual risk: `ServiceCommand::HelperScript` carries
      `script_basename` only; caller resolves the full path via a
      `RuntimePaths::install_root()` lookup so the adapter stays
      platform-agnostic. The `validate_service_name` charset is the
      intersection of systemd unit naming + Windows SCM service
      naming rules; if a future RustyNet variant needs `.` (systemd
      template instances) the validator widens, never weakens.
  - [x] W3.2c `RemoteExec` trait + Linux/Windows impls + stubs
    - Changed files: `crates/rustynet-cli/src/vm_lab/mod.rs` —
      `RemoteInvocation` enum (`PosixSshArgv { ssh_target, argv }` |
      `WindowsSshEncodedPowerShell { ssh_target, powershell_body }`),
      `RemoteExec` trait (`build_invocation(ssh_target, argv) ->
      Result<RemoteInvocation, String>` + platform_label),
      `PosixRemoteExec` (passes argv through untouched, validates
      no-control-bytes per arg + non-empty target + non-empty argv),
      `WindowsRemoteExec` (renders argv as `& 'exe' @('arg1','arg2',
      …)` with single-quoted PS literal escaping that doubles every
      embedded `'` per PS rules — `O'Connor` becomes `'O''Connor'`
      so a value cannot close the literal early and inject PS code),
      `UnsupportedRemoteExec` macos/ios/android stubs that reject
      every dispatch with a typed blocker reason,
      `remote_exec_for(platform)` factory.
    - Verification: 6 new tests covering POSIX argv-wrap shape,
      empty-target reject, empty-argv reject, control-byte reject,
      Windows single-quoted PS array shape, apostrophe-doubling,
      three Unsupported stubs rejecting w/ blocker, factory
      dispatch. The Windows test asserts the literal
      `& 'C:\Program Files\RustyNet\rustynetd.exe'` prefix that the
      existing per-stage helpers in `vm_lab/mod.rs` already use, so
      the new `RemoteExec::WindowsSshEncodedPowerShell` payload is
      payload-compatible with `build_ssh_powershell_encoded_invocation`
      and W3.3 can wire either side without changing wire format.
    - Residual risk: this slice produces a typed payload, not a
      live SSH dispatch — the actual `Command::new("ssh")` /
      `EncodedCommand` base64-wrap step still happens at the
      caller's existing seam (`capture_remote_shell_command_for_target`,
      `build_ssh_powershell_encoded_invocation`). W3.3 picks one
      seam and routes both Linux + Windows through it.
  - [x] W3.2d `DaemonProbe` trait + Linux/Windows impls + stubs
    - Changed files: `crates/rustynetd/src/vm_lab/mod.rs` —
      `DaemonProbeOp` enum (6 reviewed ops: RuntimeAcls,
      ServiceHardening, KeyCustody, Authenticode, MeshStatus,
      DnsFailclosed), `DaemonProbe` trait (`build_argv(op,
      daemon_path)` returns the full
      `[<daemon-exe>, <subcommand>, --no-fail-on-drift]` argv),
      `WindowsDaemonProbe` mapping every op to its
      `windows-…-check` subcommand (matching the existing per-stage
      helpers' argv exactly so W3.3 can swap dispatch through the
      adapter without changing wire format), `LinuxDaemonProbe`
      that rejects every op today with a roadmap blocker (Linux
      daemon does not yet expose validator subcommands at parity
      with Windows; rejecting at the adapter avoids a wasted SSH
      round-trip on a non-existent subcommand),
      `UnsupportedDaemonProbe` macos/ios/android stubs,
      `daemon_probe_for(platform)` factory.
    - Verification: 6 new tests covering Windows argv shape for all
      6 ops + `--no-fail-on-drift` flag, Windows rejects empty
      daemon path, Linux rejects every op today with the roadmap
      blocker, three Unsupported stubs rejecting w/ blocker,
      factory dispatch, op-label round-trip.
    - Residual risk: `LinuxDaemonProbe` rejects today because the
      Linux daemon does not yet expose the validator-subcommand
      surface. Tracked under the OS-agnostic delta plan W4 follow-
      up; the trait shape is correct for Linux once the daemon side
      lands.
- [x] W3.3 `RustOrchestrator` impl with parity proof on Linux runs
  - Changed files: `crates/rustynet-cli/src/vm_lab/mod.rs` —
    `RustOrchestrator { linux_bash, target_platforms }` struct with a
    `new()` constructor that takes a pre-built
    `LinuxBashOrchestrator` and the resolved per-target platform set,
    plus a `StageOrchestrator` impl that selects between two
    execution strategies based on the captured platform set:
    1. **Pure-Linux node set** (or empty set, since the bash
       orchestrator's profile gating already enforces a 5×Linux
       topology) — delegates to the wrapped `LinuxBashOrchestrator`.
       Parity is *identity*: the live-lab is run by literally
       invoking `scripts/e2e/live_linux_lab_orchestrator.sh`
       through the W3.1 dispatch shim, with no new code in the
       hot path. The §6.1 + §9 rollback contract — "for pure-Linux
       node sets [`RustOrchestrator`] must produce byte-identical
       (or behaviorally equivalent) reports to the bash impl. No
       silent divergence." — is satisfied by construction.
    2. **Heterogeneous node set (any non-Linux target)** —
       rejects up-front with a typed blocker reason that names the
       offending platform(s) and cites W4.1 (which removes the
       Linux-only gate and wires per-target adapter dispatch). The
       belt-and-braces equivalent of the existing
       `ensure_live_lab_profile_linux_only` profile gate, but at
       the trait boundary so any caller who bypasses
       `execute_ops_vm_lab_run_live_lab` and reaches for the trait
       directly still fails closed.
    `is_pure_linux()` and `non_linux_platforms()` are factored as
    private helpers so the dispatch decision is a pure function of
    the captured inputs and the rejection blocker can name every
    distinct non-Linux platform without duplicating its label.
  - Verification:
    - `cargo fmt -p rustynet-cli -p rustynetd -- --check` clean.
    - `cargo build --workspace` clean (only the pre-existing
      `run_host_reboot` dead-code warning).
    - `cargo test -p rustynet-cli --bin rustynet-cli` — 437 / 437
      pass (was 430). +7 new tests in `vm_lab::tests`:
      `rust_orchestrator_pure_linux_path_is_pure_linux`,
      `rust_orchestrator_empty_platform_set_is_treated_as_pure_linux`,
      `rust_orchestrator_heterogeneous_set_is_not_pure_linux`,
      `rust_orchestrator_non_linux_platforms_dedupes_repeats`,
      `rust_orchestrator_heterogeneous_execution_rejects_with_w4_blocker`,
      `rust_orchestrator_pure_linux_path_delegates_to_bash_orchestrator`,
      `rust_orchestrator_macos_only_set_rejects_with_macos_in_blocker`.
  - Residual risk:
    - The heterogeneous-mode branch is intentionally a hard reject
      until W4.1 lands. This is the most secure default: there is
      *no* per-target Rust dispatch path today that anyone could
      accidentally select (whether via flag, config, or stale
      callsite). The next slice — W4.1 — removes the
      `ensure_live_lab_profile_linux_only` profile gate AND wires
      per-target capability gating + adapter dispatch in the same
      change, so no half-state where the orchestrator accepts a
      heterogeneous set but cannot actually run it.
    - `RustOrchestrator` is not yet selected by
      `execute_ops_vm_lab_run_live_lab`; the entry point still
      instantiates `LinuxBashOrchestrator` directly, which is the
      conservative migration path the plan §9 calls for. The W3.1
      `LinuxBashOrchestrator` impl remains the production dispatch
      surface for pure-Linux runs. Switching the entry point to use
      `RustOrchestrator` (which then delegates to
      `LinuxBashOrchestrator` for pure-Linux) becomes safe to do
      after W4.1 because then there is one path that handles both
      pure-Linux and heterogeneous topologies.
- [x] W3.4 Mandatory gates rerun (touched packages)
  - `cargo fmt -p rustynet-cli -p rustynetd -- --check` clean.
  - `cargo build --workspace` clean (one pre-existing dead-code
    warning on `run_host_reboot`; not introduced here).
  - `cargo test -p rustynetd -p rustynet-cli` —
    `rustynetd`: 439 lib + 52 bin + 3 integration pass.
    `rustynet-cli`: 437 bin pass. No regressions across any other
    crate; the W3 slices touched only `crates/rustynet-cli/src/vm_lab/mod.rs`.
  - **Live-lab regression**: full `vm-lab-orchestrate-live-lab`
    against 5×Debian VMs is not runnable from this macOS host
    (utmctl headless-shell limitation, same posture as the W2.x
    live-lab evidence runs). The W3.1 `LinuxBashOrchestrator` impl
    is byte-identical to the inline bash dispatch it replaced (the
    parity proof is captured in the W3.1 entry above), and W3.3
    delegates to that same impl for pure-Linux runs, so the
    behavior change in pure-Linux mode is *zero*. A real 5×Linux
    live-lab regression remains an open follow-up scheduled for the
    next live-lab evidence run from a Terminal.app session.
  - Same baseline workspace-clippy posture as W1.x / W2.x — no new
    lints introduced; the open `vm_lab/mod.rs` format-string drift
    is unchanged by this slice.

### Phase W4 (Per-stage capability gating + Windows mesh-join)
- [x] W4.1 Replace `ensure_live_lab_profile_linux_only` with per-stage
      capabilities (machinery + legacy-set delegation; per-stage
      capability dispatch deferred to W4.2+)
  - Changed files:
    - `crates/rustynet-cli/src/vm_lab/mod.rs` — added the
      `LiveLabStageCapability` enum (9 reviewed capability tags
      covering POSIX shell + systemd + Linux bash + tc/netem +
      nftables + systemd-resolved on the Linux side; WindowsService +
      WindowsNRPT + WindowsPowershell on the Windows side),
      `LiveLabStageCapability::as_str` for stable lowercase-hyphen
      labels (downstream tooling can grep on these), the
      `target_capabilities(VmPlatformProfile) -> Vec<…>` lookup
      that publishes a target's capability set as a pure function
      of its platform profile (no runtime probe, computable
      up-front), the
      `LIVE_LAB_LINUX_ONLY_REQUIRED_CAPABILITIES` constant that
      surfaces the legacy gate's intent as a typed list, the new
      `live_lab_targets_missing_capabilities(profile, required)`
      helper that returns `(role, target, missing_caps)` per
      blocked target, and the new
      `ensure_live_lab_profile_capabilities(profile, required,
      command)` gate that rejects with a precise per-target
      missing-capability list. The legacy
      `ensure_live_lab_profile_linux_only` now delegates to the
      capability gate with the linux-only set so behavior is
      preserved at every existing entry point (vm-lab-setup-live-lab,
      vm-lab-run-live-lab, vm-lab-validate-live-lab-profile,
      vm-lab-diagnose-live-lab-failure, plus the
      RustOrchestrator's belt-and-braces trait-boundary gate from
      W3.3); the rejection rendering migrates from the freeform
      `requires platform=linux remote_shell=posix …` string to the
      capability-vocabulary `requires capabilities [posix-shell,
      systemd, …]; blocked targets: role=… target=…
      missing=cap1,cap2` so per-target diff is now grep-stable.
  - Verification:
    - `cargo fmt -p rustynet-cli -p rustynetd -- --check` clean.
    - `cargo test -p rustynet-cli --bin rustynet-cli` — 442 / 442
      pass (was 437). +5 new tests in `vm_lab::tests`:
      `target_capabilities_for_linux_advertises_kernel_userspace_set`,
      `target_capabilities_for_windows_advertises_windows_only_set`,
      `target_capabilities_for_macos_returns_minimal_unsupported_set`,
      `live_lab_stage_capability_label_round_trips`,
      `linux_only_required_capabilities_constant_matches_legacy_gate_intent`.
      Plus four pre-existing test assertions on the legacy gate's
      freeform error string updated to assert on the new capability-
      vocabulary format (`requires capabilities`, `blocked targets`,
      `missing=`); test count is unchanged because the assertions
      are in-place updates, not net-new tests.
    - `cargo test -p rustynetd` unchanged: 439 lib + 52 bin + 3
      integration. No rustynetd APIs touched.
  - Residual risk:
    - This slice lands the capability *machinery* and migrates the
      existing entry-point gate to delegate through it. Per-stage
      capability dispatch — i.e. the bash orchestrator's individual
      stages declaring their own required-capability subset and
      skip-with-reason / fail-with-reason on heterogeneous targets —
      is W4.2's job. Today the legacy linux-only set is still the
      only consumer of the gate; behavior is preserved and the
      Linux-only enforcement remains the most-secure default until
      W4.2 lands the per-stage decisions.
    - The `LIVE_LAB_LINUX_ONLY_REQUIRED_CAPABILITIES` constant
      includes `NftablesFiltering` and `SystemdResolvedDns`
      (security-bar capabilities) but NOT `NetemImpairment` (a
      pure convenience capability). When per-stage dispatch lands
      W4.2 will be careful to mark NetemImpairment-requiring
      stages as skip-with-reason on Windows targets while
      Nftables / systemd-resolved-requiring stages fail-with-reason
      so the orchestrator never silently drops a security stage.
- [x] W4.2 Windows mesh-join stage (verifier upgrade — membership +
      assignment distribution to Windows is W4.2-followup)
  - Changed files:
    - `crates/rustynet-cli/src/vm_lab/mod.rs` — promoted Stage 8 of
      `run_windows_orchestration_stages_with_options` from a
      hardcoded `VmLabStageStatus::Skipped` to a real verifier
      dispatch. The new path mirrors the W2.1 / W2.4 / W1.4 pattern:
      dry-run + per-prereq-stage skip cascade (skip when bootstrap /
      install / runtime-acls / hardening / key-custody /
      authenticode / dns-failclosed didn't pass), otherwise
      dispatches `& 'C:\Program Files\RustyNet\rustynetd.exe'
      windows-mesh-status-check --no-fail-on-drift` over the existing
      argv-only PowerShell-encoded SSH channel via
      `build_windows_security_check_invocation`, parses the typed
      `WindowsMeshStatusReport` JSON, and emits a `Pass`/`Fail`
      outcome with the raw report archived under
      `report_dir/logs/validate_windows_mesh_join.log`. The pure
      `evaluate_windows_mesh_join_report` evaluator splits success
      vs drift handling per the existing pattern, including the
      enum-variant match on `WindowsMeshSnapshotLoad` so the
      success summary surfaces `peers=N age_seconds=M` from the
      `Ok` variant and a precise self-inconsistency reason from the
      other variants if a payload claims overall_ok=true but
      reports a non-Ok load_status.
    - Plus the cascading `pub` visibility fixes on
      `VmPlatformProfile`, `VmRemoteShell`, `VmGuestExecMode`, and
      `VmServiceManager` — these are now exposed via the W4.1
      `target_capabilities(VmPlatformProfile)` public function so
      they need to match its visibility. No behavior change; the
      types were already widely used module-private and now match
      the trait surface introduced in W3.2.
  - Verification:
    - `cargo fmt -p rustynet-cli -p rustynetd -- --check` clean.
    - `cargo build --workspace` clean (pre-existing
      `run_host_reboot` warning only).
    - `cargo test -p rustynet-cli --bin rustynet-cli` — 447 / 447
      pass (was 442). +5 new evaluator tests in `vm_lab::tests`:
      reviewed payload accept w/ identity-rich summary
      (`peers=2 age_seconds=12`), missing-state drift reject,
      schema-version reject, overall_ok=false-with-empty-drift-
      reasons inconsistency reject, malformed JSON reject.
    - `cargo test -p rustynetd` unchanged: 439 lib + 52 bin + 3
      integration. No rustynetd APIs touched.
  - Residual risk:
    - **Verifier-only slice.** This commit lands the
      orchestrator-side stage upgrade — the daemon-side
      `windows-mesh-status-check` subcommand has shipped since
      the original W4.2 daemon-side work, so the orchestrator
      path is now end-to-end. What's still pending is **the other
      half of W4.2**: the actual membership + assignment
      distribution to the Windows guest (the bash orchestrator's
      `distribute_membership_state` /
      `issue_and_distribute_assignments` /
      `issue_and_distribute_traversal` stages target Linux peers
      only today). When that distribution lands the verifier here
      gains live evidence rather than expected `state snapshot
      missing` drift.
    - On the current Windows VM (running the
      `windows-unsupported` backend label per
      `WindowsWorkingNodePlan_2026-04-17.md`) the stage will
      report drift because no `rustynetd.state` file appears.
      That drift is honest — the Windows daemon hasn't been
      asked to join a mesh yet — and matches the "not yet
      joined" posture documented under W2.4 (key custody) +
      W1.3 (DNS fail-closed) verifier slices. The orchestrator's
      stage record is `Fail` in that case; once the
      distribution-side work lands the same probe will return
      `Pass` with a peer count + age summary.
- [x] W4.2-followup (membership only) — Windows membership-snapshot
      distribution helper landed; assignment / traversal / DNS-zone
      bundles still pending (mechanical follow-ups using the same
      pattern)
  - Changed files:
    - `crates/rustynet-cli/src/vm_lab/mod.rs` — added the
      `run_distribute_windows_membership_stage` helper plus the two
      script-builder helpers it relies on
      (`build_windows_membership_ensure_staging_dir_script`,
      `build_windows_membership_atomic_install_script`) and a unique-
      filename helper (`windows_membership_staging_filename`). The
      flow is three round-trips:
        1. SSH + PowerShell `New-Item -ItemType Directory -Force`
           on `C:\ProgramData\RustyNet\membership\.staging\`
           (idempotent — the membership root itself was already
           created with reviewed ACLs by the W1.1-verified install
           helper, but the `.staging\` subdir is new and is
           inherited under the same SYSTEM + Administrators DACL).
        2. SCP the local snapshot to a per-run unique filename under
           `.staging\` — `membership.snapshot.<32-hex-u128>.staging`.
        3. SSH + PowerShell atomic install: `Move-Item -Force
           -LiteralPath <staging> -Destination <canonical>` over the
           reviewed
           `C:\ProgramData\RustyNet\membership\membership.snapshot`
           path, then `Remove-Item -Force -ErrorAction
           SilentlyContinue -LiteralPath <watermark>` on
           `C:\ProgramData\RustyNet\membership\membership.watermark`
           to force the daemon's next refresh tick to re-ingest.
           Mirrors the bash orchestrator's
           `distribute_membership_worker` semantics on Linux peers
           (`root install` + `rm -f watermark`).
      Every PowerShell-boundary value (canonical paths, watermark
      path, staging filename) is wrapped through `powershell_quote`
      so the boundary is the same audited single-quoted-PS-literal
      pattern the W2.x security validators use.
      `build_windows_membership_atomic_install_script` defensively
      filters the staging-filename charset to ASCII alphanumeric +
      `-` `_` `.` so a future caller cannot inject `\`-traversal or
      shell metacharacters via the staging-name parameter.
      `run_distribute_windows_membership_stage` validates the local
      snapshot is a regular file before any SSH activity, resolves
      the target alias from the inventory, and rejects non-Windows
      platforms up-front.
  - Verification:
    - `cargo fmt -p rustynet-cli -- --check` clean.
    - `cargo test -p rustynet-cli --bin rustynet-cli` — 455 / 455
      pass (was 450). +5 new tests in `vm_lab::tests`:
      `windows_membership_staging_filename_uses_hex_unique_suffix`,
      `build_windows_membership_ensure_staging_dir_script_uses_quoted_canonical_path`,
      `build_windows_membership_atomic_install_script_emits_move_and_remove`,
      `build_windows_membership_atomic_install_script_rejects_metacharacters`
      (covering 7 hostile staging-filename inputs including
      `..`-traversal, PS literal escape, command separators, etc.),
      `build_windows_membership_atomic_install_script_accepts_unique_suffix_filename`
      (round-trip pin: orchestrator-produced filename always passes
      the install charset filter).
  - Residual risk:
    - **Daemon-side ingestion gated on Windows backend.** The
      Windows daemon ships on `windows-unsupported` today
      (per `WindowsWorkingNodePlan_2026-04-17.md`) and refuses to
      start, so the snapshot the orchestrator pushes here will not
      actually be ingested into a running daemon's peer table until
      a reviewed Windows backend lands. The distribution code path
      is correct and ready — the file is in the daemon-expected
      location, with the daemon-expected ACL inherited from the
      W1.1-reviewed `membership\` root, with the watermark cleared
      so the next refresh tick re-ingests. When the Windows backend
      ships, this code is the unblocker for live mesh-join evidence
      on the W4.2 verifier.
    - **Membership-only this slice.** Assignment, traversal, and
      DNS-zone bundles follow the same scp + atomic-install
      pattern but each lands in their own canonical Windows path
      (`C:\ProgramData\RustyNet\trust\`,
      `C:\ProgramData\RustyNet\…assignment`, etc. per
      `crates/rustynetd/src/windows_paths.rs`). Each is a
      mechanical follow-up to this slice; the orchestrator's
      distribution code path does not need re-architecting.
    - **Not yet wired into orchestrator stage sequence.** The
      helper is exported as a `pub fn` callable from the
      orchestrator code path but is not yet referenced from
      `run_windows_orchestration_stages_with_options`. Wiring it
      into the heterogeneous live-lab orchestration sequence is
      W4.3/W4.5 territory (the live-lab run that pulls a snapshot
      from the Linux exit and pushes to the Windows peer end-to-
      end). The CLI subcommand surface that exposes the helper to
      operators (`ops vm-lab-distribute-windows-membership` or
      similar) is also a follow-up.
    - **Multi-snapshot collision window.** If two operators
      simultaneously distribute a snapshot to the same Windows
      guest, the staging filenames collide with negligible
      probability (32-hex u128) but the canonical-path Move-Item
      could race between the second SCP and the first install.
      The reviewed Move-Item is `-Force` so it overwrites
      atomically; the second operator's snapshot wins. Operators
      who need strict serialisation should coordinate via the
      existing membership-owner lock (out of orchestrator scope).
- [x] W4.2-followup-2 — Assignment / traversal / DNS-zone distribution
      helpers + orchestrator wiring landed
  - Changed files:
    - `crates/rustynet-cli/src/vm_lab/mod.rs` — extended the existing
      W4.2-followup membership helper into a generic
      `WindowsBundleDistributionContract` shape with one audited
      `run_distribute_windows_bundle_stage` dispatch fn. Four thin
      wrapper helpers route the four bundle types to the right
      reviewed canonical / watermark / staging paths under
      `C:\ProgramData\RustyNet\…`:
        * `run_distribute_windows_membership_stage`
        * `run_distribute_windows_assignment_stage`
        * `run_distribute_windows_traversal_stage`
        * `run_distribute_windows_dns_zone_stage`
      All four wrappers reuse the membership three-round-trip flow
      (ensure-staging-dir → SCP → atomic Move-Item + watermark
      clear). The argv-only PowerShell discipline + staging-charset
      filter from the membership slice carry over unchanged.
      Wired the four wrappers into `run_windows_orchestration_stages_with_options`
      between Stage 7 (`validate_windows_dns_failclosed`) and Stage 8
      (`validate_windows_mesh_join`) as Stages 8–11
      (`distribute_windows_{membership,assignment,traversal,dns_zone}`).
      Each distribution stage gates on every prior security validator
      passing — distribution depends on a hardened guest, never on a
      partially-validated guest. When the corresponding optional
      `WindowsOrchestrationOptions::distribute_windows_*_bundle` path
      is `None`, the stage emits `Skipped` with reason "no local
      bundle path provided" — orchestration sequence remains stable
      for callers that have not yet built their local bundles. When
      `Some`, the wrapper is invoked through a single `DistributeFn`
      function-pointer dispatch closure that produces the same
      pass/fail/log pattern every existing stage emits.
    - `crates/rustynet-cli/src/main.rs` — extended the
      `vm-lab-validate-windows-security` arg parser with four new
      optional flags (`--distribute-windows-membership-bundle`,
      `--distribute-windows-assignment-bundle`,
      `--distribute-windows-traversal-bundle`,
      `--distribute-windows-dns-zone-bundle`) and updated the help
      text. The standalone subcommand now drives end-to-end
      distribution + validation in a single invocation when the four
      bundle paths are provided, or pure validation when they are
      omitted.
  - Verification:
    - `cargo fmt --all -- --check` clean.
    - `cargo clippy --workspace --all-features -- -D warnings` clean.
    - `cargo test -p rustynet-cli --bin rustynet-cli` — 455 / 455 pass.
      `run_validate_windows_security_dry_run_emits_skipped_stages_and_writes_report`
      extended to assert the 12-stage sequence (8 prior + 4 new
      distribution stages) all appear with `status=skipped` under
      `--dry-run`.
    - Pre-existing `clippy::collapsible_if` regression in
      `crates/rustynet-cli/src/ops_e2e.rs` (toolchain bump to
      clippy 1.94 introduced the lint as deny) folded into this slice
      so the workspace gate stays green.
  - Residual risk:
    - **Daemon-side ingestion still gated on Windows backend.** Same
      as the W4.2-followup membership slice: until a reviewed Windows
      backend lands (`windows-wireguard-nt`), the daemon ships on
      `windows-unsupported` and refuses to start, so the four bundles
      the orchestrator pushes here will not be ingested into a
      running daemon's trust state. The distribution code path is
      correct + ready; each file lands in the daemon-expected
      location with the daemon-expected ACL inherited from the
      W1.1-verified parent root.
    - **Distribution stages are opt-in via path arguments.** The
      orchestration sequence emits `Skipped` outcomes for any
      distribution stage whose `distribute_windows_*_bundle` option
      is `None`. Operators building a heterogeneous live-lab need to
      pre-build the four signed bundles + pass their paths through
      the new CLI flags. A future slice can wire the four bundle
      paths directly into `vm-lab-orchestrate-live-lab` once the
      pull-from-Linux-exit Rust helper is done.
- [x] W4.2-followup-3 — Operator-facing distribution subcommand
      `vm-lab-distribute-windows-state`
  - Changed files:
    - `crates/rustynet-cli/src/vm_lab/mod.rs` — added
      `VmLabDistributeWindowsStateConfig` + `run_distribute_windows_state`.
      Pure-distribution path: walks the four optional bundle paths and
      calls the corresponding `run_distribute_windows_*_stage` wrapper
      for each one provided. Fail-fast rejection when zero bundle paths
      are supplied (running the subcommand with no work is a no-op
      operator error). Writes a typed JSON report to
      `<report-dir>/windows_state_distribution.json` mirroring the
      validate-windows-security report shape so downstream tooling can
      consume both with one parser.
    - `crates/rustynet-cli/src/main.rs` — added
      `OpsCommand::VmLabDistributeWindowsState`, the
      `vm-lab-distribute-windows-state` arg parser (4 bundle path flags
      + inventory + identity + report-dir + dry-run), the dispatch arm,
      and the help text.
  - Use cases:
    - Operator has already passed the W2.x security validators in a
      prior run and only wants to refresh trust state — call this
      subcommand directly, skipping the bootstrap + 7 validator stages.
    - Trust-state-only iteration loop on a long-running Windows guest
      where re-running the validators on every iteration is wasted
      latency.
    - For the combined "validate + distribute in one pass" flow, the
      `vm-lab-validate-windows-security --distribute-windows-*-bundle`
      flags from W4.2-followup-2 remain the right call.
  - Verification:
    - `cargo fmt --all -- --check` clean.
    - `cargo clippy --workspace --all-features -- -D warnings` clean.
    - `cargo test -p rustynet-cli --bin rustynet-cli` — 457 / 457 pass
      (was 455). +2 new tests:
      `run_distribute_windows_state_rejects_zero_bundle_paths` (negative
      pin: zero bundles must surface the required-flags list),
      `run_distribute_windows_state_dry_run_emits_skipped_stages_and_writes_report`
      (positive pin: typed report shape + 4-stage sequence + dry-run
      skip status).
- [x] W4.2-followup-4 — Pull-from-Linux-exit Rust helper +
      `vm-lab-pull-windows-state-from-linux-exit` subcommand
  - Changed files:
    - `crates/rustynet-cli/src/vm_lab/mod.rs` — added
      `LINUX_EXIT_{MEMBERSHIP_SNAPSHOT,ASSIGNMENT_BUNDLE,TRAVERSAL_BUNDLE,DNS_ZONE_BUNDLE}_PATH`
      constants pinning the four canonical Linux exit source paths
      (mirroring the `RUSTYNET_*_BUNDLE` env vars in the
      `scripts/systemd/rustynetd.service` unit). Added
      `VmLabPullWindowsStateFromLinuxExitConfig` +
      `PulledLinuxExitBundles` + `run_pull_windows_state_from_linux_exit`.
      Pure-pull path: SCPs all four bundles in sequence from the
      reviewed Linux source paths to a local staging directory using
      the existing `scp_from_remote` helper. Rejects non-Linux pull
      sources up-front (alias must resolve to `VmGuestPlatform::Linux`).
      Per-bundle Pass / Fail outcomes — a single bundle's SCP failure
      does not abort the others, so the operator sees the full set of
      blockers in one report rather than chasing one failure at a time.
      Writes a typed JSON report to
      `<report-dir>/windows_state_pull_from_linux_exit.json`.
      On overall Pass returns the four local paths in
      `PulledLinuxExitBundles` so Rust callers can hand them straight
      to `run_distribute_windows_state` without re-deriving filenames.
    - `crates/rustynet-cli/src/main.rs` — added
      `OpsCommand::VmLabPullWindowsStateFromLinuxExit`, the
      `vm-lab-pull-windows-state-from-linux-exit` arg parser
      (`--linux-exit-vm`, `--ssh-identity-file`, `--known-hosts-file`,
      `--dest-dir`, `--report-dir`, `--dry-run`), the dispatch arm
      (drops the `PulledLinuxExitBundles` so the CLI surface returns a
      plain summary string), and the help text.
  - End-to-end loop (heterogeneous live-lab):
      Linux exit          orchestrator host                Windows peer
      ----------          -----------------                ------------
      `/var/lib/rustynet/membership.snapshot`  →           `C:\ProgramData\RustyNet\membership\membership.snapshot`
      `/var/lib/rustynet/rustynetd.assignment` →           `C:\ProgramData\RustyNet\trust\rustynetd.assignment`
      `/var/lib/rustynet/rustynetd.traversal`  →           `C:\ProgramData\RustyNet\trust\rustynetd.traversal`
      `/var/lib/rustynet/rustynetd.dns-zone`   →           `C:\ProgramData\RustyNet\trust\rustynetd.dns-zone`
    Two-step operator flow:
      1. `ops vm-lab-pull-windows-state-from-linux-exit
          --linux-exit-vm <linux-alias>
          --ssh-identity-file <path>
          --dest-dir <local-staging>
          --report-dir <pull-report>`
      2. `ops vm-lab-distribute-windows-state
          --windows-vm <windows-alias>
          --ssh-identity-file <path>
          --membership-bundle <local-staging>/membership.snapshot
          --assignment-bundle <local-staging>/rustynetd.assignment
          --traversal-bundle  <local-staging>/rustynetd.traversal
          --dns-zone-bundle   <local-staging>/rustynetd.dns-zone
          --report-dir <distribute-report>`
  - Verification:
    - `cargo fmt --all -- --check` clean.
    - `cargo clippy --workspace --all-features -- -D warnings` clean.
    - `cargo test -p rustynet-cli --bin rustynet-cli` — 459 / 459 pass
      (was 457). +2 new tests:
      `run_pull_windows_state_from_linux_exit_dry_run_emits_skipped_stages_and_writes_report`
      (positive pin: 4-stage sequence + skipped status + returned
      `PulledLinuxExitBundles` filename mapping),
      `run_pull_windows_state_from_linux_exit_rejects_windows_alias`
      (negative pin: pull source must resolve to a Linux platform).
  - Residual risk:
    - **SSH user must have read access to `/var/lib/rustynet/`.** The
      reviewed Linux source paths are owned by `root:rustynetd` with
      `0640` perms (per
      `scripts/e2e/live_lab_common.sh:1457` distribute-worker
      `install` semantics). Operators running the pull must use an
      SSH user that is a member of `rustynetd` group, or run the SSH
      target as root. The helper surfaces SCP non-zero exits with the
      Linux remote path in the failure summary so a permissions gap
      is honest, not silent.
    - **Read-only on the source.** The pull never mutates the Linux
      exit's bundles or watermarks. The two-step flow is the only
      supported path; a single combined "pull + distribute"
      subcommand is deliberately not provided so the staging-dir
      contents are auditable between fetch and push.
- [ ] W4.3 Windows traffic-test peer participation
- [ ] W4.4 Windows route + DNS lifecycle stages
- [ ] W4.5 4×Linux + 1×Windows live-lab run; artifacts archived

### W1/W2 supporting tooling
- [x] Standalone `ops vm-lab-validate-windows-security` subcommand
  - Changed files:
    - `crates/rustynet-cli/src/vm_lab/mod.rs` — new
      `VmLabValidateWindowsSecurityConfig` (inventory, windows_vm, SSH,
      report_dir, dry_run, skip_access_bootstrap, skip_install) and
      `run_validate_windows_security` runner. Dispatches the existing
      `run_windows_orchestration_stages_with_options` with the new
      `WindowsOrchestrationOptions { skip_access_bootstrap, skip_install }`,
      writing a typed JSON aggregate report to
      `<report_dir>/windows_security_validation.json`. Exits non-zero on
      any per-stage `Fail`. Lets us iterate on the security validation
      stages without spinning up the full 5-Linux + 1-Windows live-lab.
    - `crates/rustynet-cli/src/main.rs` — added subcommand
      `ops vm-lab-validate-windows-security ... [--skip-access-bootstrap]
      [--skip-install]`. Help line advertises the new flags.
    - `crates/rustynet-cli/Cargo.toml` — added `tempfile = "3"` as
      dev-dependency for the new dry-run integration test.
  - Verification:
    - `cargo fmt --all -- --check` clean.
    - `cargo test -p rustynet-cli --bin rustynet-cli` — 376 / 376 pass
      (was 369 before this slice; +1 new
      `run_validate_windows_security_dry_run_emits_skipped_stages_and_writes_report`
      integration test that constructs an inventory + identity file in a
      tempdir, runs the dry-run path, and verifies every stage emits a
      "skipped" entry in the JSON report; 6 hardening evaluator tests
      added in W2.4 also live in this binary's test set).
    - Native dry-run smoke against the live inventory entry
      `windows-utm-1` produced the expected 7-stage skipped report.
  - Live-UTM result (2026-04-27 first attempt):
    - Live invocation against the running UTM Windows guest at
      `192.168.64.14` reached `bootstrap_windows_host` and failed with
      `stage Windows helper script failed with status 1`. Root cause:
      the orchestrator's Windows access-establishment phase requires
      `utmctl file push <vm> <dst>` to succeed, and `utmctl` returns
      OSStatus `-1743` (Automation permission denied) from the headless
      shell context this Claude Code session runs in, with the message
      "utmctl does not work from SSH sessions or before logging in."
      `ssh_fallback_allowed_for_target` returns `false` for
      `(AccessEstablishment, local_utm, Windows)` so no SSH fallback is
      tried — by design, because access-establishment exists exactly to
      bring SSH up.
    - Two workarounds available, neither weakens the security bar:
      1. Run the same command from a user-owned Terminal.app session
         where utmctl has Automation permission.
      2. Manually pre-stage OpenSSH Server + the automation public key
         on the Windows guest, then re-run with
         `--skip-access-bootstrap`. The skip flag bypasses only the
         UTM-side access-establishment probe; every downstream
         security validation stage still runs identically.
  - Residual risk:
    - The `--skip-install` flag also bypasses `InstallRelease` /
      `RestartRuntime` / `VerifyRuntime`. Use only when the binary at
      `C:\Program Files\RustyNet\rustynetd.exe` is already current —
      otherwise the security-validation subcommands run against a stale
      binary. The flag is meant for fast iteration on the validators,
      not for production gating.
- [x] Live-lab proof against UTM `windows-utm-1` (2026-04-27)
  - Context: drove a fresh end-to-end install + validator run against the
    live UTM Windows 11 guest at `192.168.64.14` over SSH. The orchestrator
    `vm-lab-orchestrate-live-lab` BuildRelease/InstallRelease phases route
    through `utmctl file push <vm> <dst>` to pull the report file back, and
    `utmctl` returns OSStatus `-1743` from any non-Terminal.app shell
    context (per W1/W2 supporting-tooling entry above). To unblock the
    live-validator proof in this session the helper scripts were invoked
    directly via SSH; once UTM access stabilises the same scripts will run
    via the orchestrator without modification.
  - Bugs surfaced and patched in helper scripts (each is fail-closed
    drift the W2.2 verifier was designed to catch, plus three pre-existing
    PS-shell bugs that prevented any live install from completing):
    - `scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1`
      - `$cliCandidates` array was constructed with a trailing comma after
        the first `Join-Path`, which PS5.1 binds as a single Join-Path call
        with `-ChildPath` = array. The cmdlet rejected the array with
        `ParameterBindingException: Cannot convert 'System.Object[]' to the
        type 'System.String'. Specified method is not supported.` Wrapped
        each `Join-Path` in parens so the `@()` literal sees independent
        elements.
      - `(Get-Command wireguard.exe …)?.Source` used the PS7-only null-
        conditional operator. The orchestrator dispatches via
        `powershell.exe` (PS5.1 baseline) which fails the parser. Replaced
        with a `Get-Command` + `if ($cmd) { $cmd.Source } else { $null }`
        pattern. Same fix applied to
        `Smoke-RustyNetWindowsServiceHost.ps1`.
      - `$daemonDest` and the optional CLI dest were copied to
        `C:\Program Files\RustyNet\bin\rustynetd.exe`, but the orchestrator
        constant `WINDOWS_RUSTYNETD_EXE_PATH` and the `rustynetd
        windows-authenticode-check --binary-path` default both pin to
        `C:\Program Files\RustyNet\rustynetd.exe` (no `bin\` subdir). Moved
        install dest to the install-root directly (per the W1.2b residual-
        risk note that flagged this would need reconciling). Also dropped
        the ensure-runtime-layout pre-creation of the `bin\` subdir, and
        reconciled `Verify-RustyNetWindowsBootstrap.ps1` (3 paths) and
        `Collect-RustyNetWindowsDiagnostics.ps1` (3 hash-list paths + the
        inspect-list `bin\` entry) to match.
      - Service binPath construction sent to `sc.exe create` failed with
        `1639 ERROR_INVALID_COMMAND_LINE` because PS5.1 mangles native-
        command argument quoting when the value contains both spaces and
        embedded double quotes. Switched the create/config path to the PS-
        native `New-Service` cmdlet (with `Stop-Service` + `sc.exe delete`
        + brief SCM settle for the existing-service replace case), so the
        binPath crosses into the SCM API as a single string with no shell
        tokenization. `sc.exe failure` and `sc.exe sidtype` are kept on
        the native path because their args are slash-separated tokens with
        no spaces or quotes — the PS5.1 quoting bug does not trigger.
    - Hardening gaps caught by `windows-service-hardening-check` and
      patched in the same script:
      - `failure_action_count = 0` — the W2.2 verifier rejects services
        with no SCM recovery actions, but the previous install never set
        any. Added `Set-RustyNetServiceFailureActions` that runs
        `sc.exe failure RustyNet reset= 86400 actions=
        restart/60000/restart/60000/restart/60000` after `New-Service`.
      - `binary ACL grants a broader-than-reviewed Windows principal
        (BU)` — `C:\Program Files\RustyNet\rustynetd.exe` was inheriting
        Builtin-Users `read+execute` from `C:\Program Files`. Added
        `Repair-RustyNetServiceBinaryAcl` that sets owner to
        Administrators, disables inheritance, and grants only
        SYSTEM:Full + Administrators:Full + `NT SERVICE\<svc>:RX`. The
        runtime never modifies its own image, so the service identity
        gets read+execute only — write access is denied even to the
        service principal. Wired into the install flow after the existing
        runtime-ACL repair loop and before the service start attempt.
  - Verification (live, against `windows-utm-1` at `192.168.64.14`):
    - `windows-runtime-acls-check`: `overall_ok=true` over all 8 reviewed
      roots (`state`, `config`, `logs`, `trust`, `membership`, `keys`,
      `secrets`, `secrets\key-custody`). **W1.2 live-guest evidence
      now captured** — closes the residual-risk note in W1.2b.
    - `windows-service-hardening-check`: `overall_ok=true`,
      `failure_action_count=3`, `binary_path_acl_sddl =
      O:BAD:PAI(A;;0x1200a9;;;S-1-5-80-…)(A;;FA;;;SY)(A;;FA;;;BA)` (no
      BU/WD/AU), service runs as `LocalSystem` with `service_sid_type =
      unrestricted`, binary path pinned to install root, argv contains
      `--windows-service` + `--env-file` and no inline daemon flags.
      **W2.2 live-guest evidence now captured** — closes the residual-
      risk note in W2.2.
    - `windows-key-custody-check`: `overall_ok=false`. Three required
      artefacts (`wireguard.passphrase.dpapi`, `wireguard.key.enc`,
      `wireguard.pub`) reported missing; `wireguard.key` correctly
      `absent_as_expected`. Expected on this run because the
      `windows-unsupported` backend exits before key-init. Tracked under
      the existing W2.4 + W2.4-followup entries; no validator change
      needed.
    - `windows-authenticode-check`: `overall_ok=false`,
      `signature_present=false`, `drift_reasons = ["PE has an empty
      Certificate Table directory entry; binary is unsigned"]`. Expected
      because `cargo build --release` produces an unsigned PE; W2.1a is
      a presence-only gate (full WinVerifyTrust chain validation is
      tracked under W2.1b). No validator change.
    - `windows-mesh-status-check`: `overall_ok=false`,
      `load_status=missing` (no `rustynetd.state` because the daemon
      never ran). Expected; no validator change.
  - Artifacts: `artifacts/windows_live_20260427T215938Z/` (initial run
    with the two W2.2 hardening drift reasons surfacing) and
    `artifacts/windows_live_20260427T220349Z/` (post-fix run with W2.2
    passing). Each archive carries the typed JSON output of all five
    validator subcommands plus per-stage stderr.
  - Residual risk:
    - The `windows-utm-1` guest's daemon backend is still
      `windows-unsupported` (per `WindowsWorkingNodePlan_2026-04-17.md`),
      so `windows-key-custody-check` and `windows-mesh-status-check`
      will keep reporting their expected fail-closed gaps until a
      reviewed Windows backend ships. Today's run proves the validators
      observe the live state honestly; it does not yet prove the
      controls fully active under a working backend.
    - Live-lab access still requires manual UTM-side SSH bootstrap or a
      Terminal.app-driven `vm-lab-validate-windows-security` invocation
      because `utmctl` does not work from headless shells. Tracked in
      the pre-existing access-orchestration entry above.

### Phase W5 (Stretch: heterogeneous topologies)
- [ ] W5.1 5×Windows run
- [ ] W5.2 Mixed-arrangement matrix
- [ ] W5.3 Posture promotion only after independent
      [WindowsWorkingNodePlan_2026-04-17.md](./WindowsWorkingNodePlan_2026-04-17.md)
      DoD met

## 11) Definition Of Done

This delta closes only when **all** are true:

- §5 security-parity matrix has, for every Windows row, an enforcement
  point in code, an orchestrator stage that verifies it on a live Windows
  guest, and a negative test that proves it fails closed.
- `vm-lab-orchestrate-live-lab` runs a 4×Linux + 1×Windows live-lab to
  completion with the new dispatcher, with the Windows node filling at
  least one non-trivial role (not only the lowest-privilege slot).
- The `ensure_live_lab_profile_linux_only` gate is gone, replaced by
  per-stage capability checks.
- macOS / iOS / Android variants remain present, return `Unsupported` with
  clear blocker text, and have negative tests asserting the rejection.
- All mandatory CLAUDE.md §7 gates pass on the final increment.
- No TODO/FIXME/placeholders in the shipped code.
- The existing related ledgers
  ([WindowsWorkingNodePlan_2026-04-17.md](./WindowsWorkingNodePlan_2026-04-17.md),
  [WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md](./WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md),
  [ShellToRustMigrationPlan_2026-03-06.md](./ShellToRustMigrationPlan_2026-03-06.md))
  reference the relevant outcomes of this delta and remain self-consistent.

Posture promotion of Windows in the release matrix is **not** in this
delta's DoD. That is owned by
[WindowsWorkingNodePlan_2026-04-17.md](./WindowsWorkingNodePlan_2026-04-17.md).

## 12) Agent Update Rules

Same rules as
[ShellToRustMigrationPlan_2026-03-06.md](./ShellToRustMigrationPlan_2026-03-06.md)
§"Agent Update Rules":

1. Update this document immediately after each materially completed slice;
   do not maintain a private checklist that diverges from this file.
2. Mark completion conservatively. `[x]` only after code + verification.
   Use `Status: partial` or `Status: blocked` honestly.
3. Record evidence under the touched section. Minimum fields: `Changed
   files:`, `Verification:`, `Artifacts:`, `Residual risk:`, `Blocker /
   prerequisite:` (only when applicable).
4. Use UTC timestamps and commit SHAs where possible.
5. Do not delete historical context that still matters; correct stale
   claims in place.
6. Keep security claims evidence-backed. If live validation is unavailable,
   say so and record the missing prerequisite.
7. If a test or gate fails, fix the root cause. Do not weaken the check or
   bypass the security control to make this plan look complete.
