# Shell-to-Rust Security Migration Plan

Date: 2026-03-06  
Owner: Rustynet engineering

## 1) Goal
Migrate the most security-critical shell logic (`.sh`) into Rust while preserving current Linux/macOS behavior and keeping Debian 13 compatibility as a hard constraint.

Success criteria:
- reduced privileged shell attack surface,
- no regression in fail-closed behavior,
- no regression in key custody controls,
- all current gates and VM validation scenarios still pass.

## Status Update (2026-03-06)
- Phase A complete: `refresh_trust_evidence.sh` and `refresh_assignment_bundle.sh` are thin wrappers to Rust ops commands.
- Phase B complete: `install_rustynetd_service.sh` is now a thin wrapper to `rustynet ops install-systemd`; core installer logic (idempotent user/group/dir setup, credential-path pinning, env file generation, legacy cleanup/migration, systemd orchestration) is implemented in Rust.
- Phase C complete: `rustynet-cli` now provides Rust-backed ops for secure file scrubbing/removal, signing-passphrase material ensure/materialization, trust-refresh helper invocation, assignment-refresh exit-node env mutation, and role-switch coupling (`ops apply-role-coupling`); migrated `start.sh` paths are Rust-only and fail closed.
- Phase D baseline complete: added optional Rust operator UX entrypoint via `rustynet operator menu` while retaining `start.sh` as compatibility UI wrapper.
- Phase E started: added Rust ops `prepare-system-dirs`, `apply-blind-exit-lockdown`, `init-membership`, and `refresh-signed-trust`; migrated `start.sh` privilege paths are Rust-only and fail closed.
- Phase E progress: `ensure_wireguard_keys` is enforced through `rustynet ops bootstrap-wireguard-custody` with fail-closed behavior.
- Phase E progress: Linux disconnect cleanup is Rust-backed via `rustynet ops disconnect-cleanup`; `start.sh` Linux `disconnect_vpn` now dispatches to the Rust op and fails closed on error.
- Phase E progress: Linux runtime service lifecycle control is Rust-backed via `rustynet ops restart-runtime-service`, `rustynet ops stop-runtime-service`, `rustynet ops show-runtime-service-status`, `rustynet ops start-assignment-refresh-service`, and `rustynet ops check-assignment-refresh-availability`; `start.sh` Linux service paths now dispatch to Rust ops instead of direct `systemctl` mutation.
- Phase E progress: trust material import/install is Rust-backed via `rustynet ops install-trust-material`; `start.sh` `configure_trust_material` client/external-signed branches now dispatch to the Rust op instead of direct shell `install/chown/chmod`.
- Phase E progress: macOS runtime lifecycle and cleanup control is Rust-backed via `rustynet ops restart-runtime-service`, `rustynet ops stop-runtime-service`, `rustynet ops show-runtime-service-status`, and `rustynet ops disconnect-cleanup`; `start.sh` macOS start/stop/status/disconnect paths now dispatch to Rust ops instead of direct `launchctl`/plist install/`pfctl`/`pkill` mutation loops.
- Phase F complete: Phase 6 parity probe/report/bundle generators are Rust-backed (`rustynet ops collect-platform-probe`, `rustynet ops generate-platform-parity-report`, `rustynet ops collect-platform-parity-bundle`); release scripts are thin wrappers that only dispatch to Rust commands.
- Phase G complete: Phase9/Phase10 evidence pipeline is Rust-backed (`rustynet ops collect-phase9-raw-evidence`, `rustynet ops generate-phase9-artifacts`, `rustynet ops generate-phase10-artifacts`); shell/Python collection/generation logic removed from active scripts.
- Phase H complete: phase1 measured input collection + baseline orchestration are Rust-backed (`rustynet ops collect-phase1-measured-input`, `rustynet ops run-phase1-baseline`); legacy shell/Python collector logic and shell `source` ingestion are removed from the active path.
- Phase I progress: Debian two-node remote E2E orchestration is Rust-invoked (`rustynet ops run-debian-two-node-e2e`), `scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh` is wrapper-only, and active remote orchestration/probe operations now use argv-only SSH command dispatch (no `bash -se` payload/snippet path in active code); remaining work is execution evidence refresh from lab dry-runs.
- Phase E/F02 progress: peer-store validation/read flows are Rust-backed via `rustynet ops peer-store-validate` and `rustynet ops peer-store-list`; `start.sh` now consumes Rust-validated peer records instead of shell parsing `peers.db` directly.

## 2) Current Risk Inventory (Impact-First)
High-impact scripts by privilege + secret handling + size:

1. `start.sh` (~4435 lines)
- Handles key/passphrase custody flows, role switching, trust/assignment generation paths, and privileged orchestration.
- Highest long-term security/maintenance risk due to breadth and complexity.

2. `scripts/systemd/refresh_trust_evidence.sh` (root, timer-driven)
- Uses signer key + passphrase source, writes trust artifacts, validates ownership/mode.
- High impact because it runs unattended as root.

3. `scripts/systemd/refresh_assignment_bundle.sh` (root, timer-driven)
- Uses assignment signing secret + passphrase source, signs bundle, writes verifier/bundle artifacts.
- High impact because it runs unattended as root and controls tunnel policy inputs.

4. `scripts/systemd/install_rustynetd_service.sh` (root installer)
- Creates users/groups/directories, writes service units/env, checks custody paths.
- High impact due to system-wide mutation and policy wiring.

Lower priority (keep shell for now):
- `scripts/ci/*.sh`, `scripts/e2e/*.sh`.
- These are mostly orchestration/test glue and should remain thin shell wrappers.

## 3) Migration Strategy
Use a staged approach with compatibility wrappers, not a big-bang rewrite.

Principles:
- move privileged + secret-sensitive operations first,
- keep shell only as thin dispatch/wrapper where OS integration is unavoidable,
- preserve current command interfaces until replacements are proven,
- fail closed on all parse/path/permission errors.

## 4) Target Architecture
## 4.1 Rust command surface
Extend `rustynet` CLI with privileged ops commands:
- `rustynet ops refresh-trust`
- `rustynet ops refresh-assignment`
- `rustynet ops install-systemd` (Linux)
- follow-up: additional setup/role-switch subcommands currently embedded in `start.sh`.

## 4.2 Shell role after migration
- `start.sh`: interactive UX wrapper only.
- systemd helper scripts: temporary wrappers calling Rust commands, then removed after stabilization.
- CI/e2e shell scripts remain orchestration wrappers.

## 4.3 Shared secure utilities (Rust)
Centralize in reusable module(s):
- strict path validation (absolute path, no symlink, expected owner/group/mode),
- atomic write + fsync + chmod/chown,
- scrub+remove helper for sensitive files,
- typed env parsing with strict bounds and explicit defaults,
- secret handling via `Zeroizing` where material may enter memory.

## 5) Phased Plan
## Phase A (highest security ROI): systemd refreshers
Scope:
- Replace logic of:
  - `scripts/systemd/refresh_trust_evidence.sh`
  - `scripts/systemd/refresh_assignment_bundle.sh`
- Keep scripts as wrappers initially:
  - `exec /usr/local/bin/rustynet ops refresh-trust`
  - `exec /usr/local/bin/rustynet ops refresh-assignment`

Security requirements:
- Preserve/strengthen checks already present:
  - root-only execution,
  - absolute paths,
  - symlink rejection,
  - root ownership for signing key/passphrase sources,
  - allowed mode policy including `/run/credentials/*` semantics,
  - atomic output writes and strict output modes.
- No secrets in stdout/stderr; keep log lines metadata-only.

Validation:
- new unit tests for env parsing and permission matrices,
- negative tests: weak perms, symlink paths, missing passphrase, invalid TTL,
- run:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - `cargo test --workspace --all-targets --all-features`
  - `./scripts/ci/phase10_gates.sh`
  - `./scripts/ci/membership_gates.sh`

Exit criteria:
- systemd timers operate through Rust path with parity behavior,
- wrappers remain for quick rollback.

## Phase B: service installer migration
Scope:
- Port `scripts/systemd/install_rustynetd_service.sh` core logic into:
  - `rustynet ops install-systemd`
- Keep shell installer as compatibility wrapper during transition.

Security requirements:
- strict ownership/mode setting with explicit expected values,
- idempotent directory/user/group creation,
- explicit credential blob path pinning enforcement,
- safe env file generation (no shell injection footguns).

Validation:
- idempotency tests (run twice = no drift),
- unit file integrity checks,
- Debian 13/Mint/Ubuntu/Fedora install-reinstall checks.

Exit criteria:
- fresh install works on supported Linux distros without manual network cleanup.

## Phase C: `start.sh` risk decomposition
Scope:
- Migrate sensitive operational subflows first:
  - signing passphrase materialization/decryption,
  - trust/assignment signing helper actions,
  - role-switch state mutation and assignment refresh coupling,
  - secure cleanup operations.
- Keep menu rendering/prompt UX in shell initially.

Security requirements:
- reduce shell branching around secret-bearing paths,
- move path/env validation to typed Rust structs,
- eliminate direct shell parsing of signed artifact fields where possible.

Validation:
- menu-driven regression checks (admin/client/blind_exit),
- one-hop/two-hop selection and reconnect tests,
- live exit handoff under load test.

Exit criteria:
- `start.sh` becomes a thin UI wrapper over Rust ops commands.

## Phase D: optional full Rust operator UX
Scope:
- optional terminal UX port from shell menu to Rust (later), if desired.
- not required for security hardening completion.

## 6) Cross-Platform Safety Guardrails
Linux (Debian 13, Mint, Ubuntu, Fedora):
- primary migration target for root/systemd scripts.

macOS:
- do not regress launchd flow or keychain custody.
- keep existing macOS shell orchestration until Linux migrations are stable.

Guardrail:
- no migration step may weaken current fail-closed defaults or secret custody policy.

## 7) Rollout + Rollback
Rollout model:
1. Introduce Rust command.
2. Swap shell script body to `exec rustynet ops ...` wrapper.
3. Run gates + VM matrix.
4. Keep old shell implementation in history for one release cycle.

Rollback model:
- Repoint wrappers/services back to previous shell implementation by reverting one commit or switching ExecStart target.
- No state schema changes in Phase A/B to keep rollback low-risk.

## 8) Test Matrix Per Phase
Mandatory per-phase checks:
1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
3. `cargo check --workspace --all-targets --all-features`
4. `cargo test --workspace --all-targets --all-features`
5. `./scripts/ci/phase10_gates.sh`
6. `./scripts/ci/membership_gates.sh`

VM runtime validation:
1. Debian 13 client <-> exit
2. Mint client -> Debian exit
3. Ubuntu client/exit role swap
4. Fedora client/exit role swap
5. macOS compatibility sanity (no Linux migration side effects)

Network behavior checks:
- one-hop and two-hop path correctness,
- exit reselection/disconnect semantics,
- no leak during exit handoff under load,
- NAT egress through selected exit verified.

## 9) Recommended First Implementation Slice (start now)
Implement Phase A first in this order:
1. Add `rustynet ops refresh-trust` (parity with `refresh_trust_evidence.sh`).
2. Add `rustynet ops refresh-assignment` (parity with `refresh_assignment_bundle.sh`).
3. Convert both shell scripts into thin wrappers.
4. Re-run gates + Debian/Mint validation.

Reason:
- highest security impact,
- smallest migration surface compared with `start.sh`,
- easiest to validate with existing timers/gates.

## 10) Remaining Migration Scope (Current Snapshot)
Priority is based on: `privilege level` + `secret handling` + `state mutation risk` + `blast radius`.

1. `start.sh` remaining privileged/secret subflows (highest priority)
- `prepare_system_directories`
- `ensure_wireguard_keys`
- `ensure_membership_files`
- `lockdown_blind_exit_local_material`
- `configure_trust_material`
- `refresh_signed_trust_evidence`
- `write_daemon_environment`
- `start_or_restart_service` (macOS launchd branch + shell orchestration only; Linux lifecycle control path is Rust-backed)
- `disconnect_vpn` (macOS launchd/PF branch only; Linux cleanup path is Rust-backed)

2. E2E hardening follow-up (in progress)
- `rustynet ops run-debian-two-node-e2e`: collect fresh lab dry-run evidence for the argv-only remote execution path and retain regression checks to prevent shell-path reintroduction.
- `scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh` remains wrapper-only (`exec rustynet ...`).

Keep as shell wrappers for now:
- `scripts/ci/*` gate wrappers, `scripts/fuzz/smoke.sh` (orchestration glue; lower security ROI).

## 11) Next Phases (Security-First)
## Phase E: `start.sh` Privileged Core Extraction
Scope:
- Move remaining high-risk `start.sh` flows into Rust ops commands.
- Keep `start.sh` as terminal UX/menu wrapper only.

Recommended Rust command additions:
- `rustynet ops prepare-system-dirs`
- `rustynet ops bootstrap-wireguard-custody`
- `rustynet ops init-membership`
- `rustynet ops configure-trust`
- `rustynet ops apply-blind-exit-lockdown`
- `rustynet ops install-or-update-runtime`
- `rustynet ops disconnect-cleanup`

Security controls:
- enforce absolute-path + symlink rejection on all sensitive file paths,
- enforce owner/group/mode invariants before read/write,
- replace shell temp-file handling with Rust tempfiles + explicit zeroization where possible,
- move all credential materialization into Rust typed flows,
- no secret-bearing values in logs, env echoes, or error strings.

Validation:
- full compile/test gates,
- `phase10_gates` + `membership_gates`,
- Linux matrix (Debian 13/Mint/Ubuntu/Fedora) role setup and role-switch checks,
- macOS sanity run to confirm no launchd/keychain regressions.

Exit criteria:
- these `start.sh` functions are wrappers around Rust commands,
- no direct shell handling of passphrase/key material in these paths.

## Phase F: Release/Parity Pipeline Migration
Scope:
- Port phase6 parity probe/report bundle scripts to Rust.
- Remove shell + Python-heredoc JSON construction in release path.

Recommended Rust command additions:
- `rustynet ops collect-platform-probe`
- `rustynet ops generate-platform-parity-report`
- `rustynet ops collect-platform-parity-bundle`

Security controls:
- strict schema validation with typed structs,
- fail closed on stale/future timestamps and malformed source paths,
- deterministic artifact generation (canonical field handling and explicit metadata).

Validation:
- `./scripts/ci/check_phase6_platform_parity.sh`
- `./scripts/ci/phase6_gates.sh`
- cross-platform probe replay on Linux + macOS source artifacts.

Exit criteria:
- release parity artifacts are generated/validated by Rust command path only.

## Phase G: Phase9/Phase10 Evidence Pipeline Migration
Scope:
- Port operations evidence collection/generation scripts to Rust.
- keep gates unchanged; only swap artifact producer implementation.

Recommended Rust command additions:
- `rustynet ops collect-phase9-raw-evidence`
- `rustynet ops generate-phase9-artifacts`
- `rustynet ops generate-phase10-artifacts`

Security controls:
- typed, fail-closed validation for all required source artifacts,
- explicit freshness windows and replay protections retained,
- no trust in static pass/fail toggles (`gate_passed` remains rejected),
- preserve measured-evidence-only model.

Validation:
- `./scripts/ci/check_phase9_readiness.sh`
- `./scripts/ci/check_phase10_readiness.sh`
- `./scripts/ci/phase9_gates.sh`
- `./scripts/ci/phase10_gates.sh`

Exit criteria:
- operations evidence generation is Rust-backed with parity outputs.

## Phase H: Phase1 Performance Measured Input Migration
Scope:
- replace shell+python measured env collector and baseline launcher logic with Rust.

Recommended Rust command additions:
- `rustynet ops collect-phase1-measured-input`
- `rustynet ops run-phase1-baseline`

Security controls:
- remove `source` of generated shell files from baseline flow,
- validate numeric ranges and required metrics with strict typed parsing,
- enforce secure source/output filesystem permissions (reject group/world writable paths),
- produce deterministic output files with explicit permissions.

Validation:
- `./scripts/perf/run_phase1_baseline.sh`,
- `./scripts/ci/phase1_gates.sh`,
- `./scripts/ci/perf_regression_gate.sh`.

Exit criteria:
- measured-input derivation and phase1 baseline orchestration are Rust-backed.

## Phase I (In Progress): E2E Remote Orchestrator Migration
Scope:
- keep `scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh` as an `exec rustynet ...` wrapper only.
- migrate orchestration flow to `rustynet ops run-debian-two-node-e2e`.
- follow-up: refresh lab validation evidence for the argv-only remote execution path and keep guardrails that prevent shell-path regression.

Why in progress:
- high complexity but lower production-runtime risk than phases E-H,
- still high security value for privileged remote orchestration and reproducibility.

## 12) Implementation Pattern (Apply To Every Phase)
1. Add Rust command with strict typed argument/env parsing.
2. Add unit tests for parsing/validation + negative permission/path cases.
3. Preserve current interface via thin shell wrapper (`exec rustynet ...`).
4. Run mandatory gates and VM matrix for the impacted scope.
5. Document behavior and rollback in README/operations docs.
6. Keep wrapper for one release cycle, then remove dead shell logic.

## 13) Sequencing Recommendation
Execute in this order:
1. Phase E
2. Phase F
3. Phase G
4. Phase H
5. Phase I (optional)

Rationale:
- starts with highest secret/privileged runtime risk,
- then secures release/evidence integrity pipeline,
- then removes remaining shell/Python evidence glue,
- finally addresses less critical but complex e2e orchestration.
