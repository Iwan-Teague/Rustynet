# Parallel Shell/Python -> Rust Migration Delegation Map

Date: 2026-03-21

## Objective
Move remaining shell/Python logic to Rust in parallel without overlap, with security-first behavior and fail-closed defaults preserved.

## Remaining Inventory
- Shell scripts remaining: 78
- Python scripts remaining: 9
- Product runtime shell surface still active: 2 scripts
- Product runtime Python surface: 0 scripts

## 4 Parallel Sections
| Section | Owner Agent | Remaining Files | Runtime Exposure | Primary Paths |
|---|---|---:|---|---|
| S1 Runtime Core | Agent A | 2 `.sh` | Direct runtime/setup | `start.sh`, `scripts/systemd/install_rustynetd_service.sh` |
| S2 E2E/Live Lab | Agent B | 27 `.sh` | Test/lab runtime | `scripts/e2e/*.sh`, `scripts/operations/*.sh` |
| S3 CI/Release/Perf | Agent C | 48 `.sh` | CI/release only | `scripts/ci/*.sh`, `scripts/release/*.sh`, `scripts/perf/*.sh`, `scripts/fuzz/*.sh`, `artifacts/perf/phase1/measured_env.sh` |
| S4 Skill Tooling | Agent D | 1 `.sh` + 9 `.py` | Skill-only tooling | `tools/skills/install_rustynet_security_auditor.sh`, `tools/skills/rustynet-security-auditor/scripts/*.py` |

## Section Ownership and Scope

## S1 Runtime Core (Agent A)
### In scope
- `start.sh`
- `scripts/systemd/install_rustynetd_service.sh`
- Required Rust command implementations for runtime extraction in `crates/rustynet-cli/src/*`

### Out of scope
- `scripts/e2e/*`
- `scripts/ci/*`
- `tools/skills/*`

### High-impact targets left
- Remaining privileged/bootstrap mutation paths in `start.sh`.
- Reduce `start.sh` to menu/UX + strict dispatcher.
- Keep systemd install wrapper thin or replace with direct Rust invocation path.

### Acceptance criteria
- No direct privileged mutation logic in `start.sh` except explicit package-manager/bootstrap boundaries.
- `start.sh` routes security-sensitive operations through `rustynet ops` only.
- Fail-closed behavior preserved for all migrated paths.

### Required validation
- `bash -n start.sh`
- `cargo fmt --all -- --check`
- `cargo clippy -p rustynet-cli --all-targets --all-features -- -D warnings`
- `cargo test -p rustynet-cli`

## S2 E2E/Live Lab (Agent B)
### In scope
- `scripts/e2e/*.sh`
- `scripts/operations/*.sh`

### Out of scope
- `start.sh`
- `scripts/ci/*`
- `tools/skills/*`

### High-impact targets left
- `scripts/e2e/live_linux_lab_orchestrator.sh` (~3743 lines)
- `scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh` (~558)
- `scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh` (~546)
- `scripts/e2e/live_linux_exit_handoff_test.sh` (~511)
- `scripts/e2e/live_linux_lan_toggle_test.sh` (~499)
- `scripts/e2e/live_linux_cross_network_remote_exit_soak_test.sh` (~487)
- `scripts/operations/collect_network_discovery_info.sh` (~607)

### Migration objective
- Replace inline remote shell payload generation/execution with Rust ops commands.
- Keep shell scripts as thin wrappers/dispatchers where shell is still needed for orchestration.
- Preserve hardened evidence/report schemas already moved to Rust.

### Acceptance criteria
- No inline multi-line remote shell payload logic in active paths when equivalent Rust ops exists.
- Security-sensitive parsing/report generation in these scripts uses Rust ops only.
- Existing E2E entrypoint contract remains stable.

### Required validation
- `bash -n scripts/e2e/*.sh scripts/operations/*.sh`
- Targeted script dry-runs with `--help`/no-op modes where available
- `cargo check -p rustynet-cli`
- `cargo test -p rustynet-cli`

## S3 CI/Release/Perf (Agent C)
### In scope
- `scripts/ci/*.sh`
- `scripts/release/*.sh`
- `scripts/perf/*.sh`
- `scripts/fuzz/smoke.sh`
- `artifacts/perf/phase1/measured_env.sh`

### Out of scope
- `start.sh`
- `scripts/e2e/*`
- `tools/skills/*`

### High-impact targets left
- Gate orchestration chains still shell-heavy (`phase*`, `membership_gates.sh`, `security_regression_gates.sh`, `supply_chain_integrity_gates.sh`).
- Wrapper consistency and Rust-first gate dispatch standardization.

### Migration objective
- Convert shell gates from logic-heavy scripts into thin wrappers around Rust ops commands.
- Keep exact gate semantics and fail conditions.
- Remove duplicate shell parsing where equivalent Rust verification exists.

### Acceptance criteria
- CI/release/perf shell scripts become wrapper-level orchestration only.
- Security checks remain strict; no relaxed gates.
- All current gate entrypoints keep compatible CLI usage.

### Required validation
- `bash -n scripts/ci/*.sh scripts/release/*.sh scripts/perf/*.sh scripts/fuzz/smoke.sh`
- `./scripts/ci/phase10_gates.sh`
- `./scripts/ci/membership_gates.sh`
- `cargo check --workspace --all-targets --all-features`

## S4 Skill Tooling De-Python (Agent D)
### In scope
- `tools/skills/install_rustynet_security_auditor.sh`
- `tools/skills/rustynet-security-auditor/scripts/*.py` (9 files)

### Out of scope
- Product runtime scripts and daemon paths

### Files to migrate
- `tools/skills/rustynet-security-auditor/scripts/evaluate_live_coverage_promotion.py`
- `tools/skills/rustynet-security-auditor/scripts/generate_assessment_from_matrix.py`
- `tools/skills/rustynet-security-auditor/scripts/generate_assessment_report.py`
- `tools/skills/rustynet-security-auditor/scripts/generate_attack_matrix.py`
- `tools/skills/rustynet-security-auditor/scripts/generate_comparative_exploit_coverage.py`
- `tools/skills/rustynet-security-auditor/scripts/generate_live_lab_findings.py`
- `tools/skills/rustynet-security-auditor/scripts/live_lab_catalog.py`
- `tools/skills/rustynet-security-auditor/scripts/run_rustynet_live_validations.py`
- `tools/skills/rustynet-security-auditor/scripts/validate_live_lab_reports.py`

### Migration objective
- Replace Python scripts with Rust command equivalents.
- Update skill docs/invocation paths to Rust binaries.
- Keep assessment/report outputs stable and reproducible.

### Acceptance criteria
- Skill runs without Python dependency for core flows.
- Output schema compatibility is maintained or versioned with explicit migration note.

### Required validation
- Skill smoke run from `tools/skills/rustynet-security-auditor`
- `cargo check -p rustynet-cli`
- Any skill-specific fixture tests for output parity

## Parallel Work Contract (No-Conflict Rules)
1. Agent A owns `start.sh` and runtime command registration touches.
2. Agent B owns `scripts/e2e/*` and `scripts/operations/*` only.
3. Agent C owns `scripts/ci/*`, `scripts/release/*`, `scripts/perf/*`, `scripts/fuzz/*`, `artifacts/perf/*`.
4. Agent D owns `tools/skills/*` Python removal and installer updates.
5. If shared Rust command registry edits are required, each agent must confine changes to section-specific command prefixes and rebase frequently.

## Suggested Delegation Prompts
Use these directly when assigning each agent.

### Prompt A
Migrate S1 Runtime Core only: `start.sh` and `scripts/systemd/install_rustynetd_service.sh`. Keep security-sensitive flows fail-closed and routed through Rust `ops` commands. Do not modify `scripts/e2e`, `scripts/ci`, or `tools/skills`.

### Prompt B
Migrate S2 E2E/Live Lab only: `scripts/e2e/*` and `scripts/operations/*`. Replace inline shell payload logic with Rust ops where possible. Keep script interfaces stable. Do not modify `start.sh`, `scripts/ci`, or `tools/skills`.

### Prompt C
Migrate S3 CI/Release/Perf only: `scripts/ci/*`, `scripts/release/*`, `scripts/perf/*`, `scripts/fuzz/*`, `artifacts/perf/*`. Convert logic-heavy shell gates to thin Rust wrappers while preserving strict failure behavior.

### Prompt D
Migrate S4 Skill tooling only: remove Python dependence from `tools/skills/rustynet-security-auditor/scripts/*.py` and update `tools/skills/install_rustynet_security_auditor.sh` and skill docs accordingly. Keep output schema compatibility.

