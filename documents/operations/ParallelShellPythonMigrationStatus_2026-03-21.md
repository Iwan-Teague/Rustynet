# Parallel Shell/Python -> Rust Migration Status

Date: 2026-03-21
Source plan: `documents/operations/ParallelShellPythonMigrationDelegation_2026-03-21.md`

## Scope Summary
- Total `.sh` files in repo: 78
- Total `.py` files in repo: 9
- Python under active migration surface: 9 (`tools/skills/rustynet-security-auditor/scripts/*.py`)

## Section Status

### S1 Runtime Core (Agent A) - Partial complete
Completed:
- `scripts/systemd/install_rustynetd_service.sh` reduced to hardened Rust dispatcher path.
- `start.sh` signing-passphrase temp materialization moved to Rust op.
- New CLI op wired in `crates/rustynet-cli/src/main.rs` for secure passphrase temp materialization.

Remaining high-impact:
- Continue reducing `start.sh` privileged/logic-heavy flows to Rust ops calls.

### S2 E2E/Live Lab (Agent B) - Partial complete
Completed:
- Added Rust ops env-driven assignment/traversal bundle issue paths in `crates/rustynet-cli/src/ops_e2e.rs` and command wiring in `crates/rustynet-cli/src/main.rs`.
- Migrated key live-lab/e2e scripts to thin wrappers around Rust ops paths:
  - `scripts/e2e/live_lab_common.sh`
  - `scripts/e2e/live_linux_lab_orchestrator.sh`
  - `scripts/e2e/live_linux_exit_handoff_test.sh`
  - `scripts/e2e/live_linux_lan_toggle_test.sh`
  - `scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh`
  - `scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh`
  - `scripts/e2e/live_linux_cross_network_failback_roaming_test.sh`

Remaining high-impact:
- Continue migrating remaining heavy e2e shell orchestration and operations collectors.

### S3 CI/Release/Perf (Agent C + integration fixes) - Largely complete
Completed:
- Added consolidated CI/release/perf ops module:
  - `crates/rustynet-cli/src/ops_ci_release_perf.rs`
- Converted CI/release/perf/fuzz entry scripts to thin Rust-dispatch wrappers:
  - `scripts/ci/phase1_gates.sh`
  - `scripts/ci/phase9_gates.sh`
  - `scripts/ci/phase10_gates.sh`
  - `scripts/ci/membership_gates.sh`
  - `scripts/ci/supply_chain_integrity_gates.sh`
  - `scripts/ci/security_regression_gates.sh`
  - `scripts/ci/active_network_security_gates.sh`
  - `scripts/ci/phase10_hp2_gates.sh`
  - `scripts/ci/prepare_advisory_db.sh`
  - `scripts/release/generate_sbom.sh`
  - `scripts/release/create_provenance.sh`
  - `scripts/perf/run_phase3_baseline.sh`
  - `scripts/fuzz/smoke.sh`
- Hardening/integration fix applied:
  - `run-phase1-baseline` now receives explicit canonical measured source path via
    `RUSTYNET_PHASE1_PERF_SAMPLES_PATH` in `execute_ops_run_phase1_ci_gates`.

Remaining high-impact:
- Continue converting remaining logic-heavy CI shell scripts not yet reduced to wrappers.

### S4 Skill Tooling (Agent D) - Not started
Status:
- No accepted migration landed; draft was discarded because it was not compile-ready.

Remaining:
- Migrate all 9 `tools/skills/rustynet-security-auditor/scripts/*.py` commands to Rust equivalents.
- Update skill installer/invocation docs to Rust-only paths.

## Validation Results (Current Workspace)

Passing:
- `cargo fmt --all -- --check`
- `cargo check -p rustynet-cli`
- `cargo test -p rustynet-cli --bin rustynet-cli --all-features`
- `./scripts/ci/phase1_gates.sh` (PASS)
- `./scripts/ci/phase9_gates.sh` (PASS)

Failing (expected strict gate):
- `./scripts/ci/phase10_gates.sh` (FAIL)
  - Fails on commit-bound fresh-install evidence freshness/commit checks:
    `fresh_install_os_matrix_report evidence is stale; refresh OS matrix evidence`
- `./scripts/ci/membership_gates.sh` (FAIL)
  - Fails because it includes `phase10_gates` path and inherits the same strict stale-evidence failure.

## Security Note
- No gate bypasses were added.
- Fail-closed behavior is preserved: Phase 10 and Membership remain blocked until fresh install OS matrix evidence is regenerated for current commit and age window.
