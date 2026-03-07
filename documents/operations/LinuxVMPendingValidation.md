# Linux VM Pending Validation Queue

## Purpose
Track runtime/security changes that are **not yet deployed and verified on Linux VMs**.

Rule:
1. Any runtime-affecting code change must be added here before VM deployment.
2. An item can be marked `PASSED` only after required VM checks pass and evidence is logged.
3. If any VM check fails, keep item `PENDING`/`FAILED` until patch + re-test succeeds.

## VM Inventory (Current)
Update this first if IPs/hostnames changed.

| VM | OS | IP | Notes |
|---|---|---|---|
| debian-a | Debian 13 | `192.168.18.49` | primary Debian validation node |
| debian-b | Debian 13 | `192.168.18.50` | secondary Debian validation node |
| ubuntu-a | Ubuntu | `192.168.18.46` | Ubuntu compatibility node |
| fedora-a | Fedora | `192.168.18.51` | Fedora compatibility node |
| mint-a | Linux Mint | `192.168.18.53` | Mint compatibility node |

## Status Legend
- `PENDING`: not yet validated on required VMs.
- `IN_PROGRESS`: validation started, not complete.
- `PASSED`: required VM checks passed.
- `FAILED`: validation failed; patch required.

## Current Pending Change Sets (Not Yet VM-Verified)

### LNX-2026-03-06-01: Phase1 measured-input pipeline migrated/hardened in Rust
- Status: `PENDING`
- Priority: High
- Runtime impact: High (perf evidence pipeline + gate inputs)
- Files:
  - `crates/rustynet-cli/src/ops_phase1.rs`
  - `crates/rustynet-cli/src/main.rs`
  - `scripts/perf/collect_phase1_measured_env.sh`
  - `scripts/perf/run_phase1_baseline.sh`
- Change summary:
  - Replaced shell/Python collector path with Rust ops commands.
  - Removed shell `source` path from active baseline flow.
  - Added fail-closed measured-evidence checks and permission hardening.
- Required VM coverage:
  - `debian-a`, `ubuntu-a`, `fedora-a`, `mint-a`
- Required checks (run in repo root on each VM):
```bash
cargo check -p rustynet-cli
cargo test -p rustynet-cli -- --nocapture
./scripts/perf/collect_phase1_measured_env.sh
./scripts/perf/run_phase1_baseline.sh
./scripts/ci/perf_regression_gate.sh
```
- Pass criteria:
  - All commands above succeed.
  - `artifacts/perf/phase1/measured_input.json` is generated.
  - `artifacts/perf/phase1/baseline.json` and `artifacts/perf/phase1/backend_contract_perf.json` are generated.
  - No synthetic/unmeasured fallback path used.

### LNX-2026-03-06-02: start.sh one-step "exit local LAN access" UX toggle
- Status: `PENDING`
- Priority: High
- Runtime impact: High (client connectivity UX + exit LAN behavior)
- Files:
  - `start.sh`
- Change summary:
  - Toggle now auto-switches on/off using daemon status.
  - After exit selection, user gets one yes/no prompt to enable LAN access immediately.
  - Fail-closed behavior retained (requires selected exit node, blocks blind_exit role).
- Required VM coverage:
  - `debian-a`, `ubuntu-a`, `fedora-a`, `mint-a`
- Required checks:
```bash
bash -n start.sh
./start.sh
```
Manual runtime checks in menu:
1. Select an exit node.
2. Accept the prompt to enable local LAN access.
3. Verify `rustynet status` shows LAN access enabled.
4. Use toggle again; verify LAN access disables.
5. Verify enabling without selected exit node is denied.
6. On a blind_exit-role node, verify LAN toggle is denied.
- Pass criteria:
  - All manual checks behave exactly as above.
  - No role bypass or silent failure.

### LNX-2026-03-06-03: Phase G migration (Phase9/Phase10 evidence pipeline to Rust)
- Status: `PENDING`
- Priority: High
- Runtime impact: Medium-High (operations evidence collection/generation path)
- Files:
  - `crates/rustynet-cli/src/ops_phase9.rs`
  - `crates/rustynet-cli/src/main.rs`
  - `scripts/operations/collect_phase9_raw_evidence.sh`
  - `scripts/operations/generate_phase9_artifacts.sh`
  - `scripts/operations/generate_phase10_artifacts.sh`
- Change summary:
  - Added Rust ops command for phase9 raw evidence collection.
  - Added Rust ops commands for phase9/phase10 artifact generation.
  - Removed shell/Python collection+generation logic from active scripts; wrappers now dispatch to Rust only.
  - Readiness checks are still enforced (`check_phase9_readiness.sh`, `check_phase10_readiness.sh`).
- Required VM coverage:
  - `debian-a`, `ubuntu-a`, `fedora-a`, `mint-a`
- Required checks:
```bash
cargo check -p rustynet-cli
cargo test -p rustynet-cli -- --nocapture
./scripts/operations/collect_phase9_raw_evidence.sh
RUSTYNET_PHASE9_EVIDENCE_ENVIRONMENT=vm ./scripts/operations/generate_phase9_artifacts.sh
RUSTYNET_PHASE10_EVIDENCE_ENVIRONMENT=vm ./scripts/operations/generate_phase10_artifacts.sh
./scripts/ci/check_phase9_readiness.sh
./scripts/ci/check_phase10_readiness.sh
```
- Pass criteria:
  - Raw collector script succeeds and produces measured raw phase9 artifacts.
  - Both generator scripts succeed and produce measured artifacts.
  - Readiness checks pass after generation.
  - No shell/Python collection or generation path is used.

### LNX-2026-03-06-04: WireGuard boundary leakage gate false-positive fix in rustynet-cli
- Status: `PENDING`
- Priority: Medium
- Runtime impact: Medium (installer/key-custody scan path + CI gate stability)
- Files:
  - `crates/rustynet-cli/src/main.rs`
  - `crates/rustynet-cli/src/ops_install_systemd.rs`
- Change summary:
  - Removed protocol-specific error wording that triggered leakage gate.
  - Kept secure key-custody artifact matching behavior while avoiding false-positive leakage signature.
- Required VM coverage:
  - `debian-a`, `ubuntu-a`
- Required checks:
```bash
cargo test -p rustynet-cli -- --nocapture
./scripts/ci/phase1_gates.sh
```
- Pass criteria:
  - CLI tests pass.
  - Phase1 gate passes, including boundary leakage scan.

### LNX-2026-03-07-02: Boundary leakage gate hardening (case-insensitive shared scanner)
- Status: `PENDING`
- Priority: High
- Runtime impact: Medium (release-gate security enforcement path)
- Files:
  - `scripts/ci/check_backend_boundary_leakage.sh`
  - `scripts/ci/phase1_gates.sh`
  - `scripts/ci/phase3_gates.sh`
  - `scripts/ci/phase10_gates.sh`
  - `scripts/ci/membership_gates.sh`
  - `crates/rustynet-control/src/ga.rs`
  - `crates/rustynet-cli/src/ops_phase9.rs`
- Change summary:
  - Replaced duplicated, case-sensitive leakage regex checks with one shared case-insensitive scanner script.
  - Scanner now targets protocol-agnostic crate `src/` paths only to avoid test/ops false positives while hardening runtime boundaries.
  - Removed remaining protocol-specific token leakage from `rustynet-control` backend agility model (`ga.rs`).
  - Updated phase9 raw collector probe scan to match hardened token detection/scope.
- Required VM coverage:
  - `debian-a`, `ubuntu-a`
- Required checks:
```bash
cargo check --workspace --all-targets --all-features
cargo test -p rustynet-control ga::tests -- --nocapture
./scripts/ci/phase1_gates.sh
./scripts/ci/phase3_gates.sh
./scripts/ci/phase9_gates.sh
./scripts/ci/phase10_gates.sh
./scripts/ci/membership_gates.sh
```
- Pass criteria:
  - Shared boundary scanner runs in all listed gates.
  - Lowercase protocol token leakage is blocked in protocol-agnostic crates.
  - No regressions in phase3/phase9/phase10/membership gate chains.

### LNX-2026-03-07-03: Unsafe gate hardening for phase3 (parser-based scanner)
- Status: `PENDING`
- Priority: High
- Runtime impact: Medium (security CI gate correctness)
- Files:
  - `scripts/ci/check_no_unsafe_code.sh`
  - `scripts/ci/phase1_gates.sh`
  - `scripts/ci/phase3_gates.sh`
- Change summary:
  - Replaced phase3 naive regex unsafe check with parser-based Rust token scanner that ignores comments/strings/chars/raw strings.
  - Centralized unsafe scanner in shared script and reused from phase1 for consistent fail-closed unsafe policy.
  - Fixed scanner lifetime/label handling (`'a`, `'static`) so apostrophe tokens cannot desynchronize scanning and hide real `unsafe` usage.
  - Added compiler-enforced unsafe prohibition in phase3 (`RUSTFLAGS=-Dunsafe_code -Dunsafe_op_in_unsafe_fn`) as a second independent enforcement path.
  - Reduces false-positive gate bypass pressure without weakening unsafe-code prohibition.
- Required VM coverage:
  - `debian-a`, `ubuntu-a`
- Required checks:
```bash
./scripts/ci/check_no_unsafe_code.sh
./scripts/ci/phase1_gates.sh
./scripts/ci/phase3_gates.sh
RUSTFLAGS='-Dunsafe_code -Dunsafe_op_in_unsafe_fn' cargo check --workspace --all-targets --all-features
```
- Pass criteria:
  - Unsafe scanner reports pass on current source tree.
  - Lifetime-heavy Rust sources are parsed without scanner desynchronization gaps.
  - Phase3 no longer fails on string/test-token false positives.
  - Compiler rejects any workspace `unsafe` usage in phase3 gate path.
  - Any real `unsafe` keyword usage in Rust sources still fails gates.

### LNX-2026-03-07-01: Phase10 provenance defaults + secure keypair bootstrap for gates
- Status: `PENDING`
- Priority: High
- Runtime impact: Medium-High (phase10/membership gate execution path + provenance handling)
- Files:
  - `crates/rustynet-cli/src/ops_phase9.rs`
  - `scripts/ci/phase10_gates.sh`
- Change summary:
  - Added secure default provenance paths (`artifacts/phase10/provenance/*`) when explicit provenance env vars are unset.
  - Added fail-closed keypair bootstrap in Rust for phase10 generation (owner-only `0600` key files under `0700` directory).
  - Removed manual provenance env-var hard requirement from `phase10_gates.sh`; readiness verification still enforced.
- Required VM coverage:
  - `debian-a`, `ubuntu-a`
- Required checks:
```bash
cargo check -p rustynet-cli
cargo test -p rustynet-cli -- --nocapture
./scripts/ci/phase10_gates.sh
./scripts/ci/membership_gates.sh
```
- Pass criteria:
  - `phase10_gates.sh` passes without pre-seeding provenance env vars.
  - `membership_gates.sh` passes without manual provenance env setup.
  - Generated provenance key files are owner-only and provenance verification remains pass/fail closed.

## Non-Runtime / Docs-Only Changes (No VM Runtime Validation Required)
- `README.md`
- `documents/operations/MeasuredEvidenceGeneration.md`
- `documents/operations/ShellToRustMigrationPlan_2026-03-06.md`
- `documents/operations/BackendAgilityValidation.md`

## Validation Execution Log
Record each VM run here.

| Date (UTC) | Change Set ID | Commit | VM | Result | Evidence (artifacts/notes) | Tester |
|---|---|---|---|---|---|---|
| _pending_ | LNX-2026-03-06-01 | _pending_ | debian-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-06-01 | _pending_ | ubuntu-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-06-01 | _pending_ | fedora-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-06-01 | _pending_ | mint-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-06-02 | _pending_ | debian-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-06-02 | _pending_ | ubuntu-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-06-02 | _pending_ | fedora-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-06-02 | _pending_ | mint-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-06-03 | _pending_ | debian-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-06-03 | _pending_ | ubuntu-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-06-03 | _pending_ | fedora-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-06-03 | _pending_ | mint-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-06-04 | _pending_ | debian-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-06-04 | _pending_ | ubuntu-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-01 | _pending_ | debian-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-01 | _pending_ | ubuntu-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-02 | _pending_ | debian-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-02 | _pending_ | ubuntu-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-03 | _pending_ | debian-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-03 | _pending_ | ubuntu-a | _pending_ | _pending_ | _pending_ |

## PR / Commit Gate for This Queue
Before marking a change set `PASSED`:
1. Code is committed and pushed.
2. Latest commit is pulled on required VMs.
3. Required checks pass on each required VM.
4. This document is updated with evidence.
5. Only then remove from pending queue or mark `PASSED`.
