# Shell-to-Rust Security Migration Analysis (2026-03-06)

## Scope and Method
- Reviewed all `*.sh` files under `start.sh` and `scripts/`.
- Prioritized by security impact, not by script size alone.
- Security criteria used:
  - privilege boundary exposure (root/sudo/system-level actions),
  - untrusted input handling and command construction patterns,
  - interpreter variability (`bash` + inline `python`) and parsing ambiguity,
  - ability to enforce typed validation and deterministic behavior in Rust,
  - testability and fail-closed behavior.

## Executive Summary
- Highest-security migration target is `start.sh` due to privileged orchestration and large interactive input surface.
- The two files you called out (`collect_phase1_measured_env.sh`, `run_phase1_baseline.sh`) are good near-term Rust migrations because they currently depend on mixed shell/Python logic and one script executes `source` on generated shell content.
- `debian_two_node_clean_install_and_tunnel_test.sh` is another strong candidate: remote root operations rely on shell command-string composition (`bash -lc`) even though the script has safeguards.
- Several small shell wrappers (`scripts/systemd/*.sh`) already delegate to Rust (`rustynet ops ...`), so migration security gain is low there.

## Top Migration Candidates (Security-Driven)

### 1) `start.sh` (Highest impact)
- Why security gain is high:
  - Very large privileged control surface (`4553` lines), including root service actions (`systemctl`, `launchctl`, `wg`, `ip`) and interactive inputs.
  - Break-glass manual peer paths execute privileged dataplane mutations from interactive values.
- Evidence:
  - root execution helper: `run_root` ([start.sh:575](../../start.sh#L575)),
  - manual peer privileged commands: [start.sh:3330](../../start.sh#L3330), [start.sh:3349](../../start.sh#L3349), [start.sh:3370](../../start.sh#L3370),
  - service lifecycle privileged calls: [start.sh:2557](../../start.sh#L2557), [start.sh:2599](../../start.sh#L2599).
- Rust migration recommendation:
  - Split into typed Rust subcommands (`rustynet ops ...`) for service lifecycle, setup preflight, and break-glass peer actions.
  - Keep shell only as a thin menu wrapper (or replace menu with Rust TUI/CLI).
- Security uplift:
  - Stronger typed input validation, less shell parsing ambiguity, easier unit/integration tests around privileged boundaries.

### 2) `scripts/perf/run_phase1_baseline.sh` + `scripts/perf/collect_phase1_measured_env.sh` (High value, medium effort)
- Why security gain is meaningful:
  - Mixed shell + inline Python data pipeline.
  - `run_phase1_baseline.sh` sources generated shell (`source "$PHASE1_MEASURED_ENV_FILE"`), which is a shell execution boundary.
- Evidence:
  - source execution: [scripts/perf/run_phase1_baseline.sh:40](../../scripts/perf/run_phase1_baseline.sh#L40),
  - dynamic executable permission change: [scripts/perf/run_phase1_baseline.sh:32](../../scripts/perf/run_phase1_baseline.sh#L32),
  - embedded Python parser/emitter in collector: [scripts/perf/collect_phase1_measured_env.sh:57](../../scripts/perf/collect_phase1_measured_env.sh#L57).
- Rust migration recommendation:
  - Replace both with one Rust command that:
    - parses measured artifacts directly,
    - validates numeric bounds/types,
    - passes values to baseline generation without `source`.
  - Use structured output (`json`) instead of generated shell env script.
- Security uplift:
  - Removes shell code execution step (`source`) and interpreter variability.

### 3) `scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh` (High value, higher effort)
- Why security gain is high:
  - Performs remote root operations over SSH and uses command-string composition for remote execution.
  - Uses `sudo ... bash -lc '...'` with escaped command strings; this is controlled but still a fragile pattern.
- Evidence:
  - remote command string path: [scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh:328](../../scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh#L328), [scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh:331](../../scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh#L331),
  - explicit `bash -lc` with sudo over SSH: [scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh:357](../../scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh#L357), [scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh:708](../../scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh#L708).
- Rust migration recommendation:
  - Implement a Rust orchestrator using strict argument modeling for remote actions and explicit command payload construction.
  - Keep remote scripts as static templates with parameter binding, avoid ad-hoc command strings.
- Security uplift:
  - Reduces command-string injection risk and improves auditing of remote privileged actions.

## Medium Candidates (Selective migration)

### `scripts/operations/collect_phase9_raw_evidence.sh`
- Mixed shell + embedded Python parsing and artifact generation.
- Lower privilege than runtime scripts; mostly CI/operations evidence generation.
- Rust migration benefit is mainly integrity/maintainability, not immediate runtime exploit reduction.

### `scripts/operations/generate_phase10_artifacts.sh` and `scripts/operations/generate_phase9_artifacts.sh`
- Similar pattern: shell wrapper + Python validation.
- Moderate benefit if unified into typed Rust artifact validators.

## Low Priority / Low Security ROI to migrate now

### `scripts/systemd/install_rustynetd_service.sh`, `scripts/systemd/refresh_trust_evidence.sh`, `scripts/systemd/refresh_assignment_bundle.sh`
- These are already thin wrappers that enforce binary checks then `exec` into Rust ops commands.
- Evidence:
  - install wrapper exec to Rust: [scripts/systemd/install_rustynetd_service.sh:47](../../scripts/systemd/install_rustynetd_service.sh#L47),
  - trust refresh wrapper exec to Rust: [scripts/systemd/refresh_trust_evidence.sh:45](../../scripts/systemd/refresh_trust_evidence.sh#L45),
  - assignment refresh wrapper exec to Rust: [scripts/systemd/refresh_assignment_bundle.sh:45](../../scripts/systemd/refresh_assignment_bundle.sh#L45).
- Security improvement from migration is marginal because trust-sensitive logic already lives in Rust.

### Most `scripts/ci/*.sh`
- Important for pipeline rigor, but low runtime attack surface.
- Prefer targeted hardening over full migration unless CI policy requires Rust-only tooling.

## Focus Notes for the Two Files Your Other Agent Is Working On

### `collect_phase1_measured_env.sh`
- Keep behavior fail-closed on missing/invalid metrics.
- Preserve alias handling and strict numeric finite/non-negative checks currently implemented.
- Replace inline Python with Rust parser and eliminate generated shell as primary handoff format.

### `run_phase1_baseline.sh`
- Remove `source` dependency entirely.
- Consume structured measured output (JSON or direct Rust API call) and set metrics in-process.
- Preserve required-key/status gating currently enforced via `rg` checks.

## Recommended Migration Order (Security-First)
1. `scripts/perf/collect_phase1_measured_env.sh` + `scripts/perf/run_phase1_baseline.sh` (near-term, clear security gain, manageable scope).
2. Break-glass/manual-peer and service lifecycle slices from `start.sh` into Rust subcommands.
3. `scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh` remote orchestration hardening in Rust.
4. Optional: phase9/phase10 artifact-generation scripts into Rust validators.

## Suggested Boundaries (to avoid risky rewrites)
- Do not big-bang replace `start.sh` in one PR.
- Incrementally replace high-risk functions first (manual peer ops, service management, key/trust custody orchestration).
- Keep output formats stable while migrating internals to Rust.

## Bottom Line
- Yes, migrating selected shell paths to Rust will improve security.
- Best immediate ROI: the Phase1 measured-env pair plus high-privilege slices of `start.sh`.
- Not all `.sh` should be migrated now; thin wrappers and CI-only scripts are lower security priority.
