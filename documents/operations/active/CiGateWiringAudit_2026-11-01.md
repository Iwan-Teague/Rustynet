# CI Gate Wiring Audit (2026-11-01)

**Status: factual inventory, no wiring changes.** This records which scripts under
`scripts/ci/` are executed by a GitHub workflow and which are not, so the owner can
decide what to wire. Nothing here wires a gate; wiring a gate is a cost and risk
decision (runner minutes, runner-image tools such as `rg`, and whether the gate is
green on that leg today).

Measured on the tree of `claude/rustynet-mac-merge-4kfuey`
(`d54625ff`) plus the CI-gate commits that introduced this document. Re-run the
method below to refresh; do not trust a count in prose over the command.

## Method (reproducible)

"Wired" means the script's file name appears on a **non-comment line** of
`.github/workflows/cross-platform-ci.yml` or `.github/workflows/release.yml`.

```
# every script under scripts/ci (including lib/ and tests/)
find scripts/ci -name '*.sh' | sort

# workflow references for one script (word-boundary, fixed string)
rg -n -w -F -- '<script>.sh' .github/workflows

# any other textual reference (scripts, crates, start.sh)
rg -n -w -F -- '<script>.sh' scripts crates .github start.sh
```

Job names come from the top-level keys under `jobs:` that precede the referencing line.
`-w` matters: without it `required_test.sh` also matches `run_required_test.sh`.
A workflow reference proves the step exists, not that it is green or unconditional.
The "referenced from" column in the second table is textual and is **not** proof of
invocation (several hits are comments or lists in the MCP `gate_runner`).

## Summary

| Category | Count |
| --- | --- |
| Files under `scripts/ci/` (all depths) | 69 |
| Wired in a workflow | 22 (21 gates + `bootstrap_ci_tools.sh`) |
| Not in any workflow | 47 |
| of which gates | 37 (36 existing + `blind_exit_irreversibility_gates.sh`, added by this change) |
| of which self-tests | 4 (2 existing + `test_required_test_lib.sh`, `test_windows_cross_compile_gate.sh`, added by this change) |
| of which utilities / helper / manual witnesses | 3 / 1 / 2 |

## Findings recorded while auditing

1. **`anchor_secret_redaction_gates.sh` is wired (macOS and Debian 13 legs) but fails on the
   branch base.** Running the base's own copy exits 1 at the static pre-check:
   `rg` pattern 1 (`anchor_bundle_pull:.*(raw_token|token_material| token=|secret|presented|expected)`)
   matches test-fixture literals at
   `crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/anchor.rs:1403`, `:1410` and `:1421`
   (inside `#[cfg(test)]`, fed to `evaluate_bundle_pull_journal`; not log emissions). The gate's
   exemption mechanism covers exactly one fixture in `live_linux_anchor_test.rs`, so these three
   are unexempted. This needs an owner/security decision (extend the exemption by exact content, or
   restructure the fixtures); it was not changed here because it edits a security gate's
   exemption list. `test_required_test_lib.sh` records the block explicitly and fails the day it is lifted.
2. **No gate script runs on the Windows leg.** The `windows` job runs `cargo fmt/clippy/nextest` and
   `cargo audit/deny` only. Windows-specific gates (`windows_cross_compile_gate.sh`,
   `windows_compile_check.sh`) are unwired; `windows_cross_compile_gate.sh` now fails (exit 65) when it
   checks nothing instead of passing.
3. **Most unwired gates are reachable only from Rust phase runners.** `phase*_gates.sh` chain through
   `crates/rustynet-cli/src/bin/phase{5,6,7,8}_gates.rs` and `ops_ci_release_perf.rs` (`run_script(...)`
   for `phase8_gates.sh`, `check_phase9_readiness.sh`, `phase10_cross_network_exit_gates.sh`,
   `secrets_hygiene_gates.sh`, `role_auth_matrix_gates.sh`, `traversal_adversarial_gates.sh`,
   `no_leak_dataplane_gate.sh`, `windows_cross_compile_gate.sh`). Those runners run when an operator
   invokes `phase9_gates.sh` / `phase10_gates.sh` / `release_readiness_gates.sh` locally; no workflow does.
4. **`role_taxonomy_gates.sh` is deliberately unwired** (comment in `cross-platform-ci.yml`: it "has not
   been re-measured green on both legs since" the pipefail sweep). Its category siblings
   (`llm_exit_coexistence_gates.sh`, `role_taxonomy_gates.sh`) are reached only via
   `service_hosting_role_gates.sh`, which is itself unwired.
5. **Hermetic, cheap candidates** (pure bash, no cargo, no lab): `gate_exit_code_gates.sh`,
   `test_required_test_lib.sh`, `test_windows_cross_compile_gate.sh`. They are the only checks that
   guard the gate scripts themselves (QH-16 exit-code hygiene, no bare `cargo test <filter>`, the
   zero-match guard, the zero-leg Windows guard).
6. **Other lockfiles.** The workflow's `cargo audit --deny warnings` reads only the root `Cargo.lock`.

   | Lockfile | Audited by CI? | Audit result on 2026-11-01 (`cargo audit --deny warnings --file ...`, advisory DB of that day) |
   | --- | --- | --- |
   | `Cargo.lock` | yes (macOS, Debian 13, Windows jobs) | clean in CI |
   | `crates/rustynet-lab-monitor/Cargo.lock` | **yes, as of this change** (step 5 of `lab_monitor_gates.sh`; CI sets `RUSTYNET_REQUIRE_CARGO_AUDIT=1`) | was **failing**: tokio 1.52.3, RUSTSEC-2026-0386 (unsound); pinned to the patched 1.51.6 (the root lockfile's version), now clean |
   | `gui/node-map-tool/Cargo.lock` | no | **3 vulnerabilities + 3 warnings**: quick-xml 0.39.4 (RUSTSEC-2026-0194, RUSTSEC-2026-0195), webbrowser 1.2.1 (RUSTSEC-2026-0257); warnings ttf-parser (unmaintained, RUSTSEC-2026-0192), memmap2 0.9.10 (unsound, RUSTSEC-2026-0186), clipboard-win 5.4.1 (yanked). Not gated; `gui/` is outside every `--workspace` command and has no CI wiring. Needs dependency updates and a build, left for the owner |
   | `third_party/boringtun/Cargo.lock` | no | informational only: it is the vendored crate's own lockfile and is not used when the root workspace builds it as a path dependency (the root `Cargo.lock` governs); `cargo audit` on it reports 2 vulnerabilities and 6 warnings (e.g. RUSTSEC-2026-0204, RUSTSEC-2025-0055) |
   | `fuzz/` | n/a | no tracked `Cargo.lock`; `fuzz_build_gate.sh` builds unlocked |

## Scripts

### Wired in a workflow

| Script | Kind | Workflow: job(s) |
| --- | --- | --- |
| `anchor_secret_redaction_gates.sh` | gate | cross-platform-ci: debian13, macos |
| `bootstrap_ci_tools.sh` | tool bootstrap | cross-platform-ci: debian13, linux_e2e, macos, mobile_ffi, supply_chain |
| `bootstrap_macos_hardening_gates.sh` | gate | cross-platform-ci: macos |
| `check_agents_claude_mirror.sh` | gate | cross-platform-ci: debian13, macos |
| `check_backend_boundary_leakage.sh` | gate | cross-platform-ci: debian13, macos |
| `check_platform_infer_tripwire.sh` | gate | cross-platform-ci: debian13 |
| `check_release_verifier_key_pin.sh` | gate | release.yml: manifest |
| `delegated_edit_marker_gate.sh` | gate | cross-platform-ci: debian13 |
| `fuzz_build_gate.sh` | gate | cross-platform-ci: debian13, macos |
| `lab_monitor_gates.sh` | gate | cross-platform-ci: debian13, macos |
| `llm_default_deny_gates.sh` | gate | cross-platform-ci: debian13, macos |
| `membership_gates.sh` | gate | cross-platform-ci: debian13, macos |
| `mobile_unsafe_confinement_gate.sh` | gate | cross-platform-ci: mobile_ffi |
| `nas_default_deny_gates.sh` | gate | cross-platform-ci: debian13, macos |
| `release_workflow_windows_leg_gate.sh` | gate | cross-platform-ci: debian13 |
| `role_auth_matrix_gates.sh` | gate | cross-platform-ci: debian13, macos |
| `role_transition_audit_gates.sh` | gate | cross-platform-ci: debian13, macos |
| `secrets_hygiene_gates.sh` | gate | cross-platform-ci: debian13, macos |
| `security_regression_gates.sh` | gate | cross-platform-ci: debian13, macos |
| `supply_chain_integrity_gates.sh` | gate | cross-platform-ci: debian13, macos |
| `vm_lab_seam_release_hygiene_gate.sh` | gate | cross-platform-ci: macos |
| `windows_provisioner_download_integrity_gates.sh` | gate | cross-platform-ci: debian13 |

### Not in any workflow

| Script | Kind | Referenced from (textual, `rg -F`; not necessarily an invocation) |
| --- | --- | --- |
| `active_network_security_gates.sh` | gate | `mcp/gate_runner.rs` |
| `anchor_downgrade_gates.sh` | gate | nothing |
| `anchor_live_lab_gates.sh` | gate | `ci/test_required_test_lib.sh` |
| `anchor_role_gates.sh` | gate | `mcp/gate_runner.rs` |
| `blind_exit_irreversibility_gates.sh` | gate | nothing |
| `chaos_gates.sh` | gate | nothing |
| `check_dependency_exceptions.sh` | gate | `cli/bin/phase8_gates.rs`, `mcp/gate_runner.rs` |
| `check_fresh_install_os_matrix_readiness.sh` | gate | nothing |
| `check_mcp_binaries_fresh.sh` | utility | `vm_lab/lab_preflight.sh` |
| `check_phase10_readiness.sh` | gate | `cli/ops_phase9.rs` |
| `check_phase6_platform_parity.sh` | gate | nothing |
| `check_phase9_readiness.sh` | gate | `cli/ops_ci_release_perf.rs`, `cli/ops_phase9.rs` |
| `cross_platform_role_gates.sh` | gate | nothing |
| `fresh_install_os_matrix_release_gate.sh` | gate | `cli/ops_ci_release_perf.rs` |
| `gate_exit_code_gates.sh` | gate | `ci/test_required_test_lib.sh` |
| `lib/required_test.sh` | helper (sourced) | `ci/anchor_downgrade_gates.sh`, `ci/anchor_live_lab_gates.sh`, `ci/anchor_role_gates.sh`, `ci/anchor_secret_redaction_gates.sh`, `ci/blind_exit_irreversibility_gates.sh`, `ci/cross_platform_role_gates.sh`, `ci/gate_exit_code_gates.sh`, `ci/lab_monitor_gates.sh`, `ci/linux_exit_role_gates.sh`, `ci/llm_default_deny_gates.sh`, `ci/llm_exit_coexistence_gates.sh`, `ci/membership_gates.sh`, `ci/nas_default_deny_gates.sh`, `ci/orchestrator_engine_gates.sh`, `ci/role_taxonomy_gates.sh`, `ci/role_transition_audit_gates.sh`, `ci/service_hosting_role_gates.sh`, `ci/test_required_test_lib.sh` |
| `linux_exit_role_gates.sh` | gate | nothing |
| `llm_exit_coexistence_gates.sh` | gate | `ci/service_hosting_role_gates.sh` |
| `no_leak_dataplane_gate.sh` | gate | `cli/ops_ci_release_perf.rs`, `mcp/gate_runner.rs` |
| `orchestrator_engine_gates.sh` | gate | nothing |
| `perf_regression_gate.sh` | gate | `cli/bin/phase5_gates.rs` |
| `phase10_cross_network_exit_gates.sh` | gate | `cli/ops_ci_release_perf.rs` |
| `phase10_gates.sh` | gate | `cli/bin/release_readiness_gates.rs`, `mcp/gate_runner.rs` |
| `phase10_hp2_gates.sh` | gate | nothing |
| `phase1_gates.sh` | gate | nothing |
| `phase3_gates.sh` | gate | nothing |
| `phase4_gates.sh` | gate | `cli/bin/phase5_gates.rs` |
| `phase5_gates.sh` | gate | `cli/bin/phase6_gates.rs`, `cli/bin/release_readiness_gates.rs` |
| `phase6_gates.sh` | gate | `cli/bin/phase7_gates.rs` |
| `phase7_gates.sh` | gate | `cli/bin/phase8_gates.rs` |
| `phase8_gates.sh` | gate | `cli/ops_ci_release_perf.rs` |
| `phase9_gates.sh` | gate | `mcp/gate_runner.rs` |
| `regression_coverage_gates.sh` | gate | nothing |
| `release_readiness_gates.sh` | gate | `mcp/gate_runner.rs` |
| `role_taxonomy_gates.sh` | gate | `ci/role_transition_audit_gates.sh`, `ci/service_hosting_role_gates.sh`, `ci/tests/pipefail_sigpipe_race_witness.sh` |
| `run_required_test.sh` | utility | `cli/ops_ci_release_perf.rs`, `cli/vm_lab/orchestrator/stage/cross_network/scenario/host.rs` |
| `service_hosting_role_gates.sh` | gate | nothing |
| `test_check_fresh_install_os_matrix_readiness.sh` | self-test | `cli/ops_ci_release_perf.rs` |
| `test_required_test_lib.sh` | self-test | `ci/lib/required_test.sh` |
| `test_validate_cross_network_remote_exit_reports.sh` | self-test | nothing |
| `test_windows_cross_compile_gate.sh` | self-test | nothing |
| `tests/pipefail_sigpipe_race_witness.sh` | witness (manual) | nothing |
| `tests/self_exec_replaced_binary_witness.sh` | witness (manual) | nothing |
| `traversal_adversarial_gates.sh` | gate | `cli/ops_ci_release_perf.rs`, `mcp/gate_runner.rs` |
| `vendored_unsafe_drift_gate.sh` | gate | `cli/bin/check_vendored_unsafe_counts.rs`, `ci/mobile_unsafe_confinement_gate.sh` |
| `windows_compile_check.sh` | utility | nothing |
| `windows_cross_compile_gate.sh` | gate | `cli/ops_ci_release_perf.rs`, `ci/test_windows_cross_compile_gate.sh` |

## Same-review items deliberately not fixed in this change

- **The CI e2e "kill-switch" check cannot fail** (`TestQualityReview_2026-07-30.md` section 5.5; verified
  again here). In `crates/rustynet-cli/src/bin/real_wireguard_exitnode_e2e.rs` the
  `kill_switch_blocks_egress_when_tunnel_down` verdict is "ping fails" after `wg0` is set down and the
  default route is deleted. The client namespace is left with only the connected `172.16.10.0/24` route,
  so the ping fails by routing-table arithmetic whether or not any kill-switch exists, and
  `run_expect_failure_ns` accepts any non-zero exit. Not changed because the environment that did this
  work has no `ip`, `wg`, `nft` or `tcpdump`, so a rewrite of the namespace choreography could be neither
  run nor partly validated, and this is the only live scenario CI executes (a blind edit risks a
  permanently red job or a check that is still vacuous). Design for whoever has a root netns host:
  (1) give the client an underlay default route (`via 172.16.10.1`, metric 600) and let the exit
  namespace forward and masquerade `172.16.10.0/24` to the inet namespace, so a leak path exists;
  (2) add a positive control: with the tunnel down and no kill-switch the probe must **succeed**;
  (3) install the kill-switch (an nft `output` chain, policy drop, accept `lo`, `wg0` and udp/51820 to
  the exit endpoint, final `counter drop`; better, drive the real `rustynetd` kill-switch table);
  (4) assert the drop counter is non-zero and no reply arrived. Do not key on ping exit code 1: an
  output-hook drop makes `sendmsg` fail with EPERM and iputils ping then exits 2;
  (5) surface the control as its own field in `RealWireguardExitnodeE2eChecksView` and `overall_status`
  in `ops_live_lab_orchestrator.rs` so a missing control fails the report.

## Decisions for the owner

- Which of the unwired gates should run on which leg, and with what tool provisioning (`rg`
  is not guaranteed on runner images; the existing security-gate step installs it with
  `command -v rg || brew install ripgrep`).
- Whether to resolve finding 1 (a red wired gate) before anything else is wired.
- Whether to give `gui/node-map-tool` an audit step (finding 6) and update its dependencies.
