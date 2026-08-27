# Test Inventory — 2026-07-30

A complete enumeration of every automated check in this repository: unit,
integration, property, doc, bench, fuzz, shell gate, CI job, and live-lab
scenario. Compiled by static reading only — no gate, test, script or VM was run
to produce it.

Companion document: `TestQualityReview_2026-07-30.md` reviews whether these
checks do what they claim. This one only says what exists and where it runs.

Related and not superseded: `TestCoverageImprovementPlan_2026-05-24.md` (what
coverage was planned), `LiveLabSecurityTestCoverage_2026-06-22.md` (threat matrix
for the live lab), `BashRetirementPlan_2026-07-24.md` (migration of the bash
surface to Rust).

---

## 1. Totals

| Measure | Count |
| --- | --- |
| `#[test]` / `#[tokio::test]` functions under `crates/` | **7,269** |
| Tests actually executed by the workspace test stage (nextest, measured 2026-07-30) | **~10,317** across 155 binaries |
| Integration test files (`crates/*/tests/`) | 18 files across 8 crates |
| Property-based suites | 1 (`rustynet-advisor`, 12 invariants) |
| Rust doc-tests | 1 testable fence in the whole workspace |
| Benches | 3 in-workspace (+5 vendored, uncompiled) |
| Fuzz targets | 3 |
| Shell gate scripts in `scripts/ci/` | **51** |
| All `.sh`/`.ps1` under `scripts/` | 173 |
| GitHub Actions workflows | 2 (`cross-platform-ci.yml`, `release.yml`) |
| GitHub Actions jobs | 6 (4 CI legs + 2 release jobs) |
| Live-lab / e2e scenario scripts and binaries | ~70 |
| Workspace crates | 21 members + 2 excluded + `fuzz/` |

The gap between 7,269 authored functions and ~10,317 executed tests is expected:
several crates build both a lib and a bin target from the same sources, so their
test modules are compiled and run twice.

---

## 2. What actually runs, and where

This is the single most important table in the document. Everything else is
detail beneath it.

| Runner | Scope | Trigger |
| --- | --- | --- |
| **CI: macOS leg** (`macos-14`) | full workspace nextest, `--all-targets --all-features --locked`, + `lab_monitor_gates.sh` | push to `main`, every PR |
| **CI: Debian 13 leg** (`ubuntu-latest`, `debian:trixie` container) | same as macOS | push to `main`, every PR |
| **CI: Windows leg** (`windows-2022`) | **10 of 21 packages**, `--no-fail-fast` | push to `main`, every PR |
| **CI: `linux_e2e` leg** (`ubuntu-latest`) | 1 real-WireGuard e2e scenario | push to `main`, every PR |
| **CI: release** | 5-target build matrix + manifest signing | tag `v*.*.*` or manual dispatch |
| **`cargo run -p rustynet-xtask -- gates`** | fmt → clippy → test, local convenience | human |
| **`scripts/ci/*.sh`** | 51 gates | **2 of 51** are referenced by a workflow |
| **`live_linux_lab_orchestrator.sh`** | 17-gate suite + ~60 lab stages | human, against a live 5-node VM lab |
| **MCP `gate-runner`** | any gate on demand | agent |

**Nothing is scheduled.** Neither workflow has a `schedule:` trigger, so
advisory scanning happens only when someone pushes.

---

## 3. Workspace unit tests, by crate

### 3.1 `rustynetd` — 2,201 tests (2,155 inline + 45 integration)

The largest surface in the repo.

| Module group | Location | Tests |
| --- | --- | --- |
| daemon (IPC envelope, authz, bundle-pull, trust/traversal application, config validation) | `src/daemon.rs:15820-19700` | 258 |
| phase10 (dataplane state machine, killswitch/NAT/DNS, `ManagementCidr`, route ACLs) | `src/phase10.rs:7082+` | 156 |
| main / CLI verbs (membership routing, genesis capabilities, exit codes) | `src/main.rs:~5600-6400` | 145 |
| port mapper (NAT-PMP / PCP / UPnP) | `src/port_mapper.rs` | 72 |
| secret-log audit (X3 static leak gate + its own scanner tests) | `src/secret_log_audit.rs` (whole file `#![cfg(test)]`) | 70 |
| privileged helper (argv allowlist, signal allowlist, protocol framing) | `src/privileged_helper.rs` | 69 |
| Windows platform modules (15 files: DNS fail-closed, paths, Authenticode, SDDL hardening, named-pipe IPC, DPAPI custody, registry ACLs) | `src/windows_*.rs` | ~360 |
| Linux platform modules (14 files: nftables + boot killswitch, systemd hardening, DNS redirect, IPv6 leak, blind exit) | `src/linux_*.rs` | ~290 |
| macOS platform modules (16 files: pf anchors + load spec, launchd hardening, utun helper, key custody) | `src/macos_*.rs` | ~210 |
| traversal / ICE / STUN / relay-client / MTU / keepalive | `src/{traversal,stun_client,ice_priority,peer_traversal_prior,relay_client,path_mtu,dataplane_candidates,keepalive}.rs` | ~155 |
| gossip stack (inbound verification, rebroadcast, transport framing) | `src/{gossip_runtime,peer_gossip,gossip_transport}.rs` | 77 |
| enrollment + key custody | `src/{enrollment_token,enrollment_consume,key_material,key_rotation}.rs` | 80 |
| adversarial self-audit modules | `src/*_audit.rs` (8 files) | 31 |

The eight `*_audit.rs` modules deserve separate mention: they drive the real
shipped evaluators through adversarial funnels, and each carries a deny-side
case **plus** an allow-side anti-vacuity control. `policy_default_deny_audit`
additionally contains a deliberate "bite probe" that mislabels a case to prove
the harness reports violations. They are also exposed as `rustynetd`
subcommands for the VM lab.

### 3.2 `rustynet-cli` — ~3,300 tests

| Module group | Location | Tests |
| --- | --- | --- |
| `vm_lab` inline | `src/vm_lab/mod.rs` (56,159 lines) | 663 |
| `vm_lab` orchestrator subtree | `src/vm_lab/orchestrator/**` | 818 |
| `vm_lab` other modules | `src/vm_lab/{capability,bootstrap/*,script_template,...}` | 445 |
| `main.rs` inline | `src/main.rs` (28,175 lines) | 148 |
| top-level modules | `src/*.rs` | 659 |
| `src/bin/*` inline | 40+ live-lab test binaries | 539 |
| install | `src/install/*` | 36 |
| integration: `rnq09_signal_cleanup` | `tests/` | 2 (needs `--features vm-lab`) |

### 3.3 `rustynet-control` — 364 tests

`lib.rs` 123 · `membership.rs` 78 · `role_presets.rs` 68 ·
`credential_unwrap.rs` 17 · `role_audit.rs` 14 · `admin.rs` 7 · others 54 ·
`tests/membership_model_conformance.rs` 3 (a bounded 6³ model check with an
anti-vacuity floor).

### 3.4 Remaining workspace crates

| Crate | Tests | Notes |
| --- | --- | --- |
| `rustynet-relay` | 171 | transport 82, main 76, rate-limit/session/hello-limiter 13 |
| `rustynet-mcp` | 230 | ai_agent 97, lab_state 89, lib 21, repo_context 19, gate_runner 4 |
| `rustynet-sysinfo` | 124 | lib parsers 78, diagnostics 46 |
| `rustynet-crypto` | 48 | 44 main + 4 unix-custody (`#[cfg(unix)]`) |
| `rustynet-operator` | 45 | role, egress, args, menu, launch, config/* |
| `rustynet-llm-gateway` | 38 | enforce 7, session 13, protocol 11, engine 5, main 2 |
| `rustynet-nas` | 35 | protocol 9, store 13, main 11, health 2 |
| `rustynet-policy` | 32 | near-exemplary; explicit anti-vacuity controls |
| `rustynet-dns-zone` | 22 | also in the Windows leg |
| `rustynet-local-security` | 16 | unix-gated; stubs on Windows untested |
| `rustynet-advisor` | 18 | 6 inline + 12 property invariants |
| `rustynet-netns-probe` | 6 | STUN wire format |
| `rustynet-xtask` | 6 | the gate runner's own tests |
| `rustynet-windows-native` | 8 | 5 WFP shape + 3 gateway selection |
| `rustynet-backend-*` | see §4 | |

---

## 4. Integration tests

| File | Tests | Runs on |
| --- | --- | --- |
| `rustynetd/tests/role_capability_enforcement.rs` | 8 | macOS, Debian, Windows |
| `rustynetd/tests/ice_pair_race.rs` | 6 | macOS, Debian, Windows |
| `rustynetd/tests/gossip_three_peer_mesh.rs` | 6 | macOS, Debian, Windows |
| `rustynetd/tests/enrollment_two_peer_redeem.rs` | 5 | macOS, Debian, Windows |
| `rustynetd/tests/enrollment_trust_propagation.rs` | 5 | macOS, Debian, Windows |
| `rustynetd/tests/quorum_multi_approver.rs` | 5 | macOS, Debian, Windows |
| `rustynetd/tests/membership_replay_protection.rs` | 4 | macOS, Debian, Windows |
| `rustynetd/tests/enrollment_token_audit.rs` | 3 | macOS, Debian |
| `rustynetd/tests/state_fetcher.rs` | 3 | macOS, Debian, Windows |
| `rustynet-control/tests/membership_model_conformance.rs` | 3 | macOS, Debian, Windows |
| `rustynet-advisor/tests/mcda_scorer_invariants.rs` | 12 (property) | macOS, Debian |
| `rustynet-backend-api/tests/backend_contract.rs` | 21 + 19 scenario helpers | macOS, Debian, Windows |
| `rustynet-backend-api/tests/backend_contract_perf.rs` | 1 | all legs |
| `rustynet-backend-stub/tests/stub_conformance.rs` | 20 + 19 duplicated helpers | macOS, Debian, Windows |
| `rustynet-backend-wireguard/tests/conformance.rs` | 17 | macOS, Debian **only when `--all-features`** |
| `rustynet-backend-userspace/tests/userspace_conformance.rs` | 4 (2 invariant, 2 env-gated) | 2 run; 2 never |
| `rustynet-cli/tests/rnq09_signal_cleanup.rs` | 2 | macOS, Debian (needs `vm-lab`) |

---

## 5. Benches, fuzz, doc-tests

| Item | Location | Executed? |
| --- | --- | --- |
| `phase1_runtime_baseline` | `crates/rustynetd/benches/` | 1 `#[test]`, 0 benchmarks; the test runs in CI |
| `dataplane_engine` | `crates/rustynet-backend-wireguard/benches/` | 5 criterion benchmarks, 0 assertions; built, never executed |
| `relay_forward` | `crates/rustynet-relay/benches/` | 1 criterion benchmark, 0 assertions; built, never executed |
| boringtun crypto benches (5 files) | `third_party/boringtun/benches/` | **never compiled** (`autobenches = false`) |
| fuzz `ipc_parse_command` | `fuzz/fuzz_targets/` | **never in CI** |
| fuzz `membership_decode_state` | `fuzz/fuzz_targets/` | **never in CI** |
| fuzz `membership_decode_signed_update` | `fuzz/fuzz_targets/` | **never in CI** |
| fuzz corpus | `fuzz/corpus/` | 678 local inputs, **0 tracked**; crash artifacts are git-ignored |
| fuzz smoke runner | `scripts/fuzz/smoke.sh` | 3 targets × 10 s; referenced by no workflow or gate |
| doc-test | `crates/rustynetd/src/killswitch_precedence.rs:36-56` | **never** — nextest cannot run doctests |

The other 19 fenced blocks under `crates/` are `text`/`bash`/`sh`/`json`/`xml`
and are not compiled by anything.

---

## 6. CI gate scripts (`scripts/ci/`, 51)

Grouped as the MCP gate-runner reports them. The **Automated** column is the
important one: it records what runs the script without a human deciding to.

### Security (10)

| Script | Automated by |
| --- | --- |
| `secrets_hygiene_gates.sh` | live-lab orchestrator only |
| `security_regression_gates.sh` | live-lab orchestrator only |
| `supply_chain_integrity_gates.sh` | live-lab orchestrator only |
| `role_auth_matrix_gates.sh` | live-lab orchestrator only |
| `traversal_adversarial_gates.sh` | live-lab orchestrator only |
| `check_backend_boundary_leakage.sh` | **nothing** (MCP on demand) |
| `no_leak_dataplane_gate.sh` | **nothing** |
| `check_dependency_exceptions.sh` | **nothing** |
| `anchor_secret_redaction_gates.sh` | **nothing** |
| `active_network_security_gates.sh` | **nothing** |

### Phase (13)

`phase1`, `phase3`, `phase4`, `phase5`, `phase6`, `phase7`, `phase8`, `phase9`,
`phase10` — all invoked only from `live_linux_lab_orchestrator.sh:5176-5185`.
`phase10_hp2_gates.sh`, `check_phase6_platform_parity.sh`,
`check_phase9_readiness.sh`, `check_phase10_readiness.sh` — automated by nothing
(the last two are reachable from `ops_*` Rust code).

### Role / platform (8)

`anchor_role_gates.sh`, `anchor_downgrade_gates.sh`, `role_taxonomy_gates.sh`,
`role_transition_audit_gates.sh`, `service_hosting_role_gates.sh`,
`llm_exit_coexistence_gates.sh`, `phase10_cross_network_exit_gates.sh`,
`test_validate_cross_network_remote_exit_reports.sh` — **none automated**.
Several are sub-gates of `service_hosting_role_gates.sh`.

### Release / readiness (6)

`fresh_install_os_matrix_release_gate.sh` and `perf_regression_gate.sh` run from
the live-lab orchestrator. `release_readiness_gates.sh`,
`check_fresh_install_os_matrix_readiness.sh`,
`test_check_fresh_install_os_matrix_readiness.sh`,
`regression_coverage_gates.sh` — automated by nothing.

### Lab-dependent (6)

`anchor_live_lab_gates.sh`, `chaos_gates.sh`, `cross_platform_role_gates.sh`,
`linux_exit_role_gates.sh`, `orchestrator_engine_gates.sh`,
`windows_cross_compile_gate.sh` — **none automated**. Four of the six are in
fact hermetic and do not need a lab (see the review document).

### Other (8)

| Script | Automated by |
| --- | --- |
| `bootstrap_ci_tools.sh` | **CI** — macOS, Debian, Windows, e2e legs |
| `lab_monitor_gates.sh` | **CI** — macOS and Debian legs |
| `membership_gates.sh` | live-lab orchestrator |
| `run_required_test.sh` | helper, called by other gates |
| `llm_default_deny_gates.sh` | nothing (sub-gate) |
| `nas_default_deny_gates.sh` | nothing (sub-gate) |
| `check_mcp_binaries_fresh.sh` | nothing |
| `windows_compile_check.sh` | nothing |

**Two of 51 gate scripts are wired into GitHub Actions**:
`bootstrap_ci_tools.sh` and `lab_monitor_gates.sh`.

---

## 7. GitHub Actions

### `cross-platform-ci.yml` — 4 jobs, on push to `main` and every PR

| Job | Runner | What it runs |
| --- | --- | --- |
| `macos` | `macos-14` (aarch64) | bootstrap → repo hygiene → shipped-binary feature gate → `lab_monitor_gates.sh` → fmt/clippy/check/nextest `--workspace --all-targets --all-features --locked` → `cargo audit`, `cargo deny` |
| `debian13` | `ubuntu-latest` + `debian:trixie` container | same |
| `windows` | `windows-2022` | **10 of 21 packages**, `--no-fail-fast`; `rustynet-cli` cannot build on Windows |
| `linux_e2e` | `ubuntu-latest` | `scripts/e2e/real_wireguard_exitnode_e2e.sh` — the only real-WireGuard scenario in CI |

### `release.yml` — 2 jobs, on tag `v*.*.*` or manual dispatch

`build` (5-target matrix × 3 binaries) → `manifest` (sign + publish, skipped if
any matrix leg fails).

### Supply chain

`deny.toml` (11 crate bans, 7 allowed licenses), `cargo audit`, `cargo deny`,
`rust-toolchain.toml`, `.cargo-audit-db/` (gitignored),
`scripts/git-hooks/pre-commit`.

---

## 8. Excluded from every `--workspace` command

| Workspace | Contents | Gated by |
| --- | --- | --- |
| `crates/rustynet-lab-monitor/` | 270 tests, own `Cargo.lock` (168 packages) | `lab_monitor_gates.sh`, on the macOS and Debian CI legs — build gates only, no security leg |
| `gui/node-map-tool/` | 7 tests, 2,870-line `main.rs`, own lock (277 packages) | **nothing** — not compiled, linted, tested or audited anywhere |
| `fuzz/` | 3 targets, own lock (146 packages) | **nothing** |

Together these hold **218 dependency packages that no `cargo audit` or
`cargo deny` invocation ever sees.**

---

## 9. Live lab and e2e (~70 scenarios)

### Executed by CI

| Scenario | Where |
| --- | --- |
| `real_wireguard_exitnode_e2e` | `linux_e2e` job — 6 checks |

That is the entire live surface reachable from CI.

### Executed only by the live-lab orchestrator or by hand

- **Orchestrators**: `live_linux_lab_orchestrator.sh` (9,054 lines, ~60 stages),
  `live_lab_common.sh` (3,523 lines, ~130 functions), and the Rust-native
  orchestrator engine (`src/vm_lab/orchestrator/`, ~48 stage modules — its unit
  tests do run in CI).
- **Real-WireGuard scenarios not in CI**: `real_wireguard_no_leak_under_load`,
  `real_wireguard_rogue_path_hijack_e2e`, `real_wireguard_signed_state_tamper_e2e`.
- **Capture scenarios**: IPv6 leak (Linux + macOS), exit NAT lifecycle
  (Linux + macOS), exit demotion residue, macOS exit DNS fail-closed, macOS exit
  killswitch precedence.
- **Cross-network family** (8 scripts): controller switch, direct remote exit,
  relay remote exit, failback roaming, node network switch, remote-exit DNS,
  remote-exit soak, traversal adversarial.
- **Chaos family** (8 binaries, ~40 stages): clock attack, crash recovery,
  daemon fault, membership adversarial, network impairment, privileged boundary,
  resource exhaustion, signed-state adversarial. Skipped by default even on a
  live lab run.
- **`live_linux_*` stage validators**: 17 binaries, none with a `--dry-run`.
- **`live_{macos,windows}_*` wrappers**: 13 scripts.
- **netns substrate**: `netns_internet_sim.sh` (superseded for the
  orchestrator by the Rust `NetnsSubstrateProvider`; retained only as the
  `netns_daemon_path.sh` dependency and the `vm-lab-network-audit` target),
  `netns_daemon_path.sh`, `vxlan_tier_b.sh`. `netns_nat_classify.sh` and
  `netns_nat_filter.sh` were DELETED in CN-2 (2026-08-27); their gates are
  `stage/cross_network/netns.rs::run_nat_gates`.
- **Perf**: `scripts/perf/run_phase1_baseline.sh`, `perf_regression_gate.sh`.

### Evidence ledgers

`documents/operations/live_lab_run_matrix.csv` (549 rows) and
`live_lab_node_run_matrix.csv` (97 rows) — appended by the orchestrators on
exit; hand-editable and unsigned.

---

## 10. Platform coverage actually exercised

| Platform | Built | Tested |
| --- | --- | --- |
| macOS aarch64 | yes | full workspace |
| Linux x86_64 | yes | full workspace + the one e2e |
| Windows x86_64 | yes | **10 of 21 packages** |
| Windows aarch64 | release matrix only | never |
| Linux aarch64 | release matrix only | never |

`rustynet-sysinfo`, `rustynet-local-security` (Windows stubs),
`rustynet-cli`'s Windows-targeted logic and `rustynet-backend-wireguard`'s
Windows adapter all have Windows-specific code that no Windows runner executes.
`rustynet-windows-native`'s `#[cfg(windows)] mod imp` — ~1,630 lines containing
98 `unsafe` sites (DPAPI, WFP, netsh) — is compiled by the Windows leg and
executed by no test anywhere.
