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

### LNX-2026-03-07-04: F04 remote E2E orchestration hardening (argv-only active path)
- Status: `PENDING`
- Priority: High
- Runtime impact: High (privileged remote provisioning/orchestration path)
- Files:
  - `crates/rustynet-cli/src/ops_e2e.rs`
  - `crates/rustynet-cli/src/main.rs`
  - `scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh`
  - `documents/operations/ComparativeSecurityFlawAssessment_2026-03-06.md`
  - `documents/operations/ShellToRustMigrationPlan_2026-03-06.md`
- Change summary:
  - Active remote orchestration path is Rust-only (`ops run-debian-two-node-e2e`).
  - Legacy remote `bash -se` payload/snippet helpers were removed from active code path.
  - Remote orchestration/probe steps now run through argv-only SSH command dispatch helpers.
- Required VM coverage:
  - `debian-a`, `debian-b`
- Required checks:
```bash
cargo check -p rustynet-cli
cargo test -p rustynet-cli -- --nocapture
bash -n scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh
umask 077 && printf 'tempo\n' > /tmp/rustynet_sudo.pass
./scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh \
  --exit-host 192.168.18.49 \
  --client-host 192.168.18.50 \
  --ssh-user debian \
  --sudo-password-file /tmp/rustynet_sudo.pass \
  --ssh-allow-cidrs 192.168.18.2/32 \
  --skip-apt
rm -f /tmp/rustynet_sudo.pass
```
- Pass criteria:
  - E2E command succeeds and report is generated at `artifacts/phase10/debian_two_node_remote_validation.md`.
  - Report contains no failing checks.
  - No shell payload fallback path is required for successful orchestration.

### LNX-2026-03-07-05: F02 peer-store validation/read migration to Rust ops path
- Status: `PENDING`
- Priority: High
- Runtime impact: Medium-High (startup/menu peer-state parsing and candidate discovery path)
- Files:
  - `crates/rustynet-cli/src/ops_peer_store.rs`
  - `crates/rustynet-cli/src/main.rs`
  - `start.sh`
  - `documents/operations/ComparativeSecurityFlawAssessment_2026-03-06.md`
- Change summary:
  - Added Rust peer-store ops commands (`peer-store-validate`, `peer-store-list`) with strict custody + parsing controls.
  - `start.sh` peer-store flows now call Rust ops commands (no active shell peer-file parser path).
  - Startup + peer listing + admin peer listing + exit-candidate probe now consume Rust-validated records.
- Required VM coverage:
  - `debian-a`, `ubuntu-a`, `fedora-a`, `mint-a`
- Required checks:
```bash
cargo check -p rustynet-cli
cargo test -p rustynet-cli -- --nocapture
bash -n start.sh
PEER_CFG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/rustynet"
rustynet ops peer-store-validate --config-dir "${PEER_CFG_DIR}" --peers-file "${PEER_CFG_DIR}/peers.db"
rustynet ops peer-store-list --config-dir "${PEER_CFG_DIR}" --peers-file "${PEER_CFG_DIR}/peers.db"
rustynet ops peer-store-list --config-dir "${PEER_CFG_DIR}" --peers-file "${PEER_CFG_DIR}/peers.db" --role admin
stat -c '%a %u %n' "${PEER_CFG_DIR}" "${PEER_CFG_DIR}/peers.db"
./start.sh
```
Manual runtime checks in menu:
1. Run `LIST SAVED PEERS`; command completes without parser errors.
2. Run `SELECT EXIT NODE`; candidate probe executes without peer-store parse failures.
3. For a known node id, two-hop selection pre-check (`find_peer_record_by_node_id` path) resolves records without shell parser regressions.
- Pass criteria:
  - Rust peer-store ops commands succeed on all listed VMs.
  - `peers.db` custody is enforced (`config dir 0700`, `peers.db 0600`, owner is current user).
  - `start.sh` peer-listing/probe flows succeed without shell parser failures.

### LNX-2026-03-07-06: Daemon preflight parent-directory custody hardening
- Status: `PENDING`
- Priority: High
- Runtime impact: High (startup preflight for trust/assignment/membership/key custody files)
- Files:
  - `crates/rustynetd/src/daemon.rs`
  - `documents/operations/SecurityRegressionLessons_2026-03-07.md`
- Change summary:
  - `validate_file_security` now enforces parent-directory custody checks for sensitive daemon artifacts.
  - Parent directory must be non-symlink, non-group/world-writable, and trusted-owner (`runtime uid` or `root` when explicitly allowed).
  - Added regression tests for writable-parent and symlink-parent rejection paths.
- Required VM coverage:
  - `debian-a`, `ubuntu-a`, `fedora-a`, `mint-a`
- Required checks:
```bash
cargo check -p rustynetd
cargo clippy -p rustynetd --all-targets --all-features -- -D warnings
cargo test -p rustynetd validate_file_security_rejects -- --nocapture
cargo test -p rustynetd daemon_runtime_client_role_blocks_admin_mutations -- --nocapture
cargo test -p rustynetd daemon_runtime_blind_exit_role_is_least_privilege -- --nocapture
```
Manual runtime checks on each VM:
1. Run daemon/service install flow normally; verify startup succeeds with canonical secure directories.
2. Create an intentionally insecure parent directory for a copied trust/assignment artifact path and point config there.
3. Verify daemon preflight fails closed with parent-directory custody error.
- Pass criteria:
  - All listed commands pass.
  - Normal secure startup remains successful.
  - Insecure parent-directory path is rejected fail-closed on each required VM.

### LNX-2026-03-07-07: Phase10 generation handoff ordering hardening
- Status: `PENDING`
- Priority: High
- Runtime impact: High (fail-closed firewall generation rollover path)
- Files:
  - `crates/rustynetd/src/phase10.rs`
  - `documents/operations/SecurityRegressionLessons_2026-03-07.md`
- Change summary:
  - `apply_firewall_killswitch` now prunes previous generation table only after new generation fail-closed rules are installed.
  - `ensure_failclosed_table` now avoids stale generation table reuse and recreates missing target-generation fail-closed table/chain.
  - `prune_owned_tables` now preserves both target-generation and currently-active Rustynet tables during pre-apply cleanup.
  - Added deterministic privileged-helper capture test that asserts old table deletion happens only after new-generation forward rules are present.
- Required VM coverage:
  - `debian-a`, `ubuntu-a`, `fedora-a`, `mint-a`
- Required checks:
```bash
cargo check -p rustynetd
cargo clippy -p rustynetd --all-targets --all-features -- -D warnings
cargo test -p rustynetd firewall_generation_handoff_deletes_previous_table_only_after_new_rules_apply -- --nocapture
cargo test -p rustynetd phase10::tests -- --nocapture
```
Manual runtime checks on each VM:
1. Apply one generation with a selected exit node, then trigger a signed assignment generation rollover.
2. During rollover, verify connectivity remains tunnel-routed and no unmanaged egress path appears.
3. Confirm no stale `rustynet_g*` table remains after stable convergence on the new generation.
- Pass criteria:
  - All listed commands pass.
  - Generation rollover does not create a transient unmanaged forwarding window.
  - Old owned firewall table is pruned only after new generation fail-closed rules converge.

### LNX-2026-03-07-08: Security anti-regression gate bundle (parser limits + role matrix + table custody)
- Status: `PENDING`
- Priority: High
- Runtime impact: High (command ingress hardening + phase10 source ingestion limits + generation table custody)
- Files:
  - `scripts/ci/security_regression_gates.sh`
  - `scripts/ci/phase10_gates.sh`
  - `crates/rustynetd/src/daemon.rs`
  - `crates/rustynetd/src/privileged_helper.rs`
  - `crates/rustynetd/src/phase10.rs`
  - `crates/rustynet-cli/src/ops_phase9.rs`
- Change summary:
  - Added dedicated anti-regression gate script with focused security tests and optional real netns leak path.
  - Added daemon IPC ingress tests for oversized and null-byte command rejection.
  - Added strict role-command matrix regression test (`admin/client/blind_exit`) with fail-closed expectations.
  - Added privileged helper request-boundary tests for max-argument and max-argument-bytes rejection.
  - Added phase10 source ingestion size limits for JSON/state artifacts in Rust ops path and tests for oversized artifact rejection.
  - Added phase10 table-prune regression test to ensure active+target generation tables are preserved while stale tables are pruned.
  - Wired `security_regression_gates.sh` into `phase10_gates.sh` so release gate path enforces these checks.
- Required VM coverage:
  - `debian-a`, `ubuntu-a`, `fedora-a`, `mint-a`
- Required checks:
```bash
cargo check --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
./scripts/ci/security_regression_gates.sh
RUSTYNET_PHASE10_GENERATE_ARTIFACTS=0 ./scripts/ci/phase10_gates.sh
```
Optional high-assurance Linux check (root-required):
```bash
sudo -E RUSTYNET_SECURITY_RUN_REAL_NETNS_E2E=1 ./scripts/ci/security_regression_gates.sh
```
- Pass criteria:
  - All listed commands pass.
  - Security regression gate is invoked from phase10 gates and fails closed on violations.
  - Oversized/tampered ingress payloads are rejected in covered test paths.

### LNX-2026-03-07-09: Real no-leak dataplane gate under sustained load (root Linux netns + tcpdump)
- Status: `PENDING`
- Priority: High
- Runtime impact: High (real packet-level leak regression detection under tunnel load and tunnel-down state)
- Files:
  - `scripts/e2e/real_wireguard_no_leak_under_load.sh`
  - `scripts/ci/no_leak_dataplane_gate.sh`
  - `scripts/ci/security_regression_gates.sh`
  - `README.md`
  - `documents/operations/SecurityRegressionLessons_2026-03-07.md`
- Change summary:
  - Added a dedicated real no-leak dataplane gate that:
    - builds isolated Linux netns client/exit/inet topology,
    - runs sustained tunnel traffic load,
    - captures client underlay traffic with `tcpdump`,
    - fails if cleartext underlay traffic to protected destination is detected,
    - validates fail-closed behavior after tunnel-down while underlay capture remains leak-free.
  - Added strict CI enforcement controls in `security_regression_gates.sh`:
    - `RUSTYNET_SECURITY_RUN_NO_LEAK_GATE=auto|1|0`
    - `RUSTYNET_SECURITY_REQUIRE_NO_LEAK_GATE=1` to fail when gate cannot run.
- Required VM coverage:
  - `debian-a`, `ubuntu-a`, `fedora-a`, `mint-a` (Linux root execution)
- Required checks:
```bash
sudo -E ./scripts/ci/no_leak_dataplane_gate.sh
RUSTYNET_SECURITY_RUN_NO_LEAK_GATE=1 sudo -E ./scripts/ci/security_regression_gates.sh
RUSTYNET_SECURITY_REQUIRE_NO_LEAK_GATE=1 RUSTYNET_PHASE10_GENERATE_ARTIFACTS=0 sudo -E ./scripts/ci/phase10_gates.sh
```
- Pass criteria:
  - `no_leak_dataplane_report.json` exists with `status=pass` and all checks pass.
  - Under sustained load, underlay capture includes tunnel transport packets but no cleartext destination packets.
  - After tunnel down, fail-closed is observed and underlay capture remains cleartext-free.

### LNX-2026-03-07-10: Secrets hygiene gate (plaintext/log-argv/tmp + mode/owner + secure-delete coverage)
- Status: `PENDING`
- Priority: High
- Runtime impact: High (prevents secret custody regressions before release)
- Files:
  - `scripts/ci/secrets_hygiene_gates.sh`
  - `scripts/ci/security_regression_gates.sh`
  - `crates/rustynetd/src/key_material.rs`
  - `crates/rustynet-cli/src/main.rs`
  - `documents/operations/SecurityRegressionLessons_2026-03-07.md`
- Change summary:
  - Added dedicated secrets hygiene gate enforcing:
    - no runtime plaintext key artifact filenames present in tracked/workspace paths,
    - no inline secret argv flags (`--passphrase`/`--password` style) in source paths,
    - no secret-like leak signatures in artifact/log payloads,
    - no `rm -f` on sensitive key/passphrase artifacts in shell paths,
    - strict tmp-secret handling in shell (`mktemp` + `chmod 600` + secure-remove).
  - Added secure-delete regression tests:
    - `key_material::tests::remove_file_if_present_rejects_directory`
    - `key_material::tests::remove_file_if_present_removes_symlink_without_following_target`
    - `tests::secure_remove_file_rejects_directory` (`rustynet-cli`)
    - `tests::secure_remove_file_removes_target_file` (`rustynet-cli`)
    - `tests::create_secure_temp_file_sets_owner_only_mode` (`rustynet-cli`)
  - Wired gate into `security_regression_gates.sh` so it runs in phase10 regression path.
- Required VM coverage:
  - `debian-a`, `ubuntu-a`, `fedora-a`, `mint-a`
- Required checks:
```bash
./scripts/ci/secrets_hygiene_gates.sh
./scripts/ci/security_regression_gates.sh
RUSTYNET_PHASE10_GENERATE_ARTIFACTS=0 ./scripts/ci/phase10_gates.sh
```
- Pass criteria:
  - Secrets hygiene gate passes with no plaintext runtime key artifacts, no secret-like artifact/log leaks, and no inline secret argv flags.
  - Added secure-delete/mode-owner tests pass in Linux VM validation matrix.
  - Phase10 gate path continues to pass with secrets hygiene enforcement active.

### LNX-2026-03-07-11: Role/Auth matrix gate (exhaustive role x command x mode x hop)
- Status: `PENDING`
- Priority: High
- Runtime impact: High (authorization fail-closed guarantees for role/mode/hop combinations)
- Files:
  - `crates/rustynetd/src/daemon.rs`
  - `scripts/ci/role_auth_matrix_gates.sh`
  - `scripts/ci/security_regression_gates.sh`
  - `README.md`
  - `documents/operations/SecurityRegressionLessons_2026-03-07.md`
- Change summary:
  - Added exhaustive runtime authorization matrix test:
    - `daemon::tests::role_auth_matrix_runtime_is_exhaustive_and_fail_closed`
    - covers `role x command x mode x hop` combinations with strict expected deny-reason precedence.
  - Expanded static role command matrix coverage for `RouteAdvertise("0.0.0.0/0")`.
  - Added dedicated gate script:
    - `scripts/ci/role_auth_matrix_gates.sh`
    - verifies role-command matrix baseline, exhaustive matrix runtime behavior, blind-exit least-knowledge restrictions, and auto-tunnel/restricted-safe enforcement interactions.
  - Wired role/auth matrix gate into `scripts/ci/security_regression_gates.sh` so Phase10 regression path enforces it.
- Required VM coverage:
  - `debian-a`, `ubuntu-a`, `fedora-a`, `mint-a`
- Required checks:
```bash
cargo test -p rustynetd daemon::tests::node_role_command_matrix_is_fail_closed -- --nocapture
cargo test -p rustynetd daemon::tests::role_auth_matrix_runtime_is_exhaustive_and_fail_closed -- --nocapture
./scripts/ci/role_auth_matrix_gates.sh
./scripts/ci/security_regression_gates.sh
RUSTYNET_PHASE10_GENERATE_ARTIFACTS=0 ./scripts/ci/phase10_gates.sh
```
- Pass criteria:
  - Matrix gate passes and fails closed on authorization mismatches.
  - Blind-exit retains least-knowledge invariants across matrix scenarios.
  - Security regression + phase10 gate chains continue to pass with role/auth matrix enforcement active.

### LNX-2026-03-07-12: Traversal adversarial gate (forged/stale/wrong-signer/replay/NAT-mismatch)
- Status: `PENDING`
- Priority: High
- Runtime impact: High (direct-path authorization hardening and relay safety under adversarial traversal inputs)
- Files:
  - `crates/rustynetd/src/daemon.rs`
  - `crates/rustynetd/src/traversal.rs`
  - `scripts/ci/traversal_adversarial_gates.sh`
  - `scripts/ci/security_regression_gates.sh`
  - `README.md`
  - `documents/operations/SecurityRegressionLessons_2026-03-07.md`
- Change summary:
  - Added dedicated traversal adversarial gate script:
    - `scripts/ci/traversal_adversarial_gates.sh`
  - Gate enforces traversal security regressions for:
    - forged/tampered traversal signatures,
    - wrong-signer traversal hints,
    - stale traversal hints,
    - nonce replay/rollback traversal hints,
    - private SRFLX rejection.
  - Added runtime fail-closed netcheck assertion:
    - `daemon::tests::daemon_runtime_netcheck_rejects_forged_traversal_hint_fail_closed`
    - verifies invalid hint state keeps traversal status invalid with zero candidate exposure.
  - Kept NAT mismatch + relay-only denial path enforced:
    - `traversal::tests::adversarial_gate_nat_mismatch_blocks_unauthorized_direct_and_keeps_safe_relay_fallback`
  - Wired traversal adversarial gate into `security_regression_gates.sh` so phase10 path enforces it.
- Required VM coverage:
  - `debian-a`, `ubuntu-a`, `fedora-a`, `mint-a`
- Required checks:
```bash
cargo test -p rustynetd daemon::tests::traversal_adversarial_gate_rejects_forged_stale_wrong_signer_and_nonce_replay -- --nocapture
cargo test -p rustynetd daemon::tests::daemon_runtime_netcheck_rejects_forged_traversal_hint_fail_closed -- --nocapture
cargo test -p rustynetd traversal::tests::adversarial_gate_nat_mismatch_blocks_unauthorized_direct_and_keeps_safe_relay_fallback -- --nocapture
./scripts/ci/traversal_adversarial_gates.sh
./scripts/ci/security_regression_gates.sh
RUSTYNET_PHASE10_GENERATE_ARTIFACTS=0 ./scripts/ci/phase10_gates.sh
```
- Pass criteria:
  - Traversal adversarial gate passes and fails closed on any traversal trust-state violation.
  - Relay-only/NAT-mismatch scenarios never authorize direct-path planning.
  - Phase10 regression path continues to pass with traversal adversarial enforcement active.

### LNX-2026-03-07-13: Supply-chain integrity gate (signed release attestation + unsigned/tamper rejection)
- Status: `PENDING`
- Priority: High
- Runtime impact: High (release-chain trust and binary integrity enforcement)
- Files:
  - `crates/rustynet-cli/src/ops_phase9.rs`
  - `crates/rustynet-cli/src/main.rs`
  - `scripts/ci/supply_chain_integrity_gates.sh`
  - `scripts/ci/phase8_gates.sh`
  - `scripts/ci/security_regression_gates.sh`
  - `scripts/ci/verify_release_attestation.sh`
  - `scripts/release/create_provenance.sh`
  - `README.md`
  - `documents/operations/SecurityRegressionLessons_2026-03-07.md`
  - `documents/operations/ComplianceControlMap.md`
- Change summary:
  - Added Rust-native release attestation ops commands:
    - `rustynet ops sign-release-artifact`
    - `rustynet ops verify-release-artifact`
  - Added fail-closed release-attestation tests:
    - `ops_phase9::tests::release_provenance_verification_rejects_tampered_artifact`
    - `ops_phase9::tests::release_provenance_verification_rejects_unsigned_document`
  - Added dedicated supply-chain gate:
    - `scripts/ci/supply_chain_integrity_gates.sh`
    - enforces `cargo audit`, `cargo deny`, SBOM generation, signed attestation verification, and negative checks for unsigned/tampered artifact rejection.
  - Wired gate into release-assurance paths:
    - `scripts/ci/phase8_gates.sh`
    - `scripts/ci/security_regression_gates.sh`
  - Security discrepancy closed:
    - previous `scripts/ci/verify_release_attestation.sh` only hash-validated JSON fields and did not cryptographically verify signatures.
    - new path uses Ed25519 signature verification and strict attestation field binding (track/host/path/hash/size/digest), failing closed.
- Required VM coverage:
  - `debian-a`, `ubuntu-a`, `fedora-a`, `mint-a`
- Required checks:
```bash
cargo test -p rustynet-cli tests::parse_supports_ops_commands -- --nocapture
cargo test -p rustynet-cli ops_phase9::tests::release_provenance_verification_rejects_tampered_artifact -- --nocapture
cargo test -p rustynet-cli ops_phase9::tests::release_provenance_verification_rejects_unsigned_document -- --nocapture
./scripts/ci/supply_chain_integrity_gates.sh
./scripts/ci/phase8_gates.sh
./scripts/ci/security_regression_gates.sh
RUSTYNET_PHASE10_GENERATE_ARTIFACTS=0 ./scripts/ci/phase10_gates.sh
```
- Pass criteria:
  - Unsigned release attestations are rejected.
  - Tampered release artifacts are rejected after signing.
  - Phase8/phase10 gate paths remain green with supply-chain gate enforced.

### LNX-2026-03-07-14: Active-network adversarial E2E gates (signed-state tamper + rogue endpoint hijack denial)
- Status: `PENDING`
- Priority: High
- Runtime impact: High (live multi-host adversarial validation of signed-state custody and endpoint hijack resistance)
- Files:
  - `scripts/e2e/real_wireguard_signed_state_tamper_e2e.sh`
  - `scripts/e2e/real_wireguard_rogue_path_hijack_e2e.sh`
  - `scripts/ci/active_network_security_gates.sh`
  - `scripts/ci/security_regression_gates.sh`
  - `README.md`
- Change summary:
  - Added active-network signed-state tamper test:
    - bootstraps real two-host Debian E2E baseline,
    - mutates signed assignment payload while preserving stale signature,
    - requires daemon fail-closed transition (`state=FailClosed`, `restricted_safe_mode=true`),
    - restores valid signed state and verifies secure recovery.
  - Added active-network rogue endpoint hijack denial test:
    - forges assignment peer endpoint(s) toward attacker IP with invalid signature,
    - requires explicit rejection and fail-closed behavior,
    - asserts `wg show` endpoint output never adopts rogue endpoint.
  - Added gate wrapper:
    - `scripts/ci/active_network_security_gates.sh`
    - runs both adversarial E2E tests and emits measured reports under `artifacts/phase10/`.
  - Added optional wiring in `security_regression_gates.sh`:
    - `RUSTYNET_SECURITY_RUN_ACTIVE_NETWORK_GATES=1`
    - `RUSTYNET_SECURITY_REQUIRE_ACTIVE_NETWORK_GATES=1` (fail closed when not run).
- Required VM coverage:
  - `debian-a`, `debian-b`
- Required checks:
```bash
bash -n scripts/e2e/real_wireguard_signed_state_tamper_e2e.sh
bash -n scripts/e2e/real_wireguard_rogue_path_hijack_e2e.sh
bash -n scripts/ci/active_network_security_gates.sh
RUSTYNET_ACTIVE_NET_EXIT_HOST=192.168.18.49 \
RUSTYNET_ACTIVE_NET_CLIENT_HOST=192.168.18.50 \
RUSTYNET_ACTIVE_NET_SSH_USER=root \
RUSTYNET_ACTIVE_NET_SSH_ALLOW_CIDRS=192.168.18.2/32 \
RUSTYNET_ACTIVE_NET_ROGUE_ENDPOINT_IP=203.0.113.250 \
RUSTYNET_ACTIVE_NET_SKIP_APT=1 \
./scripts/ci/active_network_security_gates.sh
RUSTYNET_SECURITY_RUN_ACTIVE_NETWORK_GATES=1 \
RUSTYNET_ACTIVE_NET_EXIT_HOST=192.168.18.49 \
RUSTYNET_ACTIVE_NET_CLIENT_HOST=192.168.18.50 \
RUSTYNET_ACTIVE_NET_SSH_USER=root \
RUSTYNET_ACTIVE_NET_SSH_ALLOW_CIDRS=192.168.18.2/32 \
RUSTYNET_ACTIVE_NET_ROGUE_ENDPOINT_IP=203.0.113.250 \
RUSTYNET_ACTIVE_NET_SKIP_APT=1 \
./scripts/ci/security_regression_gates.sh
```
- Pass criteria:
  - `artifacts/phase10/signed_state_tamper_e2e_report.json` exists with `status=pass`.
  - `artifacts/phase10/rogue_path_hijack_e2e_report.json` exists with `status=pass`.
  - Tamper/hijack attempts force fail-closed state and are rejected.
  - Recovery path restores secure runtime state after valid signed-state restoration.

## Non-Runtime / Docs-Only Changes (No VM Runtime Validation Required)
- `README.md`
- `documents/operations/MeasuredEvidenceGeneration.md`
- `documents/operations/ShellToRustMigrationPlan_2026-03-06.md`
- `documents/operations/BackendAgilityValidation.md`

## Validation Execution Log
Record each VM run here.

### 2026-03-07 Fresh Reinstall Matrix (Latest Main)
- Commit: `f85da6e`
- Scope executed:
  - Full cleanup + fresh reinstall + signed membership/assignment redistribution on reachable VM matrix (`debian-a`, `debian-b`, `fedora-a`, `mint-a`) via `/tmp/run_four_node_new_envs.sh`.
  - Post-install runtime/role/tunnel verification including controlled `client -> admin -> client` (Mint) and `client -> blind_exit -> client` (Fedora) restore checks.
- Evidence:
  - `artifacts/phase10/vm_fresh_network_validation_corrected_20260307T112910Z.md`
  - `artifacts/phase10/vm_fresh_network_validation_20260307T112553Z.md` (superseded by corrected report for route/NAT parsing details).
- Outcome:
  - Reachable VM matrix: `PASS`.
  - Ubuntu (`192.168.18.46`): `BLOCKED` (unreachable), so change sets requiring `ubuntu-a` remain `PENDING`.

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
| _pending_ | LNX-2026-03-07-04 | _pending_ | debian-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-04 | _pending_ | debian-b | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-05 | _pending_ | debian-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-05 | _pending_ | ubuntu-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-05 | _pending_ | fedora-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-05 | _pending_ | mint-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-06 | _pending_ | debian-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-06 | _pending_ | ubuntu-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-06 | _pending_ | fedora-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-06 | _pending_ | mint-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-07 | _pending_ | debian-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-07 | _pending_ | ubuntu-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-07 | _pending_ | fedora-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-07 | _pending_ | mint-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-08 | _pending_ | debian-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-08 | _pending_ | ubuntu-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-08 | _pending_ | fedora-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-08 | _pending_ | mint-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-09 | _pending_ | debian-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-09 | _pending_ | ubuntu-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-09 | _pending_ | fedora-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-09 | _pending_ | mint-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-11 | _pending_ | debian-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-11 | _pending_ | ubuntu-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-11 | _pending_ | fedora-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-11 | _pending_ | mint-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-12 | _pending_ | debian-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-12 | _pending_ | ubuntu-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-12 | _pending_ | fedora-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-12 | _pending_ | mint-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-13 | _pending_ | debian-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-13 | _pending_ | ubuntu-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-13 | _pending_ | fedora-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-13 | _pending_ | mint-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-14 | _pending_ | debian-a | _pending_ | _pending_ | _pending_ |
| _pending_ | LNX-2026-03-07-14 | _pending_ | debian-b | _pending_ | _pending_ | _pending_ |

## PR / Commit Gate for This Queue
Before marking a change set `PASSED`:
1. Code is committed and pushed.
2. Latest commit is pulled on required VMs.
3. Required checks pass on each required VM.
4. This document is updated with evidence.
5. Only then remove from pending queue or mark `PASSED`.
