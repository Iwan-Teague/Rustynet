# Security Regression Lessons and Test Enforcement (2026-03-07)

## Objective
Translate known exploited VPN/overlay/network-control weaknesses into **Rustynet-specific, continuously enforced tests** so security posture cannot silently regress.

## External Vulnerability Lessons (Applied)

1. Route-level VPN bypass / split-tunnel abuse (`TunnelVision`, CVE-2024-3661)
- Public references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-3661
  - https://www.tunnelvisionbug.com/faq
- Lesson:
  - Route-based VPNs can be bypassed when route-control trust boundaries are weak or manipulated by hostile local network control-plane inputs.
- Rustynet enforcement direction:
  - Keep fail-closed route enforcement and deny unauthorized route mutation for non-admin roles.
  - Keep auto-tunnel enforcement route mutation constrained to explicit policy exceptions only.

2. Encrypted-overlay downgrade/race issues leading to unencrypted forwarding
- Public references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-28250
  - https://nvd.nist.gov/vuln/detail/CVE-2025-32793
- Lesson:
  - Policy/redirect races can create temporary cleartext paths.
- Rustynet enforcement direction:
  - Preserve deterministic reconcile ordering and fail-closed fallback.
  - Keep replay/watermark protection for signed assignment/traversal artifacts.

3. Privilege escalation via insecure local custody (writable or symlinked trusted paths)
- Public references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-10204
  - https://nvd.nist.gov/vuln/detail/CVE-2018-9105
- Lesson:
  - Local privilege boundaries are frequently broken by weak filesystem custody assumptions.
- Rustynet enforcement direction:
  - Validate **parent directory custody**, not just file ownership/mode.
  - Reject symlink parent directories for sensitive daemon artifacts.

## Implemented in This Pass

### Runtime hardening
- Added parent-directory security validation for sensitive daemon files in preflight path:
  - parent must exist,
  - parent must be a non-symlink directory,
  - parent must not be group/other writable (`mode & 0o022 == 0`),
  - parent owner must match runtime uid (or root when explicitly allowed).
- Enforcement point:
  - `crates/rustynetd/src/daemon.rs` (`validate_file_security` now calls parent-directory validator).
- Added dataplane firewall generation-handoff ordering hardening:
  - fail-closed table handoff now applies the new generation rules first and only then prunes the previous generation table,
  - stale generation state is not reused across generation changes,
  - pre-handoff pruning keeps both target and currently-active owned tables to avoid deleting active fail-closed state.
- Enforcement point:
  - `crates/rustynetd/src/phase10.rs` (`ensure_failclosed_table`, `prune_owned_tables`, `apply_firewall_killswitch`).

### New regression tests
- `daemon::tests::validate_file_security_rejects_group_writable_parent_directory`
- `daemon::tests::validate_file_security_rejects_symlink_parent_directory`
- `phase10::tests::firewall_generation_handoff_deletes_previous_table_only_after_new_rules_apply`
- `phase10::tests::prune_owned_tables_preserves_active_and_target_generation_tables`
- `daemon::tests::read_command_rejects_oversized_payload`
- `daemon::tests::read_command_rejects_null_byte_payload`
- `daemon::tests::node_role_command_matrix_is_fail_closed`
- `daemon::tests::role_auth_matrix_runtime_is_exhaustive_and_fail_closed`
- `daemon::tests::traversal_adversarial_gate_rejects_forged_stale_wrong_signer_and_nonce_replay`
- `daemon::tests::daemon_runtime_netcheck_rejects_forged_traversal_hint_fail_closed`
- `privileged_helper::tests::validate_request_rejects_too_many_arguments`
- `privileged_helper::tests::validate_request_rejects_argument_over_max_bytes`
- `traversal::tests::adversarial_gate_nat_mismatch_blocks_unauthorized_direct_and_keeps_safe_relay_fallback`
- `ops_phase9::tests::read_json_object_rejects_oversized_source`
- `ops_phase9::tests::read_utf8_regular_file_with_max_bytes_rejects_oversized_source`
- `ops_phase9::tests::release_provenance_verification_rejects_tampered_artifact`
- `ops_phase9::tests::release_provenance_verification_rejects_unsigned_document`
- `key_material::tests::remove_file_if_present_rejects_directory`
- `key_material::tests::remove_file_if_present_removes_symlink_without_following_target`
- `tests::secure_remove_file_rejects_directory` (`rustynet-cli`)
- `tests::secure_remove_file_removes_target_file` (`rustynet-cli`)
- `tests::create_secure_temp_file_sets_owner_only_mode` (`rustynet-cli`)
- `scripts/ci/no_leak_dataplane_gate.sh` + `scripts/e2e/real_wireguard_no_leak_under_load.sh` (root Linux high-assurance no-leak gate)
- `scripts/ci/secrets_hygiene_gates.sh` (plaintext-artifact/log-argv/tmp/secure-delete hygiene gate)
- `scripts/ci/role_auth_matrix_gates.sh` (exhaustive role x command x mode x hop allow/deny matrix, including blind_exit least-knowledge restrictions)
- `scripts/ci/traversal_adversarial_gates.sh` (forged/stale/wrong-signer/replay traversal-hint rejection + NAT-mismatch relay safety)
- `scripts/ci/supply_chain_integrity_gates.sh` (cargo audit/deny + SBOM + signed attestation verification + unsigned/tampered binary rejection)

These tests prevent regressions where sensitive artifact validation would accept hostile parent-directory custody.
The phase10 handoff test prevents regressions that could reintroduce transient cleartext forwarding windows during generation rollover.
The traversal adversarial tests enforce fail-closed behavior for forged/stale/wrong-signer/replayed traversal hints and block direct-path planning under NAT-mismatch relay-only conditions.

## Continuous Enforcement Path
- The new tests are part of `cargo test --workspace --all-targets --all-features`.
- Phase gates (for example Phase10) already execute workspace tests, so this hardening is enforced in CI/release gate paths.
- A dedicated gate bundle now enforces high-value anti-regression tests:
  - `scripts/ci/security_regression_gates.sh`
  - invoked by `scripts/ci/phase10_gates.sh`.
- Traversal adversarial checks are part of that gate bundle (`scripts/ci/traversal_adversarial_gates.sh`) and fail closed on:
  - forged/tampered hint signatures,
  - wrong-signer hints,
  - stale hints,
  - nonce replay/rollback hints,
  - NAT mismatch relay-only direct-path denial.
- A dedicated secrets hygiene gate is now part of the regression bundle:
  - `scripts/ci/secrets_hygiene_gates.sh`
  - asserts:
    - no runtime plaintext key artifacts at rest in repo/workspace paths,
    - no inline secret argv flags in source paths,
    - no secret-like leaks in generated artifact/log payloads,
    - strict mode/owner and secure-delete regression tests stay green,
    - shell tmp secret materialization paths enforce `chmod 600` + secure-delete cleanup.
- A dedicated role/auth matrix gate is now part of the regression bundle:
  - `scripts/ci/role_auth_matrix_gates.sh`
  - asserts:
    - exhaustive `role x command x mode x hop` authorization outcomes,
    - fail-closed deny-reason precedence (`role` -> `restricted-safe` -> `auto-tunnel`),
    - blind-exit least-knowledge status invariants (`exit_node=none`, `serving_exit_node=true`, `lan_access=off`).
- Real dataplane no-leak gate is integrated into security regression flow with strict control:
  - `RUSTYNET_SECURITY_RUN_NO_LEAK_GATE=auto` (default): run when host is root Linux.
  - `RUSTYNET_SECURITY_REQUIRE_NO_LEAK_GATE=1`: fail if gate cannot run on current host.
  - CI can enforce this gate by setting `RUSTYNET_SECURITY_REQUIRE_NO_LEAK_GATE=1`.
- Optional real Linux netns leak test is supported via:
  - `RUSTYNET_SECURITY_RUN_REAL_NETNS_E2E=1 ./scripts/ci/security_regression_gates.sh`
  - fails closed if host is not Linux or lacks root privileges.
- Supply-chain integrity gate is now enforced in both release-assurance and regression paths:
  - `scripts/ci/phase8_gates.sh` invokes `scripts/ci/supply_chain_integrity_gates.sh`
  - `scripts/ci/security_regression_gates.sh` invokes `scripts/ci/supply_chain_integrity_gates.sh`
  - Gate requirements:
    - `cargo audit --deny warnings` with advisory DB bootstrap
    - `cargo deny check bans licenses sources advisories`
    - SBOM generation + digest (`scripts/release/generate_sbom.sh`)
    - signed release provenance generation (`rustynet ops sign-release-artifact`)
    - fail-closed attestation verify (`rustynet ops verify-release-artifact`)
    - negative checks requiring rejection of unsigned and tampered release artifacts.

## Additional High-Value Backlog Tests (Next)
1. Role/Auth matrix expansion
- Extend matrix assertions to include membership-health variants (active/revoked/quarantined) and ensure authz outcomes remain deterministic across each role/mode/hop cell.
- Add coverage for additional mutating commands introduced in future CLI/daemon revisions so matrix gates remain complete by default.

2. Reconcile race/fail-closed invariant expansion
- Extend deterministic handoff tests to include NAT/table handoff sequencing and rollback-injected failures.
- Assert fail-closed guarantees across firewall + NAT + route updates as a single transaction boundary.

3. Artifact size and parser abuse limits
- Add maximum input size guards + tests for trust/assignment/traversal artifact parsing to prevent local DoS via oversized artifacts.
- Status update: completed in current security-regression gates (`artifact_limitgate_*`, `artifact_fuzzgate_*`).

4. Socket and local IPC abuse hardening tests
- Add explicit tests for socket ownership/mode drift and peer credential rejection on unauthorized UID access.

## Acceptance Standard for New Security Tests
- Every new security-sensitive behavior must include:
  - a positive test (works when secure),
  - a negative test (fails closed when violated),
  - gate inclusion (workspace or phase gate path).
