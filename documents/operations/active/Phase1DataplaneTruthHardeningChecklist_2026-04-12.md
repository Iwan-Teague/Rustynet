# Phase 1 Dataplane Truth Hardening Checklist

Prepared: 2026-04-12
Scope: `crates/rustynetd/src/phase10.rs` and its in-file tests
Objective: bind phase-10 exit-mode claims to measured route/rule truth and eliminate stale route-table ambiguity

## Checklist

- [x] `DataplaneSystem` exposes `assert_exit_policy(ExitMode)`
  Evidence:
  - code: `crates/rustynetd/src/phase10.rs`
  - tests: `phase10::tests::full_tunnel_apply_tracks_exit_mode_and_asserts_measured_policy`

- [x] Linux implementation checks `ip rule show`, `ip -4 route show table 51820`, and `ip -4 route get 1.1.1.1`
  Evidence:
  - code: `crates/rustynetd/src/phase10.rs`
  - tests: `phase10::tests::linux_assert_exit_policy_full_tunnel_checks_rule_table_and_probe`
  - tests: `phase10::tests::linux_assert_exit_policy_off_checks_rule_absence_and_underlay_probe`
  - tests: `phase10::tests::linux_assert_exit_policy_off_rejects_tunnel_probe_route`

- [x] `Phase10Controller` tracks `current_exit_mode`
  Evidence:
  - code: `crates/rustynetd/src/phase10.rs`
  - tests: `phase10::tests::full_tunnel_apply_tracks_exit_mode_and_asserts_measured_policy`
  - tests: `phase10::tests::set_and_clear_exit_node_track_exit_mode_and_assert_measured_policy`
  - tests: `phase10::tests::managed_peer_reconfigure_asserts_current_full_tunnel_policy`

- [x] `apply_generation_stages()` asserts exit policy rather than only killswitch existence
  Evidence:
  - code: `crates/rustynetd/src/phase10.rs`
  - tests: `phase10::tests::full_tunnel_apply_tracks_exit_mode_and_asserts_measured_policy`

- [x] Route rebuild flushes table 51820 before endpoint bypass routes are re-applied
  Evidence:
  - code: `crates/rustynetd/src/phase10.rs`
  - tests: `phase10::tests::apply_generation_flushes_routes_before_endpoint_bypass_rebuild`

- [x] Route rollback flushes both IPv4 and IPv6 table 51820 state
  Evidence:
  - code: `crates/rustynetd/src/phase10.rs`
  - tests: `phase10::tests::rollback_routes_flushes_ipv4_and_ipv6_table_51820`

- [x] Managed-peer endpoint reconfiguration asserts the controller's current exit policy
  Evidence:
  - code: `crates/rustynetd/src/phase10.rs`
  - tests: `phase10::tests::test_a4b_direct_to_relay_transition_asserts_measured_exit_policy`
  - tests: `phase10::tests::test_a4b_relay_to_direct_transition_asserts_measured_exit_policy`
  - tests: `phase10::tests::managed_peer_reconfigure_asserts_current_full_tunnel_policy`

## Validation Evidence

- [x] `cargo fmt --all -- --check`
- [x] `cargo check -p rustynetd`
- [x] `cargo check --workspace --all-targets --all-features`
- [x] `cargo clippy -p rustynetd --all-targets -- -D warnings`
- [x] `cargo test -p rustynetd phase10 -- --nocapture`
- [ ] `cargo audit --deny warnings`
  Reason: `cargo-audit` is not installed in this environment (`cargo audit` returned `no such command: audit`).
- [ ] `cargo deny check bans licenses sources advisories`
  Reason: `cargo-deny` is not installed in this environment (`cargo deny` returned `no such command: deny`).
