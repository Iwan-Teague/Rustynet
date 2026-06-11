#!/usr/bin/env bash
set -euo pipefail

# NAS default-deny gates (D13.c — NasNodeRoleDesign §7 controls):
# service-context truth table, tunnel-only bind, per-peer namespace
# isolation, at-rest ciphertext, quota, key custody, and
# deny-on-malformed wire input.

echo "Running NAS default-deny gates..."

required_files=(
  crates/rustynet-nas/src/store.rs
  crates/rustynet-nas/src/protocol.rs
  crates/rustynet-nas/src/main.rs
  crates/rustynetd/src/service_exposure.rs
  scripts/systemd/rustynet-nas.service
)

for path in "${required_files[@]}"; do
  test -f "$path"
done

# Enforcement points present.
rg -q 'validate_tunnel_only_bind' crates/rustynetd/src/service_exposure.rs
rg -q 'RoleCapability::ServesNas' crates/rustynet-control/src/roles.rs
rg -q 'LoadCredentialEncrypted' scripts/systemd/rustynet-nas.service
# Per-frame grant re-check in the binary (revocation is immediate).
rg -q 'admitted_peer' crates/rustynet-nas/src/main.rs

run_required_test() {
  local out
  out="$(cargo test "$@" 2>&1)" || { printf '%s\n' "$out"; return 1; }
  printf '%s\n' "$out"
  if ! printf '%s\n' "$out" | grep -Eq 'test result: ok\. [1-9][0-9]* passed'; then
    echo "GATE DEFECT: test filter matched zero tests: cargo test $*" >&2
    return 1
  fi
}

# Truth table: no policy → deny; allow → that peer/service only;
# legacy empty-context rules never grant service access;
# revoked/unknown membership → deny.
run_required_test -p rustynet-policy service_contexts_default_to_deny_on_empty_policy
run_required_test -p rustynet-policy service_allow_is_scoped_to_peer_and_service
run_required_test -p rustynet-policy empty_contexts_rule_matches_dataplane_but_never_service_contexts
run_required_test -p rustynet-policy service_context_membership_gate_denies_revoked_and_unknown_peers

# E1 — tunnel-only bind, fail-closed.
run_required_test -p rustynetd --lib service_exposure::tests::tunnel_only_bind_rejects_unspecified_addresses
run_required_test -p rustynetd --lib service_exposure::tests::tunnel_only_bind_rejects_non_tunnel_lan_address

# E2/E3 — admission + teardown-before-revoke state machine.
run_required_test -p rustynetd --lib service_exposure::tests::exposure_controller_enforces_full_lifecycle_fail_closed
run_required_test -p rustynetd --lib service_exposure::tests::capability_release_ready_only_in_torn_down

# At-rest ciphertext + namespace isolation + key custody + quota.
run_required_test -p rustynet-nas store::tests::put_get_round_trip_with_at_rest_ciphertext
run_required_test -p rustynet-nas store::tests::namespace_isolation_and_cross_namespace_replay_refused
run_required_test -p rustynet-nas store::tests::reopen_with_wrong_key_fails_keycheck
run_required_test -p rustynet-nas store::tests::open_refuses_group_world_accessible_data_root
run_required_test -p rustynet-nas store::tests::quota_enforced_and_idempotent_reput_not_double_counted

# Wire hardening: caps before allocation; no decoder panics.
run_required_test -p rustynet-nas protocol::tests::oversize_length_prefix_refused_before_allocation
run_required_test -p rustynet-nas protocol::tests::decode_never_panics_on_arbitrary_bytes

echo "NAS default-deny gates: PASS"
