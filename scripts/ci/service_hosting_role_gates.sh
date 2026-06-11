#!/usr/bin/env bash
set -euo pipefail

# Service-hosting role category gates (D13.e — SecurityMinimumBar
# §6.E controls E1-E4 + the eight-preset transition surface +
# deploy/undeploy lifecycle). The per-role truth tables live in
# nas_default_deny_gates.sh / llm_default_deny_gates.sh; this gate
# pins the shared category machinery and runs the full set.

echo "Running service-hosting role gates..."

required_files=(
  crates/rustynetd/src/service_exposure.rs
  crates/rustynet-cli/src/ops_install_systemd_service.rs
  crates/rustynet-cli/src/llm_cli.rs
  scripts/systemd/rustynet-nas.service
  scripts/systemd/rustynet-llm-gateway.service
  scripts/ci/role_taxonomy_gates.sh
  scripts/ci/nas_default_deny_gates.sh
  scripts/ci/llm_default_deny_gates.sh
  scripts/ci/llm_exit_coexistence_gates.sh
  documents/operations/active/NodeRoleTaxonomyExtension_2026-06-11.md
)

for path in "${required_files[@]}"; do
  test -f "$path"
done

# §6.E enforcement-point symbols (one hardened path per control).
rg -q 'validate_tunnel_only_bind' crates/rustynetd/src/service_exposure.rs        # E1
rg -q 'validate_loopback_only_bind' crates/rustynetd/src/service_exposure.rs      # E1 (engine)
rg -q 'evaluate_service_access' crates/rustynetd/src/service_exposure.rs          # E2
rg -q 'capability_release_ready' crates/rustynetd/src/service_exposure.rs         # E3
rg -q 'verify_session_token' crates/rustynet-llm-gateway/src/session.rs           # E4
rg -q 'render_service_port_tunnel_scope_table' crates/rustynetd/src/linux_runtime_nftables.rs
# Capability is metadata, never authority. The executable evidence
# is the tamper test below: flipping serves_nas/serves_llm in a
# signed update fails SIGNATURE verification before any capability
# semantics run — i.e. the verifier reaches the flags only through
# the already-verified payload. The capability invariants in
# membership.rs consult the flags via the canonicalised set
# (validate_membership_node_capabilities), after verification.
rg -q 'is_service_hosting_capability' crates/rustynet-control/src/membership.rs

run_required_test() {
  local out
  out="$(cargo test "$@" 2>&1)" || { printf '%s\n' "$out"; return 1; }
  printf '%s\n' "$out"
  if ! printf '%s\n' "$out" | grep -Eq 'test result: ok\. [1-9][0-9]* passed'; then
    echo "GATE DEFECT: test filter matched zero tests: cargo test $*" >&2
    return 1
  fi
}

# Signed-metadata-not-authority: tamper on the flags fails signature
# verification BEFORE any state mutation.
run_required_test -p rustynet-control membership::tests::tampered_service_hosting_capability_invalidates_signature

# Shared exposure machinery (E1-E3 deterministic state machine).
run_required_test -p rustynetd --lib service_exposure::tests::exposure_controller_enforces_full_lifecycle_fail_closed
run_required_test -p rustynetd --lib service_exposure::tests::sessions_to_sever_after_policy_change_returns_exactly_now_denied_sessions
run_required_test -p rustynetd --lib service_exposure::tests::service_hosting_view_reflects_active_node_capabilities

# Deploy/undeploy lifecycle: planner ordering for the new presets.
run_required_test -p rustynet-cli --bin rustynet-cli role_cli::tests::relay_to_nas_deploys_nas_and_undeploys_relay_in_order
run_required_test -p rustynet-cli --bin rustynet-cli role_cli::tests::exit_to_nas_tears_down_exit_serving_in_order
run_required_test -p rustynet-cli --bin rustynet-cli role_cli::tests::nas_to_llm_deploys_llm_and_undeploys_nas

# Category sub-gates (eight-preset taxonomy + per-role truth tables
# + exit coexistence).
./scripts/ci/role_taxonomy_gates.sh
./scripts/ci/role_transition_audit_gates.sh
./scripts/ci/nas_default_deny_gates.sh
./scripts/ci/llm_default_deny_gates.sh
./scripts/ci/llm_exit_coexistence_gates.sh

echo "Service-hosting role gates: PASS"
