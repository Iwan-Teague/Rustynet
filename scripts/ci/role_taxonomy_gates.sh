#!/usr/bin/env bash
set -euo pipefail

# Nine-preset role taxonomy gates (D12 base six + D13 service-hosting
# nas/llm + the blind_relay phase-2 role). Asserts the canonical
# preset/capability/transition model,
# its CLI planner consumption, the signed-membership wire vocabulary,
# and the MCP repo-context mirror all agree on the nine-role surface.
#
# Canonical design:
#   documents/operations/active/NodeRoleTaxonomy_2026-05-21.md
#   documents/operations/active/NodeRoleTaxonomyExtension_2026-06-11.md

echo "Running nine-preset role taxonomy gates..."

required_files=(
  crates/rustynet-control/src/role_presets.rs
  crates/rustynet-control/src/roles.rs
  crates/rustynet-control/src/membership.rs
  crates/rustynet-cli/src/role_cli.rs
  crates/rustynet-mcp/src/bin/repo_context.rs
  documents/operations/active/NodeRoleTaxonomy_2026-05-21.md
  documents/operations/active/NodeRoleTaxonomyExtension_2026-06-11.md
)

for path in "${required_files[@]}"; do
  test -f "$path"
done

# Canonical model: nine presets, two service-hosting capabilities,
# generalised sibling-service lifecycle.
rg -q 'ROLE_PRESET_TABLE: \[RolePresetComposition; 9\]' crates/rustynet-control/src/role_presets.rs
rg -q 'RolePreset::Nas' crates/rustynet-control/src/role_presets.rs
rg -q 'RolePreset::Llm' crates/rustynet-control/src/role_presets.rs
rg -q 'RolePreset::BlindRelay' crates/rustynet-control/src/role_presets.rs
rg -q 'Capability::ServesNas' crates/rustynet-control/src/role_presets.rs
rg -q 'Capability::ServesLlm' crates/rustynet-control/src/role_presets.rs
rg -q 'capabilities_require_nas_binary' crates/rustynet-control/src/role_presets.rs
rg -q 'capabilities_require_llm_binary' crates/rustynet-control/src/role_presets.rs
rg -q 'service_deploys' crates/rustynet-control/src/role_presets.rs
rg -q 'service_undeploys' crates/rustynet-control/src/role_presets.rs

# Signed-membership wire vocabulary.
rg -q 'RoleCapability::ServesNas' crates/rustynet-control/src/roles.rs
rg -q 'RoleCapability::ServesLlm' crates/rustynet-control/src/roles.rs
rg -q 'is_service_hosting_capability' crates/rustynet-control/src/roles.rs

# CLI planner consumes the generalised lifecycle.
rg -q 'DeployNasService' crates/rustynet-cli/src/role_cli.rs
rg -q 'UndeployNasService' crates/rustynet-cli/src/role_cli.rs
rg -q 'DeployLlmService' crates/rustynet-cli/src/role_cli.rs
rg -q 'UndeployLlmService' crates/rustynet-cli/src/role_cli.rs

# MCP repo-context mirror carries the nine-role surface.
rg -q 'Preset::Nas' crates/rustynet-mcp/src/bin/repo_context.rs
rg -q 'Preset::Llm' crates/rustynet-mcp/src/bin/repo_context.rs

# Run a filtered cargo test and fail closed if the filter matched
# zero tests (cargo exits 0 on an empty match, which would let a
# renamed/deleted test silently hollow this gate out).
run_required_test() {
  local out
  out="$(cargo test "$@" 2>&1)" || { printf '%s\n' "$out"; return 1; }
  printf '%s\n' "$out"
  if ! printf '%s\n' "$out" | grep -Eq 'test result: ok\. [1-9][0-9]* passed'; then
    echo "GATE DEFECT: test filter matched zero tests: cargo test $*" >&2
    return 1
  fi
}

# Canonical table + transition matrix (9×9 drift oracles).
run_required_test -p rustynet-control role_presets::tests::preset_table_has_exactly_nine_entries
run_required_test -p rustynet-control role_presets::tests::transition_matrix_matches_taxonomy_doc
run_required_test -p rustynet-control role_presets::tests::service_lifecycle_matrix_matches_taxonomy_extension_doc
run_required_test -p rustynet-control role_presets::tests::capability_ordering_is_append_only
run_required_test -p rustynet-control roles::tests::service_hosting_capabilities_sort_after_existing_variants

# Signed membership: round-trip + tamper coverage for the new flags.
run_required_test -p rustynet-control membership::tests::set_node_capabilities_update_round_trips_service_hosting_flags
run_required_test -p rustynet-control membership::tests::tampered_service_hosting_capability_invalidates_signature
run_required_test -p rustynet-control membership::tests::blind_exit_rejects_service_hosting_capability_mix

# CLI planner: nas/llm deploy/undeploy ordering + exit teardown.
# (--lib: the planner tests live in the rustynet-cli LIB module
# role_cli, not the main binary; --lib scoping avoids spawning the
# package's ~86 other test binaries per invocation.)
run_required_test -p rustynet-cli --lib role_cli::tests::target_nas_deploys_nas_service
run_required_test -p rustynet-cli --lib role_cli::tests::target_llm_deploys_llm_service
run_required_test -p rustynet-cli --lib role_cli::tests::relay_to_nas_deploys_nas_and_undeploys_relay_in_order
run_required_test -p rustynet-cli --lib role_cli::tests::exit_to_nas_tears_down_exit_serving_in_order
run_required_test -p rustynet-cli --lib role_cli::tests::blind_exit_to_nas_and_llm_is_locked

# Operator wizard env vocabulary.
run_required_test -p rustynet-operator role::tests::service_hosting_presets_parse_and_map_to_admin_primary

# MCP mirror stays faithful.
run_required_test -p rustynet-mcp --bin rustynet-mcp-repo-context

echo "Nine-preset role taxonomy gates: PASS"
