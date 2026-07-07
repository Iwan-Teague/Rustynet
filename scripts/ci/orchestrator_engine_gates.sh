#!/usr/bin/env bash
set -euo pipefail

# Rust-native orchestrator engine gates.
# Runs the full orchestrator test suite (plan builder, state machine runner,
# context save/load, stage implementations, role validation, parity diff,
# topology resolution, role assignment, remote shell, adapter factory) plus
# the drift gates and MCP doc-table mirror. Each group is a single cargo
# test invocation with a module-prefix filter; the 'test result: ok.'
# assertion ensures the filter matched at least one test (cargo exits 0
# on an empty match).

echo "Running Rust-native orchestrator engine gates..."

assert_at_least_one_pass() {
  local out="$1"
  if ! printf '%s\n' "$out" | grep -Eq 'test result: ok\. [1-9][0-9]* passed'; then
    echo "GATE DEFECT: test filter matched zero tests" >&2
    return 1
  fi
}

run_orch() {
  local out label="$1"; shift
  echo "  -- $label"
  out="$(cargo test -p rustynet-cli --bin rustynet-cli "$@" 2>&1)" || {
    printf '%s\n' "$out"
    return 1
  }
  assert_at_least_one_pass "$out"
}

# Core engine (plan + runner + context + parity).
run_orch "plan"            vm_lab::orchestrator::plan::tests
run_orch "runner"          vm_lab::orchestrator::runner::tests
run_orch "context"         vm_lab::orchestrator::context::tests
run_orch "parity"          vm_lab::orchestrator::parity::tests

# Topology + role assignment.
run_orch "topology"        vm_lab::topology::tests
run_orch "role_assignment" vm_lab::orchestrator::role_assignment::tests

# Adapter factory + adapters (all submodule tests).
run_orch "adapters"        'vm_lab::orchestrator::adapter::'
run_orch "remote_shell"    vm_lab::orchestrator::remote_shell::tests

# Stage implementations (the full tree — ~48 stage modules).
run_orch "stages"          vm_lab::orchestrator::stage::

# Role-validation functions.
run_orch "role_validation" vm_lab::orchestrator::role_validation::

# Stage registry drift gates.
run_orch "stage_registry"  live_lab_stage_registry::tests::every_rust_state_machine_stage_id_is_registered
run_orch "bash_registry"   live_lab_stage_registry::tests::every_bash_orchestrator_stage_literal_is_registered
run_orch "monitor_registry" live_lab_stage_registry::tests::every_monitor_fallback_catalog_stage_is_registered

# Run-matrix oracle parity (registry ≡ historical hand-maintained tables).
run_orch "matrix_oracle1"  'live_lab_run_matrix::registry_equivalence_tests::registry_matches_historical_rust_native_and_cross_os_and_special'
run_orch "matrix_oracle2"  'live_lab_run_matrix::registry_equivalence_tests::registry_matches_historical_logical_stage_name'
run_orch "matrix_oracle3"  'live_lab_run_matrix::registry_equivalence_tests::registry_matches_historical_platform_resolution'

# MCP doc table ≡ StageId::ALL.
echo "  -- mcp_doc_table"
out="$(cargo test -p rustynet-mcp --bin rustynet-mcp-repo-context 2>&1)" || {
  printf '%s\n' "$out"
  exit 1
}
assert_at_least_one_pass "$out"

echo "Rust-native orchestrator engine gates: PASS"
