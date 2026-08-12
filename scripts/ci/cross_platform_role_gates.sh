#!/usr/bin/env bash
# Track B (B1.4, B1.5, M1, M2, W1, W4) of
# documents/operations/active/AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md
#
# Verifies the cross-platform role surface: topology selector, macOS
# exit-mode validators, exit/relay service installers (per OS), and the
# platform-aware role-transition planner.
set -euo pipefail

echo "Running cross-platform role CI gates..."

# --features vm-lab is REQUIRED, not decoration: the vm_lab:: modules filtered
# below sit behind that default-off feature (RNQ-17), so without it every
# filter matches zero tests -- and `cargo test` exits 0 on an empty match, so
# the gate would report success having checked nothing. run_cli_test asserts a
# non-zero pass count so an empty match can never read as a pass.
assert_at_least_one_pass() {
  local out="$1"; shift
  if ! printf '%s\n' "$out" | grep -Eq 'test result: ok\. [1-9][0-9]* passed'; then
    echo "GATE DEFECT: test filter matched zero tests: $*" >&2
    return 1
  fi
}

run_cli_test() {
  local out
  out="$(cargo test -p rustynet-cli --features vm-lab --bin rustynet-cli "$@" 2>&1)" || {
    printf '%s\n' "$out"
    return 1
  }
  assert_at_least_one_pass "$out" "$@"
}

# role_cli is declared in lib.rs (`pub mod role_cli;`) and NOT in main.rs, so a
# --bin filter can never match its tests. That is a second, independent defect
# with the same silent-pass effect as the missing feature, and it is why these
# three filters had never run. ops_install_* is the mirror image -- bin-only --
# and vm_lab is in both, so each target below is chosen, not incidental.
run_cli_lib_test() {
  local out
  out="$(cargo test -p rustynet-cli --features vm-lab --lib "$@" 2>&1)" || {
    printf '%s\n' "$out"
    return 1
  }
  assert_at_least_one_pass "$out" "$@"
}

required_files=(
  crates/rustynet-cli/src/vm_lab/topology.rs
  crates/rustynet-cli/src/ops_install_systemd_exit.rs
  crates/rustynet-cli/src/ops_install_macos_exit.rs
  crates/rustynetd/src/linux_exit_nat_lifecycle.rs
  crates/rustynetd/src/linux_exit_dns_failclosed.rs
  crates/rustynetd/src/macos_exit_nat_lifecycle.rs
  scripts/e2e/capture_linux_exit_nat_lifecycle.sh
  scripts/e2e/capture_macos_exit_nat_lifecycle.sh
  scripts/systemd/rustynet-exit.service
  scripts/launchd/com.rustynet.exit.plist
  scripts/bootstrap/windows/Install-RustyNetWindowsExitService.ps1
  scripts/bootstrap/windows/Uninstall-RustyNetWindowsExitService.ps1
)

for path in "${required_files[@]}"; do
  test -f "$path"
done

# Topology selector surface.
rg -q 'pub enum TopologyRole' crates/rustynet-cli/src/vm_lab/topology.rs
rg -q 'pub enum TopologyPlatform' crates/rustynet-cli/src/vm_lab/topology.rs
rg -q 'pub fn parse_topology_profile_file' crates/rustynet-cli/src/vm_lab/topology.rs
rg -q 'apply_topology_overrides_to_orchestrate_config' crates/rustynet-cli/src/vm_lab/topology.rs

# Role planner emits exit-service actions.
rg -q 'ConcreteAction::DeployExitService' crates/rustynet-cli/src/role_cli.rs
rg -q 'ConcreteAction::UndeployExitService' crates/rustynet-cli/src/role_cli.rs
rg -q 'execute_platform_exit_service_action' crates/rustynet-cli/src/main.rs
rg -q 'execute_platform_relay_service_action' crates/rustynet-cli/src/main.rs

# macOS exit validators + evaluators.
rg -q 'validate_macos_exit_nat_lifecycle' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'validate_macos_exit_dns_failclosed' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'validate_macos_exit_killswitch_precedence' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'evaluate_macos_exit_nat_lifecycle_artifact' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'evaluate_macos_exit_dns_failclosed_artifact_dir' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'evaluate_macos_exit_killswitch_precedence_artifact' crates/rustynet-cli/src/vm_lab/mod.rs

# Windows active-exit promotion stage.
rg -q 'promote_windows_exit_active' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'promote_to_active_exit' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'WINDOWS_ACTIVE_EXIT_PROMOTE_TIMEOUT_SECS' crates/rustynet-cli/src/vm_lab/mod.rs

# macOS + Windows relay/anchor live-lab stage slots.
rg -q 'validate_macos_relay_service_lifecycle' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'validate_macos_anchor_bundle_pull' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'validate_windows_relay_service_lifecycle' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'validate_windows_anchor_bundle_pull' crates/rustynet-cli/src/vm_lab/mod.rs

# Step 7 (B1.2) non-Linux genesis verbs.
rg -q 'E2eBootstrapMacos' crates/rustynet-cli/src/main.rs
rg -q 'E2eBootstrapWindows' crates/rustynet-cli/src/main.rs
rg -q 'execute_ops_e2e_bootstrap_macos' crates/rustynet-cli/src/ops_e2e.rs
rg -q 'execute_ops_e2e_bootstrap_windows' crates/rustynet-cli/src/ops_e2e.rs

# Producer side: macOS NAT lifecycle snapshot subcommand + library
# functions feeding the validator's two-phase artefact contract.
rg -q 'macos-exit-nat-lifecycle-snapshot' crates/rustynetd/src/main.rs
rg -q 'build_macos_exit_nat_lifecycle_snapshot' crates/rustynetd/src/macos_exit_nat_lifecycle.rs
rg -q 'merge_macos_exit_nat_lifecycle_artifact' crates/rustynetd/src/macos_exit_nat_lifecycle.rs

# Producer side: Linux NAT lifecycle snapshot subcommand + library
# functions feeding the validator's two-phase artefact contract.
rg -q 'linux-exit-nat-lifecycle-snapshot' crates/rustynetd/src/main.rs
rg -q 'linux-exit-dns-failclosed-capture' crates/rustynetd/src/main.rs
rg -q 'build_linux_exit_nat_lifecycle_snapshot' crates/rustynetd/src/linux_exit_nat_lifecycle.rs
rg -q 'merge_linux_exit_nat_lifecycle_artifact' crates/rustynetd/src/linux_exit_nat_lifecycle.rs
rg -q 'validate_linux_exit_nat_lifecycle' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'write_linux_exit_dns_failclosed_artifacts' crates/rustynetd/src/linux_exit_dns_failclosed.rs
rg -q 'validate_linux_exit_dns_failclosed' crates/rustynet-cli/src/vm_lab/mod.rs

# Unit tests covering the surfaces above. Each `-p rustynet-cli` test
# target is a single hermetic binary, so the gate doesn't need a live
# VM lab to run; it is safe in PR-time CI.
run_cli_test \
  vm_lab::topology::tests:: -- --nocapture
run_cli_lib_test \
  role_cli::tests::admin_to_exit_advertises_default_route_then_deploys_exit_preflight -- --nocapture
run_cli_lib_test \
  role_cli::tests::exit_to_admin_undeploys_exit_preflight_then_retracts_default_route -- --nocapture
run_cli_lib_test \
  role_cli::tests::pre_d11a_surface_matrix -- --nocapture
run_cli_test \
  ops_install_systemd_exit::tests:: -- --nocapture
run_cli_test \
  ops_install_macos_exit::tests:: -- --nocapture
run_cli_test \
  vm_lab::tests::evaluate_macos_exit_nat_lifecycle_artifact_accepts_reviewed_payload -- --nocapture
run_cli_test \
  vm_lab::tests::evaluate_macos_exit_dns_failclosed_artifact_dir_accepts_reviewed_payloads -- --nocapture
run_cli_test \
  vm_lab::tests::evaluate_macos_exit_killswitch_precedence_artifact_accepts_reviewed_payload -- --nocapture
run_cli_test \
  vm_lab::tests::macos_exit_nat_lifecycle_producer_to_validator_round_trip -- --nocapture
run_cli_test \
  vm_lab::tests::macos_exit_nat_lifecycle_producer_round_trip_rejects_forwarding_not_restored -- --nocapture
cargo test -p rustynetd --lib macos_exit_nat_lifecycle:: -- --nocapture
run_cli_test \
  vm_lab::tests::linux_exit_nat_lifecycle_producer_to_validator_round_trip -- --nocapture
cargo test -p rustynetd --lib linux_exit_nat_lifecycle:: -- --nocapture
cargo test -p rustynetd --lib linux_exit_dns_failclosed:: -- --nocapture
run_cli_test \
  vm_lab::tests::evaluate_linux_exit_dns_failclosed_artifact_dir_accepts_reviewed_payloads -- --nocapture

echo "Cross-platform role CI gates: PASS"
