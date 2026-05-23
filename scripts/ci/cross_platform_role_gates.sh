#!/usr/bin/env bash
# Track B (B1.4, B1.5, M1, M2, W1, W4) of
# documents/operations/active/AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md
#
# Verifies the cross-platform role surface: topology selector, macOS
# exit-mode validators, exit/relay service installers (per OS), and the
# platform-aware role-transition planner.
set -euo pipefail

echo "Running cross-platform role CI gates..."

required_files=(
  crates/rustynet-cli/src/vm_lab/topology.rs
  crates/rustynet-cli/src/ops_install_systemd_exit.rs
  crates/rustynet-cli/src/ops_install_macos_exit.rs
  crates/rustynetd/src/macos_exit_nat_lifecycle.rs
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

# Unit tests covering the surfaces above. Each `-p rustynet-cli` test
# target is a single hermetic binary, so the gate doesn't need a live
# VM lab to run; it is safe in PR-time CI.
cargo test -p rustynet-cli --bin rustynet-cli \
  vm_lab::topology::tests:: -- --nocapture
cargo test -p rustynet-cli --bin rustynet-cli \
  role_cli::tests::admin_to_exit_advertises_default_route_then_deploys_exit_preflight -- --nocapture
cargo test -p rustynet-cli --bin rustynet-cli \
  role_cli::tests::exit_to_admin_undeploys_exit_preflight_then_retracts_default_route -- --nocapture
cargo test -p rustynet-cli --bin rustynet-cli \
  role_cli::tests::pre_d11a_surface_matrix -- --nocapture
cargo test -p rustynet-cli --bin rustynet-cli \
  ops_install_systemd_exit::tests:: -- --nocapture
cargo test -p rustynet-cli --bin rustynet-cli \
  ops_install_macos_exit::tests:: -- --nocapture
cargo test -p rustynet-cli --bin rustynet-cli \
  vm_lab::tests::evaluate_macos_exit_nat_lifecycle_artifact_accepts_reviewed_payload -- --nocapture
cargo test -p rustynet-cli --bin rustynet-cli \
  vm_lab::tests::evaluate_macos_exit_dns_failclosed_artifact_dir_accepts_reviewed_payloads -- --nocapture
cargo test -p rustynet-cli --bin rustynet-cli \
  vm_lab::tests::evaluate_macos_exit_killswitch_precedence_artifact_accepts_reviewed_payload -- --nocapture
cargo test -p rustynet-cli --bin rustynet-cli \
  vm_lab::tests::macos_exit_nat_lifecycle_producer_to_validator_round_trip -- --nocapture
cargo test -p rustynet-cli --bin rustynet-cli \
  vm_lab::tests::macos_exit_nat_lifecycle_producer_round_trip_rejects_forwarding_not_restored -- --nocapture
cargo test -p rustynetd --lib macos_exit_nat_lifecycle:: -- --nocapture

echo "Cross-platform role CI gates: PASS"
