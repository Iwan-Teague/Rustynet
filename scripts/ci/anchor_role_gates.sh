#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=lib/required_test.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/required_test.sh"

echo "Running anchor role CI gates..."

required_files=(
  scripts/systemd/rustynetd-anchor.service
  scripts/systemd/rustynet-relay.service
  scripts/launchd/com.rustynet.relay.plist
  crates/rustynet-cli/src/anchor_init.rs
  crates/rustynet-cli/src/ops_install_systemd_relay.rs
  crates/rustynet-cli/src/ops_install_macos_relay.rs
)

for path in "${required_files[@]}"; do
  test -f "$path"
done

rg -q 'RoleCapability::AnchorGossipSeed' crates/rustynet-control/src/roles.rs
rg -q 'RoleCapability::AnchorBundlePull' crates/rustynet-control/src/roles.rs
rg -q 'RoleCapability::AnchorEnrollmentEndpoint' crates/rustynet-control/src/roles.rs
rg -q 'RoleCapability::AnchorRelayColocation' crates/rustynet-control/src/roles.rs
rg -q 'RoleCapability::AnchorPortMappingAuthoritative' crates/rustynet-control/src/roles.rs
rg -q 'anchor_runtime_view_from_membership' crates/rustynetd/src/gossip_runtime.rs
rg -q 'execute_platform_relay_service_action' crates/rustynet-cli/src/main.rs

run_required_test -p rustynet-control set_node_capabilities_update_round_trips_and_previews -- --nocapture
run_required_test -p rustynet-control blind_exit_rejects_anchor_capability_mix -- --nocapture
run_required_test -p rustynet-cli role_cli::tests::target_anchor_deploys_relay_service -- --nocapture
run_required_test -p rustynet-cli ops_install_systemd_relay::tests -- --nocapture
run_required_test -p rustynet-cli ops_install_macos_relay::tests -- --nocapture
run_required_test -p rustynetd gossip_runtime::tests::anchor_runtime_view_uses_signed_capabilities_and_lex_min_authority -- --nocapture
run_required_test -p rustynetd daemon::tests::port_mapping_skipped_when_authority_unavailable -- --nocapture
run_required_test -p rustynetd daemon::tests::port_mapping_skipped_when_non_authority -- --nocapture
run_required_test -p rustynetd daemon::tests::port_mapping_proceeds_when_self_is_authority -- --nocapture

echo "Anchor role CI gates: PASS"
