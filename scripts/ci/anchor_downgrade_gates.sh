#!/usr/bin/env bash
set -euo pipefail

echo "Running anchor downgrade CI gates..."

rg -q 'replay_cache.observe' crates/rustynet-control/src/membership.rs
rg -q 'epoch_new != state.epoch.saturating_add(1)' crates/rustynet-control/src/membership.rs
rg -q 'port_mapping_skipped_when_authority_unavailable' crates/rustynetd/src/daemon.rs
rg -q 'anchor_runtime_view_uses_signed_capabilities_and_lex_min_authority' crates/rustynetd/src/gossip_runtime.rs

cargo test -p rustynet-control replay_and_rollback_are_rejected -- --nocapture
cargo test -p rustynet-control active_membership_nodes_require_signed_capabilities -- --nocapture
cargo test -p rustynet-control signed_membership_payload_carries_canonical_capabilities -- --nocapture
cargo test -p rustynet-control set_node_capabilities_update_round_trips_and_previews -- --nocapture
cargo test -p rustynetd gossip_runtime::tests::anchor_runtime_view_uses_signed_capabilities_and_lex_min_authority -- --nocapture
cargo test -p rustynetd daemon::tests::port_mapping_skipped_when_authority_unavailable -- --nocapture

echo "Anchor downgrade CI gates: PASS"
