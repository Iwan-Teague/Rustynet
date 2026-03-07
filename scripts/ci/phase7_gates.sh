#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

RUSTYNET_GATE_TEST_THREADS="${RUSTYNET_GATE_TEST_THREADS:-1}"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
RUST_TEST_THREADS="${RUSTYNET_GATE_TEST_THREADS}" cargo test --workspace --all-targets --all-features

./scripts/ci/phase6_gates.sh

./scripts/ci/run_required_test.sh rustynet-control scale::tests::ha_cluster_fails_over_to_next_healthy_replica
./scripts/ci/run_required_test.sh rustynet-control scale::tests::ha_cluster_rejects_when_no_healthy_replica_exists
./scripts/ci/run_required_test.sh rustynet-control scale::tests::tenant_guard_enforces_isolation_and_delegated_admin_limits
./scripts/ci/run_required_test.sh rustynet-control scale::tests::trust_hardening_fails_closed_when_state_missing_or_mismatched
./scripts/ci/run_required_test.sh rustynet-control scale::tests::trust_hardening_disable_requires_break_glass_secret
./scripts/ci/run_required_test.sh rustynet-relay tests::relay_selection_policy_respects_allowed_regions
./scripts/ci/run_required_test.sh rustynet-relay tests::relay_fleet_fails_over_when_primary_is_unhealthy

echo "Phase 7 CI gates: PASS"
