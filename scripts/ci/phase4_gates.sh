#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

RUSTYNET_GATE_TEST_THREADS="${RUSTYNET_GATE_TEST_THREADS:-1}"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
RUST_TEST_THREADS="${RUSTYNET_GATE_TEST_THREADS}" cargo test --workspace --all-targets --all-features

scripts/perf/run_phase1_baseline.sh
scripts/perf/run_phase3_baseline.sh

./scripts/ci/run_required_test.sh rustynetd dataplane::tests::phase4_exit_node_selection_and_lan_toggle_are_enforced
./scripts/ci/run_required_test.sh rustynetd dataplane::tests::phase4_magic_dns_handles_duplicate_hostnames_deterministically
./scripts/ci/run_required_test.sh rustynetd dataplane::tests::phase4_fail_close_blocks_tunnel_and_dns_when_required
./scripts/ci/run_required_test.sh rustynetd dataplane::tests::phase4_exit_node_clear_removes_selection
./scripts/ci/run_required_test.sh rustynet-policy contextual_policy_does_not_widen_between_shared_router_and_exit
./scripts/ci/run_required_test.sh rustynet-policy protocol_filter_is_preserved_for_shared_exit_context

echo "Phase 4 CI gates: PASS"
