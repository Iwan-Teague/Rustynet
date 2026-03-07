#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

./scripts/ci/run_required_test.sh rustynetd daemon::tests::node_role_command_matrix_is_fail_closed
./scripts/ci/run_required_test.sh rustynetd daemon::tests::role_auth_matrix_runtime_is_exhaustive_and_fail_closed
./scripts/ci/run_required_test.sh rustynetd daemon::tests::daemon_runtime_blind_exit_role_is_least_privilege
./scripts/ci/run_required_test.sh rustynetd daemon::tests::daemon_runtime_blind_exit_ignores_client_assignment_fields
./scripts/ci/run_required_test.sh rustynetd daemon::tests::daemon_runtime_auto_tunnel_enforcement_applies_and_blocks_manual_mutations
./scripts/ci/run_required_test.sh rustynetd daemon::tests::daemon_runtime_auto_tunnel_allows_relay_exit_with_upstream_exit
./scripts/ci/run_required_test.sh rustynetd daemon::tests::daemon_runtime_enters_restricted_safe_mode_without_trust_evidence

echo "Role/Auth matrix gate: PASS"
