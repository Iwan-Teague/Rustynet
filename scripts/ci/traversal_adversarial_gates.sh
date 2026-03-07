#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

./scripts/ci/run_required_test.sh rustynetd daemon::tests::load_traversal_bundle_rejects_tampered_signature_and_replay
./scripts/ci/run_required_test.sh rustynetd daemon::tests::traversal_adversarial_gate_rejects_forged_stale_wrong_signer_and_nonce_replay
./scripts/ci/run_required_test.sh rustynetd daemon::tests::load_traversal_bundle_rejects_private_srflx_candidate
./scripts/ci/run_required_test.sh rustynetd daemon::tests::daemon_runtime_netcheck_rejects_forged_traversal_hint_fail_closed
./scripts/ci/run_required_test.sh rustynetd traversal::tests::adversarial_gate_nat_mismatch_blocks_unauthorized_direct_and_keeps_safe_relay_fallback

echo "Traversal adversarial gate: PASS"
