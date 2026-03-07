#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

is_truthy() {
  local value="${1:-}"
  [[ "$value" == "1" || "$value" == "true" || "$value" == "TRUE" || "$value" == "yes" || "$value" == "YES" ]]
}

./scripts/ci/run_required_test.sh rustynetd daemon::tests::read_command_rejects_oversized_payload
./scripts/ci/run_required_test.sh rustynetd daemon::tests::read_command_rejects_null_byte_payload
./scripts/ci/run_required_test.sh rustynetd daemon::tests::node_role_command_matrix_is_fail_closed
./scripts/ci/run_required_test.sh rustynetd daemon::tests::artifact_limitgate_rejects_oversized_bundle_files
./scripts/ci/run_required_test.sh rustynetd daemon::tests::artifact_limitgate_rejects_count_overflow_for_assignment_and_traversal
./scripts/ci/run_required_test.sh rustynetd daemon::tests::artifact_limitgate_rejects_excessive_key_depth
./scripts/ci/run_required_test.sh rustynetd daemon::tests::artifact_fuzzgate_rejects_rollback_generations_fail_closed
./scripts/ci/run_required_test.sh rustynetd daemon::tests::artifact_fuzzgate_bundle_parsers_never_panic_and_fail_closed
./scripts/ci/run_required_test.sh rustynetd daemon::tests::load_auto_tunnel_bundle_rejects_equal_watermark_when_payload_digest_differs
./scripts/ci/run_required_test.sh rustynetd daemon::tests::load_trust_evidence_rejects_equal_watermark_when_payload_digest_differs

./scripts/ci/run_required_test.sh rustynetd privileged_helper::tests::validate_request_rejects_too_many_arguments
./scripts/ci/run_required_test.sh rustynetd privileged_helper::tests::validate_request_rejects_argument_over_max_bytes
./scripts/ci/run_required_test.sh rustynetd privileged_helper::tests::fuzzgate_read_request_rejects_oversized_payload
./scripts/ci/run_required_test.sh rustynetd privileged_helper::tests::fuzzgate_rejects_unknown_tokens_and_shell_metacharacters
./scripts/ci/run_required_test.sh rustynetd privileged_helper::tests::fuzzgate_malformed_inputs_never_panic

./scripts/ci/run_required_test.sh rustynet-cli ops_phase9::tests::read_json_object_rejects_oversized_source
./scripts/ci/run_required_test.sh rustynet-cli ops_phase9::tests::read_utf8_regular_file_with_max_bytes_rejects_oversized_source

./scripts/ci/secrets_hygiene_gates.sh
./scripts/ci/role_auth_matrix_gates.sh
./scripts/ci/traversal_adversarial_gates.sh
./scripts/ci/supply_chain_integrity_gates.sh

RUN_NO_LEAK_GATE_MODE="${RUSTYNET_SECURITY_RUN_NO_LEAK_GATE:-auto}"
REQUIRE_NO_LEAK_GATE="${RUSTYNET_SECURITY_REQUIRE_NO_LEAK_GATE:-${CI:-0}}"
if is_truthy "${REQUIRE_NO_LEAK_GATE}" && [[ "${RUN_NO_LEAK_GATE_MODE}" == "0" ]]; then
  echo "no-leak dataplane gate disable is forbidden when gate is required" >&2
  exit 1
fi
if [[ "${RUN_NO_LEAK_GATE_MODE}" == "1" ]]; then
  ./scripts/ci/no_leak_dataplane_gate.sh
elif [[ "${RUN_NO_LEAK_GATE_MODE}" == "auto" ]]; then
  if [[ "$(uname -s)" == "Linux" && "$(id -u)" -eq 0 ]]; then
    ./scripts/ci/no_leak_dataplane_gate.sh
  elif is_truthy "${REQUIRE_NO_LEAK_GATE}"; then
    echo "no-leak dataplane gate is required but host is not eligible (requires root Linux)" >&2
    exit 1
  else
    echo "No-leak dataplane gate skipped (requires root Linux)."
    echo "Set RUSTYNET_SECURITY_RUN_NO_LEAK_GATE=1 to run now or RUSTYNET_SECURITY_REQUIRE_NO_LEAK_GATE=1 to fail when unavailable."
  fi
elif [[ "${RUN_NO_LEAK_GATE_MODE}" != "0" ]]; then
  echo "invalid RUSTYNET_SECURITY_RUN_NO_LEAK_GATE value: ${RUN_NO_LEAK_GATE_MODE} (expected 0, 1, or auto)" >&2
  exit 1
fi

if [[ "${RUSTYNET_SECURITY_RUN_REAL_NETNS_E2E:-0}" == "1" ]]; then
  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "RUSTYNET_SECURITY_RUN_REAL_NETNS_E2E=1 requires a Linux host" >&2
    exit 1
  fi
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "RUSTYNET_SECURITY_RUN_REAL_NETNS_E2E=1 requires root privileges" >&2
    exit 1
  fi
  ./scripts/e2e/real_wireguard_exitnode_e2e.sh
fi

RUN_ACTIVE_NETWORK_GATES="${RUSTYNET_SECURITY_RUN_ACTIVE_NETWORK_GATES:-0}"
REQUIRE_ACTIVE_NETWORK_GATES="${RUSTYNET_SECURITY_REQUIRE_ACTIVE_NETWORK_GATES:-0}"
if is_truthy "${REQUIRE_ACTIVE_NETWORK_GATES}" && ! is_truthy "${RUN_ACTIVE_NETWORK_GATES}"; then
  echo "active network security gates are required but disabled; set RUSTYNET_SECURITY_RUN_ACTIVE_NETWORK_GATES=1" >&2
  exit 1
fi
if is_truthy "${RUN_ACTIVE_NETWORK_GATES}"; then
  ./scripts/ci/active_network_security_gates.sh
elif is_truthy "${REQUIRE_ACTIVE_NETWORK_GATES}"; then
  echo "active network security gates are required but did not execute" >&2
  exit 1
fi

echo "Security regression gates: PASS"
