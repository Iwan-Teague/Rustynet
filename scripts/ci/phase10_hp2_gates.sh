#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

SOURCE_DIR="${RUSTYNET_PHASE10_SOURCE_DIR:-$ROOT_DIR/artifacts/phase10/source}"
EVIDENCE_ENVIRONMENT="${RUSTYNET_PHASE10_EVIDENCE_ENVIRONMENT:-ci}"
mkdir -p "$SOURCE_DIR"

PATH_SELECTION_LOG="$SOURCE_DIR/traversal_path_selection_tests.log"
PROBE_SECURITY_LOG="$SOURCE_DIR/traversal_probe_security_tests.log"

: >"$PATH_SELECTION_LOG"
: >"$PROBE_SECURITY_LOG"

timestamp_utc() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

run_rustynetd_test() {
  local log_path="$1"
  local test_name="$2"
  printf '[%s] RUN cargo test -p rustynetd %s --all-features -- --exact --nocapture\n' \
    "$(timestamp_utc)" "$test_name" | tee -a "$log_path"
  cargo test -p rustynetd "$test_name" --all-features -- --exact --nocapture 2>&1 | tee -a "$log_path"
}

run_backend_test() {
  local log_path="$1"
  local test_name="$2"
  printf '[%s] RUN cargo test -p rustynet-backend-wireguard %s --all-targets --all-features -- --exact --nocapture\n' \
    "$(timestamp_utc)" "$test_name" | tee -a "$log_path"
  cargo test -p rustynet-backend-wireguard "$test_name" --all-targets --all-features -- --exact --nocapture 2>&1 | tee -a "$log_path"
}

run_rustynetd_test \
  "$PATH_SELECTION_LOG" \
  'daemon::tests::daemon_runtime_auto_tunnel_traversal_authority_accepts_multi_peer_snapshot'
run_rustynetd_test \
  "$PATH_SELECTION_LOG" \
  'daemon::tests::daemon_runtime_auto_tunnel_traversal_probe_falls_back_to_relay_without_handshake_evidence'
run_rustynetd_test \
  "$PATH_SELECTION_LOG" \
  'daemon::tests::daemon_runtime_auto_tunnel_traversal_probe_recovers_direct_when_handshake_arrives'
run_rustynetd_test \
  "$PATH_SELECTION_LOG" \
  'phase10::tests::traversal_probe_falls_back_to_relay_when_handshake_does_not_advance'
run_rustynetd_test \
  "$PATH_SELECTION_LOG" \
  'phase10::tests::traversal_probe_promotes_direct_when_handshake_advances'

run_rustynetd_test \
  "$PROBE_SECURITY_LOG" \
  'daemon::tests::load_traversal_bundle_rejects_tampered_signature_and_replay'
run_rustynetd_test \
  "$PROBE_SECURITY_LOG" \
  'daemon::tests::daemon_runtime_netcheck_rejects_forged_traversal_hint_fail_closed'
run_rustynetd_test \
  "$PROBE_SECURITY_LOG" \
  'daemon::tests::daemon_runtime_auto_tunnel_traversal_authority_requires_full_peer_coverage'
run_rustynetd_test \
  "$PROBE_SECURITY_LOG" \
  'daemon::tests::daemon_runtime_auto_tunnel_traversal_authority_rejects_unmanaged_peer_bundle'
run_rustynetd_test \
  "$PROBE_SECURITY_LOG" \
  'daemon::tests::daemon_runtime_auto_tunnel_traversal_runtime_sync_fail_closes_on_missing_peer_coverage'
run_rustynetd_test \
  "$PROBE_SECURITY_LOG" \
  'traversal::tests::adversarial_gate_nat_mismatch_blocks_unauthorized_direct_and_keeps_safe_relay_fallback'
run_rustynetd_test \
  "$PROBE_SECURITY_LOG" \
  'daemon::tests::traversal_adversarial_gate_rejects_forged_stale_wrong_signer_and_nonce_replay'
run_backend_test \
  "$PROBE_SECURITY_LOG" \
  'tests::latest_handshake_parser_rejects_oversized_or_malformed_output'
run_backend_test \
  "$PROBE_SECURITY_LOG" \
  'tests::linux_backend_reads_latest_handshake_for_configured_peer'

python3 - "$SOURCE_DIR" "$EVIDENCE_ENVIRONMENT" "$PATH_SELECTION_LOG" "$PROBE_SECURITY_LOG" <<'PY'
import json
import subprocess
import sys
import time
from pathlib import Path

source_dir = Path(sys.argv[1])
environment = sys.argv[2]
path_selection_log = Path(sys.argv[3])
probe_security_log = Path(sys.argv[4])
captured_at_unix = int(time.time())
git_commit = subprocess.check_output(
    ["git", "rev-parse", "HEAD"], text=True
).strip()

path_selection_report = {
    "phase": "phase10",
    "suite": "traversal_path_selection",
    "evidence_mode": "measured",
    "environment": environment,
    "captured_at_unix": captured_at_unix,
    "git_commit": git_commit,
    "status": "pass",
    "checks": {
        "direct_probe_success": "pass",
        "relay_fallback_success": "pass",
        "direct_failback_success": "pass",
        "multi_peer_snapshot_success": "pass",
    },
    "validated_by_tests": [
        "daemon::tests::daemon_runtime_auto_tunnel_traversal_authority_accepts_multi_peer_snapshot",
        "daemon::tests::daemon_runtime_auto_tunnel_traversal_probe_falls_back_to_relay_without_handshake_evidence",
        "daemon::tests::daemon_runtime_auto_tunnel_traversal_probe_recovers_direct_when_handshake_arrives",
        "phase10::tests::traversal_probe_falls_back_to_relay_when_handshake_does_not_advance",
        "phase10::tests::traversal_probe_promotes_direct_when_handshake_advances",
    ],
    "log_artifacts": [str(path_selection_log)],
}

probe_security_report = {
    "phase": "phase10",
    "suite": "traversal_probe_security",
    "evidence_mode": "measured",
    "environment": environment,
    "captured_at_unix": captured_at_unix,
    "git_commit": git_commit,
    "status": "pass",
    "checks": {
        "replay_rejected": "pass",
        "fail_closed_on_invalid_traversal": "pass",
        "no_unauthorized_endpoint_mutation": "pass",
        "managed_peer_coverage_required": "pass",
        "unmanaged_peer_bundle_rejected": "pass",
        "backend_handshake_evidence_hardened": "pass",
    },
    "validated_by_tests": [
        "daemon::tests::load_traversal_bundle_rejects_tampered_signature_and_replay",
        "daemon::tests::daemon_runtime_netcheck_rejects_forged_traversal_hint_fail_closed",
        "daemon::tests::daemon_runtime_auto_tunnel_traversal_authority_requires_full_peer_coverage",
        "daemon::tests::daemon_runtime_auto_tunnel_traversal_authority_rejects_unmanaged_peer_bundle",
        "daemon::tests::daemon_runtime_auto_tunnel_traversal_runtime_sync_fail_closes_on_missing_peer_coverage",
        "traversal::tests::adversarial_gate_nat_mismatch_blocks_unauthorized_direct_and_keeps_safe_relay_fallback",
        "daemon::tests::traversal_adversarial_gate_rejects_forged_stale_wrong_signer_and_nonce_replay",
        "rustynet-backend-wireguard::tests::latest_handshake_parser_rejects_oversized_or_malformed_output",
        "rustynet-backend-wireguard::tests::linux_backend_reads_latest_handshake_for_configured_peer",
    ],
    "log_artifacts": [str(probe_security_log)],
}

for filename, payload in [
    ("traversal_path_selection_report.json", path_selection_report),
    ("traversal_probe_security_report.json", probe_security_report),
]:
    path = source_dir / filename
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY

echo "Phase 10 HP2 traversal gates: PASS"
