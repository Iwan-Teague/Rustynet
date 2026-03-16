#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

SSH_PASSWORD_FILE=""
SUDO_PASSWORD_FILE=""
CLIENT_HOST=""
EXIT_HOST=""
PROBE_HOST=""
CLIENT_NETWORK_ID=""
EXIT_NETWORK_ID=""
ROGUE_ENDPOINT_IP="${RUSTYNET_ROGUE_ENDPOINT_IP:-203.0.113.44}"
REPORT_PATH="$ROOT_DIR/artifacts/phase10/cross_network_traversal_adversarial_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/cross_network_traversal_adversarial.log"

WORK_DIR=""
ARTIFACT_DIR=""
REPORT_WRITTEN=0
FAILURE_SUMMARY="cross-network traversal adversarial validator did not complete"
CHECK_FORGED_TRAVERSAL_REJECTED="fail"
CHECK_STALE_TRAVERSAL_REJECTED="fail"
CHECK_REPLAYED_TRAVERSAL_REJECTED="fail"
CHECK_ROGUE_ENDPOINT_REJECTED="fail"
CHECK_CONTROL_SURFACE_EXPOSURE_BLOCKED="fail"
SOURCE_ARTIFACTS=()
LOG_ARTIFACTS=()

usage() {
  cat <<'USAGE'
usage: live_linux_cross_network_traversal_adversarial_test.sh --ssh-password-file <path> --sudo-password-file <path> --client-host <user@host> --exit-host <user@host> --probe-host <user@host> --client-network-id <id> --exit-network-id <id> [options]

options:
  --rogue-endpoint-ip <ipv4>
  --report-path <path>
  --log-path <path>
USAGE
}

write_report() {
  local status="$1"
  local args=(
    python3 "$ROOT_DIR/scripts/e2e/generate_cross_network_remote_exit_report.py"
    --suite cross_network_traversal_adversarial
    --report-path "$REPORT_PATH"
    --log-path "$LOG_PATH"
    --status "$status"
    --failure-summary "$FAILURE_SUMMARY"
    --implementation-state live_measured_validator
    --client-host "$CLIENT_HOST"
    --exit-host "$EXIT_HOST"
    --probe-host "$PROBE_HOST"
    --client-network-id "$CLIENT_NETWORK_ID"
    --exit-network-id "$EXIT_NETWORK_ID"
    --source-artifact "$ROOT_DIR/scripts/e2e/live_linux_cross_network_traversal_adversarial_test.sh"
    --check "forged_traversal_rejected=${CHECK_FORGED_TRAVERSAL_REJECTED}"
    --check "stale_traversal_rejected=${CHECK_STALE_TRAVERSAL_REJECTED}"
    --check "replayed_traversal_rejected=${CHECK_REPLAYED_TRAVERSAL_REJECTED}"
    --check "rogue_endpoint_rejected=${CHECK_ROGUE_ENDPOINT_REJECTED}"
    --check "control_surface_exposure_blocked=${CHECK_CONTROL_SURFACE_EXPOSURE_BLOCKED}"
  )
  local item
  for item in "${SOURCE_ARTIFACTS[@]}"; do
    args+=(--source-artifact "$item")
  done
  for item in "${LOG_ARTIFACTS[@]}"; do
    args+=(--log-artifact "$item")
  done
  "${args[@]}"
}

cleanup() {
  local rc=$?
  set +e
  if [[ "$REPORT_WRITTEN" -eq 0 ]]; then
    write_report fail
  fi
  REPORT_WRITTEN=1
  if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
    rm -rf "$WORK_DIR"
  fi
  exit "$rc"
}

trap cleanup EXIT

run_local_test() {
  local log_path="$1"
  local test_name="$2"
  printf '[local-test] RUN %s\n' "$test_name" | tee -a "$log_path"
  ./scripts/ci/run_required_test.sh rustynetd "$test_name" --all-features 2>&1 | tee -a "$log_path"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-password-file) SSH_PASSWORD_FILE="$2"; shift 2 ;;
    --sudo-password-file) SUDO_PASSWORD_FILE="$2"; shift 2 ;;
    --client-host) CLIENT_HOST="$2"; shift 2 ;;
    --exit-host) EXIT_HOST="$2"; shift 2 ;;
    --probe-host) PROBE_HOST="$2"; shift 2 ;;
    --client-network-id) CLIENT_NETWORK_ID="$2"; shift 2 ;;
    --exit-network-id) EXIT_NETWORK_ID="$2"; shift 2 ;;
    --rogue-endpoint-ip) ROGUE_ENDPOINT_IP="$2"; shift 2 ;;
    --report-path) REPORT_PATH="$2"; shift 2 ;;
    --log-path) LOG_PATH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$SSH_PASSWORD_FILE" || -z "$SUDO_PASSWORD_FILE" || -z "$CLIENT_HOST" || -z "$EXIT_HOST" || -z "$PROBE_HOST" || -z "$CLIENT_NETWORK_ID" || -z "$EXIT_NETWORK_ID" ]]; then
  usage >&2
  exit 2
fi

python3 - "$ROGUE_ENDPOINT_IP" <<'PY'
import ipaddress
import sys

ipaddress.IPv4Address(sys.argv[1])
PY

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")"
: > "$LOG_PATH"
exec >> "$LOG_PATH" 2>&1

main() {
  local local_gate_log endpoint_report endpoint_log control_report control_log
  local endpoint_rc control_rc gate_rc

  FAILURE_SUMMARY="preparing traversal adversarial working set"
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rustynet-cross-network-traversal-adversarial.XXXXXX")"
  ARTIFACT_DIR="$(dirname "$REPORT_PATH")"
  local_gate_log="$ARTIFACT_DIR/cross_network_traversal_adversarial_local_tests.log"
  endpoint_report="$ARTIFACT_DIR/cross_network_traversal_adversarial_endpoint_hijack_report.json"
  endpoint_log="$ARTIFACT_DIR/cross_network_traversal_adversarial_endpoint_hijack.log"
  control_report="$ARTIFACT_DIR/cross_network_traversal_adversarial_control_surface_report.json"
  control_log="$ARTIFACT_DIR/cross_network_traversal_adversarial_control_surface.log"
  SOURCE_ARTIFACTS=("$endpoint_report" "$control_report")
  LOG_ARTIFACTS=("$local_gate_log" "$endpoint_log" "$control_log")
  : > "$local_gate_log"

  FAILURE_SUMMARY="running signed traversal tamper and replay regression tests"
  if run_local_test "$local_gate_log" 'daemon::tests::traversal_adversarial_gate_rejects_forged_stale_wrong_signer_and_nonce_replay' && \
     run_local_test "$local_gate_log" 'daemon::tests::load_traversal_bundle_rejects_tampered_signature_and_replay' && \
     run_local_test "$local_gate_log" 'daemon::tests::daemon_runtime_netcheck_rejects_forged_traversal_hint_fail_closed'; then
    gate_rc=0
  else
    gate_rc=$?
  fi
  if [[ "$gate_rc" -eq 0 ]]; then
    CHECK_FORGED_TRAVERSAL_REJECTED="pass"
    CHECK_STALE_TRAVERSAL_REJECTED="pass"
    CHECK_REPLAYED_TRAVERSAL_REJECTED="pass"
  fi

  FAILURE_SUMMARY="running live rogue-endpoint hijack denial test"
  if RUSTYNET_EXPECTED_GIT_COMMIT="${RUSTYNET_EXPECTED_GIT_COMMIT:-}" \
    bash "$ROOT_DIR/scripts/e2e/live_linux_endpoint_hijack_test.sh" \
      --ssh-password-file "$SSH_PASSWORD_FILE" \
      --sudo-password-file "$SUDO_PASSWORD_FILE" \
      --client-host "$CLIENT_HOST" \
      --rogue-endpoint-ip "$ROGUE_ENDPOINT_IP" \
      --report-path "$endpoint_report" \
      --log-path "$endpoint_log"; then
    endpoint_rc=0
  else
    endpoint_rc=$?
  fi
  if [[ "$endpoint_rc" -ne 0 && ! -f "$endpoint_report" ]]; then
    FAILURE_SUMMARY="endpoint hijack validator failed before emitting evidence"
    return 1
  fi
  if python3 - "$endpoint_report" <<'PY'
import json
import sys

payload = json.loads(open(sys.argv[1], encoding="utf-8").read())
checks = payload.get("checks", {})
required = (
    checks.get("hijack_drives_fail_closed") == "pass"
    and checks.get("rogue_endpoint_not_adopted") == "pass"
    and checks.get("recovery_keeps_rogue_endpoint_rejected") == "pass"
)
raise SystemExit(0 if required else 1)
PY
  then
    CHECK_ROGUE_ENDPOINT_REJECTED="pass"
  fi

  FAILURE_SUMMARY="running live control-surface exposure validation"
  if RUSTYNET_EXPECTED_GIT_COMMIT="${RUSTYNET_EXPECTED_GIT_COMMIT:-}" \
    bash "$ROOT_DIR/scripts/e2e/live_linux_control_surface_exposure_test.sh" \
      --ssh-password-file "$SSH_PASSWORD_FILE" \
      --sudo-password-file "$SUDO_PASSWORD_FILE" \
      --exit-host "$EXIT_HOST" \
      --client-host "$CLIENT_HOST" \
      --probe-host "$PROBE_HOST" \
      --report-path "$control_report" \
      --log-path "$control_log"; then
    control_rc=0
  else
    control_rc=$?
  fi
  if [[ "$control_rc" -ne 0 && ! -f "$control_report" ]]; then
    FAILURE_SUMMARY="control-surface exposure validator failed before emitting evidence"
    return 1
  fi
  if python3 - "$control_report" <<'PY'
import json
import sys

payload = json.loads(open(sys.argv[1], encoding="utf-8").read())
checks = payload.get("checks", {})
required = (
    checks.get("all_daemon_sockets_secure") == "pass"
    and checks.get("all_helper_sockets_secure") == "pass"
    and checks.get("no_rustynet_tcp_listeners") == "pass"
    and checks.get("rustynet_udp_loopback_only") == "pass"
    and checks.get("remote_underlay_dns_probe_blocked") == "pass"
)
raise SystemExit(0 if required else 1)
PY
  then
    CHECK_CONTROL_SURFACE_EXPOSURE_BLOCKED="pass"
  fi

  if [[ "$CHECK_FORGED_TRAVERSAL_REJECTED" != 'pass' ]]; then
    FAILURE_SUMMARY="forged/stale/replayed traversal rejection evidence did not pass"
    return 1
  fi
  if [[ "$CHECK_ROGUE_ENDPOINT_REJECTED" != 'pass' ]]; then
    FAILURE_SUMMARY="rogue endpoint hijack denial evidence did not pass"
    return 1
  fi
  if [[ "$CHECK_CONTROL_SURFACE_EXPOSURE_BLOCKED" != 'pass' ]]; then
    FAILURE_SUMMARY="control-surface exposure evidence did not pass"
    return 1
  fi

  FAILURE_SUMMARY=""
}

if main; then
  write_report pass
  REPORT_WRITTEN=1
else
  write_report fail
  REPORT_WRITTEN=1
  exit 1
fi

printf 'cross-network traversal adversarial report written: %s\n' "$REPORT_PATH"
