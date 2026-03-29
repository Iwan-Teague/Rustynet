#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

SSH_IDENTITY_FILE=""
CLIENT_HOST=""
EXIT_HOST=""
CLIENT_NODE_ID=""
EXIT_NODE_ID=""
CLIENT_NETWORK_ID=""
EXIT_NETWORK_ID=""
CLIENT_UNDERLAY_IP="${RUSTYNET_CLIENT_UNDERLAY_IP:-}"
EXIT_UNDERLAY_IP="${RUSTYNET_EXIT_UNDERLAY_IP:-}"
NAT_PROFILE="baseline_lan"
IMPAIRMENT_PROFILE="none"
SSH_ALLOW_CIDRS="192.168.18.0/24"
ZONE_NAME="rustynet"
DNS_INTERFACE="rustynet0"
DNS_BIND_ADDR="127.0.0.1:53535"
REPORT_PATH="$ROOT_DIR/artifacts/phase10/cross_network_remote_exit_dns_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/cross_network_remote_exit_dns.log"

REPORT_WRITTEN=0
FAILURE_SUMMARY="cross-network remote-exit DNS validator did not complete"
CHECK_MANAGED_DNS_RESOLUTION_SUCCESS="fail"
CHECK_REMOTE_EXIT_DNS_FAIL_CLOSED="fail"
CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK="fail"
CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="fail"
CHECK_DIRECT_REMOTE_EXIT_READY="fail"
CHECK_MANAGED_DNS_CHILD_READY="fail"
DIRECT_REPORT_PATH=""
DIRECT_LOG_PATH=""
MANAGED_DNS_REPORT_PATH=""
MANAGED_DNS_LOG_PATH=""
SOURCE_ARTIFACTS=()
LOG_ARTIFACTS=()

usage() {
  cat <<'USAGE'
usage: live_linux_cross_network_remote_exit_dns_test.sh --ssh-identity-file <path> --client-host <user@host> --exit-host <user@host> --client-node-id <id> --exit-node-id <id> --client-network-id <id> --exit-network-id <id> [options]

options:
  --nat-profile <profile>
  --impairment-profile <profile>
  --ssh-allow-cidrs <cidr[,cidr]>
  --client-underlay-ip <ipv4>
  --exit-underlay-ip <ipv4>
  --zone-name <name>
  --dns-interface <name>
  --dns-bind-addr <ip:port>
  --report-path <path>
  --log-path <path>
USAGE
}

write_report() {
  local status="$1"
  local args=(
    cargo run --quiet -p rustynet-cli -- ops generate-cross-network-remote-exit-report
    --suite cross_network_remote_exit_dns
    --report-path "$REPORT_PATH"
    --log-path "$LOG_PATH"
    --status "$status"
    --failure-summary "$FAILURE_SUMMARY"
    --implementation-state live_measured_validator
    --environment live_linux_cross_network_remote_exit_dns
    --client-host "$CLIENT_HOST"
    --exit-host "$EXIT_HOST"
    --client-network-id "$CLIENT_NETWORK_ID"
    --exit-network-id "$EXIT_NETWORK_ID"
    --nat-profile "$NAT_PROFILE"
    --impairment-profile "$IMPAIRMENT_PROFILE"
    --source-artifact "$ROOT_DIR/scripts/e2e/live_linux_cross_network_remote_exit_dns_test.sh"
    --check "managed_dns_resolution_success=${CHECK_MANAGED_DNS_RESOLUTION_SUCCESS}"
    --check "remote_exit_dns_fail_closed=${CHECK_REMOTE_EXIT_DNS_FAIL_CLOSED}"
    --check "remote_exit_no_underlay_leak=${CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK}"
    --check "cross_network_topology_heuristic=${CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC}"
    --check "direct_remote_exit_ready=${CHECK_DIRECT_REMOTE_EXIT_READY}"
    --check "managed_dns_child_ready=${CHECK_MANAGED_DNS_CHILD_READY}"
  )
  local item
  set +u
  if [[ -n "$DIRECT_REPORT_PATH" ]]; then
    args+=(--path-evidence-report "$DIRECT_REPORT_PATH")
  fi
  for item in "${SOURCE_ARTIFACTS[@]}"; do
    [[ -n "$item" ]] || continue
    args+=(--source-artifact "$item")
  done
  for item in "${LOG_ARTIFACTS[@]}"; do
    [[ -n "$item" ]] || continue
    args+=(--log-artifact "$item")
  done
  set -u
  "${args[@]}"
}

cleanup() {
  local rc=$?
  set +e
  if [[ "$REPORT_WRITTEN" -eq 0 ]]; then
    write_report fail
  fi
  REPORT_WRITTEN=1
  exit "$rc"
}

trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-identity-file) SSH_IDENTITY_FILE="$2"; shift 2 ;;
    --client-host) CLIENT_HOST="$2"; shift 2 ;;
    --exit-host) EXIT_HOST="$2"; shift 2 ;;
    --client-node-id) CLIENT_NODE_ID="$2"; shift 2 ;;
    --exit-node-id) EXIT_NODE_ID="$2"; shift 2 ;;
    --client-network-id) CLIENT_NETWORK_ID="$2"; shift 2 ;;
    --exit-network-id) EXIT_NETWORK_ID="$2"; shift 2 ;;
    --client-underlay-ip) CLIENT_UNDERLAY_IP="$2"; shift 2 ;;
    --exit-underlay-ip) EXIT_UNDERLAY_IP="$2"; shift 2 ;;
    --nat-profile) NAT_PROFILE="$2"; shift 2 ;;
    --impairment-profile) IMPAIRMENT_PROFILE="$2"; shift 2 ;;
    --ssh-allow-cidrs) SSH_ALLOW_CIDRS="$2"; shift 2 ;;
    --zone-name) ZONE_NAME="$2"; shift 2 ;;
    --dns-interface) DNS_INTERFACE="$2"; shift 2 ;;
    --dns-bind-addr) DNS_BIND_ADDR="$2"; shift 2 ;;
    --report-path) REPORT_PATH="$2"; shift 2 ;;
    --log-path) LOG_PATH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$SSH_IDENTITY_FILE" || -z "$CLIENT_HOST" || -z "$EXIT_HOST" || -z "$CLIENT_NODE_ID" || -z "$EXIT_NODE_ID" || -z "$CLIENT_NETWORK_ID" || -z "$EXIT_NETWORK_ID" ]]; then
  usage >&2
  exit 2
fi
if [[ -z "$NAT_PROFILE" || -z "$IMPAIRMENT_PROFILE" ]]; then
  echo "--nat-profile and --impairment-profile must be non-empty" >&2
  exit 2
fi

if [[ "$CLIENT_HOST" == "$EXIT_HOST" ]]; then
  echo "--client-host and --exit-host must differ" >&2
  exit 2
fi

if [[ "$CLIENT_NETWORK_ID" == "$EXIT_NETWORK_ID" ]]; then
  echo "--client-network-id and --exit-network-id must differ" >&2
  exit 2
fi

if [[ -n "$CLIENT_UNDERLAY_IP" ]]; then
  cargo run --quiet -p rustynet-cli -- ops validate-ipv4-address --ip "$CLIENT_UNDERLAY_IP" >/dev/null
fi
if [[ -n "$EXIT_UNDERLAY_IP" ]]; then
  cargo run --quiet -p rustynet-cli -- ops validate-ipv4-address --ip "$EXIT_UNDERLAY_IP" >/dev/null
fi

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")"
: > "$LOG_PATH"
exec >> "$LOG_PATH" 2>&1

main() {
  local artifact_dir
  local direct_rc managed_rc

  artifact_dir="$(dirname "$REPORT_PATH")"
  DIRECT_REPORT_PATH="$artifact_dir/cross_network_remote_exit_dns_direct_remote_exit_report.json"
  DIRECT_LOG_PATH="$artifact_dir/cross_network_remote_exit_dns_direct_remote_exit.log"
  MANAGED_DNS_REPORT_PATH="$artifact_dir/cross_network_remote_exit_dns_managed_dns_report.json"
  MANAGED_DNS_LOG_PATH="$artifact_dir/cross_network_remote_exit_dns_managed_dns.log"
  SOURCE_ARTIFACTS=("$DIRECT_REPORT_PATH" "$MANAGED_DNS_REPORT_PATH")
  LOG_ARTIFACTS=("$DIRECT_LOG_PATH" "$MANAGED_DNS_LOG_PATH")

  FAILURE_SUMMARY="bootstrapping direct remote-exit path for DNS validation"
  if RUSTYNET_EXPECTED_GIT_COMMIT="${RUSTYNET_EXPECTED_GIT_COMMIT:-}" \
    bash "$ROOT_DIR/scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh" \
      --ssh-identity-file "$SSH_IDENTITY_FILE" \
      --client-host "$CLIENT_HOST" \
      --exit-host "$EXIT_HOST" \
      --client-node-id "$CLIENT_NODE_ID" \
      --exit-node-id "$EXIT_NODE_ID" \
      --client-network-id "$CLIENT_NETWORK_ID" \
      --exit-network-id "$EXIT_NETWORK_ID" \
      --client-underlay-ip "${CLIENT_UNDERLAY_IP:-}" \
      --exit-underlay-ip "${EXIT_UNDERLAY_IP:-}" \
      --nat-profile "$NAT_PROFILE" \
      --impairment-profile "$IMPAIRMENT_PROFILE" \
      --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
      --report-path "$DIRECT_REPORT_PATH" \
      --log-path "$DIRECT_LOG_PATH"; then
    direct_rc=0
  else
    direct_rc=$?
  fi

  if [[ ! -f "$DIRECT_REPORT_PATH" ]]; then
    FAILURE_SUMMARY="direct remote-exit child validator failed before emitting evidence"
    return 1
  fi

  mapfile -t direct_results < <(
    cargo run --quiet -p rustynet-cli -- ops read-cross-network-report-fields \
      --report-path "$DIRECT_REPORT_PATH" \
      --include-status \
      --check direct_remote_exit_success \
      --check remote_exit_no_underlay_leak \
      --check cross_network_topology_heuristic
  ) || return 1

  if [[ "${direct_results[0]}" == 'pass' && "${direct_results[1]}" == 'pass' ]]; then
    CHECK_DIRECT_REMOTE_EXIT_READY="pass"
  fi
  if [[ "${direct_results[2]}" == 'pass' ]]; then
    CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK="pass"
  fi
  if [[ "${direct_results[3]}" == 'pass' ]]; then
    CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="pass"
  fi

  if [[ "$direct_rc" -ne 0 || "$CHECK_DIRECT_REMOTE_EXIT_READY" != 'pass' ]]; then
    FAILURE_SUMMARY="direct remote-exit child validator did not prove a secure cross-network remote-exit path"
    return 1
  fi

  FAILURE_SUMMARY="running managed DNS validation on the remote-exit client"
  if RUSTYNET_EXPECTED_GIT_COMMIT="${RUSTYNET_EXPECTED_GIT_COMMIT:-}" \
    bash "$ROOT_DIR/scripts/e2e/live_linux_managed_dns_test.sh" \
      --ssh-identity-file "$SSH_IDENTITY_FILE" \
      --signer-host "$EXIT_HOST" \
      --client-host "$CLIENT_HOST" \
      --signer-node-id "$EXIT_NODE_ID" \
      --client-node-id "$CLIENT_NODE_ID" \
      --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
      --zone-name "$ZONE_NAME" \
      --dns-interface "$DNS_INTERFACE" \
      --dns-bind-addr "$DNS_BIND_ADDR" \
      --report-path "$MANAGED_DNS_REPORT_PATH" \
      --log-path "$MANAGED_DNS_LOG_PATH"; then
    managed_rc=0
  else
    managed_rc=$?
  fi

  if [[ ! -f "$MANAGED_DNS_REPORT_PATH" ]]; then
    FAILURE_SUMMARY="managed DNS child validator failed before emitting evidence"
    return 1
  fi

  mapfile -t managed_results < <(
    cargo run --quiet -p rustynet-cli -- ops read-cross-network-report-fields \
      --report-path "$MANAGED_DNS_REPORT_PATH" \
      --include-status \
      --check dns_inspect_valid \
      --check managed_dns_service_active \
      --check resolvectl_split_dns_configured \
      --check loopback_resolver_answers_managed_name \
      --check systemd_resolved_answers_managed_name \
      --check alias_resolves_to_expected_ip \
      --check non_managed_query_refused \
      --check stale_bundle_fail_closed \
      --check valid_bundle_restored
  ) || return 1

  if [[ "${managed_results[0]}" == 'pass' ]]; then
    CHECK_MANAGED_DNS_CHILD_READY="pass"
  fi
  if [[ "${managed_results[1]}" == 'pass' && "${managed_results[2]}" == 'pass' && "${managed_results[3]}" == 'pass' && "${managed_results[4]}" == 'pass' && "${managed_results[5]}" == 'pass' && "${managed_results[6]}" == 'pass' ]]; then
    CHECK_MANAGED_DNS_RESOLUTION_SUCCESS="pass"
  fi
  if [[ "${managed_results[7]}" == 'pass' && "${managed_results[8]}" == 'pass' && "${managed_results[9]}" == 'pass' ]]; then
    CHECK_REMOTE_EXIT_DNS_FAIL_CLOSED="pass"
  fi

  if [[ "$managed_rc" -ne 0 || "$CHECK_MANAGED_DNS_CHILD_READY" != 'pass' ]]; then
    FAILURE_SUMMARY="managed DNS child validator did not produce a passing managed DNS runtime"
    return 1
  fi
  if [[ "$CHECK_MANAGED_DNS_RESOLUTION_SUCCESS" != 'pass' ]]; then
    FAILURE_SUMMARY="managed DNS did not resolve securely on the remote-exit client"
    return 1
  fi
  if [[ "$CHECK_REMOTE_EXIT_DNS_FAIL_CLOSED" != 'pass' ]]; then
    FAILURE_SUMMARY="managed DNS did not fail closed under stale or unauthorized queries on the remote-exit client"
    return 1
  fi
  if [[ "$CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK" != 'pass' ]]; then
    FAILURE_SUMMARY="remote-exit DNS path could not prove underlay leak resistance"
    return 1
  fi
  if [[ "$CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC" != 'pass' ]]; then
    FAILURE_SUMMARY="client and exit underlay topology did not credibly prove a cross-network claim"
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

printf 'cross-network remote-exit DNS report written: %s\n' "$REPORT_PATH"
