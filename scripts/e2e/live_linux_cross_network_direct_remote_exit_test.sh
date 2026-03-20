#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/e2e/live_lab_common.sh"

LIVE_LAB_LOG_PREFIX="cross-network-direct-remote-exit"
export LIVE_LAB_LOG_PREFIX

SSH_IDENTITY_FILE=""
CLIENT_HOST=""
EXIT_HOST=""
CLIENT_NODE_ID=""
EXIT_NODE_ID=""
CLIENT_NETWORK_ID=""
EXIT_NETWORK_ID=""
NAT_PROFILE="baseline_lan"
IMPAIRMENT_PROFILE="none"
SSH_ALLOW_CIDRS="192.168.18.0/24"
REPORT_PATH="$ROOT_DIR/artifacts/phase10/cross_network_direct_remote_exit_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/cross_network_direct_remote_exit.log"

REPORT_WRITTEN=0
FAILURE_SUMMARY="cross-network direct remote-exit validator did not complete"
CHECK_DIRECT_REMOTE_EXIT_SUCCESS="fail"
CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK="fail"
CHECK_REMOTE_EXIT_SERVER_IP_BYPASS_IS_NARROW="fail"
CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="fail"
CHECK_CLIENT_EXIT_SELECTED="fail"
CHECK_EXIT_SERVING_ROUTE="fail"
CHECK_CLIENT_ROUTE_VIA_RUSTYNET="fail"
CHECK_EXIT_ENDPOINT_VISIBLE="fail"
CHECK_EXIT_MASQUERADE_PRESENT="fail"
CHECK_NO_PLAINTEXT_PASSPHRASE_FILES="fail"
CLIENT_ADDR=""
EXIT_ADDR=""
BYPASS_REPORT_PATH=""
BYPASS_LOG_PATH=""
CLIENT_STATUS_FILE=""
EXIT_STATUS_FILE=""
CLIENT_INTERNET_ROUTE_FILE=""
CLIENT_ENDPOINTS_FILE=""
EXIT_NFT_FILE=""
CLIENT_PLAINTEXT_FILE=""
EXIT_PLAINTEXT_FILE=""

usage() {
  cat <<'USAGE'
usage: live_linux_cross_network_direct_remote_exit_test.sh --ssh-identity-file <path> --client-host <user@host> --exit-host <user@host> --client-node-id <id> --exit-node-id <id> --client-network-id <id> --exit-network-id <id> [options]

options:
  --nat-profile <profile>
  --impairment-profile <profile>
  --ssh-allow-cidrs <cidr[,cidr]>
  --report-path <path>
  --log-path <path>
USAGE
}

write_report() {
  local status="$1"
  export REPORT_STATUS="$status"
  export REPORT_FAILURE_SUMMARY="$FAILURE_SUMMARY"
  export REPORT_PATH LOG_PATH CLIENT_HOST EXIT_HOST CLIENT_NODE_ID EXIT_NODE_ID
  export CLIENT_NETWORK_ID EXIT_NETWORK_ID CLIENT_ADDR EXIT_ADDR
  export NAT_PROFILE IMPAIRMENT_PROFILE
  export CHECK_DIRECT_REMOTE_EXIT_SUCCESS CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK
  export CHECK_REMOTE_EXIT_SERVER_IP_BYPASS_IS_NARROW CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC
  export CHECK_CLIENT_EXIT_SELECTED CHECK_EXIT_SERVING_ROUTE CHECK_CLIENT_ROUTE_VIA_RUSTYNET
  export CHECK_EXIT_ENDPOINT_VISIBLE CHECK_EXIT_MASQUERADE_PRESENT CHECK_NO_PLAINTEXT_PASSPHRASE_FILES
  export BYPASS_REPORT_PATH BYPASS_LOG_PATH
  export CLIENT_STATUS_FILE EXIT_STATUS_FILE CLIENT_INTERNET_ROUTE_FILE CLIENT_ENDPOINTS_FILE
  export EXIT_NFT_FILE CLIENT_PLAINTEXT_FILE EXIT_PLAINTEXT_FILE ROOT_DIR

  python3 - <<'PY'
from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import time
from pathlib import Path

root_dir = Path(os.environ["ROOT_DIR"]).resolve()
ci_dir = root_dir / "scripts" / "ci"
if str(ci_dir) not in sys.path:
    sys.path.insert(0, str(ci_dir))

from cross_network_remote_exit_schema import validate_report_payload


def env_text(name: str) -> str:
    return os.environ.get(name, "")


def read_text_file(path_raw: str) -> str:
    if not path_raw:
        return ""
    path = Path(path_raw)
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def artifact_list(*items: str) -> list[str]:
    values: list[str] = []
    for item in items:
        if not item:
            continue
        path = Path(item).resolve()
        if path.exists():
            values.append(str(path))
    return values


def current_git_commit() -> str:
    expected = env_text("RUSTYNET_EXPECTED_GIT_COMMIT").strip().lower()
    if expected:
        return expected
    return (
        subprocess.check_output(["git", "rev-parse", "HEAD"], text=True)
        .strip()
        .lower()
    )


def same_underlay_prefix(client_raw: str, exit_raw: str) -> bool:
    if not client_raw or not exit_raw:
        return False
    client_ip = ipaddress.ip_address(client_raw)
    exit_ip = ipaddress.ip_address(exit_raw)
    if client_ip.version != exit_ip.version:
        return False
    prefix = 24 if client_ip.version == 4 else 64
    client_net = ipaddress.ip_network(f"{client_ip}/{prefix}", strict=False)
    exit_net = ipaddress.ip_network(f"{exit_ip}/{prefix}", strict=False)
    return client_net == exit_net


report_path = Path(env_text("REPORT_PATH")).resolve()
report_path.parent.mkdir(parents=True, exist_ok=True)
captured_at_unix = int(time.time())

bypass_payload = {}
bypass_report_path = env_text("BYPASS_REPORT_PATH")
if bypass_report_path and Path(bypass_report_path).is_file():
    bypass_payload = json.loads(Path(bypass_report_path).read_text(encoding="utf-8"))

bypass_checks = bypass_payload.get("checks", {}) if isinstance(bypass_payload, dict) else {}

topology_same_prefix = same_underlay_prefix(env_text("CLIENT_ADDR"), env_text("EXIT_ADDR"))
topology_heuristic = "fail" if topology_same_prefix else env_text("CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC")

checks = {
    "direct_remote_exit_success": env_text("CHECK_DIRECT_REMOTE_EXIT_SUCCESS"),
    "remote_exit_no_underlay_leak": env_text("CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK"),
    "remote_exit_server_ip_bypass_is_narrow": env_text("CHECK_REMOTE_EXIT_SERVER_IP_BYPASS_IS_NARROW"),
    "cross_network_topology_heuristic": topology_heuristic,
    "client_exit_selected": env_text("CHECK_CLIENT_EXIT_SELECTED"),
    "exit_serving_route": env_text("CHECK_EXIT_SERVING_ROUTE"),
    "client_route_via_rustynet0": env_text("CHECK_CLIENT_ROUTE_VIA_RUSTYNET"),
    "exit_endpoint_visible": env_text("CHECK_EXIT_ENDPOINT_VISIBLE"),
    "exit_masquerade_present": env_text("CHECK_EXIT_MASQUERADE_PRESENT"),
    "no_plaintext_passphrase_files": env_text("CHECK_NO_PLAINTEXT_PASSPHRASE_FILES"),
}

status = env_text("REPORT_STATUS")
failure_summary = env_text("REPORT_FAILURE_SUMMARY").strip()
if topology_same_prefix:
    failure_summary = (
        "client and exit underlay addresses share the same local prefix; refusing to "
        "claim cross-network direct remote exit on same-subnet topology"
    )
    status = "fail"
    checks["direct_remote_exit_success"] = "fail"

payload = {
    "schema_version": 1,
    "phase": "phase10",
    "suite": "cross_network_direct_remote_exit",
    "environment": "live_linux_cross_network_direct_remote_exit",
    "evidence_mode": "measured",
    "captured_at_unix": captured_at_unix,
    "git_commit": current_git_commit(),
    "status": status,
    "participants": {
        "client_host": env_text("CLIENT_HOST"),
        "exit_host": env_text("EXIT_HOST"),
    },
    "network_context": {
        "client_network_id": env_text("CLIENT_NETWORK_ID"),
        "exit_network_id": env_text("EXIT_NETWORK_ID"),
        "nat_profile": env_text("NAT_PROFILE"),
        "impairment_profile": env_text("IMPAIRMENT_PROFILE"),
        "client_underlay_ip": env_text("CLIENT_ADDR"),
        "exit_underlay_ip": env_text("EXIT_ADDR"),
    },
    "checks": checks,
    "source_artifacts": artifact_list(
        str((root_dir / "scripts" / "e2e" / "live_linux_cross_network_direct_remote_exit_test.sh").resolve()),
        env_text("BYPASS_REPORT_PATH"),
    ),
    "log_artifacts": artifact_list(
        env_text("LOG_PATH"),
        env_text("BYPASS_LOG_PATH"),
    ),
    "evidence": {
        "client_node_id": env_text("CLIENT_NODE_ID"),
        "exit_node_id": env_text("EXIT_NODE_ID"),
        "same_underlay_prefix_heuristic": topology_same_prefix,
        "topology_heuristic_basis": "shared /24 for IPv4 or shared /64 for IPv6 is not treated as cross-network proof",
        "nat_profile": env_text("NAT_PROFILE"),
        "impairment_profile": env_text("IMPAIRMENT_PROFILE"),
        "client_status": read_text_file(env_text("CLIENT_STATUS_FILE")),
        "exit_status": read_text_file(env_text("EXIT_STATUS_FILE")),
        "client_internet_route": read_text_file(env_text("CLIENT_INTERNET_ROUTE_FILE")),
        "client_endpoints": read_text_file(env_text("CLIENT_ENDPOINTS_FILE")),
        "exit_nft_ruleset_excerpt": read_text_file(env_text("EXIT_NFT_FILE")),
        "client_plaintext_check": read_text_file(env_text("CLIENT_PLAINTEXT_FILE")),
        "exit_plaintext_check": read_text_file(env_text("EXIT_PLAINTEXT_FILE")),
        "server_ip_bypass_report": bypass_payload,
        "server_ip_bypass_checks": bypass_checks,
    },
}
if status == "fail":
    payload["failure_summary"] = failure_summary or "cross-network direct remote-exit validation failed"

problems = validate_report_payload(report_path, payload)
if problems:
    raise SystemExit("\n".join(problems))

report_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
}

cleanup() {
  local rc=$?
  set +e
  if [[ "$REPORT_WRITTEN" -eq 0 ]]; then
    write_report fail
  fi
  REPORT_WRITTEN=1
  live_lab_cleanup
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
    --nat-profile) NAT_PROFILE="$2"; shift 2 ;;
    --impairment-profile) IMPAIRMENT_PROFILE="$2"; shift 2 ;;
    --ssh-allow-cidrs) SSH_ALLOW_CIDRS="$2"; shift 2 ;;
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

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")"
: > "$LOG_PATH"
exec >> "$LOG_PATH" 2>&1

main() {
  local issue_script issue_env assign_pub_local exit_assignment_local client_assignment_local
  local exit_refresh_local client_refresh_local
  local traversal_script traversal_env traversal_pub_local exit_traversal_local client_traversal_local
  local bypass_status client_status exit_status client_internet_route client_endpoints exit_nft
  local client_plaintext_check exit_plaintext_check
  local artifact_dir

  FAILURE_SUMMARY="initializing live-lab runtime"

  live_lab_init "rustynet-cross-network-direct-remote-exit" "$SSH_IDENTITY_FILE"

  issue_script="$LIVE_LAB_WORK_DIR/rn_issue_cross_network_direct.sh"
  issue_env="$LIVE_LAB_WORK_DIR/rn_issue_cross_network_direct.env"
  assign_pub_local="$LIVE_LAB_WORK_DIR/assignment.pub"
  exit_assignment_local="$LIVE_LAB_WORK_DIR/assignment-exit"
  client_assignment_local="$LIVE_LAB_WORK_DIR/assignment-client"
  exit_refresh_local="$LIVE_LAB_WORK_DIR/assignment-refresh-exit.env"
  client_refresh_local="$LIVE_LAB_WORK_DIR/assignment-refresh-client.env"
  traversal_script="$LIVE_LAB_WORK_DIR/rn_issue_cross_network_direct_traversal.sh"
  traversal_env="$LIVE_LAB_WORK_DIR/rn_issue_cross_network_direct_traversal.env"
  traversal_pub_local="$LIVE_LAB_WORK_DIR/traversal.pub"
  exit_traversal_local="$LIVE_LAB_WORK_DIR/traversal-exit"
  client_traversal_local="$LIVE_LAB_WORK_DIR/traversal-client"
  artifact_dir="$(dirname "$REPORT_PATH")"
  BYPASS_REPORT_PATH="$artifact_dir/cross_network_direct_remote_exit_server_ip_bypass_report.json"
  BYPASS_LOG_PATH="$artifact_dir/cross_network_direct_remote_exit_server_ip_bypass.log"
  CLIENT_STATUS_FILE="$LIVE_LAB_WORK_DIR/client_status.txt"
  EXIT_STATUS_FILE="$LIVE_LAB_WORK_DIR/exit_status.txt"
  CLIENT_INTERNET_ROUTE_FILE="$LIVE_LAB_WORK_DIR/client_internet_route.txt"
  CLIENT_ENDPOINTS_FILE="$LIVE_LAB_WORK_DIR/client_endpoints.txt"
  EXIT_NFT_FILE="$LIVE_LAB_WORK_DIR/exit_nft.txt"
  CLIENT_PLAINTEXT_FILE="$LIVE_LAB_WORK_DIR/client_plaintext_check.txt"
  EXIT_PLAINTEXT_FILE="$LIVE_LAB_WORK_DIR/exit_plaintext_check.txt"

  live_lab_push_sudo_password "$EXIT_HOST"
  live_lab_push_sudo_password "$CLIENT_HOST"

  live_lab_log "Collecting WireGuard public keys"
  EXIT_PUB_HEX="$(live_lab_collect_pubkey_hex "$EXIT_HOST")"
  CLIENT_PUB_HEX="$(live_lab_collect_pubkey_hex "$CLIENT_HOST")"
  EXIT_ADDR="$(live_lab_target_address "$EXIT_HOST")"
  CLIENT_ADDR="$(live_lab_target_address "$CLIENT_HOST")"

  NODES_SPEC="${EXIT_NODE_ID}|${EXIT_ADDR}:51820|${EXIT_PUB_HEX};${CLIENT_NODE_ID}|${CLIENT_ADDR}:51820|${CLIENT_PUB_HEX}"
  ALLOW_SPEC="${CLIENT_NODE_ID}|${EXIT_NODE_ID};${EXIT_NODE_ID}|${CLIENT_NODE_ID}"

  cat > "$issue_script" <<'ISSUEEOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: rn_issue_cross_network_direct.sh <env-file>" >&2
  exit 2
fi

source "$1"

root() {
  sudo -n "$@"
}

PASS_FILE="$(mktemp /tmp/rn-cross-network-direct-passphrase.XXXXXX)"
cleanup() {
  if [[ -f "$PASS_FILE" ]]; then
    root rustynet ops secure-remove --path "$PASS_FILE" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

root rustynet ops materialize-signing-passphrase --output "$PASS_FILE"
root chmod 0600 "$PASS_FILE"

ISSUE_DIR="/run/rustynet/assignment-issue"
root rm -rf "$ISSUE_DIR"
root install -d -m 0700 "$ISSUE_DIR"

issue_bundle() {
  local target_node_id="$1"
  local output_name="$2"
  shift 2
  root rustynet assignment issue \
    --target-node-id "$target_node_id" \
    --nodes "$NODES_SPEC" \
    --allow "$ALLOW_SPEC" \
    --signing-secret /etc/rustynet/assignment.signing.secret \
    --signing-secret-passphrase-file "$PASS_FILE" \
    --output "$ISSUE_DIR/$output_name" \
    --verifier-key-output "$ISSUE_DIR/rn-assignment.pub" \
    "$@" \
    --ttl-secs 300
}

issue_bundle "$EXIT_NODE_ID" "rn-assignment-$EXIT_NODE_ID.assignment"
issue_bundle "$CLIENT_NODE_ID" "rn-assignment-$CLIENT_NODE_ID.assignment" --exit-node-id "$EXIT_NODE_ID"
ISSUEEOF
  chmod 700 "$issue_script"

  cat > "$traversal_script" <<'TRAVEOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: rn_issue_cross_network_direct_traversal.sh <env-file>" >&2
  exit 2
fi

source "$1"

root() {
  sudo -n "$@"
}

PASS_FILE="$(mktemp /tmp/rn-cross-network-direct-traversal-passphrase.XXXXXX)"
cleanup() {
  if [[ -f "$PASS_FILE" ]]; then
    root rustynet ops secure-remove --path "$PASS_FILE" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

root rustynet ops materialize-signing-passphrase --output "$PASS_FILE"
root chmod 0600 "$PASS_FILE"

ISSUE_DIR="/run/rustynet/traversal-issue"
root rm -rf "$ISSUE_DIR"
root install -d -m 0700 "$ISSUE_DIR"
SNAPSHOT_GENERATED_AT="$(date +%s)"
SNAPSHOT_NONCE="$((SNAPSHOT_GENERATED_AT * 1000 + 1))"

declare -a node_ids=()
declare -A endpoint_by_node=()
OLD_IFS="$IFS"
IFS=';'
set -- $NODES_SPEC
IFS="$OLD_IFS"
for entry in "$@"; do
  [[ -n "$entry" ]] || continue
  IFS='|' read -r node_id endpoint _rest <<< "$entry"
  [[ -n "$node_id" && -n "$endpoint" ]] || continue
  node_ids+=("$node_id")
  endpoint_by_node["$node_id"]="$endpoint"
done

issue_pair_bundle() {
  local source_node_id="$1"
  local target_node_id="$2"
  local target_endpoint="${endpoint_by_node[$target_node_id]}"
  local relay_id="relay-${target_node_id}"
  local output_name="rn-traversal-${source_node_id}-${target_node_id}.bundle"
  root rustynet traversal issue \
    --source-node-id "$source_node_id" \
    --target-node-id "$target_node_id" \
    --nodes "$NODES_SPEC" \
    --allow "$ALLOW_SPEC" \
    --signing-secret /etc/rustynet/assignment.signing.secret \
    --signing-secret-passphrase-file "$PASS_FILE" \
    --candidates "host|${target_endpoint}|900;relay|${target_endpoint}|700|${relay_id}" \
    --generated-at "$SNAPSHOT_GENERATED_AT" \
    --nonce "$SNAPSHOT_NONCE" \
    --output "$ISSUE_DIR/$output_name" \
    --verifier-key-output "$ISSUE_DIR/rn-traversal.pub" \
    --ttl-secs 120
}

declare -a allow_sources=()
declare -a allow_targets=()
OLD_IFS="$IFS"
IFS=';'
set -- $ALLOW_SPEC
IFS="$OLD_IFS"
for entry in "$@"; do
  [[ -n "$entry" ]] || continue
  IFS='|' read -r source_node_id target_node_id <<< "$entry"
  [[ -n "$source_node_id" && -n "$target_node_id" ]] || continue
  if [[ -z "${endpoint_by_node[$target_node_id]:-}" ]]; then
    echo "target node ${target_node_id} from ALLOW_SPEC is missing in NODES_SPEC" >&2
    exit 1
  fi
  issue_pair_bundle "$source_node_id" "$target_node_id"
  allow_sources+=("$source_node_id")
  allow_targets+=("$target_node_id")
done

for node_id in "${node_ids[@]}"; do
  aggregate_path="$ISSUE_DIR/rn-traversal-${node_id}.traversal"
  root rm -f "$aggregate_path"
  root sh -c ': > "$1"' sh "$aggregate_path"
  for idx in "${!allow_sources[@]}"; do
    source_node_id="${allow_sources[$idx]}"
    target_node_id="${allow_targets[$idx]}"
    if [[ "$source_node_id" == "$node_id" ]]; then
      pair_path="$ISSUE_DIR/rn-traversal-${source_node_id}-${target_node_id}.bundle"
      root sh -c 'cat "$1" >> "$2"' sh "$pair_path" "$aggregate_path"
      root sh -c 'printf "\n" >> "$1"' sh "$aggregate_path"
    fi
  done
done
TRAVEOF
  chmod 700 "$traversal_script"

  : > "$issue_env"
  live_lab_append_env_assignment "$issue_env" "EXIT_NODE_ID" "$EXIT_NODE_ID"
  live_lab_append_env_assignment "$issue_env" "CLIENT_NODE_ID" "$CLIENT_NODE_ID"
  live_lab_append_env_assignment "$issue_env" "NODES_SPEC" "$NODES_SPEC"
  live_lab_append_env_assignment "$issue_env" "ALLOW_SPEC" "$ALLOW_SPEC"

  live_lab_log "Issuing signed direct remote-exit assignments on $EXIT_HOST"
  live_lab_scp_to "$issue_script" "$EXIT_HOST" "/tmp/rn_issue_cross_network_direct.sh"
  live_lab_scp_to "$issue_env" "$EXIT_HOST" "/tmp/rn_issue_cross_network_direct.env"
  live_lab_run_root "$EXIT_HOST" "root chmod 700 /tmp/rn_issue_cross_network_direct.sh && root bash /tmp/rn_issue_cross_network_direct.sh /tmp/rn_issue_cross_network_direct.env"
  live_lab_run_root "$EXIT_HOST" "root rm -f /tmp/rn_issue_cross_network_direct.sh /tmp/rn_issue_cross_network_direct.env"

  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment.pub" > "$assign_pub_local"
  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$EXIT_NODE_ID.assignment" > "$exit_assignment_local"
  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$CLIENT_NODE_ID.assignment" > "$client_assignment_local"

  live_lab_log "Distributing signed assignments"
  live_lab_install_assignment_bundle "$EXIT_HOST" "$assign_pub_local" "$exit_assignment_local"
  live_lab_install_assignment_bundle "$CLIENT_HOST" "$assign_pub_local" "$client_assignment_local"

  live_lab_write_assignment_refresh_env "$exit_refresh_local" "$EXIT_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC"
  live_lab_write_assignment_refresh_env "$client_refresh_local" "$CLIENT_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC" "$EXIT_NODE_ID"
  live_lab_install_assignment_refresh_env "$EXIT_HOST" "$exit_refresh_local"
  live_lab_install_assignment_refresh_env "$CLIENT_HOST" "$client_refresh_local"

  : > "$traversal_env"
  live_lab_append_env_assignment "$traversal_env" "NODES_SPEC" "$NODES_SPEC"
  live_lab_append_env_assignment "$traversal_env" "ALLOW_SPEC" "$ALLOW_SPEC"

  live_lab_log "Issuing signed traversal bundles for direct remote-exit topology"
  live_lab_scp_to "$traversal_script" "$EXIT_HOST" "/tmp/rn_issue_cross_network_direct_traversal.sh"
  live_lab_scp_to "$traversal_env" "$EXIT_HOST" "/tmp/rn_issue_cross_network_direct_traversal.env"
  live_lab_run_root "$EXIT_HOST" "root chmod 700 /tmp/rn_issue_cross_network_direct_traversal.sh && root bash /tmp/rn_issue_cross_network_direct_traversal.sh /tmp/rn_issue_cross_network_direct_traversal.env"
  live_lab_run_root "$EXIT_HOST" "root rm -f /tmp/rn_issue_cross_network_direct_traversal.sh /tmp/rn_issue_cross_network_direct_traversal.env"

  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/traversal-issue/rn-traversal.pub" > "$traversal_pub_local"
  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/traversal-issue/rn-traversal-$EXIT_NODE_ID.traversal" > "$exit_traversal_local"
  live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/traversal-issue/rn-traversal-$CLIENT_NODE_ID.traversal" > "$client_traversal_local"

  install_traversal_bundle() {
    local host="$1"
    local bundle_local="$2"
    live_lab_scp_to "$traversal_pub_local" "$host" "/tmp/rn-traversal.pub"
    live_lab_scp_to "$bundle_local" "$host" "/tmp/rn-traversal.bundle"
    live_lab_run_root "$host" "root install -m 0644 -o root -g root /tmp/rn-traversal.pub /etc/rustynet/traversal.pub && root install -m 0640 -o root -g rustynetd /tmp/rn-traversal.bundle /var/lib/rustynet/rustynetd.traversal && root rm -f /var/lib/rustynet/rustynetd.traversal.watermark /tmp/rn-traversal.pub /tmp/rn-traversal.bundle"
  }

  live_lab_log "Distributing signed traversal bundles"
  install_traversal_bundle "$EXIT_HOST" "$exit_traversal_local"
  install_traversal_bundle "$CLIENT_HOST" "$client_traversal_local"

  live_lab_log "Enforcing runtime roles"
  live_lab_enforce_host "$EXIT_HOST" "admin" "$EXIT_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$EXIT_HOST")"
  live_lab_enforce_host "$CLIENT_HOST" "client" "$CLIENT_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$CLIENT_HOST")"
  live_lab_wait_for_daemon_socket "$EXIT_HOST"
  live_lab_wait_for_daemon_socket "$CLIENT_HOST"

  live_lab_log "Advertising default route on remote exit"
  live_lab_retry_root "$EXIT_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 0.0.0.0/0" 10 2
  sleep 5

  FAILURE_SUMMARY="capturing direct remote-exit steady-state evidence"
  client_status="$(live_lab_status "$CLIENT_HOST")"
  exit_status="$(live_lab_status "$EXIT_HOST")"
  client_internet_route="$(live_lab_capture "$CLIENT_HOST" "ip -4 route get 1.1.1.1 || true")"
  client_endpoints="$(live_lab_capture_root "$CLIENT_HOST" "root wg show rustynet0 endpoints || true")"
  exit_nft="$(live_lab_capture_root "$EXIT_HOST" "root nft list ruleset || true")"
  client_plaintext_check="$(live_lab_no_plaintext_passphrase_check "$CLIENT_HOST")"
  exit_plaintext_check="$(live_lab_no_plaintext_passphrase_check "$EXIT_HOST")"

  printf '%s\n' "$client_status" > "$CLIENT_STATUS_FILE"
  printf '%s\n' "$exit_status" > "$EXIT_STATUS_FILE"
  printf '%s\n' "$client_internet_route" > "$CLIENT_INTERNET_ROUTE_FILE"
  printf '%s\n' "$client_endpoints" > "$CLIENT_ENDPOINTS_FILE"
  printf '%s\n' "$exit_nft" > "$EXIT_NFT_FILE"
  printf '%s\n' "$client_plaintext_check" > "$CLIENT_PLAINTEXT_FILE"
  printf '%s\n' "$exit_plaintext_check" > "$EXIT_PLAINTEXT_FILE"

  live_lab_log "Client status"
  printf '%s\n' "$client_status"
  live_lab_log "Exit status"
  printf '%s\n' "$exit_status"
  live_lab_log "Client route to internet"
  printf '%s\n' "$client_internet_route"
  live_lab_log "Client endpoints"
  printf '%s\n' "$client_endpoints"

  if grep -Fq "exit_node=${EXIT_NODE_ID}" <<<"$client_status" && grep -Fq 'state=ExitActive' <<<"$client_status"; then
    CHECK_CLIENT_EXIT_SELECTED="pass"
  fi
  if grep -Fq 'serving_exit_node=true' <<<"$exit_status"; then
    CHECK_EXIT_SERVING_ROUTE="pass"
  fi
  if grep -Fq 'dev rustynet0' <<<"$client_internet_route"; then
    CHECK_CLIENT_ROUTE_VIA_RUSTYNET="pass"
  fi
  if grep -Fq "${EXIT_ADDR}:51820" <<<"$client_endpoints"; then
    CHECK_EXIT_ENDPOINT_VISIBLE="pass"
  fi
  if grep -Fq 'masquerade' <<<"$exit_nft"; then
    CHECK_EXIT_MASQUERADE_PRESENT="pass"
  fi
  if [[ "$client_plaintext_check" == 'no-plaintext-passphrase-files' && "$exit_plaintext_check" == 'no-plaintext-passphrase-files' ]]; then
    CHECK_NO_PLAINTEXT_PASSPHRASE_FILES="pass"
  fi

  if python3 - "$CLIENT_ADDR" "$EXIT_ADDR" <<'PY'
import ipaddress
import sys

client_ip = ipaddress.ip_address(sys.argv[1])
exit_ip = ipaddress.ip_address(sys.argv[2])
prefix = 24 if client_ip.version == 4 else 64
client_net = ipaddress.ip_network(f"{client_ip}/{prefix}", strict=False)
exit_net = ipaddress.ip_network(f"{exit_ip}/{prefix}", strict=False)
raise SystemExit(1 if client_net == exit_net else 0)
PY
  then
    CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="pass"
  else
    CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC="fail"
  fi

  if [[ "$CHECK_CLIENT_EXIT_SELECTED" == 'pass' && "$CHECK_EXIT_SERVING_ROUTE" == 'pass' && "$CHECK_CLIENT_ROUTE_VIA_RUSTYNET" == 'pass' && "$CHECK_EXIT_ENDPOINT_VISIBLE" == 'pass' && "$CHECK_EXIT_MASQUERADE_PRESENT" == 'pass' && "$CHECK_NO_PLAINTEXT_PASSPHRASE_FILES" == 'pass' && "$CHECK_CROSS_NETWORK_TOPOLOGY_HEURISTIC" == 'pass' ]]; then
    CHECK_DIRECT_REMOTE_EXIT_SUCCESS="pass"
  fi

  FAILURE_SUMMARY="validating narrow server-IP bypass and leak resistance on direct remote-exit path"
  if RUSTYNET_EXPECTED_GIT_COMMIT="${RUSTYNET_EXPECTED_GIT_COMMIT:-}" \
    bash "$ROOT_DIR/scripts/e2e/live_linux_server_ip_bypass_test.sh" \
      --ssh-identity-file "$SSH_IDENTITY_FILE" \
      --client-host "$CLIENT_HOST" \
      --probe-host "$EXIT_HOST" \
      --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
      --report-path "$BYPASS_REPORT_PATH" \
      --log-path "$BYPASS_LOG_PATH"; then
    bypass_status=0
  else
    bypass_status=$?
  fi

  if [[ "$bypass_status" -ne 0 && ! -f "$BYPASS_REPORT_PATH" ]]; then
    FAILURE_SUMMARY="server-IP bypass validator failed before emitting evidence"
    return 1
  fi

  mapfile -t bypass_results < <(python3 - "$BYPASS_REPORT_PATH" <<'PY'
import json
import sys

payload = json.loads(open(sys.argv[1], encoding="utf-8").read())
checks = payload.get("checks", {})
print(checks.get("internet_route_via_rustynet0", "fail"))
print(checks.get("probe_service_blocked_from_client", "fail"))
print(checks.get("probe_endpoint_route_direct_not_tunnelled", "fail"))
print(checks.get("no_unexpected_bypass_routes", "fail"))
print(payload.get("status", "fail"))
PY
)

  if [[ "${bypass_results[0]}" == 'pass' && "${bypass_results[1]}" == 'pass' ]]; then
    CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK="pass"
  fi
  if [[ "${bypass_results[1]}" == 'pass' && "${bypass_results[2]}" == 'pass' && "${bypass_results[3]}" == 'pass' ]]; then
    CHECK_REMOTE_EXIT_SERVER_IP_BYPASS_IS_NARROW="pass"
  fi

  if [[ "$CHECK_DIRECT_REMOTE_EXIT_SUCCESS" != 'pass' ]]; then
    FAILURE_SUMMARY="direct remote-exit steady-state checks did not all pass"
    return 1
  fi
  if [[ "$CHECK_REMOTE_EXIT_NO_UNDERLAY_LEAK" != 'pass' ]]; then
    FAILURE_SUMMARY="direct remote-exit path leaked or could not prove leak resistance"
    return 1
  fi
  if [[ "$CHECK_REMOTE_EXIT_SERVER_IP_BYPASS_IS_NARROW" != 'pass' ]]; then
    FAILURE_SUMMARY="server-IP bypass on the direct remote-exit path was broader than allowed"
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

live_lab_log "Cross-network direct remote-exit report written: $REPORT_PATH"
