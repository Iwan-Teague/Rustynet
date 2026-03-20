#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/e2e/live_lab_common.sh"

LIVE_LAB_LOG_PREFIX="lan-toggle"
export LIVE_LAB_LOG_PREFIX

EXIT_HOST="debian@192.168.18.49"
CLIENT_HOST="debian@192.168.18.65"
BLIND_EXIT_HOST="fedora@192.168.18.51"
EXIT_NODE_ID="exit-49"
CLIENT_NODE_ID="client-65"
BLIND_EXIT_NODE_ID="client-51"
SSH_ALLOW_CIDRS="192.168.18.0/24"
SSH_IDENTITY_FILE=""
REPORT_PATH="$ROOT_DIR/artifacts/phase10/live_linux_lan_toggle_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/live_linux_lan_toggle.log"
LAN_TEST_INTERFACE="rnlan0"
LAN_TEST_GATEWAY_IP="192.168.1.1/24"
LAN_TEST_PROBE_IP="192.168.1.1"
LAN_TEST_CIDR="192.168.1.0/24"

usage() {
  cat <<USAGE
usage: $0 --ssh-identity-file <path> [options]

options:
  --exit-host <user@host>
  --client-host <user@host>
  --blind-exit-host <user@host>
  --exit-node-id <id>
  --client-node-id <id>
  --blind-exit-node-id <id>
  --ssh-allow-cidrs <cidrs>
  --report-path <path>
  --log-path <path>
USAGE
}

wait_for_lan_probe_state() {
  local target="$1"
  local desired_state="$2"
  local attempts="${3:-15}"
  local attempt
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    if live_lab_ssh "$target" "ping -c 1 -W 1 ${LAN_TEST_PROBE_IP} >/dev/null 2>&1" 20; then
      if [[ "$desired_state" == "reachable" ]]; then
        return 0
      fi
    else
      if [[ "$desired_state" == "blocked" ]]; then
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-identity-file) SSH_IDENTITY_FILE="$2"; shift 2 ;;
    --exit-host) EXIT_HOST="$2"; shift 2 ;;
    --client-host) CLIENT_HOST="$2"; shift 2 ;;
    --blind-exit-host) BLIND_EXIT_HOST="$2"; shift 2 ;;
    --exit-node-id) EXIT_NODE_ID="$2"; shift 2 ;;
    --client-node-id) CLIENT_NODE_ID="$2"; shift 2 ;;
    --blind-exit-node-id) BLIND_EXIT_NODE_ID="$2"; shift 2 ;;
    --ssh-allow-cidrs) SSH_ALLOW_CIDRS="$2"; shift 2 ;;
    --report-path) REPORT_PATH="$2"; shift 2 ;;
    --log-path) LOG_PATH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$SSH_IDENTITY_FILE" ]]; then
  usage >&2
  exit 2
fi

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")"
exec > >(tee "$LOG_PATH") 2>&1

live_lab_init "rustynet-lan-toggle" "$SSH_IDENTITY_FILE"
cleanup_all() {
  if [[ -n "${EXIT_HOST:-}" ]]; then
    live_lab_run_root "$EXIT_HOST" "root ip link delete ${LAN_TEST_INTERFACE}" >/dev/null 2>&1 || true
  fi
  live_lab_cleanup
}
trap 'cleanup_all' EXIT

ISSUE_SCRIPT="$LIVE_LAB_WORK_DIR/rn_issue_lan.sh"
ISSUE_ENV="$LIVE_LAB_WORK_DIR/rn_issue_lan.env"
ASSIGN_PUB_LOCAL="$LIVE_LAB_WORK_DIR/assignment.pub"
EXIT_ASSIGNMENT_LOCAL="$LIVE_LAB_WORK_DIR/assignment-exit"
CLIENT_ASSIGNMENT_LOCAL="$LIVE_LAB_WORK_DIR/assignment-client"
BLIND_EXIT_ASSIGNMENT_LOCAL="$LIVE_LAB_WORK_DIR/assignment-blind-exit"
EXIT_REFRESH_LOCAL="$LIVE_LAB_WORK_DIR/assignment-refresh-exit.env"
CLIENT_REFRESH_LOCAL="$LIVE_LAB_WORK_DIR/assignment-refresh-client.env"
BLIND_EXIT_REFRESH_LOCAL="$LIVE_LAB_WORK_DIR/assignment-refresh-blind-exit.env"
TRAVERSAL_SCRIPT="$LIVE_LAB_WORK_DIR/rn_issue_lan_traversal.sh"
TRAVERSAL_ENV="$LIVE_LAB_WORK_DIR/rn_issue_lan_traversal.env"
TRAVERSAL_PUB_LOCAL="$LIVE_LAB_WORK_DIR/traversal.pub"
EXIT_TRAVERSAL_LOCAL="$LIVE_LAB_WORK_DIR/traversal-exit"
CLIENT_TRAVERSAL_LOCAL="$LIVE_LAB_WORK_DIR/traversal-client"
BLIND_EXIT_TRAVERSAL_LOCAL="$LIVE_LAB_WORK_DIR/traversal-blind-exit"

for host in "$EXIT_HOST" "$CLIENT_HOST" "$BLIND_EXIT_HOST"; do
  live_lab_push_sudo_password "$host"
done

live_lab_log "Collecting WireGuard public keys"
EXIT_PUB_HEX="$(live_lab_collect_pubkey_hex "$EXIT_HOST")"
CLIENT_PUB_HEX="$(live_lab_collect_pubkey_hex "$CLIENT_HOST")"
BLIND_EXIT_PUB_HEX="$(live_lab_collect_pubkey_hex "$BLIND_EXIT_HOST")"

EXIT_ADDR="$(live_lab_target_address "$EXIT_HOST")"
CLIENT_ADDR="$(live_lab_target_address "$CLIENT_HOST")"
BLIND_EXIT_ADDR="$(live_lab_target_address "$BLIND_EXIT_HOST")"

NODES_SPEC="${EXIT_NODE_ID}|${EXIT_ADDR}:51820|${EXIT_PUB_HEX};${CLIENT_NODE_ID}|${CLIENT_ADDR}:51820|${CLIENT_PUB_HEX};${BLIND_EXIT_NODE_ID}|${BLIND_EXIT_ADDR}:51820|${BLIND_EXIT_PUB_HEX}"
ALLOW_SPEC="${CLIENT_NODE_ID}|${EXIT_NODE_ID};${EXIT_NODE_ID}|${CLIENT_NODE_ID};${BLIND_EXIT_NODE_ID}|${EXIT_NODE_ID};${EXIT_NODE_ID}|${BLIND_EXIT_NODE_ID}"

cat > "$ISSUE_SCRIPT" <<'ISSUEEOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: rn_issue_lan.sh <env-file>" >&2
  exit 2
fi

source "$1"

root() {
  sudo -n "$@"
}

PASS_FILE="$(mktemp /tmp/rn-lan-passphrase.XXXXXX)"
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
issue_bundle "$BLIND_EXIT_NODE_ID" "rn-assignment-$BLIND_EXIT_NODE_ID.assignment"
ISSUEEOF
chmod 700 "$ISSUE_SCRIPT"

cat > "$TRAVERSAL_SCRIPT" <<'TRAVEOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: rn_issue_lan_traversal.sh <env-file>" >&2
  exit 2
fi

source "$1"

root() {
  sudo -n "$@"
}

PASS_FILE="$(mktemp /tmp/rn-lan-traversal-passphrase.XXXXXX)"
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
chmod 700 "$TRAVERSAL_SCRIPT"

: > "$ISSUE_ENV"
live_lab_append_env_assignment "$ISSUE_ENV" "EXIT_NODE_ID" "$EXIT_NODE_ID"
live_lab_append_env_assignment "$ISSUE_ENV" "CLIENT_NODE_ID" "$CLIENT_NODE_ID"
live_lab_append_env_assignment "$ISSUE_ENV" "BLIND_EXIT_NODE_ID" "$BLIND_EXIT_NODE_ID"
live_lab_append_env_assignment "$ISSUE_ENV" "NODES_SPEC" "$NODES_SPEC"
live_lab_append_env_assignment "$ISSUE_ENV" "ALLOW_SPEC" "$ALLOW_SPEC"
live_lab_append_env_assignment "$ISSUE_ENV" "LAN_TEST_CIDR" "$LAN_TEST_CIDR"

live_lab_log "Issuing signed LAN-toggle assignments on $EXIT_HOST"
live_lab_scp_to "$ISSUE_SCRIPT" "$EXIT_HOST" "/tmp/rn_issue_lan.sh"
live_lab_scp_to "$ISSUE_ENV" "$EXIT_HOST" "/tmp/rn_issue_lan.env"
live_lab_run_root "$EXIT_HOST" "root chmod 700 /tmp/rn_issue_lan.sh && root bash /tmp/rn_issue_lan.sh /tmp/rn_issue_lan.env"
live_lab_run_root "$EXIT_HOST" "root rm -f /tmp/rn_issue_lan.sh /tmp/rn_issue_lan.env"

live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment.pub" > "$ASSIGN_PUB_LOCAL"
live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$EXIT_NODE_ID.assignment" > "$EXIT_ASSIGNMENT_LOCAL"
live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$CLIENT_NODE_ID.assignment" > "$CLIENT_ASSIGNMENT_LOCAL"
live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$BLIND_EXIT_NODE_ID.assignment" > "$BLIND_EXIT_ASSIGNMENT_LOCAL"

live_lab_log "Distributing signed assignments"
live_lab_install_assignment_bundle "$EXIT_HOST" "$ASSIGN_PUB_LOCAL" "$EXIT_ASSIGNMENT_LOCAL"
live_lab_install_assignment_bundle "$CLIENT_HOST" "$ASSIGN_PUB_LOCAL" "$CLIENT_ASSIGNMENT_LOCAL"
live_lab_install_assignment_bundle "$BLIND_EXIT_HOST" "$ASSIGN_PUB_LOCAL" "$BLIND_EXIT_ASSIGNMENT_LOCAL"

live_lab_write_assignment_refresh_env "$EXIT_REFRESH_LOCAL" "$EXIT_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC"
live_lab_write_assignment_refresh_env "$CLIENT_REFRESH_LOCAL" "$CLIENT_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC" "$EXIT_NODE_ID"
live_lab_write_assignment_refresh_env "$BLIND_EXIT_REFRESH_LOCAL" "$BLIND_EXIT_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC"

live_lab_install_assignment_refresh_env "$EXIT_HOST" "$EXIT_REFRESH_LOCAL"
live_lab_install_assignment_refresh_env "$CLIENT_HOST" "$CLIENT_REFRESH_LOCAL"
live_lab_install_assignment_refresh_env "$BLIND_EXIT_HOST" "$BLIND_EXIT_REFRESH_LOCAL"

: > "$TRAVERSAL_ENV"
live_lab_append_env_assignment "$TRAVERSAL_ENV" "NODES_SPEC" "$NODES_SPEC"
live_lab_append_env_assignment "$TRAVERSAL_ENV" "ALLOW_SPEC" "$ALLOW_SPEC"

live_lab_log "Issuing signed traversal bundles for LAN-toggle topology"
live_lab_scp_to "$TRAVERSAL_SCRIPT" "$EXIT_HOST" "/tmp/rn_issue_lan_traversal.sh"
live_lab_scp_to "$TRAVERSAL_ENV" "$EXIT_HOST" "/tmp/rn_issue_lan_traversal.env"
live_lab_run_root "$EXIT_HOST" "root chmod 700 /tmp/rn_issue_lan_traversal.sh && root bash /tmp/rn_issue_lan_traversal.sh /tmp/rn_issue_lan_traversal.env"
live_lab_run_root "$EXIT_HOST" "root rm -f /tmp/rn_issue_lan_traversal.sh /tmp/rn_issue_lan_traversal.env"

live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/traversal-issue/rn-traversal.pub" > "$TRAVERSAL_PUB_LOCAL"
live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/traversal-issue/rn-traversal-$EXIT_NODE_ID.traversal" > "$EXIT_TRAVERSAL_LOCAL"
live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/traversal-issue/rn-traversal-$CLIENT_NODE_ID.traversal" > "$CLIENT_TRAVERSAL_LOCAL"
live_lab_capture_root "$EXIT_HOST" "root cat /run/rustynet/traversal-issue/rn-traversal-$BLIND_EXIT_NODE_ID.traversal" > "$BLIND_EXIT_TRAVERSAL_LOCAL"

install_traversal_bundle() {
  local host="$1"
  local bundle_local="$2"
  live_lab_scp_to "$TRAVERSAL_PUB_LOCAL" "$host" "/tmp/rn-traversal.pub"
  live_lab_scp_to "$bundle_local" "$host" "/tmp/rn-traversal.bundle"
  live_lab_run_root "$host" "root install -m 0644 -o root -g root /tmp/rn-traversal.pub /etc/rustynet/traversal.pub && root install -m 0640 -o root -g rustynetd /tmp/rn-traversal.bundle /var/lib/rustynet/rustynetd.traversal && root rm -f /var/lib/rustynet/rustynetd.traversal.watermark /tmp/rn-traversal.pub /tmp/rn-traversal.bundle"
}

live_lab_log "Distributing signed traversal bundles"
install_traversal_bundle "$EXIT_HOST" "$EXIT_TRAVERSAL_LOCAL"
install_traversal_bundle "$CLIENT_HOST" "$CLIENT_TRAVERSAL_LOCAL"
install_traversal_bundle "$BLIND_EXIT_HOST" "$BLIND_EXIT_TRAVERSAL_LOCAL"

live_lab_log "Enforcing runtime roles"
live_lab_enforce_host "$EXIT_HOST" "admin" "$EXIT_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$EXIT_HOST")"
live_lab_enforce_host "$CLIENT_HOST" "client" "$CLIENT_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$CLIENT_HOST")"
live_lab_enforce_host "$BLIND_EXIT_HOST" "blind_exit" "$BLIND_EXIT_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$BLIND_EXIT_HOST")"
live_lab_wait_for_daemon_socket "$EXIT_HOST"
live_lab_wait_for_daemon_socket "$CLIENT_HOST"
live_lab_wait_for_daemon_socket "$BLIND_EXIT_HOST"

live_lab_log "Advertising default route on exit"
live_lab_retry_root "$EXIT_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 0.0.0.0/0" 10 2

live_lab_log "Provisioning synthetic LAN subnet on exit"
live_lab_run_root "$EXIT_HOST" "root ip link add ${LAN_TEST_INTERFACE} type dummy >/dev/null 2>&1 || true && root ip addr replace ${LAN_TEST_GATEWAY_IP} dev ${LAN_TEST_INTERFACE} && root ip link set ${LAN_TEST_INTERFACE} up"

sleep 5

CLIENT_STATUS_OFF_INITIAL="$(live_lab_status "$CLIENT_HOST")"
live_lab_log "Initial client status"
printf '%s\n' "$CLIENT_STATUS_OFF_INITIAL"

live_lab_apply_lan_access_coupling "$CLIENT_HOST" "false" "$LAN_TEST_CIDR"
sleep 3
if wait_for_lan_probe_state "$CLIENT_HOST" "blocked" 15; then
  lan_off_ping_status="pass"
else
  lan_off_ping_status="fail"
fi
CLIENT_STATUS_OFF="$(live_lab_status "$CLIENT_HOST")"

live_lab_apply_lan_access_coupling "$CLIENT_HOST" "true" "$LAN_TEST_CIDR"
sleep 5
if wait_for_lan_probe_state "$CLIENT_HOST" "reachable" 15; then
  lan_on_ping_status="pass"
else
  lan_on_ping_status="fail"
fi
CLIENT_STATUS_ON="$(live_lab_status "$CLIENT_HOST")"
CLIENT_ROUTE_ON="$(live_lab_capture "$CLIENT_HOST" "ip -4 route get ${LAN_TEST_PROBE_IP} || true")"

live_lab_apply_lan_access_coupling "$CLIENT_HOST" "false" "$LAN_TEST_CIDR"
sleep 3
if wait_for_lan_probe_state "$CLIENT_HOST" "blocked" 15; then
  lan_off_again_status="pass"
else
  lan_off_again_status="fail"
fi
CLIENT_STATUS_OFF_FINAL="$(live_lab_status "$CLIENT_HOST")"

if live_lab_apply_lan_access_coupling "$BLIND_EXIT_HOST" "true" "$LAN_TEST_CIDR"; then
  blind_exit_denied_status="fail"
else
  blind_exit_denied_status="pass"
fi
BLIND_EXIT_STATUS="$(live_lab_status "$BLIND_EXIT_HOST")"

CLIENT_PLAINTEXT_CHECK="$(live_lab_no_plaintext_passphrase_check "$CLIENT_HOST")"
EXIT_PLAINTEXT_CHECK="$(live_lab_no_plaintext_passphrase_check "$EXIT_HOST")"
BLIND_EXIT_PLAINTEXT_CHECK="$(live_lab_no_plaintext_passphrase_check "$BLIND_EXIT_HOST")"

live_lab_log "Client status after LAN on"
printf '%s\n' "$CLIENT_STATUS_ON"
live_lab_log "Client route to LAN probe after LAN on"
printf '%s\n' "$CLIENT_ROUTE_ON"
live_lab_log "Client status after LAN off"
printf '%s\n' "$CLIENT_STATUS_OFF_FINAL"
live_lab_log "Blind exit status"
printf '%s\n' "$BLIND_EXIT_STATUS"

check_lan_off_blocks="fail"
check_lan_on_allows="fail"
check_lan_off_again_blocks="fail"
check_client_status_initial_off="fail"
check_client_status_on="fail"
check_client_status_off="fail"
check_blind_exit_denied="fail"
check_no_plaintext_passphrases="fail"

if [[ "$lan_off_ping_status" == 'pass' ]]; then
  check_lan_off_blocks="pass"
fi
if [[ "$lan_on_ping_status" == 'pass' ]] && grep -Fq 'lan_access=on' <<<"$CLIENT_STATUS_ON" && grep -Fq 'dev rustynet0' <<<"$CLIENT_ROUTE_ON"; then
  check_lan_on_allows="pass"
fi
if [[ "$lan_off_again_status" == 'pass' ]]; then
  check_lan_off_again_blocks="pass"
fi
if grep -Fq 'lan_access=off' <<<"$CLIENT_STATUS_OFF_INITIAL" && grep -Fq "exit_node=${EXIT_NODE_ID}" <<<"$CLIENT_STATUS_OFF_INITIAL"; then
  check_client_status_initial_off="pass"
fi
if grep -Fq 'lan_access=on' <<<"$CLIENT_STATUS_ON"; then
  check_client_status_on="pass"
fi
if grep -Fq 'lan_access=off' <<<"$CLIENT_STATUS_OFF_FINAL"; then
  check_client_status_off="pass"
fi
if [[ "$blind_exit_denied_status" == 'pass' ]] && grep -Fq 'node_role=blind_exit' <<<"$BLIND_EXIT_STATUS" && grep -Fq 'lan_access=off' <<<"$BLIND_EXIT_STATUS"; then
  check_blind_exit_denied="pass"
fi
if [[ "$CLIENT_PLAINTEXT_CHECK" == 'no-plaintext-passphrase-files' && "$EXIT_PLAINTEXT_CHECK" == 'no-plaintext-passphrase-files' && "$BLIND_EXIT_PLAINTEXT_CHECK" == 'no-plaintext-passphrase-files' ]]; then
  check_no_plaintext_passphrases="pass"
fi

overall="pass"
for value in \
  "$check_lan_off_blocks" \
  "$check_lan_on_allows" \
  "$check_lan_off_again_blocks" \
  "$check_client_status_initial_off" \
  "$check_client_status_on" \
  "$check_client_status_off" \
  "$check_blind_exit_denied" \
  "$check_no_plaintext_passphrases"; do
  if [[ "$value" != 'pass' ]]; then
    overall="fail"
    break
  fi
done

captured_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
captured_at_unix="$(date -u +%s)"
git_commit="${RUSTYNET_EXPECTED_GIT_COMMIT:-$(git rev-parse HEAD)}"
git_commit="$(printf '%s' "$git_commit" | tr '[:upper:]' '[:lower:]')"
cat > "$REPORT_PATH" <<EOF_REPORT
{
  "phase": "phase10",
  "mode": "live_linux_lan_toggle",
  "evidence_mode": "measured",
  "captured_at": "${captured_at_utc}",
  "captured_at_unix": ${captured_at_unix},
  "git_commit": "${git_commit}",
  "status": "${overall}",
  "exit_host": "${EXIT_HOST}",
  "client_host": "${CLIENT_HOST}",
  "blind_exit_host": "${BLIND_EXIT_HOST}",
  "checks": {
    "lan_off_blocks": "${check_lan_off_blocks}",
    "lan_on_allows": "${check_lan_on_allows}",
    "lan_off_again_blocks": "${check_lan_off_again_blocks}",
    "client_status_initial_off": "${check_client_status_initial_off}",
    "client_status_on": "${check_client_status_on}",
    "client_status_off": "${check_client_status_off}",
    "blind_exit_denied": "${check_blind_exit_denied}",
    "no_plaintext_passphrase_files": "${check_no_plaintext_passphrases}"
  },
  "source_artifacts": [
    "${LOG_PATH}"
  ]
}
EOF_REPORT

live_lab_log "LAN toggle report written: $REPORT_PATH"
if [[ "$overall" != 'pass' ]]; then
  exit 1
fi
