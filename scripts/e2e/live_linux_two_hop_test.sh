#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/e2e/live_lab_common.sh"

LIVE_LAB_LOG_PREFIX="two-hop-live"
export LIVE_LAB_LOG_PREFIX

FINAL_EXIT_HOST="debian@192.168.18.49"
CLIENT_HOST="debian@192.168.18.65"
ENTRY_HOST="ubuntu@192.168.18.52"
SECOND_CLIENT_HOST="fedora@192.168.18.51"
FINAL_EXIT_NODE_ID="exit-49"
CLIENT_NODE_ID="client-65"
ENTRY_NODE_ID="client-52"
SECOND_CLIENT_NODE_ID="client-51"
SSH_ALLOW_CIDRS="192.168.18.0/24"
SSH_PASSWORD_FILE=""
SUDO_PASSWORD_FILE=""
REPORT_PATH="$ROOT_DIR/artifacts/phase10/live_linux_two_hop_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/live_linux_two_hop.log"

usage() {
  cat <<USAGE
usage: $0 --ssh-password-file <path> --sudo-password-file <path> [options]

options:
  --final-exit-host <user@host>
  --client-host <user@host>
  --entry-host <user@host>
  --second-client-host <user@host>
  --final-exit-node-id <id>
  --client-node-id <id>
  --entry-node-id <id>
  --second-client-node-id <id>
  --ssh-allow-cidrs <cidrs>
  --report-path <path>
  --log-path <path>
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-password-file) SSH_PASSWORD_FILE="$2"; shift 2 ;;
    --sudo-password-file) SUDO_PASSWORD_FILE="$2"; shift 2 ;;
    --final-exit-host) FINAL_EXIT_HOST="$2"; shift 2 ;;
    --client-host) CLIENT_HOST="$2"; shift 2 ;;
    --entry-host) ENTRY_HOST="$2"; shift 2 ;;
    --second-client-host) SECOND_CLIENT_HOST="$2"; shift 2 ;;
    --final-exit-node-id) FINAL_EXIT_NODE_ID="$2"; shift 2 ;;
    --client-node-id) CLIENT_NODE_ID="$2"; shift 2 ;;
    --entry-node-id) ENTRY_NODE_ID="$2"; shift 2 ;;
    --second-client-node-id) SECOND_CLIENT_NODE_ID="$2"; shift 2 ;;
    --ssh-allow-cidrs) SSH_ALLOW_CIDRS="$2"; shift 2 ;;
    --report-path) REPORT_PATH="$2"; shift 2 ;;
    --log-path) LOG_PATH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$SSH_PASSWORD_FILE" || -z "$SUDO_PASSWORD_FILE" ]]; then
  usage >&2
  exit 2
fi

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")"
exec > >(tee "$LOG_PATH") 2>&1

live_lab_init "rustynet-two-hop-live" "$SSH_PASSWORD_FILE" "$SUDO_PASSWORD_FILE"
trap 'live_lab_cleanup' EXIT

ISSUE_SCRIPT="$LIVE_LAB_WORK_DIR/rn_issue_twohop.sh"
ISSUE_ENV="$LIVE_LAB_WORK_DIR/rn_issue_twohop.env"
ASSIGN_PUB_LOCAL="$LIVE_LAB_WORK_DIR/assignment.pub"
FINAL_EXIT_ASSIGNMENT_LOCAL="$LIVE_LAB_WORK_DIR/assignment-final-exit"
CLIENT_ASSIGNMENT_LOCAL="$LIVE_LAB_WORK_DIR/assignment-client"
ENTRY_ASSIGNMENT_LOCAL="$LIVE_LAB_WORK_DIR/assignment-entry"
SECOND_CLIENT_ASSIGNMENT_LOCAL="$LIVE_LAB_WORK_DIR/assignment-second-client"
FINAL_EXIT_REFRESH_LOCAL="$LIVE_LAB_WORK_DIR/assignment-refresh-final-exit.env"
CLIENT_REFRESH_LOCAL="$LIVE_LAB_WORK_DIR/assignment-refresh-client.env"
ENTRY_REFRESH_LOCAL="$LIVE_LAB_WORK_DIR/assignment-refresh-entry.env"
SECOND_CLIENT_REFRESH_LOCAL="$LIVE_LAB_WORK_DIR/assignment-refresh-second-client.env"
TRAVERSAL_SCRIPT="$LIVE_LAB_WORK_DIR/rn_issue_twohop_traversal.sh"
TRAVERSAL_ENV="$LIVE_LAB_WORK_DIR/rn_issue_twohop_traversal.env"
TRAVERSAL_PUB_LOCAL="$LIVE_LAB_WORK_DIR/traversal.pub"
FINAL_EXIT_TRAVERSAL_LOCAL="$LIVE_LAB_WORK_DIR/traversal-final-exit"
CLIENT_TRAVERSAL_LOCAL="$LIVE_LAB_WORK_DIR/traversal-client"
ENTRY_TRAVERSAL_LOCAL="$LIVE_LAB_WORK_DIR/traversal-entry"
SECOND_CLIENT_TRAVERSAL_LOCAL="$LIVE_LAB_WORK_DIR/traversal-second-client"

for host in "$FINAL_EXIT_HOST" "$CLIENT_HOST" "$ENTRY_HOST" "$SECOND_CLIENT_HOST"; do
  live_lab_push_sudo_password "$host"
done

live_lab_log "Collecting WireGuard public keys"
FINAL_EXIT_PUB_HEX="$(live_lab_collect_pubkey_hex "$FINAL_EXIT_HOST")"
CLIENT_PUB_HEX="$(live_lab_collect_pubkey_hex "$CLIENT_HOST")"
ENTRY_PUB_HEX="$(live_lab_collect_pubkey_hex "$ENTRY_HOST")"
SECOND_CLIENT_PUB_HEX="$(live_lab_collect_pubkey_hex "$SECOND_CLIENT_HOST")"

FINAL_EXIT_ADDR="$(live_lab_target_address "$FINAL_EXIT_HOST")"
CLIENT_ADDR="$(live_lab_target_address "$CLIENT_HOST")"
ENTRY_ADDR="$(live_lab_target_address "$ENTRY_HOST")"
SECOND_CLIENT_ADDR="$(live_lab_target_address "$SECOND_CLIENT_HOST")"

NODES_SPEC="${FINAL_EXIT_NODE_ID}|${FINAL_EXIT_ADDR}:51820|${FINAL_EXIT_PUB_HEX};${CLIENT_NODE_ID}|${CLIENT_ADDR}:51820|${CLIENT_PUB_HEX};${ENTRY_NODE_ID}|${ENTRY_ADDR}:51820|${ENTRY_PUB_HEX};${SECOND_CLIENT_NODE_ID}|${SECOND_CLIENT_ADDR}:51820|${SECOND_CLIENT_PUB_HEX}"
ALLOW_SPEC="${CLIENT_NODE_ID}|${ENTRY_NODE_ID};${ENTRY_NODE_ID}|${CLIENT_NODE_ID};${CLIENT_NODE_ID}|${FINAL_EXIT_NODE_ID};${FINAL_EXIT_NODE_ID}|${CLIENT_NODE_ID};${ENTRY_NODE_ID}|${FINAL_EXIT_NODE_ID};${FINAL_EXIT_NODE_ID}|${ENTRY_NODE_ID};${SECOND_CLIENT_NODE_ID}|${FINAL_EXIT_NODE_ID};${FINAL_EXIT_NODE_ID}|${SECOND_CLIENT_NODE_ID}"

cat > "$ISSUE_SCRIPT" <<'ISSUEEOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: rn_issue_twohop.sh <env-file>" >&2
  exit 2
fi

source "$1"

root() {
  sudo -S -p '' "$@" < /tmp/rn_sudo.pass
}

PASS_FILE="$(mktemp /tmp/rn-twohop-passphrase.XXXXXX)"
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

issue_bundle "$FINAL_EXIT_NODE_ID" "rn-assignment-$FINAL_EXIT_NODE_ID.assignment"
issue_bundle "$CLIENT_NODE_ID" "rn-assignment-$CLIENT_NODE_ID.assignment" --exit-node-id "$ENTRY_NODE_ID"
issue_bundle "$ENTRY_NODE_ID" "rn-assignment-$ENTRY_NODE_ID.assignment" --exit-node-id "$FINAL_EXIT_NODE_ID"
issue_bundle "$SECOND_CLIENT_NODE_ID" "rn-assignment-$SECOND_CLIENT_NODE_ID.assignment" --exit-node-id "$FINAL_EXIT_NODE_ID"
ISSUEEOF
chmod 700 "$ISSUE_SCRIPT"

cat > "$TRAVERSAL_SCRIPT" <<'TRAVEOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: rn_issue_twohop_traversal.sh <env-file>" >&2
  exit 2
fi

source "$1"

root() {
  sudo -S -p '' "$@" < /tmp/rn_sudo.pass
}

PASS_FILE="$(mktemp /tmp/rn-twohop-traversal-passphrase.XXXXXX)"
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
live_lab_append_env_assignment "$ISSUE_ENV" "FINAL_EXIT_NODE_ID" "$FINAL_EXIT_NODE_ID"
live_lab_append_env_assignment "$ISSUE_ENV" "CLIENT_NODE_ID" "$CLIENT_NODE_ID"
live_lab_append_env_assignment "$ISSUE_ENV" "ENTRY_NODE_ID" "$ENTRY_NODE_ID"
live_lab_append_env_assignment "$ISSUE_ENV" "SECOND_CLIENT_NODE_ID" "$SECOND_CLIENT_NODE_ID"
live_lab_append_env_assignment "$ISSUE_ENV" "NODES_SPEC" "$NODES_SPEC"
live_lab_append_env_assignment "$ISSUE_ENV" "ALLOW_SPEC" "$ALLOW_SPEC"

live_lab_log "Issuing signed two-hop assignments on $FINAL_EXIT_HOST"
live_lab_scp_to "$ISSUE_SCRIPT" "$FINAL_EXIT_HOST" "/tmp/rn_issue_twohop.sh"
live_lab_scp_to "$ISSUE_ENV" "$FINAL_EXIT_HOST" "/tmp/rn_issue_twohop.env"
live_lab_run_root "$FINAL_EXIT_HOST" "root chmod 700 /tmp/rn_issue_twohop.sh && root bash /tmp/rn_issue_twohop.sh /tmp/rn_issue_twohop.env"
live_lab_run_root "$FINAL_EXIT_HOST" "root rm -f /tmp/rn_issue_twohop.sh /tmp/rn_issue_twohop.env"

live_lab_capture_root "$FINAL_EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment.pub" > "$ASSIGN_PUB_LOCAL"
live_lab_capture_root "$FINAL_EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$FINAL_EXIT_NODE_ID.assignment" > "$FINAL_EXIT_ASSIGNMENT_LOCAL"
live_lab_capture_root "$FINAL_EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$CLIENT_NODE_ID.assignment" > "$CLIENT_ASSIGNMENT_LOCAL"
live_lab_capture_root "$FINAL_EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$ENTRY_NODE_ID.assignment" > "$ENTRY_ASSIGNMENT_LOCAL"
live_lab_capture_root "$FINAL_EXIT_HOST" "root cat /run/rustynet/assignment-issue/rn-assignment-$SECOND_CLIENT_NODE_ID.assignment" > "$SECOND_CLIENT_ASSIGNMENT_LOCAL"

live_lab_log "Distributing signed assignments"
live_lab_install_assignment_bundle "$FINAL_EXIT_HOST" "$ASSIGN_PUB_LOCAL" "$FINAL_EXIT_ASSIGNMENT_LOCAL"
live_lab_install_assignment_bundle "$CLIENT_HOST" "$ASSIGN_PUB_LOCAL" "$CLIENT_ASSIGNMENT_LOCAL"
live_lab_install_assignment_bundle "$ENTRY_HOST" "$ASSIGN_PUB_LOCAL" "$ENTRY_ASSIGNMENT_LOCAL"
live_lab_install_assignment_bundle "$SECOND_CLIENT_HOST" "$ASSIGN_PUB_LOCAL" "$SECOND_CLIENT_ASSIGNMENT_LOCAL"

live_lab_write_assignment_refresh_env "$FINAL_EXIT_REFRESH_LOCAL" "$FINAL_EXIT_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC"
live_lab_write_assignment_refresh_env "$CLIENT_REFRESH_LOCAL" "$CLIENT_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC" "$ENTRY_NODE_ID"
live_lab_write_assignment_refresh_env "$ENTRY_REFRESH_LOCAL" "$ENTRY_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC" "$FINAL_EXIT_NODE_ID"
live_lab_write_assignment_refresh_env "$SECOND_CLIENT_REFRESH_LOCAL" "$SECOND_CLIENT_NODE_ID" "$NODES_SPEC" "$ALLOW_SPEC" "$FINAL_EXIT_NODE_ID"

live_lab_install_assignment_refresh_env "$FINAL_EXIT_HOST" "$FINAL_EXIT_REFRESH_LOCAL"
live_lab_install_assignment_refresh_env "$CLIENT_HOST" "$CLIENT_REFRESH_LOCAL"
live_lab_install_assignment_refresh_env "$ENTRY_HOST" "$ENTRY_REFRESH_LOCAL"
live_lab_install_assignment_refresh_env "$SECOND_CLIENT_HOST" "$SECOND_CLIENT_REFRESH_LOCAL"

: > "$TRAVERSAL_ENV"
live_lab_append_env_assignment "$TRAVERSAL_ENV" "NODES_SPEC" "$NODES_SPEC"
live_lab_append_env_assignment "$TRAVERSAL_ENV" "ALLOW_SPEC" "$ALLOW_SPEC"

live_lab_log "Issuing signed traversal bundles for two-hop topology"
live_lab_scp_to "$TRAVERSAL_SCRIPT" "$FINAL_EXIT_HOST" "/tmp/rn_issue_twohop_traversal.sh"
live_lab_scp_to "$TRAVERSAL_ENV" "$FINAL_EXIT_HOST" "/tmp/rn_issue_twohop_traversal.env"
live_lab_run_root "$FINAL_EXIT_HOST" "root chmod 700 /tmp/rn_issue_twohop_traversal.sh && root bash /tmp/rn_issue_twohop_traversal.sh /tmp/rn_issue_twohop_traversal.env"
live_lab_run_root "$FINAL_EXIT_HOST" "root rm -f /tmp/rn_issue_twohop_traversal.sh /tmp/rn_issue_twohop_traversal.env"

live_lab_capture_root "$FINAL_EXIT_HOST" "root cat /run/rustynet/traversal-issue/rn-traversal.pub" > "$TRAVERSAL_PUB_LOCAL"
live_lab_capture_root "$FINAL_EXIT_HOST" "root cat /run/rustynet/traversal-issue/rn-traversal-$FINAL_EXIT_NODE_ID.traversal" > "$FINAL_EXIT_TRAVERSAL_LOCAL"
live_lab_capture_root "$FINAL_EXIT_HOST" "root cat /run/rustynet/traversal-issue/rn-traversal-$CLIENT_NODE_ID.traversal" > "$CLIENT_TRAVERSAL_LOCAL"
live_lab_capture_root "$FINAL_EXIT_HOST" "root cat /run/rustynet/traversal-issue/rn-traversal-$ENTRY_NODE_ID.traversal" > "$ENTRY_TRAVERSAL_LOCAL"
live_lab_capture_root "$FINAL_EXIT_HOST" "root cat /run/rustynet/traversal-issue/rn-traversal-$SECOND_CLIENT_NODE_ID.traversal" > "$SECOND_CLIENT_TRAVERSAL_LOCAL"

install_traversal_bundle() {
  local host="$1"
  local bundle_local="$2"
  live_lab_scp_to "$TRAVERSAL_PUB_LOCAL" "$host" "/tmp/rn-traversal.pub"
  live_lab_scp_to "$bundle_local" "$host" "/tmp/rn-traversal.bundle"
  live_lab_run_root "$host" "root install -m 0644 -o root -g root /tmp/rn-traversal.pub /etc/rustynet/traversal.pub && root install -m 0640 -o root -g rustynetd /tmp/rn-traversal.bundle /var/lib/rustynet/rustynetd.traversal && root rm -f /var/lib/rustynet/rustynetd.traversal.watermark /tmp/rn-traversal.pub /tmp/rn-traversal.bundle"
}

live_lab_log "Distributing signed traversal bundles"
install_traversal_bundle "$FINAL_EXIT_HOST" "$FINAL_EXIT_TRAVERSAL_LOCAL"
install_traversal_bundle "$CLIENT_HOST" "$CLIENT_TRAVERSAL_LOCAL"
install_traversal_bundle "$ENTRY_HOST" "$ENTRY_TRAVERSAL_LOCAL"
install_traversal_bundle "$SECOND_CLIENT_HOST" "$SECOND_CLIENT_TRAVERSAL_LOCAL"

live_lab_log "Enforcing runtime roles"
live_lab_enforce_host "$FINAL_EXIT_HOST" "admin" "$FINAL_EXIT_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$FINAL_EXIT_HOST")"
live_lab_enforce_host "$CLIENT_HOST" "client" "$CLIENT_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$CLIENT_HOST")"
live_lab_enforce_host "$ENTRY_HOST" "admin" "$ENTRY_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$ENTRY_HOST")"
live_lab_enforce_host "$SECOND_CLIENT_HOST" "client" "$SECOND_CLIENT_NODE_ID" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$SECOND_CLIENT_HOST")"
live_lab_wait_for_daemon_socket "$FINAL_EXIT_HOST"
live_lab_wait_for_daemon_socket "$CLIENT_HOST"
live_lab_wait_for_daemon_socket "$ENTRY_HOST"
live_lab_wait_for_daemon_socket "$SECOND_CLIENT_HOST"

live_lab_log "Advertising default route on final exit and entry relay"
live_lab_retry_root "$FINAL_EXIT_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 0.0.0.0/0" 10 2
live_lab_retry_root "$ENTRY_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 0.0.0.0/0" 10 2

sleep 6

CLIENT_STATUS="$(live_lab_status "$CLIENT_HOST")"
ENTRY_STATUS="$(live_lab_status "$ENTRY_HOST")"
FINAL_EXIT_STATUS="$(live_lab_status "$FINAL_EXIT_HOST")"
SECOND_CLIENT_STATUS="$(live_lab_status "$SECOND_CLIENT_HOST")"
CLIENT_ROUTE="$(live_lab_capture "$CLIENT_HOST" "ip -4 route get 1.1.1.1 || true")"
SECOND_CLIENT_ROUTE="$(live_lab_capture "$SECOND_CLIENT_HOST" "ip -4 route get 1.1.1.1 || true")"
ENTRY_ENDPOINTS="$(live_lab_capture_root "$ENTRY_HOST" "root wg show rustynet0 endpoints || true")"
CLIENT_PLAINTEXT_CHECK="$(live_lab_no_plaintext_passphrase_check "$CLIENT_HOST")"
ENTRY_PLAINTEXT_CHECK="$(live_lab_no_plaintext_passphrase_check "$ENTRY_HOST")"
FINAL_EXIT_PLAINTEXT_CHECK="$(live_lab_no_plaintext_passphrase_check "$FINAL_EXIT_HOST")"

live_lab_log "Final status snapshot: client"
printf '%s\n' "$CLIENT_STATUS"
live_lab_log "Final status snapshot: entry"
printf '%s\n' "$ENTRY_STATUS"
live_lab_log "Final status snapshot: final exit"
printf '%s\n' "$FINAL_EXIT_STATUS"
live_lab_log "Final status snapshot: second client"
printf '%s\n' "$SECOND_CLIENT_STATUS"
live_lab_log "Client route"
printf '%s\n' "$CLIENT_ROUTE"
live_lab_log "Second client route"
printf '%s\n' "$SECOND_CLIENT_ROUTE"
live_lab_log "Entry endpoints"
printf '%s\n' "$ENTRY_ENDPOINTS"

check_client_exit_is_entry="fail"
check_entry_exit_is_final="fail"
check_entry_serves_exit="fail"
check_final_exit_serves="fail"
check_client_route_rustynet="fail"
check_second_client_route_rustynet="fail"
check_entry_peer_visibility="fail"
check_no_plaintext_passphrases="fail"

if grep -Fq "exit_node=${ENTRY_NODE_ID}" <<<"$CLIENT_STATUS" && grep -Fq "state=ExitActive" <<<"$CLIENT_STATUS"; then
  check_client_exit_is_entry="pass"
fi
if grep -Fq "exit_node=${FINAL_EXIT_NODE_ID}" <<<"$ENTRY_STATUS"; then
  check_entry_exit_is_final="pass"
fi
if grep -Fq 'serving_exit_node=true' <<<"$ENTRY_STATUS"; then
  check_entry_serves_exit="pass"
fi
if grep -Fq 'serving_exit_node=true' <<<"$FINAL_EXIT_STATUS"; then
  check_final_exit_serves="pass"
fi
if grep -Fq 'dev rustynet0' <<<"$CLIENT_ROUTE"; then
  check_client_route_rustynet="pass"
fi
if grep -Fq 'dev rustynet0' <<<"$SECOND_CLIENT_ROUTE"; then
  check_second_client_route_rustynet="pass"
fi
if grep -Fq "${CLIENT_ADDR}:51820" <<<"$ENTRY_ENDPOINTS" && grep -Fq "${FINAL_EXIT_ADDR}:51820" <<<"$ENTRY_ENDPOINTS"; then
  check_entry_peer_visibility="pass"
fi
if [[ "$CLIENT_PLAINTEXT_CHECK" == 'no-plaintext-passphrase-files' && "$ENTRY_PLAINTEXT_CHECK" == 'no-plaintext-passphrase-files' && "$FINAL_EXIT_PLAINTEXT_CHECK" == 'no-plaintext-passphrase-files' ]]; then
  check_no_plaintext_passphrases="pass"
fi

overall="pass"
for value in \
  "$check_client_exit_is_entry" \
  "$check_entry_exit_is_final" \
  "$check_entry_serves_exit" \
  "$check_final_exit_serves" \
  "$check_client_route_rustynet" \
  "$check_second_client_route_rustynet" \
  "$check_entry_peer_visibility" \
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
  "mode": "live_linux_two_hop",
  "evidence_mode": "measured",
  "captured_at": "${captured_at_utc}",
  "captured_at_unix": ${captured_at_unix},
  "git_commit": "${git_commit}",
  "status": "${overall}",
  "final_exit_host": "${FINAL_EXIT_HOST}",
  "client_host": "${CLIENT_HOST}",
  "entry_host": "${ENTRY_HOST}",
  "second_client_host": "${SECOND_CLIENT_HOST}",
  "checks": {
    "client_exit_is_entry": "${check_client_exit_is_entry}",
    "entry_exit_is_final": "${check_entry_exit_is_final}",
    "entry_serves_exit": "${check_entry_serves_exit}",
    "final_exit_serves": "${check_final_exit_serves}",
    "client_route_via_rustynet0": "${check_client_route_rustynet}",
    "second_client_route_via_rustynet0": "${check_second_client_route_rustynet}",
    "entry_peer_visibility": "${check_entry_peer_visibility}",
    "no_plaintext_passphrase_files": "${check_no_plaintext_passphrases}"
  },
  "source_artifacts": [
    "${LOG_PATH}"
  ]
}
EOF_REPORT

live_lab_log "Two-hop report written: $REPORT_PATH"
if [[ "$overall" != 'pass' ]]; then
  exit 1
fi
