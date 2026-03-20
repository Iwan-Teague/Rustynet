#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/e2e/live_lab_common.sh"

LIVE_LAB_LOG_PREFIX="role-switch-live"
export LIVE_LAB_LOG_PREFIX

DEBIAN_HOST="debian@192.168.18.65"
DEBIAN_NODE_ID="client-65"
UBUNTU_HOST="ubuntu@192.168.18.52"
UBUNTU_NODE_ID="client-52"
FEDORA_HOST="fedora@192.168.18.51"
FEDORA_NODE_ID="client-51"
MINT_HOST="mint@192.168.18.53"
MINT_NODE_ID="client-53"
SSH_ALLOW_CIDRS="192.168.18.0/24"
SSH_IDENTITY_FILE=""
REPORT_PATH="$ROOT_DIR/artifacts/phase10/role_switch_matrix_report.json"
SOURCE_PATH="$ROOT_DIR/artifacts/phase10/source/role_switch_matrix.md"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/live_linux_role_switch_matrix.log"
LAN_TEST_CIDR="192.168.1.0/24"

usage() {
  cat <<USAGE
usage: $0 --ssh-identity-file <path> [options]

options:
  --debian-host <user@host>
  --debian-node-id <id>
  --ubuntu-host <user@host>
  --ubuntu-node-id <id>
  --fedora-host <user@host>
  --fedora-node-id <id>
  --mint-host <user@host>
  --mint-node-id <id>
  --ssh-allow-cidrs <cidrs>
  --report-path <path>
  --source-path <path>
  --log-path <path>
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-identity-file) SSH_IDENTITY_FILE="$2"; shift 2 ;;
    --debian-host) DEBIAN_HOST="$2"; shift 2 ;;
    --debian-node-id) DEBIAN_NODE_ID="$2"; shift 2 ;;
    --ubuntu-host) UBUNTU_HOST="$2"; shift 2 ;;
    --ubuntu-node-id) UBUNTU_NODE_ID="$2"; shift 2 ;;
    --fedora-host) FEDORA_HOST="$2"; shift 2 ;;
    --fedora-node-id) FEDORA_NODE_ID="$2"; shift 2 ;;
    --mint-host) MINT_HOST="$2"; shift 2 ;;
    --mint-node-id) MINT_NODE_ID="$2"; shift 2 ;;
    --ssh-allow-cidrs) SSH_ALLOW_CIDRS="$2"; shift 2 ;;
    --report-path) REPORT_PATH="$2"; shift 2 ;;
    --source-path) SOURCE_PATH="$2"; shift 2 ;;
    --log-path) LOG_PATH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$SSH_IDENTITY_FILE" ]]; then
  usage >&2
  exit 2
fi

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$SOURCE_PATH")" "$(dirname "$LOG_PATH")"
exec > >(tee "$LOG_PATH") 2>&1

live_lab_init "rustynet-role-switch-live" "$SSH_IDENTITY_FILE"
trap 'live_lab_cleanup' EXIT

TMP_JSON="$LIVE_LAB_WORK_DIR/role_switch_hosts.json"
: > "$TMP_JSON"
printf '{}\n' > "$TMP_JSON"

sanitize_line() {
  printf '%s' "$1" | tr '\t\r\n' '   ' | sed 's/  */ /g'
}

status_line() {
  local host="$1"
  live_lab_status "$host" | tr -d '\r' | awk '/node_id=/{line=$0} END{print line}'
}

status_field() {
  local line="$1"
  local key="$2"
  awk -v key="$key" '{for (i=1;i<=NF;i++) if (index($i,key"=")==1){print substr($i,length(key)+2); exit}}' <<<"$line"
}

wait_for_field() {
  local host="$1"
  local key="$2"
  local expected="$3"
  local attempts="${4:-40}"
  local sleep_secs="${5:-2}"
  local line=""
  local value=""
  local attempt
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    line="$(status_line "$host")"
    value="$(status_field "$line" "$key")"
    if [[ "$value" == "$expected" ]]; then
      printf '%s\n' "$line"
      return 0
    fi
    sleep "$sleep_secs"
  done
  printf '%s\n' "$line"
  return 1
}

route_via_rustynet0() {
  local host="$1"
  local route_line
  route_line="$(live_lab_capture "$host" "ip -4 route get 1.1.1.1 || true")"
  grep -Fq 'dev rustynet0' <<<"$route_line"
}

route_advertise_denied() {
  local host="$1"
  live_lab_run_root "$host" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 10.250.0.0/16 >/dev/null 2>&1 && exit 1 || exit 0" >/dev/null 2>&1
}

exit_select_denied() {
  local host="$1"
  local baseline_exit="$2"
  if [[ -z "$baseline_exit" || "$baseline_exit" == "none" ]]; then
    return 1
  fi
  live_lab_run_root "$host" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet exit-node select '$baseline_exit' >/dev/null 2>&1 && exit 1 || exit 0" >/dev/null 2>&1
}

lan_toggle_denied() {
  local host="$1"
  if live_lab_apply_lan_access_coupling "$host" "true" "$LAN_TEST_CIDR" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

switch_role() {
  local host="$1"
  local role="$2"
  local node_id="$3"
  live_lab_enforce_host "$host" "$role" "$node_id" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$host")"
  live_lab_wait_for_daemon_socket "$host"
}

prepare_client_baseline() {
  local host="$1"
  local node_id="$2"
  switch_role "$host" client "$node_id"
  wait_for_field "$host" node_role client >/dev/null
}

record_host_result() {
  local os_id="$1"
  local temp_role="$2"
  local switch_execution="$3"
  local post_switch_reconcile="$4"
  local policy_still_enforced="$5"
  local least_privilege_preserved="$6"
  python3 - "$TMP_JSON" "$os_id" "$temp_role" "$switch_execution" "$post_switch_reconcile" "$policy_still_enforced" "$least_privilege_preserved" <<'PY'
import json
import sys
from pathlib import Path

path, os_id, temp_role, switch_execution, post_switch_reconcile, policy_still_enforced, least_privilege_preserved = sys.argv[1:]
payload = json.loads(Path(path).read_text(encoding='utf-8'))
payload[os_id] = {
    'transition': {
        'from_role': 'client',
        'to_role': temp_role,
        'status': 'pass' if switch_execution == 'pass' else 'fail',
    },
    'checks': {
        'switch_execution': switch_execution,
        'post_switch_reconcile': post_switch_reconcile,
        'policy_still_enforced': policy_still_enforced,
        'least_privilege_preserved': least_privilege_preserved,
    },
}
Path(path).write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
PY
}

overall_status="pass"

git_commit="${RUSTYNET_EXPECTED_GIT_COMMIT:-$(git rev-parse HEAD)}"
git_commit="$(printf '%s' "$git_commit" | tr '[:upper:]' '[:lower:]')"
captured_at_unix="$(date -u +%s)"
captured_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat > "$SOURCE_PATH" <<EOF_MD
# Role Switch Matrix (current commit)

Captured at: ${captured_at_utc}

EOF_MD

process_host() {
  local host="$1"
  local os_id="$2"
  local temp_role="$3"
  local node_id="$4"
  local baseline after_temp after_restore baseline_exit
  local switch_execution="fail"
  local post_switch_reconcile="fail"
  local policy_still_enforced="fail"
  local least_privilege_preserved="fail"

  printf '[role-switch] %s %s -> %s\n' "$os_id" "$host" "$temp_role"

  prepare_client_baseline "$host" "$node_id"
  baseline="$(status_line "$host")"
  baseline_exit="$(status_field "$baseline" exit_node)"

  switch_role "$host" "$temp_role" "$node_id"
  after_temp="$(wait_for_field "$host" node_role "$temp_role")"

  if [[ "$temp_role" == "blind_exit" ]]; then
    if route_advertise_denied "$host"; then
      policy_still_enforced="pass"
    fi
    if exit_select_denied "$host" "$baseline_exit" && lan_toggle_denied "$host"; then
      least_privilege_preserved="pass"
    fi
  fi

  switch_role "$host" client "$node_id"
  after_restore="$(wait_for_field "$host" node_role client)"

  if [[ "$(status_field "$after_temp" node_role)" == "$temp_role" && "$(status_field "$after_restore" node_role)" == "client" ]]; then
    switch_execution="pass"
  fi

  if [[ "$temp_role" == "blind_exit" ]]; then
    if [[ \
      "$(status_field "$after_temp" serving_exit_node)" == "true" && \
      "$(status_field "$after_temp" exit_node)" == "none" && \
      "$(status_field "$after_temp" lan_access)" == "off" && \
      -n "$baseline_exit" && "$baseline_exit" != "none" && \
      "$(status_field "$after_restore" exit_node)" == "$baseline_exit" \
    ]] && route_via_rustynet0 "$host"; then
      post_switch_reconcile="pass"
    fi
  else
    if route_advertise_denied "$host"; then
      policy_still_enforced="pass"
      least_privilege_preserved="pass"
    fi
    if [[ \
      -n "$baseline_exit" && "$baseline_exit" != "none" && \
      "$(status_field "$after_temp" serving_exit_node)" == "false" && \
      "$(status_field "$after_temp" exit_node)" == "$baseline_exit" && \
      "$(status_field "$after_restore" exit_node)" == "$baseline_exit" \
    ]] && route_via_rustynet0 "$host"; then
      post_switch_reconcile="pass"
    fi
  fi

  cat >> "$SOURCE_PATH" <<EOF_MD_HOST
## ${os_id} (${host})
- baseline: $(sanitize_line "$baseline")
- after_temp: $(sanitize_line "$after_temp")
- after_restore: $(sanitize_line "$after_restore")
- temp_role: ${temp_role}
- switch_execution: ${switch_execution}
- post_switch_reconcile: ${post_switch_reconcile}
- policy_still_enforced: ${policy_still_enforced}
- least_privilege_preserved: ${least_privilege_preserved}

EOF_MD_HOST

  record_host_result "$os_id" "$temp_role" "$switch_execution" "$post_switch_reconcile" "$policy_still_enforced" "$least_privilege_preserved"

  if [[ "$switch_execution" != "pass" || "$post_switch_reconcile" != "pass" || "$policy_still_enforced" != "pass" || "$least_privilege_preserved" != "pass" ]]; then
    overall_status="fail"
  fi
}

process_host "$DEBIAN_HOST" debian13 admin "$DEBIAN_NODE_ID"
process_host "$FEDORA_HOST" fedora blind_exit "$FEDORA_NODE_ID"
process_host "$UBUNTU_HOST" ubuntu admin "$UBUNTU_NODE_ID"
process_host "$MINT_HOST" mint admin "$MINT_NODE_ID"

python3 - "$TMP_JSON" "$REPORT_PATH" "$SOURCE_PATH" "$git_commit" "$captured_at_unix" "$overall_status" <<'PY'
import json
import sys
from pathlib import Path

hosts_path, report_path, source_path, git_commit, captured_at_unix, overall_status = sys.argv[1:]
hosts = json.loads(Path(hosts_path).read_text(encoding='utf-8'))
report = {
    'schema_version': 1,
    'evidence_mode': 'measured',
    'git_commit': git_commit,
    'captured_at_unix': int(captured_at_unix),
    'status': overall_status,
    'hosts': hosts,
    'source_artifact': source_path,
}
Path(report_path).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
PY

printf 'role_switch_report=%s\n' "$REPORT_PATH"
printf 'role_switch_source=%s\n' "$SOURCE_PATH"

if [[ "$overall_status" != "pass" ]]; then
  exit 1
fi
