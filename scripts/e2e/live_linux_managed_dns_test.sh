#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/e2e/live_lab_common.sh"

LIVE_LAB_LOG_PREFIX="managed-dns"
export LIVE_LAB_LOG_PREFIX

SIGNER_HOST="debian@192.168.18.49"
CLIENT_HOST="ubuntu@192.168.18.52"
SIGNER_NODE_ID="exit-49"
CLIENT_NODE_ID="client-52"
SSH_ALLOW_CIDRS="192.168.18.0/24"
SSH_PASSWORD_FILE=""
SUDO_PASSWORD_FILE=""
REPORT_PATH="$ROOT_DIR/artifacts/phase10/source/managed_dns_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/managed_dns_report.log"
ZONE_NAME="rustynet"
DNS_INTERFACE="rustynet0"
DNS_BIND_ADDR="127.0.0.1:53535"
MANAGED_LABEL="exit"
MANAGED_ALIAS="gateway"

usage() {
  cat <<USAGE
usage: $0 --ssh-password-file <path> --sudo-password-file <path> [options]

options:
  --signer-host <user@host>
  --client-host <user@host>
  --signer-node-id <id>
  --client-node-id <id>
  --ssh-allow-cidrs <cidrs>
  --report-path <path>
  --log-path <path>
  --zone-name <name>
  --dns-interface <name>
  --dns-bind-addr <ip:port>
USAGE
}

json_field() {
  local payload="$1"
  local field="$2"
  python3 - "$payload" "$field" <<'PY'
import json
import sys

payload = json.loads(sys.argv[1])
value = payload.get(sys.argv[2])
if value is None:
    print("")
elif isinstance(value, bool):
    print("true" if value else "false")
else:
    print(value)
PY
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-password-file) SSH_PASSWORD_FILE="$2"; shift 2 ;;
    --sudo-password-file) SUDO_PASSWORD_FILE="$2"; shift 2 ;;
    --signer-host) SIGNER_HOST="$2"; shift 2 ;;
    --client-host) CLIENT_HOST="$2"; shift 2 ;;
    --signer-node-id) SIGNER_NODE_ID="$2"; shift 2 ;;
    --client-node-id) CLIENT_NODE_ID="$2"; shift 2 ;;
    --ssh-allow-cidrs) SSH_ALLOW_CIDRS="$2"; shift 2 ;;
    --report-path) REPORT_PATH="$2"; shift 2 ;;
    --log-path) LOG_PATH="$2"; shift 2 ;;
    --zone-name) ZONE_NAME="$2"; shift 2 ;;
    --dns-interface) DNS_INTERFACE="$2"; shift 2 ;;
    --dns-bind-addr) DNS_BIND_ADDR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$SSH_PASSWORD_FILE" || -z "$SUDO_PASSWORD_FILE" ]]; then
  usage >&2
  exit 2
fi

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")"
: > "$LOG_PATH"
exec >> "$LOG_PATH" 2>&1

live_lab_init "rustynet-managed-dns" "$SSH_PASSWORD_FILE" "$SUDO_PASSWORD_FILE"
cleanup_all() {
  if [[ -n "${CLIENT_HOST:-}" ]]; then
    live_lab_run_root "$CLIENT_HOST" "root rm -f /tmp/rn-dns-query.py /tmp/rn-dns-zone.pub /tmp/rn-dns-zone.bundle" >/dev/null 2>&1 || true
  fi
  if [[ -n "${SIGNER_HOST:-}" ]]; then
    live_lab_run_root "$SIGNER_HOST" "root rm -f /tmp/rn_issue_dns_zone.sh /tmp/rn_issue_dns_zone.env /tmp/rn-dns-records.json" >/dev/null 2>&1 || true
  fi
  live_lab_cleanup
}
trap 'cleanup_all' EXIT

ISSUE_SCRIPT="$LIVE_LAB_WORK_DIR/rn_issue_dns_zone.sh"
ISSUE_ENV="$LIVE_LAB_WORK_DIR/rn_issue_dns_zone.env"
RECORDS_JSON="$LIVE_LAB_WORK_DIR/rn-dns-records.json"
QUERY_SCRIPT="$LIVE_LAB_WORK_DIR/rn-dns-query.py"
VERIFIER_LOCAL="$LIVE_LAB_WORK_DIR/dns-zone.pub"
VALID_BUNDLE_LOCAL="$LIVE_LAB_WORK_DIR/dns-zone-valid.bundle"
STALE_BUNDLE_LOCAL="$LIVE_LAB_WORK_DIR/dns-zone-stale.bundle"
MANAGED_FQDN="${MANAGED_LABEL}.${ZONE_NAME}"
MANAGED_ALIAS_FQDN="${MANAGED_ALIAS}.${ZONE_NAME}"
STALE_GENERATED_AT="$(( $(date -u +%s) - 7200 ))"
DNS_SERVER="${DNS_BIND_ADDR%:*}"
DNS_PORT="${DNS_BIND_ADDR##*:}"

for host in "$SIGNER_HOST" "$CLIENT_HOST"; do
  live_lab_push_sudo_password "$host"
done

live_lab_log "Collecting WireGuard public keys"
SIGNER_PUB_HEX="$(live_lab_collect_pubkey_hex "$SIGNER_HOST")"
CLIENT_PUB_HEX="$(live_lab_collect_pubkey_hex "$CLIENT_HOST")"

SIGNER_ADDR="$(live_lab_target_address "$SIGNER_HOST")"
CLIENT_ADDR="$(live_lab_target_address "$CLIENT_HOST")"
NODES_SPEC="${SIGNER_NODE_ID}|${SIGNER_ADDR}:51820|${SIGNER_PUB_HEX};${CLIENT_NODE_ID}|${CLIENT_ADDR}:51820|${CLIENT_PUB_HEX}"
ALLOW_SPEC="${CLIENT_NODE_ID}|${SIGNER_NODE_ID};${SIGNER_NODE_ID}|${CLIENT_NODE_ID}"

cat > "$RECORDS_JSON" <<EOF_RECORDS
[
  {
    "label": "${MANAGED_LABEL}",
    "target_node_id": "${SIGNER_NODE_ID}",
    "ttl_secs": 300,
    "aliases": ["${MANAGED_ALIAS}"]
  },
  {
    "label": "client",
    "target_node_id": "${CLIENT_NODE_ID}",
    "ttl_secs": 300
  }
]
EOF_RECORDS

cat > "$QUERY_SCRIPT" <<'PY'
#!/usr/bin/env python3
import json
import socket
import struct
import sys

if len(sys.argv) != 4:
    raise SystemExit("usage: rn-dns-query.py <server> <port> <qname>")

server = sys.argv[1]
port = int(sys.argv[2])
qname = sys.argv[3].strip(".")
if not qname:
    raise SystemExit("qname must not be empty")

header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
question = b"".join(
    bytes([len(label)]) + label.encode("ascii")
    for label in qname.split(".")
) + b"\x00" + struct.pack("!HH", 1, 1)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3.0)
sock.sendto(header + question, (server, port))
response, _ = sock.recvfrom(512)
sock.close()

flags = struct.unpack("!H", response[2:4])[0]
rcode = flags & 0x000F
answer_count = struct.unpack("!H", response[6:8])[0]
offset = 12
while offset < len(response) and response[offset] != 0:
    offset += 1 + response[offset]
offset += 5
answer_ip = ""
answer_ttl = 0
if answer_count > 0 and offset + 12 <= len(response):
    offset += 2
    rr_type, rr_class, ttl, rdlen = struct.unpack("!HHIH", response[offset:offset + 10])
    offset += 10
    if rr_type == 1 and rr_class == 1 and rdlen == 4 and offset + 4 <= len(response):
        answer_ip = ".".join(str(byte) for byte in response[offset:offset + 4])
        answer_ttl = ttl

print(json.dumps({
    "rcode": rcode,
    "answer_count": answer_count,
    "answer_ip": answer_ip,
    "answer_ttl": answer_ttl,
}, separators=(",", ":")))
PY
chmod 700 "$QUERY_SCRIPT"

cat > "$ISSUE_SCRIPT" <<'ISSUEEOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: rn_issue_dns_zone.sh <env-file>" >&2
  exit 2
fi

source "$1"

root() {
  sudo -S -p '' "$@" < /tmp/rn_sudo.pass
}

PASS_FILE="$(mktemp /tmp/rn-dns-zone-passphrase.XXXXXX)"
cleanup() {
  if [[ -f "$PASS_FILE" ]]; then
    root rustynet ops secure-remove --path "$PASS_FILE" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

root rustynet ops materialize-signing-passphrase --output "$PASS_FILE"
root chmod 0600 "$PASS_FILE"

ISSUE_DIR="/run/rustynet/dns-zone-issue"
root rm -rf "$ISSUE_DIR"
root install -d -m 0700 "$ISSUE_DIR"

issue_bundle() {
  local output_name="$1"
  shift
  root rustynet dns zone issue \
    --signing-secret /etc/rustynet/membership.owner.key \
    --signing-secret-passphrase-file "$PASS_FILE" \
    --subject-node-id "$CLIENT_NODE_ID" \
    --nodes "$NODES_SPEC" \
    --allow "$ALLOW_SPEC" \
    --records-json /tmp/rn-dns-records.json \
    --output "$ISSUE_DIR/$output_name" \
    --verifier-key-output "$ISSUE_DIR/rn-dns-zone.pub" \
    --zone-name "$ZONE_NAME" \
    "$@"
}

issue_bundle "valid.dns-zone" --ttl-secs 300
issue_bundle "stale.dns-zone" --generated-at "$STALE_GENERATED_AT" --ttl-secs 300
ISSUEEOF
chmod 700 "$ISSUE_SCRIPT"

: > "$ISSUE_ENV"
live_lab_append_env_assignment "$ISSUE_ENV" "CLIENT_NODE_ID" "$CLIENT_NODE_ID"
live_lab_append_env_assignment "$ISSUE_ENV" "NODES_SPEC" "$NODES_SPEC"
live_lab_append_env_assignment "$ISSUE_ENV" "ALLOW_SPEC" "$ALLOW_SPEC"
live_lab_append_env_assignment "$ISSUE_ENV" "ZONE_NAME" "$ZONE_NAME"
live_lab_append_env_assignment "$ISSUE_ENV" "STALE_GENERATED_AT" "$STALE_GENERATED_AT"

live_lab_log "Issuing signed managed DNS bundles on $SIGNER_HOST"
live_lab_scp_to "$ISSUE_SCRIPT" "$SIGNER_HOST" "/tmp/rn_issue_dns_zone.sh"
live_lab_scp_to "$ISSUE_ENV" "$SIGNER_HOST" "/tmp/rn_issue_dns_zone.env"
live_lab_scp_to "$RECORDS_JSON" "$SIGNER_HOST" "/tmp/rn-dns-records.json"
live_lab_run_root "$SIGNER_HOST" "root chmod 700 /tmp/rn_issue_dns_zone.sh && root bash /tmp/rn_issue_dns_zone.sh /tmp/rn_issue_dns_zone.env"
live_lab_capture_root "$SIGNER_HOST" "root cat /run/rustynet/dns-zone-issue/rn-dns-zone.pub" > "$VERIFIER_LOCAL"
live_lab_capture_root "$SIGNER_HOST" "root cat /run/rustynet/dns-zone-issue/valid.dns-zone" > "$VALID_BUNDLE_LOCAL"
live_lab_capture_root "$SIGNER_HOST" "root cat /run/rustynet/dns-zone-issue/stale.dns-zone" > "$STALE_BUNDLE_LOCAL"
live_lab_run_root "$SIGNER_HOST" "root rm -f /tmp/rn_issue_dns_zone.sh /tmp/rn_issue_dns_zone.env /tmp/rn-dns-records.json"

live_lab_log "Verifying signed managed DNS bundles locally"
rustynet dns zone verify \
  --bundle "$VALID_BUNDLE_LOCAL" \
  --verifier-key "$VERIFIER_LOCAL" \
  --expected-zone-name "$ZONE_NAME" \
  --expected-subject-node-id "$CLIENT_NODE_ID" >/dev/null
rustynet dns zone verify \
  --bundle "$STALE_BUNDLE_LOCAL" \
  --verifier-key "$VERIFIER_LOCAL" \
  --expected-zone-name "$ZONE_NAME" \
  --expected-subject-node-id "$CLIENT_NODE_ID" >/dev/null

live_lab_log "Installing DNS query helper on client"
live_lab_scp_to "$QUERY_SCRIPT" "$CLIENT_HOST" "/tmp/rn-dns-query.py"
live_lab_run_root "$CLIENT_HOST" "root chmod 700 /tmp/rn-dns-query.py"

install_dns_bundle() {
  local bundle_local="$1"
  live_lab_scp_to "$VERIFIER_LOCAL" "$CLIENT_HOST" "/tmp/rn-dns-zone.pub"
  live_lab_scp_to "$bundle_local" "$CLIENT_HOST" "/tmp/rn-dns-zone.bundle"
  live_lab_run_root "$CLIENT_HOST" "root install -m 0644 -o root -g root /tmp/rn-dns-zone.pub /etc/rustynet/dns-zone.pub && root install -m 0640 -o root -g rustynetd /tmp/rn-dns-zone.bundle /var/lib/rustynet/rustynetd.dns-zone && root rm -f /var/lib/rustynet/rustynetd.dns-zone.watermark /tmp/rn-dns-zone.pub /tmp/rn-dns-zone.bundle"
  live_lab_run_root "$CLIENT_HOST" "root systemctl restart rustynetd.service rustynetd-managed-dns.service"
  live_lab_wait_for_daemon_socket "$CLIENT_HOST"
  live_lab_retry_root "$CLIENT_HOST" "root systemctl is-active rustynetd-managed-dns.service | grep -qx active" 15 2
}

extract_expected_ip() {
  local inspect_output="$1"
  printf '%s\n' "$inspect_output" | awk -v fqdn="$MANAGED_FQDN" '
    index($0, "fqdn=" fqdn " ") {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^expected_ip=/) {
          sub(/^expected_ip=/, "", $i)
          print $i
          exit
        }
      }
    }
  '
}

live_lab_log "Installing valid managed DNS bundle on $CLIENT_HOST"
install_dns_bundle "$VALID_BUNDLE_LOCAL"

DNS_INSPECT_VALID="$(live_lab_capture_root "$CLIENT_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet dns inspect")"
RESOLVECTL_STATUS_VALID="$(live_lab_capture_root "$CLIENT_HOST" "root resolvectl status ${DNS_INTERFACE} || true")"
DIRECT_QUERY_VALID="$(live_lab_capture_root "$CLIENT_HOST" "root python3 /tmp/rn-dns-query.py ${DNS_SERVER} ${DNS_PORT} ${MANAGED_FQDN}")"
DIRECT_ALIAS_QUERY_VALID="$(live_lab_capture_root "$CLIENT_HOST" "root python3 /tmp/rn-dns-query.py ${DNS_SERVER} ${DNS_PORT} ${MANAGED_ALIAS_FQDN}")"
NON_MANAGED_DIRECT_QUERY="$(live_lab_capture_root "$CLIENT_HOST" "root python3 /tmp/rn-dns-query.py ${DNS_SERVER} ${DNS_PORT} example.com")"
RESOLVECTL_QUERY_VALID="$(live_lab_capture_root "$CLIENT_HOST" "root resolvectl flush-caches >/dev/null 2>&1 || true; root resolvectl query --legend=no ${MANAGED_FQDN} || true")"

EXPECTED_IP="$(extract_expected_ip "$DNS_INSPECT_VALID")"
if [[ -z "$EXPECTED_IP" ]]; then
  echo "failed to determine expected IP from dns inspect output" >&2
  exit 1
fi

live_lab_log "Valid dns inspect"
printf '%s\n' "$DNS_INSPECT_VALID"
live_lab_log "Valid resolvectl status"
printf '%s\n' "$RESOLVECTL_STATUS_VALID"
live_lab_log "Valid loopback DNS query"
printf '%s\n' "$DIRECT_QUERY_VALID"
live_lab_log "Valid resolvectl query"
printf '%s\n' "$RESOLVECTL_QUERY_VALID"

live_lab_log "Installing stale managed DNS bundle on $CLIENT_HOST"
install_dns_bundle "$STALE_BUNDLE_LOCAL"

DNS_INSPECT_STALE="$(live_lab_capture_root "$CLIENT_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet dns inspect")"
DIRECT_QUERY_STALE="$(live_lab_capture_root "$CLIENT_HOST" "root python3 /tmp/rn-dns-query.py ${DNS_SERVER} ${DNS_PORT} ${MANAGED_FQDN}")"

live_lab_log "Stale dns inspect"
printf '%s\n' "$DNS_INSPECT_STALE"
live_lab_log "Stale loopback DNS query"
printf '%s\n' "$DIRECT_QUERY_STALE"

live_lab_log "Restoring valid managed DNS bundle on $CLIENT_HOST"
install_dns_bundle "$VALID_BUNDLE_LOCAL"
DNS_INSPECT_RESTORED="$(live_lab_capture_root "$CLIENT_HOST" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet dns inspect")"

check_zone_issue_verify="pass"
check_dns_inspect_valid="fail"
check_managed_dns_service_active="fail"
check_resolvectl_split_dns="fail"
check_loopback_query_valid="fail"
check_resolvectl_query_valid="fail"
check_alias_query_valid="fail"
check_non_managed_refused="fail"
check_stale_bundle_fail_closed="fail"
check_valid_bundle_restored="fail"

if grep -Fq "dns inspect: state=valid" <<<"$DNS_INSPECT_VALID" && grep -Fq "zone_name=${ZONE_NAME}" <<<"$DNS_INSPECT_VALID"; then
  check_dns_inspect_valid="pass"
fi
if live_lab_run_root "$CLIENT_HOST" "root systemctl is-active rustynetd-managed-dns.service | grep -qx active" >/dev/null 2>&1; then
  check_managed_dns_service_active="pass"
fi
if grep -Fq "~${ZONE_NAME}" <<<"$RESOLVECTL_STATUS_VALID" && grep -Fq "${DNS_BIND_ADDR}" <<<"$RESOLVECTL_STATUS_VALID"; then
  check_resolvectl_split_dns="pass"
fi
if [[ "$(json_field "$DIRECT_QUERY_VALID" "rcode")" == "0" && "$(json_field "$DIRECT_QUERY_VALID" "answer_ip")" == "$EXPECTED_IP" ]]; then
  check_loopback_query_valid="pass"
fi
if [[ "$(json_field "$DIRECT_ALIAS_QUERY_VALID" "rcode")" == "0" && "$(json_field "$DIRECT_ALIAS_QUERY_VALID" "answer_ip")" == "$EXPECTED_IP" ]]; then
  check_alias_query_valid="pass"
fi
if grep -Fq "$EXPECTED_IP" <<<"$RESOLVECTL_QUERY_VALID"; then
  check_resolvectl_query_valid="pass"
fi
if [[ "$(json_field "$NON_MANAGED_DIRECT_QUERY" "rcode")" == "5" ]]; then
  check_non_managed_refused="pass"
fi
if grep -Fq "dns inspect: state=invalid" <<<"$DNS_INSPECT_STALE" && grep -Fqi "stale" <<<"$DNS_INSPECT_STALE" && [[ "$(json_field "$DIRECT_QUERY_STALE" "rcode")" == "2" ]]; then
  check_stale_bundle_fail_closed="pass"
fi
if grep -Fq "dns inspect: state=valid" <<<"$DNS_INSPECT_RESTORED"; then
  check_valid_bundle_restored="pass"
fi

overall="pass"
for value in \
  "$check_zone_issue_verify" \
  "$check_dns_inspect_valid" \
  "$check_managed_dns_service_active" \
  "$check_resolvectl_split_dns" \
  "$check_loopback_query_valid" \
  "$check_resolvectl_query_valid" \
  "$check_alias_query_valid" \
  "$check_non_managed_refused" \
  "$check_stale_bundle_fail_closed" \
  "$check_valid_bundle_restored"; do
  if [[ "$value" != "pass" ]]; then
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
  "mode": "live_linux_managed_dns",
  "evidence_mode": "measured",
  "captured_at": "${captured_at_utc}",
  "captured_at_unix": ${captured_at_unix},
  "git_commit": "${git_commit}",
  "status": "${overall}",
  "zone_name": "${ZONE_NAME}",
  "signer_host": "${SIGNER_HOST}",
  "client_host": "${CLIENT_HOST}",
  "managed_fqdn": "${MANAGED_FQDN}",
  "managed_alias_fqdn": "${MANAGED_ALIAS_FQDN}",
  "expected_ip": "${EXPECTED_IP}",
  "checks": {
    "zone_issue_verify_passes": "${check_zone_issue_verify}",
    "dns_inspect_valid": "${check_dns_inspect_valid}",
    "managed_dns_service_active": "${check_managed_dns_service_active}",
    "resolvectl_split_dns_configured": "${check_resolvectl_split_dns}",
    "loopback_resolver_answers_managed_name": "${check_loopback_query_valid}",
    "systemd_resolved_answers_managed_name": "${check_resolvectl_query_valid}",
    "alias_resolves_to_expected_ip": "${check_alias_query_valid}",
    "non_managed_query_refused": "${check_non_managed_refused}",
    "stale_bundle_fail_closed": "${check_stale_bundle_fail_closed}",
    "valid_bundle_restored": "${check_valid_bundle_restored}"
  },
  "source_artifacts": [
    "${LOG_PATH}"
  ]
}
EOF_REPORT

live_lab_log "Managed DNS report written: $REPORT_PATH"
if [[ "$overall" != "pass" ]]; then
  exit 1
fi
