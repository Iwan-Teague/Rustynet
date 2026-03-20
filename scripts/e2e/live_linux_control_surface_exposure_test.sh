#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/e2e/live_lab_common.sh"

LIVE_LAB_LOG_PREFIX="control-surface"
export LIVE_LAB_LOG_PREFIX

EXIT_HOST=""
CLIENT_HOST=""
ENTRY_HOST=""
AUX_HOST=""
EXTRA_HOST=""
PROBE_HOST=""
SSH_IDENTITY_FILE=""
DNS_BIND_ADDR="127.0.0.1:53535"
REPORT_PATH="$ROOT_DIR/artifacts/phase10/live_linux_control_surface_exposure_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/live_linux_control_surface_exposure.log"

declare -a HOST_LABELS=()
declare -a HOST_TARGETS=()

usage() {
  cat <<'USAGE'
usage: live_linux_control_surface_exposure_test.sh --ssh-identity-file <path> --client-host <user@host> [options]

options:
  --exit-host <user@host>
  --client-host <user@host>
  --entry-host <user@host>
  --aux-host <user@host>
  --extra-host <user@host>
  --probe-host <user@host>          Host used to probe the client's DNS bind over underlay when managed DNS is active.
  --dns-bind-addr <ip:port>         Expected managed DNS bind address. Default: 127.0.0.1:53535
  --report-path <path>
  --log-path <path>
USAGE
}

append_host() {
  local label="$1"
  local target="$2"
  if [[ -n "$target" ]]; then
    HOST_LABELS+=("$label")
    HOST_TARGETS+=("$target")
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-identity-file) SSH_IDENTITY_FILE="$2"; shift 2 ;;
    --exit-host) EXIT_HOST="$2"; shift 2 ;;
    --client-host) CLIENT_HOST="$2"; shift 2 ;;
    --entry-host) ENTRY_HOST="$2"; shift 2 ;;
    --aux-host) AUX_HOST="$2"; shift 2 ;;
    --extra-host) EXTRA_HOST="$2"; shift 2 ;;
    --probe-host) PROBE_HOST="$2"; shift 2 ;;
    --dns-bind-addr) DNS_BIND_ADDR="$2"; shift 2 ;;
    --report-path) REPORT_PATH="$2"; shift 2 ;;
    --log-path) LOG_PATH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$SSH_IDENTITY_FILE" || -z "$CLIENT_HOST" ]]; then
  usage >&2
  exit 2
fi

append_host "exit" "$EXIT_HOST"
append_host "client" "$CLIENT_HOST"
append_host "entry" "$ENTRY_HOST"
append_host "aux" "$AUX_HOST"
append_host "extra" "$EXTRA_HOST"

if [[ "${#HOST_TARGETS[@]}" -eq 0 ]]; then
  echo "at least one target host is required" >&2
  exit 2
fi

if [[ -z "$PROBE_HOST" ]]; then
  if [[ -n "$EXIT_HOST" && "$EXIT_HOST" != "$CLIENT_HOST" ]]; then
    PROBE_HOST="$EXIT_HOST"
  elif [[ -n "$ENTRY_HOST" && "$ENTRY_HOST" != "$CLIENT_HOST" ]]; then
    PROBE_HOST="$ENTRY_HOST"
  elif [[ -n "$AUX_HOST" && "$AUX_HOST" != "$CLIENT_HOST" ]]; then
    PROBE_HOST="$AUX_HOST"
  elif [[ -n "$EXTRA_HOST" && "$EXTRA_HOST" != "$CLIENT_HOST" ]]; then
    PROBE_HOST="$EXTRA_HOST"
  fi
fi

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")"
: > "$LOG_PATH"
exec >> "$LOG_PATH" 2>&1

live_lab_init "rustynet-control-surface" "$SSH_IDENTITY_FILE"
trap 'live_lab_cleanup' EXIT

QUERY_SCRIPT="$LIVE_LAB_WORK_DIR/rn-dns-query-timeout.py"
cat > "$QUERY_SCRIPT" <<'PY'
#!/usr/bin/env python3
import json
import socket
import sys

if len(sys.argv) != 4:
    raise SystemExit("usage: rn-dns-query-timeout.py <server> <port> <qname>")

server = sys.argv[1]
port = int(sys.argv[2])
qname = sys.argv[3].rstrip(".")

labels = qname.split(".")
qname_wire = b"".join(len(label).to_bytes(1, "big") + label.encode("ascii") for label in labels) + b"\x00"
packet = b"\x13\x37" + b"\x01\x00" + b"\x00\x01\x00\x00\x00\x00\x00\x00" + qname_wire + b"\x00\x01\x00\x01"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1.0)
sock.sendto(packet, (server, port))
result = {"received": False, "error": "timeout"}
try:
    data, _ = sock.recvfrom(512)
    result = {"received": True, "size": len(data), "error": "none"}
finally:
    sock.close()

print(json.dumps(result))
sys.exit(0 if result["received"] else 1)
PY
chmod 700 "$QUERY_SCRIPT"

for target in "${HOST_TARGETS[@]}"; do
  live_lab_push_sudo_password "$target"
  live_lab_wait_for_daemon_socket "$target"
done

for idx in "${!HOST_TARGETS[@]}"; do
  label="${HOST_LABELS[$idx]}"
  target="${HOST_TARGETS[$idx]}"
  daemon_socket_meta="$LIVE_LAB_WORK_DIR/${label}.daemon_socket.txt"
  helper_socket_meta="$LIVE_LAB_WORK_DIR/${label}.helper_socket.txt"
  inet_listeners="$LIVE_LAB_WORK_DIR/${label}.inet_listeners.txt"
  dns_service_state="$LIVE_LAB_WORK_DIR/${label}.managed_dns_state.txt"

  live_lab_log "Inspecting control surfaces on ${label} ${target}"
  live_lab_capture_root "$target" "root stat -Lc '%F|%a|%U|%G' /run/rustynet/rustynetd.sock" > "$daemon_socket_meta"
  live_lab_capture_root "$target" "root stat -Lc '%F|%a|%U|%G' /run/rustynet/rustynetd-privileged.sock" > "$helper_socket_meta"
  live_lab_capture_root "$target" "root ss -H -ltnup || true" > "$inet_listeners"
  live_lab_capture_root "$target" "root systemctl is-active rustynetd-managed-dns.service || true" > "$dns_service_state"
done

REMOTE_DNS_PROBE_STATUS="skip"
REMOTE_DNS_PROBE_OUTPUT="not-applicable"
client_dns_state_file="$LIVE_LAB_WORK_DIR/client.managed_dns_state.txt"
if [[ -n "$PROBE_HOST" && "$PROBE_HOST" != "$CLIENT_HOST" && -f "$client_dns_state_file" ]] && grep -Fqx 'active' "$client_dns_state_file"; then
  DNS_SERVER="${DNS_BIND_ADDR%:*}"
  DNS_PORT="${DNS_BIND_ADDR##*:}"
  CLIENT_ADDR="$(live_lab_target_address "$CLIENT_HOST")"
  live_lab_scp_to "$QUERY_SCRIPT" "$PROBE_HOST" "/tmp/rn-dns-query-timeout.py"
  live_lab_run_root "$PROBE_HOST" "root chmod 700 /tmp/rn-dns-query-timeout.py"
  if REMOTE_DNS_PROBE_OUTPUT="$(live_lab_capture_root "$PROBE_HOST" "root python3 /tmp/rn-dns-query-timeout.py '${CLIENT_ADDR}' '${DNS_PORT}' blocked-probe.rustynet || true")"; then
    :
  fi
  if live_lab_run_root "$PROBE_HOST" "root python3 /tmp/rn-dns-query-timeout.py '${CLIENT_ADDR}' '${DNS_PORT}' blocked-probe.rustynet" >/dev/null 2>&1; then
    REMOTE_DNS_PROBE_STATUS="fail"
  else
    REMOTE_DNS_PROBE_STATUS="pass"
  fi
  live_lab_run_root "$PROBE_HOST" "root rm -f /tmp/rn-dns-query-timeout.py" >/dev/null 2>&1 || true
fi

python3 - "$REPORT_PATH" "$DNS_BIND_ADDR" "$REMOTE_DNS_PROBE_STATUS" "$REMOTE_DNS_PROBE_OUTPUT" "$LIVE_LAB_WORK_DIR" "${HOST_LABELS[@]}" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

report_path = pathlib.Path(sys.argv[1])
dns_bind_addr = sys.argv[2]
remote_dns_probe_status = sys.argv[3]
remote_dns_probe_output = sys.argv[4]
work_dir = pathlib.Path(sys.argv[5])
host_labels = sys.argv[6:]

dns_host, dns_port = dns_bind_addr.rsplit(":", 1)
allowed_udp = {f"{dns_host}:{dns_port}"}

host_results = {}
overall = "pass"

for label in host_labels:
    daemon_meta = work_dir.joinpath(f"{label}.daemon_socket.txt").read_text(encoding="utf-8").strip()
    helper_meta = work_dir.joinpath(f"{label}.helper_socket.txt").read_text(encoding="utf-8").strip()
    listener_lines = [
        line.strip()
        for line in work_dir.joinpath(f"{label}.inet_listeners.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    dns_service_state = work_dir.joinpath(f"{label}.managed_dns_state.txt").read_text(encoding="utf-8").strip()

    daemon_parts = daemon_meta.split("|")
    helper_parts = helper_meta.split("|")
    daemon_ok = len(daemon_parts) == 4 and daemon_parts[0] == "socket" and daemon_parts[1] == "600" and daemon_parts[2] == "root"
    helper_ok = len(helper_parts) == 4 and helper_parts[0] == "socket" and helper_parts[1] == "660" and helper_parts[2] == "root"

    tcp_listener_ok = True
    udp_listener_ok = True
    rustynet_listener_lines = []
    for line in listener_lines:
        if "rustynetd" not in line:
            continue
        rustynet_listener_lines.append(line)
        parts = line.split()
        if len(parts) < 5:
            tcp_listener_ok = False
            udp_listener_ok = False
            continue
        proto = parts[0]
        local_addr = parts[4]
        if proto.startswith("tcp"):
            tcp_listener_ok = False
        elif proto.startswith("udp"):
            if local_addr not in allowed_udp:
                udp_listener_ok = False
        else:
            udp_listener_ok = False

    if not daemon_ok or not helper_ok or not tcp_listener_ok or not udp_listener_ok:
        overall = "fail"

    host_results[label] = {
        "checks": {
            "daemon_socket_secure": "pass" if daemon_ok else "fail",
            "helper_socket_secure": "pass" if helper_ok else "fail",
            "no_rustynet_tcp_listener": "pass" if tcp_listener_ok else "fail",
            "rustynet_udp_loopback_only": "pass" if udp_listener_ok else "fail",
        },
        "evidence": {
            "daemon_socket_meta": daemon_meta,
            "helper_socket_meta": helper_meta,
            "managed_dns_service_state": dns_service_state,
            "rustynet_listener_lines": rustynet_listener_lines,
        },
    }

if remote_dns_probe_status == "fail":
    overall = "fail"

captured_at = datetime.now(timezone.utc)
payload = {
    "phase": "phase10",
    "mode": "live_linux_control_surface_exposure",
    "evidence_mode": "measured",
    "captured_at": captured_at.isoformat(),
    "captured_at_unix": int(captured_at.timestamp()),
    "status": overall,
    "dns_bind_addr": dns_bind_addr,
    "checks": {
        "all_daemon_sockets_secure": "pass" if all(v["checks"]["daemon_socket_secure"] == "pass" for v in host_results.values()) else "fail",
        "all_helper_sockets_secure": "pass" if all(v["checks"]["helper_socket_secure"] == "pass" for v in host_results.values()) else "fail",
        "no_rustynet_tcp_listeners": "pass" if all(v["checks"]["no_rustynet_tcp_listener"] == "pass" for v in host_results.values()) else "fail",
        "rustynet_udp_loopback_only": "pass" if all(v["checks"]["rustynet_udp_loopback_only"] == "pass" for v in host_results.values()) else "fail",
        "remote_underlay_dns_probe_blocked": remote_dns_probe_status,
    },
    "hosts": host_results,
    "evidence": {
        "remote_underlay_dns_probe_output": remote_dns_probe_output,
    },
}

with report_path.open("w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2)
    fh.write("\n")
PY

if [[ "$(python3 - "$REPORT_PATH" <<'PY'
import json, sys
print(json.loads(open(sys.argv[1], encoding="utf-8").read())["status"])
PY
)" != "pass" ]]; then
  echo "control-surface exposure test failed; see ${REPORT_PATH}" >&2
  exit 1
fi

live_lab_log "Control-surface exposure report written: $REPORT_PATH"
