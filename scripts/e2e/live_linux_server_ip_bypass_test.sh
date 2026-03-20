#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/e2e/live_lab_common.sh"

LIVE_LAB_LOG_PREFIX="server-ip-bypass"
export LIVE_LAB_LOG_PREFIX

CLIENT_HOST=""
PROBE_HOST=""
PROBE_BIND_IP=""
SSH_IDENTITY_FILE=""
SSH_ALLOW_CIDRS="192.168.18.0/24"
PROBE_PORT="18080"
REPORT_PATH="$ROOT_DIR/artifacts/phase10/live_linux_server_ip_bypass_report.json"
LOG_PATH="$ROOT_DIR/artifacts/phase10/source/live_linux_server_ip_bypass.log"

usage() {
  cat <<'USAGE'
usage: live_linux_server_ip_bypass_test.sh --ssh-identity-file <path> --client-host <user@host> --probe-host <user@host> [options]

options:
  --client-host <user@host>
  --probe-host <user@host>         Existing mesh peer whose underlay IP will host the forbidden service probe.
  --probe-bind-ip <ipv4>           Explicit IPv4 to bind on probe host. Default: probe host underlay IP.
  --ssh-allow-cidrs <cidr[,cidr]>  Explicit management bypass CIDRs. Default: 192.168.18.0/24
  --probe-port <port>              Default: 18080
  --report-path <path>
  --log-path <path>
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-identity-file) SSH_IDENTITY_FILE="$2"; shift 2 ;;
    --client-host) CLIENT_HOST="$2"; shift 2 ;;
    --probe-host) PROBE_HOST="$2"; shift 2 ;;
    --probe-bind-ip) PROBE_BIND_IP="$2"; shift 2 ;;
    --ssh-allow-cidrs) SSH_ALLOW_CIDRS="$2"; shift 2 ;;
    --probe-port) PROBE_PORT="$2"; shift 2 ;;
    --report-path) REPORT_PATH="$2"; shift 2 ;;
    --log-path) LOG_PATH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$SSH_IDENTITY_FILE" || -z "$CLIENT_HOST" || -z "$PROBE_HOST" ]]; then
  usage >&2
  exit 2
fi

if [[ "$CLIENT_HOST" == "$PROBE_HOST" ]]; then
  echo "--client-host and --probe-host must differ" >&2
  exit 2
fi

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")"
: > "$LOG_PATH"
exec >> "$LOG_PATH" 2>&1

live_lab_init "rustynet-server-ip-bypass" "$SSH_IDENTITY_FILE"
trap 'live_lab_cleanup' EXIT

SERVER_SCRIPT="$LIVE_LAB_WORK_DIR/rn-underlay-http-server.py"
PROBE_SCRIPT="$LIVE_LAB_WORK_DIR/rn-tcp-probe.py"
cat > "$SERVER_SCRIPT" <<'PY'
#!/usr/bin/env python3
import http.server
import socketserver
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: rn-underlay-http-server.py <bind-ip> <port>")

bind_ip = sys.argv[1]
port = int(sys.argv[2])

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"probe-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass

class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

with ReusableTCPServer((bind_ip, port), Handler) as httpd:
    httpd.serve_forever()
PY
cat > "$PROBE_SCRIPT" <<'PY'
#!/usr/bin/env python3
import socket
import sys

if len(sys.argv) != 4:
    raise SystemExit("usage: rn-tcp-probe.py <host> <port> <timeout-secs>")

host = sys.argv[1]
port = int(sys.argv[2])
timeout = float(sys.argv[3])

sock = socket.create_connection((host, port), timeout)
try:
    sock.sendall(b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n")
    response = sock.recv(64)
finally:
    sock.close()

if b"probe-ok" not in response:
    raise SystemExit("probe-ok marker missing from response")

print("probe-ok")
PY
chmod 700 "$SERVER_SCRIPT" "$PROBE_SCRIPT"

if [[ -n "$PROBE_BIND_IP" ]]; then
  python3 - "$PROBE_BIND_IP" <<'PY'
import ipaddress
import sys

ipaddress.IPv4Address(sys.argv[1])
PY
  PROBE_IP="$PROBE_BIND_IP"
else
  PROBE_IP="$(live_lab_target_address "$PROBE_HOST")"
fi
PROBE_PID_PATH="/tmp/rn-underlay-http-server.pid"
PROBE_LOG_PATH="/tmp/rn-underlay-http-server.log"

cleanup_probe_server() {
  live_lab_run_root "$PROBE_HOST" "root test -f '$PROBE_PID_PATH' && root kill \"\$(cat '$PROBE_PID_PATH')\" >/dev/null 2>&1 || true; root rm -f '$PROBE_PID_PATH' '$PROBE_LOG_PATH' /tmp/rn-underlay-http-server.py /tmp/rn-tcp-probe.py" >/dev/null 2>&1 || true
  live_lab_run_root "$CLIENT_HOST" "root rm -f /tmp/rn-tcp-probe.py" >/dev/null 2>&1 || true
}
trap 'cleanup_probe_server; live_lab_cleanup' EXIT

live_lab_push_sudo_password "$CLIENT_HOST"
live_lab_push_sudo_password "$PROBE_HOST"
live_lab_wait_for_daemon_socket "$CLIENT_HOST"
live_lab_wait_for_daemon_socket "$PROBE_HOST"

live_lab_scp_to "$SERVER_SCRIPT" "$PROBE_HOST" "/tmp/rn-underlay-http-server.py"
live_lab_scp_to "$PROBE_SCRIPT" "$PROBE_HOST" "/tmp/rn-tcp-probe.py"
live_lab_scp_to "$PROBE_SCRIPT" "$CLIENT_HOST" "/tmp/rn-tcp-probe.py"
live_lab_run_root "$PROBE_HOST" "root chmod 700 /tmp/rn-underlay-http-server.py /tmp/rn-tcp-probe.py"
live_lab_run_root "$CLIENT_HOST" "root chmod 700 /tmp/rn-tcp-probe.py"

live_lab_log "Starting underlay HTTP probe service on $PROBE_HOST ($PROBE_IP:$PROBE_PORT)"
live_lab_run_root "$PROBE_HOST" "root rm -f '$PROBE_PID_PATH' '$PROBE_LOG_PATH'; root nohup python3 /tmp/rn-underlay-http-server.py '$PROBE_IP' '$PROBE_PORT' >'$PROBE_LOG_PATH' 2>&1 </dev/null & echo \$! > '$PROBE_PID_PATH'"
live_lab_retry_root "$PROBE_HOST" "root python3 /tmp/rn-tcp-probe.py '$PROBE_IP' '$PROBE_PORT' 2 >/dev/null" 15 1

CLIENT_STATUS="$(live_lab_status "$CLIENT_HOST")"
CLIENT_INTERNET_ROUTE="$(live_lab_capture "$CLIENT_HOST" "ip -4 route get 1.1.1.1 || true")"
CLIENT_PROBE_ROUTE="$(live_lab_capture "$CLIENT_HOST" "ip -4 route get '$PROBE_IP' || true")"
CLIENT_TABLE_51820="$(live_lab_capture "$CLIENT_HOST" "ip -4 route show table 51820 || true")"
CLIENT_ENDPOINTS="$(live_lab_capture_root "$CLIENT_HOST" "root wg show rustynet0 endpoints || true")"
PROBE_SELF_TEST="$(live_lab_capture_root "$PROBE_HOST" "root python3 /tmp/rn-tcp-probe.py '$PROBE_IP' '$PROBE_PORT' 2 || true")"
PROBE_FROM_CLIENT_OUTPUT="$(live_lab_capture_root "$CLIENT_HOST" "root python3 /tmp/rn-tcp-probe.py '$PROBE_IP' '$PROBE_PORT' 2 || true")"

if live_lab_run_root "$CLIENT_HOST" "root python3 /tmp/rn-tcp-probe.py '$PROBE_IP' '$PROBE_PORT' 2 >/dev/null" >/dev/null 2>&1; then
  PROBE_FROM_CLIENT_STATUS="fail"
else
  PROBE_FROM_CLIENT_STATUS="pass"
fi

live_lab_log "Client route to internet"
printf '%s\n' "$CLIENT_INTERNET_ROUTE"
live_lab_log "Client route to probe host underlay IP"
printf '%s\n' "$CLIENT_PROBE_ROUTE"
live_lab_log "Client table 51820"
printf '%s\n' "$CLIENT_TABLE_51820"
live_lab_log "Client endpoints"
printf '%s\n' "$CLIENT_ENDPOINTS"
live_lab_log "Probe host self-test output"
printf '%s\n' "$PROBE_SELF_TEST"
live_lab_log "Client probe output"
printf '%s\n' "$PROBE_FROM_CLIENT_OUTPUT"

python3 - "$REPORT_PATH" "$SSH_ALLOW_CIDRS" "$PROBE_FROM_CLIENT_STATUS" "$PROBE_IP" "$PROBE_PORT" "$CLIENT_INTERNET_ROUTE" "$CLIENT_PROBE_ROUTE" "$CLIENT_TABLE_51820" "$CLIENT_ENDPOINTS" "$PROBE_SELF_TEST" "$PROBE_FROM_CLIENT_OUTPUT" <<'PY'
import ipaddress
import json
import sys
from datetime import datetime, timezone

(
    report_path,
    allowed_cidrs_raw,
    probe_from_client_status,
    probe_ip,
    probe_port,
    client_internet_route,
    client_probe_route,
    client_table_51820,
    client_endpoints,
    probe_self_test,
    probe_from_client_output,
) = sys.argv[1:]

allowed_networks = []
for part in [item.strip() for item in allowed_cidrs_raw.split(",") if item.strip()]:
    allowed_networks.append(ipaddress.ip_network(part, strict=False))

internet_route_ok = "dev rustynet0" in client_internet_route
probe_route_direct = "dev rustynet0" not in client_probe_route and probe_ip in client_probe_route
probe_host_self_reachable = "probe-ok" in probe_self_test

unexpected_bypass_routes = []
for raw_line in client_table_51820.splitlines():
    line = raw_line.strip()
    if not line or "dev rustynet0" in line or line.startswith("default "):
        continue
    first = line.split()[0]
    try:
        network = ipaddress.ip_network(first, strict=False)
    except ValueError:
        continue
    if network.prefixlen == network.max_prefixlen:
        continue
    if any(network == allowed for allowed in allowed_networks):
        continue
    unexpected_bypass_routes.append(line)

checks = {
    "internet_route_via_rustynet0": "pass" if internet_route_ok else "fail",
    "probe_host_self_service_reachable": "pass" if probe_host_self_reachable else "fail",
    "probe_endpoint_route_direct_not_tunnelled": "pass" if probe_route_direct else "fail",
    "probe_service_blocked_from_client": probe_from_client_status,
    "no_unexpected_bypass_routes": "pass" if not unexpected_bypass_routes else "fail",
}

overall = "pass"
for value in checks.values():
    if value != "pass":
        overall = "fail"
        break

captured_at = datetime.now(timezone.utc)
payload = {
    "phase": "phase10",
    "mode": "live_linux_server_ip_bypass",
    "evidence_mode": "measured",
    "captured_at": captured_at.isoformat(),
    "captured_at_unix": int(captured_at.timestamp()),
    "status": overall,
    "probe_host_ip": probe_ip,
    "probe_port": int(probe_port),
    "checks": checks,
    "evidence": {
        "client_internet_route": client_internet_route,
        "client_probe_route": client_probe_route,
        "client_table_51820": client_table_51820,
        "client_endpoints": client_endpoints,
        "probe_self_test": probe_self_test,
        "client_probe_output": probe_from_client_output,
        "unexpected_bypass_routes": unexpected_bypass_routes,
        "allowed_management_cidrs": [str(network) for network in allowed_networks],
    },
}

with open(report_path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2)
    fh.write("\n")
PY

if [[ "$(python3 - "$REPORT_PATH" <<'PY'
import json, sys
print(json.loads(open(sys.argv[1], encoding="utf-8").read())["status"])
PY
)" != "pass" ]]; then
  echo "server-IP bypass test failed; see ${REPORT_PATH}" >&2
  exit 1
fi

live_lab_log "Server-IP bypass report written: $REPORT_PATH"
