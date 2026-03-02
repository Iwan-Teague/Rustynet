#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

RAW_DIR="${RUSTYNET_PHASE6_PARITY_RAW_DIR:-artifacts/release/raw}"
LEAK_REPORT_DEFAULT="artifacts/phase10/leak_test_report.json"
STRICT_MODE="${RUSTYNET_PHASE6_PARITY_STRICT:-1}"
PLATFORM_OVERRIDE="${RUSTYNET_PHASE6_PLATFORM_OVERRIDE:-}"

mkdir -p "$RAW_DIR"

if [[ -n "$PLATFORM_OVERRIDE" ]]; then
  PLATFORM="$PLATFORM_OVERRIDE"
else
  uname_s="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$uname_s" in
    linux*)
      PLATFORM="linux"
      ;;
    darwin*)
      PLATFORM="macos"
      ;;
    msys*|mingw*|cygwin*)
      PLATFORM="windows"
      ;;
    *)
      echo "unsupported platform for parity probe: $uname_s" >&2
      exit 1
      ;;
  esac
fi

route_hook_ready=false
dns_hook_ready=false
firewall_hook_ready=false
leak_matrix_passed=false

route_probe_cmd=""
dns_probe_cmd=""
firewall_probe_cmd=""
leak_source=""

case "$PLATFORM" in
  linux)
    route_probe_cmd="ip -o route show default"
    if command -v ip >/dev/null 2>&1 && ip -o route show default >/dev/null 2>&1; then
      route_hook_ready=true
    fi

    if command -v resolvectl >/dev/null 2>&1; then
      dns_probe_cmd="resolvectl status"
      if resolvectl status >/dev/null 2>&1; then
        dns_hook_ready=true
      fi
    else
      dns_probe_cmd="test -s /etc/resolv.conf"
      if [[ -s /etc/resolv.conf ]]; then
        dns_hook_ready=true
      fi
    fi

    if command -v nft >/dev/null 2>&1; then
      firewall_probe_cmd="nft list tables"
      if nft list tables >/dev/null 2>&1; then
        firewall_hook_ready=true
      fi
    elif command -v iptables >/dev/null 2>&1; then
      firewall_probe_cmd="iptables -S"
      if iptables -S >/dev/null 2>&1; then
        firewall_hook_ready=true
      fi
    else
      firewall_probe_cmd="nft|iptables unavailable"
    fi
    ;;
  macos)
    route_probe_cmd="route -n get default"
    if command -v route >/dev/null 2>&1 && route -n get default >/dev/null 2>&1; then
      route_hook_ready=true
    fi

    dns_probe_cmd="scutil --dns"
    if command -v scutil >/dev/null 2>&1 && scutil --dns >/dev/null 2>&1; then
      dns_hook_ready=true
    fi

    firewall_probe_cmd="pfctl -s info"
    if command -v pfctl >/dev/null 2>&1 && pfctl -s info >/dev/null 2>&1; then
      firewall_hook_ready=true
    fi
    ;;
  windows)
    route_probe_cmd="powershell.exe Get-NetRoute"
    if command -v powershell.exe >/dev/null 2>&1 && \
      powershell.exe -NoProfile -NonInteractive -Command "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1 | Out-Null" >/dev/null 2>&1; then
      route_hook_ready=true
    fi

    dns_probe_cmd="powershell.exe Get-DnsClientServerAddress"
    if command -v powershell.exe >/dev/null 2>&1 && \
      powershell.exe -NoProfile -NonInteractive -Command "Get-DnsClientServerAddress | Out-Null" >/dev/null 2>&1; then
      dns_hook_ready=true
    fi

    firewall_probe_cmd="powershell.exe Get-NetFirewallProfile"
    if command -v powershell.exe >/dev/null 2>&1 && \
      powershell.exe -NoProfile -NonInteractive -Command "Get-NetFirewallProfile | Out-Null" >/dev/null 2>&1; then
      firewall_hook_ready=true
    fi
    ;;
  *)
    echo "unsupported platform override: $PLATFORM" >&2
    exit 1
    ;;
esac

case "$PLATFORM" in
  linux)
    leak_source="${RUSTYNET_PHASE6_LEAK_REPORT_LINUX:-${RUSTYNET_PHASE6_LEAK_REPORT:-$LEAK_REPORT_DEFAULT}}"
    ;;
  macos)
    leak_source="${RUSTYNET_PHASE6_LEAK_REPORT_MACOS:-${RUSTYNET_PHASE6_LEAK_REPORT:-$LEAK_REPORT_DEFAULT}}"
    ;;
  windows)
    leak_source="${RUSTYNET_PHASE6_LEAK_REPORT_WINDOWS:-${RUSTYNET_PHASE6_LEAK_REPORT:-$LEAK_REPORT_DEFAULT}}"
    ;;
esac

if [[ -f "$leak_source" ]]; then
  if python3 - "$leak_source" <<'PY'
import json
import sys
from pathlib import Path

report = Path(sys.argv[1])
with report.open("r", encoding="utf-8") as fh:
    payload = json.load(fh)

if payload.get("status") != "pass":
    raise SystemExit(1)
if payload.get("evidence_mode") != "measured":
    raise SystemExit(1)
PY
  then
    leak_matrix_passed=true
  fi
fi

out_path="$RAW_DIR/platform_parity_${PLATFORM}.json"

export PLATFORM
export ROUTE_HOOK_READY="$route_hook_ready"
export DNS_HOOK_READY="$dns_hook_ready"
export FIREWALL_HOOK_READY="$firewall_hook_ready"
export LEAK_MATRIX_PASSED="$leak_matrix_passed"
export ROUTE_PROBE_CMD="$route_probe_cmd"
export DNS_PROBE_CMD="$dns_probe_cmd"
export FIREWALL_PROBE_CMD="$firewall_probe_cmd"
export LEAK_SOURCE="$leak_source"

python3 - "$out_path" <<'PY'
import json
import os
import socket
import time
from pathlib import Path
import sys

out = Path(sys.argv[1])
payload = {
    "platform": os.environ["PLATFORM"],
    "route_hook_ready": os.environ["ROUTE_HOOK_READY"] == "true",
    "dns_hook_ready": os.environ["DNS_HOOK_READY"] == "true",
    "firewall_hook_ready": os.environ["FIREWALL_HOOK_READY"] == "true",
    "leak_matrix_passed": os.environ["LEAK_MATRIX_PASSED"] == "true",
    "probe_time_unix": int(time.time()),
    "probe_host": socket.gethostname(),
    "probe_sources": {
        "route": os.environ.get("ROUTE_PROBE_CMD", ""),
        "dns": os.environ.get("DNS_PROBE_CMD", ""),
        "firewall": os.environ.get("FIREWALL_PROBE_CMD", ""),
        "leak_report": os.environ.get("LEAK_SOURCE", ""),
    },
}
with out.open("w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=False)
    fh.write("\n")
PY

if [[ "$STRICT_MODE" == "1" ]]; then
  if [[ "$route_hook_ready" != "true" || "$dns_hook_ready" != "true" || "$firewall_hook_ready" != "true" || "$leak_matrix_passed" != "true" ]]; then
    echo "platform parity probe recorded failing controls in $out_path" >&2
    exit 1
  fi
fi

echo "wrote platform probe: $out_path"
