#!/usr/bin/env bash
set -euo pipefail

MODE=""
PROFILE="none"
INTERFACE="rustynet0"

usage() {
  cat <<'USAGE'
usage: apply_cross_network_impairment_profile.sh --mode <apply|clear|status> [options]

options:
  --mode <mode>           apply | clear | status
  --profile <profile>     none | latency_50ms_loss_1pct | latency_120ms_loss_3pct | loss_5pct (default: none)
  --interface <iface>     network interface (default: rustynet0)
  -h, --help              show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --interface) INTERFACE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$MODE" ]]; then
  echo "--mode is required" >&2
  exit 2
fi

if ! [[ "$INTERFACE" =~ ^[A-Za-z0-9._:-]+$ ]]; then
  echo "invalid interface: $INTERFACE" >&2
  exit 2
fi

profile_supported() {
  case "$1" in
    none|latency_50ms_loss_1pct|latency_120ms_loss_3pct|loss_5pct) return 0 ;;
    *) return 1 ;;
  esac
}

if ! profile_supported "$PROFILE"; then
  echo "unsupported impairment profile: $PROFILE" >&2
  exit 2
fi

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd" >&2
    exit 1
  fi
}

require_cmd ip
require_cmd tc

if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
  echo "interface does not exist: $INTERFACE" >&2
  exit 1
fi

clear_profile() {
  tc qdisc del dev "$INTERFACE" root >/dev/null 2>&1 || true
}

apply_profile() {
  local existing_root
  if [[ "$PROFILE" == "none" ]]; then
    clear_profile
    return 0
  fi
  existing_root="$(tc qdisc show dev "$INTERFACE" | awk 'NR==1{print $2}')"
  if [[ -n "$existing_root" && "$existing_root" != "noqueue" && "$existing_root" != "netem" ]]; then
    echo "refusing to overwrite existing root qdisc on $INTERFACE: ${existing_root}" >&2
    exit 1
  fi
  case "$PROFILE" in
    latency_50ms_loss_1pct)
      tc qdisc replace dev "$INTERFACE" root netem delay 50ms 5ms loss 1%
      ;;
    latency_120ms_loss_3pct)
      tc qdisc replace dev "$INTERFACE" root netem delay 120ms 15ms loss 3%
      ;;
    loss_5pct)
      tc qdisc replace dev "$INTERFACE" root netem loss 5%
      ;;
    *)
      echo "unsupported impairment profile: $PROFILE" >&2
      exit 2
      ;;
  esac
}

case "$MODE" in
  apply)
    apply_profile
    ;;
  clear)
    clear_profile
    ;;
  status)
    tc qdisc show dev "$INTERFACE"
    ;;
  *)
    echo "unsupported mode: $MODE" >&2
    exit 2
    ;;
esac
