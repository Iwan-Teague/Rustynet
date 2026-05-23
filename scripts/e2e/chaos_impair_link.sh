#!/usr/bin/env bash
set -euo pipefail
umask 077

MODE="plan"
PLATFORM="linux"
INTERFACE=""
DIRECTION="both"
PROFILE="loss"
OUTPUT_PATH=""
ALLOW_INTERFACES=("rustynet0")

usage() {
  cat <<'USAGE'
usage: chaos_impair_link.sh --mode <plan|apply|clear> --interface <name> --profile <loss|delay|reorder|asym|mtu_blackhole> [options]

options:
  --platform <linux|macos|windows>      default: linux
  --direction <in|out|both>             default: both
  --allow-interface <name>              add an exact interface allow-list entry
  --output-path <path>                  write JSON manifest
USAGE
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

valid_token() {
  [[ "$1" =~ ^[A-Za-z0-9._:-]{1,64}$ ]]
}

interface_allowed() {
  local candidate="$1" allowed
  for allowed in "${ALLOW_INTERFACES[@]}"; do
    [[ "$candidate" == "$allowed" ]] && return 0
  done
  return 1
}

write_manifest() {
  local status="$1"
  local body
  body="$(cat <<JSON
{
  "schema_version": 1,
  "tool": "chaos_impair_link",
  "status": "$(json_escape "$status")",
  "mode": "$(json_escape "$MODE")",
  "platform": "$(json_escape "$PLATFORM")",
  "interface": "$(json_escape "$INTERFACE")",
  "direction": "$(json_escape "$DIRECTION")",
  "profile": "$(json_escape "$PROFILE")",
  "allowed_interfaces": "$(json_escape "${ALLOW_INTERFACES[*]}")",
  "mutates_host": $([[ "$MODE" == "apply" || "$MODE" == "clear" ]] && printf true || printf false)
}
JSON
)"
  if [[ -n "$OUTPUT_PATH" ]]; then
    mkdir -p "$(dirname "$OUTPUT_PATH")"
    printf '%s\n' "$body" > "$OUTPUT_PATH"
  else
    printf '%s\n' "$body"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --platform) PLATFORM="$2"; shift 2 ;;
    --interface) INTERFACE="$2"; shift 2 ;;
    --direction) DIRECTION="$2"; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --allow-interface) ALLOW_INTERFACES+=("$2"); shift 2 ;;
    --output-path) OUTPUT_PATH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$MODE" in plan|apply|clear) ;; *) printf 'invalid mode: %s\n' "$MODE" >&2; exit 2 ;; esac
case "$PLATFORM" in linux|macos|windows) ;; *) printf 'invalid platform: %s\n' "$PLATFORM" >&2; exit 2 ;; esac
case "$DIRECTION" in in|out|both) ;; *) printf 'invalid direction: %s\n' "$DIRECTION" >&2; exit 2 ;; esac
case "$PROFILE" in loss|delay|reorder|asym|mtu_blackhole) ;; *) printf 'invalid profile: %s\n' "$PROFILE" >&2; exit 2 ;; esac
if ! valid_token "$INTERFACE"; then
  printf 'invalid interface token: %s\n' "$INTERFACE" >&2
  exit 2
fi
if ! interface_allowed "$INTERFACE"; then
  printf 'interface is not allow-listed for chaos impairment: %s\n' "$INTERFACE" >&2
  exit 2
fi

if [[ "$MODE" == "plan" ]]; then
  write_manifest "planned"
  exit 0
fi

if [[ "$PLATFORM" != "linux" ]]; then
  printf 'apply/clear currently supports linux only; requested %s\n' "$PLATFORM" >&2
  exit 1
fi

case "$MODE" in
  apply)
    case "$PROFILE" in
      loss) tc qdisc replace dev "$INTERFACE" root netem loss 60% ;;
      delay) tc qdisc replace dev "$INTERFACE" root netem delay 200ms 100ms ;;
      reorder) tc qdisc replace dev "$INTERFACE" root netem delay 200ms 100ms reorder 25% ;;
      asym) tc qdisc replace dev "$INTERFACE" root netem loss 100% ;;
      mtu_blackhole) ip link set dev "$INTERFACE" mtu 1280 ;;
    esac
    write_manifest "applied"
    ;;
  clear)
    tc qdisc del dev "$INTERFACE" root >/dev/null 2>&1 || true
    if [[ "$PROFILE" == "mtu_blackhole" ]]; then
      ip link set dev "$INTERFACE" mtu 1420 >/dev/null 2>&1 || true
    fi
    write_manifest "cleared"
    ;;
esac
