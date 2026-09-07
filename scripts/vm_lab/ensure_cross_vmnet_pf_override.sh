#!/usr/bin/env bash
# ensure_cross_vmnet_pf_override.sh — keep the CP-1 host pf override loaded.
#
# THE PROBLEM this fixes (MacosCrossNetworkTrafficBlocker_2026-09-03.md §9):
# the macOS lab host already forwards between its two UTM vmnet-shared /24s
# (Apple-backend macOS guest on one, QEMU guests on the other), but vmnet's
# pf anchor com.apple.internet-sharing/network_isolation drops every packet
# between them. Four `pass quick` rules loaded into com.apple/100.rustynet-lab
# (evaluated first via /etc/pf.conf's `anchor "com.apple/*"`) open the routed
# path — and vanish on every reboot. This script re-asserts them idempotently
# so a launchd job can keep them loaded.
#
# What it opens: routed IPv4 between 192.168.64.0/24 and 192.168.65.0/24 on
# the two vmnet bridges only. Nothing else. It loads NOTHING unless BOTH lab
# bridges exist (never a half topology), and it never edits /etc/pf.conf.
#
# Loading needs root. Run under sudo, or install the companion launchd job
# (scripts/launchd/com.rustynet.cross-vmnet-pf.plist) once so it self-heals:
#     sudo mkdir -p /usr/local/lib/rustynet
#     sudo install -m 0755 scripts/vm_lab/ensure_cross_vmnet_pf_override.sh \
#         /usr/local/lib/rustynet/ensure_cross_vmnet_pf_override.sh
#     sudo install -m 0644 scripts/vm_lab/cross_vmnet_pf_override.pf \
#         /usr/local/lib/rustynet/cross_vmnet_pf_override.pf
#     sudo install -m 0644 scripts/launchd/com.rustynet.cross-vmnet-pf.plist \
#         /Library/LaunchDaemons/com.rustynet.cross-vmnet-pf.plist
#     sudo launchctl bootstrap system /Library/LaunchDaemons/com.rustynet.cross-vmnet-pf.plist
# Uninstall: sudo launchctl bootout system/com.rustynet.cross-vmnet-pf;
#     sudo rm /Library/LaunchDaemons/com.rustynet.cross-vmnet-pf.plist;
#     sudo pfctl -a com.apple/100.rustynet-lab -F all   # re-blocks CP-1 now
set -euo pipefail

ANCHOR="com.apple/100.rustynet-lab"
RULES_FILE="${RUSTYNET_CROSS_VMNET_PF_RULES:-/usr/local/lib/rustynet/cross_vmnet_pf_override.pf}"
DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

# Emit the .1 gateway addresses the host owns on bridge interfaces.
discover_bridge_gateways() {
  local iface="" inet
  while IFS= read -r line; do
    case "$line" in
      bridge*:*) iface="${line%%:*}" ;;
      *inet\ 192.168.6[0-9].1\ *|*inet\ 192.168.6[0-9].1)
        inet="$(printf '%s\n' "$line" | awk '{for(i=1;i<=NF;i++) if($i=="inet") print $(i+1)}')"
        case "$inet" in
          192.168.6[0-9].1) printf '%s %s\n' "$iface" "$inet" ;;
        esac ;;
    esac
  done < <(/sbin/ifconfig)
}

have64=0; have65=0
while read -r bridge gw; do
  [ -n "$bridge" ] || continue
  case "$gw" in
    192.168.64.1) have64=1 ;;
    192.168.65.1) have65=1 ;;
  esac
done < <(discover_bridge_gateways)

if [ "$have64" != 1 ] || [ "$have65" != 1 ]; then
  echo "skip: both lab bridges (192.168.64.1 and 192.168.65.1) are not present; loading nothing"
  exit 0
fi

if [ ! -r "$RULES_FILE" ]; then
  echo "FAILED: rules file $RULES_FILE is missing or unreadable" >&2
  exit 1
fi

expected="$(grep -E '^pass quick' "$RULES_FILE" | sort)"
if [ -z "$expected" ]; then
  echo "FAILED: $RULES_FILE carries no 'pass quick' rules" >&2
  exit 1
fi

if [ "$(id -u)" != "0" ]; then
  echo "need root; run: sudo pfctl -a $ANCHOR -f $RULES_FILE" >&2
  exit 1
fi

current="$(/sbin/pfctl -a "$ANCHOR" -sr 2>/dev/null | sed 's/^[[:space:]]*//' | grep -E '^pass quick' | sort || true)"
if [ "$current" = "$expected" ]; then
  echo "ok: $ANCHOR already carries the expected rules"
  exit 0
fi

echo "FIX: $ANCHOR differs from $RULES_FILE (loaded $(printf '%s\n' "$current" | grep -c . || true) rule(s), expected $(printf '%s\n' "$expected" | grep -c .))"
if [ "$DRY_RUN" = 1 ]; then
  echo "  would run: pfctl -a $ANCHOR -f $RULES_FILE"
  exit 0
fi
/sbin/pfctl -a "$ANCHOR" -f "$RULES_FILE" 2>&1 | grep -v 'could result in flushing of rules' || true
after="$(/sbin/pfctl -a "$ANCHOR" -sr 2>/dev/null | sed 's/^[[:space:]]*//' | grep -E '^pass quick' | sort || true)"
if [ "$after" != "$expected" ]; then
  echo "FAILED verification: $ANCHOR does not match $RULES_FILE after load" >&2
  exit 1
fi
echo "loaded: $ANCHOR now carries the expected rules"
