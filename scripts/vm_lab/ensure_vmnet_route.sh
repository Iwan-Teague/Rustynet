#!/usr/bin/env bash
# ensure_vmnet_route.sh — keep the macOS host's connected route to the UTM
# vmnet-shared subnet(s) pinned to their bridge interface, so host->guest
# traffic never silently misroutes out the corporate default (en0).
#
# THE PROBLEM this fixes (observed 2026-07-11): after Shared migrations /
# power-cycles, the connected route for the vmnet subnet (192.168.64.0/24 ->
# bridge100, host gw .1) can drop out of the routing table. `route get
# 192.168.64.x` then returns the corporate default (e.g. gw 10.230.76.157 via
# en0), so lab traffic leaves out en0 and is lost. Host->guest works only for
# ~20 min via a transient ARP-cloned /32 after a guest primes ARP, then breaks
# again — the classic "loses connection, fix it differently each time".
#
# This script discovers each vmnet bridge (a bridgeN owning a 192.168.6x.1
# address) and ensures a connected /24 route points at it. Idempotent.
#
# Adding a route needs root. Run under sudo, or install the companion launchd
# job (scripts/launchd/com.rustynet.vmnet-route.plist) once so it self-heals:
#     sudo install -m 0755 scripts/vm_lab/ensure_vmnet_route.sh \
#         /usr/local/lib/rustynet/ensure_vmnet_route.sh
#     sudo install -m 0644 scripts/launchd/com.rustynet.vmnet-route.plist \
#         /Library/LaunchDaemons/com.rustynet.vmnet-route.plist
#     sudo launchctl bootstrap system /Library/LaunchDaemons/com.rustynet.vmnet-route.plist
set -euo pipefail

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

# Emit "<bridge> <subnet-cidr>" for every vmnet-shared bridge (owns .1 of a
# 192.168.6x.0/24). Robust to bridge100/bridge101/etc.
discover_vmnet_bridges() {
  local ifc iface="" inet
  while IFS= read -r line; do
    case "$line" in
      bridge*:*) iface="${line%%:*}" ;;
      *inet\ 192.168.6[0-9].1\ *|*inet\ 192.168.6[0-9].1)
        # extract the .1 address, derive the /24 network
        inet="$(printf '%s\n' "$line" | awk '{for(i=1;i<=NF;i++) if($i=="inet") print $(i+1)}')"
        case "$inet" in
          192.168.6[0-9].1)
            printf '%s %s.0/24\n' "$iface" "${inet%.*}" ;;
        esac ;;
    esac
  done < <(/sbin/ifconfig)
}

changed=0
while read -r bridge subnet; do
  [ -n "$bridge" ] && [ -n "$subnet" ] || continue
  probe_ip="${subnet%.0/24}.2"
  # Does a lookup for an address in this subnet already resolve to the bridge?
  cur_if="$(/sbin/route -n get "$probe_ip" 2>/dev/null | awk '/interface:/{print $2}')"
  if [ "$cur_if" = "$bridge" ]; then
    echo "ok: $subnet already routes via $bridge"
    continue
  fi
  echo "FIX: $subnet resolves via '${cur_if:-<none>}', not $bridge"
  if [ "$DRY_RUN" = 1 ]; then
    echo "  would run: route -n add -net $subnet -interface $bridge"
    continue
  fi
  if [ "$(id -u)" != "0" ]; then
    echo "  need root; run: sudo route -n add -net $subnet -interface $bridge" >&2
    continue
  fi
  # Replace any stale entry, then add the connected route to the bridge.
  /sbin/route -n delete -net "$subnet" >/dev/null 2>&1 || true
  /sbin/route -n add -net "$subnet" -interface "$bridge"
  changed=$((changed+1))
done < <(discover_vmnet_bridges)

echo "ensure_vmnet_route: $changed route(s) added"
