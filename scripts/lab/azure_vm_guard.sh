#!/usr/bin/env bash
# Keep the Azure lab VM OFF unless it is doing rustysuite work.
#
# The VM (resource group RG-STUDENT-VM, VM student-vm) runs on student credit and
# is used only for Rustynet live-lab runs. This guard deallocates it (the state
# that stops compute billing; a plain stop keeps the allocation and the charge)
# whenever it is running and NOT in use. "In use" means either:
#   - a live-lab orchestrator on the lab host names azure-vm-1 (an active run), or
#   - an explicit lease written by azure_vm_up.sh has not expired.
# Unreadable state fails toward OFF for billing, but a failed power-state read is
# logged and notified, never silent.
#
# Usage: azure_vm_guard.sh [--dry-run]
# Env:   AZ_RG, AZ_VM, AZ_GUARD_STATE (state dir), AZ_GUARD_KATANA (ssh target of the
#        lab host), AZ_GUARD_NOTIFY=0 to silence desktop notifications.
# Exit:  0 ok (off, in use, or deallocated), 2 could not read the VM state.
set -u

RG="${AZ_RG:-RG-STUDENT-VM}"
VM="${AZ_VM:-student-vm}"
STATE="${AZ_GUARD_STATE:-$HOME/rustysuite-fleet/state}"
KATANA="${AZ_GUARD_KATANA:-debian@100.122.143.29}"
LEASE="$STATE/azure-vm.lease"
LOG="$STATE/azure-guard.log"
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1
mkdir -p "$STATE"

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG"; }
notify() {
  [ "${AZ_GUARD_NOTIFY:-1}" = "1" ] || return 0
  command -v osascript >/dev/null 2>&1 || return 0
  osascript -e "display notification \"$1\" with title \"Azure lab VM guard\"" >/dev/null 2>&1 || true
}

power="$(az vm get-instance-view -g "$RG" -n "$VM" \
  --query "instanceView.statuses[?starts_with(code,'PowerState/')].code | [0]" -o tsv 2>/dev/null)"
if [ -z "$power" ]; then
  log "ERROR cannot read power state of $VM (az not logged in, offline, or VM missing)"
  notify "Cannot read the VM state: run 'az login'. The VM may be running."
  exit 2
fi

case "$power" in
  PowerState/deallocated|PowerState/deallocating)
    log "ok: $VM is $power (nothing to do)"
    exit 0 ;;
  PowerState/running|PowerState/starting|PowerState/stopped|PowerState/stopping) ;;
  *) log "WARN unexpected power state '$power'; treating as running" ;;
esac

in_use=""
now="$(date +%s)"
if [ -r "$LEASE" ]; then
  exp="$(tr -dc '0-9' < "$LEASE")"
  if [ -n "$exp" ] && [ "$now" -lt "$exp" ]; then
    in_use="lease until $(date -u -r "$exp" +%H:%MZ 2>/dev/null || echo "$exp")"
  fi
fi
if [ -z "$in_use" ]; then
  # An active run on the lab host. Pattern is bracketed so the remote shell's own
  # command line cannot match itself (pgrep -f self-match over ssh).
  for attempt in 1 2 3; do
    out="$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$KATANA" \
      "pgrep -f '[v]m-lab-orchestrate-live-lab.*azure-vm-1'; echo rc=\$?" 2>/dev/null)" && break
    out=""
    sleep 3
  done
  case "$out" in
    *rc=0*) in_use="active live-lab run on the lab host" ;;
    "")     log "WARN lab host unreachable; assuming no active run" ;;
  esac
fi

if [ -n "$in_use" ]; then
  log "keep: VM $power, in use ($in_use)"
  exit 0
fi

if [ "$DRY" = 1 ]; then
  log "dry-run: would deallocate $VM ($power, not in use)"
  echo "would deallocate $VM ($power, not in use)"
  exit 0
fi
log "DEALLOCATE $VM: $power and not in use"
if az vm deallocate -g "$RG" -n "$VM" --no-wait >/dev/null 2>&1; then
  rm -f "$LEASE"
  notify "Azure VM was running with no work: deallocating it."
else
  log "ERROR az vm deallocate failed"
  notify "Azure VM is running with no work and the deallocate FAILED."
  exit 2
fi
exit 0
