#!/usr/bin/env bash
# Start the Azure lab VM for work and take a lease so the hourly guard leaves it
# alone. Usage: azure_vm_up.sh [hours]   (default 3, max 8)
# The lease is a safety net, not a plan: end every session with azure_vm_down.sh.
set -u
RG="${AZ_RG:-RG-STUDENT-VM}"; VM="${AZ_VM:-student-vm}"
STATE="${AZ_GUARD_STATE:-$HOME/rustysuite-fleet/state}"; mkdir -p "$STATE"
H="${1:-3}"
case "$H" in ''|*[!0-9]*) echo "hours must be a whole number" >&2; exit 2 ;; esac
[ "$H" -ge 1 ] && [ "$H" -le 8 ] || { echo "hours must be 1-8" >&2; exit 2; }
echo $(( $(date +%s) + H * 3600 )) > "$STATE/azure-vm.lease"
printf '%s lease %sh taken; starting %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$H" "$VM" >> "$STATE/azure-guard.log"
az vm start -g "$RG" -n "$VM" || { echo "az vm start failed" >&2; rm -f "$STATE/azure-vm.lease"; exit 1; }
echo "VM $VM started; lease for ${H}h. Run azure_vm_down.sh when done."
