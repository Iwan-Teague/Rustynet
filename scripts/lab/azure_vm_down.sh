#!/usr/bin/env bash
# Deallocate the Azure lab VM now and drop the lease.
set -u
RG="${AZ_RG:-RG-STUDENT-VM}"; VM="${AZ_VM:-student-vm}"
STATE="${AZ_GUARD_STATE:-$HOME/rustysuite-fleet/state}"; mkdir -p "$STATE"
rm -f "$STATE/azure-vm.lease"
printf '%s deallocate requested (azure_vm_down)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$STATE/azure-guard.log"
az vm deallocate -g "$RG" -n "$VM" "${@}" || { echo "az vm deallocate failed" >&2; exit 1; }
echo "VM $VM deallocated."
