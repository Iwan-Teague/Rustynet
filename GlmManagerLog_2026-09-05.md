
## 2026-09-07 04:15Z — STEP 3b: record reboot-failure stub remedy, then relaunch (attempt 2/final)
- Tree clean at b4c30979. Recording patch for stub `livelab-1788753367-2498a83338cc::validate_macos_reboot_recovery` via target-pinned CLI, then committing ledger, then mac SSH preflight, then launching attempt 2.

## 2026-09-07 04:15Z — STEP 3 attempt 2 (FINAL) launch
- Stub remedy recorded + committed (b2eeb5d5). Mac preflight OK (macs-Virtual-Machine.local, skew 0s).
- Launching: RD=state/live-lab-macos-reboot-20260907-041501, topology macos-utm-1:client debian-headless-4:exit debian-headless-2:client, --reboot-platform macos --skip-linux-live-suite --linux-backend linux-wireguard-userspace-shared --source-mode local-head --trust-inventory-ready --skip-soak --collect-artifacts-on-failure.

### 2026-09-07T04:19Z — STEP 3 reboot attempt 2: FINAL relaunch (gate cured)
Stub remedy now recorded in the provenance-worktree ledger (28885-0) the gate reads. Fresh RD (041501 holds only a refusal log). Launching:
`RD=state/live-lab-macos-reboot-$(date -u +%Y%m%d-%H%M%S); mkdir -p $RD; nohup /Users/iwan/Desktop/Rustynet/target-pinned/debug/rustynet-cli ops vm-lab-orchestrate-live-lab --node macos-utm-1:client --node debian-headless-4:exit --node debian-headless-2:client --reboot-platform macos --skip-linux-live-suite --linux-backend linux-wireguard-userspace-shared --source-mode local-head --trust-inventory-ready --skip-soak --collect-artifacts-on-failure --known-hosts-file ~/.ssh/known_hosts_lab --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 --inventory documents/operations/active/vm_lab_inventory.json --report-dir $RD > $RD.launch.log 2>&1 & disown`
Verdict source: $RD/logs/validate_macos_reboot_recovery.log + $RD/state/stages.tsv only.
