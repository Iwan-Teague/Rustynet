
## 2026-09-07 04:15Z — STEP 3b: record reboot-failure stub remedy, then relaunch (attempt 2/final)
- Tree clean at b4c30979. Recording patch for stub `livelab-1788753367-2498a83338cc::validate_macos_reboot_recovery` via target-pinned CLI, then committing ledger, then mac SSH preflight, then launching attempt 2.

## 2026-09-07 04:15Z — STEP 3 attempt 2 (FINAL) launch
- Stub remedy recorded + committed (b2eeb5d5). Mac preflight OK (macs-Virtual-Machine.local, skew 0s).
- Launching: RD=state/live-lab-macos-reboot-20260907-041501, topology macos-utm-1:client debian-headless-4:exit debian-headless-2:client, --reboot-platform macos --skip-linux-live-suite --linux-backend linux-wireguard-userspace-shared --source-mode local-head --trust-inventory-ready --skip-soak --collect-artifacts-on-failure.

### 2026-09-07T04:19Z — STEP 3 reboot attempt 2: FINAL relaunch (gate cured)
Stub remedy now recorded in the provenance-worktree ledger (28885-0) the gate reads. Fresh RD (041501 holds only a refusal log). Launching:
`RD=state/live-lab-macos-reboot-$(date -u +%Y%m%d-%H%M%S); mkdir -p $RD; nohup /Users/iwan/Desktop/Rustynet/target-pinned/debug/rustynet-cli ops vm-lab-orchestrate-live-lab --node macos-utm-1:client --node debian-headless-4:exit --node debian-headless-2:client --reboot-platform macos --skip-linux-live-suite --linux-backend linux-wireguard-userspace-shared --source-mode local-head --trust-inventory-ready --skip-soak --collect-artifacts-on-failure --known-hosts-file ~/.ssh/known_hosts_lab --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 --inventory documents/operations/active/vm_lab_inventory.json --report-dir $RD > $RD.launch.log 2>&1 & disown`
Verdict source: $RD/logs/validate_macos_reboot_recovery.log + $RD/state/stages.tsv only.

## 2026-09-07 04:35Z — STEP 3 reboot attempt 2 RESULT: FAIL (new root cause) + fix plan

- Run livelab-1788755496-b4c3097999cd, RD state/live-lab-macos-reboot-20260907-041909, PID 9208, 04:19:33→04:31:36Z.
- stages.tsv: prepare_source_archive/verify_ssh/cleanup/bootstrap_hosts/cross_network_substrate_setup/collect_pubkeys/distribute_assignments/distribute_traversal/distribute_dns_zone/enforce_baseline_runtime/validate_baseline_runtime ALL pass. BSD-stat fix (b4c30979) HELD — pre-reboot evidence capture passed this time.
- validate_macos_reboot_recovery FAIL rc=1: `macos-utm-1: shutdown -r now dispatched but exited non-zero (exit status: 255) on macos-utm-1`.
- teardown soft pass, cleanup pass. Launch log: 0 "evidence finalization failed". Matrix row appended to the 28885-0 provenance worktree's CSV (row 331) — same cross-worktree ledger resolution as enforce_launch_gate (pinned binary built from 28885-0 resolves ledgers there).
- PROOF THE MAC ACTUALLY REBOOTED: post-run SSH check 04:32Z → `macs-Virtual-Machine.local up 2 mins`. The reboot happened; the stage misclassified it.
- Root cause mod.rs:15195-15205: dispatch tolerates `Err(_)` (channel death) but macOS ssh returns `Ok(status=255)` when remote closes channel mid-command; 255 unhandled → false failure.
- Fix (in scope: vm_lab stage code; no run in flight): add arm `Ok(status) if status.code() == Some(255) => {}` with comment. Then scoped gates, commit, record stub remedy (new stub `livelab-1788755496-b4c3097999cd::validate_macos_reboot_recovery`) in BOTH ledgers (this worktree + 28885-0 provenance).
- Attempt accounting: 2 real attempts used (034405, 041909). No attempt 3 for reboot cell. Moving to STEP 4 anchor after fix+records.
