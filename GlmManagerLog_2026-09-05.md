
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

## 2026-09-07 04:38Z — STEP 4 launch: macOS anchor re-proof cell

- Fix 1ff7d04a committed (ssh-255 arm, check+17 reboot tests+fmt green). Stub livelab-1788755496-b4c3097999cd::validate_macos_reboot_recovery remedied in 28885-0 provenance ledger (gate-read path). This worktree's ledger has no such stub — nothing to commit here.
- TOPOLOGY (Rust --node form, explicit anchor election): macos-utm-1:anchor, debian-headless-4:exit, debian-headless-2:client. No --anchor-platform (mutually exclusive with --node per MCP routing rules; :anchor role is the engine-native election).
- RD=state/live-lab-macos-anchor-20260907-043830 (mkdir -p before nohup). Same base flags as reboot run minus --reboot-platform, keep --skip-linux-live-suite --skip-soak --collect-artifacts-on-failure --source-mode local-head --trust-inventory-ready --linux-backend linux-wireguard-userspace-shared + full SSH/inventory flags.
- Verdict source: logs/validate_macos_anchor_*.log (all MacosAnchor* stages) + stages.tsv only.
- Mac guest confirmed on SSH (up 2 mins after its reboot, hostname answers).

## 2026-09-07T04:52Z — STEP 4 anchor re-proof: PASS

Run `livelab-1788756583-b4c3097999cd`, RD `state/live-lab-macos-anchor-20260907-043630`, PID 15067, 04:36:59→04:49:43Z. run_passed=true (report_state.json). 20 pass / 0 fail / 2 legit skips (admin_issue, blind_exit — not elected). All four anchor stages hard-pass: anchor_validation, deploy_macos_anchor_profile, validate_macos_anchor_bundle_pull, validate_macos_anchor_port_mapping_authority. 0 'evidence finalization failed'. Matrix row appended → 28885-0 provenance ledger (332nd row, macos_anchor=pass; pinned binary appends to its build-worktree CSV). Mac guest SSH OK post-run (macs-Virtual-Machine.local, up 20 min). Refresh doc anchor cell updated with re-proof entry (row already 🟢 from 2026-09-05; this re-proves on current tree).

## STATUS 2026-09-07T04:52Z

DONE:
- STEP 2 macOS role-transition cell: GREEN + recorded (livelab-1788752486-6d3fea6cf2aa).
- STEP 3 macOS reboot-recovery: 2 real attempts, both FAIL on lab-tooling, both root-caused + fixed + stub-remedied (b4c30979 BSD stat; 1ff7d04a ssh-255). Attempt 2 PROVED the Mac actually rebooted (uptime 2 min post-run) — false failure in dispatch status handling. Attempts exhausted; Refresh row stays red; fixes need a future run to prove (pinned binary must be rebuilt with 1ff7d04a first).
- STEP 4 anchor re-proof: PASS + recorded (livelab-1788756583-b4c3097999cd).
- CP-1 (not loaded): macOS↔Linux dataplane stages never ran this session — by instruction.

NOT DONE / OPEN:
- reboot-recovery macOS row still 🔴 (2 tooling-caused false failures; both fixes committed but unproven by a green run).

### MERGE NOTE (for the owner)

Commits since 092e94cf, grouped:

(a) Lab-tooling fixes + proving live run:
- 61983773 finalizer plan derivation (proved by run 032942 full pass)
- 6d3fea6c manifest selectors snapshot (proved by run 032942)
- b4c30979 BSD stat 600|0600 (proved by run 041909: pre-reboot capture passed)
- 1ff7d04a ssh-255 shutdown-dispatch acceptance (run 041909 proved Mac rebooted; fix itself UNPROVEN by a green run — rebuild pinned binary + rerun when convenient)
- (pre-092e94cf-history in ledger commits: a0b29f83 relay ss parser, 6228d1d6 privileged status probe)

(b) Ledger/doc records:
- 2498a833, 664d28ea, 981c9231, 3b1b4a38, 5ec4e99a, b2eeb5d5, 031e8f64, a134f76e, 4a71fb44, a81baad8, 4aca5d01, + this commit
- 5a4df786, e88bbe76, 0d389d35, 774a7f7a, 01b9bdcb (earlier fwd-run rows), 160ee56c, 38470603, 9b654b13, 1778258b, d5864aae, 60ad3f9f, 82d733f9, d6a64963, a746051c, b9887739, b319b2d9, 002aabc1, a1e190ab (fwd-series logs/stubs)

(c) Open owner decisions:
- relay frame-forwarding: blocked on stale traversal/dns bundles after live_reboot_recovery (trust-state refresh — PROPOSED only, never edited; see fwd8e verdict 160ee56c / a1e190ab)
- QH-70 (open)
- CP-1 pf override persistence: not loaded this session → macOS↔Linux dataplane stages (traffic_test_matrix/two_hop/managed_dns/relay-through-mac) OFF
- 28885-0 ledger divergence: pinned binary resolves stage-triage ledger + appends matrix rows to its BUILD worktree (edit-1788746785362-28885-0). Three cross-worktree stub remedies recorded there (BSD-stat, ssh-255, + earlier) and rows 331/332 landed in its CSV. Owner must reconcile ledgers/CSVs when merging this branch.
