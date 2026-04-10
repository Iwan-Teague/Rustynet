# Live-Lab Orchestrator Function Reference

This directory contains the shell entrypoints that drive the live Linux lab.
The main orchestrator is [`live_linux_lab_orchestrator.sh`](./live_linux_lab_orchestrator.sh),
with shared SSH, file, and snapshot helpers in [`live_lab_common.sh`](./live_lab_common.sh).

Use this README as a quick map of the orchestration functions, especially the
high-level wrappers that compose many lower-level stages into one operator-facing flow.

## Recommended Live-Lab Workflow

Start here when you want to bring up and exercise a local UTM-backed lab end to
end.

| Step | Primary wrapper | What it does |
| --- | --- | --- |
| Discover | `ops vm-lab-discover-local-utm-summary` | Finds the local UTM bundles, live IPs, SSH readiness, and the fastest setup summary. Use `ops vm-lab-discover-local-utm` when you need the full JSON report. |
| Setup | `stage_run_fresh_bootstrap_and_network_setup` | Installs Rustynet on the selected nodes, boots the shared network, and enforces the baseline runtime state. |
| Link and Test | `ops vm-lab-run-live-lab` | Runs the full live-lab suite against the prepared topology. Use `stage_run_extended_soak` afterward when you want the longer resilience and reboot-recovery coverage. |
| Diagnose | `ops vm-lab-diagnose-live-lab-failure` | Collects the first failed stage and packages the useful failure context for triage. |

This is the recommended operator path: discover, set up, link and test, then
diagnose if something fails.

## How The Orchestrator Works

- `run_stage` wraps a stage with logging, summary recording, failure-digest refresh, and optional forensics capture.
- `run_parallel_node_stage` fans a worker across the selected nodes and writes per-node `results.tsv` evidence.
- `run_serial_node_stage` executes a stage one node at a time when a single authority is required.
- Most higher-level helpers are composition wrappers. They do not invent new dataplane behavior; they sequence the existing hardened stages in a consistent order.

## Supporting Shell Wrappers

These are useful shell orchestration helpers after the primary workflow above.

| Function | What it composes | When to use |
| --- | --- | --- |
| `stage_run_extended_soak` | Pre-soak two-hop validation, exit-handoff validation, LAN toggle validation, reboot recovery, and the managed-DNS refresh steps between them | Long-running resilience and reboot-recovery evidence after the baseline is healthy |
| `stage_run_cross_network_preflight` | Time, process, socket, permissions, DNS, route-policy, signed-state, and discovery-bundle readiness checks | Before any cross-network mutation or soak stage |
| `stage_run_live_role_switch_matrix` | Controlled role-switch validation across the full five-node topology | When you need release-gate role-switch evidence |
| `stage_run_live_exit_handoff` | Live exit failover evidence on a topology with entry and aux peers | When you want handoff proof without the full soak path |
| `stage_run_live_two_hop` | Two-hop proof using entry and aux peers | When you need relay-path validation or a narrower live-path check |
| `stage_run_live_lan_toggle` | Blind-exit / LAN-access toggle proof | When you need to confirm the client can move between the direct and blind-exit path safely |
| `stage_run_live_managed_dns` | Managed-DNS live validation | When you need DNS issuance, refresh, and fail-closed behavior evidence |
| `stage_run_reboot_recovery_report` | Exit reboot, client reboot, post-reboot DNS refresh, and post-reboot path checks | When you need a dedicated recovery artifact without the full soak wrapper |

## Supporting Rust CLI Wrappers

The preferred operator-facing entrypoints are in `rustynet-cli`; the shell
orchestrator remains the execution engine behind them.

| Command | What it does | When to use |
| --- | --- | --- |
| `ops vm-lab-write-live-lab-profile` | Generates a non-interactive live-lab profile from inventory-backed VM aliases or explicit SSH targets | First step for any repeatable live-lab run |
| `ops vm-lab-validate-live-lab-profile` | Verifies the generated profile is internally consistent and matches the expected backend/source-mode/topology | Before a run when profile or provenance correctness matters |
| `ops vm-lab-iterate-live-lab` | Runs typed local validation, writes the profile, performs preflight, launches the reduced live-lab flow, and prints the first failed stage on error | Narrow iteration loop while debugging a red live-lab stage |
| `ops vm-lab-diff-live-lab-runs` | Compares two report directories and shows the first divergent stage outcome | When a patch moves the blocker and you want a quick regression/progression diff |
| `ops vm-lab-bootstrap-phase --phase all` | Runs the reusable Rust bootstrap pipeline across the selected VM set: sync source, build release, install release, restart runtime, verify runtime | Fresh-install or rebuild-only workflow when you want provisioning without the full live-lab test suite |
| `ops vm-lab-preflight` | Verifies SSH reachability, sudo, free disk, and required commands | Standalone readiness check before provisioning or a live-lab run |
| `ops vm-lab-discover-local-utm` | Automatically scans the local UTM documents tree, resolves live IPs, and reports SSH port/process readiness for every discovered bundle | Use when you want the full machine-discovered local UTM lab inventory |
| `ops vm-lab-restart --wait-ready` | Restarts the selected local UTM VMs and waits for process presence, live IP resolution, SSH port-open state, and SSH auth readiness | Recovery path when discovery knows the VMs but they are not yet actually reachable over SSH |
| `ops vm-lab-status` | Captures per-node runtime and service status snapshots | Fast point-in-time inspection outside the failure-diagnostics wrapper |

The four entries above the fold are the recommended operator path:
`ops vm-lab-discover-local-utm-summary`, `stage_run_fresh_bootstrap_and_network_setup`,
`ops vm-lab-run-live-lab`, and `ops vm-lab-diagnose-live-lab-failure`.

## Recommended Workflows

Use the smallest wrapper set that matches the task:

| Goal | Preferred wrapper flow |
| --- | --- |
| Fresh install all selected Rustynet nodes | `ops vm-lab-bootstrap-phase --phase all` |
| Fresh install plus baseline and the full standard live suite | `ops vm-lab-write-live-lab-profile` -> `ops vm-lab-validate-live-lab-profile` -> `ops vm-lab-run-live-lab` |
| Reduced repeatable debug loop for a failing live-lab stage | `ops vm-lab-iterate-live-lab` |
| Investigate a red run after completion | `ops vm-lab-diagnose-live-lab-failure` and optionally `ops vm-lab-diff-live-lab-runs` |

Minimal three-command live-lab path:

| Step | Preferred command |
| --- | --- |
| Fresh install and bootstrap all selected nodes | `ops vm-lab-bootstrap-phase --phase all` |
| Configure the topology and run the full setup plus test sequence | `ops vm-lab-write-live-lab-profile` -> `ops vm-lab-validate-live-lab-profile` -> `ops vm-lab-run-live-lab` |
| Gather a stage-aware forensic bundle after a red run | `ops vm-lab-diagnose-live-lab-failure` |

Current usage in this repo:

- We have been using `ops vm-lab-write-live-lab-profile`, `ops vm-lab-validate-live-lab-profile`, and `ops vm-lab-run-live-lab` for the current five-node UTM lab work.
- `ops vm-lab-diagnose-live-lab-failure` is now the preferred post-failure collection path because it packages the failed stage context and targeted diagnostics into one bundle.
- The current blocker is inside the orchestration behavior reached by `ops vm-lab-run-live-lab`, not because these wrapper commands are missing.

## Primitive Building Blocks

These are useful when you need to isolate a failure or rerun one part of the flow.

- `stage_prepare_source_archive`
- `stage_verify_ssh_reachability`
- `prime_remote_access`
- `stage_cleanup_hosts`
- `stage_bootstrap_hosts`
- `stage_collect_pubkeys`
- `stage_membership_setup`
- `stage_distribute_membership_state`
- `stage_issue_and_distribute_assignments`
- `stage_issue_and_distribute_traversal`
- `stage_enforce_baseline_runtime`
- `stage_validate_baseline_runtime`

## Related Docs

- Live-lab runbook: [`documents/operations/LiveLinuxLabOrchestrator.md`](../../documents/operations/LiveLinuxLabOrchestrator.md)
- Cross-network prerequisites: [`documents/operations/CrossNetworkLiveLabPrerequisitesChecklist.md`](../../documents/operations/CrossNetworkLiveLabPrerequisitesChecklist.md)
- Live-lab helper functions: [`live_lab_common.sh`](./live_lab_common.sh)

## Notes

- The wrappers here are shell orchestration helpers, not new security models.
- They keep the existing hard-fail stage accounting, logs, and failure-digest behavior intact.
- For stage-by-stage evidence details, use the live-lab runbook rather than this quick map.
