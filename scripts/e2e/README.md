# Live-Lab Orchestrator Function Reference

This directory contains the shell entrypoints that drive the live Linux lab.
The main orchestrator is [`live_linux_lab_orchestrator.sh`](./live_linux_lab_orchestrator.sh),
with shared SSH, file, and snapshot helpers in [`live_lab_common.sh`](./live_lab_common.sh).
These shell stages are Linux-runtime specific; Windows, macOS, iOS, and Android
targets must not be routed into `live_linux_*` execution paths.

Use this README as a quick map of the orchestration functions, especially the
high-level wrappers that compose many lower-level stages into one operator-facing flow.

## Recommended Live-Lab Workflow

Start here when you want to bring up and exercise a local UTM-backed lab end to
end.

| Step | Primary wrapper | What it does |
| --- | --- | --- |
| Discover | `ops vm-lab-discover-local-utm-summary` | Finds the local UTM bundles, live IPs, SSH readiness, and the fastest setup summary. Use `ops vm-lab-discover-local-utm` when you need the full JSON report. |
| Setup | `ops vm-lab-setup-live-lab` | Generates or validates the live-lab profile, runs the setup-only sequence through baseline validation, and writes a resumable report directory. |
| Link and Test | `ops vm-lab-run-live-lab` | Runs the full live-lab suite, validates the report contract, and automatically continues from a setup-only report directory when setup already completed. |
| Diagnose | `ops vm-lab-diagnose-live-lab-failure` | Collects the first failed stage and packages a stage-aware forensic bundle for triage. |

This is the recommended operator path: discover, set up, link and test, then
diagnose if something fails.

Automation security posture for this workflow:

- SSH host trust is pinned from the operator-supplied `known_hosts` file
- SSH TOFU / `accept-new` is not part of the active wrapper path
- the active wrapper path expects passwordless sudo (`sudo -n`) on automation targets
- unattended runtime passphrase custody remains credential-only; plaintext passphrase files are not part of the live-lab release path
- canonical cross-network pass reports now require a suite-local SSH trust summary proving pinned host-key coverage and `sudo -n` for every participating target
- canonical cross-network pass reports now require daemon path evidence to show `transport_socket_identity_state=authoritative_backend_shared_transport`
- canonical cross-network soak pass now requires the soak to remain direct for the full duration with zero relay/fail-closed/drift samples

## Windows UTM Support Matrix

The Rust CLI now treats mixed Linux/Windows inventories as explicit rather than
implicitly Linux-only:

These labels describe current Rustynet wrapper support, not general Windows or
macOS platform capability.

- Supported for Windows UTM targets: `vm-lab-discover-local-utm`,
  `vm-lab-start`, `vm-lab-restart`, `vm-lab-sync-repo`, and the partial
  Windows bootstrap-phase surface for `sync-source` and `build-release`.
- Windows support here is `bootstrap-capable/scaffolded only`. The Windows
  provider and helper roots are real and platform-aware, but Windows
  `install-release` is still a protective stub, `build-release` remains subject
  to verified MSVC/toolchain preconditions, and `restart-runtime`,
  `verify-runtime`, and `all` are not runtime-capable proof on the current
  branch.
- Intentionally blocked for Windows UTM targets: `vm-lab-validate-live-lab-profile`,
  `vm-lab-setup-live-lab`, `vm-lab-run-live-lab`,
  `vm-lab-orchestrate-live-lab`, `vm-lab-iterate-live-lab`,
  `vm-lab-run-suite`, and `vm-lab-diagnose-live-lab-failure`.
- The `scripts/e2e/live_linux_*` stage scripts remain Linux-only until a
  Windows stage implementation exists. Mixed inventories can still live in the
  repo, but the Linux live-lab wrappers fail closed instead of inventing Debian
  shell assumptions for Windows entries. Those wrappers require explicit
  `platform=linux`, `remote_shell=posix`, `guest_exec_mode=linux_bash`, and
  `service_manager=systemd` metadata before execution starts.
- Linux UTM targets continue to use the existing shell orchestrator path.

## Capability Reporting Gap

The top-level wrappers still enforce a coarse Linux-only boundary for the live
setup/run/orchestrate flow. That is deliberate and fail-closed, but the wrapper
surface already knows more than it currently reports because several
sub-capabilities are platform-aware or partially implemented.

The wrapper-support expectations in this section are separate from the
implementation support matrix in
[`documents/operations/PlatformSupportMatrix.md`](../../documents/operations/PlatformSupportMatrix.md).

The documentation target is to move toward explicit capability reporting for
each command and stage, without changing the current support truth:

- `supported`
- `partially supported`
- `unsupported`

The capability explanation should cover the command, stage or phase, source
mode, platform mix, and the blocking requirements. The proposed machine-readable
artifact is `state/platform_capabilities.json`; a dedicated inspection command
would be a useful follow-up, but it is not required for the current execution
path.

Until that reporting layer exists, the existing Linux-only execution guards and
their fail-closed errors remain the source of truth for the operator path.

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
| `ops vm-lab-setup-live-lab` | Drives the setup-only live-lab pipeline, emits structured JSON, and supports `--resume-from` and `--rerun-stage` for setup-stage recovery | Preferred operator entrypoint for repeatable lab setup without immediately running the full suite |
| `ops vm-lab-orchestrate-live-lab` | Discovers selected local UTM VMs, restarts only the aliases that are not execution-ready, reruns discovery, then drives setup, run, and diagnose-on-failure in one report directory. `--stop-after-ready` exits after the readiness gate when you only need VM recovery proof. | Preferred one-shot wrapper when the operator wants recovery plus the standard live-lab workflow without manual branching |
| `ops vm-lab-run-live-lab` | Runs the full live-lab suite, validates required report artifacts, and can continue from an existing setup-only report directory | Preferred operator entrypoint for the full suite after setup is complete |
| `ops vm-lab-iterate-live-lab` | Runs typed local validation, writes the profile, launches the reduced live-lab flow, and prints the first failed stage on error | Narrow iteration loop while debugging a red live-lab stage |
| `ops vm-lab-diff-live-lab-runs` | Compares two report directories and shows the first divergent stage outcome | When a patch moves the blocker and you want a quick regression/progression diff |
| `ops vm-lab-bootstrap-phase --phase all` | Runs the reusable Rust bootstrap pipeline across the selected VM set: sync source, build release, install release, restart runtime, verify runtime. On the current branch, treat this as a Linux-runtime workflow; Windows guests use only the narrower verified `sync-source` and `build-release` phases plus explicit diagnostics. | Fresh-install or rebuild-only workflow when you want provisioning without the full live-lab test suite |
| `ops vm-lab-preflight` | Verifies SSH reachability, sudo, free disk, and required commands | Standalone readiness check before provisioning or a live-lab run |
| `ops vm-lab-discover-local-utm` | Automatically scans the local UTM documents tree, resolves live IPs, and reports SSH port/process readiness for every discovered bundle. `--update-inventory-live-ips` persists the refreshed IPs only when the whole matched set is execution-ready. | Use when you want the full machine-discovered local UTM lab inventory |
| `ops vm-lab-restart --wait-ready` | Restarts the selected local UTM VMs, waits for process presence, live IP resolution, SSH port-open state, and SSH auth readiness, then refreshes the inventory IP fields on success. `--json` and `--report-dir` add machine-readable result and artifact output. | Recovery path when discovery knows the VMs but they are not yet actually reachable over SSH |
| `ops vm-lab-status` | Captures per-node runtime and service status snapshots | Fast point-in-time inspection outside the failure-diagnostics wrapper |

The four entries above the fold are the recommended operator path:
`ops vm-lab-discover-local-utm-summary`, `ops vm-lab-setup-live-lab`,
`ops vm-lab-run-live-lab`, and `ops vm-lab-diagnose-live-lab-failure`.

`ops vm-lab-orchestrate-live-lab` is the optional one-shot wrapper that
automates the common discovery -> restart-if-needed -> setup -> run ->
diagnose-on-failure decision tree.

## Recommended Workflows

Use the smallest wrapper set that matches the task:

| Goal | Preferred wrapper flow |
| --- | --- |
| Fresh install all selected Linux Rustynet nodes | `ops vm-lab-bootstrap-phase --phase all` |
| Prepare a Windows UTM guest without claiming runtime parity | `ops vm-lab-sync-repo` -> `ops vm-lab-bootstrap-phase --phase sync-source` -> `ops vm-lab-bootstrap-phase --phase build-release` |
| Fresh install plus baseline and the full standard live suite | `ops vm-lab-setup-live-lab` -> `ops vm-lab-run-live-lab` |
| One command that recovers unready local UTM VMs and then runs the standard live-lab flow | `ops vm-lab-orchestrate-live-lab` |
| Reduced repeatable debug loop for a failing live-lab stage | `ops vm-lab-iterate-live-lab` |
| Investigate a red run after completion | `ops vm-lab-diagnose-live-lab-failure` and optionally `ops vm-lab-diff-live-lab-runs` |

Minimal four-command live-lab path:

| Step | Preferred command |
| --- | --- |
| Discover local UTM state and SSH readiness | `ops vm-lab-discover-local-utm-summary` |
| Configure the topology and complete setup-only stages | `ops vm-lab-setup-live-lab` |
| Run the full live-lab suite | `ops vm-lab-run-live-lab` |
| Gather a stage-aware forensic bundle after a red run | `ops vm-lab-diagnose-live-lab-failure` |

Current usage in this repo:

- We now use `ops vm-lab-setup-live-lab` plus `ops vm-lab-run-live-lab` as the primary operator path for the current five-node UTM lab work.
- `ops vm-lab-diagnose-live-lab-failure` is now the preferred post-failure collection path because it packages the failed stage context and targeted diagnostics into one bundle.
- The lower-level profile and preflight helpers still exist when you need tighter control over one slice of the workflow.

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
