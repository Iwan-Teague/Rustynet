# Live-Lab Script Reference

This directory contains the shell entrypoints that support the live lab. The
live-lab **engine** is the Rust-native `--node` orchestrator inside
`rustynet-cli` (`ops vm-lab-orchestrate-live-lab`); the legacy bash
orchestrator (`live_linux_lab_orchestrator.sh`) was retired under
`documents/operations/active/BashOrchestratorRetirementProgram_2026-08-22.md`
(G3 satisfied: sweep + dispositions archived in
`G3FullSweepDiff_2026-08-22.md` / `BashRetirementDispositions_2026-08-22.md`).

What remains here:

- [`live_lab_common.sh`](./live_lab_common.sh) — shared SSH/file/snapshot
  helpers, retained because the cross-network suite below sources it.
- The **cross-network suite**: the eight `live_linux_cross_network_*_test.sh`
  scripts plus `test_live_lab_ssh_windows.sh` (the only proof surface for the
  bash-era `cross_os_*` evidence; retained under the owner's Option-A scope
  decision).
- The focused `live_*` stage scripts — thin wrappers over the Rust test
  binaries of the same name (`live_linux_two_hop_test.sh` has been a two-line
  `exec cargo run` wrapper since `4f9689d9`; both engines always ran identical
  stage logic through them).
- These shell stages are Linux-runtime specific; Windows, macOS, iOS, and
  Android targets must not be routed into `live_linux_*` execution paths.

## Recommended Live-Lab Workflow

| Step | Primary wrapper | What it does |
| --- | --- | --- |
| Discover | `ops vm-lab-discover-local-utm-summary` | Finds the local UTM bundles, live IPs, SSH readiness. Use `ops vm-lab-discover-local-utm` for the full JSON report. |
| Setup | `ops vm-lab-setup-live-lab` | Runs the `--node` setup-only sequence through baseline validation into a resumable report directory (`--resume-from` / `--rerun-stage`). |
| Orchestrate | `ops vm-lab-orchestrate-live-lab --node <alias>:<role> ...` | The one-shot engine of record: discovery, restart-if-needed, setup, the full stage plan, and diagnose-on-failure in one report directory. `--stop-after-ready` exits after the readiness gate. |
| Diagnose | `ops vm-lab-diagnose-live-lab-failure` | Collects the first failed stage and packages a stage-aware forensic bundle. |

## Run Ledger

Every evidence run appends a row to
[`documents/operations/live_lab_node_run_matrix.csv`](../../documents/operations/live_lab_node_run_matrix.csv)
(the live `--node` ledger). The frozen bash archive
`documents/operations/live_lab_run_matrix.csv` is read-only history (MCP
`engine=bash_archive`); nothing appends to it anymore. Schema and status rules:
[`documents/operations/LiveLabRunMatrix.md`](../../documents/operations/LiveLabRunMatrix.md).

Do not claim OS/role/stage parity without a matching row that records the
commit, dirty state, report directory, node identity, and status — and take a
stage's pass/fail from its report artifact, never from the aliased ledger
column alone (QH-07).

To compare the stage outcomes of two runs:

```bash
cargo run -p rustynet-cli --features vm-lab -- ops vm-lab-diff-live-lab-runs --run-a <dir_a> --run-b <dir_b>
```

Automation security posture for this workflow:

- SSH host trust is pinned from the operator-supplied `known_hosts` file
- SSH TOFU / `accept-new` is not part of the active wrapper path
- the active wrapper path expects passwordless sudo (`sudo -n`) on automation targets
- unattended runtime passphrase custody remains credential-only; plaintext passphrase files are not part of the live-lab release path
- canonical cross-network pass reports require a suite-local SSH trust summary proving pinned host-key coverage and `sudo -n` for every participating target
- canonical cross-network pass reports require daemon path evidence to show `transport_socket_identity_state=authoritative_backend_shared_transport`
- canonical cross-network soak pass requires the soak to remain direct for the full duration with zero relay/fail-closed/drift samples

## Windows UTM Support Matrix

These labels describe current Rustynet wrapper support, not general Windows or
macOS platform capability.

- Supported for Windows UTM targets: `vm-lab-discover-local-utm`,
  `vm-lab-start`, `vm-lab-restart`, `vm-lab-sync-repo`, and the partial
  Windows bootstrap-phase surface for `sync-source` and `build-release`.
- Windows support here is `bootstrap-capable/scaffolded only`; see
  `documents/operations/PlatformSupportMatrix.md` for the implementation
  matrix and `BashRetirementDispositions_2026-08-22.md` B2 for the current
  evidence posture (the emulated lab guest does not reach a serviceable
  state; hardware `windows-x86-1` is the recorded unblock).
- The `scripts/e2e/live_linux_*` stage scripts remain Linux-only. Mixed
  inventories fail closed rather than inventing Debian shell assumptions for
  Windows entries.

## Related Docs

- Historical bash-orchestrator runbook:
  [`documents/archive/LiveLinuxLabOrchestrator.md`](../../documents/archive/LiveLinuxLabOrchestrator.md)
- Cross-network prerequisites: [`documents/operations/CrossNetworkLiveLabPrerequisitesChecklist.md`](../../documents/operations/CrossNetworkLiveLabPrerequisitesChecklist.md)
- Live-lab helper functions: [`live_lab_common.sh`](./live_lab_common.sh)

## Notes

- The wrappers here are shell orchestration helpers, not new security models.
- For stage-by-stage evidence details, use the live-lab runbook rather than
  this quick map.
