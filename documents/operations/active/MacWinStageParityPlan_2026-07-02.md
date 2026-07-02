# macOS/Windows Stage Parity Plan

**Date:** 2026-07-02
**Status:** Active
**Owner:** Live lab agent

## Problem

Linux has 36 matrix columns (21 stage + 15 one-off), macOS and Windows have only 23 each (21 stage + 2 one-off). 14 Linux-specific one-off checks have no macOS/Windows equivalent.

## Architecture

Two dispatch paths for daemon checks:

**Path A — `DaemonProbeOp` enum (6 variants):** Cross-platform checks (runtime_acls, service_hardening, key_custody, authenticode, mesh_status, dns_failclosed). Each OS has a `DaemonProbe` impl mapping to OS-prefixed subcommands (`linux-runtime-acls-check`, `windows-runtime-acls-check`, `macos-runtime-acls-check`).

**Path B — Raw SSH dispatch:** Linux-only adversarial audits (`run_linux_daemon_check_remote` with subcommand strings like `"membership-revoke-audit"`). The daemon subcommands are compiled on all platforms already — same Rust code. Only the orchestrator-side SSH dispatch is Linux-only.

## Plan

### Tier 0 — No action needed (already covered by `_stage_baseline_runtime`)
- `runtime_acls`, `service_hardening`, `mesh_status`, `authenticode`
- Daemon probes run on all 3 OSes via `DaemonProbeOp`, writes to `{os}_stage_baseline_runtime`

### Tier 1 — Add one-off matrix columns for already-running checks
- `macos_runtime_acls`, `windows_runtime_acls`
- `macos_service_hardening`, `windows_service_hardening`
- Matrix columns + `set_special_stage_values` wiring only (no new stages)

### Tier 2 — Port pure-Rust protocol audits to mac/win (5 checks)
The daemon subcommands are already compiled cross-platform. Need orchestrator SSH dispatch + matrix wiring.

| Check | Daemon subcommand | Linux stage fn |
|-------|------------------|----------------|
| membership_revoke_applies | `membership-revoke-audit` | `run_validate_linux_membership_revoke_applies_stage` |
| signature_forgery | `membership-signature-audit` | `run_validate_linux_membership_signature_forgery_stage` |
| gossip_revoked_readmit | `gossip-revoked-readmit-audit` | `run_validate_linux_gossip_revoked_readmit_stage` |
| enrollment_replay | `enrollment-replay-audit` | `run_validate_linux_enrollment_replay_stage` |
| hello_limiter_flood | `hello-limiter-audit` (relay check) | `run_validate_linux_hello_limiter_flood_stage` |

For each: create `run_validate_{os}_{check}_stage` function using SSH dispatch pattern matching the OS (Linux direct SSH, Windows PowerShell, macOS SSH), wire into sidecar orchestrator, add `set_special_stage_values` mapping, add matrix column.

### Tier 3 — Port killswitch-dependent e2e checks (2 checks)
- `revoked_peer_denied_e2e` — needs per-OS killswitch harness (nft/pf/WFP)
- `blind_exit_reversal_denied` — macOS: add matrix column only (stage exists). Windows: blocked by design.

### Tier 4 — Port OS-specific mechanism checks (2 checks)
- `privileged_helper_allowlist` — macOS: create new macOS-specific daemon validator (PH-7). Windows: already via `named_pipe_acl`.
- `policy_default_deny` — create daemon subcommand + orchestrator stage for mac/win

## Implementation Order
1. **Tier 2** (5 pure-protocol checks) — most impact, trivially portable
2. **Tier 4** (privileged_helper, policy_default_deny) — new daemon subcommands but no killswitch
3. **Tier 1** (one-off columns for already-running checks) — trivial wiring
4. **Tier 3** (killswitch-dependent) — hardest, do last

## Files to Touch (per check in Tier 2)
- `crates/rustynet-cli/src/live_lab_run_matrix.rs` — add column to `DEFAULT_MATRIX_COLUMNS`, add `set_special_stage_values` mapping
- `crates/rustynet-cli/src/vm_lab/mod.rs` — add `run_validate_{os}_{check}_stage` function, wire into mac/win sidecar orchestrator

## Current Status
- [ ] Tier 0: Confirmed — no action needed (runtime_acls, service_hardening, mesh_status, authenticode)
- [ ] Tier 2: membership_revoke_applies — mac/win stage functions
- [ ] Tier 2: signature_forgery — mac/win stage functions
- [ ] Tier 2: gossip_revoked_readmit — mac/win stage functions
- [ ] Tier 2: enrollment_replay — mac/win stage functions
- [ ] Tier 2: hello_limiter_flood — mac/win stage functions
- [ ] Tier 4: privileged_helper_allowlist — macOS validator
- [ ] Tier 4: policy_default_deny — mac/win stage functions
- [ ] Tier 1: runtime_acls + service_hardening one-off columns
- [ ] Tier 3: revoked_peer_denied_e2e — mac/win killswitch harness
- [ ] Tier 3: blind_exit_reversal_denied — macOS matrix column only
