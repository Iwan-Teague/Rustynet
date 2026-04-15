# VM Lab Capability Cookbook

**Status:** Active implementation aid

## Purpose

This document is the reusable implementation companion for the VM lab
capability-reporting work. It gives the next agent a place to pull from instead
of generating the same scaffolding on the fly.

Use this cookbook together with:

- [VmLabCapabilityReportingPlan_2026-04-14.md](./VmLabCapabilityReportingPlan_2026-04-14.md)
- [VmLabCapabilitySources_2026-04-14.md](./VmLabCapabilitySources_2026-04-14.md)

The rule is simple:

- the reporting plan explains what should exist
- the source notes explain which platform facts are verified
- this cookbook provides reusable implementation shapes and phase ordering

## Where The Prebuilt Wrappers Should Be Used

These wrappers already exist and should be reused instead of being rederived ad
hoc:

| Wrapper | Use it when | Why it exists |
| --- | --- | --- |
| `ops vm-lab-discover-local-utm-summary` | You need the fastest readiness answer for inventory-backed local UTM nodes | Fast preflight gate before any setup or recovery |
| `ops vm-lab-discover-local-utm` | You need the full JSON discovery report, inventory refresh, or report-dir artifacts | Machine-readable local UTM state capture |
| `ops vm-lab-restart --wait-ready` | Discovery says the selected VMs exist but are not execution-ready | Controlled host-side recovery with fail-closed readiness wait |
| `ops vm-lab-setup-live-lab` | You want setup-only execution and baseline validation | Primary setup path for the current live-lab workflow |
| `ops vm-lab-run-live-lab` | Setup is complete and you want the full suite | Primary run path for the standard live-lab suite |
| `ops vm-lab-diagnose-live-lab-failure` | A setup or run failed and you need the first failed stage plus forensics | Stage-aware triage bundle after a red run |
| `ops vm-lab-orchestrate-live-lab` | You want discovery, restart-if-needed, setup, run, and diagnose wired together | One-shot operator flow, still fail-closed |
| `ops vm-lab-bootstrap-phase --phase ...` | You need provisioning or phase-specific bootstrap without the full suite | Reusable provisioning-only surface |

The wrappers should remain the first-class operator entrypoints. The cookbook is
for implementing and explaining them, not replacing them.

## Additional Functions Worth Pre-Writing

These helpers would reduce repetition and make the implementation less ad hoc.
They are meant to be added where the wrapper code already lives, not in a new
sidecar execution path.

| Function | Put it in | Purpose |
| --- | --- | --- |
| `collect_vm_lab_capability_inputs` | `crates/rustynet-cli/src/vm_lab/mod.rs` | Gather command, platform, topology, source mode, and profile facts into one context |
| `normalize_vm_lab_platform_mix` | `crates/rustynet-cli/src/vm_lab/mod.rs` | Turn inventory/platform metadata into a stable platform classification |
| `evaluate_vm_lab_capability` | `crates/rustynet-cli/src/vm_lab/mod.rs` | Classify one command/stage without mutating state |
| `evaluate_vm_lab_capabilities_for_profile` | `crates/rustynet-cli/src/vm_lab/mod.rs` | Emit the full capability set for a selected profile or report dir |
| `merge_vm_lab_capability_records` | `crates/rustynet-cli/src/vm_lab/mod.rs` | Collapse per-scope results into one overall wrapper status |
| `render_vm_lab_capability_error` | `crates/rustynet-cli/src/vm_lab/mod.rs` | Produce a stable operator-facing failure string from a capability record |
| `render_vm_lab_capability_json` | `crates/rustynet-cli/src/vm_lab/mod.rs` | Emit the machine-readable capability report payload |
| `write_platform_capabilities_artifact` | `crates/rustynet-cli/src/vm_lab/mod.rs` | Persist `state/platform_capabilities.json` in the report directory |
| `select_vm_lab_capability_scope` | `crates/rustynet-cli/src/vm_lab/mod.rs` | Map CLI commands and bootstrap phases to a capability scope |
| `validate_vm_lab_capability_preconditions` | `crates/rustynet-cli/src/vm_lab/mod.rs` | Fail closed before wrapper execution when profile or topology facts are missing |

Use these helpers as pure or near-pure building blocks:

- pure classification and rendering belong in `vm_lab/mod.rs`
- CLI dispatch and argument wiring belong in `main.rs`
- Canonical Windows bootstrap helpers belong in `scripts/bootstrap/windows/*.ps1`
- `scripts/vm_lab/windows/*.ps1` remains the compatibility shim and
  access-bootstrap surface
- shell orchestrator logic remains in `scripts/e2e/live_linux_lab_orchestrator.sh`

## Security-First Helpers Worth Pre-Writing

These helpers keep the capability layer fail-closed and reduce the chance that a
future agent weakens the wrapper while trying to make the reporting friendlier.

| Function | Put it in | Purpose |
| --- | --- | --- |
| `validate_vm_lab_report_dir_fresh` | `crates/rustynet-cli/src/vm_lab/mod.rs` | Reject stale or reused report dirs before writing capability artifacts |
| `validate_vm_lab_known_hosts` | `crates/rustynet-cli/src/vm_lab/mod.rs` | Enforce pinned host-key inputs and avoid TOFU-style behavior |
| `validate_vm_lab_source_mode` | `crates/rustynet-cli/src/vm_lab/mod.rs` | Reject source modes that do not match the current wrapper path |
| `validate_vm_lab_target_topology` | `crates/rustynet-cli/src/vm_lab/mod.rs` | Reject impossible or mixed topologies before any mutation path starts |
| `sanitize_vm_lab_capability_message` | `crates/rustynet-cli/src/vm_lab/mod.rs` | Strip or normalize any text that could accidentally leak secrets or unstable paths |
| `build_vm_lab_capability_failure_context` | `crates/rustynet-cli/src/vm_lab/mod.rs` | Bundle the evidence needed for a deterministic failure message |

Security invariants to preserve:

- pinned `known_hosts` only
- no `accept-new` or TOFU
- no shell construction from untrusted values
- no secret material in capability messages or JSON artifacts
- no fallback to weaker execution paths when capability data is missing
- no support claim unless the code path exists and is tested
- no relaxation of Linux-only guards until the capability evaluator replaces the coarse check

## Recommended Phases

The phases below are intentionally strict. Each phase has an entry condition,
an exact deliverable, and an exit condition. Do not advance unless the exit
condition is satisfied.

| Phase | Entry condition | Deliverable | Exit condition | Security gate |
| --- | --- | --- | --- | --- |
| Phase 0: Docs alignment | The source-backed notes and wrapper truth are known | Update the reporting plan, cookbook, runbook, and script map so they all point to the same source-backed facts and wrapper-support truth | The docs all name the same wrapper entrypoints, source facts, and security posture | No execution semantics may change |
| Phase 1: Pure capability model | The doc model is stable | Add the enums, record types, pure evaluator, and direct unit tests in Rust | The evaluator classifies Linux, Windows, macOS, iOS, and Android cases deterministically with no side effects | No support broadening, no execution path changes |
| Phase 2: Wrapper integration | Phase 1 is complete | Wire the evaluator into the top-level wrapper guardrails and error paths | The wrappers still fail closed, but now explain the reason with capability records | Keep Linux-only execution guards intact |
| Phase 3: Artifact emission | Phase 2 is complete | Write `state/platform_capabilities.json` in the report dir | The artifact is deterministic, read-only, and matches the wrapper decision | No fallback paths, no silent downgrade |
| Phase 4: Read-only inspection CLI | Phase 3 is complete | Add `ops vm-lab-report-capabilities` if the inspection surface is needed | Operators can inspect capability truth without starting setup or run | Inspection only, no mutation, no hidden execution |
| Phase 5: Documentation sync | The code behavior is stable | Reconcile the runbook, script map, and plans with the final capability behavior | Every doc uses the same phase names, scope names, and reason codes | Documentation must not overstate support |

## Implementation Anchors

Start by reading these existing implementation points:

- `crates/rustynet-cli/src/main.rs`
- `crates/rustynet-cli/src/vm_lab/mod.rs`
- `scripts/e2e/live_linux_lab_orchestrator.sh`
- `scripts/vm_lab/windows/Enable-WindowsVmLabAccess.ps1`
- `scripts/vm_lab/windows/Install-RustyNetWindows.ps1`
- `scripts/vm_lab/windows/Collect-RustyNetWindowsDiagnostics.ps1`

These already show the current execution and helper surfaces. The new capability
layer should classify that truth, not invent a second execution model.

## Reusable Rust Snippets

The snippets below are std-only so they compile as pasted. They are shaped to be
easy to copy into `crates/rustynet-cli/src/vm_lab/mod.rs` or a small companion
module with minimal editing.

### Snippet 1: Capability taxonomy and context

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmLabCapabilityStatus {
    Supported,
    PartiallySupported,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmLabCapabilityScope {
    SetupLiveLab,
    RunLiveLab,
    OrchestrateLiveLab,
    BootstrapPhase,
    BaselineDiagnostics,
    RepoSync,
    Suite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmLabPlatform {
    Linux,
    Windows,
    MacOS,
    Ios,
    Android,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmLabSourceMode {
    WorkingTree,
    LocalHead,
    CommitRef,
    LocalSource,
    RepoUrl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmLabBootstrapPhase {
    SyncSource,
    BuildRelease,
    InstallRelease,
    RestartRuntime,
    VerifyRuntime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmLabCapabilityContext {
    pub scope: VmLabCapabilityScope,
    pub platform: VmLabPlatform,
    pub source_mode: VmLabSourceMode,
    pub bootstrap_phase: Option<VmLabBootstrapPhase>,
    pub mixed_platform_topology: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabCapabilityRecord {
    pub scope: VmLabCapabilityScope,
    pub status: VmLabCapabilityStatus,
    pub reason_code: &'static str,
    pub message: String,
}
```

### Snippet 2: Pure evaluator

```rust
pub fn evaluate_vm_lab_capability(ctx: VmLabCapabilityContext) -> VmLabCapabilityRecord {
    let (status, reason_code, message) = match ctx.scope {
        VmLabCapabilityScope::SetupLiveLab | VmLabCapabilityScope::RunLiveLab => {
            match ctx.platform {
                VmLabPlatform::Linux => {
                    if ctx.mixed_platform_topology {
                        (
                            VmLabCapabilityStatus::Unsupported,
                            "topology-mismatch",
                            "the current live-lab wrapper path is Linux-shell based and cannot satisfy the selected mixed topology".to_string(),
                        )
                    } else {
                        (
                            VmLabCapabilityStatus::Supported,
                            "linux-shell-orchestrator-only",
                            "supported through the current Linux shell orchestrator path".to_string(),
                        )
                    }
                }
                VmLabPlatform::Windows => (
                    VmLabCapabilityStatus::Unsupported,
                    "linux-shell-orchestrator-only",
                    "the current live-lab wrapper path is Linux-shell based and does not yet execute the top-level flow on Windows targets".to_string(),
                ),
                VmLabPlatform::MacOS => (
                    VmLabCapabilityStatus::Unsupported,
                    "linux-shell-orchestrator-only",
                    "the current live-lab wrapper path is Linux-shell based and does not yet execute the top-level flow on macOS targets".to_string(),
                ),
                VmLabPlatform::Ios | VmLabPlatform::Android => (
                    VmLabCapabilityStatus::Unsupported,
                    "target-platform-unsupported",
                    "the current live-lab wrapper path does not target mobile platforms".to_string(),
                ),
            }
        }
        VmLabCapabilityScope::BootstrapPhase => match (ctx.platform, ctx.bootstrap_phase) {
            (VmLabPlatform::Windows, Some(VmLabBootstrapPhase::SyncSource))
            | (VmLabPlatform::Windows, Some(VmLabBootstrapPhase::BuildRelease)) => (
                VmLabCapabilityStatus::Supported,
                "platform-specific-helper-available",
                "Windows sync-source/build-release are supported by the current PowerShell helper path".to_string(),
            ),
            (VmLabPlatform::Windows, Some(_)) => (
                VmLabCapabilityStatus::Unsupported,
                "runtime-host-not-yet-implemented",
                "this Windows bootstrap phase is not current runtime-capable proof and remains blocked until rustynetd exposes a real Windows service/config host path".to_string(),
            ),
            (VmLabPlatform::Linux, _) => (
                VmLabCapabilityStatus::Supported,
                "linux-shell-orchestrator-only",
                "the current Linux bootstrap phase is supported by the shell orchestrator path".to_string(),
            ),
            _ => (
                VmLabCapabilityStatus::Unsupported,
                "target-platform-unsupported",
                "bootstrap support is not available for this platform and phase combination".to_string(),
            ),
        },
        VmLabCapabilityScope::BaselineDiagnostics => (
            VmLabCapabilityStatus::PartiallySupported,
            "partially-implemented-subcapability",
            "diagnostics are available on some platforms, but the wrapper should report the exact helper coverage per target".to_string(),
        ),
        VmLabCapabilityScope::OrchestrateLiveLab | VmLabCapabilityScope::RepoSync | VmLabCapabilityScope::Suite => (
            VmLabCapabilityStatus::PartiallySupported,
            "composite-capability",
            "this capability must be derived from the weakest required subcommand".to_string(),
        ),
    };

    VmLabCapabilityRecord {
        scope: ctx.scope,
        status,
        reason_code,
        message,
    }
}
```

### Snippet 3: Render a machine-readable summary without extra dependencies

```rust
pub fn render_capability_summary(record: &VmLabCapabilityRecord) -> String {
    format!(
        "scope={:?} status={:?} reason_code={} message={}",
        record.scope, record.status, record.reason_code, record.message
    )
}

pub fn render_capability_report(records: &[VmLabCapabilityRecord]) -> String {
    let mut out = String::new();
    for record in records {
        out.push_str(&render_capability_summary(record));
        out.push('\n');
    }
    out
}
```

### Snippet 4: Map the top-level command to a capability scope

```rust
pub fn command_scope(command: &str) -> Option<VmLabCapabilityScope> {
    match command {
        "vm-lab-setup-live-lab" => Some(VmLabCapabilityScope::SetupLiveLab),
        "vm-lab-run-live-lab" => Some(VmLabCapabilityScope::RunLiveLab),
        "vm-lab-orchestrate-live-lab" => Some(VmLabCapabilityScope::OrchestrateLiveLab),
        "vm-lab-bootstrap-phase" => Some(VmLabCapabilityScope::BootstrapPhase),
        "vm-lab-diagnose-live-lab-failure" => Some(VmLabCapabilityScope::BaselineDiagnostics),
        "vm-lab-sync-repo" => Some(VmLabCapabilityScope::RepoSync),
        "vm-lab-run-suite" => Some(VmLabCapabilityScope::Suite),
        _ => None,
    }
}
```

### Snippet 5: Write the capability artifact

```rust
use std::fs;
use std::path::Path;

pub fn write_platform_capabilities_artifact(
    report_dir: &Path,
    records: &[VmLabCapabilityRecord],
) -> std::io::Result<()> {
    let state_dir = report_dir.join("state");
    fs::create_dir_all(&state_dir)?;
    let path = state_dir.join("platform_capabilities.json");
    let mut body = String::from("{\"records\":[");
    for (idx, record) in records.iter().enumerate() {
        if idx > 0 {
            body.push(',');
        }
        body.push_str(&format!(
            "{{\"scope\":\"{:?}\",\"status\":\"{:?}\",\"reason_code\":\"{}\",\"message\":\"{}\"}}",
            record.scope,
            record.status,
            record.reason_code,
            record.message.replace('\"', "\\\""),
        ));
    }
    body.push_str("]}");
    fs::write(path, body)
}
```

### Snippet 6: Build a profile-scoped capability set

```rust
pub fn evaluate_vm_lab_capabilities_for_profile(
    contexts: &[VmLabCapabilityContext],
) -> Vec<VmLabCapabilityRecord> {
    contexts.iter().copied().map(evaluate_vm_lab_capability).collect()
}
```

## Reusable Windows Helper Locations

If the capability evaluator needs examples of current helper coverage, these
scripts are the right places to inspect or reuse:

- `scripts/vm_lab/windows/Enable-WindowsVmLabAccess.ps1`
- `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1`
- `scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1`
- `scripts/bootstrap/windows/Verify-RustyNetWindowsBootstrap.ps1`
- `scripts/bootstrap/windows/Collect-RustyNetWindowsDiagnostics.ps1`
- `scripts/vm_lab/windows/Install-RustyNetWindows.ps1`
- `scripts/vm_lab/windows/Collect-RustyNetWindowsDiagnostics.ps1`

Those scripts already show the Windows-specific helper responsibilities:

- SSH/OpenSSH enablement
- repo sync/build bootstrap
- protective runtime install blocking
- verification and diagnostics
- diagnostics collection

## Documentation Rules For The Next Agent

- Do not guess at support from platform presence alone.
- Do not remove the existing fail-closed guardrails until the capability model
  is in place.
- When you add wrapper capability reporting, point operators back to this
  cookbook and the source notes doc.
- Keep the runbook, the script map, and the planning doc consistent.
- Treat the phase table above as the implementation contract for this slice.

## Cross-References

- Reporting plan: [VmLabCapabilityReportingPlan_2026-04-14.md](./VmLabCapabilityReportingPlan_2026-04-14.md)
- Source notes: [VmLabCapabilitySources_2026-04-14.md](./VmLabCapabilitySources_2026-04-14.md)
- Live-lab runbook: [../LiveLinuxLabOrchestrator.md](../LiveLinuxLabOrchestrator.md)
- Script map: [../../../scripts/e2e/README.md](../../../scripts/e2e/README.md)
