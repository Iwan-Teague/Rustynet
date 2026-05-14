#![forbid(unsafe_code)]
// Slice 1 is intentionally internal: nothing in the binary calls into this
// module yet because wrapper integration is reserved for Slice 2 of the
// VmLabCapabilityReportingPlan. Dead-code is therefore expected for now;
// the lint will go away on its own once Slice 2 lands.
#![allow(dead_code)]

//! VM-lab capability evaluator (Slice 1).
//!
//! This module is a pure classification surface for the top-level Rustynet
//! live-lab wrappers. It answers, for a given command/stage on a given
//! platform/source-mode/topology mix, whether the wrapper path is
//! `Supported`, `PartiallySupported`, or `Unsupported`, with a stable
//! machine-readable `reason_code` and an operator-facing message.
//!
//! Slice 1 contract (per
//! `documents/operations/active/VmLabCapabilityReportingPlan_2026-04-14.md`):
//!
//! - No execution-path changes.
//! - No support broadening.
//! - No state mutation.
//! - Capability output stays internal until the model is stable.
//!
//! The wrapper integration (Slice 2), `state/platform_capabilities.json`
//! artifact (Slice 3), and read-only inspection CLI (Slice 4) are explicitly
//! out of scope for this slice.

/// Whether a given wrapper scope is currently honest to claim as available on
/// the given target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmLabCapabilityStatus {
    Supported,
    PartiallySupported,
    Unsupported,
}

impl VmLabCapabilityStatus {
    pub fn as_label(self) -> &'static str {
        match self {
            VmLabCapabilityStatus::Supported => "Supported",
            VmLabCapabilityStatus::PartiallySupported => "PartiallySupported",
            VmLabCapabilityStatus::Unsupported => "Unsupported",
        }
    }
}

/// Top-level wrapper or stage scope being classified.
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

impl VmLabCapabilityScope {
    pub fn as_label(self) -> &'static str {
        match self {
            VmLabCapabilityScope::SetupLiveLab => "SetupLiveLab",
            VmLabCapabilityScope::RunLiveLab => "RunLiveLab",
            VmLabCapabilityScope::OrchestrateLiveLab => "OrchestrateLiveLab",
            VmLabCapabilityScope::BootstrapPhase => "BootstrapPhase",
            VmLabCapabilityScope::BaselineDiagnostics => "BaselineDiagnostics",
            VmLabCapabilityScope::RepoSync => "RepoSync",
            VmLabCapabilityScope::Suite => "Suite",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmLabPlatform {
    Linux,
    Windows,
    MacOS,
    Ios,
    Android,
}

impl VmLabPlatform {
    pub fn as_label(self) -> &'static str {
        match self {
            VmLabPlatform::Linux => "Linux",
            VmLabPlatform::Windows => "Windows",
            VmLabPlatform::MacOS => "MacOS",
            VmLabPlatform::Ios => "Ios",
            VmLabPlatform::Android => "Android",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmLabSourceMode {
    WorkingTree,
    LocalHead,
    CommitRef,
    LocalSource,
    RepoUrl,
}

impl VmLabSourceMode {
    pub fn as_label(self) -> &'static str {
        match self {
            VmLabSourceMode::WorkingTree => "WorkingTree",
            VmLabSourceMode::LocalHead => "LocalHead",
            VmLabSourceMode::CommitRef => "CommitRef",
            VmLabSourceMode::LocalSource => "LocalSource",
            VmLabSourceMode::RepoUrl => "RepoUrl",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmLabBootstrapPhase {
    SyncSource,
    BuildRelease,
    InstallRelease,
    RestartRuntime,
    VerifyRuntime,
}

impl VmLabBootstrapPhase {
    pub fn as_label(self) -> &'static str {
        match self {
            VmLabBootstrapPhase::SyncSource => "SyncSource",
            VmLabBootstrapPhase::BuildRelease => "BuildRelease",
            VmLabBootstrapPhase::InstallRelease => "InstallRelease",
            VmLabBootstrapPhase::RestartRuntime => "RestartRuntime",
            VmLabBootstrapPhase::VerifyRuntime => "VerifyRuntime",
        }
    }
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

/// Stable reason codes used by the evaluator. Operators and downstream tooling
/// may match on these byte-for-byte.
pub mod reason_code {
    pub const LINUX_SHELL_ORCHESTRATOR_ONLY: &str = "linux-shell-orchestrator-only";
    pub const TARGET_PLATFORM_UNSUPPORTED: &str = "target-platform-unsupported";
    pub const PARTIALLY_IMPLEMENTED_SUBCAPABILITY: &str = "partially-implemented-subcapability";
    pub const TOPOLOGY_MISMATCH: &str = "topology-mismatch";
    pub const PLATFORM_SPECIFIC_HELPER_AVAILABLE: &str = "platform-specific-helper-available";
    pub const RUNTIME_HOST_NOT_YET_IMPLEMENTED: &str = "runtime-host-not-yet-implemented";
    pub const COMPOSITE_CAPABILITY: &str = "composite-capability";
    pub const BOOTSTRAP_PHASE_MISSING_FOR_BOOTSTRAP_SCOPE: &str =
        "bootstrap-phase-missing-for-bootstrap-scope";
}

/// Classify one command/stage without mutating state. Pure function.
pub fn evaluate_vm_lab_capability(ctx: VmLabCapabilityContext) -> VmLabCapabilityRecord {
    let (status, reason_code, message): (VmLabCapabilityStatus, &'static str, String) = match ctx
        .scope
    {
        VmLabCapabilityScope::SetupLiveLab | VmLabCapabilityScope::RunLiveLab => {
            evaluate_setup_or_run(ctx.platform, ctx.mixed_platform_topology)
        }
        VmLabCapabilityScope::OrchestrateLiveLab
        | VmLabCapabilityScope::RepoSync
        | VmLabCapabilityScope::Suite => evaluate_composite(ctx.platform),
        VmLabCapabilityScope::BootstrapPhase => {
            evaluate_bootstrap_phase(ctx.platform, ctx.bootstrap_phase)
        }
        VmLabCapabilityScope::BaselineDiagnostics => evaluate_baseline_diagnostics(ctx.platform),
    };
    VmLabCapabilityRecord {
        scope: ctx.scope,
        status,
        reason_code,
        message,
    }
}

fn evaluate_setup_or_run(
    platform: VmLabPlatform,
    mixed_platform_topology: bool,
) -> (VmLabCapabilityStatus, &'static str, String) {
    match platform {
        VmLabPlatform::Linux => {
            if mixed_platform_topology {
                (
                    VmLabCapabilityStatus::Unsupported,
                    reason_code::TOPOLOGY_MISMATCH,
                    "the current live-lab wrapper path is Linux-shell based and cannot satisfy the selected mixed-platform topology"
                        .to_string(),
                )
            } else {
                (
                    VmLabCapabilityStatus::Supported,
                    reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
                    "supported through the current Linux shell orchestrator path".to_string(),
                )
            }
        }
        VmLabPlatform::Windows => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
            "the current live-lab wrapper path is Linux-shell based and does not yet execute the top-level flow on Windows targets"
                .to_string(),
        ),
        VmLabPlatform::MacOS => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
            "the current live-lab wrapper path is Linux-shell based and does not yet execute the top-level flow on macOS targets"
                .to_string(),
        ),
        VmLabPlatform::Ios | VmLabPlatform::Android => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::TARGET_PLATFORM_UNSUPPORTED,
            "the current live-lab wrapper path does not target mobile platforms".to_string(),
        ),
    }
}

fn evaluate_composite(platform: VmLabPlatform) -> (VmLabCapabilityStatus, &'static str, String) {
    match platform {
        VmLabPlatform::Linux => (
            VmLabCapabilityStatus::PartiallySupported,
            reason_code::COMPOSITE_CAPABILITY,
            "this composite capability must be derived from the weakest required subcommand"
                .to_string(),
        ),
        VmLabPlatform::Windows | VmLabPlatform::MacOS => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
            "the composite live-lab wrapper inherits a Linux-shell-only required subcommand and is therefore unsupported on this target"
                .to_string(),
        ),
        VmLabPlatform::Ios | VmLabPlatform::Android => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::TARGET_PLATFORM_UNSUPPORTED,
            "composite live-lab wrappers do not target mobile platforms".to_string(),
        ),
    }
}

fn evaluate_bootstrap_phase(
    platform: VmLabPlatform,
    bootstrap_phase: Option<VmLabBootstrapPhase>,
) -> (VmLabCapabilityStatus, &'static str, String) {
    let Some(phase) = bootstrap_phase else {
        return (
            VmLabCapabilityStatus::Unsupported,
            reason_code::BOOTSTRAP_PHASE_MISSING_FOR_BOOTSTRAP_SCOPE,
            "BootstrapPhase scope requires an explicit bootstrap phase before classification"
                .to_string(),
        );
    };
    match (platform, phase) {
        (VmLabPlatform::Linux, _) => (
            VmLabCapabilityStatus::Supported,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
            "the current Linux bootstrap phase is supported by the shell orchestrator path"
                .to_string(),
        ),
        (
            VmLabPlatform::Windows,
            VmLabBootstrapPhase::SyncSource | VmLabBootstrapPhase::BuildRelease,
        ) => (
            VmLabCapabilityStatus::Supported,
            reason_code::PLATFORM_SPECIFIC_HELPER_AVAILABLE,
            "Windows sync-source and build-release are supported through the current PowerShell helper path, subject to source-mode and toolchain preconditions"
                .to_string(),
        ),
        (VmLabPlatform::Windows, VmLabBootstrapPhase::InstallRelease) => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::RUNTIME_HOST_NOT_YET_IMPLEMENTED,
            "Windows install-release is a protective stub only and is not current runtime-capable proof"
                .to_string(),
        ),
        (
            VmLabPlatform::Windows,
            VmLabBootstrapPhase::RestartRuntime | VmLabBootstrapPhase::VerifyRuntime,
        ) => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::RUNTIME_HOST_NOT_YET_IMPLEMENTED,
            "this Windows bootstrap phase remains blocked until rustynetd exposes a real Windows service/config host path"
                .to_string(),
        ),
        (VmLabPlatform::MacOS, _) => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::TARGET_PLATFORM_UNSUPPORTED,
            "macOS bootstrap phases are not part of the current wrapper surface".to_string(),
        ),
        (VmLabPlatform::Ios | VmLabPlatform::Android, _) => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::TARGET_PLATFORM_UNSUPPORTED,
            "mobile bootstrap is not part of the current wrapper surface".to_string(),
        ),
    }
}

fn evaluate_baseline_diagnostics(
    platform: VmLabPlatform,
) -> (VmLabCapabilityStatus, &'static str, String) {
    match platform {
        VmLabPlatform::Linux => (
            VmLabCapabilityStatus::Supported,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
            "Linux diagnostics are supported through the current shell orchestrator path".to_string(),
        ),
        VmLabPlatform::Windows => (
            VmLabCapabilityStatus::PartiallySupported,
            reason_code::PARTIALLY_IMPLEMENTED_SUBCAPABILITY,
            "Windows diagnostics are available through PowerShell helpers; the wrapper should still report exact per-target helper coverage"
                .to_string(),
        ),
        VmLabPlatform::MacOS => (
            VmLabCapabilityStatus::PartiallySupported,
            reason_code::PARTIALLY_IMPLEMENTED_SUBCAPABILITY,
            "macOS diagnostics rely on host-side helpers with limited coverage; wrapper should report exact coverage"
                .to_string(),
        ),
        VmLabPlatform::Ios | VmLabPlatform::Android => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::TARGET_PLATFORM_UNSUPPORTED,
            "mobile diagnostics are not part of the current wrapper surface".to_string(),
        ),
    }
}

/// Evaluate a full set of contexts (e.g. one profile's mixed-platform contexts)
/// without merging them. Slice 2/3 will introduce the merge surface.
pub fn evaluate_vm_lab_capabilities_for_profile(
    contexts: &[VmLabCapabilityContext],
) -> Vec<VmLabCapabilityRecord> {
    contexts
        .iter()
        .copied()
        .map(evaluate_vm_lab_capability)
        .collect()
}

/// Map the canonical top-level command name to a capability scope, if known.
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

/// Stable one-line operator-facing summary string for a capability record.
/// No JSON, no secrets, no platform-unstable paths.
pub fn render_capability_summary(record: &VmLabCapabilityRecord) -> String {
    format!(
        "scope={} status={} reason_code={} message={}",
        record.scope.as_label(),
        record.status.as_label(),
        record.reason_code,
        record.message,
    )
}

/// Render an N-line summary for an ordered set of records. Each input record
/// produces exactly one output line in the same order; no aggregation here.
pub fn render_capability_report(records: &[VmLabCapabilityRecord]) -> String {
    let mut out = String::new();
    for record in records {
        out.push_str(&render_capability_summary(record));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_linux(scope: VmLabCapabilityScope) -> VmLabCapabilityContext {
        VmLabCapabilityContext {
            scope,
            platform: VmLabPlatform::Linux,
            source_mode: VmLabSourceMode::LocalHead,
            bootstrap_phase: None,
            mixed_platform_topology: false,
        }
    }

    fn ctx_windows(scope: VmLabCapabilityScope) -> VmLabCapabilityContext {
        VmLabCapabilityContext {
            scope,
            platform: VmLabPlatform::Windows,
            source_mode: VmLabSourceMode::LocalHead,
            bootstrap_phase: None,
            mixed_platform_topology: false,
        }
    }

    #[test]
    fn linux_setup_profile_is_supported() {
        let record = evaluate_vm_lab_capability(ctx_linux(VmLabCapabilityScope::SetupLiveLab));
        assert_eq!(record.status, VmLabCapabilityStatus::Supported);
        assert_eq!(
            record.reason_code,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY
        );
    }

    #[test]
    fn linux_run_profile_is_supported() {
        let record = evaluate_vm_lab_capability(ctx_linux(VmLabCapabilityScope::RunLiveLab));
        assert_eq!(record.status, VmLabCapabilityStatus::Supported);
        assert_eq!(
            record.reason_code,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY
        );
    }

    #[test]
    fn windows_setup_profile_is_unsupported_with_linux_shell_reason() {
        let record = evaluate_vm_lab_capability(ctx_windows(VmLabCapabilityScope::SetupLiveLab));
        assert_eq!(record.status, VmLabCapabilityStatus::Unsupported);
        assert_eq!(
            record.reason_code,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY
        );
    }

    #[test]
    fn macos_setup_profile_is_unsupported_with_linux_shell_reason() {
        let mut ctx = ctx_linux(VmLabCapabilityScope::SetupLiveLab);
        ctx.platform = VmLabPlatform::MacOS;
        let record = evaluate_vm_lab_capability(ctx);
        assert_eq!(record.status, VmLabCapabilityStatus::Unsupported);
        assert_eq!(
            record.reason_code,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY
        );
    }

    #[test]
    fn mixed_linux_topology_setup_is_unsupported_with_topology_reason() {
        let mut ctx = ctx_linux(VmLabCapabilityScope::SetupLiveLab);
        ctx.mixed_platform_topology = true;
        let record = evaluate_vm_lab_capability(ctx);
        assert_eq!(record.status, VmLabCapabilityStatus::Unsupported);
        assert_eq!(record.reason_code, reason_code::TOPOLOGY_MISMATCH);
    }

    #[test]
    fn mixed_topology_does_not_affect_non_linux_setup_reason() {
        let mut ctx = ctx_windows(VmLabCapabilityScope::SetupLiveLab);
        ctx.mixed_platform_topology = true;
        let record = evaluate_vm_lab_capability(ctx);
        assert_eq!(record.status, VmLabCapabilityStatus::Unsupported);
        assert_eq!(
            record.reason_code,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
            "non-Linux setup must keep its primary reason code even when topology is flagged mixed"
        );
    }

    #[test]
    fn windows_sync_source_bootstrap_is_supported_with_helper_reason() {
        let mut ctx = ctx_windows(VmLabCapabilityScope::BootstrapPhase);
        ctx.bootstrap_phase = Some(VmLabBootstrapPhase::SyncSource);
        let record = evaluate_vm_lab_capability(ctx);
        assert_eq!(record.status, VmLabCapabilityStatus::Supported);
        assert_eq!(
            record.reason_code,
            reason_code::PLATFORM_SPECIFIC_HELPER_AVAILABLE
        );
    }

    #[test]
    fn windows_build_release_bootstrap_is_supported_with_helper_reason() {
        let mut ctx = ctx_windows(VmLabCapabilityScope::BootstrapPhase);
        ctx.bootstrap_phase = Some(VmLabBootstrapPhase::BuildRelease);
        let record = evaluate_vm_lab_capability(ctx);
        assert_eq!(record.status, VmLabCapabilityStatus::Supported);
        assert_eq!(
            record.reason_code,
            reason_code::PLATFORM_SPECIFIC_HELPER_AVAILABLE
        );
    }

    #[test]
    fn windows_install_release_bootstrap_is_blocked_runtime_host() {
        let mut ctx = ctx_windows(VmLabCapabilityScope::BootstrapPhase);
        ctx.bootstrap_phase = Some(VmLabBootstrapPhase::InstallRelease);
        let record = evaluate_vm_lab_capability(ctx);
        assert_eq!(record.status, VmLabCapabilityStatus::Unsupported);
        assert_eq!(
            record.reason_code,
            reason_code::RUNTIME_HOST_NOT_YET_IMPLEMENTED
        );
    }

    #[test]
    fn windows_runtime_bootstrap_phases_are_blocked_runtime_host() {
        for phase in [
            VmLabBootstrapPhase::RestartRuntime,
            VmLabBootstrapPhase::VerifyRuntime,
        ] {
            let mut ctx = ctx_windows(VmLabCapabilityScope::BootstrapPhase);
            ctx.bootstrap_phase = Some(phase);
            let record = evaluate_vm_lab_capability(ctx);
            assert_eq!(record.status, VmLabCapabilityStatus::Unsupported);
            assert_eq!(
                record.reason_code,
                reason_code::RUNTIME_HOST_NOT_YET_IMPLEMENTED
            );
        }
    }

    #[test]
    fn linux_bootstrap_phases_are_supported_for_every_phase() {
        for phase in [
            VmLabBootstrapPhase::SyncSource,
            VmLabBootstrapPhase::BuildRelease,
            VmLabBootstrapPhase::InstallRelease,
            VmLabBootstrapPhase::RestartRuntime,
            VmLabBootstrapPhase::VerifyRuntime,
        ] {
            let mut ctx = ctx_linux(VmLabCapabilityScope::BootstrapPhase);
            ctx.bootstrap_phase = Some(phase);
            let record = evaluate_vm_lab_capability(ctx);
            assert_eq!(
                record.status,
                VmLabCapabilityStatus::Supported,
                "linux bootstrap phase {phase:?} should be supported"
            );
            assert_eq!(
                record.reason_code,
                reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY
            );
        }
    }

    #[test]
    fn bootstrap_phase_scope_without_phase_is_unsupported_with_explicit_reason() {
        let ctx = ctx_linux(VmLabCapabilityScope::BootstrapPhase);
        assert!(ctx.bootstrap_phase.is_none());
        let record = evaluate_vm_lab_capability(ctx);
        assert_eq!(record.status, VmLabCapabilityStatus::Unsupported);
        assert_eq!(
            record.reason_code,
            reason_code::BOOTSTRAP_PHASE_MISSING_FOR_BOOTSTRAP_SCOPE
        );
    }

    #[test]
    fn ios_and_android_are_unsupported_target_platform_for_setup() {
        for platform in [VmLabPlatform::Ios, VmLabPlatform::Android] {
            let mut ctx = ctx_linux(VmLabCapabilityScope::SetupLiveLab);
            ctx.platform = platform;
            let record = evaluate_vm_lab_capability(ctx);
            assert_eq!(record.status, VmLabCapabilityStatus::Unsupported);
            assert_eq!(record.reason_code, reason_code::TARGET_PLATFORM_UNSUPPORTED);
        }
    }

    #[test]
    fn diagnostics_is_partially_supported_for_windows_and_macos() {
        for platform in [VmLabPlatform::Windows, VmLabPlatform::MacOS] {
            let mut ctx = ctx_linux(VmLabCapabilityScope::BaselineDiagnostics);
            ctx.platform = platform;
            let record = evaluate_vm_lab_capability(ctx);
            assert_eq!(
                record.status,
                VmLabCapabilityStatus::PartiallySupported,
                "diagnostics on {platform:?} should be partially supported"
            );
            assert_eq!(
                record.reason_code,
                reason_code::PARTIALLY_IMPLEMENTED_SUBCAPABILITY
            );
        }
    }

    #[test]
    fn diagnostics_is_supported_on_linux() {
        let ctx = ctx_linux(VmLabCapabilityScope::BaselineDiagnostics);
        let record = evaluate_vm_lab_capability(ctx);
        assert_eq!(record.status, VmLabCapabilityStatus::Supported);
        assert_eq!(
            record.reason_code,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY
        );
    }

    #[test]
    fn diagnostics_is_unsupported_on_mobile_platforms() {
        for platform in [VmLabPlatform::Ios, VmLabPlatform::Android] {
            let mut ctx = ctx_linux(VmLabCapabilityScope::BaselineDiagnostics);
            ctx.platform = platform;
            let record = evaluate_vm_lab_capability(ctx);
            assert_eq!(record.status, VmLabCapabilityStatus::Unsupported);
            assert_eq!(record.reason_code, reason_code::TARGET_PLATFORM_UNSUPPORTED);
        }
    }

    #[test]
    fn composite_scopes_are_partial_on_linux_and_unsupported_elsewhere() {
        for scope in [
            VmLabCapabilityScope::OrchestrateLiveLab,
            VmLabCapabilityScope::RepoSync,
            VmLabCapabilityScope::Suite,
        ] {
            let linux = evaluate_vm_lab_capability(ctx_linux(scope));
            assert_eq!(linux.status, VmLabCapabilityStatus::PartiallySupported);
            assert_eq!(linux.reason_code, reason_code::COMPOSITE_CAPABILITY);

            let windows = evaluate_vm_lab_capability(ctx_windows(scope));
            assert_eq!(windows.status, VmLabCapabilityStatus::Unsupported);
            assert_eq!(
                windows.reason_code,
                reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY
            );
        }
    }

    #[test]
    fn command_scope_maps_known_wrappers() {
        assert_eq!(
            command_scope("vm-lab-setup-live-lab"),
            Some(VmLabCapabilityScope::SetupLiveLab)
        );
        assert_eq!(
            command_scope("vm-lab-run-live-lab"),
            Some(VmLabCapabilityScope::RunLiveLab)
        );
        assert_eq!(
            command_scope("vm-lab-orchestrate-live-lab"),
            Some(VmLabCapabilityScope::OrchestrateLiveLab)
        );
        assert_eq!(
            command_scope("vm-lab-bootstrap-phase"),
            Some(VmLabCapabilityScope::BootstrapPhase)
        );
        assert_eq!(
            command_scope("vm-lab-diagnose-live-lab-failure"),
            Some(VmLabCapabilityScope::BaselineDiagnostics)
        );
        assert_eq!(
            command_scope("vm-lab-sync-repo"),
            Some(VmLabCapabilityScope::RepoSync)
        );
        assert_eq!(
            command_scope("vm-lab-run-suite"),
            Some(VmLabCapabilityScope::Suite)
        );
    }

    #[test]
    fn command_scope_returns_none_for_unknown_commands() {
        for unknown in [
            "vm-lab-unknown",
            "vm-lab-",
            "",
            "ops",
            "vm-lab-setup-live-lab-extra",
        ] {
            assert_eq!(command_scope(unknown), None, "{unknown:?} must map to None");
        }
    }

    #[test]
    fn render_capability_summary_emits_stable_one_line_format() {
        let record = VmLabCapabilityRecord {
            scope: VmLabCapabilityScope::SetupLiveLab,
            status: VmLabCapabilityStatus::Supported,
            reason_code: reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
            message: "hello".to_string(),
        };
        assert_eq!(
            render_capability_summary(&record),
            "scope=SetupLiveLab status=Supported reason_code=linux-shell-orchestrator-only message=hello"
        );
    }

    #[test]
    fn render_capability_report_preserves_order_and_count() {
        let records = vec![
            evaluate_vm_lab_capability(ctx_linux(VmLabCapabilityScope::SetupLiveLab)),
            evaluate_vm_lab_capability(ctx_windows(VmLabCapabilityScope::SetupLiveLab)),
        ];
        let rendered = render_capability_report(&records);
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("status=Supported"));
        assert!(lines[1].contains("status=Unsupported"));
    }

    #[test]
    fn evaluate_for_profile_is_deterministic_and_preserves_order() {
        let contexts = vec![
            ctx_linux(VmLabCapabilityScope::SetupLiveLab),
            ctx_windows(VmLabCapabilityScope::SetupLiveLab),
            ctx_linux(VmLabCapabilityScope::RunLiveLab),
            ctx_windows(VmLabCapabilityScope::BaselineDiagnostics),
        ];
        let first = evaluate_vm_lab_capabilities_for_profile(&contexts);
        let second = evaluate_vm_lab_capabilities_for_profile(&contexts);
        assert_eq!(first, second, "pure evaluator must be deterministic");
        assert_eq!(first.len(), contexts.len());
        assert_eq!(first[0].status, VmLabCapabilityStatus::Supported);
        assert_eq!(first[1].status, VmLabCapabilityStatus::Unsupported);
        assert_eq!(first[2].status, VmLabCapabilityStatus::Supported);
        assert_eq!(first[3].status, VmLabCapabilityStatus::PartiallySupported);
    }

    #[test]
    fn evaluator_is_side_effect_free_for_repeat_invocations() {
        let ctx = ctx_linux(VmLabCapabilityScope::SetupLiveLab);
        let a = evaluate_vm_lab_capability(ctx);
        let b = evaluate_vm_lab_capability(ctx);
        let c = evaluate_vm_lab_capability(ctx);
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn reason_codes_use_kebab_case_lowercase_ascii() {
        for code in [
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
            reason_code::TARGET_PLATFORM_UNSUPPORTED,
            reason_code::PARTIALLY_IMPLEMENTED_SUBCAPABILITY,
            reason_code::TOPOLOGY_MISMATCH,
            reason_code::PLATFORM_SPECIFIC_HELPER_AVAILABLE,
            reason_code::RUNTIME_HOST_NOT_YET_IMPLEMENTED,
            reason_code::COMPOSITE_CAPABILITY,
            reason_code::BOOTSTRAP_PHASE_MISSING_FOR_BOOTSTRAP_SCOPE,
        ] {
            assert!(!code.is_empty(), "reason code must be non-empty: {code:?}");
            for byte in code.bytes() {
                assert!(
                    matches!(byte, b'a'..=b'z' | b'-'),
                    "reason code must be lowercase kebab-case ASCII: {code:?}"
                );
            }
        }
    }
}
