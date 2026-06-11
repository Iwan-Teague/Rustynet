#![forbid(unsafe_code)]
// Slice 1 internals (status/scope label helpers, etc.) are still reserved for
// future wrapper integration (Slice 2). The read-only inspection CLI (Slice 4)
// now consumes a subset of the public surface, so blanket dead-code is no
// longer correct; the remaining unused items keep an explicit allow so the
// linter does not block Slice-2 work.
#![allow(dead_code)]

//! VM-lab capability evaluator (Slice 1) and read-only inspection CLI
//! (Slice 4).
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
        VmLabPlatform::Linux => (
            VmLabCapabilityStatus::Supported,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
            if mixed_platform_topology {
                "supported as the Linux core of the current mixed-OS live-lab wrapper path"
                    .to_owned()
            } else {
                "supported through the current Linux shell orchestrator path".to_owned()
            },
        ),
        VmLabPlatform::Windows => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
            "the current live-lab wrapper path is Linux-shell based and does not yet execute the top-level flow on Windows targets".to_owned(),
        ),
        VmLabPlatform::MacOS => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
            "the current live-lab wrapper path is Linux-shell based and does not yet execute the top-level flow on macOS targets".to_owned(),
        ),
        VmLabPlatform::Ios | VmLabPlatform::Android => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::TARGET_PLATFORM_UNSUPPORTED,
            "the current live-lab wrapper path does not target mobile platforms".to_owned(),
        ),
    }
}

fn evaluate_composite(platform: VmLabPlatform) -> (VmLabCapabilityStatus, &'static str, String) {
    match platform {
        VmLabPlatform::Linux => (
            VmLabCapabilityStatus::PartiallySupported,
            reason_code::COMPOSITE_CAPABILITY,
            "this composite capability must be derived from the weakest required subcommand".to_owned(),
        ),
        VmLabPlatform::Windows | VmLabPlatform::MacOS => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
            "the composite live-lab wrapper inherits a Linux-shell-only required subcommand and is therefore unsupported on this target".to_owned(),
        ),
        VmLabPlatform::Ios | VmLabPlatform::Android => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::TARGET_PLATFORM_UNSUPPORTED,
            "composite live-lab wrappers do not target mobile platforms".to_owned(),
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
                .to_owned(),
        );
    };
    match (platform, phase) {
        (VmLabPlatform::Linux, _) => (
            VmLabCapabilityStatus::Supported,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
            "the current Linux bootstrap phase is supported by the shell orchestrator path".to_owned(),
        ),
        (
            VmLabPlatform::Windows,
            VmLabBootstrapPhase::SyncSource | VmLabBootstrapPhase::BuildRelease,
        ) => (
            VmLabCapabilityStatus::Supported,
            reason_code::PLATFORM_SPECIFIC_HELPER_AVAILABLE,
            "Windows sync-source and build-release are supported through the current PowerShell helper path, subject to source-mode and toolchain preconditions".to_owned(),
        ),
        (VmLabPlatform::Windows, VmLabBootstrapPhase::InstallRelease) => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::RUNTIME_HOST_NOT_YET_IMPLEMENTED,
            "Windows install-release is a protective stub only and is not current runtime-capable proof".to_owned(),
        ),
        (
            VmLabPlatform::Windows,
            VmLabBootstrapPhase::RestartRuntime | VmLabBootstrapPhase::VerifyRuntime,
        ) => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::RUNTIME_HOST_NOT_YET_IMPLEMENTED,
            "this Windows bootstrap phase remains blocked until rustynetd exposes a real Windows service/config host path".to_owned(),
        ),
        (VmLabPlatform::MacOS, _) => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::TARGET_PLATFORM_UNSUPPORTED,
            "macOS bootstrap phases are not part of the current wrapper surface".to_owned(),
        ),
        (VmLabPlatform::Ios | VmLabPlatform::Android, _) => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::TARGET_PLATFORM_UNSUPPORTED,
            "mobile bootstrap is not part of the current wrapper surface".to_owned(),
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
            "Linux diagnostics are supported through the current shell orchestrator path".to_owned(),
        ),
        VmLabPlatform::Windows => (
            VmLabCapabilityStatus::PartiallySupported,
            reason_code::PARTIALLY_IMPLEMENTED_SUBCAPABILITY,
            "Windows diagnostics are available through PowerShell helpers; the wrapper should still report exact per-target helper coverage".to_owned(),
        ),
        VmLabPlatform::MacOS => (
            VmLabCapabilityStatus::PartiallySupported,
            reason_code::PARTIALLY_IMPLEMENTED_SUBCAPABILITY,
            "macOS diagnostics rely on host-side helpers with limited coverage; wrapper should report exact coverage".to_owned(),
        ),
        VmLabPlatform::Ios | VmLabPlatform::Android => (
            VmLabCapabilityStatus::Unsupported,
            reason_code::TARGET_PLATFORM_UNSUPPORTED,
            "mobile diagnostics are not part of the current wrapper surface".to_owned(),
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

/// Render a multi-line, operator-facing error string from a capability
/// record. Pairs with [`render_capability_summary`]: the summary form is
/// the single-line `scope=... status=... reason_code=... message=...`
/// telemetry shape; this form is what a wrapper site should surface in a
/// user-visible failure message.
///
/// Shape (exact bytes for a non-Supported record):
///
/// ```text
/// rustynet vm-lab: this combination is not supported by the current wrapper path
///   scope: <scope>
///   status: <status>
///   reason_code: <reason_code>
///   details: <message>
/// ```
///
/// For a `Supported` record the first line becomes
/// `"rustynet vm-lab: this combination is supported by the current wrapper path"`,
/// since `render_vm_lab_capability_error` is also useful as the operator-facing
/// form of a positive capability assertion (e.g. dry-run preflight).
///
/// The renderer never invokes [`sanitize_vm_lab_capability_message`]; callers
/// that have not already sanitized externally-sourced messages must do so
/// themselves before passing the record in.
pub fn render_vm_lab_capability_error(record: &VmLabCapabilityRecord) -> String {
    let headline = match record.status {
        VmLabCapabilityStatus::Supported => {
            "rustynet vm-lab: this combination is supported by the current wrapper path"
        }
        VmLabCapabilityStatus::PartiallySupported => {
            "rustynet vm-lab: this combination is only partially supported by the current wrapper path"
        }
        VmLabCapabilityStatus::Unsupported => {
            "rustynet vm-lab: this combination is not supported by the current wrapper path"
        }
    };
    format!(
        "{headline}\n  scope: {scope}\n  status: {status}\n  reason_code: {reason_code}\n  details: {message}",
        scope = record.scope.as_label(),
        status = record.status.as_label(),
        reason_code = record.reason_code,
        message = record.message,
    )
}

/// Reason code used by [`merge_vm_lab_capability_records`] when the merge has
/// no records to fold. Composite scopes always require at least one
/// constituent record; an empty input is treated as fail-closed.
pub const MERGED_EMPTY_INPUT_REASON_CODE: &str = "merge-empty-record-set";

/// Reason code used by [`merge_vm_lab_capability_records`] when the merged
/// record covers records with multiple distinct reason codes. The merged
/// message enumerates them for operator inspection.
pub const MERGED_MIXED_REASON_CODE: &str = "merge-mixed-reasons";

/// Maximum capability message length after sanitization. Capability messages
/// are operator-facing strings only; very long messages either indicate a
/// caller mistake or an attempt to leak data through the capability surface,
/// so the sanitizer truncates beyond this bound with an explicit marker.
pub const MAX_CAPABILITY_MESSAGE_LEN: usize = 1024;

/// Suffix appended by [`sanitize_vm_lab_capability_message`] when the input
/// exceeds [`MAX_CAPABILITY_MESSAGE_LEN`]. The suffix is fixed text so
/// downstream tooling can deterministically detect the truncation case.
pub const SANITIZED_TRUNCATION_SUFFIX: &str = " [truncated]";

/// Defensive sanitizer for capability message bodies. The Slice-1 evaluator
/// always produces ASCII-safe message strings, but capability records may
/// also be constructed externally (e.g. by Slice-2 wrapper-derived merges)
/// from data that has not been bounded. This helper is the single
/// fail-closed sanitizer the wrapper layer can call before surfacing a
/// message in operator output, logs, or the
/// `state/platform_capabilities.json` artifact.
///
/// Rules:
/// 1. Replace any ASCII control byte (0x00..=0x1F, 0x7F) with a single ASCII
///    space. CR/LF are control bytes for this contract — capability
///    messages are one-line strings.
/// 2. Collapse any run of two or more ASCII whitespace characters into a
///    single space.
/// 3. Trim leading and trailing whitespace.
/// 4. Truncate to [`MAX_CAPABILITY_MESSAGE_LEN`] bytes if longer, appending
///    [`SANITIZED_TRUNCATION_SUFFIX`] so the cut is explicit.
///
/// Non-goals:
/// - No secret-pattern matching. The sanitizer never tries to detect or
///   redact secret-shaped substrings; producers must not embed secret
///   material in capability messages in the first place.
/// - No HTML/JSON escaping. JSON escaping is handled when the message is
///   serialized into an artifact (see
///   [`render_platform_capabilities_artifact_json`]).
pub fn sanitize_vm_lab_capability_message(input: &str) -> String {
    let mut out = String::with_capacity(input.len().min(MAX_CAPABILITY_MESSAGE_LEN));
    let mut last_was_space = true; // start "true" so any leading space is dropped
    for ch in input.chars() {
        let normalized = if (ch as u32) <= 0x1F || ch == '\u{7F}' {
            ' '
        } else {
            ch
        };
        if normalized.is_ascii_whitespace() {
            if last_was_space {
                continue;
            }
            out.push(' ');
            last_was_space = true;
        } else {
            out.push(normalized);
            last_was_space = false;
        }
    }
    let trimmed_len = out.trim_end().len();
    out.truncate(trimmed_len);
    if out.len() > MAX_CAPABILITY_MESSAGE_LEN {
        // Truncate at a char boundary to avoid splitting a multi-byte UTF-8
        // sequence, then append the truncation suffix so the cut is explicit.
        let cap = MAX_CAPABILITY_MESSAGE_LEN;
        let mut boundary = cap;
        while boundary > 0 && !out.is_char_boundary(boundary) {
            boundary -= 1;
        }
        out.truncate(boundary);
        out.push_str(SANITIZED_TRUNCATION_SUFFIX);
    }
    out
}

impl From<super::VmGuestPlatform> for VmLabPlatform {
    fn from(value: super::VmGuestPlatform) -> Self {
        match value {
            super::VmGuestPlatform::Linux => VmLabPlatform::Linux,
            super::VmGuestPlatform::Macos => VmLabPlatform::MacOS,
            super::VmGuestPlatform::Windows => VmLabPlatform::Windows,
            super::VmGuestPlatform::Ios => VmLabPlatform::Ios,
            super::VmGuestPlatform::Android => VmLabPlatform::Android,
        }
    }
}

impl From<&super::VmGuestPlatform> for VmLabPlatform {
    fn from(value: &super::VmGuestPlatform) -> Self {
        (*value).into()
    }
}

/// Normalize a slice of wrapper-side [`super::VmGuestPlatform`] values into
/// the capability vocabulary as a stable, deduplicated [`VmLabPlatform`]
/// slice.
///
/// "Stable" means: the first occurrence of each platform family in the input
/// determines its position in the output, mirroring the dedup semantics used
/// elsewhere in this module (see
/// [`merge_vm_lab_capability_records`] mixed-reason enumeration).
///
/// Mirrors the cookbook helper `normalize_vm_lab_platform_mix` and is the
/// canonical bridge that Slice-2 wrapper sites should use before feeding a
/// platform mix into [`validate_vm_lab_target_topology`] or
/// [`evaluate_vm_lab_capability`].
pub fn normalize_vm_lab_platform_mix(guests: &[super::VmGuestPlatform]) -> Vec<VmLabPlatform> {
    let mut out: Vec<VmLabPlatform> = Vec::with_capacity(guests.len());
    for guest in guests {
        let mapped: VmLabPlatform = guest.into();
        if !out.contains(&mapped) {
            out.push(mapped);
        }
    }
    out
}

/// Outcome of [`validate_vm_lab_target_topology`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmLabTopologyValidation {
    /// Topology is honest for the currently supported wrapper path.
    Ok,
    /// Topology is rejected fail-closed. The accompanying capability record
    /// carries the canonical reason code and operator-facing message; the
    /// `scope` field reflects whichever scope the caller asked the validator
    /// to interpret the topology under.
    Rejected(VmLabCapabilityRecord),
}

/// Fail-closed validator for the platform mix of a live-lab topology before
/// any execution begins. The validator is pure and never touches state.
///
/// Contract (in evaluation order):
///
/// 1. Empty platform set is rejected with `target-platform-unsupported`. A
///    wrapper that has no targets at all is not the same as a default-Linux
///    profile — that defaulting belongs in the profile loader, not here.
/// 2. Any mobile platform (`Ios` or `Android`) in the topology is rejected
///    with `target-platform-unsupported`. Mobile is not part of the current
///    wrapper surface.
/// 3. For composite/run/setup scopes (`SetupLiveLab`, `RunLiveLab`,
///    `OrchestrateLiveLab`, `RepoSync`, `Suite`), pure non-Linux desktop
///    topologies are rejected with `linux-shell-orchestrator-only` because
///    the current wrapper still needs a Linux core host. Mixed desktop
///    topologies are accepted so Phase 31's Linux+macOS+Windows profile can
///    run through the platform-aware sidecar stages.
/// 4. Otherwise the topology is `Ok` for the requested scope.
///
/// The `scope` argument decides which scope label the rejection record
/// carries. The validator does not invent a new scope.
pub fn validate_vm_lab_target_topology(
    scope: VmLabCapabilityScope,
    platforms: &[VmLabPlatform],
) -> VmLabTopologyValidation {
    if platforms.is_empty() {
        return VmLabTopologyValidation::Rejected(VmLabCapabilityRecord {
            scope,
            status: VmLabCapabilityStatus::Unsupported,
            reason_code: reason_code::TARGET_PLATFORM_UNSUPPORTED,
            message: "empty target topology: a live-lab wrapper needs at least one target node"
                .to_owned(),
        });
    }
    if platforms
        .iter()
        .any(|p| matches!(p, VmLabPlatform::Ios | VmLabPlatform::Android))
    {
        return VmLabTopologyValidation::Rejected(VmLabCapabilityRecord {
            scope,
            status: VmLabCapabilityStatus::Unsupported,
            reason_code: reason_code::TARGET_PLATFORM_UNSUPPORTED,
            message: "mobile platforms (iOS/Android) are not part of the current wrapper surface"
                .to_owned(),
        });
    }
    // Count distinct desktop platform families.
    let mut distinct: Vec<VmLabPlatform> = Vec::new();
    for platform in platforms {
        if !distinct.contains(platform) {
            distinct.push(*platform);
        }
    }
    let scope_requires_pure_linux = matches!(
        scope,
        VmLabCapabilityScope::SetupLiveLab
            | VmLabCapabilityScope::RunLiveLab
            | VmLabCapabilityScope::OrchestrateLiveLab
            | VmLabCapabilityScope::RepoSync
            | VmLabCapabilityScope::Suite
    );
    if scope_requires_pure_linux && !distinct.contains(&VmLabPlatform::Linux) {
        return VmLabTopologyValidation::Rejected(VmLabCapabilityRecord {
            scope,
            status: VmLabCapabilityStatus::Unsupported,
            reason_code: reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
            message: format!(
                "the current live-lab wrapper path is Linux-shell based and does not yet execute the top-level flow on {} targets",
                distinct[0].as_label(),
            ),
        });
    }
    VmLabTopologyValidation::Ok
}

/// Evaluate a composite scope (Orchestrate / `RepoSync` / Suite) by evaluating
/// each constituent sub-context with the Slice-1 evaluator and folding the
/// results through [`merge_vm_lab_capability_records`].
///
/// The `scope` argument is the composite scope label to attach to the merged
/// record. Constituent sub-contexts may carry any scope; the merge ignores
/// their scopes and uses only their status and reason codes. Empty
/// sub-contexts produce the same fail-closed merged record as
/// `merge_vm_lab_capability_records` on an empty input.
pub fn evaluate_composite_scope(
    scope: VmLabCapabilityScope,
    sub_contexts: &[VmLabCapabilityContext],
) -> VmLabCapabilityRecord {
    let records: Vec<VmLabCapabilityRecord> = sub_contexts
        .iter()
        .copied()
        .map(evaluate_vm_lab_capability)
        .collect();
    merge_vm_lab_capability_records(scope, &records)
}

/// Merge a set of capability records into a single composite record using a
/// weakest-link rule:
///
/// - If any constituent is `Unsupported`, the merged status is `Unsupported`.
/// - Else if any constituent is `PartiallySupported`, the merged status is
///   `PartiallySupported`.
/// - Else every constituent is `Supported`, and the merged status is
///   `Supported`.
///
/// The `scope` argument is the composite scope label to attach to the merged
/// record (typically [`VmLabCapabilityScope::OrchestrateLiveLab`],
/// [`VmLabCapabilityScope::RepoSync`], or [`VmLabCapabilityScope::Suite`]).
///
/// Reason code rules:
///
/// - Empty input -> [`MERGED_EMPTY_INPUT_REASON_CODE`] and `Unsupported`
///   status. Composite scopes never declare success without a constituent.
/// - All constituents share the same `reason_code` -> reuse that
///   constituent code (so the merged record looks like a normal Slice-1
///   record to downstream tooling).
/// - Otherwise -> [`MERGED_MIXED_REASON_CODE`] with the constituent codes
///   enumerated in the message body.
pub fn merge_vm_lab_capability_records(
    scope: VmLabCapabilityScope,
    records: &[VmLabCapabilityRecord],
) -> VmLabCapabilityRecord {
    if records.is_empty() {
        return VmLabCapabilityRecord {
            scope,
            status: VmLabCapabilityStatus::Unsupported,
            reason_code: MERGED_EMPTY_INPUT_REASON_CODE,
            message: "composite capability cannot be derived from an empty record set".to_owned(),
        };
    }

    let mut merged_status = VmLabCapabilityStatus::Supported;
    for record in records {
        merged_status = match (merged_status, record.status) {
            (VmLabCapabilityStatus::Unsupported, _) | (_, VmLabCapabilityStatus::Unsupported) => {
                VmLabCapabilityStatus::Unsupported
            }
            (VmLabCapabilityStatus::PartiallySupported, _)
            | (_, VmLabCapabilityStatus::PartiallySupported) => {
                VmLabCapabilityStatus::PartiallySupported
            }
            _ => VmLabCapabilityStatus::Supported,
        };
    }

    let first_reason = records[0].reason_code;
    let uniform = records.iter().all(|r| r.reason_code == first_reason);
    if uniform {
        return VmLabCapabilityRecord {
            scope,
            status: merged_status,
            reason_code: first_reason,
            message: format!(
                "composite {} records all share reason_code={}",
                records.len(),
                first_reason,
            ),
        };
    }

    // Stable, deterministic mixed-reason enumeration: first occurrence wins,
    // duplicates suppressed.
    let mut seen: Vec<&'static str> = Vec::with_capacity(records.len());
    for record in records {
        if !seen.contains(&record.reason_code) {
            seen.push(record.reason_code);
        }
    }
    let mut message = String::from("composite reason codes: ");
    for (idx, code) in seen.iter().enumerate() {
        if idx > 0 {
            message.push_str(", ");
        }
        message.push_str(code);
    }
    VmLabCapabilityRecord {
        scope,
        status: merged_status,
        reason_code: MERGED_MIXED_REASON_CODE,
        message,
    }
}

// ---------------------------------------------------------------------------
// Slice 4: read-only inspection CLI surface.
//
// `ops vm-lab-report-capabilities` is an inspection-only command: it never
// mutates state, never runs setup, and never gates the wrapper path. It exists
// so operators can ask the same evaluator that Slice 2/3 will use later, in
// advance, against a hypothetical (command, platform, source_mode, topology,
// bootstrap_phase) tuple, and get the exact same answer the wrapper will give.
// ---------------------------------------------------------------------------

/// Parsed inputs for `ops vm-lab-report-capabilities`. Constructed by the CLI
/// parser. The handler is deterministic: given the same config, it always
/// returns the same summary string and writes the same artifact when
/// `output_dir` is set.
/// Output format for `ops vm-lab-report-capabilities`. Defaults to
/// `Summary` (one-line `scope=... status=... reason_code=... message=...`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmLabReportCapabilitiesFormat {
    /// One-line `scope=... status=... reason_code=... message=...` form
    /// produced by [`render_capability_summary`]. Default.
    #[default]
    Summary,
    /// Multi-line operator-facing block produced by
    /// [`render_vm_lab_capability_error`]. Suitable for surfacing the
    /// verdict in a user-visible failure block.
    Error,
}

impl VmLabReportCapabilitiesFormat {
    pub fn as_label(self) -> &'static str {
        match self {
            VmLabReportCapabilitiesFormat::Summary => "Summary",
            VmLabReportCapabilitiesFormat::Error => "Error",
        }
    }
}

/// Parse the `--format` argument. Lowercase kebab-case labels only.
pub fn parse_report_capabilities_format_arg(
    value: &str,
) -> Result<VmLabReportCapabilitiesFormat, String> {
    match value {
        "summary" => Ok(VmLabReportCapabilitiesFormat::Summary),
        "error" => Ok(VmLabReportCapabilitiesFormat::Error),
        other => Err(format!(
            "invalid --format value {other:?}: expected one of summary, error"
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabReportCapabilitiesConfig {
    pub scope: VmLabCapabilityScope,
    pub platform: VmLabPlatform,
    pub source_mode: VmLabSourceMode,
    pub bootstrap_phase: Option<VmLabBootstrapPhase>,
    pub mixed_platform_topology: bool,
    /// Slice 3 artifact emission. When `Some(dir)`, the handler additionally
    /// writes `<dir>/state/platform_capabilities.json` containing the single
    /// evaluated record for this invocation. The artifact path is fixed by
    /// the plan contract; the JSON shape is documented on
    /// [`render_platform_capabilities_artifact_json`].
    pub output_dir: Option<std::path::PathBuf>,
    /// Stdout rendering format. Defaults to `Summary`.
    pub format: VmLabReportCapabilitiesFormat,
    /// When `true` and `output_dir` is set, the handler validates that
    /// `<output_dir>/state/platform_capabilities.json` does not already
    /// exist before writing. Stale dirs are rejected fail-closed; the
    /// existing artifact is not touched. Defaults to `false` so the
    /// inspection CLI keeps its idempotent default for operators who
    /// repeatedly poke at the same temp directory.
    pub require_fresh_output_dir: bool,
}

/// Parse the `--scope` argument. Accepts canonical wrapper command names
/// (e.g. `vm-lab-setup-live-lab`) and the kebab-case label form
/// (e.g. `setup-live-lab`). Anything else is fail-closed.
pub fn parse_scope_arg(value: &str) -> Result<VmLabCapabilityScope, String> {
    if let Some(scope) = command_scope(value) {
        return Ok(scope);
    }
    match value {
        "setup-live-lab" => Ok(VmLabCapabilityScope::SetupLiveLab),
        "run-live-lab" => Ok(VmLabCapabilityScope::RunLiveLab),
        "orchestrate-live-lab" => Ok(VmLabCapabilityScope::OrchestrateLiveLab),
        "bootstrap-phase" => Ok(VmLabCapabilityScope::BootstrapPhase),
        "baseline-diagnostics" => Ok(VmLabCapabilityScope::BaselineDiagnostics),
        "repo-sync" => Ok(VmLabCapabilityScope::RepoSync),
        "suite" => Ok(VmLabCapabilityScope::Suite),
        other => Err(format!(
            "invalid --scope value {other:?}: expected one of setup-live-lab, run-live-lab, \
             orchestrate-live-lab, bootstrap-phase, baseline-diagnostics, repo-sync, suite, or a \
             canonical vm-lab-* command name"
        )),
    }
}

/// Parse the `--platform` argument. Lowercase ASCII labels only. Anything else
/// is fail-closed.
pub fn parse_platform_arg(value: &str) -> Result<VmLabPlatform, String> {
    match value {
        "linux" => Ok(VmLabPlatform::Linux),
        "windows" => Ok(VmLabPlatform::Windows),
        "macos" => Ok(VmLabPlatform::MacOS),
        "ios" => Ok(VmLabPlatform::Ios),
        "android" => Ok(VmLabPlatform::Android),
        other => Err(format!(
            "invalid --platform value {other:?}: expected one of linux, windows, macos, ios, android"
        )),
    }
}

/// Parse the `--source-mode` argument. Kebab-case labels only. Anything else
/// is fail-closed.
pub fn parse_source_mode_arg(value: &str) -> Result<VmLabSourceMode, String> {
    match value {
        "working-tree" => Ok(VmLabSourceMode::WorkingTree),
        "local-head" => Ok(VmLabSourceMode::LocalHead),
        "commit-ref" => Ok(VmLabSourceMode::CommitRef),
        "local-source" => Ok(VmLabSourceMode::LocalSource),
        "repo-url" => Ok(VmLabSourceMode::RepoUrl),
        other => Err(format!(
            "invalid --source-mode value {other:?}: expected one of working-tree, local-head, \
             commit-ref, local-source, repo-url"
        )),
    }
}

/// Parse the `--bootstrap-phase` argument. Kebab-case labels only. Anything
/// else is fail-closed.
pub fn parse_bootstrap_phase_arg(value: &str) -> Result<VmLabBootstrapPhase, String> {
    match value {
        "sync-source" => Ok(VmLabBootstrapPhase::SyncSource),
        "build-release" => Ok(VmLabBootstrapPhase::BuildRelease),
        "install-release" => Ok(VmLabBootstrapPhase::InstallRelease),
        "restart-runtime" => Ok(VmLabBootstrapPhase::RestartRuntime),
        "verify-runtime" => Ok(VmLabBootstrapPhase::VerifyRuntime),
        other => Err(format!(
            "invalid --bootstrap-phase value {other:?}: expected one of sync-source, build-release, \
             install-release, restart-runtime, verify-runtime"
        )),
    }
}

/// Read-only inspection handler for `ops vm-lab-report-capabilities`.
/// Returns the rendered one-line capability summary for the requested
/// `(scope, platform, source_mode, bootstrap_phase, mixed_platform_topology)`
/// tuple. The handler never mutates filesystem, network, or process state.
///
/// Pre-execution validation:
/// - When `scope == BootstrapPhase` the caller must supply
///   `bootstrap_phase`. The fail-closed check is wired here so the CLI does
///   not surface the underlying
///   `BOOTSTRAP_PHASE_MISSING_FOR_BOOTSTRAP_SCOPE` record from a buggy
///   parser flow — that record is reserved for the evaluator's internal
///   contract.
pub fn execute_ops_vm_lab_report_capabilities(
    config: VmLabReportCapabilitiesConfig,
) -> Result<String, String> {
    if matches!(config.scope, VmLabCapabilityScope::BootstrapPhase)
        && config.bootstrap_phase.is_none()
    {
        return Err("--bootstrap-phase is required when --scope is bootstrap-phase".to_owned());
    }
    let context = VmLabCapabilityContext {
        scope: config.scope,
        platform: config.platform,
        source_mode: config.source_mode,
        bootstrap_phase: config.bootstrap_phase,
        mixed_platform_topology: config.mixed_platform_topology,
    };
    let record = evaluate_vm_lab_capability(context);
    if let Some(output_dir) = config.output_dir.as_deref() {
        if config.require_fresh_output_dir
            && let VmLabReportDirFreshness::Stale(existing) =
                validate_vm_lab_report_dir_fresh(output_dir)
        {
            return Err(format!(
                "refusing to overwrite existing platform capabilities artifact at {} \
                 (--require-fresh-output-dir is set; rerun without the flag, or pick a new --output-dir)",
                existing.display(),
            ));
        }
        write_platform_capabilities_artifact(output_dir, std::slice::from_ref(&record))
            .map_err(|err| format!("write platform capabilities artifact failed: {err}"))?;
    }
    let rendered = match config.format {
        VmLabReportCapabilitiesFormat::Summary => render_capability_summary(&record),
        VmLabReportCapabilitiesFormat::Error => render_vm_lab_capability_error(&record),
    };
    Ok(rendered)
}

/// Canonical relative artifact path inside the report dir, per
/// `VmLabCapabilityReportingPlan` Slice 3.
pub const PLATFORM_CAPABILITIES_ARTIFACT_RELATIVE_PATH: &str = "state/platform_capabilities.json";

/// Render the platform capabilities JSON artifact body for a set of records.
///
/// JSON shape:
/// ```text
/// {
///   "schema_version": 1,
///   "records": [
///     {
///       "scope": "...",
///       "status": "...",
///       "reason_code": "...",
///       "message": "..."
///     },
///     ...
///   ]
/// }
/// ```
///
/// The encoder uses only enum-label and reason-code byte sequences that are
/// already validated as ASCII (lowercase kebab-case for reason codes,
/// `PascalCase` for scope/status labels), plus the JSON-escaped `message` field.
/// `\\` and `"` are the only escapes we need to handle today; control
/// characters never appear in evaluator-produced messages by construction
/// (see the `reason_codes_use_kebab_case_lowercase_ascii` and message
/// literals in the evaluator).
pub fn render_platform_capabilities_artifact_json(records: &[VmLabCapabilityRecord]) -> String {
    let mut body = String::new();
    body.push_str("{\"schema_version\":1,\"records\":[");
    for (idx, record) in records.iter().enumerate() {
        if idx > 0 {
            body.push(',');
        }
        body.push_str("{\"scope\":\"");
        body.push_str(record.scope.as_label());
        body.push_str("\",\"status\":\"");
        body.push_str(record.status.as_label());
        body.push_str("\",\"reason_code\":\"");
        body.push_str(record.reason_code);
        body.push_str("\",\"message\":\"");
        for ch in record.message.chars() {
            match ch {
                '"' => body.push_str("\\\""),
                '\\' => body.push_str("\\\\"),
                _ => body.push(ch),
            }
        }
        body.push_str("\"}");
    }
    body.push_str("]}");
    body
}

/// Persist the platform-capabilities artifact at
/// `<output_dir>/state/platform_capabilities.json`. Creates the `state/`
/// subdirectory if needed. Writes are deterministic given the input records.
pub fn write_platform_capabilities_artifact(
    output_dir: &std::path::Path,
    records: &[VmLabCapabilityRecord],
) -> std::io::Result<std::path::PathBuf> {
    let state_dir = output_dir.join("state");
    std::fs::create_dir_all(&state_dir)?;
    let artifact_path = state_dir.join("platform_capabilities.json");
    let body = render_platform_capabilities_artifact_json(records);
    std::fs::write(&artifact_path, body)?;
    Ok(artifact_path)
}

/// Outcome of [`validate_vm_lab_report_dir_fresh`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmLabReportDirFreshness {
    /// The directory does not exist yet, exists but is empty, or exists but
    /// contains no canonical capability artifact at the expected relative
    /// path. Safe to write into.
    Fresh,
    /// The canonical capability artifact already exists at the expected
    /// relative path. Writing would overwrite it. The contained path is the
    /// existing artifact location for the operator to inspect.
    Stale(std::path::PathBuf),
}

/// Pure-but-IO-bound validator that reports whether a candidate report
/// directory is fresh for writing the
/// `state/platform_capabilities.json` artifact. The validator never
/// mutates state — it never creates directories, never removes existing
/// artifacts, and never writes anything. Callers decide whether to fail
/// closed on `Stale` based on their own freshness policy.
///
/// Specifically:
///
/// - If `report_dir` does not exist on disk, the result is `Fresh`. The
///   subsequent write helper will create it.
/// - If `report_dir` exists but does not contain
///   `<report_dir>/state/platform_capabilities.json`, the result is
///   `Fresh`. Other unrelated artifacts in the directory are not a
///   freshness violation for the capability surface.
/// - If `<report_dir>/state/platform_capabilities.json` already exists,
///   the result is `Stale(path_to_existing_artifact)` so the caller can
///   surface that path in the rejection message.
///
/// `Stale` is the only fail-closed outcome a freshness-strict caller
/// should reject on; readers and idempotent rewriters should accept it.
pub fn validate_vm_lab_report_dir_fresh(report_dir: &std::path::Path) -> VmLabReportDirFreshness {
    let artifact_path = report_dir.join(PLATFORM_CAPABILITIES_ARTIFACT_RELATIVE_PATH);
    if artifact_path.exists() {
        VmLabReportDirFreshness::Stale(artifact_path)
    } else {
        VmLabReportDirFreshness::Fresh
    }
}

/// Inputs that led to a particular capability outcome. The struct is
/// strictly informational; it never claims to express enforcement and never
/// re-runs the evaluator. It exists so downstream tooling (error logs,
/// failure artifacts, ops review bundles) can render a deterministic block
/// that captures both *what was asked for* and *what the evaluator decided*
/// without depending on the wrapper site's local string-building.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabCapabilityFailureContext {
    pub command: String,
    pub context: VmLabCapabilityContext,
    pub record: VmLabCapabilityRecord,
}

impl VmLabCapabilityFailureContext {
    /// Build a failure-context bundle from a command name and the inputs
    /// that were fed to the evaluator. The capability record is re-derived
    /// via `evaluate_vm_lab_capability(context)` so the bundle is always
    /// internally consistent: caller cannot pass a mismatched record.
    ///
    /// Slice 2 callers can drop this bundle straight into a log line, an
    /// audit artifact, or an error response, and downstream consumers will
    /// always see the same shape.
    pub fn new(command: impl Into<String>, context: VmLabCapabilityContext) -> Self {
        let record = evaluate_vm_lab_capability(context);
        Self {
            command: command.into(),
            context,
            record,
        }
    }

    /// True when the carried record is `Unsupported`. Convenience for
    /// callers that need to fail closed without re-matching on the inner
    /// status.
    pub fn is_blocker(&self) -> bool {
        matches!(self.record.status, VmLabCapabilityStatus::Unsupported)
    }
}

/// Render a deterministic operator-facing failure block from a capability
/// failure context. Pairs with [`render_vm_lab_capability_error`]: the
/// existing renderer takes just a record; this renderer also includes the
/// command identity and the input tuple, so the block is reproducible from
/// the bundle alone.
///
/// Shape (exact lines for an Unsupported record):
///
/// ```text
/// rustynet vm-lab failure: <command>
///   scope: <scope>
///   status: <status>
///   reason_code: <reason_code>
///   details: <message>
///   inputs:
///     platform: <platform>
///     source_mode: <source_mode>
///     mixed_platform_topology: <true|false>
///     bootstrap_phase: <phase|none>
/// ```
///
/// For Supported / `PartiallySupported` records the headline stays the same
/// (it documents the bundle's origin, not a positive assertion); the
/// per-status status field communicates the actual outcome.
pub fn render_vm_lab_capability_failure_block(ctx: &VmLabCapabilityFailureContext) -> String {
    let bootstrap_phase = match ctx.context.bootstrap_phase {
        Some(phase) => phase.as_label(),
        None => "none",
    };
    format!(
        "rustynet vm-lab failure: {command}\n  scope: {scope}\n  status: {status}\n  reason_code: {reason_code}\n  details: {message}\n  inputs:\n    platform: {platform}\n    source_mode: {source_mode}\n    mixed_platform_topology: {mixed}\n    bootstrap_phase: {bootstrap_phase}",
        command = ctx.command,
        scope = ctx.record.scope.as_label(),
        status = ctx.record.status.as_label(),
        reason_code = ctx.record.reason_code,
        message = ctx.record.message,
        platform = ctx.context.platform.as_label(),
        source_mode = ctx.context.source_mode.as_label(),
        mixed = ctx.context.mixed_platform_topology,
        bootstrap_phase = bootstrap_phase,
    )
}

/// Wrapper-side adapter: gather a command name plus the input axes into a
/// ready-to-use [`VmLabCapabilityFailureContext`] (which carries the
/// evaluator's verdict, ready for `is_blocker()` checks and the failure-
/// block renderer).
///
/// The command name is mapped to a scope via [`command_scope`]. If the
/// command is not a known wrapper entry point this function fails closed
/// — wrapper sites must surface a precise error rather than guessing a
/// scope.
///
/// This is the canonical entry point for Slice-2 wrapper integration: a
/// wrapper site should hand its command name plus the input axes to this
/// function and then act on the returned bundle, rather than constructing
/// `VmLabCapabilityContext` directly. Centralising assembly here means
/// future capability-evaluator extensions are picked up everywhere
/// automatically.
pub fn collect_vm_lab_capability_inputs(
    command: &str,
    platform: VmLabPlatform,
    source_mode: VmLabSourceMode,
    bootstrap_phase: Option<VmLabBootstrapPhase>,
    mixed_platform_topology: bool,
) -> Result<VmLabCapabilityFailureContext, String> {
    let Some(scope) = command_scope(command) else {
        return Err(format!(
            "unknown vm-lab command for capability collection: {command:?}"
        ));
    };
    let context = VmLabCapabilityContext {
        scope,
        platform,
        source_mode,
        bootstrap_phase,
        mixed_platform_topology,
    };
    Ok(VmLabCapabilityFailureContext::new(command, context))
}

/// Outcome of [`validate_vm_lab_capability_preconditions`]. The umbrella
/// validator returns a single typed verdict so wrapper sites can match on
/// `Ok` to proceed or surface the carried failure context directly to the
/// operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmLabCapabilityPrecondition {
    /// Inputs cleared every precondition. The carried record reflects the
    /// evaluator's verdict for the supplied tuple — usually `Supported` or
    /// `PartiallySupported`. Wrapper sites should still inspect the record
    /// status if they need to gate composite scopes more aggressively than
    /// the topology validator does.
    Ok(VmLabCapabilityFailureContext),
    /// Inputs failed a precondition. The carried context carries the
    /// canonical failure record (`Unsupported` plus the precise reason
    /// code) and the inputs that led to the rejection.
    Blocked(VmLabCapabilityFailureContext),
}

impl VmLabCapabilityPrecondition {
    /// True for the `Blocked` variant.
    pub fn is_blocked(&self) -> bool {
        matches!(self, VmLabCapabilityPrecondition::Blocked(_))
    }

    /// Borrow the underlying failure context regardless of variant. Useful
    /// for callers that always log the bundle (Ok or Blocked) and then
    /// branch on the variant separately.
    pub fn failure_context(&self) -> &VmLabCapabilityFailureContext {
        match self {
            VmLabCapabilityPrecondition::Ok(ctx) | VmLabCapabilityPrecondition::Blocked(ctx) => ctx,
        }
    }
}

/// Umbrella wrapper-precondition validator. Chains the existing capability
/// surface — [`command_scope`], [`normalize_vm_lab_platform_mix`],
/// [`validate_vm_lab_target_topology`], and the Slice-1 evaluator — into a
/// single fail-closed entry point that wrapper sites can call before any
/// mutation begins. This is the canonical wrapper-precondition helper
/// foreseen by `VmLabCapabilityReportingPlan`'s cookbook
/// (`validate_vm_lab_capability_preconditions`).
///
/// Behaviour:
///
/// 1. The command name is mapped to a capability scope via
///    [`command_scope`]. Unknown commands fail closed with `Err(String)`
///    so the wrapper surfaces a precise parser-level error, not a typed
///    `Blocked` outcome — that taxonomy is reserved for capability
///    rejections, not interface misuse.
/// 2. The wrapper-side platform mix is normalized through
///    [`normalize_vm_lab_platform_mix`] and validated by
///    [`validate_vm_lab_target_topology`] against the resolved scope. A
///    topology rejection is returned as `Blocked` carrying the validator's
///    record plus the inputs.
/// 3. If topology validation passes, the validator builds the standard
///    [`VmLabCapabilityFailureContext`] for the
///    `(scope, primary_platform, source_mode, bootstrap_phase,
///      mixed_platform_topology)` tuple. The bundle's record reflects the
///    Slice-1 evaluator's verdict. If the record's status is
///    `Unsupported` (e.g. Windows install-release bootstrap), the
///    validator returns `Blocked`. Otherwise it returns `Ok` with the same
///    bundle so the wrapper still gets the canonical telemetry surface.
///
/// `primary_platform` is the platform attached to the capability context
/// (e.g. the bootstrap target platform or the wrapper's selected
/// platform). For Phase 31 mixed desktop topologies it remains the Linux
/// core platform; the topology validator rejects pure non-Linux and mobile
/// mixes before execution.
pub fn validate_vm_lab_capability_preconditions(
    command: &str,
    primary_platform: VmLabPlatform,
    source_mode: VmLabSourceMode,
    bootstrap_phase: Option<VmLabBootstrapPhase>,
    topology: &[super::VmGuestPlatform],
) -> Result<VmLabCapabilityPrecondition, String> {
    let Some(scope) = command_scope(command) else {
        return Err(format!(
            "unknown vm-lab command for capability preconditions: {command:?}"
        ));
    };
    let mix = normalize_vm_lab_platform_mix(topology);
    let mixed_platform_topology = mix.len() > 1;
    if let VmLabTopologyValidation::Rejected(rejection) =
        validate_vm_lab_target_topology(scope, &mix)
    {
        let context = VmLabCapabilityContext {
            scope,
            platform: primary_platform,
            source_mode,
            bootstrap_phase,
            mixed_platform_topology,
        };
        let bundle = VmLabCapabilityFailureContext {
            command: command.to_owned(),
            context,
            // The topology rejection record IS the canonical failure
            // record for this precondition. Keep it intact (its
            // reason_code and message describe the topology gap exactly)
            // rather than re-deriving via the Slice-1 evaluator.
            record: rejection,
        };
        return Ok(VmLabCapabilityPrecondition::Blocked(bundle));
    }
    let bundle = VmLabCapabilityFailureContext::new(
        command,
        VmLabCapabilityContext {
            scope,
            platform: primary_platform,
            source_mode,
            bootstrap_phase,
            mixed_platform_topology,
        },
    );
    if bundle.is_blocker() {
        Ok(VmLabCapabilityPrecondition::Blocked(bundle))
    } else {
        Ok(VmLabCapabilityPrecondition::Ok(bundle))
    }
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
        assert_eq!(record.status, VmLabCapabilityStatus::Supported);
        assert_eq!(
            record.reason_code,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY
        );
        assert!(record.message.contains("mixed-OS"));
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
            message: "hello".to_owned(),
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
    fn render_error_uses_unsupported_headline_for_unsupported_record() {
        let record = evaluate_vm_lab_capability(ctx_windows(VmLabCapabilityScope::SetupLiveLab));
        let out = render_vm_lab_capability_error(&record);
        let mut lines = out.lines();
        assert_eq!(
            lines.next().unwrap(),
            "rustynet vm-lab: this combination is not supported by the current wrapper path"
        );
        assert_eq!(lines.next().unwrap(), "  scope: SetupLiveLab");
        assert_eq!(lines.next().unwrap(), "  status: Unsupported");
        assert_eq!(
            lines.next().unwrap(),
            "  reason_code: linux-shell-orchestrator-only"
        );
        assert!(lines.next().unwrap().starts_with("  details: "));
        assert!(
            lines.next().is_none(),
            "error block must have exactly five lines"
        );
    }

    #[test]
    fn render_error_uses_supported_headline_for_supported_record() {
        let record = evaluate_vm_lab_capability(ctx_linux(VmLabCapabilityScope::SetupLiveLab));
        let out = render_vm_lab_capability_error(&record);
        assert!(out.starts_with(
            "rustynet vm-lab: this combination is supported by the current wrapper path\n"
        ));
        assert!(out.contains("status: Supported"));
        assert!(out.contains("reason_code: linux-shell-orchestrator-only"));
    }

    #[test]
    fn render_error_uses_partial_headline_for_partial_record() {
        // Windows BaselineDiagnostics -> PartiallySupported per Slice-1.
        let mut ctx = ctx_windows(VmLabCapabilityScope::BaselineDiagnostics);
        ctx.platform = VmLabPlatform::Windows;
        let record = evaluate_vm_lab_capability(ctx);
        let out = render_vm_lab_capability_error(&record);
        assert!(out.starts_with(
            "rustynet vm-lab: this combination is only partially supported by the current wrapper path\n"
        ));
        assert!(out.contains("status: PartiallySupported"));
    }

    #[test]
    fn render_error_does_not_invoke_sanitizer_so_the_caller_controls_message_shape() {
        let record = VmLabCapabilityRecord {
            scope: VmLabCapabilityScope::SetupLiveLab,
            status: VmLabCapabilityStatus::Unsupported,
            reason_code: reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
            message: "preserved\twith\ttabs".to_owned(),
        };
        let out = render_vm_lab_capability_error(&record);
        // The tabs survive untouched — sanitization is the caller's
        // responsibility, by design.
        assert!(out.contains("preserved\twith\ttabs"));
    }

    #[test]
    fn render_error_is_idempotent_for_same_record() {
        let record = evaluate_vm_lab_capability(ctx_windows(VmLabCapabilityScope::SetupLiveLab));
        let a = render_vm_lab_capability_error(&record);
        let b = render_vm_lab_capability_error(&record);
        let c = render_vm_lab_capability_error(&record);
        assert_eq!(a, b);
        assert_eq!(b, c);
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

    // ----- merge_vm_lab_capability_records -----

    fn record(
        status: VmLabCapabilityStatus,
        reason: &'static str,
        message: &str,
    ) -> VmLabCapabilityRecord {
        VmLabCapabilityRecord {
            scope: VmLabCapabilityScope::SetupLiveLab,
            status,
            reason_code: reason,
            message: message.to_owned(),
        }
    }

    #[test]
    fn merge_empty_record_set_is_unsupported_with_dedicated_reason_code() {
        let merged = merge_vm_lab_capability_records(VmLabCapabilityScope::OrchestrateLiveLab, &[]);
        assert_eq!(merged.scope, VmLabCapabilityScope::OrchestrateLiveLab);
        assert_eq!(merged.status, VmLabCapabilityStatus::Unsupported);
        assert_eq!(merged.reason_code, MERGED_EMPTY_INPUT_REASON_CODE);
    }

    #[test]
    fn merge_all_supported_with_uniform_reason_reuses_constituent_reason_code() {
        let records = vec![
            record(
                VmLabCapabilityStatus::Supported,
                reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
                "a",
            ),
            record(
                VmLabCapabilityStatus::Supported,
                reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
                "b",
            ),
        ];
        let merged = merge_vm_lab_capability_records(VmLabCapabilityScope::Suite, &records);
        assert_eq!(merged.status, VmLabCapabilityStatus::Supported);
        assert_eq!(
            merged.reason_code,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY
        );
        assert!(merged.message.contains("2 records"));
    }

    #[test]
    fn merge_any_partial_demotes_to_partial_when_no_unsupported() {
        let records = vec![
            record(
                VmLabCapabilityStatus::Supported,
                reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
                "linux ok",
            ),
            record(
                VmLabCapabilityStatus::PartiallySupported,
                reason_code::PARTIALLY_IMPLEMENTED_SUBCAPABILITY,
                "partial",
            ),
        ];
        let merged = merge_vm_lab_capability_records(VmLabCapabilityScope::RepoSync, &records);
        assert_eq!(merged.status, VmLabCapabilityStatus::PartiallySupported);
        assert_eq!(merged.reason_code, MERGED_MIXED_REASON_CODE);
        assert!(merged.message.contains("linux-shell-orchestrator-only"));
        assert!(
            merged
                .message
                .contains("partially-implemented-subcapability")
        );
    }

    #[test]
    fn merge_any_unsupported_demotes_to_unsupported_even_with_supported_present() {
        let records = vec![
            record(
                VmLabCapabilityStatus::Supported,
                reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
                "ok",
            ),
            record(
                VmLabCapabilityStatus::PartiallySupported,
                reason_code::PARTIALLY_IMPLEMENTED_SUBCAPABILITY,
                "partial",
            ),
            record(
                VmLabCapabilityStatus::Unsupported,
                reason_code::RUNTIME_HOST_NOT_YET_IMPLEMENTED,
                "blocked",
            ),
        ];
        let merged =
            merge_vm_lab_capability_records(VmLabCapabilityScope::OrchestrateLiveLab, &records);
        assert_eq!(merged.status, VmLabCapabilityStatus::Unsupported);
        assert_eq!(merged.reason_code, MERGED_MIXED_REASON_CODE);
        assert!(merged.message.starts_with("composite reason codes:"));
    }

    #[test]
    fn merge_mixed_reason_codes_deduplicate_in_message() {
        let records = vec![
            record(
                VmLabCapabilityStatus::Unsupported,
                reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
                "a",
            ),
            record(
                VmLabCapabilityStatus::Unsupported,
                reason_code::TARGET_PLATFORM_UNSUPPORTED,
                "b",
            ),
            record(
                VmLabCapabilityStatus::Unsupported,
                reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
                "c",
            ),
        ];
        let merged = merge_vm_lab_capability_records(VmLabCapabilityScope::Suite, &records);
        assert_eq!(merged.reason_code, MERGED_MIXED_REASON_CODE);
        // Each reason should appear once, in first-seen order.
        let body = merged.message.as_str();
        let linux_idx = body.find("linux-shell-orchestrator-only").unwrap();
        let target_idx = body.find("target-platform-unsupported").unwrap();
        assert!(linux_idx < target_idx, "first-seen order must be preserved");
        assert_eq!(
            body.matches("linux-shell-orchestrator-only").count(),
            1,
            "duplicate reason codes must be deduped"
        );
    }

    #[test]
    fn merge_uniform_all_unsupported_reuses_constituent_reason_code() {
        let records = vec![
            record(
                VmLabCapabilityStatus::Unsupported,
                reason_code::RUNTIME_HOST_NOT_YET_IMPLEMENTED,
                "a",
            ),
            record(
                VmLabCapabilityStatus::Unsupported,
                reason_code::RUNTIME_HOST_NOT_YET_IMPLEMENTED,
                "b",
            ),
        ];
        let merged = merge_vm_lab_capability_records(VmLabCapabilityScope::Suite, &records);
        assert_eq!(merged.status, VmLabCapabilityStatus::Unsupported);
        assert_eq!(
            merged.reason_code,
            reason_code::RUNTIME_HOST_NOT_YET_IMPLEMENTED
        );
    }

    #[test]
    fn merge_preserves_caller_provided_scope_regardless_of_constituent_scopes() {
        // Constituents have SetupLiveLab scope (built by `record`), but the
        // merged record must adopt whatever composite scope the caller passes.
        let records = vec![record(
            VmLabCapabilityStatus::Supported,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
            "a",
        )];
        let merged_a =
            merge_vm_lab_capability_records(VmLabCapabilityScope::OrchestrateLiveLab, &records);
        let merged_b = merge_vm_lab_capability_records(VmLabCapabilityScope::RepoSync, &records);
        let merged_c = merge_vm_lab_capability_records(VmLabCapabilityScope::Suite, &records);
        assert_eq!(merged_a.scope, VmLabCapabilityScope::OrchestrateLiveLab);
        assert_eq!(merged_b.scope, VmLabCapabilityScope::RepoSync);
        assert_eq!(merged_c.scope, VmLabCapabilityScope::Suite);
    }

    #[test]
    fn merge_is_deterministic_for_same_inputs() {
        let records = vec![
            record(
                VmLabCapabilityStatus::Supported,
                reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
                "a",
            ),
            record(
                VmLabCapabilityStatus::PartiallySupported,
                reason_code::COMPOSITE_CAPABILITY,
                "b",
            ),
            record(
                VmLabCapabilityStatus::Unsupported,
                reason_code::TARGET_PLATFORM_UNSUPPORTED,
                "c",
            ),
        ];
        let first = merge_vm_lab_capability_records(VmLabCapabilityScope::Suite, &records);
        let second = merge_vm_lab_capability_records(VmLabCapabilityScope::Suite, &records);
        assert_eq!(first, second);
    }

    // ----- normalize_vm_lab_platform_mix -----

    #[test]
    fn from_vm_guest_platform_maps_every_variant_to_vm_lab_platform() {
        assert_eq!(
            VmLabPlatform::from(super::super::VmGuestPlatform::Linux),
            VmLabPlatform::Linux
        );
        assert_eq!(
            VmLabPlatform::from(super::super::VmGuestPlatform::Macos),
            VmLabPlatform::MacOS
        );
        assert_eq!(
            VmLabPlatform::from(super::super::VmGuestPlatform::Windows),
            VmLabPlatform::Windows
        );
        assert_eq!(
            VmLabPlatform::from(super::super::VmGuestPlatform::Ios),
            VmLabPlatform::Ios
        );
        assert_eq!(
            VmLabPlatform::from(super::super::VmGuestPlatform::Android),
            VmLabPlatform::Android
        );
    }

    #[test]
    fn from_borrowed_vm_guest_platform_matches_owned() {
        let guest = super::super::VmGuestPlatform::Windows;
        let owned: VmLabPlatform = guest.into();
        let borrowed: VmLabPlatform = (&guest).into();
        assert_eq!(owned, borrowed);
        assert_eq!(owned, VmLabPlatform::Windows);
    }

    #[test]
    fn normalize_empty_input_returns_empty_vec() {
        assert_eq!(
            normalize_vm_lab_platform_mix(&[]),
            Vec::<VmLabPlatform>::new()
        );
    }

    #[test]
    fn normalize_preserves_first_occurrence_order() {
        let guests = [
            super::super::VmGuestPlatform::Windows,
            super::super::VmGuestPlatform::Linux,
            super::super::VmGuestPlatform::Macos,
            super::super::VmGuestPlatform::Linux,
        ];
        assert_eq!(
            normalize_vm_lab_platform_mix(&guests),
            vec![
                VmLabPlatform::Windows,
                VmLabPlatform::Linux,
                VmLabPlatform::MacOS,
            ]
        );
    }

    #[test]
    fn normalize_dedupes_repeated_platform_families() {
        let guests = [
            super::super::VmGuestPlatform::Linux,
            super::super::VmGuestPlatform::Linux,
            super::super::VmGuestPlatform::Linux,
        ];
        assert_eq!(
            normalize_vm_lab_platform_mix(&guests),
            vec![VmLabPlatform::Linux]
        );
    }

    #[test]
    fn normalize_output_feeds_validate_topology_without_extra_translation() {
        let guests = [
            super::super::VmGuestPlatform::Linux,
            super::super::VmGuestPlatform::Linux,
            super::super::VmGuestPlatform::Windows,
        ];
        let mix = normalize_vm_lab_platform_mix(&guests);
        // Phase 31 permits a Linux-core mixed desktop topology. The
        // normalized mix should feed the topology validator directly
        // without an extra translation or compatibility shim.
        let result = validate_vm_lab_target_topology(VmLabCapabilityScope::SetupLiveLab, &mix);
        assert_eq!(result, VmLabTopologyValidation::Ok);
    }

    #[test]
    fn normalize_output_is_idempotent_under_round_trip_via_validate_topology() {
        // Two equal guest mixes (one with extra duplicates) must produce
        // identical normalized output, and therefore identical validator
        // outcomes.
        let a = [
            super::super::VmGuestPlatform::Linux,
            super::super::VmGuestPlatform::Windows,
        ];
        let b = [
            super::super::VmGuestPlatform::Linux,
            super::super::VmGuestPlatform::Linux,
            super::super::VmGuestPlatform::Windows,
            super::super::VmGuestPlatform::Windows,
        ];
        let mix_a = normalize_vm_lab_platform_mix(&a);
        let mix_b = normalize_vm_lab_platform_mix(&b);
        assert_eq!(mix_a, mix_b);
        let result_a = validate_vm_lab_target_topology(VmLabCapabilityScope::SetupLiveLab, &mix_a);
        let result_b = validate_vm_lab_target_topology(VmLabCapabilityScope::SetupLiveLab, &mix_b);
        assert_eq!(result_a, result_b);
    }

    // ----- validate_vm_lab_target_topology -----

    fn assert_rejected(
        result: VmLabTopologyValidation,
        expected_status: VmLabCapabilityStatus,
        expected_code: &'static str,
    ) -> VmLabCapabilityRecord {
        match result {
            VmLabTopologyValidation::Rejected(rec) => {
                assert_eq!(rec.status, expected_status);
                assert_eq!(rec.reason_code, expected_code);
                rec
            }
            VmLabTopologyValidation::Ok => panic!("expected rejection, got Ok"),
        }
    }

    #[test]
    fn validate_topology_pure_linux_setup_is_ok() {
        let platforms = vec![VmLabPlatform::Linux; 5];
        assert_eq!(
            validate_vm_lab_target_topology(VmLabCapabilityScope::SetupLiveLab, &platforms),
            VmLabTopologyValidation::Ok,
        );
    }

    #[test]
    fn validate_topology_empty_platform_set_is_rejected_with_target_platform_unsupported() {
        assert_rejected(
            validate_vm_lab_target_topology(VmLabCapabilityScope::SetupLiveLab, &[]),
            VmLabCapabilityStatus::Unsupported,
            reason_code::TARGET_PLATFORM_UNSUPPORTED,
        );
    }

    #[test]
    fn validate_topology_with_ios_target_is_rejected_with_target_platform_unsupported() {
        let platforms = vec![VmLabPlatform::Linux, VmLabPlatform::Ios];
        assert_rejected(
            validate_vm_lab_target_topology(VmLabCapabilityScope::SetupLiveLab, &platforms),
            VmLabCapabilityStatus::Unsupported,
            reason_code::TARGET_PLATFORM_UNSUPPORTED,
        );
    }

    #[test]
    fn validate_topology_with_android_target_is_rejected_with_target_platform_unsupported() {
        let platforms = vec![VmLabPlatform::Android];
        assert_rejected(
            validate_vm_lab_target_topology(VmLabCapabilityScope::RunLiveLab, &platforms),
            VmLabCapabilityStatus::Unsupported,
            reason_code::TARGET_PLATFORM_UNSUPPORTED,
        );
    }

    #[test]
    fn validate_topology_mixed_linux_and_windows_is_supported() {
        let platforms = vec![
            VmLabPlatform::Linux,
            VmLabPlatform::Linux,
            VmLabPlatform::Windows,
        ];
        assert_eq!(
            validate_vm_lab_target_topology(VmLabCapabilityScope::SetupLiveLab, &platforms),
            VmLabTopologyValidation::Ok,
        );
    }

    #[test]
    fn validate_topology_mixed_desktop_is_supported_for_live_lab_wrapper_scopes() {
        let platforms = vec![
            VmLabPlatform::Linux,
            VmLabPlatform::MacOS,
            VmLabPlatform::Windows,
        ];
        for scope in [
            VmLabCapabilityScope::SetupLiveLab,
            VmLabCapabilityScope::RunLiveLab,
            VmLabCapabilityScope::OrchestrateLiveLab,
            VmLabCapabilityScope::RepoSync,
            VmLabCapabilityScope::Suite,
        ] {
            assert_eq!(
                validate_vm_lab_target_topology(scope, &platforms),
                VmLabTopologyValidation::Ok,
                "mixed desktop topology must be accepted for {scope:?}"
            );
        }
    }

    #[test]
    fn validate_topology_pure_windows_is_rejected_with_linux_shell_orchestrator_only() {
        let platforms = vec![VmLabPlatform::Windows; 3];
        let rec = assert_rejected(
            validate_vm_lab_target_topology(VmLabCapabilityScope::SetupLiveLab, &platforms),
            VmLabCapabilityStatus::Unsupported,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
        );
        assert!(rec.message.contains("Windows"));
    }

    #[test]
    fn validate_topology_pure_macos_is_rejected_with_linux_shell_orchestrator_only() {
        let platforms = vec![VmLabPlatform::MacOS];
        let rec = assert_rejected(
            validate_vm_lab_target_topology(VmLabCapabilityScope::OrchestrateLiveLab, &platforms),
            VmLabCapabilityStatus::Unsupported,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
        );
        assert!(rec.message.contains("MacOS"));
    }

    #[test]
    fn validate_topology_attaches_caller_scope_to_rejection_record() {
        let platforms = vec![VmLabPlatform::Windows];
        let scopes = [
            VmLabCapabilityScope::SetupLiveLab,
            VmLabCapabilityScope::RunLiveLab,
            VmLabCapabilityScope::OrchestrateLiveLab,
            VmLabCapabilityScope::RepoSync,
            VmLabCapabilityScope::Suite,
        ];
        for scope in scopes {
            let rec = assert_rejected(
                validate_vm_lab_target_topology(scope, &platforms),
                VmLabCapabilityStatus::Unsupported,
                reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
            );
            assert_eq!(rec.scope, scope);
        }
    }

    #[test]
    fn validate_topology_bootstrap_phase_scope_accepts_pure_windows_topology() {
        // BootstrapPhase is one of the scopes that does NOT require a pure-
        // Linux topology — Windows bootstrap phases are evaluated separately
        // by the Slice-1 evaluator. The topology validator must not reject
        // pure-Windows targets when the caller is evaluating bootstrap.
        let platforms = vec![VmLabPlatform::Windows; 2];
        assert_eq!(
            validate_vm_lab_target_topology(VmLabCapabilityScope::BootstrapPhase, &platforms),
            VmLabTopologyValidation::Ok,
        );
    }

    // ----- sanitize_vm_lab_capability_message -----

    #[test]
    fn sanitize_preserves_normal_ascii_message_unchanged() {
        let input = "the current live-lab wrapper path is Linux-shell based";
        assert_eq!(sanitize_vm_lab_capability_message(input), input);
    }

    #[test]
    fn sanitize_replaces_control_characters_with_spaces() {
        let input = "hello\x01world\x02!";
        assert_eq!(sanitize_vm_lab_capability_message(input), "hello world !");
    }

    #[test]
    fn sanitize_replaces_cr_and_lf_with_spaces_and_collapses_runs() {
        let input = "line one\nline two\r\nline three\n\nfour";
        assert_eq!(
            sanitize_vm_lab_capability_message(input),
            "line one line two line three four"
        );
    }

    #[test]
    fn sanitize_collapses_multiple_spaces_into_one() {
        let input = "a   b    c";
        assert_eq!(sanitize_vm_lab_capability_message(input), "a b c");
    }

    #[test]
    fn sanitize_trims_leading_and_trailing_whitespace() {
        let input = "   middle    ";
        assert_eq!(sanitize_vm_lab_capability_message(input), "middle");
    }

    #[test]
    fn sanitize_handles_tabs_and_form_feeds_as_control_characters() {
        let input = "a\tb\x0Cc";
        assert_eq!(sanitize_vm_lab_capability_message(input), "a b c");
    }

    #[test]
    fn sanitize_handles_delete_character() {
        let input = "alpha\x7Fbeta";
        assert_eq!(sanitize_vm_lab_capability_message(input), "alpha beta");
    }

    #[test]
    fn sanitize_empty_input_returns_empty_string() {
        assert_eq!(sanitize_vm_lab_capability_message(""), "");
    }

    #[test]
    fn sanitize_whitespace_only_input_returns_empty_string() {
        assert_eq!(sanitize_vm_lab_capability_message("   \n\t  "), "");
    }

    #[test]
    fn sanitize_truncates_overlong_input_and_marks_truncation() {
        let big = "a".repeat(MAX_CAPABILITY_MESSAGE_LEN + 100);
        let out = sanitize_vm_lab_capability_message(big.as_str());
        assert!(out.ends_with(SANITIZED_TRUNCATION_SUFFIX));
        let body_len = out.len() - SANITIZED_TRUNCATION_SUFFIX.len();
        assert!(
            body_len <= MAX_CAPABILITY_MESSAGE_LEN,
            "body length {body_len} must respect the cap"
        );
    }

    #[test]
    fn sanitize_preserves_multibyte_utf8_when_truncating() {
        // Build a string whose final ASCII char lives near the cap, but
        // followed by a multi-byte char that would straddle the byte cap.
        // The sanitizer must back off to the nearest char boundary, not
        // split the multi-byte sequence.
        let prefix_len = MAX_CAPABILITY_MESSAGE_LEN - 1;
        let mut input = "a".repeat(prefix_len);
        input.push('é'); // 2 bytes
        input.push_str(&"b".repeat(64));
        let out = sanitize_vm_lab_capability_message(input.as_str());
        // The result must still be valid UTF-8 — String guarantees this, so
        // we just verify the truncation marker is present and the prefix
        // length is reasonable.
        assert!(out.ends_with(SANITIZED_TRUNCATION_SUFFIX));
        // No partial char before the suffix: the body must be valid UTF-8.
        let body = &out[..out.len() - SANITIZED_TRUNCATION_SUFFIX.len()];
        assert!(std::str::from_utf8(body.as_bytes()).is_ok());
    }

    #[test]
    fn sanitize_is_idempotent() {
        let input = "hello\n\t\x00 world  ";
        let first = sanitize_vm_lab_capability_message(input);
        let second = sanitize_vm_lab_capability_message(first.as_str());
        assert_eq!(first, second);
    }

    // ----- evaluate_composite_scope -----

    fn raw_context(scope: VmLabCapabilityScope, platform: VmLabPlatform) -> VmLabCapabilityContext {
        VmLabCapabilityContext {
            scope,
            platform,
            source_mode: VmLabSourceMode::LocalHead,
            bootstrap_phase: None,
            mixed_platform_topology: false,
        }
    }

    #[test]
    fn evaluate_composite_scope_with_empty_sub_contexts_fails_closed() {
        let merged = evaluate_composite_scope(VmLabCapabilityScope::OrchestrateLiveLab, &[]);
        assert_eq!(merged.scope, VmLabCapabilityScope::OrchestrateLiveLab);
        assert_eq!(merged.status, VmLabCapabilityStatus::Unsupported);
        assert_eq!(merged.reason_code, MERGED_EMPTY_INPUT_REASON_CODE);
    }

    #[test]
    fn evaluate_composite_scope_promotes_to_supported_only_when_every_subcontext_is_supported() {
        let subs = [
            raw_context(VmLabCapabilityScope::SetupLiveLab, VmLabPlatform::Linux),
            raw_context(VmLabCapabilityScope::RunLiveLab, VmLabPlatform::Linux),
        ];
        let merged = evaluate_composite_scope(VmLabCapabilityScope::OrchestrateLiveLab, &subs);
        assert_eq!(merged.status, VmLabCapabilityStatus::Supported);
        assert_eq!(
            merged.reason_code,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY
        );
    }

    #[test]
    fn evaluate_composite_scope_demotes_to_unsupported_when_any_subcontext_is_unsupported() {
        let subs = [
            raw_context(VmLabCapabilityScope::SetupLiveLab, VmLabPlatform::Linux),
            raw_context(VmLabCapabilityScope::RunLiveLab, VmLabPlatform::Windows),
        ];
        let merged = evaluate_composite_scope(VmLabCapabilityScope::OrchestrateLiveLab, &subs);
        assert_eq!(merged.status, VmLabCapabilityStatus::Unsupported);
        // Windows RunLiveLab returns linux-shell-orchestrator-only; Linux
        // SetupLiveLab returns linux-shell-orchestrator-only too. Uniform
        // reason code is reused.
        assert_eq!(
            merged.reason_code,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY
        );
    }

    #[test]
    fn evaluate_composite_scope_demotes_to_partial_when_baseline_diagnostics_is_partial_on_windows()
    {
        // Linux Setup -> Supported (linux-shell-orchestrator-only)
        // Windows BaselineDiagnostics -> PartiallySupported (partially-implemented-subcapability)
        // Composite -> PartiallySupported, mixed reason codes
        let subs = [
            raw_context(VmLabCapabilityScope::SetupLiveLab, VmLabPlatform::Linux),
            raw_context(
                VmLabCapabilityScope::BaselineDiagnostics,
                VmLabPlatform::Windows,
            ),
        ];
        let merged = evaluate_composite_scope(VmLabCapabilityScope::Suite, &subs);
        assert_eq!(merged.status, VmLabCapabilityStatus::PartiallySupported);
        assert_eq!(merged.reason_code, MERGED_MIXED_REASON_CODE);
        assert!(merged.message.contains("linux-shell-orchestrator-only"));
        assert!(
            merged
                .message
                .contains("partially-implemented-subcapability")
        );
    }

    #[test]
    fn evaluate_composite_scope_preserves_caller_provided_scope_label() {
        let subs = [raw_context(
            VmLabCapabilityScope::SetupLiveLab,
            VmLabPlatform::Linux,
        )];
        let a = evaluate_composite_scope(VmLabCapabilityScope::OrchestrateLiveLab, &subs);
        let b = evaluate_composite_scope(VmLabCapabilityScope::RepoSync, &subs);
        let c = evaluate_composite_scope(VmLabCapabilityScope::Suite, &subs);
        assert_eq!(a.scope, VmLabCapabilityScope::OrchestrateLiveLab);
        assert_eq!(b.scope, VmLabCapabilityScope::RepoSync);
        assert_eq!(c.scope, VmLabCapabilityScope::Suite);
    }

    #[test]
    fn evaluate_composite_scope_is_deterministic_for_same_subcontexts() {
        let subs = [
            raw_context(VmLabCapabilityScope::SetupLiveLab, VmLabPlatform::Linux),
            raw_context(VmLabCapabilityScope::RunLiveLab, VmLabPlatform::Windows),
            raw_context(
                VmLabCapabilityScope::BaselineDiagnostics,
                VmLabPlatform::MacOS,
            ),
        ];
        let first = evaluate_composite_scope(VmLabCapabilityScope::Suite, &subs);
        let second = evaluate_composite_scope(VmLabCapabilityScope::Suite, &subs);
        assert_eq!(first, second);
    }

    // ----- Slice 4: inspection CLI -----

    fn linux_setup_config() -> VmLabReportCapabilitiesConfig {
        VmLabReportCapabilitiesConfig {
            scope: VmLabCapabilityScope::SetupLiveLab,
            platform: VmLabPlatform::Linux,
            source_mode: VmLabSourceMode::LocalHead,
            bootstrap_phase: None,
            mixed_platform_topology: false,
            output_dir: None,
            format: VmLabReportCapabilitiesFormat::Summary,
            require_fresh_output_dir: false,
        }
    }

    #[test]
    fn parse_format_accepts_summary_and_error_labels() {
        assert_eq!(
            parse_report_capabilities_format_arg("summary").unwrap(),
            VmLabReportCapabilitiesFormat::Summary
        );
        assert_eq!(
            parse_report_capabilities_format_arg("error").unwrap(),
            VmLabReportCapabilitiesFormat::Error
        );
    }

    #[test]
    fn parse_format_rejects_unknown_and_uppercase_values() {
        for bad in ["", "Summary", "ERROR", "json", "block"] {
            assert!(
                parse_report_capabilities_format_arg(bad).is_err(),
                "expected error for {bad:?}"
            );
        }
    }

    #[test]
    fn report_capabilities_format_summary_is_default() {
        // The default-derived format is Summary, matching the previous
        // single-output behaviour.
        let default = VmLabReportCapabilitiesFormat::default();
        assert_eq!(default, VmLabReportCapabilitiesFormat::Summary);
    }

    #[test]
    fn report_capabilities_with_summary_format_returns_one_line_summary() {
        let out = execute_ops_vm_lab_report_capabilities(linux_setup_config()).unwrap();
        // One-line summary form does not start with the multi-line block
        // headline.
        assert!(!out.starts_with("rustynet vm-lab:"));
        assert!(out.starts_with("scope=SetupLiveLab status=Supported"));
        assert!(!out.contains('\n'));
    }

    #[test]
    fn report_capabilities_with_error_format_returns_multi_line_block() {
        let mut config = linux_setup_config();
        config.format = VmLabReportCapabilitiesFormat::Error;
        let out = execute_ops_vm_lab_report_capabilities(config).unwrap();
        assert!(out.starts_with("rustynet vm-lab:"));
        assert!(out.contains("scope: SetupLiveLab"));
        assert!(out.contains("status: Supported"));
        assert!(out.contains("reason_code: linux-shell-orchestrator-only"));
        assert!(out.contains("details: "));
        // Multi-line block has exactly 5 lines (no trailing newline).
        assert_eq!(out.lines().count(), 5);
    }

    #[test]
    fn report_capabilities_with_error_format_still_writes_artifact_when_output_dir_set() {
        let tmp = std::env::temp_dir().join(format!(
            "rustynet-cli-cap-format-error-artifact-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let mut config = linux_setup_config();
        config.format = VmLabReportCapabilitiesFormat::Error;
        config.output_dir = Some(tmp.clone());
        let out = execute_ops_vm_lab_report_capabilities(config).unwrap();
        // Stdout is the multi-line block...
        assert!(out.starts_with("rustynet vm-lab:"));
        // ...but the artifact still lands in the canonical location.
        let body = std::fs::read_to_string(tmp.join(PLATFORM_CAPABILITIES_ARTIFACT_RELATIVE_PATH))
            .expect("artifact must exist after a successful error-format invocation");
        assert!(body.starts_with("{\"schema_version\":1,"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn parse_scope_accepts_label_and_canonical_command_name() {
        assert_eq!(
            parse_scope_arg("setup-live-lab").unwrap(),
            VmLabCapabilityScope::SetupLiveLab
        );
        assert_eq!(
            parse_scope_arg("vm-lab-setup-live-lab").unwrap(),
            VmLabCapabilityScope::SetupLiveLab
        );
        assert_eq!(
            parse_scope_arg("run-live-lab").unwrap(),
            VmLabCapabilityScope::RunLiveLab
        );
        assert_eq!(
            parse_scope_arg("orchestrate-live-lab").unwrap(),
            VmLabCapabilityScope::OrchestrateLiveLab
        );
        assert_eq!(
            parse_scope_arg("bootstrap-phase").unwrap(),
            VmLabCapabilityScope::BootstrapPhase
        );
        assert_eq!(
            parse_scope_arg("baseline-diagnostics").unwrap(),
            VmLabCapabilityScope::BaselineDiagnostics
        );
        assert_eq!(
            parse_scope_arg("repo-sync").unwrap(),
            VmLabCapabilityScope::RepoSync
        );
        assert_eq!(
            parse_scope_arg("suite").unwrap(),
            VmLabCapabilityScope::Suite
        );
    }

    #[test]
    fn parse_scope_rejects_unknown_and_empty_values() {
        for bad in [
            "",
            "Setup-Live-Lab",
            "linux",
            "vm-lab-unknown",
            "setup live lab",
        ] {
            assert!(parse_scope_arg(bad).is_err(), "expected error for {bad:?}");
        }
    }

    #[test]
    fn parse_platform_accepts_lowercase_labels() {
        assert_eq!(parse_platform_arg("linux").unwrap(), VmLabPlatform::Linux);
        assert_eq!(
            parse_platform_arg("windows").unwrap(),
            VmLabPlatform::Windows
        );
        assert_eq!(parse_platform_arg("macos").unwrap(), VmLabPlatform::MacOS);
        assert_eq!(parse_platform_arg("ios").unwrap(), VmLabPlatform::Ios);
        assert_eq!(
            parse_platform_arg("android").unwrap(),
            VmLabPlatform::Android
        );
    }

    #[test]
    fn parse_platform_rejects_uppercase_and_unknown_values() {
        for bad in ["", "Linux", "WINDOWS", "darwin", "ubuntu"] {
            assert!(
                parse_platform_arg(bad).is_err(),
                "expected error for {bad:?}"
            );
        }
    }

    #[test]
    fn parse_source_mode_accepts_kebab_case_labels() {
        assert_eq!(
            parse_source_mode_arg("working-tree").unwrap(),
            VmLabSourceMode::WorkingTree
        );
        assert_eq!(
            parse_source_mode_arg("local-head").unwrap(),
            VmLabSourceMode::LocalHead
        );
        assert_eq!(
            parse_source_mode_arg("commit-ref").unwrap(),
            VmLabSourceMode::CommitRef
        );
        assert_eq!(
            parse_source_mode_arg("local-source").unwrap(),
            VmLabSourceMode::LocalSource
        );
        assert_eq!(
            parse_source_mode_arg("repo-url").unwrap(),
            VmLabSourceMode::RepoUrl
        );
    }

    #[test]
    fn parse_source_mode_rejects_unknown_and_empty_values() {
        for bad in ["", "WorkingTree", "main", "git"] {
            assert!(
                parse_source_mode_arg(bad).is_err(),
                "expected error for {bad:?}"
            );
        }
    }

    #[test]
    fn parse_bootstrap_phase_accepts_kebab_case_labels() {
        assert_eq!(
            parse_bootstrap_phase_arg("sync-source").unwrap(),
            VmLabBootstrapPhase::SyncSource
        );
        assert_eq!(
            parse_bootstrap_phase_arg("build-release").unwrap(),
            VmLabBootstrapPhase::BuildRelease
        );
        assert_eq!(
            parse_bootstrap_phase_arg("install-release").unwrap(),
            VmLabBootstrapPhase::InstallRelease
        );
        assert_eq!(
            parse_bootstrap_phase_arg("restart-runtime").unwrap(),
            VmLabBootstrapPhase::RestartRuntime
        );
        assert_eq!(
            parse_bootstrap_phase_arg("verify-runtime").unwrap(),
            VmLabBootstrapPhase::VerifyRuntime
        );
    }

    #[test]
    fn parse_bootstrap_phase_rejects_unknown_and_empty_values() {
        for bad in ["", "SyncSource", "all", "verify"] {
            assert!(
                parse_bootstrap_phase_arg(bad).is_err(),
                "expected error for {bad:?}"
            );
        }
    }

    #[test]
    fn report_capabilities_returns_linux_setup_supported_summary() {
        let out = execute_ops_vm_lab_report_capabilities(linux_setup_config()).unwrap();
        assert_eq!(
            out,
            "scope=SetupLiveLab status=Supported \
             reason_code=linux-shell-orchestrator-only \
             message=supported through the current Linux shell orchestrator path"
        );
    }

    #[test]
    fn report_capabilities_is_idempotent() {
        let first = execute_ops_vm_lab_report_capabilities(linux_setup_config()).unwrap();
        let second = execute_ops_vm_lab_report_capabilities(linux_setup_config()).unwrap();
        let third = execute_ops_vm_lab_report_capabilities(linux_setup_config()).unwrap();
        assert_eq!(first, second);
        assert_eq!(second, third);
    }

    #[test]
    fn report_capabilities_returns_windows_setup_unsupported_summary() {
        let mut config = linux_setup_config();
        config.platform = VmLabPlatform::Windows;
        let out = execute_ops_vm_lab_report_capabilities(config).unwrap();
        assert!(out.starts_with("scope=SetupLiveLab status=Unsupported"));
        assert!(out.contains("reason_code=linux-shell-orchestrator-only"));
    }

    #[test]
    fn report_capabilities_returns_windows_bootstrap_install_release_blocked_summary() {
        let config = VmLabReportCapabilitiesConfig {
            scope: VmLabCapabilityScope::BootstrapPhase,
            platform: VmLabPlatform::Windows,
            source_mode: VmLabSourceMode::LocalHead,
            bootstrap_phase: Some(VmLabBootstrapPhase::InstallRelease),
            mixed_platform_topology: false,
            output_dir: None,
            format: VmLabReportCapabilitiesFormat::Summary,
            require_fresh_output_dir: false,
        };
        let out = execute_ops_vm_lab_report_capabilities(config).unwrap();
        assert!(out.starts_with("scope=BootstrapPhase status=Unsupported"));
        assert!(out.contains("reason_code=runtime-host-not-yet-implemented"));
    }

    #[test]
    fn report_capabilities_returns_linux_setup_mixed_topology_supported() {
        let mut config = linux_setup_config();
        config.mixed_platform_topology = true;
        let out = execute_ops_vm_lab_report_capabilities(config).unwrap();
        assert!(out.starts_with("scope=SetupLiveLab status=Supported"));
        assert!(out.contains("reason_code=linux-shell-orchestrator-only"));
        assert!(out.contains("mixed-OS"));
    }

    #[test]
    fn report_capabilities_requires_bootstrap_phase_for_bootstrap_scope() {
        let mut config = linux_setup_config();
        config.scope = VmLabCapabilityScope::BootstrapPhase;
        config.bootstrap_phase = None;
        let err = execute_ops_vm_lab_report_capabilities(config)
            .expect_err("must fail-closed without --bootstrap-phase");
        assert!(
            err.contains("--bootstrap-phase is required"),
            "unexpected error: {err}"
        );
    }

    // ----- Slice 3: artifact emission -----

    #[test]
    fn render_artifact_emits_schema_version_and_records_array() {
        let record = evaluate_vm_lab_capability(ctx_linux(VmLabCapabilityScope::SetupLiveLab));
        let body = render_platform_capabilities_artifact_json(std::slice::from_ref(&record));
        assert!(body.starts_with("{\"schema_version\":1,\"records\":["));
        assert!(body.ends_with("]}"));
        assert!(body.contains("\"scope\":\"SetupLiveLab\""));
        assert!(body.contains("\"status\":\"Supported\""));
        assert!(body.contains("\"reason_code\":\"linux-shell-orchestrator-only\""));
        assert!(body.contains(
            "\"message\":\"supported through the current Linux shell orchestrator path\""
        ));
    }

    #[test]
    fn render_artifact_supports_multiple_records_in_order() {
        let records = vec![
            evaluate_vm_lab_capability(ctx_linux(VmLabCapabilityScope::SetupLiveLab)),
            evaluate_vm_lab_capability(ctx_windows(VmLabCapabilityScope::SetupLiveLab)),
        ];
        let body = render_platform_capabilities_artifact_json(&records);
        let first = body.find("\"status\":\"Supported\"").unwrap();
        let second = body.find("\"status\":\"Unsupported\"").unwrap();
        assert!(
            first < second,
            "records must be serialized in input order: {body}"
        );
        assert!(body.contains("},{"));
    }

    #[test]
    fn render_artifact_escapes_double_quote_and_backslash_in_message() {
        let record = VmLabCapabilityRecord {
            scope: VmLabCapabilityScope::SetupLiveLab,
            status: VmLabCapabilityStatus::Supported,
            reason_code: reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY,
            message: "needs \"quotes\" and a backslash \\ here".to_owned(),
        };
        let body = render_platform_capabilities_artifact_json(std::slice::from_ref(&record));
        assert!(body.contains("\\\"quotes\\\""));
        assert!(body.contains("backslash \\\\ here"));
    }

    #[test]
    fn write_artifact_creates_state_subdir_and_returns_path() {
        let tmp = std::env::temp_dir().join(format!(
            "rustynet-cli-platform-capabilities-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let record = evaluate_vm_lab_capability(ctx_linux(VmLabCapabilityScope::SetupLiveLab));
        let path = write_platform_capabilities_artifact(&tmp, std::slice::from_ref(&record))
            .expect("artifact write should succeed");
        assert_eq!(path, tmp.join(PLATFORM_CAPABILITIES_ARTIFACT_RELATIVE_PATH));
        let body = std::fs::read_to_string(&path).expect("artifact should be readable");
        assert!(body.starts_with("{\"schema_version\":1,"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn write_artifact_is_idempotent_for_same_records() {
        let tmp = std::env::temp_dir().join(format!(
            "rustynet-cli-platform-capabilities-idem-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let record = evaluate_vm_lab_capability(ctx_linux(VmLabCapabilityScope::SetupLiveLab));
        let path_a = write_platform_capabilities_artifact(&tmp, std::slice::from_ref(&record))
            .expect("first write should succeed");
        let body_a = std::fs::read_to_string(&path_a).unwrap();
        let path_b = write_platform_capabilities_artifact(&tmp, std::slice::from_ref(&record))
            .expect("second write should succeed");
        let body_b = std::fs::read_to_string(&path_b).unwrap();
        assert_eq!(path_a, path_b);
        assert_eq!(body_a, body_b);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn report_capabilities_emits_artifact_when_output_dir_is_set() {
        let tmp = std::env::temp_dir().join(format!(
            "rustynet-cli-platform-capabilities-cli-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let mut config = linux_setup_config();
        config.output_dir = Some(tmp.clone());
        let summary = execute_ops_vm_lab_report_capabilities(config).unwrap();
        assert!(summary.contains("status=Supported"));
        let artifact_path = tmp.join(PLATFORM_CAPABILITIES_ARTIFACT_RELATIVE_PATH);
        let body = std::fs::read_to_string(&artifact_path)
            .expect("artifact must exist after a successful invocation");
        assert!(body.contains("\"scope\":\"SetupLiveLab\""));
        assert!(body.contains("\"status\":\"Supported\""));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn report_capabilities_does_not_emit_artifact_when_output_dir_is_unset() {
        let tmp = std::env::temp_dir().join(format!(
            "rustynet-cli-platform-capabilities-noop-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::create_dir_all(&tmp);
        let summary = execute_ops_vm_lab_report_capabilities(linux_setup_config()).unwrap();
        assert!(summary.contains("status=Supported"));
        assert!(
            !tmp.join("state")
                .join("platform_capabilities.json")
                .exists(),
            "artifact must not be created when output_dir is None"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn report_capabilities_does_not_emit_artifact_when_handler_fails_closed() {
        let tmp = std::env::temp_dir().join(format!(
            "rustynet-cli-platform-capabilities-fail-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let mut config = linux_setup_config();
        config.scope = VmLabCapabilityScope::BootstrapPhase;
        config.bootstrap_phase = None;
        config.output_dir = Some(tmp.clone());
        let err = execute_ops_vm_lab_report_capabilities(config)
            .expect_err("must fail-closed when bootstrap-phase missing");
        assert!(err.contains("--bootstrap-phase is required"));
        assert!(
            !tmp.join("state")
                .join("platform_capabilities.json")
                .exists(),
            "fail-closed handler must not leave a partial artifact behind"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn report_capabilities_passes_bootstrap_phase_through_for_non_bootstrap_scopes() {
        // A non-BootstrapPhase scope still accepts a bootstrap_phase value;
        // the evaluator just ignores it. The handler must not over-reject in
        // that case.
        let config = VmLabReportCapabilitiesConfig {
            scope: VmLabCapabilityScope::SetupLiveLab,
            platform: VmLabPlatform::Linux,
            source_mode: VmLabSourceMode::LocalHead,
            bootstrap_phase: Some(VmLabBootstrapPhase::SyncSource),
            mixed_platform_topology: false,
            output_dir: None,
            format: VmLabReportCapabilitiesFormat::Summary,
            require_fresh_output_dir: false,
        };
        let out = execute_ops_vm_lab_report_capabilities(config).unwrap();
        assert!(out.starts_with("scope=SetupLiveLab status=Supported"));
    }

    // ----- validate_vm_lab_capability_preconditions (umbrella validator) -----

    #[test]
    fn preconditions_unknown_command_returns_parser_error_not_blocked() {
        let result = validate_vm_lab_capability_preconditions(
            "vm-lab-not-real",
            VmLabPlatform::Linux,
            VmLabSourceMode::LocalHead,
            None,
            &[super::super::VmGuestPlatform::Linux],
        );
        let err = result.expect_err("unknown command must fail closed at parser level");
        assert!(err.contains("unknown vm-lab command for capability preconditions"));
    }

    #[test]
    fn preconditions_pure_linux_setup_is_ok_supported_bundle() {
        let outcome = validate_vm_lab_capability_preconditions(
            "vm-lab-setup-live-lab",
            VmLabPlatform::Linux,
            VmLabSourceMode::LocalHead,
            None,
            &[super::super::VmGuestPlatform::Linux; 5],
        )
        .expect("known command must parse");
        assert!(!outcome.is_blocked());
        let bundle = outcome.failure_context();
        assert_eq!(bundle.context.scope, VmLabCapabilityScope::SetupLiveLab);
        assert!(!bundle.context.mixed_platform_topology);
        assert_eq!(bundle.record.status, VmLabCapabilityStatus::Supported);
    }

    #[test]
    fn preconditions_mixed_desktop_topology_returns_supported_linux_core_record() {
        let outcome = validate_vm_lab_capability_preconditions(
            "vm-lab-setup-live-lab",
            VmLabPlatform::Linux,
            VmLabSourceMode::LocalHead,
            None,
            &[
                super::super::VmGuestPlatform::Linux,
                super::super::VmGuestPlatform::Linux,
                super::super::VmGuestPlatform::Windows,
            ],
        )
        .expect("known command must parse");
        assert!(!outcome.is_blocked());
        let bundle = outcome.failure_context();
        assert!(bundle.context.mixed_platform_topology);
        assert_eq!(bundle.record.status, VmLabCapabilityStatus::Supported);
        assert_eq!(
            bundle.record.reason_code,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY
        );
        assert!(bundle.record.message.contains("mixed-OS"));
    }

    #[test]
    fn preconditions_pure_windows_topology_returns_blocked_with_linux_shell_only_record() {
        let outcome = validate_vm_lab_capability_preconditions(
            "vm-lab-setup-live-lab",
            VmLabPlatform::Windows,
            VmLabSourceMode::LocalHead,
            None,
            &[super::super::VmGuestPlatform::Windows; 2],
        )
        .expect("known command must parse");
        assert!(outcome.is_blocked());
        let bundle = outcome.failure_context();
        assert_eq!(
            bundle.record.reason_code,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY
        );
    }

    #[test]
    fn preconditions_bootstrap_phase_windows_install_release_returns_blocked_runtime_host() {
        let outcome = validate_vm_lab_capability_preconditions(
            "vm-lab-bootstrap-phase",
            VmLabPlatform::Windows,
            VmLabSourceMode::LocalHead,
            Some(VmLabBootstrapPhase::InstallRelease),
            // BootstrapPhase scope accepts pure-Windows topology; the
            // Slice-1 evaluator then gates per-(platform, phase).
            &[super::super::VmGuestPlatform::Windows],
        )
        .expect("known command must parse");
        assert!(outcome.is_blocked());
        let bundle = outcome.failure_context();
        assert_eq!(bundle.context.scope, VmLabCapabilityScope::BootstrapPhase);
        assert_eq!(
            bundle.record.reason_code,
            reason_code::RUNTIME_HOST_NOT_YET_IMPLEMENTED
        );
    }

    #[test]
    fn preconditions_bootstrap_phase_windows_sync_source_is_supported() {
        let outcome = validate_vm_lab_capability_preconditions(
            "vm-lab-bootstrap-phase",
            VmLabPlatform::Windows,
            VmLabSourceMode::LocalHead,
            Some(VmLabBootstrapPhase::SyncSource),
            &[super::super::VmGuestPlatform::Windows],
        )
        .expect("known command must parse");
        assert!(!outcome.is_blocked());
        let bundle = outcome.failure_context();
        assert_eq!(bundle.record.status, VmLabCapabilityStatus::Supported);
        assert_eq!(
            bundle.record.reason_code,
            reason_code::PLATFORM_SPECIFIC_HELPER_AVAILABLE
        );
    }

    #[test]
    fn preconditions_empty_topology_returns_blocked_with_target_platform_unsupported() {
        let outcome = validate_vm_lab_capability_preconditions(
            "vm-lab-setup-live-lab",
            VmLabPlatform::Linux,
            VmLabSourceMode::LocalHead,
            None,
            &[],
        )
        .expect("known command must parse");
        assert!(outcome.is_blocked());
        let bundle = outcome.failure_context();
        assert_eq!(
            bundle.record.reason_code,
            reason_code::TARGET_PLATFORM_UNSUPPORTED
        );
    }

    #[test]
    fn preconditions_ios_topology_returns_blocked_with_target_platform_unsupported() {
        let outcome = validate_vm_lab_capability_preconditions(
            "vm-lab-setup-live-lab",
            VmLabPlatform::Linux,
            VmLabSourceMode::LocalHead,
            None,
            &[
                super::super::VmGuestPlatform::Linux,
                super::super::VmGuestPlatform::Ios,
            ],
        )
        .expect("known command must parse");
        assert!(outcome.is_blocked());
        let bundle = outcome.failure_context();
        assert_eq!(
            bundle.record.reason_code,
            reason_code::TARGET_PLATFORM_UNSUPPORTED
        );
    }

    #[test]
    fn preconditions_failure_context_carries_command_and_inputs() {
        let outcome = validate_vm_lab_capability_preconditions(
            "vm-lab-setup-live-lab",
            VmLabPlatform::Windows,
            VmLabSourceMode::CommitRef,
            None,
            &[super::super::VmGuestPlatform::Windows],
        )
        .unwrap();
        let bundle = outcome.failure_context();
        assert_eq!(bundle.command, "vm-lab-setup-live-lab");
        assert_eq!(bundle.context.source_mode, VmLabSourceMode::CommitRef);
        assert_eq!(bundle.context.platform, VmLabPlatform::Windows);
    }

    #[test]
    fn preconditions_is_deterministic_for_same_inputs() {
        let inputs = || {
            validate_vm_lab_capability_preconditions(
                "vm-lab-setup-live-lab",
                VmLabPlatform::Linux,
                VmLabSourceMode::LocalHead,
                None,
                &[super::super::VmGuestPlatform::Linux],
            )
            .unwrap()
        };
        let a = inputs();
        let b = inputs();
        assert_eq!(a, b);
    }

    // ----- collect_vm_lab_capability_inputs -----

    #[test]
    fn collect_inputs_maps_known_command_to_scope_and_carries_record() {
        let bundle = collect_vm_lab_capability_inputs(
            "vm-lab-setup-live-lab",
            VmLabPlatform::Linux,
            VmLabSourceMode::LocalHead,
            None,
            false,
        )
        .expect("known wrapper command must map to a scope");
        assert_eq!(bundle.command, "vm-lab-setup-live-lab");
        assert_eq!(bundle.context.scope, VmLabCapabilityScope::SetupLiveLab);
        assert_eq!(bundle.record.status, VmLabCapabilityStatus::Supported);
        assert_eq!(
            bundle.record.reason_code,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY
        );
        assert!(!bundle.is_blocker());
    }

    #[test]
    fn collect_inputs_for_windows_setup_returns_unsupported_blocker_bundle() {
        let bundle = collect_vm_lab_capability_inputs(
            "vm-lab-setup-live-lab",
            VmLabPlatform::Windows,
            VmLabSourceMode::LocalHead,
            None,
            false,
        )
        .expect("known wrapper command must map to a scope");
        assert!(bundle.is_blocker());
        assert_eq!(
            bundle.record.reason_code,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY
        );
    }

    #[test]
    fn collect_inputs_threads_bootstrap_phase_into_context_and_record() {
        let bundle = collect_vm_lab_capability_inputs(
            "vm-lab-bootstrap-phase",
            VmLabPlatform::Windows,
            VmLabSourceMode::LocalHead,
            Some(VmLabBootstrapPhase::InstallRelease),
            false,
        )
        .unwrap();
        assert_eq!(bundle.context.scope, VmLabCapabilityScope::BootstrapPhase);
        assert_eq!(
            bundle.context.bootstrap_phase,
            Some(VmLabBootstrapPhase::InstallRelease)
        );
        assert!(bundle.is_blocker());
        assert_eq!(
            bundle.record.reason_code,
            reason_code::RUNTIME_HOST_NOT_YET_IMPLEMENTED
        );
    }

    #[test]
    fn collect_inputs_threads_mixed_platform_topology_flag_into_context() {
        let bundle = collect_vm_lab_capability_inputs(
            "vm-lab-setup-live-lab",
            VmLabPlatform::Linux,
            VmLabSourceMode::LocalHead,
            None,
            true,
        )
        .unwrap();
        assert!(bundle.context.mixed_platform_topology);
        assert!(!bundle.is_blocker());
        assert_eq!(bundle.record.status, VmLabCapabilityStatus::Supported);
        assert_eq!(
            bundle.record.reason_code,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY
        );
        assert!(bundle.record.message.contains("mixed-OS"));
    }

    #[test]
    fn collect_inputs_fails_closed_on_unknown_command_name() {
        let err = collect_vm_lab_capability_inputs(
            "vm-lab-this-does-not-exist",
            VmLabPlatform::Linux,
            VmLabSourceMode::LocalHead,
            None,
            false,
        )
        .expect_err("unknown command must fail closed");
        assert!(err.contains("unknown vm-lab command"));
        assert!(err.contains("vm-lab-this-does-not-exist"));
    }

    #[test]
    fn collect_inputs_render_block_matches_command_identity() {
        let bundle = collect_vm_lab_capability_inputs(
            "vm-lab-setup-live-lab",
            VmLabPlatform::Windows,
            VmLabSourceMode::LocalHead,
            None,
            false,
        )
        .unwrap();
        let rendered = render_vm_lab_capability_failure_block(&bundle);
        assert!(rendered.starts_with("rustynet vm-lab failure: vm-lab-setup-live-lab\n"));
        assert!(rendered.contains("status: Unsupported"));
    }

    // ----- VmLabCapabilityFailureContext / render_vm_lab_capability_failure_block -----

    #[test]
    fn failure_context_rederives_record_from_inputs() {
        let ctx = ctx_windows(VmLabCapabilityScope::SetupLiveLab);
        let bundle = VmLabCapabilityFailureContext::new("vm-lab-setup-live-lab", ctx);
        assert_eq!(bundle.command, "vm-lab-setup-live-lab");
        assert_eq!(bundle.context, ctx);
        assert_eq!(bundle.record.status, VmLabCapabilityStatus::Unsupported);
        assert_eq!(
            bundle.record.reason_code,
            reason_code::LINUX_SHELL_ORCHESTRATOR_ONLY
        );
    }

    #[test]
    fn failure_context_is_blocker_true_only_for_unsupported_record() {
        let unsupported = VmLabCapabilityFailureContext::new(
            "x",
            ctx_windows(VmLabCapabilityScope::SetupLiveLab),
        );
        assert!(unsupported.is_blocker());

        let supported =
            VmLabCapabilityFailureContext::new("x", ctx_linux(VmLabCapabilityScope::SetupLiveLab));
        assert!(!supported.is_blocker());

        let partial = VmLabCapabilityFailureContext::new(
            "x",
            VmLabCapabilityContext {
                scope: VmLabCapabilityScope::BaselineDiagnostics,
                platform: VmLabPlatform::Windows,
                source_mode: VmLabSourceMode::LocalHead,
                bootstrap_phase: None,
                mixed_platform_topology: false,
            },
        );
        assert!(!partial.is_blocker());
    }

    #[test]
    fn render_failure_block_includes_command_scope_status_reason_and_inputs() {
        let ctx = ctx_windows(VmLabCapabilityScope::SetupLiveLab);
        let bundle = VmLabCapabilityFailureContext::new("vm-lab-setup-live-lab", ctx);
        let rendered = render_vm_lab_capability_failure_block(&bundle);
        assert!(rendered.starts_with("rustynet vm-lab failure: vm-lab-setup-live-lab\n"));
        assert!(rendered.contains("scope: SetupLiveLab"));
        assert!(rendered.contains("status: Unsupported"));
        assert!(rendered.contains("reason_code: linux-shell-orchestrator-only"));
        assert!(rendered.contains("details: "));
        assert!(rendered.contains("inputs:"));
        assert!(rendered.contains("platform: Windows"));
        assert!(rendered.contains("source_mode: LocalHead"));
        assert!(rendered.contains("mixed_platform_topology: false"));
        assert!(rendered.contains("bootstrap_phase: none"));
    }

    #[test]
    fn render_failure_block_shows_bootstrap_phase_label_when_set() {
        let ctx = VmLabCapabilityContext {
            scope: VmLabCapabilityScope::BootstrapPhase,
            platform: VmLabPlatform::Windows,
            source_mode: VmLabSourceMode::LocalHead,
            bootstrap_phase: Some(VmLabBootstrapPhase::InstallRelease),
            mixed_platform_topology: false,
        };
        let bundle = VmLabCapabilityFailureContext::new("vm-lab-bootstrap-phase", ctx);
        let rendered = render_vm_lab_capability_failure_block(&bundle);
        assert!(rendered.contains("bootstrap_phase: InstallRelease"));
        assert!(rendered.contains("reason_code: runtime-host-not-yet-implemented"));
    }

    #[test]
    fn render_failure_block_is_deterministic_for_same_bundle() {
        let bundle = VmLabCapabilityFailureContext::new(
            "vm-lab-setup-live-lab",
            ctx_windows(VmLabCapabilityScope::SetupLiveLab),
        );
        let a = render_vm_lab_capability_failure_block(&bundle);
        let b = render_vm_lab_capability_failure_block(&bundle);
        assert_eq!(a, b);
    }

    #[test]
    fn render_failure_block_mixed_topology_flag_shown_as_supported_linux_core() {
        let mut ctx = ctx_linux(VmLabCapabilityScope::SetupLiveLab);
        ctx.mixed_platform_topology = true;
        let bundle = VmLabCapabilityFailureContext::new("vm-lab-setup-live-lab", ctx);
        let rendered = render_vm_lab_capability_failure_block(&bundle);
        assert!(rendered.contains("mixed_platform_topology: true"));
        assert!(rendered.contains("status: Supported"));
        assert!(rendered.contains("reason_code: linux-shell-orchestrator-only"));
        assert!(rendered.contains("mixed-OS"));
    }

    // ----- validate_vm_lab_report_dir_fresh -----

    #[test]
    fn validate_report_dir_fresh_for_non_existent_dir_returns_fresh() {
        let tmp = std::env::temp_dir().join(format!(
            "rustynet-cli-report-dir-fresh-nonexistent-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(!tmp.exists());
        assert_eq!(
            validate_vm_lab_report_dir_fresh(&tmp),
            VmLabReportDirFreshness::Fresh
        );
    }

    #[test]
    fn validate_report_dir_fresh_for_empty_existing_dir_returns_fresh() {
        let tmp = std::env::temp_dir().join(format!(
            "rustynet-cli-report-dir-fresh-empty-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        assert_eq!(
            validate_vm_lab_report_dir_fresh(&tmp),
            VmLabReportDirFreshness::Fresh
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn validate_report_dir_fresh_for_dir_with_unrelated_files_returns_fresh() {
        let tmp = std::env::temp_dir().join(format!(
            "rustynet-cli-report-dir-fresh-unrelated-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("other.json"), "{}").unwrap();
        assert_eq!(
            validate_vm_lab_report_dir_fresh(&tmp),
            VmLabReportDirFreshness::Fresh
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn validate_report_dir_fresh_returns_stale_when_canonical_artifact_already_exists() {
        let tmp = std::env::temp_dir().join(format!(
            "rustynet-cli-report-dir-fresh-stale-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let record = evaluate_vm_lab_capability(ctx_linux(VmLabCapabilityScope::SetupLiveLab));
        let path = write_platform_capabilities_artifact(&tmp, std::slice::from_ref(&record))
            .expect("first write should succeed");
        match validate_vm_lab_report_dir_fresh(&tmp) {
            VmLabReportDirFreshness::Stale(existing) => {
                assert_eq!(existing, path);
            }
            VmLabReportDirFreshness::Fresh => {
                panic!("expected Stale, got Fresh");
            }
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn report_capabilities_require_fresh_output_dir_rejects_existing_artifact() {
        let tmp = std::env::temp_dir().join(format!(
            "rustynet-cli-cap-fresh-reject-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        // Plant an existing artifact.
        let record = evaluate_vm_lab_capability(ctx_linux(VmLabCapabilityScope::SetupLiveLab));
        let _ = write_platform_capabilities_artifact(&tmp, std::slice::from_ref(&record)).unwrap();
        // Snapshot the existing artifact body.
        let existing_body =
            std::fs::read_to_string(tmp.join(PLATFORM_CAPABILITIES_ARTIFACT_RELATIVE_PATH))
                .unwrap();

        let mut config = linux_setup_config();
        config.output_dir = Some(tmp.clone());
        config.require_fresh_output_dir = true;
        let err = execute_ops_vm_lab_report_capabilities(config)
            .expect_err("must fail-closed with --require-fresh-output-dir");
        assert!(
            err.contains("refusing to overwrite"),
            "rejection message must mention overwrite refusal: {err}"
        );

        // The existing artifact body must NOT have been touched.
        let body_after =
            std::fs::read_to_string(tmp.join(PLATFORM_CAPABILITIES_ARTIFACT_RELATIVE_PATH))
                .unwrap();
        assert_eq!(
            body_after, existing_body,
            "fail-closed rejection must not overwrite the existing artifact"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn report_capabilities_require_fresh_output_dir_succeeds_when_dir_is_fresh() {
        let tmp =
            std::env::temp_dir().join(format!("rustynet-cli-cap-fresh-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let mut config = linux_setup_config();
        config.output_dir = Some(tmp.clone());
        config.require_fresh_output_dir = true;
        let out = execute_ops_vm_lab_report_capabilities(config).unwrap();
        assert!(out.contains("status=Supported"));
        assert!(
            tmp.join(PLATFORM_CAPABILITIES_ARTIFACT_RELATIVE_PATH)
                .exists(),
            "artifact must be written on a fresh require-fresh-output-dir invocation"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn report_capabilities_default_idempotent_rewrite_still_works_when_freshness_not_required() {
        let tmp = std::env::temp_dir().join(format!(
            "rustynet-cli-cap-idempotent-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let mut config = linux_setup_config();
        config.output_dir = Some(tmp.clone());
        // First write
        let _ = execute_ops_vm_lab_report_capabilities(config.clone()).unwrap();
        // Second write to the same dir, without --require-fresh-output-dir.
        // Must succeed (idempotent default behaviour for the inspection CLI).
        let _ = execute_ops_vm_lab_report_capabilities(config).unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
