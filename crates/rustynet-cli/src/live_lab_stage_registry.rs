#![forbid(unsafe_code)]

//! Single source of truth for the live-lab stage vocabulary.
//!
//! Before this module existed the stage name was hand-copied across at least
//! six components (bash orchestrator dispatch, the Rust state-machine
//! `StageId` enum, mac/win sidecar literals, the monitor's hardcoded
//! catalogs, four match tables in the CSV writer, and the docs), none of
//! which agreed — the 2026-07-03 live-lab findings pass recorded phantom
//! monitor entries, failure-causing stages invisible to the UI, and three
//! naming dialects inside one CSV column. Every component is expected to
//! consume THIS table (directly in `rustynet-cli`, or via the run-scoped
//! stage manifest emitted into each report dir) instead of keeping a copy.
//!
//! The four historical match tables in `live_lab_run_matrix.rs`
//! (`direct_platform_stage`, `logical_stage_name`, `populate_cross_os_values`
//! arms, `set_special_stage_values` arms) are now thin lookups into this
//! registry; their original bodies survive as test oracles that pin exact
//! behavioral equivalence.
//!
//! Boundary note: this is tooling-layer code (§8/§10.3 untouched) — nothing
//! here is consumed by domain, policy, or daemon crates.

use std::collections::BTreeMap;
use std::sync::OnceLock;

/// Display/pipeline group. Mirrors the monitor's PRE / BOOTSTRAP / LIVE LAB
/// grouping plus the chaos suite and job-level pseudo-stages that the
/// wrapper records (`vm_lab_setup_live_lab` etc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageGroup {
    Pre,
    Bootstrap,
    Live,
    Chaos,
    Job,
}

impl StageGroup {
    #[allow(dead_code)] // consumed by the stage-manifest emitter (next increment)
    pub fn as_str(self) -> &'static str {
        match self {
            StageGroup::Pre => "pre",
            StageGroup::Bootstrap => "bootstrap",
            StageGroup::Live => "live",
            StageGroup::Chaos => "chaos",
            StageGroup::Job => "job",
        }
    }
}

/// Which platform stream a stage belongs to: the shared/common pipeline or
/// one of the per-OS sidecar streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformStream {
    Common,
    Linux,
    Macos,
    Windows,
}

impl PlatformStream {
    #[allow(dead_code)] // consumed by the stage-manifest emitter (next increment)
    pub fn as_str(self) -> &'static str {
        match self {
            PlatformStream::Common => "common",
            PlatformStream::Linux => "linux",
            PlatformStream::Macos => "macos",
            PlatformStream::Windows => "windows",
        }
    }
}

/// How the CSV writer resolves which `{platform}_stage_*` columns a SHARED
/// stage populates (OS-specific stages carry `direct_platform` instead).
/// Encodes the arms of the historical `platforms_for_stage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformRule {
    /// All platforms present in the run's target set.
    AllPlatforms,
    /// The platform of the target labelled `exit`.
    ExitTarget,
    /// The platform of the elected relay target.
    RelayTarget,
    /// Only the linux platforms of the target set (historical default).
    LinuxOnly,
}

/// Stage severity, mirroring the bash orchestrator's `record_stage`
/// severity column: `hard` failures gate the run, `soft` failures do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageSeverity {
    Hard,
    Soft,
}

/// The closed stage-status taxonomy (Finding 3 of the 2026-07-03 live-lab
/// findings). Recorded outcomes historically spoke an open vocabulary
/// (`pass`/`fail`/`skip`/`skipped`/`not_run`/`na`/`unknown` with no defined
/// semantics); every recording layer is expected to converge on these
/// canonical strings, with [`parse_stage_status`] absorbing the historical
/// dialects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)] // consumed by the shared recorder (next increment); the monitor speaks this taxonomy via the manifest
pub enum StageStatus {
    Pending,
    Running,
    Pass,
    Fail,
    Skipped,
    NotRun,
    Reused,
    NotApplicable,
    TimedOut,
    Aborted,
}

impl StageStatus {
    #[allow(dead_code)] // consumed by the shared recorder (next increment)
    pub fn as_str(self) -> &'static str {
        match self {
            StageStatus::Pending => "pending",
            StageStatus::Running => "running",
            StageStatus::Pass => "pass",
            StageStatus::Fail => "fail",
            StageStatus::Skipped => "skipped",
            StageStatus::NotRun => "not_run",
            StageStatus::Reused => "reused",
            StageStatus::NotApplicable => "not_applicable",
            StageStatus::TimedOut => "timed_out",
            StageStatus::Aborted => "aborted",
        }
    }

    /// A final outcome: the stage will not change state again this run.
    #[allow(dead_code)] // consumed by the shared recorder (next increment)
    pub fn is_terminal(self) -> bool {
        !matches!(self, StageStatus::Pending | StageStatus::Running)
    }
}

/// Absorb every historical status dialect into the closed taxonomy.
/// Unknown strings return `None` — callers decide whether that is a loud
/// defect (recorder validation) or display-as-unknown (historical rows).
#[allow(dead_code)] // consumed by the shared recorder (next increment)
pub fn parse_stage_status(raw: &str) -> Option<StageStatus> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "pending" => Some(StageStatus::Pending),
        "running" => Some(StageStatus::Running),
        "pass" | "passed" | "success" | "succeeded" | "ok" => Some(StageStatus::Pass),
        "fail" | "failed" | "error" => Some(StageStatus::Fail),
        "skip" | "skipped" => Some(StageStatus::Skipped),
        "not_run" | "not-run" | "not run" => Some(StageStatus::NotRun),
        "reused" | "reuse" => Some(StageStatus::Reused),
        "na" | "n/a" | "not_applicable" | "not-applicable" => Some(StageStatus::NotApplicable),
        "timed_out" | "timedout" | "timeout" => Some(StageStatus::TimedOut),
        "aborted" | "abort" => Some(StageStatus::Aborted),
        _ => None,
    }
}

/// When is this stage part of the resolved plan for a given run? Mirrors
/// the gating the wrapper and monitor already apply (platform selectors,
/// role-platform election, suite flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnableRule {
    /// Always part of the plan.
    Always,
    /// Requires a macOS guest in the run (`wants_macos`).
    WantsMacos,
    /// Requires a Windows guest in the run (`wants_windows`).
    WantsWindows,
    /// macOS elected as exit (`macos_promote_exit` or `exit_platform=macos`).
    MacosExit,
    /// Windows elected as exit.
    WindowsExit,
    /// Relay elected on the given platform.
    RelayPlatform(&'static str),
    /// Anchor elected on the given platform.
    AnchorPlatform(&'static str),
    /// Admin elected on the given platform.
    AdminPlatform(&'static str),
    /// blind_exit elected on the given platform.
    BlindExitPlatform(&'static str),
    /// Live role-transition (LocalOnly admin<->client flip) elected on the
    /// given platform.
    RoleSwitchPlatform(&'static str),
    /// Part of the Linux live-validation suite (`!skip_linux_live_suite`).
    LinuxLiveSuite,
    /// The extended soak stage (`!skip_soak` / bash RUN_SOAK).
    SoakSuite,
    /// The local full gate suite stage (`!skip_gates` / bash RUN_LOCAL_GATES).
    LocalGateSuite,
    /// Opt-in chaos suite.
    ChaosSuite,
    /// Opt-in cross-network suite.
    CrossNetworkSuite,
}

/// The run selectors that resolve [`EnableRule`]s into an actual plan.
/// Mirrors the monitor's `MonitorConfig` gating fields and the wrapper's
/// role-platform selectors.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetSelectors {
    pub wants_macos: bool,
    pub wants_windows: bool,
    pub macos_promote_exit: bool,
    pub exit_platform: String,
    pub relay_platform: String,
    pub anchor_platform: String,
    pub admin_platform: String,
    pub blind_exit_platform: String,
    pub role_switch_platform: String,
    pub skip_linux_live_suite: bool,
    pub chaos_suite: bool,
    pub cross_network_suite: bool,
    pub soak_suite: bool,
    pub local_gate_suite: bool,
}

impl TargetSelectors {
    #[allow(dead_code)] // consumed by the stage-manifest emitter (next increment)
    pub fn resolves(&self, rule: EnableRule) -> bool {
        match rule {
            EnableRule::Always => true,
            EnableRule::WantsMacos => self.wants_macos,
            EnableRule::WantsWindows => self.wants_windows,
            EnableRule::MacosExit => self.macos_promote_exit || self.exit_platform == "macos",
            EnableRule::WindowsExit => self.exit_platform == "windows",
            EnableRule::RelayPlatform(platform) => self.relay_platform == platform,
            EnableRule::AnchorPlatform(platform) => self.anchor_platform == platform,
            EnableRule::AdminPlatform(platform) => self.admin_platform == platform,
            EnableRule::BlindExitPlatform(platform) => self.blind_exit_platform == platform,
            EnableRule::RoleSwitchPlatform(platform) => self.role_switch_platform == platform,
            EnableRule::LinuxLiveSuite => !self.skip_linux_live_suite,
            EnableRule::ChaosSuite => self.chaos_suite,
            EnableRule::CrossNetworkSuite => self.cross_network_suite,
            // extended_soak only ever dispatches as part of the Linux
            // live-validation suite (`execute_ops_vm_lab_run_live_lab`); when
            // that suite is skipped the soak sub-stage never runs either, so
            // it must not stay "enabled" or the terminal-outcome guarantee
            // synthesizes a spurious `aborted` for a stage that was never
            // dispatched by design.
            EnableRule::SoakSuite => self.soak_suite && !self.skip_linux_live_suite,
            EnableRule::LocalGateSuite => self.local_gate_suite,
        }
    }

    /// Human-readable reason a rule did NOT resolve, for the manifest's
    /// `not_applicable(reason)` state.
    #[allow(dead_code)] // consumed by the stage-manifest emitter (next increment)
    pub fn skip_reason(&self, rule: EnableRule) -> &'static str {
        match rule {
            EnableRule::Always => "always enabled",
            EnableRule::WantsMacos => "no macOS guest in this run",
            EnableRule::WantsWindows => "no Windows guest in this run",
            EnableRule::MacosExit => "macOS not elected as exit",
            EnableRule::WindowsExit => "Windows not elected as exit",
            EnableRule::RelayPlatform(_) => "relay not elected on this platform",
            EnableRule::AnchorPlatform(_) => "anchor not elected on this platform",
            EnableRule::AdminPlatform(_) => "admin not elected on this platform",
            EnableRule::BlindExitPlatform(_) => "blind_exit not elected on this platform",
            EnableRule::RoleSwitchPlatform(_) => "role transition not elected on this platform",
            EnableRule::LinuxLiveSuite => "linux live suite skipped for this run",
            EnableRule::ChaosSuite => "chaos suite not selected",
            EnableRule::CrossNetworkSuite => "cross-network suite not selected",
            // extended_soak only dispatches inside the Linux live suite; when
            // that suite is skipped, say so even though soak_suite itself may
            // be selected — matches the AND in `resolves()` above.
            EnableRule::SoakSuite if self.skip_linux_live_suite => {
                "linux live suite skipped for this run"
            }
            EnableRule::SoakSuite => "soak stage not selected",
            EnableRule::LocalGateSuite => "local gate suite not selected",
        }
    }
}

/// One stage, fully described as data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageSpec {
    /// Canonical recorded name.
    pub name: &'static str,
    /// Historical / phantom names that must resolve to this stage (the
    /// monitor's `distribute_windows_bundles`, etc). Node-scoped composites
    /// (`node::stage`) are handled by [`strip_node_alias`], not aliases.
    pub aliases: &'static [&'static str],
    pub group: StageGroup,
    pub stream: PlatformStream,
    /// OS-specific stages: `(platform, logical)` → `{platform}_stage_{logical}`
    /// CSV column. Mirrors the historical `direct_platform_stage` table.
    pub direct_platform: Option<(&'static str, &'static str)>,
    /// Shared stages: logical column suffix; platform resolved per
    /// [`PlatformRule`]. Mirrors the historical `logical_stage_name` table.
    pub logical: Option<&'static str>,
    /// `(platform, role)` → `{platform}_{role}` role-result column. Mirrors
    /// the historical `direct_platform_role` table.
    pub role: Option<(&'static str, &'static str)>,
    /// Cross-OS aggregate column. Mirrors `populate_cross_os_values` arms.
    pub cross_os: Option<&'static str>,
    /// One-off check column. Mirrors `set_special_stage_values` arms.
    pub special: Option<&'static str>,
    pub platform_rule: PlatformRule,
    pub enable: EnableRule,
    /// Cold-start time budget in seconds (fallback when no timing history
    /// exists). Values mirror the monitor's `default_stage_secs` table.
    pub budget_secs: u64,
    pub severity: StageSeverity,
    /// SecurityMinimumBar / audit-ledger control IDs this stage proves live
    /// (coverage-as-code; sourced from the stage evaluators' own
    /// "Proves ..." doc comments).
    pub proves: &'static [&'static str],
    /// True for display-only aggregates (the monitor's `linux_live_suite`
    /// row) that never appear in recorded outcomes.
    pub synthetic: bool,
    /// True when the stage's enablement rule can resolve `true` and the
    /// orchestrators may STILL legitimately not dispatch it (runtime
    /// gating the selectors cannot see: audit sub-passes, cross-network
    /// auto mode). The conclusion barrier never synthesizes `aborted` for
    /// these — a missing outcome is not evidence of abnormal termination.
    pub conditional_dispatch: bool,
    /// True for the Rust state-machine (`StageId`) orchestrator's EXCLUSIVE
    /// stage vocabulary — names the bash/wrapper path records equivalent work
    /// under a different (bash-dialect) name and therefore never emits
    /// (verified: 0 of 129 recorded runs). The Rust orchestrator is the
    /// in-flight Rust-first replacement for bash
    /// (`RustNativeMultiPlatformOrchestratorPlan_2026-04-28.md`, waves
    /// W5.5→W5.7); it runs ONLY when `vm-lab-orchestrate-live-lab` is passed
    /// `--node <alias>:<role>`, and that path currently emits NO
    /// `stage_manifest.json` at all (it writes `parity_input.json` for the
    /// parity-diff harness). Every manifest on disk is therefore a bash-path
    /// manifest, where this dialect genuinely does not dispatch — so we mark
    /// these `enabled: false` ("not planned") instead of advertising them as
    /// pending-and-expected (which otherwise left ~13 forever-unresolved cells
    /// downstream). NOT set on names SHARED by both dialects (`preflight`,
    /// `collect_pubkeys`, `enforce_baseline_runtime`, ...), which are
    /// `rust_native` yet genuinely record.
    ///
    /// MIGRATION CAVEAT: the discriminator is `--node` presence, NOT the
    /// `run_command` (both paths use `vm-lab-orchestrate-live-lab`). When the
    /// W5.7 default-flip makes the Rust path emit a manifest, teach
    /// `build_stage_manifest` which orchestrator is active and INVERT this:
    /// the Rust dialect becomes `enabled`, the bash dialect becomes
    /// not-planned — otherwise the manifest hides the stages that really run.
    pub state_machine_only: bool,
}

const DEFAULT_SPEC: StageSpec = StageSpec {
    name: "",
    aliases: &[],
    group: StageGroup::Live,
    stream: PlatformStream::Common,
    direct_platform: None,
    logical: None,
    role: None,
    cross_os: None,
    special: None,
    platform_rule: PlatformRule::LinuxOnly,
    enable: EnableRule::Always,
    budget_secs: 300,
    severity: StageSeverity::Hard,
    proves: &[],
    synthetic: false,
    conditional_dispatch: false,
    state_machine_only: false,
};

/// Control-ID sets shared by the per-OS variants of each audit stage.
const PROVES_MEMBERSHIP_REVOKE: &[&str] = &["RSA-0009"];
const PROVES_REVOKED_PEER_DENIED: &[&str] = &["DD-03", "RSA-0007"];
const PROVES_BLIND_EXIT_REVERSAL: &[&str] = &["RT-2", "SecMinBar-6.D.2"];
const PROVES_GOSSIP_REVOKED_READMIT: &[&str] = &["GM-1", "RSA-0034"];
const PROVES_ENROLLMENT_REPLAY: &[&str] = &["ENR-1", "TOCTOU-1", "RSA-0023"];
const PROVES_HELLO_LIMITER_FLOOD: &[&str] = &["DOS-1", "RSA-0037"];
const PROVES_RELAY_FORWARDING: &[&str] = &["HP-3", "RPT-01"];

pub const STAGES: &[StageSpec] = &[
    // ── PRE (shared pipeline head) ──────────────────────────────────────
    StageSpec {
        name: "preflight",
        group: StageGroup::Pre,
        logical: Some("bootstrap"),
        cross_os: Some("cross_os_bootstrap"),
        platform_rule: PlatformRule::AllPlatforms,
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "prepare_source_archive",
        group: StageGroup::Pre,
        logical: Some("bootstrap"),
        cross_os: Some("cross_os_bootstrap"),
        platform_rule: PlatformRule::AllPlatforms,
        budget_secs: 30,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "verify_ssh_reachability",
        group: StageGroup::Pre,
        logical: Some("bootstrap"),
        cross_os: Some("cross_os_bootstrap"),
        platform_rule: PlatformRule::AllPlatforms,
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "prime_remote_access",
        group: StageGroup::Pre,
        logical: Some("bootstrap"),
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "macos_preflight_check",
        group: StageGroup::Pre,
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "cleanup_hosts",
        group: StageGroup::Pre,
        logical: Some("bootstrap"),
        cross_os: Some("cross_os_bootstrap"),
        platform_rule: PlatformRule::AllPlatforms,
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    // ── BOOTSTRAP (shared) ──────────────────────────────────────────────
    StageSpec {
        name: "bootstrap_hosts",
        group: StageGroup::Bootstrap,
        logical: Some("bootstrap"),
        cross_os: Some("cross_os_bootstrap"),
        platform_rule: PlatformRule::AllPlatforms,
        budget_secs: 900,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "collect_pubkeys",
        group: StageGroup::Bootstrap,
        logical: Some("bootstrap"),
        cross_os: Some("cross_os_bootstrap"),
        platform_rule: PlatformRule::AllPlatforms,
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "membership_setup",
        group: StageGroup::Bootstrap,
        logical: Some("membership"),
        budget_secs: 120,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "distribute_membership_state",
        group: StageGroup::Bootstrap,
        logical: Some("membership"),
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "issue_and_distribute_assignments",
        group: StageGroup::Bootstrap,
        logical: Some("assignments"),
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    StageSpec {
        // NOTE: deliberately NOT mapped to `logical: traversal` yet — the
        // historical table only knows the Rust dialect `distribute_traversal`
        // and this bash name fell through. Healing that drift is a separate,
        // explicitly-tested change (see the healed-drift test), not part of
        // the behavior-preserving registry extraction.
        name: "issue_and_distribute_traversal",
        group: StageGroup::Bootstrap,
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    StageSpec {
        // Same deliberate gap as issue_and_distribute_traversal.
        name: "issue_and_distribute_dns_zone",
        group: StageGroup::Bootstrap,
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "enforce_baseline_runtime",
        group: StageGroup::Bootstrap,
        logical: Some("baseline_runtime"),
        platform_rule: PlatformRule::AllPlatforms,
        budget_secs: 300,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_baseline_runtime",
        group: StageGroup::Bootstrap,
        logical: Some("baseline_runtime"),
        platform_rule: PlatformRule::AllPlatforms,
        budget_secs: 300,
        ..DEFAULT_SPEC
    },
    // ── Rust state-machine dialect (StageId::as_str vocabulary) ────────
    StageSpec {
        name: "membership_init",
        state_machine_only: true,
        group: StageGroup::Bootstrap,
        logical: Some("membership"),
        cross_os: Some("cross_os_membership_convergence"),
        platform_rule: PlatformRule::AllPlatforms,
        budget_secs: 120,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "distribute_membership",
        state_machine_only: true,
        group: StageGroup::Bootstrap,
        logical: Some("membership"),
        cross_os: Some("cross_os_membership_convergence"),
        platform_rule: PlatformRule::AllPlatforms,
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "anchor_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("anchor"),
        cross_os: Some("cross_os_anchor_bundle_pull"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "admin_issue",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("admin"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "distribute_assignments",
        state_machine_only: true,
        group: StageGroup::Bootstrap,
        logical: Some("assignments"),
        platform_rule: PlatformRule::AllPlatforms,
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "distribute_traversal",
        state_machine_only: true,
        group: StageGroup::Bootstrap,
        logical: Some("traversal"),
        cross_os: Some("cross_os_direct_path"),
        platform_rule: PlatformRule::AllPlatforms,
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "distribute_dns_zone",
        state_machine_only: true,
        group: StageGroup::Bootstrap,
        logical: Some("managed_dns"),
        cross_os: Some("cross_os_dns"),
        platform_rule: PlatformRule::AllPlatforms,
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "blind_exit",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("blind_exit"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "deploy_relay_service",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("relay_service_lifecycle"),
        cross_os: Some("cross_os_relay_path"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "relay_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("relay_service_lifecycle"),
        cross_os: Some("cross_os_relay_path"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    // Rust-engine security suite: the eight Tier-0 daemon self-audits folded in
    // as one OrchestrationStage (Bucket 1). state_machine_only — only the Rust
    // `--node` plan dispatches it; the bash orchestrate path runs the audits via
    // its own per-check validators. No single logical/cross_os CSV column yet —
    // the per-check → run-matrix column mapping (the eight linux_* security
    // columns) is a follow-up; today the stage's outcome lives in
    // stages.tsv / orchestrate_result / the per-stage log.
    StageSpec {
        name: "security_audit_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    // Per-node DNS-failclosed daemon self-check — resolv.conf loopback-only,
    // no external resolver reachable through the killswitch. state_machine_only —
    // only the Rust `--node` plan dispatches it; the bash orchestrate path runs
    // the check via its own per-check validators.
    StageSpec {
        name: "dns_failclosed_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("dns_failclosed_check"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    // Rust-engine runtime-ACLs: the canonical Linux daemon self-check folded
    // into a first-class OrchestrationStage. state_machine_only — only the Rust
    // `--node` plan dispatches it; the bash orchestrate path runs the check
    // via its own per-check validators.
    StageSpec {
        name: "runtime_acls_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("runtime_acls_check"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    // Rust-engine service-hardening: the canonical Linux daemon self-check
    // folded into a first-class OrchestrationStage. state_machine_only — only
    // the Rust `--node` plan dispatches it; the bash orchestrate path runs
    // the check via its own per-check validators.
    StageSpec {
        name: "service_hardening_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("service_hardening_check"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    // Rust-engine key-custody: the canonical Linux daemon self-check
    // folded into a first-class OrchestrationStage — validates on-disk
    // key material (encrypted WG private key, public key, keys dir,
    // credentials dir, passphrase credentials) against the reviewed
    // custody contract. state_machine_only — only the Rust `--node` plan
    // dispatches it; the bash orchestrate path runs the check via its
    // own per-check validators.
    StageSpec {
        name: "key_custody_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("key_custody_check"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    // Rust-engine mesh-status: the canonical Linux daemon self-check
    // folded into a first-class OrchestrationStage — validates the
    // daemon's mesh-status view reports no drift (no stale state,
    // expected peer IDs present, within max-age bounds).
    // state_machine_only — only the Rust `--node` plan dispatches it;
    // the bash orchestrate path runs the check via its own per-check
    // validators.
    StageSpec {
        name: "mesh_status_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("mesh_status_check"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    // Rust-engine authenticode: the canonical Linux daemon self-check
    // folded into a first-class OrchestrationStage — validates that the
    // daemon reports an honest authenticode verdict (applicable: false on
    // Linux — runtime binary-signature attestation is Windows-specific).
    // state_machine_only — only the Rust `--node` plan dispatches it;
    // the bash orchestrate path runs the check via its own per-check
    // validators.
    StageSpec {
        name: "authenticode_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("authenticode_check"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    // Rust-engine IPv6 leak adversarial capture: the canonical Linux IPv6
    // tunnel-leak proof folded into a first-class OrchestrationStage — real
    // outbound IPv6 probe to a global address while tcpdump watches the
    // egress interface; 0 leaked datagrams + probe blocked by containment
    // control (disable_ipv6 or killswitch v6 drop). state_machine_only —
    // only the Rust `--node` plan dispatches it; the bash orchestrate path
    // captures and evaluates via the per-exit evidence pipeline.
    StageSpec {
        name: "ipv6_leak_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("ipv6_leak_check"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    // Rust-engine exit-demotion-residue: the two-phase exit→client
    // demotion capture folded into a first-class OrchestrationStage —
    // proves NAT torn down + forwarding restored with daemon still
    // running. state_machine_only — only the Rust `--node` plan
    // dispatches it; the bash orchestrate path validates the residue
    // via its own artifact-evaluator stage.
    StageSpec {
        name: "exit_demotion_residue_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("exit_demotion_residue_check"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    // Rust-engine exit DNS fail-closed: the six-artifact directory-based
    // leak-proof evaluator folded into a first-class OrchestrationStage.
    // state_machine_only — only the Rust `--node` plan dispatches it;
    // the bash orchestrate path runs the check via its own artifact
    // evaluator.
    StageSpec {
        name: "exit_dns_failclosed_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("exit_dns_failclosed_check"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    // Rust-engine exit NAT lifecycle: two-phase snapshot→stop→snapshot prove
    // NAT present during exit and gone after stop. state_machine_only — only
    // the Rust `--node` plan dispatches it; the bash orchestrate path runs the
    // check via its own artifact evaluator.
    StageSpec {
        name: "exit_nat_lifecycle_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("exit_nat_lifecycle_check"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    // Rust-engine blind_exit dataplane: live nft ruleset capture with
    // five hardened subchecks (ruleset captured, mesh-scoped forward,
    // no NAT, no unrestricted forward, no own-egress) — proof the
    // blind-exit dataplane posture matches the reviewed contract.
    // state_machine_only — only the Rust `--node` plan dispatches it.
    StageSpec {
        name: "blind_exit_dataplane_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("blind_exit_dataplane_check"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    // Rust-native live two-hop: delegates to the proven live_linux_two_hop_test
    // binary (cross-OS via --platform) — the same binary the bash orchestrator
    // calls, now surfaced as a first-class OrchestrationStage.
    // state_machine_only — only the Rust `--node` plan dispatches it.
    StageSpec {
        name: "live_two_hop_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("two_hop"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    // Rust-native live managed DNS: delegates to the proven
    // live_linux_managed_dns_test binary (cross-OS via --platform) — the
    // same binary the bash orchestrator calls, now surfaced as a
    // first-class OrchestrationStage (signer=exit, client=client, managed
    // peers=everything else). state_machine_only — only the Rust `--node`
    // plan dispatches it.
    StageSpec {
        name: "live_managed_dns_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("managed_dns"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "traffic_test_matrix",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("two_hop"),
        cross_os: Some("cross_os_peer_visibility"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "role_switch_matrix",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("role_switch_matrix"),
        cross_os: Some("cross_os_role_switch"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "exit_handoff",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("exit_handoff"),
        cross_os: Some("cross_os_exit_path"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "active_exit",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("exit_handoff"),
        cross_os: Some("cross_os_exit_path"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "cleanup",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("cleanup"),
        platform_rule: PlatformRule::AllPlatforms,
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    // ── macOS sidecar: bootstrap stream ────────────────────────────────
    StageSpec {
        name: "bootstrap_macos_host",
        group: StageGroup::Bootstrap,
        stream: PlatformStream::Macos,
        direct_platform: Some(("macos", "bootstrap")),
        enable: EnableRule::WantsMacos,
        budget_secs: 600,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "collect_macos_pubkey",
        group: StageGroup::Bootstrap,
        stream: PlatformStream::Macos,
        direct_platform: Some(("macos", "mixed_topology")),
        enable: EnableRule::WantsMacos,
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "amend_membership_for_macos",
        group: StageGroup::Bootstrap,
        stream: PlatformStream::Macos,
        direct_platform: Some(("macos", "membership")),
        enable: EnableRule::WantsMacos,
        budget_secs: 120,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "distribute_macos_bundles",
        group: StageGroup::Bootstrap,
        stream: PlatformStream::Macos,
        direct_platform: Some(("macos", "membership")),
        enable: EnableRule::WantsMacos,
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_mesh_join",
        group: StageGroup::Bootstrap,
        stream: PlatformStream::Macos,
        direct_platform: Some(("macos", "mixed_topology")),
        role: Some(("macos", "client")),
        cross_os: Some("cross_os_peer_visibility"),
        enable: EnableRule::WantsMacos,
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    // ── Windows sidecar: bootstrap stream ───────────────────────────────
    StageSpec {
        name: "bootstrap_windows_host",
        group: StageGroup::Bootstrap,
        stream: PlatformStream::Windows,
        direct_platform: Some(("windows", "bootstrap")),
        enable: EnableRule::WantsWindows,
        budget_secs: 600,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "amend_membership_for_windows",
        group: StageGroup::Bootstrap,
        stream: PlatformStream::Windows,
        direct_platform: Some(("windows", "membership")),
        enable: EnableRule::WantsWindows,
        budget_secs: 120,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "stage_windows_bundles_for_distribution",
        group: StageGroup::Bootstrap,
        stream: PlatformStream::Windows,
        enable: EnableRule::WantsWindows,
        ..DEFAULT_SPEC
    },
    StageSpec {
        // `distribute_windows_bundles` is the monitor's historical phantom
        // for this stage (it never existed in executing code) — kept as an
        // alias so historical UI references resolve somewhere real.
        name: "distribute_windows_membership",
        aliases: &["distribute_windows_bundles"],
        group: StageGroup::Bootstrap,
        stream: PlatformStream::Windows,
        direct_platform: Some(("windows", "membership")),
        enable: EnableRule::WantsWindows,
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "issue_windows_assignment",
        group: StageGroup::Bootstrap,
        stream: PlatformStream::Windows,
        direct_platform: Some(("windows", "assignments")),
        enable: EnableRule::WantsWindows,
        budget_secs: 120,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "distribute_windows_assignment",
        group: StageGroup::Bootstrap,
        stream: PlatformStream::Windows,
        direct_platform: Some(("windows", "assignments")),
        enable: EnableRule::WantsWindows,
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    // ── macOS live cells ────────────────────────────────────────────────
    StageSpec {
        name: "activate_macos_exit_role",
        stream: PlatformStream::Macos,
        role: Some(("macos", "exit")),
        enable: EnableRule::MacosExit,
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "capture_macos_exit_evidence_artifacts",
        stream: PlatformStream::Macos,
        direct_platform: Some(("macos", "exit_handoff")),
        role: Some(("macos", "exit")),
        enable: EnableRule::MacosExit,
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_exit_nat_lifecycle",
        stream: PlatformStream::Macos,
        direct_platform: Some(("macos", "exit_handoff")),
        role: Some(("macos", "exit")),
        enable: EnableRule::MacosExit,
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_ipv6_leak",
        stream: PlatformStream::Macos,
        direct_platform: Some(("macos", "exit_handoff")),
        role: Some(("macos", "exit")),
        enable: EnableRule::MacosExit,
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_exit_dns_failclosed",
        stream: PlatformStream::Macos,
        direct_platform: Some(("macos", "managed_dns")),
        role: Some(("macos", "exit")),
        cross_os: Some("cross_os_dns"),
        enable: EnableRule::MacosExit,
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_exit_killswitch_precedence",
        stream: PlatformStream::Macos,
        role: Some(("macos", "exit")),
        special: Some("macos_pf_killswitch"),
        enable: EnableRule::MacosExit,
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_relay_service_lifecycle",
        stream: PlatformStream::Macos,
        direct_platform: Some(("macos", "relay_service_lifecycle")),
        role: Some(("macos", "relay")),
        cross_os: Some("cross_os_relay_path"),
        enable: EnableRule::RelayPlatform("macos"),
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "deploy_macos_anchor_profile",
        stream: PlatformStream::Macos,
        enable: EnableRule::AnchorPlatform("macos"),
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_anchor_bundle_pull",
        stream: PlatformStream::Macos,
        direct_platform: Some(("macos", "anchor")),
        role: Some(("macos", "anchor")),
        cross_os: Some("cross_os_anchor_bundle_pull"),
        enable: EnableRule::AnchorPlatform("macos"),
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_anchor_port_mapping_authority",
        stream: PlatformStream::Macos,
        enable: EnableRule::AnchorPlatform("macos"),
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_admin_issue",
        stream: PlatformStream::Macos,
        enable: EnableRule::AdminPlatform("macos"),
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_role_transition",
        stream: PlatformStream::Macos,
        direct_platform: Some(("macos", "role_transition")),
        enable: EnableRule::RoleSwitchPlatform("macos"),
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_blind_exit",
        stream: PlatformStream::Macos,
        role: Some(("macos", "blind_exit")),
        enable: EnableRule::BlindExitPlatform("macos"),
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_key_custody",
        stream: PlatformStream::Macos,
        special: Some("macos_keychain_key_custody"),
        enable: EnableRule::WantsMacos,
        budget_secs: 180,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    // ── macOS audit family ──────────────────────────────────────────────
    StageSpec {
        name: "validate_macos_membership_revoke_applies",
        stream: PlatformStream::Macos,
        special: Some("macos_membership_revoke_applies"),
        enable: EnableRule::WantsMacos,
        budget_secs: 180,
        proves: PROVES_MEMBERSHIP_REVOKE,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_membership_signature_forgery",
        stream: PlatformStream::Macos,
        special: Some("macos_membership_signature_forgery"),
        enable: EnableRule::WantsMacos,
        budget_secs: 180,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_gossip_revoked_readmit",
        stream: PlatformStream::Macos,
        special: Some("macos_gossip_revoked_readmit"),
        enable: EnableRule::WantsMacos,
        budget_secs: 180,
        proves: PROVES_GOSSIP_REVOKED_READMIT,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_enrollment_replay",
        stream: PlatformStream::Macos,
        special: Some("macos_enrollment_replay"),
        enable: EnableRule::WantsMacos,
        budget_secs: 180,
        proves: PROVES_ENROLLMENT_REPLAY,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_hello_limiter_flood",
        stream: PlatformStream::Macos,
        special: Some("macos_hello_limiter_flood"),
        enable: EnableRule::WantsMacos,
        budget_secs: 180,
        proves: PROVES_HELLO_LIMITER_FLOOD,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_runtime_acls",
        stream: PlatformStream::Macos,
        special: Some("macos_runtime_acls"),
        enable: EnableRule::WantsMacos,
        budget_secs: 180,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_service_hardening",
        stream: PlatformStream::Macos,
        special: Some("macos_service_hardening"),
        enable: EnableRule::WantsMacos,
        budget_secs: 180,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_mesh_status",
        stream: PlatformStream::Macos,
        special: Some("macos_mesh_status"),
        enable: EnableRule::WantsMacos,
        budget_secs: 180,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_authenticode",
        stream: PlatformStream::Macos,
        special: Some("macos_authenticode"),
        enable: EnableRule::WantsMacos,
        budget_secs: 180,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_privileged_helper_allowlist",
        stream: PlatformStream::Macos,
        special: Some("macos_privileged_helper_allowlist"),
        enable: EnableRule::WantsMacos,
        budget_secs: 180,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_policy_default_deny",
        stream: PlatformStream::Macos,
        special: Some("macos_policy_default_deny"),
        enable: EnableRule::WantsMacos,
        budget_secs: 180,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_revoked_peer_denied_e2e",
        stream: PlatformStream::Macos,
        special: Some("macos_revoked_peer_denied_e2e"),
        enable: EnableRule::WantsMacos,
        budget_secs: 180,
        proves: PROVES_REVOKED_PEER_DENIED,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_macos_blind_exit_reversal_denied",
        stream: PlatformStream::Macos,
        special: Some("macos_blind_exit_reversal_denied"),
        enable: EnableRule::WantsMacos,
        budget_secs: 180,
        proves: PROVES_BLIND_EXIT_REVERSAL,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    // ── Windows live cells ──────────────────────────────────────────────
    StageSpec {
        name: "validate_windows_client_install",
        stream: PlatformStream::Windows,
        direct_platform: Some(("windows", "baseline_runtime")),
        role: Some(("windows", "client")),
        enable: EnableRule::WantsWindows,
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_runtime_acls",
        stream: PlatformStream::Windows,
        role: Some(("windows", "client")),
        enable: EnableRule::WantsWindows,
        budget_secs: 180,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_named_pipe_acls",
        stream: PlatformStream::Windows,
        role: Some(("windows", "client")),
        special: Some("windows_named_pipe_acl"),
        enable: EnableRule::WantsWindows,
        budget_secs: 180,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_service_hardening",
        stream: PlatformStream::Windows,
        role: Some(("windows", "client")),
        enable: EnableRule::WantsWindows,
        budget_secs: 180,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_key_custody",
        stream: PlatformStream::Windows,
        role: Some(("windows", "client")),
        special: Some("windows_dpapi_key_custody"),
        enable: EnableRule::WantsWindows,
        budget_secs: 180,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_authenticode",
        stream: PlatformStream::Windows,
        enable: EnableRule::WantsWindows,
        budget_secs: 180,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_dns_failclosed",
        stream: PlatformStream::Windows,
        direct_platform: Some(("windows", "managed_dns")),
        cross_os: Some("cross_os_dns"),
        enable: EnableRule::WantsWindows,
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_exit_nat_lifecycle",
        stream: PlatformStream::Windows,
        direct_platform: Some(("windows", "exit_handoff")),
        role: Some(("windows", "exit")),
        enable: EnableRule::WindowsExit,
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_exit_dns_failclosed",
        stream: PlatformStream::Windows,
        direct_platform: Some(("windows", "managed_dns")),
        role: Some(("windows", "exit")),
        enable: EnableRule::WindowsExit,
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_exit_killswitch_precedence",
        stream: PlatformStream::Windows,
        role: Some(("windows", "exit")),
        enable: EnableRule::WindowsExit,
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_relay_service_lifecycle",
        stream: PlatformStream::Windows,
        direct_platform: Some(("windows", "relay_service_lifecycle")),
        role: Some(("windows", "relay")),
        cross_os: Some("cross_os_relay_path"),
        enable: EnableRule::RelayPlatform("windows"),
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_anchor_bundle_pull",
        stream: PlatformStream::Windows,
        direct_platform: Some(("windows", "anchor")),
        role: Some(("windows", "anchor")),
        cross_os: Some("cross_os_anchor_bundle_pull"),
        enable: EnableRule::AnchorPlatform("windows"),
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_admin_issue",
        stream: PlatformStream::Windows,
        role: Some(("windows", "admin")),
        enable: EnableRule::AdminPlatform("windows"),
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_role_transition",
        stream: PlatformStream::Windows,
        direct_platform: Some(("windows", "role_transition")),
        enable: EnableRule::RoleSwitchPlatform("windows"),
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "promote_windows_exit_active",
        stream: PlatformStream::Windows,
        direct_platform: Some(("windows", "exit_handoff")),
        role: Some(("windows", "exit")),
        cross_os: Some("cross_os_exit_path"),
        enable: EnableRule::WindowsExit,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "capture_windows_exit_evidence_artifacts",
        stream: PlatformStream::Windows,
        direct_platform: Some(("windows", "exit_handoff")),
        role: Some(("windows", "exit")),
        enable: EnableRule::WindowsExit,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "pull_windows_exit_evidence_artifacts",
        stream: PlatformStream::Windows,
        direct_platform: Some(("windows", "exit_handoff")),
        role: Some(("windows", "exit")),
        enable: EnableRule::WindowsExit,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "distribute_windows_assignment_verifier_key",
        group: StageGroup::Bootstrap,
        stream: PlatformStream::Windows,
        enable: EnableRule::WantsWindows,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "distribute_windows_traversal_verifier_key",
        group: StageGroup::Bootstrap,
        stream: PlatformStream::Windows,
        enable: EnableRule::WantsWindows,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "distribute_windows_dns_zone_verifier_key",
        group: StageGroup::Bootstrap,
        stream: PlatformStream::Windows,
        enable: EnableRule::WantsWindows,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "distribute_windows_traversal",
        group: StageGroup::Bootstrap,
        stream: PlatformStream::Windows,
        enable: EnableRule::WantsWindows,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "distribute_windows_dns_zone",
        group: StageGroup::Bootstrap,
        stream: PlatformStream::Windows,
        enable: EnableRule::WantsWindows,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_mesh_join",
        group: StageGroup::Bootstrap,
        stream: PlatformStream::Windows,
        direct_platform: Some(("windows", "mixed_topology")),
        cross_os: Some("cross_os_peer_visibility"),
        enable: EnableRule::WantsWindows,
        budget_secs: 180,
        ..DEFAULT_SPEC
    },
    // ── Windows audit family ────────────────────────────────────────────
    StageSpec {
        name: "validate_windows_membership_revoke_applies",
        stream: PlatformStream::Windows,
        special: Some("windows_membership_revoke_applies"),
        enable: EnableRule::WantsWindows,
        budget_secs: 180,
        proves: PROVES_MEMBERSHIP_REVOKE,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_membership_signature_forgery",
        stream: PlatformStream::Windows,
        special: Some("windows_membership_signature_forgery"),
        enable: EnableRule::WantsWindows,
        budget_secs: 180,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_gossip_revoked_readmit",
        stream: PlatformStream::Windows,
        special: Some("windows_gossip_revoked_readmit"),
        enable: EnableRule::WantsWindows,
        budget_secs: 180,
        proves: PROVES_GOSSIP_REVOKED_READMIT,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_enrollment_replay",
        stream: PlatformStream::Windows,
        special: Some("windows_enrollment_replay"),
        enable: EnableRule::WantsWindows,
        budget_secs: 180,
        proves: PROVES_ENROLLMENT_REPLAY,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_hello_limiter_flood",
        stream: PlatformStream::Windows,
        special: Some("windows_hello_limiter_flood"),
        enable: EnableRule::WantsWindows,
        budget_secs: 180,
        proves: PROVES_HELLO_LIMITER_FLOOD,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_mesh_status",
        stream: PlatformStream::Windows,
        special: Some("windows_mesh_status"),
        enable: EnableRule::WantsWindows,
        budget_secs: 180,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_privileged_helper_allowlist",
        stream: PlatformStream::Windows,
        special: Some("windows_privileged_helper_allowlist"),
        enable: EnableRule::WantsWindows,
        budget_secs: 180,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_policy_default_deny",
        stream: PlatformStream::Windows,
        special: Some("windows_policy_default_deny"),
        enable: EnableRule::WantsWindows,
        budget_secs: 180,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_revoked_peer_denied_e2e",
        stream: PlatformStream::Windows,
        special: Some("windows_revoked_peer_denied_e2e"),
        enable: EnableRule::WantsWindows,
        budget_secs: 180,
        proves: PROVES_REVOKED_PEER_DENIED,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_windows_blind_exit_reversal_denied",
        stream: PlatformStream::Windows,
        special: Some("windows_blind_exit_reversal_denied"),
        enable: EnableRule::WantsWindows,
        budget_secs: 180,
        proves: PROVES_BLIND_EXIT_REVERSAL,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    // ── Linux live cells ────────────────────────────────────────────────
    StageSpec {
        name: "validate_linux_relay_service_lifecycle",
        stream: PlatformStream::Linux,
        direct_platform: Some(("linux", "relay_service_lifecycle")),
        role: Some(("linux", "relay")),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_anchor_bundle_pull",
        stream: PlatformStream::Linux,
        direct_platform: Some(("linux", "anchor")),
        role: Some(("linux", "anchor")),
        cross_os: Some("cross_os_anchor_bundle_pull"),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_exit_nat_lifecycle",
        stream: PlatformStream::Linux,
        direct_platform: Some(("linux", "exit_handoff")),
        role: Some(("linux", "exit")),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_ipv6_leak",
        stream: PlatformStream::Linux,
        direct_platform: Some(("linux", "exit_handoff")),
        role: Some(("linux", "exit")),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_exit_demotion_residue",
        stream: PlatformStream::Linux,
        direct_platform: Some(("linux", "exit_handoff")),
        role: Some(("linux", "exit")),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_dns_failclosed",
        stream: PlatformStream::Linux,
        direct_platform: Some(("linux", "managed_dns")),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_exit_dns_failclosed",
        stream: PlatformStream::Linux,
        direct_platform: Some(("linux", "managed_dns")),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_blind_exit_dataplane",
        stream: PlatformStream::Linux,
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    // ── Linux audit family ──────────────────────────────────────────────
    StageSpec {
        name: "validate_linux_membership_revoke_applies",
        stream: PlatformStream::Linux,
        special: Some("linux_membership_revoke_applies"),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        proves: PROVES_MEMBERSHIP_REVOKE,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_revoked_peer_denied_e2e",
        stream: PlatformStream::Linux,
        special: Some("linux_revoked_peer_denied_e2e"),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        proves: PROVES_REVOKED_PEER_DENIED,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_membership_signature_forgery",
        stream: PlatformStream::Linux,
        special: Some("linux_membership_signature_forgery"),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_privileged_helper_allowlist",
        stream: PlatformStream::Linux,
        special: Some("linux_privileged_helper_allowlist"),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_policy_default_deny",
        stream: PlatformStream::Linux,
        special: Some("linux_policy_default_deny"),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_runtime_acls",
        stream: PlatformStream::Linux,
        special: Some("linux_runtime_acls"),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_service_hardening",
        stream: PlatformStream::Linux,
        special: Some("linux_service_hardening"),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_authenticode",
        stream: PlatformStream::Linux,
        special: Some("linux_authenticode"),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_key_custody",
        stream: PlatformStream::Linux,
        special: Some("linux_key_custody"),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_membership_genesis",
        stream: PlatformStream::Linux,
        special: Some("linux_membership_genesis"),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_mesh_status",
        stream: PlatformStream::Linux,
        special: Some("linux_mesh_status"),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_blind_exit_reversal_denied",
        stream: PlatformStream::Linux,
        special: Some("linux_blind_exit_reversal_denied"),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        proves: PROVES_BLIND_EXIT_REVERSAL,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_gossip_revoked_readmit",
        stream: PlatformStream::Linux,
        special: Some("linux_gossip_revoked_readmit"),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        proves: PROVES_GOSSIP_REVOKED_READMIT,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_enrollment_replay",
        stream: PlatformStream::Linux,
        special: Some("linux_enrollment_replay"),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        proves: PROVES_ENROLLMENT_REPLAY,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_hello_limiter_flood",
        stream: PlatformStream::Linux,
        special: Some("linux_hello_limiter_flood"),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        proves: PROVES_HELLO_LIMITER_FLOOD,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "validate_linux_relay_forwards_frame",
        stream: PlatformStream::Linux,
        special: Some("linux_relay_forwards_frame"),
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 300,
        proves: PROVES_RELAY_FORWARDING,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    // ── bash live suite (shared LIVE stages) ────────────────────────────
    StageSpec {
        name: "upgrade_admin_node_membership",
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 120,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "live_anchor",
        logical: Some("anchor"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::LinuxLiveSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "live_relay",
        logical: Some("relay_service_lifecycle"),
        cross_os: Some("cross_os_relay_path"),
        platform_rule: PlatformRule::RelayTarget,
        enable: EnableRule::LinuxLiveSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "live_exit_handoff",
        logical: Some("exit_handoff"),
        cross_os: Some("cross_os_exit_path"),
        platform_rule: PlatformRule::ExitTarget,
        enable: EnableRule::LinuxLiveSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "live_two_hop",
        logical: Some("two_hop"),
        enable: EnableRule::LinuxLiveSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "live_lan_toggle",
        logical: Some("lan_toggle"),
        cross_os: Some("cross_os_lan_toggle"),
        enable: EnableRule::LinuxLiveSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "live_role_switch_matrix",
        logical: Some("role_switch_matrix"),
        cross_os: Some("cross_os_role_switch"),
        enable: EnableRule::LinuxLiveSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "live_managed_dns",
        logical: Some("managed_dns"),
        cross_os: Some("cross_os_dns"),
        enable: EnableRule::LinuxLiveSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "live_network_flap_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("network_flap"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::LinuxLiveSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "live_reboot_recovery_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("reboot_recovery"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::LinuxLiveSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "live_secrets_not_in_logs_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("secrets_not_in_logs"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::LinuxLiveSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "live_key_custody_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("key_custody"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    // Rust-engine live enrollment-restart test: admin node killed
    // mid-enrollment, daemon must recover and membership integrity
    // must remain intact. Single-stage binary, cross-OS.
    StageSpec {
        name: "live_enrollment_restart_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("enrollment_restart"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    // Rust-engine live LAN-toggle test: three cycles (off→on→off)
    // proving LAN-access toggle with enforcement evidence and
    // blind-exit rejection. Cross-OS (Linux/macOS/Windows via --platform).
    StageSpec {
        name: "live_lan_toggle_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("lan_toggle"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    // Rust-engine live mixed-topology test: one node per OS
    // (Linux+macOS+Windows), mutual membership visibility +
    // datapath freshness proof. All-platforms.
    StageSpec {
        name: "live_mixed_topology_validation",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("mixed_topology"),
        platform_rule: PlatformRule::AllPlatforms,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "live_mixed_topology",
        logical: Some("mixed_topology"),
        cross_os: Some("cross_os_peer_visibility"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::LinuxLiveSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "live_reboot_recovery",
        logical: Some("reboot_recovery"),
        enable: EnableRule::LinuxLiveSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "live_secrets_not_in_logs",
        logical: Some("secrets_not_in_logs"),
        enable: EnableRule::LinuxLiveSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "live_key_custody",
        logical: Some("key_custody"),
        enable: EnableRule::LinuxLiveSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "live_enrollment_restart",
        logical: Some("enrollment_restart"),
        enable: EnableRule::LinuxLiveSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "live_network_flap",
        logical: Some("network_flap"),
        enable: EnableRule::LinuxLiveSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "live_hello_limiter_flood_validation",
        group: StageGroup::Live,
        logical: Some("hello_limiter_flood"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::LinuxLiveSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "extended_soak",
        state_machine_only: true,
        group: StageGroup::Live,
        logical: Some("extended_soak"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::SoakSuite,
        ..DEFAULT_SPEC
    },
    // ── chaos suite ─────────────────────────────────────────────────────
    StageSpec {
        name: "chaos_clock_attack",
        group: StageGroup::Chaos,
        logical: Some("chaos"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::ChaosSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "chaos_crash_recovery",
        group: StageGroup::Chaos,
        logical: Some("chaos"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::ChaosSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "chaos_daemon_fault",
        group: StageGroup::Chaos,
        logical: Some("chaos"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::ChaosSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "chaos_daemon_sigstop_sigcont",
        group: StageGroup::Chaos,
        logical: Some("chaos"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::ChaosSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "chaos_membership_adversarial",
        group: StageGroup::Chaos,
        logical: Some("chaos"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::ChaosSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "chaos_network_impairment",
        group: StageGroup::Chaos,
        logical: Some("chaos"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::ChaosSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "chaos_privileged_boundary",
        group: StageGroup::Chaos,
        logical: Some("chaos"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::ChaosSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "chaos_resource_exhaustion",
        group: StageGroup::Chaos,
        logical: Some("chaos"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::ChaosSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "chaos_signed_state_adversarial",
        group: StageGroup::Chaos,
        logical: Some("chaos"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::ChaosSuite,
        ..DEFAULT_SPEC
    },
    // ── cross-network + job-level ───────────────────────────────────────
    StageSpec {
        name: "cross_network_nat_classification",
        logical: Some("cross_network"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::CrossNetworkSuite,
        // Cross-network auto mode decides at runtime whether the substrate
        // is available; the selectors cannot see that.
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "cross_network_nat_matrix",
        logical: Some("cross_network"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::CrossNetworkSuite,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "cross_network_controller_switch",
        logical: Some("cross_network"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::CrossNetworkSuite,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "cross_network_direct_remote_exit",
        logical: Some("cross_network"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::CrossNetworkSuite,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "cross_network_failback_roaming",
        logical: Some("cross_network"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::CrossNetworkSuite,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "cross_network_node_network_switch",
        logical: Some("cross_network"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::CrossNetworkSuite,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "cross_network_relay_remote_exit",
        logical: Some("cross_network"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::CrossNetworkSuite,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "cross_network_remote_exit_dns",
        logical: Some("cross_network"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::CrossNetworkSuite,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "cross_network_remote_exit_soak",
        logical: Some("cross_network"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::CrossNetworkSuite,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "cross_network_traversal_adversarial",
        logical: Some("cross_network"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::CrossNetworkSuite,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "cross_network_preflight",
        group: StageGroup::Pre,
        logical: Some("cross_network"),
        platform_rule: PlatformRule::AllPlatforms,
        enable: EnableRule::CrossNetworkSuite,
        conditional_dispatch: true,
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "local_full_gate_suite",
        group: StageGroup::Job,
        enable: EnableRule::LocalGateSuite,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "fresh_install_os_matrix_report",
        group: StageGroup::Job,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "vm_lab_setup_live_lab",
        group: StageGroup::Job,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "vm_lab_run_live_lab",
        group: StageGroup::Job,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "restart_unready_vms",
        group: StageGroup::Pre,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "discover_local_utm",
        group: StageGroup::Pre,
        budget_secs: 60,
        ..DEFAULT_SPEC
    },
    StageSpec {
        name: "rediscover_local_utm",
        group: StageGroup::Pre,
        budget_secs: 60,
        conditional_dispatch: true,
        ..DEFAULT_SPEC
    },
    StageSpec {
        // Display-only aggregate the monitor uses for the whole Linux
        // live-validation suite; never appears in recorded outcomes.
        name: "linux_live_suite",
        stream: PlatformStream::Linux,
        enable: EnableRule::LinuxLiveSuite,
        budget_secs: 3_600,
        synthetic: true,
        ..DEFAULT_SPEC
    },
];

/// `node::stage` composites (per-node parallel audit workers) record under a
/// node-scoped name; classification always applies to the bare stage.
pub fn strip_node_alias(stage: &str) -> &str {
    stage.rsplit("::").next().unwrap_or(stage)
}

fn registry_index() -> &'static BTreeMap<&'static str, &'static StageSpec> {
    static INDEX: OnceLock<BTreeMap<&'static str, &'static StageSpec>> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut index = BTreeMap::new();
        for spec in STAGES {
            index.insert(spec.name, spec);
            for alias in spec.aliases {
                index.insert(*alias, spec);
            }
        }
        index
    })
}

/// Look up a stage by canonical name or alias; node-scoped composites are
/// resolved to their bare stage first.
pub fn find_stage(stage: &str) -> Option<&'static StageSpec> {
    registry_index().get(strip_node_alias(stage)).copied()
}

/// All canonical stage names (no aliases, no synthetics excluded — callers
/// filter on [`StageSpec::synthetic`] when they need recordable names only).
#[allow(dead_code)] // consumed by the stage-manifest emitter (next increment)
pub fn all_stage_names() -> impl Iterator<Item = &'static str> {
    STAGES.iter().map(|spec| spec.name)
}

/// Registry-backed replacement for the historical `direct_platform_stage`
/// match table: `(platform, logical)` for OS-specific stages.
pub fn direct_platform_stage(stage: &str) -> Option<(&'static str, &'static str)> {
    find_stage(stage)?.direct_platform
}

/// Registry-backed replacement for the historical `direct_platform_role`
/// match table: `(platform, role)` role-result column attribution.
pub fn direct_platform_role(stage: &str) -> Option<(&'static str, &'static str)> {
    find_stage(stage)?.role
}

/// Registry-backed replacement for the historical `logical_stage_name`
/// match table, preserving its prefix fallbacks (`chaos_*` → chaos,
/// `*reboot*` → reboot_recovery) for names the registry does not know.
pub fn logical_stage_name(stage: &str) -> Option<&'static str> {
    let stage = strip_node_alias(stage);
    // A registered stage without a logical mapping is a deliberate gap
    // (e.g. the issue_and_distribute_* dialect drift) — the historical
    // prefix fallbacks below still apply to it exactly as they did when it
    // was unregistered.
    if let Some(spec) = find_stage(stage)
        && spec.logical.is_some()
    {
        return spec.logical;
    }
    if stage.starts_with("chaos_") {
        return Some("chaos");
    }
    if stage.starts_with("cross_network_") {
        return Some("cross_network");
    }
    if stage.contains("reboot") {
        return Some("reboot_recovery");
    }
    None
}

/// Registry-backed replacement for the `populate_cross_os_values` match
/// arms: the cross-OS aggregate column a stage feeds, if any.
pub fn cross_os_column(stage: &str) -> Option<&'static str> {
    find_stage(stage)?.cross_os
}

/// Registry-backed replacement for the `set_special_stage_values` match
/// arms: the one-off check column a stage feeds, if any.
pub fn special_column(stage: &str) -> Option<&'static str> {
    find_stage(stage)?.special
}

/// Registry-backed replacement for `is_rust_native_stage_name`.
#[allow(dead_code)] // kept for the drift gate; production platform choice goes through platform_rule
pub fn is_rust_native_stage_name(stage: &str) -> bool {
    // RNQ-16: membership in the Rust engine's stage vocabulary is DERIVED
    // from the typed authority (`StageId`), not stored per registry entry —
    // the two can no longer drift. Aliases resolve to their canonical name
    // first; unknown `chaos_`/`cross_network_` names keep the historical
    // prefix fallback (they are Rust-suite families by construction).
    let canonical = find_stage(stage).map(|spec| spec.name).unwrap_or(stage);
    crate::vm_lab::orchestrator::stage::StageId::try_from(canonical).is_ok()
        || canonical.starts_with("chaos_")
        || canonical.starts_with("cross_network_")
}

/// Registry-backed platform-resolution rule for shared stages, preserving
/// the historical `platforms_for_stage` fallbacks: unknown `cross_network_*`
/// names resolve on all platforms; every other unknown name is linux-only.
pub fn platform_rule(stage: &str) -> PlatformRule {
    let stage = strip_node_alias(stage);
    if let Some(spec) = find_stage(stage) {
        return spec.platform_rule;
    }
    if stage.starts_with("cross_network_") || stage.starts_with("chaos_") {
        PlatformRule::AllPlatforms
    } else {
        PlatformRule::LinuxOnly
    }
}

/// Cold-start budget for a stage: the registry value when known, else the
/// historical heuristic fallbacks (mirrors the monitor's
/// `default_stage_secs`).
#[allow(dead_code)] // consumed by the stage-manifest emitter (next increment)
pub fn default_budget_secs(stage: &str) -> u64 {
    let stage = strip_node_alias(stage);
    if let Some(spec) = find_stage(stage) {
        return spec.budget_secs;
    }
    if stage.starts_with("validate_macos_")
        || stage.starts_with("validate_windows_")
        || stage.starts_with("activate_macos_")
        || stage.starts_with("capture_macos_")
        || stage.starts_with("deploy_macos_")
    {
        180
    } else if stage.contains("collect") || stage.contains("distribute") {
        60
    } else if stage.contains("membership") || stage.contains("assignment") {
        120
    } else {
        // Includes the historical `contains("baseline")` arm, whose value
        // equals the default.
        300
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn registry_names_and_aliases_are_unique() {
        let mut seen = BTreeSet::new();
        for spec in STAGES {
            assert!(
                seen.insert(spec.name),
                "duplicate stage name: {}",
                spec.name
            );
            for alias in spec.aliases {
                assert!(seen.insert(*alias), "duplicate alias: {alias}");
            }
        }
    }

    #[test]
    fn registry_resolves_aliases_and_node_composites() {
        // Monitor phantom → the real stage.
        let spec = find_stage("distribute_windows_bundles").expect("alias resolves");
        assert_eq!(spec.name, "distribute_windows_membership");
        // Node-scoped composite → bare stage.
        let spec =
            find_stage("debian-headless-1::validate_linux_hello_limiter_flood").expect("resolves");
        assert_eq!(spec.name, "validate_linux_hello_limiter_flood");
        assert_eq!(spec.proves, PROVES_HELLO_LIMITER_FLOOD);
        // Unknown names stay unknown.
        assert!(find_stage("no_such_stage_ever").is_none());
    }

    #[test]
    fn every_recorded_vocabulary_name_is_registered() {
        // The full set of stage names observed in real recorded data
        // (live_lab_stage_timings.csv stage column + run-matrix
        // first_failed_stage values as of 2026-07-03). Every one must
        // resolve in the registry — this is the anti-drift floor: a stage
        // that records outcomes but is absent here is exactly the
        // "invisible failure" class the registry exists to kill.
        const RECORDED: &[&str] = &[
            // timings CSV vocabulary
            "bootstrap_hosts",
            "chaos_clock_attack",
            "chaos_crash_recovery",
            "chaos_daemon_fault",
            "chaos_daemon_sigstop_sigcont",
            "chaos_membership_adversarial",
            "chaos_network_impairment",
            "chaos_privileged_boundary",
            "chaos_resource_exhaustion",
            "chaos_signed_state_adversarial",
            "cleanup_hosts",
            "collect_pubkeys",
            "cross_network_nat_classification",
            "distribute_membership_state",
            "enforce_baseline_runtime",
            "extended_soak",
            "fresh_install_os_matrix_report",
            "issue_and_distribute_assignments",
            "issue_and_distribute_dns_zone",
            "issue_and_distribute_traversal",
            "live_anchor",
            "live_enrollment_restart",
            "live_exit_handoff",
            "live_key_custody",
            "live_lan_toggle",
            "live_managed_dns",
            "live_network_flap",
            "live_reboot_recovery",
            "live_relay",
            "live_role_switch_matrix",
            "live_secrets_not_in_logs",
            "live_two_hop",
            "local_full_gate_suite",
            "macos_preflight_check",
            "membership_setup",
            "preflight",
            "prepare_source_archive",
            "prime_remote_access",
            "upgrade_admin_node_membership",
            "validate_baseline_runtime",
            "verify_ssh_reachability",
            // first_failed_stage extras
            "activate_macos_exit_role",
            "amend_membership_for_macos",
            "amend_membership_for_windows",
            "bootstrap_macos_host",
            "bootstrap_windows_host",
            "capture_macos_exit_evidence_artifacts",
            "capture_windows_exit_evidence_artifacts",
            "debian-headless-1::validate_linux_hello_limiter_flood",
            "debian-headless-1::validate_linux_membership_genesis",
            "debian-headless-4::validate_linux_blind_exit_dataplane",
            "deploy_macos_anchor_profile",
            "distribute_windows_assignment_verifier_key",
            "distribute_windows_dns_zone",
            "distribute_windows_dns_zone_verifier_key",
            "distribute_windows_traversal",
            "distribute_windows_traversal_verifier_key",
            "live_managed_dns",
            "membership_init",
            "pull_windows_exit_evidence_artifacts",
            "relay_validation",
            "restart_unready_vms",
            "role_switch_matrix",
            "traffic_test_matrix",
            "validate_macos_admin_issue",
            "validate_macos_blind_exit",
            "validate_macos_exit_dns_failclosed",
            "validate_macos_hello_limiter_flood",
            "validate_macos_mesh_status",
            "validate_macos_relay_service_lifecycle",
            "validate_windows_admin_issue",
            "validate_windows_anchor_bundle_pull",
            "validate_windows_authenticode",
            "validate_windows_dns_failclosed",
            "validate_windows_enrollment_replay",
            "validate_windows_gossip_revoked_readmit",
            "validate_windows_hello_limiter_flood",
            "validate_windows_mesh_join",
            "validate_windows_named_pipe_acls",
            "vm_lab_run_live_lab",
            "vm_lab_setup_live_lab",
        ];
        let missing: Vec<&str> = RECORDED
            .iter()
            .filter(|name| find_stage(name).is_none())
            .copied()
            .collect();
        assert!(
            missing.is_empty(),
            "recorded stage names missing from the registry: {missing:?}"
        );
    }

    #[test]
    fn selectors_resolve_enable_rules() {
        let selectors = TargetSelectors {
            wants_macos: true,
            exit_platform: "macos".to_owned(),
            relay_platform: "linux".to_owned(),
            skip_linux_live_suite: true,
            ..TargetSelectors::default()
        };
        assert!(selectors.resolves(EnableRule::Always));
        assert!(selectors.resolves(EnableRule::WantsMacos));
        assert!(!selectors.resolves(EnableRule::WantsWindows));
        assert!(selectors.resolves(EnableRule::MacosExit));
        assert!(!selectors.resolves(EnableRule::WindowsExit));
        assert!(selectors.resolves(EnableRule::RelayPlatform("linux")));
        assert!(!selectors.resolves(EnableRule::RelayPlatform("macos")));
        assert!(!selectors.resolves(EnableRule::LinuxLiveSuite));
        assert!(!selectors.resolves(EnableRule::ChaosSuite));

        // macos_promote_exit alone elects the macOS exit stages.
        let promoted = TargetSelectors {
            macos_promote_exit: true,
            ..TargetSelectors::default()
        };
        assert!(promoted.resolves(EnableRule::MacosExit));

        // Empty selectors: default-deny for everything conditional.
        let empty = TargetSelectors::default();
        assert!(!empty.resolves(EnableRule::WantsMacos));
        assert!(!empty.resolves(EnableRule::MacosExit));
        assert!(!empty.resolves(EnableRule::ChaosSuite));
        assert!(empty.resolves(EnableRule::LinuxLiveSuite));
    }

    #[test]
    fn role_switch_platform_selector_default_denies_and_elects() {
        // Default-deny: an unset role_switch_platform never elects the stage
        // on any platform.
        let empty = TargetSelectors::default();
        assert!(!empty.resolves(EnableRule::RoleSwitchPlatform("macos")));
        assert!(!empty.resolves(EnableRule::RoleSwitchPlatform("windows")));

        let macos_elected = TargetSelectors {
            role_switch_platform: "macos".to_owned(),
            ..TargetSelectors::default()
        };
        assert!(macos_elected.resolves(EnableRule::RoleSwitchPlatform("macos")));
        assert!(!macos_elected.resolves(EnableRule::RoleSwitchPlatform("windows")));

        let spec = find_stage("validate_macos_role_transition")
            .expect("validate_macos_role_transition is registered");
        assert_eq!(spec.stream, PlatformStream::Macos);
        assert_eq!(spec.enable, EnableRule::RoleSwitchPlatform("macos"));

        let windows_elected = TargetSelectors {
            role_switch_platform: "windows".to_owned(),
            ..TargetSelectors::default()
        };
        assert!(windows_elected.resolves(EnableRule::RoleSwitchPlatform("windows")));
        assert!(!windows_elected.resolves(EnableRule::RoleSwitchPlatform("macos")));

        let windows_spec = find_stage("validate_windows_role_transition")
            .expect("validate_windows_role_transition is registered");
        assert_eq!(windows_spec.stream, PlatformStream::Windows);
        assert_eq!(
            windows_spec.enable,
            EnableRule::RoleSwitchPlatform("windows")
        );
    }

    #[test]
    fn soak_suite_selector_requires_linux_live_suite_too() {
        // extended_soak only ever dispatches inside the Linux live-validation
        // suite; skip_linux_live_suite must disable it even when soak_suite
        // (--skip-soak's inverse) is selected, or the conclusion barrier
        // synthesizes a spurious `aborted` for a stage that was never
        // dispatched by design (see run livelab-1783174602-844175f5ad2a).
        let soak_selected = TargetSelectors {
            soak_suite: true,
            ..TargetSelectors::default()
        };
        assert!(soak_selected.resolves(EnableRule::SoakSuite));

        let soak_selected_but_linux_suite_skipped = TargetSelectors {
            soak_suite: true,
            skip_linux_live_suite: true,
            ..TargetSelectors::default()
        };
        assert!(!soak_selected_but_linux_suite_skipped.resolves(EnableRule::SoakSuite));
        assert_eq!(
            soak_selected_but_linux_suite_skipped.skip_reason(EnableRule::SoakSuite),
            "linux live suite skipped for this run"
        );

        let spec = find_stage("extended_soak").expect("extended_soak is registered");
        assert_eq!(spec.enable, EnableRule::SoakSuite);
    }

    #[test]
    fn stage_status_taxonomy_round_trips_and_absorbs_dialects() {
        // Canonical strings round-trip.
        for status in [
            StageStatus::Pending,
            StageStatus::Running,
            StageStatus::Pass,
            StageStatus::Fail,
            StageStatus::Skipped,
            StageStatus::NotRun,
            StageStatus::Reused,
            StageStatus::NotApplicable,
            StageStatus::TimedOut,
            StageStatus::Aborted,
        ] {
            assert_eq!(parse_stage_status(status.as_str()), Some(status));
        }
        // Historical dialects normalize.
        assert_eq!(parse_stage_status("skip"), Some(StageStatus::Skipped));
        assert_eq!(parse_stage_status("SKIPPED"), Some(StageStatus::Skipped));
        assert_eq!(parse_stage_status("passed"), Some(StageStatus::Pass));
        assert_eq!(parse_stage_status("not_run"), Some(StageStatus::NotRun));
        assert_eq!(parse_stage_status("n/a"), Some(StageStatus::NotApplicable));
        assert_eq!(parse_stage_status("timeout"), Some(StageStatus::TimedOut));
        // Unknown strings are a caller decision, not a silent bucket.
        assert_eq!(parse_stage_status("exploded"), None);
        // Terminality: only pending/running are non-terminal.
        assert!(!StageStatus::Pending.is_terminal());
        assert!(!StageStatus::Running.is_terminal());
        assert!(StageStatus::Aborted.is_terminal());
        assert!(StageStatus::Skipped.is_terminal());
    }

    #[test]
    fn synthetic_stages_are_marked() {
        assert!(
            find_stage("linux_live_suite")
                .expect("registered")
                .synthetic
        );
        assert!(!find_stage("preflight").expect("registered").synthetic);
    }

    /// Finding 1D (drift gate, orchestrator half): every stage-name
    /// literal the bash orchestrator records must resolve in the registry.
    /// A new bash stage that lands without a registry entry fails this
    /// test instead of becoming invisible to every consumer.
    #[test]
    fn every_bash_orchestrator_stage_literal_is_registered() {
        let script_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/e2e/live_linux_lab_orchestrator.sh");
        let source = std::fs::read_to_string(&script_path)
            .unwrap_or_else(|err| panic!("read {}: {err}", script_path.display()));
        let mut names = std::collections::BTreeSet::new();
        for line in source.lines() {
            let line = line.trim_start();
            for prefix in [
                "run_stage hard ",
                "run_stage soft ",
                "run_setup_stage hard ",
                "run_setup_stage soft ",
                "record_stage_skip \"",
            ] {
                if let Some(rest) = line.find(prefix).map(|idx| &line[idx + prefix.len()..]) {
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
                        .collect();
                    if !name.is_empty() {
                        names.insert(name);
                    }
                }
            }
        }
        assert!(
            names.len() >= 30,
            "extraction regressed — only {} stage literals found",
            names.len()
        );
        let missing: Vec<String> = names
            .into_iter()
            .filter(|name| find_stage(name).is_none())
            .collect();
        assert!(
            missing.is_empty(),
            "bash orchestrator records stages the registry does not know: {missing:?}"
        );
    }

    /// Finding 1D (drift gate, monitor half): every stage-name literal in
    /// the lab monitor's fallback catalogs must resolve in the registry.
    /// The monitor is workspace-excluded (no build-time sharing), so this
    /// reads its source as text — exactly the hand-copied surface whose
    /// phantoms (collect_windows_pubkey, distribute_windows_bundles) went
    /// unnoticed for weeks. The fallback only governs pre-manifest report
    /// dirs, but while it exists it must not drift.
    #[test]
    fn every_monitor_fallback_catalog_stage_is_registered() {
        let source_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../rustynet-lab-monitor/src/app.rs");
        let source = std::fs::read_to_string(&source_path)
            .unwrap_or_else(|err| panic!("read {}: {err}", source_path.display()));
        // The fallback-catalog regions: the planned_stage_groups arrays and
        // the three *_live_lab_catalog functions.
        let mut regions = String::new();
        for (start, end) in [
            ("pub fn planned_stage_groups", "pub async fn refresh_state"),
            ("fn macos_live_lab_catalog", "fn format_duration"),
        ] {
            let from = source
                .find(start)
                .unwrap_or_else(|| panic!("marker {start:?} missing from monitor source"));
            let to = source[from..]
                .find(end)
                .map(|offset| from + offset)
                .unwrap_or_else(|| panic!("marker {end:?} missing from monitor source"));
            regions.push_str(&source[from..to]);
        }
        let mut names = std::collections::BTreeSet::new();
        for piece in regions.split('"').skip(1).step_by(2) {
            // Stage-name shape: snake_case with at least one underscore.
            if piece.len() > 3
                && piece.contains('_')
                && piece
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                names.insert(piece.to_owned());
            }
        }
        assert!(
            names.len() >= 60,
            "extraction regressed — only {} monitor catalog literals found",
            names.len()
        );
        let missing: Vec<String> = names
            .into_iter()
            .filter(|name| find_stage(name).is_none())
            .collect();
        assert!(
            missing.is_empty(),
            "monitor fallback catalog names the registry does not know: {missing:?}"
        );
    }

    /// Finding 1D (drift gate, Rust state-machine half): every StageId
    /// the Rust orchestrator can record must resolve in the registry.
    #[test]
    fn every_rust_state_machine_stage_id_is_registered() {
        for stage in crate::vm_lab::orchestrator::stage::StageId::ALL {
            assert!(
                find_stage(stage.as_str()).is_some(),
                "StageId::{stage:?} ({}) missing from the registry",
                stage.as_str()
            );
        }
    }

    #[test]
    fn budget_fallback_matches_monitor_heuristics_for_unknown_names() {
        assert_eq!(default_budget_secs("validate_macos_future_check"), 180);
        assert_eq!(default_budget_secs("distribute_future_bundle"), 60);
        assert_eq!(default_budget_secs("future_membership_thing"), 120);
        assert_eq!(default_budget_secs("future_baseline_thing"), 300);
        assert_eq!(default_budget_secs("totally_unknown"), 300);
    }
}
