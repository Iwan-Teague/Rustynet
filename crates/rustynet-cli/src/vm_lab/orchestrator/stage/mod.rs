#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;

pub mod active_exit;
pub mod admin_issue;
pub mod anchor_validation;
pub mod authenticode_validation;
pub mod blind_exit;
pub mod blind_exit_dataplane_validation;
pub mod chaos;
pub mod cleanup;
pub mod collect_pubkeys;
pub mod cross_network;
pub mod deploy_relay;
pub mod distribute_assignments;
pub mod distribute_dns_zone;
pub mod distribute_membership;
pub mod distribute_traversal;
pub mod dns_failclosed_validation;
pub mod enforce_runtime;
pub mod exit_demotion_residue_validation;
pub mod exit_dns_failclosed_validation;
pub mod exit_handoff;
pub mod exit_nat_lifecycle_validation;
pub mod final_cleanup;
pub mod install;
pub mod ipv6_leak_validation;
pub mod key_custody_validation;
pub mod live_anchor;
pub mod live_enrollment_restart_validation;
pub mod live_extended_soak_validation;
pub mod live_hello_limiter_flood_validation;
pub mod live_key_custody_validation;
pub mod live_lan_toggle_validation;
pub mod live_managed_dns_validation;
pub mod live_mixed_topology_validation;
pub mod live_network_flap_validation;
pub mod live_reboot_recovery_validation;
pub mod live_secrets_not_in_logs_validation;
pub mod live_two_hop_validation;
pub mod membership_init;
pub mod mesh_status_validation;
pub mod preflight;
pub mod relay_validation;
pub mod role_switch_matrix;
pub mod runtime_acls_validation;
pub mod security_audit_validation;
pub mod service_hardening_validation;
pub mod source_archive;
pub mod traffic_test_matrix;
pub mod validate_runtime;
pub mod verify_ssh;

/// Pipeline suite a stage belongs to. The single typed authority (RNQ-16)
/// for plan inclusion: `PlanBuilder::build` iterates [`StageId::ALL`] in
/// order and includes a stage iff its suite is enabled, and the suite
/// id-lists (`live_suite_stages()`, …) derive from this tag. Adding a stage
/// = one catalog row below + one `OrchestrationStage` impl + one
/// `PlanBuilder` instantiation arm (compiler-enforced exhaustive match).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StageSuite {
    /// Discovery → baseline validation. Always included; `--setup-only`
    /// stops after the last Setup stage.
    Setup,
    /// Post-baseline validation + role lifecycle + live_* stages. Dropped by
    /// `--skip-linux-live-suite`.
    Live,
    /// The extended soak stage. Dropped by `--skip-soak` (and by
    /// `--skip-linux-live-suite`).
    Soak,
    /// Cross-network suite. Opt-out via `--skip-cross-network` (and dropped
    /// by `--skip-linux-live-suite`).
    CrossNetwork,
    /// Chaos suite. Opt-in via `--enable-chaos-suite` (and dropped by
    /// `--skip-linux-live-suite`).
    Chaos,
    /// Final teardown. Always included; `always_run`-exempt from
    /// skip-cascade.
    Cleanup,
}

macro_rules! define_stage_catalog {
    ($($variant:ident => $name:literal @ $suite:ident),+ $(,)?) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum StageId { $($variant),+ }

        impl StageId {
            /// Every variant, in canonical pipeline order. This IS the
            /// fully-enabled plan order — `PlanBuilder::build` derives from
            /// it (RNQ-16), so it can no longer drift from execution.
            pub const ALL: &'static [StageId] = &[$(StageId::$variant),+];

            pub fn as_str(&self) -> &'static str {
                match self { $(StageId::$variant => $name),+ }
            }

            /// The suite this stage belongs to (plan-inclusion authority).
            pub fn suite(&self) -> StageSuite {
                match self { $(StageId::$variant => StageSuite::$suite),+ }
            }
        }
    };
}

// Single authority for the typed ID, canonical pipeline order, wire name,
// and suite membership (RNQ-16).
define_stage_catalog! {
    Preflight => "preflight" @ Setup,
    PrepareSourceArchive => "prepare_source_archive" @ Setup,
    VerifySshReachability => "verify_ssh_reachability" @ Setup,
    CleanupHosts => "cleanup_hosts" @ Setup,
    BootstrapHosts => "bootstrap_hosts" @ Setup,
    CollectPubkeys => "collect_pubkeys" @ Setup,
    MembershipInit => "membership_init" @ Setup,
    DistributeMembership => "distribute_membership" @ Setup,
    AnchorValidation => "anchor_validation" @ Setup,
    AdminIssue => "admin_issue" @ Setup,
    DistributeAssignments => "distribute_assignments" @ Setup,
    DistributeTraversal => "distribute_traversal" @ Setup,
    DistributeDnsZone => "distribute_dns_zone" @ Setup,
    EnforceBaselineRuntime => "enforce_baseline_runtime" @ Setup,
    BlindExit => "blind_exit" @ Setup,
    ValidateBaselineRuntime => "validate_baseline_runtime" @ Setup,
    SecurityAuditValidation => "security_audit_validation" @ Live,
    DnsFailclosedValidation => "dns_failclosed_validation" @ Live,
    RuntimeAclsValidation => "runtime_acls_validation" @ Live,
    ServiceHardeningValidation => "service_hardening_validation" @ Live,
    KeyCustodyValidation => "key_custody_validation" @ Live,
    MeshStatusValidation => "mesh_status_validation" @ Live,
    AuthenticodeValidation => "authenticode_validation" @ Live,
    Ipv6LeakValidation => "ipv6_leak_validation" @ Live,
    DeployRelayService => "deploy_relay_service" @ Live,
    RelayValidation => "relay_validation" @ Live,
    TrafficTestMatrix => "traffic_test_matrix" @ Live,
    RoleSwitchMatrix => "role_switch_matrix" @ Live,
    ExitHandoff => "exit_handoff" @ Live,
    ActiveExit => "active_exit" @ Live,
    ExitDnsFailclosedValidation => "exit_dns_failclosed_validation" @ Live,
    ExitNatLifecycleValidation => "exit_nat_lifecycle_validation" @ Live,
    ExitDemotionResidueValidation => "exit_demotion_residue_validation" @ Live,
    BlindExitDataplaneValidation => "blind_exit_dataplane_validation" @ Live,
    LiveAnchor => "live_anchor" @ Live,
    LiveTwoHopValidation => "live_two_hop_validation" @ Live,
    LiveManagedDnsValidation => "live_managed_dns_validation" @ Live,
    LiveNetworkFlapValidation => "live_network_flap_validation" @ Live,
    LiveRebootRecoveryValidation => "live_reboot_recovery_validation" @ Live,
    LiveSecretsNotInLogsValidation => "live_secrets_not_in_logs_validation" @ Live,
    LiveKeyCustodyValidation => "live_key_custody_validation" @ Live,
    LiveEnrollmentRestartValidation => "live_enrollment_restart_validation" @ Live,
    LiveLanToggleValidation => "live_lan_toggle_validation" @ Live,
    LiveMixedTopologyValidation => "live_mixed_topology_validation" @ Live,
    LiveHelloLimiterFloodValidation => "live_hello_limiter_flood_validation" @ Live,
    LiveExtendedSoakValidation => "extended_soak" @ Soak,
    CrossNetworkPreflight => "cross_network_preflight" @ CrossNetwork,
    CrossNetworkDirectRemoteExit => "cross_network_direct_remote_exit" @ CrossNetwork,
    CrossNetworkNodeNetworkSwitch => "cross_network_node_network_switch" @ CrossNetwork,
    CrossNetworkRelayRemoteExit => "cross_network_relay_remote_exit" @ CrossNetwork,
    CrossNetworkFailbackRoaming => "cross_network_failback_roaming" @ CrossNetwork,
    CrossNetworkControllerSwitch => "cross_network_controller_switch" @ CrossNetwork,
    CrossNetworkTraversalAdversarial => "cross_network_traversal_adversarial" @ CrossNetwork,
    CrossNetworkRemoteExitDns => "cross_network_remote_exit_dns" @ CrossNetwork,
    CrossNetworkRemoteExitSoak => "cross_network_remote_exit_soak" @ CrossNetwork,
    CrossNetworkNatClassification => "cross_network_nat_classification" @ CrossNetwork,
    CrossNetworkNatMatrix => "cross_network_nat_matrix" @ CrossNetwork,
    ChaosClockAttack => "chaos_clock_attack" @ Chaos,
    ChaosCrashRecovery => "chaos_crash_recovery" @ Chaos,
    ChaosDaemonFault => "chaos_daemon_fault" @ Chaos,
    ChaosDaemonSigstopSigcont => "chaos_daemon_sigstop_sigcont" @ Chaos,
    ChaosMembershipAdversarial => "chaos_membership_adversarial" @ Chaos,
    ChaosNetworkImpairment => "chaos_network_impairment" @ Chaos,
    ChaosPrivilegedBoundary => "chaos_privileged_boundary" @ Chaos,
    ChaosResourceExhaustion => "chaos_resource_exhaustion" @ Chaos,
    ChaosSignedStateAdversarial => "chaos_signed_state_adversarial" @ Chaos,
    Cleanup => "cleanup" @ Cleanup,
}

impl std::fmt::Display for StageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TryFrom<&str> for StageId {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        StageId::ALL
            .iter()
            .find(|s| s.as_str() == value)
            .cloned()
            .ok_or_else(|| format!("unknown Rust-native stage: '{value}'"))
    }
}

/// How a stage fans out across nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageFanout {
    /// Execute once for the whole lab (e.g. membership-init on exit node).
    Once,
    /// Execute once per role-matched node.
    PerNode,
}

/// One stage in the orchestration pipeline. One impl per stage file.
pub trait OrchestrationStage: Send + Sync {
    fn id(&self) -> StageId;
    fn name(&self) -> &str;

    /// Stages that must pass before this one runs.
    /// Failure or skip of a dependency triggers skip-cascade on this stage.
    fn dependencies(&self) -> &[StageId];

    /// Which roles this stage operates on. Empty slice = all roles.
    fn applies_to_roles(&self) -> &[NodeRole];

    fn fanout(&self) -> StageFanout;

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome;

    /// Teardown stages that MUST run even when an earlier stage failed —
    /// exempt from dependency skip-cascade so this run's own killswitch / exit
    /// NAT residue is always removed from the guests (leaving residue is a
    /// release-blocker per the operating contract). An `always_run` stage is
    /// still ordered after its [`dependencies`](Self::dependencies) and is
    /// still honored by an explicit `--skip-stage`; it is only exempt from
    /// being *cascade*-skipped because a dependency failed. Default `false`.
    fn always_run(&self) -> bool {
        false
    }
}

/// How much of each captured stream reaches the stage summary. Enough to carry
/// a guest's error and a little context; the rest stays in the report dir.
const STAGE_FAILURE_STREAM_BUDGET: usize = 4000;

/// Render a failed live-lab binary's output for the stage summary.
///
/// These stages shell out to a `live_*` binary which SSHes to the guests. The
/// guest's own diagnostic arrives on the binary's **stdout**, while the
/// binary's terse wrapper message goes to stderr. Reporting only stderr — as
/// every one of these stages did — throws the actual cause away and leaves a
/// summary like
///
/// ```text
/// enforce-host failed for debian@192.168.64.10:22 with status 1
///   hint: unclassified failure; check the error message above
/// ```
///
/// where nothing is "above": `.output()` captured the guest's explanation and
/// the stage dropped it. The real cause of that failure —
/// `assignment exit node rocky-utm-1-bootstrap lacks signed membership
/// capability exit_server` — existed only in the guest's journal and had to be
/// recovered by reproducing the command by hand over SSH. That cost a
/// live-lab cycle three times over.
///
/// So surface BOTH streams, labelled. Note stdout is not merely a fallback for
/// an empty stderr: the two carry different halves of the story, and it is
/// exactly when stderr is non-empty (the wrapper message) that stdout (the
/// cause) matters most.
pub(crate) fn format_stage_binary_failure(
    label: &str,
    status: std::process::ExitStatus,
    stdout: &[u8],
    stderr: &[u8],
) -> String {
    /// Keep the **tail**, not the head.
    ///
    /// A failing CLI dumps its whole usage text (11.5 KB) and prints the actual
    /// error last, so clipping the head yields a screenful of help and hides
    /// the one line worth reading — which is exactly what happened on the first
    /// run of this formatter. The existing enforce_runtime reporter already
    /// says "(stdout tail)" for the same reason.
    fn clip(raw: &[u8]) -> String {
        let text = String::from_utf8_lossy(raw);
        let text = text.trim();
        let total = text.chars().count();
        if total <= STAGE_FAILURE_STREAM_BUDGET {
            return text.to_owned();
        }
        let skip = total - STAGE_FAILURE_STREAM_BUDGET;
        let tail: String = text.chars().skip(skip).collect();
        format!(
            "…(clipped {} of {} bytes; tail follows)\n{tail}",
            raw.len().saturating_sub(tail.len()),
            raw.len()
        )
    }
    let out = clip(stdout);
    let err = clip(stderr);
    let mut detail = String::new();
    if !err.is_empty() {
        detail.push_str(&format!("\nstderr: {err}"));
    }
    if !out.is_empty() {
        detail.push_str(&format!("\nstdout: {out}"));
    }
    if detail.is_empty() {
        detail.push_str(" (the binary produced no output on either stream)");
    }
    format!("{label} failed (exit {status}):{detail}")
}

#[cfg(test)]
mod failure_format_tests {
    use super::*;

    fn exit_status_failure() -> std::process::ExitStatus {
        // A real ExitStatus is only constructible by running something.
        std::process::Command::new("sh")
            .args(["-c", "exit 1"])
            .status()
            .expect("spawn sh")
    }

    #[test]
    fn both_streams_are_surfaced_when_both_are_present() {
        // The regression: stderr held the useless wrapper line while stdout
        // held the cause, so a stderr-only summary (or a stdout-as-fallback
        // one) discarded exactly the half worth reading.
        let summary = format_stage_binary_failure(
            "live_two_hop",
            exit_status_failure(),
            b"selected exit node rocky-utm-1-bootstrap lacks capability exit_server",
            b"enforce-host failed for debian@192.168.64.10:22 with status 1",
        );
        assert!(summary.contains("enforce-host failed"), "{summary}");
        assert!(
            summary.contains("lacks capability exit_server"),
            "the guest's cause arrives on stdout and must not be dropped: {summary}"
        );
    }

    #[test]
    fn a_silent_binary_says_so_rather_than_looking_like_a_clean_failure() {
        let summary =
            format_stage_binary_failure("live_two_hop", exit_status_failure(), b"", b"   ");
        assert!(summary.contains("no output on either stream"), "{summary}");
    }

    #[test]
    fn oversized_output_keeps_the_tail_where_the_error_is() {
        // A failing CLI dumps its whole usage text and prints the real error
        // LAST. Clipping the head hid it behind 11.5 KB of help on this
        // formatter's first live run, which is the whole reason it clips the
        // tail instead.
        let mut noisy = vec![b'x'; STAGE_FAILURE_STREAM_BUDGET * 2];
        noisy.extend_from_slice(b"THE ACTUAL ERROR");
        let summary =
            format_stage_binary_failure("live_two_hop", exit_status_failure(), &noisy, b"");
        assert!(
            summary.contains("THE ACTUAL ERROR"),
            "the tail carries the error and must survive clipping"
        );
        assert!(summary.contains("clipped"), "clipping must be disclosed");
        assert!(
            summary.len() < STAGE_FAILURE_STREAM_BUDGET * 2,
            "a runaway log must not swallow the summary"
        );
    }
}
