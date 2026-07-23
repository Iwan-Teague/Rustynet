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
    ($($variant:ident => $name:literal @ $suite:ident / $tier:ident),+ $(,)?) => {
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

            /// Acceptance tier (`NodeEngineAcceptanceSpec_2026-07-23.md`
            /// §3/§9, increment A1). The tier token is a REQUIRED part of
            /// every catalog row — a row without one fails to parse — so
            /// this map is total over `StageId` by construction; the §9
            /// totality gate is the compiler, and the registry tests only
            /// pin the classification itself. Purely additive metadata:
            /// plan inclusion/order stay owned by [`StageId::suite`].
            pub fn tier(&self) -> crate::live_lab_stage_registry::Tier {
                use crate::live_lab_stage_registry::Tier;
                match self { $(StageId::$variant => Tier::$tier),+ }
            }
        }
    };
}

// Single authority for the typed ID, canonical pipeline order, wire name,
// suite membership (RNQ-16), and acceptance tier (A1). Row shape:
// `Variant => "wire_name" @ Suite / Tier`. Tier calls that involve judgment
// carry a one-line comment on the row so a reviewer can check the call.
define_stage_catalog! {
    Preflight => "preflight" @ Setup / T0Core,
    PrepareSourceArchive => "prepare_source_archive" @ Setup / T0Core,
    VerifySshReachability => "verify_ssh_reachability" @ Setup / T0Core,
    CleanupHosts => "cleanup_hosts" @ Setup / T0Core,
    BootstrapHosts => "bootstrap_hosts" @ Setup / T0Core,
    CollectPubkeys => "collect_pubkeys" @ Setup / T0Core,
    MembershipInit => "membership_init" @ Setup / T0Core,
    DistributeMembership => "distribute_membership" @ Setup / T0Core,
    AnchorValidation => "anchor_validation" @ Setup / T1Role,
    AdminIssue => "admin_issue" @ Setup / T1Role,
    DistributeAssignments => "distribute_assignments" @ Setup / T0Core,
    DistributeTraversal => "distribute_traversal" @ Setup / T0Core,
    DistributeDnsZone => "distribute_dns_zone" @ Setup / T0Core,
    EnforceBaselineRuntime => "enforce_baseline_runtime" @ Setup / T0Core,
    // blind_exit ACTIVATES the blind_exit role posture (role capability),
    // not baseline plumbing — T1 like the other role-lifecycle stages.
    BlindExit => "blind_exit" @ Setup / T1Role,
    ValidateBaselineRuntime => "validate_baseline_runtime" @ Setup / T0Core,
    SecurityAuditValidation => "security_audit_validation" @ Live / T4Security,
    DnsFailclosedValidation => "dns_failclosed_validation" @ Live / T4Security,
    // Live default-deny ACL enforcement — a wrong GREEN is fail-open, so
    // security tier rather than core plumbing.
    RuntimeAclsValidation => "runtime_acls_validation" @ Live / T4Security,
    ServiceHardeningValidation => "service_hardening_validation" @ Live / T4Security,
    KeyCustodyValidation => "key_custody_validation" @ Live / T4Security,
    // Mesh-status self-check: peers visible, no stale state — core mesh
    // health / reachability evidence, not a role capability.
    MeshStatusValidation => "mesh_status_validation" @ Live / T0Core,
    // Windows binary-signing (Authenticode) verification — binary-trust
    // control, so security tier.
    AuthenticodeValidation => "authenticode_validation" @ Live / T4Security,
    Ipv6LeakValidation => "ipv6_leak_validation" @ Live / T4Security,
    DeployRelayService => "deploy_relay_service" @ Live / T1Role,
    RelayValidation => "relay_validation" @ Live / T1Role,
    TrafficTestMatrix => "traffic_test_matrix" @ Live / T0Core,
    // Live role-transition matrix (admin<->client flips) — role-capability
    // lifecycle; the cross-OS half is the bash-dialect cross_os_role_switch
    // aggregate, not this stage.
    RoleSwitchMatrix => "role_switch_matrix" @ Live / T1Role,
    ExitHandoff => "exit_handoff" @ Live / T1Role,
    ActiveExit => "active_exit" @ Live / T1Role,
    // Spec §3 places the EXIT-scoped dns-failclosed inside the exit role's
    // T1 list ("exit→NAT+handoff+dns-failclosed+demotion-residue"); the
    // standalone dns_failclosed_validation above is the T4 family member.
    ExitDnsFailclosedValidation => "exit_dns_failclosed_validation" @ Live / T1Role,
    ExitNatLifecycleValidation => "exit_nat_lifecycle_validation" @ Live / T1Role,
    ExitDemotionResidueValidation => "exit_demotion_residue_validation" @ Live / T1Role,
    BlindExitDataplaneValidation => "blind_exit_dataplane_validation" @ Live / T1Role,
    LiveAnchor => "live_anchor" @ Live / T1Role,
    LiveTwoHopValidation => "live_two_hop_validation" @ Live / T1Role,
    LiveManagedDnsValidation => "live_managed_dns_validation" @ Live / T1Role,
    LiveNetworkFlapValidation => "live_network_flap_validation" @ Live / T2Resilience,
    LiveRebootRecoveryValidation => "live_reboot_recovery_validation" @ Live / T2Resilience,
    LiveSecretsNotInLogsValidation => "live_secrets_not_in_logs_validation" @ Live / T4Security,
    LiveKeyCustodyValidation => "live_key_custody_validation" @ Live / T4Security,
    // Daemon killed MID-enrollment, then trust state must be consistent
    // (token consumed ⟺ member) — restart/fault-recovery family; the
    // anchor's enrollment-SERVING capability is live_anchor's T1 scope.
    LiveEnrollmentRestartValidation => "live_enrollment_restart_validation" @ Live / T2Resilience,
    // Asserts the killswitch + blind-exit posture HOLD through LAN-access
    // toggling — the map's "killswitch" T4 family member. The bash-dialect
    // mac/win cross_os_lan_toggle aggregate is a different (cross-OS) cell.
    LiveLanToggleValidation => "live_lan_toggle_validation" @ Live / T4Security,
    // Requires Linux+macOS+Windows ALL present (skips otherwise) and proves
    // one signed membership view + fresh WireGuard handshakes across the
    // three OSes — the `--node` dialect's carrier of cross-OS
    // membership-convergence + peer-visibility coverage today.
    LiveMixedTopologyValidation => "live_mixed_topology_validation" @ Live / T3CrossOs,
    // HELLO-flood rate-limiter adversarial probe (DOS-1) — security tier.
    LiveHelloLimiterFloodValidation => "live_hello_limiter_flood_validation" @ Live / T4Security,
    LiveExtendedSoakValidation => "extended_soak" @ Soak / T2Resilience,
    // Cross-NETWORK ≠ cross-OS: this suite exercises NAT/netns traversal
    // between simulated networks (spec §3 has no cross-network tier), so
    // each stage tiers by its SUBJECT — substrate correctness (T0), role
    // capability reached across networks (T1), roaming/failover (T2),
    // adversarial (T4) — never T3CrossOs.
    CrossNetworkPreflight => "cross_network_preflight" @ CrossNetwork / T0Core,
    CrossNetworkDirectRemoteExit => "cross_network_direct_remote_exit" @ CrossNetwork / T1Role,
    CrossNetworkNodeNetworkSwitch => "cross_network_node_network_switch" @ CrossNetwork / T2Resilience,
    CrossNetworkRelayRemoteExit => "cross_network_relay_remote_exit" @ CrossNetwork / T1Role,
    CrossNetworkFailbackRoaming => "cross_network_failback_roaming" @ CrossNetwork / T2Resilience,
    CrossNetworkControllerSwitch => "cross_network_controller_switch" @ CrossNetwork / T2Resilience,
    CrossNetworkTraversalAdversarial => "cross_network_traversal_adversarial" @ CrossNetwork / T4Security,
    CrossNetworkRemoteExitDns => "cross_network_remote_exit_dns" @ CrossNetwork / T1Role,
    CrossNetworkRemoteExitSoak => "cross_network_remote_exit_soak" @ CrossNetwork / T2Resilience,
    // NAT classification/matrix validate the traversal SUBSTRATE every
    // cross-network capability rests on (not a role, not a disturbance) —
    // core-correctness tier.
    CrossNetworkNatClassification => "cross_network_nat_classification" @ CrossNetwork / T0Core,
    CrossNetworkNatMatrix => "cross_network_nat_matrix" @ CrossNetwork / T0Core,
    // The chaos suite splits by SUBJECT: adversarial-input stages targeting
    // trust/security controls are T4 (spec §3 T4 is "as tagged in the map";
    // chaos_privileged_boundary IS the map's privileged-helper-allowlist
    // member); fault/impairment stages are T2 (spec §3 T2 lists "chaos").
    // Clock rollback vs freshness/anti-replay protection — adversarial.
    ChaosClockAttack => "chaos_clock_attack" @ Chaos / T4Security,
    ChaosCrashRecovery => "chaos_crash_recovery" @ Chaos / T2Resilience,
    ChaosDaemonFault => "chaos_daemon_fault" @ Chaos / T2Resilience,
    ChaosDaemonSigstopSigcont => "chaos_daemon_sigstop_sigcont" @ Chaos / T2Resilience,
    ChaosMembershipAdversarial => "chaos_membership_adversarial" @ Chaos / T4Security,
    ChaosNetworkImpairment => "chaos_network_impairment" @ Chaos / T2Resilience,
    ChaosPrivilegedBoundary => "chaos_privileged_boundary" @ Chaos / T4Security,
    // Resource exhaustion = availability disturbance + recovery, closer to
    // impairment than to a trust-control bypass — resilience tier.
    ChaosResourceExhaustion => "chaos_resource_exhaustion" @ Chaos / T2Resilience,
    ChaosSignedStateAdversarial => "chaos_signed_state_adversarial" @ Chaos / T4Security,
    // Clean teardown, residue-asserted — named in spec §3's T0 list.
    Cleanup => "cleanup" @ Cleanup / T0Core,
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
