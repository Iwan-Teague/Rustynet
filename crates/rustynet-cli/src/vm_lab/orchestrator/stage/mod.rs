#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;

/// Resolve the SSH username for a lab guest: the inventory's value when it has
/// one, and only otherwise a per-platform default.
///
/// Hoisted out of the LAN-toggle stage (QH-49) after QH-56: stages that
/// hardcoded "debian" for every non-Windows guest dialled one node's username
/// against another node's host the moment a role landed on a Fedora/Rocky
/// guest, and died with Permission denied. The inventory records the real
/// username; throwing it away is the bug. The fallback deliberately preserves
/// the LAN-toggle stage's historical values rather than unifying with the
/// "administrator"/"admin" defaults some stages use - changing an untested
/// fallback is a separate behavioural change from fixing "the real username
/// was available and thrown away".
pub(crate) fn resolve_ssh_user(inventory_user: Option<&str>, platform: VmGuestPlatform) -> String {
    if let Some(user) = inventory_user.map(str::trim).filter(|u| !u.is_empty()) {
        return user.to_owned();
    }
    match platform {
        VmGuestPlatform::Windows => "admin",
        _ => "debian",
    }
    .to_owned()
}

/// The evidence/wire label for a node's platform, refused for the platforms
/// that cannot host the lab validation runtime. Shared by the standalone
/// validation-binary spawners (audit I3): each stage used to carry its own
/// `_ => "linux"` label helper, so a missing adapter or a never-hosted
/// platform (Ios/Android) was silently stamped `linux` into the `--platform`
/// argv and the run's evidence. The desktop platforms tag through the
/// exhaustive [`VmGuestPlatform::evidence_tag`]; everything else is an
/// `Err` the caller must surface as a stage failure.
pub(crate) fn desktop_platform_tag(
    platform: VmGuestPlatform,
    context: &str,
) -> Result<&'static str, String> {
    match platform {
        VmGuestPlatform::Linux | VmGuestPlatform::Macos | VmGuestPlatform::Windows => {
            Ok(platform.evidence_tag())
        }
        VmGuestPlatform::Ios | VmGuestPlatform::Android => Err(format!(
            "{context}: platform {platform:?} cannot host the lab validation \
             runtime (refusing to label it linux)"
        )),
    }
}

#[cfg(test)]
mod desktop_platform_tag_tests {
    use super::*;

    /// Audit I3: the desktop platforms tag through the exhaustive
    /// [`VmGuestPlatform::evidence_tag`] table and the never-hosted platforms
    /// are refused instead of labelled. Mutation caught: reintroducing a
    /// `_ => Ok("linux")` arm (or widening the desktop set) makes the
    /// Ios/Android entries return `Ok("linux")` and fails this test; the
    /// desktop labels come from `evidence_tag_covers_every_variant`.
    #[test]
    fn desktop_platform_tag_refuses_never_hosted_platforms() {
        assert_eq!(
            desktop_platform_tag(VmGuestPlatform::Linux, "t"),
            Ok("linux")
        );
        assert_eq!(
            desktop_platform_tag(VmGuestPlatform::Macos, "t"),
            Ok("macos")
        );
        assert_eq!(
            desktop_platform_tag(VmGuestPlatform::Windows, "t"),
            Ok("windows")
        );
        for refused in [VmGuestPlatform::Ios, VmGuestPlatform::Android] {
            let err = desktop_platform_tag(refused, "stage-x")
                .expect_err("never-hosted platform must be refused, never labelled");
            assert!(
                err.contains("stage-x") && err.contains("refusing to label it linux"),
                "refusal must name the context and the refusal: {err}"
            );
        }
    }
}

pub mod active_exit;
pub mod admin_issue;
pub mod anchor_validation;
pub mod authenticode_validation;
pub mod blind_exit;
pub mod blind_exit_dataplane_validation;
pub mod bundle_evidence;
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
pub mod gossip_convergence_validation;
pub mod host_cross_build;
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
// MAC-D3: the three macOS anchor validators, promoted from the bash-era
// registry vocabulary into first-class --node engine stages.
pub mod macos_anchor_bundle_pull_validation;
pub mod macos_anchor_port_mapping_authority_validation;
pub mod macos_anchor_profile_deploy;
pub mod macos_reboot_recovery_validation;
pub mod macos_role_transition_validation;
pub mod membership_init;
pub mod mesh_status_validation;
pub mod negative_control;
pub mod preflight;
pub mod refresh_signed_bundles;
pub mod relay_forwards_frame_validation;
pub mod relay_validation;
pub mod role_switch_matrix;
pub mod role_transition_ordering_eval;
pub mod runtime_acls_validation;
pub mod scenario;
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
    /// T5 negative-control / adjudication suite. Opt-in via
    /// `--enable-negative-control` (and dropped by `--skip-linux-live-suite`),
    /// exactly mirroring the chaos suite's opt-in guarantee: it stays OUT of
    /// the default plan so a normal live lab never injects the negative-control
    /// faults. See `stage/negative_control.rs`.
    NegativeControl,
    /// HP-3 relay-frame-forwarding opt-in validation. Opt-in via
    /// `--enable-relay-forwarding-validation` (and dropped by
    /// `--skip-linux-live-suite`), mirroring the chaos suite's opt-in
    /// guarantee: it stays OUT of the default plan because it injects nft
    /// blocks on two peer daemons and restarts them MID-RUN (QH-64), so a
    /// normal live lab never carries that disruption. See
    /// `stage/relay_forwards_frame_validation.rs`.
    Disruptive,
    /// Final teardown. Always included; `always_run`-exempt from
    /// skip-cascade.
    Cleanup,
}

/// QH-83 evidence-on-pass: the on-disk witness a stage MUST have written for
/// a `Passed` verdict to stand. The wrapper in
/// `orchestrator::runner::StateMachineRunner` checks the declaration after
/// `execute` returns `Passed` and demotes the verdict to
/// `StageOutcome::NotProven` when the witness is absent or empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageEvidence {
    /// The stage's own log (`logs/<id>.log`) must exist and be non-empty
    /// after trimming. Use only for stages that genuinely append
    /// stage-scoped evidence lines during `execute` via
    /// `append_stage_evidence_line`.
    StageLog,
    /// A stage-declared data artifact, relative to the run's report
    /// directory. Malformed declarations (empty, absolute, or
    /// parent-escaping) are rejected at plan validation
    /// (`StateMachineRunner::new`), never silently honored.
    File(&'static str),
    /// Explicit named opt-out for stages whose contract genuinely produces
    /// no on-disk witness. The reason string is recorded in the plan
    /// artifact so audits can distinguish a deliberate, reviewable opt-out
    /// from an unreviewed default.
    None { reason: &'static str },
}

/// Phase-1 placeholder reason carried by stages whose pass-verdict witness
/// is not yet declared. Each such declaration is upgraded (usually to
/// `File(...)`) in the per-suite QH-83 evidence batches tracked in
/// `QualityHardeningTodo_2026-07-25.md`.
pub const PHASE1_EVIDENCE_PENDING: &str =
    "phase-1 declaration: no on-disk witness is verified behind this verdict yet";

/// Teardown opt-out reason: residue-removal stages are release-critical and
/// must never be blocked by the evidence-on-pass check.
pub const TEARDOWN_EVIDENCE_OPT_OUT: &str = "teardown opt-out: residue removal is release-critical and must not be blocked by the evidence-on-pass check";

macro_rules! define_stage_catalog {
    ($($variant:ident => $name:literal @ $suite:ident / $tier:ident / $evidence:expr),+ $(,)?) => {
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

            /// QH-83 evidence-on-pass declaration for this stage — the
            /// on-disk witness a `Passed` verdict requires. The evidence
            /// token is a REQUIRED part of every catalog row — a row
            /// without one fails to parse — so this map is total over
            /// `StageId` by construction: the 82nd stage forces its own
            /// conscious witness-or-opt-out decision at the catalog row,
            /// with the compiler as the totality gate. Purely additive
            /// metadata: verdicts stay owned by each stage's `execute`.
            pub fn evidence(&self) -> StageEvidence {
                match self { $(StageId::$variant => $evidence),+ }
            }
        }
    };
}

// Single authority for the typed ID, canonical pipeline order, wire name,
// suite membership (RNQ-16), acceptance tier (A1), and QH-83 evidence
// declaration. Row shape: `Variant => "wire_name" @ Suite / Tier / Evidence`.
// Tier calls that involve judgment carry a one-line comment on the row so a
// reviewer can check the call; evidence declarations other than
// PHASE1_EVIDENCE_PENDING carry one too.
define_stage_catalog! {
    // QH-83 Setup batch: the Setup rows carry real witnesses — preflight and
    // prepare_source_archive declare the artifacts they already write (with
    // fatal write failures), the per-node probe/bootstrap stages append
    // count-bearing stage-log lines, and the bundle-distribution rows declare
    // their per-alias bundle_evidence.json witnesses (F1b). MembershipInit
    // was the reference StageLog row; anchor_validation and
    // validate_baseline_runtime append per-validated-node witnesses too.
    Preflight => "preflight" @ Setup / T0Core / StageEvidence::File("logs/cross_bridge_preflight.txt"),
    PrepareSourceArchive => "prepare_source_archive" @ Setup / T0Core / StageEvidence::File("state/source_archive_provenance.json"),
    VerifySshReachability => "verify_ssh_reachability" @ Setup / T0Core / StageEvidence::StageLog,
    CleanupHosts => "cleanup_hosts" @ Setup / T0Core / StageEvidence::StageLog,
    BootstrapHosts => "bootstrap_hosts" @ Setup / T0Core / StageEvidence::StageLog,
    // TOPOLOGY-LEVEL substrate seam (spec §0.5, 2026-08-27): must run BEFORE
    // collect_pubkeys so overlay addresses — not raw cross-LAN-unroutable
    // underlay IPs — are what land in ctx.endpoints. A no-op pass unless an
    // overlay-provisioning substrate is selected. Substrate
    // correctness is T0 like the nat_classification/matrix rows below.
    CrossNetworkSubstrateSetup => "cross_network_substrate_setup" @ Setup / T0Core / StageEvidence::StageLog,
    CollectPubkeys => "collect_pubkeys" @ Setup / T0Core / StageEvidence::StageLog,
    MembershipInit => "membership_init" @ Setup / T0Core / StageEvidence::StageLog,
    // QH-83 F1b: every bundle-distribution pass writes a per-alias witness
    // (alias, node_id, minted file, sha256, remote install destination) via
    // stage/bundle_evidence.rs; the runner demotes an unwitnessed pass.
    DistributeMembership => "distribute_membership" @ Setup / T0Core / StageEvidence::File("logs/distribute_membership.bundle_evidence.json"),
    // QH-83 Setup batch: anchor_validation appends one witness line per
    // validated anchor node (alias + substage summary); the
    // reported_skips.json side-car write is fatal on failure too.
    AnchorValidation => "anchor_validation" @ Setup / T1Role / StageEvidence::StageLog,
    // QH-83 Setup batch: admin_issue appends a per-validated-node witness
    // line (status role=admin + peer-list exit 0).
    AdminIssue => "admin_issue" @ Setup / T1Role / StageEvidence::StageLog,
    DistributeAssignments => "distribute_assignments" @ Setup / T0Core / StageEvidence::File("logs/distribute_assignment.bundle_evidence.json"),
    DistributeTraversal => "distribute_traversal" @ Setup / T0Core / StageEvidence::File("logs/distribute_traversal.bundle_evidence.json"),
    DistributeDnsZone => "distribute_dns_zone" @ Setup / T0Core / StageEvidence::File("logs/distribute_dns-zone.bundle_evidence.json"),
    // QH-83 Setup batch: enforce appends an enforced_nodes=N witness line.
    EnforceBaselineRuntime => "enforce_baseline_runtime" @ Setup / T0Core / StageEvidence::StageLog,
    // blind_exit ACTIVATES the blind_exit role posture (role capability),
    // not baseline plumbing — T1 like the other role-lifecycle stages.
    // QH-83/F4: a PASS verdict writes one witness line per validated node via
    // append_stage_evidence_line (stage/blind_exit.rs), so the runner's
    // verify_declared_evidence can demote an unwitnessed PASS to NotProven.
    BlindExit => "blind_exit" @ Setup / T1Role / StageEvidence::StageLog,
    // QH-83 Setup batch: validate_baseline_runtime appends a
    // validated_nodes=N witness line (the F3 empty-scope guard stands).
    ValidateBaselineRuntime => "validate_baseline_runtime" @ Setup / T0Core / StageEvidence::StageLog,
    SecurityAuditValidation => "security_audit_validation" @ Live / T4Security / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    DnsFailclosedValidation => "dns_failclosed_validation" @ Live / T4Security / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    // Live default-deny ACL enforcement — a wrong GREEN is fail-open, so
    // security tier rather than core plumbing.
    RuntimeAclsValidation => "runtime_acls_validation" @ Live / T4Security / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    ServiceHardeningValidation => "service_hardening_validation" @ Live / T4Security / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    KeyCustodyValidation => "key_custody_validation" @ Live / T4Security / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    // Mesh-status self-check: peers visible, no stale state — core mesh
    // health / reachability evidence, not a role capability.
    MeshStatusValidation => "mesh_status_validation" @ Live / T0Core / StageEvidence::StageLog,
    // Gossip peer convergence: registered, accepting signed bundles, no
    // unknown-source rejections. Core mesh health like mesh_status, not a role
    // capability — a wrong GREEN here means the epidemic is silently dead.
    GossipConvergenceValidation => "gossip_convergence_validation" @ Live / T0Core / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    // Windows binary-signing (Authenticode) verification — binary-trust
    // control, so security tier.
    AuthenticodeValidation => "authenticode_validation" @ Live / T4Security / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    Ipv6LeakValidation => "ipv6_leak_validation" @ Live / T4Security / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    DeployRelayService => "deploy_relay_service" @ Live / T1Role / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    RelayValidation => "relay_validation" @ Live / T1Role / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    TrafficTestMatrix => "traffic_test_matrix" @ Live / T0Core / StageEvidence::File("logs/traffic_test_matrix.pair_results.log"),
    // Live role-transition matrix (admin<->client flips) — role-capability
    // lifecycle; the cross-OS half is the bash-dialect cross_os_role_switch
    // aggregate, not this stage.
    RoleSwitchMatrix => "role_switch_matrix" @ Live / T1Role / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    ExitHandoff => "exit_handoff" @ Live / T1Role / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    // Audit B4: the ONLY pass path of this stage writes the egress NAT
    // session pair (client traffic translated by the exit) — declared as the
    // pass witness so a bare Passed with no proof is demoted by the runner.
    // Skips (unimplemented platform, no client, offline egress) carry their
    // own reported-skip artifacts and are not gated on this witness.
    ActiveExit => "active_exit" @ Live / T1Role / StageEvidence::File("active_exit.egress_evidence.json"),
    // Spec §3 places the EXIT-scoped dns-failclosed inside the exit role's
    // T1 list ("exit→NAT+handoff+dns-failclosed+demotion-residue"); the
    // standalone dns_failclosed_validation above is the T4 family member.
    ExitDnsFailclosedValidation => "exit_dns_failclosed_validation" @ Live / T1Role / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    ExitNatLifecycleValidation => "exit_nat_lifecycle_validation" @ Live / T1Role / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    ExitDemotionResidueValidation => "exit_demotion_residue_validation" @ Live / T1Role / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    BlindExitDataplaneValidation => "blind_exit_dataplane_validation" @ Live / T1Role / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    LiveAnchor => "live_anchor" @ Live / T1Role / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    // MAC-D3: macOS anchor validators, previously registry-only (bash era).
    // Wire names match the legacy registry vocabulary so run-matrix evidence
    // stays comparable. Gated Live: skipped-with-reason unless the macOS
    // anchor validators are elected (--anchor-platform macos) and a macOS
    // anchor node is assigned.
    MacosAnchorProfileDeploy => "deploy_macos_anchor_profile" @ Live / T1Role / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    MacosAnchorBundlePullValidation => "validate_macos_anchor_bundle_pull" @ Live / T1Role / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    MacosAnchorPortMappingAuthorityValidation => "validate_macos_anchor_port_mapping_authority" @ Live / T1Role / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    // C6: live macOS role-transition validator, previously the legacy
    // vm_lab hub block `validate_macos_role_transition` that never
    // dispatched under the Rust engine (W5.7). Wire name matches the
    // legacy registry vocabulary so run-matrix evidence stays comparable.
    // Gated Live: skipped-with-reason unless the run elects macOS for
    // role transition (--role-switch-platform macos).
    MacosRoleTransitionValidation => "validate_macos_role_transition" @ Live / T1Role / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    LiveTwoHopValidation => "live_two_hop_validation" @ Live / T1Role / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    LiveManagedDnsValidation => "live_managed_dns_validation" @ Live / T1Role / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    LiveNetworkFlapValidation => "live_network_flap_validation" @ Live / T2Resilience / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    LiveRebootRecoveryValidation => "live_reboot_recovery_validation" @ Live / T2Resilience / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    // C7: live macOS reboot-with-protection validator
    // (MacosDnsBackupRebootSurvivalPlan_2026-09-02.md). Wire name matches the
    // registry vocabulary so run-matrix evidence stays comparable. Gated
    // Live: skipped-with-reason unless the run elects macOS for reboot
    // recovery (--reboot-platform macos).
    MacosRebootRecoveryValidation => "validate_macos_reboot_recovery" @ Live / T2Resilience / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    LiveSecretsNotInLogsValidation => "live_secrets_not_in_logs_validation" @ Live / T4Security / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    LiveKeyCustodyValidation => "live_key_custody_validation" @ Live / T4Security / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    // Daemon killed MID-enrollment, then trust state must be consistent
    // (token consumed ⟺ member) — restart/fault-recovery family; the
    // anchor's enrollment-SERVING capability is live_anchor's T1 scope.
    LiveEnrollmentRestartValidation => "live_enrollment_restart_validation" @ Live / T2Resilience / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    // Asserts the killswitch + blind-exit posture HOLD through LAN-access
    // toggling — the map's "killswitch" T4 family member. Its registry spec
    // feeds the `cross_os_lan_toggle` schema column, the same cell the
    // bash-dialect `live_lan_toggle` wrapper historically fed.
    LiveLanToggleValidation => "live_lan_toggle_validation" @ Live / T4Security / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    // Requires Linux+macOS+Windows ALL present (skips otherwise) and proves
    // one signed membership view + fresh WireGuard handshakes across the
    // three OSes — the `--node` dialect's carrier of cross-OS
    // membership-convergence + peer-visibility coverage today.
    LiveMixedTopologyValidation => "live_mixed_topology_validation" @ Live / T3CrossOs / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    // HELLO-flood rate-limiter adversarial probe (DOS-1) — security tier.
    LiveHelloLimiterFloodValidation => "live_hello_limiter_flood_validation" @ Live / T4Security / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    // HP-3 relay-frame-forwarding opt-in proof: asserts the relay actually
    // FORWARDS ciphertext between two peers (not just accepts registrations)
    // by blocking direct peer↔peer nft paths and routing a counter-probe
    // through the relay. Disruptive by design (nft blocks + two daemon
    // restarts mid-run, QH-64) — hence its own Disruptive suite, last Live
    // placement to minimize the post-restart tail, opt-in via
    // --enable-relay-forwarding-validation. Role-capability proof: T1.
    // HP-3 freshness prerequisite: re-mint + redistribute the signed
    // traversal and dns_zone bundles immediately before HP-3 so the proof
    // never runs against bundles that expired mid-run (BUNDLE_TTL_SECS /
    // TRAVERSAL_TTL_SECS stay as configured; this stage never lengthens
    // them). Gated by the same --enable-relay-forwarding-validation flag;
    // skipped (fail-closed) otherwise. Role-capability proof: T1.
    // QH-83 F1b: the pass distributes BOTH the traversal and the dns-zone
    // bundle and writes both witnesses under this stage's OWN paths
    // (bundle_evidence::BundleWitnessScope::Refresh — the Setup rows above
    // keep theirs, so the runner's clear-at-start here cannot erase them);
    // the runner checks the traversal one (the outcome this stage returns).
    // Both spellings are pinned by bundle_evidence.rs's
    // `each_witness_scope_owns_a_distinct_path`.
    RefreshSignedBundles => "refresh_signed_bundles" @ Disruptive / T1Role / StageEvidence::File("logs/refresh_signed_bundles.traversal.bundle_evidence.json"),
    RelayForwardsFrameValidation => "relay_forwards_frame_validation" @ Disruptive / T1Role / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    LiveExtendedSoakValidation => "extended_soak" @ Soak / T2Resilience / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    // Cross-NETWORK ≠ cross-OS: this suite exercises NAT/netns traversal
    // between simulated networks (spec §3 has no cross-network tier), so
    // each stage tiers by its SUBJECT — substrate correctness (T0), role
    // capability reached across networks (T1), roaming/failover (T2),
    // adversarial (T4) — never T3CrossOs.
    CrossNetworkPreflight => "cross_network_preflight" @ CrossNetwork / T0Core / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    CrossNetworkDirectRemoteExit => "cross_network_direct_remote_exit" @ CrossNetwork / T1Role / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    CrossNetworkNodeNetworkSwitch => "cross_network_node_network_switch" @ CrossNetwork / T2Resilience / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    CrossNetworkRelayRemoteExit => "cross_network_relay_remote_exit" @ CrossNetwork / T1Role / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    CrossNetworkFailbackRoaming => "cross_network_failback_roaming" @ CrossNetwork / T2Resilience / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    CrossNetworkControllerSwitch => "cross_network_controller_switch" @ CrossNetwork / T2Resilience / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    CrossNetworkTraversalAdversarial => "cross_network_traversal_adversarial" @ CrossNetwork / T4Security / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    CrossNetworkRemoteExitDns => "cross_network_remote_exit_dns" @ CrossNetwork / T1Role / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    CrossNetworkRemoteExitSoak => "cross_network_remote_exit_soak" @ CrossNetwork / T2Resilience / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    // NAT classification/matrix validate the traversal SUBSTRATE every
    // cross-network capability rests on (not a role, not a disturbance) —
    // core-correctness tier.
    CrossNetworkNatClassification => "cross_network_nat_classification" @ CrossNetwork / T0Core / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    CrossNetworkNatMatrix => "cross_network_nat_matrix" @ CrossNetwork / T0Core / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    // The chaos suite splits by SUBJECT: adversarial-input stages targeting
    // trust/security controls are T4 (spec §3 T4 is "as tagged in the map";
    // chaos_privileged_boundary IS the map's privileged-helper-allowlist
    // member); fault/impairment stages are T2 (spec §3 T2 lists "chaos").
    // Clock rollback vs freshness/anti-replay protection — adversarial.
    ChaosClockAttack => "chaos_clock_attack" @ Chaos / T4Security / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    ChaosCrashRecovery => "chaos_crash_recovery" @ Chaos / T2Resilience / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    ChaosDaemonFault => "chaos_daemon_fault" @ Chaos / T2Resilience / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    ChaosDaemonSigstopSigcont => "chaos_daemon_sigstop_sigcont" @ Chaos / T2Resilience / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    ChaosMembershipAdversarial => "chaos_membership_adversarial" @ Chaos / T4Security / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    ChaosNetworkImpairment => "chaos_network_impairment" @ Chaos / T2Resilience / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    ChaosPrivilegedBoundary => "chaos_privileged_boundary" @ Chaos / T4Security / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    // Resource exhaustion = availability disturbance + recovery, closer to
    // impairment than to a trust-control bypass — resilience tier.
    ChaosResourceExhaustion => "chaos_resource_exhaustion" @ Chaos / T2Resilience / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    ChaosSignedStateAdversarial => "chaos_signed_state_adversarial" @ Chaos / T4Security / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    // T5 negative-control / adjudication suite (spec §3-T5 / §5) — the four
    // injected-fault controls, each of which PASSES iff its targeted operation
    // fails for the specific named reason (the inversion). All T5NegativeControl
    // by definition; opt-in, out of the default plan (like chaos). Impl +
    // adjudication in `stage/negative_control.rs`.
    NegativeControlSignedBundleRejection => "negative_control_signed_bundle_rejection" @ NegativeControl / T5NegativeControl / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    NegativeControlPlantedResidue => "negative_control_planted_residue" @ NegativeControl / T5NegativeControl / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    NegativeControlWrongNodeSubstitution => "negative_control_wrong_node_substitution" @ NegativeControl / T5NegativeControl / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    NegativeControlDaemonKillMidStage => "negative_control_daemon_kill_mid_stage" @ NegativeControl / T5NegativeControl / StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING },
    // Always-run overlay teardown (FinalCleanupStage pattern): vxlan link
    // residue on a guest is release-blocking exactly like exit-NAT residue,
    // so this must survive skip-cascade and run just before cleanup.
    CrossNetworkSubstrateTeardown => "cross_network_substrate_teardown" @ Cleanup / T0Core / StageEvidence::None { reason: TEARDOWN_EVIDENCE_OPT_OUT },
    // Clean teardown, residue-asserted — named in spec §3's T0 list.
    Cleanup => "cleanup" @ Cleanup / T0Core / StageEvidence::None { reason: TEARDOWN_EVIDENCE_OPT_OUT },
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

    /// TRUTH PREREQUISITES: stages that must PASS before this one runs. A
    /// failure or skip of one triggers skip-cascade on this stage (§3.1).
    ///
    /// This is the interim rule for every un-migrated stage: its `dependencies`
    /// are all truth prerequisites (the historical, conservative behaviour). A
    /// migrated scenario stage that needs a predecessor only *ordered* before
    /// it — without gating on its pass — declares that in
    /// [`ordering_after`](Self::ordering_after) instead, never here.
    fn dependencies(&self) -> &[StageId];

    /// ORDERING-ONLY edges: stages this one must run AFTER, purely for
    /// destructive/shared-resource serialisation — it does NOT require them to
    /// pass and is NOT skip-cascaded when one fails (§3.1). An ordering edge to
    /// a stage not in the plan is ignored (rule 3: an omitted ordering
    /// predecessor never becomes an implicit requirement); a stage that cannot
    /// safely run without a predecessor must list it in
    /// [`dependencies`](Self::dependencies) instead. Default: none.
    fn ordering_after(&self) -> &[StageId] {
        &[]
    }

    /// Which roles this stage operates on. Empty slice = all roles.
    fn applies_to_roles(&self) -> &[NodeRole];

    fn fanout(&self) -> StageFanout;

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome;

    /// Teardown stages that MUST run even when an earlier stage failed —
    /// exempt from dependency skip-cascade AND from explicit skips
    /// (`--skip-stage`, the `--rerun-stage` tail) and from the shutdown flag,
    /// so this run's own killswitch / exit-NAT residue is always removed from
    /// the guests (leaving residue is a release-blocker per the operating
    /// contract). The runner checks `always_run` ahead of every skip source
    /// in `skip_decision` (`orchestrator::runner`), so a skip source added
    /// later cannot reintroduce the residue fail-open. Default `false`.
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
    format_stage_binary_failure_with_log(label, status, stdout, stderr, None)
}

/// As [`format_stage_binary_failure`], but names the binary's own complete log so a
/// clipped summary cannot be misread as lost evidence.
///
/// The clip disclosure on its own is a **false signal**. These stages pass
/// `--log-path`, and the binary writes its full unclipped output there, so
/// "clipped N of M bytes" describes the *inline copy* only — nothing is actually
/// lost. On 2026-07-25 that line was read as evidence destruction twice in one day,
/// once in a disposition ledger, while a complete 13.5 KB log sat beside it in the
/// same report directory. Naming the artifact removes the ambiguity for free.
/// The truncation behaviour itself is deliberate (see `clip`) and unchanged.
pub(crate) fn format_stage_binary_failure_with_log(
    label: &str,
    status: std::process::ExitStatus,
    stdout: &[u8],
    stderr: &[u8],
    full_log: Option<&str>,
) -> String {
    /// Keep the **tail**, not the head.
    ///
    /// A failing CLI dumps its whole usage text (11.5 KB) and prints the actual
    /// error last, so clipping the head yields a screenful of help and hides
    /// the one line worth reading — which is exactly what happened on the first
    /// run of this formatter. The existing enforce_runtime reporter already
    /// says "(stdout tail)" for the same reason.
    fn clip(raw: &[u8], full_log: Option<&str>) -> String {
        let text = String::from_utf8_lossy(raw);
        let text = text.trim();
        let total = text.chars().count();
        if total <= STAGE_FAILURE_STREAM_BUDGET {
            return text.to_owned();
        }
        let skip = total - STAGE_FAILURE_STREAM_BUDGET;
        let tail: String = text.chars().skip(skip).collect();
        let pointer = match full_log {
            Some(path) => format!("; complete unclipped output: {path}"),
            None => String::new(),
        };
        format!(
            "…(clipped {} of {} bytes; tail follows{pointer})\n{tail}",
            raw.len().saturating_sub(tail.len()),
            raw.len()
        )
    }
    let out = clip(stdout, full_log);
    let err = clip(stderr, full_log);
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
    fn a_clipped_summary_names_the_complete_log_so_it_is_not_read_as_evidence_loss() {
        let mut noisy = vec![b'x'; STAGE_FAILURE_STREAM_BUDGET * 2];
        noisy.extend_from_slice(b"THE ACTUAL ERROR");
        let summary = format_stage_binary_failure_with_log(
            "live_two_hop",
            exit_status_failure(),
            &noisy,
            b"",
            Some("/report/live_two_hop.log"),
        );
        assert!(
            summary.contains("clipped"),
            "clipping stays disclosed: {summary}"
        );
        assert!(
            summary.contains("/report/live_two_hop.log"),
            "a clipped summary must name the unclipped log, or the disclosure reads as \
             evidence loss when a complete copy sits beside it: {summary}"
        );
        // With no log to point at, the disclosure is unchanged.
        let plain = format_stage_binary_failure("live_two_hop", exit_status_failure(), &noisy, b"");
        assert!(plain.contains("clipped"), "{plain}");
        assert!(!plain.contains("complete unclipped output"), "{plain}");
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
