#![allow(dead_code)]
use std::time::{Duration, Instant};

use crate::vm_lab::orchestrator::adapter::node_adapter::{NodeAdapter, RoleValidatorKind};
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::mesh_status::{
    LiveHandshakeObservation, evaluate_live_handshake_status, parse_guest_now_unix,
};
use crate::vm_lab::orchestrator::stage::node_diagnostics::{
    PHASE_MESH_STATUS_FAILURE, capture_all_nodes_diagnostics,
};
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const REPORTED_SKIPS_FILENAME: &str = "mesh_status_validation.reported_skips.json";

/// QH-70 live-handshake poll: handshakes complete asynchronously after the
/// membership bundles are enforced, so a first-poll failure would be a flaky
/// failure, and a flaky stage gets ignored. Wait across the deadline (the
/// `gossip_convergence` poll precedent) before calling it a failure.
const LIVE_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(120);
const LIVE_HANDSHAKE_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Prove every Linux node's daemon passes the mesh-status self-check —
/// the daemon's mesh-status view reports no drift (no stale state,
/// expected peer IDs present, within max-age bounds) — folding the
/// formerly bash-only check into the standard Rust orchestrator so a
/// `--node` run exercises it.
///
/// A snapshot pass alone is NOT sufficient (QH-70): after the validator
/// succeeds, the stage polls the node's daemon `status` surface and requires
/// LIVE dataplane evidence — `path_live_peer_count` and
/// `path_programmed_peer_count` non-zero and a latest handshake within the
/// 180 s window whenever the run topology expects peers
/// (`assignments.len() - 1`: full mesh is the run's own contract, since
/// `traffic_test_matrix` pings every pair). `relay_session_*` fields are
/// echoed into failures as evidence but never gate — relay deploy runs two
/// stages later. **A pass therefore means snapshot-valid AND
/// live-handshake-proven**; historical rows that passed on the snapshot alone
/// are not comparable (forward-only ledger boundary).
///
/// Runs after `key_custody_validation` and before the relay/traffic stages.
/// This is a per-node posture check, so it applies to every node regardless
/// of role. Accepted only on an explicit `overall_ok: true` (fail-closed).
/// A macOS / Windows node is **reported-skipped** — named in
/// `mesh_status_validation.reported_skips.json`, never a silent pass — on
/// the [`mesh_status_runtime_implemented`] posture gate.
pub struct MeshStatusValidationStage;

impl OrchestrationStage for MeshStatusValidationStage {
    fn id(&self) -> StageId {
        StageId::MeshStatusValidation
    }
    fn name(&self) -> &str {
        "mesh_status_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::KeyCustodyValidation]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();
        // A topology with no nodes validated NOTHING: a pass here would record
        // a green ledger row for an unexercised control — the vacuous-pass
        // false green (skip-semantics review F1). Skip so the run stays
        // Partial and the gap stays visible; never `Passed`.
        if aliases.is_empty() {
            return StageOutcome::Skipped(
                "no node assignments in this topology; nothing was validated".to_owned(),
            );
        }
        // Every OTHER assigned node must be live: full mesh is the run's own
        // contract (traffic_test_matrix pings every pair). A single-node run
        // expects zero live peers.
        let expected_live_peers = ctx.assignments.len().saturating_sub(1) as u32;

        // AQ-254 (c): underlay attestation. For every node whose inventory
        // entry declares a `dataplane_endpoint`, capture the LIVE WireGuard
        // peer endpoints and fail the stage when any announced endpoint sits
        // on a non-public underlay (tailnet/CGNAT 100.64.0.0/10, RFC1918,
        // loopback, …) — the exact fail-open b72 exposed. An unloadable
        // inventory fails closed; violations join `failures` below; a clean
        // node leaves a per-node evidence line. Nodes WITHOUT a declared
        // override are out of scope and behave exactly as before.
        let underlay = {
            match super::underlay_attestation::attest_inventory_dataplane_nodes(ctx, self.name()) {
                Ok(report) => report,
                Err(e) => {
                    return StageOutcome::Failed(format!(
                        "mesh_status_validation: underlay attestation failed closed: {e}"
                    ));
                }
            }
        };
        let mut failures: Vec<String> = Vec::new();
        for line in &underlay.evidence_lines {
            if let Err(e) =
                append_stage_evidence_line(&ctx.report_dir, "mesh_status_validation", line)
            {
                failures.push(format!("underlay attestation evidence not recorded: {e}"));
            }
        }
        failures.extend(underlay.violations);

        let mut reported_skips: Vec<(String, String)> = Vec::new();
        let mut observations: Vec<LiveHandshakeObservation> = Vec::new();
        for alias in &aliases {
            let adapter = match ctx.adapters.get(alias.as_str()) {
                Some(adapter) => adapter,
                None => {
                    failures.push(format!("{alias}: no adapter for mesh-status node"));
                    continue;
                }
            };
            let platform = adapter.platform();
            if !adapter.supports_role_validator(RoleValidatorKind::MeshStatus) {
                reported_skips.push((alias.clone(), format!("{platform:?}")));
                continue;
            }
            let expected_node_id = ctx.node_ids.get(alias.as_str()).map(String::as_str);
            if let Err(e) =
                adapter.run_role_validator(RoleValidatorKind::MeshStatus, expected_node_id, None)
            {
                failures.push(format!("{alias}: {e}"));
                continue;
            }
            // QH-70: the snapshot passing is necessary but not sufficient —
            // demand live dataplane evidence before this stage may pass.
            match poll_live_handshake(adapter.as_ref(), alias, expected_live_peers) {
                Ok(observation) => observations.push(observation),
                Err(e) => failures.push(e),
            }
        }

        // Record every accepted live-handshake observation as stage evidence
        // (QH-70 follow-up): one JSON line per node in the stage log, so a
        // reader confirms from the artifact alone that the check ran with the
        // non-zero expectation and saw live peers. A write failure fails the
        // stage — evidence that silently went missing must not read as a pass.
        for observation in &observations {
            let line = match serde_json::to_string(observation) {
                Ok(line) => line,
                Err(e) => {
                    failures.push(format!(
                        "{alias_for_observation}: live handshake observation not serializable: {e}",
                        alias_for_observation = observation.alias
                    ));
                    continue;
                }
            };
            if let Err(e) =
                append_stage_evidence_line(&ctx.report_dir, "mesh_status_validation", &line)
            {
                failures.push(format!(
                    "{}: live handshake observation could not be recorded: {e}",
                    observation.alias
                ));
            }
        }

        if !reported_skips.is_empty() {
            write_reported_skips_note(ctx, &reported_skips);
        }
        if !failures.is_empty() {
            // Best-effort network snapshot of every node at failure time; it
            // can never change the verdict.
            capture_all_nodes_diagnostics(ctx, PHASE_MESH_STATUS_FAILURE);
        }
        outcome_for(&failures, &reported_skips)
    }
}

/// Poll the node's daemon status until [`evaluate_live_handshake_status`]
/// passes or the deadline expires; a poll that never got a passing status
/// fails the stage (fail-closed, the existing `failures` path). Every peer
/// other than this node is expected live: `assignments.len() - 1`.
/// Freshness is judged on the GUEST clock the status query reports
/// (`now_unix=<...>`, review F2) — never the orchestrator host clock.
///
/// Returns the accepted [`LiveHandshakeObservation`] (QH-70 follow-up) so the
/// stage can record the per-node evidence; the observation is only produced
/// on acceptance, never on a failed poll.
fn poll_live_handshake(
    adapter: &dyn NodeAdapter,
    alias: &str,
    expected_live_peers: u32,
) -> Result<LiveHandshakeObservation, String> {
    let deadline = Instant::now() + LIVE_HANDSHAKE_DEADLINE;
    loop {
        let attempt = match adapter.collect_daemon_status() {
            Ok(status) => {
                // Review F2: freshness is judged on the GUEST clock the
                // status query itself reports (`now_unix=<...>`), not the
                // orchestrator host clock — host/guest skew (VM
                // pause/resume, NTP drift) must not flake a healthy node.
                // A missing or unparseable emission is an Err and re-enters
                // the retry loop (fail closed).
                match parse_guest_now_unix(&status) {
                    Ok(now_unix) => evaluate_live_handshake_status(
                        alias,
                        &status,
                        expected_live_peers,
                        now_unix,
                    ),
                    Err(err) => Err(format!("{alias}: live handshake: {err}")),
                }
            }
            Err(e) => Err(format!("{alias}: live handshake: {e}")),
        };
        match attempt {
            Ok(observation) => return Ok(observation),
            Err(err) => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "{err} (after {}s)",
                        LIVE_HANDSHAKE_DEADLINE.as_secs()
                    ));
                }
                std::thread::sleep(LIVE_HANDSHAKE_POLL_INTERVAL);
            }
        }
    }
}

fn outcome_for(failures: &[String], reported_skips: &[(String, String)]) -> StageOutcome {
    if !failures.is_empty() {
        StageOutcome::Failed(failures.join("; "))
    } else if !reported_skips.is_empty() {
        StageOutcome::Skipped(format!(
            "no node executed this validation; {} node(s) reported a runtime skip",
            reported_skips.len()
        ))
    } else {
        StageOutcome::Passed
    }
}

fn reported_skips_json_bytes(reported_skips: &[(String, String)]) -> Vec<u8> {
    let skipped: Vec<serde_json::Value> = reported_skips
        .iter()
        .map(|(alias, platform)| serde_json::json!({ "alias": alias, "platform": platform }))
        .collect();
    let body = serde_json::json!({
        "stage": "mesh_status_validation",
        "reported_skipped_mesh_status": skipped,
        "reason": "Mesh-status check runs live on Linux through the Rust engine; \
                   non-Linux nodes are reported-skipped (named, never a silent pass)",
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

fn write_reported_skips_note(ctx: &OrchestrationContext, reported_skips: &[(String, String)]) {
    let path = ctx.report_dir.join(REPORTED_SKIPS_FILENAME);
    let _ = std::fs::write(&path, reported_skips_json_bytes(reported_skips));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::VmGuestPlatform;
    use crate::vm_lab::orchestrator::error::{
        AdapterError, BundleKind, GossipIdentity, InstallReport, MembershipOwnerKey,
        MembershipSnapshot, NodeId, NodeMembershipPeer, TrafficTestResult, TunnelsList,
        ValidatorReport, WireguardPublicKey,
    };
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use crate::vm_lab::orchestrator::source_archive::SourceArchive;
    use std::path::{Path, PathBuf};

    #[test]
    fn outcome_no_failures_no_skips_is_passed() {
        assert_eq!(outcome_for(&[], &[]), StageOutcome::Passed);
    }

    #[test]
    fn outcome_reported_skip_only_is_skipped() {
        assert!(
            matches!(
                outcome_for(&[], &[("mac-1".into(), "Macos".into())]),
                StageOutcome::Skipped(_)
            ),
            "expected a skip; got {:?}",
            outcome_for(&[], &[("mac-1".into(), "Macos".into())])
        );
    }

    #[test]
    fn outcome_failure_is_failed_even_with_skips() {
        assert!(matches!(
            outcome_for(
                &["deb-1: mesh status check failed".into()],
                &[("mac-1".into(), "Macos".into())]
            ),
            StageOutcome::Failed(_)
        ));
    }

    #[test]
    fn reported_skip_note_names_every_skipped_node() {
        let bytes = reported_skips_json_bytes(&[
            ("mac-1".into(), "Macos".into()),
            ("win-1".into(), "Windows".into()),
        ]);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("mac-1") && s.contains("win-1"));
        assert!(s.contains("mesh_status_validation"));
    }

    // ── QH-70 follow-up: recorded live-handshake observation ────────────────

    const POLL_NOW: u64 = 1_700_000_100;

    /// Shape per `rustynetd/src/daemon.rs` IPC `status` line, with the guest
    /// clock emission the poll requires (`now_unix`, review F2).
    const POLL_STATUS: &str = "node_id=deb-1 path_mode=direct \
         path_live_peer_count=2 path_programmed_peer_count=2 \
         path_latest_live_handshake_unix=1700000080 \
         relay_session_state=none relay_session_established_peers=0 \
         gossip_peers_registered=2 gossip_identity_mismatch=false";

    fn poll_status() -> String {
        format!("{POLL_STATUS} now_unix={POLL_NOW}")
    }

    /// Minimal adapter double (same pattern as the `diagnostics` FakeAdapter):
    /// only the calls `poll_live_handshake`/`execute` actually make are
    /// implemented; everything else is `unimplemented!()` so a future change
    /// that starts calling one fails loudly instead of silently taking a
    /// defaulted value.
    #[derive(Debug)]
    struct FakeStatusAdapter;

    impl NodeAdapter for FakeStatusAdapter {
        fn platform(&self) -> VmGuestPlatform {
            VmGuestPlatform::Linux
        }
        fn alias(&self) -> &str {
            "deb-1"
        }
        fn collect_daemon_status(&self) -> Result<String, AdapterError> {
            Ok(poll_status())
        }
        fn run_role_validator(
            &self,
            _kind: RoleValidatorKind,
            _expected_node_id: Option<&str>,
            _expected_dns_posture: Option<&str>,
        ) -> Result<(), AdapterError> {
            // Test double: the snapshot half passes unconditionally here; the
            // live-handshake half under test stays fully exercised.
            Ok(())
        }
        fn collect_artifacts(&self, _dst: &Path) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn start_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn stop_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn restart_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn uninstall_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn issue_membership_owner_key(&self) -> Result<MembershipOwnerKey, AdapterError> {
            unimplemented!()
        }
        fn collect_wireguard_public_key(&self) -> Result<WireguardPublicKey, AdapterError> {
            unimplemented!()
        }
        fn collect_gossip_identity(&self) -> Result<GossipIdentity, AdapterError> {
            unimplemented!()
        }
        fn collect_node_id(&self) -> Result<NodeId, AdapterError> {
            unimplemented!()
        }
        fn run_validator(
            &self,
            _op: crate::vm_lab::DaemonProbeOp,
            _extra_args: &[String],
        ) -> Result<ValidatorReport, AdapterError> {
            unimplemented!()
        }
        fn ping_mesh_peer(&self, _peer: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!()
        }
        fn probe_denied_peer(&self, _denied: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!()
        }
        fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError> {
            unimplemented!()
        }
        fn cleanup_runtime_state(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn check_ssh_reachable(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn endpoint(&self) -> String {
            unimplemented!()
        }
        fn collect_mesh_ip(&self) -> Result<String, AdapterError> {
            unimplemented!()
        }
        fn install_daemon(
            &self,
            _source: &SourceArchive,
            _ctx: &OrchestrationContext,
        ) -> Result<InstallReport, AdapterError> {
            unimplemented!()
        }
        fn init_membership_snapshot(
            &self,
            _owner_key: &MembershipOwnerKey,
            _peers: &[NodeMembershipPeer],
        ) -> Result<MembershipSnapshot, AdapterError> {
            unimplemented!()
        }
        fn distribute_signed_bundle(
            &self,
            _kind: BundleKind,
            _bundle_path: &Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn distribute_verifier_key(
            &self,
            _kind: BundleKind,
            _pub_key_path: &Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn issue_bundles_to_dir(
            &self,
            _kind: BundleKind,
            _env_content: &str,
            _local_out_dir: &Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
    }

    fn temp_report_dir(label: &str) -> PathBuf {
        let unique = crate::vm_lab::unique_suffix();
        let dir = std::env::temp_dir().join(format!("rustynet-meshstatus-{label}-{unique}"));
        std::fs::create_dir_all(&dir).expect("report dir");
        dir
    }

    /// Regression: `poll_live_handshake` must return the observation it
    /// accepted, with the parsed fields — not a bare pass. If the observation
    /// recording is dropped (a revert to `Result<(), String>`), this fails to
    /// compile; if it returns a hollow observation, the assertions fail.
    #[test]
    fn poll_live_handshake_returns_accepted_observation() {
        let adapter = FakeStatusAdapter;
        let obs = poll_live_handshake(&adapter, "deb-1", 2)
            .unwrap_or_else(|err| panic!("fresh live mesh must pass; got: {err}"));
        assert_eq!(obs.alias, "deb-1");
        assert_eq!(obs.path_live_peer_count, 2);
        assert_eq!(obs.expected_live_peers, 2);
        assert_eq!(obs.path_latest_live_handshake_unix, 1_700_000_080);
        assert_eq!(obs.guest_now_unix, POLL_NOW);
        assert_eq!(obs.handshake_age_seconds, 20);
    }

    /// The per-node evidence row must be a self-describing JSON line carrying
    /// every observed field, so a reader confirms the expectation (and the
    /// live evidence behind it) from the artifact alone.
    #[test]
    fn observation_serializes_to_complete_evidence_row() {
        let adapter = FakeStatusAdapter;
        let obs = poll_live_handshake(&adapter, "deb-1", 2)
            .unwrap_or_else(|err| panic!("fresh live mesh must pass; got: {err}"));
        let line = serde_json::to_string(&obs).expect("observation serializes");
        for fragment in [
            "\"alias\":\"deb-1\"",
            "\"path_live_peer_count\":2",
            "\"expected_live_peers\":2",
            "\"path_latest_live_handshake_unix\":1700000080",
            "\"guest_now_unix\":1700000100",
            "\"handshake_age_seconds\":20",
        ] {
            assert!(
                line.contains(fragment),
                "evidence row must contain {fragment}; got: {line}"
            );
        }
    }

    /// End-to-end over the stage: `execute` must write one evidence row per
    /// polled node into the stage log (above the recorder's terminal verdict),
    /// and the stage passes when every node produced its observation.
    #[test]
    fn execute_writes_per_node_observation_rows_to_stage_log() {
        let report_dir = temp_report_dir("rows");
        let mut ctx = OrchestrationContext::new(Vec::new(), report_dir.clone(), "net".to_owned());
        ctx.assignments.push(NodeRoleAssignment {
            alias: "deb-1".to_owned(),
            role: NodeRole::Client,
        });
        ctx.adapters
            .insert("deb-1".to_owned(), Box::new(FakeStatusAdapter));

        let outcome = MeshStatusValidationStage.execute(&mut ctx);

        assert_eq!(outcome, StageOutcome::Passed);
        let log = std::fs::read_to_string(report_dir.join("logs/mesh_status_validation.log"))
            .expect("stage log exists");
        assert!(
            log.contains("\"alias\":\"deb-1\"") && log.contains("\"expected_live_peers\":0"),
            "stage log must carry the observation row; got: {log}"
        );
        // A passing stage captures no failure diagnostics.
        assert!(
            !report_dir
                .join("logs/diag_mesh-status-failure_deb-1.txt")
                .exists()
        );
    }

    /// A failing stage snapshots every node's network state (best effort) and
    /// the verdict stays Failed. Mutation caught: dropping the capture call or
    /// letting capture change the outcome.
    #[test]
    fn failure_captures_node_diagnostics_for_every_node() {
        use crate::vm_lab::orchestrator::stage::node_diagnostics::test_support::{
            EventLog, Responder, ShellAdapter, ctx_with_adapters, ok,
        };
        let report_dir = temp_report_dir("diag-on-failure");
        let log: EventLog = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let responder: std::sync::Arc<Responder> = std::sync::Arc::new(|_: &[String]| ok("x\n"));
        // ShellAdapter has no live identity, so the mesh-status validator
        // fails closed at the node-identity challenge.
        let mut ctx = ctx_with_adapters(
            &report_dir,
            vec![
                ShellAdapter::new("deb-1", &log, responder.clone()),
                ShellAdapter::new("deb-2", &log, responder),
            ],
        );
        assert!(matches!(
            MeshStatusValidationStage.execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
        for alias in ["deb-1", "deb-2"] {
            let body = std::fs::read_to_string(
                report_dir.join(format!("logs/diag_mesh-status-failure_{alias}.txt")),
            )
            .expect("diag file per node");
            assert!(body.contains("== nft list ruleset =="), "{body}");
        }
    }

    /// AQ-254 (c) fixtures: a Linux adapter whose `wg show all endpoints`
    /// (via the scripted shell seam) reports the given output, plus a status
    /// line healthy enough for the live-handshake poll.
    struct AttestAdapter {
        log: crate::vm_lab::orchestrator::stage::node_diagnostics::test_support::EventLog,
        responder: std::sync::Arc<
            crate::vm_lab::orchestrator::stage::node_diagnostics::test_support::Responder,
        >,
    }

    impl std::fmt::Debug for AttestAdapter {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("AttestAdapter").finish_non_exhaustive()
        }
    }
    impl NodeAdapter for AttestAdapter {
        fn platform(&self) -> VmGuestPlatform {
            VmGuestPlatform::Linux
        }
        fn alias(&self) -> &str {
            "deb-1"
        }
        fn collect_daemon_status(&self) -> Result<String, AdapterError> {
            Ok(poll_status())
        }
        fn run_role_validator(
            &self,
            _kind: RoleValidatorKind,
            _expected_node_id: Option<&str>,
            _expected_dns_posture: Option<&str>,
        ) -> Result<(), AdapterError> {
            Ok(())
        }
        fn shell_host(
            &self,
        ) -> Result<
            std::sync::Arc<dyn crate::vm_lab::orchestrator::remote_shell::RemoteShellHost>,
            AdapterError,
        > {
            use crate::vm_lab::orchestrator::stage::node_diagnostics::test_support::ScriptedShell;
            Ok(std::sync::Arc::new(ScriptedShell {
                log: std::sync::Arc::clone(&self.log),
                responder: std::sync::Arc::clone(&self.responder),
            }))
        }
        fn collect_artifacts(&self, _dst: &Path) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn start_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn stop_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn restart_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn uninstall_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn issue_membership_owner_key(&self) -> Result<MembershipOwnerKey, AdapterError> {
            unimplemented!()
        }
        fn collect_wireguard_public_key(&self) -> Result<WireguardPublicKey, AdapterError> {
            unimplemented!()
        }
        fn collect_gossip_identity(&self) -> Result<GossipIdentity, AdapterError> {
            unimplemented!()
        }
        fn collect_node_id(&self) -> Result<NodeId, AdapterError> {
            unimplemented!()
        }
        fn run_validator(
            &self,
            _op: crate::vm_lab::DaemonProbeOp,
            _extra_args: &[String],
        ) -> Result<ValidatorReport, AdapterError> {
            unimplemented!()
        }
        fn ping_mesh_peer(&self, _peer: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!()
        }
        fn probe_denied_peer(&self, _denied: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!()
        }
        fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError> {
            unimplemented!()
        }
        fn cleanup_runtime_state(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn check_ssh_reachable(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn endpoint(&self) -> String {
            unimplemented!()
        }
        fn collect_mesh_ip(&self) -> Result<String, AdapterError> {
            unimplemented!()
        }
        fn install_daemon(
            &self,
            _source: &SourceArchive,
            _ctx: &OrchestrationContext,
        ) -> Result<InstallReport, AdapterError> {
            unimplemented!()
        }
        fn init_membership_snapshot(
            &self,
            _owner_key: &MembershipOwnerKey,
            _peers: &[NodeMembershipPeer],
        ) -> Result<MembershipSnapshot, AdapterError> {
            unimplemented!()
        }
        fn distribute_signed_bundle(
            &self,
            _kind: BundleKind,
            _bundle_path: &Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn distribute_verifier_key(
            &self,
            _kind: BundleKind,
            _pub_key_path: &Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn issue_bundles_to_dir(
            &self,
            _kind: BundleKind,
            _env_content: &str,
            _local_out_dir: &Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
    }

    /// Inventory declaring `dataplane_endpoint` for exactly `alias`.
    fn inventory_declaring(dir: &Path, alias: &str, dataplane: &str) -> PathBuf {
        let inventory = dir.join("vm_lab_inventory.json");
        std::fs::write(
            inventory.as_path(),
            format!(
                r#"{{
                  "version": 1,
                  "entries": [
                    {{
                      "alias": "{alias}",
                      "ssh_target": "100.64.15.9",
                      "dataplane_endpoint": "{dataplane}",
                      "platform": "linux"
                    }}
                  ]
                }}"#
            ),
        )
        .expect("write inventory");
        inventory
    }

    fn attest_ctx_with_wg_output(
        report_dir: &Path,
        wg_output: &'static str,
    ) -> (
        OrchestrationContext,
        crate::vm_lab::orchestrator::stage::node_diagnostics::test_support::EventLog,
    ) {
        use crate::vm_lab::orchestrator::stage::node_diagnostics::test_support::{EventLog, ok};
        let log: EventLog = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let responder: std::sync::Arc<
            crate::vm_lab::orchestrator::stage::node_diagnostics::test_support::Responder,
        > = std::sync::Arc::new(move |_: &[String]| ok(wg_output));
        let mut ctx =
            OrchestrationContext::new(Vec::new(), report_dir.to_path_buf(), "net".to_owned());
        ctx.assignments.push(NodeRoleAssignment {
            alias: "deb-1".to_owned(),
            role: NodeRole::Client,
        });
        ctx.adapters.insert(
            "deb-1".to_owned(),
            Box::new(AttestAdapter {
                log: std::sync::Arc::clone(&log),
                responder,
            }),
        );
        (ctx, log)
    }

    /// AQ-254 (c), enforcement: a node whose inventory declares a
    /// `dataplane_endpoint` but whose LIVE WireGuard endpoints announce a
    /// tailnet/CGNAT underlay fails the stage, naming node, peer and endpoint.
    /// On the pre-AQ-254 stage this topology PASSED (the check did not exist),
    /// which is the before/after evidence.
    #[test]
    fn live_tailnet_endpoint_fails_mesh_status_validation() {
        let report_dir = temp_report_dir("attest-tailnet");
        let dir = std::env::temp_dir().join(format!(
            "rustynet-meshstatus-attest-tailnet-inv-{}",
            crate::vm_lab::unique_suffix()
        ));
        std::fs::create_dir_all(&dir).expect("inventory dir");
        let (mut ctx, _log) =
            attest_ctx_with_wg_output(&report_dir, "wg0\tPEERKEYAAAA\t100.100.5.5:51820\n");
        ctx.inventory_path = Some(inventory_declaring(&dir, "deb-1", "203.0.113.7"));

        match MeshStatusValidationStage.execute(&mut ctx) {
            StageOutcome::Failed(message) => {
                for needle in [
                    "deb-1",
                    "PEERKEYAAAA",
                    "100.100.5.5:51820",
                    "not the public internet",
                ] {
                    assert!(message.contains(needle), "must name {needle}: {message}");
                }
            }
            other => panic!("expected Failed (tailnet underlay), got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A declared node whose live endpoints are all public attests clean:
    /// the stage still passes and the stage log carries the per-node
    /// attestation witness line.
    #[test]
    fn live_public_endpoints_pass_and_leave_an_attestation_witness() {
        let report_dir = temp_report_dir("attest-public");
        let dir = std::env::temp_dir().join(format!(
            "rustynet-meshstatus-attest-public-inv-{}",
            crate::vm_lab::unique_suffix()
        ));
        std::fs::create_dir_all(&dir).expect("inventory dir");
        let (mut ctx, _log) =
            attest_ctx_with_wg_output(&report_dir, "wg0\tPEERKEYAAAA\t203.0.113.7:51820\n");
        ctx.inventory_path = Some(inventory_declaring(&dir, "deb-1", "203.0.113.7"));

        assert_eq!(
            MeshStatusValidationStage.execute(&mut ctx),
            StageOutcome::Passed
        );
        let log = std::fs::read_to_string(report_dir.join("logs/mesh_status_validation.log"))
            .expect("stage log exists");
        assert!(
            log.contains("underlay_attestation: node=deb-1") && log.contains("verdict=all_public"),
            "stage log must carry the attestation witness; got: {log}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Out-of-scope discipline: an inventory that declares NO dataplane
    /// endpoint for the node changes nothing — no capture is attempted (the
    /// shell seam is never even called) and the verdict is untouched.
    #[test]
    fn undeclared_node_is_not_captured_and_verdict_is_unchanged() {
        let report_dir = temp_report_dir("attest-undeclared");
        let dir = std::env::temp_dir().join(format!(
            "rustynet-meshstatus-attest-undecl-inv-{}",
            crate::vm_lab::unique_suffix()
        ));
        std::fs::create_dir_all(&dir).expect("inventory dir");
        // Note the adapter still answers wg with a TAILNET endpoint: if the
        // stage wrongly attested an undeclared node, this verdict would flip.
        // (b85 revision of b83's review F3) The inventory entry deliberately
        // declares NO dataplane_endpoint: a mere inventory entry is out of
        // scope. A DECLARED-but-unassigned alias is the opposite case and is
        // reported as a `verdict=not_in_run` evidence line, never a failure
        // (see
        // underlay_attestation::tests::declared_but_unassigned_alias_is_reported_not_failed),
        // so this fixture must not declare one for OTHER-node.
        let (mut ctx, log) =
            attest_ctx_with_wg_output(&report_dir, "wg0\tPEERKEYAAAA\t100.100.5.5:51820\n");
        let inventory = dir.join("vm_lab_inventory.json");
        std::fs::write(
            inventory.as_path(),
            r#"{
              "version": 1,
              "entries": [
                {
                  "alias": "OTHER-node",
                  "ssh_target": "100.64.15.9",
                  "platform": "linux"
                }
              ]
            }"#,
        )
        .expect("write inventory");
        ctx.inventory_path = Some(inventory);

        assert_eq!(
            MeshStatusValidationStage.execute(&mut ctx),
            StageOutcome::Passed
        );
        let events = log.lock().expect("event log");
        assert!(
            events.iter().all(|e| !e.contains("wg show")),
            "no underlay capture may run for an undeclared node; got: {events:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The empty-assignments guard must SKIP, never PASS: with zero nodes the
    /// stage validated nothing, and a pass would record a green ledger row for
    /// an unexercised control (skip-semantics review F1's vacuous pass).
    /// Mutation caught: reverting the guard arm to `return StageOutcome::Passed;`
    /// (the empty-assignments-vacuous-pass mutation).
    #[test]
    fn empty_assignments_is_skipped_never_passed() {
        let mut ctx = OrchestrationContext::new(
            Vec::new(),
            temp_report_dir("empty-assignments"),
            "net".to_owned(),
        );
        assert!(
            matches!(
                MeshStatusValidationStage.execute(&mut ctx),
                StageOutcome::Skipped(_)
            ),
            "an empty topology must skip, never pass; got {:?}",
            MeshStatusValidationStage.execute(&mut ctx)
        );
    }
}
