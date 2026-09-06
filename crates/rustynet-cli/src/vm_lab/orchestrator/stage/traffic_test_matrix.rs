#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{StageOutcome, TrafficTestResult};
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct TrafficTestMatrixStage;

impl OrchestrationStage for TrafficTestMatrixStage {
    fn id(&self) -> StageId {
        StageId::TrafficTestMatrix
    }
    fn name(&self) -> &str {
        "traffic_test_matrix"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::ValidateBaselineRuntime]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();

        // Always re-collect mesh IPs fresh here.  The values cached during
        // collect_pubkeys were gathered before bundle distribution and
        // enforce_runtime, so daemons had auto_tunnel_enforce=false and the
        // WireGuard interface IP was not yet set to the deterministic
        // assignment.  After enforce_runtime the daemon applies the assignment
        // bundle and sets the correct unique IP.
        //
        // Retry for up to 60 s to allow the WireGuard interface to settle and
        // to detect IP collisions (duplicate IPs across nodes indicate the
        // assignment bundle has not yet been applied).
        {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            loop {
                let mut fresh: std::collections::HashMap<String, String> =
                    std::collections::HashMap::new();
                let mut any_error = false;
                for alias in &aliases {
                    match ctx
                        .adapters
                        .get(alias.as_str())
                        .map(|a| a.collect_mesh_ip())
                    {
                        Some(Ok(ip)) => {
                            fresh.insert(alias.clone(), ip);
                        }
                        _ => {
                            any_error = true;
                        }
                    }
                }
                // Collision: two different aliases mapped to the same IP means
                // the assignment bundle has not yet updated the interface.
                let unique_count: std::collections::HashSet<String> =
                    fresh.values().cloned().collect();
                let has_collision = unique_count.len() < fresh.len();
                let has_missing = any_error || fresh.len() < aliases.len();
                // Accept results or keep retrying until deadline.
                if (!has_collision && !has_missing) || std::time::Instant::now() >= deadline {
                    // Replace stale cached entries with fresh data.  Stale
                    // collect_pubkeys entries (pre-enforce IP values) must not
                    // survive into the traffic test; clear the map first so any
                    // node that failed collection here does not retain a stale IP.
                    ctx.mesh_ips.clear();
                    for (alias, ip) in fresh {
                        ctx.mesh_ips.insert(alias, ip);
                    }
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
        }

        if ctx.mesh_ips.is_empty() {
            return StageOutcome::Failed(
                "no mesh IPs available; cannot run traffic tests".to_owned(),
            );
        }

        let mesh_ips = ctx.mesh_ips.clone();
        let mut errors = Vec::new();

        // WireGuard handshakes complete asynchronously after the daemon applies the
        // assignment bundle.  The IP collection loop above exits as soon as IPs are
        // stable, which may be before the first handshake completes.  Retry each
        // positive ping for up to PING_SETTLE_SECS so a slow-starting handshake does
        // not produce a false failure.
        const PING_SETTLE_SECS: u64 = 30;
        const PING_RETRY_INTERVAL_SECS: u64 = 2;

        let progress_log = ctx.report_dir.join("logs/traffic_test_matrix_progress.log");
        let _ = std::fs::create_dir_all(progress_log.parent().unwrap());

        for src_alias in &aliases {
            eprintln!(
                "traffic_test_matrix: probing peer-pairs from {src_alias} ({}/{} nodes)",
                aliases.iter().position(|a| a == src_alias).unwrap_or(0) + 1,
                aliases.len(),
            );
            let _ = std::fs::write(&progress_log, format!("{src_alias}: probing peer-pairs\n"));
            // Tracks whether this src demonstrated baseline mesh reachability
            // (reached at least one peer). The default-deny negative test below
            // is only meaningful once we know the data path works: otherwise a
            // ping that "fails" to the denied IP could simply mean the interface
            // is down, and crediting that as "blocked" would fake-pass the
            // security control. No baseline → the negative result is inconclusive
            // and must fail closed, not silently pass.
            let mut src_reached_peer = false;
            // Positive tests: ping each peer (with retry to allow handshake settle)
            for peer_alias in &aliases {
                if peer_alias == src_alias {
                    continue;
                }
                let peer_ip = match mesh_ips.get(peer_alias) {
                    Some(ip) => ip.clone(),
                    None => {
                        errors.push(format!("{src_alias}: no mesh IP for '{peer_alias}'"));
                        continue;
                    }
                };
                let ping_deadline =
                    std::time::Instant::now() + std::time::Duration::from_secs(PING_SETTLE_SECS);
                let final_result = loop {
                    let result = ctx
                        .adapters
                        .get(src_alias.as_str())
                        .map(|a| a.ping_mesh_peer(&peer_ip));
                    match &result {
                        Some(Ok(TrafficTestResult::Reachable)) => break result,
                        _ => {
                            if std::time::Instant::now() >= ping_deadline {
                                break result;
                            }
                            std::thread::sleep(std::time::Duration::from_secs(
                                PING_RETRY_INTERVAL_SECS,
                            ));
                        }
                    }
                };
                match final_result {
                    Some(Ok(TrafficTestResult::Reachable)) => {
                        src_reached_peer = true;
                    }
                    Some(Ok(TrafficTestResult::Blocked)) => {
                        errors.push(format!(
                            "{src_alias} → {peer_alias} ({peer_ip}): blocked (expected reachable)"
                        ));
                    }
                    Some(Ok(TrafficTestResult::Error(e))) => {
                        errors.push(format!("{src_alias} → {peer_alias} ({peer_ip}): {e}"));
                    }
                    Some(Err(e)) => errors.push(format!("{src_alias} → {peer_alias}: {e}")),
                    None => errors.push(format!("no adapter for '{src_alias}'")),
                }
            }

            // Negative test: confirm default-deny.
            // TEST-NET-2 (RFC 5737) — never routable in real meshes.
            //
            // Security posture: this verifies a default-deny ACL, so it must
            // fail CLOSED. A "blocked" result only counts as a pass when the
            // node has proven baseline mesh reachability above — otherwise an
            // unreachable denied IP is indistinguishable from a dead data path
            // and crediting it would fake-pass the control. A probe Error is
            // likewise inconclusive, not a pass.
            let denied_ip = "198.51.100.1";
            match ctx
                .adapters
                .get(src_alias.as_str())
                .map(|a| a.probe_denied_peer(denied_ip))
            {
                Some(Ok(TrafficTestResult::Blocked)) => {
                    if !src_reached_peer {
                        errors.push(format!(
                            "{src_alias}: default-deny INCONCLUSIVE — {denied_ip} was unreachable \
                             but the node reached no mesh peer, so the block cannot be attributed \
                             to policy (failing closed)"
                        ));
                    }
                }
                Some(Ok(TrafficTestResult::Reachable)) => {
                    errors.push(format!(
                        "{src_alias}: default-deny VIOLATED — {denied_ip} was reachable"
                    ));
                }
                Some(Ok(TrafficTestResult::Error(e))) => {
                    errors.push(format!(
                        "{src_alias}: default-deny INCONCLUSIVE — probe to {denied_ip} errored \
                         ({e}); cannot confirm the target is blocked by policy (failing closed)"
                    ));
                }
                Some(Err(e)) => errors.push(format!("{src_alias}: probe_denied_peer error: {e}")),
                None => errors.push(format!(
                    "{src_alias}: no adapter; cannot run default-deny negative test (failing closed)"
                )),
            }
        }

        if errors.is_empty() {
            StageOutcome::Passed
        } else {
            // Failure-time tunnel capture (MacosCrossNetworkTrafficBlocker
            // §6 item 3): the matrix already failed, so snapshot every
            // node's tunnel/daemon state before returning. Best effort —
            // capture errors are recorded in the per-node capture file and
            // never mask the stage failure that triggered the capture.
            let mut message = errors.join("; ");
            for summary in capture_failure_state(ctx) {
                message.push_str("; ");
                message.push_str(&summary);
            }
            StageOutcome::Failed(message)
        }
    }
}

/// Snapshot per-node tunnel state at failure time so a blocked-mesh failure
/// can be triaged from the report directory without re-running the lab.
///
/// For every topology node with an adapter, collect the mesh IP, the active
/// tunnel list (which carries per-peer latest-handshake lines on kernel-wg
/// backends), and the daemon failure reason, then write them to
/// `logs/traffic_test_matrix.failure_capture.<alias>.txt` under the report
/// dir. Each collector error is recorded inside that file as a
/// `capture error: ...` line — capture is diagnostic only and must never
/// change the stage outcome. Returns one summary line per node for the stage
/// failure message.
fn capture_failure_state(ctx: &OrchestrationContext) -> Vec<String> {
    let mut summaries = Vec::new();
    let logs_dir = ctx.report_dir.join("logs");
    if let Err(e) = std::fs::create_dir_all(&logs_dir) {
        eprintln!("traffic_test_matrix: failure-capture cannot create logs dir: {e}");
        return summaries;
    }
    for assignment in &ctx.assignments {
        let alias = assignment.alias.as_str();
        let Some(adapter) = ctx.adapters.get(alias) else {
            continue;
        };
        let mesh_ip = adapter.collect_mesh_ip();
        let tunnels = adapter.collect_active_tunnels();
        let daemon_reason = adapter.collect_daemon_failure_reason();
        let mut out = String::new();
        out.push_str("# traffic_test_matrix failure capture\n");
        out.push_str(&format!("node: {alias}\n"));
        match &mesh_ip {
            Ok(ip) => out.push_str(&format!("mesh_ip: {ip}\n")),
            Err(e) => out.push_str(&format!("capture error: collect_mesh_ip: {e}\n")),
        }
        match &tunnels {
            Ok(list) => {
                out.push_str(&format!("tunnels: {} line(s)\n", list.tunnels.len()));
                for line in &list.tunnels {
                    out.push_str(&format!("tunnel: {line}\n"));
                }
            }
            Err(e) => out.push_str(&format!("capture error: collect_active_tunnels: {e}\n")),
        }
        match &daemon_reason {
            Ok(Some(reason)) => out.push_str(&format!("daemon_failure_reason: {reason}\n")),
            Ok(None) => out.push_str("daemon_failure_reason: (none reported)\n"),
            Err(e) => {
                out.push_str(&format!(
                    "capture error: collect_daemon_failure_reason: {e}\n"
                ));
            }
        }
        let capture_path =
            logs_dir.join(format!("traffic_test_matrix.failure_capture.{alias}.txt"));
        if let Err(e) = std::fs::write(&capture_path, &out) {
            eprintln!("traffic_test_matrix: failure-capture write failed for {alias}: {e}");
        }
        let daemon_summary = match &daemon_reason {
            Ok(Some(_)) => "reported",
            Ok(None) => "none",
            Err(_) => "error",
        };
        let tunnel_lines = tunnels.as_ref().map(|l| l.tunnels.len()).unwrap_or(0);
        summaries.push(format!(
            "[failure-capture {alias}: {tunnel_lines} tunnel line(s), daemon={daemon_summary}]"
        ));
    }
    summaries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
    use crate::vm_lab::orchestrator::error::{
        AdapterError, BundleKind, GossipIdentity, InstallReport, MembershipOwnerKey,
        MembershipSnapshot, NodeId, NodeMembershipPeer, TunnelsList, ValidatorReport,
        WireguardPublicKey,
    };
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use crate::vm_lab::orchestrator::source_archive::SourceArchive;
    use crate::vm_lab::{DaemonProbeOp, VmGuestPlatform};
    use std::collections::HashMap;
    use std::path::Path;

    #[test]
    fn empty_assignments_no_mesh_ips_fails() {
        let mut ctx = OrchestrationContext {
            assignments: vec![],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: std::env::temp_dir(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            reflexive_endpoints: HashMap::new(),
            lab_stun_servers: Vec::new(),
            linux_backend: None,
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
        };
        // No assignments, no adapters, no mesh IPs → fail
        assert!(matches!(
            TrafficTestMatrixStage.execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
    }

    /// Stub adapter for the failure-capture tests: implements only the
    /// methods the traffic matrix touches on its failure path. A single-node
    /// topology means the peer-ping loop is skipped, and
    /// `probe_denied_peer` returning Blocked with no baseline reachability
    /// fails closed as INCONCLUSIVE fast (no retry-loop sleeps).
    #[derive(Debug)]
    struct FakeCaptureAdapter {
        fail_collectors: bool,
    }

    impl NodeAdapter for FakeCaptureAdapter {
        fn platform(&self) -> VmGuestPlatform {
            VmGuestPlatform::Linux
        }
        fn alias(&self) -> &str {
            "node-a"
        }
        fn ssh_connection_params(
            &self,
        ) -> Option<crate::vm_lab::orchestrator::adapter::node_adapter::SshConnectionParams>
        {
            None
        }
        fn install_daemon(
            &self,
            _source: &SourceArchive,
            _ctx: &OrchestrationContext,
        ) -> Result<InstallReport, AdapterError> {
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
            _op: DaemonProbeOp,
            _extra_args: &[String],
        ) -> Result<ValidatorReport, AdapterError> {
            unimplemented!()
        }
        fn ping_mesh_peer(&self, _peer: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!()
        }
        fn probe_denied_peer(&self, _denied: &str) -> Result<TrafficTestResult, AdapterError> {
            Ok(TrafficTestResult::Blocked)
        }
        fn collect_daemon_failure_reason(&self) -> Result<Option<String>, AdapterError> {
            if self.fail_collectors {
                Err(AdapterError::Ssh {
                    message: "collector down".to_owned(),
                })
            } else {
                Ok(Some("daemon exited: killswitch active".to_owned()))
            }
        }
        fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError> {
            if self.fail_collectors {
                Err(AdapterError::Ssh {
                    message: "collector down".to_owned(),
                })
            } else {
                Ok(TunnelsList {
                    tunnels: vec!["wg0\tpeer-a\tlatest-handshake=1234".to_owned()],
                })
            }
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
            Ok("100.64.0.1".to_owned())
        }
        fn collect_artifacts(&self, _dst: &Path) -> Result<(), AdapterError> {
            unimplemented!()
        }
    }

    fn capture_ctx(report_dir: &Path, fail_collectors: bool) -> OrchestrationContext {
        let mut adapters: HashMap<String, Box<dyn NodeAdapter>> = HashMap::new();
        adapters.insert(
            "node-a".to_owned(),
            Box::new(FakeCaptureAdapter { fail_collectors }),
        );
        OrchestrationContext {
            assignments: vec![NodeRoleAssignment {
                alias: "node-a".to_owned(),
                role: NodeRole::Client,
            }],
            adapters,
            source_archive: None,
            report_dir: report_dir.to_path_buf(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            reflexive_endpoints: HashMap::new(),
            lab_stun_servers: Vec::new(),
            linux_backend: None,
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
        }
    }

    #[test]
    fn failure_capture_writes_per_node_file_on_failed_stage() {
        let report_dir =
            std::env::temp_dir().join(format!("ttm-capture-ok-{}", std::process::id()));
        let mut ctx = capture_ctx(&report_dir, false);
        let message = match TrafficTestMatrixStage.execute(&mut ctx) {
            StageOutcome::Failed(m) => m,
            _ => panic!("expected StageOutcome::Failed"),
        };
        assert!(
            message.contains("[failure-capture node-a: 1 tunnel line(s), daemon=reported]"),
            "message: {message}"
        );
        let capture_path = report_dir.join("logs/traffic_test_matrix.failure_capture.node-a.txt");
        let content = std::fs::read_to_string(&capture_path).expect("capture file written");
        assert!(content.contains("mesh_ip: 100.64.0.1"));
        assert!(content.contains("tunnel: wg0\tpeer-a\tlatest-handshake=1234"));
        assert!(content.contains("daemon_failure_reason: daemon exited: killswitch active"));
        let _ = std::fs::remove_dir_all(&report_dir);
    }

    #[test]
    fn failure_capture_errors_do_not_mask_stage_failure() {
        let report_dir =
            std::env::temp_dir().join(format!("ttm-capture-err-{}", std::process::id()));
        let mut ctx = capture_ctx(&report_dir, true);
        let message = match TrafficTestMatrixStage.execute(&mut ctx) {
            StageOutcome::Failed(m) => m,
            _ => panic!("expected StageOutcome::Failed"),
        };
        assert!(
            message.contains("INCONCLUSIVE"),
            "original stage error masked: {message}"
        );
        assert!(
            message.contains("[failure-capture node-a: 0 tunnel line(s), daemon=error]"),
            "message: {message}"
        );
        let capture_path = report_dir.join("logs/traffic_test_matrix.failure_capture.node-a.txt");
        let content = std::fs::read_to_string(&capture_path).expect("capture file written");
        assert!(content.contains("capture error: collect_active_tunnels"));
        assert!(content.contains("capture error: collect_daemon_failure_reason"));
        let _ = std::fs::remove_dir_all(&report_dir);
    }
}
