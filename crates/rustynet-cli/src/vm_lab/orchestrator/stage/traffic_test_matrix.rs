#![allow(dead_code)]
use std::collections::HashMap;
use std::path::Path;

use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{StageOutcome, TrafficTestResult};
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct TrafficTestMatrixStage;

/// Mesh-IP settle budget for the fresh-collection loop before it accepts
/// whatever it has. Shortened under cfg(test) so the collision-at-deadline
/// test reaches the accept branch in ~1 s instead of sleeping 60 s.
#[cfg(test)]
const MESH_IP_SETTLE_SECS: u64 = 1;
#[cfg(not(test))]
const MESH_IP_SETTLE_SECS: u64 = 60;
#[cfg(test)]
const MESH_IP_RETRY_INTERVAL_SECS: u64 = 0;
#[cfg(not(test))]
const MESH_IP_RETRY_INTERVAL_SECS: u64 = 3;

/// The settle deadline for the fresh mesh-IP collection loop.
fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(MESH_IP_SETTLE_SECS)
}

/// The per-pair results witness backing the traffic-matrix verdict (QH-83
/// `File` declaration on `StageId::TrafficTestMatrix`; H4 collision guard).
const PAIR_RESULTS_RELATIVE: &str = "logs/traffic_test_matrix.pair_results.log";

/// Write the pair-results witness. Called before EVERY return after mesh-IP
/// collection (pass, fail, and collision-fail) so the verdict is never
/// recorded without the on-disk evidence behind it. An unwritable witness is
/// itself a failure: the stage must not pass with the evidence missing.
fn write_pair_results(report_dir: &Path, lines: &[String]) -> Result<(), String> {
    let path = report_dir.join(PAIR_RESULTS_RELATIVE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("create logs dir for pair-results witness: {err}"))?;
    }
    let mut body = lines.join("\n");
    body.push('\n');
    std::fs::write(&path, body)
        .map_err(|err| format!("write pair-results witness {}: {err}", path.display()))
}

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
        let mut evidence: Vec<String> = Vec::new();

        // Always re-collect mesh IPs fresh here.  The values cached during
        // collect_pubkeys were gathered before bundle distribution and
        // enforce_runtime, so daemons had auto_tunnel_enforce=false and the
        // WireGuard interface IP was not yet set to the deterministic
        // assignment.  After enforce_runtime the daemon applies the assignment
        // bundle and sets the correct unique IP.
        //
        // Retry for up to MESH_IP_SETTLE_SECS to allow the WireGuard interface
        // to settle and to detect IP collisions (duplicate IPs across nodes
        // indicate the assignment bundle has not yet been applied).
        //
        // H4: a collision still present AT THE DEADLINE is a failure, not a
        // degraded accept. The pre-guard code accepted the duplicates, after
        // which every "pair" pinged the shared IP — i.e. a node pinging
        // itself — and the matrix passed as a no-op. The guard fails the
        // stage naming the duplicate IP and its aliases instead.
        let collisions: Vec<(String, Vec<String>)> = {
            let settle_deadline = deadline();
            loop {
                let mut fresh: HashMap<String, String> = HashMap::new();
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
                if (!has_collision && !has_missing) || std::time::Instant::now() >= settle_deadline
                {
                    // Group aliases by IP so the collision report can name every
                    // node sharing a duplicate address (computed before `fresh`
                    // moves into the context).
                    let mut ip_aliases: HashMap<String, Vec<String>> = HashMap::new();
                    for (alias, ip) in &fresh {
                        ip_aliases
                            .entry(ip.clone())
                            .or_default()
                            .push(alias.clone());
                    }
                    let mut collisions: Vec<(String, Vec<String>)> = ip_aliases
                        .into_iter()
                        .filter(|(_ip, aliases)| aliases.len() > 1)
                        .collect();
                    collisions.sort();
                    for (_ip, shared) in &mut collisions {
                        shared.sort();
                    }
                    // Replace stale cached entries with fresh data.  Stale
                    // collect_pubkeys entries (pre-enforce IP values) must not
                    // survive into the traffic test; clear the map first so any
                    // node that failed collection here does not retain a stale IP.
                    ctx.mesh_ips.clear();
                    ctx.mesh_ips.extend(fresh);
                    break collisions;
                }
                std::thread::sleep(std::time::Duration::from_secs(MESH_IP_RETRY_INTERVAL_SECS));
            }
        };

        // Witness header + the mesh-IP assignment snapshot behind whatever
        // verdict follows.
        evidence.push("# traffic_test_matrix pair results".to_owned());
        for alias in &aliases {
            match ctx.mesh_ips.get(alias) {
                Some(ip) => evidence.push(format!("node: {alias} mesh_ip: {}", single_line(ip))),
                None => evidence.push(format!("node: {alias} mesh_ip: (missing)")),
            }
        }
        for (ip, shared) in &collisions {
            evidence.push(format!(
                "collision: ip={} aliases={}",
                single_line(ip),
                shared.join(",")
            ));
        }

        if !collisions.is_empty() {
            let detail = collisions
                .iter()
                .map(|(ip, shared)| format!("ip {ip} assigned to {}", shared.join(" and ")))
                .collect::<Vec<_>>()
                .join("; ");
            let message = format!(
                "mesh IP collision at settle deadline: {detail} — the assignment bundle was \
                 not applied distinctly on every node; failing instead of running a self-ping \
                 matrix that would vacuously pass"
            );
            // The witness is written BEFORE the failure return so the verdict
            // carries its evidence even on this path.
            return match write_pair_results(&ctx.report_dir, &evidence) {
                Ok(()) => StageOutcome::Failed(message),
                Err(write_err) => StageOutcome::Failed(format!(
                    "{message}; ALSO failed to write the pair-results witness: {write_err}"
                )),
            };
        }

        if ctx.mesh_ips.is_empty() {
            evidence.push("result: no mesh IPs available".to_owned());
            let message = "no mesh IPs available; cannot run traffic tests".to_owned();
            return match write_pair_results(&ctx.report_dir, &evidence) {
                Ok(()) => StageOutcome::Failed(message),
                Err(write_err) => StageOutcome::Failed(format!(
                    "{message}; ALSO failed to write the pair-results witness: {write_err}"
                )),
            };
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
                        evidence.push(format!(
                            "pair: src={src_alias} dst={peer_alias} ip=(missing) result=no-mesh-ip"
                        ));
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
                        evidence.push(format!(
                            "pair: src={src_alias} dst={peer_alias} ip={peer_ip} result=reachable"
                        ));
                        src_reached_peer = true;
                    }
                    Some(Ok(TrafficTestResult::Blocked)) => {
                        evidence.push(format!(
                            "pair: src={src_alias} dst={peer_alias} ip={peer_ip} result=blocked"
                        ));
                        errors.push(format!(
                            "{src_alias} → {peer_alias} ({peer_ip}): blocked (expected reachable)"
                        ));
                    }
                    Some(Ok(TrafficTestResult::Error(e))) => {
                        evidence.push(format!(
                            "pair: src={src_alias} dst={peer_alias} ip={peer_ip} result=error:{}",
                            single_line(&e)
                        ));
                        errors.push(format!("{src_alias} → {peer_alias} ({peer_ip}): {e}"));
                    }
                    Some(Err(e)) => {
                        evidence.push(format!(
                            "pair: src={src_alias} dst={peer_alias} ip={peer_ip} result=adapter-error:{}",
                            single_line(&e.to_string())
                        ));
                        errors.push(format!("{src_alias} → {peer_alias}: {e}"));
                    }
                    None => {
                        evidence.push(format!(
                            "pair: src={src_alias} dst={peer_alias} ip={peer_ip} result=no-adapter"
                        ));
                        errors.push(format!("no adapter for '{src_alias}'"));
                    }
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
                    if src_reached_peer {
                        evidence.push(format!(
                            "deny_probe: src={src_alias} ip={denied_ip} result=blocked"
                        ));
                    } else {
                        evidence.push(format!(
                            "deny_probe: src={src_alias} ip={denied_ip} result=inconclusive-no-baseline"
                        ));
                        errors.push(format!(
                            "{src_alias}: default-deny INCONCLUSIVE — {denied_ip} was unreachable \
                             but the node reached no mesh peer, so the block cannot be attributed \
                             to policy (failing closed)"
                        ));
                    }
                }
                Some(Ok(TrafficTestResult::Reachable)) => {
                    evidence.push(format!(
                        "deny_probe: src={src_alias} ip={denied_ip} result=reachable (VIOLATION)"
                    ));
                    errors.push(format!(
                        "{src_alias}: default-deny VIOLATED — {denied_ip} was reachable"
                    ));
                }
                Some(Ok(TrafficTestResult::Error(e))) => {
                    evidence.push(format!(
                        "deny_probe: src={src_alias} ip={denied_ip} result=inconclusive-error:{}",
                        single_line(&e)
                    ));
                    errors.push(format!(
                        "{src_alias}: default-deny INCONCLUSIVE — probe to {denied_ip} errored \
                         ({e}); cannot confirm the target is blocked by policy (failing closed)"
                    ));
                }
                Some(Err(e)) => {
                    evidence.push(format!(
                        "deny_probe: src={src_alias} ip={denied_ip} result=adapter-error:{}",
                        single_line(&e.to_string())
                    ));
                    errors.push(format!("{src_alias}: probe_denied_peer error: {e}"));
                }
                None => {
                    evidence.push(format!(
                        "deny_probe: src={src_alias} ip={denied_ip} result=no-adapter"
                    ));
                    errors.push(format!(
                        "{src_alias}: no adapter; cannot run default-deny negative test (failing closed)"
                    ));
                }
            }
        }

        if errors.is_empty() {
            // Pass path: the pair-results witness IS the declared QH-83
            // evidence for this stage, so a failure to write it must not
            // record a pass.
            return match write_pair_results(&ctx.report_dir, &evidence) {
                Ok(()) => StageOutcome::Passed,
                Err(write_err) => StageOutcome::Failed(format!(
                    "pair-results witness could not be written behind the pass: {write_err}"
                )),
            };
        }
        // Failure path: capture still runs, and the witness is written best
        // effort so triage sees the pair data that produced the failure. A
        // witness write failure here is recorded in the message but never
        // masks the stage failure.
        {
            let mut message = errors.join("; ");
            for summary in capture_failure_state(ctx) {
                message.push_str("; ");
                message.push_str(&summary);
            }
            if let Err(write_err) = write_pair_results(&ctx.report_dir, &evidence) {
                message.push_str("; ");
                message.push_str(&format!("pair-results witness write failed: {write_err}"));
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
/// True when `alias` is safe to embed as a filename component of the capture
/// file: no path separators and no parent-directory fragment, so a malformed
/// topology entry cannot make `std::fs::write` escape the report dir.
fn is_safe_capture_alias(alias: &str) -> bool {
    !alias.is_empty() && !alias.contains(['/', '\\']) && !alias.contains("..")
}

/// Collapse newlines and carriage returns so a remote-controlled string (SSH
/// output collected from the node under test) cannot forge additional lines
/// in the evidence file.
fn single_line(s: &str) -> String {
    s.replace(['\n', '\r'], "\\n")
}

fn capture_failure_state(ctx: &OrchestrationContext) -> Vec<String> {
    let mut summaries = Vec::new();
    let logs_dir = ctx.report_dir.join("logs");
    if let Err(e) = std::fs::create_dir_all(&logs_dir) {
        eprintln!("traffic_test_matrix: failure-capture cannot create logs dir: {e}");
        return summaries;
    }
    for assignment in &ctx.assignments {
        let alias = assignment.alias.as_str();
        if !is_safe_capture_alias(alias) {
            // Diagnostic-only capture: skipping an unsafe alias is fail-safe,
            // while writing it would let a topology entry clobber a file
            // outside the report dir.
            eprintln!("traffic_test_matrix: failure-capture skipped unsafe alias {alias:?}");
            continue;
        }
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
            Ok(ip) => out.push_str(&format!("mesh_ip: {}\n", single_line(ip))),
            Err(e) => out.push_str(&format!(
                "capture error: collect_mesh_ip: {}\n",
                single_line(&e.to_string())
            )),
        }
        match &tunnels {
            Ok(list) => {
                out.push_str(&format!("tunnels: {} line(s)\n", list.tunnels.len()));
                for line in &list.tunnels {
                    out.push_str(&format!("tunnel: {}\n", single_line(line)));
                }
            }
            Err(e) => out.push_str(&format!(
                "capture error: collect_active_tunnels: {}\n",
                single_line(&e.to_string())
            )),
        }
        match &daemon_reason {
            Ok(Some(reason)) => {
                out.push_str(&format!("daemon_failure_reason: {}\n", single_line(reason)))
            }
            Ok(None) => out.push_str("daemon_failure_reason: (none reported)\n"),
            Err(e) => {
                out.push_str(&format!(
                    "capture error: collect_daemon_failure_reason: {}\n",
                    single_line(&e.to_string())
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
        // A tunnel-collector error is NOT "no tunnels established": report it
        // distinctly so triage does not misread an unknown state as a
        // blocked-mesh signal.
        let tunnel_summary = match tunnels.as_ref() {
            Ok(list) => format!("{} tunnel line(s)", list.tunnels.len()),
            Err(_) => "tunnels=error".to_string(),
        };
        summaries.push(format!(
            "[failure-capture {alias}: {tunnel_summary}, daemon={daemon_summary}]"
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
            relay_forwarding_validation_elected: false,
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
        alias: &'static str,
        mesh_ip: &'static str,
        /// Factory for `ping_mesh_peer`'s result; `None` keeps the historical
        /// unimplemented!() (single-node tests never ping).
        ping: Option<fn() -> Result<TrafficTestResult, AdapterError>>,
    }

    impl FakeCaptureAdapter {
        /// The historical single-node fixture: alias node-a, mesh IP
        /// 100.64.0.1, ping never called.
        fn single(fail_collectors: bool) -> Self {
            FakeCaptureAdapter {
                fail_collectors,
                alias: "node-a",
                mesh_ip: "100.64.0.1",
                ping: None,
            }
        }
    }

    impl NodeAdapter for FakeCaptureAdapter {
        fn platform(&self) -> VmGuestPlatform {
            VmGuestPlatform::Linux
        }
        fn alias(&self) -> &str {
            self.alias
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
            match self.ping {
                Some(make) => make(),
                None => unimplemented!("ping_mesh_peer not configured for this fixture"),
            }
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
            Ok(self.mesh_ip.to_owned())
        }
        fn collect_artifacts(&self, _dst: &Path) -> Result<(), AdapterError> {
            unimplemented!()
        }
    }

    fn capture_ctx(report_dir: &Path, fail_collectors: bool) -> OrchestrationContext {
        let mut adapters: HashMap<String, Box<dyn NodeAdapter>> = HashMap::new();
        adapters.insert(
            "node-a".to_owned(),
            Box::new(FakeCaptureAdapter::single(fail_collectors)),
        );
        matrix_ctx_from_adapters(
            vec![NodeRoleAssignment {
                alias: "node-a".to_owned(),
                role: NodeRole::Client,
            }],
            adapters,
            report_dir,
        )
    }

    /// Build a context from explicit assignments + adapters so multi-node
    /// matrix tests can express per-node mesh IPs.
    fn matrix_ctx_from_adapters(
        assignments: Vec<NodeRoleAssignment>,
        adapters: HashMap<String, Box<dyn NodeAdapter>>,
        report_dir: &Path,
    ) -> OrchestrationContext {
        OrchestrationContext {
            assignments,
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
            relay_forwarding_validation_elected: false,
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
            message.contains("[failure-capture node-a: tunnels=error, daemon=error]"),
            "message: {message}"
        );
        let capture_path = report_dir.join("logs/traffic_test_matrix.failure_capture.node-a.txt");
        let content = std::fs::read_to_string(&capture_path).expect("capture file written");
        assert!(content.contains("capture error: collect_active_tunnels"));
        assert!(content.contains("capture error: collect_daemon_failure_reason"));
        let _ = std::fs::remove_dir_all(&report_dir);
    }

    #[test]
    fn capture_alias_safety_rejects_path_fragments() {
        assert!(is_safe_capture_alias("node-a"));
        assert!(is_safe_capture_alias("linux.x86_exit.1"));
        // Path separators, parent-directory fragments, and the empty alias
        // must never become filename components of the capture file.
        assert!(!is_safe_capture_alias("../escape"));
        assert!(!is_safe_capture_alias("a/b"));
        assert!(!is_safe_capture_alias("a\\b"));
        assert!(!is_safe_capture_alias(".."));
        assert!(!is_safe_capture_alias(""));
    }

    #[test]
    fn single_line_collapses_newlines_from_remote_output() {
        assert_eq!(single_line("ok"), "ok");
        assert_eq!(
            single_line("forged\nmesh_ip: 100.64.0.1\r\n"),
            "forged\\nmesh_ip: 100.64.0.1\\n\\n"
        );
    }

    // ── H4: collision guard + pair-results witness ────────────────────────────

    /// Mutation caught: reverting the H4 collision guard (accepting duplicate
    /// mesh IPs at the settle deadline) makes this test see the old passing
    /// no-op instead of the failure. Two nodes sharing one mesh IP must fail
    /// the stage naming the duplicate IP and both aliases, with the
    /// pair-results witness written behind the failure.
    #[test]
    fn collision_at_deadline_fails_naming_duplicate() {
        let report_dir = std::env::temp_dir().join(format!("ttm-collision-{}", std::process::id()));
        let mut adapters: HashMap<String, Box<dyn NodeAdapter>> = HashMap::new();
        adapters.insert(
            "node-a".to_owned(),
            Box::new(FakeCaptureAdapter {
                fail_collectors: false,
                alias: "node-a",
                mesh_ip: "100.64.0.9",
                ping: None,
            }),
        );
        adapters.insert(
            "node-b".to_owned(),
            Box::new(FakeCaptureAdapter {
                fail_collectors: false,
                alias: "node-b",
                mesh_ip: "100.64.0.9",
                ping: None,
            }),
        );
        let ctx = matrix_ctx_from_adapters(
            vec![
                NodeRoleAssignment {
                    alias: "node-a".to_owned(),
                    role: NodeRole::Client,
                },
                NodeRoleAssignment {
                    alias: "node-b".to_owned(),
                    role: NodeRole::Client,
                },
            ],
            adapters,
            &report_dir,
        );
        let mut ctx = ctx;
        let message = match TrafficTestMatrixStage.execute(&mut ctx) {
            StageOutcome::Failed(m) => m,
            other => panic!("expected Failed for duplicate mesh IP, got {other:?}"),
        };
        assert!(
            message.contains("mesh IP collision"),
            "message must name the collision: {message}"
        );
        assert!(
            message.contains("100.64.0.9")
                && message.contains("node-a")
                && message.contains("node-b"),
            "message must name the duplicate IP and both aliases: {message}"
        );
        let witness = std::fs::read_to_string(report_dir.join(PAIR_RESULTS_RELATIVE))
            .expect("pair-results witness written on the collision-failure path");
        assert!(witness.contains("node: node-a mesh_ip: 100.64.0.9"));
        assert!(witness.contains("node: node-b mesh_ip: 100.64.0.9"));
        assert!(witness.contains("collision: ip=100.64.0.9 aliases=node-a,node-b"));
        let _ = std::fs::remove_dir_all(&report_dir);
    }

    /// Mutation caught: dropping the witness write on the pass path leaves
    /// the declared QH-83 `File` evidence absent behind a `Passed` verdict
    /// (the runner-level check would also demote it, but this test pins the
    /// stage's own contract). A clean two-node matrix with reachable pairs
    /// passes AND writes the full pair-results witness.
    #[test]
    fn pair_results_witness_written_on_pass() {
        let report_dir =
            std::env::temp_dir().join(format!("ttm-pass-witness-{}", std::process::id()));
        let mut adapters: HashMap<String, Box<dyn NodeAdapter>> = HashMap::new();
        adapters.insert(
            "node-a".to_owned(),
            Box::new(FakeCaptureAdapter {
                fail_collectors: false,
                alias: "node-a",
                mesh_ip: "100.64.0.1",
                ping: Some(|| Ok(TrafficTestResult::Reachable)),
            }),
        );
        adapters.insert(
            "node-b".to_owned(),
            Box::new(FakeCaptureAdapter {
                fail_collectors: false,
                alias: "node-b",
                mesh_ip: "100.64.0.2",
                ping: Some(|| Ok(TrafficTestResult::Reachable)),
            }),
        );
        let ctx = matrix_ctx_from_adapters(
            vec![
                NodeRoleAssignment {
                    alias: "node-a".to_owned(),
                    role: NodeRole::Client,
                },
                NodeRoleAssignment {
                    alias: "node-b".to_owned(),
                    role: NodeRole::Client,
                },
            ],
            adapters,
            &report_dir,
        );
        let mut ctx = ctx;
        match TrafficTestMatrixStage.execute(&mut ctx) {
            StageOutcome::Passed => {}
            other => panic!("expected Passed for a clean two-node matrix, got {other:?}"),
        }
        let witness = std::fs::read_to_string(report_dir.join(PAIR_RESULTS_RELATIVE))
            .expect("pair-results witness written on the pass path");
        assert!(witness.contains("node: node-a mesh_ip: 100.64.0.1"));
        assert!(witness.contains("node: node-b mesh_ip: 100.64.0.2"));
        assert!(witness.contains("pair: src=node-a dst=node-b ip=100.64.0.2 result=reachable"));
        assert!(witness.contains("pair: src=node-b dst=node-a ip=100.64.0.1 result=reachable"));
        assert!(witness.contains("deny_probe: src=node-a ip=198.51.100.1 result=blocked"));
        assert!(witness.contains("deny_probe: src=node-b ip=198.51.100.1 result=blocked"));
        let _ = std::fs::remove_dir_all(&report_dir);
    }
}
