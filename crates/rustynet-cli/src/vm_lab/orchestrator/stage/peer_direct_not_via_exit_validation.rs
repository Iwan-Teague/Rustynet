use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::peer_direct_not_via_exit::{
    CAPTURE_SETTLE_SECS, CAPTURE_WINDOW_SECS, PeerDirectReport, PeerDirectTargets,
    PeerDirectValidationKind, peer_direct_runtime_implemented, run_linux_peer_direct_not_via_exit,
    unused_mesh_probe_addr_for, validation_kind_for,
};
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const REPORTED_SKIPS_FILENAME: &str = "peer_direct_not_via_exit_validation.reported_skips.json";
const VERDICT_FILENAME: &str = "peer_direct_not_via_exit_validation.verdict.json";
const CAPTURES_FILENAME: &str = "peer_direct_not_via_exit_validation.captures.txt";

/// Prove the peer-direct invariant live: with an exit assigned and in use, a
/// client's traffic to ANOTHER mesh node (entry/relay/anchor/admin/aux/extra)
/// flows peer-to-peer and NEVER appears on the exit — while internet-bound
/// control traffic from the same client DOES arrive on the exit's tunnel
/// interface (the positive control that keeps the capture honest).
///
/// Topology premise: an exit assignment AND a client AND at least one other
/// mesh node. A topology without that premise is **skipped with a named
/// reason**; every actual execution fails closed (precondition violations,
/// silent captures, missing probe receipts and any peer packet on the exit
/// are failures, never passes). A macOS / Windows node is **reported-skipped**
/// — named in `peer_direct_not_via_exit_validation.reported_skips.json`,
/// never a silent pass.
///
/// The product-code twin of this invariant is the route-set guard
/// `enforce_exit_default_cannot_shadow_mesh_peers` (rustynetd daemon.rs),
/// enforced at bootstrap and reconcile.
pub struct PeerDirectNotViaExitValidationStage;

/// Roles eligible as the PEER side of the proof: any mesh node that is not
/// the client and not the exit. (The exit's own LAN clients and the exit
/// itself are exactly what the exit-family stages already cover.)
const PEER_ELIGIBLE_ROLES: &[NodeRole] = &[
    NodeRole::Entry,
    NodeRole::Relay,
    NodeRole::Anchor,
    NodeRole::Admin,
    NodeRole::Aux,
    NodeRole::Extra,
];

impl OrchestrationStage for PeerDirectNotViaExitValidationStage {
    fn id(&self) -> StageId {
        StageId::PeerDirectNotViaExitValidation
    }
    fn name(&self) -> &str {
        "peer_direct_not_via_exit_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::ActiveExit]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        // Topology-scope proof: spans client, exit and peer in one capture
        // window, so it cannot be scoped to a single role.
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let exit_alias = match ctx.assignments.iter().find(|a| a.role == NodeRole::Exit) {
            Some(assignment) => assignment.alias.clone(),
            None => {
                return StageOutcome::Skipped(
                    "peer-direct: no Exit node in assignments — the premise (an exit-using \
                     client talking to another mesh node) is absent from this topology"
                        .to_owned(),
                );
            }
        };
        let client_alias = match ctx.assignments.iter().find(|a| a.role == NodeRole::Client) {
            Some(assignment) => assignment.alias.clone(),
            None => {
                return StageOutcome::Skipped(
                    "peer-direct: no Client node in assignments — the premise (an exit-using \
                     client talking to another mesh node) is absent from this topology"
                        .to_owned(),
                );
            }
        };
        let peer_alias = match pick_peer_assignment(&ctx.assignments, &exit_alias, &client_alias) {
            Some(alias) => alias,
            None => {
                return StageOutcome::Skipped(
                    "peer-direct: no other mesh node (entry/relay/anchor/admin/aux/extra) in \
                     this topology — there is no peer to prove direct delivery to"
                        .to_owned(),
                );
            }
        };

        // Adapters first: every probe/capture shell comes from these, and the
        // platform gate needs them too. A missing adapter is a data-integrity
        // failure, not a skip.
        let client_adapter = match ctx.adapters.get(client_alias.as_str()) {
            Some(adapter) => adapter,
            None => {
                return StageOutcome::Failed(format!(
                    "{client_alias}: no adapter for the peer-direct proof client"
                ));
            }
        };
        let exit_adapter = match ctx.adapters.get(exit_alias.as_str()) {
            Some(adapter) => adapter,
            None => {
                return StageOutcome::Failed(format!(
                    "{exit_alias}: no adapter for the peer-direct proof exit"
                ));
            }
        };
        let peer_adapter = match ctx.adapters.get(peer_alias.as_str()) {
            Some(adapter) => adapter,
            None => {
                return StageOutcome::Failed(format!(
                    "{peer_alias}: no adapter for the peer-direct proof peer"
                ));
            }
        };

        // Mesh addresses come from the orchestrator's collected table; a
        // missing address is a data-integrity failure, not a skip.
        let client_ip = match mesh_ip_for(&ctx.mesh_ips, &client_alias) {
            Ok(ip) => ip,
            Err(e) => return StageOutcome::Failed(format!("peer-direct: {e}")),
        };
        let exit_ip = match mesh_ip_for(&ctx.mesh_ips, &exit_alias) {
            Ok(ip) => ip,
            Err(e) => return StageOutcome::Failed(format!("peer-direct: {e}")),
        };
        let peer_ip = match mesh_ip_for(&ctx.mesh_ips, &peer_alias) {
            Ok(ip) => ip,
            Err(e) => return StageOutcome::Failed(format!("peer-direct: {e}")),
        };

        // Platform gates BEFORE any probe: non-Linux nodes are reported-
        // skipped as a set (named, never a silent pass). All three roles of
        // the proof (client, exit, peer) must run on Linux.
        let reported_skips: Vec<(String, String)> = [
            (&client_alias, client_adapter.platform()),
            (&exit_alias, exit_adapter.platform()),
            (&peer_alias, peer_adapter.platform()),
        ]
        .iter()
        .filter(|(_, platform)| !peer_direct_runtime_implemented(*platform))
        .map(|(alias, platform)| ((*alias).clone(), format!("{platform:?}")))
        .collect();
        if reported_skips_require_skip(&reported_skips) {
            write_reported_skips_note(ctx, &reported_skips);
            return StageOutcome::Skipped(format!(
                "peer-direct validation is not implemented on {} of the proof's nodes \
                 (client/exit/peer must all be Linux): {}",
                reported_skips.len(),
                reported_skips
                    .iter()
                    .map(|(alias, platform)| format!("{alias} ({platform})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        let unused_probe_ip = {
            let mut known: Vec<&str> = ctx.mesh_ips.values().map(|ip| ip.as_str()).collect();
            known.push(client_ip.as_str());
            known.push(exit_ip.as_str());
            known.push(peer_ip.as_str());
            match unused_mesh_probe_addr_for(&known) {
                Some(addr) => addr,
                None => {
                    return StageOutcome::Failed(
                        "peer-direct: no collision-free unused mesh-CIDR address found for the \
                         negative-space probe (failing closed rather than probing a known \
                         address)"
                            .to_owned(),
                    );
                }
            }
        };

        let client_shell = match client_adapter.shell_host() {
            Ok(shell) => shell,
            Err(e) => {
                return StageOutcome::Failed(format!(
                    "{client_alias}: shell host unavailable for the peer-direct probes: {e}"
                ));
            }
        };
        let exit_shell = match exit_adapter.shell_host() {
            Ok(shell) => shell,
            Err(e) => {
                return StageOutcome::Failed(format!(
                    "{exit_alias}: shell host unavailable for the peer-direct exit capture: {e}"
                ));
            }
        };
        let peer_shell = match peer_adapter.shell_host() {
            Ok(shell) => shell,
            Err(e) => {
                return StageOutcome::Failed(format!(
                    "{peer_alias}: shell host unavailable for the peer-direct peer capture: {e}"
                ));
            }
        };

        // Gate/dispatch desync check (mirrors the exit-DNS stage): the gate
        // above accepted Linux, so the dispatch table must serve it — a None
        // here is a bug, and failing closed names it.
        match validation_kind_for(VmGuestPlatform::Linux) {
            Some(PeerDirectValidationKind::Linux) => {}
            None => {
                return StageOutcome::Failed(
                    "peer-direct: runtime gate accepted Linux but no validator dispatches it \
                     (gate/dispatch desync)"
                        .to_owned(),
                );
            }
        }

        let targets = PeerDirectTargets {
            client_alias,
            exit_alias,
            peer_alias,
            client_ip,
            exit_ip,
            peer_ip,
            unused_probe_ip,
        };
        let mut report = match run_linux_peer_direct_not_via_exit(
            client_shell,
            exit_shell,
            peer_shell,
            &targets,
            CAPTURE_WINDOW_SECS,
            CAPTURE_SETTLE_SECS,
        ) {
            Ok(report) => report,
            Err(e) => {
                return StageOutcome::Failed(format!(
                    "{}: peer-direct proof failed: {e}",
                    targets.exit_alias
                ));
            }
        };

        // The verdict + raw captures land on every completed run — pass AND
        // fail. A write failure fails the stage: an unwitnessed verdict must
        // never be recorded.
        if let Err(e) = write_verdict_artifact(&ctx.report_dir, &report) {
            return StageOutcome::Failed(format!("peer-direct verdict write failed: {e}"));
        }
        if let Err(e) = write_captures_artifact(&ctx.report_dir, &report) {
            return StageOutcome::Failed(format!("peer-direct captures write failed: {e}"));
        }

        if report.failures.is_empty() {
            match write_pass_witness(&ctx.report_dir, &report) {
                Ok(()) => StageOutcome::Passed,
                Err(e) => StageOutcome::Failed(format!("peer-direct witness write failed: {e}")),
            }
        } else {
            report.failures.insert(
                0,
                format!(
                    "peer-direct validation FAILED on exit {}:",
                    targets.exit_alias
                ),
            );
            StageOutcome::Failed(report.failures.join(" | "))
        }
    }
}

/// The orchestrator's collected mesh address for one node; a missing entry is
/// a data-integrity failure (the proof cannot run against guessed addresses).
fn mesh_ip_for(
    mesh_ips: &std::collections::HashMap<String, String>,
    alias: &str,
) -> Result<String, String> {
    mesh_ips.get(alias).cloned().ok_or_else(|| {
        format!(
            "{alias}: no mesh address collected — the proof needs the orchestrator's \
                 per-node mesh addresses"
        )
    })
}

/// Deterministic peer pick: PEER_ELIGIBLE_ROLES, sorted by alias, excluding
/// the exit and client aliases. Sorted so the proof targets the same node
/// for a given topology every run.
fn pick_peer_assignment(
    assignments: &[crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment],
    exit_alias: &str,
    client_alias: &str,
) -> Option<String> {
    let mut candidates: Vec<String> = assignments
        .iter()
        .filter(|a| PEER_ELIGIBLE_ROLES.contains(&a.role))
        .map(|a| a.alias.clone())
        .filter(|alias| alias != exit_alias && alias != client_alias)
        .collect();
    candidates.sort();
    candidates.dedup();
    candidates.into_iter().next()
}

fn verdict_json_bytes(report: &PeerDirectReport) -> Result<Vec<u8>, String> {
    let body = serde_json::json!({
        "stage": "peer_direct_not_via_exit_validation",
        "client": {
            "alias": report.targets.client_alias,
            "mesh_ip": report.targets.client_ip,
        },
        "exit": {
            "alias": report.targets.exit_alias,
            "mesh_ip": report.targets.exit_ip,
        },
        "peer": {
            "alias": report.targets.peer_alias,
            "mesh_ip": report.targets.peer_ip,
        },
        "unused_probe_ip": report.targets.unused_probe_ip,
        "control_target": crate::vm_lab::orchestrator::role_validation::peer_direct_not_via_exit::CONTROL_TARGET,
        "exit_capture_filter": report.exit_capture_filter,
        "peer_capture_filter": report.peer_capture_filter,
        "probes": {
            "route_get_control": report.probes.route_get_control_raw,
            "route_get_peer": report.probes.route_get_peer_raw,
            "ping_peer_rc": report.probes.ping_peer_rc,
            "tcp_ok": report.probes.tcp_ok,
            "tcp_reply_len": report.probes.tcp_reply_len,
            "udp_send_rc": report.probes.udp_send_rc,
            "unused_ping_rc": report.probes.unused_ping_rc,
            "control_ping_rc": report.probes.control_ping_rc,
            "listener_facility": report.probes.listener_facility,
            "listener_saw_payload": report.probes.listener_saw_payload,
        },
        "counts": {
            "exit_saw_peer": report.counts.exit_saw_peer,
            "exit_saw_unused": report.counts.exit_saw_unused,
            "exit_saw_control_in_on_tunnel": report.counts.exit_saw_control_in_on_tunnel,
            "peer_icmp_echo_requests": report.counts.peer_icmp_echo_requests,
            "peer_tcp_probe_packets": report.counts.peer_tcp_probe_packets,
            "peer_udp_probe_packets": report.counts.peer_udp_probe_packets,
        },
        "peer_direct": report.failures.is_empty(),
        "failures": report.failures,
        "observations": report.observations,
        "exit_capture_stdout": report.exit_capture,
        "peer_capture_stdout": report.peer_capture,
        "listener_stdout": report.listener_stdout,
    });
    serde_json::to_vec_pretty(&body).map_err(|err| format!("serialize verdict failed: {err}"))
}

fn write_verdict_artifact(
    report_dir: &std::path::Path,
    report: &PeerDirectReport,
) -> Result<(), String> {
    let path = report_dir.join(VERDICT_FILENAME);
    let bytes = verdict_json_bytes(report)?;
    std::fs::write(&path, bytes).map_err(|err| format!("write {} failed: {err}", path.display()))
}

fn write_captures_artifact(
    report_dir: &std::path::Path,
    report: &PeerDirectReport,
) -> Result<(), String> {
    let path = report_dir.join(CAPTURES_FILENAME);
    let body = format!(
        "== exit capture (filter: {}) ==\n{}\n== peer capture (filter: {}) ==\n{}\n== peer listener stdout ==\n{}\n",
        report.exit_capture_filter,
        report.exit_capture,
        report.peer_capture_filter,
        report.peer_capture,
        report.listener_stdout,
    );
    std::fs::write(&path, body.as_bytes())
        .map_err(|err| format!("write {} failed: {err}", path.display()))
}

/// QH-83 pass witness: names all three nodes, their addresses and the key
/// counts, so a bare PASS can never be recorded without the evidence behind
/// it. An unwritable witness fails the stage — fail closed.
fn write_pass_witness(
    report_dir: &std::path::Path,
    report: &PeerDirectReport,
) -> Result<(), String> {
    append_stage_evidence_line(
        report_dir,
        StageId::PeerDirectNotViaExitValidation.as_str(),
        &format!(
            "peer_direct=not_via_exit client={}-{} exit={}-{} peer={}-{} \
             exit_saw_peer={} control_in_on_exit_tunnel={} peer_icmp={} peer_tcp={} peer_udp={}",
            report.targets.client_alias,
            report.targets.client_ip,
            report.targets.exit_alias,
            report.targets.exit_ip,
            report.targets.peer_alias,
            report.targets.peer_ip,
            report.counts.exit_saw_peer,
            report.counts.exit_saw_control_in_on_tunnel,
            report.counts.peer_icmp_echo_requests,
            report.counts.peer_tcp_probe_packets,
            report.counts.peer_udp_probe_packets,
        ),
    )
}

fn reported_skips_json_bytes(reported_skips: &[(String, String)]) -> Vec<u8> {
    let skipped: Vec<serde_json::Value> = reported_skips
        .iter()
        .map(|(alias, platform)| serde_json::json!({ "alias": alias, "platform": platform }))
        .collect();
    let body = serde_json::json!({
        "stage": "peer_direct_not_via_exit_validation",
        "reported_skipped_peer_direct_not_via_exit": skipped,
        "reason": "The peer-direct proof runs live on Linux guests; non-Linux nodes in the \
                   proof's client/exit/peer set are reported-skipped (named, never a silent pass)",
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

fn write_reported_skips_note(ctx: &OrchestrationContext, reported_skips: &[(String, String)]) {
    let path = ctx.report_dir.join(REPORTED_SKIPS_FILENAME);
    let _ = std::fs::write(&path, reported_skips_json_bytes(reported_skips));
}

/// Platform gate: ANY non-Linux node in the proof's client/exit/peer set
/// blocks execution — the proof must be reported-skipped (named), never run
/// partially or silently passed. Extracted as a pure predicate so the
/// gate's existence is unit-pinned (mutation target).
fn reported_skips_require_skip(reported_skips: &[(String, String)]) -> bool {
    !reported_skips.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_is_topology_scoped_once_and_depends_on_active_exit() {
        assert_eq!(PeerDirectNotViaExitValidationStage.applies_to_roles(), &[]);
        assert_eq!(
            PeerDirectNotViaExitValidationStage.fanout(),
            StageFanout::Once
        );
        assert_eq!(
            PeerDirectNotViaExitValidationStage.dependencies(),
            &[StageId::ActiveExit]
        );
        assert_eq!(
            PeerDirectNotViaExitValidationStage.id(),
            StageId::PeerDirectNotViaExitValidation
        );
        assert_eq!(
            PeerDirectNotViaExitValidationStage.name(),
            "peer_direct_not_via_exit_validation"
        );
    }

    fn assignment(
        alias: &str,
        role: NodeRole,
    ) -> crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment {
        crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment {
            alias: alias.to_owned(),
            role,
        }
    }

    #[test]
    fn peer_pick_is_deterministic_and_excludes_exit_and_client() {
        let assignments = vec![
            assignment("win-client-1", NodeRole::Client),
            assignment("lenovo-exit-1", NodeRole::Exit),
            assignment("z-relay-1", NodeRole::Relay),
            assignment("a-entry-1", NodeRole::Entry),
            assignment("mac-standby-1", NodeRole::BlindExit),
        ];
        let picked = pick_peer_assignment(&assignments, "lenovo-exit-1", "win-client-1");
        assert_eq!(
            picked.as_deref(),
            Some("a-entry-1"),
            "sorted first eligible"
        );
        // The exit alias never wins even if a role collides.
        let only_exit = vec![
            assignment("lenovo-exit-1", NodeRole::Exit),
            assignment("lenovo-exit-2", NodeRole::Entry),
        ];
        assert_eq!(
            pick_peer_assignment(&only_exit, "lenovo-exit-1", "win-client-1").as_deref(),
            Some("lenovo-exit-2")
        );
        // A topology with only client+exit has NO peer.
        let pair = vec![
            assignment("win-client-1", NodeRole::Client),
            assignment("lenovo-exit-1", NodeRole::Exit),
        ];
        assert_eq!(
            pick_peer_assignment(&pair, "lenovo-exit-1", "win-client-1"),
            None
        );
        // A CLIENT alias sorting FIRST never wins (role eligibility, not just
        // alias exclusion, keeps client traffic out of the proof's target).
        let client_first = vec![
            assignment("aaa-client-1", NodeRole::Client),
            assignment("lenovo-exit-1", NodeRole::Exit),
            assignment("b-entry-1", NodeRole::Entry),
        ];
        assert_eq!(
            pick_peer_assignment(&client_first, "lenovo-exit-1", "aaa-client-1").as_deref(),
            Some("b-entry-1"),
            "an alias-sorting-first client must never be picked as the peer"
        );
    }

    #[test]
    fn verdict_json_carries_addrs_counts_failures_and_capture_excerpts() {
        let targets = PeerDirectTargets {
            client_alias: "win-client-1".to_owned(),
            exit_alias: "lenovo-exit-1".to_owned(),
            peer_alias: "a-entry-1".to_owned(),
            client_ip: "100.95.199.56".to_owned(),
            exit_ip: "100.123.229.22".to_owned(),
            peer_ip: "100.66.184.214".to_owned(),
            unused_probe_ip: "100.127.255.253".to_owned(),
        };
        let report = PeerDirectReport {
            targets,
            exit_capture_filter: "host 100.66.184.214 or host 192.0.2.1 or host 100.127.255.253"
                .to_owned(),
            peer_capture_filter: "host 100.95.199.56".to_owned(),
            probes: Default::default(),
            counts: Default::default(),
            exit_capture: "15:41:02.113422 rustynet0  In IP 100.95.199.56 > 192.0.2.1: ICMP"
                .to_owned(),
            peer_capture: "15:41:01.900100 rustynet0  In IP 100.95.199.56 > 100.66.184.214: ICMP"
                .to_owned(),
            listener_stdout: "PEER_DIRECT_TCP_RECV: peer-direct-probe".to_owned(),
            failures: vec!["synthetic failure for the test".to_owned()],
            observations: vec!["synthetic observation".to_owned()],
        };
        let bytes = verdict_json_bytes(&report).expect("verdict json");
        let s = String::from_utf8(bytes).expect("utf8");
        for needle in [
            "100.95.199.56",
            "100.123.229.22",
            "100.66.184.214",
            "100.127.255.253",
            "exit_saw_peer",
            "exit_saw_control_in_on_tunnel",
            "synthetic failure for the test",
            "synthetic observation",
            "control_ping_rc",
            "rustynet0  In IP 100.95.199.56",
            "PEER_DIRECT_TCP_RECV",
            "peer_direct_not_via_exit_validation",
        ] {
            assert!(
                s.contains(needle),
                "verdict json must contain {needle}: {s}"
            );
        }
    }

    #[test]
    fn pass_witness_names_all_three_nodes_and_counts() {
        let dir = std::env::temp_dir().join(format!(
            "pdir_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let targets = PeerDirectTargets {
            client_alias: "win-client-1".to_owned(),
            exit_alias: "lenovo-exit-1".to_owned(),
            peer_alias: "a-entry-1".to_owned(),
            client_ip: "100.95.199.56".to_owned(),
            exit_ip: "100.123.229.22".to_owned(),
            peer_ip: "100.66.184.214".to_owned(),
            unused_probe_ip: "100.127.255.253".to_owned(),
        };
        let report = PeerDirectReport {
            targets,
            exit_capture_filter: String::new(),
            peer_capture_filter: String::new(),
            probes: Default::default(),
            counts: crate::vm_lab::orchestrator::role_validation::peer_direct_not_via_exit::PeerDirectCounts {
                exit_saw_peer: 0,
                exit_saw_unused: 0,
                exit_saw_control_in_on_tunnel: 3,
                peer_icmp_echo_requests: 5,
                peer_tcp_probe_packets: 2,
                peer_udp_probe_packets: 1,
            },
            exit_capture: String::new(),
            peer_capture: String::new(),
            listener_stdout: String::new(),
            failures: Vec::new(),
            observations: Vec::new(),
        };
        write_pass_witness(&dir, &report).expect("witness write");
        let log = std::fs::read_to_string(
            crate::vm_lab::orchestrator::evidence::rust_native_stage_log_path(
                &dir,
                StageId::PeerDirectNotViaExitValidation.as_str(),
            ),
        )
        .expect("stage log");
        for needle in [
            "peer_direct=not_via_exit",
            "client=win-client-1-100.95.199.56",
            "exit=lenovo-exit-1-100.123.229.22",
            "peer=a-entry-1-100.66.184.214",
            "exit_saw_peer=0",
            "control_in_on_exit_tunnel=3",
            "peer_icmp=5",
            "peer_tcp=2",
            "peer_udp=1",
        ] {
            assert!(log.contains(needle), "witness must contain {needle}: {log}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn witness_write_failure_is_propagated() {
        let dir = std::env::temp_dir().join(format!(
            "pdir_witness_blocker_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test dir");
        std::fs::write(dir.join("logs"), b"not a directory").expect("blocker file");
        let targets = PeerDirectTargets {
            client_alias: "c".to_owned(),
            exit_alias: "e".to_owned(),
            peer_alias: "p".to_owned(),
            client_ip: "1".to_owned(),
            exit_ip: "2".to_owned(),
            peer_ip: "3".to_owned(),
            unused_probe_ip: "4".to_owned(),
        };
        let report = PeerDirectReport {
            targets,
            exit_capture_filter: String::new(),
            peer_capture_filter: String::new(),
            probes: Default::default(),
            counts: Default::default(),
            exit_capture: String::new(),
            peer_capture: String::new(),
            listener_stdout: String::new(),
            failures: Vec::new(),
            observations: Vec::new(),
        };
        let err = write_pass_witness(&dir, &report)
            .expect_err("witness write must fail when the logs path is a regular file");
        assert!(!err.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reported_skip_note_names_every_skipped_node() {
        let bytes = reported_skips_json_bytes(&[
            ("mac-1".into(), "Macos".into()),
            ("win-1".into(), "Windows".into()),
        ]);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("mac-1") && s.contains("win-1"));
        assert!(s.contains("peer_direct_not_via_exit_validation"));
    }

    /// Mutation caught: gating on `false` (or dropping the reported-skip
    /// branch in execute) would let a non-Linux topology run (and silently
    /// pass) this proof. The gate predicate and the platform knowledge are
    /// both pinned here.
    #[test]
    fn runtime_gate_rejects_every_non_linux_platform() {
        for uncovered in [
            VmGuestPlatform::Macos,
            VmGuestPlatform::Windows,
            VmGuestPlatform::Ios,
            VmGuestPlatform::Android,
        ] {
            assert!(!peer_direct_runtime_implemented(uncovered));
        }
        assert!(peer_direct_runtime_implemented(VmGuestPlatform::Linux));
        assert!(!reported_skips_require_skip(&[]));
        assert!(reported_skips_require_skip(&[(
            "mac-1".to_owned(),
            "Macos".to_owned()
        )]));
    }

    #[test]
    fn peer_eligible_roles_exclude_client_and_exit_roles() {
        assert!(!PEER_ELIGIBLE_ROLES.contains(&NodeRole::Client));
        assert!(!PEER_ELIGIBLE_ROLES.contains(&NodeRole::Exit));
        assert!(!PEER_ELIGIBLE_ROLES.contains(&NodeRole::BlindExit));
        for role in [
            NodeRole::Entry,
            NodeRole::Relay,
            NodeRole::Anchor,
            NodeRole::Admin,
            NodeRole::Aux,
            NodeRole::Extra,
        ] {
            assert!(PEER_ELIGIBLE_ROLES.contains(&role));
        }
    }
}
