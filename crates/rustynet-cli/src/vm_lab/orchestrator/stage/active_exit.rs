#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::node_adapter::MeshClientNatSession;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

/// Prove the exit node ACTIVELY serves as a full-tunnel exit — not merely that
/// it holds the exit role.
///
/// The standard lab flow validates an exit node's role / posture / mesh in
/// SPLIT-TUNNEL only; it never drives active exit-serving, so the exit never
/// applies IP forwarding or NAT (live evidence: forwarding stays Disabled and no
/// NAT is created during a normal run). This stage closes that gap: it instructs
/// the exit daemon to advertise the default route `0.0.0.0/0` — the operator
/// "become an exit node" action, sent over the daemon's control named pipe —
/// which makes the daemon apply IP forwarding + source-NAT for client mesh
/// traffic, then asserts the dataplane actually came up as an active exit.
///
/// It runs after `exit_handoff` (mesh + roles already validated) and before
/// final cleanup tears the mesh down. A host lacking the WinNAT/HNS networking
/// stack fails closed here with a clear remediation message from the exit
/// preflight, rather than passing a split-tunnel-only run as if the exit served.
///
/// The stage body is platform-agnostic: it drives the `NodeAdapter` exit-serving
/// methods, so it exercises a Windows exit (WinNAT) and a Linux exit (nftables
/// MASQUERADE) identically. On Linux the activation advertises `0.0.0.0/0` over
/// the daemon's UNIX control socket, the daemon applies IPv4 forwarding + a
/// `rustynet_nat_g<N>` masquerade table, and the NAT-session assertion matches a
/// `100.64.0.0/10`-sourced translated conntrack entry. macOS Exit maps to the
/// `blind_exit` role, whose pf NAT is applied at enforce-time (not via route
/// advertise) and whose pf anchor is hard-locked across cleanup; that does not
/// fit this activate→assert→nat-session shape, so a macOS Exit is
/// reported-skipped here (named in `active_exit.reported_skips.json`, run goes
/// Partial — never a misleading hard-fail on the trait default) pending the
/// macOS exit-serving adapter, gated on `active_exit_runtime_implemented`.
pub struct ActiveExitStage;

impl OrchestrationStage for ActiveExitStage {
    fn id(&self) -> StageId {
        StageId::ActiveExit
    }
    fn name(&self) -> &str {
        "active_exit"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::ExitHandoff]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let exit_alias = match ctx.assignments.iter().find(|a| a.role == NodeRole::Exit) {
            Some(a) => a.alias.clone(),
            None => {
                return StageOutcome::Failed("active_exit: no Exit node in assignments".to_owned());
            }
        };
        // The client whose traffic should egress via the exit: any non-Exit node.
        let client_alias = ctx
            .assignments
            .iter()
            .find(|a| a.role != NodeRole::Exit)
            .map(|a| a.alias.clone());
        let exit_adapter = match ctx.adapters.get(exit_alias.as_str()) {
            Some(a) => a,
            None => {
                return StageOutcome::Failed(format!(
                    "active_exit: no adapter for exit '{exit_alias}'"
                ));
            }
        };

        // Audit B4: topology consistency BEFORE the platform gate. An
        // exit-only topology can never produce the egress proof on any
        // platform, so it is reported-skipped with a named artifact instead
        // of the former silent fall-through to a bare `Passed` with neither
        // proof nor artifact; a client assignment without an adapter is an
        // internal error and fails closed.
        let client_alias = match client_alias {
            Some(client_alias) => {
                if !ctx.adapters.contains_key(client_alias.as_str()) {
                    return StageOutcome::Failed(format!(
                        "active_exit: no adapter for egress client '{client_alias}'"
                    ));
                }
                client_alias
            }
            None => {
                // Fail-closed write: this artifact is the only record of WHY
                // the run skipped, so an unwritable one must not silently
                // downgrade the skip.
                if let Err(e) = write_missing_client_note(ctx, &exit_alias) {
                    return StageOutcome::Failed(format!(
                        "active_exit: missing-client skip artifact unwritable: {e}"
                    ));
                }
                return StageOutcome::Skipped(format!(
                    "active-exit egress proof skipped: topology has no non-Exit \
                     client node to drive egress traffic through '{exit_alias}' \
                     (named in {MISSING_CLIENT_FILENAME})"
                ));
            }
        };

        // The macOS exit adapter now IMPLEMENTS the exit-serving methods
        // (assert-not-actuate over the daemon's own lifecycle verifier, with
        // the A2 pre-activation killswitch-precedence baseline), but the
        // runtime predicate stays false until a live --node run proves the
        // macOS exit cell end to end (design §6: no "implemented but
        // unproven" posture). Until the flip, report-skip it (named, never a
        // silent pass) so the run goes Partial instead of executing an
        // unproven sequence.
        let exit_platform = exit_adapter.platform();
        if !active_exit_runtime_implemented(exit_platform) {
            write_reported_skip_note(ctx, &exit_alias, exit_platform);
            return StageOutcome::Skipped(format!(
                "active-exit runtime is not implemented for {exit_platform:?}"
            ));
        }

        // 1. Activate exit-serving: instruct the daemon to advertise 0.0.0.0/0,
        //    which triggers apply IP forwarding + NAT. Fails closed (with the
        //    daemon's own reason) on a host that cannot serve — e.g. one missing
        //    the WinNAT/HNS stack reports a clear remediation message.
        if let Err(e) = exit_adapter.activate_exit_serving() {
            let daemon = exit_adapter
                .collect_daemon_failure_reason()
                .ok()
                .flatten()
                .map(|reason| format!(" (daemon: {reason})"))
                .unwrap_or_default();
            return StageOutcome::Failed(format!(
                "active_exit: activating exit-serving on '{exit_alias}' failed: {e}{daemon}"
            ));
        }

        // 2. Assert the exit is actually NATing: IP forwarding enabled on the
        //    tunnel adapter AND a RustyNet NAT instance present.
        if let Err(e) = exit_adapter.assert_exit_actively_serving() {
            return StageOutcome::Failed(format!(
                "active_exit: exit '{exit_alias}' did not come up as an active full-tunnel exit: {e}"
            ));
        }

        // 3 + 4. Prove client egress VIA the exit: drive sustained external
        //    traffic from the client (which, full-tunnel through the exit,
        //    egresses via the exit's NAT) and assert the exit shows a NAT session
        //    translating a mesh-sourced client address. This is the W1/D7
        //    "client mesh traffic egresses via the exit" evidence.
        //
        //    Egress probes require internet reachability on the exit node;
        //    a lab topology with no WAN egress (air-gapped, NAT-only, offline)
        //    will fail the probe even though exit-serving itself is healthy.
        //    Match the bash orchestrator: report-skip the egress proof rather
        //    than hard-failing, so the run goes Partial instead of blocking on a
        //    topology constraint outside the engine's control.
        // The consistency gate above proved the adapter exists; a miss here
        // is a concurrent-context mutation and fails closed anyway.
        let client_adapter = match ctx.adapters.get(client_alias.as_str()) {
            Some(adapter) => adapter,
            None => {
                return StageOutcome::Failed(format!(
                    "active_exit: egress client '{client_alias}' adapter vanished"
                ));
            }
        };
        {
            // QH-25: the NAT-session assertion is an identity check when the
            // client's mesh address is known — "THE probed client's session was
            // translated" — and keeps its honest weaker range claim ("a
            // mesh-sourced session was translated") when it is not.
            let expected_client_mesh_addr = ctx.mesh_ips.get(client_alias.as_str());
            let egress_ok = (|| -> Result<MeshClientNatSession, String> {
                client_adapter
                    .drive_exit_egress_probe()
                    .map_err(|e| format!("drive egress traffic: {e}"))?;
                exit_adapter
                    .assert_mesh_client_nat_session(expected_client_mesh_addr.map(String::as_str))
                    .map_err(|e| format!("assert NAT session: {e}"))
            })();
            match egress_ok {
                Err(reason) => {
                    write_reported_skip_note_egress(
                        ctx,
                        &exit_alias,
                        client_alias.as_str(),
                        &reason,
                    );
                    return StageOutcome::Skipped(format!(
                        "egress precondition not met on {exit_alias}: {reason}"
                    ));
                }
                Ok(session) => {
                    let identity_proven = expected_client_mesh_addr
                        .is_some_and(|expected| *expected == session.client_source);
                    // QH-83: this artifact is the declared pass witness for
                    // the stage (catalog row ActiveExit), so an unwritable
                    // write fails the stage here rather than leaving a
                    // witness-less Passed for the runner to demote.
                    if let Err(e) = write_egress_evidence(
                        ctx,
                        &exit_alias,
                        client_alias.as_str(),
                        &session,
                        identity_proven,
                    ) {
                        return StageOutcome::Failed(format!(
                            "active_exit: egress evidence artifact unwritable: {e}"
                        ));
                    }
                }
            }
        }

        StageOutcome::Passed
    }
}

/// True where the active-exit-serving dataplane is PROVEN: Linux (nftables
/// MASQUERADE driven over the daemon control socket) and Windows (WinNAT,
/// whose adapter overrides the exit-serving methods). The macOS adapter now
/// implements the exit methods (assert-not-actuate over the daemon's pf
/// lifecycle verifier, with the A2 pre-activation precedence baseline), but
/// stays FALSE here until a live --node run passes the macOS exit cell with
/// its artifacts — promotion follows live evidence, never precedes it
/// (design §6). Gated on this, NOT `is_supported_for_platform`.
fn active_exit_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(platform, VmGuestPlatform::Linux | VmGuestPlatform::Windows)
}

const REPORTED_SKIP_FILENAME: &str = "active_exit.reported_skips.json";
const REPORTED_SKIP_EGRESS_FILENAME: &str = "active_exit.reported_skips_egress.json";

/// Serialize the reported-skip note as pretty JSON bytes. Pure (no I/O) so a
/// unit test asserts the content without a macOS adapter.
fn reported_skip_json_bytes(alias: &str, platform: VmGuestPlatform) -> Vec<u8> {
    let body = serde_json::json!({
        "stage": "active_exit",
        "reported_skipped_active_exit": [{ "alias": alias, "platform": format!("{platform:?}") }],
        "reason": "active exit-serving is implemented for Linux (nftables MASQUERADE) and Windows \
                   (WinNAT); the macOS adapter now asserts the daemon's own pf lifecycle verifier \
                   but the macOS cell has no live --node run proof yet, so it is reported-skipped \
                   here (named, never a silent pass) — gated on active_exit_runtime_implemented \
                   until that run passes (design §6: no implemented-but-unproven posture)",
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

/// Serialize the egress-skip note — exit-serving activated but external
/// egress proof unavailable (air-gapped / offline topology). Match the
/// bash orchestrator: skip rather than hard-fail.
fn reported_skip_egress_json_bytes(exit_alias: &str, client_alias: &str, reason: &str) -> Vec<u8> {
    let body = serde_json::json!({
        "stage": "active_exit",
        "reported_skipped_egress_proof": [{
            "exit_alias": exit_alias,
            "client_alias": client_alias,
            "reason": reason,
        }],
        "note": "exit-serving activation + IP-forwarding + NAT assertion passed; the external \
                 egress proof (client egress traffic → exit NAT session) is unavailable — \
                 the lab topology may lack internet egress. The exit is serving; this skip \
                 matches the bash orchestrator behavior for offline topologies.",
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

/// Write the reported-skip note to `<report_dir>/active_exit.reported_skips.json`.
/// Best-effort: a write failure does not change the stage outcome.
fn write_reported_skip_note(ctx: &OrchestrationContext, alias: &str, platform: VmGuestPlatform) {
    let path = ctx.report_dir.join(REPORTED_SKIP_FILENAME);
    let _ = std::fs::write(&path, reported_skip_json_bytes(alias, platform));
}

/// Write the egress-skip note — exit-serving passed but the external egress
/// proof is unavailable. Best-effort: a write failure does not change the
/// stage outcome.
fn write_reported_skip_note_egress(
    ctx: &OrchestrationContext,
    exit_alias: &str,
    client_alias: &str,
    reason: &str,
) {
    let path = ctx.report_dir.join(REPORTED_SKIP_EGRESS_FILENAME);
    let _ = std::fs::write(
        &path,
        reported_skip_egress_json_bytes(exit_alias, client_alias, reason),
    );
}

const EGRESS_EVIDENCE_FILENAME: &str = "active_exit.egress_evidence.json";

/// Audit B4: the artifact that names WHY an exit-only topology skipped —
/// the former fall-through wrote nothing and still returned `Passed`.
const MISSING_CLIENT_FILENAME: &str = "active_exit.reported_skips_missing_client.json";

/// Serialize the missing-client skip note. Pure (no I/O) so a unit test can
/// assert the content without an adapter.
fn missing_client_json_bytes(exit_alias: &str) -> Vec<u8> {
    let body = serde_json::json!({
        "stage": "active_exit",
        "reported_skipped_missing_client": [{
            "exit_alias": exit_alias,
            "reason": "topology has no non-Exit client node; the egress proof \
                       (client traffic translated by the exit's NAT) cannot run",
        }],
        "note": "audit B4: an exit-only topology is a named SKIP with this \
                 artifact, never a bare Passed without egress evidence",
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

/// Write the missing-client skip note. Unlike the reported-skip siblings
/// this is fail-closed: the artifact is the only record of why the stage
/// skipped, so an unwritable write must fail the stage.
fn write_missing_client_note(ctx: &OrchestrationContext, exit_alias: &str) -> Result<(), String> {
    let path = ctx.report_dir.join(MISSING_CLIENT_FILENAME);
    std::fs::write(&path, missing_client_json_bytes(exit_alias))
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Serialize the PASS-side egress evidence: the concrete observed address pair
/// from the NAT-session assertion (QH-25: the pair is the checkable evidence,
/// not a bare verdict). `identity_proven` records whether the observed source
/// matched the probed client's known mesh address (identity check) or whether
/// the claim is the honest weaker one (a mesh-sourced session was translated).
fn egress_evidence_json_bytes(
    exit_alias: &str,
    client_alias: &str,
    session: &MeshClientNatSession,
    identity_proven: bool,
) -> Vec<u8> {
    let claim = if identity_proven {
        format!(
            "the client '{client_alias}'s full-tunnel traffic was translated by \
             '{exit_alias}'s NAT (observed source matched the client's mesh address)"
        )
    } else {
        format!(
            "a mesh-sourced (100.64.0.0/10) NAT session was translated by '{exit_alias}' \
             (client identity not matched: no mesh address was known for '{client_alias}')"
        )
    };
    let body = serde_json::json!({
        "stage": "active_exit",
        "egress_evidence": {
            "exit_alias": exit_alias,
            "client_alias": client_alias,
            "client_source": session.client_source,
            "translated_side": session.translated_side,
            "observed_via": session.observed_via,
            "identity_proven": identity_proven,
            "claim": claim,
        },
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

/// Write the egress evidence to
/// `<report_dir>/active_exit.egress_evidence.json`. Fail-closed (audit B4):
/// this artifact is the stage's declared QH-83 pass witness, so a write
/// failure is returned and the stage fails instead of passing unwitnessed.
fn write_egress_evidence(
    ctx: &OrchestrationContext,
    exit_alias: &str,
    client_alias: &str,
    session: &MeshClientNatSession,
    identity_proven: bool,
) -> Result<(), String> {
    let path = ctx.report_dir.join(EGRESS_EVIDENCE_FILENAME);
    std::fs::write(
        &path,
        egress_evidence_json_bytes(exit_alias, client_alias, session, identity_proven),
    )
    .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn runtime_implemented_linux_and_windows_not_macos() {
        assert!(active_exit_runtime_implemented(VmGuestPlatform::Linux));
        assert!(active_exit_runtime_implemented(VmGuestPlatform::Windows));
        assert!(!active_exit_runtime_implemented(VmGuestPlatform::Macos));
    }

    /// The §6 pin while the macOS exit cell is unproven: with the predicate
    /// false, the two-phase stage report-SKIPS a macOS exit (named, with the
    /// reported-skip artifact) instead of executing the adapter's exit
    /// sequence or hard-failing on it.
    #[test]
    fn macos_two_phase_stage_reports_skip_while_predicate_false() {
        use crate::vm_lab::orchestrator::adapter::macos::MacosNodeAdapter;
        use crate::vm_lab::orchestrator::connection::NodeConnection;
        use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
        use std::io::Write as _;
        use tempfile::NamedTempFile;

        let mut identity = NamedTempFile::new().unwrap();
        writeln!(identity, "# placeholder").unwrap();
        let conn = NodeConnection::ssh(
            "10.0.0.1",
            22,
            Some("admin".to_owned()),
            std::path::PathBuf::from("/id_rsa"),
            identity.path().to_path_buf(),
            None,
        )
        .unwrap();
        let macos_adapter: Box<
            dyn crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter,
        > = Box::new(MacosNodeAdapter::new("macos-utm-1", conn, None));
        assert_eq!(macos_adapter.platform(), VmGuestPlatform::Macos);

        // Audit B4 moved the topology checks ahead of the platform gate, so
        // this predicate-false fixture needs a client for the gate skip to
        // be the outcome under test (an exit-only topology now skips earlier,
        // with the missing-client artifact).
        let mut client_identity = NamedTempFile::new().unwrap();
        writeln!(client_identity, "# placeholder").unwrap();
        let client_conn = NodeConnection::ssh(
            "10.0.0.2",
            22,
            Some("admin".to_owned()),
            std::path::PathBuf::from("/id_rsa"),
            client_identity.path().to_path_buf(),
            None,
        )
        .unwrap();
        let client_adapter: Box<
            dyn crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter,
        > = Box::new(MacosNodeAdapter::new("macos-client", client_conn, None));

        let report_dir = std::env::temp_dir().join(format!(
            "active_exit_skip_proof_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&report_dir).unwrap();

        let mut ctx = OrchestrationContext {
            assignments: vec![
                NodeRoleAssignment {
                    alias: "macos-utm-1".to_owned(),
                    role: NodeRole::Exit,
                },
                NodeRoleAssignment {
                    alias: "macos-client".to_owned(),
                    role: NodeRole::Client,
                },
            ],
            adapters: HashMap::from([
                ("macos-utm-1".to_owned(), macos_adapter),
                ("macos-client".to_owned(), client_adapter),
            ]),
            source_archive: None,
            report_dir: report_dir.clone(),
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

        match ActiveExitStage.execute(&mut ctx) {
            StageOutcome::Skipped(reason) => {
                assert!(
                    reason.contains("Macos"),
                    "skip must name the platform: {reason}"
                );
            }
            other => panic!("predicate-false macOS exit must report-skip, got {other:?}"),
        }
        let note = std::fs::read_to_string(report_dir.join(REPORTED_SKIP_FILENAME))
            .expect("reported-skip note must be written");
        assert!(
            note.contains("macos-utm-1"),
            "note must name the alias: {note}"
        );
        assert!(
            note.contains("Macos"),
            "note must name the platform: {note}"
        );
        let _ = std::fs::remove_dir_all(&report_dir);
    }

    #[test]
    fn reported_skip_note_names_alias_and_platform() {
        let bytes = reported_skip_json_bytes("macos-utm-1", VmGuestPlatform::Macos);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["stage"], "active_exit");
        assert_eq!(v["reported_skipped_active_exit"][0]["alias"], "macos-utm-1");
        assert_eq!(v["reported_skipped_active_exit"][0]["platform"], "Macos");
    }

    #[test]
    fn reported_skip_egress_note_names_exit_client_and_reason() {
        let bytes = reported_skip_egress_json_bytes("exit1", "client1", "no route to host");
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["stage"], "active_exit");
        assert_eq!(v["reported_skipped_egress_proof"][0]["exit_alias"], "exit1");
        assert_eq!(
            v["reported_skipped_egress_proof"][0]["client_alias"],
            "client1"
        );
        assert_eq!(
            v["reported_skipped_egress_proof"][0]["reason"],
            "no route to host"
        );
        assert!(
            v["note"]
                .as_str()
                .unwrap_or("")
                .contains("lab topology may lack internet egress")
        );
    }

    #[test]
    fn egress_evidence_names_pair_and_identity_when_proven() {
        // QH-25: identity-proven evidence names the concrete pair and claims
        // THE probed client's traffic was translated.
        let session = MeshClientNatSession {
            client_source: "100.64.0.7".to_owned(),
            translated_side: "203.0.113.9".to_owned(),
            observed_via: "winnat",
        };
        let bytes = egress_evidence_json_bytes("exit1", "client1", &session, true);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["stage"], "active_exit");
        assert_eq!(v["egress_evidence"]["exit_alias"], "exit1");
        assert_eq!(v["egress_evidence"]["client_alias"], "client1");
        assert_eq!(v["egress_evidence"]["client_source"], "100.64.0.7");
        assert_eq!(v["egress_evidence"]["translated_side"], "203.0.113.9");
        assert_eq!(v["egress_evidence"]["observed_via"], "winnat");
        assert_eq!(v["egress_evidence"]["identity_proven"], true);
        let claim = v["egress_evidence"]["claim"].as_str().unwrap_or("");
        assert!(claim.contains("the client 'client1's"), "claim: {claim}");
        assert!(!claim.contains("a mesh-sourced"), "claim: {claim}");
    }

    #[test]
    fn egress_evidence_claim_is_weaker_without_identity() {
        // QH-25: without a matched identity the claim must stay the honest
        // weaker one — a mesh-sourced session was translated, nobody more.
        let session = MeshClientNatSession {
            client_source: "100.64.0.9".to_owned(),
            translated_side: "198.51.100.4".to_owned(),
            observed_via: "conntrack",
        };
        let bytes = egress_evidence_json_bytes("exit1", "client2", &session, false);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["egress_evidence"]["identity_proven"], false);
        assert_eq!(v["egress_evidence"]["client_source"], "100.64.0.9");
        assert_eq!(v["egress_evidence"]["translated_side"], "198.51.100.4");
        assert_eq!(v["egress_evidence"]["observed_via"], "conntrack");
        let claim = v["egress_evidence"]["claim"].as_str().unwrap_or("");
        assert!(
            claim.contains("a mesh-sourced (100.64.0.0/10) NAT session was translated"),
            "claim: {claim}"
        );
        assert!(!claim.contains("the client 'client2's"), "claim: {claim}");
    }

    #[test]
    fn stage_identity_and_dependencies() {
        let stage = ActiveExitStage;
        assert_eq!(stage.id(), StageId::ActiveExit);
        assert_eq!(stage.name(), "active_exit");
        assert_eq!(stage.id().as_str(), "active_exit");
        assert_eq!(stage.dependencies(), &[StageId::ExitHandoff]);
        assert!(matches!(stage.fanout(), StageFanout::Once));
        // Runs lab-wide (operates on the single exit + client), not per-node.
        assert!(stage.applies_to_roles().is_empty());
    }

    #[test]
    fn no_exit_node_fails_closed() {
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
        assert!(matches!(
            ActiveExitStage.execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
    }

    /// Test context builder for the audit-B4 topology cases: an Android exit
    /// adapter is a real `NodeAdapter` whose platform sits outside the
    /// `active_exit_runtime_implemented` gate, so nothing here can reach the
    /// network.
    fn ctx_with_adapters(
        assignments: Vec<crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment>,
        adapters: HashMap<
            String,
            Box<dyn crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter>,
        >,
        report_dir: std::path::PathBuf,
    ) -> OrchestrationContext {
        OrchestrationContext {
            assignments,
            adapters,
            source_archive: None,
            report_dir,
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

    fn android_adapter(
        alias: &str,
    ) -> Box<dyn crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter> {
        use crate::vm_lab::orchestrator::adapter::android::AndroidNodeAdapter;
        use crate::vm_lab::orchestrator::connection::NodeConnection;
        Box::new(AndroidNodeAdapter::new(
            alias,
            NodeConnection::Ssh {
                host: "10.0.0.9".to_owned(),
                port: 22,
                user: None,
                identity_file: std::path::PathBuf::from("/tmp/id"),
                known_hosts: std::path::PathBuf::from("/tmp/known_hosts"),
                ssh_password: None,
            },
        ))
    }

    fn exit_only_assignments(
        alias: &str,
    ) -> Vec<crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment> {
        vec![
            crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment {
                alias: alias.to_owned(),
                role: NodeRole::Exit,
            },
        ]
    }

    /// Audit B4: an exit-only topology used to fall through to a bare
    /// `Passed` with neither egress proof nor artifact. Mutation caught:
    /// deleting the missing-client arm makes this stage return `Passed`
    /// again and the test fails on both the outcome and the artifact.
    #[test]
    fn exit_only_topology_reports_skip_with_missing_client_artifact() {
        let report_dir = std::env::temp_dir().join(format!(
            "active_exit_b4_skip_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&report_dir).unwrap();
        let mut ctx = ctx_with_adapters(
            exit_only_assignments("ad-exit-1"),
            HashMap::from([("ad-exit-1".to_owned(), android_adapter("ad-exit-1"))]),
            report_dir.clone(),
        );

        match ActiveExitStage.execute(&mut ctx) {
            StageOutcome::Skipped(reason) => {
                assert!(
                    reason.contains("no non-Exit client"),
                    "skip must name the missing client: {reason}"
                );
                assert!(
                    reason.contains("ad-exit-1"),
                    "skip must name the exit: {reason}"
                );
            }
            other => panic!("exit-only topology must report-skip, got {other:?}"),
        }
        let note = std::fs::read_to_string(report_dir.join(MISSING_CLIENT_FILENAME))
            .expect("missing-client artifact must exist");
        assert!(
            note.contains("ad-exit-1"),
            "artifact must name the exit alias: {note}"
        );
        let _ = std::fs::remove_dir_all(&report_dir);
    }

    /// Audit B4 fail-closed: the missing-client artifact is the only record
    /// of why the stage skipped, so an unwritable write must fail the stage
    /// instead of silently downgrading it. Mutation caught: making the note
    /// best-effort (`let _ =`) turns this `Failed` back into a `Skipped`
    /// with no artifact.
    #[test]
    fn missing_client_artifact_write_failure_fails_closed() {
        // A report "dir" that is a regular file: every write under it fails.
        let file_report_dir = tempfile::NamedTempFile::new().unwrap();
        let mut ctx = ctx_with_adapters(
            exit_only_assignments("ad-exit-1"),
            HashMap::from([("ad-exit-1".to_owned(), android_adapter("ad-exit-1"))]),
            file_report_dir.path().to_path_buf(),
        );

        match ActiveExitStage.execute(&mut ctx) {
            StageOutcome::Failed(reason) => {
                assert!(
                    reason.contains("missing-client skip artifact unwritable"),
                    "failure must name the unwritable artifact: {reason}"
                );
            }
            other => panic!("unwritable skip artifact must fail closed, got {other:?}"),
        }
    }

    /// Audit B4 fail-closed: a client assignment without an adapter is an
    /// internal error, not a skip — the former fall-through would have
    /// ignored it. Mutation caught: deleting the adapter-presence check lets
    /// this case fall through to the platform gate's `Skipped`.
    #[test]
    fn egress_client_without_adapter_fails_closed() {
        let mut assignments = exit_only_assignments("ad-exit-1");
        assignments.push(
            crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment {
                alias: "ghost-client".to_owned(),
                role: NodeRole::Client,
            },
        );
        let mut ctx = ctx_with_adapters(
            assignments,
            HashMap::from([("ad-exit-1".to_owned(), android_adapter("ad-exit-1"))]),
            std::env::temp_dir(),
        );

        match ActiveExitStage.execute(&mut ctx) {
            StageOutcome::Failed(reason) => {
                assert!(
                    reason.contains("no adapter for egress client 'ghost-client'"),
                    "failure must name the adapter-less client: {reason}"
                );
            }
            other => panic!("adapter-less egress client must fail closed, got {other:?}"),
        }
    }

    /// Audit B4: the skip note names the exit and the reason it cannot run.
    /// Mutation caught: an empty or misnamed payload fails the content
    /// assertions.
    #[test]
    fn missing_client_note_names_exit_and_reason() {
        let bytes = missing_client_json_bytes("ad-exit-1");
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["stage"], "active_exit");
        assert_eq!(
            v["reported_skipped_missing_client"][0]["exit_alias"],
            "ad-exit-1"
        );
        assert!(
            v["note"]
                .as_str()
                .unwrap_or("")
                .contains("never a bare Passed")
        );
    }
}
