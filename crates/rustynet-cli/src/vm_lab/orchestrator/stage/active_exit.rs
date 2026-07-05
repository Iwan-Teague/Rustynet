#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
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

        // macOS Exit maps to the blind_exit role, whose pf NAT is applied at
        // enforce-time (not via route-advertise) and whose pf anchor is
        // hard-locked across cleanup — it does not fit this
        // activate→assert→nat-session shape, so the macOS adapter has no
        // exit-serving override and would hit the trait fail-closed default.
        // Report-skip it (named, never a silent pass) so the run goes Partial
        // instead of a misleading hard-fail; gated on
        // active_exit_runtime_implemented pending the macOS exit-serving adapter.
        let exit_platform = exit_adapter.platform();
        if !active_exit_runtime_implemented(exit_platform) {
            write_reported_skip_note(ctx, &exit_alias, exit_platform);
            return StageOutcome::Skipped;
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
        if let Some(client_alias) = client_alias
            && let Some(client_adapter) = ctx.adapters.get(client_alias.as_str())
        {
            if let Err(e) = client_adapter.drive_exit_egress_probe() {
                return StageOutcome::Failed(format!(
                    "active_exit: driving exit-egress traffic from client '{client_alias}' failed: {e}"
                ));
            }
            if let Err(e) = exit_adapter.assert_mesh_client_nat_session() {
                return StageOutcome::Failed(format!(
                    "active_exit: client '{client_alias}' traffic did not egress via exit '{exit_alias}' NAT: {e}"
                ));
            }
        }

        StageOutcome::Passed
    }
}

/// True where the active-exit-serving dataplane is implemented: Linux (nftables
/// MASQUERADE driven over the daemon control socket) and Windows (WinNAT, whose
/// adapter overrides the exit-serving methods). macOS is NOT implemented here —
/// its blind_exit pf NAT is applied at enforce-time, not via route-advertise —
/// so a macOS Exit is reported-skipped rather than hard-failing the trait
/// default. Gated on this, NOT `is_supported_for_platform`, so promotion follows
/// a live macOS exit-serving run rather than preceding it.
fn active_exit_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(platform, VmGuestPlatform::Linux | VmGuestPlatform::Windows)
}

const REPORTED_SKIP_FILENAME: &str = "active_exit.reported_skips.json";

/// Serialize the reported-skip note as pretty JSON bytes. Pure (no I/O) so a
/// unit test asserts the content without a macOS adapter.
fn reported_skip_json_bytes(alias: &str, platform: VmGuestPlatform) -> Vec<u8> {
    let body = serde_json::json!({
        "stage": "active_exit",
        "reported_skipped_active_exit": [{ "alias": alias, "platform": format!("{platform:?}") }],
        "reason": "active exit-serving is implemented for Linux (nftables MASQUERADE) and Windows \
                   (WinNAT); a macOS Exit maps to the blind_exit role whose pf NAT is applied at \
                   enforce-time (not via route-advertise), so it is reported-skipped here (named, \
                   never a silent pass) pending the macOS exit-serving adapter — gated on \
                   active_exit_runtime_implemented, not is_supported_for_platform",
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

/// Write the reported-skip note to `<report_dir>/active_exit.reported_skips.json`.
/// Best-effort: a write failure does not change the stage outcome.
fn write_reported_skip_note(ctx: &OrchestrationContext, alias: &str, platform: VmGuestPlatform) {
    let path = ctx.report_dir.join(REPORTED_SKIP_FILENAME);
    let _ = std::fs::write(&path, reported_skip_json_bytes(alias, platform));
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

    #[test]
    fn reported_skip_note_names_alias_and_platform() {
        let bytes = reported_skip_json_bytes("macos-utm-1", VmGuestPlatform::Macos);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["stage"], "active_exit");
        assert_eq!(v["reported_skipped_active_exit"][0]["alias"], "macos-utm-1");
        assert_eq!(v["reported_skipped_active_exit"][0]["platform"], "Macos");
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
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
        };
        assert!(matches!(
            ActiveExitStage.execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
    }
}
