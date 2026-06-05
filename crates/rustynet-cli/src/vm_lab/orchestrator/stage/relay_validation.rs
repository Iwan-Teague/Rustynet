#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::relay::{
    relay_lab_runtime_implemented, validate_relay_lifecycle,
};
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

/// Prove every Relay node ACTIVELY serves the relay datapath + health
/// endpoint and tears them down cleanly — folding the formerly
/// Linux-only `live_linux_relay_test` lifecycle proof into the standard
/// orchestrator so it runs cross-OS (Linux, macOS, Windows).
///
/// For each `Relay`-role node it captures a during-run snapshot
/// (service active + datapath UDP port bound + health TCP port bound +
/// `/healthz` returns `ok`), stops the service, captures an after-stop
/// snapshot asserting the inverse (service inactive, both ports gone,
/// `/healthz` unreachable), then restarts the service so subsequent
/// stages inherit a serving relay. Everything is driven through the
/// adapter's cross-OS [`RemoteShellHost`] seam with argv-only probes.
///
/// It runs after `deploy_relay_service` (which installs the relay verifier
/// key + the `rustynet-relay.service` unit and starts it) and before the
/// traffic matrix. Depending on the deploy stage means a deploy failure
/// skip-cascades here rather than re-surfacing as a confusing
/// "relay role not deployed?" probe failure. A run with no Relay nodes is a
/// skip-noop: the stage passes without touching any host, mirroring the
/// empty-assignment case in `role_switch_matrix`.
///
/// macOS / Windows relay nodes are **reported-skipped** (named in
/// `relay_validation.reported_skips.json`, never a silent pass) on the same
/// [`NodeRole::is_supported_for_platform`] posture gate `deploy_relay_service`
/// uses — so a flag flip on archived cross-OS evidence (Phase 8) lights up
/// deploy and validation together.
pub struct RelayValidationStage;

impl OrchestrationStage for RelayValidationStage {
    fn id(&self) -> StageId {
        StageId::RelayValidation
    }
    fn name(&self) -> &str {
        "relay_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::DeployRelayService]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[NodeRole::Relay]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        // Self-filter for Relay nodes (the runner ignores applies_to_roles).
        let relay_aliases: Vec<String> = ctx
            .assignments
            .iter()
            .filter(|a| a.role == NodeRole::Relay)
            .map(|a| a.alias.clone())
            .collect();

        // No Relay nodes in this lab → nothing to validate. Skip-noop:
        // pass without touching any host, like role_switch_matrix's
        // empty-assignment case.
        if relay_aliases.is_empty() {
            return StageOutcome::Passed;
        }

        let mut failures: Vec<String> = Vec::new();
        // (alias, platform) pairs reported-skipped because relay runtime
        // validation is not yet live-supported on their platform.
        let mut reported_skips: Vec<(String, String)> = Vec::new();
        for alias in &relay_aliases {
            let adapter = match ctx.adapters.get(alias.as_str()) {
                Some(adapter) => adapter,
                None => {
                    failures.push(format!("{alias}: no adapter for relay node"));
                    continue;
                }
            };
            let platform = adapter.platform();
            // Runtime-implemented gate (shared with DeployRelayService): validate
            // the relay only where its deploy adapter ran. Linux + macOS validate
            // live; a relay node on a platform with no relay-deploy adapter
            // (Windows today) is reported-skipped — named, never a silent pass —
            // matching the deploy stage so a relay we intentionally did not
            // deploy is never hard-failed here. Decoupled from
            // is_supported_for_platform: this live validation produces the
            // evidence that promotes it.
            if !relay_lab_runtime_implemented(platform) {
                reported_skips.push((alias.clone(), format!("{platform:?}")));
                continue;
            }
            let shell = match adapter.shell_host() {
                Ok(shell) => shell,
                Err(e) => {
                    failures.push(format!("{alias}: shell host unavailable: {e}"));
                    continue;
                }
            };
            if let Err(e) = validate_relay_lifecycle(&*shell, platform) {
                failures.push(format!("{alias}: {e}"));
            }
        }

        // Record the reported skips as evidence (best-effort write); not
        // failures, but they MUST be named on disk so a macOS/Windows relay
        // node is never silently treated as validated.
        if !reported_skips.is_empty() {
            write_reported_skips_note(ctx, &reported_skips);
        }

        if failures.is_empty() {
            StageOutcome::Passed
        } else {
            StageOutcome::Failed(failures.join("; "))
        }
    }
}

/// File name (under `ctx.report_dir`) the reported-skip note is written to
/// when a Relay node's platform is not yet live-supported for relay
/// validation (macOS / Windows, pending cross-OS Phase 8 evidence).
const REPORTED_SKIPS_FILENAME: &str = "relay_validation.reported_skips.json";

/// Serialize the reported-skip note as pretty JSON bytes. Pure (no I/O) so a
/// unit test can assert the content without touching the filesystem.
fn reported_skips_json_bytes(reported_skips: &[(String, String)]) -> Vec<u8> {
    let skipped: Vec<serde_json::Value> = reported_skips
        .iter()
        .map(|(alias, platform)| serde_json::json!({ "alias": alias, "platform": platform }))
        .collect();
    let body = serde_json::json!({
        "stage": "relay_validation",
        "reported_skipped_relay_validation": skipped,
        "reason": "relay runtime validation is implemented for Linux + macOS; a relay node on a \
                   platform with no relay-deploy adapter (Windows, pending its SCM relay install) \
                   is reported-skipped (named, never a silent pass) — gated on \
                   relay_lab_runtime_implemented, not is_supported_for_platform",
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

/// Write the reported-skip note to `<report_dir>/relay_validation.reported_skips.json`.
/// Best-effort: a write failure does not fail the stage, but the common path
/// leaves a machine-readable artifact naming every skipped relay node.
fn write_reported_skips_note(ctx: &OrchestrationContext, reported_skips: &[(String, String)]) {
    let path = ctx.report_dir.join(REPORTED_SKIPS_FILENAME);
    let _ = std::fs::write(&path, reported_skips_json_bytes(reported_skips));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn empty_ctx() -> OrchestrationContext {
        OrchestrationContext {
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
        }
    }

    #[test]
    fn stage_identity_and_dependencies() {
        let stage = RelayValidationStage;
        assert_eq!(stage.id(), StageId::RelayValidation);
        assert_eq!(stage.name(), "relay_validation");
        assert_eq!(stage.id().as_str(), "relay_validation");
        assert_eq!(stage.dependencies(), &[StageId::DeployRelayService]);
        assert!(matches!(stage.fanout(), StageFanout::PerNode));
        assert_eq!(stage.applies_to_roles(), &[NodeRole::Relay]);
    }

    #[test]
    fn reported_skips_note_names_every_skipped_relay() {
        // A macOS/Windows relay must be named in the skip note, never silently
        // treated as validated.
        let skips = vec![
            ("relay-mac".to_owned(), "Macos".to_owned()),
            ("relay-win".to_owned(), "Windows".to_owned()),
        ];
        let bytes = reported_skips_json_bytes(&skips);
        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).expect("reported-skip note must be valid JSON");
        assert_eq!(parsed["stage"], "relay_validation");
        let listed = parsed["reported_skipped_relay_validation"]
            .as_array()
            .expect("skip list");
        assert_eq!(listed.len(), 2);
        assert!(
            listed
                .iter()
                .any(|v| v["alias"] == "relay-mac" && v["platform"] == "Macos")
        );
        assert!(
            listed
                .iter()
                .any(|v| v["alias"] == "relay-win" && v["platform"] == "Windows")
        );
    }

    #[test]
    fn empty_assignments_passes_skip_noop() {
        let mut ctx = empty_ctx();
        assert_eq!(RelayValidationStage.execute(&mut ctx), StageOutcome::Passed);
    }

    #[test]
    fn no_relay_role_among_non_relay_assignments_passes_skip_noop() {
        // Assignments present but none Relay → still a skip-noop pass:
        // the stage only validates Relay nodes.
        use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
        let mut ctx = empty_ctx();
        ctx.assignments = vec![
            NodeRoleAssignment {
                alias: "n1".to_owned(),
                role: NodeRole::Exit,
            },
            NodeRoleAssignment {
                alias: "n2".to_owned(),
                role: NodeRole::Client,
            },
        ];
        assert_eq!(RelayValidationStage.execute(&mut ctx), StageOutcome::Passed);
    }

    #[test]
    fn relay_role_without_adapter_fails_closed() {
        // A Relay assignment with no adapter wired must fail closed
        // (never silently skip an unvalidatable relay).
        use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
        let mut ctx = empty_ctx();
        ctx.assignments = vec![NodeRoleAssignment {
            alias: "relay-1".to_owned(),
            role: NodeRole::Relay,
        }];
        let outcome = RelayValidationStage.execute(&mut ctx);
        match outcome {
            StageOutcome::Failed(msg) => {
                assert!(msg.contains("relay-1"), "got: {msg}");
                assert!(msg.contains("no adapter"), "got: {msg}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
