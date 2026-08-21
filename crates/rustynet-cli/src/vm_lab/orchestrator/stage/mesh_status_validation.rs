#![allow(dead_code)]
use std::collections::HashMap;

use crate::vm_lab::orchestrator::adapter::node_adapter::RoleValidatorKind;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{StageOutcome, WireguardPublicKey};
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const REPORTED_SKIPS_FILENAME: &str = "mesh_status_validation.reported_skips.json";

/// Prove every Linux node's daemon passes the mesh-status self-check —
/// the daemon's mesh-status view reports no drift (no stale state,
/// expected peer IDs present, within max-age bounds) — folding the
/// formerly bash-only check into the standard Rust orchestrator so a
/// `--node` run exercises it.
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
        if aliases.is_empty() {
            return StageOutcome::Passed;
        }

        let mut failures: Vec<String> = Vec::new();
        let mut reported_skips: Vec<(String, String)> = Vec::new();
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
            let expected_peers =
                expected_mesh_peers(alias, &aliases, &ctx.node_ids, &ctx.collected_pubkeys);
            if let Err(e) = adapter.run_role_validator_with_peers(
                RoleValidatorKind::MeshStatus,
                expected_node_id,
                &expected_peers,
            ) {
                failures.push(format!("{alias}: {e}"));
            }
        }

        if !reported_skips.is_empty() {
            write_reported_skips_note(ctx, &reported_skips);
        }
        outcome_for(&failures, &reported_skips)
    }
}

/// The node ids of the mesh peers `alias` must see: every OTHER assigned node
/// confirmed up (it has a collected WireGuard pubkey) that has a known node id.
///
/// Design (§4.1 clause 2): naming the expected peers makes the daemon's own
/// peer check active — a node that reached only a SUBSET of the mesh is flagged
/// as missing an expected peer, not passed on a bare non-empty count. The set is
/// restricted to collected-pubkey nodes so a node that never joined is NOT
/// expected: one node's bootstrap failure must not cascade into every other
/// node's mesh-status. Self is excluded, and the result is node ids (the id
/// space the daemon's snapshot `peer_ids` use, bound to `ctx.node_ids` by the
/// §4.7 identity challenge).
fn expected_mesh_peers<'a>(
    alias: &str,
    aliases: &[String],
    node_ids: &'a HashMap<String, String>,
    collected_pubkeys: &HashMap<String, WireguardPublicKey>,
) -> Vec<&'a str> {
    aliases
        .iter()
        .filter(|other| other.as_str() != alias)
        .filter(|other| collected_pubkeys.contains_key(other.as_str()))
        .filter_map(|other| node_ids.get(other.as_str()).map(String::as_str))
        .collect()
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

    #[test]
    fn expected_mesh_peers_names_confirmed_up_peers_by_node_id_excluding_self() {
        let aliases = vec!["self".to_owned(), "up".to_owned(), "down".to_owned()];
        let mut node_ids = HashMap::new();
        node_ids.insert("self".to_owned(), "node-self".to_owned());
        node_ids.insert("up".to_owned(), "node-up".to_owned());
        node_ids.insert("down".to_owned(), "node-down".to_owned());
        let mut collected = HashMap::new();
        collected.insert("self".to_owned(), WireguardPublicKey("s".repeat(64)));
        collected.insert("up".to_owned(), WireguardPublicKey("u".repeat(64)));
        // "down" is assigned and has a node id but never came up (no collected
        // pubkey) — it must NOT be expected, so its failure cannot cascade.

        let peers = expected_mesh_peers("self", &aliases, &node_ids, &collected);
        // Only "up": self excluded, "down" excluded (never joined), and the peer
        // is named by its node id (not its alias).
        assert_eq!(peers, vec!["node-up"]);
    }
}
