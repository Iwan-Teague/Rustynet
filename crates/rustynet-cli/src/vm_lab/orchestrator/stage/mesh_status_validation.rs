#![allow(dead_code)]
use std::time::{Duration, Instant};

use crate::vm_lab::orchestrator::adapter::node_adapter::{NodeAdapter, RoleValidatorKind};
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::mesh_status::evaluate_live_handshake_status;
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
        if aliases.is_empty() {
            return StageOutcome::Passed;
        }
        // Every OTHER assigned node must be live: full mesh is the run's own
        // contract (traffic_test_matrix pings every pair). A single-node run
        // expects zero live peers.
        let expected_live_peers = ctx.assignments.len().saturating_sub(1) as u32;

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
            if let Err(e) =
                adapter.run_role_validator(RoleValidatorKind::MeshStatus, expected_node_id, None)
            {
                failures.push(format!("{alias}: {e}"));
                continue;
            }
            // QH-70: the snapshot passing is necessary but not sufficient —
            // demand live dataplane evidence before this stage may pass.
            if let Err(e) = poll_live_handshake(adapter.as_ref(), alias, expected_live_peers) {
                failures.push(e);
            }
        }

        if !reported_skips.is_empty() {
            write_reported_skips_note(ctx, &reported_skips);
        }
        outcome_for(&failures, &reported_skips)
    }
}

/// Poll the node's daemon status until [`evaluate_live_handshake_status`]
/// passes or the deadline expires; a poll that never got a passing status
/// fails the stage (fail-closed, the existing `failures` path). Every peer
/// other than this node is expected live: `assignments.len() - 1`.
fn poll_live_handshake(
    adapter: &dyn NodeAdapter,
    alias: &str,
    expected_live_peers: u32,
) -> Result<(), String> {
    let deadline = Instant::now() + LIVE_HANDSHAKE_DEADLINE;
    loop {
        let attempt = match adapter.collect_daemon_status() {
            Ok(status) => {
                let now_unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| format!("{alias}: live handshake: system clock error: {e}"))?
                    .as_secs();
                evaluate_live_handshake_status(alias, &status, expected_live_peers, now_unix)
            }
            Err(e) => Err(format!("{alias}: live handshake: {e}")),
        };
        match attempt {
            Ok(()) => return Ok(()),
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
}
