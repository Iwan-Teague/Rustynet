#![allow(dead_code)]
//! MAC-D3: validate the macOS anchor port-mapping authority as a first-class
//! `--node` stage. Previously a bash-era registry entry that never dispatched
//! under the Rust engine; now wired into the engine of record so an elected
//! macOS anchor run proves port-mapping authority live.
//!
//! Identity contract (adversarial review, 2026-09-05): the guest check
//! `anchor-port-mapping-status-check --self-node-id <id>` answers "does
//! `<id>` hold the capability in the signed snapshot" for whatever id it is
//! TOLD — it cannot itself bind that id to the running daemon. So this stage
//! (a) takes the id from `ctx.node_ids`, which `collect_pubkeys` (a hard
//! transitive prerequisite via `MacosAnchorProfileDeploy`) recorded from the
//! daemon's own report, never from the inventory label; (b) re-reads the
//! daemon's node id at validation time and fails closed on any mismatch, so
//! the same-run TOCTOU window between the two reads cannot produce a pass
//! under a stale identity; and (c) never guesses a fallback id. The G2
//! re-wire should move the derivation daemon-side (the check refusing a
//! `--self-node-id` that differs from its persisted identity), which would
//! make the orchestrator unable to choose the queried identity at all.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::path::Path;

pub struct MacosAnchorPortMappingAuthorityValidationStage;

impl OrchestrationStage for MacosAnchorPortMappingAuthorityValidationStage {
    fn id(&self) -> StageId {
        StageId::MacosAnchorPortMappingAuthorityValidation
    }

    fn name(&self) -> &str {
        "validate_macos_anchor_port_mapping_authority"
    }

    fn dependencies(&self) -> &[StageId] {
        &[StageId::MacosAnchorProfileDeploy]
    }

    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }

    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let macos_alias = match macos_anchor_alias(ctx) {
            Ok(alias) => alias,
            Err(skip) => return StageOutcome::Skipped(skip),
        };
        if !ctx.macos_anchor_validators_elected {
            return StageOutcome::Skipped(
                "macOS anchor validators were not elected for this run (--anchor-platform macos)"
                    .to_owned(),
            );
        }
        let inventory_path = match ctx.inventory_path.as_deref() {
            Some(path) => path.to_owned(),
            None => {
                // Fail closed: the validators were elected but the run-local
                // inventory path is missing (e.g. a resumed context). Never
                // silently skip a security posture validation.
                return StageOutcome::Failed(
                    "macOS anchor validators elected but orchestration context carries no inventory path"
                        .to_owned(),
                );
            }
        };
        let adapter = match ctx.adapters.get(macos_alias.as_str()) {
            Some(adapter) => adapter,
            None => {
                return StageOutcome::Failed(format!(
                    "no adapter registered for macOS anchor node {macos_alias}"
                ));
            }
        };
        let params = match adapter.ssh_connection_params() {
            Some(params) => params,
            None => {
                return StageOutcome::Failed(format!(
                    "{macos_alias}: no SSH connection params available for port-mapping validation"
                ));
            }
        };
        let ssh_identity_file = params.identity_file.clone();
        let known_hosts_path = params.known_hosts.clone();
        let membership_node_id = match membership_node_id_for(ctx, macos_alias.as_str()) {
            Ok(id) => id,
            Err(err) => return StageOutcome::Failed(err),
        };
        // Validation-time cross-check (adversarial review): the recorded id is
        // orchestrator belief from collect_pubkeys; re-read the daemon's own
        // node id NOW and refuse to validate under a stale identity, so a node
        // that holds the capability under a different id than it currently
        // runs as can never pass.
        let live_node_id = match adapter.collect_node_id() {
            Ok(id) => id.0,
            Err(err) => {
                return StageOutcome::Failed(format!(
                    "{macos_alias}: could not re-read the daemon's node id at validation time: {err}"
                ));
            }
        };
        if let Err(err) = assert_live_identity_matches(
            macos_alias.as_str(),
            membership_node_id.as_str(),
            live_node_id.as_str(),
        ) {
            return StageOutcome::Failed(err);
        }
        match crate::vm_lab::exercise_macos_anchor_port_mapping_authority_live(
            &macos_alias,
            membership_node_id.as_str(),
            Path::new(&inventory_path),
            &ssh_identity_file,
            Some(known_hosts_path.as_path()),
        ) {
            Ok(_detail) => StageOutcome::Passed,
            Err(err) => StageOutcome::Failed(format!("{macos_alias}: {err}")),
        }
    }
}

/// The node id the daemon on `alias` runs as and the signed membership
/// snapshot is keyed by — `ctx.node_ids` (daemon-reported in
/// `collect_pubkeys`). This is the ONLY identity the port-mapping status
/// check may be asked about: the inventory `node_id` is a lab label, and
/// passing it made the daemon look up a node absent from the snapshot and
/// report a false "does not hold the capability"
/// (`labrun-1788266019601-1574-3`). Fails closed when the context carries no
/// id — never guesses.
fn membership_node_id_for(ctx: &OrchestrationContext, alias: &str) -> Result<String, String> {
    ctx.node_ids.get(alias).cloned().ok_or_else(|| {
        format!(
            "{alias}: orchestration context carries no daemon-reported membership node id \
             for the macOS anchor (collect_pubkeys did not record one); refusing to query \
             the port-mapping authority under a guessed identity"
        )
    })
}

/// The id recorded at `collect_pubkeys` must equal the id the daemon reports
/// at validation time; anything else (re-provisioned guest, restarted daemon
/// under another identity, stale resumed context) fails closed. Pure so the
/// refusal is unit-tested without a guest.
fn assert_live_identity_matches(alias: &str, recorded: &str, live: &str) -> Result<(), String> {
    if recorded == live {
        return Ok(());
    }
    Err(format!(
        "{alias}: daemon node id changed since collect_pubkeys (recorded={recorded}, \
         live={live}); refusing to validate port-mapping authority under a stale identity"
    ))
}

/// Resolve the single macOS anchor node alias, or fail with a skip reason.
/// Skips (not failures) when no macOS node is assigned the anchor role: the
/// stage is a no-op on topologies without an elected macOS anchor.
fn macos_anchor_alias(ctx: &OrchestrationContext) -> Result<String, String> {
    let mut macos_anchor: Option<String> = None;
    for assignment in &ctx.assignments {
        if assignment.role != NodeRole::Anchor {
            continue;
        }
        let is_macos = ctx
            .adapters
            .get(assignment.alias.as_str())
            .map(|adapter| adapter.platform() == VmGuestPlatform::Macos)
            .unwrap_or(false);
        if is_macos {
            if macos_anchor.is_some() {
                return Err(
                    "multiple macOS nodes are assigned the anchor role in this topology".to_owned(),
                );
            }
            macos_anchor = Some(assignment.alias.clone());
        }
    }
    macos_anchor
        .ok_or_else(|| "no macOS node is assigned the anchor role in this topology".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;

    fn empty_ctx() -> OrchestrationContext {
        let report_dir = std::env::temp_dir().join("macos-anchor-port-mapping-stage-test");
        OrchestrationContext::new(
            Vec::<NodeRoleAssignment>::new(),
            report_dir,
            "net".to_owned(),
        )
    }

    #[test]
    fn skips_when_no_node_is_assigned_the_anchor_role() {
        let mut ctx = empty_ctx();
        assert!(!ctx.macos_anchor_validators_elected);
        let outcome = MacosAnchorPortMappingAuthorityValidationStage.execute(&mut ctx);
        assert!(matches!(outcome, StageOutcome::Skipped(_)));
    }

    #[test]
    fn membership_node_id_comes_from_the_daemon_reported_context_never_a_guess() {
        let mut ctx = empty_ctx();
        let err = membership_node_id_for(&ctx, "macos-utm-1").unwrap_err();
        assert!(
            err.contains("no daemon-reported membership node id"),
            "{err}"
        );
        assert!(err.contains("macos-utm-1"), "{err}");
        assert!(
            !err.contains("-bootstrap"),
            "must not fall back to a guessed id: {err}"
        );

        ctx.node_ids
            .insert("macos-utm-1".to_owned(), "macos-utm-1-bootstrap".to_owned());
        assert_eq!(
            membership_node_id_for(&ctx, "macos-utm-1").unwrap(),
            "macos-utm-1-bootstrap"
        );
    }

    #[test]
    fn live_identity_must_match_the_recorded_membership_id() {
        assert!(
            assert_live_identity_matches(
                "macos-utm-1",
                "macos-utm-1-bootstrap",
                "macos-utm-1-bootstrap"
            )
            .is_ok()
        );
        let err =
            assert_live_identity_matches("macos-utm-1", "macos-utm-1-bootstrap", "macos-client-1")
                .unwrap_err();
        assert!(err.contains("recorded=macos-utm-1-bootstrap"), "{err}");
        assert!(err.contains("live=macos-client-1"), "{err}");
        assert!(err.contains("refusing"), "{err}");
    }

    #[test]
    fn stage_metadata_matches_the_catalog() {
        assert_eq!(
            MacosAnchorPortMappingAuthorityValidationStage.id(),
            StageId::MacosAnchorPortMappingAuthorityValidation
        );
        assert_eq!(
            MacosAnchorPortMappingAuthorityValidationStage.name(),
            "validate_macos_anchor_port_mapping_authority"
        );
        assert_eq!(
            MacosAnchorPortMappingAuthorityValidationStage.fanout(),
            StageFanout::Once
        );
    }
}
