#![allow(dead_code)]
use crate::vm_lab::orchestrator::adapter::node_adapter::RoleValidatorKind;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const REPORTED_SKIPS_FILENAME: &str = "dns_failclosed_validation.reported_skips.json";

/// Prove every Linux node's daemon passes the DNS-failclosed self-check —
/// resolv.conf loopback-only, no external resolver reachable through the
/// killswitch — folding the formerly bash-only check into the standard Rust
/// orchestrator so a `--node` run exercises it.
///
/// Runs after `security_audit_validation` (the daemon must be up + baseline-good
/// before DNS posture is meaningful) and before the relay/traffic stages.
/// This is a per-node posture check, so it applies to every node regardless of
/// role. Accepted only on an explicit `overall_ok: true` (fail-closed). A macOS /
/// Windows node is **reported-skipped** — named in
/// `dns_failclosed_validation.reported_skips.json`, never a silent pass — on the
/// [`dns_failclosed_runtime_implemented`] posture gate.
pub struct DnsFailclosedValidationStage;

impl OrchestrationStage for DnsFailclosedValidationStage {
    fn id(&self) -> StageId {
        StageId::DnsFailclosedValidation
    }
    fn name(&self) -> &str {
        "dns_failclosed_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::SecurityAuditValidation]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        if ctx.assignments.is_empty() {
            return StageOutcome::Passed;
        }

        let mut failures: Vec<String> = Vec::new();
        let mut reported_skips: Vec<(String, String)> = Vec::new();
        // Does this topology have a primary exit that non-exit nodes route
        // through? distribute_assignments::build_bundle_env assigns every
        // non-exit node to the `NodeRole::Exit` node's id, so their
        // exit_mode becomes FullTunnel and their DNS posture FullyProtected.
        let has_primary_exit = ctx.assignments.iter().any(|a| {
            matches!(a.role, NodeRole::Exit)
                || matches!(&a.role, NodeRole::Custom(name) if name == "exit")
        });
        for assignment in &ctx.assignments {
            let alias = &assignment.alias;
            let adapter = match ctx.adapters.get(alias.as_str()) {
                Some(adapter) => adapter,
                None => {
                    failures.push(format!("{alias}: no adapter for dns-failclosed node"));
                    continue;
                }
            };
            let platform = adapter.platform();
            if !adapter.supports_role_validator(RoleValidatorKind::DnsFailclosed) {
                reported_skips.push((alias.clone(), format!("{platform:?}")));
                continue;
            }
            let expected_node_id = ctx.node_ids.get(alias.as_str()).map(String::as_str);
            // M5: the expected DNS posture is THREADED from the node's planned
            // role AND the run topology — never inferred from the state the
            // check observes (that would make the verification a tautology).
            // The lab's distribute_assignments (build_bundle_env) assigns EVERY
            // non-exit node to the single primary exit, so a non-exit node in
            // an exit-topology is FULL-TUNNEL (FullyProtected), not a plain
            // scoped client — see expected_dns_posture_for.
            let expected_dns_posture = expected_dns_posture_for(&assignment.role, has_primary_exit);
            if let Err(e) = adapter.run_role_validator(
                RoleValidatorKind::DnsFailclosed,
                expected_node_id,
                Some(expected_dns_posture),
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

/// The DNS posture the orchestrator EXPECTS a node to hold, from its planned
/// role AND whether the run topology has a primary exit
/// (MacosClientDnsFailclosedDiagnosis_2026-09-02 §6; corrected 2026-09-03).
/// Exit / blind-exit nodes serve traffic and hold the full fail-closed posture.
/// Every OTHER node is assigned the primary exit by
/// distribute_assignments::build_bundle_env when one exists, making it a
/// FULL-TUNNEL node (exit_mode=FullTunnel → macos_dns_posture=FullyProtected) —
/// NOT a plain scoped client. Only a topology with NO primary exit leaves a
/// non-exit node genuinely plain (scoped-resolver-only). Never inferred from
/// observed state — the check verifies the report against this expectation.
fn expected_dns_posture_for(role: &NodeRole, has_primary_exit: bool) -> &'static str {
    match role {
        NodeRole::Exit | NodeRole::BlindExit => "fully_protected",
        NodeRole::Custom(name) if name == "exit" || name == "blind_exit" => "fully_protected",
        _ => {
            if has_primary_exit {
                "fully_protected"
            } else {
                "scoped_resolver_only"
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
        "stage": "dns_failclosed_validation",
        "reported_skipped_dns_failclosed": skipped,
        "reason": "DNS-failclosed check runs live on Linux through the Rust engine; \
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
                &["deb-1: dns failclosed check failed".into()],
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
        assert!(s.contains("dns_failclosed_validation"));
    }

    #[test]
    fn expected_dns_posture_is_topology_aware() {
        // Exit-family nodes always hold the full posture (they serve the exit).
        for role in [
            NodeRole::Exit,
            NodeRole::BlindExit,
            NodeRole::Custom("exit".into()),
        ] {
            assert_eq!(expected_dns_posture_for(&role, true), "fully_protected");
            assert_eq!(expected_dns_posture_for(&role, false), "fully_protected");
        }
        // In an exit-topology, every non-exit node is assigned the primary exit
        // (build_bundle_env) → FULL-TUNNEL → FullyProtected. This is the fix: a
        // Client is NOT a plain scoped node here.
        for role in [
            NodeRole::Client,
            NodeRole::Anchor,
            NodeRole::Admin,
            NodeRole::Relay,
            NodeRole::Entry,
            NodeRole::Aux,
            NodeRole::Extra,
            NodeRole::Custom("client".into()),
        ] {
            assert_eq!(
                expected_dns_posture_for(&role, true),
                "fully_protected",
                "{role:?} in an exit-topology is full-tunnel, must expect fully_protected"
            );
            // With NO primary exit, a non-exit node is genuinely plain (scoped).
            assert_eq!(
                expected_dns_posture_for(&role, false),
                "scoped_resolver_only"
            );
        }
    }
}
