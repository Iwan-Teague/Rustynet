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
            // M5: the expected DNS posture is THREADED from the node's
            // planned role — never inferred from the state the check
            // observes (that would make the verification a tautology).
            let expected_dns_posture = expected_dns_posture_for_role(&assignment.role);
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

/// The DNS posture the orchestrator EXPECTS a node with this planned role to
/// hold (MacosClientDnsFailclosedDiagnosis_2026-09-02 §6, review A1). Exit
/// and blind-exit nodes carry the machine's traffic and hold the full
/// fail-closed posture; every other role is a plain mesh node holding the
/// scoped-resolver-only posture. The macOS validator/daemon check verify the
/// report against this expectation.
///
/// Shared with `validate_baseline_runtime`, which must thread the SAME
/// expected posture into its per-node `macos-dns-failclosed-check` dispatch:
/// without it the daemon check defaults to `fully_protected`
/// (`rustynetd/src/main.rs:2524`) and reds every plain-client macOS node.
/// This is the orchestrator's planned-role mirror of the daemon's own
/// `macos_dns_posture` rule (`rustynetd/src/phase10.rs:801`: FullyProtected
/// iff FullTunnel exit_mode OR serve_exit_node) — in the planned-role model
/// the only roles that carry the machine's traffic / serve an exit are
/// exit and blind_exit. If the orchestrator ever grows a role whose nodes
/// route ALL traffic through an exit (a full-tunnel client), it MUST map to
/// `fully_protected` here too.
pub(crate) fn expected_dns_posture_for_role(role: &NodeRole) -> &'static str {
    match role {
        NodeRole::Exit | NodeRole::BlindExit => "fully_protected",
        NodeRole::Anchor | NodeRole::Admin | NodeRole::Relay | NodeRole::Client => {
            "scoped_resolver_only"
        }
        NodeRole::Entry | NodeRole::Aux | NodeRole::Extra => "scoped_resolver_only",
        NodeRole::Custom(name) => match name.as_str() {
            "exit" | "blind_exit" => "fully_protected",
            _ => "scoped_resolver_only",
        },
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
}
