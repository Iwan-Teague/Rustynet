#![allow(dead_code)]
use crate::vm_lab::orchestrator::adapter::node_adapter::RoleValidatorKind;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const REPORTED_SKIPS_FILENAME: &str = "service_hardening_validation.reported_skips.json";

/// Prove every Linux node's daemon passes the service-hardening self-check —
/// the installed systemd unit's hardening directives match the shipped
/// baseline — folding the formerly bash-only check into the standard Rust
/// orchestrator so a `--node` run exercises it.
///
/// Runs after `runtime_acls_validation` and before the relay/traffic stages.
/// This is a per-node posture check, so it applies to every node regardless of
/// role. Accepted only on an explicit `overall_ok: true` (fail-closed). A macOS /
/// Windows node is **reported-skipped** — named in
/// `service_hardening_validation.reported_skips.json`, never a silent pass — on
/// the [`service_hardening_runtime_implemented`] posture gate.
pub struct ServiceHardeningValidationStage;

impl OrchestrationStage for ServiceHardeningValidationStage {
    fn id(&self) -> StageId {
        StageId::ServiceHardeningValidation
    }
    fn name(&self) -> &str {
        "service_hardening_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::RuntimeAclsValidation]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();
        // A topology with no nodes validated NOTHING: a pass here would record
        // a green ledger row for an unexercised control — the vacuous-pass
        // false green (skip-semantics review F1). Skip so the run stays
        // Partial and the gap stays visible; never `Passed`.
        if aliases.is_empty() {
            return StageOutcome::Skipped(
                "no node assignments in this topology; nothing was validated".to_owned(),
            );
        }

        let mut failures: Vec<String> = Vec::new();
        let mut reported_skips: Vec<(String, String)> = Vec::new();
        // Aliases whose service-hardening validator actually ran and passed —
        // the witness names them so a PASS is never backed by nothing.
        let mut validated: Vec<String> = Vec::new();
        for alias in &aliases {
            let adapter = match ctx.adapters.get(alias.as_str()) {
                Some(adapter) => adapter,
                None => {
                    failures.push(format!("{alias}: no adapter for service-hardening node"));
                    continue;
                }
            };
            let platform = adapter.platform();
            if !adapter.supports_role_validator(RoleValidatorKind::ServiceHardening) {
                reported_skips.push((alias.clone(), format!("{platform:?}")));
                continue;
            }
            let expected_node_id = ctx.node_ids.get(alias.as_str()).map(String::as_str);
            match adapter.run_role_validator(
                RoleValidatorKind::ServiceHardening,
                expected_node_id,
                None,
            ) {
                Ok(()) => validated.push(alias.clone()),
                Err(e) => failures.push(format!("{alias}: {e}")),
            }
        }

        if !reported_skips.is_empty() {
            write_reported_skips_note(ctx, &reported_skips);
        }
        // QH-83: the witness is written on the single pass path and a write
        // failure fails the stage — an unwitnessed service-hardening pass
        // must never be recorded (the runner would demote it).
        match outcome_for(&failures, &reported_skips) {
            StageOutcome::Passed => {
                match write_service_hardening_witness(&ctx.report_dir, &validated) {
                    Ok(()) => StageOutcome::Passed,
                    Err(e) => {
                        StageOutcome::Failed(format!("service hardening witness write failed: {e}"))
                    }
                }
            }
            other => other,
        }
    }
}

/// Writes the QH-83 witness line for a service-hardening PASS: the validated
/// node count plus each alias whose hardening posture was actually proven, so
/// a bare PASS can never be recorded without the on-disk evidence behind it.
/// An unwritable witness fails the stage — fail closed.
fn write_service_hardening_witness(
    report_dir: &std::path::Path,
    validated: &[String],
) -> Result<(), String> {
    append_stage_evidence_line(
        report_dir,
        StageId::ServiceHardeningValidation.as_str(),
        &format!(
            "service_hardening=yes validated_nodes={} ({})",
            validated.len(),
            validated.join(",")
        ),
    )
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
        "stage": "service_hardening_validation",
        "reported_skipped_service_hardening": skipped,
        "reason": "Service-hardening check runs live on Linux through the Rust engine; \
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
                &["deb-1: service hardening check failed".into()],
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
        assert!(s.contains("service_hardening_validation"));
    }

    /// The empty-assignments guard must SKIP, never PASS: with zero nodes the
    /// stage validated nothing, and a pass would record a green ledger row for
    /// an unexercised control (skip-semantics review F1's vacuous pass).
    /// Mutation caught: reverting the guard arm to `return StageOutcome::Passed;`
    /// (the empty-assignments-vacuous-pass mutation).
    #[test]
    fn empty_assignments_is_skipped_never_passed() {
        let mut ctx = OrchestrationContext::new(Vec::new(), std::env::temp_dir(), "net".to_owned());
        assert!(
            matches!(
                ServiceHardeningValidationStage.execute(&mut ctx),
                StageOutcome::Skipped(_)
            ),
            "an empty topology must skip, never pass; got {:?}",
            ServiceHardeningValidationStage.execute(&mut ctx)
        );
    }

    // QH-83: the pass witness must name the validated node count and the
    // aliases — a bare "pass" line would be appeasement, not evidence.
    // Mutation caught: dropping the witness write or demoting it to
    // best-effort.
    #[test]
    fn service_hardening_witness_line_names_the_validated_node_count() {
        let dir = std::env::temp_dir().join(format!(
            "svch_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        write_service_hardening_witness(&dir, &["deb-1".to_owned(), "deb-2".to_owned()])
            .expect("witness write");
        let log = std::fs::read_to_string(
            crate::vm_lab::orchestrator::evidence::rust_native_stage_log_path(
                &dir,
                StageId::ServiceHardeningValidation.as_str(),
            ),
        )
        .expect("stage log");
        assert!(log.contains("service_hardening=yes"), "{log}");
        assert!(log.contains("validated_nodes=2"), "{log}");
        assert!(log.contains("deb-1") && log.contains("deb-2"), "{log}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fail-closed check: a witness write that cannot land must surface as an
    /// error the execute path turns into `Failed` — never a silent pass.
    #[test]
    fn service_hardening_witness_write_failure_is_propagated() {
        let dir = std::env::temp_dir().join(format!(
            "svch_witness_blocker_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test dir");
        std::fs::write(dir.join("logs"), b"not a directory").expect("blocker file");
        let err = write_service_hardening_witness(&dir, &["deb-1".to_owned()])
            .expect_err("witness write must fail when the logs path is a regular file");
        assert!(!err.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
