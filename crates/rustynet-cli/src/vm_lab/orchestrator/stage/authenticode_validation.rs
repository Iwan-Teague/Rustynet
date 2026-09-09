#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::node_adapter::RoleValidatorKind;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const REPORTED_SKIPS_FILENAME: &str = "authenticode_validation.reported_skips.json";

/// Evidence artifact the Linux (non-attesting stub) reports are written to,
/// under `ctx.report_dir`. The raw producer JSON is preserved verbatim so the
/// ledger row is backed by what the daemon actually emitted, not by a
/// stage-side claim.
const REPORT_FILENAME: &str = "authenticode_validation.report.json";

/// Prove every node's daemon reports an honest authenticode verdict —
/// `applicable: false` on Linux (runtime binary-signature attestation is
/// Windows-specific; Linux relies on dpkg/rpm install-time verification),
/// evaluated by the same typed evaluator the bash live-suite applies —
/// folding the formerly bash-only check into the standard Rust orchestrator
/// so a `--node` run exercises it.
///
/// Runs after `mesh_status_validation` and before relay deploy. This is a
/// per-node posture check, so it applies to every node regardless of role.
///
/// Fail-closed stage semantics: the Linux producer is a known NON-ATTESTING
/// stub (`applicable: false, overall_ok: true`, zero I/O), so a Linux "pass"
/// is NEVER a [`StageOutcome::Passed`] — the raw producer report is written to
/// `authenticode_validation.report.json` (a write failure fails the stage) and
/// the stage reports a skip naming the non-attesting stub. A macOS / Windows
/// node is **reported-skipped** — named in
/// `authenticode_validation.reported_skips.json`, never a silent pass.
pub struct AuthenticodeValidationStage;

impl OrchestrationStage for AuthenticodeValidationStage {
    fn id(&self) -> StageId {
        StageId::AuthenticodeValidation
    }
    fn name(&self) -> &str {
        "authenticode_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::MeshStatusValidation]
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
        let mut linux_stub_reports: Vec<(String, String)> = Vec::new();
        for alias in &aliases {
            let adapter = match ctx.adapters.get(alias.as_str()) {
                Some(adapter) => adapter,
                None => {
                    failures.push(format!("{alias}: no adapter for authenticode node"));
                    continue;
                }
            };
            let platform = adapter.platform();
            if !adapter.supports_role_validator(RoleValidatorKind::Authenticode) {
                reported_skips.push((alias.clone(), format!("{platform:?}")));
                continue;
            }
            let expected_node_id = ctx.node_ids.get(alias.as_str()).map(String::as_str);
            if platform == VmGuestPlatform::Linux {
                // The Linux producer cannot attest (constant non-attesting
                // stub): capture the RAW report as evidence and count the node
                // as a named skip. A constant pass must never mint a Passed
                // outcome for a ledger row that was never really exercised.
                match adapter.run_linux_authenticode_validator_with_report(expected_node_id) {
                    Ok(raw_report) => linux_stub_reports.push((alias.clone(), raw_report)),
                    Err(e) => failures.push(format!("{alias}: {e}")),
                }
                continue;
            }
            if let Err(e) =
                adapter.run_role_validator(RoleValidatorKind::Authenticode, expected_node_id, None)
            {
                failures.push(format!("{alias}: {e}"));
            }
        }

        if !linux_stub_reports.is_empty() {
            // Fail closed on the evidence write: a stub pass without its
            // preserved raw report is exactly the false-green this stage
            // exists to prevent.
            if let Err(write_err) = write_authenticode_report_artifact(ctx, &linux_stub_reports) {
                failures.push(format!(
                    "failed to write {REPORT_FILENAME} (raw authenticode producer evidence): \
                     {write_err}"
                ));
            }
        }
        if !reported_skips.is_empty() {
            write_reported_skips_note(ctx, &reported_skips);
        }
        outcome_for(&failures, &reported_skips, linux_stub_reports.len())
    }
}

fn outcome_for(
    failures: &[String],
    reported_skips: &[(String, String)],
    linux_stub_report_count: usize,
) -> StageOutcome {
    if !failures.is_empty() {
        StageOutcome::Failed(failures.join("; "))
    } else if linux_stub_report_count > 0 || !reported_skips.is_empty() {
        let mut reasons: Vec<String> = Vec::new();
        if linux_stub_report_count > 0 {
            reasons.push(format!(
                "Linux authenticode is a non-attesting stub: {linux_stub_report_count} node(s) \
                 captured raw not-applicable producer reports as evidence \
                 ({REPORT_FILENAME}); this stage cannot attest binary signatures on Linux"
            ));
        }
        if !reported_skips.is_empty() {
            reasons.push(format!(
                "{} node(s) reported a runtime skip",
                reported_skips.len()
            ));
        }
        StageOutcome::Skipped(reasons.join("; "))
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
        "stage": "authenticode_validation",
        "reported_skipped_authenticode": skipped,
        "reason": "Authenticode check runs live on Linux through the Rust engine; \
                   non-Linux nodes are reported-skipped (named, never a silent pass)",
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

fn authenticode_report_json_bytes(linux_stub_reports: &[(String, String)]) -> Vec<u8> {
    let reports: Vec<serde_json::Value> = linux_stub_reports
        .iter()
        .map(|(alias, raw_report)| {
            // Embed the daemon's report as structured JSON; if it somehow
            // does not re-parse (the evaluator already validated it), keep
            // the raw bytes as a string rather than dropping evidence.
            let parsed = serde_json::from_str::<serde_json::Value>(raw_report)
                .unwrap_or(serde_json::Value::String(raw_report.clone()));
            serde_json::json!({ "alias": alias, "report": parsed })
        })
        .collect();
    let body = serde_json::json!({
        "stage": "authenticode_validation",
        "linux_authenticode_reports": reports,
        "reason": "Linux authenticode is a non-attesting stub (applicable=false, \
                   overall_ok=true, zero I/O); raw producer reports are preserved \
                   verbatim and the stage reports a skip, never a pass",
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

fn write_authenticode_report_artifact(
    ctx: &OrchestrationContext,
    linux_stub_reports: &[(String, String)],
) -> Result<(), String> {
    let path = ctx.report_dir.join(REPORT_FILENAME);
    std::fs::write(&path, authenticode_report_json_bytes(linux_stub_reports))
        .map_err(|err| format!("{}: {err}", path.display()))
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
        assert_eq!(outcome_for(&[], &[], 0), StageOutcome::Passed);
    }

    #[test]
    fn outcome_reported_skip_only_is_skipped() {
        assert!(
            matches!(
                outcome_for(&[], &[("mac-1".into(), "Macos".into())], 0),
                StageOutcome::Skipped(_)
            ),
            "expected a skip; got {:?}",
            outcome_for(&[], &[("mac-1".into(), "Macos".into())], 0)
        );
    }

    // Mutation coverage for the non-attesting-stub rule: reverting the
    // linux_stub_report_count arm in `outcome_for` to fall through to
    // `StageOutcome::Passed` turns this test red — a Linux run whose producer
    // is a constant non-attesting stub must surface as a skip, never a pass.
    #[test]
    fn outcome_linux_stub_report_is_skipped_not_passed() {
        let outcome = outcome_for(&[], &[], 1);
        assert!(
            matches!(&outcome, StageOutcome::Skipped(message) if message.contains("non-attesting stub")),
            "a Linux stub pass must be a named skip, got {outcome:?}"
        );
    }

    #[test]
    fn outcome_failure_is_failed_even_with_skips() {
        assert!(matches!(
            outcome_for(
                &["deb-1: authenticode check failed".into()],
                &[("mac-1".into(), "Macos".into())],
                0
            ),
            StageOutcome::Failed(_)
        ));
        assert!(matches!(
            outcome_for(&["deb-1: evaluator rejected".into()], &[], 1),
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
        assert!(s.contains("authenticode_validation"));
    }

    #[test]
    fn report_artifact_embeds_raw_producer_report_per_node() {
        let raw = r#"{"schema_version":1,"overall_ok":true,"applicable":false,"reason":"stub"}"#;
        let bytes = authenticode_report_json_bytes(&[("deb-1".into(), raw.to_owned())]);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("deb-1"));
        assert!(s.contains("linux_authenticode_reports"));
        // The raw report is preserved structurally, not summarized away.
        assert!(s.contains("schema_version") && s.contains("applicable"));
        assert!(s.contains("non-attesting stub"));
    }
}
