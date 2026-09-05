#![allow(dead_code)]
use crate::vm_lab::LINUX_RUSTYNETD_PATH;
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::macos_install::MACOS_RUSTYNETD_PATH;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::security_audit::{
    AuditResult, run_security_audits, security_audit_runtime_implemented, security_audits_ok,
};
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const WINDOWS_RUSTYNETD_PATH: &str = r"C:\Program Files\RustyNet\rustynetd.exe";

const REPORTED_SKIPS_FILENAME: &str = "security_audit_validation.reported_skips.json";

/// Per-control evidence artifact. The run-matrix recorder reads this to
/// populate the twenty-four `{platform}_{audit_id}` security columns, which the
/// aggregate stage outcome alone cannot address — one stage status cannot carry
/// eight independent control verdicts.
pub const PER_CONTROL_FILENAME: &str = "security_audit_validation.per_control.json";

/// Schema version of the per-control artifact, and the field it is stamped in.
/// The recorder rejects an unrecognised version rather than guessing at a shape
/// it does not know — a report directory can legitimately be written by one
/// binary and recorded by another.
pub const PER_CONTROL_SCHEMA_VERSION: u64 = 1;
pub const PER_CONTROL_SCHEMA_VERSION_FIELD: &str = "schema_version";

/// Prove every node's daemon passes the eight Tier-0 adversarial self-audits —
/// membership-revoke, revoked-peer-denied, membership-signature,
/// privileged-helper-allowlist, policy-default-deny, gossip-revoked-readmit,
/// enrollment-replay, blind-exit-reversal (the exact set `rustynetd` exposes) —
/// folding the formerly bash-only Linux security suite into the standard Rust
/// orchestrator so a `--node` run exercises it.
///
/// Runs after `validate_baseline_runtime` (the daemon must be up + baseline-good
/// before its security posture is meaningful) and before the traffic matrix.
/// These are node-posture checks, so it applies to every node regardless of
/// role. Each audit is accepted only on an explicit `overall_ok: true`
/// (fail-closed). The [`security_audit_runtime_implemented`] posture gate admits
/// all three desktop platforms, so a macOS or Windows node IS audited here; only
/// a non-desktop platform (iOS/Android), which has no daemon audit surface, is
/// **reported-skipped** — named in
/// `security_audit_validation.reported_skips.json`, never a silent pass. Note
/// that admitting a platform is runtime support, not evidence — though macOS has
/// in fact executed this stage and passed (2026-07-19, run
/// `live-lab-direct-1784500192`); Windows has not yet reached it in a recorded
/// `--node` run. A run with no nodes is a skip-noop pass.
pub struct SecurityAuditValidationStage;

impl OrchestrationStage for SecurityAuditValidationStage {
    fn id(&self) -> StageId {
        StageId::SecurityAuditValidation
    }
    fn name(&self) -> &str {
        "security_audit_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::ValidateBaselineRuntime]
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
        // (alias, platform tag, per-audit verdicts) for the per-control artifact.
        let mut per_control: Vec<(String, &'static str, Vec<AuditResult>)> = Vec::new();
        // (alias, platform) reported-skipped because security-audit validation is
        // not yet live-supported on their platform via the Rust engine.
        let mut reported_skips: Vec<(String, String)> = Vec::new();
        for alias in &aliases {
            let adapter = match ctx.adapters.get(alias.as_str()) {
                Some(adapter) => adapter,
                None => {
                    failures.push(format!("{alias}: no adapter for security-audit node"));
                    continue;
                }
            };
            let platform = adapter.platform();
            if !security_audit_runtime_implemented(platform) {
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
            let daemon_path = match platform {
                VmGuestPlatform::Linux => LINUX_RUSTYNETD_PATH,
                VmGuestPlatform::Macos => MACOS_RUSTYNETD_PATH,
                VmGuestPlatform::Windows => WINDOWS_RUSTYNETD_PATH,
                _ => {
                    reported_skips.push((alias.clone(), format!("{platform:?}")));
                    continue;
                }
            };
            let Some(tag) = platform_tag(platform) else {
                // Unreachable today (the posture gate above excludes every
                // platform without a column set), but fail loudly rather than
                // charge one platform's verdicts to another's columns.
                failures.push(format!(
                    "{alias}: no run-matrix column prefix for platform {platform:?}"
                ));
                continue;
            };
            let results = run_security_audits(&*shell, daemon_path, alias);
            if let Err(e) = security_audits_ok(&results) {
                failures.push(format!("{alias}: {e}"));
            }
            per_control.push((alias.clone(), tag, results));
        }

        if !reported_skips.is_empty() {
            write_reported_skips_note(ctx, &reported_skips);
        }
        // Written UNCONDITIONALLY, including the empty case. A report directory
        // is legitimately reused (resume / rerun-stage / run-only), and leaving a
        // previous invocation's artifact in place would let the recorder read it
        // as THIS run's evidence — recording `pass` for controls that were never
        // exercised, on a run where the stage failed. That is the green-washing
        // direction, the exact defect class this artifact exists to close.
        if let Err(e) = write_per_control_evidence(ctx, &per_control) {
            failures.push(format!("per-control security evidence not written: {e}"));
        }
        outcome_for(&failures, &reported_skips)
    }
}

/// Fail iff any node failed; else Skipped iff every node that did not fail was
/// reported-skipped (nothing was actually validated live); else Passed.
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
        "stage": "security_audit_validation",
        "reported_skipped_security_audit": skipped,
        "reason": "the eight Tier-0 daemon self-audits run live on Linux/macOS/Windows \
                   through the Rust engine; a non-desktop-platform node (iOS/Android) is \
                   reported-skipped (named, never a silent pass)",
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

fn write_reported_skips_note(ctx: &OrchestrationContext, reported_skips: &[(String, String)]) {
    let path = ctx.report_dir.join(REPORTED_SKIPS_FILENAME);
    let _ = std::fs::write(&path, reported_skips_json_bytes(reported_skips));
}

/// The run-matrix column prefix for a platform. Only the three desktop
/// platforms have security columns; anything else is reported-skipped before
/// this is reached, so it never contributes a row.
fn platform_tag(platform: VmGuestPlatform) -> Option<&'static str> {
    // EXHAUSTIVE deliberately: a `_` arm would silently merge a newly supported
    // platform into the LINUX columns, contaminating one platform's evidence
    // with another's and producing no error. Adding a variant must break this
    // match instead.
    match platform {
        VmGuestPlatform::Linux => Some("linux"),
        VmGuestPlatform::Macos => Some("macos"),
        VmGuestPlatform::Windows => Some("windows"),
        VmGuestPlatform::Ios | VmGuestPlatform::Android => None,
    }
}

fn per_control_json_bytes(rows: &[(String, &'static str, Vec<AuditResult>)]) -> Vec<u8> {
    let controls: Vec<serde_json::Value> = rows
        .iter()
        .flat_map(|(alias, platform, results)| {
            results.iter().map(move |result| {
                serde_json::json!({
                    "alias": alias,
                    "platform": platform,
                    "audit_id": result.audit_id,
                    "status": result.verdict.matrix_status(),
                    "detail": result.verdict.detail().unwrap_or_default(),
                })
            })
        })
        .collect();
    let body = serde_json::json!({
        "stage": "security_audit_validation",
        PER_CONTROL_SCHEMA_VERSION_FIELD.to_string(): PER_CONTROL_SCHEMA_VERSION,
        "controls": controls,
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

fn write_per_control_evidence(
    ctx: &OrchestrationContext,
    rows: &[(String, &'static str, Vec<AuditResult>)],
) -> Result<(), String> {
    let path = ctx.report_dir.join(PER_CONTROL_FILENAME);
    crate::vm_lab::orchestrator::context::atomic_write_fsync(
        &path,
        &per_control_json_bytes(rows),
        None,
    )
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
                &["deb-1: policy_default_deny failed".into()],
                &[("mac-1".into(), "Macos".into())]
            ),
            StageOutcome::Failed(_)
        ));
    }

    use crate::vm_lab::orchestrator::role_validation::security_audit::{
        AuditResult, AuditVerdict, LINUX_SECURITY_AUDITS,
    };

    fn results(verdicts: &[(&'static str, AuditVerdict)]) -> Vec<AuditResult> {
        verdicts
            .iter()
            .map(|(audit_id, verdict)| AuditResult {
                audit_id,
                verdict: verdict.clone(),
            })
            .collect()
    }

    #[test]
    fn per_control_artifact_carries_one_row_per_audit_per_node() {
        let rows = vec![
            (
                "deb-1".to_string(),
                "linux",
                results(&[
                    ("policy_default_deny", AuditVerdict::Passed),
                    ("enrollment_replay", AuditVerdict::Passed),
                ]),
            ),
            (
                "mac-1".to_string(),
                "macos",
                results(&[("policy_default_deny", AuditVerdict::Passed)]),
            ),
        ];
        let parsed: serde_json::Value =
            serde_json::from_slice(&per_control_json_bytes(&rows)).expect("valid json");
        let controls = parsed["controls"].as_array().expect("controls array");
        assert_eq!(controls.len(), 3);
        assert_eq!(controls[0]["platform"], "linux");
        assert_eq!(controls[0]["audit_id"], "policy_default_deny");
        assert_eq!(controls[0]["status"], "pass");
        assert_eq!(controls[2]["platform"], "macos");
    }

    #[test]
    fn per_control_artifact_distinguishes_failed_from_blocked() {
        let rows = vec![(
            "deb-1".to_string(),
            "linux",
            results(&[
                (
                    "policy_default_deny",
                    AuditVerdict::Failed("violation observed".into()),
                ),
                (
                    "enrollment_replay",
                    AuditVerdict::Blocked("dispatch failed".into()),
                ),
            ]),
        )];
        let parsed: serde_json::Value =
            serde_json::from_slice(&per_control_json_bytes(&rows)).expect("valid json");
        let controls = parsed["controls"].as_array().expect("controls array");
        assert_eq!(controls[0]["status"], "fail");
        assert_eq!(controls[1]["status"], "blocked");
        // The detail must survive: a bare status cannot be triaged.
        assert_eq!(controls[1]["detail"], "dispatch failed");
    }

    #[test]
    fn every_audit_id_matches_a_real_run_matrix_column_on_every_desktop_platform() {
        // The whole point of the artifact is that `{platform}_{audit_id}`
        // addresses a real column. If a label drifts, the recorder silently
        // drops the row (set_status ignores unknown keys) and the control goes
        // back to reading `not_run` — the exact defect this closes.
        let schema: Vec<&str> = crate::live_lab_run_matrix::DEFAULT_MATRIX_COLUMNS.to_vec();
        for (label, _, _) in LINUX_SECURITY_AUDITS {
            for platform in ["linux", "macos", "windows"] {
                let column = format!("{platform}_{label}");
                assert!(
                    schema.contains(&column.as_str()),
                    "no run-matrix column `{column}` for audit `{label}`"
                );
            }
        }
    }

    #[test]
    fn a_run_that_exercises_nothing_still_overwrites_a_stale_artifact() {
        // Report directories are reused (resume / rerun-stage / run-only). If a
        // rerun in which no node was reachable left the previous invocation's
        // artifact in place, the recorder would read it as THIS run's evidence
        // and record `pass` for controls that were never exercised on a run
        // whose stage failed. The write is therefore unconditional.
        let report_dir = std::env::temp_dir().join(format!(
            "rustynet-sec-audit-stale-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&report_dir).expect("report dir");
        let path = report_dir.join(PER_CONTROL_FILENAME);
        std::fs::write(&path, br#"{"schema_version":1,"controls":[{"alias":"deb-1","platform":"linux","audit_id":"policy_default_deny","status":"pass"}]}"#)
            .expect("seed a previous invocation's artifact");

        let ctx = OrchestrationContext {
            assignments: Vec::new(),
            adapters: std::collections::HashMap::new(),
            source_archive: None,
            report_dir: report_dir.clone(),
            stage_outcomes: std::collections::HashMap::new(),
            collected_pubkeys: std::collections::HashMap::new(),
            collected_gossip_identities: std::collections::HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: std::collections::HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: std::collections::HashMap::new(),
            endpoints: std::collections::HashMap::new(),
            reflexive_endpoints: std::collections::HashMap::new(),
            lab_stun_servers: Vec::new(),
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
        };
        write_per_control_evidence(&ctx, &[]).expect("evidence write must succeed");

        let written = std::fs::read_to_string(&path).expect("artifact");
        let parsed: serde_json::Value = serde_json::from_str(&written).expect("valid json");
        assert!(
            parsed["controls"].as_array().expect("controls").is_empty(),
            "the stale claim must be erased, not left behind: {written}"
        );
        let _ = std::fs::remove_dir_all(report_dir);
    }

    #[test]
    fn platform_tag_maps_the_three_desktop_platforms_and_no_others() {
        assert_eq!(platform_tag(VmGuestPlatform::Linux), Some("linux"));
        assert_eq!(platform_tag(VmGuestPlatform::Macos), Some("macos"));
        assert_eq!(platform_tag(VmGuestPlatform::Windows), Some("windows"));
        // A platform with no security columns must yield None, so the caller
        // fails loudly instead of charging its verdicts to the linux columns.
        assert_eq!(platform_tag(VmGuestPlatform::Ios), None);
        assert_eq!(platform_tag(VmGuestPlatform::Android), None);
    }

    #[test]
    fn reported_skip_note_names_every_skipped_node() {
        let bytes = reported_skips_json_bytes(&[
            ("mac-1".into(), "Macos".into()),
            ("win-1".into(), "Windows".into()),
        ]);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("mac-1") && s.contains("win-1"));
        assert!(s.contains("security_audit_validation"));
    }
}
