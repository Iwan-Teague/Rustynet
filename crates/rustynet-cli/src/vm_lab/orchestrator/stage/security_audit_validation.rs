#![allow(dead_code)]
use crate::vm_lab::LINUX_RUSTYNETD_PATH;
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::macos_install::MACOS_RUSTYNETD_PATH;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::security_audit::{
    AuditResult, run_security_audits, run_substrate_transit_control,
    security_audit_runtime_implemented, security_audits_ok, substrate_transit_declared,
    substrate_transit_probe_targets,
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
/// `--node` run. A run with no nodes is an honest skip (`Skipped`, never a
/// vacuous pass): nothing was validated, so the run stays Partial and the gap
/// stays visible.
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
            // Substrate-transit control: Linux-only (the vxlan lab substrate is
            // a Linux construct), evaluated outside the eight-entry battery so
            // it never claims a run-matrix column on macOS/Windows. Passes iff
            // the run's declared vxlan posture matches the daemon's live
            // substrate_transit status; when active, the nft ruleset must
            // carry the exact attested rule shape with non-zero counters in
            // both the group and boot tables. Evidence lands in the stage log
            // so a PASS is never backed by nothing.
            if platform == VmGuestPlatform::Linux {
                let declared = substrate_transit_declared(ctx.substrate_record.as_ref());
                // Live mesh addresses, resolved at control time through each
                // peer's adapter: the collect_pubkeys cache in ctx.mesh_ips
                // was gathered pre-enforce and is stale (the traffic-test
                // stage re-collects for the same reason). The control
                // validates the value as IPv4 and fails closed when a peer's
                // live address cannot be resolved.
                let resolve_mesh_ip = |peer: &str| -> Result<String, String> {
                    ctx.adapters
                        .get(peer)
                        .ok_or_else(|| format!("no adapter for peer `{peer}`"))?
                        .collect_mesh_ip()
                        .map_err(|e| format!("collect_mesh_ip failed for `{peer}`: {e}"))
                };
                // Probe targets: every attested peer minus this node, so the
                // control drives real transit through each rule BEFORE reading
                // its counter (the stage runs before any traffic stage —
                // without the probes the counters are vacuously zero).
                let participants = ctx
                    .substrate_record
                    .as_ref()
                    .map(|record| record.participants.clone())
                    .unwrap_or_default();
                let probe_targets = substrate_transit_probe_targets(&participants, alias);
                match run_substrate_transit_control(
                    &*shell,
                    declared,
                    &probe_targets,
                    &resolve_mesh_ip,
                ) {
                    Ok(line) => {
                        if let Err(e) = append_stage_evidence_line(
                            &ctx.report_dir,
                            StageId::SecurityAuditValidation.as_str(),
                            &format!("{alias}: {line}"),
                        ) {
                            failures.push(format!(
                                "{alias}: substrate transit evidence not written: {e}"
                            ));
                        }
                    }
                    Err(e) => failures.push(format!("{alias}: substrate transit control: {e}")),
                }
            }
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
        // (alias, platform tag) for every node whose audits actually ran —
        // the witness names them so a PASS is never backed by nothing.
        let audited: Vec<(String, &'static str)> = per_control
            .iter()
            .map(|(alias, tag, _)| (alias.clone(), *tag))
            .collect();
        // QH-83: the witness is written on the single pass path and a write
        // failure fails the stage — an unwitnessed security-audit pass must
        // never be recorded (the runner would demote it).
        match outcome_for(&failures, &reported_skips) {
            StageOutcome::Passed => match write_security_audit_witness(&ctx.report_dir, &audited) {
                Ok(()) => StageOutcome::Passed,
                Err(e) => StageOutcome::Failed(format!("security audit witness write failed: {e}")),
            },
            other => other,
        }
    }
}

/// Writes the QH-83 witness line for a security-audit PASS: the audited node
/// count plus each validated node's alias and run-matrix platform tag, so a
/// bare PASS can never be recorded without the on-disk evidence behind it.
/// An unwritable witness fails the stage — fail closed.
fn write_security_audit_witness(
    report_dir: &std::path::Path,
    audited: &[(String, &'static str)],
) -> Result<(), String> {
    let nodes: Vec<String> = audited
        .iter()
        .map(|(alias, tag)| format!("{alias}:{tag}"))
        .collect();
    append_stage_evidence_line(
        report_dir,
        StageId::SecurityAuditValidation.as_str(),
        &format!(
            "security_audit=yes audited_nodes={} ({})",
            nodes.len(),
            nodes.join(",")
        ),
    )
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
            linux_backend: None,
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
            relay_forwarding_validation_elected: false,
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
                SecurityAuditValidationStage.execute(&mut ctx),
                StageOutcome::Skipped(_)
            ),
            "an empty topology must skip, never pass; got {:?}",
            SecurityAuditValidationStage.execute(&mut ctx)
        );
    }

    // QH-83: the pass witness must name the audited node count and each
    // node's platform tag — a bare "pass" line would be appeasement, not
    // evidence. Mutation caught: dropping the witness write or demoting it
    // to best-effort.
    #[test]
    fn security_audit_witness_line_names_the_audited_node_count() {
        let dir = std::env::temp_dir().join(format!(
            "secaudit_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        write_security_audit_witness(
            &dir,
            &[("deb-1".to_owned(), "linux"), ("deb-2".to_owned(), "linux")],
        )
        .expect("witness write");
        let log = std::fs::read_to_string(
            crate::vm_lab::orchestrator::evidence::rust_native_stage_log_path(
                &dir,
                StageId::SecurityAuditValidation.as_str(),
            ),
        )
        .expect("stage log");
        assert!(log.contains("security_audit=yes"), "{log}");
        assert!(log.contains("audited_nodes=2"), "{log}");
        assert!(
            log.contains("deb-1:linux") && log.contains("deb-2:linux"),
            "{log}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fail-closed check: a witness write that cannot land must surface as an
    /// error the execute path turns into `Failed` — never a silent pass.
    #[test]
    fn security_audit_witness_write_failure_is_propagated() {
        let dir = std::env::temp_dir().join(format!(
            "secaudit_witness_blocker_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test dir");
        std::fs::write(dir.join("logs"), b"not a directory").expect("blocker file");
        let err = write_security_audit_witness(&dir, &[("deb-1".to_owned(), "linux")])
            .expect_err("witness write must fail when the logs path is a regular file");
        assert!(!err.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
    // ── substrate-transit stage wiring: live targets, self never probed ─────

    use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
    use crate::vm_lab::orchestrator::error::{
        AdapterError, BundleKind, GossipIdentity, InstallReport, MembershipOwnerKey,
        MembershipSnapshot, NodeId, NodeMembershipPeer, TrafficTestResult, TunnelsList,
        ValidatorReport,
    };
    use crate::vm_lab::orchestrator::remote_shell::{
        MockRunInvocation, MockShellHost, RemoteExitStatus, RemoteShellHost,
    };
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use crate::vm_lab::orchestrator::role_validation::security_audit::{
        SUBSTRATE_TRANSIT_RULE_COMMENT, parse_substrate_transit_status,
    };
    use crate::vm_lab::orchestrator::source_archive::SourceArchive;
    use crate::vm_lab::orchestrator::stage::cross_network::substrate::SubstrateRecord;

    /// Adapter double whose shell is a shared [`MockShellHost`] and whose live
    /// mesh ip is a configured value — enough for the substrate-transit
    /// control path; every other adapter surface fails loudly.
    #[derive(Debug)]
    struct ShellNodeAdapter {
        alias: &'static str,
        platform: crate::vm_lab::VmGuestPlatform,
        shell: std::sync::Arc<MockShellHost>,
        mesh_ip: String,
    }

    impl NodeAdapter for ShellNodeAdapter {
        fn platform(&self) -> crate::vm_lab::VmGuestPlatform {
            self.platform
        }
        fn alias(&self) -> &str {
            self.alias
        }
        fn shell_host(&self) -> Result<std::sync::Arc<dyn RemoteShellHost>, AdapterError> {
            Ok(self.shell.clone())
        }
        fn collect_mesh_ip(&self) -> Result<String, AdapterError> {
            Ok(self.mesh_ip.clone())
        }
        fn collect_artifacts(&self, _dst: &std::path::Path) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn start_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn stop_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn restart_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn uninstall_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn issue_membership_owner_key(&self) -> Result<MembershipOwnerKey, AdapterError> {
            unimplemented!()
        }
        fn collect_wireguard_public_key(
            &self,
        ) -> Result<crate::vm_lab::orchestrator::error::WireguardPublicKey, AdapterError> {
            unimplemented!()
        }
        fn collect_gossip_identity(&self) -> Result<GossipIdentity, AdapterError> {
            unimplemented!()
        }
        fn collect_node_id(&self) -> Result<NodeId, AdapterError> {
            unimplemented!()
        }
        fn run_validator(
            &self,
            _op: crate::vm_lab::DaemonProbeOp,
            _extra_args: &[String],
        ) -> Result<ValidatorReport, AdapterError> {
            unimplemented!()
        }
        fn ping_mesh_peer(&self, _peer_mesh_ip: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!()
        }
        fn probe_denied_peer(&self, _denied_ip: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!()
        }
        fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError> {
            unimplemented!()
        }
        fn cleanup_runtime_state(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn check_ssh_reachable(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn endpoint(&self) -> String {
            unimplemented!()
        }
        fn install_daemon(
            &self,
            _source: &SourceArchive,
            _ctx: &OrchestrationContext,
        ) -> Result<InstallReport, AdapterError> {
            unimplemented!()
        }
        fn init_membership_snapshot(
            &self,
            _owner_key: &MembershipOwnerKey,
            _peers: &[NodeMembershipPeer],
        ) -> Result<MembershipSnapshot, AdapterError> {
            unimplemented!()
        }
        fn distribute_signed_bundle(
            &self,
            _kind: BundleKind,
            _bundle_path: &std::path::Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn distribute_verifier_key(
            &self,
            _kind: BundleKind,
            _pub_key_path: &std::path::Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn issue_bundles_to_dir(
            &self,
            _kind: BundleKind,
            _env_content: &str,
            _local_out_dir: &std::path::Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
    }

    fn stage_exit_ok(stdout: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    fn stage_status_argv() -> [&'static str; 6] {
        [
            "sudo",
            "-n",
            "env",
            "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
            "/usr/local/bin/rustynet",
            "status",
        ]
    }

    fn stage_ruleset_argv() -> [&'static str; 5] {
        ["sudo", "-n", "nft", "list", "ruleset"]
    }

    fn stage_ping_argv(ip: &str) -> [&str; 6] {
        ["ping", "-c", "3", "-W", "3", ip]
    }

    fn stage_rendered_rule(daddr: &str, packets: u64) -> String {
        format!(
            "oifname \"mgmt0\" ip daddr {daddr} udp sport 4789 udp dport 4789 counter \
             packets {packets} bytes 400 accept comment \"{SUBSTRATE_TRANSIT_RULE_COMMENT}\""
        )
    }

    fn stage_ruleset(peer_a: u64, peer_b: u64) -> String {
        format!(
            "table inet rustynet_g2 {{\n    {}\n    {}\n}}\ntable inet rustynet_boot {{\n    {}\n    {}\n}}\n",
            stage_rendered_rule("192.0.2.11", peer_a),
            stage_rendered_rule("192.0.2.12", peer_b),
            stage_rendered_rule("192.0.2.11", peer_a),
            stage_rendered_rule("192.0.2.12", peer_b),
        )
    }

    #[test]
    fn stage_probes_live_peer_mesh_ips_never_self_nor_the_stale_cache() {
        let dir = std::env::temp_dir().join(format!(
            "secaudit_transit_stage_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test dir");

        let deb_shell = std::sync::Arc::new(MockShellHost::new());
        let active_status = "node_id=deb-1-node node_role=client state=FullTunnel \
             gossip_transport_error=none substrate_transit=lab-active overlay=rustynet-vx0 \
             underlay=mgmt0 peers=2";
        assert!(
            parse_substrate_transit_status(active_status).is_ok(),
            "test status line must parse"
        );
        deb_shell.program_run_response(&stage_status_argv(), stage_exit_ok(active_status));
        deb_shell.program_run_response(&stage_ruleset_argv(), stage_exit_ok(&stage_ruleset(2, 3)));
        deb_shell.program_run_response(&stage_ruleset_argv(), stage_exit_ok(&stage_ruleset(5, 7)));
        deb_shell.program_run_response(&stage_ping_argv("192.0.2.11"), stage_exit_ok(""));

        let mut ctx = OrchestrationContext::new(
            vec![NodeRoleAssignment {
                alias: "deb-1".to_owned(),
                role: NodeRole::Client,
            }],
            dir.clone(),
            "net".to_owned(),
        );
        // The STALE pre-enforce cache: the control must resolve probe targets
        // through the live adapters instead of reading these values.
        ctx.mesh_ips
            .insert("peer-1".to_owned(), "203.0.113.99".to_owned());
        ctx.substrate_record = Some(SubstrateRecord {
            substrate_id: "vxlan".to_owned(),
            topology_digest: "digest".to_owned(),
            provisioned: true,
            participants: vec!["deb-1".to_owned(), "peer-1".to_owned()],
        });
        ctx.adapters.insert(
            "deb-1".to_owned(),
            Box::new(ShellNodeAdapter {
                alias: "deb-1",
                platform: VmGuestPlatform::Linux,
                shell: deb_shell.clone(),
                mesh_ip: "192.0.2.10".to_owned(),
            }),
        );
        ctx.adapters.insert(
            "peer-1".to_owned(),
            Box::new(ShellNodeAdapter {
                alias: "peer-1",
                platform: VmGuestPlatform::Linux,
                shell: std::sync::Arc::new(MockShellHost::new()),
                mesh_ip: "192.0.2.11".to_owned(),
            }),
        );

        // The eight daemon audits are unprogrammed here, so the stage fails —
        // but the substrate-transit control itself must have run its probes
        // against the LIVE addresses and appended its evidence line.
        let outcome = SecurityAuditValidationStage.execute(&mut ctx);
        assert!(
            matches!(outcome, StageOutcome::Failed(_)),
            "unprogrammed audits must fail the stage; got {outcome:?}"
        );
        let log = std::fs::read_to_string(dir.join("logs").join("security_audit_validation.log"))
            .expect("the control passed, so its evidence line must be on disk");
        assert!(
            log.contains("probes=probe peer=peer-1 ip=192.0.2.11 exit=0"),
            "the evidence line must name the LIVE post-enforce probe target: {log}"
        );
        assert!(
            log.contains("counters=rustynet_g2:192.0.2.11=2->5,rustynet_g2:192.0.2.12=3->7"),
            "{log}"
        );
        let log = deb_shell.run_log();
        let pings: Vec<&MockRunInvocation> = log
            .iter()
            .filter(|call| call.argv.first().map(String::as_str) == Some("ping"))
            .collect();
        assert_eq!(pings.len(), 1, "exactly one probe: {pings:?}");
        assert_eq!(
            pings[0].argv.last().map(String::as_str),
            Some("192.0.2.11"),
            "the probe must use the live adapter address, never the stale cache value \
             203.0.113.99: {pings:?}"
        );
        assert!(
            !deb_shell
                .run_log()
                .iter()
                .any(|call| call.argv.last().map(String::as_str) == Some("192.0.2.10")),
            "the stage must never probe the node's own mesh ip"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
