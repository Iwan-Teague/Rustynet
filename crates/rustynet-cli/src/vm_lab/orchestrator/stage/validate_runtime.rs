#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::report::ValidatorResult;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct ValidateBaselineRuntimeStage {
    max_parallel_node_workers: usize,
    shutdown_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ValidateBaselineRuntimeStage {
    pub fn new(
        max_parallel_node_workers: usize,
        shutdown_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            max_parallel_node_workers: max_parallel_node_workers.max(1),
            shutdown_flag,
        }
    }
}

/// Expectation flags this stage attaches to each `DaemonProbeOp` dispatch.
///
/// QH-39: `mesh-status` used to be dispatched with only `--no-fail-on-drift`.
/// The daemon's evaluator nests BOTH the staleness and the future-timestamp
/// test inside `if let Some(max_age)`
/// (`rustynetd/src/windows_mesh_status.rs:167-177`), so with no expectations
/// its `Ok` branch asserts nothing at all and `overall_ok: true` means only
/// "a state file exists and parses". `macos-utm-1` recorded
/// `MeshStatus: passed` on a host with no daemon running.
///
/// The freshness bound closes exactly that — but ONLY because the daemon now
/// heartbeats the snapshot (`rustynetd::daemon::STATE_SNAPSHOT_HEARTBEAT_INTERVAL_SECS`).
/// An earlier attempt at this bound was reverted precisely because it was not
/// true then: `persist_state` was reachable only from a command handler or the
/// reconcile apply block, which is gated on `FailClosed || Recoverable ||
/// assignment_changed || membership_changed || local_route_reconcile_pending`,
/// so a converged healthy node's snapshot aged without bound and the bound
/// would have failed HEALTHY nodes in the `--skip-setup` / `--rerun-stage`
/// reuse loops. With the heartbeat, a live daemon refreshes the snapshot on a
/// fixed cadence and a dead, wedged, or fail-closed one stops — so the bound
/// reads liveness, in continuous runs and reuse loops alike.
///
/// `SNAPSHOT_MAX_AGE_SECONDS` is shared with the dedicated
/// `mesh_status_validation` stage rather than re-derived — read its doc
/// comment for the measurement behind 180 s and for the `--resume-from` /
/// single-stage-re-run limit, which applies here identically. This stage runs
/// EARLIER in the pipeline (immediately after the daemon restart in
/// `enforce_baseline_runtime`), so the margin here is strictly larger.
///
/// NOT emitted: `--expected-peer-id`. The daemon persists
/// `SessionStateSnapshot.peer_ids` from `self.advertised_routes`
/// (`daemon.rs:9762-9765`) — i.e. advertised route CIDRs, not peer node ids —
/// so no node id can ever match one and passing `ctx.node_ids` here would red
/// every node in the run. That mismatch is a separate daemon-side defect;
/// asserting peer visibility has to wait for it.
fn probe_expectations(op: crate::vm_lab::DaemonProbeOp) -> Vec<String> {
    use crate::vm_lab::DaemonProbeOp;
    use crate::vm_lab::orchestrator::role_validation::mesh_status::SNAPSHOT_MAX_AGE_SECONDS;

    match op {
        DaemonProbeOp::MeshStatus => vec![
            "--max-age-seconds".to_owned(),
            SNAPSHOT_MAX_AGE_SECONDS.to_owned(),
        ],
        _ => Vec::new(),
    }
}

/// Generic drift surfacing (design §5.2 Item 2): pull the first
/// `drift_reasons` entry out of a kept daemon report. No hard-coded drift
/// strings — whatever the daemon reported is what surfaces in the failure
/// message. Non-string reasons render via their JSON form so nothing is
/// silently dropped.
fn first_drift_reason(report: &serde_json::Value) -> Option<String> {
    report
        .get("drift_reasons")
        .and_then(serde_json::Value::as_array)
        .and_then(|reasons| reasons.first())
        .map(|first| match first {
            serde_json::Value::String(text) => text.clone(),
            other => other.to_string(),
        })
}

/// `logs/<stage>.validator-evidence.json` schema (design §5.2 Item 2): the
/// daemon's report is embedded VERBATIM (P1 — no re-shaping), so the evidence
/// artifact carries what the node actually said, not a re-derived summary.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ValidatorEvidence {
    schema_version: u32,
    stage: String,
    results: Vec<ValidatorEvidenceEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ValidatorEvidenceEntry {
    alias: String,
    op: String,
    passed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    report: Option<serde_json::Value>,
}

fn build_validator_evidence(
    stage: &str,
    records: &std::collections::HashMap<String, Vec<ValidatorResult>>,
) -> ValidatorEvidence {
    let mut results = Vec::new();
    for (alias, node_records) in records {
        for record in node_records {
            results.push(ValidatorEvidenceEntry {
                alias: alias.clone(),
                op: record.op.clone(),
                passed: record.passed,
                report: record.report.clone(),
            });
        }
    }
    ValidatorEvidence {
        schema_version: 1,
        stage: stage.to_owned(),
        results,
    }
}

impl OrchestrationStage for ValidateBaselineRuntimeStage {
    fn id(&self) -> StageId {
        StageId::ValidateBaselineRuntime
    }
    fn name(&self) -> &str {
        "validate_baseline_runtime"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::EnforceBaselineRuntime]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        use crate::vm_lab::DaemonProbeOp;

        const OPS: &[DaemonProbeOp] = &[
            DaemonProbeOp::RuntimeAcls,
            DaemonProbeOp::ServiceHardening,
            DaemonProbeOp::KeyCustody,
            DaemonProbeOp::Authenticode,
            DaemonProbeOp::MeshStatus,
            DaemonProbeOp::DnsFailclosed,
        ];

        let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();

        // Collect pass: gather all results before any mutation
        let all_results = crate::vm_lab::orchestrator::parallel::bounded_parallel_map_cancellable(
            &aliases,
            self.max_parallel_node_workers,
            &self.shutdown_flag,
            |alias| {
                let op_results: Vec<
                    Result<crate::vm_lab::orchestrator::error::ValidatorReport, String>,
                > = OPS
                    .iter()
                    .map(|&op| match ctx.adapters.get(alias.as_str()) {
                        Some(adapter) => adapter
                            .run_validator(op, probe_expectations(op).as_slice())
                            .map_err(|e| e.to_string()),
                        None => Err(format!("no adapter for '{alias}'")),
                    })
                    .collect();
                (alias.clone(), op_results)
            },
            |alias| {
                (
                    alias.clone(),
                    OPS.iter()
                        .map(|_| Err("cancelled before node work was admitted".to_owned()))
                        .collect(),
                )
            },
        );

        use std::collections::HashMap;

        let mut errors = Vec::new();
        // Record per-node, per-op results as machine-readable evidence so the
        // run report carries the actual validator detail rather than an empty
        // list. Written to report_dir and read back by build_live_lab_run_report.
        let mut records: HashMap<String, Vec<ValidatorResult>> = HashMap::new();
        for (alias, op_results) in all_results {
            let mut node_records: Vec<ValidatorResult> = Vec::new();
            for (op, r) in OPS.iter().zip(op_results) {
                // §5.2 Item 2: keep the daemon's parsed report verbatim (last
                // object wins when the output carried several). The verdict is
                // unchanged — only what is KEPT differs.
                let (passed, summary, report) = match &r {
                    Ok(report_out) if report_out.passed => (
                        true,
                        "passed".to_owned(),
                        report_out.reports.last().cloned(),
                    ),
                    Ok(report_out) => (
                        false,
                        "validator reported not passed".to_owned(),
                        report_out.reports.last().cloned(),
                    ),
                    Err(e) => (false, e.clone(), None),
                };
                // Generic drift surfacing: read the first `drift_reasons`
                // entry straight out of the kept report. No hard-coded drift
                // strings — whatever the daemon reports is what surfaces.
                let drift_note = report.as_ref().and_then(first_drift_reason);
                node_records.push(ValidatorResult {
                    op: format!("{op:?}"),
                    passed,
                    summary,
                    report,
                });
                match r {
                    Ok(report_out) if !report_out.passed => match drift_note {
                        Some(reason) => errors.push(format!(
                            "{alias}/{op:?}: validation not passed — drift: {reason}"
                        )),
                        None => errors.push(format!("{alias}/{op:?}: validation not passed")),
                    },
                    Err(e) => errors.push(format!("{alias}/{op:?}: {e}")),
                    Ok(_) => {}
                }
            }
            records.insert(alias, node_records);
        }

        // Best-effort: a write failure must not change the verdict (the actual
        // validation already happened above); it only means the report ships
        // without per-op detail, which is the prior behaviour.
        if let Ok(json) = serde_json::to_string_pretty(&records) {
            let path = ctx.report_dir.join("validator_results.json");
            let _ = std::fs::write(path, json);
        }

        // §5.2 Item 2 evidence artifact: per-node, per-op verdicts with the
        // daemon report embedded verbatim. Best-effort like the artifact above.
        let evidence = build_validator_evidence("validate_baseline_runtime", &records);
        let logs_dir = ctx.report_dir.join("logs");
        if std::fs::create_dir_all(&logs_dir).is_ok() {
            if let Ok(json) = serde_json::to_string_pretty(&evidence) {
                let _ = std::fs::write(
                    logs_dir.join("validate_baseline_runtime.validator-evidence.json"),
                    json,
                );
            }
        }

        if errors.is_empty() {
            StageOutcome::Passed
        } else {
            StageOutcome::Failed(errors.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn empty_assignments_passes() {
        let mut ctx = OrchestrationContext {
            assignments: vec![],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: std::env::temp_dir(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            reflexive_endpoints: HashMap::new(),
            lab_stun_servers: Vec::new(),
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
        };
        assert_eq!(
            ValidateBaselineRuntimeStage::new(
                1,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )
            .execute(&mut ctx),
            StageOutcome::Passed
        );
    }

    // ----- QH-39: the baseline mesh-status dispatch must assert something --

    use crate::vm_lab::{
        DaemonProbe, DaemonProbeOp, LinuxDaemonProbe, MacosDaemonProbe, WindowsDaemonProbe,
    };
    use std::path::Path;

    fn platform_probes() -> Vec<(&'static str, Box<dyn DaemonProbe>)> {
        vec![
            ("linux", Box::new(LinuxDaemonProbe)),
            ("windows", Box::new(WindowsDaemonProbe)),
            ("macos", Box::new(MacosDaemonProbe)),
        ]
    }

    fn dispatch_argv(probe: &dyn DaemonProbe, op: DaemonProbeOp) -> Vec<String> {
        probe
            .build_argv_with_extra_args(
                op,
                Path::new("/usr/local/bin/rustynetd"),
                probe_expectations(op).as_slice(),
            )
            .expect("probe must build argv")
    }

    /// THE test whose absence let the defect live: the rendered argv must
    /// carry the freshness bound, on every platform.
    ///
    /// Asserted on the argv the stage actually dispatches (probe + this
    /// stage's expectations), not by reading the constant — dropping the
    /// expectations from either half breaks this.
    #[test]
    fn mesh_status_dispatch_argv_carries_the_freshness_bound_on_every_platform() {
        for (label, probe) in platform_probes() {
            let argv = dispatch_argv(probe.as_ref(), DaemonProbeOp::MeshStatus);
            let pair = argv
                .windows(2)
                .position(|w| w[0] == "--max-age-seconds")
                .map(|i| argv[i + 1].clone());
            assert_eq!(
                pair.as_deref(),
                Some("180"),
                "{label} mesh-status dispatch must bound snapshot staleness: {argv:?}"
            );
        }
    }

    /// Shape is not enough: the bound must be SEMANTICALLY usable.
    ///
    /// A previous attempt's tests asserted only the argv's shape, so a
    /// meaningless bound (`86400`) would have passed them, and nothing tied
    /// the orchestrator's number to the cadence at which the daemon actually
    /// refreshes the snapshot. Both ends are pinned here, against the daemon's
    /// own constant rather than a copy of it.
    #[test]
    fn the_freshness_bound_is_sound_against_the_daemon_heartbeat_cadence() {
        let heartbeat = rustynetd::daemon::STATE_SNAPSHOT_HEARTBEAT_INTERVAL_SECS;
        let bound: u64 =
            crate::vm_lab::orchestrator::role_validation::mesh_status::SNAPSHOT_MAX_AGE_SECONDS
                .parse()
                .expect("the bound must be an integer the daemon's parser accepts");

        assert!(
            bound >= heartbeat * 3,
            "bound {bound}s must clear the {heartbeat}s heartbeat with margin or healthy nodes red"
        );
        assert!(
            bound <= 600,
            "bound {bound}s is too loose to detect a daemon that stopped refreshing the snapshot"
        );
    }

    /// `--no-fail-on-drift` STAYS, deliberately.
    ///
    /// It suppresses only the daemon's non-zero EXIT, not the drift itself:
    /// the report still carries `overall_ok=false` + `drift_reasons`, and the
    /// orchestrator takes its verdict from that JSON
    /// (`adapter/ssh.rs::validator_report_ok`). Dropping the flag would make
    /// `run_remote` turn a drifted node into an `AdapterError::Ssh` and throw
    /// the report away, so the stage would fail with a bare exit code instead
    /// of the reasons. Drift tolerance is not what made this check vacuous —
    /// the missing expectations were.
    #[test]
    fn mesh_status_dispatch_keeps_no_fail_on_drift_so_the_report_survives() {
        for (label, probe) in platform_probes() {
            let argv = dispatch_argv(probe.as_ref(), DaemonProbeOp::MeshStatus);
            assert!(
                argv.iter().any(|a| a == "--no-fail-on-drift"),
                "{label} must keep the exit-code suppression that preserves the JSON report: {argv:?}"
            );
        }
    }

    #[test]
    fn non_mesh_status_ops_dispatch_without_expectation_flags() {
        for op in [
            DaemonProbeOp::RuntimeAcls,
            DaemonProbeOp::ServiceHardening,
            DaemonProbeOp::KeyCustody,
            DaemonProbeOp::Authenticode,
            DaemonProbeOp::DnsFailclosed,
        ] {
            assert!(
                probe_expectations(op).is_empty(),
                "{op:?} takes no expectation flags today"
            );
        }
    }

    /// The extras widen an argv that two adapters join into a `sudo -n …`
    /// shell string, so a token that is not shell-safe must be rejected at
    /// the builder rather than reaching a remote shell.
    #[test]
    fn dispatch_argv_rejects_a_non_shell_safe_extra_argument() {
        for (label, probe) in platform_probes() {
            let err = probe
                .build_argv_with_extra_args(
                    DaemonProbeOp::MeshStatus,
                    Path::new("/usr/local/bin/rustynetd"),
                    &["180; rm -rf /".to_owned()],
                )
                .expect_err("an unsafe extra must be rejected");
            assert!(err.contains("not a shell-safe token"), "{label}: {err}");
        }
    }

    /// §5.2 Item 2: the validator-evidence artifact round-trips with the
    /// schema it promises — {schema_version:1, stage, results:[{alias, op,
    /// passed, report}]} — and the embedded daemon report survives VERBATIM
    /// (P1: no re-shaping).
    #[test]
    fn validator_evidence_artifact_round_trips_with_verbatim_report() {
        let daemon_report: serde_json::Value = serde_json::json!({
            "overall_ok": false,
            "drift_reasons": ["resolver drifted from signed zone"],
            "checks": { "dns": { "ok": false } }
        });
        let mut records = std::collections::HashMap::new();
        records.insert(
            "macos-utm-1".to_owned(),
            vec![
                ValidatorResult {
                    op: "DnsFailclosed".to_owned(),
                    passed: false,
                    summary: "validator reported not passed".to_owned(),
                    report: Some(daemon_report.clone()),
                },
                ValidatorResult {
                    op: "MeshStatus".to_owned(),
                    passed: true,
                    summary: "passed".to_owned(),
                    report: None,
                },
            ],
        );

        let evidence = build_validator_evidence("validate_baseline_runtime", &records);
        assert_eq!(evidence.schema_version, 1);
        assert_eq!(evidence.stage, "validate_baseline_runtime");
        assert_eq!(evidence.results.len(), 2);

        let json = serde_json::to_string_pretty(&evidence).expect("evidence must serialize");
        let round: ValidatorEvidence =
            serde_json::from_str(&json).expect("evidence must deserialize under its own schema");

        assert_eq!(round.schema_version, 1);
        assert_eq!(round.stage, "validate_baseline_runtime");
        let dns = round
            .results
            .iter()
            .find(|e| e.op == "DnsFailclosed")
            .expect("dns entry present");
        assert!(!dns.passed);
        assert_eq!(dns.alias, "macos-utm-1");
        // Verbatim: byte-equal to the report that went in, no re-shaping.
        assert_eq!(dns.report.as_ref(), Some(&daemon_report));

        let mesh = round
            .results
            .iter()
            .find(|e| e.op == "MeshStatus")
            .expect("mesh entry present");
        assert!(mesh.passed);
        assert!(mesh.report.is_none());
        // An absent report is OMITTED, not serialized as null — a consumer
        // must be able to distinguish "no report" from "empty report".
        assert!(
            !json.contains("\"report\": null"),
            "absent reports must be skipped, not null: {json}"
        );
    }

    /// §5.2 Item 2 generic drift surfacing: the failure message carries the
    /// daemon's own first drift reason, with no hard-coded drift strings.
    #[test]
    fn first_drift_reason_extracts_daemons_own_reason_verbatim() {
        let report: serde_json::Value = serde_json::json!({
            "overall_ok": true,
            "drift_reasons": ["resolver drifted", "second reason"]
        });
        assert_eq!(
            first_drift_reason(&report).as_deref(),
            Some("resolver drifted"),
            "first reason surfaces, verbatim"
        );

        // No drift_reasons / empty array / non-string first entry.
        assert_eq!(
            first_drift_reason(&serde_json::json!({ "overall_ok": true })),
            None
        );
        assert_eq!(
            first_drift_reason(&serde_json::json!({ "drift_reasons": [] })),
            None
        );
        // Non-string reasons render via their JSON form rather than dropping.
        assert_eq!(
            first_drift_reason(&serde_json::json!({ "drift_reasons": [7] })).as_deref(),
            Some("7")
        );
    }
}
