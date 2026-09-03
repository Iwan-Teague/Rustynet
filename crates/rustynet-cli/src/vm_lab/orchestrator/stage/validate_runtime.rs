#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
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
/// NOT emitted on macOS `DnsFailclosed` either — the `--posture` expectation,
/// that is, is now REQUIRED there. The daemon's `macos-dns-failclosed-check`
/// defaults to `fully_protected` when no `--posture` is given
/// (`rustynetd/src/main.rs:2524`), but a plain-client macOS node correctly
/// holds only the ScopedResolverOnly posture (scoped /etc/resolver/rustynet,
/// general DNS untouched, NO pf DNS-block floor), so the un-argued dispatch
/// failed every plain-client macOS node with
/// "macos-utm-1/DnsFailclosed: validation not passed". The expected posture
/// is therefore THREADED from the node's PLANNED role — the same derivation
/// the dedicated `dns_failclosed_validation` stage uses
/// (`expected_dns_posture_for_role`) — never inferred from observed state.
/// Exit / blind-exit nodes keep `fully_protected`: threading their posture
/// down to `scoped_resolver_only` would WEAKEN the check (a missing pf
/// DNS-block floor on an exit node must still fail).
///
/// The flag is emitted ONLY for the macOS adapter: the daemon's
/// `linux-dns-failclosed-check` / `windows-dns-failclosed-check` argument
/// parsers reject unknown flags fail-closed (`rustynetd/src/main.rs:2547`),
/// so appending `--posture` there would turn a healthy check into an argv
/// error.
fn probe_expectations(
    op: crate::vm_lab::DaemonProbeOp,
    platform: crate::vm_lab::VmGuestPlatform,
    role: &NodeRole,
) -> Vec<String> {
    use crate::vm_lab::DaemonProbeOp;
    use crate::vm_lab::VmGuestPlatform;
    use crate::vm_lab::orchestrator::role_validation::mesh_status::SNAPSHOT_MAX_AGE_SECONDS;
    use crate::vm_lab::orchestrator::stage::dns_failclosed_validation::expected_dns_posture_for_role;

    match (op, platform) {
        (DaemonProbeOp::MeshStatus, _) => vec![
            "--max-age-seconds".to_owned(),
            SNAPSHOT_MAX_AGE_SECONDS.to_owned(),
        ],
        (DaemonProbeOp::DnsFailclosed, VmGuestPlatform::Macos) => vec![
            "--posture".to_owned(),
            expected_dns_posture_for_role(role).to_owned(),
        ],
        _ => Vec::new(),
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
        // The planned role per alias, for expectation derivation that depends
        // on it (the macOS DNS-failclosed posture). Aliases above are built
        // from these same assignments, so every lookup below hits.
        let roles: std::collections::HashMap<String, NodeRole> = ctx
            .assignments
            .iter()
            .map(|a| (a.alias.clone(), a.role.clone()))
            .collect();

        // Collect pass: gather all results before any mutation
        let all_results = crate::vm_lab::orchestrator::parallel::bounded_parallel_map_cancellable(
            &aliases,
            self.max_parallel_node_workers,
            &self.shutdown_flag,
            |alias| {
                let op_results: Vec<Result<bool, String>> = OPS
                    .iter()
                    .map(|&op| match ctx.adapters.get(alias.as_str()) {
                        Some(adapter) => {
                            let role = roles
                                .get(alias.as_str())
                                .expect("alias was collected from ctx.assignments");
                            let expectations = probe_expectations(op, adapter.platform(), role);
                            adapter
                                .run_validator(op, expectations.as_slice())
                                .map(|r| r.passed)
                                .map_err(|e| e.to_string())
                        }
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

        use crate::vm_lab::orchestrator::report::ValidatorResult;
        use std::collections::HashMap;

        let mut errors = Vec::new();
        // Record per-node, per-op results as machine-readable evidence so the
        // run report carries the actual validator detail rather than an empty
        // list. Written to report_dir and read back by build_live_lab_run_report.
        let mut records: HashMap<String, Vec<ValidatorResult>> = HashMap::new();
        for (alias, op_results) in all_results {
            let mut node_records: Vec<ValidatorResult> = Vec::new();
            for (op, r) in OPS.iter().zip(op_results) {
                let (passed, summary) = match &r {
                    Ok(true) => (true, "passed".to_owned()),
                    Ok(false) => (false, "validator reported not passed".to_owned()),
                    Err(e) => (false, e.clone()),
                };
                node_records.push(ValidatorResult {
                    op: format!("{op:?}"),
                    passed,
                    summary,
                });
                match r {
                    Ok(false) => errors.push(format!("{alias}/{op:?}: validation not passed")),
                    Err(e) => errors.push(format!("{alias}/{op:?}: {e}")),
                    Ok(true) => {}
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

    use crate::vm_lab::orchestrator::role::NodeRole;
    use crate::vm_lab::{
        DaemonProbe, DaemonProbeOp, LinuxDaemonProbe, MacosDaemonProbe, VmGuestPlatform,
        WindowsDaemonProbe,
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
                probe_expectations(op, VmGuestPlatform::Linux, &NodeRole::Client).as_slice(),
            )
            .expect("probe must build argv")
    }

    fn posture_flag_in(argv: &[String]) -> Option<&String> {
        argv.windows(2)
            .position(|w| w[0] == "--posture")
            .map(|i| &argv[i + 1])
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
        ] {
            assert!(
                probe_expectations(op, VmGuestPlatform::Macos, &NodeRole::Client).is_empty(),
                "{op:?} takes no expectation flags today"
            );
        }
    }

    /// The macOS DnsFailclosed dispatch must thread the expected posture from
    /// the node's PLANNED role: a plain-client node gets the scoped-resolver
    /// posture it actually holds (the daemon check otherwise defaults to
    /// `fully_protected` and reds every healthy client), while exit-class
    /// roles keep the full posture — scoping an exit node would WEAKEN its
    /// check, so the exit mapping is pinned to `fully_protected` here.
    #[test]
    fn macos_dns_failclosed_dispatch_threads_posture_from_the_planned_role() {
        let scoped = [
            NodeRole::Client,
            NodeRole::Anchor,
            NodeRole::Admin,
            NodeRole::Relay,
            NodeRole::Entry,
            NodeRole::Aux,
            NodeRole::Extra,
            NodeRole::Custom("client".to_owned()),
        ];
        for role in scoped {
            let argv = MacosDaemonProbe
                .build_argv_with_extra_args(
                    DaemonProbeOp::DnsFailclosed,
                    Path::new("/usr/local/bin/rustynetd"),
                    probe_expectations(DaemonProbeOp::DnsFailclosed, VmGuestPlatform::Macos, &role)
                        .as_slice(),
                )
                .expect("macos probe must build argv");
            assert_eq!(
                posture_flag_in(&argv),
                Some(&"scoped_resolver_only".to_owned()),
                "{role:?} is a plain mesh node: expected the scoped-resolver posture, argv {argv:?}"
            );
        }

        let full = [
            NodeRole::Exit,
            NodeRole::BlindExit,
            NodeRole::Custom("exit".to_owned()),
            NodeRole::Custom("blind_exit".to_owned()),
        ];
        for role in full {
            let argv = MacosDaemonProbe
                .build_argv_with_extra_args(
                    DaemonProbeOp::DnsFailclosed,
                    Path::new("/usr/local/bin/rustynetd"),
                    probe_expectations(DaemonProbeOp::DnsFailclosed, VmGuestPlatform::Macos, &role)
                        .as_slice(),
                )
                .expect("macos probe must build argv");
            assert_eq!(
                posture_flag_in(&argv),
                Some(&"fully_protected".to_owned()),
                "{role:?} carries the machine's traffic: the full fail-closed check must NOT be scoped, argv {argv:?}"
            );
        }
    }

    /// The `--posture` flag is macOS-only: the daemon's
    /// `linux-dns-failclosed-check` / `windows-dns-failclosed-check` argument
    /// parsers reject unknown flags fail-closed, so appending the flag there
    /// would turn a healthy node's check into an argv error.
    #[test]
    fn dns_failclosed_posture_flag_stays_off_non_macos_adapters() {
        for (label, probe) in platform_probes() {
            if label == "macos" {
                continue;
            }
            for role in [NodeRole::Client, NodeRole::Exit] {
                let argv = probe
                    .build_argv_with_extra_args(
                        DaemonProbeOp::DnsFailclosed,
                        Path::new("/usr/local/bin/rustynetd"),
                        probe_expectations(
                            DaemonProbeOp::DnsFailclosed,
                            VmGuestPlatform::Linux,
                            &role,
                        )
                        .as_slice(),
                    )
                    .expect("probe must build argv");
                assert!(
                    posture_flag_in(&argv).is_none(),
                    "{label} dns-failclosed check must not receive --posture, argv {argv:?}"
                );
            }
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
}
