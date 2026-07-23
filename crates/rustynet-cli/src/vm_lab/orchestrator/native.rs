//! The Rust-native `--node` execution engine (executor + plan glue).
//!
//! Extracted from `vm_lab/mod.rs` (RNQ-15, behavior-preserving move): the
//! `execute_rust_native_orchestration` entry point the dispatcher routes to
//! when `--node` / `--run-only` is present, the stage-plan construction and
//! mode filtering, platform-selector role election, and the run network
//! profile record. Evidence emission lives in [`super::evidence`].

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::vm_lab::orchestrator;
use crate::vm_lab::orchestrator::evidence::{
    RustNativeFinalizeInputs, RustNativeStageRecorder, finalize_rust_native_run,
    validate_collected_os_version, validate_rust_native_reuse_evidence,
    write_rust_native_node_stage_plan, write_rust_native_report_state_initial,
};
use crate::vm_lab::{
    VmGuestPlatform, VmInventoryEntry, VmLabOrchestrateLiveLabConfig, collected_at_utc_now,
    ensure_local_regular_file_path, ensure_report_dir_fresh, file_sha256_hex,
    finalize_vm_lab_orchestration_result_with_inventory, load_inventory, network_audit,
    network_profile, normalize_manifest_path, resolve_absolute_path, write_orchestration_artifact,
};

pub(crate) fn execute_rust_native_orchestration(
    config: VmLabOrchestrateLiveLabConfig,
) -> Result<String, String> {
    use orchestrator::adapter::factory::node_adapter_for;
    use orchestrator::connection::NodeConnection;
    use orchestrator::context::OrchestrationContext;
    use orchestrator::context::OrchestrationContextBinding;
    use orchestrator::context::OrchestratorDialect;
    use orchestrator::error::StageOutcome;
    use orchestrator::runner::StageObserver;
    use orchestrator::runner::StateMachineRunner;
    use orchestrator::stage::OrchestrationStage;

    // Capture scalar config while `config` is intact (fields below are consumed
    // by value). The Rust-path manifest selectors are built later from the
    // resolved topology, so the audit snapshot reflects only what this plan
    // actually honors.
    let dry_run = config.dry_run;
    let skip_live_suite = config.skip_linux_live_suite;
    let enable_chaos_suite = config.enable_chaos_suite;
    let enable_negative_control = config.enable_negative_control;
    let enable_cross_network_suite = !config.skip_cross_network;
    let cross_network_options = orchestrator::stage::cross_network::CrossNetworkOptions::from_cli(
        enable_cross_network_suite,
        config.cross_network_nat_profiles.as_deref(),
        config.cross_network_required_nat_profiles.as_deref(),
        config.cross_network_impairment_profile.as_deref(),
        config.cross_network_substrate.as_deref(),
    )?;
    let setup_only = config.setup_only;
    let run_only = config.run_only;
    // RNQ-07: a nonzero per-stage deadline is now enforced (real cancellable
    // process-isolated stages), not rejected. Zero = no deadline (unchanged).
    let stage_timeout_secs = config.stage_timeout_secs;

    let resume_from_stage = config.resume_from.clone().filter(|s| !s.is_empty());
    let rerun_stage = config.rerun_stage.clone().filter(|s| !s.is_empty());
    let iterate_mode = resume_from_stage.is_some() || rerun_stage.is_some();

    if run_only && iterate_mode {
        return Err("--run-only and --resume-from/--rerun-stage are mutually exclusive".to_owned());
    }
    if resume_from_stage.is_some() && rerun_stage.is_some() {
        return Err("--resume-from and --rerun-stage are mutually exclusive".to_owned());
    }
    if let Some(ref stage) = resume_from_stage
        && !orchestrator::stage::StageId::ALL
            .iter()
            .any(|s| s.as_str() == stage.as_str())
    {
        return Err(format!(
            "--resume-from stage '{stage}' is not a Rust-native stage; valid stages: {}",
            orchestrator::stage::StageId::ALL
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    } else if let Some(ref stage) = rerun_stage
        && !orchestrator::stage::StageId::ALL
            .iter()
            .any(|s| s.as_str() == stage.as_str())
    {
        return Err(format!(
            "--rerun-stage stage '{stage}' is not a Rust-native stage; valid stages: {}",
            orchestrator::stage::StageId::ALL
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let known_hosts = config
        .known_hosts_path
        .clone()
        .ok_or_else(|| "--known-hosts-file is required when --node flags are present".to_owned())?;
    ensure_local_regular_file_path(config.ssh_identity_file.as_path(), "SSH identity file")?;
    ensure_local_regular_file_path(known_hosts.as_path(), "SSH known-hosts file")?;

    let inventory_path = resolve_absolute_path(config.inventory_path.as_path())?;
    let inventory = load_inventory(&inventory_path)?;

    let report_dir = resolve_absolute_path(config.report_dir.as_path())?;
    if run_only {
        if !report_dir.is_dir() {
            return Err(format!(
                "--run-only requires an existing setup report directory: {}",
                report_dir.display()
            ));
        }
    } else if iterate_mode {
        if !report_dir.is_dir() {
            return Err(format!(
                "--resume-from / --rerun-stage requires an existing report directory: {}",
                report_dir.display()
            ));
        }
        let stages_tsv = report_dir.join("state/stages.tsv");
        if !stages_tsv.is_file() {
            return Err(format!(
                "no previous run evidence found at {} (state/stages.tsv missing); \
                 --resume-from / --rerun-stage requires a completed prior run",
                report_dir.display()
            ));
        }
    } else {
        ensure_report_dir_fresh(report_dir.as_path(), "vm-lab-orchestrate-live-lab")?;
    }
    fs::create_dir_all(report_dir.as_path()).map_err(|err| {
        format!(
            "create report directory failed ({}): {err}",
            report_dir.display()
        )
    })?;

    // The run's network profile is resolved and recorded (or, on resume,
    // digest-verified against the manifests) before anything else runs;
    // profile drift after launch fails closed (rulebook §15.4).
    let network_profile_record = ensure_orchestration_network_profile_record(
        report_dir.as_path(),
        inventory_path.as_path(),
        config.network_profile.as_deref(),
    )?;
    eprintln!(
        "network profile: {} digest={} (derived={}, enforced={})",
        network_profile_record.id,
        network_profile_record.digest,
        network_profile_record.derived,
        network_profile_record.enforced
    );

    // Install cancellation before readiness can update inventory or restart a
    // VM. Registration failure is fatal: default SIGTERM handling would bypass
    // the runner's always-run cleanup contract.
    let shutdown_flag = orchestrator::diagnostics::register_shutdown_handlers()?;

    // Capture run-start timing for run_summary.json (Bucket 2 evidence parity).
    let run_started_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let run_started_utc = collected_at_utc_now();

    let context_path = report_dir.join("state/orchestration_context.json");
    let context_binding = || -> Result<OrchestrationContextBinding, String> {
        Ok(OrchestrationContextBinding {
            report_dir: normalize_manifest_path(report_dir.as_path()),
            inventory_sha256: file_sha256_hex(inventory_path.as_path())?,
            source_mode: config
                .source_mode
                .as_deref()
                .unwrap_or("working-tree")
                .to_owned(),
            repo_ref: config.repo_ref.clone(),
        })
    };
    let mut ctx = if run_only || iterate_mode {
        let loaded = OrchestrationContext::load_bound(
            context_path.as_path(),
            report_dir.clone(),
            &context_binding()?,
        )?;
        if loaded.assignments.is_empty() {
            return Err(format!(
                "persisted orchestration context '{}' contains no node assignments",
                context_path.display()
            ));
        }
        if !config.node_assignments.is_empty() && config.node_assignments != loaded.assignments {
            return Err(format!(
                "--run-only --node assignments do not match persisted context at {}; omit --node or pass the same aliases/roles",
                context_path.display()
            ));
        }
        loaded
    } else {
        let network_id = format!(
            "rustynet-lab-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );
        OrchestrationContext::new(
            config.node_assignments.clone(),
            report_dir.clone(),
            network_id,
        )
    };
    // Set the dialect signal so any downstream tool can determine which
    // orchestrator engine produced this run (Bucket 4 dialect-awareness).
    ctx.set_dialect(OrchestratorDialect::RustNative);
    if let Some(cidrs) = config.orchestrate_ssh_allow_cidrs.as_deref() {
        let trimmed = cidrs.trim();
        if !trimmed.is_empty() {
            ctx.ssh_allow_cidrs = trimmed.to_owned();
        }
    }

    // Augment node_assignments from platform selectors (--exit-platform,
    // --relay-platform, etc.) so a mac/win role cell runs live even when the
    // operator omits the explicit --node <alias>:<role> pair. Each selector
    // picks the first unassigned inventory entry whose platform matches.
    augment_assignments_from_platform_selectors(
        &mut ctx,
        &inventory,
        config.exit_platform.as_deref(),
        config.relay_platform.as_deref(),
        config.anchor_platform.as_deref(),
        config.admin_platform.as_deref(),
        config.blind_exit_platform.as_deref(),
    )?;

    // Collect node hosts first so we can auto-derive ssh_allow_cidrs when not
    // provided. This mirrors the bash orchestrator's auto-detection behaviour.
    let node_entries: Vec<(
        &crate::vm_lab::VmInventoryEntry,
        &crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment,
    )> = ctx
        .assignments
        .iter()
        .map(|assignment| {
            inventory
                .iter()
                .find(|e| e.alias == assignment.alias)
                .map(|entry| (entry, assignment))
                .ok_or_else(|| {
                    format!(
                        "alias '{}' not found in inventory ({})",
                        assignment.alias,
                        inventory_path.display()
                    )
                })
        })
        .collect::<Result<Vec<_>, String>>()?;
    for (entry, assignment) in &node_entries {
        let platform = entry.platform.unwrap_or(VmGuestPlatform::Linux);
        if !assignment.role.is_lab_assignable_for_platform(&platform) {
            return Err(format!(
                "role '{}' is not lab-assignable on platform {platform:?}",
                assignment.role
            ));
        }
        assignment
            .role
            .daemon_node_role_for_platform(&platform)
            .map_err(|err| format!("role mapping for '{}': {err}", assignment.alias))?;
        assignment
            .role
            .product_capabilities_for_platform(&platform)
            .map_err(|err| format!("capability mapping for '{}': {err}", assignment.alias))?;
    }

    // Resolve the plan and validate any prior evidence before readiness can
    // restart a guest or the current invocation can overwrite prior evidence.
    let source_mode = orchestrator::stage::source_archive::parse_archive_source_mode(
        config.source_mode.as_deref(),
    )?;
    let rebuild_only = match config.rebuild_nodes.as_ref() {
        Some(rebuild) => {
            for alias in rebuild {
                if !ctx.assignments.iter().any(|a| &a.alias == alias) {
                    return Err(format!(
                        "--rebuild-nodes alias '{alias}' is not one of the --node aliases for this run"
                    ));
                }
            }
            Some(rebuild.clone())
        }
        None => None,
    };
    let stages = filter_rust_native_stages_for_mode(
        build_rust_native_orchestration_stages(
            rebuild_only.clone(),
            source_mode,
            skip_live_suite,
            enable_chaos_suite,
            enable_negative_control,
            config.skip_soak,
            cross_network_options,
            config.max_parallel_node_workers.unwrap_or(1),
            std::sync::Arc::clone(&shutdown_flag),
        ),
        setup_only,
        run_only,
    );

    // RNQ-07: wrap every stage in a real cancellable per-stage deadline. A
    // stage that exceeds `stage_timeout_secs` is cancelled, its subprocess
    // tree is reaped, and it records a terminal fail-closed `timed_out`
    // outcome (never a pass; the run fails). `stage_timeout_secs == 0` leaves
    // the plan untouched (no deadline). The wrapper forwards every plan-facing
    // trait method, so plan validation, topo order, skip-cascade, evidence
    // manifests, and always-run cleanup semantics are unchanged. The shared
    // `timeout_ledger` lets the evidence observer relabel a cancelled stage's
    // terminal row `timed_out` instead of a generic `fail`; deadlines are
    // additive and never touch the SIGTERM/SIGINT shutdown flag above.
    let stage_timeout_policy =
        orchestrator::diagnostics::StageDeadlinePolicy::for_timeout_secs(stage_timeout_secs);
    let subprocess_tree: std::sync::Arc<dyn orchestrator::diagnostics::SubprocessTreeControl> =
        std::sync::Arc::new(
            orchestrator::diagnostics::OrchestratorSubprocessTree::for_current_process(),
        );
    let timeout_ledger =
        std::sync::Arc::new(orchestrator::diagnostics::StageTimeoutLedger::default());
    let stages = orchestrator::diagnostics::apply_stage_deadlines(
        stages,
        stage_timeout_policy,
        &subprocess_tree,
        &timeout_ledger,
    );

    let setup_stage_ids = rust_native_setup_stage_ids();
    let plan_stage_ids: Vec<orchestrator::stage::StageId> = stages.iter().map(|s| s.id()).collect();
    let reuse_binding: Option<(Vec<orchestrator::stage::StageId>, String)> = if run_only {
        Some((
            setup_stage_ids.clone(),
            validate_rust_native_reuse_evidence(report_dir.as_path(), &setup_stage_ids)?,
        ))
    } else if let Some(ref target) = resume_from_stage {
        let target_id = orchestrator::stage::StageId::try_from(target.as_str())?;
        let pos = plan_stage_ids
            .iter()
            .position(|id| id == &target_id)
            .ok_or_else(|| format!("--resume-from stage '{target}' is not in the active plan"))?;
        let reused_ids = plan_stage_ids[..pos].to_vec();
        let digest = validate_rust_native_reuse_evidence(report_dir.as_path(), &reused_ids)?;
        Some((reused_ids, digest))
    } else if let Some(ref target) = rerun_stage {
        let target_id = orchestrator::stage::StageId::try_from(target.as_str())?;
        let pos = plan_stage_ids
            .iter()
            .position(|id| id == &target_id)
            .ok_or_else(|| format!("--rerun-stage stage '{target}' is not in the active plan"))?;
        let reused_ids = plan_stage_ids[..pos].to_vec();
        let digest = validate_rust_native_reuse_evidence(report_dir.as_path(), &reused_ids)?;
        Some((reused_ids, digest))
    } else {
        None
    };
    let selected_aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();
    // Evidence state must be writable before readiness can mutate inventory or
    // restart a guest. A run that cannot record its lifecycle does not start.
    write_rust_native_report_state_initial(
        report_dir.as_path(),
        config.source_mode.as_deref().unwrap_or("working-tree"),
        config.repo_ref.as_deref(),
    )?;
    let readiness_outcomes = orchestrator::readiness::run(
        &config,
        inventory_path.as_path(),
        &selected_aliases,
        report_dir.as_path(),
    )?;

    // Snapshot (alias, target, role) now for the run_summary nodes.tsv (Bucket 2);
    // node_id is filled from ctx.node_ids after the run populates it. Owned
    // strings so no borrow of `node_entries`/`inventory` lingers.
    let node_targets: Vec<(String, String, String, String)> = node_entries
        .iter()
        .map(|(entry, assignment)| {
            let target = entry
                .last_known_ip
                .as_deref()
                .unwrap_or(entry.ssh_target.as_str())
                .to_owned();
            let platform =
                format!("{:?}", entry.platform.unwrap_or(VmGuestPlatform::Linux)).to_lowercase();
            (
                assignment.alias.clone(),
                target,
                assignment.role.as_str().to_owned(),
                platform,
            )
        })
        .collect();

    // Auto-derive /24 ssh_allow_cidrs from node underlay IPs when not set.
    if ctx.ssh_allow_cidrs.is_empty() {
        use std::net::Ipv4Addr;
        use std::str::FromStr;
        let mut derived: Vec<String> = node_entries
            .iter()
            .filter_map(|(entry, _)| {
                let host = entry
                    .last_known_ip
                    .as_deref()
                    .unwrap_or(entry.ssh_target.as_str());
                // Strip optional user@ prefix from ssh_target.
                let ip_str = host.split('@').next_back().unwrap_or(host);
                Ipv4Addr::from_str(ip_str).ok().map(|ip| {
                    let o = ip.octets();
                    format!("{}.{}.{}.0/24", o[0], o[1], o[2])
                })
            })
            .collect();
        derived.sort();
        derived.dedup();
        if !derived.is_empty() {
            ctx.ssh_allow_cidrs = derived.join(",");
        }
    }

    for (entry, assignment) in &node_entries {
        let host = entry
            .last_known_ip
            .as_deref()
            .unwrap_or(entry.ssh_target.as_str())
            .to_owned();

        let platform = entry.platform.unwrap_or(VmGuestPlatform::Linux);
        if !assignment.role.is_lab_assignable_for_platform(&platform) {
            return Err(format!(
                "role '{}' is not lab-assignable on platform {platform:?}; Windows Exit is lab-assignable for evidence generation only, but unsupported platforms remain fail-closed",
                assignment.role
            ));
        }

        let conn = NodeConnection::ssh(
            host.clone(),
            config.ssh_port,
            entry.ssh_user.clone(),
            config.ssh_identity_file.clone(),
            known_hosts.clone(),
            entry.ssh_password.clone(),
        )
        .map_err(|err| {
            format!(
                "build SSH connection for alias '{}' ({}): {err}",
                assignment.alias, host
            )
        })?;

        let adapter = node_adapter_for(
            assignment.alias.clone(),
            platform,
            conn,
            entry.rustynet_src_dir.clone(),
        )
        .map_err(|err| {
            format!(
                "create adapter for alias '{}' (platform {platform:?}): {err}",
                assignment.alias
            )
        })?;

        ctx.adapters.insert(assignment.alias.clone(), adapter);
    }

    // Collect per-node OS version strings for nodes.tsv evidence. This must be a
    // real, attributable distro+version: the probe retries transient SSH, and a
    // bare platform placeholder ("linux"/"macos"/"windows") is rejected here and
    // now. Previously a transient first-connection SSH failure degraded silently
    // to the placeholder, which the run-matrix finalizer then refused as
    // Linux-umbrella evidence — silently dropping the ENTIRE matrix append so
    // even a green run left no §10.9 row (ledger 2026-07-11). Fail loud, early,
    // and attributably instead. Unsupported-by-design mobile adapters do not
    // assert attributable OS evidence, so they are exempt from the hard check.
    let mut os_versions: std::collections::HashMap<String, String> =
        std::collections::HashMap::with_capacity(ctx.adapters.len());
    for (alias, adapter) in &ctx.adapters {
        let version = adapter.collect_os_version();
        validate_collected_os_version(adapter.platform(), alias, &version)?;
        os_versions.insert(alias.clone(), version);
    }

    // Build the manifest audit snapshot from this run's resolved topology and
    // only the selectors the Rust plan honors. The `--node` plan now honors
    // chaos, cross-network, soak, and skip-linux-live-suite; bash-only platform
    // election selectors remain inactive. wants_macos/windows come from the real
    // `--node` guest platforms, not the ignored `*_platform` flags.
    let manifest_selectors = crate::live_lab_stage_registry::TargetSelectors {
        wants_macos: node_entries
            .iter()
            .any(|(entry, _)| entry.platform == Some(VmGuestPlatform::Macos)),
        wants_windows: node_entries
            .iter()
            .any(|(entry, _)| entry.platform == Some(VmGuestPlatform::Windows)),
        macos_promote_exit: false,
        exit_platform: String::new(),
        relay_platform: String::new(),
        anchor_platform: String::new(),
        admin_platform: String::new(),
        blind_exit_platform: String::new(),
        role_switch_platform: String::new(),
        skip_linux_live_suite: skip_live_suite,
        chaos_suite: enable_chaos_suite && !skip_live_suite,
        cross_network_suite: enable_cross_network_suite && !skip_live_suite,
        soak_suite: !config.skip_soak && !skip_live_suite,
        local_gate_suite: false,
        negative_control_suite: enable_negative_control && !skip_live_suite,
    };

    // Finding 1/4 (recorder-first): emit the run-scoped stage manifest that
    // reflects THIS run's actual plan — the Rust state-machine dialect enabled
    // + barrier-eligible, the bash dialect/sidecars not-planned — BEFORE any
    // stage runs, so every downstream consumer reads the plan from the report
    // dir. Capture the plan names now, since StateMachineRunner::new moves
    // `stages`.
    let plan_names: std::collections::HashSet<String> = stages
        .iter()
        .map(|stage| stage.id().as_str().to_owned())
        .collect();
    // Record THIS run's node→role topology in the manifest so consumers (the
    // monitor) render live roles from the current run instead of inferring them
    // from the previous finalized matrix row (emit-don't-infer).
    let manifest_node_assignments: Vec<crate::live_lab_stage_manifest::ManifestNodeAssignment> =
        ctx.assignments
            .iter()
            .map(|a| crate::live_lab_stage_manifest::ManifestNodeAssignment {
                alias: a.alias.clone(),
                role: a.role.as_str().to_owned(),
            })
            .collect();
    crate::live_lab_stage_manifest::ensure_stage_manifest_with_plan(
        report_dir.as_path(),
        "vm-lab-orchestrate-live-lab",
        if setup_only {
            "setup_only"
        } else if run_only {
            "run_only"
        } else {
            "full"
        },
        &manifest_selectors,
        &plan_names,
        &manifest_node_assignments,
    )?;
    write_rust_native_node_stage_plan(report_dir.as_path(), &stages)?;

    // --dry-run is a WIRING CHECK: the manifest above already records the
    // resolved plan (what WOULD run) and the adapters/topology were validated
    // when they were constructed. A dry run must NOT execute any stage or
    // bootstrap the guests. Return the plan summary now. (Previously the Rust
    // `--node` path ignored dry_run and ran a full real bootstrap — a foot-gun
    // for anyone using dry_run as a fast wiring check.)
    if dry_run {
        let node_count = ctx.adapters.len();
        let stage_count = plan_names.len();
        // Remove the report dir this dry run created (only the manifest lives
        // there) so a subsequent REAL run to the SAME --report-dir is not blocked
        // by ensure_report_dir_fresh's empty-dir precondition. The dry run's value
        // is this summary; the guests were never touched. Safe: this run created
        // the dir (ensure_report_dir_fresh required it fresh/absent).
        if let Err(err) = fs::remove_dir_all(report_dir.as_path()) {
            eprintln!(
                "warning: dry-run cleanup of {} failed: {err}",
                report_dir.display()
            );
        }
        return Ok(format!(
            "dry-run (rust --node): {node_count} node(s), {stage_count} planned stage(s); \
             topology + adapters validated, no stages executed (report dir not persisted).",
        ));
    }

    let mut runner = StateMachineRunner::new(stages)?.with_shutdown_flag(shutdown_flag.clone());
    if let Some((reused_ids, evidence_sha256)) = reuse_binding {
        runner = runner.with_reused_skips(reused_ids, evidence_sha256);
    }
    if let Some(ref target) = rerun_stage {
        let target_id = orchestrator::stage::StageId::try_from(target.as_str())?;
        let pos = plan_stage_ids
            .iter()
            .position(|id| id == &target_id)
            .ok_or_else(|| format!("--rerun-stage stage '{target}' is not in the active plan"))?;
        runner = runner.with_explicit_skips(plan_stage_ids.iter().skip(pos + 1).cloned());
    }
    // Realtime: the observer upserts a `running` stages.tsv row at each stage
    // start and its terminal row at finish, so the monitor reads active-stage
    // + outcomes directly instead of inferring them.
    let recorder = RustNativeStageRecorder {
        report_dir: report_dir.as_path(),
        started_at: std::cell::RefCell::new(std::collections::HashMap::new()),
        errors: std::cell::RefCell::new(Vec::new()),
    };
    let pre_cleanup_diagnostics = |hook_ctx: &orchestrator::context::OrchestrationContext,
                                   prior: &[(orchestrator::stage::StageId, StageOutcome)]|
     -> Result<(), String> {
        if !prior
            .iter()
            .any(|(_, outcome)| matches!(outcome, StageOutcome::Failed(_)))
        {
            return Ok(());
        }
        orchestrator::diagnostics::collect_failure_diagnostics(
            hook_ctx,
            !config.skip_diagnose_on_failure,
            config.collect_artifacts_on_failure,
        )
    };
    // RNQ-07: the timeout-aware observer wraps the realtime recorder so a stage
    // the deadline cancelled records its terminal row as `timed_out` (closed
    // taxonomy) instead of the generic `fail` the recorder would derive from
    // `StageOutcome::Failed`. With no deadline the ledger is empty and every
    // event delegates verbatim to the inner recorder.
    let timeout_recorder = orchestrator::diagnostics::TimeoutAwareStageRecorder::new(
        &recorder,
        std::sync::Arc::clone(&timeout_ledger),
    );
    let mut results = runner.run_with_observer_and_pre_cleanup_hook(
        &mut ctx,
        &timeout_recorder,
        Some(&pre_cleanup_diagnostics),
    )?;
    if shutdown_flag.load(std::sync::atomic::Ordering::Acquire) {
        eprintln!(
            "rust orchestrator: received SIGTERM/SIGINT — {} stage(s) skipped; \
             always-run cleanup stage(s) were still executed",
            results
                .iter()
                .filter(|(_, o)| {
                    matches!(
                        o,
                        StageOutcome::Skipped | StageOutcome::NotRun | StageOutcome::Reused { .. }
                    )
                })
                .count()
        );
    }
    if setup_only
        && results
            .iter()
            .any(|(_, outcome)| matches!(outcome, StageOutcome::Failed(_)))
    {
        // setup-only success intentionally leaves the mesh up for a later
        // run-only pass. Failure still tears down guest residue: stranded
        // killswitch or exit-NAT state is release-blocking.
        let cleanup =
            orchestrator::stage::final_cleanup::FinalCleanupStage::new(rebuild_only.clone());
        let cleanup_id = orchestrator::stage::StageId::Cleanup;
        recorder.stage_started(&cleanup_id);
        let diagnostic_error = orchestrator::diagnostics::collect_failure_diagnostics(
            &ctx,
            !config.skip_diagnose_on_failure,
            config.collect_artifacts_on_failure,
        )
        .err();
        let cleanup_outcome = match (cleanup.execute(&mut ctx), diagnostic_error) {
            (StageOutcome::Failed(cleanup_error), Some(diagnostic_error)) => {
                StageOutcome::Failed(format!(
                    "pre-cleanup diagnostics failed: {diagnostic_error}; cleanup failed: {cleanup_error}"
                ))
            }
            (_, Some(diagnostic_error)) => StageOutcome::Failed(format!(
                "pre-cleanup diagnostics failed: {diagnostic_error}; cleanup completed"
            )),
            (outcome, None) => outcome,
        };
        recorder.stage_finished(&cleanup_id, &cleanup_outcome);
        ctx.record_outcome(cleanup_id.clone(), cleanup_outcome.clone());
        results.push((cleanup_id, cleanup_outcome));
    }
    if setup_only
        && !results
            .iter()
            .any(|(_, outcome)| matches!(outcome, StageOutcome::Failed(_)))
        && let Err(err) = ctx.save_bound(context_path.as_path(), &context_binding()?)
    {
        let cleanup =
            orchestrator::stage::final_cleanup::FinalCleanupStage::new(rebuild_only.clone());
        let cleanup_id = orchestrator::stage::StageId::Cleanup;
        recorder.stage_started(&cleanup_id);
        let cleanup_outcome = cleanup.execute(&mut ctx);
        recorder.stage_finished(&cleanup_id, &cleanup_outcome);
        ctx.record_outcome(cleanup_id, cleanup_outcome.clone());
        return Err(format!(
            "persist setup-only orchestration context failed; cleanup outcome={cleanup_outcome:?}: {err}"
        ));
    }

    let passed = results
        .iter()
        .filter(|(_, o)| matches!(o, StageOutcome::Passed))
        .count();
    let failed = results
        .iter()
        .filter(|(_, o)| matches!(o, StageOutcome::Failed(_)))
        .count();
    let skipped = results
        .iter()
        .filter(|(_, o)| {
            matches!(
                o,
                StageOutcome::Skipped | StageOutcome::NotRun | StageOutcome::Reused { .. }
            )
        })
        .count();

    eprintln!(
        "rust orchestrator: {} node(s), {} stage(s); passed={passed} failed={failed} \
         skipped={skipped}; parity_input: {}",
        ctx.assignments.len(),
        results.len(),
        report_dir.join("parity_input.json").display()
    );

    // RNQ-05: finalize this run's evidence as ONE transaction owned by
    // `finalize_rust_native_run` — run summary, failure digest, parity
    // snapshot, artifact completeness, context persist, reuse seal, the
    // fail-closed gate, the matrix append, the report-dir durability barrier,
    // and the commit marker STRICTLY LAST. The inline sequence this replaces
    // wrote `run_passed=true` BEFORE the matrix append and demoted on a
    // discarded Result — a crash in that window left a durable pass marker
    // with no matrix row. The transaction (with its per-writer
    // fault-injection tests) is now the single finalization path.
    let mut prior_evidence_errors = recorder.take_errors();
    // A full run persists its context inside the transaction (sealed into the
    // reuse digest); `--setup-only` persisted it above and `--run-only`
    // loaded it, so neither carries a binding here. A binding that cannot be
    // built is an evidence error: the run demotes rather than sealing
    // evidence that omits the context.
    let context_binding_for_finalize = if !setup_only && !run_only {
        match context_binding() {
            Ok(binding) => Some(binding),
            Err(err) => {
                prior_evidence_errors
                    .push(format!("build orchestration context binding failed: {err}"));
                None
            }
        }
    } else {
        None
    };

    let orchestration_dir = report_dir.join("orchestration");
    finalize_rust_native_run(
        RustNativeFinalizeInputs {
            ctx: &ctx,
            results: &results,
            node_targets: &node_targets,
            os_versions: &os_versions,
            readiness_outcomes,
            context_binding: context_binding_for_finalize,
            prior_evidence_errors,
            run_started_unix,
            run_started_utc: run_started_utc.as_str(),
            source_mode: config.source_mode.as_deref().unwrap_or("working-tree"),
            repo_ref: config.repo_ref.as_deref(),
            skip_live_suite,
            skip_soak: config.skip_soak,
            skip_cross_network: config.skip_cross_network,
        },
        |vm_lab_outcomes| {
            finalize_vm_lab_orchestration_result_with_inventory(
                "vm-lab-orchestrate-live-lab",
                report_dir.as_path(),
                orchestration_dir.as_path(),
                Some(inventory_path.as_path()),
                vm_lab_outcomes,
                Vec::new(),
                Vec::new(),
            )
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn build_rust_native_orchestration_stages(
    rebuild_only: Option<Vec<String>>,
    source_mode: orchestrator::stage::source_archive::ArchiveSourceMode,
    skip_live_suite: bool,
    enable_chaos_suite: bool,
    enable_negative_control: bool,
    skip_soak: bool,
    cross_network: orchestrator::stage::cross_network::CrossNetworkOptions,
    max_parallel_node_workers: usize,
    shutdown_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Vec<Box<dyn orchestrator::stage::OrchestrationStage>> {
    orchestrator::plan::PlanBuilder::new()
        .with_rebuild_only(rebuild_only)
        .with_source_mode(source_mode)
        .with_skip_live_suite(skip_live_suite)
        .with_enable_chaos_suite(enable_chaos_suite)
        .with_enable_negative_control(enable_negative_control)
        .with_skip_soak(skip_soak)
        .with_cross_network_options(cross_network)
        .with_max_parallel_node_workers(max_parallel_node_workers)
        .with_shutdown_flag(shutdown_flag)
        .build()
}

pub(crate) fn rust_native_setup_stage_ids() -> Vec<orchestrator::stage::StageId> {
    // Derived from the stage catalog's Setup suite tag (RNQ-16), minus
    // `admin_issue` and `blind_exit` — the two Setup-suite stages the proven
    // `--setup-only` contract has always omitted (pinned by the
    // setup-only-plan mode tests in `vm_lab/mod.rs`).
    use orchestrator::stage::{StageId, StageSuite};
    StageId::ALL
        .iter()
        .filter(|id| {
            id.suite() == StageSuite::Setup
                && !matches!(id, StageId::AdminIssue | StageId::BlindExit)
        })
        .cloned()
        .collect()
}

/// Augment `ctx.assignments` from platform selectors so `--exit-platform macos`
/// etc. actually assign the matching guest to the requested role (F8-6).
fn augment_assignments_from_platform_selectors(
    ctx: &mut orchestrator::context::OrchestrationContext,
    inventory: &[VmInventoryEntry],
    exit_platform: Option<&str>,
    relay_platform: Option<&str>,
    anchor_platform: Option<&str>,
    admin_platform: Option<&str>,
    blind_exit_platform: Option<&str>,
) -> Result<(), String> {
    use orchestrator::role::NodeRole;
    let selectors: &[(&str, NodeRole, Option<&str>)] = &[
        ("exit", NodeRole::Exit, exit_platform),
        ("relay", NodeRole::Relay, relay_platform),
        ("anchor", NodeRole::Anchor, anchor_platform),
        ("admin", NodeRole::Admin, admin_platform),
        ("blind_exit", NodeRole::BlindExit, blind_exit_platform),
    ];
    for (selector_name, role, platform_opt) in selectors {
        let Some(platform_str) = platform_opt else {
            continue;
        };
        let target_platform = VmGuestPlatform::parse(platform_str)
            .map_err(|e| format!("--{selector_name}-platform: {e}"))?;
        let assigned_aliases: std::collections::HashSet<&str> =
            ctx.assignments.iter().map(|a| a.alias.as_str()).collect();
        let Some(entry) = inventory.iter().find(|e| {
            e.platform == Some(target_platform) && !assigned_aliases.contains(e.alias.as_str())
        }) else {
            return Err(format!(
                "--{selector_name}-platform={platform_str}: no unassigned inventory entry found for that platform"
            ));
        };
        ctx.assignments
            .push(orchestrator::role_assignment::NodeRoleAssignment {
                alias: entry.alias.clone(),
                role: role.clone(),
            });
    }
    Ok(())
}

fn filter_rust_native_stages_for_mode(
    mut stages: Vec<Box<dyn orchestrator::stage::OrchestrationStage>>,
    setup_only: bool,
    run_only: bool,
) -> Vec<Box<dyn orchestrator::stage::OrchestrationStage>> {
    use orchestrator::stage::StageSuite;
    if setup_only {
        // Setup-only stops after the last Setup-suite stage (leaves the mesh
        // up on success; the runner still cleans up on failure).
        let setup = rust_native_setup_stage_ids();
        stages.retain(|stage| setup.contains(&stage.id()));
    } else if run_only {
        // Run-only reloads persisted setup state and runs the live suites
        // against the existing mesh — every suite EXCEPT the final teardown
        // (the mesh stays up). Setup stages are retained so the runner can
        // inject them as Passed dependencies. Suite tags are the RNQ-16
        // authority; this can no longer drift from the catalog.
        stages.retain(|stage| stage.id().suite() != StageSuite::Cleanup);
    }
    stages
}

#[cfg(test)]
pub(crate) fn rust_native_orchestration_stage_ids() -> Vec<orchestrator::stage::StageId> {
    build_rust_native_orchestration_stages(
        None,
        orchestrator::stage::source_archive::ArchiveSourceMode::Head,
        false,
        false,
        false,
        false,
        orchestrator::stage::cross_network::CrossNetworkOptions::default(),
        1,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )
    .iter()
    .map(|stage| stage.id())
    .collect()
}

#[cfg(test)]
pub(crate) fn rust_native_orchestration_stage_ids_for_mode(
    setup_only: bool,
    run_only: bool,
) -> Vec<orchestrator::stage::StageId> {
    filter_rust_native_stages_for_mode(
        build_rust_native_orchestration_stages(
            None,
            orchestrator::stage::source_archive::ArchiveSourceMode::Head,
            false,
            false,
            false,
            false,
            orchestrator::stage::cross_network::CrossNetworkOptions::default(),
            1,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        ),
        setup_only,
        run_only,
    )
    .iter()
    .map(|stage| stage.id())
    .collect()
}

const NETWORK_PROFILE_RECORD_RELATIVE_PATH: &str = "orchestration/network_profile.json";
const NETWORK_EVIDENCE_RELATIVE_PATH: &str = "orchestration/vm_network_evidence.json";

/// Resolve and immutably record the run's network profile (rulebook §15.4),
/// then capture a read-only network audit into the report directory.
///
/// - First launch: resolves `--network-profile` (or the unique derived
///   management-plane default), runs the Slice A audit against it, writes
///   `orchestration/network_profile.json` + `orchestration/vm_network_evidence.json`.
///   An EXPLICIT profile is enforced: an audit that is not `pass` stops the
///   run before deployment or signed-state mutation. The derived default
///   records observations without blocking (the fleet migration to the
///   dual-plane target is approval-gated; see the connectivity ledger).
/// - Resume/run-only: the existing record is digest-verified against the
///   on-repo manifests; profile drift after launch fails closed.
pub(crate) fn ensure_orchestration_network_profile_record(
    report_dir: &Path,
    inventory_path: &Path,
    explicit_profile: Option<&str>,
) -> Result<network_profile::OrchestrationNetworkProfileRecord, String> {
    let record_path = report_dir.join(NETWORK_PROFILE_RECORD_RELATIVE_PATH);
    let profile_dir = PathBuf::from(network_profile::DEFAULT_NETWORK_PROFILE_DIR);
    if record_path.is_file() {
        let raw = fs::read_to_string(&record_path).map_err(|err| {
            format!(
                "read network profile record failed ({}): {err}",
                record_path.display()
            )
        })?;
        let record: network_profile::OrchestrationNetworkProfileRecord = serde_json::from_str(&raw)
            .map_err(|err| {
                format!(
                    "parse network profile record failed ({}): {err}",
                    record_path.display()
                )
            })?;
        record.verify_against_manifests(&profile_dir)?;
        if let Some(explicit) = explicit_profile
            && explicit != record.id
        {
            return Err(format!(
                "this run is bound to network profile {} (recorded at launch); it cannot be switched to {explicit:?} mid-run",
                record.id
            ));
        }
        return Ok(record);
    }
    let (profile, derived) =
        network_profile::resolve_orchestration_network_profile(explicit_profile, &profile_dir)?;
    let evidence_path = report_dir.join(NETWORK_EVIDENCE_RELATIVE_PATH);
    let audit_result =
        network_audit::execute_ops_vm_lab_network_audit(network_audit::VmLabNetworkAuditConfig {
            inventory_path: Some(inventory_path.to_path_buf()),
            profile_dir: Some(profile_dir.clone()),
            profile: Some(profile.id.as_str().to_owned()),
            utmctl_path: None,
            ssh_identity_file: None,
            known_hosts_path: None,
            output_path: Some(evidence_path.clone()),
            skip_guests: true,
            repo_root: None,
        });
    let evidence_recorded = match &audit_result {
        Ok(_) => Some(NETWORK_EVIDENCE_RELATIVE_PATH.to_owned()),
        Err(_) => None,
    };
    let record = network_profile::OrchestrationNetworkProfileRecord::from_profile(
        &profile,
        derived,
        evidence_recorded,
    );
    if record.enforced {
        if let Err(err) = &audit_result {
            return Err(format!(
                "--network-profile {} launch audit failed; the run stops before deployment: {err}",
                record.id
            ));
        }
        let evidence_raw = fs::read_to_string(&evidence_path).map_err(|err| {
            format!(
                "read network evidence failed ({}): {err}",
                evidence_path.display()
            )
        })?;
        let evidence: Value = serde_json::from_str(&evidence_raw)
            .map_err(|err| format!("parse network evidence failed: {err}"))?;
        let status = evidence
            .get("overall_status")
            .and_then(Value::as_str)
            .unwrap_or("fail");
        if status != "pass" {
            return Err(format!(
                "--network-profile {} preflight status is {status}; the observed fleet does not satisfy the profile and the run stops before deployment (evidence: {})",
                record.id,
                evidence_path.display()
            ));
        }
    } else if let Err(err) = &audit_result {
        eprintln!("warning: launch network audit failed (recorded without evidence): {err}");
    }
    let serialized = serde_json::to_string_pretty(&record)
        .map_err(|err| format!("serialize network profile record failed: {err}"))?;
    write_orchestration_artifact(&record_path, &serialized)?;
    Ok(record)
}
