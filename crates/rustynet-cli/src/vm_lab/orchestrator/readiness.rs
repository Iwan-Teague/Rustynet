use std::fs;
use std::path::Path;

use crate::vm_lab::*;

pub(in crate::vm_lab) fn run(
    config: &VmLabOrchestrateLiveLabConfig,
    inventory_path: &Path,
    selected_aliases: &[String],
    report_dir: &Path,
) -> Result<Vec<VmLabStageOutcome>, String> {
    let orchestration_dir = report_dir.join("orchestration");
    fs::create_dir_all(orchestration_dir.as_path()).map_err(|err| {
        format!(
            "create rust readiness orchestration dir '{}': {err}",
            orchestration_dir.display()
        )
    })?;

    let mut outcomes = Vec::new();
    if config.dry_run {
        let dry_discovery = stage_outcome(
            "discover_local_utm",
            VmLabStageStatus::Skipped,
            format!(
                "dry-run: would discover and probe aliases {}",
                selected_aliases.join(", ")
            ),
            vec![],
        );
        emit_vm_lab_progress_outcome("vm-lab-orchestrate-live-lab", &dry_discovery);
        outcomes.push(dry_discovery);
        return Ok(outcomes);
    }
    let discovery_timeout = timeout_or_default(
        config.discovery_timeout_secs,
        DEFAULT_UTM_IP_DISCOVERY_TIMEOUT_SECS,
    )
    .as_secs();
    let ready_timeout = timeout_or_default(
        config.ready_timeout_secs,
        DEFAULT_RESTART_READY_TIMEOUT_SECS,
    )
    .as_secs();
    let discover_config = VmLabDiscoverLocalUtmConfig {
        inventory_path: Some(inventory_path.to_path_buf()),
        utm_documents_root: config.utm_documents_root.clone(),
        utmctl_path: config.utmctl_path.clone(),
        ssh_identity_file: Some(config.ssh_identity_file.clone()),
        known_hosts_path: config.known_hosts_path.clone(),
        ssh_port: config.ssh_port,
        timeout_secs: discovery_timeout,
        update_inventory_live_ips: true,
        report_dir: None,
    };

    let initial_discovery = execute_ops_vm_lab_discover_local_utm(discover_config.clone())?;
    let initial_discovery_path = orchestration_dir.join("discover_initial.json");
    write_orchestration_artifact(initial_discovery_path.as_path(), initial_discovery.as_str())?;
    let initial_readiness =
        selected_local_utm_readiness_from_report(initial_discovery.as_str(), selected_aliases)?;
    let unready_aliases = not_execution_ready_aliases(&initial_readiness);
    let discovery_outcome = stage_outcome(
        "discover_local_utm",
        VmLabStageStatus::Pass,
        format!(
            "selected aliases readiness: {}",
            render_selected_local_utm_readiness(&initial_readiness)
        ),
        vec![initial_discovery_path.clone()],
    );
    emit_vm_lab_progress_outcome("vm-lab-orchestrate-live-lab", &discovery_outcome);
    outcomes.push(discovery_outcome);

    match decide_restart_unready(
        unready_aliases.is_empty(),
        config.dry_run,
        config.trust_inventory_ready,
    ) {
        RestartUnreadyDecision::AllReady => Ok(outcomes),
        RestartUnreadyDecision::DryRunSkip => {
            let restart_outcome = stage_outcome(
                "restart_unready_vms",
                VmLabStageStatus::Skipped,
                format!(
                    "dry-run: would restart aliases {}",
                    unready_aliases.join(", ")
                ),
                vec![initial_discovery_path],
            );
            emit_vm_lab_progress_outcome("vm-lab-orchestrate-live-lab", &restart_outcome);
            outcomes.push(restart_outcome);
            Ok(outcomes)
        }
        RestartUnreadyDecision::TrustInventorySkip => {
            eprintln!(
                "warning: --trust-inventory-ready set; skipping restart for probed-unready aliases: {}",
                unready_aliases.join(", ")
            );
            let restart_outcome = stage_outcome(
                "restart_unready_vms",
                VmLabStageStatus::Skipped,
                format!(
                    "skipped by --trust-inventory-ready: bootstrap/live SSH will fail loudly if unreachable: {}",
                    unready_aliases.join(", ")
                ),
                vec![initial_discovery_path],
            );
            emit_vm_lab_progress_outcome("vm-lab-orchestrate-live-lab", &restart_outcome);
            outcomes.push(restart_outcome);
            Ok(outcomes)
        }
        RestartUnreadyDecision::Restart => {
            let restart_output = execute_ops_vm_lab_restart(VmLabRestartConfig {
                inventory_path: inventory_path.to_path_buf(),
                vm_aliases: unready_aliases.clone(),
                raw_targets: Vec::new(),
                select_all: false,
                utmctl_path: config
                    .utmctl_path
                    .clone()
                    .unwrap_or_else(default_utmctl_path),
                service: None,
                wait_ready: true,
                ssh_port: config.ssh_port,
                ready_timeout_secs: ready_timeout,
                ssh_user: None,
                ssh_identity_file: Some(config.ssh_identity_file.clone()),
                known_hosts_path: config.known_hosts_path.clone(),
                timeout_secs: config.timeout_secs,
                json_output: false,
                report_dir: Some(orchestration_dir.clone()),
            });
            let restart_path = orchestration_dir.join("restart_unready_vms.txt");
            match restart_output {
                Ok(output) => {
                    write_orchestration_artifact(restart_path.as_path(), output.as_str())?;
                    let restart_outcome = stage_outcome(
                        "restart_unready_vms",
                        VmLabStageStatus::Pass,
                        format!("restarted aliases {}", unready_aliases.join(", ")),
                        vec![restart_path.clone()],
                    );
                    emit_vm_lab_progress_outcome("vm-lab-orchestrate-live-lab", &restart_outcome);
                    outcomes.push(restart_outcome);
                }
                Err(err) => {
                    write_orchestration_artifact(restart_path.as_path(), err.as_str())?;
                    let restart_outcome = stage_outcome(
                        "restart_unready_vms",
                        VmLabStageStatus::Fail,
                        format!("restart failed for aliases {}", unready_aliases.join(", ")),
                        vec![initial_discovery_path, restart_path.clone()],
                    );
                    emit_vm_lab_progress_outcome("vm-lab-orchestrate-live-lab", &restart_outcome);
                    outcomes.push(restart_outcome);
                    return Err(format!(
                        "Rust --node readiness gate failed restarting aliases {} (artifact: {})",
                        unready_aliases.join(", "),
                        restart_path.display()
                    ));
                }
            }

            let rediscovery = execute_ops_vm_lab_discover_local_utm(discover_config)?;
            let rediscovery_path = orchestration_dir.join("discover_post_restart.json");
            write_orchestration_artifact(rediscovery_path.as_path(), rediscovery.as_str())?;
            let post_restart_readiness =
                selected_local_utm_readiness_from_report(rediscovery.as_str(), selected_aliases)?;
            let still_unready = not_execution_ready_aliases(&post_restart_readiness);
            let rediscovery_status = if still_unready.is_empty() {
                VmLabStageStatus::Pass
            } else {
                VmLabStageStatus::Fail
            };
            let rediscovery_outcome = stage_outcome(
                "rediscover_local_utm",
                rediscovery_status.clone(),
                format!(
                    "selected aliases readiness after restart: {}",
                    render_selected_local_utm_readiness(&post_restart_readiness)
                ),
                vec![rediscovery_path.clone()],
            );
            emit_vm_lab_progress_outcome("vm-lab-orchestrate-live-lab", &rediscovery_outcome);
            outcomes.push(rediscovery_outcome);
            if rediscovery_status == VmLabStageStatus::Fail {
                return Err(format!(
                    "Rust --node readiness gate failed after recovery; still unready: {} (artifact: {})",
                    still_unready.join(", "),
                    rediscovery_path.display()
                ));
            }
            Ok(outcomes)
        }
    }
}
