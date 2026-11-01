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
    // Controller-aware: UTM aliases are read from the discovery report; libvirt
    // aliases (which the UTM bundle-scan does not enumerate) are probed live
    // through the same observer at the same readiness bar. See mod.rs.
    let initial_readiness = selected_nodes_readiness_with_libvirt(
        initial_discovery.as_str(),
        selected_aliases,
        inventory_path,
        &discover_config,
    )?;
    let unready_aliases = not_execution_ready_aliases(&initial_readiness);
    // Controller-less SSH-only aliases discovery cannot report (never probed):
    // they have no start controller, so a restart can never apply to them.
    let not_reported_aliases = not_reported_by_discovery_aliases(&initial_readiness);
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
                dry_run_restart_detail(&unready_aliases, &not_reported_aliases),
                vec![initial_discovery_path],
            );
            emit_vm_lab_progress_outcome("vm-lab-orchestrate-live-lab", &restart_outcome);
            outcomes.push(restart_outcome);
            Ok(outcomes)
        }
        RestartUnreadyDecision::TrustInventorySkip => {
            eprintln!(
                "warning: --trust-inventory-ready set; skipping restart for aliases that are \
                 unready or not reported by discovery: {}",
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
                    return Err(restart_failure_message(
                        &unready_aliases,
                        &not_reported_aliases,
                        restart_path.as_path(),
                    ));
                }
            }

            let rediscovery = execute_ops_vm_lab_discover_local_utm(discover_config.clone())?;
            let rediscovery_path = orchestration_dir.join("discover_post_restart.json");
            write_orchestration_artifact(rediscovery_path.as_path(), rediscovery.as_str())?;
            let post_restart_readiness = selected_nodes_readiness_with_libvirt(
                rediscovery.as_str(),
                selected_aliases,
                inventory_path,
                &discover_config,
            )?;
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

/// Aliases the discovery report could not speak for: controller-less SSH-only
/// nodes come back unready with reason `not-reported-by-discovery` and were
/// never probed, so "unready" for them means "unknown", not "probed down".
fn not_reported_by_discovery_aliases(summary: &LocalUtmSelectedReadinessSummary) -> Vec<String> {
    summary
        .unready_entries
        .iter()
        .filter(|entry| {
            entry
                .reason_codes
                .iter()
                .any(|code| code == NOT_REPORTED_BY_DISCOVERY_REASON_CODE)
        })
        .map(|entry| entry.alias.clone())
        .collect()
}

/// Dry-run detail for the restart gate. Only aliases that have a start
/// controller "would be restarted"; a not-reported (controller-less) alias has
/// none, so a real run would fail on it unless `--trust-inventory-ready` is
/// passed — say that instead of promising a restart.
fn dry_run_restart_detail(unready_aliases: &[String], not_reported: &[String]) -> String {
    let restartable: Vec<&str> = unready_aliases
        .iter()
        .filter(|alias| !not_reported.contains(alias))
        .map(String::as_str)
        .collect();
    let mut detail = if restartable.is_empty() {
        "dry-run: no restart would run".to_owned()
    } else {
        format!("dry-run: would restart aliases {}", restartable.join(", "))
    };
    if !not_reported.is_empty() {
        detail.push_str(&format!(
            "; {} not reported by discovery (SSH-only, no start controller): cannot be \
             restarted, a real run fails on them unless --trust-inventory-ready is passed",
            not_reported.join(", ")
        ));
    }
    detail
}

/// Error for a failed readiness restart. When controller-less aliases are among
/// the unready ones the restart can only have failed because they have no start
/// controller, so tell the operator the way forward.
fn restart_failure_message(
    unready_aliases: &[String],
    not_reported: &[String],
    artifact: &Path,
) -> String {
    let mut message = format!(
        "Rust --node readiness gate failed restarting aliases {} (artifact: {})",
        unready_aliases.join(", "),
        artifact.display()
    );
    if !not_reported.is_empty() {
        message.push_str(&format!(
            "; {} cannot be restarted (SSH-only, no start controller): pass \
             --trust-inventory-ready for SSH-only nodes",
            not_reported.join(", ")
        ));
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(alias: &str, codes: &[&str]) -> LocalUtmSelectedReadinessEntry {
        LocalUtmSelectedReadinessEntry {
            alias: alias.to_owned(),
            reason_codes: codes.iter().map(|c| (*c).to_owned()).collect(),
        }
    }

    fn summary() -> LocalUtmSelectedReadinessSummary {
        LocalUtmSelectedReadinessSummary {
            ready_aliases: vec!["ok-1".to_owned()],
            unready_entries: vec![
                entry("utm-1", &["ssh-auth-rejected"]),
                entry("cloud-1", &[NOT_REPORTED_BY_DISCOVERY_REASON_CODE]),
            ],
        }
    }

    #[test]
    fn only_not_reported_entries_are_split_out() {
        assert_eq!(
            not_reported_by_discovery_aliases(&summary()),
            vec!["cloud-1".to_owned()]
        );
    }

    /// The dry-run text never promises a restart for a controller-less alias.
    /// Mutation caught: listing every unready alias under "would restart".
    #[test]
    fn dry_run_detail_does_not_promise_restart_for_controllerless_alias() {
        let unready = vec!["utm-1".to_owned(), "cloud-1".to_owned()];
        let not_reported = vec!["cloud-1".to_owned()];
        let detail = dry_run_restart_detail(&unready, &not_reported);
        assert!(detail.contains("would restart aliases utm-1"), "{detail}");
        assert!(
            !detail.contains("would restart aliases utm-1, cloud-1"),
            "{detail}"
        );
        assert!(
            detail.contains("cloud-1 not reported by discovery"),
            "{detail}"
        );
        assert!(detail.contains("--trust-inventory-ready"), "{detail}");

        // Only controller-less unready aliases: no restart claimed at all.
        let only = dry_run_restart_detail(&not_reported, &not_reported);
        assert!(!only.contains("would restart"), "{only}");
        assert!(only.contains("no restart would run"), "{only}");

        // No controller-less aliases: the historical text, unchanged.
        assert_eq!(
            dry_run_restart_detail(&unready[..1], &[]),
            "dry-run: would restart aliases utm-1"
        );
    }

    /// A failed restart that involved controller-less aliases names the flag
    /// to pass; one that did not keeps the historical text byte-for-byte.
    /// Mutation caught: dropping the hint, or adding it unconditionally.
    #[test]
    fn restart_failure_message_tells_operator_to_trust_inventory_for_ssh_only_nodes() {
        let artifact = Path::new("/r/orchestration/restart_unready_vms.txt");
        let with =
            restart_failure_message(&["cloud-1".to_owned()], &["cloud-1".to_owned()], artifact);
        assert!(
            with.starts_with(
                "Rust --node readiness gate failed restarting aliases cloud-1 \
                 (artifact: /r/orchestration/restart_unready_vms.txt)"
            ),
            "{with}"
        );
        assert!(
            with.contains("pass --trust-inventory-ready for SSH-only nodes"),
            "{with}"
        );
        assert_eq!(
            restart_failure_message(&["utm-1".to_owned()], &[], artifact),
            "Rust --node readiness gate failed restarting aliases utm-1 \
             (artifact: /r/orchestration/restart_unready_vms.txt)"
        );
    }
}
