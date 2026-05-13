#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{StageOutcome, TrafficTestResult};
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct TrafficTestMatrixStage;

impl OrchestrationStage for TrafficTestMatrixStage {
    fn id(&self) -> StageId {
        StageId::TrafficTestMatrix
    }
    fn name(&self) -> &str {
        "traffic_test_matrix"
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

        // Collect mesh IPs from adapters for any node not yet in the map.
        // Always attempt collection rather than skipping when the map is
        // non-empty: collect_pubkeys may have populated it before daemon
        // startup, leaving some nodes (e.g. Windows) without an entry.
        let missing_aliases: Vec<String> = aliases
            .iter()
            .filter(|a| !ctx.mesh_ips.contains_key(a.as_str()))
            .cloned()
            .collect();
        if !missing_aliases.is_empty() {
            // Retry for up to 30 s: the WireGuard interface on a node that was
            // just started in EnforceBaselineRuntime may take a few seconds to
            // receive its IP assignment even after the SCM service is Running.
            let deadline =
                std::time::Instant::now() + std::time::Duration::from_secs(30);
            let mut remaining: Vec<String> = missing_aliases.clone();
            loop {
                let mut still_missing = Vec::new();
                for alias in &remaining {
                    match ctx
                        .adapters
                        .get(alias.as_str())
                        .map(|a| a.collect_mesh_ip())
                    {
                        Some(Ok(ip)) => {
                            ctx.mesh_ips.insert(alias.clone(), ip);
                        }
                        _ => still_missing.push(alias.clone()),
                    }
                }
                remaining = still_missing;
                if remaining.is_empty() || std::time::Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
        }

        if ctx.mesh_ips.is_empty() {
            return StageOutcome::Failed(
                "no mesh IPs available; cannot run traffic tests".to_string(),
            );
        }

        let mesh_ips = ctx.mesh_ips.clone();
        let mut errors = Vec::new();

        for src_alias in &aliases {
            // Positive tests: ping each peer
            for peer_alias in &aliases {
                if peer_alias == src_alias {
                    continue;
                }
                let peer_ip = match mesh_ips.get(peer_alias) {
                    Some(ip) => ip.clone(),
                    None => {
                        errors.push(format!("{src_alias}: no mesh IP for '{peer_alias}'"));
                        continue;
                    }
                };
                match ctx
                    .adapters
                    .get(src_alias.as_str())
                    .map(|a| a.ping_mesh_peer(&peer_ip))
                {
                    Some(Ok(TrafficTestResult::Reachable)) => {}
                    Some(Ok(TrafficTestResult::Blocked)) => {
                        errors.push(format!(
                            "{src_alias} → {peer_alias} ({peer_ip}): blocked (expected reachable)"
                        ));
                    }
                    Some(Ok(TrafficTestResult::Error(e))) => {
                        errors.push(format!("{src_alias} → {peer_alias} ({peer_ip}): {e}"));
                    }
                    Some(Err(e)) => errors.push(format!("{src_alias} → {peer_alias}: {e}")),
                    None => errors.push(format!("no adapter for '{src_alias}'")),
                }
            }

            // Negative test: confirm default-deny
            // TEST-NET-2 (RFC 5737) — never routable in real meshes
            let denied_ip = "198.51.100.1";
            match ctx
                .adapters
                .get(src_alias.as_str())
                .map(|a| a.probe_denied_peer(denied_ip))
            {
                Some(Ok(TrafficTestResult::Blocked)) | Some(Ok(TrafficTestResult::Error(_))) => {}
                Some(Ok(TrafficTestResult::Reachable)) => {
                    errors.push(format!(
                        "{src_alias}: default-deny VIOLATED — {denied_ip} was reachable"
                    ));
                }
                Some(Err(e)) => errors.push(format!("{src_alias}: probe_denied_peer error: {e}")),
                None => {} // no adapter: skip denied probe
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
    fn empty_assignments_no_mesh_ips_fails() {
        let mut ctx = OrchestrationContext {
            assignments: vec![],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: std::env::temp_dir(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            network_id: "net".to_string(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
        };
        // No assignments, no adapters, no mesh IPs → fail
        assert!(matches!(
            TrafficTestMatrixStage.execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
    }
}
