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

        // Always re-collect mesh IPs fresh here.  The values cached during
        // collect_pubkeys were gathered before bundle distribution and
        // enforce_runtime, so daemons had auto_tunnel_enforce=false and the
        // WireGuard interface IP was not yet set to the deterministic
        // assignment.  After enforce_runtime the daemon applies the assignment
        // bundle and sets the correct unique IP.
        //
        // Retry for up to 60 s to allow the WireGuard interface to settle and
        // to detect IP collisions (duplicate IPs across nodes indicate the
        // assignment bundle has not yet been applied).
        {
            let deadline =
                std::time::Instant::now() + std::time::Duration::from_secs(60);
            loop {
                let mut fresh: std::collections::HashMap<String, String> =
                    std::collections::HashMap::new();
                let mut any_error = false;
                for alias in &aliases {
                    match ctx.adapters.get(alias.as_str()).map(|a| a.collect_mesh_ip()) {
                        Some(Ok(ip)) => {
                            fresh.insert(alias.clone(), ip);
                        }
                        _ => {
                            any_error = true;
                        }
                    }
                }
                // Collision: two different aliases mapped to the same IP means
                // the assignment bundle has not yet updated the interface.
                let unique_count: std::collections::HashSet<String> =
                    fresh.values().cloned().collect();
                let has_collision = unique_count.len() < fresh.len();
                let has_missing = any_error || fresh.len() < aliases.len();
                // Accept results or keep retrying until deadline.
                if (!has_collision && !has_missing) || std::time::Instant::now() >= deadline {
                    // Replace stale cached entries with fresh data.  Stale
                    // collect_pubkeys entries (pre-enforce IP values) must not
                    // survive into the traffic test; clear the map first so any
                    // node that failed collection here does not retain a stale IP.
                    ctx.mesh_ips.clear();
                    for (alias, ip) in fresh {
                        ctx.mesh_ips.insert(alias, ip);
                    }
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
