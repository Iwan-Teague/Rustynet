#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct CollectPubkeysStage;

impl OrchestrationStage for CollectPubkeysStage {
    fn id(&self) -> StageId {
        StageId::CollectPubkeys
    }
    fn name(&self) -> &str {
        "collect_pubkeys"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::BootstrapHosts]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        use crate::vm_lab::orchestrator::error::WireguardPublicKey;

        let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();

        struct NodeData {
            alias: String,
            pubkey: Result<WireguardPublicKey, String>,
            node_id: Result<String, String>,
            mesh_ip: Option<String>,
            endpoint: String,
        }

        // Collect pass: no ctx mutation
        let data: Vec<NodeData> = aliases
            .iter()
            .map(|alias| {
                let (pubkey, node_id, mesh_ip, endpoint) = match ctx.adapters.get(alias.as_str()) {
                    Some(adapter) => {
                        let pk = adapter
                            .collect_wireguard_public_key()
                            .map_err(|e| e.to_string());
                        let nid = adapter
                            .collect_node_id()
                            .map(|n| n.0)
                            .map_err(|e| e.to_string());
                        let mip = adapter.collect_mesh_ip().ok();
                        let ep = adapter.endpoint();
                        (pk, nid, mip, ep)
                    }
                    None => (
                        Err(format!("no adapter for '{alias}'")),
                        Err(format!("no adapter for '{alias}'")),
                        None,
                        "0.0.0.0:51820".to_owned(),
                    ),
                };
                NodeData {
                    alias: alias.clone(),
                    pubkey,
                    node_id,
                    mesh_ip,
                    endpoint,
                }
            })
            .collect();

        // Mutate pass: adapter borrows no longer live
        let mut errors = Vec::new();
        for d in data {
            match d.pubkey {
                Ok(pk) => {
                    ctx.collected_pubkeys.insert(d.alias.clone(), pk);
                }
                Err(e) => errors.push(format!("{}: pubkey: {e}", d.alias)),
            }
            match d.node_id {
                Ok(nid) => {
                    ctx.node_ids.insert(d.alias.clone(), nid);
                }
                Err(e) => errors.push(format!("{}: node_id: {e}", d.alias)),
            }
            if let Some(ip) = d.mesh_ip {
                ctx.mesh_ips.insert(d.alias.clone(), ip);
            }
            ctx.endpoints.insert(d.alias.clone(), d.endpoint);
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
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
        };
        assert_eq!(CollectPubkeysStage.execute(&mut ctx), StageOutcome::Passed);
    }
}
