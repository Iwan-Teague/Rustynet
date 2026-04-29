#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{BundleKind, StageOutcome};
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct DistributeDnsZoneStage;

impl OrchestrationStage for DistributeDnsZoneStage {
    fn id(&self) -> StageId {
        StageId::DistributeDnsZone
    }
    fn name(&self) -> &str {
        "distribute_dns_zone"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::DistributeTraversal]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        use crate::vm_lab::orchestrator::stage::distribute_assignments::distribute_bundle_kind;
        distribute_bundle_kind(ctx, BundleKind::DnsZone, "rn-dns-zone", "dns-zone")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn no_exit_node_fails() {
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
        assert!(matches!(
            DistributeDnsZoneStage.execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
    }
}
