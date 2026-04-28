#![allow(dead_code)]
use std::collections::HashMap;
use std::path::PathBuf;

use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
use crate::vm_lab::orchestrator::error::{StageOutcome, WireguardPublicKey};
use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
use crate::vm_lab::orchestrator::source_archive::SourceArchive;
use crate::vm_lab::orchestrator::stage::StageId;

/// Shared state threaded through all orchestration stages.
pub struct OrchestrationContext {
    /// Role assignment for each node alias in this lab run.
    pub assignments: Vec<NodeRoleAssignment>,
    /// Per-alias adapter handles (populated before stage execution begins).
    pub adapters: HashMap<String, Box<dyn NodeAdapter>>,
    /// The source archive shipped to remote nodes.
    pub source_archive: Option<SourceArchive>,
    /// Directory for logs, JSON reports, and collected artifacts.
    pub report_dir: PathBuf,
    /// Accumulated per-stage outcomes.
    pub stage_outcomes: HashMap<StageId, StageOutcome>,
    /// Collected WireGuard public keys, keyed by node alias.
    pub collected_pubkeys: HashMap<String, WireguardPublicKey>,
    /// Mesh network identifier passed to the bootstrap env.
    pub network_id: String,
    /// Pre-generated node IDs, keyed by alias.
    /// Populated by the Preflight / PrepareSourceArchive stage before
    /// `install_daemon` runs. If absent for an alias, `install_daemon`
    /// falls back to `<alias>-bootstrap`.
    pub node_ids: HashMap<String, String>,
    /// CIDRs that SSH is allowed from (passed to bootstrap env as
    /// `SSH_ALLOW_CIDRS`). Empty string means no restriction at bootstrap.
    pub ssh_allow_cidrs: String,
}

impl OrchestrationContext {
    pub fn new(
        assignments: Vec<NodeRoleAssignment>,
        report_dir: PathBuf,
        network_id: String,
    ) -> Self {
        OrchestrationContext {
            assignments,
            adapters: HashMap::new(),
            source_archive: None,
            report_dir,
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            network_id,
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
        }
    }

    pub fn record_outcome(&mut self, stage: StageId, outcome: StageOutcome) {
        self.stage_outcomes.insert(stage, outcome);
    }

    pub fn outcome_of(&self, stage: &StageId) -> Option<&StageOutcome> {
        self.stage_outcomes.get(stage)
    }
}
