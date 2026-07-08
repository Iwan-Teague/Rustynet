#![allow(dead_code)]
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
use crate::vm_lab::orchestrator::error::{StageOutcome, WireguardPublicKey};
use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
use crate::vm_lab::orchestrator::source_archive::SourceArchive;
use crate::vm_lab::orchestrator::stage::StageId;
use serde::{Deserialize, Serialize};

pub const ORCHESTRATION_CONTEXT_SCHEMA_VERSION: u64 = 2;

pub const ENV_ORCHESTRATOR_DIALECT: &str = "RUSTYNET_ORCHESTRATOR_DIALECT";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OrchestratorDialect {
    RustNative,
    LegacyBash,
}

impl OrchestratorDialect {
    pub fn as_str(&self) -> &'static str {
        match self {
            OrchestratorDialect::RustNative => "rust-native",
            OrchestratorDialect::LegacyBash => "legacy-bash",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedOrchestrationContext {
    schema_version: u64,
    assignments: Vec<NodeRoleAssignment>,
    node_ids: HashMap<String, String>,
    collected_pubkeys: HashMap<String, WireguardPublicKey>,
    membership_snapshot: Option<Vec<u8>>,
    mesh_ips: HashMap<String, String>,
    endpoints: HashMap<String, String>,
    network_id: String,
    #[serde(default)]
    ssh_allow_cidrs: String,
    #[serde(default)]
    orchestrator_dialect: Option<OrchestratorDialect>,
}

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
    /// Collected `WireGuard` public keys, keyed by node alias.
    pub collected_pubkeys: HashMap<String, WireguardPublicKey>,
    /// Mesh network identifier passed to the bootstrap env.
    pub network_id: String,
    /// Pre-generated node IDs, keyed by alias.
    /// Populated by the Preflight / `PrepareSourceArchive` stage before
    /// `install_daemon` runs. If absent for an alias, `install_daemon`
    /// falls back to `<alias>-bootstrap`.
    pub node_ids: HashMap<String, String>,
    /// CIDRs that SSH is allowed from (passed to bootstrap env as
    /// `SSH_ALLOW_CIDRS`). Empty string means no restriction at bootstrap.
    pub ssh_allow_cidrs: String,
    /// Membership snapshot bytes collected from exit node during `MembershipInit`.
    pub membership_snapshot: Option<Vec<u8>>,
    /// `WireGuard` mesh IPs per alias, collected during `CollectPubkeys`.
    pub mesh_ips: HashMap<String, String>,
    /// `WireGuard` endpoint (host:port) per alias, collected during `CollectPubkeys`.
    pub endpoints: HashMap<String, String>,
    /// Orchestrator engine that produced this run (set before stage execution).
    pub orchestrator_dialect: Option<OrchestratorDialect>,
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
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            orchestrator_dialect: None,
        }
    }

    pub fn set_dialect(&mut self, dialect: OrchestratorDialect) {
        self.orchestrator_dialect = Some(dialect);
    }

    pub fn record_outcome(&mut self, stage: StageId, outcome: StageOutcome) {
        self.stage_outcomes.insert(stage, outcome);
    }

    pub fn outcome_of(&self, stage: &StageId) -> Option<&StageOutcome> {
        self.stage_outcomes.get(stage)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let snapshot = PersistedOrchestrationContext {
            schema_version: ORCHESTRATION_CONTEXT_SCHEMA_VERSION,
            assignments: self.assignments.clone(),
            node_ids: self.node_ids.clone(),
            collected_pubkeys: self.collected_pubkeys.clone(),
            membership_snapshot: self.membership_snapshot.clone(),
            mesh_ips: self.mesh_ips.clone(),
            endpoints: self.endpoints.clone(),
            network_id: self.network_id.clone(),
            ssh_allow_cidrs: self.ssh_allow_cidrs.clone(),
            orchestrator_dialect: self.orchestrator_dialect,
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                format!(
                    "create orchestration context state dir '{}': {err}",
                    parent.display()
                )
            })?;
        }
        let bytes = serde_json::to_vec_pretty(&snapshot)
            .map_err(|err| format!("serialize orchestration context: {err}"))?;
        fs::write(path, bytes).map_err(|err| {
            format!(
                "write orchestration context state '{}': {err}",
                path.display()
            )
        })
    }

    pub fn load(path: &Path, report_dir: PathBuf) -> Result<Self, String> {
        let bytes = fs::read(path).map_err(|err| {
            format!(
                "load persisted orchestration context '{}': {err}",
                path.display()
            )
        })?;
        let snapshot: PersistedOrchestrationContext =
            serde_json::from_slice(&bytes).map_err(|err| {
                format!(
                    "parse persisted orchestration context '{}': {err}",
                    path.display()
                )
            })?;
        if snapshot.schema_version != ORCHESTRATION_CONTEXT_SCHEMA_VERSION {
            return Err(format!(
                "stale persisted orchestration context '{}': schema_version={} expected={}",
                path.display(),
                snapshot.schema_version,
                ORCHESTRATION_CONTEXT_SCHEMA_VERSION
            ));
        }
        Ok(OrchestrationContext {
            assignments: snapshot.assignments,
            adapters: HashMap::new(),
            source_archive: None,
            report_dir,
            stage_outcomes: HashMap::new(),
            collected_pubkeys: snapshot.collected_pubkeys,
            network_id: snapshot.network_id,
            node_ids: snapshot.node_ids,
            ssh_allow_cidrs: snapshot.ssh_allow_cidrs,
            membership_snapshot: snapshot.membership_snapshot,
            mesh_ips: snapshot.mesh_ips,
            endpoints: snapshot.endpoints,
            orchestrator_dialect: snapshot.orchestrator_dialect,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::role::NodeRole;
    use tempfile::tempdir;

    #[test]
    fn orchestration_context_save_load_round_trips_run_only_fields() {
        let tmp = tempdir().unwrap();
        let mut ctx = OrchestrationContext::new(
            vec![NodeRoleAssignment {
                alias: "exit".to_owned(),
                role: NodeRole::Exit,
            }],
            tmp.path().to_path_buf(),
            "net-1".to_owned(),
        );
        ctx.node_ids
            .insert("exit".to_owned(), "exit-node-id".to_owned());
        ctx.collected_pubkeys
            .insert("exit".to_owned(), WireguardPublicKey("a".repeat(64)));
        ctx.membership_snapshot = Some(b"snapshot".to_vec());
        ctx.mesh_ips
            .insert("exit".to_owned(), "100.64.0.1".to_owned());
        ctx.endpoints
            .insert("exit".to_owned(), "192.0.2.10:51820".to_owned());
        ctx.ssh_allow_cidrs = "192.0.2.0/24".to_owned();
        ctx.set_dialect(OrchestratorDialect::RustNative);

        let path = tmp.path().join("state/orchestration_context.json");
        ctx.save(path.as_path()).unwrap();
        let loaded = OrchestrationContext::load(path.as_path(), tmp.path().to_path_buf()).unwrap();

        assert_eq!(loaded.assignments, ctx.assignments);
        assert_eq!(loaded.node_ids, ctx.node_ids);
        assert_eq!(loaded.collected_pubkeys, ctx.collected_pubkeys);
        assert_eq!(loaded.membership_snapshot, ctx.membership_snapshot);
        assert_eq!(loaded.mesh_ips, ctx.mesh_ips);
        assert_eq!(loaded.endpoints, ctx.endpoints);
        assert_eq!(loaded.network_id, ctx.network_id);
        assert_eq!(loaded.ssh_allow_cidrs, ctx.ssh_allow_cidrs);
        assert_eq!(
            loaded.orchestrator_dialect,
            Some(OrchestratorDialect::RustNative)
        );
        assert!(loaded.adapters.is_empty());
        assert!(loaded.stage_outcomes.is_empty());
    }
}
