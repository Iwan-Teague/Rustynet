#![allow(dead_code)]
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
use crate::vm_lab::orchestrator::error::{GossipIdentity, StageOutcome, WireguardPublicKey};
use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
use crate::vm_lab::orchestrator::source_archive::SourceArchive;
use crate::vm_lab::orchestrator::stage::StageId;
use serde::{Deserialize, Serialize};

// v5: added `substrate_record` (topology-level cross-network substrate seam).
// A v4 snapshot predates the substrate seam; rejecting it as stale is the
// fail-closed choice (re-run setup rather than resume with unknown overlay
// provenance).
// v6: added `reflexive_endpoints` (per-alias server-reflexive STUN endpoints
// collected during `CollectPubkeys` and consumed by traversal bundle
// emission). A v5 snapshot predates cross-NAT STUN threading; rejecting it as
// stale is the fail-closed choice (re-run setup so reflexive endpoints are
// actually collected under the configured STUN servers rather than resumed
// without them).
pub const ORCHESTRATION_CONTEXT_SCHEMA_VERSION: u64 = 6;

pub const ENV_ORCHESTRATOR_DIALECT: &str = "RUSTYNET_ORCHESTRATOR_DIALECT";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OrchestratorDialect {
    RustNative,
}

impl OrchestratorDialect {
    pub fn as_str(&self) -> &'static str {
        match self {
            OrchestratorDialect::RustNative => "rust-native",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedOrchestrationContext {
    assignments: Vec<NodeRoleAssignment>,
    node_ids: BTreeMap<String, String>,
    collected_pubkeys: BTreeMap<String, WireguardPublicKey>,
    #[serde(default)]
    collected_gossip_identities: BTreeMap<String, GossipIdentity>,
    membership_snapshot: Option<Vec<u8>>,
    mesh_ips: BTreeMap<String, String>,
    endpoints: BTreeMap<String, String>,
    network_id: String,
    #[serde(default)]
    ssh_allow_cidrs: String,
    #[serde(default)]
    orchestrator_dialect: Option<OrchestratorDialect>,
    /// Server-reflexive STUN endpoint (`ip:port`) per node alias, collected
    /// during `CollectPubkeys` when the daemon reports `stun_candidates`.
    /// Consumed by traversal bundle emission (`SRFLX_SPEC`).
    #[serde(default)]
    reflexive_endpoints: BTreeMap<String, String>,
    /// Topology-level cross-network substrate provenance (id + topology
    /// digest). The live handle is NEVER serialized; this record is what a
    /// resumed run checks the requested substrate against, failing closed on
    /// mismatch.
    #[serde(default)]
    substrate_record:
        Option<crate::vm_lab::orchestrator::stage::cross_network::substrate::SubstrateRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrchestrationContextBinding {
    pub report_dir: String,
    pub inventory_sha256: String,
    pub source_mode: String,
    pub repo_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedOrchestrationContextEnvelope {
    schema_version: u64,
    binding: OrchestrationContextBinding,
    payload_sha256: String,
    payload: PersistedOrchestrationContext,
}

fn payload_digest(
    binding: &OrchestrationContextBinding,
    payload: &PersistedOrchestrationContext,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(binding, payload))
        .map_err(|err| format!("serialize orchestration context digest input: {err}"))?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Atomic durable write shared by the persisted orchestration context and the
/// `--node` evidence finalizer's commit marker (RNQ-05): unique temp file in
/// the target's directory → write → fsync(file) → rename into place →
/// fsync(directory). A reader can never observe a torn file, and after `Ok`
/// the bytes are durable across a crash. `mode` (unix) is applied at
/// temp-create time so the final file never transitions through a wider
/// permission set; `None` keeps the process default (umask).
pub(crate) fn atomic_write_fsync(
    path: &Path,
    bytes: &[u8],
    mode: Option<u32>,
) -> Result<(), String> {
    static TEMP_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let parent = path
        .parent()
        .ok_or_else(|| format!("atomic write target has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "create atomic write directory '{}': {err}",
            parent.display()
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            format!(
                "atomic write target has no UTF-8 file name: {}",
                path.display()
            )
        })?;
    let tmp = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if let Some(mode) = mode {
            options.mode(mode);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    let mut file = options
        .open(&tmp)
        .map_err(|err| format!("create atomic write temp '{}': {err}", tmp.display()))?;
    let write_result = (|| {
        file.write_all(bytes)
            .map_err(|err| format!("write atomic write temp '{}': {err}", tmp.display()))?;
        file.sync_all()
            .map_err(|err| format!("sync atomic write temp '{}': {err}", tmp.display()))?;
        fs::rename(&tmp, path).map_err(|err| {
            format!(
                "replace atomic write target '{}' from '{}': {err}",
                path.display(),
                tmp.display()
            )
        })?;
        #[cfg(unix)]
        {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|err| {
                    format!("sync atomic write directory '{}': {err}", parent.display())
                })?;
        }
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    write_result
}

fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    atomic_write_fsync(path, bytes, Some(0o600))
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
    /// What each node publishes into membership's `node_pubkey_hex`. Kept
    /// separate from `collected_pubkeys`, which still feeds the real tunnel.
    pub collected_gossip_identities: HashMap<String, GossipIdentity>,
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
    /// Server-reflexive STUN endpoint (`ip:port`) per alias, collected during
    /// `CollectPubkeys` from the daemon netcheck `stun_candidates` field.
    /// Persisted in the context envelope so a resumed run can emit
    /// `SRFLX_SPEC` for traversal bundles without re-collecting.
    pub reflexive_endpoints: HashMap<String, String>,
    /// Cross-NAT STUN servers (`ip:port`) configured via
    /// `--lab-stun-servers`, replacing the default-gateway STUN default on
    /// every install path. Run-local only (never serialized): a resumed
    /// context reloads an empty vec — the fail-closed direction (no
    /// candidate-collection requirement without the flag re-supplied).
    pub lab_stun_servers: Vec<std::net::SocketAddr>,
    /// `--linux-backend` pin forwarded as `RUSTYNET_BACKEND` in every Linux
    /// guest's bootstrap env. Run-local like `lab_stun_servers`: `None` on a
    /// resumed context, which leaves the install's existing-value behavior
    /// untouched (bootstrap has already happened by then anyway).
    pub linux_backend: Option<String>,
    /// Orchestrator engine that produced this run (set before stage execution).
    pub orchestrator_dialect: Option<OrchestratorDialect>,
    /// Live topology-level substrate handle (overlay/underlay IPs + created
    /// links). Run-local only — rebuilt by the setup stage, drained by the
    /// always-run teardown stage, never serialized.
    pub substrate:
        Option<crate::vm_lab::orchestrator::stage::cross_network::substrate::SubstrateHandle>,
    /// Persisted substrate provenance (mirrors the handle's record; survives
    /// `--resume-from` so a mismatched resume fails closed).
    pub substrate_record:
        Option<crate::vm_lab::orchestrator::stage::cross_network::substrate::SubstrateRecord>,
    /// Whether THIS run elected the macOS anchor validator set
    /// (`--anchor-platform macos`), which dispatches
    /// `deploy_macos_anchor_profile` + `validate_macos_anchor_bundle_pull` +
    /// `validate_macos_anchor_port_mapping_authority` in the same invocation.
    /// Run-local only (never serialized): a resumed context reloads as
    /// `false`, which grades macOS anchor runtime coverage as a reported
    /// skip — the fail-closed direction (a re-run re-derives it from the
    /// selector). `anchor_validation` consults this to distinguish a macOS
    /// anchor whose bundle-pull runtime is delegated to that validator set
    /// (this run) from one whose runtime has no evidence path (reported
    /// skip; MAC-D1).
    pub macos_anchor_validators_elected: bool,
    /// Run-local election flag for the C6 macOS live role-transition
    /// validator (`validate_macos_role_transition`): true only when the run
    /// elected `--role-switch-platform macos` AND the stage is really in
    /// this run's plan (tightened in native.rs after the plan is built).
    /// `false`, which grades the macOS role-transition cell as a reported
    /// skip — the fail-closed direction (a resumed context reloads `false`;
    /// the flag is re-derived from the selector on every run).
    pub macos_role_transition_elected: bool,
    /// Run-local election flag for the C7 macOS live reboot-recovery
    /// validator (`validate_macos_reboot_recovery`): true only when the run
    /// elected `--reboot-platform macos` AND the stage is really in this
    /// run's plan (tightened in native.rs after the plan is built).
    /// `false`, which grades the macOS reboot-recovery cell as a reported
    /// skip — the fail-closed direction (a resumed context reloads `false`;
    /// the flag is re-derived from the selector on every run).
    pub macos_reboot_recovery_elected: bool,
    /// Absolute path of the resolved inventory this run started from,
    /// threaded so runtime stages can self-serve inventory lookups
    /// (e.g. the macOS anchor validator set re-reading per-node lab
    /// parameters; MAC-D3). Run-local only (never serialized): a resumed
    /// context reloads as `None`, which the macOS anchor stages treat as a
    /// fail-closed failure rather than a silent pass.
    pub inventory_path: Option<std::path::PathBuf>,
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
            collected_gossip_identities: HashMap::new(),
            network_id,
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            reflexive_endpoints: HashMap::new(),
            lab_stun_servers: Vec::new(),
            linux_backend: None,
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
            inventory_path: None,
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

    pub fn save_bound(
        &self,
        path: &Path,
        binding: &OrchestrationContextBinding,
    ) -> Result<(), String> {
        let payload = PersistedOrchestrationContext {
            assignments: self.assignments.clone(),
            node_ids: self.node_ids.clone().into_iter().collect(),
            collected_pubkeys: self.collected_pubkeys.clone().into_iter().collect(),
            collected_gossip_identities: self
                .collected_gossip_identities
                .clone()
                .into_iter()
                .collect(),
            membership_snapshot: self.membership_snapshot.clone(),
            mesh_ips: self.mesh_ips.clone().into_iter().collect(),
            endpoints: self.endpoints.clone().into_iter().collect(),
            network_id: self.network_id.clone(),
            ssh_allow_cidrs: self.ssh_allow_cidrs.clone(),
            orchestrator_dialect: self.orchestrator_dialect,
            reflexive_endpoints: self.reflexive_endpoints.clone().into_iter().collect(),
            substrate_record: self.substrate_record.clone(),
        };
        let envelope = PersistedOrchestrationContextEnvelope {
            schema_version: ORCHESTRATION_CONTEXT_SCHEMA_VERSION,
            payload_sha256: payload_digest(binding, &payload)?,
            binding: binding.clone(),
            payload,
        };
        let bytes = serde_json::to_vec_pretty(&envelope)
            .map_err(|err| format!("serialize orchestration context: {err}"))?;
        atomic_write_private(path, &bytes)
    }

    pub fn load_bound(
        path: &Path,
        report_dir: PathBuf,
        expected_binding: &OrchestrationContextBinding,
    ) -> Result<Self, String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path)
                .map_err(|err| format!("stat persisted context '{}': {err}", path.display()))?
                .permissions()
                .mode()
                & 0o777;
            if mode & 0o077 != 0 {
                return Err(format!(
                    "persisted orchestration context '{}' has insecure mode {mode:o}; expected 600",
                    path.display()
                ));
            }
        }
        let bytes = fs::read(path).map_err(|err| {
            format!(
                "load persisted orchestration context '{}': {err}",
                path.display()
            )
        })?;
        let envelope: PersistedOrchestrationContextEnvelope = serde_json::from_slice(&bytes)
            .map_err(|err| {
                format!(
                    "parse persisted orchestration context '{}': {err}",
                    path.display()
                )
            })?;
        if envelope.schema_version != ORCHESTRATION_CONTEXT_SCHEMA_VERSION {
            return Err(format!(
                "stale persisted orchestration context '{}': schema_version={} expected={}",
                path.display(),
                envelope.schema_version,
                ORCHESTRATION_CONTEXT_SCHEMA_VERSION
            ));
        }
        if &envelope.binding != expected_binding {
            return Err(format!(
                "persisted orchestration context '{}' provenance mismatch: actual={:?} expected={expected_binding:?}",
                path.display(),
                envelope.binding
            ));
        }
        let actual_digest = payload_digest(&envelope.binding, &envelope.payload)?;
        if actual_digest != envelope.payload_sha256 {
            return Err(format!(
                "persisted orchestration context '{}' digest mismatch",
                path.display()
            ));
        }
        let snapshot = envelope.payload;
        Ok(OrchestrationContext {
            assignments: snapshot.assignments,
            adapters: HashMap::new(),
            source_archive: None,
            report_dir,
            stage_outcomes: HashMap::new(),
            collected_pubkeys: snapshot.collected_pubkeys.into_iter().collect(),
            collected_gossip_identities: snapshot.collected_gossip_identities.into_iter().collect(),
            network_id: snapshot.network_id,
            node_ids: snapshot.node_ids.into_iter().collect(),
            ssh_allow_cidrs: snapshot.ssh_allow_cidrs,
            membership_snapshot: snapshot.membership_snapshot,
            mesh_ips: snapshot.mesh_ips.into_iter().collect(),
            endpoints: snapshot.endpoints.into_iter().collect(),
            reflexive_endpoints: snapshot.reflexive_endpoints.into_iter().collect(),
            // Run-local STUN configuration is never persisted; a resumed
            // context reloads an empty vec — the fail-closed direction
            // (candidate collection is only required when the flag is
            // re-supplied on the resuming invocation).
            lab_stun_servers: Vec::new(),
            linux_backend: None,
            orchestrator_dialect: snapshot.orchestrator_dialect,
            substrate: None,
            substrate_record: snapshot.substrate_record,
            // Run-local election flag is never persisted; a resumed context
            // reloads `false` — the fail-closed direction (macOS anchor
            // runtime grades as a reported skip until the run is re-derived
            // from the `--anchor-platform macos` selector).
            macos_anchor_validators_elected: false,
            // Same run-local rule for the role-transition election: never
            // persisted, so a resumed context reloads `false` and the C6
            // stage grades as a reported skip until the run is re-derived
            // from the `--role-switch-platform macos` selector.
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
            // Same run-local rule: the absolute inventory path is never
            // persisted; macOS anchor stages fail closed on `None`.
            inventory_path: None,
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
        ctx.reflexive_endpoints
            .insert("exit".to_owned(), "203.0.113.7:41338".to_owned());
        ctx.ssh_allow_cidrs = "192.0.2.0/24".to_owned();
        ctx.set_dialect(OrchestratorDialect::RustNative);
        ctx.substrate_record = Some(
            crate::vm_lab::orchestrator::stage::cross_network::substrate::SubstrateRecord {
                substrate_id: "vxlan".to_owned(),
                topology_digest: "digest".to_owned(),
                provisioned: true,
                participants: vec!["exit".to_owned()],
            },
        );

        let path = tmp.path().join("state/orchestration_context.json");
        let binding = OrchestrationContextBinding {
            report_dir: tmp.path().display().to_string(),
            inventory_sha256: "inventory-digest".to_owned(),
            source_mode: "working-tree".to_owned(),
            repo_ref: None,
        };
        ctx.save_bound(path.as_path(), &binding).unwrap();
        let loaded =
            OrchestrationContext::load_bound(path.as_path(), tmp.path().to_path_buf(), &binding)
                .unwrap();

        assert_eq!(loaded.assignments, ctx.assignments);
        assert_eq!(loaded.node_ids, ctx.node_ids);
        assert_eq!(loaded.collected_pubkeys, ctx.collected_pubkeys);
        assert_eq!(loaded.membership_snapshot, ctx.membership_snapshot);
        assert_eq!(loaded.mesh_ips, ctx.mesh_ips);
        assert_eq!(loaded.endpoints, ctx.endpoints);
        assert_eq!(loaded.reflexive_endpoints, ctx.reflexive_endpoints);
        assert!(
            loaded.lab_stun_servers.is_empty(),
            "lab_stun_servers is run-local and must not survive persistence"
        );
        assert_eq!(loaded.network_id, ctx.network_id);
        assert_eq!(loaded.ssh_allow_cidrs, ctx.ssh_allow_cidrs);
        assert_eq!(
            loaded.orchestrator_dialect,
            Some(OrchestratorDialect::RustNative)
        );
        assert!(loaded.adapters.is_empty());
        assert!(loaded.stage_outcomes.is_empty());
        assert_eq!(loaded.substrate_record, ctx.substrate_record);
        assert!(
            loaded.substrate.is_none(),
            "the live substrate handle must never survive persistence"
        );
    }

    #[test]
    fn orchestration_context_rejects_tamper_and_binding_mismatch() {
        let tmp = tempdir().expect("tempdir");
        let ctx = OrchestrationContext::new(Vec::new(), tmp.path().to_path_buf(), "net".to_owned());
        let path = tmp.path().join("state/orchestration_context.json");
        let binding = OrchestrationContextBinding {
            report_dir: tmp.path().display().to_string(),
            inventory_sha256: "inventory-a".to_owned(),
            source_mode: "working-tree".to_owned(),
            repo_ref: None,
        };
        ctx.save_bound(&path, &binding).expect("save");

        let mut wrong = binding.clone();
        wrong.inventory_sha256 = "inventory-b".to_owned();
        assert!(OrchestrationContext::load_bound(&path, tmp.path().to_path_buf(), &wrong).is_err());

        let body = fs::read_to_string(&path).expect("read context");
        let tampered = body.replace("\"network_id\": \"net\"", "\"network_id\": \"evil\"");
        fs::write(&path, tampered).expect("tamper context");
        assert!(
            OrchestrationContext::load_bound(&path, tmp.path().to_path_buf(), &binding).is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn orchestration_context_rejects_group_readable_mode() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempdir().expect("tempdir");
        let ctx = OrchestrationContext::new(Vec::new(), tmp.path().to_path_buf(), "net".to_owned());
        let path = tmp.path().join("state/orchestration_context.json");
        let binding = OrchestrationContextBinding {
            report_dir: tmp.path().display().to_string(),
            inventory_sha256: "inventory".to_owned(),
            source_mode: "working-tree".to_owned(),
            repo_ref: None,
        };
        ctx.save_bound(&path, &binding).expect("save");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("chmod");
        assert!(
            OrchestrationContext::load_bound(&path, tmp.path().to_path_buf(), &binding).is_err()
        );
    }
}
