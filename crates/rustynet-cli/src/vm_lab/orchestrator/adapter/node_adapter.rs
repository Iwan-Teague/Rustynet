#![allow(dead_code)]
use std::path::Path;

use crate::vm_lab::DaemonProbeOp;
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{
    AdapterError, BundleKind, InstallReport, MembershipOwnerKey, MembershipSnapshot, NodeId,
    TrafficTestResult, TunnelsList, ValidatorReport, WireguardPublicKey,
};
use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
use crate::vm_lab::orchestrator::source_archive::SourceArchive;

/// Per-node, per-OS interface for the orchestration pipeline.
/// Connection details are injected at construction via `NodeConnection`;
/// no transport argument appears in any method signature.
pub trait NodeAdapter: Send + Sync + std::fmt::Debug {
    fn platform(&self) -> VmGuestPlatform;

    /// The alias this adapter was constructed for (matches `NodeRoleAssignment::alias`).
    fn alias(&self) -> &str;

    // ── Install lifecycle ─────────────────────────────────────────

    fn install_daemon(
        &self,
        source: &SourceArchive,
        ctx: &OrchestrationContext,
    ) -> Result<InstallReport, AdapterError>;

    fn start_daemon(&self) -> Result<(), AdapterError>;
    fn stop_daemon(&self) -> Result<(), AdapterError>;
    fn restart_daemon(&self) -> Result<(), AdapterError>;
    fn uninstall_daemon(&self) -> Result<(), AdapterError>;

    // ── Membership owner (exit role only) ─────────────────────────

    fn issue_membership_owner_key(&self) -> Result<MembershipOwnerKey, AdapterError>;

    fn init_membership_snapshot(
        &self,
        owner_key: &MembershipOwnerKey,
        peers: &[NodeRoleAssignment],
    ) -> Result<MembershipSnapshot, AdapterError>;

    // ── Per-node identity + key collection ────────────────────────

    fn collect_wireguard_public_key(&self) -> Result<WireguardPublicKey, AdapterError>;
    fn collect_node_id(&self) -> Result<NodeId, AdapterError>;

    // ── Bundle distribution ───────────────────────────────────────

    fn distribute_signed_bundle(
        &self,
        kind: BundleKind,
        bundle_path: &Path,
    ) -> Result<(), AdapterError>;

    // ── Validators ────────────────────────────────────────────────

    fn run_validator(&self, op: DaemonProbeOp) -> Result<ValidatorReport, AdapterError>;

    // ── Traffic tests ─────────────────────────────────────────────

    /// Positive connectivity: confirm this node reaches `peer_mesh_ip` via tunnel.
    fn ping_mesh_peer(&self, peer_mesh_ip: &str) -> Result<TrafficTestResult, AdapterError>;

    /// Negative ACL test: confirm default-deny blocks traffic to a non-mesh IP.
    /// MUST return `TrafficTestResult::Blocked` for the stage to pass.
    /// `Reachable` result = security failure, stage fails.
    fn probe_denied_peer(&self, denied_ip: &str) -> Result<TrafficTestResult, AdapterError>;

    fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError>;

    // ── Diagnostics + cleanup ─────────────────────────────────────

    /// Collect diagnostic artifacts to `dst`.
    /// Key material MUST be excluded: `*/keys/*`, `*.priv`, `*.pem` paths
    /// must never appear in the archive.
    fn collect_artifacts(&self, dst: &Path) -> Result<(), AdapterError>;

    fn cleanup_runtime_state(&self) -> Result<(), AdapterError>;

    // ── SSH reachability probe ────────────────────────────────────

    fn check_ssh_reachable(&self) -> Result<(), AdapterError>;

    // ── Endpoint identity ─────────────────────────────────────────

    /// Return the WireGuard-reachable endpoint for this node: "host:51820".
    fn endpoint(&self) -> String;

    // ── Mesh IP collection ────────────────────────────────────────

    fn collect_mesh_ip(&self) -> Result<String, AdapterError>;

    // ── Bundle issuance (exit node only) ──────────────────────────

    fn issue_bundles_to_dir(
        &self,
        kind: BundleKind,
        env_content: &str,
        local_out_dir: &Path,
    ) -> Result<(), AdapterError>;
}
