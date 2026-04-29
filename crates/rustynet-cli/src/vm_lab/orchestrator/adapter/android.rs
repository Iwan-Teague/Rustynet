#![allow(dead_code)]
use std::path::Path;

use crate::vm_lab::DaemonProbeOp;
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{
    AdapterError, BundleKind, InstallReport, MembershipOwnerKey, MembershipSnapshot, NodeId,
    NodeMembershipPeer, TrafficTestResult, TunnelsList, ValidatorReport, WireguardPublicKey,
};
use crate::vm_lab::orchestrator::source_archive::SourceArchive;

/// Android adapter — not yet implemented.
/// ADB variant is a lab escape hatch, not a production path.
/// All methods fail closed with a security-specific rejection.
/// See §11 of RustNativeMultiPlatformOrchestratorPlan_2026-04-28.md
/// for what a future W6 track requires before this guard can be lifted.
#[derive(Debug)]
pub struct AndroidNodeAdapter {
    #[allow(dead_code)]
    conn: NodeConnection,
    alias: String,
}

impl AndroidNodeAdapter {
    pub fn new(alias: impl Into<String>, conn: NodeConnection) -> Self {
        AndroidNodeAdapter {
            alias: alias.into(),
            conn,
        }
    }
}

const ANDROID_UNSUPPORTED_MSG: &str = "\
Android node adapter is not yet implemented. Blocked by security minimum bar: \
(1) no daemon validator coverage — service-hardening-check, key-custody-check, \
dns-failclosed-check not implemented for Android; \
(2) no reviewed key custody model — Android Keystore / StrongBox integration not designed; \
(3) ADB connection model is a lab-only escape hatch — production Android requires \
an app-layer management channel reviewed against security minimum bar.";

fn android_unsupported() -> AdapterError {
    AdapterError::UnsupportedPlatform {
        platform: VmGuestPlatform::Android,
        message: ANDROID_UNSUPPORTED_MSG.to_string(),
    }
}

impl NodeAdapter for AndroidNodeAdapter {
    fn platform(&self) -> VmGuestPlatform {
        VmGuestPlatform::Android
    }
    fn alias(&self) -> &str {
        &self.alias
    }
    fn install_daemon(
        &self,
        _: &SourceArchive,
        _: &OrchestrationContext,
    ) -> Result<InstallReport, AdapterError> {
        Err(android_unsupported())
    }
    fn start_daemon(&self) -> Result<(), AdapterError> {
        Err(android_unsupported())
    }
    fn stop_daemon(&self) -> Result<(), AdapterError> {
        Err(android_unsupported())
    }
    fn restart_daemon(&self) -> Result<(), AdapterError> {
        Err(android_unsupported())
    }
    fn uninstall_daemon(&self) -> Result<(), AdapterError> {
        Err(android_unsupported())
    }
    fn issue_membership_owner_key(&self) -> Result<MembershipOwnerKey, AdapterError> {
        Err(android_unsupported())
    }
    fn init_membership_snapshot(
        &self,
        _: &MembershipOwnerKey,
        _: &[NodeMembershipPeer],
    ) -> Result<MembershipSnapshot, AdapterError> {
        Err(android_unsupported())
    }
    fn collect_wireguard_public_key(&self) -> Result<WireguardPublicKey, AdapterError> {
        Err(android_unsupported())
    }
    fn collect_node_id(&self) -> Result<NodeId, AdapterError> {
        Err(android_unsupported())
    }
    fn distribute_signed_bundle(&self, _: BundleKind, _: &Path) -> Result<(), AdapterError> {
        Err(android_unsupported())
    }
    fn run_validator(&self, _: DaemonProbeOp) -> Result<ValidatorReport, AdapterError> {
        Err(android_unsupported())
    }
    fn ping_mesh_peer(&self, _: &str) -> Result<TrafficTestResult, AdapterError> {
        Err(android_unsupported())
    }
    fn probe_denied_peer(&self, _: &str) -> Result<TrafficTestResult, AdapterError> {
        Err(android_unsupported())
    }
    fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError> {
        Err(android_unsupported())
    }
    fn collect_artifacts(&self, _: &Path) -> Result<(), AdapterError> {
        Err(android_unsupported())
    }
    fn cleanup_runtime_state(&self) -> Result<(), AdapterError> {
        Err(android_unsupported())
    }
    fn check_ssh_reachable(&self) -> Result<(), AdapterError> {
        Err(android_unsupported())
    }
    fn endpoint(&self) -> String {
        "0.0.0.0:0".to_string()
    }
    fn collect_mesh_ip(&self) -> Result<String, AdapterError> {
        Err(android_unsupported())
    }
    fn issue_bundles_to_dir(
        &self,
        _kind: BundleKind,
        _env_content: &str,
        _local_out_dir: &std::path::Path,
    ) -> Result<(), AdapterError> {
        Err(android_unsupported())
    }
}
