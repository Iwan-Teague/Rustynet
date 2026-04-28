#![allow(dead_code)]
use std::path::Path;

use crate::vm_lab::DaemonProbeOp;
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{
    AdapterError, BundleKind, InstallReport, MembershipOwnerKey, MembershipSnapshot, NodeId,
    TrafficTestResult, TunnelsList, ValidatorReport, WireguardPublicKey,
};
use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
use crate::vm_lab::orchestrator::source_archive::SourceArchive;

/// Windows node adapter stub. Full implementation ships in W5.2.
#[derive(Debug)]
pub struct WindowsNodeAdapter {
    #[allow(dead_code)]
    conn: NodeConnection,
}

impl WindowsNodeAdapter {
    pub fn new(conn: NodeConnection) -> Self {
        WindowsNodeAdapter { conn }
    }
}

fn unimplemented_windows() -> AdapterError {
    AdapterError::Protocol {
        message: "WindowsNodeAdapter method not yet implemented (W5.2)".to_string(),
    }
}

impl NodeAdapter for WindowsNodeAdapter {
    fn platform(&self) -> VmGuestPlatform {
        VmGuestPlatform::Windows
    }
    fn install_daemon(
        &self,
        _: &SourceArchive,
        _: &OrchestrationContext,
    ) -> Result<InstallReport, AdapterError> {
        Err(unimplemented_windows())
    }
    fn start_daemon(&self) -> Result<(), AdapterError> {
        Err(unimplemented_windows())
    }
    fn stop_daemon(&self) -> Result<(), AdapterError> {
        Err(unimplemented_windows())
    }
    fn restart_daemon(&self) -> Result<(), AdapterError> {
        Err(unimplemented_windows())
    }
    fn uninstall_daemon(&self) -> Result<(), AdapterError> {
        Err(unimplemented_windows())
    }
    fn issue_membership_owner_key(&self) -> Result<MembershipOwnerKey, AdapterError> {
        Err(unimplemented_windows())
    }
    fn init_membership_snapshot(
        &self,
        _: &MembershipOwnerKey,
        _: &[NodeRoleAssignment],
    ) -> Result<MembershipSnapshot, AdapterError> {
        Err(unimplemented_windows())
    }
    fn collect_wireguard_public_key(&self) -> Result<WireguardPublicKey, AdapterError> {
        Err(unimplemented_windows())
    }
    fn collect_node_id(&self) -> Result<NodeId, AdapterError> {
        Err(unimplemented_windows())
    }
    fn distribute_signed_bundle(&self, _: BundleKind, _: &Path) -> Result<(), AdapterError> {
        Err(unimplemented_windows())
    }
    fn run_validator(&self, _: DaemonProbeOp) -> Result<ValidatorReport, AdapterError> {
        Err(unimplemented_windows())
    }
    fn ping_mesh_peer(&self, _: &str) -> Result<TrafficTestResult, AdapterError> {
        Err(unimplemented_windows())
    }
    fn probe_denied_peer(&self, _: &str) -> Result<TrafficTestResult, AdapterError> {
        Err(unimplemented_windows())
    }
    fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError> {
        Err(unimplemented_windows())
    }
    fn collect_artifacts(&self, _: &Path) -> Result<(), AdapterError> {
        Err(unimplemented_windows())
    }
    fn cleanup_runtime_state(&self) -> Result<(), AdapterError> {
        Err(unimplemented_windows())
    }
}
