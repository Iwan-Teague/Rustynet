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

/// Linux node adapter stub. Full implementation ships in W5.1.
#[derive(Debug)]
pub struct LinuxNodeAdapter {
    conn: NodeConnection,
}

impl LinuxNodeAdapter {
    pub fn new(conn: NodeConnection) -> Self {
        LinuxNodeAdapter { conn }
    }
}

fn unimplemented_linux() -> AdapterError {
    AdapterError::Protocol {
        message: "LinuxNodeAdapter method not yet implemented (W5.1)".to_string(),
    }
}

impl NodeAdapter for LinuxNodeAdapter {
    fn platform(&self) -> VmGuestPlatform {
        VmGuestPlatform::Linux
    }
    fn install_daemon(
        &self,
        _: &SourceArchive,
        _: &OrchestrationContext,
    ) -> Result<InstallReport, AdapterError> {
        Err(unimplemented_linux())
    }
    fn start_daemon(&self) -> Result<(), AdapterError> {
        Err(unimplemented_linux())
    }
    fn stop_daemon(&self) -> Result<(), AdapterError> {
        Err(unimplemented_linux())
    }
    fn restart_daemon(&self) -> Result<(), AdapterError> {
        Err(unimplemented_linux())
    }
    fn uninstall_daemon(&self) -> Result<(), AdapterError> {
        Err(unimplemented_linux())
    }
    fn issue_membership_owner_key(&self) -> Result<MembershipOwnerKey, AdapterError> {
        Err(unimplemented_linux())
    }
    fn init_membership_snapshot(
        &self,
        _: &MembershipOwnerKey,
        _: &[NodeRoleAssignment],
    ) -> Result<MembershipSnapshot, AdapterError> {
        Err(unimplemented_linux())
    }
    fn collect_wireguard_public_key(&self) -> Result<WireguardPublicKey, AdapterError> {
        Err(unimplemented_linux())
    }
    fn collect_node_id(&self) -> Result<NodeId, AdapterError> {
        Err(unimplemented_linux())
    }
    fn distribute_signed_bundle(&self, _: BundleKind, _: &Path) -> Result<(), AdapterError> {
        Err(unimplemented_linux())
    }
    fn run_validator(&self, _: DaemonProbeOp) -> Result<ValidatorReport, AdapterError> {
        Err(unimplemented_linux())
    }
    fn ping_mesh_peer(&self, _: &str) -> Result<TrafficTestResult, AdapterError> {
        Err(unimplemented_linux())
    }
    fn probe_denied_peer(&self, _: &str) -> Result<TrafficTestResult, AdapterError> {
        Err(unimplemented_linux())
    }
    fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError> {
        Err(unimplemented_linux())
    }
    fn collect_artifacts(&self, _: &Path) -> Result<(), AdapterError> {
        Err(unimplemented_linux())
    }
    fn cleanup_runtime_state(&self) -> Result<(), AdapterError> {
        Err(unimplemented_linux())
    }
}

#[allow(dead_code)]
fn conn_host(conn: &NodeConnection) -> Option<&str> {
    match conn {
        NodeConnection::Ssh { host, .. } => Some(host.as_str()),
        _ => None,
    }
}
