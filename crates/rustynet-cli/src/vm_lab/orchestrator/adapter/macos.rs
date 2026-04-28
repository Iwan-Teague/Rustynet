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

/// macOS node adapter stub. Full implementation ships in W5.3.
#[derive(Debug)]
pub struct MacosNodeAdapter {
    #[allow(dead_code)]
    conn: NodeConnection,
    alias: String,
}

impl MacosNodeAdapter {
    pub fn new(alias: impl Into<String>, conn: NodeConnection) -> Self {
        MacosNodeAdapter {
            alias: alias.into(),
            conn,
        }
    }
}

fn unimplemented_macos() -> AdapterError {
    AdapterError::Protocol {
        message: "MacosNodeAdapter method not yet implemented (W5.3)".to_string(),
    }
}

impl NodeAdapter for MacosNodeAdapter {
    fn platform(&self) -> VmGuestPlatform {
        VmGuestPlatform::Macos
    }
    fn alias(&self) -> &str {
        &self.alias
    }
    fn install_daemon(
        &self,
        _: &SourceArchive,
        _: &OrchestrationContext,
    ) -> Result<InstallReport, AdapterError> {
        Err(unimplemented_macos())
    }
    fn start_daemon(&self) -> Result<(), AdapterError> {
        Err(unimplemented_macos())
    }
    fn stop_daemon(&self) -> Result<(), AdapterError> {
        Err(unimplemented_macos())
    }
    fn restart_daemon(&self) -> Result<(), AdapterError> {
        Err(unimplemented_macos())
    }
    fn uninstall_daemon(&self) -> Result<(), AdapterError> {
        Err(unimplemented_macos())
    }
    fn issue_membership_owner_key(&self) -> Result<MembershipOwnerKey, AdapterError> {
        Err(unimplemented_macos())
    }
    fn init_membership_snapshot(
        &self,
        _: &MembershipOwnerKey,
        _: &[NodeRoleAssignment],
    ) -> Result<MembershipSnapshot, AdapterError> {
        Err(unimplemented_macos())
    }
    fn collect_wireguard_public_key(&self) -> Result<WireguardPublicKey, AdapterError> {
        Err(unimplemented_macos())
    }
    fn collect_node_id(&self) -> Result<NodeId, AdapterError> {
        Err(unimplemented_macos())
    }
    fn distribute_signed_bundle(&self, _: BundleKind, _: &Path) -> Result<(), AdapterError> {
        Err(unimplemented_macos())
    }
    fn run_validator(&self, _: DaemonProbeOp) -> Result<ValidatorReport, AdapterError> {
        Err(unimplemented_macos())
    }
    fn ping_mesh_peer(&self, _: &str) -> Result<TrafficTestResult, AdapterError> {
        Err(unimplemented_macos())
    }
    fn probe_denied_peer(&self, _: &str) -> Result<TrafficTestResult, AdapterError> {
        Err(unimplemented_macos())
    }
    fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError> {
        Err(unimplemented_macos())
    }
    fn collect_artifacts(&self, _: &Path) -> Result<(), AdapterError> {
        Err(unimplemented_macos())
    }
    fn cleanup_runtime_state(&self) -> Result<(), AdapterError> {
        Err(unimplemented_macos())
    }
}
