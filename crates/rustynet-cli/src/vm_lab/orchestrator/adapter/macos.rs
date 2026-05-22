#![allow(dead_code)]
use std::path::Path;

use crate::vm_lab::DaemonProbeOp;
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::macos_install::{self, MACOS_RUSTYNETD_PATH};
use crate::vm_lab::orchestrator::adapter::macos_membership;
use crate::vm_lab::orchestrator::adapter::macos_traffic;
use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{
    AdapterError, BundleKind, InstallReport, MembershipOwnerKey, MembershipSnapshot, NodeId,
    NodeMembershipPeer, TrafficTestResult, TunnelsList, ValidatorReport, WireguardPublicKey,
};
use crate::vm_lab::orchestrator::source_archive::SourceArchive;

const VALIDATOR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// macOS node adapter — W5.3 implementation.
/// Dispatches all operations via SSH. Service management uses launchd.
#[derive(Debug)]
pub struct MacosNodeAdapter {
    conn: NodeConnection,
    alias: String,
    /// Path to the `RustyNet` source tree on the remote macOS host.
    /// When present, `install_daemon` builds from this workdir instead
    /// of transferring a source archive.
    workdir: Option<String>,
}

impl MacosNodeAdapter {
    pub fn new(alias: impl Into<String>, conn: NodeConnection, workdir: Option<String>) -> Self {
        MacosNodeAdapter {
            alias: alias.into(),
            conn,
            workdir,
        }
    }
}

impl NodeAdapter for MacosNodeAdapter {
    fn platform(&self) -> VmGuestPlatform {
        VmGuestPlatform::Macos
    }

    fn alias(&self) -> &str {
        &self.alias
    }

    // ── Install lifecycle ─────────────────────────────────────────────────────

    fn install_daemon(
        &self,
        source: &SourceArchive,
        ctx: &OrchestrationContext,
    ) -> Result<InstallReport, AdapterError> {
        if let Some(workdir) = &self.workdir {
            macos_install::install_daemon_from_workdir(&self.conn, &self.alias, workdir, ctx)
        } else {
            macos_install::install_daemon(&self.conn, &self.alias, source, ctx)
        }
    }

    fn start_daemon(&self) -> Result<(), AdapterError> {
        macos_install::start_daemon(&self.conn)
    }

    fn stop_daemon(&self) -> Result<(), AdapterError> {
        macos_install::stop_daemon(&self.conn)
    }

    fn restart_daemon(&self) -> Result<(), AdapterError> {
        macos_install::restart_daemon(&self.conn)
    }

    fn enforce_runtime(&self, ctx: &OrchestrationContext) -> Result<(), AdapterError> {
        macos_install::enforce_daemon(&self.conn, &self.alias, ctx)
    }

    fn uninstall_daemon(&self) -> Result<(), AdapterError> {
        macos_install::uninstall_daemon(&self.conn)
    }

    // ── Membership owner ──────────────────────────────────────────────────────

    fn issue_membership_owner_key(&self) -> Result<MembershipOwnerKey, AdapterError> {
        macos_membership::issue_membership_owner_key(&self.conn)
    }

    fn init_membership_snapshot(
        &self,
        owner_key: &MembershipOwnerKey,
        peers: &[NodeMembershipPeer],
    ) -> Result<MembershipSnapshot, AdapterError> {
        macos_membership::init_membership_snapshot(&self.conn, owner_key, peers)
    }

    // ── Per-node identity + key collection ────────────────────────────────────

    fn collect_wireguard_public_key(&self) -> Result<WireguardPublicKey, AdapterError> {
        let hex = macos_traffic::collect_wireguard_public_key(&self.conn)?;
        Ok(WireguardPublicKey(hex))
    }

    fn collect_node_id(&self) -> Result<NodeId, AdapterError> {
        let id = macos_traffic::collect_node_id(&self.conn)?;
        Ok(NodeId(id))
    }

    // ── Bundle distribution ───────────────────────────────────────────────────

    fn distribute_signed_bundle(
        &self,
        kind: BundleKind,
        bundle_path: &Path,
    ) -> Result<(), AdapterError> {
        macos_membership::distribute_signed_bundle(&self.conn, kind, bundle_path)
    }

    fn distribute_verifier_key(
        &self,
        kind: BundleKind,
        pub_key_path: &Path,
    ) -> Result<(), AdapterError> {
        macos_membership::distribute_verifier_key(&self.conn, kind, pub_key_path)
    }

    // ── Validators ────────────────────────────────────────────────────────────

    fn run_validator(&self, op: DaemonProbeOp) -> Result<ValidatorReport, AdapterError> {
        use crate::vm_lab::{DaemonProbe, MacosDaemonProbe};
        let probe = MacosDaemonProbe;
        let argv = probe
            .build_argv(op, MACOS_RUSTYNETD_PATH.as_ref())
            .map_err(|message| AdapterError::Protocol { message })?;
        let op_label = argv.get(1).cloned().unwrap_or_default();
        // All argv elements come from `MacosDaemonProbe::build_argv`, which produces
        // a fixed set of known-safe strings. No user-controlled input reaches argv.
        let script = argv.join(" ");
        let output = ssh::run_remote(&self.conn, &script, VALIDATOR_TIMEOUT)?;
        let passed = !output.contains("\"passed\": false") && !output.contains("\"passed\":false");
        Ok(ValidatorReport {
            op_label,
            output,
            passed,
        })
    }

    // ── Traffic tests ─────────────────────────────────────────────────────────

    fn ping_mesh_peer(&self, peer_mesh_ip: &str) -> Result<TrafficTestResult, AdapterError> {
        macos_traffic::ping_mesh_peer(&self.conn, peer_mesh_ip)
    }

    fn probe_denied_peer(&self, denied_ip: &str) -> Result<TrafficTestResult, AdapterError> {
        macos_traffic::probe_denied_peer(&self.conn, denied_ip)
    }

    fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError> {
        macos_traffic::collect_active_tunnels(&self.conn)
    }

    // ── Diagnostics + cleanup ─────────────────────────────────────────────────

    fn collect_artifacts(&self, dst: &Path) -> Result<(), AdapterError> {
        macos_traffic::collect_artifacts(&self.conn, dst)
    }

    fn cleanup_runtime_state(&self) -> Result<(), AdapterError> {
        macos_traffic::cleanup_runtime_state(&self.conn)
    }

    fn check_ssh_reachable(&self) -> Result<(), AdapterError> {
        macos_traffic::check_ssh_reachable(&self.conn)
    }

    fn endpoint(&self) -> String {
        match &self.conn {
            crate::vm_lab::orchestrator::connection::NodeConnection::Ssh { host, .. } => {
                format!("{host}:51820")
            }
            _ => "0.0.0.0:51820".to_owned(),
        }
    }

    fn collect_mesh_ip(&self) -> Result<String, AdapterError> {
        macos_traffic::collect_mesh_ip(&self.conn)
    }

    fn issue_bundles_to_dir(
        &self,
        kind: BundleKind,
        env_content: &str,
        local_out_dir: &std::path::Path,
    ) -> Result<(), AdapterError> {
        use crate::vm_lab::orchestrator::adapter::macos_install::MACOS_RUSTYNET_PATH;
        macos_traffic::issue_bundles_to_dir(
            &self.conn,
            MACOS_RUSTYNET_PATH,
            &kind,
            env_content,
            local_out_dir,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    fn make_adapter(alias: &str) -> MacosNodeAdapter {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# placeholder").unwrap();
        let conn = NodeConnection::ssh(
            "10.0.0.1",
            22,
            Some("admin".to_owned()),
            PathBuf::from("/id_rsa"),
            f.path().to_path_buf(),
        )
        .unwrap();
        MacosNodeAdapter::new(alias, conn, None)
    }

    #[test]
    fn macos_adapter_platform_is_macos() {
        let adapter = make_adapter("mac-node");
        assert_eq!(adapter.platform(), VmGuestPlatform::Macos);
    }

    #[test]
    fn macos_adapter_alias_round_trips() {
        let adapter = make_adapter("macos-mini-1");
        assert_eq!(adapter.alias(), "macos-mini-1");
    }

    #[test]
    fn macos_adapter_workdir_stored() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# placeholder").unwrap();
        let conn = NodeConnection::ssh(
            "10.0.0.1",
            22,
            None,
            PathBuf::from("/id_rsa"),
            f.path().to_path_buf(),
        )
        .unwrap();
        let adapter = MacosNodeAdapter::new("mac", conn, Some("/Users/admin/rustynet".to_owned()));
        assert_eq!(adapter.workdir.as_deref(), Some("/Users/admin/rustynet"));
    }
}
