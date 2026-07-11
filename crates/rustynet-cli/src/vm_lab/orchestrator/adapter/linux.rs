#![allow(dead_code)]
use std::path::Path;
use std::time::Duration;

use crate::vm_lab::DaemonProbeOp;
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::linux_install;
use crate::vm_lab::orchestrator::adapter::linux_membership;
use crate::vm_lab::orchestrator::adapter::linux_traffic;
use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
use crate::vm_lab::orchestrator::adapter::node_adapter::SshConnectionParams;
use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{
    AdapterError, BundleKind, InstallReport, MembershipOwnerKey, MembershipSnapshot, NodeId,
    NodeMembershipPeer, TrafficTestResult, TunnelsList, ValidatorReport, WireguardPublicKey,
};
use crate::vm_lab::orchestrator::source_archive::SourceArchive;

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);

/// Linux node adapter — full W5.1 implementation.
/// Dispatches all operations via SSH using `NodeConnection::Ssh`.
#[derive(Debug)]
pub struct LinuxNodeAdapter {
    conn: NodeConnection,
    alias: String,
}

impl LinuxNodeAdapter {
    pub fn new(alias: impl Into<String>, conn: NodeConnection) -> Self {
        LinuxNodeAdapter {
            alias: alias.into(),
            conn,
        }
    }
}

impl NodeAdapter for LinuxNodeAdapter {
    fn platform(&self) -> VmGuestPlatform {
        VmGuestPlatform::Linux
    }

    fn collect_os_version(&self) -> String {
        use crate::vm_lab::orchestrator::adapter::ssh;
        ssh::run_remote(
            &self.conn,
            "if [ -r /etc/os-release ]; then \
                 . /etc/os-release; \
                 printf '%s (%s)' \"${PRETTY_NAME:-${NAME:-Linux}}\" \"$(uname -m)\"; \
             else \
                 printf 'Linux kernel %s (%s)' \"$(uname -r)\" \"$(uname -m)\"; \
             fi",
            Duration::from_secs(10),
        )
        .map(|v| v.trim().to_owned())
        .unwrap_or_else(|_| "linux".to_owned())
    }

    fn alias(&self) -> &str {
        &self.alias
    }

    fn ssh_connection_params(&self) -> Option<SshConnectionParams> {
        self.conn.ssh_connection_params()
    }

    /// Build a cross-OS RemoteShellHost from this node's SSH connection, so the
    /// anchor / relay role-validation stages can drive OS-agnostic primitives
    /// over the same hardened transport the adapter already uses.
    fn shell_host(
        &self,
    ) -> Result<
        std::sync::Arc<dyn crate::vm_lab::orchestrator::remote_shell::RemoteShellHost>,
        AdapterError,
    > {
        crate::vm_lab::orchestrator::remote_shell::new_remote_shell_host(
            self.platform(),
            self.conn.clone(),
        )
    }

    // ── Install lifecycle ─────────────────────────────────────────────────────

    fn install_daemon(
        &self,
        source: &SourceArchive,
        ctx: &OrchestrationContext,
    ) -> Result<InstallReport, AdapterError> {
        linux_install::install_daemon(&self.conn, &self.alias, source, ctx)
    }

    fn start_daemon(&self) -> Result<(), AdapterError> {
        linux_install::start_daemon(&self.conn)
    }

    fn enforce_runtime(&self, ctx: &OrchestrationContext) -> Result<(), AdapterError> {
        linux_install::enforce_daemon(&self.conn, &self.alias, ctx)
    }

    fn stop_daemon(&self) -> Result<(), AdapterError> {
        linux_install::stop_daemon(&self.conn)
    }

    fn restart_daemon(&self) -> Result<(), AdapterError> {
        linux_install::restart_daemon(&self.conn)
    }

    fn uninstall_daemon(&self) -> Result<(), AdapterError> {
        linux_install::uninstall_daemon(&self.conn)
    }

    // ── Membership owner ──────────────────────────────────────────────────────

    fn issue_membership_owner_key(&self) -> Result<MembershipOwnerKey, AdapterError> {
        linux_membership::issue_membership_owner_key(&self.conn)
    }

    fn init_membership_snapshot(
        &self,
        owner_key: &MembershipOwnerKey,
        peers: &[NodeMembershipPeer],
    ) -> Result<MembershipSnapshot, AdapterError> {
        linux_membership::init_membership_snapshot(&self.conn, owner_key, peers)
    }

    // ── Per-node identity + key collection ────────────────────────────────────

    fn collect_wireguard_public_key(&self) -> Result<WireguardPublicKey, AdapterError> {
        let hex = linux_traffic::collect_wireguard_public_key(&self.conn)?;
        Ok(WireguardPublicKey(hex))
    }

    fn collect_node_id(&self) -> Result<NodeId, AdapterError> {
        let id = linux_traffic::collect_node_id(&self.conn)?;
        Ok(NodeId(id))
    }

    // ── Bundle distribution ───────────────────────────────────────────────────

    fn distribute_signed_bundle(
        &self,
        kind: BundleKind,
        bundle_path: &Path,
    ) -> Result<(), AdapterError> {
        linux_membership::distribute_signed_bundle(&self.conn, kind, bundle_path)
    }

    fn distribute_verifier_key(
        &self,
        kind: BundleKind,
        pub_key_path: &Path,
    ) -> Result<(), AdapterError> {
        linux_membership::distribute_verifier_key(&self.conn, kind, pub_key_path)
    }

    // ── Validators ────────────────────────────────────────────────────────────

    fn run_validator(&self, op: DaemonProbeOp) -> Result<ValidatorReport, AdapterError> {
        use crate::vm_lab::{DaemonProbe, LinuxDaemonProbe};
        let probe = LinuxDaemonProbe;
        let argv = probe
            .build_argv(op, linux_install::LINUX_RUSTYNETD_PATH.as_ref())
            .map_err(|message| AdapterError::Protocol { message })?;
        // All argv elements come from `LinuxDaemonProbe::build_argv`, which produces
        // a fixed set of known-safe strings: binary path + a `linux-*-check` subcommand
        // + `--no-fail-on-drift`. No user-controlled input reaches argv.
        //
        // Run with `sudo -n`: the validators inspect root-owned security state
        // (`/var/lib/rustynet/keys` 0700 root, `/etc/rustynet/credentials` 0700
        // root). Without sudo every key-custody/service-hardening probe reports
        // false "permission denied" drift, so validate_baseline_runtime fails on
        // a node whose posture is actually correct. Passwordless sudo is already
        // a precondition of the bootstrap + cleanup paths.
        let script = format!("sudo -n {}", argv.join(" "));
        let op_label = argv.get(1).cloned().unwrap_or_default();
        let output = ssh::run_remote(&self.conn, &script, SHORT_TIMEOUT)?;
        let passed = ssh::validator_report_ok(&output);
        Ok(ValidatorReport {
            op_label,
            output,
            passed,
        })
    }

    // ── Traffic tests ─────────────────────────────────────────────────────────

    fn ping_mesh_peer(&self, peer_mesh_ip: &str) -> Result<TrafficTestResult, AdapterError> {
        linux_traffic::ping_mesh_peer(&self.conn, peer_mesh_ip)
    }

    fn probe_denied_peer(&self, denied_ip: &str) -> Result<TrafficTestResult, AdapterError> {
        linux_traffic::probe_denied_peer(&self.conn, denied_ip)
    }

    fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError> {
        linux_traffic::collect_active_tunnels(&self.conn)
    }

    fn drive_exit_egress_probe(&self) -> Result<(), AdapterError> {
        linux_traffic::drive_exit_egress_probe(&self.conn)
    }

    // ── Active full-tunnel exit serving ───────────────────────────────────────

    fn activate_exit_serving(&self) -> Result<(), AdapterError> {
        linux_traffic::activate_exit_serving(&self.conn)
    }

    fn assert_exit_actively_serving(&self) -> Result<(), AdapterError> {
        linux_traffic::assert_exit_actively_serving(&self.conn)
    }

    fn assert_mesh_client_nat_session(&self) -> Result<(), AdapterError> {
        linux_traffic::assert_mesh_client_nat_session(&self.conn)
    }

    // ── Relay runtime deploy ───────────────────────────────────────────────────

    fn deploy_relay_service(&self) -> Result<(), AdapterError> {
        linux_install::deploy_relay_service(&self.conn)
    }

    // ── Diagnostics + cleanup ─────────────────────────────────────────────────

    fn collect_artifacts(&self, dst: &Path) -> Result<(), AdapterError> {
        linux_traffic::collect_artifacts(&self.conn, dst)
    }

    fn cleanup_runtime_state(&self) -> Result<(), AdapterError> {
        linux_traffic::cleanup_runtime_state(&self.conn)
    }

    fn collect_daemon_failure_reason(&self) -> Result<Option<String>, AdapterError> {
        linux_traffic::collect_daemon_failure_reason(&self.conn)
    }

    fn assert_node_clean(&self) -> Result<(), AdapterError> {
        linux_traffic::assert_node_clean(&self.conn)
    }

    fn check_ssh_reachable(&self) -> Result<(), AdapterError> {
        linux_traffic::check_ssh_reachable(&self.conn)
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
        linux_traffic::collect_mesh_ip(&self.conn)
    }

    fn issue_bundles_to_dir(
        &self,
        kind: BundleKind,
        env_content: &str,
        local_out_dir: &std::path::Path,
    ) -> Result<(), AdapterError> {
        linux_traffic::issue_bundles_to_dir(
            &self.conn,
            linux_install::LINUX_RUSTYNET_PATH,
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

    fn make_adapter(alias: &str) -> LinuxNodeAdapter {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# placeholder").unwrap();
        let conn = NodeConnection::ssh(
            "10.0.0.1",
            22,
            Some("debian".to_owned()),
            PathBuf::from("/id_rsa"),
            f.path().to_path_buf(),
            None,
        )
        .unwrap();
        LinuxNodeAdapter::new(alias, conn)
    }

    #[test]
    fn linux_adapter_platform_is_linux() {
        let adapter = make_adapter("node1");
        assert_eq!(adapter.platform(), VmGuestPlatform::Linux);
    }

    #[test]
    fn linux_adapter_alias_round_trips() {
        let adapter = make_adapter("exit-node-1");
        assert_eq!(adapter.alias(), "exit-node-1");
    }
}
