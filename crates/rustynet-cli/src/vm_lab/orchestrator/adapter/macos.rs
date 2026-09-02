#![allow(dead_code)]
use std::path::Path;
use std::time::Duration;

use crate::vm_lab::orchestrator::adapter::macos_exit_traffic;
use crate::vm_lab::orchestrator::adapter::macos_install::{self, MACOS_RUSTYNETD_PATH};
use crate::vm_lab::orchestrator::adapter::macos_membership;
use crate::vm_lab::orchestrator::adapter::macos_traffic;
use crate::vm_lab::orchestrator::adapter::node_adapter::MeshClientNatSession;
use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
use crate::vm_lab::orchestrator::adapter::node_adapter::SshConnectionParams;
use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{
    AdapterError, BundleKind, GossipIdentity, InstallReport, MembershipOwnerKey,
    MembershipSnapshot, NodeId, NodeMembershipPeer, TrafficTestResult, TunnelsList,
    ValidatorReport, WireguardPublicKey,
};
use crate::vm_lab::orchestrator::source_archive::SourceArchive;
use crate::vm_lab::DaemonProbeOp;
use crate::vm_lab::VmGuestPlatform;

const VALIDATOR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Build the `sudo -n <validator argv>` remote command from the probe's argv,
/// validating each element at the seam: the binary as a POSIX path, every
/// other element as a CLI token. The rendered command is the quoted,
/// space-joined argv, which the remote POSIX shell parses identically to the
/// previous unquoted form for these token classes.
fn build_validator_command(argv: &[String]) -> Result<ssh::RemoteCommand, AdapterError> {
    use crate::vm_lab::orchestrator::adapter::validated_args::ValidatedArg;

    if argv.is_empty() {
        return Err(AdapterError::Protocol {
            message: "validator argv must not be empty".to_owned(),
        });
    }
    let mut args = vec![
        ValidatedArg::cli_token("sudo").map_err(AdapterError::from)?,
        ValidatedArg::cli_token("-n").map_err(AdapterError::from)?,
    ];
    args.push(ValidatedArg::path(&argv[0]).map_err(AdapterError::from)?);
    for token in &argv[1..] {
        args.push(ValidatedArg::cli_token(token).map_err(AdapterError::from)?);
    }
    ssh::RemoteCommand::from_args("macos validator", &args)
}

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

    fn collect_os_version(&self) -> String {
        use crate::vm_lab::orchestrator::adapter::ssh;
        // Retry the read-only probe so a transient first-connection SSH timeout
        // does not degrade to the bare "macos" placeholder (which the run-matrix
        // finalizer rejects for lacking a version number). See ledger 2026-07-11.
        ssh::run_remote_retrying(
            &self.conn,
            "printf 'macOS %s (%s)' \"$(sw_vers -productVersion)\" \"$(uname -m)\"",
            Duration::from_secs(10),
            3,
            Duration::from_millis(500),
        )
        .map(|v| v.trim().to_owned())
        .unwrap_or_else(|_| "macos".to_owned())
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
        if let Some(workdir) = &self.workdir {
            // Pass the fresh source archive even when a workdir is
            // configured: install_daemon_from_workdir will extract it
            // when the workdir is absent on the remote host (cold
            // bootstrap) so the build step always picks up the
            // newest code.
            macos_install::install_daemon_from_workdir(
                &self.conn,
                &self.alias,
                workdir,
                Some(source),
                ctx,
            )
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

    fn deploy_relay_service(&self) -> Result<(), AdapterError> {
        macos_install::deploy_relay_service(&self.conn, self.workdir.as_deref())
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

    fn collect_gossip_identity(&self) -> Result<GossipIdentity, AdapterError> {
        // the lab macOS bootstrap scripts never run `key init-gossip`, so no secret exists to export.
        Ok(GossipIdentity::DeferredPlatform)
    }

    fn collect_node_id(&self) -> Result<NodeId, AdapterError> {
        let id = macos_traffic::collect_node_id(&self.conn)?;
        Ok(NodeId(id))
    }

    fn collect_live_identity(
        &self,
    ) -> Result<
        crate::vm_lab::orchestrator::role_validation::identity_challenge::IdentityEvidence,
        AdapterError,
    > {
        macos_traffic::query_live_identity(&self.conn)
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

    fn run_validator(
        &self,
        op: DaemonProbeOp,
        extra_args: &[String],
    ) -> Result<ValidatorReport, AdapterError> {
        use crate::vm_lab::{DaemonProbe, MacosDaemonProbe};
        let probe = MacosDaemonProbe;
        let argv = probe
            .build_argv_with_extra_args(op, MACOS_RUSTYNETD_PATH.as_ref(), extra_args)
            .map_err(|message| AdapterError::Protocol { message })?;
        let op_label = argv.get(1).cloned().unwrap_or_default();
        // Every argv element is validated per class at the seam (path for the
        // binary, cli_token for the rest) regardless of its origin, then
        // rendered as a quoted, space-joined argv.
        //
        // Run with `sudo -n`: the validators inspect root-owned state
        // (`/usr/local/var/rustynet/keys`, launchd config). Without sudo the
        // checks report false "permission denied" drift. Same fix as the Linux
        // adapter; the lab macOS guest has passwordless sudo.
        let script = build_validator_command(&argv)?;
        let output = ssh::run_remote(&self.conn, script.as_str(), VALIDATOR_TIMEOUT)?;
        let passed = ssh::validator_report_ok(&output);
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

    // ── Active full-tunnel exit serving ───────────────────────────────────────
    //
    // Assert-not-actuate (design §0 decision 2 / §3): the daemon holds the
    // enforce-time pf NAT; the adapter verifies it through the daemon's own
    // verifier subcommands and never mutates the product firewall from the
    // CLI. The killswitch-precedence fold-in is ordered by
    // MacosExitActivationSequence (design §5/A2): the mutating experiment is
    // issued ONLY from the pre-activation baseline position inside
    // activate_exit_serving, and its window is closed by a post-check
    // lifecycle snapshot proving the restore.

    fn activate_exit_serving(&self) -> Result<(), AdapterError> {
        macos_exit_traffic::activate_exit_serving(&self.conn, &self.alias)
    }

    fn assert_exit_actively_serving(&self) -> Result<(), AdapterError> {
        macos_exit_traffic::assert_exit_actively_serving(&self.conn)
    }

    fn assert_mesh_client_nat_session(
        &self,
        expected_client_mesh_addr: Option<&str>,
    ) -> Result<MeshClientNatSession, AdapterError> {
        macos_exit_traffic::assert_mesh_client_nat_session(&self.conn, expected_client_mesh_addr)
    }

    // ── Diagnostics + cleanup ─────────────────────────────────────────────────

    fn collect_artifacts(&self, dst: &Path) -> Result<(), AdapterError> {
        macos_traffic::collect_artifacts(&self.conn, dst)
    }

    fn cleanup_runtime_state(&self) -> Result<(), AdapterError> {
        macos_traffic::cleanup_runtime_state(&self.conn)
    }

    fn prime_remote_access(&self) -> Result<(), AdapterError> {
        macos_install::prime_remote_access(&self.conn)
    }

    fn collect_daemon_failure_reason(&self) -> Result<Option<String>, AdapterError> {
        macos_traffic::collect_daemon_failure_reason(&self.conn)
    }

    fn assert_node_clean(&self) -> Result<(), AdapterError> {
        macos_traffic::assert_node_clean(&self.conn)
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
            None,
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
            None,
        )
        .unwrap();
        let adapter = MacosNodeAdapter::new("mac", conn, Some("/Users/admin/rustynet".to_owned()));
        assert_eq!(adapter.workdir.as_deref(), Some("/Users/admin/rustynet"));
    }

    #[test]
    fn build_validator_command_renders_quoted_argv_for_a_representative_validator() {
        let argv = vec![
            "/usr/local/bin/rustynetd".to_owned(),
            "macos-key-custody-check".to_owned(),
            "--no-fail-on-drift".to_owned(),
        ];
        let cmd = build_validator_command(&argv).unwrap();
        assert_eq!(
            cmd.as_str(),
            "'sudo' '-n' '/usr/local/bin/rustynetd' 'macos-key-custody-check' \
             '--no-fail-on-drift'"
        );
    }

    #[test]
    fn build_validator_command_rejects_empty_and_unsafe_argv() {
        assert!(build_validator_command(&[]).is_err());
        let injected = vec![
            "/usr/local/bin/rustynetd".to_owned(),
            "macos-key-custody-check; id".to_owned(),
        ];
        assert!(build_validator_command(&injected).is_err());
    }
}
