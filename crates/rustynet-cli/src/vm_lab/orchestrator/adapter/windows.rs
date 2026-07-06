#![allow(dead_code)]
use std::path::Path;

use crate::vm_lab::DaemonProbeOp;
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
use crate::vm_lab::orchestrator::adapter::node_adapter::SshConnectionParams;
use crate::vm_lab::orchestrator::adapter::windows_install::{
    self, WINDOWS_RUSTYNETD_PATH, run_remote_ps,
};
use crate::vm_lab::orchestrator::adapter::windows_membership;
use crate::vm_lab::orchestrator::adapter::windows_traffic;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{
    AdapterError, BundleKind, InstallReport, MembershipOwnerKey, MembershipSnapshot, NodeId,
    NodeMembershipPeer, TrafficTestResult, TunnelsList, ValidatorReport, WireguardPublicKey,
};
use crate::vm_lab::orchestrator::source_archive::SourceArchive;

const VALIDATOR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Windows node adapter — W5.2 implementation.
/// Dispatches all operations via SSH using `NodeConnection::Ssh` and
/// `PowerShell` encoded commands.
#[derive(Debug)]
pub struct WindowsNodeAdapter {
    conn: NodeConnection,
    alias: String,
    /// Path to the `RustyNet` source tree on the remote Windows host,
    /// used by `install_daemon`. Populated from inventory `rustynet_src_dir`.
    workdir: Option<String>,
}

impl WindowsNodeAdapter {
    pub fn new(alias: impl Into<String>, conn: NodeConnection, workdir: Option<String>) -> Self {
        WindowsNodeAdapter {
            alias: alias.into(),
            conn,
            workdir,
        }
    }
}

impl NodeAdapter for WindowsNodeAdapter {
    fn platform(&self) -> VmGuestPlatform {
        VmGuestPlatform::Windows
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

    fn deploy_relay_service(&self) -> Result<(), AdapterError> {
        windows_install::deploy_relay_service(&self.conn)
    }

    fn install_daemon(
        &self,
        source: &SourceArchive,
        ctx: &OrchestrationContext,
    ) -> Result<InstallReport, AdapterError> {
        let workdir = self
            .workdir
            .as_deref()
            .ok_or_else(|| AdapterError::Protocol {
                message: format!(
                    "install_daemon for Windows alias '{}' requires rustynet_src_dir \
                 in inventory (remote workdir not set)",
                    self.alias
                ),
            })?;
        windows_install::install_daemon(&self.conn, &self.alias, workdir, source, ctx)
    }

    fn start_daemon(&self) -> Result<(), AdapterError> {
        windows_install::start_daemon(&self.conn)
    }

    fn enforce_runtime(&self, ctx: &OrchestrationContext) -> Result<(), AdapterError> {
        windows_install::enforce_daemon(&self.conn, &self.alias, ctx)
    }

    fn stop_daemon(&self) -> Result<(), AdapterError> {
        windows_install::stop_daemon(&self.conn)
    }

    fn restart_daemon(&self) -> Result<(), AdapterError> {
        windows_install::restart_daemon(&self.conn)
    }

    fn uninstall_daemon(&self) -> Result<(), AdapterError> {
        windows_install::uninstall_daemon(&self.conn)
    }

    // ── Membership owner ──────────────────────────────────────────────────────

    fn issue_membership_owner_key(&self) -> Result<MembershipOwnerKey, AdapterError> {
        windows_membership::issue_membership_owner_key(&self.conn)
    }

    fn init_membership_snapshot(
        &self,
        owner_key: &MembershipOwnerKey,
        peers: &[NodeMembershipPeer],
    ) -> Result<MembershipSnapshot, AdapterError> {
        windows_membership::init_membership_snapshot(&self.conn, owner_key, peers)
    }

    // ── Per-node identity + key collection ────────────────────────────────────

    fn collect_wireguard_public_key(&self) -> Result<WireguardPublicKey, AdapterError> {
        let hex = windows_traffic::collect_wireguard_public_key(&self.conn)?;
        Ok(WireguardPublicKey(hex))
    }

    fn collect_node_id(&self) -> Result<NodeId, AdapterError> {
        let id = windows_traffic::collect_node_id(&self.conn)?;
        Ok(NodeId(id))
    }

    // ── Bundle distribution ───────────────────────────────────────────────────

    fn distribute_signed_bundle(
        &self,
        kind: BundleKind,
        bundle_path: &Path,
    ) -> Result<(), AdapterError> {
        windows_membership::distribute_signed_bundle(&self.conn, kind, bundle_path)
    }

    fn distribute_verifier_key(
        &self,
        kind: BundleKind,
        pub_key_path: &Path,
    ) -> Result<(), AdapterError> {
        windows_membership::distribute_verifier_key(&self.conn, kind, pub_key_path)
    }

    // ── Validators ────────────────────────────────────────────────────────────

    fn run_validator(&self, op: DaemonProbeOp) -> Result<ValidatorReport, AdapterError> {
        use crate::vm_lab::{DaemonProbe, WindowsDaemonProbe};
        let probe = WindowsDaemonProbe;
        let argv = probe
            .build_argv(op, WINDOWS_RUSTYNETD_PATH.as_ref())
            .map_err(|message| AdapterError::Protocol { message })?;
        // argv: [daemon_path, subcommand, "--no-fail-on-drift"]
        // All elements come from `WindowsDaemonProbe::build_argv`, which produces
        // a fixed set of known-safe strings. No user-controlled input reaches argv.
        let op_label = argv.get(1).cloned().unwrap_or_default();
        let script = build_validator_script(&argv);
        let output = run_remote_ps(&self.conn, &script, VALIDATOR_TIMEOUT)?;
        let passed = crate::vm_lab::orchestrator::adapter::ssh::validator_report_ok(&output);
        Ok(ValidatorReport {
            op_label,
            output,
            passed,
        })
    }

    // ── Traffic tests ─────────────────────────────────────────────────────────

    fn ping_mesh_peer(&self, peer_mesh_ip: &str) -> Result<TrafficTestResult, AdapterError> {
        windows_traffic::ping_mesh_peer(&self.conn, peer_mesh_ip)
    }

    fn probe_denied_peer(&self, denied_ip: &str) -> Result<TrafficTestResult, AdapterError> {
        windows_traffic::probe_denied_peer(&self.conn, denied_ip)
    }

    fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError> {
        windows_traffic::collect_active_tunnels(&self.conn)
    }

    fn activate_exit_serving(&self) -> Result<(), AdapterError> {
        windows_traffic::activate_exit_serving(&self.conn)
    }

    fn assert_exit_actively_serving(&self) -> Result<(), AdapterError> {
        windows_traffic::assert_exit_actively_serving(&self.conn)
    }

    fn assert_mesh_client_nat_session(&self) -> Result<(), AdapterError> {
        windows_traffic::assert_mesh_client_nat_session(&self.conn)
    }

    // ── Diagnostics + cleanup ─────────────────────────────────────────────────

    fn collect_artifacts(&self, dst: &Path) -> Result<(), AdapterError> {
        windows_traffic::collect_artifacts(&self.conn, dst)
    }

    fn cleanup_runtime_state(&self) -> Result<(), AdapterError> {
        windows_traffic::cleanup_runtime_state(&self.conn)
    }

    fn prime_remote_access(&self) -> Result<(), AdapterError> {
        // Windows SSH sessions run as Administrator by default; no sudo priming needed.
        Ok(())
    }

    fn collect_daemon_failure_reason(&self) -> Result<Option<String>, AdapterError> {
        windows_traffic::collect_daemon_failure_reason(&self.conn)
    }

    fn assert_node_clean(&self) -> Result<(), AdapterError> {
        windows_traffic::assert_node_clean(&self.conn)
    }

    fn check_ssh_reachable(&self) -> Result<(), AdapterError> {
        windows_traffic::check_ssh_reachable(&self.conn)
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
        windows_traffic::collect_mesh_ip(&self.conn)
    }

    fn issue_bundles_to_dir(
        &self,
        kind: BundleKind,
        env_content: &str,
        local_out_dir: &std::path::Path,
    ) -> Result<(), AdapterError> {
        // Bundle issuance runs locally on the orchestrator process.  The Windows
        // trust CLI (`rustynet.exe`) only supports `trust` subcommands and cannot
        // run `ops e2e-issue-*`; the full ops CLI is Linux-only.  Generate an
        // ephemeral signing key here and produce the bundle files locally.
        std::fs::create_dir_all(local_out_dir).map_err(|e| AdapterError::Io {
            message: format!("create bundle output dir: {e}"),
        })?;
        match kind {
            BundleKind::Assignment => {
                crate::ops_e2e::issue_assignment_bundles_locally(env_content, local_out_dir)
                    .map_err(|message| AdapterError::Protocol { message })
            }
            BundleKind::Traversal => {
                crate::ops_e2e::issue_traversal_bundles_locally(env_content, local_out_dir)
                    .map_err(|message| AdapterError::Protocol { message })
            }
            BundleKind::DnsZone => {
                crate::ops_e2e::issue_dns_zone_bundles_locally(env_content, local_out_dir)
                    .map_err(|message| AdapterError::Protocol { message })
            }
            BundleKind::Membership => Err(AdapterError::Protocol {
                message: "Membership bundles are issued via init_membership_snapshot".to_owned(),
            }),
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Build a `PowerShell` script that invokes the validator binary.
/// argv must be [`daemon_path`, subcommand, ...flags] as produced by
/// `WindowsDaemonProbe::build_argv`.
fn build_validator_script(argv: &[String]) -> String {
    use crate::vm_lab::orchestrator::adapter::windows_install::ps_quote;
    if argv.is_empty() {
        return String::new();
    }
    // Quote binary path; remaining args are fixed safe strings (subcommand + flags).
    let binary = ps_quote(argv[0].as_str()).unwrap_or_else(|_| format!("'{}'", argv[0]));
    let rest: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
    if rest.is_empty() {
        format!("& {binary}")
    } else {
        format!(
            "$out = & {binary} {} 2>&1; Write-Output $out",
            rest.join(" ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    fn make_adapter(alias: &str) -> WindowsNodeAdapter {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# placeholder").unwrap();
        let conn = NodeConnection::ssh(
            "10.0.0.1",
            22,
            Some("Administrator".to_owned()),
            PathBuf::from("/id_rsa"),
            f.path().to_path_buf(),
            None,
        )
        .unwrap();
        WindowsNodeAdapter::new(alias, conn, None)
    }

    #[test]
    fn windows_adapter_platform_is_windows() {
        let adapter = make_adapter("win-node");
        assert_eq!(adapter.platform(), VmGuestPlatform::Windows);
    }

    #[test]
    fn windows_adapter_alias_round_trips() {
        let adapter = make_adapter("win-exit-1");
        assert_eq!(adapter.alias(), "win-exit-1");
    }

    #[test]
    fn install_daemon_errors_without_workdir() {
        let adapter = make_adapter("win-no-workdir");
        use crate::vm_lab::orchestrator::context::OrchestrationContext;
        use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
        use crate::vm_lab::orchestrator::source_archive::SourceArchive;
        let ctx = OrchestrationContext::new(
            vec![NodeRoleAssignment {
                alias: "win-no-workdir".to_owned(),
                role: crate::vm_lab::orchestrator::role::NodeRole::Client,
            }],
            std::path::PathBuf::from("/tmp/report"),
            "test-network".to_owned(),
        );
        // SourceArchive::Inline requires actual bytes; use a temp archive.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let archive = SourceArchive {
            path: tmp.path().to_path_buf(),
        };
        let err = adapter.install_daemon(&archive, &ctx).unwrap_err();
        assert!(
            matches!(err, AdapterError::Protocol { .. }),
            "expected Protocol error when workdir is None, got: {err:?}"
        );
        assert!(
            err.to_string().contains("rustynet_src_dir"),
            "error must mention rustynet_src_dir: {err}"
        );
    }

    #[test]
    fn build_validator_script_produces_call_operator() {
        let argv = vec![
            r"C:\Program Files\RustyNet\rustynetd.exe".to_owned(),
            "windows-runtime-acls-check".to_owned(),
            "--no-fail-on-drift".to_owned(),
        ];
        let script = build_validator_script(&argv);
        assert!(
            script.contains("& "),
            "script must use PS call operator: {script}"
        );
        assert!(
            script.contains("windows-runtime-acls-check"),
            "script must contain subcommand: {script}"
        );
        assert!(
            script.contains("--no-fail-on-drift"),
            "script must contain flag: {script}"
        );
    }

    #[test]
    fn build_validator_script_empty_argv_returns_empty() {
        assert_eq!(build_validator_script(&[]), "");
    }
}
