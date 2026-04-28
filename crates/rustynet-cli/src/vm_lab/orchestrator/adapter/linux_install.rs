#![allow(dead_code)]
use std::io::Write as IoWrite;
use std::time::Duration;

use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{AdapterError, InstallReport};
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::source_archive::SourceArchive;

/// Canonical path of `rustynetd` on Linux targets.
pub const LINUX_RUSTYNETD_PATH: &str = "/usr/local/bin/rustynetd";
/// Canonical path of `rustynet` CLI on Linux targets.
pub const LINUX_RUSTYNET_PATH: &str = "/usr/local/bin/rustynet";
/// Canonical systemd service name.
pub const LINUX_SERVICE_NAME: &str = "rustynetd";
/// Daemon UNIX socket path.
pub const LINUX_DAEMON_SOCKET: &str = "/run/rustynet/rustynetd.sock";

/// Bootstrap script embedded at compile time from the reviewed copy at
/// `scripts/bootstrap/linux/rn_bootstrap.sh`. The script is the same one
/// the bash orchestrator ships via heredoc; factored here so the Rust
/// adapter can scp + invoke it without shelling out to the bash orchestrator.
static BOOTSTRAP_SCRIPT: &str =
    include_str!("../../../../../../scripts/bootstrap/linux/rn_bootstrap.sh");

/// Scp the `SourceArchive`, the bootstrap env, and the bootstrap script to
/// the remote host. Then run the bootstrap script and wait for the daemon
/// socket to appear. Returns an `InstallReport` on success.
pub fn install_daemon(
    conn: &NodeConnection,
    alias: &str,
    source: &SourceArchive,
    ctx: &OrchestrationContext,
) -> Result<InstallReport, AdapterError> {
    let role = ctx
        .assignments
        .iter()
        .find(|a| a.alias == alias)
        .map(|a| &a.role)
        .cloned()
        .unwrap_or(NodeRole::Client);
    let node_id = ctx
        .node_ids
        .get(alias)
        .cloned()
        .unwrap_or_else(|| format!("{alias}-bootstrap"));

    // Write bootstrap script to a temp file.
    let script_tmp = write_temp_file("rn_bootstrap_", ".sh", BOOTSTRAP_SCRIPT.as_bytes())?;

    // Write env file.
    let env_content = build_bootstrap_env(&node_id, &role, ctx);
    let env_tmp = write_temp_file("rn_bootstrap_env_", ".env", env_content.as_bytes())?;

    let short_timeout = Duration::from_secs(30);
    let build_timeout = Duration::from_secs(900); // cargo build can take a while
    let socket_timeout = Duration::from_secs(300);

    // SCP the three artefacts.
    ssh::scp_to(
        conn,
        script_tmp.as_path(),
        "/tmp/rn_bootstrap.sh",
        short_timeout,
    )?;
    ssh::scp_to(
        conn,
        env_tmp.as_path(),
        "/tmp/rn_bootstrap.env",
        short_timeout,
    )?;
    ssh::scp_to(conn, source.path(), "/tmp/rn_source.tar.gz", short_timeout)?;

    // Cleanup temp files (best-effort; ignore errors).
    let _ = std::fs::remove_file(&script_tmp);
    let _ = std::fs::remove_file(&env_tmp);

    // Run bootstrap.
    ssh::run_remote(
        conn,
        "chmod 700 /tmp/rn_bootstrap.sh && bash /tmp/rn_bootstrap.sh /tmp/rn_bootstrap.env",
        build_timeout,
    )?;

    // Wait for daemon socket.
    ssh::wait_for_remote_socket(conn, LINUX_DAEMON_SOCKET, socket_timeout)?;

    // Verify binaries are present and the rustynetd group exists.
    let verify_script = format!(
        "test -x {rustynetd} && test -x {rustynet} && test -f /var/lib/rustynet/keys/wireguard.pub && getent group rustynetd >/dev/null 2>&1",
        rustynetd = LINUX_RUSTYNETD_PATH,
        rustynet = LINUX_RUSTYNET_PATH,
    );
    ssh::run_remote(conn, &verify_script, short_timeout)?;

    Ok(InstallReport {
        daemon_path: LINUX_RUSTYNETD_PATH.into(),
        service_name: LINUX_SERVICE_NAME.to_string(),
    })
}

/// Start the rustynetd systemd service.
pub fn start_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    run_systemctl(conn, "start")
}

/// Stop the rustynetd systemd service.
pub fn stop_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    run_systemctl(conn, "stop")
}

/// Restart the rustynetd systemd service.
pub fn restart_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    run_systemctl(conn, "restart")
}

/// Stop the service and remove daemon binaries and configuration.
pub fn uninstall_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    let timeout = Duration::from_secs(60);
    // Stop service (best-effort — it may not be running).
    let _ = ssh::run_remote(
        conn,
        "if systemctl is-active rustynetd >/dev/null 2>&1; then systemctl stop rustynetd; fi",
        timeout,
    );
    ssh::run_remote(
        conn,
        &format!(
            "rm -f {rustynetd} {rustynet} /etc/systemd/system/rustynetd.service && systemctl daemon-reload 2>/dev/null || true && rm -rf /etc/rustynet /var/lib/rustynet /run/rustynet",
            rustynetd = LINUX_RUSTYNETD_PATH,
            rustynet = LINUX_RUSTYNET_PATH,
        ),
        timeout,
    )?;
    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn run_systemctl(conn: &NodeConnection, action: &str) -> Result<(), AdapterError> {
    let timeout = Duration::from_secs(60);
    ssh::run_remote(conn, &format!("systemctl {action} rustynetd"), timeout)?;
    Ok(())
}

fn build_bootstrap_env(node_id: &str, role: &NodeRole, ctx: &OrchestrationContext) -> String {
    let role_str = match role {
        NodeRole::Exit => "exit",
        NodeRole::Client => "client",
        NodeRole::Entry => "entry",
        NodeRole::Aux => "aux",
        NodeRole::Extra => "extra",
        NodeRole::Custom(s) => s.as_str(),
    };
    let ssh_allow_cidrs = &ctx.ssh_allow_cidrs;
    let network_id = &ctx.network_id;
    format!(
        "ROLE={role_str}\nNODE_ID={node_id}\nNETWORK_ID={network_id}\nSSH_ALLOW_CIDRS={ssh_allow_cidrs}\nSOURCE_ARCHIVE=/tmp/rn_source.tar.gz\n"
    )
}

/// Write `content` to a temp file with the given prefix and suffix.
/// Returns the temp file path.
fn write_temp_file(
    prefix: &str,
    suffix: &str,
    content: &[u8],
) -> Result<std::path::PathBuf, AdapterError> {
    let mut path = std::env::temp_dir();
    path.push(format!("{prefix}{}{suffix}", std::process::id()));
    let mut file = std::fs::File::create(&path).map_err(|err| AdapterError::Io {
        message: format!("create temp file failed: {err}"),
    })?;
    file.write_all(content).map_err(|err| AdapterError::Io {
        message: format!("write temp file failed: {err}"),
    })?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;

    #[test]
    fn bootstrap_env_includes_role_and_node_id() {
        use std::collections::HashMap;
        let assignments = vec![NodeRoleAssignment {
            alias: "node1".to_string(),
            role: NodeRole::Exit,
        }];
        let ctx = OrchestrationContext {
            assignments,
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: "/tmp".into(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            network_id: "test-net".to_string(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: "10.0.0.0/8".to_string(),
        };
        let env = build_bootstrap_env("exit-node1-abc123", &NodeRole::Exit, &ctx);
        assert!(env.contains("ROLE=exit"), "must contain ROLE=exit: {env}");
        assert!(
            env.contains("NODE_ID=exit-node1-abc123"),
            "must contain NODE_ID: {env}"
        );
        assert!(
            env.contains("NETWORK_ID=test-net"),
            "must contain NETWORK_ID: {env}"
        );
    }

    #[test]
    fn bootstrap_env_custom_role() {
        use std::collections::HashMap;
        let ctx = OrchestrationContext {
            assignments: vec![],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: "/tmp".into(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            network_id: "net".to_string(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
        };
        let env = build_bootstrap_env("id1", &NodeRole::Custom("special".to_string()), &ctx);
        assert!(env.contains("ROLE=special"), "custom role: {env}");
    }

    #[test]
    fn bootstrap_script_is_non_empty() {
        assert!(
            !BOOTSTRAP_SCRIPT.is_empty(),
            "embedded bootstrap script must not be empty"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("rn_bootstrap.sh"),
            "embedded script must contain its own name"
        );
    }
}
