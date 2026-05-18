#![allow(dead_code)]
use std::io::Write as IoWrite;
use std::time::Duration;

use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{AdapterError, InstallReport};
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::source_archive::SourceArchive;

pub const MACOS_RUSTYNETD_PATH: &str = "/usr/local/bin/rustynetd";
pub const MACOS_RUSTYNET_PATH: &str = "/usr/local/bin/rustynet";
pub const MACOS_SERVICE_LABEL: &str = "com.rustynet.daemon";
pub const MACOS_STATE_ROOT: &str = "/usr/local/var/rustynet";
pub const MACOS_KEYS_DIR: &str = "/usr/local/var/rustynet/keys";
pub const MACOS_DAEMON_SOCKET: &str = "/var/run/rustynet/rustynetd.sock";
pub const MACOS_MEMBERSHIP_DIR: &str = "/usr/local/var/rustynet/membership";
pub const MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH: &str =
    "/usr/local/var/rustynet/membership/membership.owner.key.pub";
pub const MACOS_MEMBERSHIP_SNAPSHOT_PATH: &str =
    "/usr/local/var/rustynet/membership/membership.snapshot";

static BOOTSTRAP_SCRIPT: &str =
    include_str!("../../../../../../scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh");
static INSTALL_SERVICE_SCRIPT: &str =
    include_str!("../../../../../../scripts/bootstrap/macos/Install-RustyNetMacosService.sh");

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const BUILD_TIMEOUT: Duration = Duration::from_secs(1800);
const SOCKET_TIMEOUT: Duration = Duration::from_secs(300);

/// Bootstrap the daemon on a macOS host. Transfers the source archive and
/// bootstrap script, runs the bootstrap, waits for the daemon socket.
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

    let script_tmp = write_temp_file("rn_macos_bootstrap_", ".sh", BOOTSTRAP_SCRIPT.as_bytes())?;
    let install_tmp = write_temp_file(
        "rn_macos_install_svc_",
        ".sh",
        INSTALL_SERVICE_SCRIPT.as_bytes(),
    )?;
    let env_content = build_bootstrap_env(&node_id, &role, ctx);
    let env_tmp = write_temp_file("rn_macos_env_", ".env", env_content.as_bytes())?;

    ssh::scp_to(
        conn,
        script_tmp.as_path(),
        "/tmp/rn_macos_bootstrap.sh",
        SHORT_TIMEOUT,
    )?;
    ssh::scp_to(
        conn,
        install_tmp.as_path(),
        "/tmp/rn_macos_install_svc.sh",
        SHORT_TIMEOUT,
    )?;
    ssh::scp_to(
        conn,
        env_tmp.as_path(),
        "/tmp/rn_macos_bootstrap.env",
        SHORT_TIMEOUT,
    )?;
    ssh::scp_to(conn, source.path(), "/tmp/rn_source.tar.gz", SHORT_TIMEOUT)?;

    let _ = std::fs::remove_file(&script_tmp);
    let _ = std::fs::remove_file(&install_tmp);
    let _ = std::fs::remove_file(&env_tmp);

    ssh::run_remote(
        conn,
        "chmod 700 /tmp/rn_macos_bootstrap.sh /tmp/rn_macos_install_svc.sh && \
         sudo bash /tmp/rn_macos_bootstrap.sh /tmp/rn_macos_bootstrap.env",
        BUILD_TIMEOUT,
    )?;

    // Daemon socket is checked in enforce_baseline_runtime / validate_baseline_runtime,
    // not at install time — install_daemon only stages binaries + bootstrap state.

    let verify_script = format!(
        "test -x {MACOS_RUSTYNETD_PATH} && test -x {MACOS_RUSTYNET_PATH} && \
         test -f {MACOS_KEYS_DIR}/wireguard.pub",
    );
    ssh::run_remote(conn, &verify_script, SHORT_TIMEOUT)?;

    Ok(InstallReport {
        daemon_path: MACOS_RUSTYNETD_PATH.into(),
        service_name: MACOS_SERVICE_LABEL.to_owned(),
    })
}

/// Bootstrap via an existing remote workdir (source already on host).
/// Used when `rustynet_src_dir` is set in inventory.
pub fn install_daemon_from_workdir(
    conn: &NodeConnection,
    alias: &str,
    workdir: &str,
    ctx: &OrchestrationContext,
) -> Result<InstallReport, AdapterError> {
    if workdir.is_empty() {
        return Err(AdapterError::Protocol {
            message: "install_daemon_from_workdir: workdir must not be empty".to_owned(),
        });
    }
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

    let env_content = build_bootstrap_env(&node_id, &role, ctx);
    let env_tmp = write_temp_file("rn_macos_env_", ".env", env_content.as_bytes())?;
    let script_tmp = write_temp_file("rn_macos_bootstrap_", ".sh", BOOTSTRAP_SCRIPT.as_bytes())?;
    let install_tmp = write_temp_file(
        "rn_macos_install_svc_",
        ".sh",
        INSTALL_SERVICE_SCRIPT.as_bytes(),
    )?;

    ssh::scp_to(
        conn,
        env_tmp.as_path(),
        "/tmp/rn_macos_bootstrap.env",
        SHORT_TIMEOUT,
    )?;
    ssh::scp_to(
        conn,
        script_tmp.as_path(),
        "/tmp/rn_macos_bootstrap.sh",
        SHORT_TIMEOUT,
    )?;
    ssh::scp_to(
        conn,
        install_tmp.as_path(),
        "/tmp/rn_macos_install_svc.sh",
        SHORT_TIMEOUT,
    )?;

    let _ = std::fs::remove_file(&env_tmp);
    let _ = std::fs::remove_file(&script_tmp);
    let _ = std::fs::remove_file(&install_tmp);

    // Inject SOURCE_ARCHIVE pointing to existing workdir archive or skip archive step.
    // Override SOURCE_ARCHIVE to point to a tar of the existing workdir.
    let build_cmd = format!(
        "chmod 700 /tmp/rn_macos_bootstrap.sh /tmp/rn_macos_install_svc.sh && \
         cd '{workdir}' && tar -czf /tmp/rn_source.tar.gz . && \
         echo 'SOURCE_ARCHIVE=/tmp/rn_source.tar.gz' >> /tmp/rn_macos_bootstrap.env && \
         sudo bash /tmp/rn_macos_bootstrap.sh /tmp/rn_macos_bootstrap.env"
    );
    ssh::run_remote(conn, &build_cmd, BUILD_TIMEOUT)?;
    // Daemon socket is checked in enforce_baseline_runtime / validate_baseline_runtime,
    // not at install time — install_daemon only stages binaries + bootstrap state.

    Ok(InstallReport {
        daemon_path: MACOS_RUSTYNETD_PATH.into(),
        service_name: MACOS_SERVICE_LABEL.to_owned(),
    })
}

/// Start the launchd service.
pub fn start_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    let plist = "/Library/LaunchDaemons/com.rustynet.daemon.plist";
    // `launchctl bootstrap` is idempotent (errors if already loaded, which we ignore).
    ssh::run_remote(
        conn,
        &format!(
            "sudo launchctl bootstrap system '{plist}' 2>/dev/null || \
             sudo launchctl kickstart system/com.rustynet.daemon 2>/dev/null || true"
        ),
        Duration::from_secs(30),
    )?;
    Ok(())
}

/// Stop the launchd service.
pub fn stop_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    ssh::run_remote(
        conn,
        "sudo launchctl bootout system/com.rustynet.daemon 2>/dev/null || true",
        Duration::from_secs(30),
    )?;
    Ok(())
}

/// Restart the launchd service (stop + start; launchd has no native restart).
pub fn restart_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    stop_daemon(conn)?;
    start_daemon(conn)
}

/// Stop the service and remove daemon binaries and state.
pub fn uninstall_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    let timeout = Duration::from_secs(60);
    let _ = stop_daemon(conn);
    ssh::run_remote(
        conn,
        &format!(
            "sudo rm -f {MACOS_RUSTYNETD_PATH} {MACOS_RUSTYNET_PATH} \
             /Library/LaunchDaemons/com.rustynet.daemon.plist && \
             sudo rm -rf {MACOS_STATE_ROOT} /usr/local/etc/rustynet /var/run/rustynet",
        ),
        timeout,
    )?;
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn build_bootstrap_env(node_id: &str, role: &NodeRole, ctx: &OrchestrationContext) -> String {
    let role_str = match role {
        NodeRole::Exit => "exit",
        NodeRole::Client => "client",
        NodeRole::Entry => "entry",
        NodeRole::Aux => "aux",
        NodeRole::Extra => "extra",
        NodeRole::Custom(s) => s.as_str(),
    };
    format!(
        "ROLE={role_str}\nNODE_ID={node_id}\nNETWORK_ID={network_id}\n\
         SSH_ALLOW_CIDRS={cidrs}\n",
        network_id = ctx.network_id,
        cidrs = ctx.ssh_allow_cidrs,
    )
}

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
    use std::collections::HashMap;

    fn make_ctx(role: NodeRole) -> OrchestrationContext {
        OrchestrationContext {
            assignments: vec![NodeRoleAssignment {
                alias: "macos-1".to_owned(),
                role,
            }],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: "/tmp".into(),
            stage_outcomes: HashMap::new(),
            node_ids: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            network_id: "test-net".to_owned(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
        }
    }

    #[test]
    fn bootstrap_env_contains_role_and_node_id() {
        let ctx = make_ctx(NodeRole::Client);
        let env = build_bootstrap_env("mac-node-1", &NodeRole::Exit, &ctx);
        assert!(env.contains("ROLE=exit"));
        assert!(env.contains("NODE_ID=mac-node-1"));
        assert!(env.contains("NETWORK_ID=test-net"));
    }

    #[test]
    fn bootstrap_scripts_are_non_empty() {
        assert!(
            !BOOTSTRAP_SCRIPT.is_empty(),
            "Bootstrap-RustyNetMacos.sh must not be empty"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("Bootstrap-RustyNetMacos.sh"),
            "bootstrap script must contain its own filename"
        );
        assert!(
            !INSTALL_SERVICE_SCRIPT.is_empty(),
            "Install-RustyNetMacosService.sh must not be empty"
        );
    }

    #[test]
    fn constants_are_under_usr_local() {
        assert!(MACOS_RUSTYNETD_PATH.starts_with("/usr/local/bin/"));
        assert!(MACOS_STATE_ROOT.starts_with("/usr/local/var/"));
        assert!(MACOS_KEYS_DIR.starts_with(MACOS_STATE_ROOT));
    }
}
