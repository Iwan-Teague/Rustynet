#![allow(dead_code)]
use std::io::Write as IoWrite;
use std::time::Duration;

use crate::vm_lab::VmGuestPlatform;
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
pub const MACOS_DAEMON_SOCKET: &str = "/private/var/run/rustynet/rustynetd.sock";
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
        "/tmp/Install-RustyNetMacosService.sh",
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
        "chmod 700 /tmp/rn_macos_bootstrap.sh /tmp/Install-RustyNetMacosService.sh && \
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

/// Bootstrap via a remote workdir.
///
/// Used when `rustynet_src_dir` is set in inventory.  When `source` is
/// `Some` and the workdir is absent on the remote host, the source
/// archive is SCP'd over and extracted into the workdir before the
/// build step runs.  This guarantees the bootstrap always builds the
/// freshest code rather than silently falling back to the binary
/// already installed at `/usr/local/bin/rustynetd` (which may be from
/// an earlier deploy).  Pass `None` only for legacy callers that
/// genuinely need the "use existing workdir if present, else
/// SKIP_BUILD" behaviour.
pub fn install_daemon_from_workdir(
    conn: &NodeConnection,
    alias: &str,
    workdir: &str,
    source: Option<&SourceArchive>,
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
        "/tmp/Install-RustyNetMacosService.sh",
        SHORT_TIMEOUT,
    )?;

    let _ = std::fs::remove_file(&env_tmp);
    let _ = std::fs::remove_file(&script_tmp);
    let _ = std::fs::remove_file(&install_tmp);

    // Probe: exit 0 if workdir exists, non-zero otherwise.
    let workdir_present =
        ssh::run_remote(conn, &format!("test -d '{workdir}'"), SHORT_TIMEOUT).is_ok();

    let build_cmd = if workdir_present {
        // Workdir already has the fresh source (a prior caller — e.g.
        // an earlier orchestrator stage or a manual sync — populated
        // it).  Pack it into the bootstrap archive path and proceed.
        format!(
            "chmod 700 /tmp/rn_macos_bootstrap.sh /tmp/Install-RustyNetMacosService.sh && \
             cd '{workdir}' && tar -czf /tmp/rn_source.tar.gz . && \
             echo 'SOURCE_ARCHIVE=/tmp/rn_source.tar.gz' >> /tmp/rn_macos_bootstrap.env && \
             sudo bash /tmp/rn_macos_bootstrap.sh /tmp/rn_macos_bootstrap.env"
        )
    } else if let Some(source) = source {
        // Workdir absent but the orchestrator carried a fresh source
        // archive.  Ship it directly, then run the bootstrap with
        // SOURCE_ARCHIVE pointing at the SCP'd tarball.  Skipping
        // build here (the old behaviour) silently kept stale
        // binaries across deploys and was the actual root cause of
        // "membership role preflight failed" reappearing after the
        // capability fix was merged.
        ssh::scp_to(conn, source.path(), "/tmp/rn_source.tar.gz", BUILD_TIMEOUT)?;
        "chmod 700 /tmp/rn_macos_bootstrap.sh /tmp/Install-RustyNetMacosService.sh && \
             echo 'SOURCE_ARCHIVE=/tmp/rn_source.tar.gz' >> /tmp/rn_macos_bootstrap.env && \
             sudo bash /tmp/rn_macos_bootstrap.sh /tmp/rn_macos_bootstrap.env"
            .to_owned()
    } else {
        // No workdir AND no source — last-resort legacy path: rely on
        // SKIP_BUILD=1 so the bootstrap re-runs the service-install
        // phase against whatever binary is already on disk.
        "chmod 700 /tmp/rn_macos_bootstrap.sh /tmp/Install-RustyNetMacosService.sh && \
             echo 'SKIP_BUILD=1' >> /tmp/rn_macos_bootstrap.env && \
             echo 'SOURCE_ARCHIVE=/dev/null' >> /tmp/rn_macos_bootstrap.env && \
             sudo bash /tmp/rn_macos_bootstrap.sh /tmp/rn_macos_bootstrap.env"
            .to_owned()
    };
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

/// Enforce production runtime for the macOS daemon.
///
/// Mirrors `enforce_daemon` on Linux: re-installs the launchd plist with
/// `--auto-tunnel-enforce true` and extended max-age windows, then restarts
/// the daemon so it picks up the bundles deployed in the prior pipeline stages.
///
/// Called by [`MacosNodeAdapter::enforce_runtime`] from the
/// `EnforceBaselineRuntime` stage, which runs after all bundle-distribution
/// stages (`DistributeAssignments`, `DistributeTraversal`, `DistributeDnsZone`)
/// have completed.
///
/// Max-age windows: 86400 s (24 h). The pipeline issues bundles once and does
/// not rotate them; production daemons rely on periodic refresh timers that do
/// not exist in the lab. This matches the Linux lab setting.
pub fn enforce_daemon(
    conn: &NodeConnection,
    alias: &str,
    ctx: &OrchestrationContext,
) -> Result<(), AdapterError> {
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
    let daemon_node_role = role
        .daemon_node_role_for_platform(&VmGuestPlatform::Macos)
        .map_err(|message| AdapterError::Protocol { message })?;
    let ssh_allow_cidrs = ctx.ssh_allow_cidrs.clone();
    let ssh_allow_flag = if ssh_allow_cidrs.is_empty() {
        "false"
    } else {
        "true"
    };

    // Write the install-service script to a temp file on the remote host and
    // re-invoke it with enforce-mode settings.  The script is compiled into the
    // binary so the same version is always used; the local working copy stays in
    // sync automatically when the binary is rebuilt.
    let install_tmp = write_temp_file(
        "rn_macos_install_svc_",
        ".sh",
        INSTALL_SERVICE_SCRIPT.as_bytes(),
    )?;
    ssh::scp_to(
        conn,
        install_tmp.as_path(),
        "/tmp/Install-RustyNetMacosService.sh",
        SHORT_TIMEOUT,
    )?;
    let _ = std::fs::remove_file(&install_tmp);

    // Build the re-install command: same params as bootstrap but with
    // auto-tunnel-enforce=true and extended max-age windows.
    // trust-max-age-secs 86400: macOS has no periodic trust-evidence refresh
    // timer (unlike Linux rustynetd-trust-refresh.service).  The lab issues
    // trust evidence once during bootstrap; 86400 s keeps it valid for the
    // duration of any reasonable lab run without requiring a separate refresh.
    let script = format!(
        "chmod 700 /tmp/Install-RustyNetMacosService.sh && \
         sudo /tmp/Install-RustyNetMacosService.sh \
           --rustynetd-bin {MACOS_RUSTYNETD_PATH} \
           --state-root {MACOS_STATE_ROOT} \
           --node-id '{node_id}' \
           --node-role '{daemon_node_role}' \
           --network-id '{network_id}' \
           --auto-tunnel-enforce true \
           --trust-max-age-secs 86400 \
           --auto-tunnel-max-age-secs 86400 \
           --traversal-max-age-secs 86400 \
           --dns-zone-max-age-secs 86400 \
           --fail-closed-ssh-allow '{ssh_allow_flag}' \
           --fail-closed-ssh-allow-cidrs '{ssh_allow_cidrs}'",
        network_id = ctx.network_id,
    );
    ssh::run_remote(conn, &script, Duration::from_secs(60))?;
    Ok(())
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
             sudo rm -rf {MACOS_STATE_ROOT} /usr/local/etc/rustynet /private/var/run/rustynet",
        ),
        timeout,
    )?;
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn build_bootstrap_env(node_id: &str, role: &NodeRole, ctx: &OrchestrationContext) -> String {
    let role_str = role.as_str();
    let daemon_node_role = role
        .daemon_node_role_for_platform(&VmGuestPlatform::Macos)
        .expect("macOS lab role must have explicit daemon role mapping");
    format!(
        "ROLE={role_str}\nDAEMON_NODE_ROLE={daemon_node_role}\nNODE_ID={node_id}\nNETWORK_ID={network_id}\n\
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
        assert!(env.contains("DAEMON_NODE_ROLE=blind_exit"));
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
    fn bootstrap_maps_orchestrator_exit_role_to_daemon_blind_exit() {
        assert!(
            !BOOTSTRAP_SCRIPT.contains("daemon_node_role_from_orchestrator_role"),
            "macOS daemon role mapping must live in Rust role model, not bootstrap shell"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("DAEMON_NODE_ROLE"),
            "bootstrap script must consume explicit Rust-provided daemon role"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("admin|client|blind_exit"),
            "bootstrap script must validate daemon role values fail-closed"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("--node-role \"${daemon_node_role}\""),
            "installer call must pass explicit daemon node role, not raw ROLE"
        );
    }

    #[test]
    fn install_service_script_pins_userspace_shared_backend_and_keychain_env() {
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("<string>macos-wireguard-userspace-shared</string>"),
            "install script must launch userspace-shared backend"
        );
        assert!(
            !INSTALL_SERVICE_SCRIPT.contains("<string>macos-wireguard</string>"),
            "install script must not regress to legacy command backend"
        );
        for needle in [
            "--wg-private-key",
            "--wg-encrypted-private-key",
            "--wg-key-passphrase",
            "RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT",
            "RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE",
            "RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH",
        ] {
            assert!(
                INSTALL_SERVICE_SCRIPT.contains(needle),
                "install script missing {needle}"
            );
        }
    }

    #[test]
    fn install_service_script_rejects_plist_unsafe_inputs_before_rendering() {
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("require_safe_plist_string"),
            "install script must validate plist-rendered path inputs"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("--node-id contains characters unsafe"),
            "install script must validate node id before plist rendering"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("--network-id contains characters unsafe"),
            "install script must validate network id before plist rendering"
        );
    }

    #[test]
    fn constants_are_under_usr_local() {
        assert!(MACOS_RUSTYNETD_PATH.starts_with("/usr/local/bin/"));
        assert!(MACOS_STATE_ROOT.starts_with("/usr/local/var/"));
        assert!(MACOS_KEYS_DIR.starts_with(MACOS_STATE_ROOT));
    }
}
