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
    let _ = socket_timeout; // daemon socket is checked in enforce_baseline_runtime / validate_baseline_runtime, not install.

    // Verify binaries are present and the rustynetd group exists.
    // /var/lib/rustynet/keys is `drwx------ root:root` (mode 700) by design
    // so the orchestrator's SSH user cannot stat through it without sudo.
    // Using `sudo -n` keeps the check non-interactive and consistent with
    // the bootstrap script's other privileged steps; passwordless sudo is
    // already a precondition of the bootstrap path.
    let verify_script = format!(
        "test -x {LINUX_RUSTYNETD_PATH} && test -x {LINUX_RUSTYNET_PATH} && \
         sudo -n test -f /var/lib/rustynet/keys/wireguard.pub && \
         getent group rustynetd >/dev/null 2>&1",
    );
    ssh::run_remote(conn, &verify_script, short_timeout)?;

    Ok(InstallReport {
        daemon_path: LINUX_RUSTYNETD_PATH.into(),
        service_name: LINUX_SERVICE_NAME.to_owned(),
    })
}

/// Enforce baseline runtime: re-run `install-systemd` with
/// `auto_tunnel_enforce=true` so the daemon applies assignment bundles.
///
/// Called by `EnforceBaselineRuntime` after all verifier keys are in place.
/// This is distinct from `start_daemon` (plain `systemctl start`, a no-op if
/// the daemon is already running) because:
///  * Bootstrap starts the daemon with `auto_tunnel_enforce=false`.
///  * After assignment/traversal/dns-zone bundles are distributed we must
///    restart the daemon with enforcement enabled and a fresh trust token.
///  * `rustynet ops e2e-enforce-host` wraps `ops install-systemd` with the
///    correct env and refreshes trust evidence immediately before restart.
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
    let role_str = role
        .daemon_node_role_for_platform(&VmGuestPlatform::Linux)
        .map_err(|message| AdapterError::Protocol { message })?;
    // SSH_ALLOW_CIDRS may contain commas; quote the whole arg.
    // Backslash-escape any single quotes in the cidr string (none expected in practice).
    let ssh_allow_cidrs = ctx.ssh_allow_cidrs.replace('\'', "'\\''");

    // Detect the SSH user's home directory for the source root that the
    // bootstrap script extracts to (`${HOME}/Rustynet`).
    let home = ssh::run_remote(conn, "echo $HOME", Duration::from_secs(10))?
        .trim()
        .to_owned();
    if home.is_empty() {
        return Err(AdapterError::Protocol {
            message: "could not determine $HOME on remote for e2e-enforce-host".to_owned(),
        });
    }
    let src_dir = format!("{home}/Rustynet");

    // Run e2e-enforce-host as root: re-installs systemd units with
    // auto_tunnel_enforce=true and refreshes trust evidence before restart.
    // Budget: install-systemd rebuild is fast (binaries already present);
    // add 120 s for daemon restart + socket readiness poll.
    //
    // RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS=86400: the assignment bundle is issued
    // by the exit node during DistributeAssignments and may be several minutes
    // old by the time enforce_daemon runs.  The production default (300 s) is
    // correct for nodes with an active assignment-refresh timer, but the lab
    // pipeline distributes a single bundle and doesn't rotate it.  86400 s
    // matches the Windows lab setting and lets the daemon start successfully.
    //
    // RUSTYNET_TRAVERSAL_MAX_AGE_SECS=86400: the traversal bundle is issued
    // with a 120-s TTL but the lab pipeline does not refresh it, so the same
    // extended window is needed here.
    //
    // RUSTYNET_DNS_ZONE_MAX_AGE_SECS=86400: the dns-zone bundle is distributed
    // once by DistributeDnsZone and is not refreshed.  The default 300-s window
    // causes dns_alarm_state=error once the bundle ages past 5 minutes, which
    // can block traffic validation in longer pipeline runs.
    let script = format!(
        "sudo \
         RUSTYNET_INSTALL_SOURCE_ROOT={src_dir} \
         RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS=86400 \
         RUSTYNET_TRAVERSAL_MAX_AGE_SECS=86400 \
         RUSTYNET_DNS_ZONE_MAX_AGE_SECS=86400 \
         rustynet ops e2e-enforce-host \
         --role {role_str} \
         --node-id '{node_id}' \
         --src-dir '{src_dir}' \
         --ssh-allow-cidrs '{ssh_allow_cidrs}'"
    );
    ssh::run_remote(conn, &script, Duration::from_secs(120))?;
    Ok(())
}

/// Start the rustynetd systemd service.
///
/// In the orchestration pipeline, prefer `enforce_daemon` over this function:
/// `enforce_daemon` transitions the daemon from its bootstrap
/// (`auto_tunnel_enforce=false`) to an enforcement-enabled configuration.
/// `start_daemon` is a plain `systemctl start`, which is a no-op when the
/// daemon is already running.
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
        "if sudo systemctl is-active rustynetd >/dev/null 2>&1; then sudo systemctl stop rustynetd; fi",
        timeout,
    );
    // Remove WireGuard interface if still present (daemon may not have torn it
    // down, e.g. if the previous run's cleanup stage was skipped).  Best-effort.
    let _ = ssh::run_remote(
        conn,
        "sudo ip link delete rustynet0 2>/dev/null || true",
        Duration::from_secs(10),
    );
    ssh::run_remote(
        conn,
        &format!(
            "sudo rm -f {LINUX_RUSTYNETD_PATH} {LINUX_RUSTYNET_PATH} /etc/systemd/system/rustynetd.service && sudo systemctl daemon-reload 2>/dev/null || true && sudo rm -rf /etc/rustynet /var/lib/rustynet /run/rustynet",
        ),
        timeout,
    )?;
    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn run_systemctl(conn: &NodeConnection, action: &str) -> Result<(), AdapterError> {
    let timeout = Duration::from_secs(60);
    ssh::run_remote(conn, &format!("sudo systemctl {action} rustynetd"), timeout)?;
    Ok(())
}

fn build_bootstrap_env(node_id: &str, role: &NodeRole, ctx: &OrchestrationContext) -> String {
    let role_str = role
        .daemon_node_role_for_platform(&VmGuestPlatform::Linux)
        .expect("Linux lab role must have explicit daemon role mapping");
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
            alias: "node1".to_owned(),
            role: NodeRole::Exit,
        }];
        let ctx = OrchestrationContext {
            assignments,
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: "/tmp".into(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            network_id: "test-net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: "10.0.0.0/8".to_owned(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
        };
        let env = build_bootstrap_env("exit-node1-abc123", &NodeRole::Exit, &ctx);
        assert!(
            env.contains("ROLE=admin"),
            "exit node must map to admin role: {env}"
        );
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
    fn bootstrap_env_non_exit_roles_map_to_client() {
        use std::collections::HashMap;
        let ctx = OrchestrationContext {
            assignments: vec![],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: "/tmp".into(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
        };
        for role in [
            NodeRole::Client,
            NodeRole::Entry,
            NodeRole::Aux,
            NodeRole::Extra,
        ] {
            let env = build_bootstrap_env("id1", &role, &ctx);
            assert!(
                env.contains("ROLE=client"),
                "non-exit role {role:?} must map to client: {env}"
            );
        }
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
