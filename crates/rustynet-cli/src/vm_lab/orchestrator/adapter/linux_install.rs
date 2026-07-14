#![allow(dead_code)]
use std::time::Duration;

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::adapter::verifier_key::decode_assignment_pubkey_hex;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{AdapterError, InstallReport};
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::source_archive::SourceArchive;

/// Canonical path of `rustynetd` on Linux targets.
pub const LINUX_RUSTYNETD_PATH: &str = "/usr/local/bin/rustynetd";
/// Canonical path of `rustynet` CLI on Linux targets.
pub const LINUX_RUSTYNET_PATH: &str = "/usr/local/bin/rustynet";
/// Canonical path of the `rustynet-relay` sibling binary on Linux targets.
/// Built + installed by the bootstrap script (alongside rustynetd / rustynet)
/// so a node assigned (or later role-switched to) Relay always has it; the
/// relay *service* is only enabled on Relay nodes by `DeployRelayServiceStage`.
pub const LINUX_RUSTYNET_RELAY_PATH: &str = "/usr/local/bin/rustynet-relay";
/// Canonical systemd service name.
pub const LINUX_SERVICE_NAME: &str = "rustynetd";
/// Daemon UNIX socket path.
pub const LINUX_DAEMON_SOCKET: &str = "/run/rustynet/rustynetd.sock";

const LINUX_DAEMON_READY_PROBE: &str = "for i in $(seq 1 40); do \
       if sudo -n env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock \
          /usr/local/bin/rustynet status >/dev/null 2>&1; then \
         echo daemon-ready; exit 0; \
       fi; \
       sleep 1; \
     done; \
     sudo -n systemctl status rustynetd.service --no-pager || true; \
     echo daemon-not-ready; exit 1";

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
    let env_content = build_bootstrap_env(&node_id, &role, ctx)?;
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

    // Run bootstrap, streaming stdout+stderr to a per-node log so cargo
    // build progress is visible in real time rather than only on completion.
    let bootstrap_log = ctx
        .report_dir
        .join("logs")
        .join(format!("bootstrap_node_{alias}.log"));
    ssh::run_remote_with_log(
        conn,
        "chmod 700 /tmp/rn_bootstrap.sh && bash /tmp/rn_bootstrap.sh /tmp/rn_bootstrap.env",
        build_timeout,
        &bootstrap_log,
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
         test -x {LINUX_RUSTYNET_RELAY_PATH} && \
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
    // node_id flows from inventory/daemon status into a single-quoted arg below;
    // escape embedded single quotes for parity with ssh_allow_cidrs so a stray
    // quote cannot break out of the quoting (defence-in-depth).
    let node_id = node_id.replace('\'', "'\\''");

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
        "sudo -n env \
         PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin \
         RUSTYNET_INSTALL_SOURCE_ROOT={src_dir} \
         RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS=86400 \
         RUSTYNET_TRAVERSAL_MAX_AGE_SECS=86400 \
         RUSTYNET_DNS_ZONE_MAX_AGE_SECS=86400 \
         {LINUX_RUSTYNET_PATH} ops e2e-enforce-host \
         --role {role_str} \
         --node-id '{node_id}' \
         --src-dir '{src_dir}' \
         --ssh-allow-cidrs '{ssh_allow_cidrs}'"
    );
    ssh::run_remote(conn, &script, Duration::from_secs(120))?;
    Ok(())
}

/// Deploy the `rustynet-relay` sibling service onto this Relay node so the
/// `relay_validation` stage has a live relay to prove.
///
/// The relay binary is already present at [`LINUX_RUSTYNET_RELAY_PATH`] (built +
/// installed by the bootstrap script while the network was open). This step
/// supplies the two things the unit needs that the baseline install does not:
///
///   1. The relay `--verifier-key`: `rustynet-relay` loads it as raw 32 bytes,
///      and its systemd unit fail-closes (`ExecStartPre`) if the file is absent.
///      We derive it from the assignment authority public key the orchestrator
///      already distributed to this node as `/etc/rustynet/assignment.pub` (hex)
///      — the same control-plane verifier the relay must trust, and a PUBLIC key
///      (never secret), so it is safe to read, decode, and re-place. Decoding to
///      raw bytes happens in Rust (fail-closed on a short / non-hex key); the
///      bytes are shipped via scp + `install` so no data is ever interpolated
///      into a shell string and the guest needs no `xxd`.
///   2. The installed + enabled `rustynet-relay.service`, via the shared
///      `ops install-systemd-relay` helper — the one hardened relay-install path
///      (also used by the role-transition orchestrator). It reads the unit from
///      `scripts/systemd/rustynet-relay.service` relative to the source root the
///      bootstrap extracted to (`$HOME/Rustynet`), so it runs with that cwd.
///
/// Fail-closed throughout: a missing assignment key, a malformed key, or a
/// failed install all surface as `Err`.
pub fn deploy_relay_service(conn: &NodeConnection) -> Result<(), AdapterError> {
    let short_timeout = Duration::from_secs(30);

    // 1. Read the already-distributed assignment authority pubkey (hex). It
    //    lives at /etc/rustynet/assignment.pub (placed by
    //    distribute_verifier_key(Assignment) during DistributeAssignments).
    //    /etc/rustynet is 0750 root:rustynetd, so read it with sudo -n.
    let assignment_hex = ssh::run_remote(
        conn,
        "sudo -n cat /etc/rustynet/assignment.pub",
        short_timeout,
    )?;

    // 2. Decode hex -> raw 32 bytes (fail-closed); the relay --verifier-key
    //    loader requires exactly 32 raw bytes.
    let verifier_bytes = decode_assignment_pubkey_hex(&assignment_hex)
        .map_err(|message| AdapterError::Protocol { message })?;

    // 3. Ship the raw verifier key to the host and install it at the unit's
    //    fail-closed-checked path (mode 0644). scp the bytes (no shell data
    //    interpolation), then install with a constant command.
    let tmp = write_temp_file("rn_relay_verifier_", ".pub", &verifier_bytes)?;
    let ship = ssh::scp_to(
        conn,
        tmp.as_path(),
        "/tmp/rn-relay-verifier.pub",
        short_timeout,
    );
    let _ = std::fs::remove_file(&tmp);
    ship?;
    ssh::run_remote(
        conn,
        "sudo -n sh -c 'install -d -m 0750 /etc/rustynet && \
         install -m 0644 /tmp/rn-relay-verifier.pub /etc/rustynet/relay-verifier.pub && \
         rm -f /tmp/rn-relay-verifier.pub'",
        short_timeout,
    )?;

    // 4. Install + enable + start rustynet-relay.service via the shared helper.
    //    It reads scripts/systemd/rustynet-relay.service relative to cwd, so run
    //    from the source root the bootstrap extracted to ($HOME/Rustynet). The
    //    source dir is passed only inside a single-quoted env assignment; the
    //    executed shell body is a compile-time constant.
    let home = ssh::run_remote(conn, "echo $HOME", Duration::from_secs(10))?
        .trim()
        .to_owned();
    if home.is_empty() {
        return Err(AdapterError::Protocol {
            message: "could not determine $HOME on remote for install-systemd-relay".to_owned(),
        });
    }
    let src_dir = format!("{home}/Rustynet");
    let src_dir_esc = src_dir.replace('\'', "'\\''");
    // Absolute CLI path (not bare `rustynet`) so the install never depends on
    // sudo's PATH inside the root `sh -c`. The executed shell body stays a
    // compile-time constant; only the source dir is a (single-quoted) value.
    let install_cmd = format!(
        "sudo -n env RN_SRC='{src_dir_esc}' sh -c 'cd \"$RN_SRC\" && {LINUX_RUSTYNET_PATH} ops install-systemd-relay'"
    );
    ssh::run_remote(conn, &install_cmd, Duration::from_secs(120))?;
    Ok(())
}

/// Start the rustynetd systemd service.
///
/// In the orchestration pipeline, prefer `enforce_daemon` over this function:
/// `enforce_daemon` transitions the daemon from its bootstrap
/// (`auto_tunnel_enforce=false`) to an enforcement-enabled configuration.
/// `start_daemon` starts systemd, then waits until the daemon accepts a real
/// status request. This closes the systemd-active -> socket-accepting race.
pub fn start_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    run_systemctl(conn, "start")?;
    wait_for_linux_daemon_ready(conn)
}

/// Stop the rustynetd systemd service.
pub fn stop_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    run_systemctl(conn, "stop")
}

/// Restart the rustynetd systemd service.
pub fn restart_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    run_systemctl(conn, "restart")?;
    wait_for_linux_daemon_ready(conn)
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
    // Tear down the rustynet-relay sibling service first (best-effort — most
    // nodes never had it). Then remove both binaries, both unit files, the
    // relay env file, and all state dirs (incl the relay replay store under
    // /var/lib/rustynet and the relay runtime dir). Leaving a stranded relay
    // unit/binary would let a prior run's relay keep binding :4500 across runs.
    ssh::run_remote(
        conn,
        &format!(
            "sudo systemctl stop rustynet-relay.service 2>/dev/null || true; \
             sudo systemctl disable rustynet-relay.service 2>/dev/null || true; \
             sudo rm -f {LINUX_RUSTYNETD_PATH} {LINUX_RUSTYNET_PATH} {LINUX_RUSTYNET_RELAY_PATH} \
                        /etc/systemd/system/rustynetd.service /etc/systemd/system/rustynet-relay.service \
                        /etc/default/rustynet-relay && \
             sudo systemctl daemon-reload 2>/dev/null || true && \
             sudo rm -rf /etc/rustynet /var/lib/rustynet /run/rustynet /run/rustynet-relay",
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

fn wait_for_linux_daemon_ready(conn: &NodeConnection) -> Result<(), AdapterError> {
    let output = ssh::run_remote(conn, LINUX_DAEMON_READY_PROBE, Duration::from_secs(60))?;
    if output.contains("daemon-ready") {
        Ok(())
    } else {
        Err(AdapterError::Protocol {
            message: format!(
                "Linux daemon failed readiness probe at {LINUX_DAEMON_SOCKET}: {}",
                output.trim()
            ),
        })
    }
}

fn build_bootstrap_env(
    node_id: &str,
    role: &NodeRole,
    ctx: &OrchestrationContext,
) -> Result<String, AdapterError> {
    let role_str = role
        .daemon_node_role_for_platform(&VmGuestPlatform::Linux)
        .map_err(|message| AdapterError::Protocol { message })?;
    let ssh_allow_cidrs = &ctx.ssh_allow_cidrs;
    let network_id = &ctx.network_id;
    Ok(format!(
        "ROLE={role_str}\nNODE_ID={node_id}\nNETWORK_ID={network_id}\nSSH_ALLOW_CIDRS={ssh_allow_cidrs}\nSOURCE_ARCHIVE=/tmp/rn_source.tar.gz\nRUSTYNET_BOOTSTRAP_REGISTRY_ATTEMPTS=2\n"
    ))
}

/// Write `content` to a temp file with the given prefix and suffix.
/// Returns the temp file path.
fn write_temp_file(
    prefix: &str,
    suffix: &str,
    content: &[u8],
) -> Result<std::path::PathBuf, AdapterError> {
    // Bootstrap runs per-node in parallel. A PID-only name lets workers
    // overwrite one another's role/node-id env file before SCP, producing a
    // valid build with the wrong identity. `tempfile` creates a collision-free
    // mode-0600 file; persist it only until the caller finishes SCP.
    super::write_secure_temp_file(prefix, suffix, content)
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
            orchestrator_dialect: None,
        };
        let env = build_bootstrap_env("exit-node1-abc123", &NodeRole::Exit, &ctx).expect("env");
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
        assert!(
            env.contains("RUSTYNET_BOOTSTRAP_REGISTRY_ATTEMPTS=2"),
            "Rust-native lab bootstrap should reach offline fallback quickly on no-egress guests: {env}"
        );
    }

    #[test]
    fn parallel_temp_files_are_unique_and_keep_each_workers_content() {
        let payloads = [b"exit-node".as_slice(), b"client-a", b"client-b"];
        let paths = crate::vm_lab::orchestrator::parallel::bounded_parallel_map(
            &payloads,
            payloads.len(),
            |payload| write_temp_file("rn_parallel_test_", ".env", payload).unwrap(),
        );

        let unique: std::collections::HashSet<_> = paths.iter().collect();
        assert_eq!(unique.len(), payloads.len());
        for (path, expected) in paths.iter().zip(payloads) {
            assert_eq!(std::fs::read(path).unwrap(), expected);
            std::fs::remove_file(path).unwrap();
        }
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
            orchestrator_dialect: None,
        };
        for role in [
            NodeRole::Client,
            NodeRole::Entry,
            NodeRole::Aux,
            NodeRole::Extra,
        ] {
            let env = build_bootstrap_env("id1", &role, &ctx).expect("env");
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

    /// Regression: the Linux lab bootstrap must relax the freshness window
    /// (86400 s) for the auto-tunnel, traversal and DNS-zone bundles at
    /// bootstrap time, the same way the macOS Bootstrap-RustyNetMacos.sh and
    /// the Windows installer already do. The bootstrap installs the daemon via
    /// `rustynet ops e2e-bootstrap-host`, which forwards these env vars into
    /// `ops install-systemd`; without them a freshly bootstrapped Linux node
    /// runs the strict 300 s/120 s production window and can be stranded
    /// fail-closed if the later `e2e-enforce-host` pass is interrupted (the
    /// daemon ages a bundle past 300 s, wedges in restrict_permanent, and the
    /// enforce restart cannot cleanly cycle the socket). The systemd unit's
    /// 300 s/120 s production default is unchanged; this only sets the LAB
    /// window via the bootstrap env passthrough.
    #[test]
    fn bootstrap_script_relaxes_lab_freshness_window_for_all_bundles() {
        for env_assignment in [
            "RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS=86400",
            "RUSTYNET_TRAVERSAL_MAX_AGE_SECS=86400",
            "RUSTYNET_DNS_ZONE_MAX_AGE_SECS=86400",
        ] {
            assert!(
                BOOTSTRAP_SCRIPT.contains(env_assignment),
                "linux bootstrap must forward {env_assignment} on the e2e-bootstrap-host \
                 invocation so the bootstrap-time daemon uses the relaxed lab freshness \
                 window instead of the strict 300 s/120 s production default"
            );
        }
        // The relaxed env must be on the e2e-bootstrap-host invocation itself
        // (not some unrelated command), so e2e-bootstrap-host forwards it into
        // install-systemd.
        assert!(
            BOOTSTRAP_SCRIPT.contains("rustynet ops e2e-bootstrap-host"),
            "bootstrap must install the daemon via e2e-bootstrap-host"
        );
    }

    #[test]
    fn bootstrap_script_builds_and_installs_the_relay_binary() {
        // The relay runtime deploy stage assumes the bootstrap built + installed
        // rustynet-relay (the deploy stage only places the verifier key + unit).
        assert!(
            BOOTSTRAP_SCRIPT.contains("-p rustynet-relay --features daemon"),
            "bootstrap must build the rustynet-relay binary"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("install -m 0755 target/release/rustynet-relay"),
            "bootstrap must install rustynet-relay to /usr/local/bin"
        );
    }

    #[test]
    fn bootstrap_script_builds_only_the_installed_cli_binary() {
        // `cargo build -p rustynet-cli` builds every bin target in that package.
        // The lab installs only target/release/rustynet-cli, so building helper
        // bins on every node is dead work and made no-egress bootstrap much slower.
        assert!(
            BOOTSTRAP_SCRIPT.contains("-p rustynet-cli --features vm-lab --bin rustynet-cli"),
            "bootstrap must compile only the installed rustynet-cli binary, \
             with the vm-lab feature so guests serve the `ops e2e-*` \
             lab-protocol commands (RNQ-17 gates them out of default builds)"
        );
        assert!(
            !BOOTSTRAP_SCRIPT.contains("-p rustynetd -p rustynet-cli"),
            "bootstrap must not build the whole rustynet-cli package bin set"
        );
    }

    #[test]
    fn bootstrap_uses_absolute_installed_cli_under_sudo_secure_path() {
        assert!(BOOTSTRAP_SCRIPT.contains("/usr/local/bin/rustynet ops e2e-bootstrap-host"));
        assert!(
            BOOTSTRAP_SCRIPT
                .contains("PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin")
        );
        assert!(
            !BOOTSTRAP_SCRIPT.contains("\n  rustynet ops e2e-bootstrap-host"),
            "Rocky sudo secure_path may exclude /usr/local/bin"
        );
    }

    #[test]
    fn bootstrap_repins_regular_fail_closed_resolver_immediately_before_daemon_start() {
        assert!(BOOTSTRAP_SCRIPT.contains("pin_regular_resolv_conf()"));
        assert!(BOOTSTRAP_SCRIPT.contains("pin_regular_resolv_conf 1.1.1.1 8.8.8.8"));
        let protected_pin = BOOTSTRAP_SCRIPT
            .find("pin_regular_resolv_conf 127.0.0.1")
            .expect("protected resolver pin");
        let daemon_start = BOOTSTRAP_SCRIPT
            .find("/usr/local/bin/rustynet ops e2e-bootstrap-host")
            .expect("daemon bootstrap invocation");
        assert!(
            protected_pin < daemon_start,
            "regular loopback resolver must be pinned before rustynetd starts"
        );
        assert!(
            BOOTSTRAP_SCRIPT[protected_pin..daemon_start]
                .contains("failed to pin /etc/resolv.conf as a regular file")
                || BOOTSTRAP_SCRIPT.contains("[[ -L /etc/resolv.conf || ! -f /etc/resolv.conf ]]"),
            "bootstrap must fail closed if distro DNS management recreates a symlink"
        );
    }

    #[test]
    fn bootstrap_network_diagnostics_timeout_getent_before_offline_fallback() {
        // No-egress UTM guests can leave getent blocked indefinitely. Diagnostics
        // must be bounded so the script reaches the cargo --offline fallback.
        assert!(
            BOOTSTRAP_SCRIPT.contains("timeout 10 getent ahosts"),
            "bootstrap DNS diagnostics must not hang before offline cargo fallback"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("RUSTYNET_BOOTSTRAP_REGISTRY_ATTEMPTS:-8"),
            "bootstrap registry probe count should remain configurable"
        );
    }

    #[test]
    fn bootstrap_prerequisites_support_fedora_ca_and_llvm_layout() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("/etc/pki/tls/certs/ca-bundle.crt"),
            "Fedora/RHEL CA bundle must satisfy prerequisite validation"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("sqlite-devel clang llvm llvm-devel nftables"),
            "Fedora/RHEL install must include llvm-devel, which provides llvm-config"
        );
        assert!(BOOTSTRAP_SCRIPT.contains("wireguard-tools tar gzip tcpdump iputils"));
        assert!(BOOTSTRAP_SCRIPT.contains("tcpdump iputils-ping"));
        assert!(BOOTSTRAP_SCRIPT.contains("gzip tcpdump ping"));
        assert!(BOOTSTRAP_SCRIPT.contains("install_rustup_hardened"));
        assert!(BOOTSTRAP_SCRIPT.contains("${HOME}/.cargo/bin:/usr/local/sbin"));
        assert!(BOOTSTRAP_SCRIPT.contains("rustup-init.sha256"));
        assert!(BOOTSTRAP_SCRIPT.contains("sha256sum -c rustup-init.sha256"));
        assert!(
            !BOOTSTRAP_SCRIPT.contains("wireguard-tools rustup"),
            "Rocky repositories do not provide a rustup RPM; rustup must use the checksum-verified installer"
        );
    }

    #[test]
    fn bootstrap_root_timeout_wraps_child_command_not_sudo() {
        // `timeout sudo resolvectl ...` can leave the root child alive after
        // sudo exits. Run timeout under sudo so diagnostics cannot stall the
        // Rust engine before the offline cargo fallback.
        assert!(
            BOOTSTRAP_SCRIPT.contains("sudo -n timeout --kill-after=5"),
            "root command timeout must wrap the child command under sudo"
        );
    }

    #[test]
    fn bootstrap_keeps_firewalld_enabled_and_opens_only_wireguard_udp() {
        assert!(BOOTSTRAP_SCRIPT.contains("configure_lab_wireguard_firewall()"));
        assert!(BOOTSTRAP_SCRIPT.contains("systemctl is-active --quiet firewalld.service"));
        assert!(BOOTSTRAP_SCRIPT.contains("firewall-cmd --permanent --add-port=51820/udp"));
        assert!(BOOTSTRAP_SCRIPT.contains("firewall-cmd --add-port=51820/udp"));
        assert!(!BOOTSTRAP_SCRIPT.contains("systemctl stop firewalld"));
        assert!(!BOOTSTRAP_SCRIPT.contains("systemctl disable firewalld"));
    }

    #[test]
    fn daemon_start_readiness_requires_a_live_control_request() {
        assert!(LINUX_DAEMON_READY_PROBE.contains("for i in $(seq 1 40)"));
        assert!(LINUX_DAEMON_READY_PROBE.contains(LINUX_DAEMON_SOCKET));
        assert!(LINUX_DAEMON_READY_PROBE.contains("/usr/local/bin/rustynet status"));
        assert!(LINUX_DAEMON_READY_PROBE.contains("daemon-not-ready; exit 1"));
    }
}
