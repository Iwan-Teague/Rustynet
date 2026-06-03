#![allow(dead_code)]
use std::time::Duration;

use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::{AdapterError, TrafficTestResult, TunnelsList};

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const MEDIUM_TIMEOUT: Duration = Duration::from_secs(120);

/// Flush every `rustynet*` nftables table (the bootstrap killswitch
/// `rustynet_boot` AND any runtime generation table such as `rustynet_g1` a
/// crashed daemon left behind). Their default OUTPUT policy is drop, which would
/// block the next bootstrap's outbound traffic (incl. cargo registry downloads).
/// Enumerated (not a fixed name) so an unanticipated table cannot leave egress
/// blocked; idempotent (no matching tables → no-op) and best-effort.
///
/// The table list is captured into `$rn_tables` FIRST, then iterated with a
/// `for` loop. The obvious `nft list tables | awk … | while read t; do sudo
/// nft delete …; done` is BROKEN: the `sudo` inside the loop shares the loop's
/// stdin (the awk pipe) and drains it, so `read` never sees the table names and
/// nothing is deleted. That silent no-op left `rustynet_boot` behind on every
/// run; `assert_node_clean` (C2) is what surfaced it. Capture-then-`for` has no
/// pipe for the inner `sudo` to consume.
///
/// Wrapped in a bounded retry-until-clean loop: the `rustynet_boot` L8 boot
/// killswitch is installed at the daemon's `ExecStartPre` and survives teardown
/// by design, and a daemon torn down mid-shutdown (or a restart that fires
/// inside `RestartSec` right as cleanup disables it) can re-program a table
/// after a single delete pass — observed live as `assert_node_clean` finding
/// `rustynet_boot` after cleanup. Re-deleting until no `rustynet*` table remains
/// converges once the daemon is actually down (nothing re-applies the table with
/// the unit stopped, verified live).
const LINUX_NFT_KILLSWITCH_RESET_COMMAND: &str = "if command -v nft >/dev/null 2>&1; then \
         for _ in $(seq 1 10); do \
             rn_tables=$(sudo -n nft list tables 2>/dev/null \
                 | awk '$2==\"inet\" && $3 ~ /^rustynet/ {print $3}'); \
             [ -z \"$rn_tables\" ] && break; \
             for t in $rn_tables; do sudo -n nft delete table inet \"$t\" 2>/dev/null || true; done; \
             sleep 0.5; \
         done; \
     fi";

/// Collect `WireGuard` public key from `/var/lib/rustynet/keys/wireguard.pub`.
/// Returns the base64-encoded key as a hex string (32-byte decode → hex).
pub fn collect_wireguard_public_key(conn: &NodeConnection) -> Result<String, AdapterError> {
    let raw = ssh::run_remote(
        conn,
        "if sudo -n true >/dev/null 2>&1; then \
             sudo -n cat /var/lib/rustynet/keys/wireguard.pub; \
         else \
             cat /var/lib/rustynet/keys/wireguard.pub; \
         fi",
        SHORT_TIMEOUT,
    )?;
    let hex = decode_wireguard_pubkey_to_hex(raw.trim())
        .map_err(|err| AdapterError::Protocol { message: err })?;
    Ok(hex)
}

/// Read the local `node_id` from the running daemon via `rustynet status`.
pub fn collect_node_id(conn: &NodeConnection) -> Result<String, AdapterError> {
    // /run/rustynet/ is mode 770 root:rustynetd; the daemon control socket
    // is unreadable to a non-root SSH user, so the status query needs sudo.
    //
    // This runs in the CollectPubkeys stage, immediately after bootstrap.
    // `install_daemon` does NOT wait for the socket (unlike the macOS path),
    // and systemd reports the unit active before the daemon binds its socket,
    // so a single status query can race the daemon's startup. Retry for up to
    // ~40 s (matching the macOS socket wait) before giving up.
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    loop {
        let attempt_err = match ssh::run_remote(
            conn,
            "sudo -n env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet status",
            SHORT_TIMEOUT,
        ) {
            Ok(status) => match ssh::parse_status_node_id(&status) {
                Some(node_id) => return Ok(node_id),
                None => AdapterError::Protocol {
                    message: format!(
                        "node_id field not found in rustynet status output: {}",
                        &status[..status.len().min(200)]
                    ),
                },
            },
            Err(e) => e,
        };
        if std::time::Instant::now() >= deadline {
            return Err(attempt_err);
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// Positive connectivity: ping `peer_mesh_ip` 3 times via the tunnel.
/// Returns `TrafficTestResult::Reachable` on success.
pub fn ping_mesh_peer(
    conn: &NodeConnection,
    peer_mesh_ip: &str,
) -> Result<TrafficTestResult, AdapterError> {
    validate_ip_arg(peer_mesh_ip)?;
    let script = format!("ping -c 3 -W 5 {peer_mesh_ip} >/dev/null 2>&1");
    match ssh::run_remote_check(conn, &script, Duration::from_secs(30))? {
        true => Ok(TrafficTestResult::Reachable),
        false => Ok(TrafficTestResult::Error(format!(
            "ping to {peer_mesh_ip} failed"
        ))),
    }
}

/// Negative ACL test: confirm `denied_ip` is blocked by default-deny policy.
/// MUST return `TrafficTestResult::Blocked` for the stage to pass.
pub fn probe_denied_peer(
    conn: &NodeConnection,
    denied_ip: &str,
) -> Result<TrafficTestResult, AdapterError> {
    validate_ip_arg(denied_ip)?;
    // ping with a very short deadline — we expect it to fail immediately.
    let script = format!("ping -c 1 -W 2 {denied_ip} >/dev/null 2>&1");
    match ssh::run_remote_check(conn, &script, Duration::from_secs(10))? {
        // Ping succeeded → traffic reached the denied target → security failure.
        true => Ok(TrafficTestResult::Reachable),
        // Ping failed → as expected, traffic is blocked.
        false => Ok(TrafficTestResult::Blocked),
    }
}

/// Collect list of active `WireGuard` tunnels from `wg show all latest-handshakes`.
pub fn collect_active_tunnels(conn: &NodeConnection) -> Result<TunnelsList, AdapterError> {
    let output = ssh::run_remote(
        conn,
        "if command -v wg >/dev/null 2>&1; then \
             if sudo -n true >/dev/null 2>&1; then \
                 sudo -n wg show all latest-handshakes 2>&1; \
             else \
                 wg show all latest-handshakes 2>&1; \
             fi; \
         else \
             echo wg-not-installed; \
         fi",
        SHORT_TIMEOUT,
    )?;
    let tunnels: Vec<String> = output
        .lines()
        .filter(|line| !line.is_empty())
        .map(std::string::ToString::to_string)
        .collect();

    // Kernel WireGuard backends expose peers via `wg show`. The
    // `linux-wireguard-userspace-shared` backend (boringtun on a TUN device)
    // registers nothing with kernel `wg`, so `wg show` is empty (or `wg` is
    // absent) even with a live tunnel carrying traffic. Fall back to the
    // daemon's own status, which is backend-agnostic: a non-fail-closed daemon
    // with at least one programmed peer tunnel is an active tunnel.
    let kernel_wg_unusable =
        tunnels.is_empty() || tunnels.iter().all(|l| l.contains("wg-not-installed"));
    if kernel_wg_unusable {
        let status = ssh::run_remote(
            conn,
            "sudo -n rustynet status 2>/dev/null || rustynet status 2>/dev/null || true",
            SHORT_TIMEOUT,
        )?;
        let derived = tunnels_from_daemon_status(&status);
        if !derived.is_empty() {
            return Ok(TunnelsList { tunnels: derived });
        }
    }
    Ok(TunnelsList { tunnels })
}

/// Derive the active-tunnel list from `rustynet status` (space-separated
/// `key=value` tokens) for backends `wg show` cannot see. Returns one synthetic
/// line per programmed peer when the daemon is NOT fail-closed
/// (`restriction_mode=None`) and has at least one programmed peer tunnel
/// (`path_programmed_peer_count>=1`); otherwise empty (fail-closed: a restricted
/// daemon or a zero-peer dataplane is not an active tunnel).
fn tunnels_from_daemon_status(status: &str) -> Vec<String> {
    let value = |key: &str| {
        status
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix(key))
    };
    let not_restricted = value("restriction_mode=") == Some("None");
    let programmed = value("path_programmed_peer_count=")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    if !not_restricted || programmed == 0 {
        return Vec::new();
    }
    let mode = value("path_programmed_mode=").unwrap_or("programmed");
    (0..programmed)
        .map(|i| {
            format!("userspace-shared peer {i}: {mode} (dataplane applied, restriction_mode=None)")
        })
        .collect()
}

/// Collect diagnostic artifacts from the remote host to `dst`.
/// Key material paths (`*/keys/*`, `*.priv`, `*.pem`) MUST NOT appear in
/// the archive. This is enforced by the `--exclude` arguments to tar and
/// verified by the key-exclusion invariant test.
pub fn collect_artifacts(conn: &NodeConnection, dst: &std::path::Path) -> Result<(), AdapterError> {
    use std::time::Duration;

    let remote_tmp = "/tmp/rn_diag_artifacts.tar.gz";
    // Create archive on remote, excluding key material. /var/lib/rustynet/
    // and /run/rustynet/ are root-owned, mode 700/770; tar needs sudo to
    // read into them. We then chown the archive back so scp_from (running
    // as the SSH user) can read it.
    let tar_script = format!(
        "sudo -n tar -czf {remote_tmp} \
         --exclude='*/keys/*' \
         --exclude='*.priv' \
         --exclude='*.pem' \
         --exclude='*.key' \
         --ignore-failed-read \
         /var/lib/rustynet/ \
         /var/log/ \
         /run/rustynet/ \
         2>/dev/null; \
         sudo -n chown \"$(id -u):$(id -g)\" {remote_tmp} 2>/dev/null; \
         true"
    );
    ssh::run_remote(conn, &tar_script, Duration::from_secs(60))?;

    // Download the archive.
    ssh::scp_from(conn, remote_tmp, dst, Duration::from_secs(120))?;

    // Remove temp archive from remote (best-effort).
    let _ = ssh::run_remote(conn, &format!("rm -f {remote_tmp}"), SHORT_TIMEOUT);

    // Verify the archive contains no key material — security invariant check.
    verify_no_key_material(dst)?;

    Ok(())
}

/// Remove runtime state files, leaving the installation intact.
pub fn cleanup_runtime_state(conn: &NodeConnection) -> Result<(), AdapterError> {
    // Disable + stop the ENTIRE rustynet systemd footprint and WAIT until no
    // rustynetd process remains BEFORE the nft reset below. A daemon — or a
    // timer-driven service — re-applies the `rustynet_boot` fail-closed
    // killswitch after the reset deletes it, which then trips assert_node_clean.
    // Three refinements over stopping `rustynetd` alone:
    //   1. The unit set is ENUMERATED dynamically (`systemctl list-unit-files`
    //      filtered to `rustynet*`), not a fixed list. A node re-provisioned
    //      into a new role can be running units from a prior role —
    //      `rustynet-relay`, `rustynetd-privileged-helper`,
    //      `rustynetd-managed-dns`, the refresh timers, and crucially the
    //      `rustynet-push-all.timer` bundle-distribution timer, which fires
    //      periodically and re-applies `rustynet_boot` minutes after cleanup.
    //      Observed live as assert_node_clean finding `rustynet_boot` on the
    //      exit node even after a clean reset, because the enabled push-all
    //      timer re-installed it between the reset and the assertion. Enumerating
    //      catches every unit, including any added later.
    //   2. The wait keys on the actual PROCESS (`pgrep -x rustynetd`), not the
    //      systemd unit state, so a daemon launched outside `rustynetd.service`
    //      (or still mid-shutdown re-applying the boot table) is waited out.
    //   3. A `sudo pkill -x rustynetd` backstop terminates any stray daemon the
    //      units do not own (after `disable --now`, so systemd will not restart
    //      it). reset-failed clears failed-unit latches.
    // Best-effort: a host without any rustynet unit is a no-op.
    let _ = ssh::run_remote(
        conn,
        "rn_units=$(systemctl list-unit-files 2>/dev/null \
             | awk '$1 ~ /^rustynet/ {print $1}'); \
         for unit in $rn_units; do \
             sudo -n systemctl disable --now \"$unit\" 2>/dev/null || true; \
         done; \
         sudo -n pkill -x rustynetd 2>/dev/null || true; \
         for _ in $(seq 1 60); do \
             pgrep -x rustynetd >/dev/null 2>&1 && sleep 0.5 || break; \
         done; \
         for unit in $rn_units; do \
             sudo -n systemctl reset-failed \"$unit\" 2>/dev/null || true; \
         done",
        Duration::from_secs(60),
    );
    // Flush every rustynet nftables table the daemon may have left behind so the
    // next bootstrap is not blocked by a leftover default-deny killswitch.
    let _ = ssh::run_remote(
        conn,
        LINUX_NFT_KILLSWITCH_RESET_COMMAND,
        Duration::from_secs(30),
    );
    // Restart systemd-resolved so the next bootstrap inherits a clean DNS
    // stub. The daemon's network plumbing can leave the stub at 127.0.0.53
    // in a degraded state after teardown, causing DNS timeouts during cargo
    // registry downloads in the subsequent bootstrap stage.
    let _ = ssh::run_remote(
        conn,
        "if command -v systemctl >/dev/null 2>&1 && \
              systemctl is-active systemd-resolved >/dev/null 2>&1; then \
             sudo -n systemctl restart systemd-resolved 2>/dev/null || true; \
         fi",
        Duration::from_secs(30),
    );
    // Privileged: state files are root:rustynetd, mode 600/640.
    ssh::run_remote(
        conn,
        // rustynetd.state persists operational state (incl. selected_exit_node)
        // across restarts; purge it on rebuild so the daemon re-derives its exit
        // selection from the freshly distributed auto-tunnel bundle rather than
        // a stale prior-topology value (see macos_traffic::cleanup_runtime_state
        // for the live failure mode). No anti-replay watermark lives in it.
        "sudo -n rm -rf /run/rustynet \
         /var/lib/rustynet/membership.snapshot \
         /var/lib/rustynet/membership.log \
         /var/lib/rustynet/membership.watermark \
         /var/lib/rustynet/rustynetd.assignment \
         /var/lib/rustynet/rustynetd.assignment.watermark \
         /var/lib/rustynet/rustynetd.traversal \
         /var/lib/rustynet/rustynetd.traversal.watermark \
         /var/lib/rustynet/rustynetd.dns-zone \
         /var/lib/rustynet/rustynetd.state \
         /var/lib/rustynet/rustynetd.trust 2>/dev/null; true",
        Duration::from_secs(30),
    )?;
    Ok(())
}

/// Best-effort: the Linux daemon's own fail-closed/startup reason, read from
/// `/var/lib/rustynet/logs/rustynetd.log`, so an enforce failure reports the
/// cause rather than just the daemon-socket-timeout symptom.
pub fn collect_daemon_failure_reason(
    conn: &NodeConnection,
) -> Result<Option<String>, AdapterError> {
    let tail = ssh::run_remote(
        conn,
        "sudo -n tail -n 200 /var/lib/rustynet/logs/rustynetd.log 2>/dev/null || true",
        SHORT_TIMEOUT,
    )?;
    Ok(crate::vm_lab::orchestrator::adapter::node_adapter::extract_daemon_failure_reason(&tail))
}

/// nftables probe used by [`assert_node_clean`]: prints any leftover `rustynet*`
/// inet table names (space-separated); empty output means the node is clean.
const LINUX_NFT_LEFTOVER_PROBE: &str = "sudo -n nft list tables 2>/dev/null \
     | awk '$2==\"inet\" && $3 ~ /^rustynet/ {print $3}' | tr '\\n' ' '";

/// After cleanup, assert no leftover RustyNet nftables killswitch table remains
/// (a default-deny `rustynet*` table would starve the next bootstrap's egress).
/// Fails loudly so a reset that did not take is caught here, not as a cargo DNS
/// timeout five stages later.
pub fn assert_node_clean(conn: &NodeConnection) -> Result<(), AdapterError> {
    let leftover = ssh::run_remote(conn, LINUX_NFT_LEFTOVER_PROBE, SHORT_TIMEOUT)?;
    let leftover = leftover.trim();
    if leftover.is_empty() {
        Ok(())
    } else {
        Err(AdapterError::Protocol {
            message: format!(
                "node still dirty: leftover rustynet nftables table(s) after cleanup: {leftover}"
            ),
        })
    }
}

/// Verify SSH connectivity by running a no-op command.
pub fn check_ssh_reachable(conn: &NodeConnection) -> Result<(), AdapterError> {
    ssh::run_remote(conn, "echo reachable", Duration::from_secs(10))?;
    Ok(())
}

/// Collect the `WireGuard` mesh IP from the running daemon interface or status.
pub fn collect_mesh_ip(conn: &NodeConnection) -> Result<String, AdapterError> {
    let ip = ssh::run_remote(
        conn,
        "ip addr show rustynet0 2>/dev/null \
         | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -1 || echo ''",
        SHORT_TIMEOUT,
    )?;
    let ip = ip.trim().to_owned();
    if !ip.is_empty() {
        return Ok(ip);
    }
    let status = ssh::run_remote(
        conn,
        "rustynet status 2>/dev/null || echo ''",
        SHORT_TIMEOUT,
    )?;
    ssh::parse_status_field(&status, "mesh_ip")
        .or_else(|| ssh::parse_status_field(&status, "wg_ip"))
        .ok_or_else(|| AdapterError::Protocol {
            message: "mesh IP not found via rustynet0 interface or rustynet status".to_owned(),
        })
}

/// Issue signed bundles on this exit node and SCP the results to `local_out_dir`.
pub fn issue_bundles_to_dir(
    conn: &NodeConnection,
    rustynet_path: &str,
    kind: &crate::vm_lab::orchestrator::error::BundleKind,
    env_content: &str,
    local_out_dir: &std::path::Path,
) -> Result<(), AdapterError> {
    use std::io::Write as IoWrite;
    let pid = std::process::id();
    let remote_env = format!("/tmp/rn_issue_env_{pid}.env");
    let remote_issue_dir = format!("/tmp/rn_issue_{pid}");

    let issue_subcmd = match kind {
        crate::vm_lab::orchestrator::error::BundleKind::Assignment => {
            "e2e-issue-assignment-bundles-from-env"
        }
        crate::vm_lab::orchestrator::error::BundleKind::Traversal => {
            "e2e-issue-traversal-bundles-from-env"
        }
        crate::vm_lab::orchestrator::error::BundleKind::DnsZone => {
            "e2e-issue-dns-zone-bundles-from-env"
        }
        crate::vm_lab::orchestrator::error::BundleKind::Membership => {
            return Err(AdapterError::Protocol {
                message: "Membership bundles are issued via init_membership_snapshot".to_owned(),
            });
        }
    };

    let mut env_tmp = std::env::temp_dir();
    env_tmp.push(format!("rn_issue_env_{pid}.env"));
    {
        let mut f = std::fs::File::create(&env_tmp).map_err(|e| AdapterError::Io {
            message: format!("create env tmp: {e}"),
        })?;
        f.write_all(env_content.as_bytes())
            .map_err(|e| AdapterError::Io {
                message: format!("write env tmp: {e}"),
            })?;
    }
    ssh::scp_to(conn, &env_tmp, &remote_env, MEDIUM_TIMEOUT)?;
    let _ = std::fs::remove_file(&env_tmp);

    ssh::run_remote(
        conn,
        &format!("mkdir -p '{remote_issue_dir}'"),
        SHORT_TIMEOUT,
    )?;

    // Ensure /etc/rustynet/ has the strict mode 0750 root:rustynetd that
    // validate_key_custody_permissions requires before the signing-secret load.
    // install-systemd sets this during bootstrap, but some bootstrap paths
    // leave it at 0755 if install-systemd runs before the rustynetd group GID
    // is fully resolved.  Re-enforcing here is safe and idempotent.
    ssh::run_remote(
        conn,
        "sudo -n chmod 0750 /etc/rustynet && \
         sudo -n chown root:rustynetd /etc/rustynet",
        SHORT_TIMEOUT,
    )?;

    let safe_rustynet = rustynet_path.replace('\'', "'\"'\"'");
    ssh::run_remote(
        conn,
        &format!(
            "sudo -n env RUSTYNET_NODE_ROLE=admin \
             '{safe_rustynet}' ops {issue_subcmd} \
             --env-file '{remote_env}' --issue-dir '{remote_issue_dir}'"
        ),
        MEDIUM_TIMEOUT,
    )?;

    // rustynet creates the issue dir as root:root 0700; make it and its
    // files readable by the SSH user so the listing and scp_from below work.
    ssh::run_remote(
        conn,
        &format!(
            "sudo -n chmod 755 '{remote_issue_dir}' && \
             sudo -n chmod 644 '{remote_issue_dir}'/*"
        ),
        SHORT_TIMEOUT,
    )?;

    let listing = ssh::run_remote(
        conn,
        &format!("ls -1 '{remote_issue_dir}' 2>/dev/null"),
        SHORT_TIMEOUT,
    )?;

    std::fs::create_dir_all(local_out_dir).map_err(|e| AdapterError::Io {
        message: format!("create local out dir: {e}"),
    })?;

    for filename in listing.lines().map(str::trim).filter(|s| !s.is_empty()) {
        let remote_path = format!("{remote_issue_dir}/{filename}");
        let local_path = local_out_dir.join(filename);
        ssh::scp_from(conn, &remote_path, &local_path, MEDIUM_TIMEOUT)?;
    }

    let _ = ssh::run_remote(
        conn,
        &format!("rm -f '{remote_env}' && rm -rf '{remote_issue_dir}'"),
        SHORT_TIMEOUT,
    );

    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Validate that an IP address argument contains no shell-dangerous characters.
fn validate_ip_arg(ip: &str) -> Result<(), AdapterError> {
    if ip
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '/'))
    {
        Ok(())
    } else {
        Err(AdapterError::Protocol {
            message: format!(
                "IP argument '{ip}' contains characters not safe for shell embedding \
                 (allowed: alphanumeric, '.', ':', '/')"
            ),
        })
    }
}

fn decode_wireguard_pubkey_to_hex(value: &str) -> Result<String, String> {
    let decoded = base64_decode_simple(value.as_bytes())
        .map_err(|err| format!("base64 decode of WireGuard public key failed: {err}"))?;
    if decoded.len() != 32 {
        return Err(format!(
            "expected 32-byte WireGuard public key, got {} bytes",
            decoded.len()
        ));
    }
    let mut out = String::with_capacity(64);
    for byte in decoded {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

/// Minimal base64 decode that handles the standard alphabet (A-Z, a-z, 0-9, +, /).
/// Used for the 44-char `WireGuard` key (32 bytes → 44 base64 chars with `=` padding).
fn base64_decode_simple(encoded: &[u8]) -> Result<Vec<u8>, String> {
    // Filter out whitespace.
    let filtered: Vec<u8> = encoded
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if filtered.is_empty() {
        return Err("empty base64 input".to_owned());
    }
    // Lookup table: ASCII byte → 6-bit value (64 = padding, 255 = invalid).
    let mut table = [255u8; 256];
    for (i, ch) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .iter()
        .enumerate()
    {
        table[*ch as usize] = i as u8;
    }
    table[b'=' as usize] = 64;

    let mut output = Vec::with_capacity((filtered.len() * 3) / 4);
    let mut i = 0;
    while i + 3 < filtered.len() {
        let a = table[filtered[i] as usize];
        let b = table[filtered[i + 1] as usize];
        let c = table[filtered[i + 2] as usize];
        let d = table[filtered[i + 3] as usize];
        if a == 255 || b == 255 {
            return Err(format!("invalid base64 character at position {i}"));
        }
        output.push((a << 2) | (b >> 4));
        if c != 64 {
            output.push(((b & 0xf) << 4) | (c >> 2));
        }
        if d != 64 {
            output.push(((c & 0x3) << 6) | d);
        }
        i += 4;
    }
    Ok(output)
}

/// Assert that the collected artifact archive at `path` contains no key material.
/// This is a security invariant: `collect_artifacts` MUST NOT include
/// any file whose path contains `keys/`, ends with `.priv`, or ends with `.pem`.
fn verify_no_key_material(path: &std::path::Path) -> Result<(), AdapterError> {
    use std::process::Command;
    let output = Command::new("tar")
        .arg("-tzf")
        .arg(path.as_os_str())
        .output()
        .map_err(|err| AdapterError::Io {
            message: format!("tar -tzf failed: {err}"),
        })?;
    if !output.status.success() {
        return Err(AdapterError::Io {
            message: "tar -tzf on collected artifact archive returned non-zero".to_owned(),
        });
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    for entry in listing.lines() {
        if entry.contains("keys/")
            || entry.ends_with(".priv")
            || entry.ends_with(".pem")
            || entry.ends_with(".key")
        {
            return Err(AdapterError::KeyExclusionViolation {
                path: entry.to_owned(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_nft_killswitch_reset_enumerates_all_rustynet_tables() {
        let cmd = LINUX_NFT_KILLSWITCH_RESET_COMMAND;
        // Guards on nft presence so a node without nft is a no-op.
        assert!(cmd.contains("command -v nft"));
        // Enumerates rustynet inet tables rather than a single fixed name, so a
        // leftover runtime table (e.g. rustynet_g1) cannot leave egress blocked.
        assert!(cmd.contains("nft list tables"));
        assert!(cmd.contains("$3 ~ /^rustynet/"));
        assert!(cmd.contains("nft delete table inet"));
        // Best-effort: tolerates absence at every privileged step.
        assert!(cmd.contains("|| true"));
        // Must NOT regress to deleting only the fixed `rustynet_boot` table.
        assert!(!cmd.contains("delete table inet rustynet_boot"));
        // Regression guard for the silent-no-op bug: the table list MUST be
        // captured into a variable first, then iterated with `for`. Piping
        // `… | while read t; do sudo nft delete …; done` is broken — the inner
        // `sudo` shares and drains the loop's stdin (the awk pipe), so `read`
        // sees nothing and no table is deleted. That left `rustynet_boot`
        // behind on every run until C2's assert_node_clean surfaced it.
        assert!(
            !cmd.contains("while read"),
            "reset must not pipe into `while read` (inner sudo drains the pipe)"
        );
        assert!(
            cmd.contains("rn_tables=$("),
            "reset must capture the table list into a variable first"
        );
        assert!(
            cmd.contains("for t in $rn_tables"),
            "reset must iterate the captured list with a `for` loop"
        );
    }

    #[test]
    fn linux_node_clean_probe_targets_rustynet_nft_tables() {
        let p = LINUX_NFT_LEFTOVER_PROBE;
        assert!(p.contains("nft list tables"));
        assert!(p.contains("$3 ~ /^rustynet/"));
    }

    #[test]
    fn validate_ip_arg_accepts_valid_ipv4() {
        assert!(validate_ip_arg("10.0.0.1").is_ok());
        assert!(validate_ip_arg("192.168.1.100").is_ok());
    }

    #[test]
    fn validate_ip_arg_accepts_valid_cidr() {
        assert!(validate_ip_arg("10.0.0.0/8").is_ok());
    }

    #[test]
    fn validate_ip_arg_accepts_ipv6() {
        assert!(validate_ip_arg("fd00::1").is_ok());
    }

    #[test]
    fn validate_ip_arg_rejects_injection() {
        assert!(validate_ip_arg("10.0.0.1; rm -rf /").is_err());
        assert!(validate_ip_arg("$(whoami)").is_err());
        assert!(validate_ip_arg("10.0.0.1 && id").is_err());
    }

    #[test]
    fn base64_decode_wireguard_key() {
        // A known 32-byte key encoded in base64.
        let encoded = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let hex = decode_wireguard_pubkey_to_hex(encoded).unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn base64_decode_real_key() {
        // A valid 32-byte WireGuard public key in base64.
        let encoded = "6YIGkxJfmPNflshVeSPOc9LFNJrIcblSFQFGFhXqhg4=";
        let result = decode_wireguard_pubkey_to_hex(encoded);
        assert!(result.is_ok(), "failed: {result:?}");
        assert_eq!(result.unwrap().len(), 64);
    }

    #[test]
    fn base64_decode_rejects_wrong_length() {
        let encoded = "aGVsbG8="; // "hello" → 5 bytes
        let result = decode_wireguard_pubkey_to_hex(encoded);
        assert!(result.is_err(), "must reject non-32-byte key");
        assert!(
            result.unwrap_err().contains("32-byte"),
            "error must mention 32-byte"
        );
    }

    #[test]
    fn key_exclusion_rejects_keys_in_path() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Build a tar.gz with a dummy file at a keys/ path.
        let dir = tempfile::tempdir().unwrap();
        let keys_dir = dir.path().join("keys");
        std::fs::create_dir_all(&keys_dir).unwrap();
        let mut f = std::fs::File::create(keys_dir.join("wireguard.priv")).unwrap();
        writeln!(f, "secret").unwrap();
        drop(f);

        let archive = NamedTempFile::new().unwrap();
        let status = std::process::Command::new("tar")
            .arg("-czf")
            .arg(archive.path())
            .arg("-C")
            .arg(dir.path())
            .arg("keys/wireguard.priv")
            .status()
            .unwrap();
        assert!(status.success());

        let result = verify_no_key_material(archive.path());
        assert!(result.is_err(), "must reject archive containing keys/ path");
        match result.unwrap_err() {
            AdapterError::KeyExclusionViolation { .. } => {}
            other => panic!("wrong error variant: {other:?}"),
        }
    }

    #[test]
    fn check_ssh_reachable_fn_exists() {
        // Compilation test — function signature is valid.
        let _: fn(&NodeConnection) -> Result<(), AdapterError> = check_ssh_reachable;
    }

    #[test]
    fn key_exclusion_allows_non_key_paths() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let dir = tempfile::tempdir().unwrap();
        let mut f = std::fs::File::create(dir.path().join("daemon.log")).unwrap();
        writeln!(f, "log data").unwrap();
        drop(f);

        let archive = NamedTempFile::new().unwrap();
        let status = std::process::Command::new("tar")
            .arg("-czf")
            .arg(archive.path())
            .arg("-C")
            .arg(dir.path())
            .arg("daemon.log")
            .status()
            .unwrap();
        assert!(status.success());

        let result = verify_no_key_material(archive.path());
        assert!(result.is_ok(), "must allow non-key archive: {result:?}");
    }

    // ── userspace-shared tunnel liveness (wg show is empty for boringtun) ──────

    #[test]
    fn daemon_status_derives_active_tunnels_when_programmed_and_unrestricted() {
        // A healthy client (the r33 shape): not fail-closed, one programmed peer.
        let status = "node_id=debian-3 state=ExitActive restriction_mode=None \
                      path_programmed_mode=direct_programmed path_programmed_peer_count=1 \
                      reconcile_failures=0";
        let tunnels = super::tunnels_from_daemon_status(status);
        assert_eq!(tunnels.len(), 1, "one programmed peer -> one tunnel line");
        assert!(tunnels[0].contains("direct_programmed"));
    }

    #[test]
    fn daemon_status_derives_one_line_per_programmed_peer() {
        let status = "restriction_mode=None path_programmed_peer_count=3";
        assert_eq!(super::tunnels_from_daemon_status(status).len(), 3);
    }

    #[test]
    fn daemon_status_is_empty_when_fail_closed() {
        // restriction_mode != None means the daemon tore the dataplane down.
        let status = "state=FailClosed restriction_mode=Permanent path_programmed_peer_count=1";
        assert!(super::tunnels_from_daemon_status(status).is_empty());
    }

    #[test]
    fn daemon_status_is_empty_when_no_programmed_peers() {
        let status = "restriction_mode=None path_programmed_peer_count=0";
        assert!(super::tunnels_from_daemon_status(status).is_empty());
    }

    #[test]
    fn daemon_status_is_empty_when_keys_absent() {
        // An unparseable / empty status must fail closed, never a phantom tunnel.
        assert!(super::tunnels_from_daemon_status("").is_empty());
        assert!(super::tunnels_from_daemon_status("garbage output").is_empty());
    }
}
