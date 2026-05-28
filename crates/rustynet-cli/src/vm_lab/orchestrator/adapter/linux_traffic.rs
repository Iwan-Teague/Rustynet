#![allow(dead_code)]
use std::time::Duration;

use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::{AdapterError, TrafficTestResult, TunnelsList};

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const MEDIUM_TIMEOUT: Duration = Duration::from_secs(120);

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
    let status = ssh::run_remote(
        conn,
        "sudo -n env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet status",
        SHORT_TIMEOUT,
    )?;
    ssh::parse_status_node_id(&status).ok_or_else(|| AdapterError::Protocol {
        message: format!(
            "node_id field not found in rustynet status output: {}",
            &status[..status.len().min(200)]
        ),
    })
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
    Ok(TunnelsList { tunnels })
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
    // Stop daemon first (best-effort).
    let _ = ssh::run_remote(
        conn,
        "sudo -n systemctl stop rustynetd 2>/dev/null || true",
        Duration::from_secs(30),
    );
    // Flush the rustynet_boot nftables table installed by the daemon's
    // ExecStartPre. Its default OUTPUT policy is drop, which blocks outbound
    // traffic (including cargo registry downloads) during the next bootstrap
    // run if it is not removed here. The table is re-created on daemon start
    // so removing it at cleanup is safe and idempotent.
    let _ = ssh::run_remote(
        conn,
        "if command -v nft >/dev/null 2>&1; then \
             sudo -n nft delete table inet rustynet_boot 2>/dev/null || true; \
         fi",
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
        "sudo -n rm -rf /run/rustynet \
         /var/lib/rustynet/membership.snapshot \
         /var/lib/rustynet/membership.log \
         /var/lib/rustynet/membership.watermark \
         /var/lib/rustynet/rustynetd.assignment \
         /var/lib/rustynet/rustynetd.assignment.watermark \
         /var/lib/rustynet/rustynetd.traversal \
         /var/lib/rustynet/rustynetd.traversal.watermark \
         /var/lib/rustynet/rustynetd.dns-zone \
         /var/lib/rustynet/rustynetd.trust 2>/dev/null; true",
        Duration::from_secs(30),
    )?;
    Ok(())
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
}
