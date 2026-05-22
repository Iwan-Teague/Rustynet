#![allow(dead_code)]
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::Duration;

use crate::vm_lab::orchestrator::adapter::macos_install::{MACOS_KEYS_DIR, MACOS_STATE_ROOT};
use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::{AdapterError, TrafficTestResult, TunnelsList};

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const MEDIUM_TIMEOUT: Duration = Duration::from_secs(120);

/// Read the `WireGuard` public key from the macOS state root.
/// Returns the base64-encoded key decoded to hex.
/// The keys directory is mode 700 owned by rustynetd, so the SSH user needs
/// sudo to traverse it. Try sudo first, fall back to direct access.
pub fn collect_wireguard_public_key(conn: &NodeConnection) -> Result<String, AdapterError> {
    let pub_key_path = format!("{MACOS_KEYS_DIR}/wireguard.pub");
    let output = ssh::run_remote(
        conn,
        &format!(
            "if sudo -n true >/dev/null 2>&1; then \
                 sudo -n cat '{pub_key_path}'; \
             else \
                 cat '{pub_key_path}' 2>/dev/null || echo ''; \
             fi"
        ),
        SHORT_TIMEOUT,
    )?;
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Err(AdapterError::Protocol {
            message: format!(
                "WireGuard public key not found at {pub_key_path}; \
                 has the daemon been bootstrapped?"
            ),
        });
    }
    decode_wireguard_pubkey_to_hex(trimmed).map_err(|err| AdapterError::Protocol { message: err })
}

/// Read the local `node_id` from the running daemon via `rustynet status`.
/// Falls back to extracting `--node-id` from the launchd plist if the
/// `rustynet` CLI binary is absent (e.g. a SKIP_BUILD bootstrap that only
/// installed `rustynetd`).
pub fn collect_node_id(conn: &NodeConnection) -> Result<String, AdapterError> {
    let output = ssh::run_remote(
        conn,
        "if test -x /usr/local/bin/rustynet; then \
             sudo -n env \
               RUSTYNET_DAEMON_SOCKET=/private/var/run/rustynet/rustynetd.sock \
               /usr/local/bin/rustynet status 2>&1; \
         else \
             sudo -n /usr/libexec/PlistBuddy \
               -c 'Print :ProgramArguments' \
               /Library/LaunchDaemons/com.rustynet.daemon.plist 2>/dev/null \
               | awk '/--node-id/{getline; gsub(/^[[:space:]]+|[[:space:]]+$/, \"\"); print}'; \
         fi",
        SHORT_TIMEOUT,
    )?;
    // Try to parse as `rustynet status` output first (contains `node_id=<value>`).
    if let Some(nid) = ssh::parse_status_node_id(&output) {
        return Ok(nid);
    }
    // Plist fallback: awk emits the raw node-id value on a single line.
    let trimmed = output.trim().to_owned();
    if trimmed.is_empty() {
        return Err(AdapterError::Protocol {
            message: "could not determine node_id: rustynet CLI absent and plist fallback \
                      returned empty (plist may not exist yet)"
                .to_owned(),
        });
    }
    Ok(trimmed)
}

/// Ping `peer_mesh_ip` 3 times. Returns `Reachable` on success.
pub fn ping_mesh_peer(
    conn: &NodeConnection,
    peer_mesh_ip: &str,
) -> Result<TrafficTestResult, AdapterError> {
    validate_ip_arg(peer_mesh_ip)?;
    // macOS `ping` uses -c (count) and -W (wait ms) like Linux.
    let output = ssh::run_remote(
        conn,
        &format!("ping -c 3 -W 1000 '{peer_mesh_ip}' >/dev/null 2>&1 && echo ok || echo fail"),
        Duration::from_secs(30),
    )?;
    if output.trim() == "ok" {
        Ok(TrafficTestResult::Reachable)
    } else {
        Ok(TrafficTestResult::Error(format!(
            "ping to {peer_mesh_ip} failed"
        )))
    }
}

/// Negative ACL test: confirm `denied_ip` is blocked.
pub fn probe_denied_peer(
    conn: &NodeConnection,
    denied_ip: &str,
) -> Result<TrafficTestResult, AdapterError> {
    validate_ip_arg(denied_ip)?;
    let output = ssh::run_remote(
        conn,
        &format!("ping -c 1 -W 5000 '{denied_ip}' >/dev/null 2>&1 && echo ok || echo fail"),
        Duration::from_secs(15),
    )?;
    if output.trim() == "ok" {
        Ok(TrafficTestResult::Reachable) // reached denied target = security failure
    } else {
        Ok(TrafficTestResult::Blocked) // blocked as expected
    }
}

/// Collect active `WireGuard` tunnels via `wg show`.
pub fn collect_active_tunnels(conn: &NodeConnection) -> Result<TunnelsList, AdapterError> {
    let output = ssh::run_remote(
        conn,
        "wg show 2>/dev/null || echo 'wg-not-installed'",
        SHORT_TIMEOUT,
    )?;
    let tunnels: Vec<String> = output
        .lines()
        .filter(|l| !l.is_empty())
        .map(std::string::ToString::to_string)
        .collect();
    Ok(TunnelsList { tunnels })
}

/// Collect diagnostic artifacts from the macOS host to `dst`.
/// Key material paths (`keys/*`, `*.priv`) MUST NOT appear in the archive.
pub fn collect_artifacts(conn: &NodeConnection, dst: &Path) -> Result<(), AdapterError> {
    let remote_tmp = "/tmp/rn_diag_artifacts.tar.gz";

    let diag_cmd = format!(
        "tar -czf '{remote_tmp}' \
         --exclude='{MACOS_STATE_ROOT}/keys' \
         --exclude='*.priv' \
         --exclude='*.key' \
         --exclude='*.pem' \
         '{MACOS_STATE_ROOT}' /usr/local/var/log/rustynet 2>/dev/null || \
         tar -czf '{remote_tmp}' --files-from /dev/null"
    );
    ssh::run_remote(conn, &diag_cmd, MEDIUM_TIMEOUT)?;

    if let Some(parent) = dst.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|err| AdapterError::Io {
            message: format!("create local artifact destination dir failed: {err}"),
        })?;
    }
    ssh::scp_from(conn, remote_tmp, dst, Duration::from_secs(120))?;

    // Remove temp archive from remote (best-effort).
    let _ = ssh::run_remote(conn, &format!("rm -f '{remote_tmp}'"), SHORT_TIMEOUT);

    verify_no_key_material_tarball(dst)?;

    Ok(())
}

/// Remove runtime state files, leaving the installation intact.
pub fn cleanup_runtime_state(conn: &NodeConnection) -> Result<(), AdapterError> {
    // Stop service first (best-effort).
    let _ = ssh::run_remote(
        conn,
        "sudo launchctl bootout system/com.rustynet.daemon 2>/dev/null || true",
        SHORT_TIMEOUT,
    );

    // Remove runtime state but keep keys and installation.
    ssh::run_remote(
        conn,
        &format!(
            "sudo rm -f \
             '{MACOS_STATE_ROOT}/membership/membership.snapshot' \
             '{MACOS_STATE_ROOT}/membership/membership.log' \
             '{MACOS_STATE_ROOT}/membership/membership.watermark' \
             '{MACOS_STATE_ROOT}/trust/rustynetd.assignment' \
             '{MACOS_STATE_ROOT}/trust/rustynetd.assignment.watermark' \
             '{MACOS_STATE_ROOT}/trust/rustynetd.traversal' \
             '{MACOS_STATE_ROOT}/trust/rustynetd.traversal.watermark' \
             '{MACOS_STATE_ROOT}/trust/rustynetd.dns-zone' \
             '{MACOS_STATE_ROOT}/trust/rustynetd.dns-zone.watermark' \
             2>/dev/null || true"
        ),
        SHORT_TIMEOUT,
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
        "ifconfig 2>/dev/null \
         | grep -A 5 'rustynet\\|utun' \
         | grep 'inet ' \
         | awk '{print $2}' | head -1 || echo ''",
        SHORT_TIMEOUT,
    )?;
    let ip = ip.trim().to_owned();
    if !ip.is_empty() {
        return Ok(ip);
    }
    let status = ssh::run_remote(
        conn,
        "RUSTYNET_DAEMON_SOCKET=/private/var/run/rustynet/rustynetd.sock \
         /usr/local/bin/rustynet status 2>/dev/null || echo ''",
        SHORT_TIMEOUT,
    )?;
    ssh::parse_status_field(&status, "mesh_ip")
        .or_else(|| ssh::parse_status_field(&status, "wg_ip"))
        .ok_or_else(|| AdapterError::Protocol {
            message: "mesh IP not found via ifconfig or rustynet status".to_owned(),
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

    let safe_rustynet = rustynet_path.replace('\'', "'\"'\"'");
    ssh::run_remote(
        conn,
        &format!(
            "env RUSTYNET_NODE_ROLE=admin sudo \
             '{safe_rustynet}' ops {issue_subcmd} \
             --env-file '{remote_env}' --issue-dir '{remote_issue_dir}'"
        ),
        MEDIUM_TIMEOUT,
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

fn validate_ip_arg(ip: &str) -> Result<(), AdapterError> {
    let addr = ip.parse::<IpAddr>().map_err(|err| AdapterError::Protocol {
        message: format!("IP argument {ip:?} is not a parseable IP address: {err}"),
    })?;
    if addr.is_unspecified() {
        return Err(AdapterError::Protocol {
            message: format!("IP argument {ip:?} must not be unspecified"),
        });
    }
    if addr.is_multicast() {
        return Err(AdapterError::Protocol {
            message: format!("IP argument {ip:?} must not be multicast"),
        });
    }
    if matches!(addr, IpAddr::V4(v4) if v4 == Ipv4Addr::BROADCAST) {
        return Err(AdapterError::Protocol {
            message: format!("IP argument {ip:?} must not be IPv4 broadcast"),
        });
    }
    Ok(())
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

fn base64_decode_simple(encoded: &[u8]) -> Result<Vec<u8>, String> {
    let filtered: Vec<u8> = encoded
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if filtered.is_empty() {
        return Err("empty base64 input".to_owned());
    }
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

/// Assert that the collected artifact tarball at `path` contains no key material.
fn verify_no_key_material_tarball(path: &Path) -> Result<(), AdapterError> {
    use std::process::Command;
    let output = Command::new("tar")
        .args(["-tzf"])
        .arg(path.as_os_str())
        .output()
        .map_err(|err| AdapterError::Io {
            message: format!("list tar contents failed: {err}"),
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AdapterError::Io {
            message: format!(
                "list tar contents failed with status {}: {}",
                output.status,
                stderr.trim()
            ),
        });
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    for entry in listing.lines() {
        let lower = entry.to_lowercase();
        if lower.contains("/keys/")
            || lower.ends_with(".priv")
            || lower.ends_with(".pem")
            || lower.ends_with(".key")
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
    fn validate_ip_arg_accepts_ipv6() {
        assert!(validate_ip_arg("fd00::1").is_ok());
    }

    #[test]
    fn validate_ip_arg_rejects_injection() {
        assert!(validate_ip_arg("10.0.0.1; rm -rf /").is_err());
        assert!(validate_ip_arg("$(whoami)").is_err());
    }

    #[test]
    fn validate_ip_arg_rejects_cidr_and_dns_names() {
        assert!(validate_ip_arg("10.0.0.1/24").is_err());
        assert!(validate_ip_arg("peer-a.local").is_err());
    }

    #[test]
    fn validate_ip_arg_rejects_unsafe_special_addresses() {
        assert!(validate_ip_arg("0.0.0.0").is_err());
        assert!(validate_ip_arg("::").is_err());
        assert!(validate_ip_arg("224.0.0.1").is_err());
        assert!(validate_ip_arg("ff02::1").is_err());
        assert!(validate_ip_arg("255.255.255.255").is_err());
    }

    #[test]
    fn base64_decode_wireguard_key_roundtrip() {
        let encoded = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let hex = decode_wireguard_pubkey_to_hex(encoded).unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn base64_decode_rejects_wrong_length() {
        let encoded = "aGVsbG8="; // "hello" = 5 bytes
        let result = decode_wireguard_pubkey_to_hex(encoded);
        assert!(result.is_err(), "must reject non-32-byte key");
        assert!(result.unwrap_err().contains("32-byte"));
    }

    #[test]
    fn verify_no_key_material_tarball_fails_closed_on_unreadable_archive() {
        let path = std::env::temp_dir().join(format!(
            "rustynet-macos-invalid-artifact-{}.tar.gz",
            std::process::id()
        ));
        std::fs::write(&path, b"not a tarball").expect("write invalid tarball");
        let result = verify_no_key_material_tarball(&path);
        let _ = std::fs::remove_file(&path);
        assert!(
            result.is_err(),
            "unreadable artifact tarball must fail closed"
        );
    }
}
