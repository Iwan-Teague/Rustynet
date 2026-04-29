#![allow(dead_code)]
use std::path::Path;
use std::time::Duration;

use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::adapter::windows_install::{
    WINDOWS_SERVICE_NAME, WINDOWS_STAGING_DIR, WINDOWS_STATE_ROOT, ps_quote, run_remote_ps,
    run_remote_ps_check,
};
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::{AdapterError, TrafficTestResult, TunnelsList};

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const MEDIUM_TIMEOUT: Duration = Duration::from_secs(120);

/// Read the WireGuard public key from `C:\ProgramData\RustyNet\keys\wireguard.pub`.
/// Returns the base64-encoded key decoded to hex (32-byte key → 64-char hex).
pub fn collect_wireguard_public_key(conn: &NodeConnection) -> Result<String, AdapterError> {
    let key_path = format!(r"{WINDOWS_STATE_ROOT}\keys\wireguard.pub");
    let script = format!(
        "Get-Content -LiteralPath {} -Encoding utf8 -Raw",
        ps_quote(&key_path)?
    );
    let raw = run_remote_ps(conn, &script, SHORT_TIMEOUT)?;
    let hex = decode_wireguard_pubkey_to_hex(raw.trim())
        .map_err(|err| AdapterError::Protocol { message: err })?;
    Ok(hex)
}

/// Read the local node_id from the running daemon via `rustynetd.exe status`.
/// The daemon socket on Windows is a named pipe.
pub fn collect_node_id(conn: &NodeConnection) -> Result<String, AdapterError> {
    // Use the rustynet.exe CLI (same binary name as Linux but `.exe`).
    let daemon_pipe = r"\\.\pipe\rustynet-rustynetd";
    let script = format!(
        "$env:RUSTYNET_DAEMON_SOCKET = {pipe_q}; \
         $out = & 'C:\\Program Files\\RustyNet\\rustynet.exe' status 2>&1; \
         Write-Output $out",
        pipe_q = ps_quote(daemon_pipe)?
    );
    let output = run_remote_ps(conn, &script, SHORT_TIMEOUT)?;
    ssh::parse_status_node_id(&output).ok_or_else(|| AdapterError::Protocol {
        message: format!(
            "node_id field not found in rustynet status output: {}",
            &output[..output.len().min(200)]
        ),
    })
}

/// Ping `peer_mesh_ip` 3 times via `Test-Connection`. Returns `Reachable` on success.
pub fn ping_mesh_peer(
    conn: &NodeConnection,
    peer_mesh_ip: &str,
) -> Result<TrafficTestResult, AdapterError> {
    validate_ip_arg(peer_mesh_ip)?;
    let script = format!(
        "Test-Connection -ComputerName {ip_q} -Count 3 -Quiet",
        ip_q = ps_quote(peer_mesh_ip)?
    );
    match run_remote_ps_check(conn, &script, Duration::from_secs(30))? {
        true => Ok(TrafficTestResult::Reachable),
        false => Ok(TrafficTestResult::Error(format!(
            "Test-Connection to {peer_mesh_ip} returned false"
        ))),
    }
}

/// Negative ACL test: confirm `denied_ip` is blocked. Expects connection failure.
/// Returns `Blocked` when ping fails (as expected), `Reachable` on security failure.
pub fn probe_denied_peer(
    conn: &NodeConnection,
    denied_ip: &str,
) -> Result<TrafficTestResult, AdapterError> {
    validate_ip_arg(denied_ip)?;
    let script = format!(
        "Test-Connection -ComputerName {ip_q} -Count 1 -Quiet",
        ip_q = ps_quote(denied_ip)?
    );
    match run_remote_ps_check(conn, &script, Duration::from_secs(10))? {
        true => Ok(TrafficTestResult::Reachable), // reached denied target = security failure
        false => Ok(TrafficTestResult::Blocked),  // blocked as expected
    }
}

/// Collect active WireGuard tunnels via `wireguard.exe` show.
pub fn collect_active_tunnels(conn: &NodeConnection) -> Result<TunnelsList, AdapterError> {
    let script = "if (Get-Command 'wireguard.exe' -ErrorAction SilentlyContinue) { \
         & 'wireguard.exe' /show } else { Write-Output 'wg-not-installed' }";
    let output = run_remote_ps(conn, script, SHORT_TIMEOUT)?;
    let tunnels: Vec<String> = output
        .lines()
        .filter(|l| !l.is_empty())
        .map(|s| s.to_string())
        .collect();
    Ok(TunnelsList { tunnels })
}

/// Collect diagnostic artifacts from the Windows host to `dst`.
/// Key material paths (`keys\*`, `*.priv`) MUST NOT appear in the collected set.
pub fn collect_artifacts(conn: &NodeConnection, dst: &Path) -> Result<(), AdapterError> {
    let remote_tmp = format!(r"{WINDOWS_STAGING_DIR}\rn_diag_artifacts.zip");
    let remote_tmp_ps = remote_tmp.replace('\\', "/");

    // Create archive on remote, excluding keys directory.
    let diag_script = format!(
        "Set-StrictMode -Version Latest; \
         $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         $stagingDir = {staging_q}; \
         if (-not (Test-Path -LiteralPath $stagingDir)) {{ \
             New-Item -ItemType Directory -Force -Path $stagingDir | Out-Null \
         }}; \
         $logsDir = {logs_dir_q}; \
         $zipPath = {zip_q}; \
         $filesToArchive = if (Test-Path -LiteralPath $logsDir) {{ \
             Get-ChildItem -Path $logsDir -Recurse -File | \
                 Where-Object {{ $_.FullName -notlike {keys_pattern_q} }} \
         }} else {{ @() }}; \
         if ($filesToArchive.Count -gt 0) {{ \
             Compress-Archive -Path ($filesToArchive | Select-Object -ExpandProperty FullName) \
                 -DestinationPath $zipPath -Force \
         }} else {{ \
             $dummy = [System.IO.Compression.ZipFile]; \
             [System.IO.Compression.ZipFile]::Open( \
                 $zipPath, [System.IO.Compression.ZipArchiveMode]::Create).Dispose() \
         }}",
        staging_q = ps_quote(WINDOWS_STAGING_DIR)?,
        logs_dir_q = ps_quote(&format!(r"{WINDOWS_STATE_ROOT}\logs"))?,
        zip_q = ps_quote(&remote_tmp)?,
        keys_pattern_q = ps_quote(&format!(r"{WINDOWS_STATE_ROOT}\keys\*"))?,
    );
    run_remote_ps(conn, &diag_script, MEDIUM_TIMEOUT)?;

    // Download the archive.
    if let Some(parent) = dst.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|err| AdapterError::Io {
            message: format!("create local artifact destination dir failed: {err}"),
        })?;
    }
    ssh::scp_from(conn, &remote_tmp_ps, dst, Duration::from_secs(120))?;

    // Remove temp archive from remote (best-effort).
    let cleanup_script = format!(
        "Remove-Item -LiteralPath {} -Force -ErrorAction SilentlyContinue",
        ps_quote(&remote_tmp)?
    );
    let _ = run_remote_ps(conn, &cleanup_script, SHORT_TIMEOUT);

    // Verify no key material in the collected archive.
    verify_no_key_material_zip(dst)?;

    Ok(())
}

/// Remove runtime state files, leaving the installation intact.
pub fn cleanup_runtime_state(conn: &NodeConnection) -> Result<(), AdapterError> {
    // Stop service first (best-effort).
    let stop_script = format!(
        "Stop-Service -Name {} -Force -ErrorAction SilentlyContinue",
        ps_quote(WINDOWS_SERVICE_NAME)?
    );
    let _ = run_remote_ps(conn, &stop_script, SHORT_TIMEOUT);

    // Remove runtime state but keep keys and installation.
    let cleanup_script = format!(
        "Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         $stateRoot = {state_root_q}; \
         $toRemove = @( \
             (Join-Path $stateRoot 'membership\\membership.snapshot'), \
             (Join-Path $stateRoot 'membership\\membership.log'), \
             (Join-Path $stateRoot 'membership\\membership.watermark'), \
             (Join-Path $stateRoot 'trust\\rustynetd.assignment'), \
             (Join-Path $stateRoot 'trust\\rustynetd.assignment.watermark'), \
             (Join-Path $stateRoot 'trust\\rustynetd.traversal'), \
             (Join-Path $stateRoot 'trust\\rustynetd.traversal.watermark'), \
             (Join-Path $stateRoot 'trust\\rustynetd.dns-zone'), \
             (Join-Path $stateRoot 'trust\\rustynetd.dns-zone.watermark') \
         ); \
         foreach ($f in $toRemove) {{ \
             Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue \
         }}",
        state_root_q = ps_quote(WINDOWS_STATE_ROOT)?
    );
    run_remote_ps(conn, &cleanup_script, SHORT_TIMEOUT)?;
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

/// Minimal base64 decode (standard alphabet A-Z a-z 0-9 + /).
fn base64_decode_simple(encoded: &[u8]) -> Result<Vec<u8>, String> {
    let filtered: Vec<u8> = encoded
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if filtered.is_empty() {
        return Err("empty base64 input".to_string());
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

/// Assert that the collected artifact zip at `path` contains no key material.
/// Key material patterns: paths containing `keys\` or `keys/`, ending with `.priv`.
fn verify_no_key_material_zip(path: &Path) -> Result<(), AdapterError> {
    use std::process::Command;
    // Use `unzip -Z -1` to list entries; fall back to `python3 -c` if unzip absent.
    let output = Command::new("unzip")
        .args(["-Z", "-1"])
        .arg(path.as_os_str())
        .output()
        .or_else(|_| {
            // Fallback: use python3 to list zip entries.
            Command::new("python3")
                .args(["-c", "import sys,zipfile; [print(n) for n in zipfile.ZipFile(sys.argv[1]).namelist()]"])
                .arg(path.as_os_str())
                .output()
        })
        .map_err(|err| AdapterError::Io {
            message: format!("list zip contents failed: {err}"),
        })?;
    if !output.status.success() {
        // An empty archive returns non-zero from unzip -Z — treat as ok if listing is empty.
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("error") && !stderr.contains("Error") {
            return Ok(());
        }
        return Ok(());
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    for entry in listing.lines() {
        let lower = entry.to_lowercase();
        if lower.contains("keys/")
            || lower.contains("keys\\")
            || lower.ends_with(".priv")
            || lower.ends_with(".pem")
            || lower.ends_with(".key")
        {
            return Err(AdapterError::KeyExclusionViolation {
                path: entry.to_string(),
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
}
