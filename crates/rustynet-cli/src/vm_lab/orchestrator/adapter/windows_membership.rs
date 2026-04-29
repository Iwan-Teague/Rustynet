#![allow(dead_code)]
use std::path::Path;
use std::time::Duration;

use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::adapter::windows_install::{
    WINDOWS_MEMBERSHIP_OWNER_PUBKEY_PATH, WINDOWS_MEMBERSHIP_SNAPSHOT_PATH, WINDOWS_RUSTYNET_PATH,
    WINDOWS_STAGING_DIR, WINDOWS_STATE_ROOT, ps_quote, run_remote_ps,
};
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::{
    AdapterError, BundleKind, MembershipOwnerKey, MembershipSnapshot, NodeMembershipPeer,
};
use crate::vm_lab::orchestrator::role::NodeRole;

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const MEDIUM_TIMEOUT: Duration = Duration::from_secs(120);

/// Read the membership owner public key from a Windows exit node.
/// Reads `WINDOWS_MEMBERSHIP_OWNER_PUBKEY_PATH` via PowerShell `Get-Content`.
pub fn issue_membership_owner_key(
    conn: &NodeConnection,
) -> Result<MembershipOwnerKey, AdapterError> {
    let read_script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         $p = {path_q}; \
         if (-not (Test-Path -LiteralPath $p)) {{ \
             throw 'membership owner public key not found at ' + $p + '; has membership been initialized?' \
         }}; \
         (Get-Content -LiteralPath $p -Raw).Trim()",
        path_q = ps_quote(WINDOWS_MEMBERSHIP_OWNER_PUBKEY_PATH)?,
    );
    let pem = run_remote_ps(conn, &read_script, SHORT_TIMEOUT)?;
    let pem = pem.trim().to_string();
    if pem.is_empty() {
        return Err(AdapterError::Protocol {
            message: "membership owner public key is empty on remote; \
                      has membership been initialized?"
                .to_string(),
        });
    }
    Ok(MembershipOwnerKey {
        public_key_pem: pem,
    })
}

/// Initialize the membership snapshot on a Windows exit node.
///
/// Runs `rustynet.exe ops init-membership`, then adds each non-exit peer
/// via `ops e2e-membership-add`, then reads back the snapshot bytes.
/// Requires the SSH session to run as an Administrator user.
pub fn init_membership_snapshot(
    conn: &NodeConnection,
    _owner_key: &MembershipOwnerKey,
    peers: &[NodeMembershipPeer],
) -> Result<MembershipSnapshot, AdapterError> {
    // 1. Run ops init-membership (idempotent).
    let init_script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         $env:RUSTYNET_NODE_ROLE = 'admin'; \
         & {rustynet_q} ops init-membership; \
         if ($LASTEXITCODE -ne 0) {{ throw 'ops init-membership failed with exit code ' + $LASTEXITCODE }}",
        rustynet_q = ps_quote(WINDOWS_RUSTYNET_PATH)?,
    );
    run_remote_ps(conn, &init_script, MEDIUM_TIMEOUT)?;

    // 2. Add each non-exit peer.
    for peer in peers {
        if peer.role == NodeRole::Exit {
            continue;
        }
        let pubkey_hex = hex_32_arg(&peer.public_key_hex)?;
        let add_script = format!(
            "$ErrorActionPreference = 'Stop'; \
             $ProgressPreference = 'SilentlyContinue'; \
             $ownerApprover = (& {rustynet_q} ops owner-approver-id 2>$null); \
             if (-not $ownerApprover) {{ $ownerApprover = 'none' }}; \
             & {rustynet_q} ops e2e-membership-add \
                 --client-node-id {node_id_q} \
                 --client-pubkey-hex {pubkey_q} \
                 --owner-approver-id $ownerApprover; \
             if ($LASTEXITCODE -ne 0) {{ \
                 throw 'ops e2e-membership-add failed for ' + {node_id_q} \
             }}",
            rustynet_q = ps_quote(WINDOWS_RUSTYNET_PATH)?,
            node_id_q = ps_quote(&peer.node_id)?,
            pubkey_q = ps_quote(&pubkey_hex)?,
        );
        run_remote_ps(conn, &add_script, MEDIUM_TIMEOUT)?;
    }

    // 3. Read snapshot back as base64.
    let read_snapshot_script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         [Convert]::ToBase64String([System.IO.File]::ReadAllBytes({snapshot_q}))",
        snapshot_q = ps_quote(WINDOWS_MEMBERSHIP_SNAPSHOT_PATH)?,
    );
    let snapshot_b64 = run_remote_ps(conn, &read_snapshot_script, SHORT_TIMEOUT)?;
    let data = base64_decode(snapshot_b64.trim())?;
    Ok(MembershipSnapshot { data })
}

/// Distribute a signed bundle to a Windows client node.
/// Stages the bundle in `WINDOWS_STAGING_DIR`, SCPs it, then uses
/// PowerShell `Move-Item` to install atomically to the final path.
pub fn distribute_signed_bundle(
    conn: &NodeConnection,
    kind: BundleKind,
    bundle_path: &Path,
) -> Result<(), AdapterError> {
    let (remote_staging, remote_dst) = remote_bundle_paths(&kind);

    let dst_parent = remote_dst
        .rsplit_once('\\')
        .map(|(dir, _)| dir.to_string())
        .unwrap_or_else(|| WINDOWS_STATE_ROOT.to_string());
    let ensure_dirs_script = format!(
        "foreach ($d in @({staging_q}, {dst_parent_q})) {{ \
             if (-not (Test-Path -LiteralPath $d)) {{ \
                 New-Item -ItemType Directory -Force -Path $d | Out-Null \
             }} \
         }}",
        staging_q = ps_quote(WINDOWS_STAGING_DIR)?,
        dst_parent_q = ps_quote(&dst_parent)?,
    );
    run_remote_ps(conn, &ensure_dirs_script, SHORT_TIMEOUT)?;

    ssh::scp_to(
        conn,
        bundle_path,
        &remote_staging.replace('\\', "/"),
        MEDIUM_TIMEOUT,
    )?;

    let install_script = format!(
        "Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         Move-Item -LiteralPath {src_q} -Destination {dst_q} -Force",
        src_q = ps_quote(&remote_staging)?,
        dst_q = ps_quote(&remote_dst)?,
    );
    run_remote_ps(conn, &install_script, SHORT_TIMEOUT)?;

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn remote_bundle_paths(kind: &BundleKind) -> (String, String) {
    let staging = WINDOWS_STAGING_DIR;
    let state = WINDOWS_STATE_ROOT;
    match kind {
        BundleKind::Membership => (
            format!(r"{staging}\rn-membership.snapshot"),
            format!(r"{state}\membership\membership.snapshot"),
        ),
        BundleKind::Assignment => (
            format!(r"{staging}\rn-assignment.bundle"),
            format!(r"{state}\trust\rustynetd.assignment"),
        ),
        BundleKind::Traversal => (
            format!(r"{staging}\rn-traversal.bundle"),
            format!(r"{state}\trust\rustynetd.traversal"),
        ),
        BundleKind::DnsZone => (
            format!(r"{staging}\rn-dns-zone.bundle"),
            format!(r"{state}\trust\rustynetd.dns-zone"),
        ),
    }
}

fn hex_32_arg(value: &str) -> Result<String, AdapterError> {
    if NodeMembershipPeer::is_valid_public_key_hex(value) {
        Ok(value.to_string())
    } else {
        Err(AdapterError::Protocol {
            message: "WireGuard public key must be 64 hex chars".to_string(),
        })
    }
}

fn base64_decode(encoded: &str) -> Result<Vec<u8>, AdapterError> {
    base64_std_decode(encoded).map_err(|err| AdapterError::Protocol {
        message: format!("base64 decode of membership snapshot failed: {err}"),
    })
}

fn base64_std_decode(encoded: &str) -> Result<Vec<u8>, String> {
    let clean: String = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    use std::io::Write;
    use std::process::{Command, Stdio};
    let output = Command::new("base64")
        .arg("-d")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(clean.as_bytes());
            }
            child.wait_with_output()
        })
        .map_err(|err| format!("base64 -d spawn failed: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!("base64 -d failed: {stderr}"));
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_bundle_paths_contain_expected_filenames() {
        let (staging, dst) = remote_bundle_paths(&BundleKind::Membership);
        assert!(staging.contains("membership"), "staging: {staging}");
        assert!(dst.contains("membership.snapshot"), "dst: {dst}");

        let (staging, dst) = remote_bundle_paths(&BundleKind::Assignment);
        assert!(staging.contains("assignment"), "staging: {staging}");
        assert!(dst.contains("rustynetd.assignment"), "dst: {dst}");

        let (staging, dst) = remote_bundle_paths(&BundleKind::Traversal);
        assert!(staging.contains("traversal"), "staging: {staging}");
        assert!(dst.contains("rustynetd.traversal"), "dst: {dst}");

        let (staging, dst) = remote_bundle_paths(&BundleKind::DnsZone);
        assert!(staging.contains("dns-zone"), "staging: {staging}");
        assert!(dst.contains("rustynetd.dns-zone"), "dst: {dst}");
    }

    #[test]
    fn remote_bundle_staging_paths_are_under_staging_dir() {
        for kind in &[
            BundleKind::Membership,
            BundleKind::Assignment,
            BundleKind::Traversal,
            BundleKind::DnsZone,
        ] {
            let (staging, _) = remote_bundle_paths(kind);
            assert!(
                staging.starts_with(WINDOWS_STAGING_DIR),
                "staging path '{staging}' must be under WINDOWS_STAGING_DIR"
            );
        }
    }

    #[test]
    fn remote_bundle_dst_paths_are_under_state_root() {
        for kind in &[
            BundleKind::Membership,
            BundleKind::Assignment,
            BundleKind::Traversal,
            BundleKind::DnsZone,
        ] {
            let (_, dst) = remote_bundle_paths(kind);
            assert!(
                dst.starts_with(WINDOWS_STATE_ROOT),
                "dst path '{dst}' must be under WINDOWS_STATE_ROOT"
            );
        }
    }

    #[test]
    fn membership_owner_pubkey_path_is_under_state_root() {
        assert!(
            WINDOWS_MEMBERSHIP_OWNER_PUBKEY_PATH.starts_with(r"C:\ProgramData\RustyNet"),
            "pubkey path must be under state root: {WINDOWS_MEMBERSHIP_OWNER_PUBKEY_PATH}"
        );
    }

    #[test]
    fn membership_snapshot_path_is_under_state_root() {
        assert!(
            WINDOWS_MEMBERSHIP_SNAPSHOT_PATH.starts_with(r"C:\ProgramData\RustyNet"),
            "snapshot path must be under state root: {WINDOWS_MEMBERSHIP_SNAPSHOT_PATH}"
        );
    }

    #[test]
    fn hex_32_arg_requires_64_hex_chars() {
        assert!(hex_32_arg(&"a".repeat(64)).is_ok());
        assert!(hex_32_arg("").is_err());
        assert!(hex_32_arg(&"g".repeat(64)).is_err());
        assert!(hex_32_arg(&"a".repeat(63)).is_err());
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"hello membership";
        let encoded = {
            use std::io::Write;
            use std::process::{Command, Stdio};
            let mut child = Command::new("base64")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(data).unwrap();
            let out = child.wait_with_output().unwrap();
            String::from_utf8(out.stdout).unwrap()
        };
        let decoded = base64_decode(encoded.trim()).unwrap();
        assert_eq!(decoded, data);
    }
}
