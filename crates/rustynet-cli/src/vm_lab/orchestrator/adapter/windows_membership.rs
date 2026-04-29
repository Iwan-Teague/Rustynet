#![allow(dead_code)]
use std::path::Path;
use std::time::Duration;

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::adapter::windows_install::{
    WINDOWS_STAGING_DIR, WINDOWS_STATE_ROOT, ps_quote, run_remote_ps,
};
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::{
    AdapterError, BundleKind, MembershipOwnerKey, MembershipSnapshot,
};
use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const MEDIUM_TIMEOUT: Duration = Duration::from_secs(120);

const WINDOWS_MEMBERSHIP_BLOCKED_MSG: &str = "\
Windows as a membership owner (exit node) is not yet implemented. \
Blocked by W5.4: Windows exit-node role requires (1) rustynetd.exe ops \
init-membership subcommand reviewed and tested on Windows; \
(2) Windows key custody model (DPAPI / credential store) reviewed \
against security minimum bar; (3) membership signing path on Windows \
verified end-to-end.";

/// Read the membership owner public key from a Windows exit node.
/// Blocked until W5.4 — Windows as a membership-owner exit node is not
/// yet reviewed against the security minimum bar.
pub fn issue_membership_owner_key(
    _conn: &NodeConnection,
) -> Result<MembershipOwnerKey, AdapterError> {
    Err(AdapterError::UnsupportedPlatform {
        platform: VmGuestPlatform::Windows,
        message: WINDOWS_MEMBERSHIP_BLOCKED_MSG.to_string(),
    })
}

/// Initialize the membership snapshot on a Windows exit node.
/// Blocked until W5.4 — same security minimum bar requirements as above.
pub fn init_membership_snapshot(
    _conn: &NodeConnection,
    _owner_key: &MembershipOwnerKey,
    _peers: &[NodeRoleAssignment],
) -> Result<MembershipSnapshot, AdapterError> {
    Err(AdapterError::UnsupportedPlatform {
        platform: VmGuestPlatform::Windows,
        message: WINDOWS_MEMBERSHIP_BLOCKED_MSG.to_string(),
    })
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

    // Ensure the staging dir and the destination parent dir both exist.
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

    // SCP the bundle to the staging path (SCP uses forward-slash paths).
    ssh::scp_to(
        conn,
        bundle_path,
        &remote_staging.replace('\\', "/"),
        MEDIUM_TIMEOUT,
    )?;

    // Atomic install: Move-Item from staging to final destination.
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
    fn issue_membership_owner_key_returns_unsupported() {
        use std::io::Write;
        use std::path::PathBuf;
        use tempfile::NamedTempFile;
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# kh").unwrap();
        let conn = crate::vm_lab::orchestrator::connection::NodeConnection::ssh(
            "10.0.0.1",
            22,
            None,
            PathBuf::from("/id_rsa"),
            f.path().to_path_buf(),
        )
        .unwrap();
        let err = issue_membership_owner_key(&conn).unwrap_err();
        assert!(
            matches!(err, AdapterError::UnsupportedPlatform { .. }),
            "expected UnsupportedPlatform, got: {err:?}"
        );
        assert!(
            err.to_string().contains("security minimum bar"),
            "error must mention 'security minimum bar': {err}"
        );
    }
}
