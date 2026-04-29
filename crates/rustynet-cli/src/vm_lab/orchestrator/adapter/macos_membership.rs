#![allow(dead_code)]
use std::path::Path;
use std::time::Duration;

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::macos_install::MACOS_STATE_ROOT;
use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::{
    AdapterError, BundleKind, MembershipOwnerKey, MembershipSnapshot,
};
use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const MEDIUM_TIMEOUT: Duration = Duration::from_secs(120);

const MACOS_MEMBERSHIP_BLOCKED_MSG: &str = "\
macOS as a membership owner (exit node) is not yet implemented. \
Blocked by W5.4: macOS exit-node role requires (1) rustynetd ops \
init-membership subcommand reviewed and tested on macOS; \
(2) macOS key custody model (Keychain / Secure Enclave) reviewed \
against security minimum bar; (3) membership signing path on macOS \
verified end-to-end.";

const MACOS_STAGING_DIR: &str = "/tmp/rustynet-staging";

/// Read the membership owner public key from a macOS exit node.
/// Blocked until W5.4 — macOS as a membership-owner exit node is not
/// yet reviewed against the security minimum bar.
pub fn issue_membership_owner_key(
    _conn: &NodeConnection,
) -> Result<MembershipOwnerKey, AdapterError> {
    Err(AdapterError::UnsupportedPlatform {
        platform: VmGuestPlatform::Macos,
        message: MACOS_MEMBERSHIP_BLOCKED_MSG.to_string(),
    })
}

/// Initialize the membership snapshot on a macOS exit node.
/// Blocked until W5.4 — same security minimum bar requirements as above.
pub fn init_membership_snapshot(
    _conn: &NodeConnection,
    _owner_key: &MembershipOwnerKey,
    _peers: &[NodeRoleAssignment],
) -> Result<MembershipSnapshot, AdapterError> {
    Err(AdapterError::UnsupportedPlatform {
        platform: VmGuestPlatform::Macos,
        message: MACOS_MEMBERSHIP_BLOCKED_MSG.to_string(),
    })
}

/// Distribute a signed bundle to a macOS client node.
/// Uses the same atomic install pattern as Linux: scp to temp, then
/// `install -m 0640 -o root -g rustynetd` to the final path.
pub fn distribute_signed_bundle(
    conn: &NodeConnection,
    kind: BundleKind,
    bundle_path: &Path,
) -> Result<(), AdapterError> {
    let (remote_tmp, install_dst) = remote_bundle_paths(&kind);
    ssh::scp_to(conn, bundle_path, &remote_tmp, MEDIUM_TIMEOUT)?;
    let install_dir = install_dst
        .rsplit_once('/')
        .map(|(dir, _)| dir)
        .unwrap_or(MACOS_STATE_ROOT);
    ssh::run_remote(
        conn,
        &format!(
            "sudo install -d -m 0700 -o rustynetd -g rustynetd '{install_dir}' && \
             sudo install -m 0640 -o root -g rustynetd '{remote_tmp}' '{install_dst}' && \
             sudo rm -f '{remote_tmp}'"
        ),
        SHORT_TIMEOUT,
    )?;
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn remote_bundle_paths(kind: &BundleKind) -> (String, String) {
    let staging = MACOS_STAGING_DIR;
    let state = MACOS_STATE_ROOT;
    match kind {
        BundleKind::Membership => (
            format!("{staging}/rn-membership.snapshot"),
            format!("{state}/membership/membership.snapshot"),
        ),
        BundleKind::Assignment => (
            format!("{staging}/rn-assignment.bundle"),
            format!("{state}/trust/rustynetd.assignment"),
        ),
        BundleKind::Traversal => (
            format!("{staging}/rn-traversal.bundle"),
            format!("{state}/trust/rustynetd.traversal"),
        ),
        BundleKind::DnsZone => (
            format!("{staging}/rn-dns-zone.bundle"),
            format!("{state}/trust/rustynetd.dns-zone"),
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

        let (staging, dst) = remote_bundle_paths(&BundleKind::DnsZone);
        assert!(staging.contains("dns-zone"), "staging: {staging}");
        assert!(dst.contains("rustynetd.dns-zone"), "dst: {dst}");
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
                dst.starts_with(MACOS_STATE_ROOT),
                "dst path '{dst}' must be under MACOS_STATE_ROOT"
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
