#![allow(dead_code)]
use std::path::Path;
use std::time::Duration;

use crate::vm_lab::orchestrator::adapter::macos_install::{
    MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH, MACOS_MEMBERSHIP_SNAPSHOT_PATH, MACOS_RUSTYNET_PATH,
    MACOS_STATE_ROOT,
};
use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::{
    AdapterError, BundleKind, MembershipOwnerKey, MembershipSnapshot, NodeMembershipPeer,
};
use crate::vm_lab::orchestrator::role::NodeRole;

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const MEDIUM_TIMEOUT: Duration = Duration::from_secs(120);

const MACOS_STAGING_DIR: &str = "/tmp/rustynet-staging";

/// Read the membership owner public key from a macOS exit node.
/// Reads `MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH` via SSH `cat`.
pub fn issue_membership_owner_key(
    conn: &NodeConnection,
) -> Result<MembershipOwnerKey, AdapterError> {
    let pem = ssh::run_remote(
        conn,
        &format!("cat '{MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH}' 2>/dev/null || echo ''"),
        SHORT_TIMEOUT,
    )?;
    let pem = pem.trim().to_owned();
    if pem.is_empty() {
        return Err(AdapterError::Protocol {
            message: "membership owner public key not found on remote; \
                      has membership been initialized?"
                .to_owned(),
        });
    }
    Ok(MembershipOwnerKey {
        public_key_pem: pem,
    })
}

/// Initialize the membership snapshot on a macOS exit node.
///
/// Runs `rustynet ops init-membership`, then adds each non-exit peer
/// via `ops e2e-membership-add`, then reads back the snapshot bytes.
/// Requires the SSH session to have sudo / admin privilege.
pub fn init_membership_snapshot(
    conn: &NodeConnection,
    _owner_key: &MembershipOwnerKey,
    peers: &[NodeMembershipPeer],
) -> Result<MembershipSnapshot, AdapterError> {
    // 1. Run ops init-membership (idempotent).
    ssh::run_remote(
        conn,
        &format!("env RUSTYNET_NODE_ROLE=admin sudo '{MACOS_RUSTYNET_PATH}' ops init-membership",),
        MEDIUM_TIMEOUT,
    )?;

    // 2. Add each non-exit peer.
    for peer in peers {
        if peer.role == NodeRole::Exit {
            continue;
        }
        let node_id_arg = shell_safe_arg(&peer.node_id)?;
        let pubkey_arg = hex_32_safe_arg(&peer.public_key_hex)?;
        ssh::run_remote(
            conn,
            &format!(
                "owner_approver_id=\"$('{MACOS_RUSTYNET_PATH}' ops owner-approver-id 2>/dev/null || echo none)\"; \
                 sudo '{MACOS_RUSTYNET_PATH}' ops e2e-membership-add \
                     --client-node-id '{node_id_arg}' \
                     --client-pubkey-hex '{pubkey_arg}' \
                     --owner-approver-id \"$owner_approver_id\"",
            ),
            MEDIUM_TIMEOUT,
        )?;
    }

    // 3. Read snapshot back as base64.
    let snapshot_b64 = ssh::run_remote(
        conn,
        &format!("cat '{MACOS_MEMBERSHIP_SNAPSHOT_PATH}' | base64",),
        SHORT_TIMEOUT,
    )?;
    let data = base64_decode(snapshot_b64.trim())?;
    Ok(MembershipSnapshot { data })
}

/// Distribute a signed bundle to a macOS client node.
/// Uses the same atomic install pattern as Linux: scp to temp, then
/// `sudo install` with permissions appropriate to the bundle kind.
///
/// Membership snapshots require mode 0600 owned by the daemon user because
/// `load_membership_snapshot` uses a strict `mode & 0o077 != 0` check.
/// Other bundles (assignment, traversal, dns-zone) are installed as
/// root:rustynetd 0640.
pub fn distribute_signed_bundle(
    conn: &NodeConnection,
    kind: BundleKind,
    bundle_path: &Path,
) -> Result<(), AdapterError> {
    let (remote_tmp, install_dst) = remote_bundle_paths(&kind);
    ssh::scp_to(conn, bundle_path, &remote_tmp, MEDIUM_TIMEOUT)?;
    let install_dir = install_dst
        .rsplit_once('/')
        .map_or(MACOS_STATE_ROOT, |(dir, _)| dir);
    let (mode, owner) = if matches!(kind, BundleKind::Membership) {
        ("0600", "rustynetd")
    } else {
        ("0640", "root")
    };
    ssh::run_remote(
        conn,
        &format!(
            "sudo install -d -m 0700 -o rustynetd -g rustynetd '{install_dir}' && \
             sudo install -m {mode} -o {owner} -g rustynetd '{remote_tmp}' '{install_dst}' && \
             sudo rm -f '{remote_tmp}'"
        ),
        SHORT_TIMEOUT,
    )?;
    Ok(())
}

/// Distribute the verifier public-key for `kind` to this macOS node.
pub fn distribute_verifier_key(
    conn: &NodeConnection,
    kind: BundleKind,
    pub_key_path: &Path,
) -> Result<(), AdapterError> {
    let dst = macos_verifier_key_path(&kind);
    let remote_tmp = format!("{MACOS_STAGING_DIR}/rn-verifier-key.pub");
    ssh::scp_to(conn, pub_key_path, &remote_tmp, MEDIUM_TIMEOUT)?;
    let dst_dir = dst.rsplit_once('/').map_or(MACOS_STATE_ROOT, |(d, _)| d);
    ssh::run_remote(
        conn,
        &format!(
            "sudo install -d -m 0755 -o root -g wheel '{dst_dir}' && \
             sudo install -m 0644 -o root -g wheel '{remote_tmp}' '{dst}' && \
             sudo rm -f '{remote_tmp}'"
        ),
        SHORT_TIMEOUT,
    )?;
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn macos_verifier_key_path(kind: &BundleKind) -> String {
    let state = MACOS_STATE_ROOT;
    match kind {
        BundleKind::Assignment => format!("{state}/trust/assignment.pub"),
        BundleKind::Traversal => format!("{state}/trust/traversal.pub"),
        BundleKind::DnsZone => format!("{state}/trust/dns-zone.pub"),
        BundleKind::Membership => format!("{state}/trust/membership.pub"),
    }
}

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

/// Reject shell-dangerous characters to prevent injection via alias strings.
fn shell_safe_arg(value: &str) -> Result<String, AdapterError> {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        Ok(value.to_owned())
    } else {
        Err(AdapterError::Protocol {
            message: format!(
                "value '{value}' contains characters not safe for shell argument embedding \
                 (allowed: alphanumeric, hyphen, underscore, dot)"
            ),
        })
    }
}

fn hex_32_safe_arg(value: &str) -> Result<String, AdapterError> {
    if NodeMembershipPeer::is_valid_public_key_hex(value) {
        Ok(value.to_owned())
    } else {
        Err(AdapterError::Protocol {
            message: "WireGuard public key must be 64 hex chars".to_owned(),
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
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(format!("base64 -d failed: {stderr}"));
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::adapter::macos_install::MACOS_MEMBERSHIP_DIR;

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
    fn membership_owner_pubkey_path_is_under_membership_dir() {
        assert!(
            MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH.starts_with(MACOS_MEMBERSHIP_DIR),
            "pubkey path must be under membership dir: {MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH}"
        );
    }

    #[test]
    fn membership_snapshot_path_is_under_membership_dir() {
        assert!(
            MACOS_MEMBERSHIP_SNAPSHOT_PATH.starts_with(MACOS_MEMBERSHIP_DIR),
            "snapshot path must be under membership dir: {MACOS_MEMBERSHIP_SNAPSHOT_PATH}"
        );
    }

    #[test]
    fn shell_safe_arg_accepts_valid() {
        assert_eq!(shell_safe_arg("node-exit-1").unwrap(), "node-exit-1");
        assert_eq!(shell_safe_arg("abc.def_ghi").unwrap(), "abc.def_ghi");
    }

    #[test]
    fn shell_safe_arg_rejects_special_chars() {
        assert!(shell_safe_arg("node; rm -rf /").is_err());
        assert!(shell_safe_arg("node$(whoami)").is_err());
        assert!(shell_safe_arg("node`id`").is_err());
    }

    #[test]
    fn hex_32_safe_arg_requires_64_hex_chars() {
        assert!(hex_32_safe_arg(&"a".repeat(64)).is_ok());
        assert!(hex_32_safe_arg("").is_err());
        assert!(hex_32_safe_arg(&"g".repeat(64)).is_err());
        assert!(hex_32_safe_arg(&"a".repeat(63)).is_err());
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"hello macos membership";
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
