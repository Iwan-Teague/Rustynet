#![allow(dead_code)]
use std::path::Path;
use std::time::Duration;

use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::{
    AdapterError, BundleKind, MembershipOwnerKey, MembershipSnapshot, NodeMembershipPeer,
};
use crate::vm_lab::orchestrator::role::NodeRole;
use rustynet_control::membership::MEMBERSHIP_SCHEMA_VERSION;
use rustynet_control::roles::role_capability_csv;

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const MEDIUM_TIMEOUT: Duration = Duration::from_secs(120);
const LINUX_MEMBERSHIP_LOG_PATH: &str = "/var/lib/rustynet/membership.log";

/// Read the membership owner public key from the exit node.
/// The exit node is the only node that holds the owner signing key;
/// calling this on a non-exit node will return an empty key or error.
pub fn issue_membership_owner_key(
    conn: &NodeConnection,
) -> Result<MembershipOwnerKey, AdapterError> {
    let pem = ssh::run_remote(
        conn,
        "sudo -n cat /etc/rustynet/membership.owner.key.pub 2>/dev/null || \
         sudo -n cat /var/lib/rustynet/membership.owner.key.pub 2>/dev/null || \
         echo ''",
        SHORT_TIMEOUT,
    )?;
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

/// Initialize the membership snapshot on the exit node and return its bytes.
/// Runs `rustynet ops init-membership` for each non-exit peer that is in
/// `peers`, then reads back the snapshot + log from the remote.
pub fn init_membership_snapshot(
    conn: &NodeConnection,
    _owner_key: &MembershipOwnerKey,
    peers: &[NodeMembershipPeer],
) -> Result<MembershipSnapshot, AdapterError> {
    // 1. Run ops init-membership on the exit node (idempotent if already done).
    //    Privileged: needs to write into /var/lib/rustynet/ (root:rustynetd).
    //    RUSTYNET_NODE_ID is required by init-membership; source it from the exit
    //    peer entry in the peers list so the caller need not duplicate that lookup.
    let exit_node_id = peers
        .iter()
        .find(|p| p.role == NodeRole::Exit)
        .map_or("", |p| p.node_id.as_str());
    let exit_node_id_arg = shell_safe_arg(exit_node_id)?;
    ssh::run_remote(
        conn,
        &format!(
            "sudo -n env RUSTYNET_NODE_ROLE=admin RUSTYNET_NODE_ID='{exit_node_id_arg}' \
             /usr/local/bin/rustynet ops init-membership"
        ),
        MEDIUM_TIMEOUT,
    )?;

    // 2. Add each non-exit peer via e2e-membership-add.
    //    Privileged: writes membership.snapshot, reads owner key.
    //    owner_approver_id convention: "{exit_node_id}-owner" (matches ops_e2e.rs).
    //    There is no `rustynet ops owner-approver-id` command; derive from the exit peer.
    let owner_approver_id_arg = shell_safe_arg(&format!("{exit_node_id}-owner"))?;
    for peer in peers {
        if peer.role == NodeRole::Exit {
            continue;
        }
        let node_id_arg = shell_safe_arg(&peer.node_id)?;
        let pubkey_arg = hex_32_safe_arg(&peer.public_key_hex)?;
        let capabilities_arg = shell_safe_arg(&role_capability_csv(&peer.capabilities))?;
        ssh::run_remote(
            conn,
            &format!(
                "sudo -n /usr/local/bin/rustynet ops e2e-membership-add \
                 --client-node-id '{node_id_arg}' \
                 --client-pubkey-hex '{pubkey_arg}' \
                 --capabilities '{capabilities_arg}' \
                 --owner-approver-id '{owner_approver_id_arg}'"
            ),
            MEDIUM_TIMEOUT,
        )?;
    }

    // 3. Read back the snapshot bytes. /var/lib/rustynet/ is mode 700 root-owned.
    // `test -s` first so a missing/empty snapshot fails loudly here instead of
    // being masked by the pipe (cat's non-zero exit is swallowed by base64's
    // success, yielding an empty "valid" snapshot that would later be
    // distributed to peers and rejected by the daemon).
    let snapshot_b64 = ssh::run_remote(
        conn,
        "sudo -n test -s /var/lib/rustynet/membership.snapshot && \
         sudo -n cat /var/lib/rustynet/membership.snapshot | base64 -w 0",
        SHORT_TIMEOUT,
    )?;
    let data = base64_decode(&snapshot_b64)?;
    if data.is_empty() {
        return Err(AdapterError::Protocol {
            message: "membership snapshot decoded to zero bytes; init-membership/\
                      e2e-membership-add did not produce a snapshot"
                .to_owned(),
        });
    }
    Ok(MembershipSnapshot { data })
}

/// Distribute a signed bundle to this (non-exit) node.
/// The bundle is scp'd to a temp path, then installed atomically.
///
/// Membership snapshots require mode 0600 owned by the daemon user because
/// `load_membership_snapshot` uses a strict `mode & 0o077 != 0` check.
/// Other bundles (assignment, traversal, dns-zone) are installed as
/// root:rustynetd 0640; the daemon's trust-evidence loader accepts group-read
/// for root-owned files (`mode & 0o037`).
pub fn distribute_signed_bundle(
    conn: &NodeConnection,
    kind: BundleKind,
    bundle_path: &Path,
) -> Result<(), AdapterError> {
    let (remote_tmp, install_dst) = remote_bundle_paths(&kind);
    // SCP bundle to temp path.
    ssh::scp_to(conn, bundle_path, &remote_tmp, MEDIUM_TIMEOUT)?;
    // Install atomically with correct permissions.
    let install_dir = install_dst
        .rsplit_once('/')
        .map_or("/var/lib/rustynet", |(dir, _)| dir);
    // Membership snapshot: mode 0600 owned by the daemon user so the strict
    // `mode & 0o077 == 0` check in load_membership_snapshot passes.
    // Other bundles: mode 0640 root:rustynetd (daemon accepts group-read for
    // root-owned trust evidence).
    let (mode, owner) = if matches!(kind, BundleKind::Membership) {
        ("0600", "rustynetd")
    } else {
        ("0640", "root")
    };
    let log_init = if matches!(kind, BundleKind::Membership) {
        let log_header = membership_log_header();
        format!(
            " && (sudo -n test -s '{LINUX_MEMBERSHIP_LOG_PATH}' || \
             printf '%s\n' '{log_header}' | sudo -n tee '{LINUX_MEMBERSHIP_LOG_PATH}' >/dev/null) && \
             sudo -n chown rustynetd:rustynetd '{LINUX_MEMBERSHIP_LOG_PATH}' && \
             sudo -n chmod 0600 '{LINUX_MEMBERSHIP_LOG_PATH}'"
        )
    } else {
        String::new()
    };
    ssh::run_remote(
        conn,
        &format!(
            "sudo -n install -d -m 0700 -o rustynetd -g rustynetd {install_dir} && \
             sudo -n install -m {mode} -o {owner} -g rustynetd '{remote_tmp}' '{install_dst}' && \
             sudo -n rm -f '{remote_tmp}'{log_init}"
        ),
        SHORT_TIMEOUT,
    )?;
    Ok(())
}

/// Distribute the verifier public-key for `kind` to this Linux node.
///
/// SCPs the local pub-key file to a temp path, then installs it with
/// `sudo install -m 0644 -o root -g root` at the daemon-canonical path.
pub fn distribute_verifier_key(
    conn: &NodeConnection,
    kind: BundleKind,
    pub_key_path: &Path,
) -> Result<(), AdapterError> {
    let expected_sha256 =
        crate::vm_lab::orchestrator::adapter::verifier_key::validated_verifier_key_sha256(
            pub_key_path,
        )?;
    let dst = linux_verifier_key_path(&kind);
    let remote_tmp = "/tmp/rn-verifier-key.pub";
    ssh::scp_to(conn, pub_key_path, remote_tmp, MEDIUM_TIMEOUT)?;
    let dst_dir = dst.rsplit_once('/').map_or("/etc/rustynet", |(d, _)| d);
    ssh::run_remote(
        conn,
        &format!(
            "sudo -n install -d -m 0755 -o root -g root '{dst_dir}' && \
             sudo -n install -m 0644 -o root -g root '{remote_tmp}' '{dst}' && \
             sudo -n rm -f '{remote_tmp}' && \
             test \"$(sudo -n sha256sum '{dst}' | awk '{{print $1}}')\" = '{expected_sha256}'"
        ),
        SHORT_TIMEOUT,
    )?;
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn linux_verifier_key_path(kind: &BundleKind) -> String {
    match kind {
        BundleKind::Assignment => "/etc/rustynet/assignment.pub".to_owned(),
        BundleKind::Traversal => "/etc/rustynet/traversal.pub".to_owned(),
        BundleKind::DnsZone => "/etc/rustynet/dns-zone.pub".to_owned(),
        BundleKind::Membership => "/etc/rustynet/membership.pub".to_owned(),
    }
}

fn remote_bundle_paths(kind: &BundleKind) -> (String, String) {
    match kind {
        BundleKind::Membership => (
            "/tmp/rn-membership.snapshot".to_owned(),
            "/var/lib/rustynet/membership.snapshot".to_owned(),
        ),
        BundleKind::Assignment => (
            "/tmp/rn-assignment.bundle".to_owned(),
            "/var/lib/rustynet/rustynetd.assignment".to_owned(),
        ),
        BundleKind::Traversal => (
            "/tmp/rn-traversal.bundle".to_owned(),
            "/var/lib/rustynet/rustynetd.traversal".to_owned(),
        ),
        BundleKind::DnsZone => (
            "/tmp/rn-dns-zone.bundle".to_owned(),
            "/var/lib/rustynet/rustynetd.dns-zone".to_owned(),
        ),
    }
}

fn membership_log_header() -> String {
    format!("version={MEMBERSHIP_SCHEMA_VERSION}")
}

/// Reject shell-dangerous characters to prevent injection via alias strings.
fn shell_safe_arg(value: &str) -> Result<String, AdapterError> {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ','))
    {
        Ok(value.to_owned())
    } else {
        Err(AdapterError::Protocol {
            message: format!(
                "value '{value}' contains characters not safe for shell argument embedding \
                 (allowed: alphanumeric, hyphen, underscore, dot, comma)"
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
    // Simple base64 decode without pulling in a new crate: delegate to the
    // `base64` crate already used by mod.rs via the `base64` dependency.
    // We access it via `std` since `base64` is workspace-level.
    // For now: spawn `base64 -d` locally on the received bytes.
    // This is an internal implementation detail — the bytes are used only
    // for forwarding the snapshot to non-exit peers, not for cryptographic ops.
    let decoded = base64_std_decode(encoded).map_err(|err| AdapterError::Protocol {
        message: format!("base64 decode of membership snapshot failed: {err}"),
    })?;
    Ok(decoded)
}

fn base64_std_decode(encoded: &str) -> Result<Vec<u8>, String> {
    // base64 alphabet: A-Z a-z 0-9 + / = (padding) and whitespace (ignored).
    let clean: String = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    // Use base64 via a process call so we don't need direct crate access here.
    // (The base64 crate is available but accessed via the workspace; routing
    // through a shell call is simpler at this layer.)
    use std::process::Command;
    let output = Command::new("base64")
        .arg("-d")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(stdin) = child.stdin.take() {
                let mut stdin = stdin;
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

    #[test]
    fn shell_safe_arg_accepts_valid() {
        assert_eq!(shell_safe_arg("node-exit-1").unwrap(), "node-exit-1");
        assert_eq!(shell_safe_arg("abc.def_ghi").unwrap(), "abc.def_ghi");
        // capability CSVs contain commas (e.g. "client,entry_relay")
        assert_eq!(
            shell_safe_arg("client,entry_relay").unwrap(),
            "client,entry_relay"
        );
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
    fn remote_bundle_paths_correct() {
        let (tmp, dst) = remote_bundle_paths(&BundleKind::Membership);
        assert!(tmp.contains("membership"));
        assert!(dst.contains("membership.snapshot"));

        let (tmp, dst) = remote_bundle_paths(&BundleKind::Assignment);
        assert!(tmp.contains("assignment"));
        assert!(dst.contains("rustynetd.assignment"));
    }

    #[test]
    fn membership_log_header_matches_control_schema() {
        assert_eq!(membership_log_header(), "version=1");
    }
}
