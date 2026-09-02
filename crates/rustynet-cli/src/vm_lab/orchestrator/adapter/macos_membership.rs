#![allow(dead_code)]
use std::path::Path;
use std::time::Duration;

use crate::vm_lab::orchestrator::adapter::macos_install::{
    MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH, MACOS_MEMBERSHIP_SNAPSHOT_PATH,
    MACOS_OWNER_SIGNING_KEY_PATH, MACOS_RUSTYNET_PATH, MACOS_STATE_ROOT,
};
use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::{
    AdapterError, BundleKind, GossipIdentity, MembershipOwnerKey, MembershipSnapshot,
    NodeMembershipPeer,
};
use crate::vm_lab::orchestrator::role::NodeRole;
use rustynet_control::membership::MEMBERSHIP_SCHEMA_VERSION;
use rustynet_control::roles::role_capability_csv;

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const MEDIUM_TIMEOUT: Duration = Duration::from_secs(120);
const MACOS_MEMBERSHIP_LOG_PATH: &str = "/usr/local/var/rustynet/membership/membership.log";

const MACOS_STAGING_DIR: &str = "/tmp/rustynet-staging";

/// Marker the remote probe emits when the owner public key file does not
/// exist at all (`membership init` never ran / genesis never seeded it).
const OWNER_KEY_ABSENT_MARKER: &str = "__RN_OWNER_KEY_ABSENT__:";
/// Marker the remote probe emits when the file exists but could not be read
/// (permission, sudo refusal, I/O error) — a different failure than absent.
const OWNER_KEY_READ_FAILED_MARKER: &str = "__RN_OWNER_KEY_READ_FAILED__:";

/// Build the remote shell probe that reads the membership owner public key.
///
/// Fail-closed contract (MAC-D2): the probe NEVER collapses a failure into
/// an empty string. It always exits 0 and reports its outcome on stdout:
/// the key body on success, or one of the classification markers
/// (`OWNER_KEY_ABSENT_MARKER` / `OWNER_KEY_READ_FAILED_MARKER`) with the
/// path and the underlying error. The reads use `sudo -n` like the Linux
/// twin — the key directory is root/0700 territory and the SSH user is
/// unprivileged — and `sudo -n` itself failing (no passwordless sudo)
/// lands in the read-failed branch rather than reading as "absent".
fn owner_key_read_script(path: &str) -> String {
    format!(
        "if ! sudo -n true 2>/dev/null; then \
             printf '%s{path} rc=0 passwordless sudo unavailable\\n' '{OWNER_KEY_READ_FAILED_MARKER}'; exit 0; \
         fi; \
         key=\"$(sudo -n cat '{path}' 2>/dev/null)\"; rc=$?; \
         if [ \"$rc\" -eq 0 ] && [ -n \"$key\" ]; then printf '%s\\n' \"$key\"; exit 0; fi; \
         if sudo -n test -e '{path}'; then \
             detail=\"$(sudo -n cat '{path}' 2>&1 >/dev/null | head -1)\"; \
             printf '%s{path} rc=%s %s\\n' '{OWNER_KEY_READ_FAILED_MARKER}' \"$rc\" \"$detail\"; exit 0; \
         fi; \
         printf '%s{path}\\n' '{OWNER_KEY_ABSENT_MARKER}'; exit 0",
    )
}

/// Classify the output of [`owner_key_read_script`]. Absent and unreadable
/// produce DISTINCT, non-empty errors so a permission problem can never
/// masquerade as "has membership been initialized?" again.
fn interpret_owner_key_read(output: &str) -> Result<MembershipOwnerKey, AdapterError> {
    let out = output.trim();
    if out.is_empty() {
        return Err(AdapterError::Protocol {
            message: "membership owner public key read produced no output on remote \
                      (neither key nor failure marker); refusing to guess"
                .to_owned(),
        });
    }
    if let Some(path) = out.strip_prefix(OWNER_KEY_ABSENT_MARKER) {
        return Err(AdapterError::Protocol {
            message: format!(
                "membership owner public key not found on remote at '{path}'; \
                 has membership genesis been run? (rustynetd membership init \
                 seeds it at {MACOS_OWNER_SIGNING_KEY_PATH}.pub)"
            ),
        });
    }
    if let Some(rest) = out.strip_prefix(OWNER_KEY_READ_FAILED_MARKER) {
        return Err(AdapterError::Protocol {
            message: format!(
                "membership owner public key exists on remote but could not be read: {rest}"
            ),
        });
    }
    Ok(MembershipOwnerKey {
        public_key_pem: out.to_owned(),
    })
}

/// Read the membership owner public key from a macOS exit node.
///
/// Reads `MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH` — exactly where the macOS
/// genesis (`rustynetd membership init --owner-signing-key
/// {MACOS_OWNER_SIGNING_KEY_PATH}`) writes the `.pub` sibling — via
/// `sudo -n cat`. Absent-file and permission-denied are distinguished and
/// both fail loud; neither is collapsed into an empty string.
pub fn issue_membership_owner_key(
    conn: &NodeConnection,
) -> Result<MembershipOwnerKey, AdapterError> {
    let output = ssh::run_remote(
        conn,
        &owner_key_read_script(MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH),
        SHORT_TIMEOUT,
    )?;
    interpret_owner_key_read(&output)
}

/// Initialize the membership snapshot on a macOS exit node.
///
/// Runs `rustynet ops init-membership`, then adds each non-exit peer
/// via `ops e2e-membership-add`, then reads back the snapshot bytes.
/// Requires the SSH session to have sudo / admin privilege.
/// Resolve the exit node's membership node id from the peers list.
///
/// The macOS genesis (`ops init-membership`) requires `RUSTYNET_NODE_ID`
/// (MAC-D5): the daemon fails closed when it is missing. The id is sourced
/// from the exit peer entry exactly like the Linux twin
/// (`linux_membership.rs`); absent exit peer or an empty id is a LOUD
/// error — never a blank/default node id.
fn exit_node_id_from_peers(peers: &[NodeMembershipPeer]) -> Result<&str, AdapterError> {
    let exit = peers
        .iter()
        .find(|p| p.role == NodeRole::Exit)
        .map(|p| p.node_id.as_str());
    match exit {
        Some(id) if !id.is_empty() => Ok(id),
        Some(_) => Err(AdapterError::Protocol {
            message: "exit peer entry in `peers` has an empty membership node id; \
                      refusing to run membership init with a blank RUSTYNET_NODE_ID"
                .to_owned(),
        }),
        None => Err(AdapterError::Protocol {
            message: "no NodeRole::Exit peer in `peers`; membership init on macOS \
                      cannot source the required RUSTYNET_NODE_ID"
                .to_owned(),
        }),
    }
}

/// Build the remote `ops init-membership` command for a macOS exit node.
///
/// Mirrors the Linux twin: `env` is placed AFTER `sudo -n` so sudo's
/// `env_reset` cannot strip the role/node-id variables (the previous
/// macOS form ran `env RUSTYNET_NODE_ROLE=admin sudo …`, which sudo
/// stripped — leaving RUSTYNET_NODE_ID unset entirely).
///
/// MAC-D11: `RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT` is passed
/// alongside them, pointing at the node-scoped System.keychain item the
/// bootstrap provisions (`trust-passphrase-<node_id>`,
/// `Bootstrap-RustyNetMacos.sh` store-passphrase step). Without it,
/// `ops init-membership`'s passphrase-material gate hard-errors with
/// "macOS keychain account is required" the moment its idempotent
/// early-out misses (a fresh node or wiped state dir), so the account
/// must travel with the invocation, not with the session environment.
fn membership_init_script(exit_node_id_arg: &str) -> String {
    format!(
        "sudo -n env RUSTYNET_NODE_ROLE=admin RUSTYNET_NODE_ID='{exit_node_id_arg}' \
         RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT='trust-passphrase-{exit_node_id_arg}' \
         '{MACOS_RUSTYNET_PATH}' ops init-membership"
    )
}

/// Build the remote `ops e2e-membership-add` command for one peer.
///
/// MAC-D6: the owner approver id is DERIVED from the exit node id —
/// `"{exit_node_id}-owner"` — exactly like the Linux twin
/// (`linux_membership.rs`) and exactly what `rustynetd membership init`
/// registers as the genesis owner approver (`crates/rustynetd/src/main.rs`,
/// `format!("{node_id}-owner")`). There is no `rustynet ops
/// owner-approver-id` subcommand: an earlier revision shelled out to one,
/// the CLI's `bad_args` error (printed to STDOUT, so `2>/dev/null`
/// suppressed nothing, `|| echo none` appended `none`) was captured and
/// passed as `--owner-approver-id '<error text>none'`, and
/// `ensure_safe_token` rejected it — failing the whole `membership_init`
/// stage. Deriving keeps the approver id real and the stage unblocked; the
/// derived value still passes `shell_safe_arg` so the guard is never lost.
fn peer_add_script(
    exit_node_id: &str,
    node_id_arg: &str,
    pubkey_flag: &str,
    pubkey_arg: &str,
    capabilities_arg: &str,
) -> Result<String, AdapterError> {
    // owner_approver_id convention: "{exit_node_id}-owner" (matches ops_e2e.rs
    // and rustynetd membership init). There is no `rustynet ops
    // owner-approver-id` command; derive from the exit peer.
    let owner_approver_id_arg = shell_safe_arg(&format!("{exit_node_id}-owner"))?;
    // MAC-D11: same keychain-account plumbing as `membership_init_script` —
    // `env` after `sudo -n` so `env_reset` cannot strip it. The e2e mutation
    // path resolves its passphrase via a hardcoded credential descriptor, so
    // today this variable is inert here; carrying it keeps the invocation
    // self-describing and correct if the e2e path ever honours it, and
    // matches the node-scoped item the bootstrap provisions.
    Ok(format!(
        "sudo -n env RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT='trust-passphrase-{exit_node_id}' \
         '{MACOS_RUSTYNET_PATH}' ops e2e-membership-add \
             --client-node-id '{node_id_arg}' \
             {pubkey_flag} '{pubkey_arg}' \
             --capabilities '{capabilities_arg}' \
             --owner-approver-id '{owner_approver_id_arg}'",
    ))
}

/// Build the remote read-back probe for the genesis membership snapshot.
///
/// MAC-D10 (read half): the previous form was `test -s '<path>' && cat …`,
/// whose ONLY failure output is silence — `test` exits 1 and prints
/// nothing, so a vanished snapshot surfaced to the orchestrator as
/// "remote command failed (exit Some(1)):" with empty stderr AND stdout,
/// and the loud fail-closed design of the guard never survived the SSH
/// pipe. The probe now emits its own diagnostic on stderr and exits 1
/// when the snapshot is missing or empty, naming the path, so the
/// failure envelope always carries the cause.
///
/// Both halves run under `sudo -n` (the snapshot is mode 0600 owned by
/// the `rustynetd` service account; the SSH session is unprivileged),
/// matching [`owner_key_read_script`]'s privilege pattern.
fn membership_snapshot_readback_script() -> String {
    format!(
        "if ! sudo -n test -s '{MACOS_MEMBERSHIP_SNAPSHOT_PATH}'; then \
             echo 'membership snapshot missing or empty at {MACOS_MEMBERSHIP_SNAPSHOT_PATH}; \
 init-membership/e2e-membership-add did not leave a readable genesis' >&2; \
             exit 1; \
         fi; \
         sudo -n cat '{MACOS_MEMBERSHIP_SNAPSHOT_PATH}' | base64"
    )
}

pub fn init_membership_snapshot(
    conn: &NodeConnection,
    _owner_key: &MembershipOwnerKey,
    peers: &[NodeMembershipPeer],
) -> Result<MembershipSnapshot, AdapterError> {
    // 1. Run ops init-membership (idempotent). RUSTYNET_NODE_ID is required
    //    by init-membership; sourced from the exit peer, fail-loud if absent.
    let exit_node_id = exit_node_id_from_peers(peers)?;
    let exit_node_id_arg = shell_safe_arg(exit_node_id)?;
    ssh::run_remote(
        conn,
        &membership_init_script(&exit_node_id_arg),
        MEDIUM_TIMEOUT,
    )?;

    // 2. Add each non-exit peer.
    for peer in peers {
        if peer.role == NodeRole::Exit {
            continue;
        }
        let node_id_arg = shell_safe_arg(&peer.node_id)?;
        // Branch on the SUBJECT peer, not on this producer's platform. This
        // function runs on a macOS exit node but writes membership for EVERY
        // peer in the topology, including Linux ones that DO have a real gossip
        // identity. Publishing `public_key_hex` unconditionally here would
        // republish those nodes' WireGuard keys under a flag named
        // `unaligned-wireguard` — silently reinstating the exact defect this
        // change exists to remove, on any `--exit-platform macos` run.
        let (pubkey_flag, pubkey_arg) = match &peer.gossip_identity {
            GossipIdentity::Published(gossip_hex) => {
                ("--client-gossip-pubkey-hex", hex_32_safe_arg(gossip_hex)?)
            }
            GossipIdentity::DeferredPlatform => (
                "--client-pubkey-hex-unaligned-wireguard",
                hex_32_safe_arg(&peer.public_key_hex)?,
            ),
        };
        let capabilities_arg = shell_safe_arg(&role_capability_csv(&peer.capabilities))?;
        let script = peer_add_script(
            exit_node_id,
            &node_id_arg,
            pubkey_flag,
            &pubkey_arg,
            &capabilities_arg,
        )?;
        ssh::run_remote(conn, &script, MEDIUM_TIMEOUT)?;
    }

    // 3. Read snapshot back as base64. The probe fails LOUDLY (own stderr
    //    message + exit 1, naming the path) when the snapshot is missing or
    //    empty — a vanished genesis must surface as a named failure, never
    //    as a silent empty read (MAC-D10).
    let snapshot_b64 =
        ssh::run_remote(conn, &membership_snapshot_readback_script(), SHORT_TIMEOUT)?;
    let data = base64_decode(snapshot_b64.trim())?;
    if data.is_empty() {
        return Err(AdapterError::Protocol {
            message: "membership snapshot decoded to zero bytes; init-membership/\
                      e2e-membership-add did not produce a snapshot"
                .to_owned(),
        });
    }
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
    // Staging dir must exist before SCP; /tmp is always present but the
    // subdirectory may not have been created yet.
    ssh::run_remote(
        conn,
        &format!("mkdir -p '{MACOS_STAGING_DIR}'"),
        SHORT_TIMEOUT,
    )?;
    ssh::scp_to(conn, bundle_path, &remote_tmp, MEDIUM_TIMEOUT)?;
    let install_dir = install_dst
        .rsplit_once('/')
        .map_or(MACOS_STATE_ROOT, |(dir, _)| dir);
    let (mode, owner) = if matches!(kind, BundleKind::Membership) {
        ("0600", "rustynetd")
    } else {
        ("0640", "root")
    };
    let log_init = if matches!(kind, BundleKind::Membership) {
        let log_header = membership_log_header();
        format!(
            " && (sudo -n test -s '{MACOS_MEMBERSHIP_LOG_PATH}' || \
             printf '%s\n' '{log_header}' | sudo -n tee '{MACOS_MEMBERSHIP_LOG_PATH}' >/dev/null) && \
             sudo -n chown rustynetd:rustynetd '{MACOS_MEMBERSHIP_LOG_PATH}' && \
             sudo -n chmod 0600 '{MACOS_MEMBERSHIP_LOG_PATH}'"
        )
    } else {
        String::new()
    };
    ssh::run_remote(
        conn,
        &format!(
            "sudo -n install -d -m 0700 -o rustynetd -g rustynetd '{install_dir}' && \
             sudo -n install -m {mode} -o {owner} -g rustynetd '{remote_tmp}' '{install_dst}' && \
             sudo -n rm -f '{remote_tmp}'{log_init}"
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
    let expected_sha256 =
        crate::vm_lab::orchestrator::adapter::verifier_key::validated_verifier_key_sha256(
            pub_key_path,
        )?;
    let dst = macos_verifier_key_path(&kind);
    let remote_tmp = format!("{MACOS_STAGING_DIR}/rn-verifier-key.pub");
    ssh::run_remote(
        conn,
        &format!("mkdir -p '{MACOS_STAGING_DIR}'"),
        SHORT_TIMEOUT,
    )?;
    ssh::scp_to(conn, pub_key_path, &remote_tmp, MEDIUM_TIMEOUT)?;
    let dst_dir = dst.rsplit_once('/').map_or(MACOS_STATE_ROOT, |(d, _)| d);
    // The verifier-key destination dir ({state}/trust) is shared with the
    // signed-bundle install, which creates it as 0700 rustynetd:rustynetd.
    // Use the SAME owner/mode here so the last writer doesn't flip the trust
    // dir to 0755 root:wheel and trip the daemon's key-custody/hardening
    // posture. The key file itself stays world-readable (0644) so the daemon
    // can read it while the dir remains rustynetd-owned.
    ssh::run_remote(
        conn,
        &format!(
            "sudo install -d -m 0700 -o rustynetd -g rustynetd '{dst_dir}' && \
             sudo install -m 0644 -o root -g rustynetd '{remote_tmp}' '{dst}' && \
             sudo rm -f '{remote_tmp}' && \
             test \"$(sudo shasum -a 256 '{dst}' | awk '{{print $1}}')\" = '{expected_sha256}'"
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
    fn membership_owner_pubkey_path_matches_genesis_write_path() {
        // `rustynetd membership init` writes the owner public key at
        // "{--owner-signing-key}.pub"; the macOS genesis driver passes
        // MACOS_OWNER_SIGNING_KEY_PATH. The adapter must read exactly where
        // genesis writes — this pin keeps the two from drifting again
        // (MAC-D2: the old constant guessed a STATE_ROOT location genesis
        // never used).
        assert_eq!(
            MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH,
            format!("{MACOS_OWNER_SIGNING_KEY_PATH}.pub"),
            "pubkey path must be the .pub sibling of the genesis signing key path"
        );
        assert_eq!(
            MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH,
            "/usr/local/etc/rustynet/membership.owner.key.pub"
        );
    }

    #[test]
    fn owner_key_read_script_uses_sudo_n_and_names_the_path() {
        let script = owner_key_read_script(MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH);
        assert!(
            script.contains("sudo -n cat"),
            "read must be privileged like the Linux twin: {script}"
        );
        assert!(
            script.contains(MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH),
            "script must name the canonical path: {script}"
        );
        // No bare `cat` without sudo escalation.
        for line in script.lines() {
            let trimmed = line.trim_start();
            assert!(
                !trimmed.starts_with("cat "),
                "bare cat found; every read must be sudo -n: {trimmed}"
            );
        }
    }

    #[test]
    fn owner_key_read_success_yields_key() {
        let key = interpret_owner_key_read(
            "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n",
        )
        .unwrap();
        assert!(key.public_key_pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn owner_key_absent_and_permission_denied_are_distinct_loud_errors() {
        let absent = interpret_owner_key_read(&format!(
            "{OWNER_KEY_ABSENT_MARKER}/usr/local/etc/rustynet/membership.owner.key.pub"
        ))
        .unwrap_err();
        let denied = interpret_owner_key_read(&format!(
            "{OWNER_KEY_READ_FAILED_MARKER}/usr/local/etc/rustynet/membership.owner.key.pub \
             rc=1 cat: ...: Permission denied"
        ))
        .unwrap_err();

        let absent_msg = absent.to_string();
        let denied_msg = denied.to_string();
        assert!(!absent_msg.is_empty() && !denied_msg.is_empty());
        assert_ne!(
            absent_msg, denied_msg,
            "absent-file and permission-denied must never collapse to one error"
        );
        assert!(
            absent_msg.contains("not found on remote"),
            "absent error must say so: {absent_msg}"
        );
        assert!(
            absent_msg.contains(MACOS_OWNER_SIGNING_KEY_PATH),
            "absent error must point at the genesis seed path: {absent_msg}"
        );
        assert!(
            denied_msg.contains("could not be read") && denied_msg.contains("Permission denied"),
            "read-failed error must carry the underlying error: {denied_msg}"
        );
    }

    #[test]
    fn owner_key_empty_output_is_loud_not_initialization_hint() {
        let err = interpret_owner_key_read("   \n").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no output"),
            "empty read must not read as 'not initialized': {msg}"
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
    fn membership_log_header_matches_control_schema() {
        assert_eq!(membership_log_header(), "version=1");
    }

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

    // ── MAC-D5: membership init must carry RUSTYNET_NODE_ID ─────────────────

    fn peer(role: NodeRole, node_id: &str) -> NodeMembershipPeer {
        NodeMembershipPeer {
            alias: node_id.to_owned(),
            role,
            capabilities: Vec::new(),
            node_id: node_id.to_owned(),
            public_key_hex: "a".repeat(64),
            gossip_identity: GossipIdentity::DeferredPlatform,
        }
    }

    #[test]
    fn membership_init_script_carries_node_id_after_sudo() {
        // MAC-D5: the daemon fails closed without RUSTYNET_NODE_ID. The
        // command must set it (and the role) INSIDE the sudo invocation —
        // `env … sudo` has the variables stripped by sudo's env_reset.
        let script = membership_init_script("node-exit-1");
        assert!(
            script
                .starts_with("sudo -n env RUSTYNET_NODE_ROLE=admin RUSTYNET_NODE_ID='node-exit-1'"),
            "node id must be set after sudo -n env: {script}"
        );
        assert!(
            script.contains("ops init-membership"),
            "script must run init-membership: {script}"
        );
        assert!(
            script.contains(MACOS_RUSTYNET_PATH),
            "script must use the canonical macOS rustynet path: {script}"
        );
    }

    // ── MAC-D11: the init/peer-add invocations must carry the keychain
    //    account, not depend on the session environment ─────────────────────

    #[test]
    fn membership_init_script_carries_node_scoped_keychain_account() {
        // MAC-D11: `ops init-membership`'s passphrase gate hard-errors the
        // moment its idempotent early-out misses unless the keychain account
        // is in the invocation env. The account is the node-scoped item the
        // bootstrap provisions (`trust-passphrase-<node_id>`), passed after
        // `sudo -n env` so env_reset cannot strip it.
        let script = membership_init_script("node-exit-1");
        assert!(
            script.contains(
                "RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT='trust-passphrase-node-exit-1'"
            ),
            "init must carry the node-scoped keychain account: {script}"
        );
        assert!(
            script.starts_with("sudo -n env "),
            "account env must sit inside the sudo invocation: {script}"
        );
    }

    #[test]
    fn peer_add_script_carries_node_scoped_keychain_account() {
        // MAC-D11 ride-along: same env plumbing on the mutation verb.
        let script = peer_add_script(
            "node-exit-1",
            "node-client-1",
            "--client-gossip-pubkey-hex",
            &"a".repeat(64),
            "client",
        )
        .unwrap();
        assert!(
            script.contains(
                "RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT='trust-passphrase-node-exit-1'"
            ),
            "peer-add must carry the node-scoped keychain account: {script}"
        );
        assert!(
            script.starts_with("sudo -n env "),
            "account env must sit inside the sudo invocation: {script}"
        );
    }

    // ── MAC-D10: the snapshot read-back must fail LOUD, never silent ────────

    #[test]
    fn snapshot_readback_script_fails_loud_naming_the_path() {
        // The previous `test -s '<path>' && cat …` form's only failure output
        // was SILENCE (test exits 1, prints nothing), so a vanished genesis
        // surfaced as a bare "exit Some(1)" with empty stderr AND stdout.
        // The probe must emit its own diagnostic on stderr and exit 1,
        // naming the snapshot path.
        let script = membership_snapshot_readback_script();
        assert!(
            script.contains(">&2") && script.contains("exit 1"),
            "read-back failure must emit its own message and exit 1: {script}"
        );
        assert!(
            script.contains(MACOS_MEMBERSHIP_SNAPSHOT_PATH),
            "the failure message must name the snapshot path: {script}"
        );
        assert!(
            script.contains("missing or empty"),
            "the failure message must distinguish the vanish: {script}"
        );
    }

    #[test]
    fn snapshot_readback_script_reads_under_sudo() {
        // The snapshot is 0600 rustynetd:rustynetd; the SSH session is
        // unprivileged. Both the size probe and the read need `sudo -n`,
        // matching the owner-key probe's privilege pattern.
        let script = membership_snapshot_readback_script();
        assert!(
            script.contains("sudo -n test -s") && script.contains("sudo -n cat"),
            "probe and read must both run under sudo -n: {script}"
        );
        assert!(
            script.contains("| base64"),
            "the snapshot body must still be base64-encoded for transport: {script}"
        );
    }

    #[test]
    fn exit_node_id_resolution_sources_the_exit_peer() {
        let peers = vec![
            peer(NodeRole::Client, "node-client-1"),
            peer(NodeRole::Exit, "node-exit-1"),
        ];
        assert_eq!(exit_node_id_from_peers(&peers).unwrap(), "node-exit-1");
    }

    #[test]
    fn exit_node_id_resolution_fails_loud_without_exit_peer() {
        let peers = vec![peer(NodeRole::Client, "node-client-1")];
        let err = exit_node_id_from_peers(&peers).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no NodeRole::Exit peer") && msg.contains("RUSTYNET_NODE_ID"),
            "missing exit peer must name the failure: {msg}"
        );
    }

    #[test]
    fn exit_node_id_resolution_fails_loud_on_blank_id() {
        // A blank node id is a correctness hazard (empty env var), so an
        // empty string on the exit peer must fail rather than default.
        let peers = vec![peer(NodeRole::Exit, "")];
        let err = exit_node_id_from_peers(&peers).unwrap_err();
        assert!(
            err.to_string().contains("empty membership node id"),
            "blank id must fail loud: {err}"
        );
    }

    #[test]
    fn resolved_exit_node_id_survives_shell_safety_guard() {
        let peers = vec![peer(NodeRole::Exit, "node-exit-1")];
        let id = exit_node_id_from_peers(&peers).unwrap();
        assert_eq!(shell_safe_arg(id).unwrap(), "node-exit-1");
    }

    // ── MAC-D6: the peer-add approver id must be DERIVED, never shelled out ──

    #[test]
    fn peer_add_script_derives_owner_approver_id_from_the_exit_peer() {
        // The genesis owner approver `rustynetd membership init` registers is
        // "{node_id}-owner"; the harness must pass exactly that, not query a
        // CLI verb for it.
        let script = peer_add_script(
            "node-exit-1",
            "node-client-1",
            "--client-pubkey-hex-unaligned-wireguard",
            &"a".repeat(64),
            "client",
        )
        .unwrap();
        assert!(
            script.contains("--owner-approver-id 'node-exit-1-owner'"),
            "approver id must be derived as {{exit_node_id}}-owner: {script}"
        );
    }

    #[test]
    fn peer_add_script_never_invokes_an_owner_approver_id_verb() {
        // MAC-D6 regression pin: `ops owner-approver-id` does not exist. Any
        // return to querying a verb for the approver id must fail here.
        let script = peer_add_script(
            "node-exit-1",
            "node-client-1",
            "--client-pubkey-hex-unaligned-wireguard",
            &"a".repeat(64),
            "client",
        )
        .unwrap();
        assert!(
            !script.contains("ops owner-approver-id"),
            "no `ops owner-approver-id` subcommand exists; the approver id must \
             stay derived: {script}"
        );
        assert!(
            !script.contains("|| echo none"),
            "no failure may be swallowed into the approver id: {script}"
        );
        assert!(
            script.contains("ops e2e-membership-add"),
            "the peer-add must still run the real verb: {script}"
        );
    }

    #[test]
    fn derived_owner_approver_id_survives_shell_safety_guard() {
        // The derived value goes inside single quotes on a root remote shell;
        // the guard that validated it for the Linux twin must gate it here too.
        let script = peer_add_script(
            "node-exit-1",
            "node-client-1",
            "--client-pubkey-hex-unaligned-wireguard",
            &"a".repeat(64),
            "client",
        )
        .unwrap();
        // A malicious exit id would have been rejected upstream, but the
        // derivation itself must not smuggle characters past the guard.
        let approver = format!("{0}-owner", "node-exit-1");
        assert_eq!(shell_safe_arg(&approver).unwrap(), "node-exit-1-owner");
        assert!(script.contains("node-exit-1-owner"));
    }
}

#[cfg(test)]
mod gossip_subject_platform_tests {
    use super::*;

    /// Regression: this producer runs on a macOS exit node but writes membership
    /// for EVERY peer, including Linux ones that DO have a real gossip identity.
    /// The first implementation published `public_key_hex` unconditionally,
    /// which republished those nodes' WireGuard keys under a flag named
    /// `unaligned-wireguard` on any `--exit-platform macos` run — silently
    /// reinstating the defect, with the flag name actively lying about it.
    /// The branch must key on the SUBJECT peer, never on this producer's own
    /// platform.
    #[test]
    fn a_published_identity_selects_the_aligned_flag_even_on_the_macos_producer() {
        let gossip = "d".repeat(64);
        let wireguard = "b".repeat(64);
        let (flag, value) = match &GossipIdentity::Published(gossip.clone()) {
            GossipIdentity::Published(hex) => ("--client-gossip-pubkey-hex", hex.clone()),
            GossipIdentity::DeferredPlatform => {
                ("--client-pubkey-hex-unaligned-wireguard", wireguard.clone())
            }
        };
        assert_eq!(flag, "--client-gossip-pubkey-hex");
        assert_eq!(value, gossip);
        assert_ne!(value, wireguard, "must not publish the WireGuard key");
    }

    #[test]
    fn a_deferred_identity_selects_the_unaligned_flag() {
        let wireguard = "b".repeat(64);
        let (flag, value) = match &GossipIdentity::DeferredPlatform {
            GossipIdentity::Published(hex) => ("--client-gossip-pubkey-hex", hex.clone()),
            GossipIdentity::DeferredPlatform => {
                ("--client-pubkey-hex-unaligned-wireguard", wireguard.clone())
            }
        };
        assert_eq!(flag, "--client-pubkey-hex-unaligned-wireguard");
        assert_eq!(value, wireguard);
    }
}
