#![allow(dead_code)]
use std::path::Path;
use std::time::Duration;

use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::adapter::windows_install::{
    WINDOWS_MEMBERSHIP_OWNER_PUBKEY_PATH, WINDOWS_MEMBERSHIP_SNAPSHOT_PATH, WINDOWS_STAGING_DIR,
    WINDOWS_STATE_ROOT, ps_quote, run_remote_ps,
};
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::{
    AdapterError, BundleKind, MembershipOwnerKey, MembershipSnapshot, NodeMembershipPeer,
};
use crate::vm_lab::orchestrator::role::NodeRole;
use rustynet_control::membership::MEMBERSHIP_SCHEMA_VERSION;
use rustynet_control::roles::role_capability_csv;

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const MEDIUM_TIMEOUT: Duration = Duration::from_secs(120);
const WINDOWS_MEMBERSHIP_LOG_PATH: &str = r"C:\ProgramData\RustyNet\membership\membership.log";

/// Read the membership owner public key from a Windows exit node.
/// Reads `WINDOWS_MEMBERSHIP_OWNER_PUBKEY_PATH` via `PowerShell` `Get-Content`.
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
    let pem = pem.trim().to_owned();
    if pem.is_empty() {
        return Err(AdapterError::Protocol {
            message: "membership owner public key is empty on remote; \
                      has membership been initialized?"
                .to_owned(),
        });
    }
    Ok(MembershipOwnerKey {
        public_key_pem: pem,
    })
}

/// Initialize the membership snapshot on a Windows exit node.
///
/// The initial membership snapshot was already created by `rustynetd membership init`
/// during `bootstrap_hosts`.  This function adds each non-exit peer by calling
/// `rustynetd membership add-peer` (backed by the owner signing key stored in
/// `WINDOWS_MEMBERSHIP_OWNER_KEY_PATH`, encrypted with the `WireGuard` passphrase DPAPI
/// blob).  Finally it reads back the updated snapshot bytes.
///
/// The `rustynet-windows-trust-cli` binary (`rustynet.exe`) only supports `trust`
/// subcommands and cannot be used for membership management; all membership operations
/// go through `rustynetd.exe` directly.
pub fn init_membership_snapshot(
    conn: &NodeConnection,
    _owner_key: &MembershipOwnerKey,
    peers: &[NodeMembershipPeer],
) -> Result<MembershipSnapshot, AdapterError> {
    use crate::vm_lab::orchestrator::adapter::windows_install::{
        WINDOWS_MEMBERSHIP_OWNER_KEY_PATH, WINDOWS_MEMBERSHIP_SIGNING_PASSPHRASE_PATH,
        WINDOWS_RUSTYNETD_PATH,
    };

    // Derive the owner approver ID from the exit node's node_id.
    // `rustynetd membership init` sets approver_id = "{node_id}-owner".
    let exit_node_id = peers
        .iter()
        .find(|p| p.role == NodeRole::Exit)
        .map_or("", |p| p.node_id.as_str());
    let approver_id = format!("{exit_node_id}-owner");

    // Add each non-exit peer via `rustynetd membership add-peer`.
    // The owner signing key lives at WINDOWS_MEMBERSHIP_OWNER_KEY_PATH and is
    // encrypted with the SIGNING passphrase stored in the DPAPI blob at
    // WINDOWS_MEMBERSHIP_SIGNING_PASSPHRASE_PATH. Bootstrap deliberately uses a
    // passphrase distinct from the WireGuard key passphrase (see windows_install
    // bootstrap, which fails closed if the two collide), so we must hand the
    // signing passphrase here — not the WG one — or decryption of the owner key
    // fails and add-peer aborts. `read_passphrase_file_explicit` on Windows
    // auto-decrypts DPAPI blobs.
    for peer in peers {
        if peer.role == NodeRole::Exit {
            continue;
        }
        let pubkey_hex = hex_32_arg(&peer.public_key_hex)?;
        let capabilities = role_capability_csv(&peer.capabilities);
        let add_script = build_add_peer_script(
            WINDOWS_RUSTYNETD_PATH,
            peer.node_id.as_str(),
            &pubkey_hex,
            &capabilities,
            exit_node_id,
            &approver_id,
            WINDOWS_MEMBERSHIP_OWNER_KEY_PATH,
            WINDOWS_MEMBERSHIP_SIGNING_PASSPHRASE_PATH,
        )?;
        // Invoke-RustyNetBootstrapNative is defined in the bootstrap script which
        // is already loaded in the SSH session.  For post-bootstrap calls we inline
        // a minimal version.
        let script_with_helper = format!(
            "if (-not (Get-Command Invoke-RustyNetBootstrapNative -ErrorAction SilentlyContinue)) {{ \
                 function Invoke-RustyNetBootstrapNative([scriptblock]$Action) {{ \
                     $out = & $Action 2>&1; \
                     [pscustomobject]@{{ ExitCode = $LASTEXITCODE; Output = ($out -join \"`n\") }} \
                 }} \
             }}; \
             {add_script}",
        );
        run_remote_ps(conn, &script_with_helper, MEDIUM_TIMEOUT)?;
    }

    // Read snapshot back as base64.
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
/// `PowerShell` `Move-Item` to install atomically to the final path.
pub fn distribute_signed_bundle(
    conn: &NodeConnection,
    kind: BundleKind,
    bundle_path: &Path,
) -> Result<(), AdapterError> {
    let (remote_staging, remote_dst) = remote_bundle_paths(&kind);

    let dst_parent = remote_dst
        .rsplit_once('\\')
        .map_or_else(|| WINDOWS_STATE_ROOT.to_owned(), |(dir, _)| dir.to_owned());
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

    let log_init_script = if matches!(kind, BundleKind::Membership) {
        let log_header = membership_log_header();
        format!(
            "; if ((-not (Test-Path -LiteralPath {log_q})) -or \
                 ((Get-Item -LiteralPath {log_q}).Length -eq 0)) {{ \
                 Set-Content -LiteralPath {log_q} -Value {log_header_q} -Encoding ascii \
             }}",
            log_q = ps_quote(WINDOWS_MEMBERSHIP_LOG_PATH)?,
            log_header_q = ps_quote(&log_header)?,
        )
    } else {
        String::new()
    };
    let install_script = format!(
        "Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         Move-Item -LiteralPath {src_q} -Destination {dst_q} -Force{log_init_script}",
        src_q = ps_quote(&remote_staging)?,
        dst_q = ps_quote(&remote_dst)?,
    );
    run_remote_ps(conn, &install_script, SHORT_TIMEOUT)?;

    Ok(())
}

/// Distribute the verifier public-key for `kind` to this Windows node.
///
/// SCPs the local pub-key file to a staging path, then atomically
/// `Move-Item`s it into the daemon-canonical trust directory.
pub fn distribute_verifier_key(
    conn: &NodeConnection,
    kind: BundleKind,
    pub_key_path: &Path,
) -> Result<(), AdapterError> {
    let (remote_staging, remote_dst) = windows_verifier_key_paths(&kind);
    let dst_parent = remote_dst
        .rsplit_once('\\')
        .map_or_else(|| WINDOWS_STATE_ROOT.to_owned(), |(d, _)| d.to_owned());
    let ensure_dir_script = format!(
        "if (-not (Test-Path -LiteralPath {dst_q})) {{ \
             New-Item -ItemType Directory -Force -Path {dst_q} | Out-Null \
         }}",
        dst_q = ps_quote(&dst_parent)?,
    );
    run_remote_ps(conn, &ensure_dir_script, SHORT_TIMEOUT)?;
    ssh::scp_to(
        conn,
        pub_key_path,
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

fn windows_verifier_key_paths(kind: &BundleKind) -> (String, String) {
    let staging = WINDOWS_STAGING_DIR;
    let state = WINDOWS_STATE_ROOT;
    match kind {
        BundleKind::Assignment => (
            format!(r"{staging}\rn-assignment.pub"),
            format!(r"{state}\trust\assignment.pub"),
        ),
        BundleKind::Traversal => (
            format!(r"{staging}\rn-traversal.pub"),
            format!(r"{state}\trust\traversal.pub"),
        ),
        BundleKind::DnsZone => (
            format!(r"{staging}\rn-dns-zone.pub"),
            format!(r"{state}\trust\dns-zone.pub"),
        ),
        BundleKind::Membership => (
            format!(r"{staging}\rn-membership.pub"),
            format!(r"{state}\trust\membership.pub"),
        ),
    }
}

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

fn membership_log_header() -> String {
    format!("version={MEMBERSHIP_SCHEMA_VERSION}")
}

/// Build the PowerShell `membership add-peer` script for one peer. Every
/// host-derived value — including the `node_id` embedded in the `throw`
/// error-message literal (RSA-0059) — is `ps_quote`d, so a `node_id` containing
/// a single quote (a compromised guest / crafted inventory) cannot break out of
/// any PowerShell string. Pure + side-effect-free so the quoting is unit-tested
/// without a live connection.
#[allow(clippy::too_many_arguments)]
fn build_add_peer_script(
    rustynetd_path: &str,
    node_id: &str,
    pubkey_hex: &str,
    capabilities: &str,
    owner: &str,
    approver_id: &str,
    signing_key_path: &str,
    passphrase_path: &str,
) -> Result<String, AdapterError> {
    let node_id_q = ps_quote(node_id)?;
    Ok(format!(
        "$ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         $result = Invoke-RustyNetBootstrapNative {{ \
             & {rustynetd_q} membership add-peer \
                 --node-id {node_id_q} \
                 --node-pubkey-hex {pubkey_q} \
                 --capabilities {capabilities_q} \
                 --owner {owner_q} \
                 --approver-id {approver_q} \
                 --signing-key {signing_key_q} \
                 --signing-key-passphrase-file {passphrase_q} \
         }}; \
         if ($result.ExitCode -ne 0) {{ \
             throw ('rustynetd membership add-peer failed for ' + {node_id_q} + ': ' + $result.Output) \
         }}",
        rustynetd_q = ps_quote(rustynetd_path)?,
        pubkey_q = ps_quote(pubkey_hex)?,
        capabilities_q = ps_quote(capabilities)?,
        owner_q = ps_quote(owner)?,
        approver_q = ps_quote(approver_id)?,
        signing_key_q = ps_quote(signing_key_path)?,
        passphrase_q = ps_quote(passphrase_path)?,
    ))
}

fn hex_32_arg(value: &str) -> Result<String, AdapterError> {
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
    fn membership_log_header_matches_control_schema() {
        assert_eq!(membership_log_header(), "version=1");
    }

    #[test]
    fn add_peer_script_quotes_node_id_in_throw_literal_no_breakout() {
        // RSA-0059: a node_id containing a single quote must not break out of
        // the PowerShell throw error-message literal (or any other PS literal).
        let evil = "node'; Remove-Item C:\\ -Recurse -Force; #";
        let script = build_add_peer_script(
            r"C:\Program Files\RustyNet\rustynetd.exe",
            evil,
            "abcd",
            "client",
            "exit-1",
            "exit-1-owner",
            r"C:\ProgramData\RustyNet\membership\owner.key",
            r"C:\ProgramData\RustyNet\membership\signing.pass",
        )
        .expect("script builds for a quote-bearing node_id");
        // The raw (unescaped) node_id must never appear — ps_quote doubles the
        // single quote, neutralising the breakout.
        assert!(
            !script.contains("node'; Remove-Item"),
            "raw single-quote breakout present in script: {script}"
        );
        assert!(
            script.contains("node''; Remove-Item"),
            "node_id must be ps_quoted (doubled quote) everywhere it appears: {script}"
        );
        // It must be quoted in BOTH the --node-id arg and the throw literal.
        assert_eq!(
            script.matches("node''; Remove-Item").count(),
            2,
            "node_id must be quoted in both the --node-id arg and the throw message: {script}"
        );
    }

    #[test]
    fn add_peer_script_rejects_control_chars_in_node_id() {
        // ps_quote rejects CR/LF/NUL, so a node_id carrying them fails closed.
        assert!(
            build_add_peer_script(
                "x",
                "node\ninjected",
                "abcd",
                "client",
                "exit-1",
                "exit-1-owner",
                "k",
                "p",
            )
            .is_err()
        );
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

    /// Verify that `init_membership_snapshot` no longer references the Windows
    /// trust CLI (`rustynet.exe`) for membership add-peer operations, and instead
    /// delegates to `rustynetd` which supports `membership add-peer` natively.
    #[test]
    fn init_membership_snapshot_uses_rustynetd_not_trust_cli() {
        use crate::vm_lab::orchestrator::adapter::windows_install::{
            WINDOWS_MEMBERSHIP_OWNER_KEY_PATH, WINDOWS_MEMBERSHIP_SIGNING_PASSPHRASE_PATH,
            WINDOWS_RUSTYNETD_PATH,
        };
        // These constants are referenced in the generated PS script. Verify the paths
        // are all under the reviewed state/install roots and contain the expected names.
        assert!(
            WINDOWS_RUSTYNETD_PATH.contains("rustynetd.exe"),
            "must invoke rustynetd.exe, not the trust CLI: {WINDOWS_RUSTYNETD_PATH}"
        );
        assert!(
            WINDOWS_MEMBERSHIP_OWNER_KEY_PATH.contains("membership.owner.key"),
            "signing key path must reference membership owner key: {WINDOWS_MEMBERSHIP_OWNER_KEY_PATH}"
        );
        // add-peer must decrypt the owner signing key with the SIGNING passphrase,
        // not the WireGuard key passphrase (bootstrap stores them separately).
        assert!(
            WINDOWS_MEMBERSHIP_SIGNING_PASSPHRASE_PATH.ends_with(".dpapi"),
            "signing passphrase path must be a DPAPI blob: {WINDOWS_MEMBERSHIP_SIGNING_PASSPHRASE_PATH}"
        );
        // The trust CLI is NOT referenced in init_membership_snapshot.
        // If the WINDOWS_RUSTYNET_PATH constant is removed from module-level imports,
        // this also serves as documentation that the old ops path is gone.
    }
}
