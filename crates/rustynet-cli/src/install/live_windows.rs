//! The live Windows node install (runs as Administrator on a Windows host).
//!
//! Unlike the Unix paths, the reviewed Windows service installer
//! (`Install-RustyNetWindowsService.ps1`) does placement + DPAPI key custody +
//! SCM registration itself, so this module is a thin, OS-agnostic wrapper: it
//! stages the acquired binaries into the layout the script expects, delivers the
//! trust anchor, and shells the embedded script in its `-NoDaemonStart` gated
//! mode. That reaches the same fail-closed "installed, awaiting enrollment"
//! terminal state as Linux/macOS: the SCM service is created but Stopped, no
//! trust is self-seeded, and host DNS is left untouched, until the deferred
//! enrollment seam delivers trust material and starts the service.
//!
//! This file is deliberately OS-agnostic Rust (it compiles on the Unix dev host
//! so the crate keeps building there) — it only *functions* on Windows, and
//! `install::run` only routes the Windows arm here on a Windows host. The Unix
//! `common::` helpers (which hardcode `/usr/local/bin`, `/etc/rustynet`, unix
//! perms) must NOT be used here.

use super::acquire::{Acquired, SHIPPING};
use super::{InstallRequest, InstallRole, TrustAnchorSource};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The reviewed Windows service-install script, embedded so no source tree is
/// needed on-target (same approach as the macOS installer).
const INSTALL_SERVICE_SCRIPT_WIN: &str =
    include_str!("../../../../scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1");

const INSTALL_ROOT: &str = r"C:\Program Files\RustyNet";
const STATE_ROOT: &str = r"C:\ProgramData\RustyNet";
const SERVICE_NAME: &str = "RustyNet";
/// Admin-only staging root for the binaries + script we run as Administrator.
const INSTALL_SRC_ROOT: &str = r"C:\ProgramData\RustyNet\install-src";
/// SYSTEM + Administrators full control, no inheritance (locale-independent SIDs).
const ACL_SYSTEM: &str = "*S-1-5-18:(OI)(CI)F";
const ACL_ADMINS: &str = "*S-1-5-32-544:(OI)(CI)F";

pub(super) fn install(req: &InstallRequest, acquired: &Acquired) -> Result<String, String> {
    let node_id = resolve_windows_node_id(&req.node_id)?;
    windows_service_role(req.role)?;

    let src_root = stage_source_root(&acquired.staging_dir)?;
    let anchor = deliver_trust_anchor_windows(&req.trust_anchor)?;
    let report = Path::new(STATE_ROOT).join("install-report.json");
    // Never let a stale report from a prior run be mistaken for this run's result.
    let _ = std::fs::remove_file(&report);
    let out = run_service_installer(&src_root, &node_id, &report)?;
    // The staged binaries/script live under an admin-locked dir; clear it after.
    let _ = std::fs::remove_dir_all(INSTALL_SRC_ROOT);

    let combined = format!(
        "{}\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
        std::fs::read_to_string(&report).unwrap_or_default()
    );
    let svc = classify_install(out.status.success(), &combined)?;

    Ok(format!(
        "rustynet installed on Windows (node_id={node_id}, role=client): acquired binaries ({}); \
         {anchor} {svc}",
        acquired.notes.join("; ")
    ))
}

fn windows_service_role(role: InstallRole) -> Result<(), String> {
    match role {
        InstallRole::Node => Ok(()),
        other => Err(format!(
            "Windows install currently supports --role node; {other:?} (relay/exit/anchor sibling \
             services) land next"
        )),
    }
}

/// Resolve the node id: explicit `--node-id`, else `%COMPUTERNAME%`, else the
/// `hostname` command.
fn resolve_windows_node_id(node_id: &Option<String>) -> Result<String, String> {
    if let Some(id) = node_id {
        let id = id.trim();
        if id.is_empty() {
            return Err("--node-id must not be empty".to_owned());
        }
        return validate_windows_node_id(id);
    }
    if let Ok(name) = std::env::var("COMPUTERNAME") {
        let name = name.trim().to_owned();
        if !name.is_empty() {
            return validate_windows_node_id(&name);
        }
    }
    let host = Command::new(system32("hostname.exe"))
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            "could not determine the Windows computer name; pass --node-id explicitly".to_owned()
        })?;
    validate_windows_node_id(&host)
}

/// The install script (`Test-RustyNetNodeId`) accepts only `[A-Za-z0-9_.-]`, at
/// most 128 chars. Enforce the same here so an invalid id fails fast with a
/// clear message instead of an opaque pre-trap PowerShell throw with no report.
fn validate_windows_node_id(id: &str) -> Result<String, String> {
    if id.is_empty() || id.len() > 128 {
        return Err(format!(
            "--node-id must be 1..=128 characters (got {})",
            id.len()
        ));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        return Err(format!(
            "--node-id '{id}' has invalid characters (allowed: letters, digits, '_', '.', '-')"
        ));
    }
    Ok(id.to_owned())
}

/// Stage the acquired `.exe`s into `<src>\target\release\` (the layout the PS1
/// sources from), under an admin-only-locked directory so a non-admin cannot
/// swap a binary or the script before we run them as Administrator.
fn stage_source_root(staging: &Path) -> Result<PathBuf, String> {
    let src_root = PathBuf::from(INSTALL_SRC_ROOT);
    let release = src_root.join("target").join("release");
    let _ = std::fs::remove_dir_all(&src_root); // clear any stale staging
    std::fs::create_dir_all(&release)
        .map_err(|err| format!("cannot create the Windows staging dir: {err}"))?;
    lock_admin_acl(&src_root)?;
    for name in SHIPPING {
        let file = format!("{name}.exe");
        std::fs::copy(staging.join(&file), release.join(&file))
            .map_err(|err| format!("cannot stage {file}: {err}"))?;
    }
    Ok(src_root)
}

/// Deliver the membership owner public key (§6.B). It is a PUBLIC verification
/// key with no Windows daemon consumer yet, so it is thumbprint-verified and
/// parked at the canonical Windows trust path with a SYSTEM+Administrators-only
/// DACL (the enrollment seam consumes it later).
fn deliver_trust_anchor_windows(anchor: &TrustAnchorSource) -> Result<String, String> {
    let Some(src) = &anchor.owner_key_file else {
        return Ok(
            "(no --owner-key-file supplied; the node has no membership owner key and will await \
             enrollment.)"
                .to_owned(),
        );
    };
    let bytes = std::fs::read(src)
        .map_err(|err| format!("cannot read owner key {}: {err}", src.display()))?;
    if let Some(expected) = &anchor.expected_thumbprint {
        let actual = crate::release_manifest::sha256_hex(&bytes);
        if actual != expected.trim().to_ascii_lowercase() {
            return Err(format!(
                "owner key thumbprint mismatch (expected {}, got {actual}) — fail closed",
                expected.trim()
            ));
        }
    }
    let trust_dir = Path::new(STATE_ROOT).join("trust");
    std::fs::create_dir_all(&trust_dir)
        .map_err(|err| format!("cannot create {}: {err}", trust_dir.display()))?;
    // Reclaim ownership + clear any attacker-planted ACEs on the trust dir BEFORE
    // writing the anchor — C:\ProgramData lets non-admins create/own subdirs, and
    // the dir owner keeps FILE_DELETE_CHILD over what we write.
    lock_admin_acl(&trust_dir)?;
    let dest = trust_dir.join("membership.owner.key.pub");
    std::fs::write(&dest, &bytes)
        .map_err(|err| format!("cannot write {}: {err}", dest.display()))?;
    lock_admin_acl(&dest)?;
    // Re-verify the ON-DISK key against the thumbprint: confirms what actually
    // landed and defends against a swap in the write→lock window.
    if let Some(expected) = &anchor.expected_thumbprint {
        let on_disk = std::fs::read(&dest)
            .map_err(|err| format!("cannot re-read {}: {err}", dest.display()))?;
        let actual = crate::release_manifest::sha256_hex(&on_disk);
        if actual != expected.trim().to_ascii_lowercase() {
            return Err(format!(
                "owner key on disk does not match the thumbprint after write (expected {}, got \
                 {actual}) — fail closed",
                expected.trim()
            ));
        }
    }
    Ok(format!(
        "trust anchor delivered to {}{} (parked for enrollment; no daemon consumer yet).",
        dest.display(),
        if anchor.expected_thumbprint.is_some() {
            " (thumbprint-verified)"
        } else {
            " (WARNING: no --owner-key-thumbprint — delivery unverified)"
        }
    ))
}

/// Write the embedded PS1 into the admin-locked staging root and run it in gated
/// mode (`-NoDaemonStart`): SCM service created but Stopped, no self-seeded
/// trust, host DNS untouched.
fn run_service_installer(src_root: &Path, node_id: &str, report: &Path) -> Result<Output, String> {
    let ps1 = src_root.join("Install-RustyNetWindowsService.ps1");
    std::fs::write(&ps1, INSTALL_SERVICE_SCRIPT_WIN)
        .map_err(|err| format!("cannot stage the Windows install script: {err}"))?;
    Command::new(system32(r"WindowsPowerShell\v1.0\powershell.exe"))
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&ps1)
        .arg("-RustyNetRoot")
        .arg(src_root)
        .args(["-InstallRoot", INSTALL_ROOT])
        .args(["-StateRoot", STATE_ROOT])
        .args(["-ServiceName", SERVICE_NAME])
        .args(["-NodeId", node_id])
        .args(["-NodeRole", "client"])
        .arg("-OutputPath")
        .arg(report)
        .arg("-NoDaemonStart")
        .output()
        .map_err(|err| format!("failed to run the Windows service installer: {err}"))
}

/// Resolve a `System32` utility by absolute path (via `%SystemRoot%`, fallback
/// `C:\Windows`), so a bare-name exec running as Administrator cannot be
/// search-order / application-directory hijacked.
pub(super) fn system32(rel: &str) -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    format!(r"{root}\System32\{rel}")
}

/// Lock a path to SYSTEM + Administrators only. Reclaims ownership FIRST (an
/// attacker-owner otherwise keeps implicit WRITE_DAC and can rewrite the DACL),
/// clears any pre-planted explicit ACEs (`/reset`), then strips inheritance and
/// grants only the reviewed principals with an inheritable ACE so children are
/// covered too. Mirrors the reviewed PS1 ACL helpers (which also `/setowner`
/// first). `/T` recurses so a directory's contents are locked in the same call.
pub(super) fn lock_admin_acl(path: &Path) -> Result<(), String> {
    let p = path.to_string_lossy().into_owned();
    let icacls = system32("icacls.exe");
    for args in [
        vec!["/setowner", "*S-1-5-32-544", "/T"],
        vec!["/reset", "/T"],
        vec![
            "/inheritance:r",
            "/grant:r",
            ACL_SYSTEM,
            "/grant:r",
            ACL_ADMINS,
            "/T",
        ],
    ] {
        let mut argv = vec![p.as_str()];
        argv.extend(args);
        let out = Command::new(&icacls)
            .args(&argv)
            .output()
            .map_err(|err| format!("failed to run icacls on {p}: {err}"))?;
        if !out.status.success() {
            return Err(format!(
                "icacls hardening ({}) failed for {p}: {}",
                argv[1..].join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
    }
    Ok(())
}

/// Classify the installer outcome from its exit status + JSON report / output.
/// A gated install's success terminal state is the SCM service present but
/// Stopped (`windows-installed-awaiting-enrollment`); a missing WireGuard-for-
/// Windows backend is an actionable prerequisite error; anything else fails.
fn classify_install(exit_ok: bool, combined: &str) -> Result<String, String> {
    // Success requires BOTH a zero exit and the gated-success reason token — a
    // stale report from a prior run must never mask a failing install.
    if exit_ok && combined.contains("windows-installed-awaiting-enrollment") {
        return Ok(
            "SCM service 'RustyNet' registered and left Stopped; no trust self-seeded, host DNS \
             untouched — awaiting enrollment. It starts once trust material is delivered and the \
             service is enabled + started. This is the correct fail-closed terminal state for a \
             fresh node."
                .to_owned(),
        );
    }
    if combined.contains("windows-runtime-backend-explicitly-unsupported") {
        return Err(
            "WireGuard for Windows is not installed (backend windows-unsupported) — install it \
             from https://www.wireguard.com/install/, then re-run `rustynet install`."
                .to_owned(),
        );
    }
    if combined.contains("windows-gated-install-service-not-stopped") {
        return Err(
            "the Windows daemon is not Stopped after a gated install (expected awaiting-enrollment) \
             — fail closed."
                .to_owned(),
        );
    }
    Err(format!(
        "Windows service registration did not reach the awaiting-enrollment state (installer \
         exit_ok={exit_ok}):\n{}",
        combined.trim()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_role_accepts_node_rejects_others() {
        assert!(windows_service_role(InstallRole::Node).is_ok());
        assert!(windows_service_role(InstallRole::Relay).is_err());
        assert!(windows_service_role(InstallRole::Exit).is_err());
    }

    #[test]
    fn resolve_node_id_prefers_explicit() {
        assert_eq!(
            resolve_windows_node_id(&Some("  win-1 ".to_owned())).unwrap(),
            "win-1"
        );
        assert!(resolve_windows_node_id(&Some("  ".to_owned())).is_err());
    }

    #[test]
    fn node_id_validation_matches_the_ps1_charset() {
        assert_eq!(
            validate_windows_node_id("win_client.1-a").unwrap(),
            "win_client.1-a"
        );
        assert!(validate_windows_node_id("bad space").is_err());
        assert!(validate_windows_node_id("bad/slash").is_err());
        assert!(validate_windows_node_id("bad;semi").is_err());
        assert!(validate_windows_node_id("").is_err());
        assert!(validate_windows_node_id(&"x".repeat(129)).is_err());
    }

    #[test]
    fn classify_maps_the_reason_tokens() {
        assert!(
            classify_install(
                true,
                r#"{"status":"pass","reason":"windows-installed-awaiting-enrollment"}"#
            )
            .unwrap()
            .contains("awaiting enrollment")
        );
        let wg = classify_install(
            false,
            r#"{"status":"blocked","reason":"windows-runtime-backend-explicitly-unsupported"}"#,
        )
        .unwrap_err();
        assert!(wg.contains("WireGuard for Windows"), "{wg}");
        assert!(
            classify_install(
                false,
                r#"{"reason":"windows-gated-install-service-not-stopped"}"#
            )
            .unwrap_err()
            .contains("not Stopped")
        );
        assert!(classify_install(false, "unexpected garbage").is_err());
        // A non-zero exit must NOT pass even if a stale report carries the token.
        assert!(
            classify_install(
                false,
                r#"{"reason":"windows-installed-awaiting-enrollment"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn embedded_windows_script_supports_the_gated_flag() {
        assert!(
            INSTALL_SERVICE_SCRIPT_WIN.contains("$NoDaemonStart"),
            "param missing"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT_WIN.contains("windows-installed-awaiting-enrollment"),
            "gated status token missing"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT_WIN.contains("[string]$NodeId"),
            "NodeId param missing"
        );
    }
}
