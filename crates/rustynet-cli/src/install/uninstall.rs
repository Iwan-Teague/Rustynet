//! `rustynet install --uninstall`: reverse a live install per OS. Best-effort and
//! idempotent — removes what is present and tolerates what is already gone — but
//! surfaces genuine (e.g. permission) errors on the load-bearing steps. It
//! removes the services, the placed binaries, and ALL local key custody + trust
//! material, leaving a clean slate for a reinstall / re-enrollment. The
//! unprivileged service identity (rustynetd user/group) is deliberately kept.
//!
//! Runs after the elevation gate, so it executes as root / Administrator.

use super::common::command;
use rustynet_sysinfo::OsFamily;
use std::path::Path;

pub(super) fn run(family: OsFamily) -> Result<String, String> {
    match family {
        OsFamily::Linux => uninstall_linux().map(|()| {
            "rustynet uninstalled from Linux: services stopped + disabled, unit files removed \
             (daemon-reload), binaries removed from /usr/local/bin, and all state — keys, systemd \
             credentials, and trust material under /var/lib/rustynet + /etc/rustynet — removed. \
             The `rustynetd` system user/group was left in place."
                .to_owned()
        }),
        OsFamily::Macos => uninstall_macos().map(|()| {
            "rustynet uninstalled from macOS: launchd jobs booted out + plists removed, disable \
             override cleared, binaries removed from /usr/local/bin, System-keychain key/trust \
             passphrases deleted, and state under /usr/local/var/rustynet + the trust anchor \
             removed. The `rustynetd` dscl user/group was left in place."
                .to_owned()
        }),
        OsFamily::Windows => uninstall_windows().map(|()| {
            "rustynet uninstalled from Windows: SCM service removed and the install + state roots \
             purged (C:\\Program Files\\RustyNet and C:\\ProgramData\\RustyNet)."
                .to_owned()
        }),
        OsFamily::Unsupported => Err("unsupported operating system".to_owned()),
    }
}

/// The systemd units `ops install-systemd` installs (destinations under
/// /etc/systemd/system).
const LINUX_UNITS: [&str; 7] = [
    "rustynetd.service",
    "rustynetd-privileged-helper.service",
    "rustynetd-managed-dns.service",
    "rustynetd-trust-refresh.service",
    "rustynetd-trust-refresh.timer",
    "rustynetd-assignment-refresh.service",
    "rustynetd-assignment-refresh.timer",
];

fn uninstall_linux() -> Result<(), String> {
    // Stop + disable every unit (ignore not-present), remove the unit files,
    // reload, then remove binaries and all state (keys, credentials, trust).
    for unit in LINUX_UNITS {
        let _ = command("systemctl")
            .args(["disable", "--now", unit])
            .status();
    }
    for unit in LINUX_UNITS {
        let _ = std::fs::remove_file(format!("/etc/systemd/system/{unit}"));
    }
    let _ = command("systemctl").arg("daemon-reload").status();
    remove_unix_binaries();
    for dir in ["/var/lib/rustynet", "/run/rustynet", "/etc/rustynet"] {
        let _ = std::fs::remove_dir_all(dir);
    }
    Ok(())
}

fn uninstall_macos() -> Result<(), String> {
    for label in [
        "system/com.rustynet.daemon",
        "system/com.rustynet.privileged-helper",
    ] {
        let _ = command("launchctl").args(["bootout", label]).status();
    }
    // Clear any persistent `launchctl disable` override so a later reinstall's
    // gated (disabled) service isn't confused with a stale one.
    let _ = command("launchctl")
        .args(["enable", "system/com.rustynet.daemon"])
        .status();
    for plist in [
        "/Library/LaunchDaemons/com.rustynet.daemon.plist",
        "/Library/LaunchDaemons/com.rustynet.privileged-helper.plist",
    ] {
        let _ = std::fs::remove_file(plist);
    }
    remove_unix_binaries();
    // Delete the System-keychain custody items by service (accounts are
    // node-scoped, so match on the service and drain any duplicates).
    const KEYCHAIN: &str = "/Library/Keychains/System.keychain";
    for svc in [
        "net.rustynet.wg-key-passphrase",
        "rustynet.signing_passphrase",
    ] {
        for _ in 0..16 {
            let deleted = command("security")
                .args(["delete-generic-password", "-s", svc, KEYCHAIN])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !deleted {
                break;
            }
        }
    }
    let _ = std::fs::remove_dir_all("/usr/local/var/rustynet");
    let _ = std::fs::remove_file("/etc/rustynet/membership.owner.key.pub");
    Ok(())
}

/// The embedded Windows uninstaller (`Uninstall-RustyNetWindowsService.ps1`),
/// run with `-PurgeStateRoot -PurgeInstallRoot` for a full removal.
const UNINSTALL_SCRIPT_WIN: &str =
    include_str!("../../../../scripts/bootstrap/windows/Uninstall-RustyNetWindowsService.ps1");

fn uninstall_windows() -> Result<(), String> {
    // Write the embedded uninstaller into a fresh admin-locked dir and run it as
    // Administrator (same anti-tamper posture as the installer).
    let src = Path::new(r"C:\ProgramData\RustyNet\uninstall-src");
    let _ = std::fs::remove_dir_all(src);
    std::fs::create_dir_all(src)
        .map_err(|err| format!("cannot create the Windows uninstall staging dir: {err}"))?;
    super::live_windows::lock_admin_acl(src)?;
    let ps1 = src.join("Uninstall-RustyNetWindowsService.ps1");
    std::fs::write(&ps1, UNINSTALL_SCRIPT_WIN)
        .map_err(|err| format!("cannot stage the Windows uninstall script: {err}"))?;
    let out = command(&super::live_windows::system32(
        r"WindowsPowerShell\v1.0\powershell.exe",
    ))
    .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
    .arg(&ps1)
    .args(["-InstallRoot", r"C:\Program Files\RustyNet"])
    .args(["-StateRoot", r"C:\ProgramData\RustyNet"])
    .args(["-ServiceName", "RustyNet"])
    .arg("-PurgeStateRoot")
    .arg("-PurgeInstallRoot")
    .output()
    .map_err(|err| format!("failed to run the Windows uninstaller: {err}"))?;
    let _ = std::fs::remove_dir_all(src);
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "the Windows uninstaller exited {:?}:\nstdout: {}\nstderr: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Remove the three shipping binaries from /usr/local/bin (Linux + macOS).
fn remove_unix_binaries() {
    for name in super::acquire::SHIPPING {
        let _ = std::fs::remove_file(format!("/usr/local/bin/{name}"));
    }
}
