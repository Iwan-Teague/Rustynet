//! Preflight: elevation gating for a live install. Fail-closed with actionable
//! guidance if not elevated. The engine NEVER self-elevates and never shells
//! `sudo` — the caller is responsible for running under the right privileges.

use rustynet_sysinfo::OsFamily;

/// Require the elevation a live install needs on this OS family.
pub(super) fn require_elevation(family: OsFamily) -> Result<(), String> {
    match family {
        OsFamily::Linux | OsFamily::Macos => require_root_unix(),
        OsFamily::Windows => require_admin_windows(),
        OsFamily::Unsupported => Err("unsupported operating system".to_owned()),
    }
}

#[cfg(unix)]
fn require_root_unix() -> Result<(), String> {
    if nix::unistd::Uid::effective().is_root() {
        Ok(())
    } else {
        Err(
            "rustynet install must run as root — re-run under sudo, e.g. `sudo rustynet install …`"
                .to_owned(),
        )
    }
}

#[cfg(not(unix))]
fn require_root_unix() -> Result<(), String> {
    Err("the root elevation check is only meaningful on a unix host".to_owned())
}

#[cfg(windows)]
fn require_admin_windows() -> Result<(), String> {
    // Two independent Administrator-only operations run early (before any work);
    // either succeeding proves an elevated token. `net session` is the common
    // check but false-negatives when the Server (LanmanServer) service is
    // stopped/disabled, so also accept `fsutil dirty query` (admin-only, no
    // service dependency). Both are resolved by absolute System32 path so a
    // bare-name exec cannot be search-order-hijacked into this elevated process.
    // The engine never self-elevates; the operator runs from an elevated shell.
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_owned());
    let net = format!(r"{sysroot}\System32\net.exe");
    let fsutil = format!(r"{sysroot}\System32\fsutil.exe");
    if admin_probe_ok(&net, &["session"]) || admin_probe_ok(&fsutil, &["dirty", "query", &drive]) {
        Ok(())
    } else {
        Err(
            "rustynet install must run as Administrator — re-run from an elevated \
             (Run as administrator) PowerShell or Command Prompt"
                .to_owned(),
        )
    }
}

#[cfg(windows)]
fn admin_probe_ok(program: &str, args: &[&str]) -> bool {
    std::process::Command::new(program)
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn require_admin_windows() -> Result<(), String> {
    // Unreachable at runtime off Windows (host_facts() would not report Windows).
    Err("the Administrator elevation check is only meaningful on Windows".to_owned())
}
