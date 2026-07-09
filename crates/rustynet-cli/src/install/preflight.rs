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
    // The Windows service-install path (Install-RustyNetWindowsService.ps1) does
    // its own Administrator gate via `net session`; this is the early, legible
    // check so we fail before any work. Full token-group inspection lands with
    // the Windows live path.
    Err(
        "Windows live install is not yet wired in the engine; run the Windows bootstrap directly"
            .to_owned(),
    )
}

#[cfg(not(windows))]
fn require_admin_windows() -> Result<(), String> {
    // Unreachable at runtime off Windows (host_facts() would not report Windows).
    Err("the Administrator elevation check is only meaningful on Windows".to_owned())
}
