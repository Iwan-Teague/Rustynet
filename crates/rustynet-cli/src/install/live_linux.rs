//! The live Linux node install (runs as root on a Linux host). Confident steps
//! landed here: provision runtime prerequisites (argv apt/dnf — replaces the old
//! bootstrap's `sudo -n`), then place the shipping binaries into /usr/local/bin.
//!
//! The remaining steps are precisely specified but need on-hardware iteration:
//!   - key custody: `rustynetd key init` (encrypted WG key + pubkey) + two
//!     `systemd-creds encrypt` blobs under /etc/rustynet/credentials/.
//!   - trust anchor: deliver the membership owner pubkey + trust-evidence/verifier
//!     key, sha256-thumbprint-verified (no thumbprint check exists upstream yet).
//!   - service register: `crate::ops_install_systemd::execute_ops_install_systemd`
//!     (creates the rustynetd user/dirs/units + daemon-reload/enable/start). It
//!     requires the custody `.cred` blobs + trust material to already exist, so
//!     those two steps must land first. A fresh node then reaches "installed +
//!     enabled, awaiting enrollment" — the daemon activates once it has trust
//!     material (the enrollment seam), which is correct fail-closed behavior.

use super::acquire::{Acquired, SHIPPING};
use rustynet_sysinfo::PkgFamily;
use std::path::Path;
use std::process::Command;

pub(super) fn install(pkg: Option<PkgFamily>, acquired: &Acquired) -> Result<String, String> {
    provision_prereqs(pkg)?;
    let placed = place_binaries(&acquired.staging_dir)?;
    let acq = acquired.notes.join("; ");
    Err(format!(
        "Linux install progress: acquired binaries ({acq}); runtime prerequisites installed; \
         {placed} binaries placed in /usr/local/bin (0755). Remaining steps — key custody \
         (rustynetd key init + systemd-creds), trust anchor delivery + thumbprint verify, and \
         service registration (ops install-systemd) — are not yet wired; they land next. \
         Preview with --dry-run."
    ))
}

fn provision_prereqs(pkg: Option<PkgFamily>) -> Result<(), String> {
    for argv in prereq_commands(pkg)? {
        run_argv(&argv)?;
    }
    Ok(())
}

/// The package-manager commands (argv only, no shell) to install the Linux
/// runtime prerequisites. The installer runs as root, so no `sudo`.
fn prereq_commands(pkg: Option<PkgFamily>) -> Result<Vec<Vec<String>>, String> {
    let owned = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<String>>();
    match pkg {
        Some(PkgFamily::Apt) => Ok(vec![
            owned(&["apt-get", "update", "-y"]),
            owned(&[
                "apt-get",
                "install",
                "-y",
                "--no-install-recommends",
                "wireguard-tools",
                "iproute2",
                "nftables",
            ]),
        ]),
        Some(PkgFamily::Dnf) => Ok(vec![owned(&[
            "dnf",
            "install",
            "-y",
            "wireguard-tools",
            "iproute2",
            "nftables",
        ])]),
        None => Err(
            "unrecognized Linux distro — cannot select a package manager; install \
             wireguard-tools, iproute2 and nftables manually, then re-run"
                .to_owned(),
        ),
    }
}

fn run_argv(argv: &[String]) -> Result<(), String> {
    let status = Command::new(&argv[0])
        .args(&argv[1..])
        .status()
        .map_err(|err| format!("failed to run `{}`: {err}", argv[0]))?;
    if !status.success() {
        return Err(format!("command failed: {}", argv.join(" ")));
    }
    Ok(())
}

/// Copy each shipping binary from staging into /usr/local/bin (0755). Running as
/// root, so the destination is root-owned.
fn place_binaries(staging: &Path) -> Result<usize, String> {
    let dst_dir = Path::new("/usr/local/bin");
    for name in SHIPPING {
        let src = staging.join(name);
        let dst = dst_dir.join(name);
        std::fs::copy(&src, &dst)
            .map_err(|err| format!("cannot place {}: {err}", dst.display()))?;
        set_mode_0755(&dst);
    }
    Ok(SHIPPING.len())
}

#[cfg(unix)]
fn set_mode_0755(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
}

#[cfg(not(unix))]
fn set_mode_0755(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apt_prereq_commands_update_then_install() {
        let cmds = prereq_commands(Some(PkgFamily::Apt)).unwrap();
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0], vec!["apt-get", "update", "-y"]);
        assert!(cmds[1].contains(&"install".to_owned()));
        assert!(cmds[1].contains(&"wireguard-tools".to_owned()));
        assert!(cmds[1].contains(&"nftables".to_owned()));
        // argv-only: no shell metacharacters anywhere.
        for cmd in &cmds {
            for token in cmd {
                assert!(!token.contains(';') && !token.contains('|') && !token.contains('&'));
            }
        }
    }

    #[test]
    fn dnf_prereq_commands_single_install() {
        let cmds = prereq_commands(Some(PkgFamily::Dnf)).unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0][0], "dnf");
        assert!(cmds[0].contains(&"wireguard-tools".to_owned()));
    }

    #[test]
    fn unknown_distro_fails_closed() {
        assert!(prereq_commands(None).is_err());
    }
}
