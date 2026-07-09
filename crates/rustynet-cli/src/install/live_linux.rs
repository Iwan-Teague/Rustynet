//! The live Linux node install (runs as root on a Linux host). Orchestrates the
//! researched hardened path: provision prerequisites, place binaries, set up key
//! custody (`rustynetd key init` + `systemd-creds`), deliver + thumbprint-verify
//! the trust anchor, then delegate the user/dirs/units/service to the existing
//! `ops install-systemd` verb. OS-agnostic primitives live in `super::common`.
//!
//! It shells out to the just-installed `rustynet ops install-systemd` (with env
//! set via `Command::env`) rather than calling `execute_ops_install_systemd`
//! in-process, because that verb is env-driven and `std::env::set_var` is unsafe
//! (forbidden workspace-wide) in edition 2024.
//!
//! A fresh node reaches "installed + enabled, awaiting enrollment": the daemon's
//! ExecStartPre requires trust-evidence + verifier-key (delivered by
//! `rustynet enrollment consume`), so it activates only after enrollment —
//! correct fail-closed behavior.

use super::acquire::Acquired;
use super::common::{
    RUSTYNET, RUSTYNETD, command, deliver_trust_anchor, ensure_dir, place_binaries, random_hex_32,
    resolve_node_id, run, which, write_file,
};
use super::{InstallRequest, InstallRole};
use rustynet_sysinfo::PkgFamily;
use std::path::Path;

pub(super) fn install(
    req: &InstallRequest,
    pkg: Option<PkgFamily>,
    acquired: &Acquired,
) -> Result<String, String> {
    let node_id = resolve_node_id(&req.node_id)?;
    let role = linux_service_role(req.role)?;
    provision_prereqs(pkg)?;
    let placed = place_binaries(&acquired.staging_dir)?;
    setup_key_custody()?;
    let anchor = deliver_trust_anchor(&req.trust_anchor)?;
    let svc = register_service(&node_id, role)?;
    Ok(format!(
        "rustynet installed on Linux (node_id={node_id}, role={role}): acquired binaries ({}); \
         {placed} binaries in /usr/local/bin; key custody provisioned; {anchor} {svc}",
        acquired.notes.join("; ")
    ))
}

fn linux_service_role(role: InstallRole) -> Result<&'static str, String> {
    match role {
        InstallRole::Node => Ok("client"),
        other => Err(format!(
            "Linux install currently supports --role node; {other:?} (relay/exit/anchor sibling \
             services) land next"
        )),
    }
}

fn provision_prereqs(pkg: Option<PkgFamily>) -> Result<(), String> {
    // Idempotent + offline-tolerant: if the runtime tools are already present,
    // skip the package manager entirely (which needs network). This is what lets
    // the installer re-run cleanly and provision a host whose prereqs were
    // installed earlier but which has no repo connectivity right now.
    if prereqs_present() {
        return Ok(());
    }
    for argv in prereq_commands(pkg)? {
        run(
            &argv[0],
            &argv[1..].iter().map(String::as_str).collect::<Vec<_>>(),
        )?;
    }
    Ok(())
}

/// True iff every Linux runtime prerequisite executable is already on PATH —
/// `wg` (wireguard-tools), `ip` (iproute2), `nft` (nftables).
fn prereqs_present() -> bool {
    ["wg", "ip", "nft"].iter().all(|b| which(b).is_some())
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

/// Linux key custody: encrypted WG key + pubkey via `rustynetd key init`, then
/// the passphrase encrypted into the two `.cred` blobs the systemd unit loads.
/// Plaintext material is scrubbed. (Linux has no `key store-passphrase`.)
fn setup_key_custody() -> Result<(), String> {
    ensure_dir("/run/rustynet", 0o770)?;
    ensure_dir("/var/lib/rustynet", 0o700)?;
    ensure_dir("/var/lib/rustynet/keys", 0o700)?;
    ensure_dir("/etc/rustynet", 0o750)?;
    ensure_dir("/etc/rustynet/credentials", 0o700)?;

    let passphrase = random_hex_32()?;
    let passfile = "/etc/rustynet/credentials/.wg-passphrase.tmp";
    write_file(Path::new(passfile), passphrase.as_bytes(), 0o600)?;

    // key init + credential encryption inside a closure so the plaintext
    // passphrase file and runtime private key are scrubbed on EVERY exit path —
    // including an early failure — never leaving cleartext key material at rest
    // (§4).
    let custody = (|| -> Result<(), String> {
        run(
            RUSTYNETD,
            &[
                "key",
                "init",
                "--runtime-private-key",
                "/run/rustynet/wireguard.key",
                "--encrypted-private-key",
                "/var/lib/rustynet/keys/wireguard.key.enc",
                "--public-key",
                "/var/lib/rustynet/keys/wireguard.pub",
                "--passphrase-file",
                passfile,
                "--force",
            ],
        )?;

        for name in ["wg_key_passphrase", "signing_key_passphrase"] {
            let dest = format!("/etc/rustynet/credentials/{name}.cred");
            run(
                "systemd-creds",
                &["encrypt", &format!("--name={name}"), passfile, &dest],
            )?;
            run("chown", &["root:root", &dest])?;
            run("chmod", &["0600", &dest])?;
        }
        Ok(())
    })();

    let _ = std::fs::remove_file(passfile);
    let _ = std::fs::remove_file("/run/rustynet/wireguard.key");
    custody
}

/// Delegate user/dirs/units/service to `ops install-systemd`. Shelled with env
/// via Command (set_var is forbidden-unsafe). Needs the scripts/systemd/ unit
/// templates, resolved from cwd (a source checkout) or RUSTYNET_INSTALL_SOURCE_ROOT.
///
/// On a fresh, unenrolled node the daemon's ExecStartPre gate requires the
/// trust-evidence + verifier-key that only enrollment delivers, so
/// `ops install-systemd` returns non-zero at the service-start step. That is the
/// expected terminal state ("installed + enabled, awaiting enrollment"), not an
/// install failure. We classify it: if the service is installed + enabled and
/// the node is genuinely pre-enrollment (no trust-evidence file), report the
/// clean awaiting-enrollment outcome; otherwise surface the real error.
fn register_service(node_id: &str, role: &str) -> Result<String, String> {
    let source_root = std::env::current_dir()
        .map_err(|err| format!("cannot resolve the current dir for install-systemd: {err}"))?;
    let out = command(RUSTYNET)
        .args(["ops", "install-systemd"])
        .env("RUSTYNET_NODE_ID", node_id)
        .env("RUSTYNET_NODE_ROLE", role)
        .env("RUSTYNET_INSTALL_SOURCE_ROOT", &source_root)
        .current_dir(&source_root)
        .output()
        .map_err(|err| format!("failed to run `rustynet ops install-systemd`: {err}"))?;

    if out.status.success() {
        return Ok(if service_is_active("rustynetd.service") {
            "service installed, enabled, and running.".to_owned()
        } else {
            awaiting_enrollment_message()
        });
    }

    // Non-zero exit: benign iff the service registered (enabled) and the node is
    // genuinely pre-enrollment. Anything else is a real failure — surface it.
    if service_is_enabled("rustynetd.service") && node_is_unenrolled() {
        return Ok(awaiting_enrollment_message());
    }
    Err(format!(
        "`rustynet ops install-systemd` failed (exit {:?}) and the node is NOT in the expected \
         installed-and-enabled state — this is a real failure, not the awaiting-enrollment seam.\n\
         stdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    ))
}

fn awaiting_enrollment_message() -> String {
    "service installed and enabled; the daemon is awaiting enrollment — it activates once trust \
     material is delivered (run `rustynet enrollment consume <token>`). This is the correct \
     fail-closed terminal state for a fresh node."
        .to_owned()
}

fn service_is_enabled(unit: &str) -> bool {
    systemctl_stdout(&["is-enabled", unit])
        .map(|s| s.trim() == "enabled")
        .unwrap_or(false)
}

fn service_is_active(unit: &str) -> bool {
    systemctl_stdout(&["is-active", unit])
        .map(|s| s.trim() == "active")
        .unwrap_or(false)
}

/// A node is unenrolled iff the daemon's trust-evidence file (delivered by
/// enrollment) does not yet exist. The path is read from the installed unit's
/// environment so it tracks the template rather than hardcoding it; a missing
/// unit env is treated as unenrolled.
fn node_is_unenrolled() -> bool {
    match unit_env_value("rustynetd.service", "RUSTYNET_TRUST_EVIDENCE") {
        Some(path) => !Path::new(&path).exists(),
        None => true,
    }
}

fn systemctl_stdout(args: &[&str]) -> Option<String> {
    command("systemctl")
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Extract a single `Environment=KEY=VALUE` entry from an installed unit via
/// `systemctl show -p Environment`.
fn unit_env_value(unit: &str, key: &str) -> Option<String> {
    let text = systemctl_stdout(&["show", unit, "--property=Environment"])?;
    parse_unit_env_value(&text, key)
}

/// Pure parse of a `systemctl show -p Environment` line
/// (`Environment=A=1 B=2 …`) into the value for `key`.
fn parse_unit_env_value(text: &str, key: &str) -> Option<String> {
    let rest = text.trim().strip_prefix("Environment=")?;
    let needle = format!("{key}=");
    rest.split_whitespace()
        .find_map(|tok| tok.strip_prefix(&needle).map(str::to_owned))
}

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

    #[test]
    fn node_role_maps_node_to_client_and_rejects_others() {
        assert_eq!(linux_service_role(InstallRole::Node).unwrap(), "client");
        assert!(linux_service_role(InstallRole::Relay).is_err());
        assert!(linux_service_role(InstallRole::Exit).is_err());
    }

    #[test]
    fn awaiting_enrollment_message_is_clear() {
        let m = awaiting_enrollment_message();
        assert!(m.contains("enrollment"), "{m}");
        assert!(m.contains("enabled"), "{m}");
    }

    #[test]
    fn parse_unit_env_value_extracts_paths() {
        let line = "Environment=RUSTYNET_TRUST_EVIDENCE=/var/lib/rustynet/rustynetd.trust \
                    RUSTYNET_TRUST_VERIFIER_KEY=/etc/rustynet/trust-evidence.pub";
        assert_eq!(
            parse_unit_env_value(line, "RUSTYNET_TRUST_EVIDENCE").as_deref(),
            Some("/var/lib/rustynet/rustynetd.trust")
        );
        assert_eq!(
            parse_unit_env_value(line, "RUSTYNET_TRUST_VERIFIER_KEY").as_deref(),
            Some("/etc/rustynet/trust-evidence.pub")
        );
        assert!(parse_unit_env_value(line, "RUSTYNET_MISSING").is_none());
        assert!(parse_unit_env_value("", "RUSTYNET_TRUST_EVIDENCE").is_none());
        assert!(parse_unit_env_value("Environment=", "RUSTYNET_TRUST_EVIDENCE").is_none());
    }
}
