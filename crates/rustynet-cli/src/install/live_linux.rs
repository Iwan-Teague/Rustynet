//! The live Linux node install (runs as root on a Linux host). Orchestrates the
//! researched hardened path: provision prerequisites, place binaries, set up key
//! custody (`rustynetd key init` + `systemd-creds`), deliver + thumbprint-verify
//! the trust anchor, then delegate the user/dirs/units/service to the existing
//! `ops install-systemd` verb.
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

use super::acquire::{Acquired, SHIPPING};
use super::{InstallRequest, InstallRole, TrustAnchorSource};
use rustynet_sysinfo::PkgFamily;
use std::io::Read;
use std::path::Path;
use std::process::Command;

const BIN_DIR: &str = "/usr/local/bin";
const RUSTYNETD: &str = "/usr/local/bin/rustynetd";
const RUSTYNET: &str = "/usr/local/bin/rustynet";

pub(super) fn install(
    req: &InstallRequest,
    pkg: Option<PkgFamily>,
    acquired: &Acquired,
) -> Result<String, String> {
    let node_id = resolve_node_id(req)?;
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

fn resolve_node_id(req: &InstallRequest) -> Result<String, String> {
    if let Some(id) = &req.node_id {
        let id = id.trim();
        if id.is_empty() {
            return Err("--node-id must not be empty".to_owned());
        }
        return Ok(id.to_owned());
    }
    hostname().ok_or_else(|| {
        "could not determine hostname for the node id; pass --node-id explicitly".to_owned()
    })
}

/// The host's name, from /etc/hostname (Linux) or the `hostname` command.
fn hostname() -> Option<String> {
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        let h = h.trim().to_owned();
        if !h.is_empty() {
            return Some(h);
        }
    }
    Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
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

/// True iff every runtime prerequisite executable is already on PATH — `wg`
/// (wireguard-tools), `ip` (iproute2), `nft` (nftables).
fn prereqs_present() -> bool {
    ["wg", "ip", "nft"].iter().all(|b| which(b).is_some())
}

/// Resolve an executable by scanning `$PATH` (argv-only, no shell); the first
/// executable match wins.
fn which(bin: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(bin))
        .find(|cand| is_executable(cand))
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
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

/// Place each shipping binary from staging into /usr/local/bin (0755). Running
/// as root, so the destination is root-owned.
fn place_binaries(staging: &Path) -> Result<usize, String> {
    for name in SHIPPING {
        let src = staging.join(name);
        let dst = Path::new(BIN_DIR).join(name);
        place_one(&src, &dst)?;
    }
    Ok(SHIPPING.len())
}

/// Atomically install one executable: copy to a temp file in the destination
/// directory, set its mode, then rename it over the target. The rename (rather
/// than an in-place `copy` over `dst`) is what lets an *upgrade* replace a binary
/// that is currently executing — `copy` onto a running executable fails with
/// `ETXTBSY` ("Text file busy"), whereas `rename` swaps the directory entry and
/// leaves the running process's inode intact. Temp and target share a directory,
/// so the rename stays within one filesystem (no cross-device `EXDEV`).
fn place_one(src: &Path, dst: &Path) -> Result<(), String> {
    let dir = dst
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", dst.display()))?;
    let file_name = dst
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("{} has no file name", dst.display()))?;
    let tmp = dir.join(format!(".{file_name}.rn-install.tmp"));
    let _ = std::fs::remove_file(&tmp); // clear any stale temp from an aborted run
    std::fs::copy(src, &tmp).map_err(|err| format!("cannot stage {}: {err}", tmp.display()))?;
    set_mode(&tmp, 0o755);
    std::fs::rename(&tmp, dst).map_err(|err| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot place {}: {err}", dst.display())
    })
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

    let _ = std::fs::remove_file(passfile);
    let _ = std::fs::remove_file("/run/rustynet/wireguard.key");
    Ok(())
}

/// Deliver the membership owner public key (§6.B) to its canonical path,
/// root-only, symlink-rejecting, and sha256-thumbprint-verified if a thumbprint
/// was supplied (upstream has no thumbprint check — this is the enforcement).
fn deliver_trust_anchor(anchor: &TrustAnchorSource) -> Result<String, String> {
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
    let dest = "/etc/rustynet/membership.owner.key.pub";
    if Path::new(dest)
        .symlink_metadata()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(format!(
            "{dest} is a symlink — refusing to write through it"
        ));
    }
    write_file(Path::new(dest), &bytes, 0o640)?;
    run("chown", &["root:rustynetd", dest])?;
    Ok(format!(
        "trust anchor delivered to {dest}{}.",
        if anchor.expected_thumbprint.is_some() {
            " (thumbprint-verified)"
        } else {
            " (WARNING: no --owner-key-thumbprint — delivery unverified)"
        }
    ))
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
    let out = Command::new(RUSTYNET)
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
    Command::new("systemctl")
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

// --- small root-context helpers (argv-only exec, no shell) ---

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|err| format!("failed to run `{program}`: {err}"))?;
    if !status.success() {
        return Err(format!(
            "command failed (exit {:?}): {program} {}",
            status.code(),
            args.join(" ")
        ));
    }
    Ok(())
}

fn ensure_dir(path: &str, mode: u32) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|err| format!("cannot create {path}: {err}"))?;
    set_mode(Path::new(path), mode);
    Ok(())
}

fn write_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|err| format!("cannot write {}: {err}", path.display()))?;
    set_mode(path, mode);
    Ok(())
}

fn random_hex_32() -> Result<String, String> {
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|err| format!("cannot open /dev/urandom: {err}"))?;
    let mut buf = [0u8; 32];
    f.read_exact(&mut buf)
        .map_err(|err| format!("cannot read /dev/urandom: {err}"))?;
    let mut out = String::with_capacity(64);
    for b in buf {
        out.push_str(&format!("{b:02x}"));
    }
    Ok(out)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

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
    fn random_hex_is_64_lowercase_hex() {
        let h = random_hex_32().unwrap();
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn trust_anchor_none_is_awaiting_enrollment_not_error() {
        let a = TrustAnchorSource {
            owner_key_file: None,
            expected_thumbprint: None,
        };
        let msg = deliver_trust_anchor(&a).unwrap();
        assert!(msg.contains("await enrollment"), "{msg}");
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

    #[test]
    fn awaiting_enrollment_message_is_clear() {
        let m = awaiting_enrollment_message();
        assert!(m.contains("enrollment"), "{m}");
        assert!(m.contains("enabled"), "{m}");
    }

    #[test]
    fn which_resolves_present_and_rejects_absent() {
        // `sh` lives in a PATH dir on every unix host the tests run on.
        #[cfg(unix)]
        assert!(which("sh").is_some());
        assert!(which("rustynet_definitely_not_a_real_binary_xyz").is_none());
    }

    #[test]
    fn place_one_creates_then_atomically_overwrites() {
        let dir = std::env::temp_dir().join(format!("rn-place-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src");
        let dst = dir.join("dst");

        std::fs::write(&src, b"v1").unwrap();
        place_one(&src, &dst).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"v1");

        // Overwrite an existing target (the upgrade path).
        std::fs::write(&src, b"v2-longer").unwrap();
        place_one(&src, &dst).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"v2-longer");
        // No temp residue left behind.
        assert!(!dir.join(".dst.rn-install.tmp").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
