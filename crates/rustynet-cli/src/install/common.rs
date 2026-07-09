//! Shared, OS-agnostic primitives for the live (root-context) install paths on
//! Unix hosts (`live_linux`, `live_macos`). Everything here is argv-only exec (no
//! shell), fail-closed, and identical across the supported Unix platforms:
//! node-id resolution, `$PATH` executable probing, atomic binary placement into
//! `/usr/local/bin`, filesystem helpers, and the §6.B membership-owner-key trust
//! anchor delivery (thumbprint-verified, symlink-rejecting).

use super::TrustAnchorSource;
use super::acquire::SHIPPING;
use std::io::Read;
use std::path::Path;
use std::process::Command;

/// The Unix binary install directory (Linux + macOS both use `/usr/local/bin`).
pub(super) const BIN_DIR: &str = "/usr/local/bin";
pub(super) const RUSTYNETD: &str = "/usr/local/bin/rustynetd";
pub(super) const RUSTYNET: &str = "/usr/local/bin/rustynet";

/// The trusted `PATH` the installer pins for every child process it spawns.
/// The installer runs as root (often via `sudo`, which on default macOS does NOT
/// set `secure_path`), so an inherited user PATH could otherwise redirect a
/// bare-name helper — e.g. a user-writable `/opt/homebrew/bin` ordered ahead of
/// `/usr/bin` — to an attacker-planted binary that then runs as root. Pinning
/// PATH to the system directories (dscl/codesign/security/chown/chmod/systemctl/
/// systemd-creds/apt-get/dnf/hostname all live here) closes that hijack.
pub(super) const TRUSTED_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// A [`Command`] for `program` with the sanitized [`TRUSTED_PATH`], so a
/// bare-name helper cannot be hijacked through an inherited PATH. Every external
/// program the installer runs as root goes through this.
pub(super) fn command(program: &str) -> Command {
    let mut c = Command::new(program);
    c.env("PATH", TRUSTED_PATH);
    c
}

/// A [`Command`] with a fully cleared environment except a pinned
/// [`TRUSTED_PATH`]. Use this when spawning a **shell** as root (e.g. `bash`),
/// because a shell honors additional env-based code-execution channels that PATH
/// pinning does not cover — `BASH_ENV`/`ENV` (a script sourced at startup) and
/// exported shell functions (`BASH_FUNC_*`). Clearing the environment neutralizes
/// those; the installer's shell scripts take all input via argv, never env.
pub(super) fn command_clean(program: &str) -> Command {
    let mut c = Command::new(program);
    c.env_clear().env("PATH", TRUSTED_PATH);
    c
}

/// Resolve the node id: the explicit `--node-id`, else the host's name.
pub(super) fn resolve_node_id(node_id: &Option<String>) -> Result<String, String> {
    if let Some(id) = node_id {
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

/// The host's name, from /etc/hostname (Linux) or the `hostname` command (both).
fn hostname() -> Option<String> {
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        let h = h.trim().to_owned();
        if !h.is_empty() {
            return Some(h);
        }
    }
    command("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Place each shipping binary from staging into /usr/local/bin (0755). Running
/// as root, so the destination is root-owned.
pub(super) fn place_binaries(staging: &Path) -> Result<usize, String> {
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
pub(super) fn place_one(src: &Path, dst: &Path) -> Result<(), String> {
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

/// Deliver the membership owner public key (§6.B) to its canonical path,
/// symlink-rejecting, and sha256-thumbprint-verified if a thumbprint was
/// supplied (upstream has no thumbprint check — this is the enforcement).
///
/// The file is written root-owned at 0644. It is a PUBLIC verification key, so
/// its confidentiality is irrelevant; what matters is integrity — only root can
/// write it (0644 → root-only write, world read). Writing it root-owned rather
/// than `chown root:rustynetd` deliberately removes any dependency on the
/// `rustynetd` group already existing, which lets the caller deliver the anchor
/// before or after creating the service identity without a deterministic chown
/// failure on a fresh host.
pub(super) fn deliver_trust_anchor(anchor: &TrustAnchorSource) -> Result<String, String> {
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
    write_file(Path::new(dest), &bytes, 0o644)?;
    Ok(format!(
        "trust anchor delivered to {dest} (root-owned, public key){}.",
        if anchor.expected_thumbprint.is_some() {
            " (thumbprint-verified)"
        } else {
            " (WARNING: no --owner-key-thumbprint — delivery unverified)"
        }
    ))
}

/// Resolve an executable by scanning `$PATH` (argv-only, no shell); the first
/// executable match wins.
pub(super) fn which(bin: &str) -> Option<std::path::PathBuf> {
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

// --- small root-context helpers (argv-only exec, no shell) ---

pub(super) fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let status = command(program)
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

pub(super) fn ensure_dir(path: &str, mode: u32) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|err| format!("cannot create {path}: {err}"))?;
    set_mode(Path::new(path), mode);
    Ok(())
}

pub(super) fn write_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|err| format!("cannot write {}: {err}", path.display()))?;
    set_mode(path, mode);
    Ok(())
}

pub(super) fn random_hex_32() -> Result<String, String> {
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
pub(super) fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
pub(super) fn set_mode(_path: &Path, _mode: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_node_id_uses_explicit_then_hostname() {
        assert_eq!(
            resolve_node_id(&Some("  node-x ".to_owned())).unwrap(),
            "node-x"
        );
        assert!(resolve_node_id(&Some("   ".to_owned())).is_err());
        // None falls back to hostname(), which is non-empty on any test host.
        assert!(resolve_node_id(&None).is_ok());
    }

    #[test]
    fn which_resolves_present_and_rejects_absent() {
        // `sh` lives in a PATH dir on every unix host the tests run on.
        #[cfg(unix)]
        assert!(which("sh").is_some());
        assert!(which("rustynet_definitely_not_a_real_binary_xyz").is_none());
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

    #[test]
    fn trust_anchor_none_is_awaiting_enrollment_not_error() {
        let a = TrustAnchorSource {
            owner_key_file: None,
            expected_thumbprint: None,
        };
        let msg = deliver_trust_anchor(&a).unwrap();
        assert!(msg.contains("await enrollment"), "{msg}");
    }
}
