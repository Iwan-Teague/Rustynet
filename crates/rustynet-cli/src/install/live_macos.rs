//! The live macOS node install (runs as root on a macOS host). Provisions a bare
//! machine into a hardened rustynet node in the exact ordering the macOS
//! key-custody + launchd model requires, reaching the same fail-closed
//! "installed, awaiting enrollment" terminal state as Linux.
//!
//! Ordering invariant (each step depends on the previous):
//!   1. ensure the `wg` prerequisite (key init shells `wg genkey`/`wg pubkey`)
//!   2. create the `rustynetd` service identity via `dscl` (idempotent)
//!   3. unlock the System keychain (so `store-passphrase` can write it)
//!   4. place binaries, then `codesign --force -s -` rustynetd — the keychain
//!      item is bound to the re-signed cdhash, so this MUST precede custody
//!   5. key custody: `rustynetd key init` (encrypted key + pubkey) then
//!      `rustynetd key store-passphrase` into the System keychain (owned identity)
//!   6. deliver + thumbprint-verify the membership owner-key trust anchor
//!   7. register the launchd services (embedded reviewed installer script, gated
//!      mode): privileged-helper bootstrapped + running, daemon plist installed
//!      but `launchctl disable`d so it stays down until the (deferred) enrollment
//!      seam runs `launchctl enable` + `bootstrap` — the macOS analogue of
//!      Linux's ExecStartPre-gated (enabled-but-down) systemd unit.
//!
//! Unlike Linux (systemd-creds), macOS stores the passphrase in the Keychain via
//! the daemon's own `key store-passphrase` verb, read back by the launchd daemon
//! under its own code signature. The daemon plist is rendered by the embedded
//! `Install-RustyNetMacosService.sh` (the single reviewed renderer, shared with
//! the live-lab hardening validator) rather than a second Rust renderer.

use super::acquire::Acquired;
use super::common::{
    RUSTYNETD, command, command_clean, deliver_trust_anchor, ensure_dir, place_binaries,
    random_hex_32, resolve_node_id, run, which, write_file,
};
use super::{InstallRequest, InstallRole};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;

const STATE_ROOT: &str = "/usr/local/var/rustynet";
const KEYS_DIR: &str = "/usr/local/var/rustynet/keys";
const BOOTSTRAP_DIR: &str = "/usr/local/var/rustynet/bootstrap";
const RUNTIME_KEY: &str = "/usr/local/var/rustynet/keys/wireguard.key";
const ENCRYPTED_KEY: &str = "/usr/local/var/rustynet/keys/wireguard.key.enc";
const PUBLIC_KEY: &str = "/usr/local/var/rustynet/keys/wireguard.pub";
const PASSPHRASE_FILE: &str = "/usr/local/var/rustynet/bootstrap/wireguard.passphrase";
const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";

/// The reviewed macOS service-install script, embedded so the installer needs no
/// on-target source tree (it renders both launchd plists inline — it reads no
/// template file). This is the single reviewed daemon-plist renderer, also used
/// (via its own `include_str!`) by the live-lab macOS adapter, so there is one
/// plist shape and one hardening-validated body.
const INSTALL_SERVICE_SCRIPT: &str =
    include_str!("../../../../scripts/bootstrap/macos/Install-RustyNetMacosService.sh");

pub(super) fn install(req: &InstallRequest, acquired: &Acquired) -> Result<String, String> {
    let node_id = resolve_node_id(&req.node_id)?;
    macos_service_role(req.role)?;

    let wg = ensure_wg()?;
    ensure_rustynetd_user()?;
    unlock_system_keychain();
    let placed = place_binaries(&acquired.staging_dir)?;
    codesign_daemon()?;
    setup_state_dirs()?;
    setup_key_custody(&node_id, &wg)?;
    let anchor = deliver_trust_anchor(&req.trust_anchor)?;
    let svc = register_service_gated(&node_id)?;

    Ok(format!(
        "rustynet installed on macOS (node_id={node_id}, role=client): acquired binaries ({}); \
         {placed} binaries in /usr/local/bin; rustynetd re-signed (ad-hoc); key custody in the \
         System keychain (account wg-passphrase-{node_id}, wg={}); {anchor} {svc}",
        acquired.notes.join("; "),
        wg.display()
    ))
}

fn macos_service_role(role: InstallRole) -> Result<(), String> {
    match role {
        InstallRole::Node => Ok(()),
        other => Err(format!(
            "macOS install currently supports --role node; {other:?} (relay/exit/anchor sibling \
             services) land with macOS service registration"
        )),
    }
}

/// Well-known Homebrew `wg` locations (arm64, then Intel). Checked as a fallback
/// because the installer's inherited PATH under `sudo` may not include the
/// Homebrew bin dir (a minimal/sanitized PATH, or a hardened `secure_path`
/// sudoers), so `which("wg")` alone can miss a brew-installed `wg`.
const BREW_WG_PATHS: [&str; 2] = ["/opt/homebrew/bin/wg", "/usr/local/bin/wg"];

/// Resolve `wg` (wireguard-tools) — the macOS userspace-shared backend runs
/// boringtun in-process, but `rustynetd key init` still shells `wg genkey` /
/// `wg pubkey`. Check PATH, then the Homebrew locations. Fail closed with an
/// actionable message if absent — brew refuses to run as root, so we do not
/// auto-install here. Stock macOS has no `wg`, so this is the real prerequisite.
/// (`wg` is passed to `rustynetd` by absolute path, never resolved via PATH at
/// exec time.)
fn ensure_wg() -> Result<PathBuf, String> {
    if let Some(p) = which("wg") {
        return Ok(p);
    }
    for cand in BREW_WG_PATHS {
        let p = Path::new(cand);
        if p.exists() {
            return Ok(p.to_path_buf());
        }
    }
    Err(
        "`wg` (wireguard-tools) is required for key generation but was not found on PATH or in \
         the Homebrew locations; install it (as your normal user, not root): \
         `brew install wireguard-tools`, then re-run `sudo rustynet install`"
            .to_owned(),
    )
}

/// Create the unprivileged `rustynetd` service identity via `dscl` (idempotent).
/// User + group both named `rustynetd`, sharing one free id in 500..599, no
/// login shell, empty home — a non-login service account.
fn ensure_rustynetd_user() -> Result<(), String> {
    if dscl_read_ok("/Users/rustynetd") {
        return Ok(());
    }
    let id = pick_free_service_id()?;
    let id = id.to_string();
    let steps: [&[&str]; 9] = [
        &[".", "-create", "/Groups/rustynetd"],
        &[
            ".",
            "-create",
            "/Groups/rustynetd",
            "RealName",
            "RustyNet Daemon",
        ],
        &[".", "-create", "/Groups/rustynetd", "gid", &id],
        &[".", "-create", "/Users/rustynetd"],
        &[
            ".",
            "-create",
            "/Users/rustynetd",
            "RealName",
            "RustyNet Daemon",
        ],
        &[".", "-create", "/Users/rustynetd", "UniqueID", &id],
        &[".", "-create", "/Users/rustynetd", "PrimaryGroupID", &id],
        &[
            ".",
            "-create",
            "/Users/rustynetd",
            "UserShell",
            "/usr/bin/false",
        ],
        &[
            ".",
            "-create",
            "/Users/rustynetd",
            "NFSHomeDirectory",
            "/var/empty",
        ],
    ];
    for args in steps {
        run("dscl", args)?;
    }
    Ok(())
}

fn dscl_read_ok(record: &str) -> bool {
    command("dscl")
        .args([".", "-read", record])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// First id in 500..599 not already claimed by a user (`dscl -search` prints
/// nothing for a free id). Fail closed if the range is exhausted.
fn pick_free_service_id() -> Result<u32, String> {
    for id in 500u32..600 {
        let out = command("dscl")
            .args([".", "-search", "/Users", "UniqueID", &id.to_string()])
            .output()
            .map_err(|err| format!("failed to probe uid {id} via dscl: {err}"))?;
        if out.status.success() && String::from_utf8_lossy(&out.stdout).trim().is_empty() {
            return Ok(id);
        }
    }
    Err("no free uid in 500..599 for the rustynetd service account".to_owned())
}

/// Unlock the System keychain and disable its idle auto-lock (best-effort). If
/// it stays locked, `key store-passphrase` surfaces the real fail-closed error
/// later; a missing keychain file is nothing to unlock.
fn unlock_system_keychain() {
    if !Path::new(SYSTEM_KEYCHAIN).exists() {
        return;
    }
    let _ = command("security")
        .args(["set-keychain-settings", SYSTEM_KEYCHAIN])
        .status();
    let _ = command("security")
        .args(["unlock-keychain", "-p", "", SYSTEM_KEYCHAIN])
        .status();
}

/// Re-sign the placed rustynetd with a stable ad-hoc identity. Required BEFORE
/// `key store-passphrase`: the owned-identity keychain ACL binds read access to
/// rustynetd's cdhash, and a linker-signed binary has no stable cdhash (the
/// daemon would then fail to read the passphrase back → "os secure store
/// unavailable"). Only rustynetd is re-signed (the CLI + relay do not do an
/// owned-identity keychain store).
fn codesign_daemon() -> Result<(), String> {
    run("codesign", &["--force", "-s", "-", RUSTYNETD])
}

/// Create the macOS state tree with least-exposure modes. `key init` writes the
/// key material here as root; the keys directory is then handed to `rustynetd`
/// so the launchd daemon can read the encrypted key.
fn setup_state_dirs() -> Result<(), String> {
    ensure_dir(STATE_ROOT, 0o755)?;
    ensure_dir(KEYS_DIR, 0o700)?;
    ensure_dir(BOOTSTRAP_DIR, 0o700)?;
    ensure_dir("/usr/local/var/rustynet/trust", 0o755)?;
    ensure_dir("/usr/local/var/rustynet/membership", 0o755)?;
    ensure_dir("/usr/local/var/log/rustynet", 0o755)?;
    ensure_dir("/etc/rustynet", 0o755)?;
    Ok(())
}

/// macOS key custody: generate the encrypted WG key + pubkey via `rustynetd key
/// init` (threading the resolved `wg` path through argv, since it shells `wg`
/// for keygen), then store the passphrase in the System keychain via `rustynetd
/// key store-passphrase` under rustynetd's own (re-signed) identity. Plaintext
/// passphrase + runtime key are scrubbed; the keys directory is handed to
/// `rustynetd` so the daemon can read the encrypted key back.
fn setup_key_custody(node_id: &str, wg: &Path) -> Result<(), String> {
    let passphrase = random_hex_32()?;
    write_file(Path::new(PASSPHRASE_FILE), passphrase.as_bytes(), 0o600)?;

    // Generate the encrypted key + store the passphrase inside a closure so the
    // plaintext passphrase file AND the plaintext runtime private key are
    // scrubbed on EVERY exit path — including an early failure (e.g. a locked
    // keychain failing `store-passphrase`). Never leave cleartext key material
    // at rest (§4).
    let custody = (|| -> Result<(), String> {
        let status = command(RUSTYNETD)
            .args([
                "key",
                "init",
                "--runtime-private-key",
                RUNTIME_KEY,
                "--encrypted-private-key",
                ENCRYPTED_KEY,
                "--public-key",
                PUBLIC_KEY,
                "--passphrase-file",
                PASSPHRASE_FILE,
                "--force",
            ])
            .env("RUSTYNET_WG_BINARY_PATH", wg)
            .status()
            .map_err(|err| format!("failed to run `rustynetd key init`: {err}"))?;
        if !status.success() {
            return Err(format!(
                "`rustynetd key init` failed (exit {:?})",
                status.code()
            ));
        }

        // Owned-identity keychain store (no --keychain-allow-any-app): only the
        // re-signed rustynetd may read this passphrase back.
        run(
            RUSTYNETD,
            &[
                "key",
                "store-passphrase",
                "--passphrase-file",
                PASSPHRASE_FILE,
                "--keychain-account",
                &format!("wg-passphrase-{node_id}"),
            ],
        )
    })();

    // Scrub the plaintext passphrase + runtime private key regardless of outcome.
    let _ = std::fs::remove_file(PASSPHRASE_FILE);
    let _ = std::fs::remove_file(RUNTIME_KEY);
    custody?;

    // Hand the keys directory to rustynetd so the launchd daemon can read the
    // encrypted key back.
    run("chown", &["-R", "rustynetd:rustynetd", KEYS_DIR])
}

/// Register the launchd services by shelling the embedded reviewed service-install
/// script in its `--no-daemon-start` gated mode: it renders + installs both
/// plists and bootstraps the privileged helper, then `launchctl disable`s the
/// daemon so it stays down (now and across reboots) until the deferred enrollment
/// seam runs `launchctl enable` + `bootstrap`. This is the macOS analogue of
/// Linux's "installed + enabled, ExecStartPre-gated" awaiting-enrollment state.
///
/// `node_id` MUST match the id Increment 1's key custody used for the keychain
/// account (`wg-passphrase-<node_id>`), or the daemon cannot decrypt its key.
fn register_service_gated(node_id: &str) -> Result<String, String> {
    // Pipe the embedded script to `bash -s` via stdin — there is NO on-disk
    // script for an attacker to swap between write and exec. (`/usr/local` is
    // admin-group-writable on macOS, so a predictable temp path there would be a
    // TOCTOU root-exec hazard.) `bash -s -- <args>` runs the stdin script with
    // <args> as positional parameters, exactly as the script's flag parser wants.
    let mut child = command_clean("bash")
        .args([
            "-s",
            "--",
            "--rustynetd-bin",
            RUSTYNETD,
            "--state-root",
            STATE_ROOT,
            "--log-dir",
            "/usr/local/var/log/rustynet",
            "--node-id",
            node_id,
            "--node-role",
            "client",
            "--network-id",
            "",
            "--wg-interface",
            "utun9",
            "--no-daemon-start",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn the macOS service installer: {err}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "no stdin handle for the macOS service installer".to_owned())?
        .write_all(INSTALL_SERVICE_SCRIPT.as_bytes())
        .map_err(|err| format!("failed to pipe the macOS service installer script: {err}"))?;
    let out = child
        .wait_with_output()
        .map_err(|err| format!("the macOS service installer did not complete: {err}"))?;
    if !out.status.success() {
        return Err(format!(
            "macOS service registration failed (exit {:?}).\nstdout: {}\nstderr: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    // Fail closed if the daemon somehow started (or its state cannot be
    // confirmed) — the gated install must leave it disabled/awaiting enrollment,
    // never running without trust evidence.
    if daemon_is_running() {
        return Err(
            "the macOS daemon may be running, or its state could not be confirmed, after a gated \
             install (expected disabled/awaiting enrollment) — fail closed"
                .to_owned(),
        );
    }
    Ok(
        "launchd services registered: privileged-helper running; the daemon plist is installed \
        and disabled, awaiting enrollment — it activates once trust material is delivered and the \
        service is enabled + bootstrapped. This is the correct fail-closed terminal state for a \
        fresh node."
            .to_owned(),
    )
}

/// True iff the `com.rustynet.daemon` launchd job is loaded AND running. A gated
/// (disabled, not bootstrapped) job is not loaded, so `launchctl print` fails and
/// this returns false.
fn daemon_is_running() -> bool {
    match command("launchctl")
        .args(["print", "system/com.rustynet.daemon"])
        .output()
    {
        // A successful launchctl run: "state = running" means running; a non-zero
        // exit ("Could not find service …") means not loaded — the gated state.
        Ok(o) => {
            o.status.success() && String::from_utf8_lossy(&o.stdout).contains("state = running")
        }
        // Could not even run launchctl: we cannot confirm the daemon is stopped,
        // so treat it as possibly-running and fail closed.
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_role_accepts_node_rejects_others() {
        assert!(macos_service_role(InstallRole::Node).is_ok());
        assert!(macos_service_role(InstallRole::Relay).is_err());
        assert!(macos_service_role(InstallRole::Exit).is_err());
        assert!(macos_service_role(InstallRole::Anchor).is_err());
    }

    #[test]
    fn ensure_wg_ok_when_resolvable_else_actionable_error() {
        let resolvable =
            which("wg").is_some() || BREW_WG_PATHS.iter().any(|p| Path::new(p).exists());
        match ensure_wg() {
            Ok(_) => assert!(resolvable),
            Err(e) => {
                assert!(!resolvable);
                assert!(e.contains("brew install wireguard-tools"), "{e}");
            }
        }
    }

    #[test]
    fn macos_state_paths_are_under_the_state_root() {
        for p in [
            KEYS_DIR,
            BOOTSTRAP_DIR,
            RUNTIME_KEY,
            ENCRYPTED_KEY,
            PUBLIC_KEY,
        ] {
            assert!(p.starts_with(STATE_ROOT), "{p}");
        }
    }

    #[test]
    fn embedded_service_script_supports_the_gated_flag() {
        // The embedded copy must carry the gated-install flag + the disable path
        // we depend on, and must still render the reviewed plist body.
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("--no-daemon-start"),
            "flag arm missing"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("launchctl disable system/com.rustynet.daemon"),
            "disable path missing"
        );
        // The non-gated branch must re-enable before bootstrap so a host a prior
        // gated install disabled can still be started by a non-gated caller.
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("launchctl enable system/com.rustynet.daemon"),
            "recovery enable missing"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("NO_DAEMON_START"),
            "gate variable missing"
        );
        // Reviewed plist body must be untouched (RunAtLoad stays true).
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("<key>RunAtLoad</key>"),
            "plist body missing"
        );
    }
}
