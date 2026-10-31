//! `rustynet install --uninstall`: reverse a live install per OS. Best-effort and
//! idempotent — removes what is present and tolerates what is already gone — but
//! surfaces genuine (e.g. permission) errors on the load-bearing steps. It
//! removes the services, the placed binaries, and ALL local key custody + trust
//! material, leaving a clean slate for a reinstall / re-enrollment. The
//! unprivileged service identity (rustynetd user/group) is deliberately kept.
//!
//! Runs after the elevation gate, so it executes as root / Administrator.
//!
//! The one exception to "remove all key custody" is the macOS owner signing key
//! and its passphrase: both are KEPT by default (see [`UninstallOptions`]).
//! Deleting the passphrase while the key file survives makes the owner key
//! permanently unopenable, which locks the network out of membership signing.

use super::common::command;
use rustynet_sysinfo::OsFamily;
use std::io::ErrorKind;
use std::path::Path;
use std::time::Duration;

/// The exact typed phrase `--confirm-owner-key-deletion` must carry before
/// `--delete-owner-key` is honoured. Case-sensitive.
pub const OWNER_KEY_DELETION_CONFIRMATION: &str = "DELETE-OWNER-KEY";

/// macOS owner signing key file. Twin of `crate::DEFAULT_MEMBERSHIP_OWNER_SIGNING_KEY_PATH`
/// on macOS (main.rs) and rustynetd's `DEFAULT_MEMBERSHIP_OWNER_SIGNING_KEY_PATH`
/// (daemon.rs). Pinned by a test below.
const MACOS_OWNER_SIGNING_KEY_PATH: &str = "/usr/local/etc/rustynet/membership.owner.key";

/// The System keychain, where every macOS custody item is stored.
const MACOS_SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";

/// Keychain service of the WireGuard key passphrase. Node-scoped state; deleted
/// with the state it protects, as before.
const MACOS_WG_KEY_PASSPHRASE_KEYCHAIN_SERVICE: &str = "net.rustynet.wg-key-passphrase";

/// Bounded drain of duplicate keychain items per service.
const MACOS_KEYCHAIN_DRAIN_LIMIT: usize = 16;

/// Options for `rustynet install --uninstall`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UninstallOptions {
    /// Explicit opt-in, macOS only. Also deletes the owner signing key file and
    /// every item in the `rustynet.signing_passphrase` keychain service. Off by
    /// default. The service also holds the trust signing passphrase, and the
    /// accounts cannot be told apart at uninstall time, so both go together.
    pub delete_owner_key: bool,
}

/// What happened to the macOS owner key, rendered into the uninstall report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnerKeyOutcome {
    /// Kept by default; the key file is present on this host.
    KeptPresent,
    /// Kept by default; there is no key file on this host.
    KeptAbsent,
    /// Deleted under the opt-in.
    Removed,
    /// Opt-in requested, but there was no key file (passphrase-only host).
    AlreadyAbsent,
}

/// Result of deleting the owner key file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnerKeyRemoval {
    Removed,
    AlreadyAbsent,
}

pub(super) fn run(family: OsFamily, opts: UninstallOptions) -> Result<String, String> {
    refuse_owner_key_deletion_off_macos(family, opts)?;
    match family {
        OsFamily::Linux => uninstall_linux().map(|()| {
            "rustynet uninstalled from Linux: services stopped + disabled, unit files removed \
             (daemon-reload), binaries removed from /usr/local/bin, and all state — keys, systemd \
             credentials, and trust material under /var/lib/rustynet + /etc/rustynet — removed. \
             The `rustynetd` system user/group was left in place."
                .to_owned()
        }),
        OsFamily::Macos => uninstall_macos(opts),
        OsFamily::Windows => uninstall_windows().map(|()| {
            "rustynet uninstalled from Windows: SCM service removed and the install + state roots \
             purged (C:\\Program Files\\RustyNet and C:\\ProgramData\\RustyNet)."
                .to_owned()
        }),
        OsFamily::Unsupported => Err("unsupported operating system".to_owned()),
    }
}

/// Dry-run report for `--uninstall --dry-run`. Changes nothing. Lists what would
/// be removed AND what would be kept, so the owner sees the kept items first.
pub(super) fn dry_run_report(family: OsFamily, opts: UninstallOptions) -> Result<String, String> {
    refuse_owner_key_deletion_off_macos(family, opts)?;
    match family {
        OsFamily::Macos => {
            let present = owner_key_file_present();
            let outcome = planned_owner_key_outcome(opts, present);
            Ok(format!(
                "uninstall dry-run for macOS (nothing changed).\n\
                 Would remove: launchd jobs and plists, binaries in /usr/local/bin, \
                 keychain service(s) {services:?}, /usr/local/var/rustynet, \
                 /etc/rustynet/membership.owner.key.pub.\n\n{report}",
                services = macos_keychain_services_to_delete(opts),
                report = owner_key_report(outcome),
            ))
        }
        OsFamily::Linux => Ok("uninstall dry-run for Linux (nothing changed).\n\
             Would remove: systemd units, binaries in /usr/local/bin, and delete \
             /var/lib/rustynet, /run/rustynet and /etc/rustynet with no prompt. \
             /etc/rustynet holds the owner signing key, so the owner key is removed too. \
             This opt-in does not apply on Linux."
            .to_owned()),
        OsFamily::Windows => Ok("uninstall dry-run for Windows (nothing changed).\n\
             Would run the Windows uninstaller with -PurgeStateRoot -PurgeInstallRoot, \
             which removes C:\\ProgramData\\RustyNet (it holds the owner signing key)."
            .to_owned()),
        OsFamily::Unsupported => Err("unsupported operating system".to_owned()),
    }
}

/// `--delete-owner-key` is a macOS-only deliberate path. Refuse it elsewhere
/// before any mutation, so the flag can never imply a safety it does not give.
fn refuse_owner_key_deletion_off_macos(
    family: OsFamily,
    opts: UninstallOptions,
) -> Result<(), String> {
    if opts.delete_owner_key && !matches!(family, OsFamily::Macos) {
        return Err(
            "--delete-owner-key is macOS-only; nothing was changed. Linux and Windows uninstall \
             remove their state directories, which hold the owner signing key, without this \
             opt-in (unchanged by this patch)."
                .to_owned(),
        );
    }
    Ok(())
}

/// The macOS launchd bootout order (M2,
/// MacosHelperShutdownOrderingImplementationPlan_2026-09-02): the daemon
/// STRICTLY before the privileged helper, with the bounded daemon-exit wait
/// between the two — the daemon's shutdown rollback dials the helper socket,
/// so the helper must outlive the daemon.
const MACOS_UNINSTALL_BOOTOUT_ORDER: [&str; 2] = [
    "system/com.rustynet.daemon",
    "system/com.rustynet.privileged-helper",
];

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

fn uninstall_macos(opts: UninstallOptions) -> Result<String, String> {
    // Owner-key custody goes FIRST, before any service or file is touched. With
    // the opt-in, a failure to delete the key file returns here, so the
    // passphrase is never deleted while the key file is still present.
    let owner_key = match owner_key_file_removal_target(opts) {
        Some(path) => match remove_owner_key_file(Path::new(path))? {
            OwnerKeyRemoval::Removed => OwnerKeyOutcome::Removed,
            OwnerKeyRemoval::AlreadyAbsent => OwnerKeyOutcome::AlreadyAbsent,
        },
        None => planned_owner_key_outcome(opts, owner_key_file_present()),
    };

    for (index, label) in MACOS_UNINSTALL_BOOTOUT_ORDER.iter().enumerate() {
        let _ = command("launchctl").args(["bootout", label]).status();
        if index == 0 {
            // M2: the helper is booted out only after the daemon job has
            // actually exited (bounded wait below) — never back-to-back.
            wait_for_macos_daemon_exit();
        }
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
    // node-scoped, so match on the service and drain any duplicates). The
    // owner-key passphrase service is in this list only under the opt-in.
    for svc in macos_keychain_services_to_delete(opts) {
        for _ in 0..MACOS_KEYCHAIN_DRAIN_LIMIT {
            let deleted = command("security")
                .args(macos_keychain_delete_argv(svc))
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
    Ok(format!(
        "rustynet uninstalled from macOS: launchd jobs booted out + plists removed, disable \
         override cleared, binaries removed from /usr/local/bin, the WireGuard key passphrase \
         deleted from the System keychain, and state under /usr/local/var/rustynet + the trust \
         anchor removed. The `rustynetd` dscl user/group was left in place.\n\n{}",
        owner_key_report(owner_key)
    ))
}

/// Keychain services the macOS uninstall deletes, in order. The owner-key
/// passphrase service is included only under the explicit opt-in.
fn macos_keychain_services_to_delete(opts: UninstallOptions) -> Vec<&'static str> {
    let mut services = vec![MACOS_WG_KEY_PASSPHRASE_KEYCHAIN_SERVICE];
    if opts.delete_owner_key {
        services.push(crate::DEFAULT_MACOS_PASSPHRASE_KEYCHAIN_SERVICE);
    }
    services
}

/// The `security` argv that deletes one generic-password item (by service) from
/// the System keychain. Carries no secret.
fn macos_keychain_delete_argv(service: &str) -> Vec<String> {
    vec![
        "delete-generic-password".to_owned(),
        "-s".to_owned(),
        service.to_owned(),
        MACOS_SYSTEM_KEYCHAIN.to_owned(),
    ]
}

/// The owner-key file to delete. `None` by default: the key is kept.
fn owner_key_file_removal_target(opts: UninstallOptions) -> Option<&'static str> {
    opts.delete_owner_key
        .then_some(MACOS_OWNER_SIGNING_KEY_PATH)
}

/// Whether the macOS owner key file is present on this host. A dangling symlink
/// counts as present, so the report never understates what is kept.
fn owner_key_file_present() -> bool {
    std::fs::symlink_metadata(MACOS_OWNER_SIGNING_KEY_PATH).is_ok()
}

/// The owner-key outcome for a run that does not delete it (default) or that
/// would delete it (opt-in, dry-run), given whether the key file is present.
fn planned_owner_key_outcome(opts: UninstallOptions, key_present: bool) -> OwnerKeyOutcome {
    match (opts.delete_owner_key, key_present) {
        (false, true) => OwnerKeyOutcome::KeptPresent,
        (false, false) => OwnerKeyOutcome::KeptAbsent,
        (true, true) => OwnerKeyOutcome::Removed,
        (true, false) => OwnerKeyOutcome::AlreadyAbsent,
    }
}

/// Delete the owner key file. A missing file is already the desired state and is
/// not an error. Any other failure is returned, so the caller stops before it
/// touches the keychain passphrase.
fn remove_owner_key_file(path: &Path) -> Result<OwnerKeyRemoval, String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(OwnerKeyRemoval::Removed),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(OwnerKeyRemoval::AlreadyAbsent),
        Err(err) => Err(format!(
            "cannot delete the owner signing key {}: {err}. Uninstall stopped before any change; \
             the owner key and its passphrase are both kept.",
            path.display()
        )),
    }
}

/// The owner-key section of the uninstall report and dry-run. It states what was
/// kept or deleted, why, and how to delete it deliberately.
fn owner_key_report(outcome: OwnerKeyOutcome) -> String {
    let path = MACOS_OWNER_SIGNING_KEY_PATH;
    let service = crate::DEFAULT_MACOS_PASSPHRASE_KEYCHAIN_SERVICE;
    let manual = format!(
        "To delete them later, either reinstall rustynet and run `rustynet install --uninstall \
         --delete-owner-key --confirm-owner-key-deletion {OWNER_KEY_DELETION_CONFIRMATION}` \
         (irreversible), or remove them by hand: `sudo rm -f {path}` and `sudo security \
         delete-generic-password -s {service} {MACOS_SYSTEM_KEYCHAIN}` (repeat until it reports \
         the item was not found)."
    );
    let why = "Why kept: the key file cannot be opened without its passphrase, and the owner key \
               signs membership changes. Deleting only one of them locks the network out of \
               membership signing, and no product path rotates the owner key in place.";
    match outcome {
        OwnerKeyOutcome::KeptPresent => format!(
            "KEPT: owner signing key {path}, and the owner and trust signing passphrases in the \
             System keychain service `{service}`. {why} {manual}"
        ),
        OwnerKeyOutcome::KeptAbsent => format!(
            "KEPT: no owner signing key file was present at {path} on this host. The keychain \
             service `{service}` (owner and trust signing passphrases, if present) was kept. \
             {why} {manual}"
        ),
        OwnerKeyOutcome::Removed => format!(
            "DELETED (--delete-owner-key, typed confirmation given): owner signing key {path} and \
             every item in the System keychain service `{service}`. That service also holds the \
             trust signing passphrase, and uninstall cannot tell the accounts apart, so both are \
             gone. This cannot be undone without a backup."
        ),
        OwnerKeyOutcome::AlreadyAbsent => format!(
            "DELETED (--delete-owner-key): no owner signing key file was present at {path}. Every \
             item in the System keychain service `{service}` was deleted (owner and trust \
             signing passphrases)."
        ),
    }
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

/// Bounded wait (20 × 0.5 s = 10 s ≥ launchd's 5 s SIGTERM→SIGKILL ceiling
/// plus margin) for the daemon job to report exit, before the helper is booted
/// out (plan M2 / design §2 Option A poll): `launchctl bootout` returns at
/// SIGTERM delivery, not at job exit, and the daemon's shutdown rollback dials
/// the privileged-helper socket. Best-effort: expiry falls through to the
/// helper bootout exactly as the old bare-`sleep 1` did, so uninstall can
/// never hang.
fn wait_for_macos_daemon_exit() {
    for _ in 0..MACOS_DAEMON_EXIT_WAIT_POLLS {
        let exited = command("launchctl")
            .args(["print", "system/com.rustynet.daemon"])
            .output()
            .map(|out| {
                macos_daemon_job_reported_exit(
                    out.status.success(),
                    &String::from_utf8_lossy(&out.stdout),
                )
            })
            .unwrap_or(true);
        if exited {
            return;
        }
        std::thread::sleep(Duration::from_millis(MACOS_DAEMON_EXIT_WAIT_POLL_MILLIS));
    }
}

/// The uninstall daemon-exit wait's budget, pinned by test
/// ([`MACOS_DAEMON_EXIT_WAIT_POLLS`] ×
/// [`MACOS_DAEMON_EXIT_WAIT_POLL_MILLIS`]): 20 polls × 500 ms = 10 s, which
/// must stay at or above launchd's 5 s SIGTERM→SIGKILL ceiling so a
/// SIGTERMed daemon is fully dead before the helper job is booted out.
const MACOS_DAEMON_EXIT_WAIT_POLLS: usize = 20;
const MACOS_DAEMON_EXIT_WAIT_POLL_MILLIS: u64 = 500;

/// True when `launchctl print` says the daemon job has exited: the job is
/// absent (non-zero print exit) or present but reports no `pid = ` line.
fn macos_daemon_job_reported_exit(print_ok: bool, print_stdout: &str) -> bool {
    !print_ok || !print_stdout.contains("pid = ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_uninstall_boots_out_daemon_before_helper() {
        assert_eq!(
            MACOS_UNINSTALL_BOOTOUT_ORDER[0], "system/com.rustynet.daemon",
            "the daemon must be booted out first"
        );
        assert_eq!(
            MACOS_UNINSTALL_BOOTOUT_ORDER[1], "system/com.rustynet.privileged-helper",
            "the helper must be booted out second, after the daemon-exit wait \
             (uninstall_macos inserts wait_for_macos_daemon_exit between the two)"
        );
    }

    #[test]
    fn macos_daemon_job_reported_exit_matrix() {
        // Job present and still running a process: keep waiting.
        assert!(!macos_daemon_job_reported_exit(true, "\tpid = 512\n"));
        // Job absent (launchctl print exits non-zero): exited.
        assert!(macos_daemon_job_reported_exit(false, ""));
        // Job present but no pid line (loaded, not running): exited.
        assert!(macos_daemon_job_reported_exit(
            true,
            "\tstate = not running\n"
        ));
    }
    /// The daemon-exit wait budget is pinned SYMBOLICALLY (post-merge review
    /// §Tests e): 20 polls × 500 ms = 10 s, at or above launchd's 5 s
    /// SIGTERM→SIGKILL ceiling with margin. The pin is a COMPILE-TIME
    /// assertion, so the constants cannot quietly shrink below what the
    /// daemon needs to finish its rollback before the helper job is booted
    /// out — shrinking them fails this test's build outright.
    #[test]
    fn macos_daemon_exit_wait_budget_cannot_shrink_below_the_launchd_ceiling() {
        const BUDGET_MILLIS: u64 =
            MACOS_DAEMON_EXIT_WAIT_POLLS as u64 * MACOS_DAEMON_EXIT_WAIT_POLL_MILLIS;
        const _: () = assert!(
            BUDGET_MILLIS >= 10_000,
            "the uninstall daemon-exit wait must stay at 10 s (20 × 500 ms): launchd \
             SIGKILLs a SIGTERMed job after 5 s, and the daemon's rollback dials the \
             helper socket that the following bootout takes down"
        );
        const _: () = assert!(
            MACOS_DAEMON_EXIT_WAIT_POLLS >= 2,
            "a single poll is not a wait; the bounded poll loop must have headroom"
        );
        assert_eq!(
            std::time::Duration::from_millis(BUDGET_MILLIS),
            std::time::Duration::from_secs(10),
            "documented budget: 10 s"
        );
    }

    fn unique_temp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "rustynet-uninstall-test-{}-{tag}",
            std::process::id()
        ))
    }

    /// The macOS custody constants used by the uninstall are the same literals
    /// the rest of the crate uses (main.rs / rustynetd). Pinned here so drift
    /// fails a test instead of silently pointing uninstall at the wrong item.
    #[test]
    fn macos_custody_paths_and_services_match_crate_twins() {
        assert_eq!(
            MACOS_OWNER_SIGNING_KEY_PATH,
            "/usr/local/etc/rustynet/membership.owner.key"
        );
        assert_eq!(
            crate::DEFAULT_MACOS_PASSPHRASE_KEYCHAIN_SERVICE,
            "rustynet.signing_passphrase"
        );
        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                MACOS_OWNER_SIGNING_KEY_PATH,
                crate::DEFAULT_MEMBERSHIP_OWNER_SIGNING_KEY_PATH
            );
        }
    }

    /// (a) The default macOS uninstall never deletes the owner-key passphrase
    /// service, and no argv it would run names that service. The owner key file
    /// is not in the removal plan either. Fails on the pre-fix code, which
    /// deleted `rustynet.signing_passphrase` unconditionally.
    #[test]
    fn macos_default_uninstall_keeps_owner_key_passphrase_service() {
        let default = UninstallOptions::default();
        let services = macos_keychain_services_to_delete(default);
        assert!(
            !services.contains(&crate::DEFAULT_MACOS_PASSPHRASE_KEYCHAIN_SERVICE),
            "default macOS uninstall must not delete the owner-key passphrase service: {services:?}"
        );
        assert_eq!(services, vec![MACOS_WG_KEY_PASSPHRASE_KEYCHAIN_SERVICE]);
        for svc in &services {
            let argv = macos_keychain_delete_argv(svc);
            assert!(
                !argv.iter().any(|arg| arg == "rustynet.signing_passphrase"),
                "no default argv may name the owner-key passphrase service: {argv:?}"
            );
        }
        assert_eq!(
            owner_key_file_removal_target(default),
            None,
            "default macOS uninstall keeps the owner signing key file"
        );
    }

    /// (b) With the explicit opt-in, the deliberate path does what the report
    /// says: remove the key file, drain the passphrase service with the exact
    /// argv, and report DELETED. The dry-run shows the same plan.
    #[test]
    fn macos_opt_in_deletes_owner_key_file_and_passphrase_service() {
        let opt_in = UninstallOptions {
            delete_owner_key: true,
        };
        assert_eq!(
            owner_key_file_removal_target(opt_in),
            Some(MACOS_OWNER_SIGNING_KEY_PATH)
        );
        let services = macos_keychain_services_to_delete(opt_in);
        assert!(services.contains(&crate::DEFAULT_MACOS_PASSPHRASE_KEYCHAIN_SERVICE));
        assert!(services.contains(&MACOS_WG_KEY_PASSPHRASE_KEYCHAIN_SERVICE));
        let expected: Vec<String> = [
            "delete-generic-password",
            "-s",
            "rustynet.signing_passphrase",
            "/Library/Keychains/System.keychain",
        ]
        .iter()
        .map(|part| (*part).to_owned())
        .collect();
        assert_eq!(
            macos_keychain_delete_argv("rustynet.signing_passphrase"),
            expected
        );
        assert_eq!(
            planned_owner_key_outcome(opt_in, true),
            OwnerKeyOutcome::Removed
        );
        let report = owner_key_report(OwnerKeyOutcome::Removed);
        assert!(report.starts_with("DELETED"), "{report}");
        assert!(report.contains(MACOS_OWNER_SIGNING_KEY_PATH), "{report}");
        let dry = dry_run_report(OsFamily::Macos, opt_in).expect("macOS opt-in dry-run");
        assert!(dry.contains("DELETED"), "{dry}");
    }

    /// (c) A host with only the passphrase and no key file. Default: keep the
    /// passphrase, say the key is absent, no error. Opt-in: a missing key file is
    /// not an error, and the passphrase service is still deleted.
    #[test]
    fn macos_passphrase_only_host_uninstall_is_sensible() {
        let default = UninstallOptions::default();
        let kept = owner_key_report(planned_owner_key_outcome(default, false));
        assert!(
            kept.starts_with("KEPT:") && kept.contains("no owner signing key file"),
            "{kept}"
        );

        let opt_in = UninstallOptions {
            delete_owner_key: true,
        };
        assert_eq!(
            planned_owner_key_outcome(opt_in, false),
            OwnerKeyOutcome::AlreadyAbsent
        );
        assert!(
            macos_keychain_services_to_delete(opt_in)
                .contains(&crate::DEFAULT_MACOS_PASSPHRASE_KEYCHAIN_SERVICE)
        );
        let gone = owner_key_report(OwnerKeyOutcome::AlreadyAbsent);
        assert!(
            gone.starts_with("DELETED") && gone.contains("no owner signing key file"),
            "{gone}"
        );

        let missing = unique_temp_path("missing-key");
        assert_eq!(
            remove_owner_key_file(&missing),
            Ok(OwnerKeyRemoval::AlreadyAbsent),
            "a missing key file is already the desired state, not an error"
        );
    }

    /// The file step deletes a present key once, then reports it absent.
    #[test]
    fn remove_owner_key_file_deletes_a_present_key_once() {
        let path = unique_temp_path("present-key");
        std::fs::write(&path, b"test fixture, not key material").expect("write fixture");
        assert_eq!(remove_owner_key_file(&path), Ok(OwnerKeyRemoval::Removed));
        assert!(!path.exists(), "the key file must be gone after removal");
        assert_eq!(
            remove_owner_key_file(&path),
            Ok(OwnerKeyRemoval::AlreadyAbsent)
        );
    }

    /// `--delete-owner-key` is refused off macOS before any change is made.
    #[test]
    fn owner_key_deletion_is_refused_off_macos() {
        let opt_in = UninstallOptions {
            delete_owner_key: true,
        };
        assert!(refuse_owner_key_deletion_off_macos(OsFamily::Linux, opt_in).is_err());
        assert!(refuse_owner_key_deletion_off_macos(OsFamily::Windows, opt_in).is_err());
        assert!(refuse_owner_key_deletion_off_macos(OsFamily::Macos, opt_in).is_ok());
        assert!(
            refuse_owner_key_deletion_off_macos(OsFamily::Linux, UninstallOptions::default())
                .is_ok()
        );
    }

    /// The dry-run lists the kept owner key and passphrase by default. Either
    /// variant (key present or absent on this host) starts with `KEPT:`, so the
    /// assertion does not depend on the machine's filesystem.
    #[test]
    fn dry_run_report_shows_kept_owner_key_by_default() {
        let dry =
            dry_run_report(OsFamily::Macos, UninstallOptions::default()).expect("macOS dry-run");
        assert!(dry.contains("KEPT:"), "{dry}");
        assert!(!dry.contains("DELETED"), "{dry}");
        assert!(dry.contains(MACOS_OWNER_SIGNING_KEY_PATH), "{dry}");
    }
}
