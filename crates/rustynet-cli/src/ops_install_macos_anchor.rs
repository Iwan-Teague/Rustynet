//! Install/uninstall the `com.rustynet.anchor` launchd service on macOS.
//!
//! This mirrors `ops_install_macos_relay.rs` for the anchor role
//! transition executor. It is intentionally narrow: validate the source
//! plist against the reviewed hardened shape, copy it into place, drive
//! `launchctl` with argv-only calls, and return a structured report for
//! operator output and role-transition audit logs.
//!
//! macOS parity for `scripts/systemd/rustynetd-anchor.service`. The
//! anchor profile enables the loopback bundle-pull listener so a peer can
//! pull the signed membership snapshot byte-for-byte after presenting the
//! authority token. The listener's security controls (loopback-only bind
//! unless `--anchor-bundle-pull-allow-lan`, >=32 printable-ASCII token,
//! fail-closed when the token is missing) are enforced in `daemon.rs`;
//! this installer additionally refuses to deploy a plist whose reviewed
//! hardened shape has drifted (verify-before-serve), so a weakened plist
//! never reaches `/Library/LaunchDaemons`.

use std::path::{Path, PathBuf};
use std::process::Command;

use rustynetd::macos_service_hardening::{
    REVIEWED_MACOS_ANCHOR_LAUNCHD_LABEL, REVIEWED_MACOS_ANCHOR_LAUNCHD_PLIST_PATH,
    REVIEWED_MACOS_ANCHOR_SOURCE_PLIST_PATH, build_macos_anchor_service_hardening_report,
    parse_plist_scalars, parse_plist_string_array, parse_plist_string_dict,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchdAnchorMode {
    InstallAndBootstrap,
    DisableAndRemove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallMacosAnchorConfig {
    pub mode: LaunchdAnchorMode,
    pub source_plist_path: PathBuf,
    pub dest_plist_path: PathBuf,
    pub label: String,
    pub domain: String,
    pub dry_run: bool,
}

impl InstallMacosAnchorConfig {
    pub fn default_install() -> Self {
        Self {
            mode: LaunchdAnchorMode::InstallAndBootstrap,
            source_plist_path: PathBuf::from(REVIEWED_MACOS_ANCHOR_SOURCE_PLIST_PATH),
            dest_plist_path: PathBuf::from(REVIEWED_MACOS_ANCHOR_LAUNCHD_PLIST_PATH),
            label: REVIEWED_MACOS_ANCHOR_LAUNCHD_LABEL.to_owned(),
            domain: "system".to_owned(),
            dry_run: false,
        }
    }

    pub fn default_uninstall() -> Self {
        Self {
            mode: LaunchdAnchorMode::DisableAndRemove,
            source_plist_path: PathBuf::from(REVIEWED_MACOS_ANCHOR_SOURCE_PLIST_PATH),
            dest_plist_path: PathBuf::from(REVIEWED_MACOS_ANCHOR_LAUNCHD_PLIST_PATH),
            label: REVIEWED_MACOS_ANCHOR_LAUNCHD_LABEL.to_owned(),
            domain: "system".to_owned(),
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallMacosAnchorReport {
    pub mode: LaunchdAnchorMode,
    pub dest_plist_path: PathBuf,
    pub label: String,
    pub domain: String,
    pub steps: Vec<String>,
    pub dry_run: bool,
}

impl InstallMacosAnchorReport {
    pub fn summary(&self) -> String {
        let dry_tag = if self.dry_run { " (dry-run)" } else { "" };
        let mode_tag = match self.mode {
            LaunchdAnchorMode::InstallAndBootstrap => "install+bootstrap",
            LaunchdAnchorMode::DisableAndRemove => "bootout+remove",
        };
        let mut out = format!(
            "rustynet-anchor launchd service: {mode_tag}{dry_tag} at {} ({}/{})\n",
            self.dest_plist_path.display(),
            self.domain,
            self.label
        );
        for step in &self.steps {
            out.push_str(&format!("  - {step}\n"));
        }
        out
    }
}

pub fn execute_install_macos_anchor(
    config: InstallMacosAnchorConfig,
) -> Result<InstallMacosAnchorReport, String> {
    validate_launchd_target(&config)?;
    let mut steps = Vec::new();

    match config.mode {
        LaunchdAnchorMode::InstallAndBootstrap => {
            let plist_body = read_source_plist(&config.source_plist_path, config.dry_run)?;
            steps.push(format!(
                "read source plist ({} bytes) from {}",
                plist_body.len(),
                config.source_plist_path.display()
            ));

            // Verify-before-serve: refuse to deploy a plist whose
            // reviewed hardened shape has drifted (wrong loopback addr,
            // missing token-path flag, allow-lan flipped to true, weakened
            // hardening keys, …). On a dry-run with no source plist the
            // body is empty; skip the shape check then (there is nothing
            // to validate and nothing will be written).
            if !plist_body.is_empty() {
                validate_reviewed_anchor_plist_shape(&plist_body)?;
                steps.push(
                    "validated source plist matches reviewed anchor hardened shape \
                     (loopback bundle-pull addr, token-path, allow-lan=false, hardening keys)"
                        .to_owned(),
                );
            } else {
                steps.push(
                    "dry-run: source plist absent; skipped reviewed-shape validation (no write)"
                        .to_owned(),
                );
            }

            if !config.dry_run {
                write_plist_atomic(&config.dest_plist_path, &plist_body)?;
            }
            steps.push(format!(
                "{} plist at {}",
                if config.dry_run {
                    "would write"
                } else {
                    "wrote"
                },
                config.dest_plist_path.display()
            ));

            run_launchctl(
                &["bootout", &domain_target(&config)],
                config.dry_run,
                &mut steps,
                true,
            )?;
            let dest = config.dest_plist_path.to_string_lossy().into_owned();
            run_launchctl(
                &["bootstrap", config.domain.as_str(), dest.as_str()],
                config.dry_run,
                &mut steps,
                false,
            )?;
            run_launchctl(
                &["kickstart", "-k", &domain_target(&config)],
                config.dry_run,
                &mut steps,
                false,
            )?;
        }
        LaunchdAnchorMode::DisableAndRemove => {
            run_launchctl(
                &["bootout", &domain_target(&config)],
                config.dry_run,
                &mut steps,
                true,
            )?;
            if !config.dry_run && config.dest_plist_path.exists() {
                std::fs::remove_file(&config.dest_plist_path).map_err(|err| {
                    format!("remove {} failed: {err}", config.dest_plist_path.display())
                })?;
                steps.push(format!("removed {}", config.dest_plist_path.display()));
            } else if config.dry_run {
                steps.push(format!("would remove {}", config.dest_plist_path.display()));
            } else {
                steps.push(format!(
                    "{} already absent (no-op)",
                    config.dest_plist_path.display()
                ));
            }
        }
    }

    Ok(InstallMacosAnchorReport {
        mode: config.mode,
        dest_plist_path: config.dest_plist_path,
        label: config.label,
        domain: config.domain,
        steps,
        dry_run: config.dry_run,
    })
}

/// Thin install/uninstall wrappers mirroring `ops_install_macos_relay`.
/// The relay siblings are reached through the role-transition
/// `ConcreteAction::DeployRelayService` path; the anchor profile has no
/// dedicated role-transition action wired yet (that is a follow-on
/// increment), so these wrappers are exercised by the unit tests and the
/// `ops install-macos-anchor` verb path uses `execute_install_macos_anchor`
/// directly. Kept as the canonical installer API so the future
/// role-transition wiring drops in without re-deriving the default
/// config shape.
#[cfg_attr(not(test), allow(dead_code))]
pub fn install(dry_run: bool) -> Result<InstallMacosAnchorReport, String> {
    let mut config = InstallMacosAnchorConfig::default_install();
    config.dry_run = dry_run;
    execute_install_macos_anchor(config)
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn uninstall(dry_run: bool) -> Result<InstallMacosAnchorReport, String> {
    let mut config = InstallMacosAnchorConfig::default_uninstall();
    config.dry_run = dry_run;
    execute_install_macos_anchor(config)
}

/// Verify-before-serve gate: parse the source plist and assert its
/// reviewed hardened shape via the shared `macos_service_hardening`
/// evaluators. Fails closed (returns the joined drift reasons) on any
/// drift, so a plist with a weakened bundle-pull posture (LAN bind,
/// missing token-path, allow-lan=true) or weakened hardening keys is
/// never written to `/Library/LaunchDaemons`.
fn validate_reviewed_anchor_plist_shape(plist_body: &str) -> Result<(), String> {
    let observed = parse_plist_scalars(plist_body);
    let program_arguments = parse_plist_string_array(plist_body, "ProgramArguments");
    let environment = parse_plist_string_dict(plist_body, "EnvironmentVariables");
    let report = build_macos_anchor_service_hardening_report(
        true,
        None,
        observed,
        program_arguments,
        environment,
    );
    if report.overall_ok {
        return Ok(());
    }
    Err(format!(
        "source anchor plist failed reviewed hardened-shape validation: {}",
        report.drift_reasons.join("; ")
    ))
}

fn validate_launchd_target(config: &InstallMacosAnchorConfig) -> Result<(), String> {
    validate_label(&config.label)?;
    validate_domain(&config.domain)?;
    if !config.dry_run && !config.dest_plist_path.is_absolute() {
        return Err(format!(
            "launchd destination must be absolute: {}",
            config.dest_plist_path.display()
        ));
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<(), String> {
    if label.is_empty()
        || !label.contains('.')
        || !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err("launchd label must be a reverse-DNS ASCII identifier".to_owned());
    }
    Ok(())
}

fn validate_domain(domain: &str) -> Result<(), String> {
    if domain == "system" {
        return Ok(());
    }
    if let Some(uid) = domain.strip_prefix("gui/")
        && !uid.is_empty()
        && uid.bytes().all(|b| b.is_ascii_digit())
    {
        return Ok(());
    }
    Err("launchd domain must be `system` or `gui/<uid>`".to_owned())
}

fn domain_target(config: &InstallMacosAnchorConfig) -> String {
    format!("{}/{}", config.domain, config.label)
}

fn read_source_plist(path: &Path, dry_run: bool) -> Result<String, String> {
    if dry_run && !path.exists() {
        return Ok(String::new());
    }
    std::fs::read_to_string(path)
        .map_err(|err| format!("read source plist at {} failed: {err}", path.display()))
}

fn write_plist_atomic(dest: &Path, body: &str) -> Result<(), String> {
    let parent = dest
        .parent()
        .ok_or_else(|| format!("destination {} has no parent directory", dest.display()))?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        dest.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("com.rustynet.anchor.plist")
    ));
    std::fs::write(&tmp, body.as_bytes())
        .map_err(|err| format!("write {} failed: {err}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644));
    }
    std::fs::rename(&tmp, dest).map_err(|err| {
        format!(
            "rename {} -> {} failed: {err}",
            tmp.display(),
            dest.display()
        )
    })?;
    Ok(())
}

fn run_launchctl(
    args: &[&str],
    dry_run: bool,
    steps: &mut Vec<String>,
    allow_failure: bool,
) -> Result<(), String> {
    if dry_run {
        steps.push(format!("would run: launchctl {}", args.join(" ")));
        return Ok(());
    }
    let output = Command::new("launchctl")
        .args(args)
        .output()
        .map_err(|err| format!("launchctl exec failed: {err}"))?;
    let summary = format!(
        "launchctl {} (exit={})",
        args.join(" "),
        output.status.code().unwrap_or(-1)
    );
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if allow_failure {
            steps.push(format!("{summary}; ignored: {}", stderr.trim()));
            return Ok(());
        }
        return Err(format!("{summary}: {stderr}"));
    }
    steps.push(summary);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal but reviewed-shape-valid anchor plist body for the
    /// shape-validation tests. Mirrors scripts/launchd/com.rustynet.anchor.plist.
    const REVIEWED_ANCHOR_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.rustynet.anchor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/rustynetd</string>
        <string>daemon</string>
        <string>--wg-private-key</string>
        <string>/usr/local/var/rustynet/keys/wireguard.key</string>
        <string>--wg-encrypted-private-key</string>
        <string>/usr/local/var/rustynet/keys/wireguard.key.enc</string>
        <string>--wg-key-passphrase</string>
        <string>/usr/local/var/rustynet/bootstrap/wireguard.passphrase</string>
        <string>--wg-public-key</string>
        <string>/usr/local/var/rustynet/keys/wireguard.pub</string>
        <string>--backend</string>
        <string>macos-wireguard-userspace-shared</string>
        <string>--anchor-bundle-pull-addr</string>
        <string>127.0.0.1:51822</string>
        <string>--anchor-bundle-pull-token-path</string>
        <string>/usr/local/var/rustynet/anchor-bundle-pull.token</string>
        <string>--anchor-bundle-pull-allow-lan</string>
        <string>false</string>
    </array>
    <key>UserName</key>
    <string>rustynetd</string>
    <key>GroupName</key>
    <string>rustynetd</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>AbandonProcessGroup</key>
    <false/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT</key>
        <string>wg-passphrase-daemon-local</string>
        <key>RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE</key>
        <string>net.rustynet.wg-key-passphrase</string>
        <key>RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH</key>
        <string>/usr/local/var/rustynet/bootstrap/wireguard.passphrase</string>
        <key>RUSTYNET_ANCHOR_BUNDLE_PULL_ADDR</key>
        <string>127.0.0.1:51822</string>
        <key>RUSTYNET_ANCHOR_BUNDLE_PULL_TOKEN_PATH</key>
        <string>/usr/local/var/rustynet/anchor-bundle-pull.token</string>
        <key>RUSTYNET_ANCHOR_BUNDLE_PULL_ALLOW_LAN</key>
        <string>false</string>
    </dict>
</dict>
</plist>"#;

    #[test]
    fn dry_run_install_reports_planned_launchctl_steps() {
        let dir = std::env::temp_dir().join(format!(
            "rustynet-macos-anchor-install-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("com.rustynet.anchor.plist");
        std::fs::write(&source, REVIEWED_ANCHOR_PLIST).unwrap();
        let dest = dir.join("LaunchDaemons").join("com.rustynet.anchor.plist");
        let cfg = InstallMacosAnchorConfig {
            mode: LaunchdAnchorMode::InstallAndBootstrap,
            source_plist_path: source,
            dest_plist_path: dest.clone(),
            label: "com.rustynet.anchor".to_owned(),
            domain: "system".to_owned(),
            dry_run: true,
        };

        let report = execute_install_macos_anchor(cfg).unwrap();
        assert_eq!(report.mode, LaunchdAnchorMode::InstallAndBootstrap);
        assert!(report.dry_run);
        assert!(
            report
                .steps
                .iter()
                .any(|step| step.contains("validated source plist matches reviewed anchor"))
        );
        assert!(report.steps.iter().any(|step| step.contains("would write")));
        assert!(
            report
                .steps
                .iter()
                .any(|step| step.contains("would run: launchctl bootstrap system"))
        );
        assert!(
            report
                .steps
                .iter()
                .any(|step| step.contains("would run: launchctl kickstart -k"))
        );
        assert!(!dest.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dry_run_uninstall_reports_planned_bootout() {
        let report = uninstall(true).unwrap();
        assert_eq!(report.mode, LaunchdAnchorMode::DisableAndRemove);
        assert!(
            report.steps.iter().any(
                |step| step.contains("would run: launchctl bootout system/com.rustynet.anchor")
            )
        );
        assert!(
            report
                .steps
                .iter()
                .any(|step| step.contains("would remove"))
        );
    }

    #[test]
    fn install_wrapper_uses_launchd_install_shape_in_dry_run() {
        // cargo runs unit tests with cwd = crate manifest dir, so the
        // default cwd-relative source plist path is not readable here.
        // Assert the wrapper SHAPE (mode/label/domain/launchctl steps)
        // independent of whether the repo plist resolves.
        let report = install(true).expect("dry-run install should not require host mutation");
        assert_eq!(report.mode, LaunchdAnchorMode::InstallAndBootstrap);
        assert!(report.dry_run);
        assert_eq!(report.label, "com.rustynet.anchor");
        assert_eq!(report.domain, "system");
        assert!(
            report
                .steps
                .iter()
                .any(|step| step.contains("would run: launchctl bootstrap system"))
        );
    }

    #[test]
    fn shipped_repo_plist_passes_reviewed_shape_gate() {
        // The reviewed-shape gate must accept the ACTUAL shipped plist at
        // scripts/launchd/com.rustynet.anchor.plist. Resolve it via
        // CARGO_MANIFEST_DIR (crates/rustynet-cli) -> repo root so the
        // test is independent of the cargo test cwd. A drift in the
        // shipped plist (weakened loopback/token/allow-lan posture or
        // hardening keys) surfaces here.
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("crate dir has repo-root grandparent")
            .to_path_buf();
        let plist = repo_root.join("scripts/launchd/com.rustynet.anchor.plist");
        let body = std::fs::read_to_string(&plist)
            .unwrap_or_else(|err| panic!("read shipped plist {} failed: {err}", plist.display()));
        validate_reviewed_anchor_plist_shape(&body)
            .expect("shipped anchor plist must pass the reviewed hardened-shape gate");
    }

    #[test]
    fn uninstall_wrapper_uses_launchd_remove_shape_in_dry_run() {
        let report = uninstall(true).expect("dry-run uninstall should not require host mutation");
        assert_eq!(report.mode, LaunchdAnchorMode::DisableAndRemove);
        assert!(report.dry_run);
        assert!(
            report.steps.iter().any(
                |step| step.contains("would run: launchctl bootout system/com.rustynet.anchor")
            )
        );
    }

    #[test]
    fn summary_includes_dry_run_tag() {
        let report = InstallMacosAnchorReport {
            mode: LaunchdAnchorMode::InstallAndBootstrap,
            dest_plist_path: PathBuf::from("/Library/LaunchDaemons/com.rustynet.anchor.plist"),
            label: "com.rustynet.anchor".to_owned(),
            domain: "system".to_owned(),
            steps: vec!["planned".to_owned()],
            dry_run: true,
        };
        let summary = report.summary();
        assert!(summary.contains("dry-run"));
        assert!(summary.contains("install+bootstrap"));
        assert!(summary.contains("system/com.rustynet.anchor"));
    }

    #[test]
    fn defaults_target_launch_daemons() {
        let cfg = InstallMacosAnchorConfig::default_install();
        assert_eq!(cfg.mode, LaunchdAnchorMode::InstallAndBootstrap);
        assert_eq!(
            cfg.dest_plist_path,
            PathBuf::from("/Library/LaunchDaemons/com.rustynet.anchor.plist")
        );
        assert_eq!(
            cfg.source_plist_path,
            PathBuf::from("scripts/launchd/com.rustynet.anchor.plist")
        );
        assert_eq!(cfg.label, "com.rustynet.anchor");
        assert_eq!(cfg.domain, "system");
        assert!(!cfg.dry_run);
    }

    #[test]
    fn label_validator_rejects_shell_metacharacters() {
        let mut cfg = InstallMacosAnchorConfig {
            dry_run: true,
            ..InstallMacosAnchorConfig::default_install()
        };
        cfg.label = "com.rustynet.anchor;rm".to_owned();
        let err = execute_install_macos_anchor(cfg).expect_err("bad label must fail closed");
        assert!(err.contains("reverse-DNS"));
    }

    #[test]
    fn reviewed_shape_gate_rejects_allow_lan_true_plist() {
        // A plist whose bundle-pull posture has been weakened (allow-lan
        // flipped to true) must be refused before any launchctl call —
        // the verify-before-serve / default-deny control.
        let tampered = REVIEWED_ANCHOR_PLIST.replace(
            "<key>RUSTYNET_ANCHOR_BUNDLE_PULL_ALLOW_LAN</key>\n        <string>false</string>",
            "<key>RUSTYNET_ANCHOR_BUNDLE_PULL_ALLOW_LAN</key>\n        <string>true</string>",
        );
        // Also flip the ProgramArguments allow-lan so the report is
        // unambiguously the weakened posture.
        let tampered = tampered.replace(
            "<string>--anchor-bundle-pull-allow-lan</string>\n        <string>false</string>",
            "<string>--anchor-bundle-pull-allow-lan</string>\n        <string>true</string>",
        );
        let err = validate_reviewed_anchor_plist_shape(&tampered)
            .expect_err("allow-lan=true plist must be refused");
        assert!(
            err.contains("allow-lan") || err.contains("ALLOW_LAN"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn reviewed_shape_gate_rejects_missing_token_path_plist() {
        // Drop the token-path flag from ProgramArguments — fail-closed:
        // a plist without the token-path must not deploy.
        let tampered = REVIEWED_ANCHOR_PLIST.replace(
            "<string>--anchor-bundle-pull-token-path</string>\n        <string>/usr/local/var/rustynet/anchor-bundle-pull.token</string>\n        ",
            "",
        );
        let err = validate_reviewed_anchor_plist_shape(&tampered)
            .expect_err("missing token-path plist must be refused");
        assert!(
            err.contains("token-path") || err.contains("TOKEN_PATH"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn install_refuses_to_write_tampered_plist() {
        // End-to-end: a tampered source plist must abort install BEFORE
        // the destination plist is written (even in non-dry-run flow we
        // never reach write because the gate fails first). Use dry_run
        // for the bootout/bootstrap planning but a real (tampered)
        // source on disk so read_source_plist returns the body.
        let dir = std::env::temp_dir().join(format!(
            "rustynet-macos-anchor-tamper-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("com.rustynet.anchor.plist");
        let tampered = REVIEWED_ANCHOR_PLIST.replace("127.0.0.1:51822", "0.0.0.0:51822");
        std::fs::write(&source, tampered).unwrap();
        let dest = dir.join("LaunchDaemons").join("com.rustynet.anchor.plist");
        let cfg = InstallMacosAnchorConfig {
            mode: LaunchdAnchorMode::InstallAndBootstrap,
            source_plist_path: source,
            dest_plist_path: dest.clone(),
            label: "com.rustynet.anchor".to_owned(),
            domain: "system".to_owned(),
            dry_run: true,
        };
        let err = execute_install_macos_anchor(cfg)
            .expect_err("tampered loopback addr must fail the reviewed-shape gate");
        assert!(
            err.contains("reviewed hardened-shape validation"),
            "unexpected error: {err}"
        );
        assert!(!dest.exists(), "tampered plist must not be written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn real_write_uses_atomic_rename_and_0644_mode() {
        let dir = std::env::temp_dir().join(format!(
            "rustynet-macos-anchor-write-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("com.rustynet.anchor.plist");
        let body = "<plist version=\"1.0\"><dict/></plist>\n";

        write_plist_atomic(&dest, body).expect("write_plist_atomic");
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), body);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
