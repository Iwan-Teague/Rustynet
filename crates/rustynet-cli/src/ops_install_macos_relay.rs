//! Install/uninstall the `com.rustynet.relay` launchd service on macOS.
//!
//! This mirrors `ops_install_systemd_relay.rs` for the relay/anchor role
//! transition executor. It is intentionally narrow: copy the reviewed plist,
//! drive `launchctl` with argv-only calls, and return a structured report for
//! operator output and role-transition audit logs.

use std::path::{Path, PathBuf};
use std::process::Command;

use rustynetd::macos_service_hardening::{
    REVIEWED_MACOS_RELAY_LAUNCHD_LABEL, REVIEWED_MACOS_RELAY_LAUNCHD_PLIST_PATH,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchdRelayMode {
    InstallAndBootstrap,
    DisableAndRemove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallMacosRelayConfig {
    pub mode: LaunchdRelayMode,
    pub source_plist_path: PathBuf,
    pub dest_plist_path: PathBuf,
    pub label: String,
    pub domain: String,
    pub dry_run: bool,
}

impl InstallMacosRelayConfig {
    pub fn default_install() -> Self {
        Self {
            mode: LaunchdRelayMode::InstallAndBootstrap,
            source_plist_path: PathBuf::from("scripts/launchd/com.rustynet.relay.plist"),
            dest_plist_path: PathBuf::from(REVIEWED_MACOS_RELAY_LAUNCHD_PLIST_PATH),
            label: REVIEWED_MACOS_RELAY_LAUNCHD_LABEL.to_owned(),
            domain: "system".to_owned(),
            dry_run: false,
        }
    }

    pub fn default_uninstall() -> Self {
        Self {
            mode: LaunchdRelayMode::DisableAndRemove,
            source_plist_path: PathBuf::from("scripts/launchd/com.rustynet.relay.plist"),
            dest_plist_path: PathBuf::from(REVIEWED_MACOS_RELAY_LAUNCHD_PLIST_PATH),
            label: REVIEWED_MACOS_RELAY_LAUNCHD_LABEL.to_owned(),
            domain: "system".to_owned(),
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallMacosRelayReport {
    pub mode: LaunchdRelayMode,
    pub dest_plist_path: PathBuf,
    pub label: String,
    pub domain: String,
    pub steps: Vec<String>,
    pub dry_run: bool,
}

impl InstallMacosRelayReport {
    pub fn summary(&self) -> String {
        let dry_tag = if self.dry_run { " (dry-run)" } else { "" };
        let mode_tag = match self.mode {
            LaunchdRelayMode::InstallAndBootstrap => "install+bootstrap",
            LaunchdRelayMode::DisableAndRemove => "bootout+remove",
        };
        let mut out = format!(
            "rustynet-relay launchd service: {mode_tag}{dry_tag} at {} ({}/{})\n",
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

pub fn execute_install_macos_relay(
    config: InstallMacosRelayConfig,
) -> Result<InstallMacosRelayReport, String> {
    validate_launchd_target(&config)?;
    let mut steps = Vec::new();

    match config.mode {
        LaunchdRelayMode::InstallAndBootstrap => {
            let plist_body = read_source_plist(&config.source_plist_path, config.dry_run)?;
            steps.push(format!(
                "read source plist ({} bytes) from {}",
                plist_body.len(),
                config.source_plist_path.display()
            ));

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
        LaunchdRelayMode::DisableAndRemove => {
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

    Ok(InstallMacosRelayReport {
        mode: config.mode,
        dest_plist_path: config.dest_plist_path,
        label: config.label,
        domain: config.domain,
        steps,
        dry_run: config.dry_run,
    })
}

pub fn install(dry_run: bool) -> Result<InstallMacosRelayReport, String> {
    let mut config = InstallMacosRelayConfig::default_install();
    config.dry_run = dry_run;
    execute_install_macos_relay(config)
}

pub fn uninstall(dry_run: bool) -> Result<InstallMacosRelayReport, String> {
    let mut config = InstallMacosRelayConfig::default_uninstall();
    config.dry_run = dry_run;
    execute_install_macos_relay(config)
}

fn validate_launchd_target(config: &InstallMacosRelayConfig) -> Result<(), String> {
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

fn domain_target(config: &InstallMacosRelayConfig) -> String {
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
            .unwrap_or("com.rustynet.relay.plist")
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

    #[test]
    fn dry_run_install_reports_planned_launchctl_steps() {
        let dir = std::env::temp_dir().join(format!(
            "rustynet-macos-relay-install-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("com.rustynet.relay.plist");
        std::fs::write(&source, "<plist version=\"1.0\"><dict/></plist>\n").unwrap();
        let dest = dir.join("LaunchDaemons").join("com.rustynet.relay.plist");
        let cfg = InstallMacosRelayConfig {
            mode: LaunchdRelayMode::InstallAndBootstrap,
            source_plist_path: source,
            dest_plist_path: dest.clone(),
            label: "com.rustynet.relay".to_owned(),
            domain: "system".to_owned(),
            dry_run: true,
        };

        let report = execute_install_macos_relay(cfg).unwrap();
        assert_eq!(report.mode, LaunchdRelayMode::InstallAndBootstrap);
        assert!(report.dry_run);
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
        assert_eq!(report.mode, LaunchdRelayMode::DisableAndRemove);
        assert!(
            report
                .steps
                .iter()
                .any(|step| step.contains("would run: launchctl bootout system/com.rustynet.relay"))
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
        let report = install(true).expect("dry-run install should not require host mutation");
        assert_eq!(report.mode, LaunchdRelayMode::InstallAndBootstrap);
        assert!(report.dry_run);
        assert_eq!(report.label, "com.rustynet.relay");
        assert_eq!(report.domain, "system");
        assert!(
            report
                .steps
                .iter()
                .any(|step| step.contains("would run: launchctl bootstrap system"))
        );
    }

    #[test]
    fn uninstall_wrapper_uses_launchd_remove_shape_in_dry_run() {
        let report = uninstall(true).expect("dry-run uninstall should not require host mutation");
        assert_eq!(report.mode, LaunchdRelayMode::DisableAndRemove);
        assert!(report.dry_run);
        assert!(
            report
                .steps
                .iter()
                .any(|step| step.contains("would run: launchctl bootout system/com.rustynet.relay"))
        );
    }

    #[test]
    fn summary_includes_dry_run_tag() {
        let report = InstallMacosRelayReport {
            mode: LaunchdRelayMode::InstallAndBootstrap,
            dest_plist_path: PathBuf::from("/Library/LaunchDaemons/com.rustynet.relay.plist"),
            label: "com.rustynet.relay".to_owned(),
            domain: "system".to_owned(),
            steps: vec!["planned".to_owned()],
            dry_run: true,
        };
        let summary = report.summary();
        assert!(summary.contains("dry-run"));
        assert!(summary.contains("install+bootstrap"));
        assert!(summary.contains("system/com.rustynet.relay"));
    }

    #[test]
    fn defaults_target_launch_daemons() {
        let cfg = InstallMacosRelayConfig::default_install();
        assert_eq!(cfg.mode, LaunchdRelayMode::InstallAndBootstrap);
        assert_eq!(
            cfg.dest_plist_path,
            PathBuf::from("/Library/LaunchDaemons/com.rustynet.relay.plist")
        );
        assert_eq!(
            cfg.source_plist_path,
            PathBuf::from("scripts/launchd/com.rustynet.relay.plist")
        );
        assert_eq!(cfg.label, "com.rustynet.relay");
        assert_eq!(cfg.domain, "system");
        assert!(!cfg.dry_run);
    }

    #[test]
    fn label_validator_rejects_shell_metacharacters() {
        let mut cfg = InstallMacosRelayConfig {
            dry_run: true,
            ..InstallMacosRelayConfig::default_install()
        };
        cfg.label = "com.rustynet.relay;rm".to_owned();
        let err = execute_install_macos_relay(cfg).expect_err("bad label must fail closed");
        assert!(err.contains("reverse-DNS"));
    }

    #[test]
    fn real_write_uses_atomic_rename_and_0644_mode() {
        let dir =
            std::env::temp_dir().join(format!("rustynet-macos-relay-write-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("com.rustynet.relay.plist");
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
