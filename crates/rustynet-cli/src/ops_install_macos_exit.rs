//! Track B Step 3 (B1.4) — install/uninstall the `com.rustynet.exit`
//! launchd service on macOS.
//!
//! Mirrors `ops_install_macos_relay.rs` for the exit-mode preflight
//! one-shot: lay down a reviewed plist, drive `launchctl` with argv-
//! only calls, and return a structured report for operator output and
//! role-transition audit logs. The runtime exit-serving lifecycle (pf
//! NAT activate, default-route advertise, DNS killswitch arm) stays
//! owned by `rustynetd`'s launchd unit; this installer is install-time
//! evidence the host is prepared for the `exit` preset.

use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchdExitMode {
    InstallAndBootstrap,
    DisableAndRemove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallMacosExitConfig {
    pub mode: LaunchdExitMode,
    pub source_plist_path: PathBuf,
    pub dest_plist_path: PathBuf,
    pub label: String,
    pub domain: String,
    pub dry_run: bool,
}

impl InstallMacosExitConfig {
    pub fn default_install() -> Self {
        Self {
            mode: LaunchdExitMode::InstallAndBootstrap,
            source_plist_path: PathBuf::from("scripts/launchd/com.rustynet.exit.plist"),
            dest_plist_path: PathBuf::from("/Library/LaunchDaemons/com.rustynet.exit.plist"),
            label: "com.rustynet.exit".to_owned(),
            domain: "system".to_owned(),
            dry_run: false,
        }
    }

    pub fn default_uninstall() -> Self {
        Self {
            mode: LaunchdExitMode::DisableAndRemove,
            source_plist_path: PathBuf::from("scripts/launchd/com.rustynet.exit.plist"),
            dest_plist_path: PathBuf::from("/Library/LaunchDaemons/com.rustynet.exit.plist"),
            label: "com.rustynet.exit".to_owned(),
            domain: "system".to_owned(),
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallMacosExitReport {
    pub mode: LaunchdExitMode,
    pub dest_plist_path: PathBuf,
    pub label: String,
    pub domain: String,
    pub steps: Vec<String>,
    pub dry_run: bool,
}

impl InstallMacosExitReport {
    pub fn summary(&self) -> String {
        let dry_tag = if self.dry_run { " (dry-run)" } else { "" };
        let mode_tag = match self.mode {
            LaunchdExitMode::InstallAndBootstrap => "install+bootstrap",
            LaunchdExitMode::DisableAndRemove => "bootout+remove",
        };
        let mut out = format!(
            "rustynet-exit launchd service: {mode_tag}{dry_tag} at {} ({}/{})\n",
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

pub fn execute_install_macos_exit(
    config: InstallMacosExitConfig,
) -> Result<InstallMacosExitReport, String> {
    validate_launchd_target(&config)?;
    let mut steps = Vec::new();

    match config.mode {
        LaunchdExitMode::InstallAndBootstrap => {
            let plist_body = read_source_plist(&config.source_plist_path)?;
            let source_desc = if config.source_plist_path.exists() {
                config.source_plist_path.display().to_string()
            } else {
                format!(
                    "embedded reviewed plist ({} not present on node)",
                    config.source_plist_path.display()
                )
            };
            steps.push(format!(
                "read source plist ({} bytes) from {source_desc}",
                plist_body.len(),
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
        LaunchdExitMode::DisableAndRemove => {
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

    Ok(InstallMacosExitReport {
        mode: config.mode,
        dest_plist_path: config.dest_plist_path,
        label: config.label,
        domain: config.domain,
        steps,
        dry_run: config.dry_run,
    })
}

fn validate_launchd_target(config: &InstallMacosExitConfig) -> Result<(), String> {
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

fn domain_target(config: &InstallMacosExitConfig) -> String {
    format!("{}/{}", config.domain, config.label)
}

/// The reviewed exit launchd unit, embedded at compile time. `role set exit`
/// invokes this installer ON THE NODE (e.g. a lab guest), where the repo source
/// tree is NOT present at the CWD-relative `scripts/launchd/` path — reading the
/// configured `source_plist_path` there fails with "No such file". The embedded
/// copy is `include_str!` of the exact reviewed file the repo ships, so an
/// on-disk source and the fallback install byte-identically.
const REVIEWED_EXIT_PLIST: &str = include_str!("../../../scripts/launchd/com.rustynet.exit.plist");

fn read_source_plist(path: &Path) -> Result<String, String> {
    // Prefer an explicit on-disk source (operator override, or the repo path on
    // a host that has the tree); fall back to the embedded reviewed plist when
    // it does not resolve — the on-node `role set exit` case that previously
    // failed closed with a misleading "No such file".
    if path.exists() {
        return std::fs::read_to_string(path)
            .map_err(|err| format!("read source plist at {} failed: {err}", path.display()));
    }
    Ok(REVIEWED_EXIT_PLIST.to_owned())
}

fn write_plist_atomic(dest: &Path, body: &str) -> Result<(), String> {
    let parent = dest
        .parent()
        .ok_or_else(|| format!("destination {} has no parent directory", dest.display()))?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        dest.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("com.rustynet.exit.plist")
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
            "rustynet-macos-exit-install-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("com.rustynet.exit.plist");
        std::fs::write(&source, "<plist version=\"1.0\"><dict/></plist>\n").unwrap();
        let dest = dir.join("LaunchDaemons").join("com.rustynet.exit.plist");
        let cfg = InstallMacosExitConfig {
            mode: LaunchdExitMode::InstallAndBootstrap,
            source_plist_path: source,
            dest_plist_path: dest.clone(),
            label: "com.rustynet.exit".to_owned(),
            domain: "system".to_owned(),
            dry_run: true,
        };

        let report = execute_install_macos_exit(cfg).unwrap();
        assert_eq!(report.mode, LaunchdExitMode::InstallAndBootstrap);
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
        let cfg = InstallMacosExitConfig {
            dry_run: true,
            ..InstallMacosExitConfig::default_uninstall()
        };
        let report = execute_install_macos_exit(cfg).unwrap();
        assert_eq!(report.mode, LaunchdExitMode::DisableAndRemove);
        assert!(
            report
                .steps
                .iter()
                .any(|step| step.contains("would run: launchctl bootout system/com.rustynet.exit"))
        );
        assert!(
            report
                .steps
                .iter()
                .any(|step| step.contains("would remove"))
        );
    }

    #[test]
    fn summary_includes_dry_run_tag() {
        let report = InstallMacosExitReport {
            mode: LaunchdExitMode::InstallAndBootstrap,
            dest_plist_path: PathBuf::from("/Library/LaunchDaemons/com.rustynet.exit.plist"),
            label: "com.rustynet.exit".to_owned(),
            domain: "system".to_owned(),
            steps: vec!["planned".to_owned()],
            dry_run: true,
        };
        let summary = report.summary();
        assert!(summary.contains("dry-run"));
        assert!(summary.contains("install+bootstrap"));
        assert!(summary.contains("system/com.rustynet.exit"));
    }

    #[test]
    fn defaults_target_launch_daemons() {
        let cfg = InstallMacosExitConfig::default_install();
        assert_eq!(cfg.mode, LaunchdExitMode::InstallAndBootstrap);
        assert_eq!(
            cfg.dest_plist_path,
            PathBuf::from("/Library/LaunchDaemons/com.rustynet.exit.plist")
        );
        assert_eq!(
            cfg.source_plist_path,
            PathBuf::from("scripts/launchd/com.rustynet.exit.plist")
        );
        assert_eq!(cfg.label, "com.rustynet.exit");
        assert_eq!(cfg.domain, "system");
        assert!(!cfg.dry_run);
    }

    #[test]
    fn label_validator_rejects_shell_metacharacters() {
        let mut cfg = InstallMacosExitConfig {
            dry_run: true,
            ..InstallMacosExitConfig::default_install()
        };
        cfg.label = "com.rustynet.exit;rm".to_owned();
        let err = execute_install_macos_exit(cfg).expect_err("bad label must fail closed");
        assert!(err.contains("reverse-DNS"));
    }

    #[test]
    fn install_falls_back_to_embedded_plist_when_source_absent() {
        // Regression for run #10: `role set exit` runs this installer ON THE
        // NODE, where the repo-relative `scripts/launchd/com.rustynet.exit.plist`
        // does not resolve. It must fall back to the embedded reviewed plist
        // rather than fail closed with "No such file".
        let dir = std::env::temp_dir().join(format!(
            "rustynet-macos-exit-embed-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("LaunchDaemons")).unwrap();
        let absent_source = dir.join("absent").join("com.rustynet.exit.plist");
        assert!(!absent_source.exists());
        let cfg = InstallMacosExitConfig {
            mode: LaunchdExitMode::InstallAndBootstrap,
            source_plist_path: absent_source,
            dest_plist_path: dir.join("LaunchDaemons").join("com.rustynet.exit.plist"),
            label: "com.rustynet.exit".to_owned(),
            domain: "system".to_owned(),
            dry_run: true,
        };
        let report = execute_install_macos_exit(cfg).expect("install must not fail closed");
        assert!(
            report
                .steps
                .iter()
                .any(|s| s.contains("embedded reviewed plist")),
            "must report the embedded fallback when the source is absent: {:?}",
            report.steps
        );
        // The embedded plist is the reviewed forwarding-preflight unit.
        assert!(
            REVIEWED_EXIT_PLIST.contains("net.inet.ip.forwarding=1")
                && REVIEWED_EXIT_PLIST.contains("<string>com.rustynet.exit</string>"),
            "embedded plist must be the reviewed exit unit"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
