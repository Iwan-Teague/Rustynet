//! Track B Step 3 (B1.4) — install/uninstall the `rustynet-exit.service`
//! sibling systemd unit on Linux.
//!
//! Pre-arms a Linux host for the `exit` role-preset transition by laying
//! down a reviewed oneshot unit that enables `net.ipv4.ip_forward=1` and
//! verifies the sysctl actually took effect. The runtime exit-serving
//! lifecycle (NAT activate, default-route advertise, killswitch arm)
//! stays owned by `rustynetd.service` — this installer is the operator-
//! visible audit point that the host is prepared, not a parallel exit
//! dataplane. One hardened execution path per security-sensitive flow,
//! per `AGENTS.md`.
//!
//! Mirrors the existing `ops_install_systemd_relay.rs` shape so the
//! role-transition executor can dispatch to it uniformly: the same
//! `InstallExitConfig` / `RelayUnitMode`-style mode enum, the same
//! atomic-file-install pattern, the same dry-run plumbing, the same
//! `systemctl` argv-only command construction.

use std::path::{Path, PathBuf};
use std::process::Command;

/// What to do with the `rustynet-exit.service` unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitUnitMode {
    /// Install + enable + start. Used when entering the `exit` /
    /// `blind_exit` preset.
    InstallAndEnable,
    /// Stop + disable + remove the unit file. Used when leaving the
    /// `exit` / `blind_exit` preset.
    DisableAndRemove,
}

/// Configuration for the installer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallExitConfig {
    pub mode: ExitUnitMode,
    /// Path to the source unit file
    /// (in-repo: `scripts/systemd/rustynet-exit.service`).
    pub source_unit_path: PathBuf,
    /// Path to install at (default
    /// `/etc/systemd/system/rustynet-exit.service`).
    pub dest_unit_path: PathBuf,
    /// When true, plan-only: report what would happen without touching
    /// the filesystem or systemd. Used by tests, CI, and operator dry
    /// runs.
    pub dry_run: bool,
}

impl InstallExitConfig {
    pub fn default_install() -> Self {
        Self {
            mode: ExitUnitMode::InstallAndEnable,
            source_unit_path: PathBuf::from("scripts/systemd/rustynet-exit.service"),
            dest_unit_path: PathBuf::from("/etc/systemd/system/rustynet-exit.service"),
            dry_run: false,
        }
    }

    pub fn default_uninstall() -> Self {
        Self {
            mode: ExitUnitMode::DisableAndRemove,
            source_unit_path: PathBuf::from("scripts/systemd/rustynet-exit.service"),
            dest_unit_path: PathBuf::from("/etc/systemd/system/rustynet-exit.service"),
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallExitReport {
    pub mode: ExitUnitMode,
    pub dest_unit_path: PathBuf,
    pub steps: Vec<String>,
    pub dry_run: bool,
}

impl InstallExitReport {
    /// Operator-friendly summary string suitable for stdout +
    /// inclusion in the role-transition audit log.
    pub fn summary(&self) -> String {
        let dry_tag = if self.dry_run { " (dry-run)" } else { "" };
        let mode_tag = match self.mode {
            ExitUnitMode::InstallAndEnable => "install+enable",
            ExitUnitMode::DisableAndRemove => "disable+remove",
        };
        let mut out = format!(
            "rustynet-exit systemd unit: {mode_tag}{dry_tag} at {}\n",
            self.dest_unit_path.display()
        );
        for step in &self.steps {
            out.push_str(&format!("  - {step}\n"));
        }
        out
    }
}

pub fn execute_install_exit(config: InstallExitConfig) -> Result<InstallExitReport, String> {
    let mut steps = Vec::new();
    let report_dest = config.dest_unit_path.clone();

    match config.mode {
        ExitUnitMode::InstallAndEnable => {
            let unit_body = read_source_unit(&config.source_unit_path, config.dry_run)?;
            steps.push(format!(
                "read source unit ({} bytes) from {}",
                unit_body.len(),
                config.source_unit_path.display()
            ));

            if !config.dry_run {
                write_unit_atomic(&config.dest_unit_path, &unit_body)?;
            }
            steps.push(format!(
                "{} unit file at {}",
                if config.dry_run {
                    "would write"
                } else {
                    "wrote"
                },
                config.dest_unit_path.display()
            ));

            run_systemctl(&["daemon-reload"], config.dry_run, &mut steps)?;
            run_systemctl(
                &["enable", "rustynet-exit.service"],
                config.dry_run,
                &mut steps,
            )?;
            run_systemctl(
                &["start", "rustynet-exit.service"],
                config.dry_run,
                &mut steps,
            )?;
        }
        ExitUnitMode::DisableAndRemove => {
            // Stop + disable. Stop may fail if the unit isn't running;
            // we tolerate that since the goal is to leave no exit
            // preflight active.
            run_systemctl(
                &["stop", "rustynet-exit.service"],
                config.dry_run,
                &mut steps,
            )
            .ok();
            run_systemctl(
                &["disable", "rustynet-exit.service"],
                config.dry_run,
                &mut steps,
            )
            .ok();
            steps.push("disabled rustynet-exit.service".to_owned());

            if !config.dry_run && config.dest_unit_path.exists() {
                std::fs::remove_file(&config.dest_unit_path).map_err(|err| {
                    format!("remove {} failed: {err}", config.dest_unit_path.display())
                })?;
                steps.push(format!("removed {}", config.dest_unit_path.display()));
            } else if config.dry_run {
                steps.push(format!("would remove {}", config.dest_unit_path.display()));
            } else {
                steps.push(format!(
                    "{} already absent (no-op)",
                    config.dest_unit_path.display()
                ));
            }

            run_systemctl(&["daemon-reload"], config.dry_run, &mut steps)?;
        }
    }

    Ok(InstallExitReport {
        mode: config.mode,
        dest_unit_path: report_dest,
        steps,
        dry_run: config.dry_run,
    })
}

fn read_source_unit(path: &Path, dry_run: bool) -> Result<String, String> {
    if dry_run && !path.exists() {
        return Ok(String::new());
    }
    std::fs::read_to_string(path)
        .map_err(|err| format!("read source unit at {} failed: {err}", path.display()))
}

fn write_unit_atomic(dest: &Path, body: &str) -> Result<(), String> {
    let parent = dest
        .parent()
        .ok_or_else(|| format!("destination {} has no parent directory", dest.display()))?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        dest.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("rustynet-exit.service")
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
            "rename {} → {} failed: {err}",
            tmp.display(),
            dest.display()
        )
    })?;
    Ok(())
}

fn run_systemctl(args: &[&str], dry_run: bool, steps: &mut Vec<String>) -> Result<(), String> {
    if dry_run {
        steps.push(format!("would run: systemctl {}", args.join(" ")));
        return Ok(());
    }
    let output = Command::new("systemctl")
        .args(args)
        .output()
        .map_err(|err| format!("systemctl exec failed: {err}"))?;
    let summary = format!(
        "systemctl {} (exit={})",
        args.join(" "),
        output.status.code().unwrap_or(-1)
    );
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("{summary}: {stderr}"));
    }
    steps.push(summary);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_install_reports_planned_steps() {
        let dir =
            std::env::temp_dir().join(format!("rustynet-exit-install-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("rustynet-exit.service");
        std::fs::write(&source, "[Unit]\nDescription=test\n").unwrap();
        let dest = dir.join("dest").join("rustynet-exit.service");
        let cfg = InstallExitConfig {
            mode: ExitUnitMode::InstallAndEnable,
            source_unit_path: source.clone(),
            dest_unit_path: dest.clone(),
            dry_run: true,
        };
        let report = execute_install_exit(cfg).unwrap();
        assert_eq!(report.mode, ExitUnitMode::InstallAndEnable);
        assert!(report.dry_run);
        assert!(report.steps.iter().any(|s| s.contains("would write")));
        assert!(
            report
                .steps
                .iter()
                .any(|s| s.contains("would run: systemctl daemon-reload"))
        );
        assert!(
            report
                .steps
                .iter()
                .any(|s| s.contains("would run: systemctl enable rustynet-exit.service"))
        );
        assert!(!dest.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dry_run_uninstall_reports_planned_steps() {
        let dir = std::env::temp_dir().join(format!(
            "rustynet-exit-uninstall-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("rustynet-exit.service");
        std::fs::write(&dest, "[Unit]\nDescription=test\n").unwrap();
        let cfg = InstallExitConfig {
            mode: ExitUnitMode::DisableAndRemove,
            source_unit_path: PathBuf::from("unused.service"),
            dest_unit_path: dest.clone(),
            dry_run: true,
        };
        let report = execute_install_exit(cfg).unwrap();
        assert_eq!(report.mode, ExitUnitMode::DisableAndRemove);
        assert!(
            report
                .steps
                .iter()
                .any(|s| s.contains("would run: systemctl stop rustynet-exit.service"))
        );
        assert!(
            report
                .steps
                .iter()
                .any(|s| s.contains("would run: systemctl disable rustynet-exit.service"))
        );
        assert!(report.steps.iter().any(|s| s.contains("would remove")));
        assert!(dest.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn summary_includes_dry_run_tag() {
        let report = InstallExitReport {
            mode: ExitUnitMode::InstallAndEnable,
            dest_unit_path: PathBuf::from("/etc/systemd/system/rustynet-exit.service"),
            steps: vec!["foo".to_owned()],
            dry_run: true,
        };
        let summary = report.summary();
        assert!(summary.contains("dry-run"));
        assert!(summary.contains("install+enable"));
        assert!(summary.contains("/etc/systemd/system/rustynet-exit.service"));
    }

    #[test]
    fn default_install_targets_etc_systemd_system() {
        let cfg = InstallExitConfig::default_install();
        assert_eq!(cfg.mode, ExitUnitMode::InstallAndEnable);
        assert_eq!(
            cfg.dest_unit_path,
            PathBuf::from("/etc/systemd/system/rustynet-exit.service")
        );
        assert_eq!(
            cfg.source_unit_path,
            PathBuf::from("scripts/systemd/rustynet-exit.service")
        );
        assert!(!cfg.dry_run);
    }

    #[test]
    fn default_uninstall_targets_etc_systemd_system() {
        let cfg = InstallExitConfig::default_uninstall();
        assert_eq!(cfg.mode, ExitUnitMode::DisableAndRemove);
        assert_eq!(
            cfg.dest_unit_path,
            PathBuf::from("/etc/systemd/system/rustynet-exit.service")
        );
    }

    #[test]
    fn real_write_uses_atomic_rename_and_0644_mode() {
        let dir =
            std::env::temp_dir().join(format!("rustynet-exit-write-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("rustynet-exit.service");
        let unit_body = "[Unit]\nDescription=tmp\n[Service]\nExecStart=/bin/true\n";

        write_unit_atomic(&dest, unit_body).expect("write_unit_atomic");
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), unit_body);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
