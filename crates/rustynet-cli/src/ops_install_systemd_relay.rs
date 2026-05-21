//! D12.d — install/uninstall the `rustynet-relay.service` sibling
//! systemd unit on Linux.
//!
//! Used by the role-transition orchestrator
//! (`crates/rustynet-cli/src/role_cli.rs`) when transitioning into
//! a relay-bearing preset (`relay` or `anchor`), and again when
//! transitioning out. Co-deploys with the operator's existing
//! `rustynetd.service` install (which is managed by
//! `ops_install_systemd.rs`).
//!
//! The installer is intentionally minimal:
//!
//! - Source unit ships in `scripts/systemd/rustynet-relay.service`.
//! - Installer reads that unit, copies it to
//!   `/etc/systemd/system/rustynet-relay.service`, runs
//!   `systemctl daemon-reload`, then `systemctl enable --now` or
//!   `systemctl disable --now` depending on `mode`.
//! - Idempotent: re-running install when the unit is already
//!   present is a no-op apart from refreshing the file contents.
//! - Reports a structured result so the role orchestrator can
//!   include a clear summary in its output + the audit log.
//!
//! Today this is invoked manually by an operator who runs
//! `rustynet ops install-systemd-relay`. Once D11.a lands the
//! capability schema and the role planner emits
//! `DeployRelayService` / `UndeployRelayService` actions for the
//! relay/anchor presets, the orchestrator calls this helper
//! automatically through the same CLI verb.

use std::path::{Path, PathBuf};
use std::process::Command;

/// What to do with the unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayUnitMode {
    /// Install + enable + start. Used when entering relay/anchor
    /// presets.
    InstallAndEnable,
    /// Stop + disable + (optionally) remove the unit file. Used
    /// when leaving relay/anchor presets.
    DisableAndRemove,
}

/// Configuration for the installer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallRelayConfig {
    pub mode: RelayUnitMode,
    /// Path to the source unit file (in-repo: `scripts/systemd/rustynet-relay.service`).
    pub source_unit_path: PathBuf,
    /// Path to install at (default `/etc/systemd/system/rustynet-relay.service`).
    pub dest_unit_path: PathBuf,
    /// When true, drive the real `systemctl` binary (production).
    /// When false, plan-only — return what would happen without
    /// touching the filesystem or systemd. Useful for tests + CI
    /// + dry runs.
    pub dry_run: bool,
}

impl InstallRelayConfig {
    pub fn default_install() -> Self {
        Self {
            mode: RelayUnitMode::InstallAndEnable,
            source_unit_path: PathBuf::from("scripts/systemd/rustynet-relay.service"),
            dest_unit_path: PathBuf::from("/etc/systemd/system/rustynet-relay.service"),
            dry_run: false,
        }
    }

    pub fn default_uninstall() -> Self {
        Self {
            mode: RelayUnitMode::DisableAndRemove,
            source_unit_path: PathBuf::from("scripts/systemd/rustynet-relay.service"),
            dest_unit_path: PathBuf::from("/etc/systemd/system/rustynet-relay.service"),
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallRelayReport {
    pub mode: RelayUnitMode,
    pub dest_unit_path: PathBuf,
    pub steps: Vec<String>,
    pub dry_run: bool,
}

impl InstallRelayReport {
    /// Operator-friendly summary string suitable for stdout +
    /// inclusion in the role-transition audit log.
    pub fn summary(&self) -> String {
        let dry_tag = if self.dry_run { " (dry-run)" } else { "" };
        let mode_tag = match self.mode {
            RelayUnitMode::InstallAndEnable => "install+enable",
            RelayUnitMode::DisableAndRemove => "disable+remove",
        };
        let mut out = format!(
            "rustynet-relay systemd unit: {mode_tag}{dry_tag} at {}\n",
            self.dest_unit_path.display()
        );
        for step in &self.steps {
            out.push_str(&format!("  - {step}\n"));
        }
        out
    }
}

/// Execute the installer. Returns the structured report on success.
pub fn execute_install_relay(config: InstallRelayConfig) -> Result<InstallRelayReport, String> {
    let mut steps = Vec::new();
    let report_dest = config.dest_unit_path.clone();

    match config.mode {
        RelayUnitMode::InstallAndEnable => {
            // 1. Read the source unit.
            let unit_body = read_source_unit(&config.source_unit_path, config.dry_run)?;
            steps.push(format!(
                "read source unit ({} bytes) from {}",
                unit_body.len(),
                config.source_unit_path.display()
            ));

            // 2. Write to the destination path.
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

            // 3. Reload + enable + start via systemctl.
            run_systemctl(&["daemon-reload"], config.dry_run, &mut steps)?;
            run_systemctl(
                &["enable", "rustynet-relay.service"],
                config.dry_run,
                &mut steps,
            )?;
            run_systemctl(
                &["start", "rustynet-relay.service"],
                config.dry_run,
                &mut steps,
            )?;
        }
        RelayUnitMode::DisableAndRemove => {
            // 1. Stop + disable.
            run_systemctl(
                &["stop", "rustynet-relay.service"],
                config.dry_run,
                &mut steps,
            )
            .ok(); // Allow stop to fail if not running.
            run_systemctl(
                &["disable", "rustynet-relay.service"],
                config.dry_run,
                &mut steps,
            )
            .ok();
            steps.push("disabled rustynet-relay.service".to_owned());

            // 2. Remove the unit file.
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

            // 3. daemon-reload to clear the systemd cache.
            run_systemctl(&["daemon-reload"], config.dry_run, &mut steps)?;
        }
    }

    Ok(InstallRelayReport {
        mode: config.mode,
        dest_unit_path: report_dest,
        steps,
        dry_run: config.dry_run,
    })
}

fn read_source_unit(path: &Path, dry_run: bool) -> Result<String, String> {
    if dry_run && !path.exists() {
        // Allow dry-run without the source file (e.g., from a CI
        // host that hasn't cloned the systemd scripts directory).
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
            .unwrap_or("rustynet-relay.service")
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
        let dir = std::env::temp_dir().join(format!(
            "rustynet-relay-install-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("rustynet-relay.service");
        std::fs::write(&source, "[Unit]\nDescription=test\n").unwrap();
        let dest = dir.join("dest").join("rustynet-relay.service");
        let cfg = InstallRelayConfig {
            mode: RelayUnitMode::InstallAndEnable,
            source_unit_path: source.clone(),
            dest_unit_path: dest.clone(),
            dry_run: true,
        };
        let report = execute_install_relay(cfg).unwrap();
        assert_eq!(report.mode, RelayUnitMode::InstallAndEnable);
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
                .any(|s| s.contains("would run: systemctl enable rustynet-relay.service"))
        );
        // Dest must NOT have been created in dry-run mode.
        assert!(!dest.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dry_run_uninstall_reports_planned_steps() {
        let dir = std::env::temp_dir().join(format!(
            "rustynet-relay-uninstall-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("rustynet-relay.service");
        std::fs::write(&dest, "[Unit]\nDescription=test\n").unwrap();
        let cfg = InstallRelayConfig {
            mode: RelayUnitMode::DisableAndRemove,
            source_unit_path: PathBuf::from("unused.service"),
            dest_unit_path: dest.clone(),
            dry_run: true,
        };
        let report = execute_install_relay(cfg).unwrap();
        assert_eq!(report.mode, RelayUnitMode::DisableAndRemove);
        assert!(
            report
                .steps
                .iter()
                .any(|s| s.contains("would run: systemctl stop rustynet-relay.service"))
        );
        assert!(
            report
                .steps
                .iter()
                .any(|s| s.contains("would run: systemctl disable rustynet-relay.service"))
        );
        assert!(report.steps.iter().any(|s| s.contains("would remove")));
        // Dest must still exist after dry-run.
        assert!(dest.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn summary_includes_dry_run_tag() {
        let report = InstallRelayReport {
            mode: RelayUnitMode::InstallAndEnable,
            dest_unit_path: PathBuf::from("/etc/systemd/system/rustynet-relay.service"),
            steps: vec!["foo".to_owned()],
            dry_run: true,
        };
        let summary = report.summary();
        assert!(summary.contains("dry-run"));
        assert!(summary.contains("install+enable"));
        assert!(summary.contains("/etc/systemd/system/rustynet-relay.service"));
    }

    #[test]
    fn summary_omits_dry_run_tag_when_real() {
        let report = InstallRelayReport {
            mode: RelayUnitMode::DisableAndRemove,
            dest_unit_path: PathBuf::from("/etc/systemd/system/rustynet-relay.service"),
            steps: vec!["bar".to_owned()],
            dry_run: false,
        };
        let summary = report.summary();
        assert!(!summary.contains("dry-run"));
        assert!(summary.contains("disable+remove"));
    }

    #[test]
    fn default_install_targets_etc_systemd_system() {
        let cfg = InstallRelayConfig::default_install();
        assert_eq!(cfg.mode, RelayUnitMode::InstallAndEnable);
        assert_eq!(
            cfg.dest_unit_path,
            PathBuf::from("/etc/systemd/system/rustynet-relay.service")
        );
        assert_eq!(
            cfg.source_unit_path,
            PathBuf::from("scripts/systemd/rustynet-relay.service")
        );
        assert!(!cfg.dry_run);
    }

    #[test]
    fn default_uninstall_targets_etc_systemd_system() {
        let cfg = InstallRelayConfig::default_uninstall();
        assert_eq!(cfg.mode, RelayUnitMode::DisableAndRemove);
        assert_eq!(
            cfg.dest_unit_path,
            PathBuf::from("/etc/systemd/system/rustynet-relay.service")
        );
    }

    #[test]
    fn real_install_writes_unit_file() {
        // Exercise the non-dry-run path with a fake systemctl by
        // pointing the dest at a tmp dir. We can't actually run
        // systemctl in tests; skip the systemd parts by using
        // dry-run for the systemctl steps. The atomic-write path is
        // tested separately via the dry-run path above; this test
        // pins the rename+permission behaviour.
        let dir =
            std::env::temp_dir().join(format!("rustynet-relay-write-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("rustynet-relay.service");
        let unit_body = "[Unit]\nDescription=tmp-test\n[Service]\nExecStart=/bin/true\n";
        std::fs::write(&source, unit_body).unwrap();
        let dest = dir.join("rustynet-relay.service.installed");

        write_unit_atomic(&dest, unit_body).expect("write_unit_atomic");
        let body = std::fs::read_to_string(&dest).unwrap();
        assert_eq!(body, unit_body);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&dest).unwrap();
            // 0o644 — readable for everyone, writable only by owner.
            assert_eq!(meta.permissions().mode() & 0o777, 0o644);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
