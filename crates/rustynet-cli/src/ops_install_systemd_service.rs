//! D13.c/D13.d — install/uninstall the service-hosting sibling
//! systemd units on Linux (`rustynet-nas.service`,
//! `rustynet-llm-gateway.service`).
//!
//! One generalised hardened installer for the service-hosting
//! category, mirroring the reviewed relay installer
//! (`ops_install_systemd_relay.rs`) step for step: read the in-repo
//! source unit, atomic-write into `/etc/systemd/system/`, then
//! `systemctl daemon-reload` + `enable` + `start` (reverse for
//! uninstall: stop/disable tolerated-failing, remove file,
//! daemon-reload). `dry_run` plans without touching disk or
//! systemd (CI-safe).
//!
//! Invoked by the role-transition executor in `main.rs`
//! (`execute_platform_nas_service_action` /
//! `execute_platform_llm_service_action`) when the planner emits
//! `DeployNasService` / `DeployLlmService` and their undeploy
//! counterparts. Ordering contract: deploy runs BEFORE the signed
//! capability advertisement; undeploy runs after session severance
//! and BEFORE the signed revocation
//! (`NodeRoleTaxonomyExtension_2026-06-11.md` §4).

use std::path::{Path, PathBuf};
use std::process::Command;

use rustynet_control::role_presets::ServiceKind;

/// What to do with the unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceUnitMode {
    /// Install + enable + start. Used when entering the preset.
    InstallAndEnable,
    /// Stop + disable + remove the unit file. Used when leaving.
    DisableAndRemove,
}

/// Configuration for one install/uninstall execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallServiceConfig {
    /// Which service-hosting sibling this drives. Only `Nas` and
    /// `Llm` are valid — the relay keeps its own reviewed installer.
    pub kind: ServiceKind,
    pub mode: ServiceUnitMode,
    /// Path to the in-repo source unit file.
    pub source_unit_path: PathBuf,
    /// Path to install at under `/etc/systemd/system/`.
    pub dest_unit_path: PathBuf,
    /// Plan-only mode: report what would happen without touching
    /// the filesystem or systemd.
    pub dry_run: bool,
}

impl InstallServiceConfig {
    fn unit_file_name(kind: ServiceKind) -> &'static str {
        match kind {
            ServiceKind::Nas => "rustynet-nas.service",
            ServiceKind::Llm => "rustynet-llm-gateway.service",
            // The relay has its own reviewed installer
            // (ops_install_systemd_relay.rs); routing it through
            // here is a programming error surfaced at validate().
            ServiceKind::Relay => "rustynet-relay.service",
        }
    }

    fn with_mode(kind: ServiceKind, mode: ServiceUnitMode) -> Self {
        let unit = Self::unit_file_name(kind);
        Self {
            kind,
            mode,
            source_unit_path: PathBuf::from(format!("scripts/systemd/{unit}")),
            dest_unit_path: PathBuf::from(format!("/etc/systemd/system/{unit}")),
            dry_run: false,
        }
    }

    pub fn nas_install() -> Self {
        Self::with_mode(ServiceKind::Nas, ServiceUnitMode::InstallAndEnable)
    }

    pub fn nas_uninstall() -> Self {
        Self::with_mode(ServiceKind::Nas, ServiceUnitMode::DisableAndRemove)
    }

    pub fn llm_install() -> Self {
        Self::with_mode(ServiceKind::Llm, ServiceUnitMode::InstallAndEnable)
    }

    pub fn llm_uninstall() -> Self {
        Self::with_mode(ServiceKind::Llm, ServiceUnitMode::DisableAndRemove)
    }

    fn validate(&self) -> Result<&'static str, String> {
        if self.kind == ServiceKind::Relay {
            return Err(
                "relay unit lifecycle is owned by ops_install_systemd_relay; refusing".to_owned(),
            );
        }
        Ok(Self::unit_file_name(self.kind))
    }
}

/// Structured result for the role orchestrator's output + the
/// transition audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallServiceReport {
    pub kind: ServiceKind,
    pub mode: ServiceUnitMode,
    pub dest_unit_path: PathBuf,
    pub steps: Vec<String>,
    pub dry_run: bool,
}

impl InstallServiceReport {
    pub fn summary(&self) -> String {
        let dry_tag = if self.dry_run { " (dry-run)" } else { "" };
        let mode_tag = match self.mode {
            ServiceUnitMode::InstallAndEnable => "install+enable",
            ServiceUnitMode::DisableAndRemove => "disable+remove",
        };
        let mut out = format!(
            "{} systemd unit: {mode_tag}{dry_tag} at {}\n",
            self.kind.binary_name(),
            self.dest_unit_path.display()
        );
        for step in &self.steps {
            out.push_str(&format!("  - {step}\n"));
        }
        out
    }
}

/// Execute the installer. Fail-closed: any systemctl or filesystem
/// failure during install aborts with the error (the role
/// transition stops before the signed advertisement); uninstall
/// tolerates stop/disable failures for units that are not running
/// but never tolerates a unit file it cannot remove.
pub fn execute_install_service(
    config: InstallServiceConfig,
) -> Result<InstallServiceReport, String> {
    let unit_name = config.validate()?;
    let mut steps = Vec::new();
    let report_dest = config.dest_unit_path.clone();

    match config.mode {
        ServiceUnitMode::InstallAndEnable => {
            let unit_body = read_source_unit(&config.source_unit_path, config.dry_run)?;
            steps.push(format!(
                "read source unit ({} bytes) from {}",
                unit_body.len(),
                config.source_unit_path.display()
            ));

            if !config.dry_run {
                write_unit_atomic(&config.dest_unit_path, &unit_body, unit_name)?;
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
            run_systemctl(&["enable", unit_name], config.dry_run, &mut steps)?;
            run_systemctl(&["start", unit_name], config.dry_run, &mut steps)?;
        }
        ServiceUnitMode::DisableAndRemove => {
            // Stop/disable may fail when the unit was never started;
            // that is acceptable on the teardown path.
            run_systemctl(&["stop", unit_name], config.dry_run, &mut steps).ok();
            run_systemctl(&["disable", unit_name], config.dry_run, &mut steps).ok();
            steps.push(format!("disabled {unit_name}"));

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

    Ok(InstallServiceReport {
        kind: config.kind,
        mode: config.mode,
        dest_unit_path: report_dest,
        steps,
        dry_run: config.dry_run,
    })
}

fn read_source_unit(path: &Path, dry_run: bool) -> Result<String, String> {
    if dry_run && !path.exists() {
        // Allow dry-run without the source file (e.g. a CI host
        // without the systemd scripts directory).
        return Ok(String::new());
    }
    std::fs::read_to_string(path)
        .map_err(|err| format!("read source unit at {} failed: {err}", path.display()))
}

fn write_unit_atomic(dest: &Path, body: &str, unit_name: &str) -> Result<(), String> {
    let parent = dest
        .parent()
        .ok_or_else(|| format!("destination {} has no parent directory", dest.display()))?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        dest.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(unit_name)
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
