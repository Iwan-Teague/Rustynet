//! D13.c/D13.d — install/uninstall the service-hosting sibling
//! systemd units on Linux (`rustynet-nas.service`,
//! `rustynet-llm-gateway.service`).
//!
//! One generalised hardened installer for the service-hosting
//! category, mirroring the reviewed relay installer
//! (`ops_install_systemd_relay.rs`) step for step: read the embedded
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

/// The `rustynet-nas.service` unit body, embedded at compile time from
/// `scripts/systemd/rustynet-nas.service` so the installer works on an
/// installed node that has only the binaries and no source checkout
/// (the same approach as `install/live_linux.rs` `SYSTEMD_UNIT_TEMPLATES`).
const NAS_UNIT_BODY: &str = include_str!("../../../scripts/systemd/rustynet-nas.service");

/// The `rustynet-llm-gateway.service` unit body, embedded at compile
/// time from `scripts/systemd/rustynet-llm-gateway.service` so the
/// installer works on an installed node that has only the binaries and
/// no source checkout (the same approach as `install/live_linux.rs`
/// `SYSTEMD_UNIT_TEMPLATES`).
const LLM_UNIT_BODY: &str = include_str!("../../../scripts/systemd/rustynet-llm-gateway.service");

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
            // RustyDNS tandem (Phase 1): the `dns` service kind exists
            // for planning/parity only. There is no reviewed
            // `rustydnsd` unit yet, so routing it through this
            // installer is surfaced as a programming error at
            // validate(), exactly like the relay.
            ServiceKind::Dns => "rustydnsd.service",
        }
    }

    fn with_mode(kind: ServiceKind, mode: ServiceUnitMode) -> Self {
        let unit = Self::unit_file_name(kind);
        Self {
            kind,
            mode,
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
        if self.kind == ServiceKind::Dns {
            return Err(
                "rustydnsd unit lifecycle is not available yet (RustyDNS tandem \
                 Phase 1 is control-plane only); refusing"
                    .to_owned(),
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
            // The unit body is embedded at compile time.
            let unit_body = unit_body(config.kind);
            steps.push(format!("read embedded unit ({} bytes)", unit_body.len()));

            if !config.dry_run {
                write_unit_atomic(&config.dest_unit_path, unit_body, unit_name)?;
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

/// The embedded unit body for one service-hosting kind. `Relay` and
/// `Dns` never reach this: `validate()` refuses both before any body
/// is read, so the empty body keeps the match total without inventing
/// units that do not exist.
fn unit_body(kind: ServiceKind) -> &'static str {
    match kind {
        ServiceKind::Nas => NAS_UNIT_BODY,
        ServiceKind::Llm => LLM_UNIT_BODY,
        ServiceKind::Relay | ServiceKind::Dns => "",
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin: the embedded unit must stay byte-identical to the checked-in
    /// `scripts/systemd/rustynet-nas.service` file. The read here is an
    /// independent runtime read from `CARGO_MANIFEST_DIR`, not another
    /// `include_str!` of the same path, so the two really can drift apart
    /// and this test would catch it.
    #[test]
    fn embedded_nas_unit_is_byte_identical_to_checked_in_file() {
        let checked_in = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/systemd/rustynet-nas.service");
        let on_disk = std::fs::read(&checked_in).expect("read checked-in rustynet-nas.service");
        assert_eq!(
            NAS_UNIT_BODY.as_bytes(),
            on_disk.as_slice(),
            "embedded rustynet-nas.service must be byte-identical to the checked-in unit"
        );
    }

    /// Pin: the embedded unit must stay byte-identical to the checked-in
    /// `scripts/systemd/rustynet-llm-gateway.service` file. The read here is
    /// an independent runtime read from `CARGO_MANIFEST_DIR`, not another
    /// `include_str!` of the same path, so the two really can drift apart
    /// and this test would catch it.
    #[test]
    fn embedded_llm_unit_is_byte_identical_to_checked_in_file() {
        let checked_in = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/systemd/rustynet-llm-gateway.service");
        let on_disk =
            std::fs::read(&checked_in).expect("read checked-in rustynet-llm-gateway.service");
        assert_eq!(
            LLM_UNIT_BODY.as_bytes(),
            on_disk.as_slice(),
            "embedded rustynet-llm-gateway.service must be byte-identical to the checked-in unit"
        );
    }

    /// Regression witness for PF-2: the default install used to read
    /// `scripts/systemd/rustynet-nas.service` relative to the CWD, so on an
    /// installed node outside a source checkout it failed with
    /// "read source unit at scripts/systemd/rustynet-nas.service failed:
    /// No such file or directory" (or, in dry-run, silently planned an
    /// empty unit). The unit is now embedded, so the plan must carry the
    /// real unit bytes regardless of the working directory (the tests run
    /// from `crates/rustynet-cli`, where that relative path does not
    /// exist).
    #[test]
    fn nas_default_install_dry_run_needs_no_source_checkout() {
        let dir =
            std::env::temp_dir().join(format!("rustynet-nas-embed-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("rustynet-nas.service");
        let checked_in = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/systemd/rustynet-nas.service");
        let expected_len = std::fs::read(&checked_in)
            .expect("read checked-in unit")
            .len();
        let cfg = InstallServiceConfig {
            dest_unit_path: dest.clone(),
            dry_run: true,
            ..InstallServiceConfig::nas_install()
        };
        let report = execute_install_service(cfg).unwrap();
        let expected_step = format!("read embedded unit ({expected_len} bytes)");
        assert!(
            report.steps.contains(&expected_step),
            "dry-run plan must carry the embedded unit bytes (expected step \
             {expected_step:?}), got {:?}",
            report.steps
        );
        assert!(report.steps.iter().any(|s| s.contains("would write")));
        assert!(!dest.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression witness for PF-2, `llm` kind: same CWD-relative defect,
    /// same embedded fix, for `scripts/systemd/rustynet-llm-gateway.service`.
    #[test]
    fn llm_default_install_dry_run_needs_no_source_checkout() {
        let dir =
            std::env::temp_dir().join(format!("rustynet-llm-embed-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("rustynet-llm-gateway.service");
        let checked_in = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/systemd/rustynet-llm-gateway.service");
        let expected_len = std::fs::read(&checked_in)
            .expect("read checked-in unit")
            .len();
        let cfg = InstallServiceConfig {
            dest_unit_path: dest.clone(),
            dry_run: true,
            ..InstallServiceConfig::llm_install()
        };
        let report = execute_install_service(cfg).unwrap();
        let expected_step = format!("read embedded unit ({expected_len} bytes)");
        assert!(
            report.steps.contains(&expected_step),
            "dry-run plan must carry the embedded unit bytes (expected step \
             {expected_step:?}), got {:?}",
            report.steps
        );
        assert!(report.steps.iter().any(|s| s.contains("would write")));
        assert!(!dest.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
