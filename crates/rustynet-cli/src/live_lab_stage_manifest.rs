#![forbid(unsafe_code)]

//! Run-scoped stage manifest (Finding 1B of the 2026-07-03 live-lab
//! findings): the resolved plan for ONE run, written to
//! `<report_dir>/orchestration/stage_manifest.json` at run start.
//!
//! The manifest is the run-time data contract between the orchestrators
//! (which know the plan) and every consumer that previously hand-copied the
//! stage vocabulary — most importantly the monitor TUI, which is
//! deliberately excluded from the cargo workspace and therefore cannot
//! share the registry at build time. Consumers render/validate against the
//! manifest found in the report dir; a held run's display is thereby pinned
//! to the config that launched it, immune to later config edits.
//!
//! Every stage the registry knows appears exactly once, resolved to
//! `enabled: true` or `enabled: false` + `skip_reason` from the run's
//! actual selectors. Synthetic display aggregates are marked so recorders
//! know they never appear in outcomes.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::live_lab_stage_registry::{self, STAGES, TargetSelectors};

pub const STAGE_MANIFEST_RELATIVE_PATH: &str = "orchestration/stage_manifest.json";
pub const STAGE_MANIFEST_SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StageManifest {
    pub schema_version: u64,
    pub generated_at_unix: u64,
    /// The command that resolved this plan (`vm-lab-orchestrate-live-lab`,
    /// `live-linux-lab-orchestrator`, ...).
    pub run_command: String,
    /// `full` | `setup_only` | `validate_only` | `dry_run`. The conclusion
    /// barrier only synthesizes `aborted` outcomes for planned-but-
    /// unrecorded stages on `full` runs — a setup-only run legitimately
    /// records nothing for the live suite.
    #[serde(default = "default_run_mode")]
    pub run_mode: String,
    pub selectors: ManifestSelectors,
    pub stages: Vec<ManifestStage>,
}

/// Snapshot of the selectors the plan was resolved from — recorded so a
/// consumer can re-derive or audit the enablement decisions.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ManifestSelectors {
    pub wants_macos: bool,
    pub wants_windows: bool,
    pub macos_promote_exit: bool,
    #[serde(default)]
    pub exit_platform: String,
    #[serde(default)]
    pub relay_platform: String,
    #[serde(default)]
    pub anchor_platform: String,
    #[serde(default)]
    pub admin_platform: String,
    #[serde(default)]
    pub blind_exit_platform: String,
    #[serde(default)]
    pub role_switch_platform: String,
    pub skip_linux_live_suite: bool,
    pub chaos_suite: bool,
    pub cross_network_suite: bool,
}

impl From<&TargetSelectors> for ManifestSelectors {
    fn from(selectors: &TargetSelectors) -> Self {
        Self {
            wants_macos: selectors.wants_macos,
            wants_windows: selectors.wants_windows,
            macos_promote_exit: selectors.macos_promote_exit,
            exit_platform: selectors.exit_platform.clone(),
            relay_platform: selectors.relay_platform.clone(),
            anchor_platform: selectors.anchor_platform.clone(),
            admin_platform: selectors.admin_platform.clone(),
            blind_exit_platform: selectors.blind_exit_platform.clone(),
            role_switch_platform: selectors.role_switch_platform.clone(),
            skip_linux_live_suite: selectors.skip_linux_live_suite,
            chaos_suite: selectors.chaos_suite,
            cross_network_suite: selectors.cross_network_suite,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ManifestStage {
    pub name: String,
    /// pre | bootstrap | live | chaos | job
    pub group: String,
    /// common | linux | macos | windows
    pub stream: String,
    pub enabled: bool,
    /// Present exactly when `enabled` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    /// Cold-start time budget in seconds.
    pub budget_secs: u64,
    /// hard | soft
    pub severity: String,
    /// Display-only aggregate; never appears in recorded outcomes.
    #[serde(default)]
    pub synthetic: bool,
    /// Exempt from the conclusion barrier: job-level bookkeeping stages
    /// and stages whose dispatch is runtime-gated beyond the selectors
    /// (audit sub-passes, cross-network auto mode) — a missing outcome is
    /// not evidence of abnormal termination for these.
    #[serde(default)]
    pub barrier_exempt: bool,
}

fn default_run_mode() -> String {
    "full".to_owned()
}

/// Resolve the full registry against this run's selectors.
pub fn build_stage_manifest(
    run_command: &str,
    run_mode: &str,
    selectors: &TargetSelectors,
) -> StageManifest {
    let stages = STAGES
        .iter()
        .map(|spec| {
            let enabled = selectors.resolves(spec.enable);
            ManifestStage {
                name: spec.name.to_owned(),
                group: spec.group.as_str().to_owned(),
                stream: spec.stream.as_str().to_owned(),
                enabled,
                skip_reason: (!enabled).then(|| selectors.skip_reason(spec.enable).to_owned()),
                budget_secs: spec.budget_secs,
                severity: match spec.severity {
                    live_lab_stage_registry::StageSeverity::Hard => "hard".to_owned(),
                    live_lab_stage_registry::StageSeverity::Soft => "soft".to_owned(),
                },
                synthetic: spec.synthetic,
                barrier_exempt: spec.conditional_dispatch
                    || spec.group == live_lab_stage_registry::StageGroup::Job
                    || (run_command == "vm-lab-orchestrate-live-lab" && spec.rust_native),
            }
        })
        .collect();
    StageManifest {
        schema_version: STAGE_MANIFEST_SCHEMA_VERSION,
        generated_at_unix: unix_now(),
        run_command: run_command.to_owned(),
        run_mode: run_mode.to_owned(),
        selectors: ManifestSelectors::from(selectors),
        stages,
    }
}

/// Write the manifest into `<report_dir>/orchestration/stage_manifest.json`
/// (atomic tmp+rename). Returns the written path.
pub fn write_stage_manifest(
    report_dir: &Path,
    manifest: &StageManifest,
) -> Result<PathBuf, String> {
    let path = report_dir.join(STAGE_MANIFEST_RELATIVE_PATH);
    let parent = path
        .parent()
        .ok_or_else(|| format!("stage manifest path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "create orchestration dir failed ({}): {err}",
            parent.display()
        )
    })?;
    let body = serde_json::to_string_pretty(manifest)
        .map_err(|err| format!("serialize stage manifest failed: {err}"))?;
    let tmp_path = path.with_extension("json.tmp");
    fs::write(tmp_path.as_path(), body).map_err(|err| {
        format!(
            "write stage manifest tmp failed ({}): {err}",
            tmp_path.display()
        )
    })?;
    fs::rename(tmp_path.as_path(), path.as_path()).map_err(|err| {
        format!(
            "rename stage manifest into place failed ({}): {err}",
            path.display()
        )
    })?;
    Ok(path)
}

/// Read a previously emitted manifest, if one exists.
pub fn read_stage_manifest(report_dir: &Path) -> Result<Option<StageManifest>, String> {
    let path = report_dir.join(STAGE_MANIFEST_RELATIVE_PATH);
    if !path.exists() {
        return Ok(None);
    }
    let body = fs::read_to_string(path.as_path())
        .map_err(|err| format!("read stage manifest failed ({}): {err}", path.display()))?;
    serde_json::from_str(&body)
        .map(Some)
        .map_err(|err| format!("parse stage manifest failed ({}): {err}", path.display()))
}

/// Emit a manifest unless one already exists for this run (the wrapper
/// emits before launching bash; a standalone bash run emits its own).
/// Returns the path and whether a new manifest was written.
pub fn ensure_stage_manifest(
    report_dir: &Path,
    run_command: &str,
    run_mode: &str,
    selectors: &TargetSelectors,
) -> Result<(PathBuf, bool), String> {
    let path = report_dir.join(STAGE_MANIFEST_RELATIVE_PATH);
    if path.exists() {
        return Ok((path, false));
    }
    let manifest = build_stage_manifest(run_command, run_mode, selectors);
    let path = write_stage_manifest(report_dir, &manifest)?;
    Ok((path, true))
}

/// `ops emit-stage-manifest` parsed config (the bash orchestrator's entry
/// point into manifest emission; the Rust wrapper calls
/// [`ensure_stage_manifest`] directly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmitStageManifestConfig {
    pub report_dir: PathBuf,
    pub run_command: String,
    pub run_mode: String,
    pub selectors: TargetSelectors,
}

pub fn execute_ops_emit_stage_manifest(config: EmitStageManifestConfig) -> Result<String, String> {
    let (path, written) = ensure_stage_manifest(
        config.report_dir.as_path(),
        config.run_command.as_str(),
        config.run_mode.as_str(),
        &config.selectors,
    )?;
    Ok(if written {
        format!("stage manifest written: {}", path.display())
    } else {
        format!("stage manifest already present: {}", path.display())
    })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_selectors() -> TargetSelectors {
        TargetSelectors {
            wants_macos: true,
            wants_windows: true,
            macos_promote_exit: true,
            exit_platform: "macos".to_owned(),
            relay_platform: "windows".to_owned(),
            anchor_platform: "macos".to_owned(),
            admin_platform: "windows".to_owned(),
            blind_exit_platform: "macos".to_owned(),
            role_switch_platform: "macos".to_owned(),
            skip_linux_live_suite: false,
            chaos_suite: true,
            cross_network_suite: true,
            soak_suite: true,
            local_gate_suite: true,
        }
    }

    #[test]
    fn manifest_covers_every_registry_stage_exactly_once() {
        let manifest = build_stage_manifest("test-run", "full", &TargetSelectors::default());
        let mut names: Vec<&str> = manifest.stages.iter().map(|s| s.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), manifest.stages.len(), "duplicate stage names");
        assert_eq!(
            manifest.stages.len(),
            crate::live_lab_stage_registry::STAGES.len()
        );
    }

    #[test]
    fn manifest_resolves_enablement_and_skip_reasons() {
        // Default selectors: linux-only run — mac/win cells not applicable,
        // linux suite enabled, chaos not selected.
        let manifest = build_stage_manifest("test-run", "full", &TargetSelectors::default());
        let by_name = |name: &str| {
            manifest
                .stages
                .iter()
                .find(|stage| stage.name == name)
                .unwrap_or_else(|| panic!("{name} missing from manifest"))
        };
        assert!(by_name("preflight").enabled);
        assert!(by_name("validate_linux_hello_limiter_flood").enabled);
        let mac_exit = by_name("validate_macos_exit_nat_lifecycle");
        assert!(!mac_exit.enabled);
        assert_eq!(
            mac_exit.skip_reason.as_deref(),
            Some("macOS not elected as exit")
        );
        let chaos = by_name("chaos_daemon_fault");
        assert!(!chaos.enabled);
        assert_eq!(
            chaos.skip_reason.as_deref(),
            Some("chaos suite not selected")
        );

        // With full selectors, exactly the role cells whose platform lost
        // the election stay off: exit went to macOS (windows exit cells +
        // its evidence capture/pull stages off), relay to Windows (macOS
        // relay cell off), anchor to macOS (windows anchor cell off), admin
        // to Windows (macOS admin cell off).
        let full = build_stage_manifest("test-run", "full", &full_selectors());
        let mut disabled: Vec<&str> = full
            .stages
            .iter()
            .filter(|stage| !stage.enabled)
            .map(|stage| stage.name.as_str())
            .collect();
        disabled.sort_unstable();
        assert_eq!(
            disabled,
            vec![
                "capture_windows_exit_evidence_artifacts",
                "promote_windows_exit_active",
                "pull_windows_exit_evidence_artifacts",
                "validate_macos_admin_issue",
                "validate_macos_relay_service_lifecycle",
                "validate_windows_anchor_bundle_pull",
                "validate_windows_exit_dns_failclosed",
                "validate_windows_exit_killswitch_precedence",
                "validate_windows_exit_nat_lifecycle",
            ]
        );
    }

    #[test]
    fn manifest_round_trips_through_report_dir() {
        let dir = std::env::temp_dir().join(format!(
            "stage_manifest_test_{}_{}",
            std::process::id(),
            unix_now()
        ));
        fs::create_dir_all(&dir).expect("create temp report dir");
        let manifest =
            build_stage_manifest("vm-lab-orchestrate-live-lab", "full", &full_selectors());
        let path = write_stage_manifest(dir.as_path(), &manifest).expect("write");
        assert!(path.ends_with(STAGE_MANIFEST_RELATIVE_PATH));
        let loaded = read_stage_manifest(dir.as_path())
            .expect("read")
            .expect("present");
        assert_eq!(loaded, manifest);

        // ensure_stage_manifest is idempotent: second call does not rewrite.
        let (path_again, written) = ensure_stage_manifest(
            dir.as_path(),
            "other-command",
            "full",
            &TargetSelectors::default(),
        )
        .expect("ensure");
        assert_eq!(path_again, path);
        assert!(!written);
        let still = read_stage_manifest(dir.as_path())
            .expect("read")
            .expect("present");
        assert_eq!(
            still.run_command, "vm-lab-orchestrate-live-lab",
            "existing manifest must not be clobbered"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn synthetic_aggregates_are_marked_in_manifest() {
        let manifest = build_stage_manifest("test-run", "full", &TargetSelectors::default());
        let synthetic: Vec<&str> = manifest
            .stages
            .iter()
            .filter(|stage| stage.synthetic)
            .map(|stage| stage.name.as_str())
            .collect();
        assert_eq!(synthetic, vec!["linux_live_suite"]);
    }

    #[test]
    fn wrapper_manifest_exempts_rust_native_dialect_from_barrier() {
        let manifest = build_stage_manifest(
            "vm-lab-orchestrate-live-lab",
            "full",
            &TargetSelectors::default(),
        );
        let membership_init = manifest
            .stages
            .iter()
            .find(|stage| stage.name == "membership_init")
            .expect("membership_init stage");
        assert!(membership_init.enabled);
        assert!(membership_init.barrier_exempt);

        let bash_live = manifest
            .stages
            .iter()
            .find(|stage| stage.name == "live_managed_dns")
            .expect("live_managed_dns stage");
        assert!(bash_live.enabled);
        assert!(!bash_live.barrier_exempt);

        for conditional_preflight in ["restart_unready_vms", "rediscover_local_utm"] {
            let stage = manifest
                .stages
                .iter()
                .find(|stage| stage.name == conditional_preflight)
                .unwrap_or_else(|| panic!("{conditional_preflight} stage"));
            assert!(stage.enabled);
            assert!(stage.barrier_exempt);
        }
    }
}
