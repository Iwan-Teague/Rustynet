//! Run-scoped stage manifest reader (finding 1 of the 2026-07-03 live-lab
//! findings, monitor half).
//!
//! The orchestrators write the resolved plan for each run to
//! `<report_dir>/orchestration/stage_manifest.json` before any stage
//! executes (see rustynet-cli's `live_lab_stage_manifest.rs`). This monitor
//! is deliberately excluded from the cargo workspace, so it cannot share
//! that crate at build time — the manifest is a RUN-TIME data contract, and
//! this module is the monitor-side deserializer. Deserialization is
//! tolerant (serde defaults, unknown fields ignored) so a newer emitter
//! never breaks an older monitor.
//!
//! When a manifest exists, the stage grid renders THE RUN'S OWN plan —
//! every stage name the orchestrators can record, resolved
//! enabled/not-applicable from the selectors that actually launched the
//! run — instead of this binary's hardcoded fallback catalog. That is what
//! makes phantom entries and invisible failure-causing stages structurally
//! impossible for manifest-era runs, and it pins a held run's display to
//! the config that launched it (immune to later config edits).

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

pub const STAGE_MANIFEST_RELATIVE_PATH: &str = "orchestration/stage_manifest.json";

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct RunStageManifest {
    #[serde(default)]
    pub schema_version: u64,
    #[serde(default)]
    pub run_command: String,
    #[serde(default)]
    pub run_mode: String,
    #[serde(default)]
    pub stages: Vec<ManifestStage>,
    /// The node→role topology this run was launched with (Rust `--node` path).
    /// Empty on bash/wrapper runs. The monitor prefers these over the previous
    /// finalized run's roles so VM STATUS reflects the CURRENT run live.
    #[serde(default)]
    pub node_assignments: Vec<ManifestNodeAssignment>,
}

/// One `<alias>:<role>` assignment recorded by the Rust `--node` orchestrator.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ManifestNodeAssignment {
    #[serde(default)]
    pub alias: String,
    #[serde(default)]
    pub role: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ManifestStage {
    pub name: String,
    /// pre | bootstrap | live | chaos | job
    #[serde(default)]
    pub group: String,
    /// common | linux | macos | windows
    #[serde(default)]
    pub stream: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub skip_reason: Option<String>,
    /// Cold-start time budget in seconds.
    #[serde(default)]
    pub budget_secs: u64,
    /// Display-only aggregate; never appears in recorded outcomes.
    #[serde(default)]
    pub synthetic: bool,
    /// True when this stage is a validation/check rather than setup,
    /// cleanup, or display-only plumbing. Schema-v1 manifests omit this;
    /// `None` keeps the UI honest instead of guessing from a stage name.
    #[serde(default)]
    pub counts_as_check: Option<bool>,
}

/// Read the manifest for a report dir. Missing is distinct from malformed:
/// an active run may briefly be waiting for emission, while malformed data is
/// a producer defect that must be shown loudly instead of silently replaced
/// by a plausible-looking local catalog.
pub fn read_stage_manifest(report_dir: &Path) -> Result<Option<RunStageManifest>> {
    let path = report_dir.join(STAGE_MANIFEST_RELATIVE_PATH);
    if !path.exists() {
        return Ok(None);
    }
    let body =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let manifest: RunStageManifest =
        serde_json::from_str(&body).with_context(|| format!("parsing {}", path.display()))?;
    if manifest.stages.is_empty() {
        anyhow::bail!("stage manifest contains no stages: {}", path.display());
    }
    Ok(Some(manifest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parses_the_emitter_shape_and_tolerates_unknowns() {
        let dir = tempfile::tempdir().unwrap();
        let orchestration = dir.path().join("orchestration");
        std::fs::create_dir_all(&orchestration).unwrap();
        // Mirrors rustynet-cli's emitter output, plus an unknown field and
        // a stage missing optional keys — both must parse.
        std::fs::write(
            orchestration.join("stage_manifest.json"),
            r#"{
                "schema_version": 1,
                "generated_at_unix": 1751500000,
                "run_command": "vm-lab-orchestrate-live-lab",
                "run_mode": "full",
                "selectors": {"wants_macos": true, "wants_windows": false,
                              "macos_promote_exit": true, "exit_platform": "",
                              "relay_platform": "", "anchor_platform": "",
                              "admin_platform": "", "blind_exit_platform": "",
                              "skip_linux_live_suite": true, "chaos_suite": false,
                              "cross_network_suite": false},
                "stages": [
                    {"name": "preflight", "group": "pre", "stream": "common",
                     "enabled": true, "budget_secs": 60, "severity": "hard",
                     "synthetic": false, "barrier_exempt": false,
                     "some_future_field": 42},
                    {"name": "activate_macos_exit_role", "group": "live",
                     "stream": "macos", "enabled": true, "budget_secs": 180,
                     "severity": "hard"},
                    {"name": "chaos_daemon_fault", "group": "chaos",
                     "stream": "common", "enabled": false,
                     "skip_reason": "chaos suite not selected",
                     "budget_secs": 300, "severity": "hard"}
                ]
            }"#,
        )
        .unwrap();

        let manifest = read_stage_manifest(dir.path())
            .expect("manifest read")
            .expect("manifest parses");
        assert_eq!(manifest.run_mode, "full");
        assert_eq!(manifest.stages.len(), 3);
        assert!(manifest.stages[0].enabled);
        assert_eq!(manifest.stages[1].group, "live");
        assert!(!manifest.stages[2].enabled);
        assert_eq!(
            manifest.stages[2].skip_reason.as_deref(),
            Some("chaos suite not selected")
        );
    }

    /// Cross-binary contract: a manifest emitted by the REAL rustynet-cli
    /// emitter (ops emit-stage-manifest, captured 2026-07-03 with a macOS
    /// promote-exit / skip-linux-suite selector set) must parse. The
    /// monitor is workspace-excluded, so this committed fixture is the
    /// only CI-visible seam between the two binaries — regenerate it when
    /// the emitter schema version bumps.
    #[test]
    fn real_emitter_output_parses() {
        let dir = tempfile::tempdir().unwrap();
        let orchestration = dir.path().join("orchestration");
        std::fs::create_dir_all(&orchestration).unwrap();
        std::fs::write(
            orchestration.join("stage_manifest.json"),
            include_str!("../../fixtures/stage_manifest_emitted_2026-07-03.json"),
        )
        .unwrap();

        let manifest = read_stage_manifest(dir.path())
            .expect("real emitter output parses")
            .expect("manifest present");
        assert_eq!(manifest.run_command, "vm-lab-orchestrate-live-lab");
        assert_eq!(manifest.run_mode, "full");
        assert!(manifest.stages.len() >= 150, "{}", manifest.stages.len());
        let by_name = |name: &str| {
            manifest
                .stages
                .iter()
                .find(|stage| stage.name == name)
                .unwrap_or_else(|| panic!("{name} missing"))
        };
        assert!(by_name("activate_macos_exit_role").enabled);
        assert!(!by_name("validate_linux_hello_limiter_flood").enabled);
        assert!(
            by_name("validate_linux_hello_limiter_flood")
                .skip_reason
                .is_some()
        );
        assert!(by_name("linux_live_suite").synthetic);
    }

    #[test]
    fn missing_manifest_is_distinct_from_invalid_manifest() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_stage_manifest(dir.path()).unwrap().is_none());

        let orchestration = dir.path().join("orchestration");
        std::fs::create_dir_all(&orchestration).unwrap();
        std::fs::write(
            orchestration.join("stage_manifest.json"),
            r#"{"schema_version": 1, "stages": []}"#,
        )
        .unwrap();
        assert!(read_stage_manifest(dir.path()).is_err());

        std::fs::write(orchestration.join("stage_manifest.json"), "not json").unwrap();
        assert!(read_stage_manifest(dir.path()).is_err());
    }

    #[test]
    fn a_report_dir_that_does_not_exist_at_all_is_missing_not_an_error() {
        // Distinct from `missing_manifest_is_distinct_from_invalid_manifest`,
        // which creates the report dir but omits the manifest file -- here
        // the report dir itself was never created (e.g. queried before the
        // orchestrator has made anything on disk yet).
        let dir = tempfile::tempdir().unwrap();
        let never_created = dir.path().join("does-not-exist-yet");
        assert!(read_stage_manifest(&never_created).unwrap().is_none());
    }

    #[test]
    fn a_genuinely_empty_manifest_file_is_malformed_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let orchestration = dir.path().join("orchestration");
        std::fs::create_dir_all(&orchestration).unwrap();
        std::fs::write(orchestration.join("stage_manifest.json"), "").unwrap();

        assert!(read_stage_manifest(dir.path()).is_err());
    }

    #[test]
    fn non_utf8_bytes_are_malformed_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let orchestration = dir.path().join("orchestration");
        std::fs::create_dir_all(&orchestration).unwrap();
        std::fs::write(
            orchestration.join("stage_manifest.json"),
            [0x7b, 0xff, 0xfe, 0x00, 0x22],
        )
        .unwrap();

        assert!(read_stage_manifest(dir.path()).is_err());
    }

    #[test]
    fn a_manifest_torn_mid_write_is_malformed_not_a_panic() {
        // Simulates a concurrently-writing orchestrator caught exactly
        // mid-write: a syntactically valid JSON prefix that stops abruptly
        // partway through the stages array, as if only part of the buffer
        // had been flushed to disk when this read happened.
        let dir = tempfile::tempdir().unwrap();
        let orchestration = dir.path().join("orchestration");
        std::fs::create_dir_all(&orchestration).unwrap();
        std::fs::write(
            orchestration.join("stage_manifest.json"),
            r#"{"schema_version": 1, "run_mode": "full", "stages": [{"name": "preflight", "grou"#,
        )
        .unwrap();

        assert!(read_stage_manifest(dir.path()).is_err());
    }

    #[test]
    fn a_stage_missing_its_required_name_field_is_rejected_not_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let orchestration = dir.path().join("orchestration");
        std::fs::create_dir_all(&orchestration).unwrap();
        std::fs::write(
            orchestration.join("stage_manifest.json"),
            r#"{"schema_version": 1, "stages": [{"group": "pre", "enabled": true}]}"#,
        )
        .unwrap();

        assert!(read_stage_manifest(dir.path()).is_err());
    }

    #[test]
    fn a_corrupt_write_followed_by_a_valid_write_recovers_on_the_next_read() {
        // "Concurrently updated": the monitor polls every 2s, so a read that
        // lands mid-write today must not poison anything for the NEXT read
        // once the writer finishes. Each `read_stage_manifest` call is
        // independent (no cached/sticky error state), so this is really
        // exercising that property directly.
        let dir = tempfile::tempdir().unwrap();
        let orchestration = dir.path().join("orchestration");
        std::fs::create_dir_all(&orchestration).unwrap();
        let path = orchestration.join("stage_manifest.json");

        std::fs::write(&path, r#"{"schema_version": 1, "stages": [{"nam"#).unwrap();
        assert!(read_stage_manifest(dir.path()).is_err());

        std::fs::write(
            &path,
            r#"{"schema_version": 1, "run_mode": "full", "stages": [{"name": "preflight", "enabled": true}]}"#,
        )
        .unwrap();
        let manifest = read_stage_manifest(dir.path())
            .expect("read succeeds once the write completes")
            .expect("manifest present");
        assert_eq!(manifest.stages.len(), 1);
        assert_eq!(manifest.stages[0].name, "preflight");
    }
}
