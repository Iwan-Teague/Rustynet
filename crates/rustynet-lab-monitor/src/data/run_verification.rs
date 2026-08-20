//! Monitor-side run verification (L0.7c,
//! `LiveLabTestCoverageImplementationDesign_2026-08-19` §3.4).
//!
//! The run-level half of `VerifiedPass`: a stage/run may render release-green
//! only when the run as a whole is verified — the native dialect is declared,
//! the candidate verifier accepted this run's plan, the run was finally
//! promoted, and the required cleanup ran in the current generation. This module
//! reads those run-level artifacts and returns a typed verdict; it never panics
//! and a missing or unreadable artifact is a reason, never a pass. The per-stage
//! "current-generation raw pass" half is applied at the grid.

use std::collections::HashSet;
use std::path::Path;

use serde::Deserialize;

use crate::data::stage_manifest::{NATIVE_EXECUTION_DIALECT, NativeRunManifest};

/// Subset of the CLI's `evidence_verdict.v1.json` the monitor cross-checks.
#[derive(Debug, Clone, Deserialize)]
struct EvidenceVerdictDoc {
    #[serde(default)]
    run_instance_id: String,
    #[serde(default)]
    plan_digest: String,
    #[serde(default)]
    verdict: String,
}

/// Subset of the CLI's `report_state.json` (the final-promotion marker).
#[derive(Debug, Clone, Default, Deserialize)]
struct ReportStateDoc {
    #[serde(default)]
    run_passed: bool,
}

/// Why a run is not release-verified — surfaced so the monitor can explain the
/// specific missing predicate instead of a bare non-green.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnverifiedReason {
    /// No `native_run` block — a bash/wrapper or setup-only run, never a release
    /// candidate on the `--node` engine. Display-only, never release-green.
    NotNativeRun,
    /// A `native_run` block declaring an unrecognized dialect (producer error).
    WrongDialect(String),
    /// No readable candidate verdict artifact.
    NoVerdict,
    /// The verdict was rejected/unavailable/other (carries the raw value).
    VerdictNotPassed(String),
    /// The verdict binds to a different run instance than the manifest.
    VerdictRunMismatch,
    /// The verdict binds to a different resolved plan than the manifest.
    VerdictPlanMismatch,
    /// The run was not finally promoted (`report_state.run_passed != true`).
    NotPromoted,
    /// A required cleanup stage is not a current-generation pass (carries the id).
    CleanupIncomplete(String),
}

/// The run-level half of `VerifiedPass`. `verified` is true only when every
/// run-level predicate holds; the grid still requires each enabled stage to be a
/// current-generation raw pass before a group renders green.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunVerification {
    pub verified: bool,
    pub reason: Option<UnverifiedReason>,
    /// The current run instance (from `native_run`), used to filter stage rows to
    /// this generation. `None` when this is not a native run.
    pub run_instance_id: Option<String>,
}

impl RunVerification {
    fn unverified(reason: UnverifiedReason, run_instance_id: Option<String>) -> Self {
        Self {
            verified: false,
            reason: Some(reason),
            run_instance_id,
        }
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Compute the run-level verification for `report_dir`.
///
/// `native_run` is the parsed manifest's native block (`None` on a bash/setup
/// run). `current_gen_pass_stages` is the set of stage ids that recorded a
/// current-generation raw `pass` in `stages.tsv` — used to confirm the required
/// cleanup actually ran this generation, not in a prior reused run.
pub fn verify_run(
    report_dir: &Path,
    native_run: Option<&NativeRunManifest>,
    current_gen_pass_stages: &HashSet<String>,
) -> RunVerification {
    let native_run = match native_run {
        Some(nr) => nr,
        None => return RunVerification::unverified(UnverifiedReason::NotNativeRun, None),
    };
    let generation = Some(native_run.run_instance_id.clone());

    if native_run.execution_dialect != NATIVE_EXECUTION_DIALECT {
        return RunVerification::unverified(
            UnverifiedReason::WrongDialect(native_run.execution_dialect.clone()),
            generation,
        );
    }

    let verdict: EvidenceVerdictDoc =
        match read_json(&report_dir.join("state/evidence_verdict.v1.json")) {
            Some(v) => v,
            None => return RunVerification::unverified(UnverifiedReason::NoVerdict, generation),
        };
    if verdict.verdict != "passed" {
        return RunVerification::unverified(
            UnverifiedReason::VerdictNotPassed(verdict.verdict),
            generation,
        );
    }
    if verdict.run_instance_id != native_run.run_instance_id {
        return RunVerification::unverified(UnverifiedReason::VerdictRunMismatch, generation);
    }
    if verdict.plan_digest != native_run.resolved_plan_digest {
        return RunVerification::unverified(UnverifiedReason::VerdictPlanMismatch, generation);
    }

    let report_state: ReportStateDoc =
        read_json(&report_dir.join("state/report_state.json")).unwrap_or_default();
    if !report_state.run_passed {
        return RunVerification::unverified(UnverifiedReason::NotPromoted, generation);
    }

    for cleanup_id in &native_run.required_cleanup_stage_ids {
        if !current_gen_pass_stages.contains(cleanup_id) {
            return RunVerification::unverified(
                UnverifiedReason::CleanupIncomplete(cleanup_id.clone()),
                generation,
            );
        }
    }

    RunVerification {
        verified: true,
        reason: None,
        run_instance_id: generation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native(dialect: &str, run: &str, digest: &str, cleanup: &[&str]) -> NativeRunManifest {
        NativeRunManifest {
            execution_dialect: dialect.to_owned(),
            run_instance_id: run.to_owned(),
            plan_kind: "standard".to_owned(),
            resolved_plan_digest: digest.to_owned(),
            required_cleanup_stage_ids: cleanup.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn write_verdict(dir: &Path, run: &str, digest: &str, verdict: &str) {
        let state = dir.join("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join("evidence_verdict.v1.json"),
            format!(
                "{{\"run_instance_id\":\"{run}\",\"plan_digest\":\"{digest}\",\"verdict\":\"{verdict}\"}}"
            ),
        )
        .unwrap();
    }

    fn write_report_state(dir: &Path, run_passed: bool) {
        let state = dir.join("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join("report_state.json"),
            format!("{{\"run_passed\":{run_passed}}}"),
        )
        .unwrap();
    }

    fn pass_set(stages: &[&str]) -> HashSet<String> {
        stages.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn a_fully_verified_native_run_is_verified() {
        let dir = tempfile::tempdir().unwrap();
        write_verdict(dir.path(), "run-1", "digest-1", "passed");
        write_report_state(dir.path(), true);
        let nr = native("native_node_v1", "run-1", "digest-1", &["teardown_full"]);
        let v = verify_run(dir.path(), Some(&nr), &pass_set(&["teardown_full"]));
        assert!(v.verified, "{v:?}");
        assert_eq!(v.run_instance_id.as_deref(), Some("run-1"));
    }

    #[test]
    fn a_bash_run_with_no_native_block_is_never_verified() {
        let dir = tempfile::tempdir().unwrap();
        let v = verify_run(dir.path(), None, &pass_set(&[]));
        assert!(!v.verified);
        assert_eq!(v.reason, Some(UnverifiedReason::NotNativeRun));
    }

    #[test]
    fn a_missing_or_rejected_verdict_blocks_verification() {
        let dir = tempfile::tempdir().unwrap();
        let nr = native("native_node_v1", "run-1", "digest-1", &[]);
        // No verdict on disk.
        let v = verify_run(dir.path(), Some(&nr), &pass_set(&[]));
        assert_eq!(v.reason, Some(UnverifiedReason::NoVerdict));
        // A rejected verdict.
        write_verdict(dir.path(), "run-1", "digest-1", "rejected");
        let v = verify_run(dir.path(), Some(&nr), &pass_set(&[]));
        assert_eq!(
            v.reason,
            Some(UnverifiedReason::VerdictNotPassed("rejected".to_owned()))
        );
    }

    #[test]
    fn a_foreign_run_or_plan_verdict_does_not_verify_this_run() {
        let dir = tempfile::tempdir().unwrap();
        write_report_state(dir.path(), true);
        let nr = native("native_node_v1", "run-1", "digest-1", &[]);
        // Verdict bound to a different run instance.
        write_verdict(dir.path(), "run-OTHER", "digest-1", "passed");
        assert_eq!(
            verify_run(dir.path(), Some(&nr), &pass_set(&[])).reason,
            Some(UnverifiedReason::VerdictRunMismatch)
        );
        // Verdict bound to a different plan digest.
        write_verdict(dir.path(), "run-1", "digest-OTHER", "passed");
        assert_eq!(
            verify_run(dir.path(), Some(&nr), &pass_set(&[])).reason,
            Some(UnverifiedReason::VerdictPlanMismatch)
        );
    }

    #[test]
    fn an_unpromoted_run_is_not_verified_even_with_a_passed_verdict() {
        let dir = tempfile::tempdir().unwrap();
        write_verdict(dir.path(), "run-1", "digest-1", "passed");
        write_report_state(dir.path(), false);
        let nr = native("native_node_v1", "run-1", "digest-1", &[]);
        assert_eq!(
            verify_run(dir.path(), Some(&nr), &pass_set(&[])).reason,
            Some(UnverifiedReason::NotPromoted)
        );
    }

    #[test]
    fn incomplete_current_generation_cleanup_blocks_verification() {
        let dir = tempfile::tempdir().unwrap();
        write_verdict(dir.path(), "run-1", "digest-1", "passed");
        write_report_state(dir.path(), true);
        let nr = native("native_node_v1", "run-1", "digest-1", &["teardown_full"]);
        // teardown_full is NOT in the current-generation pass set.
        let v = verify_run(dir.path(), Some(&nr), &pass_set(&["preflight"]));
        assert_eq!(
            v.reason,
            Some(UnverifiedReason::CleanupIncomplete(
                "teardown_full".to_owned()
            ))
        );
    }

    #[test]
    fn an_unrecognized_dialect_is_a_producer_error() {
        let dir = tempfile::tempdir().unwrap();
        let nr = native("legacy_bash_v0", "run-1", "digest-1", &[]);
        assert_eq!(
            verify_run(dir.path(), Some(&nr), &pass_set(&[])).reason,
            Some(UnverifiedReason::WrongDialect("legacy_bash_v0".to_owned()))
        );
    }
}
