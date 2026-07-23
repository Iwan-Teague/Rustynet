#![forbid(unsafe_code)]

//! Independent evidence verifier for `--node` live-lab runs (spec §4.8,
//! adversarial finding B2; increment A2).
//!
//! Every §4 evidence property is otherwise self-attested by the engine being
//! judged — a rubber-stamping orchestrator emits perfect evidence by
//! construction, and the run-matrix CSV is an unsigned, hand-editable file.
//! This module recomputes §4.1 (manifest completeness), §4.2 (terminal-state
//! taxonomy / the overall verdict), §4.5 (digest-bound manifest ↔ CSV row ↔
//! report_dir cross-check) and §4.6 (marker-last finalizer) **from the raw
//! report_dir artifacts**, and is the authority on "valid run". The
//! orchestrator's self-reported verdict is advisory only. §4.3/§4.4/§4.7 are
//! deliberately NOT here — they are proven by the T5 negative-control suite,
//! not by artifact recomputation.
//!
//! ## Independence rules (spec §4.8)
//!
//! The verdict is a **second implementation** of the run-conclusion
//! algorithm, written against the spec — it never calls the orchestrator's
//! `overall_result` / `apply_conclusion_barrier` / append path, because if
//! that logic is wrong, calling it would hide the bug. The only shared code
//! is pure IO/parsing that defines the artifact FORMATS (not the verdict):
//! - [`crate::live_lab_stage_manifest::read_stage_manifest`] — the plan file,
//! - [`crate::live_lab_stage_recorder::read_rows`] — the positional
//!   `stages.tsv` parser (the same tolerance every consumer applies),
//! - [`crate::live_lab_run_matrix::parse_csv_record`] — the CSV field parser,
//! - [`crate::vm_lab::sha256_hex_bytes`] / [`crate::vm_lab::file_sha256_hex`]
//!   — digest helpers (reusing the existing `sha2` dependency).
//!
//! ## Evidence basis for the recomputed verdict
//!
//! The verdict is recomputed from `state/stages.tsv` UNION
//! `orchestration/orchestrate_result.json` outcomes, per-stage-merged by
//! severity rank. The run-matrix writer's evidence set at append time is
//! `stages.tsv` + its in-process outcome vector; that vector is a SUBSET of
//! what lands in `orchestrate_result.json` (the barrier-exempt reconcile pass
//! appends skipped rows only after the CSV row is locked in). Because the
//! merge keeps the worst status per stage and extra stages can only add
//! `aborted`/`incomplete` flags, this verifier's basis is uniformly at least
//! as strict as the writer's: any divergence from the ledger row is in the
//! conservative direction (never accepting a pass the raw artifacts do not
//! support), which is the correct failure mode for the authority.
//!
//! §4.1 is deliberately narrower: a planned, enabled, non-synthetic,
//! non-barrier-exempt stage must have a TERMINAL status **in `stages.tsv`
//! itself** (the recorder-first contract). An outcome that exists only in
//! `orchestrate_result.json` means the engine bypassed the recorder — that is
//! the silent-evaporation class §4.1 exists to catch.
//!
//! ## Exit codes (the CI gate contract)
//!
//! - `0` — every checked property holds AND the recomputed verdict is `pass`
//!   (a valid pass; safe to count toward a bar).
//! - `2` — every checked property holds but the verdict is not `pass` (valid
//!   evidence of a non-pass — e.g. a T5 negative control failing correctly).
//! - `1` — INVALID: at least one §4 property is violated.
//! - `3` — verifier error (unusable arguments / unreadable report_dir).
//!
//! A plain `verifier && flip` therefore gates on *valid pass*, while T5
//! tooling can distinguish a valid fail (2) from broken evidence (1).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::live_lab_run_matrix::{default_live_lab_node_run_matrix_path, parse_csv_record};
use crate::live_lab_stage_manifest::{StageManifest, read_stage_manifest};
use crate::live_lab_stage_recorder::{STAGES_TSV_RELATIVE_PATH, read_rows};
use crate::vm_lab::{file_sha256_hex, sha256_hex_bytes};

pub const REPORT_STATE_RELATIVE_PATH: &str = "state/report_state.json";
pub const ORCHESTRATE_RESULT_RELATIVE_PATH: &str = "orchestration/orchestrate_result.json";
pub const REPORT_LOCAL_ROW_RELATIVE_PATH: &str = "state/live_lab_run_matrix_row.csv";
/// The sentinel the Rust-native finalizer writes when a run has no setup
/// manifest; anything that is not a 64-char hex digest is treated the same.
const NO_SETUP_MANIFEST_SENTINEL: &str = "rust-native-no-setup-manifest";

// ── The independently re-derived status taxonomy ───────────────────────────
// Second implementation of the closed taxonomy + historical dialects (spec
// §2 / §4.2). Deliberately NOT the run-matrix writer's `normalize_status`,
// but it must accept the same wire strings, because both read the same raw
// files. The NO-VERDICT set (never a pass): skip/skipped, not_run, reused,
// unknown, empty, running, pending.

/// A recorded stage status, normalized into the verdict vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusClass {
    Pass,
    Fail,
    Skip,
    Reused,
    Blocked,
    Aborted,
    TimedOut,
    NotRun,
    NotApplicable,
    /// Live (non-terminal) states and anything unrecognized/empty. For the
    /// verdict these all read as "unknown" (incomplete), exactly as the
    /// run-conclusion algorithm treats them; they are never a pass.
    Running,
    Pending,
    Unknown,
}

impl StatusClass {
    /// Severity rank for per-stage merging (worst status wins; ties keep the
    /// later record). Mirrors the run-conclusion precedence: a `fail`
    /// anywhere dominates everything.
    fn rank(self) -> u8 {
        match self {
            StatusClass::Fail => 8,
            StatusClass::TimedOut => 7,
            StatusClass::Aborted => 6,
            StatusClass::Blocked => 5,
            StatusClass::Pass => 4,
            StatusClass::Skip => 3,
            StatusClass::Reused
            | StatusClass::Unknown
            | StatusClass::Running
            | StatusClass::Pending => 2,
            StatusClass::NotRun => 1,
            StatusClass::NotApplicable => 0,
        }
    }

    /// A terminal outcome: the stage will not change state again this run.
    /// `Unknown` is non-terminal on purpose — an unparseable status cannot
    /// certify completion.
    fn is_terminal(self) -> bool {
        !matches!(
            self,
            StatusClass::Running | StatusClass::Pending | StatusClass::Unknown
        )
    }

    /// Statuses that leave the run incomplete (the no-verdict set §4.2):
    /// never a pass, and they demote a marker-claimed pass to `partial`.
    fn is_incomplete(self) -> bool {
        matches!(
            self,
            StatusClass::Skip
                | StatusClass::NotRun
                | StatusClass::Reused
                | StatusClass::Unknown
                | StatusClass::Running
                | StatusClass::Pending
        )
    }

    fn is_aborted_like(self) -> bool {
        matches!(self, StatusClass::Aborted | StatusClass::TimedOut)
    }
}

/// Classify one raw status string. Absorbs the same historical dialects the
/// recording layers speak; anything else is `Unknown`.
fn classify_status(raw: &str) -> StatusClass {
    match raw.trim().to_ascii_lowercase().as_str() {
        "pass" | "passed" | "success" | "succeeded" | "ok" => StatusClass::Pass,
        "fail" | "failed" | "error" => StatusClass::Fail,
        "skip" | "skipped" => StatusClass::Skip,
        "reused" | "reuse" => StatusClass::Reused,
        "blocked" => StatusClass::Blocked,
        "aborted" | "abort" => StatusClass::Aborted,
        "timed_out" | "timedout" | "timeout" => StatusClass::TimedOut,
        "not_run" | "not-run" | "not run" => StatusClass::NotRun,
        "na" | "n/a" | "not_applicable" | "not-applicable" => StatusClass::NotApplicable,
        "running" => StatusClass::Running,
        "pending" => StatusClass::Pending,
        _ => StatusClass::Unknown,
    }
}

/// A raw status string that is OUTSIDE the closed taxonomy (§4.2 violation).
/// Empty and the literal `unknown` are tolerated as historical no-verdict
/// values — they are never a pass, so they cannot corrupt a verdict.
fn is_taxonomy_violation(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") {
        return false;
    }
    classify_status(raw) == StatusClass::Unknown
}

/// Node-path recorded stage names may be alias-qualified
/// (`debian-1::validate_x`); plan membership is by the bare name.
fn strip_alias_prefix(stage: &str) -> &str {
    stage.rsplit("::").next().unwrap_or(stage)
}

// ── Report structures ───────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct PropertyCheck {
    pub pass: bool,
    pub reasons: Vec<String>,
}

impl PropertyCheck {
    fn passing() -> Self {
        PropertyCheck {
            pass: true,
            reasons: Vec::new(),
        }
    }

    fn fail(&mut self, reason: String) {
        self.pass = false;
        self.reasons.push(reason);
    }

    fn note(&mut self, reason: String) {
        self.reasons.push(reason);
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MarkerSummary {
    pub present: bool,
    pub run_complete: bool,
    pub run_passed: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LedgerRowSummary {
    pub found: bool,
    pub matrix_path: String,
    pub run_id: String,
    pub run_started_utc: String,
    pub overall_result: String,
    pub first_failed_stage: String,
    pub row_role: String,
}

/// The verifier's structured verdict. `valid` is the §4.8 authority answer;
/// `recomputed_overall_result` is the independently derived verdict the
/// ledger row must agree with.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerdictReport {
    pub verifier: &'static str,
    pub schema_version: u64,
    pub report_dir: String,
    pub run_mode: Option<String>,
    pub recomputed_overall_result: String,
    pub recomputed_first_failed_stage: Option<String>,
    pub marker: MarkerSummary,
    /// Marker pass-claim (`run_complete && run_passed`) == recomputed pass.
    /// Informational: a marker-claimed pass demoted to `partial` by
    /// incomplete stages reads `false` here without being a violation.
    pub agreement_with_marker: bool,
    pub ledger_row: LedgerRowSummary,
    pub agreement_with_ledger_row: bool,
    #[serde(rename = "properties")]
    pub properties: PropertyReport,
    /// sha256 of every artifact the verdict was derived from — the verdict is
    /// thereby digest-bound (§4.5): re-verification detects any later edit.
    pub artifact_sha256: BTreeMap<String, String>,
    pub valid: bool,
    pub valid_pass: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PropertyReport {
    #[serde(rename = "4.1_manifest_completeness")]
    pub p4_1_manifest_completeness: PropertyCheck,
    #[serde(rename = "4.2_terminal_state_taxonomy")]
    pub p4_2_terminal_state_taxonomy: PropertyCheck,
    #[serde(rename = "4.5_digest_bound_cross_check")]
    pub p4_5_digest_bound_cross_check: PropertyCheck,
    #[serde(rename = "4.6_marker_last_finalizer")]
    pub p4_6_marker_last_finalizer: PropertyCheck,
}

#[derive(Debug, Clone)]
pub struct VerifierConfig {
    pub report_dir: PathBuf,
    /// Shared `--node` ledger to cross-check; defaults to the repo's
    /// `documents/operations/live_lab_node_run_matrix.csv`.
    pub matrix_path: Option<PathBuf>,
}

// ── Verifier ────────────────────────────────────────────────────────────────

/// Canonical display form of a path — the same normalization the run-matrix
/// writer applies to `report_dir` before recording it, so string comparison
/// against CSV cells is well-defined.
fn canonical_display(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

fn json_bool(value: &serde_json::Value, key: &str) -> bool {
    value.get(key).and_then(serde_json::Value::as_bool) == Some(true)
}

fn json_str<'v>(value: &'v serde_json::Value, key: &str) -> &'v str {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}

/// One merged per-stage outcome (worst status wins).
#[derive(Debug, Clone)]
struct MergedOutcome {
    class: StatusClass,
}

/// Verify one run's evidence. IO-level failures (missing/unreadable
/// report_dir) return `Err`; every judgement about the run itself lands in
/// the report.
pub fn verify(config: &VerifierConfig) -> Result<VerdictReport, String> {
    let report_dir = config.report_dir.as_path();
    if !report_dir.is_dir() {
        return Err(format!(
            "report dir does not exist or is not a directory: {}",
            report_dir.display()
        ));
    }
    let report_dir_display = canonical_display(report_dir);

    let mut p41 = PropertyCheck::passing();
    let mut p42 = PropertyCheck::passing();
    let mut p45 = PropertyCheck::passing();
    let mut p46 = PropertyCheck::passing();
    let mut digests = BTreeMap::new();

    // ── Raw artifact ingest ─────────────────────────────────────────────
    let manifest: Option<StageManifest> = match read_stage_manifest(report_dir) {
        Ok(manifest) => manifest,
        Err(err) => {
            p41.fail(format!("stage manifest unreadable: {err}"));
            None
        }
    };
    let run_mode = manifest.as_ref().map(|m| m.run_mode.clone());

    let stages_tsv_path = report_dir.join(STAGES_TSV_RELATIVE_PATH);
    let tsv_rows = read_rows(report_dir);

    let orchestrate_path = report_dir.join(ORCHESTRATE_RESULT_RELATIVE_PATH);
    let orchestrate_outcomes: Vec<(String, String)> = if orchestrate_path.is_file() {
        match fs::read_to_string(&orchestrate_path)
            .map_err(|err| err.to_string())
            .and_then(|body| {
                serde_json::from_str::<serde_json::Value>(&body).map_err(|err| err.to_string())
            }) {
            Ok(value) => value
                .get("outcomes")
                .and_then(serde_json::Value::as_array)
                .map(|outcomes| {
                    outcomes
                        .iter()
                        .filter_map(|outcome| {
                            let stage = outcome.get("stage")?.as_str()?.to_owned();
                            let status = json_str(outcome, "status").to_owned();
                            Some((stage, status))
                        })
                        .collect()
                })
                .unwrap_or_default(),
            Err(err) => {
                p42.fail(format!("orchestrate_result.json unreadable: {err}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    let marker_path = report_dir.join(REPORT_STATE_RELATIVE_PATH);
    let marker_json: Option<serde_json::Value> = if marker_path.is_file() {
        match fs::read_to_string(&marker_path)
            .map_err(|err| err.to_string())
            .and_then(|body| serde_json::from_str(&body).map_err(|err| err.to_string()))
        {
            Ok(value) => Some(value),
            Err(err) => {
                // An unreadable commit marker can never certify a pass.
                p46.fail(format!("report_state.json unreadable: {err}"));
                None
            }
        }
    } else {
        None
    };
    let marker = MarkerSummary {
        present: marker_json.is_some(),
        run_complete: marker_json
            .as_ref()
            .is_some_and(|v| json_bool(v, "run_complete")),
        run_passed: marker_json
            .as_ref()
            .is_some_and(|v| json_bool(v, "run_passed")),
    };

    // Digest-bind every artifact the verdict is derived from (§4.5).
    for (label, path) in [
        (
            "stage_manifest.json",
            report_dir.join(crate::live_lab_stage_manifest::STAGE_MANIFEST_RELATIVE_PATH),
        ),
        ("stages.tsv", stages_tsv_path.clone()),
        ("report_state.json", marker_path.clone()),
        ("orchestrate_result.json", orchestrate_path.clone()),
        (
            "live_lab_run_matrix_row.csv",
            report_dir.join(REPORT_LOCAL_ROW_RELATIVE_PATH),
        ),
    ] {
        if path.is_file() {
            match file_sha256_hex(&path) {
                Ok(digest) => {
                    digests.insert(label.to_owned(), digest);
                }
                Err(err) => p45.fail(format!("digest {label} failed: {err}")),
            }
        }
    }

    // ── §4.2: taxonomy + the recomputed verdict ─────────────────────────
    // Merge tsv rows then orchestrate outcomes per stage name (full,
    // alias-qualified name — the writer's dedupe key), keeping the worst
    // status; ties keep the later record.
    let mut merged: BTreeMap<String, MergedOutcome> = BTreeMap::new();
    let mut ingest = |stage: &str, raw_status: &str, source: &str, p42: &mut PropertyCheck| {
        if is_taxonomy_violation(raw_status) {
            p42.fail(format!(
                "stage '{stage}' has status '{raw_status}' outside the closed taxonomy ({source})"
            ));
        }
        let class = classify_status(raw_status);
        merged
            .entry(stage.to_owned())
            .and_modify(|existing| {
                if class.rank() >= existing.class.rank() {
                    existing.class = class;
                }
            })
            .or_insert(MergedOutcome { class });
    };
    for row in &tsv_rows {
        ingest(&row.stage, &row.status, "stages.tsv", &mut p42);
    }
    for (stage, status) in &orchestrate_outcomes {
        ingest(stage, status, "orchestrate_result.json", &mut p42);
    }

    // A recorded stage name the manifest does not know (after alias strip)
    // is outside the run's stage vocabulary — the silent-drift class the
    // registry-resolved manifest exists to kill.
    if let Some(manifest) = manifest.as_ref() {
        let manifest_names: BTreeSet<&str> =
            manifest.stages.iter().map(|s| s.name.as_str()).collect();
        for name in merged.keys() {
            if !manifest_names.contains(strip_alias_prefix(name)) {
                p42.fail(format!(
                    "recorded stage '{name}' is not in the run's stage manifest"
                ));
            }
        }
    }

    // Conclusion barrier (§4.1's verdict-side mirror): on a `full` run,
    // every planned enabled non-synthetic non-exempt stage with NO recorded
    // outcome is treated as `aborted` — silent evaporation must not read as
    // a clean run. (The recorded set here spans tsv + orchestrate outcomes,
    // matching the run-conclusion algorithm; the stricter tsv-only demand is
    // §4.1 below.)
    let recorded_stripped: BTreeSet<String> = merged
        .keys()
        .map(|name| strip_alias_prefix(name).to_owned())
        .collect();
    let mut synthesized_aborted: Vec<String> = Vec::new();
    if let Some(manifest) = manifest.as_ref()
        && manifest.run_mode == "full"
    {
        for stage in manifest
            .stages
            .iter()
            .filter(|s| s.enabled && !s.synthetic && !s.barrier_exempt)
        {
            if !recorded_stripped.contains(&stage.name) {
                synthesized_aborted.push(stage.name.clone());
            }
        }
    }

    // The verdict precedence (independently re-derived):
    //   1. any `fail` ⇒ fail (dominates everything, including the marker);
    //   2. else marker run_complete: run_passed ⇒ aborted|partial|pass by
    //      stage states; !run_passed ⇒ fail;
    //   3. else by stage states alone;
    //   4. the no-verdict set is never a pass.
    let any_fail = merged.values().any(|o| o.class == StatusClass::Fail);
    let has_aborted =
        merged.values().any(|o| o.class.is_aborted_like()) || !synthesized_aborted.is_empty();
    let has_incomplete = merged.values().any(|o| o.class.is_incomplete());
    let any_pass = merged.values().any(|o| o.class == StatusClass::Pass);

    let recomputed = if any_fail {
        "fail"
    } else if marker.run_complete {
        if marker.run_passed {
            if has_aborted {
                "aborted"
            } else if has_incomplete {
                "partial"
            } else {
                "pass"
            }
        } else {
            "fail"
        }
    } else if has_aborted {
        "aborted"
    } else if has_incomplete {
        "partial"
    } else if any_pass {
        "pass"
    } else {
        "unknown"
    };
    // First failing stage in the merged (name-ordered) evidence — the same
    // order the ledger writer reports after its dedupe.
    let first_failed = merged
        .iter()
        .find(|(_, outcome)| outcome.class == StatusClass::Fail)
        .map(|(name, _)| name.clone());

    // ── §4.1: manifest completeness (recorder-first, tsv-only) ──────────
    match manifest.as_ref() {
        None => {
            if p41.pass {
                p41.fail("stage manifest missing (orchestration/stage_manifest.json)".to_owned());
            }
        }
        Some(manifest) if manifest.run_mode != "full" => {
            p41.note(format!(
                "run_mode={}: completeness barrier applies to full runs only",
                manifest.run_mode
            ));
        }
        Some(manifest) => {
            // Terminal status per bare stage name, from stages.tsv ONLY.
            let mut tsv_terminal: BTreeSet<&str> = BTreeSet::new();
            let mut tsv_nonterminal: BTreeSet<&str> = BTreeSet::new();
            for row in &tsv_rows {
                let bare = strip_alias_prefix(&row.stage);
                if classify_status(&row.status).is_terminal() {
                    tsv_terminal.insert(bare);
                } else {
                    tsv_nonterminal.insert(bare);
                }
            }
            for stage in manifest
                .stages
                .iter()
                .filter(|s| s.enabled && !s.synthetic && !s.barrier_exempt)
            {
                if tsv_terminal.contains(stage.name.as_str()) {
                    continue;
                }
                if tsv_nonterminal.contains(stage.name.as_str()) {
                    p41.fail(format!(
                        "planned stage '{}' has no TERMINAL status in stages.tsv (still running/pending/unknown)",
                        stage.name
                    ));
                } else {
                    p41.fail(format!(
                        "planned stage '{}' recorded no outcome in stages.tsv (silent evaporation)",
                        stage.name
                    ));
                }
            }
        }
    }

    // ── §4.5: digest-bound manifest ↔ CSV row ↔ report_dir cross-check ──
    let matrix_path = config
        .matrix_path
        .clone()
        .unwrap_or_else(default_live_lab_node_run_matrix_path);
    let ledger_row_summary = cross_check_ledger(
        report_dir,
        report_dir_display.as_str(),
        matrix_path.as_path(),
        recomputed,
        &mut p45,
        &mut digests,
    );

    // Marker ↔ report_dir digest binding: the finalizer records the report
    // dir path and its sha256 inside the marker; a marker copied from a
    // different run (or hand-built with a stale digest) fails here.
    if let Some(marker_json) = marker_json.as_ref() {
        let recorded_path = json_str(marker_json, "report_dir_path");
        let recorded_digest = json_str(marker_json, "report_dir_sha256");
        if !recorded_path.is_empty() {
            let expected = sha256_hex_bytes(recorded_path.as_bytes());
            if recorded_digest != expected {
                p45.fail(format!(
                    "report_state.json report_dir_sha256 does not match its recorded report_dir_path (recorded {recorded_digest}, computed {expected})"
                ));
            }
            if recorded_path != report_dir_display {
                p45.fail(format!(
                    "report_state.json is bound to a different report_dir: marker says '{recorded_path}', verifying '{report_dir_display}'"
                ));
            }
        }
        // Setup-manifest binding: node runs write a sentinel; only a real
        // digest claim is checked, and only against an existing file.
        let setup_digest = json_str(marker_json, "setup_manifest_sha256");
        if setup_digest != NO_SETUP_MANIFEST_SENTINEL
            && setup_digest.len() == 64
            && setup_digest.chars().all(|c| c.is_ascii_hexdigit())
        {
            let setup_path = report_dir.join("state/setup_manifest.json");
            if setup_path.is_file() {
                match file_sha256_hex(&setup_path) {
                    Ok(actual) if actual != setup_digest => p45.fail(format!(
                        "state/setup_manifest.json digest mismatch: marker claims {setup_digest}, file is {actual}"
                    )),
                    Ok(actual) => {
                        digests.insert("setup_manifest.json".to_owned(), actual);
                    }
                    Err(err) => p45.fail(format!("digest setup_manifest.json failed: {err}")),
                }
            } else {
                p45.note(
                    "marker claims a setup_manifest digest but state/setup_manifest.json is absent"
                        .to_owned(),
                );
            }
        }
    }

    // ── §4.6: marker-last finalizer ─────────────────────────────────────
    // Any pass claim — recomputed, ledger row, or report-local row — is only
    // valid over a durable commit marker with run_complete && run_passed. A
    // crash before the marker (or a hand-edited CSV) must never read as a
    // valid pass, regardless of what the CSV says.
    let marker_claims_pass = marker.run_complete && marker.run_passed;
    let ledger_claims_pass = ledger_row_summary.overall_result == "pass";
    if (recomputed == "pass" || ledger_claims_pass) && !marker_claims_pass {
        let claim = if recomputed == "pass" {
            "recomputed verdict is pass"
        } else {
            "ledger row claims pass"
        };
        p46.fail(format!(
            "{claim} but the commit marker does not certify it (present={}, run_complete={}, run_passed={}) — crash-before-marker or hand-edited row",
            marker.present, marker.run_complete, marker.run_passed
        ));
    }

    let agreement_with_marker = marker_claims_pass == (recomputed == "pass");
    let agreement_with_ledger_row =
        ledger_row_summary.found && ledger_row_summary.overall_result == recomputed && p45.pass;

    let valid = p41.pass && p42.pass && p45.pass && p46.pass;
    Ok(VerdictReport {
        verifier: "live_lab_evidence_verifier",
        schema_version: 1,
        report_dir: report_dir_display,
        run_mode,
        recomputed_overall_result: recomputed.to_owned(),
        recomputed_first_failed_stage: first_failed,
        marker,
        agreement_with_marker,
        ledger_row: ledger_row_summary,
        agreement_with_ledger_row,
        properties: PropertyReport {
            p4_1_manifest_completeness: p41,
            p4_2_terminal_state_taxonomy: p42,
            p4_5_digest_bound_cross_check: p45,
            p4_6_marker_last_finalizer: p46,
        },
        artifact_sha256: digests,
        valid,
        valid_pass: valid && recomputed == "pass",
    })
}

/// Locate this run's Final ledger row and cross-check it against the
/// report-local row copy and the recomputed verdict (§4.5 / finding S3).
fn cross_check_ledger(
    report_dir: &Path,
    report_dir_display: &str,
    matrix_path: &Path,
    recomputed: &str,
    p45: &mut PropertyCheck,
    digests: &mut BTreeMap<String, String>,
) -> LedgerRowSummary {
    let mut summary = LedgerRowSummary {
        found: false,
        matrix_path: matrix_path.display().to_string(),
        run_id: String::new(),
        run_started_utc: String::new(),
        overall_result: String::new(),
        first_failed_stage: String::new(),
        row_role: String::new(),
    };

    // 1. The report-local copy of this run's row.
    let local_path = report_dir.join(REPORT_LOCAL_ROW_RELATIVE_PATH);
    let local = match read_single_row_csv(local_path.as_path()) {
        Ok(Some(local)) => local,
        Ok(None) => {
            p45.fail(format!(
                "report-local matrix row missing ({REPORT_LOCAL_ROW_RELATIVE_PATH}) — run never finalized a row"
            ));
            return summary;
        }
        Err(err) => {
            p45.fail(format!("report-local matrix row unreadable: {err}"));
            return summary;
        }
    };
    let local_get = |key: &str| local.get(key).map(String::as_str).unwrap_or("");
    if local_get("row_role") != "final" {
        p45.fail(format!(
            "report-local matrix row is '{}', not 'final' — the run's Final row was never written",
            local_get("row_role")
        ));
    }
    // A local row copied from another run's report dir must not vouch here.
    if local_get("report_dir") != report_dir_display {
        p45.fail(format!(
            "report-local matrix row is bound to a different report_dir: row says '{}', verifying '{report_dir_display}'",
            local_get("report_dir")
        ));
    }
    let key_started = local_get("run_started_utc").to_owned();

    // 2. The shared ledger row for the same (report_dir, run_started_utc)
    //    key with row_role=final.
    let ledger_body = match fs::read_to_string(matrix_path) {
        Ok(body) => body,
        Err(err) => {
            p45.fail(format!(
                "node run-matrix ledger unreadable ({}): {err}",
                matrix_path.display()
            ));
            return summary;
        }
    };
    let mut lines = ledger_body.lines();
    let header = match lines.next() {
        Some(header) if !header.trim().is_empty() => header,
        _ => {
            p45.fail(format!(
                "node run-matrix ledger is empty: {}",
                matrix_path.display()
            ));
            return summary;
        }
    };
    let header_columns = match parse_csv_record(header) {
        Ok(columns) => columns,
        Err(err) => {
            p45.fail(format!("node run-matrix ledger header unparseable: {err}"));
            return summary;
        }
    };
    let column_index = |name: &str| header_columns.iter().position(|column| column == name);
    let (Some(i_report_dir), Some(i_started), Some(i_role)) = (
        column_index("report_dir"),
        column_index("run_started_utc"),
        column_index("row_role"),
    ) else {
        p45.fail(
            "node run-matrix ledger header lacks report_dir/run_started_utc/row_role columns"
                .to_owned(),
        );
        return summary;
    };

    let mut matches: Vec<(Vec<String>, String)> = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(fields) = parse_csv_record(line) else {
            continue; // malformed rows never match — and are never trusted
        };
        let field = |index: usize| fields.get(index).map(String::as_str).unwrap_or("");
        if field(i_report_dir) == report_dir_display
            && field(i_started) == key_started
            && field(i_role) == "final"
        {
            matches.push((fields, line.to_owned()));
        }
    }
    match matches.len() {
        0 => {
            p45.fail(format!(
                "no Final ledger row for report_dir '{report_dir_display}' (run_started_utc '{key_started}') in {}",
                matrix_path.display()
            ));
            return summary;
        }
        1 => {}
        n => {
            p45.fail(format!(
                "{n} Final ledger rows claim the same run key (report_dir + run_started_utc) — duplicate or forged rows"
            ));
            return summary;
        }
    }
    let (ledger_fields, ledger_line) = matches.remove(0);
    let ledger_get = |name: &str| {
        column_index(name)
            .and_then(|index| ledger_fields.get(index))
            .map(String::as_str)
            .unwrap_or("")
    };
    summary.found = true;
    summary.run_id = ledger_get("run_id").to_owned();
    summary.run_started_utc = ledger_get("run_started_utc").to_owned();
    summary.overall_result = ledger_get("overall_result").to_owned();
    summary.first_failed_stage = ledger_get("first_failed_stage").to_owned();
    summary.row_role = ledger_get("row_role").to_owned();
    digests.insert(
        "ledger_row".to_owned(),
        sha256_hex_bytes(ledger_line.as_bytes()),
    );

    // 3. Field-for-field: the report-local copy and the shared-ledger row
    //    must agree on every column the local copy carries. A swapped row or
    //    a column-shift in the positional CSV surfaces here (finding S3).
    let mut mismatched: Vec<String> = Vec::new();
    for (column, local_value) in &local {
        if ledger_get(column) != local_value {
            mismatched.push(column.clone());
        }
    }
    if !mismatched.is_empty() {
        let shown = mismatched
            .iter()
            .take(8)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        p45.fail(format!(
            "report-local row and shared-ledger row disagree on {} column(s): {shown}{}",
            mismatched.len(),
            if mismatched.len() > 8 { ", …" } else { "" }
        ));
    }

    // 4. The ledger's verdict must equal the independently recomputed one —
    //    a rubber-stamped or hand-edited overall_result surfaces here.
    if summary.overall_result != recomputed {
        p45.fail(format!(
            "ledger row overall_result '{}' disagrees with the independently recomputed verdict '{recomputed}'",
            summary.overall_result
        ));
    }
    summary
}

/// Read a one-row CSV (header + exactly one data row) into column → value.
fn read_single_row_csv(path: &Path) -> Result<Option<BTreeMap<String, String>>, String> {
    if !path.is_file() {
        return Ok(None);
    }
    let body = fs::read_to_string(path)
        .map_err(|err| format!("read failed ({}): {err}", path.display()))?;
    let mut lines = body.lines().filter(|line| !line.trim().is_empty());
    let header = lines
        .next()
        .ok_or_else(|| format!("empty CSV: {}", path.display()))?;
    let row = lines
        .next()
        .ok_or_else(|| format!("CSV has a header but no data row: {}", path.display()))?;
    if lines.next().is_some() {
        return Err(format!("expected exactly one data row: {}", path.display()));
    }
    let columns = parse_csv_record(header)?;
    let fields = parse_csv_record(row)?;
    Ok(Some(
        columns
            .into_iter()
            .enumerate()
            .map(|(index, column)| (column, fields.get(index).cloned().unwrap_or_default()))
            .collect(),
    ))
}

// ── Output rendering + exit codes ───────────────────────────────────────────

/// Exit code contract (see module docs): 0 valid pass, 2 valid non-pass,
/// 1 invalid.
pub fn exit_code(report: &VerdictReport) -> i32 {
    if !report.valid {
        1
    } else if report.valid_pass {
        0
    } else {
        2
    }
}

pub fn render_json(report: &VerdictReport) -> String {
    serde_json::to_string_pretty(report)
        .unwrap_or_else(|err| format!("{{\"error\":\"serialize verdict failed: {err}\"}}"))
}

pub fn render_human(report: &VerdictReport) -> String {
    let mut out = String::new();
    let verdict_line = |check: &PropertyCheck| if check.pass { "PASS" } else { "FAIL" };
    out.push_str(&format!(
        "live-lab evidence verifier — report_dir: {}\n",
        report.report_dir
    ));
    out.push_str(&format!(
        "recomputed overall_result: {}{}\n",
        report.recomputed_overall_result,
        report
            .recomputed_first_failed_stage
            .as_deref()
            .map(|stage| format!(" (first failed: {stage})"))
            .unwrap_or_default()
    ));
    out.push_str(&format!(
        "commit marker: present={} run_complete={} run_passed={} (agreement: {})\n",
        report.marker.present,
        report.marker.run_complete,
        report.marker.run_passed,
        report.agreement_with_marker
    ));
    if report.ledger_row.found {
        out.push_str(&format!(
            "ledger row: run_id={} overall_result={} row_role={} (agreement: {})\n",
            report.ledger_row.run_id,
            report.ledger_row.overall_result,
            report.ledger_row.row_role,
            report.agreement_with_ledger_row
        ));
    } else {
        out.push_str(&format!(
            "ledger row: NOT FOUND in {}\n",
            report.ledger_row.matrix_path
        ));
    }
    for (name, check) in [
        (
            "§4.1 manifest completeness",
            &report.properties.p4_1_manifest_completeness,
        ),
        (
            "§4.2 terminal-state taxonomy",
            &report.properties.p4_2_terminal_state_taxonomy,
        ),
        (
            "§4.5 digest-bound cross-check",
            &report.properties.p4_5_digest_bound_cross_check,
        ),
        (
            "§4.6 marker-last finalizer",
            &report.properties.p4_6_marker_last_finalizer,
        ),
    ] {
        out.push_str(&format!("{name}: {}\n", verdict_line(check)));
        for reason in &check.reasons {
            out.push_str(&format!("  - {reason}\n"));
        }
    }
    for (artifact, digest) in &report.artifact_sha256 {
        out.push_str(&format!("sha256 {artifact}: {digest}\n"));
    }
    out.push_str(&format!(
        "VERDICT: {}\n",
        if report.valid_pass {
            "VALID PASS"
        } else if report.valid {
            "VALID (not a pass)"
        } else {
            "INVALID"
        }
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live_lab_stage_manifest::{
        ManifestSelectors, ManifestStage, STAGE_MANIFEST_SCHEMA_VERSION, StageManifest,
        write_stage_manifest,
    };

    // ── Fixture builders ────────────────────────────────────────────────

    fn stage(name: &str, enabled: bool, synthetic: bool, barrier_exempt: bool) -> ManifestStage {
        ManifestStage {
            name: name.to_owned(),
            group: "live".to_owned(),
            stream: "common".to_owned(),
            enabled,
            skip_reason: (!enabled).then(|| "not planned".to_owned()),
            budget_secs: 60,
            severity: "hard".to_owned(),
            synthetic,
            counts_as_check: true,
            barrier_exempt,
        }
    }

    fn write_manifest(dir: &Path, run_mode: &str, stages: Vec<ManifestStage>) {
        let manifest = StageManifest {
            schema_version: STAGE_MANIFEST_SCHEMA_VERSION,
            generated_at_unix: 0,
            run_command: "vm-lab-orchestrate-live-lab".to_owned(),
            run_mode: run_mode.to_owned(),
            selectors: ManifestSelectors::default(),
            stages,
            node_assignments: Vec::new(),
        };
        write_stage_manifest(dir, &manifest).expect("write manifest");
    }

    fn write_stages_tsv(dir: &Path, rows: &[(&str, &str)]) {
        let state = dir.join("state");
        std::fs::create_dir_all(&state).expect("mkdir state");
        let body: String = rows
            .iter()
            .map(|(stage, status)| {
                format!("{stage}\thard\t{status}\t0\t/logs/{stage}.log\t\tT0\tT1\n")
            })
            .collect();
        std::fs::write(dir.join(STAGES_TSV_RELATIVE_PATH), body).expect("write stages.tsv");
    }

    fn write_marker(dir: &Path, run_complete: bool, run_passed: bool) {
        let state = dir.join("state");
        std::fs::create_dir_all(&state).expect("mkdir state");
        let path = canonical_display(dir);
        let marker = serde_json::json!({
            "version": 1,
            "created_at_unix": 0,
            "updated_at_unix": 0,
            "report_dir_path": path,
            "report_dir_sha256": sha256_hex_bytes(path.as_bytes()),
            "setup_manifest_sha256": "rust-native-no-setup-manifest",
            "setup_complete": false,
            "run_complete": run_complete,
            "run_passed": run_passed,
            "full_release_gate_requested": false,
            "full_release_evidence_complete": false,
            "last_run": null,
        });
        std::fs::write(
            dir.join(REPORT_STATE_RELATIVE_PATH),
            serde_json::to_string_pretty(&marker).expect("serialize marker"),
        )
        .expect("write marker");
    }

    const FIXTURE_SCHEMA: &[&str] = &[
        "run_id",
        "run_started_utc",
        "run_finished_utc",
        "git_commit",
        "report_dir",
        "run_command",
        "overall_result",
        "first_failed_stage",
        "notes",
        "row_role",
    ];

    fn fixture_row(dir: &Path, overall_result: &str, first_failed: &str, row_role: &str) -> String {
        [
            "livelab-1-abc",
            "2026-07-23T00:00:00Z",
            "2026-07-23T01:00:00Z",
            "deadbeef",
            canonical_display(dir).as_str(),
            "vm-lab-orchestrate-live-lab",
            overall_result,
            first_failed,
            "",
            row_role,
        ]
        .join(",")
    }

    fn write_local_row(dir: &Path, row: &str) {
        std::fs::create_dir_all(dir.join("state")).expect("mkdir state");
        std::fs::write(
            dir.join(REPORT_LOCAL_ROW_RELATIVE_PATH),
            format!("{}\n{row}\n", FIXTURE_SCHEMA.join(",")),
        )
        .expect("write local row");
    }

    fn write_ledger(path: &Path, rows: &[&str]) {
        let mut body = format!("{}\n", FIXTURE_SCHEMA.join(","));
        for row in rows {
            body.push_str(row);
            body.push('\n');
        }
        std::fs::write(path, body).expect("write ledger");
    }

    /// A complete, coherent fixture: two planned stages both `pass` in
    /// stages.tsv, marker committed+passed, matching Final row in the local
    /// copy and the shared ledger.
    fn valid_pass_fixture(root: &Path) -> (PathBuf, PathBuf) {
        let report_dir = root.join("report");
        std::fs::create_dir_all(&report_dir).expect("mkdir report");
        write_manifest(
            &report_dir,
            "full",
            vec![
                stage("preflight", true, false, false),
                stage("cleanup", true, false, false),
                stage("job_marker", true, false, true),
                stage("linux_live_suite", true, true, false),
                stage("not_planned_stage", false, false, false),
            ],
        );
        write_stages_tsv(&report_dir, &[("preflight", "pass"), ("cleanup", "pass")]);
        write_marker(&report_dir, true, true);
        let row = fixture_row(&report_dir, "pass", "", "final");
        write_local_row(&report_dir, &row);
        let ledger = root.join("ledger.csv");
        write_ledger(&ledger, &[&row]);
        (report_dir, ledger)
    }

    fn run_verify(report_dir: &Path, ledger: &Path) -> VerdictReport {
        verify(&VerifierConfig {
            report_dir: report_dir.to_path_buf(),
            matrix_path: Some(ledger.to_path_buf()),
        })
        .expect("verify")
    }

    // ── (a) a valid pass run verifies OK ────────────────────────────────

    #[test]
    fn valid_pass_run_verifies_ok() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        let report = run_verify(&report_dir, &ledger);
        assert_eq!(report.recomputed_overall_result, "pass");
        assert!(report.properties.p4_1_manifest_completeness.pass);
        assert!(report.properties.p4_2_terminal_state_taxonomy.pass);
        assert!(
            report.properties.p4_5_digest_bound_cross_check.pass,
            "reasons: {:?}",
            report.properties.p4_5_digest_bound_cross_check.reasons
        );
        assert!(report.properties.p4_6_marker_last_finalizer.pass);
        assert!(report.valid && report.valid_pass);
        assert!(report.agreement_with_marker);
        assert!(report.agreement_with_ledger_row);
        assert_eq!(exit_code(&report), 0);
        // The verdict is digest-bound to the raw artifacts it was derived from.
        for artifact in [
            "stage_manifest.json",
            "stages.tsv",
            "report_state.json",
            "live_lab_run_matrix_row.csv",
            "ledger_row",
        ] {
            assert!(
                report.artifact_sha256.contains_key(artifact),
                "digest for {artifact} missing"
            );
        }
        let human = render_human(&report);
        assert!(human.contains("VALID PASS"), "{human}");
        assert!(render_json(&report).contains("\"valid_pass\": true"));
    }

    // ── (b) planned stage missing from stages.tsv ⇒ §4.1 INVALID ───────

    #[test]
    fn missing_planned_stage_is_silent_evaporation() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        // Drop `cleanup` from stages.tsv; manifest still plans it.
        write_stages_tsv(&report_dir, &[("preflight", "pass")]);
        let report = run_verify(&report_dir, &ledger);
        assert!(!report.properties.p4_1_manifest_completeness.pass);
        assert!(
            report.properties.p4_1_manifest_completeness.reasons[0].contains("cleanup"),
            "{:?}",
            report.properties.p4_1_manifest_completeness.reasons
        );
        // The conclusion barrier demotes the verdict too: the evaporated
        // stage reads `aborted`, so the marker's pass cannot survive.
        assert_eq!(report.recomputed_overall_result, "aborted");
        assert!(!report.valid);
        assert_eq!(exit_code(&report), 1);
    }

    #[test]
    fn running_stage_is_not_a_terminal_outcome() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        write_stages_tsv(
            &report_dir,
            &[("preflight", "pass"), ("cleanup", "running")],
        );
        let report = run_verify(&report_dir, &ledger);
        assert!(!report.properties.p4_1_manifest_completeness.pass);
        assert!(
            report.properties.p4_1_manifest_completeness.reasons[0].contains("TERMINAL"),
            "{:?}",
            report.properties.p4_1_manifest_completeness.reasons
        );
        assert!(!report.valid);
    }

    #[test]
    fn missing_manifest_fails_completeness() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        std::fs::remove_file(
            report_dir.join(crate::live_lab_stage_manifest::STAGE_MANIFEST_RELATIVE_PATH),
        )
        .expect("remove manifest");
        let report = run_verify(&report_dir, &ledger);
        assert!(!report.properties.p4_1_manifest_completeness.pass);
        assert!(!report.valid);
    }

    // ── (c) a fail stage ⇒ verdict fail even when marker/CSV say pass ──

    #[test]
    fn fail_stage_dominates_marker_and_csv_pass_claims() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        write_stages_tsv(&report_dir, &[("preflight", "pass"), ("cleanup", "fail")]);
        // Marker + both CSV rows still (fraudulently) claim pass.
        let report = run_verify(&report_dir, &ledger);
        assert_eq!(report.recomputed_overall_result, "fail");
        assert_eq!(
            report.recomputed_first_failed_stage.as_deref(),
            Some("cleanup")
        );
        assert!(!report.properties.p4_5_digest_bound_cross_check.pass);
        assert!(!report.agreement_with_marker);
        assert!(!report.agreement_with_ledger_row);
        assert!(!report.valid);
        assert_eq!(exit_code(&report), 1);
    }

    // ── (d) reused/skipped are never a pass (§4.2) ──────────────────────

    #[test]
    fn reused_and_skipped_never_count_as_pass() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        write_stages_tsv(
            &report_dir,
            &[("preflight", "reused"), ("cleanup", "skipped")],
        );
        // The rows claim pass; the recomputed verdict must demote to partial.
        let report = run_verify(&report_dir, &ledger);
        assert_eq!(report.recomputed_overall_result, "partial");
        assert!(!report.properties.p4_5_digest_bound_cross_check.pass);
        assert!(!report.valid);

        // With an HONEST partial row, the evidence is valid — but it is
        // still not a pass (exit 2, never 0).
        let row = fixture_row(&report_dir, "partial", "", "final");
        write_local_row(&report_dir, &row);
        write_ledger(&ledger, &[&row]);
        let report = run_verify(&report_dir, &ledger);
        assert_eq!(report.recomputed_overall_result, "partial");
        assert!(report.valid, "reasons: {:?}", report.properties);
        assert!(!report.valid_pass);
        assert_eq!(exit_code(&report), 2);
    }

    #[test]
    fn out_of_taxonomy_status_violates_4_2() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        write_stages_tsv(&report_dir, &[("preflight", "pass"), ("cleanup", "banana")]);
        let report = run_verify(&report_dir, &ledger);
        assert!(!report.properties.p4_2_terminal_state_taxonomy.pass);
        assert!(!report.valid);
    }

    #[test]
    fn recorded_stage_outside_the_manifest_violates_4_2() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        write_stages_tsv(
            &report_dir,
            &[
                ("preflight", "pass"),
                ("cleanup", "pass"),
                ("mystery_stage", "pass"),
            ],
        );
        let report = run_verify(&report_dir, &ledger);
        assert!(!report.properties.p4_2_terminal_state_taxonomy.pass);
        assert!(!report.valid);
    }

    // ── (e) marker missing / run_passed=false ⇒ never a valid pass ─────

    #[test]
    fn missing_marker_is_never_a_valid_pass() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        std::fs::remove_file(report_dir.join(REPORT_STATE_RELATIVE_PATH)).expect("remove marker");
        // All stages pass and the CSV says pass — but there is no durable
        // commit marker (crash before step 10).
        let report = run_verify(&report_dir, &ledger);
        assert_eq!(report.recomputed_overall_result, "pass");
        assert!(!report.properties.p4_6_marker_last_finalizer.pass);
        assert!(!report.valid);
        assert!(!report.valid_pass);
        assert_eq!(exit_code(&report), 1);
    }

    #[test]
    fn run_passed_false_is_never_a_valid_pass() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        write_marker(&report_dir, true, false);
        // CSV still claims pass; the recomputed verdict is fail
        // (run_complete && !run_passed) and the row disagrees.
        let report = run_verify(&report_dir, &ledger);
        assert_eq!(report.recomputed_overall_result, "fail");
        assert!(!report.properties.p4_5_digest_bound_cross_check.pass);
        assert!(
            !report.properties.p4_6_marker_last_finalizer.pass,
            "a ledger pass claim without a certifying marker violates §4.6"
        );
        assert!(!report.valid_pass);
        assert_eq!(exit_code(&report), 1);
    }

    #[test]
    fn honest_valid_fail_run_passes_all_properties() {
        // A correctly-adjudicated RED run (T5-style) must verify as VALID —
        // coherent evidence of a fail — with exit code 2, never 0.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        write_stages_tsv(&report_dir, &[("preflight", "pass"), ("cleanup", "fail")]);
        write_marker(&report_dir, true, false);
        let row = fixture_row(&report_dir, "fail", "cleanup", "final");
        write_local_row(&report_dir, &row);
        write_ledger(&ledger, &[&row]);
        let report = run_verify(&report_dir, &ledger);
        assert_eq!(report.recomputed_overall_result, "fail");
        assert!(report.valid, "properties: {:?}", report.properties);
        assert!(!report.valid_pass);
        assert!(report.agreement_with_marker);
        assert!(report.agreement_with_ledger_row);
        assert_eq!(exit_code(&report), 2);
    }

    // ── (f) ledger overall_result disagreeing with recomputation ───────

    #[test]
    fn hand_edited_ledger_verdict_is_detected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        write_stages_tsv(&report_dir, &[("preflight", "pass"), ("cleanup", "fail")]);
        write_marker(&report_dir, true, false);
        // Both row copies hand-edited to pass (a consistent forgery, so the
        // field-for-field check alone cannot see it).
        let row = fixture_row(&report_dir, "pass", "", "final");
        write_local_row(&report_dir, &row);
        write_ledger(&ledger, &[&row]);
        let report = run_verify(&report_dir, &ledger);
        assert_eq!(report.recomputed_overall_result, "fail");
        assert!(!report.properties.p4_5_digest_bound_cross_check.pass);
        assert!(
            report
                .properties
                .p4_5_digest_bound_cross_check
                .reasons
                .iter()
                .any(|reason| reason.contains("disagrees with the independently recomputed")),
            "{:?}",
            report.properties.p4_5_digest_bound_cross_check.reasons
        );
        assert!(!report.valid);
        assert_eq!(exit_code(&report), 1);
    }

    // ── (g) report-local row vs shared-ledger row mismatch (S3) ────────

    #[test]
    fn swapped_or_shifted_ledger_row_is_detected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        // Ledger row for the same run key differs from the report-local copy
        // (e.g. a column shift moved values around: run_id and git_commit
        // fields no longer match the run's own record).
        let forged = [
            "livelab-OTHER-run",
            "2026-07-23T00:00:00Z",
            "2026-07-23T01:00:00Z",
            "0000000",
            canonical_display(&report_dir).as_str(),
            "vm-lab-orchestrate-live-lab",
            "pass",
            "",
            "",
            "final",
        ]
        .join(",");
        write_ledger(&ledger, &[&forged]);
        let report = run_verify(&report_dir, &ledger);
        assert!(!report.properties.p4_5_digest_bound_cross_check.pass);
        assert!(
            report
                .properties
                .p4_5_digest_bound_cross_check
                .reasons
                .iter()
                .any(|reason| reason.contains("disagree on")),
            "{:?}",
            report.properties.p4_5_digest_bound_cross_check.reasons
        );
        assert!(!report.valid);
    }

    #[test]
    fn missing_final_ledger_row_is_detected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        // Only an interim row (or a row for another dir) in the ledger.
        let interim = fixture_row(&report_dir, "pass", "", "interim");
        write_ledger(&ledger, &[&interim]);
        let report = run_verify(&report_dir, &ledger);
        assert!(!report.properties.p4_5_digest_bound_cross_check.pass);
        assert!(!report.ledger_row.found);
        assert!(!report.valid);
    }

    #[test]
    fn marker_bound_to_a_different_report_dir_is_detected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        // A marker copied from another run: internally consistent digest,
        // but bound to a different report_dir path.
        let foreign = "/somewhere/else/live-lab-other";
        let marker = serde_json::json!({
            "report_dir_path": foreign,
            "report_dir_sha256": sha256_hex_bytes(foreign.as_bytes()),
            "setup_manifest_sha256": "rust-native-no-setup-manifest",
            "run_complete": true,
            "run_passed": true,
        });
        std::fs::write(
            report_dir.join(REPORT_STATE_RELATIVE_PATH),
            serde_json::to_string_pretty(&marker).expect("serialize"),
        )
        .expect("write marker");
        let report = run_verify(&report_dir, &ledger);
        assert!(!report.properties.p4_5_digest_bound_cross_check.pass);
        assert!(
            report
                .properties
                .p4_5_digest_bound_cross_check
                .reasons
                .iter()
                .any(|reason| reason.contains("different report_dir")),
            "{:?}",
            report.properties.p4_5_digest_bound_cross_check.reasons
        );
        assert!(!report.valid);
    }

    #[test]
    fn setup_only_run_mode_skips_the_completeness_barrier() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        write_manifest(
            &report_dir,
            "setup_only",
            vec![
                stage("preflight", true, false, false),
                stage("cleanup", true, false, false),
            ],
        );
        write_stages_tsv(&report_dir, &[("preflight", "pass")]);
        // No barrier: the missing `cleanup` outcome is legitimate here.
        let report = run_verify(&report_dir, &ledger);
        assert!(report.properties.p4_1_manifest_completeness.pass);
        // The verdict is still marker-pass (no synthesized aborted).
        assert_eq!(report.recomputed_overall_result, "pass");
    }

    #[test]
    fn orchestrate_only_outcome_does_not_satisfy_recorder_first_4_1() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        write_stages_tsv(&report_dir, &[("preflight", "pass")]);
        // `cleanup` finished ONLY per orchestrate_result.json — the engine
        // bypassed the recorder. §4.1 must still flag it; the verdict-side
        // barrier must NOT double-count it as aborted.
        std::fs::create_dir_all(report_dir.join("orchestration")).expect("mkdir");
        std::fs::write(
            report_dir.join(ORCHESTRATE_RESULT_RELATIVE_PATH),
            serde_json::json!({
                "command": "vm-lab-orchestrate-live-lab",
                "overall_status": "pass",
                "outcomes": [
                    {"stage": "preflight", "status": "pass", "artifacts": []},
                    {"stage": "cleanup", "status": "pass", "artifacts": []},
                ],
            })
            .to_string(),
        )
        .expect("write orchestrate_result");
        let report = run_verify(&report_dir, &ledger);
        assert!(!report.properties.p4_1_manifest_completeness.pass);
        // Verdict-side: cleanup counts as recorded (pass), so the verdict
        // stays pass and the ledger row still agrees.
        assert_eq!(report.recomputed_overall_result, "pass");
        assert!(!report.valid);
    }

    #[test]
    fn alias_qualified_rows_satisfy_the_plan_and_keep_their_full_name() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        write_stages_tsv(
            &report_dir,
            &[("debian-1::preflight", "pass"), ("cleanup", "fail")],
        );
        write_marker(&report_dir, true, false);
        let row = fixture_row(&report_dir, "fail", "cleanup", "final");
        write_local_row(&report_dir, &row);
        write_ledger(&ledger, &[&row]);
        let report = run_verify(&report_dir, &ledger);
        // The alias-qualified row satisfies §4.1 for `preflight`.
        assert!(
            report.properties.p4_1_manifest_completeness.pass,
            "{:?}",
            report.properties.p4_1_manifest_completeness.reasons
        );
        assert_eq!(report.recomputed_overall_result, "fail");
        assert!(report.valid);
    }

    #[test]
    fn duplicate_final_rows_for_one_run_key_are_detected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        let row = fixture_row(&report_dir, "pass", "", "final");
        write_ledger(&ledger, &[&row, &row]);
        let report = run_verify(&report_dir, &ledger);
        assert!(!report.properties.p4_5_digest_bound_cross_check.pass);
        assert!(!report.valid);
    }

    #[test]
    fn exit_codes_follow_the_gate_contract() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (report_dir, ledger) = valid_pass_fixture(tmp.path());
        assert_eq!(exit_code(&run_verify(&report_dir, &ledger)), 0);
        // Nonexistent report dir is a verifier error, not a verdict.
        assert!(
            verify(&VerifierConfig {
                report_dir: tmp.path().join("nope"),
                matrix_path: Some(ledger),
            })
            .is_err()
        );
    }
}
