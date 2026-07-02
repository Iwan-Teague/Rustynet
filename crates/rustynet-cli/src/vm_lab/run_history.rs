//! FIS-0006: SPRT/CUSUM flake-vs-regression classifier over the live-lab
//! run matrix.
//!
//! Per-(topology-signature) outcome series are Bernoulli-coded
//! (pass=0, fail=1) in the matrix's append order. Two classical sequential
//! detectors run per cell: Wald's SPRT (flaky-stationary vs regressed) and
//! Page's CUSUM (shift latch). The critical census finding is honored:
//! a Bernoulli detector has NO signal on a degenerate all-fail series, so
//! those cells are classified on `first_failed_stage` identity CHURN
//! instead (the signal `trend_verdict` already keys on) — stable failure
//! mode = stuck, churning failure mode = moving. The pooled baseline p0 is
//! held OUT of the cell under test to avoid circularity; a single global
//! pooled p0 is the documented interim under-fit.

use std::collections::BTreeMap;
use std::path::Path;

use crate::live_lab_run_matrix::parse_csv_record;

const TOPOLOGY_COLUMN: usize = 11;
const OVERALL_RESULT_COLUMN: usize = 12;
const FIRST_FAILED_STAGE_COLUMN: usize = 13;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CusumVerdict {
    /// Failure rate shifted UP from baseline: regression signature.
    ShiftUp,
    /// Failure rate shifted DOWN: improvement.
    ShiftDown,
}

/// Page's CUSUM (Biometrika 1954): two one-sided cumulative sums with
/// slack `k` = half the shift to detect and decision interval `h`.
#[derive(Debug, Clone)]
pub struct CusumDetector {
    sum_pos: f64,
    sum_neg: f64,
    k: f64,
    h: f64,
    baseline_p0: f64,
}

impl CusumDetector {
    pub fn new(baseline_p0: f64, shift_to_detect_p1: f64, target_false_alarm_arl: f64) -> Self {
        let k = (shift_to_detect_p1 - baseline_p0).abs() / 2.0;
        let h = if target_false_alarm_arl < 100.0 {
            3.0
        } else {
            5.0
        };
        Self {
            sum_pos: 0.0,
            sum_neg: 0.0,
            k,
            h,
            baseline_p0,
        }
    }

    pub fn update(&mut self, is_failure: bool) -> Option<CusumVerdict> {
        let x = if is_failure { 1.0 } else { 0.0 } - self.baseline_p0;
        self.sum_pos = (self.sum_pos + x - self.k).max(0.0);
        self.sum_neg = (self.sum_neg - x - self.k).max(0.0);
        if self.sum_pos > self.h {
            Some(CusumVerdict::ShiftUp)
        } else if self.sum_neg > self.h {
            Some(CusumVerdict::ShiftDown)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SprtVerdict {
    /// Accept H1: the cell's failure rate is at the regressed level p1.
    Regression,
    /// Accept H0: stationary flakiness at the baseline level p0.
    FlakyStationary,
}

/// Wald's SPRT (1945): sequential log-likelihood ratio between
/// H0 (stationary flaky, rate p0) and H1 (regressed, rate p1), with
/// error-rate-derived acceptance bounds.
#[derive(Debug, Clone)]
pub struct SprtClassifier {
    llr: f64,
    p0: f64,
    p1: f64,
    a_threshold: f64,
    b_threshold: f64,
    pub observations: u32,
}

impl SprtClassifier {
    pub fn new(p0: f64, p1: f64, alpha: f64, beta: f64) -> Self {
        let a_threshold = ((1.0 - beta) / alpha).ln();
        let b_threshold = (beta / (1.0 - alpha)).ln();
        Self {
            llr: 0.0,
            p0,
            p1,
            a_threshold,
            b_threshold,
            observations: 0,
        }
    }

    pub fn update(&mut self, is_failure: bool) -> Option<SprtVerdict> {
        let likelihood = if is_failure {
            self.p1 / self.p0
        } else {
            (1.0 - self.p1) / (1.0 - self.p0)
        };
        self.llr += likelihood.ln();
        self.observations += 1;
        if self.llr >= self.a_threshold {
            Some(SprtVerdict::Regression)
        } else if self.llr <= self.b_threshold {
            Some(SprtVerdict::FlakyStationary)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct CellOutcome {
    pub failed: bool,
    pub first_failed_stage: String,
}

#[derive(Debug, Clone)]
pub struct CellReport {
    pub key: String,
    pub runs: usize,
    pub failures: usize,
    pub label: String,
}

/// Group matrix rows into per-topology outcome series (append order).
/// Rows with an `unknown` overall result carry no pass/fail evidence and
/// are skipped.
pub fn collect_cell_series(rows: &[Vec<String>]) -> BTreeMap<String, Vec<CellOutcome>> {
    let mut cells: BTreeMap<String, Vec<CellOutcome>> = BTreeMap::new();
    for row in rows {
        let Some(result) = row.get(OVERALL_RESULT_COLUMN) else {
            continue;
        };
        let failed = match result.trim().to_ascii_lowercase().as_str() {
            "pass" => false,
            "fail" => true,
            _ => continue,
        };
        let key = row
            .get(TOPOLOGY_COLUMN)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "(no topology)".to_owned());
        let first_failed_stage = row
            .get(FIRST_FAILED_STAGE_COLUMN)
            .map(|value| value.trim().to_owned())
            .unwrap_or_default();
        cells.entry(key).or_default().push(CellOutcome {
            failed,
            first_failed_stage,
        });
    }
    cells
}

/// Classify every cell. `held_out_p0` for cell i pools every OTHER cell's
/// failures (clamped away from 0/1 so likelihood ratios stay finite).
pub fn classify_cells(cells: &BTreeMap<String, Vec<CellOutcome>>) -> Vec<CellReport> {
    let totals: Vec<(usize, usize)> = cells
        .values()
        .map(|outcomes| {
            (
                outcomes.len(),
                outcomes.iter().filter(|outcome| outcome.failed).count(),
            )
        })
        .collect();
    let grand_runs: usize = totals.iter().map(|(runs, _)| runs).sum();
    let grand_failures: usize = totals.iter().map(|(_, failures)| failures).sum();

    cells
        .iter()
        .zip(totals)
        .map(|((key, outcomes), (runs, failures))| {
            let held_out_runs = grand_runs - runs;
            let held_out_failures = grand_failures - failures;
            let p0 = if held_out_runs == 0 {
                0.5
            } else {
                (held_out_failures as f64 / held_out_runs as f64).clamp(0.05, 0.95)
            };
            let label = classify_cell(outcomes, p0);
            CellReport {
                key: key.clone(),
                runs,
                failures,
                label,
            }
        })
        .collect()
}

fn classify_cell(outcomes: &[CellOutcome], held_out_p0: f64) -> String {
    let failures = outcomes.iter().filter(|outcome| outcome.failed).count();
    if failures == 0 {
        return "healthy (all pass)".to_owned();
    }
    if failures == outcomes.len() {
        // Degenerate all-fail series: Bernoulli carries no signal. The
        // discriminating observation is whether the FAILURE MODE moved:
        // first_failed_stage churn, CUSUM around an even-odds baseline.
        let mut churn_detector = CusumDetector::new(0.5, 0.9, 50.0);
        let mut verdict = None;
        let mut churns = 0usize;
        for pair in outcomes.windows(2) {
            let churned = pair[0].first_failed_stage != pair[1].first_failed_stage;
            churns += usize::from(churned);
            if let Some(hit) = churn_detector.update(churned) {
                verdict = Some(hit);
            }
        }
        let last_stage = outcomes
            .last()
            .map(|outcome| outcome.first_failed_stage.clone())
            .unwrap_or_default();
        let windows = outcomes.len().saturating_sub(1);
        return match verdict {
            Some(CusumVerdict::ShiftUp) => format!(
                "all-fail, failure mode CHURNING ({churns} mode changes; last: {last_stage})"
            ),
            _ if churns == 0 && outcomes.len() >= 2 => {
                format!("all-fail, STUCK at {last_stage}")
            }
            // Short-series fallback: a clear churn majority is CHURNING even
            // before the CUSUM decision interval accumulates.
            _ if windows >= 3 && churns * 2 > windows => format!(
                "all-fail, failure mode CHURNING ({churns}/{windows} mode changes; last: {last_stage})"
            ),
            _ => format!(
                "all-fail (churn indeterminate, {churns}/{windows} mode changes; last: {last_stage})"
            ),
        };
    }
    // Mixed series: real Bernoulli signal. H1 = a materially elevated
    // failure rate over the held-out pooled baseline.
    let p1 = (held_out_p0 + 0.3).min(0.95);
    let mut sprt = SprtClassifier::new(held_out_p0, p1, 0.05, 0.05);
    let mut cusum = CusumDetector::new(held_out_p0, p1, 100.0);
    let mut sprt_verdict = None;
    let mut cusum_verdict = None;
    for outcome in outcomes {
        if let Some(hit) = sprt.update(outcome.failed) {
            sprt_verdict = Some(hit);
        }
        if let Some(hit) = cusum.update(outcome.failed) {
            cusum_verdict = Some(hit);
        }
    }
    match (sprt_verdict, cusum_verdict) {
        (Some(SprtVerdict::Regression), _) => format!(
            "REGRESSION (SPRT accepts H1 vs pooled p0={held_out_p0:.2}{})",
            match cusum_verdict {
                Some(CusumVerdict::ShiftUp) => "; CUSUM shift-up latched",
                _ => "",
            }
        ),
        (Some(SprtVerdict::FlakyStationary), Some(CusumVerdict::ShiftDown)) => {
            "flaky-stationary, improving (CUSUM shift-down)".to_owned()
        }
        (Some(SprtVerdict::FlakyStationary), _) => {
            format!("flaky-stationary (SPRT accepts H0 at pooled p0={held_out_p0:.2})")
        }
        (None, Some(CusumVerdict::ShiftUp)) => {
            "suspected regression (CUSUM shift-up; SPRT indeterminate)".to_owned()
        }
        (None, Some(CusumVerdict::ShiftDown)) => {
            "improving (CUSUM shift-down; SPRT indeterminate)".to_owned()
        }
        (None, None) => "indeterminate (need more runs)".to_owned(),
    }
}

/// Read the run matrix and render the per-cell flake report.
pub fn render_flake_report(matrix_path: &Path) -> Result<String, String> {
    let raw = std::fs::read_to_string(matrix_path)
        .map_err(|err| format!("read run matrix {}: {err}", matrix_path.display()))?;
    let mut lines = raw.lines();
    let _header = lines.next();
    let mut rows = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        rows.push(parse_csv_record(line)?);
    }
    let cells = collect_cell_series(&rows);
    let reports = classify_cells(&cells);
    let mut out = format!(
        "live-lab flake report: {} rows, {} topology cells (pooled p0 held out per cell; single global pool = documented interim under-fit)\n",
        rows.len(),
        reports.len()
    );
    for report in reports {
        out.push_str(&format!(
            "  [{}/{} failed] {} -> {}\n",
            report.failures,
            report.runs,
            truncate_key(&report.key),
            report.label
        ));
    }
    Ok(out)
}

fn truncate_key(key: &str) -> String {
    const MAX: usize = 72;
    if key.len() <= MAX {
        key.to_owned()
    } else {
        format!("{}…", &key[..MAX])
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CellOutcome, CusumDetector, CusumVerdict, SprtClassifier, SprtVerdict, classify_cells,
    };
    use std::collections::BTreeMap;

    fn outcome(failed: bool, stage: &str) -> CellOutcome {
        CellOutcome {
            failed,
            first_failed_stage: stage.to_owned(),
        }
    }

    #[test]
    fn sprt_flags_known_regression_and_accepts_stationary_flake() {
        // Baseline 10% flake; a cell failing 9 of 10 runs must accept H1.
        let mut sprt = SprtClassifier::new(0.1, 0.4, 0.05, 0.05);
        let mut verdict = None;
        for is_failure in [true, true, false, true, true, true, true, true, true, true] {
            if let Some(hit) = sprt.update(is_failure) {
                verdict = Some(hit);
                break;
            }
        }
        assert_eq!(verdict, Some(SprtVerdict::Regression));

        // A long clean-ish run at the baseline accepts H0.
        let mut sprt = SprtClassifier::new(0.1, 0.4, 0.05, 0.05);
        let mut verdict = None;
        for _ in 0..30 {
            if let Some(hit) = sprt.update(false) {
                verdict = Some(hit);
                break;
            }
        }
        assert_eq!(verdict, Some(SprtVerdict::FlakyStationary));
    }

    #[test]
    fn cusum_latches_shift_up_on_failure_burst() {
        let mut cusum = CusumDetector::new(0.1, 0.5, 100.0);
        let mut verdict = None;
        // 20 clean runs, then a sustained failure burst.
        for _ in 0..20 {
            assert_eq!(cusum.update(false), None);
        }
        for _ in 0..12 {
            if let Some(hit) = cusum.update(true) {
                verdict = Some(hit);
                break;
            }
        }
        assert_eq!(verdict, Some(CusumVerdict::ShiftUp));
    }

    #[test]
    fn all_fail_cells_classify_on_failure_mode_churn_not_bernoulli() {
        let mut cells = BTreeMap::new();
        cells.insert(
            "stuck-cell".to_owned(),
            vec![
                outcome(true, "live_anchor"),
                outcome(true, "live_anchor"),
                outcome(true, "live_anchor"),
                outcome(true, "live_anchor"),
            ],
        );
        cells.insert(
            "churning-cell".to_owned(),
            vec![
                outcome(true, "live_anchor"),
                outcome(true, "bootstrap_hosts"),
                outcome(true, "cleanup_hosts"),
                outcome(true, "vm_lab_setup"),
                outcome(true, "live_anchor"),
                outcome(true, "bootstrap_hosts"),
                outcome(true, "cleanup_hosts"),
                outcome(true, "vm_lab_setup"),
                outcome(true, "live_anchor"),
                outcome(true, "bootstrap_hosts"),
            ],
        );
        cells.insert(
            "healthy-cell".to_owned(),
            vec![outcome(false, ""), outcome(false, "")],
        );
        let reports = classify_cells(&cells);
        let by_key: BTreeMap<&str, &str> = reports
            .iter()
            .map(|report| (report.key.as_str(), report.label.as_str()))
            .collect();
        assert!(
            by_key["stuck-cell"].contains("STUCK at live_anchor"),
            "got: {}",
            by_key["stuck-cell"]
        );
        assert!(
            by_key["churning-cell"].contains("CHURNING"),
            "got: {}",
            by_key["churning-cell"]
        );
        assert!(by_key["healthy-cell"].contains("healthy"));
    }

    #[test]
    fn mixed_cell_regression_flagged_against_held_out_baseline() {
        let mut cells = BTreeMap::new();
        // Big healthy pool: held-out p0 for the bad cell stays low.
        cells.insert(
            "pool".to_owned(),
            (0..40).map(|_| outcome(false, "")).collect(),
        );
        cells.insert(
            "bad-cell".to_owned(),
            vec![
                outcome(false, ""),
                outcome(true, "traffic"),
                outcome(true, "traffic"),
                outcome(true, "traffic"),
                outcome(true, "traffic"),
                outcome(true, "traffic"),
                outcome(true, "traffic"),
                outcome(false, ""),
                outcome(true, "traffic"),
                outcome(true, "traffic"),
            ],
        );
        let reports = classify_cells(&cells);
        let bad = reports
            .iter()
            .find(|report| report.key == "bad-cell")
            .expect("bad cell present");
        assert!(
            bad.label.contains("REGRESSION") || bad.label.contains("suspected regression"),
            "got: {}",
            bad.label
        );
    }
}
