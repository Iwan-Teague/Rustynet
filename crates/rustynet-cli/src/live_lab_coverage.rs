#![forbid(unsafe_code)]

//! Coverage-as-code (Finding 5 of the 2026-07-03 live-lab findings):
//! which security controls have LIVE verification, per OS, according to
//! the run matrix — computed from data instead of prose.
//!
//! The registry declares which control IDs each audit stage proves
//! (`StageSpec::proves`, sourced from the stage evaluators' own
//! "Proves ..." doc comments); every such stage records its outcome into a
//! dedicated one-off matrix column (`StageSpec::special`). This module
//! joins the two: for every (control, OS) claim, the latest run-matrix
//! evidence — or the explicit absence of any.
//!
//! v1 is a report (`ops live-lab-coverage-report`); a control silently
//! losing its live proof shows as NO-LIVE-EVIDENCE here long before a
//! prose audit would notice. Gate enforcement (fail on coverage
//! regression, with reviewed exceptions) layers on top once dispatch
//! becomes selector-visible via the shared recorder (Finding 4).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::live_lab_stage_registry::{PlatformStream, STAGES};

/// One (control, OS) coverage claim resolved against the matrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageCell {
    pub control_id: String,
    pub os: String,
    pub stage: String,
    /// Latest recorded status for the stage's evidence column, if any run
    /// ever populated it.
    pub latest_status: Option<String>,
    pub latest_run_id: Option<String>,
    pub latest_run_started: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveLabCoverageReportConfig {
    pub matrix_path: Option<PathBuf>,
}

/// Statuses that count as "a run actually exercised this check".
fn is_live_evidence(status: &str) -> bool {
    !matches!(status.trim(), "" | "not_run" | "na" | "unknown")
}

/// All (control, OS, stage, evidence-column) claims the registry makes.
fn coverage_claims() -> Vec<(String, String, String, String)> {
    let mut claims = Vec::new();
    for spec in STAGES {
        if spec.proves.is_empty() {
            continue;
        }
        let Some(column) = spec.special else {
            // A `proves` claim without a dedicated evidence column cannot
            // be joined against the matrix yet; surface it as unjoinable
            // rather than dropping it silently.
            for control in spec.proves {
                claims.push((
                    (*control).to_owned(),
                    spec.stream.as_str().to_owned(),
                    spec.name.to_owned(),
                    String::new(),
                ));
            }
            continue;
        };
        let os = match spec.stream {
            PlatformStream::Linux => "linux",
            PlatformStream::Macos => "macos",
            PlatformStream::Windows => "windows",
            PlatformStream::Common => "common",
        };
        for control in spec.proves {
            claims.push((
                (*control).to_owned(),
                os.to_owned(),
                spec.name.to_owned(),
                column.to_owned(),
            ));
        }
    }
    claims
}

/// Resolve every claim against the matrix rows (latest row wins; interim
/// rows are ignored when a role column exists — legacy rows with an empty
/// role still count, matching the monitor's latest-wins reading).
pub fn build_coverage_cells(matrix_path: &Path) -> Result<Vec<CoverageCell>, String> {
    let body = fs::read_to_string(matrix_path).map_err(|err| {
        format!(
            "read live-lab run matrix failed ({}): {err}",
            matrix_path.display()
        )
    })?;
    let mut lines = body.lines();
    let header = lines
        .next()
        .ok_or_else(|| format!("live-lab run matrix is empty: {}", matrix_path.display()))?;
    let header_columns = crate::live_lab_run_matrix::parse_csv_record(header)?;
    let column_index = |name: &str| header_columns.iter().position(|column| column == name);
    let run_id_index = column_index("run_id");
    let started_index = column_index("run_started_utc");
    let role_index = column_index("row_role");

    // Latest non-interim value per evidence column, scanning top-to-bottom
    // so later rows overwrite earlier ones.
    let mut latest: BTreeMap<String, (String, Option<String>, Option<String>)> = BTreeMap::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(fields) = crate::live_lab_run_matrix::parse_csv_record(line) else {
            continue;
        };
        let field = |index: Option<usize>| {
            index
                .and_then(|index| fields.get(index))
                .map(String::as_str)
                .unwrap_or("")
        };
        if field(role_index) == "interim" {
            continue;
        }
        for (column_position, column_name) in header_columns.iter().enumerate() {
            let Some(value) = fields.get(column_position) else {
                continue;
            };
            if is_live_evidence(value) {
                latest.insert(
                    column_name.clone(),
                    (
                        value.clone(),
                        Some(field(run_id_index).to_owned()).filter(|v| !v.is_empty()),
                        Some(field(started_index).to_owned()).filter(|v| !v.is_empty()),
                    ),
                );
            }
        }
    }

    Ok(coverage_claims()
        .into_iter()
        .map(|(control_id, os, stage, column)| {
            let evidence = (!column.is_empty())
                .then(|| latest.get(column.as_str()))
                .flatten();
            CoverageCell {
                control_id,
                os,
                stage,
                latest_status: evidence.map(|(status, _, _)| status.clone()),
                latest_run_id: evidence.and_then(|(_, run, _)| run.clone()),
                latest_run_started: evidence.and_then(|(_, _, started)| started.clone()),
            }
        })
        .collect())
}

pub fn execute_ops_live_lab_coverage_report(
    config: LiveLabCoverageReportConfig,
) -> Result<String, String> {
    // Default to the Rust `--node` matrix: coverage claims must reflect the
    // engine we actually ship. The legacy bash matrix is a frozen archive — its
    // stage results are not evidence for the `--node` engine (they diverged, and
    // reading them as such is what made two-hop look proven when the `--node`
    // engine had never passed it). Pass `--matrix-path` explicitly to report on
    // the archive.
    let matrix_path = config
        .matrix_path
        .unwrap_or_else(crate::live_lab_run_matrix::default_live_lab_node_run_matrix_path);
    let cells = build_coverage_cells(matrix_path.as_path())?;
    Ok(render_coverage_report(&cells))
}

fn render_coverage_report(cells: &[CoverageCell]) -> String {
    let mut by_control: BTreeMap<&str, Vec<&CoverageCell>> = BTreeMap::new();
    for cell in cells {
        by_control
            .entry(cell.control_id.as_str())
            .or_default()
            .push(cell);
    }
    let mut out = String::from(
        "live-lab security-control coverage (registry `proves` x run-matrix evidence)\n",
    );
    let mut uncovered = Vec::new();
    for (control, control_cells) in &by_control {
        out.push_str(&format!("{control}:\n"));
        let mut any_live = false;
        for cell in control_cells {
            match (&cell.latest_status, &cell.latest_run_started) {
                (Some(status), started) => {
                    any_live = true;
                    out.push_str(&format!(
                        "  {:<8} {:<45} {}{}\n",
                        cell.os,
                        cell.stage,
                        status,
                        started
                            .as_deref()
                            .map(|s| format!(" ({s})"))
                            .unwrap_or_default()
                    ));
                }
                (None, _) => {
                    out.push_str(&format!(
                        "  {:<8} {:<45} NO-LIVE-EVIDENCE\n",
                        cell.os, cell.stage
                    ));
                }
            }
        }
        if !any_live {
            uncovered.push(*control);
        }
    }
    if uncovered.is_empty() {
        out.push_str("all claimed controls have live evidence on at least one OS\n");
    } else {
        out.push_str(&format!(
            "controls with ZERO live evidence on any OS: {}\n",
            uncovered.join(", ")
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_matrix(rows: &[&str]) -> PathBuf {
        // A process-wide counter guarantees a unique path per call: these tests
        // run in parallel in one process, and a timestamp alone can collide when
        // two of them build a fixture inside the same clock tick, letting one
        // test clobber another's matrix and fail intermittently.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "coverage_matrix_{}_{}_{}.csv",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let header =
            "run_id,run_started_utc,row_role,linux_hello_limiter_flood,windows_enrollment_replay";
        let mut body = format!("{header}\n");
        for row in rows {
            body.push_str(row);
            body.push('\n');
        }
        fs::write(&path, body).expect("write synthetic matrix");
        path
    }

    #[test]
    fn coverage_joins_latest_evidence_per_control_and_os() {
        let path = temp_matrix(&[
            "run-1,2026-07-01T00:00:00Z,final,pass,fail",
            "run-2,2026-07-02T00:00:00Z,final,fail,not_run",
        ]);
        let cells = build_coverage_cells(path.as_path()).expect("cells");
        // DOS-1 on linux: latest populated value wins (run-2's fail).
        let dos1_linux = cells
            .iter()
            .find(|cell| cell.control_id == "DOS-1" && cell.os == "linux")
            .expect("DOS-1 linux claim");
        assert_eq!(dos1_linux.latest_status.as_deref(), Some("fail"));
        assert_eq!(dos1_linux.latest_run_id.as_deref(), Some("run-2"));
        // ENR-1 on windows: run-2's not_run is not evidence, run-1's fail is.
        let enr1_windows = cells
            .iter()
            .find(|cell| cell.control_id == "ENR-1" && cell.os == "windows")
            .expect("ENR-1 windows claim");
        assert_eq!(enr1_windows.latest_status.as_deref(), Some("fail"));
        assert_eq!(enr1_windows.latest_run_id.as_deref(), Some("run-1"));
        // Claims whose columns this synthetic matrix lacks resolve to none.
        let dos1_macos = cells
            .iter()
            .find(|cell| cell.control_id == "DOS-1" && cell.os == "macos")
            .expect("DOS-1 macos claim");
        assert_eq!(dos1_macos.latest_status, None);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn coverage_ignores_interim_rows() {
        let path = temp_matrix(&[
            "run-1,2026-07-01T00:00:00Z,final,pass,",
            "run-2,2026-07-02T00:00:00Z,interim,fail,",
        ]);
        let cells = build_coverage_cells(path.as_path()).expect("cells");
        let dos1_linux = cells
            .iter()
            .find(|cell| cell.control_id == "DOS-1" && cell.os == "linux")
            .expect("DOS-1 linux claim");
        assert_eq!(
            dos1_linux.latest_status.as_deref(),
            Some("pass"),
            "interim rows must not provide coverage evidence"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn report_names_controls_without_any_live_evidence() {
        let path = temp_matrix(&["run-1,2026-07-01T00:00:00Z,final,,"]);
        let cells = build_coverage_cells(path.as_path()).expect("cells");
        let report = render_coverage_report(&cells);
        assert!(report.contains("ZERO live evidence"), "{report}");
        assert!(report.contains("DOS-1"), "{report}");
        assert!(report.contains("NO-LIVE-EVIDENCE"), "{report}");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn every_registry_proves_claim_is_joinable() {
        // A `proves` claim without an evidence column cannot be verified
        // from the matrix — that combination must stay impossible.
        let unjoinable: Vec<String> = coverage_claims()
            .into_iter()
            .filter(|(_, _, _, column)| column.is_empty())
            .map(|(control, os, stage, _)| format!("{control}/{os}/{stage}"))
            .collect();
        assert!(
            unjoinable.is_empty(),
            "proves claims without evidence columns: {unjoinable:?}"
        );
    }
}
