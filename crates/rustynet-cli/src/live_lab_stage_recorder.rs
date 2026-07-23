#![forbid(unsafe_code)]

//! Shared per-stage recorder for the live-lab recording contract (Fable5
//! Findings 1/3/4, "recorder-first"). This is the ONE owner of
//! `<report_dir>/state/stages.tsv` writes: a stage's row is UPSERTED to
//! `running` when it starts and REPLACED with its terminal outcome when it
//! finishes, so a consumer (the monitor) can read "what is running now"
//! directly from the file whose status column is `running`, instead of
//! reverse-engineering it from log text or pipeline position.
//!
//! Both orchestrators are meant to reach this same code: the Rust
//! state-machine `--node` runner calls these functions in-process; the bash
//! orchestrator calls them via thin `ops record-stage-*` subcommands (a
//! later increment). Because the byte-for-byte output is produced by one
//! implementation, the two pipelines become indistinguishable to every
//! consumer.
//!
//! FORMAT — deliberately the EXISTING 8-column v1 layout the bash
//! orchestrator already writes and every consumer already parses positionally
//! (`stage \t severity \t status \t rc \t log_path \t summary \t started_at
//! \t finished_at`), with NO header/marker line — so a recorder-written file
//! is byte-shape-identical to a bash-written one and every reader (the
//! monitor, the run-summary/failure-digest tools) handles it unchanged. A
//! `running` status row is the only new thing; it already surfaces as a live
//! spinner via the monitor's existing status lookup, and it is transient
//! (replaced by the terminal outcome), so end-of-run readers only ever see
//! terminal rows. (An earlier `#schema_version=2` marker was dropped: the bash
//! conclusion tools parse every non-empty line and do not skip comments, so a
//! marker line would have been ingested as a bogus stage row.)
//!
//! Boundary note: tooling-layer code (§8/§10.3 untouched) — nothing here is
//! consumed by domain, policy, or daemon crates.

use std::fs;
use std::path::{Path, PathBuf};

pub const STAGES_TSV_RELATIVE_PATH: &str = "state/stages.tsv";

/// The canonical terminal + live status strings written into the status
/// column. Mirrors the registry's closed `StageStatus` taxonomy; `running`
/// is the live one the realtime contract adds.
pub const STATUS_RUNNING: &str = "running";

/// One `stages.tsv` row in the 8-column v1-positional layout. `pub(crate)`
/// (fields included) so the §4.8 evidence verifier reads the raw rows through
/// this one canonical parser instead of forking a second TSV reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StageRow {
    pub(crate) stage: String,
    pub(crate) severity: String,
    pub(crate) status: String,
    pub(crate) rc: String,
    pub(crate) log_path: String,
    pub(crate) summary: String,
    pub(crate) started_at: String,
    pub(crate) finished_at: String,
}

impl StageRow {
    fn to_tsv(&self) -> String {
        // Every field sanitized so an embedded tab/newline can never shift
        // the positional columns a downstream reader depends on.
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize(&self.stage),
            sanitize(&self.severity),
            sanitize(&self.status),
            sanitize(&self.rc),
            sanitize(&self.log_path),
            sanitize(&self.summary),
            sanitize(&self.started_at),
            sanitize(&self.finished_at),
        )
    }

    /// Parse one line. `None` for the schema marker, blank lines, or any line
    /// with fewer than 3 columns (matching the monitor's own tolerance).
    fn parse(line: &str) -> Option<StageRow> {
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 3 {
            return None;
        }
        let get = |idx: usize| cols.get(idx).copied().unwrap_or("").to_owned();
        Some(StageRow {
            stage: get(0),
            severity: get(1),
            status: get(2),
            rc: get(3),
            log_path: get(4),
            summary: get(5),
            started_at: get(6),
            finished_at: get(7),
        })
    }
}

/// Strip characters that would corrupt a single TSV field.
fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if matches!(ch, '\t' | '\n' | '\r') {
                ' '
            } else {
                ch
            }
        })
        .collect()
}

/// Read every parseable row of `<report_dir>/state/stages.tsv` (missing file
/// = no rows). Shared with the §4.8 evidence verifier as a pure parser.
pub(crate) fn read_rows(report_dir: &Path) -> Vec<StageRow> {
    let path = report_dir.join(STAGES_TSV_RELATIVE_PATH);
    match fs::read_to_string(&path) {
        Ok(body) => body.lines().filter_map(StageRow::parse).collect(),
        Err(_) => Vec::new(),
    }
}

/// Atomically UPSERT one row keyed by stage name (replace-or-append), then
/// rewrite `stages.tsv` via tmp+rename so a concurrent reader never sees a
/// partial file. SINGLE-WRITER contract: exactly one process/thread records a
/// given run's `stages.tsv`; the recorder must be the only writer.
fn upsert_row(report_dir: &Path, row: StageRow) -> Result<(), String> {
    let path = report_dir.join(STAGES_TSV_RELATIVE_PATH);
    let parent = path
        .parent()
        .ok_or_else(|| format!("stages.tsv path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("create state dir failed ({}): {err}", parent.display()))?;

    let mut rows = read_rows(report_dir);
    match rows.iter_mut().find(|existing| existing.stage == row.stage) {
        Some(existing) => *existing = row,
        None => rows.push(row),
    }

    let mut body = String::with_capacity(rows.len() * 96);
    for row in &rows {
        body.push_str(&row.to_tsv());
        body.push('\n');
    }

    let tmp = path.with_extension("tsv.tmp");
    fs::write(tmp.as_path(), body)
        .map_err(|err| format!("write stages.tsv tmp failed ({}): {err}", tmp.display()))?;
    fs::rename(tmp.as_path(), path.as_path()).map_err(|err| {
        format!(
            "rename stages.tsv into place failed ({}): {err}",
            path.display()
        )
    })?;
    Ok(())
}

/// Record that `stage` has STARTED: upsert a `running` row with no rc and no
/// finished_at. Idempotent — a second start for the same stage just refreshes
/// the running row.
pub fn record_stage_start(
    report_dir: &Path,
    stage: &str,
    severity: &str,
    log_path: &str,
    summary: &str,
    started_at: &str,
) -> Result<(), String> {
    upsert_row(
        report_dir,
        StageRow {
            stage: stage.to_owned(),
            severity: severity.to_owned(),
            status: STATUS_RUNNING.to_owned(),
            rc: String::new(),
            log_path: log_path.to_owned(),
            summary: summary.to_owned(),
            started_at: started_at.to_owned(),
            finished_at: String::new(),
        },
    )
}

/// Record `stage`'s TERMINAL outcome: upsert (replacing any `running` row)
/// with the final status/rc/summary and finished_at.
#[allow(clippy::too_many_arguments)]
pub fn record_stage_finish(
    report_dir: &Path,
    stage: &str,
    severity: &str,
    status: &str,
    rc: &str,
    log_path: &str,
    summary: &str,
    started_at: &str,
    finished_at: &str,
) -> Result<(), String> {
    upsert_row(
        report_dir,
        StageRow {
            stage: stage.to_owned(),
            severity: severity.to_owned(),
            status: status.to_owned(),
            rc: rc.to_owned(),
            log_path: log_path.to_owned(),
            summary: summary.to_owned(),
            started_at: started_at.to_owned(),
            finished_at: finished_at.to_owned(),
        },
    )
}

/// The stage name of the single row currently `running`, if any — the
/// realtime "active stage" a consumer reads DIRECTLY instead of inferring.
/// Returns the first running row (the single-writer serial contract keeps it
/// unique per run). The canonical reference reader for the running-row
/// contract (the monitor reads the same column in its own crate; consumed
/// here by the recorder's tests until the CLI-side reader lands).
#[allow(dead_code)]
pub fn active_stage(report_dir: &Path) -> Option<String> {
    read_rows(report_dir)
        .into_iter()
        .find(|row| row.status == STATUS_RUNNING)
        .map(|row| row.stage)
}

// ── `ops record-stage-start/finish` CLI surface ───────────────────────────
// The bash-callable interface into the recorder (Finding 4). The bash
// orchestrator invokes these per stage instead of appending to stages.tsv
// directly, so exactly one implementation owns the file across both paths.

/// `ops record-stage-start` parsed config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordStageStartConfig {
    pub report_dir: PathBuf,
    pub stage: String,
    pub severity: String,
    pub log_path: String,
    pub summary: String,
    pub started_at: String,
}

/// `ops record-stage-finish` parsed config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordStageFinishConfig {
    pub report_dir: PathBuf,
    pub stage: String,
    pub severity: String,
    pub status: String,
    pub rc: String,
    pub log_path: String,
    pub summary: String,
    pub started_at: String,
    pub finished_at: String,
}

pub fn execute_ops_record_stage_start(config: RecordStageStartConfig) -> Result<String, String> {
    record_stage_start(
        config.report_dir.as_path(),
        &config.stage,
        &config.severity,
        &config.log_path,
        &config.summary,
        &config.started_at,
    )?;
    Ok(format!("recorded start: {}", config.stage))
}

pub fn execute_ops_record_stage_finish(config: RecordStageFinishConfig) -> Result<String, String> {
    record_stage_finish(
        config.report_dir.as_path(),
        &config.stage,
        &config.severity,
        &config.status,
        &config.rc,
        &config.log_path,
        &config.summary,
        &config.started_at,
        &config.finished_at,
    )?;
    Ok(format!(
        "recorded finish: {} = {}",
        config.stage, config.status
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_report_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "recorder_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    fn read_raw(report_dir: &Path) -> String {
        std::fs::read_to_string(report_dir.join(STAGES_TSV_RELATIVE_PATH)).unwrap_or_default()
    }

    #[test]
    fn start_writes_a_running_row_the_v1_monitor_reads_positionally() {
        let dir = temp_report_dir("start");
        record_stage_start(
            &dir,
            "preflight",
            "hard",
            "/logs/preflight.log",
            "verify",
            "T0",
        )
        .unwrap();
        let raw = read_raw(&dir);
        // Pure v1: no header/marker line -- the first line is a data row every
        // existing positional reader handles unchanged.
        assert!(!raw.starts_with('#'), "no marker/comment line: {raw:?}");
        let row = raw.lines().next().expect("a data row");
        let cols: Vec<&str> = row.split('\t').collect();
        assert_eq!(cols[0], "preflight");
        assert_eq!(cols[1], "hard");
        assert_eq!(cols[2], "running", "status column reads running");
        assert_eq!(cols[3], "", "no rc while running");
        assert_eq!(cols[7], "", "no finished_at while running");
        assert_eq!(active_stage(&dir).as_deref(), Some("preflight"));
    }

    #[test]
    fn finish_replaces_the_running_row_in_place_not_append() {
        let dir = temp_report_dir("finish");
        record_stage_start(
            &dir,
            "preflight",
            "hard",
            "/logs/preflight.log",
            "verify",
            "T0",
        )
        .unwrap();
        record_stage_finish(
            &dir,
            "preflight",
            "hard",
            "pass",
            "0",
            "/logs/preflight.log",
            "verify",
            "T0",
            "T1",
        )
        .unwrap();
        let data_rows: Vec<String> = read_raw(&dir)
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(str::to_owned)
            .collect();
        assert_eq!(
            data_rows.len(),
            1,
            "the running row was replaced, not appended"
        );
        let cols: Vec<&str> = data_rows[0].split('\t').collect();
        assert_eq!(cols[2], "pass");
        assert_eq!(cols[3], "0");
        assert_eq!(cols[7], "T1");
        assert_eq!(active_stage(&dir), None, "no running row after finish");
    }

    #[test]
    fn multiple_stages_serialize_with_at_most_one_running() {
        let dir = temp_report_dir("multi");
        record_stage_start(&dir, "preflight", "hard", "", "", "T0").unwrap();
        record_stage_finish(&dir, "preflight", "hard", "pass", "0", "", "", "T0", "T1").unwrap();
        record_stage_start(&dir, "bootstrap_hosts", "hard", "", "", "T1").unwrap();
        assert_eq!(active_stage(&dir).as_deref(), Some("bootstrap_hosts"));
        let data_rows: Vec<String> = read_raw(&dir)
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(str::to_owned)
            .collect();
        assert_eq!(data_rows.len(), 2);
    }

    #[test]
    fn summary_with_tabs_or_newlines_cannot_shift_columns() {
        let dir = temp_report_dir("sanitize");
        record_stage_finish(
            &dir,
            "s",
            "hard",
            "fail",
            "1",
            "/l",
            "line1\tinjected\ncol\r more",
            "T0",
            "T1",
        )
        .unwrap();
        let row = read_raw(&dir)
            .lines()
            .find(|l| !l.starts_with('#'))
            .unwrap()
            .to_owned();
        let cols: Vec<&str> = row.split('\t').collect();
        assert_eq!(cols.len(), 8, "sanitized summary keeps exactly 8 columns");
        assert_eq!(cols[0], "s");
        assert_eq!(cols[2], "fail");
        assert!(!cols[5].contains('\t') && !cols[5].contains('\n'));
    }

    #[test]
    fn active_stage_is_none_without_a_file() {
        let dir = temp_report_dir("empty");
        assert_eq!(active_stage(&dir), None);
    }

    #[test]
    fn ops_start_then_finish_upsert_a_single_row_via_the_cli_configs() {
        // The bash-callable surface: a start followed by a finish must leave
        // exactly one row (running replaced by terminal), never two.
        let dir = temp_report_dir("ops");
        execute_ops_record_stage_start(RecordStageStartConfig {
            report_dir: dir.clone(),
            stage: "bootstrap_hosts".to_owned(),
            severity: "hard".to_owned(),
            log_path: "/l".to_owned(),
            summary: "install".to_owned(),
            started_at: "T0".to_owned(),
        })
        .unwrap();
        assert_eq!(active_stage(&dir).as_deref(), Some("bootstrap_hosts"));
        execute_ops_record_stage_finish(RecordStageFinishConfig {
            report_dir: dir.clone(),
            stage: "bootstrap_hosts".to_owned(),
            severity: "hard".to_owned(),
            status: "pass".to_owned(),
            rc: "0".to_owned(),
            log_path: "/l".to_owned(),
            summary: "install".to_owned(),
            started_at: "T0".to_owned(),
            finished_at: "T1".to_owned(),
        })
        .unwrap();
        let data_rows: Vec<String> = read_raw(&dir)
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(str::to_owned)
            .collect();
        assert_eq!(data_rows.len(), 1, "start+finish upsert to one row");
        assert!(data_rows[0].contains("\tpass\t"));
        assert_eq!(active_stage(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
