//! Morning artifact: the run manifest and per-escalation checkpoints
//! (proposal §3.3 / §12). Pure serialization plus filesystem writers; the
//! writers are exercised against a tempdir in tests.

use std::fs;
use std::path::Path;

use serde_json::{Map, Value};

use crate::vm_lab::overnight::backlog::{BacklogCounts, Cell, FrontierBacklog};

/// Top-level summary the operator reads in the morning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunManifest {
    pub started_at: String,
    pub ended_at: Option<String>,
    pub branch: String,
    pub run_id: String,
    pub units_run: u32,
    pub cells_verified_this_run: u32,
    pub cells_escalated: u32,
    pub counts: BacklogCounts,
    pub running: bool,
}

impl RunManifest {
    pub fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            "started_at".to_owned(),
            Value::String(self.started_at.clone()),
        );
        m.insert(
            "ended_at".to_owned(),
            self.ended_at
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        m.insert("branch".to_owned(), Value::String(self.branch.clone()));
        m.insert("run_id".to_owned(), Value::String(self.run_id.clone()));
        m.insert("units_run".to_owned(), Value::from(self.units_run));
        m.insert(
            "cells_verified_this_run".to_owned(),
            Value::from(self.cells_verified_this_run),
        );
        m.insert(
            "cells_escalated".to_owned(),
            Value::from(self.cells_escalated),
        );
        m.insert("running".to_owned(), Value::Bool(self.running));

        let c = &self.counts;
        let mut counts = Map::new();
        counts.insert("total".to_owned(), Value::from(c.total as u64));
        counts.insert("verified".to_owned(), Value::from(c.verified as u64));
        counts.insert("red".to_owned(), Value::from(c.red as u64));
        counts.insert("flaky".to_owned(), Value::from(c.flaky as u64));
        counts.insert("unbuilt".to_owned(), Value::from(c.unbuilt as u64));
        counts.insert("unknown".to_owned(), Value::from(c.unknown as u64));
        counts.insert("parked".to_owned(), Value::from(c.parked as u64));
        m.insert("counts".to_owned(), Value::Object(counts));

        Value::Object(m)
    }

    pub fn to_json_string(&self) -> Result<String, String> {
        serde_json::to_string_pretty(&self.to_json_value())
            .map_err(|e| format!("serialize manifest failed: {e}"))
    }
}

/// A red cell the loop could not green — escalated for morning review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub cell_id: String,
    pub state: String,
    pub attempts: u32,
    pub stage_hint: String,
    pub reason: String,
    pub last_progress: Option<String>,
}

impl Checkpoint {
    pub fn from_cell(cell: &Cell, reason: &str) -> Checkpoint {
        Checkpoint {
            cell_id: cell.id(),
            state: cell.state.as_str().to_owned(),
            attempts: cell.attempts,
            stage_hint: cell.stage_hint.clone(),
            reason: reason.to_owned(),
            last_progress: cell.progress.clone(),
        }
    }

    pub fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("cell".to_owned(), Value::String(self.cell_id.clone()));
        m.insert("state".to_owned(), Value::String(self.state.clone()));
        m.insert("attempts".to_owned(), Value::from(self.attempts));
        m.insert(
            "stage_hint".to_owned(),
            Value::String(self.stage_hint.clone()),
        );
        m.insert("reason".to_owned(), Value::String(self.reason.clone()));
        m.insert(
            "last_progress".to_owned(),
            self.last_progress
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        Value::Object(m)
    }
}

fn cell_slug(cell_id: &str) -> String {
    cell_id
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

/// Write `manifest.json`, the backlog snapshot, and one checkpoint file per
/// escalation into the run directory. Creates the directory if needed.
pub fn write_run_artifacts(
    dir: &Path,
    manifest: &RunManifest,
    backlog: &FrontierBacklog,
    checkpoints: &[Checkpoint],
) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("create run dir {}: {e}", dir.display()))?;

    fs::write(dir.join("manifest.json"), manifest.to_json_string()?)
        .map_err(|e| format!("write manifest: {e}"))?;

    fs::write(dir.join("frontier-backlog.json"), backlog.to_json_string()?)
        .map_err(|e| format!("write backlog snapshot: {e}"))?;

    if !checkpoints.is_empty() {
        let esc_dir = dir.join("escalations");
        fs::create_dir_all(&esc_dir).map_err(|e| format!("create escalations dir: {e}"))?;
        for cp in checkpoints {
            let body = serde_json::to_string_pretty(&cp.to_json_value())
                .map_err(|e| format!("serialize checkpoint: {e}"))?;
            let file = esc_dir.join(format!("{}.json", cell_slug(&cp.cell_id)));
            fs::write(&file, body)
                .map_err(|e| format!("write checkpoint {}: {e}", file.display()))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::VmGuestPlatform;
    use crate::vm_lab::overnight::backlog::{MarchRole, PriorVerdicts};

    fn sample() -> (RunManifest, FrontierBacklog, Vec<Checkpoint>) {
        let backlog = FrontierBacklog::build(
            &[VmGuestPlatform::Linux, VmGuestPlatform::Windows],
            &PriorVerdicts::new(),
        );
        let cell = backlog
            .cells
            .iter()
            .find(|c| c.platform == VmGuestPlatform::Windows && c.role == MarchRole::Relay)
            .cloned()
            .expect("windows relay");
        let manifest = RunManifest {
            started_at: "2026-06-09T00:00:00Z".to_owned(),
            ended_at: Some("2026-06-09T08:00:00Z".to_owned()),
            branch: "overnight/2026-06-09_a1b2".to_owned(),
            run_id: "a1b2".to_owned(),
            units_run: 12,
            cells_verified_this_run: 3,
            cells_escalated: 1,
            counts: backlog.counts(),
            running: false,
        };
        let cp = Checkpoint::from_cell(&cell, "attempt budget exhausted");
        (manifest, backlog, vec![cp])
    }

    #[test]
    fn manifest_json_has_expected_fields() {
        let (manifest, _, _) = sample();
        let json = manifest.to_json_string().expect("serialize");
        let value: Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(value["branch"], "overnight/2026-06-09_a1b2");
        assert_eq!(value["units_run"], 12);
        assert_eq!(value["running"], false);
        assert!(value["counts"]["total"].as_u64().unwrap() > 0);
    }

    #[test]
    fn write_run_artifacts_creates_files() {
        let (manifest, backlog, checkpoints) = sample();
        let tmp = tempfile::tempdir().expect("tempdir");
        write_run_artifacts(tmp.path(), &manifest, &backlog, &checkpoints).expect("write");

        assert!(tmp.path().join("manifest.json").is_file());
        assert!(tmp.path().join("frontier-backlog.json").is_file());
        let esc = tmp.path().join("escalations");
        assert!(esc.is_dir());
        let entries: Vec<_> = fs::read_dir(&esc)
            .expect("read escalations")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(entries.len(), 1);

        // Backlog snapshot round-trips.
        let snap = fs::read_to_string(tmp.path().join("frontier-backlog.json")).expect("read");
        let back = FrontierBacklog::from_json_str(&snap).expect("parse backlog");
        assert_eq!(back, backlog);
    }

    #[test]
    fn no_escalations_dir_when_none() {
        let (manifest, backlog, _) = sample();
        let tmp = tempfile::tempdir().expect("tempdir");
        write_run_artifacts(tmp.path(), &manifest, &backlog, &[]).expect("write");
        assert!(!tmp.path().join("escalations").exists());
    }

    #[test]
    fn checkpoint_slug_is_filesystem_safe() {
        assert_eq!(cell_slug("windows/relay"), "windows_relay");
        assert_eq!(cell_slug("linux/blind_exit"), "linux_blind_exit");
    }
}
