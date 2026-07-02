use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::sync::watch;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JobState {
    pub job_id: String,
    pub state: String,
    #[serde(default, alias = "orchestrator_pid")]
    #[allow(dead_code)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub started_unix: Option<u64>,
    #[serde(default)]
    pub area: String,
    #[serde(default)]
    pub report_dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_args: Option<HashMap<String, serde_json::Value>>,
}

impl JobState {
    pub fn is_running(&self) -> bool {
        self.state == "running" && self.pid.map(pid_is_alive).unwrap_or(true)
    }
}

#[cfg(unix)]
fn pid_is_alive(pid: u32) -> bool {
    use nix::errno::Errno;
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    match kill(Pid::from_raw(pid as i32), None) {
        Ok(()) | Err(Errno::EPERM) => true,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn pid_is_alive(_pid: u32) -> bool {
    true
}

/// Scan job state dirs for *.json files, return the most-recently-started
/// running job, or None.
pub fn find_active_job(repo_root: &Path) -> Result<Option<JobState>> {
    let mut jobs = find_running_jobs(repo_root)?;

    // Find the most-recently-started running job.
    jobs.sort_by_key(|j| std::cmp::Reverse(j.started_unix.unwrap_or(0)));
    Ok(jobs.into_iter().next())
}

pub fn find_running_jobs(repo_root: &Path) -> Result<Vec<JobState>> {
    let mut jobs: Vec<JobState> = Vec::new();
    for dir in [
        repo_root.join("state/deepseek-mcp-jobs"),
        repo_root.join("state/lab-monitor-jobs"),
    ] {
        if !dir.exists() {
            continue;
        }
        for entry in
            std::fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let raw = std::fs::read_to_string(&path)?;
            match serde_json::from_str::<JobState>(&raw) {
                Ok(job) => jobs.push(job),
                Err(_) => continue,
            }
        }
    }

    // Track which report dirs are already known from job-state JSONs
    let tracked_report_dirs: std::collections::HashSet<String> = jobs
        .iter()
        .filter_map(|j| repo_root.join(&j.report_dir).canonicalize().ok())
        .map(|p| p.display().to_string())
        .collect();

    // Discover orphan report dirs (launched via CLI or ad-hoc scripts)
    let state_dir = repo_root.join("state");
    if let Ok(readdir) = std::fs::read_dir(&state_dir) {
        for entry in readdir.flatten() {
            let dir_path = entry.path();
            if !dir_path.is_dir() {
                continue;
            }
            // Must contain state/stages.tsv to be a report dir
            if !dir_path.join("state/stages.tsv").exists() {
                continue;
            }
            let canonical = dir_path.canonicalize().ok();
            let dir_str = canonical
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            if tracked_report_dirs.contains(&dir_str) {
                continue;
            }
            // Active = orchestrate_result.json missing AND report_state.json not run_complete
            let has_final_result = dir_path
                .join("orchestration/orchestrate_result.json")
                .exists()
                || read_report_complete_flag(&dir_path);
            if has_final_result {
                continue;
            }
            let started_unix = read_started_unix(&dir_path);
            let area = infer_area_from_dir_name(&dir_path);
            jobs.push(JobState {
                job_id: dir_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("orphan")
                    .to_owned(),
                state: "running".to_owned(),
                pid: None,
                started_unix,
                area,
                report_dir: dir_path.display().to_string(),
                request_args: None,
            });
        }
    }

    jobs.retain(JobState::is_running);
    jobs.sort_by_key(|j| std::cmp::Reverse(j.started_unix.unwrap_or(0)));
    Ok(jobs)
}

/// Check if report_state.json exists and has run_complete: true
fn read_report_complete_flag(dir: &Path) -> bool {
    let path = dir.join("state/report_state.json");
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return false,
    };
    match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(v) => v
            .get("run_complete")
            .and_then(|c| c.as_bool())
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Best-effort parse of the run's creation timestamp
fn read_started_unix(dir: &Path) -> Option<u64> {
    let path = dir.join("state/report_state.json");
    if let Ok(raw) = std::fs::read_to_string(&path)
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw)
        && let Some(ts) = v.get("created_at_unix").and_then(|t| t.as_u64())
    {
        return Some(ts);
    }
    // Fallback: dir modification time
    dir.metadata()
        .ok()
        .and_then(|m| m.created().or(m.modified()).ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
}

/// Best-guess area label from dir name
fn infer_area_from_dir_name(dir: &Path) -> String {
    let name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("live-lab");
    // Extract meaningful segments: "live-lab-macos-exit-direct-r3" → "macos exit"
    let parts: Vec<&str> = name.split('-').collect();
    if parts.len() >= 3 && parts[0] == "live" && parts[1] == "lab" {
        parts[2..]
            .iter()
            .filter(|s| !s.starts_with("r") || s.len() > 2)
            .take(3)
            .cloned()
            .collect::<Vec<&str>>()
            .join(" ")
    } else {
        name.to_owned()
    }
}

/// Poll every 2s and send events on the watch channel when the active job changes.
#[allow(dead_code)]
pub async fn watch_active_job(repo_root: PathBuf, tx: watch::Sender<Option<JobState>>) {
    let mut last_job_id: Option<String> = None;
    loop {
        let current = match find_active_job(&repo_root) {
            Ok(Some(job)) => {
                let changed = last_job_id.as_deref() != Some(&job.job_id)
                    || last_job_id.is_none() != Some(&job.job_id).is_some();
                if changed {
                    last_job_id = Some(job.job_id.clone());
                    let _ = tx.send(Some(job.clone()));
                }
                Some(job)
            }
            Ok(None) => {
                if last_job_id.is_some() {
                    last_job_id = None;
                    let _ = tx.send(None);
                }
                None
            }
            Err(_) => continue,
        };
        // Keep the binding alive
        let _ = &current;
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deepseek_orchestrator_pid_alias_is_running_pid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let jobs = dir.path().join("state/deepseek-mcp-jobs");
        std::fs::create_dir_all(&jobs).expect("jobs dir");
        std::fs::write(
            jobs.join("labrun-1-2-3.json"),
            format!(
                r#"{{
                    "job_id": "labrun-1-2-3",
                    "state": "running",
                    "started_unix": 1,
                    "area": "macOS exit",
                    "report_dir": "state/deepseek-lab-labrun-1-2-3",
                    "orchestrator_pid": {}
                }}"#,
                std::process::id()
            ),
        )
        .expect("job json");

        let running = find_running_jobs(dir.path()).expect("running jobs");

        assert_eq!(running.len(), 1);
        assert_eq!(running[0].pid, Some(std::process::id()));
    }
}
