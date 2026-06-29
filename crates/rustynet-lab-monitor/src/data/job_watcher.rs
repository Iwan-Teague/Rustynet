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

    jobs.retain(JobState::is_running);
    jobs.sort_by_key(|j| std::cmp::Reverse(j.started_unix.unwrap_or(0)));
    Ok(jobs)
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
