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

/// Finding 3 (monitor half): re-read a specific job's state JSON by id,
/// regardless of PID liveness. `find_active_job` silently filters out a
/// job whose JSON still claims `running` but whose PID is dead — exactly
/// the crashed/abandoned case the operator most needs to see. Callers
/// compare: invisible to the active scan + JSON still `running` = the run
/// ended abnormally without a recorded ending.
pub fn job_state_by_id(repo_root: &Path, job_id: &str) -> Option<JobState> {
    for dir in [
        repo_root.join("state/deepseek-mcp-jobs"),
        repo_root.join("state/lab-monitor-jobs"),
    ] {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            if let Ok(raw) = std::fs::read_to_string(&path)
                && let Ok(job) = serde_json::from_str::<JobState>(&raw)
                && job.job_id == job_id
            {
                return Some(job);
            }
        }
    }
    None
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
    find_running_jobs_with_live_processes(repo_root, find_live_orchestrator_report_dirs())
}

/// `infer_role_and_platform_from_dir_name`, applied to a job's `report_dir`
/// path directly -- the convenience form callers with a `JobState` actually
/// have on hand.
pub fn infer_role_and_platform_from_report_dir(report_dir: &Path) -> Option<(String, String)> {
    let name = report_dir.file_name()?.to_str()?;
    infer_role_and_platform_from_dir_name(name)
}

/// The actual implementation, taking the live-process list as a parameter
/// instead of shelling out to `ps` itself, so tests can exercise the
/// job-state-JSON/orphan-scan logic in isolation from whatever orchestrator
/// processes happen to really be running on the machine at test time.
fn find_running_jobs_with_live_processes(
    repo_root: &Path,
    live_processes: Vec<(u32, PathBuf)>,
) -> Result<Vec<JobState>> {
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

    // Track which report dirs are already known, from job-state JSONs first
    // and growing as orphan/process-discovered ones are added below, so the
    // same report dir is never double-counted across the three sources.
    let mut seen_report_dirs: std::collections::HashSet<String> = jobs
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
            if seen_report_dirs.contains(&dir_str) {
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
            // No completion marker alone doesn't mean running -- most report
            // dirs under state/ are crashed/abandoned runs from way in the
            // past that never got one written. Require recent activity too.
            if !has_recent_activity(&dir_path) {
                continue;
            }
            let started_unix = read_started_unix(&dir_path);
            let area = infer_area_from_dir_name(&dir_path);
            seen_report_dirs.insert(dir_str);
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

    // Discover orchestrator processes directly from the process table, so a
    // run launched ad-hoc from the CLI with --report-dir pointing anywhere
    // on disk (e.g. /private/tmp/...) is still found even though it has no
    // job-state JSON and its report dir isn't under repo_root/state/.
    for (pid, dir_path) in live_processes {
        if !dir_path.is_dir() {
            continue;
        }
        let canonical = dir_path.canonicalize().ok();
        let dir_str = canonical
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        if !seen_report_dirs.insert(dir_str) {
            continue;
        }
        let started_unix = read_started_unix(&dir_path);
        let area = infer_area_from_dir_name(&dir_path);
        jobs.push(JobState {
            job_id: dir_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("orchestrator")
                .to_owned(),
            state: "running".to_owned(),
            pid: Some(pid),
            started_unix,
            area,
            report_dir: dir_path.display().to_string(),
            request_args: None,
        });
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

/// An orphan report dir with no completion marker only counts as "running" if
/// something in it was touched within this window. Without this, every
/// crashed/abandoned run under `state/` (which never gets a completion
/// marker written) would show up as running forever.
const ORPHAN_LIVENESS_WINDOW: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// Best-effort "is this report dir still being actively written to". Checks
/// `state/stages.tsv` and the newest file directly under `logs/` (one level,
/// not a recursive walk) against `ORPHAN_LIVENESS_WINDOW`.
fn has_recent_activity(dir: &Path) -> bool {
    let now = std::time::SystemTime::now();
    let is_recent = |path: &Path| -> bool {
        path.metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age <= ORPHAN_LIVENESS_WINDOW)
    };
    if is_recent(&dir.join("state/stages.tsv")) {
        return true;
    }
    let Ok(logs) = std::fs::read_dir(dir.join("logs")) else {
        return false;
    };
    logs.flatten().any(|entry| is_recent(&entry.path()))
}

/// CLI subcommands that run a live-lab orchestration and accept
/// `--report-dir` -- matched as a substring against each process's argv.
const ORCHESTRATOR_SUBCOMMANDS: &[&str] = &["vm-lab-orchestrate-live-lab", "vm-lab-setup-live-lab"];

/// Discover orchestrator processes directly from the process table via
/// `ps`, so an ad-hoc CLI-launched run is found even when it has no
/// job-state JSON and its `--report-dir` isn't under `repo_root/state/`
/// (e.g. `/private/tmp/...`, which is how most manual runs are launched).
/// Best-effort: an empty result on any failure just means this source
/// contributes nothing, not that the scan fails.
fn find_live_orchestrator_report_dirs() -> Vec<(u32, PathBuf)> {
    let output = std::process::Command::new("ps")
        .args(["-eo", "pid=,args=", "-ww"])
        .output();
    match output {
        Ok(output) if output.status.success() => {
            parse_orchestrator_processes(&String::from_utf8_lossy(&output.stdout))
        }
        _ => Vec::new(),
    }
}

/// Pure parser for `ps -eo pid=,args=` output, isolated from the `ps`
/// invocation so it's unit-testable without a real process table.
fn parse_orchestrator_processes(ps_output: &str) -> Vec<(u32, PathBuf)> {
    let mut found = Vec::new();
    for line in ps_output.lines() {
        let line = line.trim_start();
        let Some((pid_str, command)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let Ok(pid) = pid_str.trim().parse::<u32>() else {
            continue;
        };
        if !ORCHESTRATOR_SUBCOMMANDS
            .iter()
            .any(|sub| command.contains(sub))
        {
            continue;
        }
        if let Some(report_dir) = extract_arg_value(command, "--report-dir") {
            found.push((pid, PathBuf::from(report_dir)));
        }
    }
    found
}

/// Extract the value following `flag` in a whitespace-separated argv
/// string. Best-effort: the orchestrator's own flags are always simple
/// unquoted tokens, so no shell-style parsing is needed.
fn extract_arg_value(command: &str, flag: &str) -> Option<String> {
    let mut tokens = command.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == flag {
            return tokens.next().map(str::to_owned);
        }
    }
    None
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
    if let Some((role, platform)) = infer_role_and_platform_from_dir_name(name) {
        return format!("{platform} {role}");
    }
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

/// Parses the live-lab orchestrator's `rn_role_{os}_{role_words...}_...`
/// report-dir naming convention (e.g.
/// "rn_role_linux_blind_exit_daemon_main_20260703_08" ->
/// `("blind_exit", "linux")`, "rn_role_macos_admin_20260702_01" ->
/// `("admin", "macos")`) -- used to recover which role/platform a live-lab
/// job launched OUTSIDE this monitor (raw CLI, another user's session) is
/// actually targeting, since such jobs have no `request_args` at all (see
/// `JobState::request_args` and the 3 discovery paths in
/// `find_running_jobs_with_live_processes`, all of which set it to `None`
/// for anything other than a job-state JSON this monitor itself wrote).
/// Returns `None` if the name doesn't match the convention or the role
/// tokens don't resolve to one of the known role labels.
pub fn infer_role_and_platform_from_dir_name(name: &str) -> Option<(String, String)> {
    const KNOWN_ROLES: [&str; 6] = ["client", "admin", "exit", "blind_exit", "relay", "anchor"];

    let rest = name.strip_prefix("rn_role_")?;
    let tokens: Vec<&str> = rest.split('_').collect();
    let os_idx = tokens
        .iter()
        .position(|t| matches!(*t, "linux" | "macos" | "windows"))?;
    let platform = tokens[os_idx].to_owned();

    // Grow the candidate role string one token at a time and check it
    // against the known role labels after each token, rather than guessing
    // where the role name ends via a fixed stop-word list -- trailing
    // descriptors after the real role vary ("daemon", "main", "mixed",
    // "direct", ...) and a stop-word list would need to enumerate all of
    // them. Once a valid role has matched, the next non-matching token
    // means we've walked past it into a trailing descriptor -- stop there
    // (so "blind_exit_daemon" doesn't keep growing into "blind_exit_daemon"
    // and lose the match).
    let mut candidate = String::new();
    let mut matched: Option<String> = None;
    for token in &tokens[os_idx + 1..] {
        if !candidate.is_empty() {
            candidate.push('_');
        }
        candidate.push_str(token);
        if KNOWN_ROLES.contains(&candidate.as_str()) {
            matched = Some(candidate.clone());
        } else if matched.is_some() {
            break;
        }
    }
    matched.map(|role| (role, platform))
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
    fn parse_orchestrator_processes_extracts_pid_and_report_dir() {
        let ps_output = " 8226 target/debug/rustynet-cli ops vm-lab-orchestrate-live-lab --inventory documents/operations/active/vm_lab_inventory.json --report-dir /private/tmp/rn_role_windows_anchor_mixed_20260702_01 --ssh-identity-file /Users/iwan/.ssh/rustynet_lab_ed25519\n\
             50807 /bin/zsh -c echo unrelated\n";

        let found = parse_orchestrator_processes(ps_output);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, 8226);
        assert_eq!(
            found[0].1,
            PathBuf::from("/private/tmp/rn_role_windows_anchor_mixed_20260702_01")
        );
    }

    #[test]
    fn parse_orchestrator_processes_ignores_non_orchestrator_and_malformed_lines() {
        let ps_output = "not-a-pid some command\n\
             1234 some-unrelated-process --report-dir /tmp/x\n\
             5678 rustynet-cli ops vm-lab-orchestrate-live-lab\n"; // no --report-dir at all

        let found = parse_orchestrator_processes(ps_output);

        assert!(
            found.is_empty(),
            "malformed pid, non-orchestrator command, and missing --report-dir must all be skipped: {found:?}"
        );
    }

    #[test]
    fn parse_orchestrator_processes_matches_setup_live_lab_too() {
        let ps_output = " 999 rustynet-cli ops vm-lab-setup-live-lab --report-dir /tmp/setup-run\n";

        let found = parse_orchestrator_processes(ps_output);

        assert_eq!(found, vec![(999, PathBuf::from("/tmp/setup-run"))]);
    }

    #[test]
    fn infers_role_and_platform_from_real_report_dir_names() {
        // Regression: jobs discovered via the orphan/live-process paths
        // (i.e. launched outside this monitor -- raw CLI, another user's
        // session) always have request_args = None, so this parser is the
        // ONLY way the stage grid ever learns what such a job is actually
        // targeting. Names taken from real report dirs seen in the lab.
        assert_eq!(
            infer_role_and_platform_from_dir_name(
                "rn_role_linux_blind_exit_daemon_main_20260703_08"
            ),
            Some(("blind_exit".to_owned(), "linux".to_owned()))
        );
        assert_eq!(
            infer_role_and_platform_from_dir_name("rn_role_linux_blind_exit_main_20260702_01"),
            Some(("blind_exit".to_owned(), "linux".to_owned()))
        );
        assert_eq!(
            infer_role_and_platform_from_dir_name("rn_role_macos_admin_20260702_01"),
            Some(("admin".to_owned(), "macos".to_owned()))
        );
        // "mixed" is a trailing descriptor, not part of the role -- the
        // growing-candidate match must stop at "anchor", not swallow it
        // into an unrecognized "anchor_mixed".
        assert_eq!(
            infer_role_and_platform_from_dir_name("rn_role_windows_anchor_mixed_20260702_01"),
            Some(("anchor".to_owned(), "windows".to_owned()))
        );
    }

    #[test]
    fn infer_role_and_platform_returns_none_for_unrecognized_names() {
        assert_eq!(
            infer_role_and_platform_from_dir_name("live-lab-macos-exit-r3"),
            None
        );
        assert_eq!(
            infer_role_and_platform_from_dir_name("rn_role_linux_"),
            None
        );
        assert_eq!(
            infer_role_and_platform_from_dir_name("rn_role_linux_totally_unknown_role_20260702_01"),
            None
        );
    }

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

        let running =
            find_running_jobs_with_live_processes(dir.path(), Vec::new()).expect("running jobs");

        assert_eq!(running.len(), 1);
        assert_eq!(running[0].pid, Some(std::process::id()));
    }

    fn write_orphan_report_dir(repo_root: &Path, name: &str, stages_tsv_age: std::time::Duration) {
        let report_dir = repo_root.join("state").join(name);
        std::fs::create_dir_all(report_dir.join("state")).expect("state dir");
        let stages_tsv = report_dir.join("state/stages.tsv");
        std::fs::write(&stages_tsv, "stage\tstatus\n").expect("stages.tsv");
        let stale_time = std::time::SystemTime::now() - stages_tsv_age;
        std::fs::File::open(&stages_tsv)
            .expect("reopen stages.tsv")
            .set_modified(stale_time)
            .expect("backdate stages.tsv");
    }

    #[test]
    fn stale_orphan_report_dir_without_recent_activity_is_not_running() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_orphan_report_dir(
            dir.path(),
            "live-lab-abandoned-run",
            std::time::Duration::from_secs(2 * 60 * 60),
        );

        let running =
            find_running_jobs_with_live_processes(dir.path(), Vec::new()).expect("running jobs");

        assert!(
            running.is_empty(),
            "a report dir with no completion marker but no recent activity must not be shown as running: {running:?}"
        );
    }

    #[test]
    fn orphan_report_dir_with_recent_activity_is_running() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_orphan_report_dir(
            dir.path(),
            "live-lab-in-progress-run",
            std::time::Duration::from_secs(30),
        );

        let running =
            find_running_jobs_with_live_processes(dir.path(), Vec::new()).expect("running jobs");

        assert_eq!(running.len(), 1);
        assert_eq!(running[0].job_id, "live-lab-in-progress-run");
    }

    #[test]
    fn process_discovered_report_dir_outside_repo_root_is_running() {
        let repo = tempfile::tempdir().expect("repo tempdir");
        let external = tempfile::tempdir().expect("external report dir, e.g. /private/tmp/...");

        // self::process::id() so the pid is guaranteed alive during the test.
        let live_processes = vec![(std::process::id(), external.path().to_path_buf())];
        let running = find_running_jobs_with_live_processes(repo.path(), live_processes)
            .expect("running jobs");

        assert_eq!(running.len(), 1);
        assert_eq!(running[0].pid, Some(std::process::id()));
        assert_eq!(running[0].report_dir, external.path().display().to_string());
    }

    #[test]
    fn process_discovered_report_dir_with_a_dead_pid_is_not_running() {
        let repo = tempfile::tempdir().expect("repo tempdir");
        let external = tempfile::tempdir().expect("external report dir");

        // A pid that (barring astronomically unlucky reuse) is not alive.
        // Not u32::MAX: cast to i32 that's -1, which kill() treats as a
        // broadcast-permission check rather than "does this pid exist" and
        // trivially succeeds.
        let live_processes = vec![(999_999_999, external.path().to_path_buf())];
        let running = find_running_jobs_with_live_processes(repo.path(), live_processes)
            .expect("running jobs");

        assert!(running.is_empty(), "{running:?}");
    }

    #[test]
    fn process_discovered_report_dir_already_tracked_is_not_duplicated() {
        let repo = tempfile::tempdir().expect("repo tempdir");
        let jobs_dir = repo.path().join("state/deepseek-mcp-jobs");
        std::fs::create_dir_all(&jobs_dir).expect("jobs dir");
        let tracked_report_dir = repo.path().join("state/tracked-run");
        std::fs::create_dir_all(&tracked_report_dir).expect("tracked report dir");
        std::fs::write(
            jobs_dir.join("labrun-1.json"),
            format!(
                r#"{{"job_id":"labrun-1","state":"running","started_unix":1,"area":"x","report_dir":"state/tracked-run","orchestrator_pid":{}}}"#,
                std::process::id()
            ),
        )
        .expect("job json");

        // The process table also reports the same (canonicalized) report
        // dir -- must not produce a second entry for it.
        let live_processes = vec![(std::process::id(), tracked_report_dir.clone())];
        let running = find_running_jobs_with_live_processes(repo.path(), live_processes)
            .expect("running jobs");

        assert_eq!(running.len(), 1, "{running:?}");
    }
}
