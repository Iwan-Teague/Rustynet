//! Lab State MCP Server — queries and manages the UTM VM lab, and drives the
//! autonomous live-lab loop (run → catch bugs → patch → re-verify) via async
//! background jobs so an agent can work unattended for hours.
//!
//! Short ops (discover/restart/recover/sync/diagnostics) run synchronously
//! under a kill-on-timeout watchdog. The multi-hour live-lab runs are launched
//! as **detached background jobs** (start_live_lab_run) that survive an
//! MCP-server reload; the agent polls get_job_status / tail_job_log and reads
//! structured results via get_run_result / read_report_artifact. This keeps
//! every MCP call short, so a single call never blocks past a client's request
//! timeout.

#![forbid(unsafe_code)]

use rustynet_mcp::{
    CommandOutcome, GetPromptResult, McpServer, Prompt, PromptArgument, ServerInfo, Tool,
    ToolCallResult, json_schema_array_string, json_schema_boolean, json_schema_object,
    json_schema_string, prompt_text, read_file_capped, run_server, run_with_timeout, spawn_logged,
    tail_file, text_content, tool_error, tool_success, truncate_output, truncate_tail,
};
use serde_json::{Value, json};
use socket2::{Domain, SockAddr, Socket, Type};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Default machine-readable inventory path (repo-relative).
const DEFAULT_INVENTORY: &str = "documents/operations/active/vm_lab_inventory.json";
/// Where job records + logs live (repo-relative; under gitignored state/).
const JOBS_SUBDIR: &str = "state/mcp-jobs";
/// Durable append-only loop journal (repo-relative; under gitignored state/).
/// Survives MCP-server reloads and the agent's context compaction over a long run.
const LOOP_JOURNAL: &str = "state/mcp-loop-journal.jsonl";
/// Timeout for discovery/inventory ops. Generous because the FIRST lab call on a
/// cold checkout must also build rustynet-cli (the largest crate), which can take
/// several minutes; warm calls return in seconds. The kill-on-timeout watchdog
/// still bounds a genuinely hung probe.
const DISCOVERY_TIMEOUT_SECS: u64 = 600;
/// A live-lab job mutates shared VMs, shared SSH identity/known-hosts state, and
/// the shared warm Cargo target. More than one concurrent run produces false
/// failures and can fight over node services, so fail closed.
const MAX_CONCURRENT_LIVE_LAB_JOBS: usize = 1;

const CANONICAL_COVERAGE_COLUMNS: &[&str] = &[
    "linux_stage_bootstrap",
    "linux_stage_membership",
    "linux_stage_assignments",
    "linux_stage_baseline_runtime",
    "linux_stage_anchor",
    "linux_stage_relay_service_lifecycle",
    "linux_stage_exit_handoff",
    "linux_stage_lan_toggle",
    "linux_stage_two_hop",
    "linux_stage_role_switch_matrix",
    "linux_stage_managed_dns",
    "linux_stage_traversal",
    "linux_stage_mixed_topology",
    "linux_stage_reboot_recovery",
    "linux_stage_extended_soak",
    "linux_stage_chaos",
    "linux_stage_cleanup",
    "linux_stage_secrets_not_in_logs",
    "linux_stage_key_custody",
    "linux_stage_enrollment_restart",
    "linux_stage_network_flap",
    "macos_stage_bootstrap",
    "macos_stage_membership",
    "macos_stage_assignments",
    "macos_stage_baseline_runtime",
    "macos_stage_anchor",
    "macos_stage_relay_service_lifecycle",
    "macos_stage_exit_handoff",
    "macos_stage_lan_toggle",
    "macos_stage_two_hop",
    "macos_stage_role_switch_matrix",
    "macos_stage_managed_dns",
    "macos_stage_traversal",
    "macos_stage_mixed_topology",
    "macos_stage_reboot_recovery",
    "macos_stage_extended_soak",
    "macos_stage_chaos",
    "macos_stage_cleanup",
    "macos_stage_secrets_not_in_logs",
    "macos_stage_key_custody",
    "macos_stage_enrollment_restart",
    "macos_stage_network_flap",
    "windows_stage_bootstrap",
    "windows_stage_membership",
    "windows_stage_assignments",
    "windows_stage_baseline_runtime",
    "windows_stage_anchor",
    "windows_stage_relay_service_lifecycle",
    "windows_stage_exit_handoff",
    "windows_stage_lan_toggle",
    "windows_stage_two_hop",
    "windows_stage_role_switch_matrix",
    "windows_stage_managed_dns",
    "windows_stage_traversal",
    "windows_stage_mixed_topology",
    "windows_stage_reboot_recovery",
    "windows_stage_extended_soak",
    "windows_stage_chaos",
    "windows_stage_cleanup",
    "windows_stage_secrets_not_in_logs",
    "windows_stage_key_custody",
    "windows_stage_enrollment_restart",
    "windows_stage_network_flap",
    "cross_os_bootstrap",
    "cross_os_membership_convergence",
    "cross_os_peer_visibility",
    "cross_os_direct_path",
    "cross_os_relay_path",
    "cross_os_exit_path",
    "cross_os_dns",
    "cross_os_lan_toggle",
    "cross_os_role_switch",
    "cross_os_anchor_bundle_pull",
    "cross_os_anchor_enrollment",
];

fn main() {
    let server = LabStateServer::new();
    run_server(server);
}

struct LabStateServer {
    repo_root: PathBuf,
    /// Live children spawned this server-lifetime, for liveness/kill/reap.
    /// Lost across restart — completion is then read from the report dir.
    jobs: Mutex<HashMap<String, std::process::Child>>,
    job_seq: AtomicU64,
}

impl LabStateServer {
    fn new() -> Self {
        Self {
            repo_root: rustynet_mcp::repo_root(),
            jobs: Mutex::new(HashMap::new()),
            job_seq: AtomicU64::new(0),
        }
    }

    // ── Synchronous command helpers (short ops) ──────────────────────

    fn run_cli(&self, cli_args: &[&str], title: &str, timeout_secs: u64) -> ToolCallResult {
        let mut full: Vec<&str> = vec![
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--features",
            "vm-lab",
            "--",
        ];
        full.extend_from_slice(cli_args);
        match run_with_timeout(
            "cargo",
            &full,
            &self.repo_root,
            &[("CARGO_TERM_COLOR", "never")],
            Duration::from_secs(timeout_secs),
        ) {
            Ok(outcome) => format_lab_outcome(title, &outcome),
            Err(e) => tool_error(&e),
        }
    }

    fn run_ops(&self, subcommand: &str, extra_args: &[&str], timeout_secs: u64) -> ToolCallResult {
        self.run_ops_with_inventory(subcommand, None, extra_args, timeout_secs)
    }

    /// `run_ops`, but able to target a different inventory.
    ///
    /// Every tool used to be welded to DEFAULT_INVENTORY, so none could act on a
    /// second fleet or a scratch inventory. The override is **confined to the
    /// repo** (`confined_repo_path`): an inventory path is read AND is where live
    /// IPs get written back, so an arbitrary path would let a caller reach outside
    /// the workspace.
    fn run_ops_with_inventory(
        &self,
        subcommand: &str,
        inventory: Option<&str>,
        extra_args: &[&str],
        timeout_secs: u64,
    ) -> ToolCallResult {
        let inventory = inventory.unwrap_or(DEFAULT_INVENTORY);
        let mut args: Vec<&str> = vec!["ops", subcommand, "--inventory", inventory];
        args.extend_from_slice(extra_args);
        self.run_cli(&args, &format!("ops {subcommand}"), timeout_secs)
    }

    /// Resolve an optional `inventory` argument, confined to the repo.
    fn arg_inventory(&self, args: Option<&Value>) -> Result<Option<String>, String> {
        match arg_str(args, "inventory") {
            None => Ok(None),
            Some(path) => self
                .confined_repo_path(path, "inventory")
                .map(|resolved| Some(resolved.to_string_lossy().to_string())),
        }
    }

    fn run_shell_script(&self, script: &str, args: &[&str], timeout_secs: u64) -> ToolCallResult {
        let script_path = self.repo_root.join(script);
        let mut full: Vec<&str> = vec![script_path.to_str().unwrap_or(script)];
        full.extend_from_slice(args);
        match run_with_timeout(
            "bash",
            &full,
            &self.repo_root,
            &[],
            Duration::from_secs(timeout_secs),
        ) {
            Ok(outcome) => format_lab_outcome(script, &outcome),
            Err(e) => tool_error(&e),
        }
    }

    fn ensure_report_dir(&self, dir: &str) -> Result<String, String> {
        let path = self.confined_repo_path(dir, "report_dir")?;
        std::fs::create_dir_all(&path)
            .map_err(|e| format!("cannot create report_dir {}: {e}", path.display()))?;
        Ok(path.to_string_lossy().to_string())
    }

    fn abs_path(&self, dir: &str) -> PathBuf {
        self.confined_repo_path(dir, "path")
            .unwrap_or_else(|_| self.repo_root.join("__invalid_out_of_repo_path__"))
    }

    fn confined_repo_path(&self, raw: &str, label: &str) -> Result<PathBuf, String> {
        if raw.trim().is_empty() {
            return Err(format!("{label} cannot be empty"));
        }
        let repo = self
            .repo_root
            .canonicalize()
            .unwrap_or_else(|_| self.repo_root.clone());
        let p = Path::new(raw);
        let candidate = if p.is_absolute() {
            p.to_path_buf()
        } else {
            repo.join(p)
        };
        let normalized = canonicalize_existing_prefix(&candidate);
        if !normalized.starts_with(&repo) {
            return Err(format!(
                "{label} must stay under repo root {}",
                repo.display()
            ));
        }
        if let Some(existing) = deepest_existing_ancestor(&normalized)
            && let Ok(real) = existing.canonicalize()
            && !real.starts_with(&repo)
        {
            return Err(format!(
                "{label} ancestor escapes repo root via symlink: {}",
                existing.display()
            ));
        }
        Ok(normalized)
    }

    fn report_dir_from_record(&self, dir: &str) -> Option<PathBuf> {
        self.confined_repo_path(dir, "job report_dir").ok()
    }

    fn active_live_job_count(&self) -> usize {
        let Ok(entries) = std::fs::read_dir(self.jobs_dir()) else {
            return 0;
        };
        entries
            .flatten()
            .filter_map(|entry| {
                let p = entry.path();
                (p.extension().map(|e| e == "json").unwrap_or(false))
                    .then(|| std::fs::read_to_string(p).ok())
                    .flatten()
            })
            .filter_map(|s| serde_json::from_str::<Value>(&s).ok())
            .filter(|rec| {
                let job_id = rec.get("job_id").and_then(|v| v.as_str()).unwrap_or("");
                let pid = rec.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
                let Some(report_dir) = rec
                    .get("report_dir")
                    .and_then(|v| v.as_str())
                    .and_then(|dir| self.report_dir_from_record(dir))
                else {
                    return pid != 0 && self.pid_alive_verified(job_id, pid);
                };
                self.job_state(job_id, pid, &report_dir) == "running"
            })
            .count()
    }

    // ── Background-job machinery ──────────────────────────────────────

    fn jobs_dir(&self) -> PathBuf {
        self.repo_root.join(JOBS_SUBDIR)
    }

    fn new_job_id(&self) -> String {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let seq = self.job_seq.fetch_add(1, Ordering::Relaxed);
        // Include the pid: each piped client request is a fresh server process
        // whose job_seq restarts at 0, so without the pid two same-millisecond
        // starts would collide and silently overwrite each other's record.
        format!("ll-{millis}-{}-{seq}", std::process::id())
    }

    fn job_record_path(&self, job_id: &str) -> PathBuf {
        self.jobs_dir().join(format!("{job_id}.json"))
    }

    fn write_job_record(&self, job_id: &str, rec: &Value) -> Result<(), String> {
        std::fs::create_dir_all(self.jobs_dir())
            .map_err(|e| format!("cannot create jobs dir: {e}"))?;
        std::fs::write(
            self.job_record_path(job_id),
            serde_json::to_string_pretty(rec).unwrap_or_default(),
        )
        .map_err(|e| format!("cannot write job record: {e}"))
    }

    fn read_job_record(&self, job_id: &str) -> Option<Value> {
        let s = std::fs::read_to_string(self.job_record_path(job_id)).ok()?;
        serde_json::from_str(&s).ok()
    }

    /// Process start-time string (`ps -o lstart=`), used as a PID-identity token
    /// to detect PID reuse. Rendered in UTC so the string is stable across a
    /// local DST transition over a long run. `None` if the pid is not alive.
    /// Works on macOS and Linux. Captured at spawn and re-checked on every
    /// liveness probe; a non-empty result also proves the pid is currently live.
    fn pid_start_time(&self, pid: u64) -> Option<String> {
        if pid == 0 {
            return None;
        }
        let out = run_with_timeout(
            "ps",
            &["-o", "state=,lstart=", "-p", &pid.to_string()],
            &self.repo_root,
            &[("TZ", "UTC")],
            Duration::from_secs(5),
        )
        .ok()?;
        if !out.success {
            return None;
        }
        parse_ps_state_lstart(&out.stdout)
    }

    /// Liveness WITH PID-reuse protection. The pid must be alive AND its process
    /// start-time must match the token recorded at spawn. Over a 24h+ run the OS
    /// recycles pids; a bare `kill -0` would then report a crashed job's recycled
    /// pid as "running" forever (and cancel_job would signal an unrelated
    /// process). On a start-time mismatch we fail closed to "not this job".
    /// Records written before this field existed (no `pid_start`) fall back to
    /// bare liveness — no regression for in-flight legacy jobs.
    fn pid_alive_verified(&self, job_id: &str, pid: u64) -> bool {
        let Some(current_start) = self.pid_start_time(pid) else {
            return false; // pid not alive
        };
        match self.read_job_record(job_id).and_then(|r| {
            r.get("pid_start")
                .and_then(|v| v.as_str())
                .map(String::from)
        }) {
            // Identity recorded → must match exactly, else the pid was recycled.
            Some(expected) if !expected.is_empty() => expected == current_start,
            // Legacy record without identity → alive pid is the best we have.
            _ => true,
        }
    }

    /// running / passed / failed / ended for a job.
    ///
    /// The completion record (report_state.json) is checked FIRST and is
    /// authoritative — this is immune to PID reuse, which is a real hazard over
    /// 24h+ runs where a finished job's pid could be recycled by the OS. Liveness
    /// is only consulted when there is no completion record yet (e.g. a job that
    /// crashed before writing one), and even then it is PID-identity-checked
    /// (`pid_alive_verified`) so a recycled pid can't peg the job "running".
    fn job_state(&self, job_id: &str, pid: u64, report_dir: &Path) -> String {
        let report_state = self.read_report_state(report_dir);
        if let Some(rs) = &report_state
            && rs
                .get("run_complete")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        {
            let passed = rs
                .get("run_passed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            return if passed {
                "passed".into()
            } else {
                "failed".into()
            };
        }
        // Decide liveness WITHOUT holding the jobs lock across the (blocking)
        // pid probe — otherwise list_jobs/prune_jobs would serialize every job op
        // behind a `kill` subprocess. Recover a poisoned lock (into_inner) so a
        // panic elsewhere can't permanently degrade job tracking.
        enum Live {
            Done,
            Alive,
            Unknown,
        }
        let live = {
            let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
            match jobs.get_mut(job_id) {
                Some(child) => match child.try_wait() {
                    Ok(Some(_)) => Live::Done,
                    Ok(None) => Live::Alive,
                    Err(_) => Live::Unknown,
                },
                None => Live::Unknown,
            }
        };
        let running = match live {
            Live::Alive => true,
            Live::Done => false,
            Live::Unknown => self.pid_alive_verified(job_id, pid),
        };
        if running {
            "running".into()
        } else if report_state.is_some() {
            "ended (setup-only or stopped before run completion)".into()
        } else {
            "ended (no completion record — likely crashed; check tail_job_log)".into()
        }
    }

    fn read_report_state(&self, report_dir: &Path) -> Option<Value> {
        let s = std::fs::read_to_string(report_dir.join("state/report_state.json")).ok()?;
        serde_json::from_str(&s).ok()
    }

    /// Read the per-run matrix row CSV (header line + data line) → column map.
    fn read_matrix_row(&self, report_dir: &Path) -> Option<BTreeMap<String, String>> {
        let s =
            std::fs::read_to_string(report_dir.join("state/live_lab_run_matrix_row.csv")).ok()?;
        let mut lines = s.lines();
        let header = split_csv_line(lines.next()?);
        let row = split_csv_line(lines.next()?);
        Some(header.into_iter().zip(row).collect())
    }

    fn find_failure_digest(&self, report_dir: &Path) -> Option<Value> {
        for cand in [
            "failure_digest.json",
            "state/failure_digest.json",
            "orchestration/failure_digest.json",
            "diagnostics/failure_digest.json",
        ] {
            if let Ok(s) = std::fs::read_to_string(report_dir.join(cand))
                && let Ok(v) = serde_json::from_str(&s)
            {
                return Some(v);
            }
        }
        find_digest_recursive(report_dir, 3)
    }

    /// Diagnose a profile-less (Rust --node) run directly from report-dir
    /// evidence artifacts — no SSH-into-nodes deep triage.
    fn diagnose_profileless_run(
        &self,
        report_dir: &Path,
        stage_filter: Option<&str>,
        collect_artifacts: bool,
    ) -> ToolCallResult {
        let mut out = format!(
            "# Profile-less run diagnosis\n\nReport dir: `{}`\n\n",
            report_dir.display()
        );

        // ── 1. Orchestrate result ──────────────────────────────────────
        let orchestrate_path = report_dir.join("orchestration/orchestrate_result.json");
        let orchestrate: Option<Value> = std::fs::read_to_string(&orchestrate_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());
        if let Some(ref orch) = orchestrate {
            let overall = orch
                .get("overall_status")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let outcomes = orch.get("outcomes").and_then(|v| v.as_array());
            let fail_count = outcomes
                .map(|a| {
                    a.iter()
                        .filter(|o| {
                            o.get("status")
                                .and_then(|v| v.as_str())
                                .is_some_and(|s| s.to_lowercase() == "fail")
                        })
                        .count()
                })
                .unwrap_or(0);
            let total = outcomes.map(|a| a.len()).unwrap_or(0);
            out.push_str(&format!(
                "## Overall: **{overall}** ({fail_count}/{total} stages failed)\n\n"
            ));
            if let Some(a) = outcomes
                && !a.is_empty()
            {
                out.push_str("| stage | status | summary |\n|---|---|---|\n");
                for o in a {
                    let stage = o.get("stage").and_then(|v| v.as_str()).unwrap_or("?");
                    let status = o.get("status").and_then(|v| v.as_str()).unwrap_or("?");
                    let summary = o
                        .get("summary")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .chars()
                        .take(120)
                        .collect::<String>();
                    out.push_str(&format!("| {stage} | {status} | {summary} |\n"));
                }
                out.push('\n');
            }
        } else {
            out.push_str("_orchestration/orchestrate_result.json not found._\n\n");
        }

        // ── 2. Failure digest ──────────────────────────────────────────
        let digest = self.find_failure_digest(report_dir);
        let first_failure_info: Option<(
            String, // stage
            String, // primary_failure_reason or message
            String, // log path
        )> = digest.as_ref().and_then(|d| {
            let ff = d.get("first_failure").unwrap_or(d);
            let stage = ff.get("stage").and_then(|v| v.as_str())?;
            let reason = ff
                .get("primary_failure_reason")
                .or_else(|| ff.get("reason"))
                .or_else(|| ff.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let log_path = ff.get("log_path").and_then(|v| v.as_str()).unwrap_or("");
            Some((stage.to_string(), reason.to_string(), log_path.to_string()))
        });

        if let Some((ref stage, ref reason, ref log)) = first_failure_info {
            out.push_str("## First failure\n\n");
            out.push_str(&format!("- **Stage:** `{stage}`\n"));
            out.push_str(&format!("- **Reason:** {reason}\n"));
            if !log.is_empty() {
                out.push_str(&format!("- **Log:** `{log}`\n"));
            }
            out.push('\n');
        }

        // ── 3. stages.tsv — first failed row ───────────────────────────
        let tsv_path = report_dir.join("state/stages.tsv");
        let tsv_failures: Vec<(String, String, String, String)> =
            // (stage, status, rc, log_path)
            if let Ok(body) = std::fs::read_to_string(&tsv_path) {
                body.lines()
                    .filter(|l| !l.trim().is_empty())
                    .filter_map(|line| {
                        let cols: Vec<&str> = line.split('\t').collect();
                        if cols.len() < 5 {
                            return None;
                        }
                        let status = cols[2].to_lowercase();
                        (status == "fail" || status == "error").then(|| {
                            (
                                cols[0].to_string(),
                                cols[2].to_string(),
                                cols[3].to_string(),
                                cols[4].to_string(),
                            )
                        })
                    })
                    .collect()
            } else {
                Vec::new()
            };

        if !tsv_failures.is_empty() {
            if first_failure_info.is_none() {
                let first = &tsv_failures[0];
                out.push_str("## First failed stage (from stages.tsv)\n\n");
                out.push_str(&format!(
                    "- **Stage:** `{}` (rc={})\n- **Log:** `{}`\n\n",
                    first.0, first.2, first.3
                ));
            }
            out.push_str("## All failed stages (stages.tsv)\n\n");
            out.push_str("| stage | rc | log |\n|---|---|---|\n");
            for (stage, _status, rc, log) in &tsv_failures {
                out.push_str(&format!("| {stage} | {rc} | {log} |\n"));
            }
            out.push('\n');
        } else if orchestrate.is_none() && digest.is_none() && !tsv_path.exists() {
            // No evidence at all — fail closed.
            return tool_error(&format!(
                "No diagnosable evidence found in report dir `{}` (no orchestrate_result.json, \
                 no failure_digest.json, no stages.tsv). The run may not have started or \
                 completed. Check the run's job log or the report dir contents.",
                report_dir.display()
            ));
        } else if orchestrate.is_some() && first_failure_info.is_none() {
            out.push_str(
                "## stages.tsv\n\n_no failed stages recorded (all pass or skipped)._ \n\n",
            );
        }

        // ── 4. Stage-filtered log tail ─────────────────────────────────
        if let Some(stage_name) = stage_filter {
            let lower = stage_name.to_lowercase();
            let norm = lower
                .strip_prefix("linux_stage_")
                .or_else(|| lower.strip_prefix("macos_stage_"))
                .or_else(|| lower.strip_prefix("windows_stage_"))
                .unwrap_or(lower.as_str());
            out.push_str(&format!("## Stage log tail: `{stage_name}`\n\n"));
            let mut found = false;
            // Prefer matching row from stages.tsv for log path.
            if let Ok(body) = std::fs::read_to_string(&tsv_path) {
                for line in body.lines().filter(|l| !l.trim().is_empty()) {
                    let cols: Vec<&str> = line.split('\t').collect();
                    if cols.len() < 5 {
                        continue;
                    }
                    let name_l = cols[0].to_lowercase();
                    if !name_l.contains(norm) && !norm.contains(name_l.as_str()) {
                        continue;
                    }
                    let raw = cols[4];
                    for cand in [
                        PathBuf::from(raw),
                        report_dir.join(raw),
                        report_dir.join(raw.trim_start_matches("./")),
                    ] {
                        if cand.is_file() {
                            match read_file_capped(&cand, 1_000_000) {
                                Ok(content) => {
                                    out.push_str(&format!(
                                        "- **Log:** `{}`\n\n```\n{}\n```\n",
                                        cand.display(),
                                        truncate_tail(&content, 40, 16_000),
                                    ));
                                    found = true;
                                }
                                Err(e) => {
                                    out.push_str(&format!("_Cannot read log: {e}_\n"));
                                }
                            }
                            break;
                        }
                    }
                }
            }
            if !found {
                out.push_str("_No matching stage log found in stages.tsv. Use list_report_artifacts + read_report_artifact._\n");
            }
        }

        // ── 5. Triage guidance ─────────────────────────────────────────
        if collect_artifacts {
            out.push_str(
                "\n**Note:** `collect_artifacts` requires SSH into nodes (needs a profile). \
                 For a profile-less run use `list_report_artifacts` and `read_report_artifact` \
                 to browse the report dir directly.\n\n",
            );
        }
        out.push_str(
            "\n## Further triage\n\n\
             - `explain_stage(<first_failed_stage>)` — owning file + likely causes\n\
             - `get_stage_log(<stage>)` — full stage log from stages.tsv\n\
             - `grep_report(<pattern>)` — search all report artifacts\n\
             - `list_report_artifacts` — browse the report dir\n\
             - `read_report_artifact(<path>)` — read any file in the report dir\n",
        );

        tool_success(&out)
    }

    /// First inventory alias whose `platform` field matches (case-insensitive).
    /// Linux entries have no `platform` field, so this returns the windows/macos
    /// aliases used by auto-topology.
    fn inventory_alias_for_platform(&self, platform: &str) -> Option<String> {
        let s = std::fs::read_to_string(self.repo_root.join(DEFAULT_INVENTORY)).ok()?;
        let inv: Value = serde_json::from_str(&s).ok()?;
        inv.get("entries")?.as_array()?.iter().find_map(|e| {
            let p = e.get("platform").and_then(|v| v.as_str())?;
            p.eq_ignore_ascii_case(platform)
                .then(|| e.get("alias").and_then(|v| v.as_str()).map(String::from))
                .flatten()
        })
    }

    /// `(alias, lab_role)` for every Linux inventory entry (no `platform`
    /// field) that has both `alias` and `lab_role` set. This is the same
    /// Linux-backbone data `get_lab_topology` renders under "linux nodes (by
    /// lab_role)" — used here to auto-synthesize a Rust `--node` topology.
    fn inventory_linux_lab_roles(&self) -> Vec<(String, String)> {
        let Ok(s) = std::fs::read_to_string(self.repo_root.join(DEFAULT_INVENTORY)) else {
            return Vec::new();
        };
        let Ok(inv) = serde_json::from_str::<Value>(&s) else {
            return Vec::new();
        };
        inv.get("entries")
            .and_then(|v| v.as_array())
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.get("platform").and_then(|v| v.as_str()).is_none())
                    .filter_map(|e| {
                        let alias = e.get("alias").and_then(|v| v.as_str())?;
                        let role = e.get("lab_role").and_then(|v| v.as_str())?;
                        Some((alias.to_owned(), role.to_owned()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Untracked files under `crates/` — these are NOT captured by working-tree
    /// source deploy (`git stash create` only stashes tracked changes), so a
    /// patch that adds a new file won't reach the VMs until it's `git add`ed.
    fn untracked_crate_files(&self) -> Vec<String> {
        match run_with_timeout(
            "git",
            &["status", "--porcelain", "--untracked-files=all"],
            &self.repo_root,
            &[],
            Duration::from_secs(30),
        ) {
            Ok(o) if o.success => o
                .stdout
                .lines()
                .filter_map(|l| l.strip_prefix("?? "))
                .filter(|p| p.starts_with("crates/"))
                .take(20)
                .map(String::from)
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Secret-free topology digest + resolved auto-topology preview.
    fn get_lab_topology(&self) -> ToolCallResult {
        let s = match std::fs::read_to_string(self.repo_root.join(DEFAULT_INVENTORY)) {
            Ok(s) => s,
            Err(e) => return tool_error(&format!("Cannot read inventory: {e}")),
        };
        let inv: Value = match serde_json::from_str(&s) {
            Ok(v) => v,
            Err(e) => return tool_error(&format!("Invalid inventory JSON: {e}")),
        };
        let entries = inv
            .get("entries")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut out = String::from(
            "# Lab Topology\n\n| alias | platform | lab_role | exit | relay | in_all | mesh_ip |\n|---|---|---|---|---|---|---|\n",
        );
        let mut linux_roles: Vec<String> = Vec::new();
        for e in &entries {
            let g = |k: &str| e.get(k).and_then(|v| v.as_str()).unwrap_or("");
            let b = |k: &str| match e.get(k).and_then(|v| v.as_bool()) {
                Some(true) => "yes",
                Some(false) => "no",
                None => "-",
            };
            let platform = if g("platform").is_empty() {
                "linux"
            } else {
                g("platform")
            };
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                g("alias"),
                platform,
                g("lab_role"),
                b("exit_capable"),
                b("relay_capable"),
                b("include_in_all"),
                g("mesh_ip"),
            ));
            if platform == "linux" && !g("alias").is_empty() && !g("lab_role").is_empty() {
                linux_roles.push(format!("{}={}", g("alias"), g("lab_role")));
            }
        }

        out.push_str("\n## Auto-topology (what start_live_lab_run uses with no VM flags)\n");
        out.push_str(&format!(
            "- windows_vm → {}\n",
            self.inventory_alias_for_platform("windows")
                .unwrap_or_else(|| "(none in inventory)".into())
        ));
        out.push_str(&format!(
            "- macos_vm → {}\n",
            self.inventory_alias_for_platform("macos")
                .unwrap_or_else(|| "(none in inventory)".into())
        ));
        out.push_str(&format!(
            "- linux nodes (by lab_role) → {}\n",
            if linux_roles.is_empty() {
                "(none tagged)".into()
            } else {
                linux_roles.join(", ")
            }
        ));
        out.push_str(
            "\nOverride any with start_live_lab_run's `nodes` ('alias:role') / windows_vm / macos_vm. Credentials are intentionally omitted from MCP output.\n",
        );
        tool_success(&out)
    }

    /// "Show me every VM and whether it is on."
    ///
    /// Delegates to the controller-aware CLI (`ops vm-lab-discover-hosts`) rather
    /// than shelling `utmctl list` itself. It used to do the latter, which made it
    /// **structurally incapable of seeing a second host**: once the Linux/KVM box
    /// joined the lab, *the* "show me all VMs" tool silently omitted every guest on
    /// it and still read as a complete answer. A partial answer that looks total is
    /// worse than an error. Delegating also removes the duplicate power-state path
    /// (§3: one hardened execution path per workflow) — libvirt support arrives for
    /// free and there is nothing to keep in sync.
    /// Every declared host with its guests, via the controller-aware CLI.
    ///
    /// The one place that asks "what VMs exist and are they on?", shared by every
    /// tool that needs the answer. Both host kinds are covered because the CLI
    /// dispatches per controller; nothing here knows what a hypervisor is.
    fn discovered_hosts_json(&self) -> Result<Vec<Value>, String> {
        let outcome = run_with_timeout(
            "cargo",
            &[
                "run",
                "--quiet",
                "-p",
                "rustynet-cli",
                "--features",
                "vm-lab",
                "--",
                "ops",
                "vm-lab-discover-hosts",
                "--inventory",
                DEFAULT_INVENTORY,
                "--format",
                "json",
            ],
            &self.repo_root,
            &[("CARGO_TERM_COLOR", "never")],
            Duration::from_secs(120),
        )
        .map_err(|e| format!("could not run vm-lab-discover-hosts: {e}"))?;
        if !outcome.success {
            return Err(format!(
                "vm-lab-discover-hosts failed: {}",
                outcome.stderr.trim()
            ));
        }
        let parsed: Value = serde_json::from_str(outcome.stdout.trim())
            .map_err(|e| format!("could not parse vm-lab-discover-hosts JSON: {e}"))?;
        parsed
            .get("hosts")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| "vm-lab-discover-hosts JSON has no hosts array".to_owned())
    }

    /// `alias -> "started" | "stopped"` across EVERY host.
    ///
    /// Replaces a `utmctl list` map that could only answer for UTM guests, so a
    /// libvirt guest came back `power=unknown` even though virsh knows perfectly
    /// well. That is honest but useless exactly when it matters: a STOPPED box
    /// guest showed `power=unknown, TCP=false`, which reads as a network fault and
    /// hides the fact that the fix is `power_on_vm`.
    ///
    /// A host that could not be probed contributes nothing, so its guests stay
    /// `unknown` rather than being claimed stopped — absence of evidence is not
    /// evidence of absence.
    fn controller_status_map(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        let Ok(hosts) = self.discovered_hosts_json() else {
            return map;
        };
        for host in &hosts {
            if !host
                .get("probe_ok")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                continue;
            }
            let Some(guests) = host.get("guests").and_then(Value::as_array) else {
                continue;
            };
            for guest in guests {
                let running = guest
                    .get("running")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let status = if running { "started" } else { "stopped" };
                if let Some(alias) = guest.get("alias").and_then(Value::as_str) {
                    map.insert(alias.to_owned(), status.to_owned());
                }
                if let Some(domain) = guest.get("domain").and_then(Value::as_str) {
                    map.entry(domain.to_owned())
                        .or_insert_with(|| status.to_owned());
                }
            }
        }
        map
    }

    fn get_vm_power_state(&self, filter: Option<&str>) -> ToolCallResult {
        let hosts = match self.discovered_hosts_json() {
            Ok(h) => h,
            Err(e) => return tool_error(&e),
        };
        let hosts = &hosts;

        let mut out = String::from("# VM power state (all hosts)\n\n");
        out.push_str("| alias | domain | host | status | ip |\n|---|---|---|---|---|\n");
        let mut rows = 0usize;
        // A host we could not probe is reported, never skipped: "no VMs" must not
        // be indistinguishable from "could not ask".
        let mut unprobed: Vec<String> = Vec::new();

        for host in hosts {
            let host_id = host
                .get("host_id")
                .and_then(Value::as_str)
                .unwrap_or("(unknown)");
            if !host
                .get("probe_ok")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                unprobed.push(format!(
                    "- **{host_id}**: {}",
                    host.get("probe_error")
                        .and_then(Value::as_str)
                        .unwrap_or("probe failed")
                ));
                continue;
            }
            let Some(guests) = host.get("guests").and_then(Value::as_array) else {
                continue;
            };
            for guest in guests {
                let domain = guest.get("domain").and_then(Value::as_str).unwrap_or("-");
                let alias = guest.get("alias").and_then(Value::as_str).unwrap_or("-");
                if let Some(f) = filter
                    && f != domain
                    && f != alias
                {
                    continue;
                }
                let status = if guest
                    .get("running")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    "started"
                } else {
                    "stopped"
                };
                let ip = guest.get("ip").and_then(Value::as_str).unwrap_or("-");
                out.push_str(&format!(
                    "| {alias} | {domain} | {host_id} | {status} | {ip} |\n"
                ));
                rows += 1;
            }
        }
        if rows == 0 {
            out.push_str("| (none matched) | | | | |\n");
        }
        out.push_str(
            "\n_started + SSH-reachable = ready. started + unreachable = network/killswitch (recover_stuck_vms / update_inventory), NOT a power issue. stopped = power_on_vm._\n",
        );
        if !unprobed.is_empty() {
            out.push_str(&format!(
                "\n## ⚠️ Hosts that could NOT be probed — their VMs are NOT listed above\n{}\n",
                unprobed.join("\n")
            ));
        }
        tool_success(&out)
    }

    fn host_disk_status(&self) -> ToolCallResult {
        let mut out = String::from("# Host disk status\n\n## Filesystem (repo volume)\n");
        match run_with_timeout(
            "df",
            &["-h", &self.repo_root.to_string_lossy()],
            &self.repo_root,
            &[],
            Duration::from_secs(15),
        ) {
            Ok(o) if o.success => out.push_str(&format!("```\n{}\n```\n", o.stdout.trim())),
            _ => out.push_str("(df unavailable)\n"),
        }
        out.push_str("\n## Lab disk consumers\n");
        for dir in ["state", "target-livelab", "target"] {
            let p = self.repo_root.join(dir);
            if p.exists()
                && let Ok(o) = run_with_timeout(
                    "du",
                    &["-sh", &p.to_string_lossy()],
                    &self.repo_root,
                    &[],
                    Duration::from_secs(60),
                )
                && o.success
            {
                out.push_str(&format!("- {}\n", o.stdout.trim()));
            }
        }
        out.push_str(
            "\nReclaim with prune_jobs (old run dirs/logs). target-livelab is a warm build cache for lab jobs; target/ is the gate-runner build cache.\n",
        );
        tool_success(&out)
    }

    /// Footer naming the hosts a UTM-only answer does NOT cover.
    /// The precise reason an alias did not resolve to a UTM controller.
    ///
    /// `alias_to_utm` returns `None` both when the alias is absent AND when it is
    /// present but backed by a non-UTM controller (libvirt has no `utm_name`).
    /// Reporting the second case as "not in inventory" is a **lie** that sends an
    /// operator hunting a phantom inventory bug, so the two are told apart here.
    ///
    /// These tools are UTM-only by construction (they drive `utmctl`). The
    /// controller-aware path is the CLI — `ops vm-lab-start|stop|restart` already
    /// dispatch per controller (LinuxVmHostPlan §11 increment 2) — so the error
    /// points there rather than inviting a second, weaker virsh implementation
    /// inside the MCP (§3: one hardened path per workflow).
    fn utm_resolution_error(&self, alias: &str) -> String {
        let Ok(body) = std::fs::read_to_string(self.repo_root.join(DEFAULT_INVENTORY)) else {
            return format!("Unknown alias '{alias}' (inventory unreadable)");
        };
        let Ok(inv) = serde_json::from_str::<Value>(&body) else {
            return format!("Unknown alias '{alias}' (inventory unparseable)");
        };
        let entry = inv
            .get("entries")
            .and_then(|entries| entries.as_array())
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry.get("alias").and_then(|v| v.as_str()) == Some(alias))
            });
        let Some(entry) = entry else {
            return format!("Unknown alias '{alias}' (not in inventory)");
        };
        let kind = entry
            .get("controller")
            .and_then(|controller| controller.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("<none>");
        let host = entry
            .get("controller")
            .and_then(|controller| controller.get("host_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("<unset>");
        format!(
            "alias '{alias}' IS in the inventory but is not UTM-backed (controller.type={kind}, host_id={host}). \
             This tool drives utmctl and only serves local_utm guests. For a {kind} guest use the \
             controller-aware CLI (`ops vm-lab-start` / `vm-lab-stop` / `vm-lab-restart`), or the \
             discover_hosts / host_preflight tools for multi-host state."
        )
    }

    fn alias_to_utm(&self, alias: &str) -> Option<(String, String, String, u16)> {
        let s = std::fs::read_to_string(self.repo_root.join(DEFAULT_INVENTORY)).ok()?;
        let inv: Value = serde_json::from_str(&s).ok()?;
        inv.get("entries")?.as_array()?.iter().find_map(|e| {
            if e.get("alias").and_then(|v| v.as_str()) != Some(alias) {
                return None;
            }
            let utm_name = e
                .get("controller")
                .and_then(|c| c.get("utm_name"))
                .and_then(|v| v.as_str())?
                .to_string();
            let platform = e
                .get("platform")
                .and_then(|v| v.as_str())
                .unwrap_or("linux")
                .to_string();
            let ip = e
                .get("last_known_ip")
                .and_then(|v| v.as_str())
                .or_else(|| e.get("ssh_target").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_string();
            let port = e.get("ssh_port").and_then(|v| v.as_u64()).unwrap_or(22) as u16;
            Some((utm_name, platform, ip, port))
        })
    }

    /// utmctl power status (started/stopped/...) for one utm_name.
    fn utm_power_status(&self, utm_name: &str) -> Option<String> {
        let o = run_with_timeout(
            &utmctl_path(),
            &["list"],
            &self.repo_root,
            &[],
            Duration::from_secs(30),
        )
        .ok()?;
        if !o.success {
            return None;
        }
        o.stdout.lines().find_map(|line| {
            let t = line.trim();
            if t.is_empty() || t.starts_with("UUID") {
                return None;
            }
            let status = t.split_whitespace().nth(1)?;
            let name = t.get(t.find(status)? + status.len()..)?.trim();
            (name == utm_name).then(|| status.to_string())
        })
    }

    fn check_vm_reachable(&self, alias: &str) -> ToolCallResult {
        if alias.is_empty() {
            return tool_error("Missing required parameter: alias");
        }
        let Some((utm_name, _platform, ip, port)) = self.alias_to_utm(alias) else {
            return tool_error(&self.utm_resolution_error(alias));
        };
        let power = self
            .utm_power_status(&utm_name)
            .unwrap_or_else(|| "unknown".into());
        let reachable = tcp_reachable(&ip, port, Duration::from_secs(3));
        let (verdict, action) = match (power.as_str(), reachable) {
            ("stopped", _) => ("DOWN — powered off", "power_on_vm"),
            (_, true) => ("UP and reachable (TCP open)", "ready"),
            ("started", false) => (
                "UP but UNREACHABLE",
                "reset_vm_network (clears killswitch + restarts networking) or recover_stuck_vms. If it stays unreachable, the VM is likely on the wrong UTM network (NAT vs bridged — host-side fix) or has a stale inventory IP → update_inventory.",
            ),
            (_, false) => (
                "UNREACHABLE, power state unknown",
                "get_vm_power_state; power_on_vm if stopped",
            ),
        };
        tool_success(&format!(
            "# Reachability: {alias}\n\n- **utm_name:** {utm_name}\n- **power:** {power}\n- **address:** {}:{port}\n- **TCP/{port} reachable:** {reachable}\n- **verdict:** {verdict}\n- **suggested:** {action}\n",
            if ip.is_empty() {
                "(no IP in inventory)"
            } else {
                &ip
            }
        ))
    }

    /// Network recovery invalidates prior network evidence and forces a
    /// fresh preflight (LiveLabVmConnectivityRulebook §11.2/§11.3): the
    /// current `state/vm_network_evidence.json` is renamed aside (never
    /// deleted) and the caller is told to re-run audit/preflight.
    fn invalidate_network_evidence(&self, reason: &str) -> String {
        let evidence = self.repo_root.join("state/vm_network_evidence.json");
        if !evidence.is_file() {
            return format!(
                "\n## Network evidence\nNo current network evidence to invalidate. Re-run audit_lab_network / preflight_check before the next evidence run ({reason}).\n"
            );
        }
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let aside = self.repo_root.join(format!(
            "state/vm_network_evidence.invalidated-{stamp}.json"
        ));
        match std::fs::rename(&evidence, &aside) {
            Ok(()) => format!(
                "\n## Network evidence INVALIDATED\n{reason} changed network state, so the prior network evidence was moved aside to {}. Run audit_lab_network / preflight_check again before the next evidence run.\n",
                aside.display()
            ),
            Err(e) => format!(
                "\n## Network evidence\n\u{26a0}\u{fe0f} could not move the prior evidence aside ({e}); treat state/vm_network_evidence.json as STALE and re-run audit_lab_network before the next evidence run.\n"
            ),
        }
    }

    fn reset_vm_network(&self, alias: &str) -> ToolCallResult {
        if alias.is_empty() {
            return tool_error("Missing required parameter: alias");
        }
        let Some((utm_name, platform, ip, port)) = self.alias_to_utm(alias) else {
            return tool_error(&self.utm_resolution_error(alias));
        };
        match platform.as_str() {
            "macos" => {
                return tool_error(
                    "macOS UTM uses Apple Virtualization (no utmctl exec); reset its network via the serial console or manually.",
                );
            }
            "windows" => {
                return tool_error(
                    "reset_vm_network targets Linux guests; for Windows use restart_vm (power cycle) or power_off_vm force=true + power_on_vm.",
                );
            }
            _ => {}
        }
        // Must be running for the guest agent (utmctl exec) to work.
        match self.utm_power_status(&utm_name).as_deref() {
            Some("started") => {}
            Some(other) => {
                return tool_error(&format!(
                    "VM '{alias}' is '{other}', not started — power_on_vm first (utmctl exec needs a running guest)."
                ));
            }
            None => {} // unknown — attempt anyway
        }
        let utmctl = utmctl_path();
        // Out-of-band network reset (no SSH) via the QEMU guest agent.
        let steps: &[(&str, &[&str])] = &[
            ("flush killswitch (nft)", &["nft", "flush", "ruleset"]),
            ("stop rustynetd", &["systemctl", "stop", "rustynetd"]),
            (
                "stop privileged helper",
                &["systemctl", "stop", "rustynetd-privileged-helper"],
            ),
            (
                "restart systemd-networkd",
                &["systemctl", "restart", "systemd-networkd"],
            ),
            (
                "restart networking.service",
                &["systemctl", "restart", "networking"],
            ),
        ];
        let mut out = format!(
            "# Network reset: {alias} (utm_name={utm_name})\n\nOut-of-band via utmctl exec (no SSH needed).\n\n"
        );
        for (label, cmd) in steps {
            let mut argv: Vec<&str> = vec!["exec", &utm_name, "--cmd", "/usr/bin/sudo"];
            argv.extend_from_slice(cmd);
            match run_with_timeout(
                &utmctl,
                &argv,
                &self.repo_root,
                &[],
                Duration::from_secs(60),
            ) {
                Ok(o) => {
                    let tag = if o.success { "✅" } else { "⚠️" };
                    let msg = o.stderr.trim();
                    let suffix = if msg.is_empty() {
                        String::new()
                    } else {
                        format!(" — {}", truncate_output(msg, 3, 300))
                    };
                    out.push_str(&format!("- {tag} {label}{suffix}\n"));
                }
                Err(e) => out.push_str(&format!("- ❌ {label} — {e}\n")),
            }
        }
        std::thread::sleep(Duration::from_secs(5));
        let reachable = tcp_reachable(&ip, port, Duration::from_secs(3));
        out.push_str(&format!(
            "\n## Re-probe\n- TCP/{port} @ {} reachable: **{reachable}**\n",
            if ip.is_empty() { "(no IP)" } else { &ip }
        ));
        if !reachable {
            out.push_str(
                "\nStill unreachable from the host. Likely the VM is on the wrong UTM network (NAT vs bridged — fix the adapter in UTM, host-side), or its IP changed → run update_inventory then check_vm_reachable.\n",
            );
        }
        out.push_str(&self.invalidate_network_evidence("reset_vm_network"));
        tool_success(&out)
    }

    /// Out-of-band Linux guest network diagnostics via utmctl exec (no SSH).
    /// The triage companion to reset_vm_network: shows why a guest is
    /// unreachable (addresses, routes, the nft killswitch, daemon state) when
    /// SSH is dead.
    ///
    /// One root shell writes every probe (with `@@`-markers) to a single temp
    /// file; an unprivileged `cat` reads it back. Going through a complete file
    /// is what makes this reliable: the QEMU guest agent's stdout capture races
    /// on short, fast commands (a direct `systemctl is-active` is captured only
    /// ~2/3 of the time), and `sudo <cmd>` under use_pty returns nothing at all,
    /// so the privileged probes (nft/journalctl) would otherwise be blank.
    fn get_vm_network_info(&self, alias: &str) -> ToolCallResult {
        if alias.is_empty() {
            return tool_error("Missing required parameter: alias");
        }
        let Some((utm_name, platform, ip, port)) = self.alias_to_utm(alias) else {
            return tool_error(&self.utm_resolution_error(alias));
        };
        match platform.as_str() {
            "macos" => {
                return tool_error(
                    "macOS UTM uses Apple Virtualization (no utmctl exec); gather network info over SSH via get_vm_diagnostics or the serial console.",
                );
            }
            "windows" => {
                return tool_error(
                    "get_vm_network_info targets Linux guests (utmctl exec); for Windows use get_vm_diagnostics over SSH.",
                );
            }
            _ => {}
        }
        // The guest agent (utmctl exec) only answers on a running VM.
        match self.utm_power_status(&utm_name).as_deref() {
            Some("started") => {}
            Some(other) => {
                return tool_error(&format!(
                    "VM '{alias}' is '{other}', not started — power_on_vm first (utmctl exec needs a running guest)."
                ));
            }
            None => {} // unknown — attempt anyway
        }
        let utmctl = utmctl_path();
        let reachable = tcp_reachable(&ip, port, Duration::from_secs(3));
        let mut out = format!(
            "# Network info: {alias} (utm_name={utm_name})\n\nOut-of-band via utmctl exec (no SSH needed).\n\n- **address:** {}:{port}\n- **TCP/{port} reachable from host:** {reachable}\n",
            if ip.is_empty() { "(no IP)" } else { &ip }
        );
        // Static, no untrusted interpolation — the alias only reaches utmctl as a
        // separate argv element, never this in-guest script.
        const PROBE_SCRIPT: &str = "{ \
            echo '@@ip addr'; ip addr; \
            echo '@@ip route'; ip route; \
            echo '@@rustynetd active?'; systemctl is-active rustynetd; \
            echo '@@nft ruleset (killswitch)'; nft list ruleset; \
            echo '@@rustynetd recent log'; journalctl -u rustynetd --no-pager -n 30; \
            } > /tmp/rn_netinfo 2>&1";
        // Step 1: one root shell writes all probes to the temp file.
        let _ = run_with_timeout(
            &utmctl,
            &[
                "exec",
                &utm_name,
                "--cmd",
                "/usr/bin/sudo",
                "/bin/sh",
                "-c",
                PROBE_SCRIPT,
            ],
            &self.repo_root,
            &[],
            Duration::from_secs(90),
        );
        // Step 2: unprivileged read of the complete file (one retry — a large
        // file's cat is reliable, but guard the rare empty first read).
        let mut raw = String::new();
        for attempt in 0..2 {
            match run_with_timeout(
                &utmctl,
                &["exec", &utm_name, "--cmd", "/bin/cat", "/tmp/rn_netinfo"],
                &self.repo_root,
                &[],
                Duration::from_secs(60),
            ) {
                Ok(o) if !o.stdout.trim().is_empty() => {
                    raw = o.stdout;
                    break;
                }
                Ok(_) => {
                    if attempt == 0 {
                        std::thread::sleep(Duration::from_millis(400));
                    }
                }
                Err(e) => return tool_error(&format!("guest read failed: {e}")),
            }
        }
        if raw.trim().is_empty() {
            out.push_str(
                "\n_No probe output captured (guest agent may be slow). Retry, or use get_vm_diagnostics over SSH._\n",
            );
            return tool_success(&out);
        }
        // Split the combined output on the @@section markers.
        let mut sections: Vec<(String, String)> = Vec::new();
        let mut cur_label: Option<String> = None;
        let mut cur_body = String::new();
        for line in raw.lines() {
            if let Some(label) = line.strip_prefix("@@") {
                if let Some(prev) = cur_label.take() {
                    sections.push((prev, std::mem::take(&mut cur_body)));
                }
                cur_label = Some(label.to_string());
            } else if cur_label.is_some() {
                cur_body.push_str(line);
                cur_body.push('\n');
            }
        }
        if let Some(prev) = cur_label.take() {
            sections.push((prev, cur_body));
        }
        for (label, body) in &sections {
            let trimmed = body.trim();
            let shown = if trimmed.is_empty() {
                "(no output)".to_string()
            } else {
                truncate_tail(trimmed, 60, 6_000)
            };
            out.push_str(&format!("\n## {label}\n```\n{shown}\n```\n"));
        }
        out.push_str(
            "\nIf the nft ruleset is a stale killswitch blocking SSH → reset_vm_network. If addresses look wrong (NAT subnet) → the VM is on the wrong UTM network (host-side fix). If the daemon log shows repeated reconcile/fail-closed errors → that's your patch target.\n",
        );
        tool_success(&out)
    }

    /// Diagnose HOST-side routing to lab VM subnets — the failure class none
    /// of the guest-facing tools (check_vm_reachable, reset_vm_network,
    /// get_vm_network_info) can see, because it isn't a guest problem: the
    /// host's own kernel route table doesn't know how to reach the VM's
    /// subnet at all. Two distinct causes, both hit live in the same
    /// session: (1) a QEMU-bridged/shared VM (linux/windows) — the host
    /// physically isn't on that LAN right now (Wi-Fi/Ethernet roam), not
    /// fixable remotely; (2) the macOS VM's Apple-Virtualization NAT subnet
    /// — the host's route to it is stale or missing (a dead mesh-session
    /// gateway, or a VPN default route swallowing it), fixable with one
    /// `route add`, which this tool derives and prints but does not execute
    /// (needs sudo). `alias` filters to one node; omit for all of them.
    fn diagnose_host_lab_network(&self, alias: Option<&str>) -> ToolCallResult {
        let inv_entries = match std::fs::read_to_string(self.repo_root.join(DEFAULT_INVENTORY)) {
            Ok(s) => match serde_json::from_str::<Value>(&s) {
                Ok(v) => v
                    .get("entries")
                    .and_then(|e| e.as_array())
                    .cloned()
                    .unwrap_or_default(),
                Err(e) => return tool_error(&format!("inventory invalid JSON: {e}")),
            },
            Err(e) => return tool_error(&format!("inventory unreadable: {e}")),
        };

        let mut out = String::from("# Host lab-network diagnosis\n\n");
        let mut any_actionable = false;
        let mut checked = 0u32;

        for e in &inv_entries {
            let entry_alias = e.get("alias").and_then(|v| v.as_str()).unwrap_or("");
            if entry_alias.is_empty() {
                continue;
            }
            if let Some(only) = alias
                && only != entry_alias
            {
                continue;
            }
            let platform = e
                .get("platform")
                .and_then(|v| v.as_str())
                .unwrap_or("linux");
            let inventory_ip = e
                .get("last_known_ip")
                .and_then(|v| v.as_str())
                .or_else(|| e.get("ssh_target").and_then(|v| v.as_str()))
                .unwrap_or("");
            // Freshness FIRST, before any route diagnosis: a VM's UTM
            // "Shared" subnet can be silently reallocated on every restart,
            // which otherwise looks identical to "host off this LAN" (both
            // present as zero interfaces owning the stale subnet). Resolve
            // the CURRENT live IP via ARP-by-MAC and diagnose against that
            // instead of blindly trusting inventory.
            let bundle_path = e
                .get("controller")
                .and_then(|c| c.get("bundle_path"))
                .and_then(|v| v.as_str());
            let fresh_ip = bundle_path.and_then(|p| resolve_live_ip_via_arp_by_mac(Path::new(p)));
            let ip: String = fresh_ip.clone().unwrap_or_else(|| inventory_ip.to_owned());
            let Ok(target) = ip.parse::<Ipv4Addr>() else {
                out.push_str(&format!(
                    "- ⏭️ {entry_alias}: no IPv4 last_known_ip/ssh_target in inventory, skipped\n"
                ));
                continue;
            };
            checked += 1;
            if let Some(fresh) = fresh_ip.as_deref()
                && !inventory_ip.is_empty()
                && fresh != inventory_ip
            {
                any_actionable = true;
                out.push_str(&format!(
                    "  ℹ️ {entry_alias}: inventory is STALE — says {inventory_ip}, but the VM's MAC currently resolves to {fresh} (ARP). Diagnosing against the fresh address below; run update_inventory to persist it.\n"
                ));
            }

            // The most basic, most common cause of "unreachable" is simply
            // "the VM is off" — check this BEFORE any host-routing
            // diagnosis, or a stopped VM (whose UTM-managed bridge/vmenet
            // interface gets torn down with it) reads as a confusing
            // routing problem instead of the obvious fix.
            if let Some(utm_name) = e
                .get("controller")
                .and_then(|c| c.get("utm_name"))
                .and_then(|v| v.as_str())
                && let Some(power) = self.utm_power_status(utm_name)
                && power != "started"
            {
                any_actionable = true;
                out.push_str(&format!(
                    "- ⏸️ {entry_alias} ({ip}, {platform}): VM is '{power}', not running — power_on_vm first. (Any host-routing state below would be stale/misleading while the VM's bridge interface doesn't exist.)\n"
                ));
                continue;
            }

            let route_out = run_with_timeout(
                "route",
                &["get", &target.to_string()],
                &self.repo_root,
                &[],
                Duration::from_secs(5),
            );
            let route = match &route_out {
                Ok(o) if o.success => parse_route_get_output(&o.stdout),
                Ok(o) => {
                    out.push_str(&format!(
                        "- ❌ {entry_alias} ({ip}): `route get` failed — {}\n",
                        truncate_output(o.stderr.trim(), 2, 200)
                    ));
                    continue;
                }
                Err(err) => {
                    out.push_str(&format!(
                        "- ❌ {entry_alias} ({ip}): could not run `route get` — {err}\n"
                    ));
                    continue;
                }
            };
            let Some(route) = route else {
                out.push_str(&format!(
                    "- ❌ {entry_alias} ({ip}): unparseable `route get` output\n"
                ));
                continue;
            };

            let owning = host_interfaces_in_same_slash24(target);
            let verdict = classify_host_route(&route, &owning);
            let observed_iface = route.interface.as_deref().unwrap_or("(none)");
            let port = e.get("ssh_port").and_then(|v| v.as_u64()).unwrap_or(22) as u16;

            match verdict {
                HostLabRouteVerdict::Correct => {
                    // The route table alone isn't sufficient: two UTM
                    // bridges can both legitimately own the same default
                    // NAT subnet without both leading to THIS VM (found
                    // live — a shared multi-VM bridge and a private per-VM
                    // bridge both claiming 192.168.64.0/24). Confirm real
                    // reachability, not just an interface-name match.
                    if tcp_reachable(&ip, port, Duration::from_secs(2)) {
                        out.push_str(&format!(
                            "- ✅ {entry_alias} ({ip}, {platform}): host route correct (via `{observed_iface}`), TCP/{port} reachable\n"
                        ));
                    } else {
                        any_actionable = true;
                        out.push_str(&format!(
                            "- ⚠️ {entry_alias} ({ip}, {platform}): host route LOOKS correct (via `{observed_iface}`) but TCP/{port} is NOT reachable — possible duplicate-subnet bridge collision (another interface may also claim this /24 without actually leading here) or a guest-side issue (see check_vm_reachable/reset_vm_network).\n"
                        ));
                    }
                }
                HostLabRouteVerdict::StaleOrMissing => {
                    any_actionable = true;
                    let expected = owning.first().map(String::as_str).unwrap_or("?");
                    let octets = target.octets();
                    let subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
                    out.push_str(&format!(
                        "- 🛠️ {entry_alias} ({ip}, {platform}): HOST ROUTE STALE/MISSING — resolves via `{observed_iface}` (destination `{}`) but `{expected}` actually owns this subnet.\n  **Fix:** `sudo route add -net {subnet} -interface {expected}` (or call apply_host_route_fix, which verifies real reachability and tries every candidate interface if there's more than one)\n",
                        route.destination
                    ));
                    if owning.len() > 1 {
                        out.push_str(&format!(
                            "  ⚠️ {} interfaces claim this subnet ({}) — likely two UTM VMs both defaulted to the same NAT range; the suggested fix above may pick the wrong one, worth investigating separately.\n",
                            owning.len(),
                            owning.join(", ")
                        ));
                    }
                }
                HostLabRouteVerdict::OffLabLan => {
                    any_actionable = true;
                    out.push_str(&format!(
                        "- 🌐 {entry_alias} ({ip}, {platform}): HOST OFF THIS LAN — no local interface currently owns this subnet (resolves via `{observed_iface}`, destination `{}`), and the VM's MAC could not be resolved anywhere via ARP either (already checked above, not just a stale-inventory case). This is a physical network change, not fixable remotely — reconnect the host to the lab network.\n",
                        route.destination
                    ));
                }
            }
        }

        if checked == 0 {
            return tool_error(&match alias {
                Some(a) => format!("no inventory entry '{a}' with a usable IP found"),
                None => "no inventory entries with a usable IP found".to_string(),
            });
        }

        out.push_str(&format!(
            "\n**{checked} node(s) checked{}.**\n",
            if any_actionable {
                " — action needed on at least one (see 🛠️/🌐 above)"
            } else {
                ", all host routes look correct"
            }
        ));
        tool_success(&out)
    }

    /// Apply the fix `diagnose_host_lab_network` can only prescribe: re-runs
    /// the SAME diagnosis fresh (this tool never accepts a raw command from
    /// the caller — the fix command is always derived internally from the
    /// live route/interface state, never free text), and if the verdict is
    /// the fixable one (stale/missing host route), runs the `route`
    /// delete+add pair via `osascript ... with administrator privileges`.
    /// That's macOS's native authorization prompt: the password/Touch ID
    /// goes straight into the OS's Security Server on the user's own
    /// screen — this process, and the calling agent, never see it, never
    /// log it, never transmit it. If the verdict is "host off this LAN"
    /// there is nothing to fix (a physical network fact); if it's already
    /// correct this is a no-op. Re-verifies the route after a successful
    /// run before reporting success.
    fn apply_host_route_fix(&self, alias: &str) -> ToolCallResult {
        if alias.is_empty() {
            return tool_error("Missing required parameter: alias");
        }
        let inv_entries = match std::fs::read_to_string(self.repo_root.join(DEFAULT_INVENTORY)) {
            Ok(s) => match serde_json::from_str::<Value>(&s) {
                Ok(v) => v
                    .get("entries")
                    .and_then(|e| e.as_array())
                    .cloned()
                    .unwrap_or_default(),
                Err(e) => return tool_error(&format!("inventory invalid JSON: {e}")),
            },
            Err(e) => return tool_error(&format!("inventory unreadable: {e}")),
        };
        let Some(entry) = inv_entries
            .iter()
            .find(|e| e.get("alias").and_then(|v| v.as_str()) == Some(alias))
        else {
            return tool_error(&self.utm_resolution_error(alias));
        };
        let platform = entry
            .get("platform")
            .and_then(|v| v.as_str())
            .unwrap_or("linux");
        let inventory_ip = entry
            .get("last_known_ip")
            .and_then(|v| v.as_str())
            .or_else(|| entry.get("ssh_target").and_then(|v| v.as_str()))
            .unwrap_or("");
        // Freshness FIRST, same reasoning as diagnose_host_lab_network: a
        // VM's UTM "Shared" subnet can be silently reallocated on every
        // restart, so trust ARP-by-MAC over inventory's possibly-stale IP.
        let bundle_path = entry
            .get("controller")
            .and_then(|c| c.get("bundle_path"))
            .and_then(|v| v.as_str());
        let fresh_ip = bundle_path.and_then(|p| resolve_live_ip_via_arp_by_mac(Path::new(p)));
        let stale_inventory_note = fresh_ip
            .as_deref()
            .filter(|fresh| !inventory_ip.is_empty() && *fresh != inventory_ip)
            .map(|fresh| {
                format!(
                    "inventory was stale (said {inventory_ip}, MAC resolves to {fresh} via ARP) — "
                )
            })
            .unwrap_or_default();
        let ip: String = fresh_ip.clone().unwrap_or_else(|| inventory_ip.to_owned());
        let Ok(target) = ip.parse::<Ipv4Addr>() else {
            return tool_error(&format!(
                "'{alias}' has no IPv4 last_known_ip/ssh_target in inventory"
            ));
        };

        // Refuse outright if the VM is off — its UTM-managed bridge/vmenet
        // interface is torn down with it, so any route-add attempt fails
        // with a confusing `route: bad address: <iface>` error instead of
        // the actual, obvious fix (power_on_vm).
        if let Some(utm_name) = entry
            .get("controller")
            .and_then(|c| c.get("utm_name"))
            .and_then(|v| v.as_str())
            && let Some(power) = self.utm_power_status(utm_name)
            && power != "started"
        {
            return tool_error(&format!(
                "'{alias}' ({ip}, {platform}): VM is '{power}', not running — power_on_vm first, then retry. A stopped VM's bridge interface doesn't exist, so any route fix would fail anyway."
            ));
        }

        let route = match run_with_timeout(
            "route",
            &["get", &target.to_string()],
            &self.repo_root,
            &[],
            Duration::from_secs(5),
        ) {
            Ok(o) if o.success => parse_route_get_output(&o.stdout),
            Ok(o) => {
                return tool_error(&format!("`route get` failed: {}", o.stderr.trim()));
            }
            Err(e) => return tool_error(&format!("could not run `route get`: {e}")),
        };
        let Some(route) = route else {
            return tool_error("unparseable `route get` output");
        };
        let owning = host_interfaces_in_same_slash24(target);
        let verdict = classify_host_route(&route, &owning);
        let port = entry.get("ssh_port").and_then(|v| v.as_u64()).unwrap_or(22) as u16;

        // Reachability, not the route-table classification alone, is the
        // single source of truth for "is there anything to do" — two UTM
        // bridges can both legitimately own the same default NAT subnet
        // without both leading to THIS VM (found live: a shared multi-VM
        // bridge and a private per-VM bridge both claiming
        // 192.168.64.0/24), so `classify_host_route` saying "Correct" does
        // NOT guarantee the guest actually answers.
        if verdict != HostLabRouteVerdict::OffLabLan
            && tcp_reachable(&target.to_string(), port, Duration::from_secs(3))
        {
            return tool_success(&format!(
                "# Route fix: {alias}\n\n{stale_inventory_note}Already correct (via `{}`) and TCP/{port} reachable — nothing to do.\n",
                route.interface.as_deref().unwrap_or("?")
            ));
        }
        if verdict == HostLabRouteVerdict::OffLabLan {
            return tool_error(&format!(
                "'{alias}' ({ip}, {platform}): host is off this VM's LAN — no local interface currently owns that subnet, and the VM's MAC could not be resolved anywhere via ARP either (not just a stale-inventory case). This is a physical network change, not something this tool can fix — reconnect the host, then retry."
            ));
        }
        if owning.is_empty() {
            return tool_error("internal error: not OffLabLan but no owning interface");
        }

        let octets = target.octets();
        let subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
        let mut tried: Vec<String> = Vec::new();

        for interface in &owning {
            if !is_safe_interface_name(interface) {
                continue;
            }
            tried.push(interface.clone());
            let shell_cmd = build_route_fix_shell_command(&target.to_string(), &subnet, interface);
            let prompt = format!(
                "RustyNet lab wants to fix the host route to {subnet} (via {interface}) for VM '{alias}'."
            );
            let applescript = format!(
                "do shell script {} with prompt {} with administrator privileges",
                apple_script_string_literal(&shell_cmd),
                apple_script_string_literal(&prompt)
            );
            match run_with_timeout(
                "osascript",
                &["-e", &applescript],
                &self.repo_root,
                &[],
                Duration::from_secs(240),
            ) {
                Ok(o) if o.success => {
                    std::thread::sleep(Duration::from_millis(300));
                    if tcp_reachable(&target.to_string(), port, Duration::from_secs(5)) {
                        let invalidation = self.invalidate_network_evidence("apply_host_route_fix");
                        return tool_success(&format!(
                            "# Route fix: {alias}\n\n{stale_inventory_note}✅ Applied and confirmed reachable: `{subnet}` now routes via `{interface}` (TCP/{port} open).\n{invalidation}"
                        ));
                    }
                    // Route looks structurally fine but the guest still
                    // isn't answering here — try the next candidate
                    // interface, if any.
                }
                Ok(o) if o.timed_out => {
                    // The AppleScript authorization dialog has no timeout of
                    // its own — this is OUR watchdog killing a process that
                    // was (as far as we know) still waiting on the user.
                    // Report this distinctly from a real failure: an empty
                    // stderr + "failed" reads as a mysterious dead end,
                    // when what actually happened is the dialog was never
                    // seen/approved in time.
                    return tool_error(&format!(
                        "No response within 240s to the authorization prompt for `{interface}` — it may have appeared behind another window/Space, or on a display that wasn't visible. No changes made. Bring the frontmost app to Terminal/Claude and retry, watching for a native macOS password/Touch ID dialog."
                    ));
                }
                Ok(o) => {
                    let stderr = o.stderr.trim();
                    if stderr.contains("User canceled") || stderr.contains("(-128)") {
                        return tool_error(
                            "Authorization prompt was canceled by the user — no changes made.",
                        );
                    }
                    return tool_error(&format!(
                        "route fix failed via `{interface}`: {}",
                        truncate_output(stderr, 5, 400)
                    ));
                }
                Err(e) => return tool_error(&format!("could not invoke osascript: {e}")),
            }
        }

        tool_error(&format!(
            "Tried {} interface(s) claiming `{subnet}` ({}) — none resulted in a reachable TCP/{port} on {alias} ({ip}). The route table now points at `{}`, but the guest still isn't answering; this may be a guest-side issue (see check_vm_reachable/reset_vm_network) rather than a host-routing one.",
            tried.len(),
            tried.join(", "),
            tried.last().map(String::as_str).unwrap_or("?")
        ))
    }

    /// Real TCP-level check that a guest can actually reach the internet
    /// THROUGH the tunnel (not just that the tunnel process is alive) — run
    /// on the guest itself over the existing key-based SSH exec, same
    /// mechanism every other remote-command tool here uses.
    fn check_vm_internet_reachable(&self, ssh_target: &str, ssh_user: &str) -> bool {
        let script = format!(
            "curl -sS -x socks5h://127.0.0.1:{VM_INTERNET_PROXY_PORT} -m 8 -o /dev/null -w '%{{http_code}}' https://static.rust-lang.org/ 2>/dev/null"
        );
        self.ssh_exec(ssh_target, ssh_user, &script, Duration::from_secs(15))
            .map(|o| o.success && o.stdout.trim().starts_with('2'))
            .unwrap_or(false)
    }

    /// Same check with no proxy involved — is the guest's own, un-tunneled
    /// route to the internet working right now?
    fn check_vm_internet_reachable_direct(&self, ssh_target: &str, ssh_user: &str) -> bool {
        let script = "curl -sS -m 8 -o /dev/null -w '%{http_code}' https://static.rust-lang.org/ 2>/dev/null";
        self.ssh_exec(ssh_target, ssh_user, script, Duration::from_secs(15))
            .map(|o| o.success && o.stdout.trim().starts_with('2'))
            .unwrap_or(false)
    }

    /// Explain WHY a guest can't reach the internet directly, distinguishing
    /// the two failure modes found live in this lab: (1) UTM's isolated
    /// internal Shared-Network bridge not completing its own NAT forward —
    /// independent of which physical network the host is on, confirmed by
    /// it failing identically across a host network change; vs (2) the
    /// guest sitting on a REAL physical-LAN gateway (MACNAT'd) that the
    /// physical network itself gates by MAC address (captive portal /
    /// 802.1X) — the guest's virtual MAC was never individually admitted,
    /// unlike the host's own physical MAC. Both present identically as
    /// "reaches gateway, nothing beyond" if you only check reachability;
    /// this tells them apart so the fix (or "not fixable, use the tunnel")
    /// is clear instead of another blind diagnosis-by-hand.
    fn diagnose_guest_internet_blocker(&self, ssh_target: &str, ssh_user: &str) -> String {
        let host_has_internet = run_with_timeout(
            "curl",
            &[
                "-sS",
                "-m",
                "5",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "https://static.rust-lang.org/",
            ],
            &self.repo_root,
            &[],
            Duration::from_secs(10),
        )
        .map(|o| o.success && o.stdout.trim().starts_with('2'))
        .unwrap_or(false);
        if !host_has_internet {
            return "the HOST itself has no internet access right now — not fixable from this tool; check the host's own network connection.".to_owned();
        }

        let Ok(target) = ssh_target.parse::<Ipv4Addr>() else {
            return "internet reachable from the host, but the guest's target IP isn't a parseable IPv4 address, so its network path couldn't be classified.".to_owned();
        };
        let owning = host_interfaces_in_same_slash24(target);
        let network_path = classify_guest_network_path(&owning);

        let gateway = self
            .ssh_exec(
                ssh_target,
                ssh_user,
                "ip route 2>/dev/null | awk '/default/{print $3; exit}'",
                Duration::from_secs(10),
            )
            .map(|o| o.stdout.trim().to_owned())
            .unwrap_or_default();
        let gateway_reachable = if gateway.is_empty() {
            false
        } else {
            let ping_script =
                format!("ping -c2 -W2 {gateway} >/dev/null 2>&1 && echo OK || echo FAIL");
            self.ssh_exec(ssh_target, ssh_user, &ping_script, Duration::from_secs(15))
                .map(|o| o.stdout.trim() == "OK")
                .unwrap_or(false)
        };

        if !gateway_reachable {
            return format!(
                "the guest can't even reach its own gateway ({}) — this is a host-routing or guest-network-config issue, not an internet-access one; see diagnose_host_lab_network.",
                if gateway.is_empty() {
                    "unknown".to_owned()
                } else {
                    gateway
                }
            );
        }
        match network_path {
            "physical-lan" => "guest reaches its gateway (a REAL physical-LAN router, the same one the host uses) but not beyond, while the host itself has full internet — classic per-device network admission control (captive portal / 802.1X): the guest's own virtual MAC was never individually authenticated to this network, unlike the host's physical MAC. Not fixable by this tool; use set_vm_internet_access enable, or sign this guest's MAC into the portal directly if the network supports multiple devices.".to_owned(),
            "isolated-utm-bridge" => "guest reaches its (UTM-internal virtual) gateway but not beyond, while the host itself has full internet — this looks like UTM/Apple-Virtualization's Shared-Network NAT not completing the forward to the real network, independent of which physical network the host is on (the same bridge failed identically across a host network change). Not something fixable directly; use set_vm_internet_access enable to route around it.".to_owned(),
            _ => "guest reaches its gateway but not beyond, and the owning interface's nature could not be classified. Use set_vm_internet_access enable to route around it regardless.".to_owned(),
        }
    }

    /// Give a lab VM internet access without an agent ever hand-typing SSH:
    /// spawns (enable), tears down (disable), or reports (status) a reverse
    /// dynamic SOCKS tunnel — `ssh -R 1080 user@guest` — so the guest routes
    /// outbound traffic through the HOST's own internet connection. Exists
    /// because UTM's "Shared" NAT subnets have no outbound path of their own
    /// in this lab (confirmed live: guest reaches its gateway, nothing
    /// beyond it, despite host IP forwarding being on — a UTM/vmnet-layer
    /// gap, not a rustynet one), which otherwise blocks `dnf`/`apt-get`
    /// install and the rustup bootstrap entirely on a fresh guest.
    fn set_vm_internet_access(&self, args: Option<&Value>) -> ToolCallResult {
        let Some(alias) = arg_str(args, "alias") else {
            return tool_error("Missing required parameter: alias");
        };
        let action = arg_str(args, "action").unwrap_or("enable");
        if !is_valid_vm_internet_access_action(action) {
            return tool_error(&format!(
                "Unknown action '{action}' — expected enable, disable, or status"
            ));
        }

        let inv_entries = match std::fs::read_to_string(self.repo_root.join(DEFAULT_INVENTORY)) {
            Ok(s) => match serde_json::from_str::<Value>(&s) {
                Ok(v) => v
                    .get("entries")
                    .and_then(|e| e.as_array())
                    .cloned()
                    .unwrap_or_default(),
                Err(e) => return tool_error(&format!("inventory invalid JSON: {e}")),
            },
            Err(e) => return tool_error(&format!("inventory unreadable: {e}")),
        };
        let Some(entry) = inv_entries
            .iter()
            .find(|e| e.get("alias").and_then(|v| v.as_str()) == Some(alias))
        else {
            return tool_error(&self.utm_resolution_error(alias));
        };
        let ssh_target = entry
            .get("last_known_ip")
            .and_then(|v| v.as_str())
            .or_else(|| entry.get("ssh_target").and_then(|v| v.as_str()))
            .unwrap_or("");
        let ssh_user = entry.get("ssh_user").and_then(|v| v.as_str()).unwrap_or("");
        if ssh_target.is_empty() || ssh_user.is_empty() {
            return tool_error(&format!(
                "'{alias}' is missing ssh_target/ssh_user in inventory"
            ));
        }

        let existing_pid = read_vm_internet_tunnel_pid(&self.repo_root, alias);
        let tunnel_alive = existing_pid.map(host_pid_alive).unwrap_or(false);

        match action {
            "status" => {
                let direct_reachable =
                    self.check_vm_internet_reachable_direct(ssh_target, ssh_user);
                let mut out = format!(
                    "# VM internet access: {alias}\n\n- direct internet (no tunnel): {direct_reachable}\n"
                );
                if !direct_reachable {
                    out.push_str(&format!(
                        "  - diagnosis: {}\n",
                        self.diagnose_guest_internet_blocker(ssh_target, ssh_user)
                    ));
                }
                if tunnel_alive {
                    let reachable = self.check_vm_internet_reachable(ssh_target, ssh_user);
                    out.push_str(&format!(
                        "- tunnel: ACTIVE (host pid {})\n- internet reachable through tunnel: {reachable}\n",
                        existing_pid.unwrap_or(0)
                    ));
                } else {
                    out.push_str("- tunnel: not active\n");
                }
                tool_success(&out)
            }
            "disable" => {
                // Bind the real pid rather than `unwrap_or(0)`: makes the
                // `tunnel_alive ⟹ existing_pid.is_some()` invariant explicit and
                // keeps a stray 0 out of `kill_process_group` (`kill -- -<pid>`,
                // where group 0 means "the caller's own group"). The server
                // self-signal is already unreachable — both via that invariant and
                // because `run_with_timeout` runs each `kill` in its own process
                // group — so this is defense-in-depth + clarity, not a live-bug fix.
                if tunnel_alive && let Some(pid) = existing_pid {
                    self.kill_process_group(u64::from(pid));
                }
                remove_vm_internet_tunnel_state(&self.repo_root, alias);
                tool_success(&format!(
                    "# VM internet access: {alias}\n\n✅ Disabled{}.\n",
                    if tunnel_alive {
                        " — tunnel stopped"
                    } else {
                        " (nothing was running)"
                    }
                ))
            }
            "enable" => {
                if tunnel_alive {
                    let reachable = self.check_vm_internet_reachable(ssh_target, ssh_user);
                    return tool_success(&format!(
                        "# VM internet access: {alias}\n\nAlready enabled (host pid {}) — internet reachable through it: {reachable}.\n",
                        existing_pid.unwrap_or(0)
                    ));
                }
                let dest = format!("{ssh_user}@{ssh_target}");
                let log_dir = self.repo_root.join("state/vm-internet-tunnels");
                if let Err(e) = std::fs::create_dir_all(&log_dir) {
                    return tool_error(&format!("cannot create {}: {e}", log_dir.display()));
                }
                let log_path = log_dir.join(format!("{alias}.log"));
                // Reuse the crate's hardened SSH transport policy (strict host-key
                // checking + BatchMode + IdentitiesOnly + known_hosts + identity)
                // rather than a bespoke, weaker inline arg set. Beyond the obvious
                // hardening (the old inline args used `StrictHostKeyChecking=no`),
                // this keeps the persistent forwarding tunnel and the reachability
                // probe (`ssh_exec`, which also builds on `ssh_transport_opts`) on
                // IDENTICAL host-key policy: previously the tunnel used `=no` while
                // the probe used `=yes`, so a guest the tunnel accepted but the
                // probe rejected got its otherwise-healthy tunnel torn down as a
                // false "unreachable".
                let opts = build_vm_internet_tunnel_argv(
                    self.ssh_transport_opts(),
                    VM_INTERNET_PROXY_PORT,
                    dest,
                );
                let argv: Vec<&str> = opts.iter().map(String::as_str).collect();
                let pid = match spawn_logged("ssh", &argv, &self.repo_root, &[], &log_path) {
                    Ok(child) => child.id(),
                    Err(e) => return tool_error(&format!("failed to start tunnel: {e}")),
                };
                std::thread::sleep(Duration::from_millis(1500));
                if !host_pid_alive(pid) {
                    return tool_error(&format!(
                        "SSH reverse tunnel for '{alias}' exited immediately — check {} for details (likely auth or connectivity failure).",
                        log_path.display()
                    ));
                }
                if !self.check_vm_internet_reachable(ssh_target, ssh_user) {
                    self.kill_process_group(u64::from(pid));
                    return tool_error(&format!(
                        "Tunnel process started (pid {pid}) but the guest still can't reach the internet through it — check {} and the guest's own network state.",
                        log_path.display()
                    ));
                }
                if let Err(e) = write_vm_internet_tunnel_pid(&self.repo_root, alias, pid) {
                    // Can't track it → don't leave it: an unpersisted tunnel is an
                    // orphan a later `disable` can't find. Stop it and fail loud.
                    self.kill_process_group(u64::from(pid));
                    return tool_error(&format!(
                        "tunnel started (pid {pid}) but its state could not be persisted, so it was stopped to avoid an untracked orphan: {e}"
                    ));
                }
                tool_success(&format!(
                    "# VM internet access: {alias}\n\n✅ Enabled — reverse SOCKS proxy on the guest's 127.0.0.1:{VM_INTERNET_PROXY_PORT} (host pid {pid}), internet reachability confirmed.\n\nGuest-side usage: `curl -x socks5h://127.0.0.1:{VM_INTERNET_PROXY_PORT} ...`, or for a package manager: `http_proxy=socks5h://127.0.0.1:{VM_INTERNET_PROXY_PORT} https_proxy=socks5h://127.0.0.1:{VM_INTERNET_PROXY_PORT} apt-get ...` / `dnf --setopt=proxy=socks5h://127.0.0.1:{VM_INTERNET_PROXY_PORT} install ...`.\n"
                ))
            }
            _ => unreachable!("validated above"),
        }
    }

    /// Load an inventory entry's fields needed by the LAN-presence tools:
    /// bundle_path (to read config.plist / resolve via ARP-by-MAC),
    /// last_known_ip (fallback if ARP-by-MAC finds nothing fresh), and
    /// utm_name (for stop/start).
    fn classify_vm_current_network_path(
        &self,
        bundle_path: &str,
        fallback_ip: &str,
    ) -> (String, &'static str) {
        let ip = resolve_live_ip_via_arp_by_mac(Path::new(bundle_path))
            .unwrap_or_else(|| fallback_ip.to_owned());
        let Ok(target) = ip.parse::<Ipv4Addr>() else {
            return (ip, "unknown");
        };
        let owning = host_interfaces_in_same_slash24(target);
        (ip, classify_guest_network_path(&owning))
    }

    /// Read-only: is this VM (or all of them, if `alias` is omitted)
    /// currently reachable directly on the physical LAN — a real DHCP
    /// lease from the same router the host uses, like `debian-headless-4`
    /// — or stuck on UTM's isolated internal Shared-Network bridge? Uses a
    /// FRESH ARP-by-MAC resolution, not stale inventory, since a VM's
    /// network path can change on every restart.
    fn diagnose_vm_lan_presence(&self, alias: Option<&str>) -> ToolCallResult {
        let inv_entries = match std::fs::read_to_string(self.repo_root.join(DEFAULT_INVENTORY)) {
            Ok(s) => match serde_json::from_str::<Value>(&s) {
                Ok(v) => v
                    .get("entries")
                    .and_then(|e| e.as_array())
                    .cloned()
                    .unwrap_or_default(),
                Err(e) => return tool_error(&format!("inventory invalid JSON: {e}")),
            },
            Err(e) => return tool_error(&format!("inventory unreadable: {e}")),
        };

        let mut out = String::from("# VM LAN presence\n\n");
        let mut checked = 0u32;
        for entry in &inv_entries {
            let entry_alias = entry.get("alias").and_then(|v| v.as_str()).unwrap_or("");
            if entry_alias.is_empty() {
                continue;
            }
            if let Some(only) = alias
                && only != entry_alias
            {
                continue;
            }
            let Some(bundle_path) = entry
                .get("controller")
                .and_then(|c| c.get("bundle_path"))
                .and_then(|v| v.as_str())
            else {
                out.push_str(&format!(
                    "- ⏭️ {entry_alias}: no controller.bundle_path in inventory, skipped\n"
                ));
                continue;
            };
            let fallback_ip = entry
                .get("last_known_ip")
                .and_then(|v| v.as_str())
                .or_else(|| entry.get("ssh_target").and_then(|v| v.as_str()))
                .unwrap_or("");
            checked += 1;
            let declared_mode = utm_config_network_mode(Path::new(bundle_path))
                .unwrap_or_else(|| "unknown".to_owned());
            let (live_ip, path_kind) =
                self.classify_vm_current_network_path(bundle_path, fallback_ip);
            let mark = if path_kind == "physical-lan" {
                "✅"
            } else {
                "🛠️"
            };
            out.push_str(&format!(
                "- {mark} {entry_alias} ({live_ip}): {path_kind} (declared UTM mode: {declared_mode})\n"
            ));
        }
        if checked == 0 {
            return tool_error(&match alias {
                Some(a) => format!("no inventory entry '{a}' found"),
                None => "no inventory entries found".to_string(),
            });
        }
        out.push_str(&format!(
            "\n**{checked} node(s) checked.** 🛠️ = not on the physical LAN — call apply_vm_bridged_network to fix.\n"
        ));
        tool_success(&out)
    }

    /// Force a VM directly onto the physical LAN, deterministically, like
    /// `debian-headless-4` — instead of hoping UTM's "Shared" mode happens
    /// to MACNAT it there (observed live: non-deterministic per VM, per
    /// restart). No-ops if it's already there. Otherwise: flips the UTM
    /// bundle's Network Mode from `Shared` to `Bridged` (verified live —
    /// this lab's `Windows.utm` runs exactly this, successfully, with no
    /// other config needed), power-cycles the VM, waits for a fresh
    /// physical-LAN lease, and persists the new IP to inventory. Blocking,
    /// minutes-scale (same class as `ensure_lab_ready`) — a VM reboot +
    /// DHCP cycle takes real wall-clock time.
    /// DEPRECATED (LiveLabVmConnectivityRulebook §11.3): this tool used to
    /// push a VM onto the host's everyday LAN (`en0`) via AppleScript with no
    /// profile, transaction, rollback, or evidence contract. It now refuses
    /// unconditionally. VM network mutation happens ONLY through the typed
    /// Rust transaction (`prepare_lab_network` → `rustynet ops
    /// vm-lab-network-prepare --approve-reconfigure`) under an explicitly
    /// allowlisted physical profile — and `en0` is denied by policy at the
    /// profile, plan, and render layers.
    fn apply_vm_bridged_network(&self, alias: &str) -> ToolCallResult {
        let subject = if alias.is_empty() {
            "<missing alias>"
        } else {
            alias
        };
        tool_error(&format!(
            "apply_vm_bridged_network is DEPRECATED and refuses to run (requested for '{subject}'). \
             Bridging a lab VM onto the host's everyday LAN is never a default attachment \
             (LiveLabVmConnectivityRulebook §5/§11.3). Use the sanctioned path instead: \
             1) audit_lab_network to see current attachments; \
             2) prepare_lab_network with an explicitly allowlisted physical network profile and \
             approve_reconfigure=true — it runs the atomic stop→rewrite→verify→rollback transaction; \
             3) restore_lab_network <transaction_id> to undo. en0 is denied by policy in every profile."
        ))
    }

    /// Summarize the trend across the last N run-matrix rows (converging or stuck?).
    fn get_run_trend(&self, args: Option<&Value>) -> ToolCallResult {
        let limit = args
            .and_then(|a| a.get("limit"))
            .and_then(|v| v.as_u64())
            .unwrap_or(10)
            .clamp(1, 200) as usize;
        let matrix_path = self
            .repo_root
            .join("documents/operations/live_lab_run_matrix.csv");
        let content = match std::fs::read_to_string(&matrix_path) {
            Ok(c) => c,
            Err(e) => return tool_error(&format!("Cannot read run matrix: {e}")),
        };
        let mut lines = content.lines();
        let Some(header_line) = lines.next() else {
            return tool_success("# Run trend\n\nMatrix is empty.\n");
        };
        let header = split_csv_line(header_line);
        let col = |name: &str| header.iter().position(|h| h == name);
        let (Some(c_run), Some(c_commit), Some(c_result), Some(c_stage)) = (
            col("run_id"),
            col("git_commit"),
            col("overall_result"),
            col("first_failed_stage"),
        ) else {
            return tool_error(
                "Run matrix missing expected columns (run_id/git_commit/overall_result/first_failed_stage)",
            );
        };
        let all: Vec<Vec<String>> = lines
            .filter(|l| !l.trim().is_empty())
            .map(split_csv_line)
            .collect();
        if all.is_empty() {
            return tool_success("# Run trend\n\nNo data rows in the matrix yet.\n");
        }
        let cell =
            |row: &[String], i: usize| row.get(i).map(|s| s.trim().to_string()).unwrap_or_default();
        // Newest-first tail of the matrix.
        let recent: Vec<&Vec<String>> = all.iter().rev().take(limit).collect();
        // Oldest-first (result, stage) pairs feed the verdict.
        let verdict_rows: Vec<(String, String)> = recent
            .iter()
            .rev()
            .map(|&r| (cell(r, c_result), cell(r, c_stage)))
            .collect();
        let verdict = trend_verdict(&verdict_rows);

        let mut out = format!(
            "# Run trend (last {} of {} runs)\n\n**Verdict:** {verdict}\n\n| run_id | commit | result | first_failed_stage |\n|---|---|---|---|\n",
            recent.len(),
            all.len()
        );
        for &r in &recent {
            let commit = cell(r, c_commit);
            let short = commit.get(..10).unwrap_or(commit.as_str()).to_string();
            let result = cell(r, c_result);
            let stage = cell(r, c_stage);
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                cell(r, c_run),
                short,
                if result.is_empty() {
                    "-"
                } else {
                    result.as_str()
                },
                if stage.is_empty() {
                    "-"
                } else {
                    stage.as_str()
                },
            ));
        }
        out.push_str(
            "\nLegend: GREEN — stable (≥2 pass) · JUST GREEN (1 pass) · STUCK at X (≥2 fails, same stage → patch that stage) · MOVING (fails, but the stage is advancing).\n",
        );
        tool_success(&out)
    }

    /// Coverage-driven work finder: aggregate every per-OS-stage and cross-OS
    /// cell DOWN the whole run-matrix history and surface what still needs to be
    /// proven green — regressed, never-passed, never-run, stale-green — so an
    /// agent can be handed a target instead of hunting for work.
    fn find_untested_work(&self, args: Option<&Value>) -> ToolCallResult {
        let os_filter = arg_str(args, "os").map(|s| s.to_ascii_lowercase());
        let include_green = arg_bool(args, "include_green");
        let path = self
            .repo_root
            .join("documents/operations/live_lab_run_matrix.csv");
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => return tool_error(&format!("Cannot read run matrix: {e}")),
        };
        let mut lines = content.lines();
        let Some(header_line) = lines.next() else {
            return tool_success("# Untested work\n\nMatrix is empty.\n");
        };
        let header = split_csv_line(header_line);
        let run_idx = header.iter().position(|h| h == "run_id");
        // Coverage cells = per-OS stage columns + cross-OS scenario columns.
        // Include canonical columns even when an older matrix header has not
        // been schema-upgraded yet; those cells classify as NEVER-RUN.
        let cols = coverage_columns_from_header(&header);
        let rows: Vec<Vec<String>> = lines
            .filter(|l| !l.trim().is_empty())
            .map(split_csv_line)
            .collect();
        if rows.is_empty() {
            return tool_success("# Untested work\n\nNo data rows in the matrix yet.\n");
        }
        let total = rows.len();
        let stale_window = 15usize;

        let (mut regressed, mut never_passed, mut never_run, mut stale_green) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let mut green = 0u32;

        for (idx, name) in &cols {
            if let Some(f) = &os_filter {
                let belongs = if f == "cross" {
                    name.starts_with("cross_os_")
                } else {
                    name.starts_with(&format!("{f}_"))
                };
                if !belongs {
                    continue;
                }
            }
            let (mut passes, mut fails) = (0u32, 0u32);
            let mut last_status: Option<&str> = None;
            let mut last_run = String::new();
            let mut last_idx = 0usize;
            for (ri, row) in rows.iter().enumerate() {
                let v = idx.and_then(|i| row.get(i)).map(|s| s.trim()).unwrap_or("");
                if v == "pass" || v == "fail" {
                    if v == "pass" {
                        passes += 1;
                    } else {
                        fails += 1;
                    }
                    last_status = Some(if v == "pass" { "pass" } else { "fail" });
                    last_run = run_idx
                        .and_then(|j| row.get(j))
                        .cloned()
                        .unwrap_or_default();
                    last_idx = ri;
                }
            }
            let entry = format!(
                "`{name}` — {passes} pass / {fails} fail{}",
                if last_run.is_empty() {
                    String::new()
                } else {
                    format!(" (last: {last_run})")
                }
            );
            match last_status {
                None => never_run.push(format!("`{name}`")),
                Some("fail") => {
                    if passes > 0 {
                        regressed.push(entry);
                    } else {
                        never_passed.push(entry);
                    }
                }
                Some(_) => {
                    if last_idx + stale_window < total {
                        stale_green.push(entry);
                    } else {
                        green += 1;
                    }
                }
            }
        }

        let mut out = format!(
            "# Untested / failing work ({total} runs analyzed{})\n\n",
            os_filter
                .as_ref()
                .map(|f| format!(", os={f}"))
                .unwrap_or_default()
        );
        let mut section = |title: &str, items: &[String], hint: &str| {
            out.push_str(&format!("## {title} ({}){hint}\n", items.len()));
            if items.is_empty() {
                out.push_str("- (none)\n");
            }
            for it in items {
                out.push_str(&format!("- {it}\n"));
            }
            out.push('\n');
        };
        section(
            "🔴 REGRESSED — passed before, latest run FAILED",
            &regressed,
            " — fix these first",
        );
        section(
            "🟠 NEVER PASSED — only ever failed",
            &never_passed,
            " — unproven, needs a working impl",
        );
        section(
            "⚪ NEVER RUN — no pass/fail on record",
            &never_run,
            " — untested; some are unsupported-by-design (check get_platform_support before targeting)",
        );
        section(
            "🟡 STALE GREEN — passed only in older runs",
            &stale_green,
            " — re-verify they still hold",
        );
        if include_green {
            out.push_str(&format!("## 🟢 GREEN (current): {green}\n\n"));
        } else {
            out.push_str(&format!(
                "_{green} cell(s) currently green — pass include_green=true to list them._\n\n"
            ));
        }
        let next = regressed
            .first()
            .or(never_passed.first())
            .or(stale_green.first());
        if let Some(n) = next {
            out.push_str(&format!(
                "**Suggested next target:** {n}\nStrip the `<os>_stage_` / `cross_os_` prefix → explain_stage on that stage for the owning file + causes, then drive a focused run (start_live_lab_run with the relevant role topology). Record the attempt with write_loop_note.\n"
            ));
        } else if !never_run.is_empty() {
            out.push_str(
                "**Suggested next target:** pick a NEVER-RUN cell that IS supported on its platform (get_platform_support) and prove it green.\n",
            );
        } else {
            out.push_str("**Everything covered is green.** Consider a fresh full-matrix run to catch regressions.\n");
        }
        tool_success(&out)
    }

    /// Case-insensitive substring search across every file in a run's report dir.
    fn grep_report(&self, args: Option<&Value>) -> ToolCallResult {
        let report_dir = match self.resolve_report_dir(args) {
            Ok(d) => d,
            Err(e) => return tool_error(&e),
        };
        let pattern = arg_str(args, "pattern").unwrap_or("");
        if pattern.is_empty() {
            return tool_error("Missing required parameter: pattern");
        }
        let needle = pattern.to_lowercase();
        let max_matches = args
            .and_then(|a| a.get("max_matches"))
            .and_then(|v| v.as_u64())
            .unwrap_or(100)
            .clamp(1, 1000) as usize;
        let skip_ext = [
            ".tar", ".gz", ".tgz", ".zip", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".pcap", ".bin",
        ];
        let mut files: Vec<(String, u64)> = Vec::new();
        collect_files(&report_dir, &report_dir, &mut files, 0);
        files.sort();
        let mut matches: Vec<String> = Vec::new();
        let mut scanned = 0usize;
        let mut truncated = false;
        'outer: for (rel, size) in &files {
            let rel_l = rel.to_lowercase();
            if *size > 8_000_000 || skip_ext.iter().any(|e| rel_l.ends_with(e)) {
                continue;
            }
            let Ok(content) = read_file_capped(&report_dir.join(rel), 8_000_000) else {
                continue;
            };
            scanned += 1;
            for (lineno, line) in content.lines().enumerate() {
                if line.to_lowercase().contains(&needle) {
                    matches.push(format!(
                        "`{rel}`:{} — {}",
                        lineno + 1,
                        truncate_output(line.trim(), 1, 400)
                    ));
                    if matches.len() >= max_matches {
                        truncated = true;
                        break 'outer;
                    }
                }
            }
        }
        let mut out = format!(
            "# grep_report: \"{pattern}\"\n\n`{}`\n\n- files scanned: {scanned}\n- matches: {}{}\n\n",
            report_dir.display(),
            matches.len(),
            if truncated {
                format!(" (capped at {max_matches})")
            } else {
                String::new()
            },
        );
        if matches.is_empty() {
            out.push_str(
                "No matches. Try list_report_artifacts to see the files, or a broader pattern.\n",
            );
        } else {
            for m in &matches {
                out.push_str(&format!("- {m}\n"));
            }
        }
        tool_success(&out)
    }

    /// Pull one stage's row(s) from state/stages.tsv and the tail of its log.
    fn get_stage_log(&self, args: Option<&Value>) -> ToolCallResult {
        let report_dir = match self.resolve_report_dir(args) {
            Ok(d) => d,
            Err(e) => return tool_error(&e),
        };
        let stage = arg_str(args, "stage").unwrap_or("").trim().to_string();
        if stage.is_empty() {
            return tool_error("Missing required parameter: stage");
        }
        // Strip OS prefixes so 'linux_stage_anchor' matches an 'anchor' row.
        let lower = stage.to_lowercase();
        let norm = lower
            .strip_prefix("linux_stage_")
            .or_else(|| lower.strip_prefix("macos_stage_"))
            .or_else(|| lower.strip_prefix("windows_stage_"))
            .unwrap_or(lower.as_str());

        let mut out = format!("# Stage log: '{stage}'\n\n`{}`\n\n", report_dir.display());
        let mut matched_logs: Vec<PathBuf> = Vec::new();
        match std::fs::read_to_string(report_dir.join("state/stages.tsv")) {
            Ok(body) => {
                let mut hits = 0;
                out.push_str(
                    "## Matching rows in state/stages.tsv\n\n| stage | status | rc | description |\n|---|---|---|---|\n",
                );
                for line in body.lines().filter(|l| !l.trim().is_empty()) {
                    let cols: Vec<&str> = line.split('\t').collect();
                    if cols.len() < 6 {
                        continue;
                    }
                    let name_l = cols[0].to_lowercase();
                    if !name_l.contains(norm) && !norm.contains(name_l.as_str()) {
                        continue;
                    }
                    hits += 1;
                    out.push_str(&format!(
                        "| {} | {} | {} | {} |\n",
                        cols[0], cols[2], cols[3], cols[5]
                    ));
                    // Resolve the log path (col 4): absolute, report-relative, or ./-prefixed.
                    let raw = cols[4];
                    for cand in [
                        PathBuf::from(raw),
                        report_dir.join(raw),
                        report_dir.join(raw.trim_start_matches("./")),
                    ] {
                        if cand.is_file() && !matched_logs.iter().any(|m| m == &cand) {
                            matched_logs.push(cand);
                            break;
                        }
                    }
                }
                if hits == 0 {
                    out.push_str("| (none matched) | | | |\n");
                }
            }
            Err(_) => out.push_str(
                "_state/stages.tsv not found (run may predate it or not have completed)._\n",
            ),
        }
        // If the TSV gave no log, fall back to filename matching.
        if matched_logs.is_empty() {
            let mut files: Vec<(String, u64)> = Vec::new();
            collect_files(&report_dir, &report_dir, &mut files, 0);
            for (rel, _) in &files {
                let rel_l = rel.to_lowercase();
                if rel_l.contains(norm) && (rel_l.ends_with(".log") || rel_l.ends_with(".txt")) {
                    matched_logs.push(report_dir.join(rel));
                }
            }
        }
        if matched_logs.is_empty() {
            out.push_str(
                "\nNo stage log located. Use list_report_artifacts to browse, grep_report to search, or tail_job_log for the run's combined log.\n",
            );
            return tool_success(&out);
        }
        for log in matched_logs.iter().take(3) {
            let rel = log.strip_prefix(&report_dir).unwrap_or(log);
            out.push_str(&format!("\n## {} (tail)\n", rel.display()));
            match read_file_capped(log, 1_000_000) {
                Ok(content) => out.push_str(&format!(
                    "```\n{}\n```\n",
                    truncate_tail(content.trim(), 300, 60_000)
                )),
                Err(e) => out.push_str(&format!("_cannot read: {e}_\n")),
            }
        }
        tool_success(&out)
    }

    /// Resolve a report dir from a specific (dir_key | job_key) arg pair, so a
    /// single call can take two runs (diff_runs).
    fn resolve_report_dir_keyed(
        &self,
        args: Option<&Value>,
        dir_key: &str,
        job_key: &str,
    ) -> Result<PathBuf, String> {
        if let Some(dir) = arg_str(args, dir_key) {
            return self.confined_repo_path(dir, dir_key);
        }
        if let Some(job_id) = arg_str(args, job_key) {
            let rec = self
                .read_job_record(job_id)
                .ok_or_else(|| format!("Unknown job_id: {job_id}"))?;
            let dir = rec
                .get("report_dir")
                .and_then(|v| v.as_str())
                .ok_or("job record missing report_dir")?;
            return self.confined_repo_path(dir, "job report_dir");
        }
        Err(format!("Provide {dir_key} or {job_key}"))
    }

    /// Compare two runs' stage outcomes (which stages flipped pass↔fail).
    fn diff_runs(&self, args: Option<&Value>) -> ToolCallResult {
        let old = match self.resolve_report_dir_keyed(args, "old_report_dir", "old_job_id") {
            Ok(d) => d,
            Err(e) => return tool_error(&format!("old run: {e}")),
        };
        let new = match self.resolve_report_dir_keyed(args, "new_report_dir", "new_job_id") {
            Ok(d) => d,
            Err(e) => return tool_error(&format!("new run: {e}")),
        };
        let old_s = old.to_string_lossy().to_string();
        let new_s = new.to_string_lossy().to_string();
        // No --inventory: this op reads only the two report dirs' stages.tsv.
        self.run_cli(
            &[
                "ops",
                "vm-lab-diff-live-lab-runs",
                "--old-report-dir",
                &old_s,
                "--new-report-dir",
                &new_s,
            ],
            "Run diff (old → new)",
            DISCOVERY_TIMEOUT_SECS,
        )
    }

    /// Consolidated loop-start readiness: one go/no-go over host tools, ssh
    /// material, the inventory, disk, the working-tree deploy set, and every
    /// node's power+TCP. Replaces ~6 separate calls at the top of the loop.
    fn preflight_check(&self) -> ToolCallResult {
        let mut out = String::from("# Lab preflight (go/no-go)\n\n## Host prerequisites\n");
        let mut hard_fail = false;
        let mut warn = false;
        let which = |bin: &str| {
            run_with_timeout(
                "which",
                &[bin],
                &self.repo_root,
                &[],
                Duration::from_secs(5),
            )
            .map(|o| o.success)
            .unwrap_or(false)
        };

        if which("cargo") {
            out.push_str("- ✅ cargo present\n");
        } else {
            out.push_str("- ❌ cargo NOT found (gates + CLI cannot run)\n");
            hard_fail = true;
        }
        let utmctl = utmctl_path();
        if Path::new(&utmctl).exists() || which("utmctl") {
            out.push_str(&format!("- ✅ utmctl present ({utmctl})\n"));
        } else {
            out.push_str(&format!(
                "- ❌ utmctl NOT found at {utmctl} (set RUSTYNET_UTMCTL_PATH)\n"
            ));
            hard_fail = true;
        }
        for (bin, why) in [("ssh", "node access"), ("git", "source deploy")] {
            if which(bin) {
                out.push_str(&format!("- ✅ {bin} present\n"));
            } else {
                out.push_str(&format!("- ❌ {bin} NOT found ({why})\n"));
                hard_fail = true;
            }
        }
        let id = default_ssh_identity();
        if Path::new(&id).exists() {
            out.push_str(&format!("- ✅ ssh identity {id}\n"));
        } else {
            out.push_str(&format!("- ⚠️ ssh identity missing: {id}\n"));
            warn = true;
        }
        let kh = default_known_hosts();
        if Path::new(&kh).exists() {
            out.push_str(&format!("- ✅ known_hosts {kh}\n"));
        } else {
            out.push_str(&format!("- ⚠️ known_hosts missing: {kh}\n"));
            warn = true;
        }

        out.push_str("\n## Inventory\n");
        let inv_entries = match std::fs::read_to_string(self.repo_root.join(DEFAULT_INVENTORY)) {
            Ok(s) => match serde_json::from_str::<Value>(&s) {
                Ok(v) => {
                    let entries = v
                        .get("entries")
                        .and_then(|e| e.as_array())
                        .cloned()
                        .unwrap_or_default();
                    out.push_str(&format!(
                        "- ✅ inventory parseable ({} entries)\n",
                        entries.len()
                    ));
                    entries
                }
                Err(e) => {
                    out.push_str(&format!("- ❌ inventory invalid JSON: {e}\n"));
                    hard_fail = true;
                    Vec::new()
                }
            },
            Err(e) => {
                out.push_str(&format!("- ❌ inventory unreadable: {e}\n"));
                hard_fail = true;
                Vec::new()
            }
        };

        out.push_str("\n## Disk\n");
        match run_with_timeout(
            "df",
            &["-h", "."],
            &self.repo_root,
            &[],
            Duration::from_secs(10),
        ) {
            Ok(o) if o.success => {
                let last = o.stdout.lines().last().unwrap_or("").trim();
                if let Some(pct) = last
                    .split_whitespace()
                    .find(|t| t.ends_with('%'))
                    .and_then(|t| t.trim_end_matches('%').parse::<u32>().ok())
                {
                    if pct >= 90 {
                        out.push_str(&format!(
                            "- ⚠️ disk {pct}% full — prune_jobs / host_disk_status\n"
                        ));
                        warn = true;
                    } else {
                        out.push_str(&format!("- ✅ disk {pct}% used\n"));
                    }
                } else {
                    out.push_str(&format!("- {last}\n"));
                }
            }
            _ => {
                out.push_str("- ⚠️ could not read df\n");
                warn = true;
            }
        }

        out.push_str("\n## Source (working-tree deploy)\n");
        let untracked = self.untracked_crate_files();
        if untracked.is_empty() {
            out.push_str("- ✅ no untracked crates/ files (working-tree deploy is complete)\n");
        } else {
            out.push_str(&format!(
                "- ⚠️ {} untracked crates/ file(s) will NOT deploy — `git add` them:\n",
                untracked.len()
            ));
            for p in &untracked {
                out.push_str(&format!("  - `{p}`\n"));
            }
            warn = true;
        }

        out.push_str("\n## Nodes (power + TCP)\n");
        let status_map = self.controller_status_map();
        let (mut nodes_ok, mut nodes_total) = (0u32, 0u32);
        for e in &inv_entries {
            let alias = e.get("alias").and_then(|v| v.as_str()).unwrap_or("");
            if alias.is_empty() {
                continue;
            }
            nodes_total += 1;
            let utm_name = e
                .get("controller")
                .and_then(|c| c.get("utm_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let platform = e
                .get("platform")
                .and_then(|v| v.as_str())
                .unwrap_or("linux");
            let ip = e
                .get("last_known_ip")
                .and_then(|v| v.as_str())
                .or_else(|| e.get("ssh_target").and_then(|v| v.as_str()))
                .unwrap_or("");
            let port = e.get("ssh_port").and_then(|v| v.as_u64()).unwrap_or(22) as u16;
            // Look up by ALIAS first: it is the one identity that spans both
            // controller kinds. `controller.utm_name` is empty for a libvirt guest
            // (it has a domain, not a utm_name), so keying on it reported every box
            // guest as power=unknown — which reads as a network fault and hides
            // that a stopped guest just needs power_on_vm. utm_name stays as a
            // fallback for anything the discovery keys only by domain.
            let power = status_map
                .get(alias)
                .or_else(|| {
                    if utm_name.is_empty() {
                        None
                    } else {
                        status_map.get(utm_name)
                    }
                })
                .map(|s| s.as_str())
                .unwrap_or("unknown");
            let reachable = tcp_reachable(ip, port, Duration::from_secs(2));
            let mark = if reachable {
                nodes_ok += 1;
                "✅"
            } else if power == "started" {
                "⚠️"
            } else {
                "❌"
            };
            out.push_str(&format!(
                "- {mark} {alias} ({platform}): power={power}, TCP/{port}@{}={reachable}\n",
                if ip.is_empty() { "?" } else { ip }
            ));
        }
        if nodes_ok < nodes_total {
            // Some nodes unreachable: runnable on the reachable subset, but flag
            // it so a full-topology run isn't started blind. Recoverable, not a
            // hard NO-GO.
            warn = true;
        }

        let verdict = if hard_fail {
            "🛑 NO-GO — fix the ❌ host/inventory prerequisites before running."
        } else if warn {
            "⚠️ GO WITH CAUTION — runnable, but address the ⚠️ items (recover unreachable nodes via check_vm_reachable / reset_vm_network / power_on_vm; `git add` untracked code; free disk)."
        } else {
            "✅ GO — all prerequisites met."
        };
        out.push_str(&format!(
            "\n## Verdict\n{verdict}\n- nodes reachable: {nodes_ok}/{nodes_total}\n"
        ));
        tool_success(&out)
    }

    /// Append one structured note to the durable loop journal.
    fn write_loop_note(&self, args: Option<&Value>) -> ToolCallResult {
        let note = arg_str(args, "note").unwrap_or("").trim();
        if note.is_empty() {
            return tool_error("Missing required parameter: note");
        }
        let iteration = args
            .and_then(|a| a.get("iteration"))
            .and_then(|v| v.as_u64());
        let status = arg_str(args, "status");
        let rec = json!({
            "ts_unix": now_unix(),
            "iteration": iteration,
            "status": status,
            "note": note,
        });
        let path = self.abs_path(LOOP_JOURNAL);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let line = format!("{}\n", serde_json::to_string(&rec).unwrap_or_default());
        use std::io::Write;
        let res = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut f| f.write_all(line.as_bytes()));
        match res {
            Ok(_) => {
                let count = std::fs::read_to_string(&path)
                    .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
                    .unwrap_or(0);
                tool_success(&format!(
                    "# Loop note recorded (#{count}{})\n\n{}\n\nRead the history with get_loop_journal.\n",
                    iteration
                        .map(|i| format!(", iteration {i}"))
                        .unwrap_or_default(),
                    truncate_output(note, 5, 500)
                ))
            }
            Err(e) => tool_error(&format!("Cannot write loop journal: {e}")),
        }
    }

    /// Read back the loop journal (last N notes) — the agent's memory across
    /// context compaction over a long run.
    /// Every attempt already made against a failing stage, so an agent picking
    /// it up does not re-derive or repeat one.
    ///
    /// Joins two sources and derives the outcome rather than storing it:
    /// `live_lab_stage_triage.jsonl` (what failed + what was tried) and
    /// `live_lab_node_stage_results.csv` (the engine's own per-run status).
    /// A patch that worked turns the stage green in the next run; one that did
    /// not opens a new stub against a new commit. Reading the chain therefore
    /// cannot drift from what the runs actually did.
    fn stage_triage_history(&self, args: Option<&Value>) -> ToolCallResult {
        let stage = arg_str(args, "stage").unwrap_or("").trim().to_owned();
        if stage.is_empty() {
            return tool_error("stage is required, e.g. stage=live_two_hop_validation");
        }
        let os_filter = arg_str(args, "os").map(|s| s.trim().to_ascii_lowercase());

        let path = self.abs_path("documents/operations/live_lab_stage_triage.jsonl");
        let body = std::fs::read_to_string(&path).unwrap_or_default();
        let mut records: Vec<Value> = Vec::new();
        for line in body.lines().filter(|l| !l.trim().is_empty()) {
            match serde_json::from_str::<Value>(line) {
                Ok(v) => records.push(v),
                // A corrupt line must not silently read as "nothing tried".
                Err(err) => {
                    return tool_error(&format!(
                        "stage triage ledger is malformed ({}): {err}",
                        path.display()
                    ));
                }
            }
        }

        let field = |v: &Value, k: &str| -> String {
            v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_owned()
        };
        let mut hits: Vec<&Value> = records
            .iter()
            .filter(|r| field(r, "stage") == stage)
            .filter(|r| match &os_filter {
                None => true,
                Some(os) => r
                    .get("os_family")
                    .and_then(|v| v.as_array())
                    .is_some_and(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str())
                            .any(|x| x.eq_ignore_ascii_case(os))
                    }),
            })
            .collect();
        hits.sort_by_key(|r| field(r, "ts_utc"));

        if hits.is_empty() {
            return tool_success(&format!(
                "# Stage triage history — {stage}\n\nNo attempts recorded{}.\n\nEither this stage has \
                 never failed under the `--node` engine, or the ledger predates it. Check \
                 `documents/operations/live_lab_node_stage_results.csv` for raw run history.\n\n\
                 NOTE: this ledger is `--node` only. The legacy bash archive uses a different stage \
                 vocabulary (`linux_stage_two_hop` vs `live_two_hop_validation`), so its results are \
                 not evidence here.\n",
                os_filter
                    .as_deref()
                    .map(|os| format!(" for os={os}"))
                    .unwrap_or_default()
            ));
        }

        let unfilled = hits.iter().filter(|r| field(r, "patch").is_empty()).count();
        let mut out = format!(
            "# Stage triage history — {stage}\n\n{} attempt(s) recorded{}. Oldest first.\n",
            hits.len(),
            os_filter
                .as_deref()
                .map(|os| format!(" for os={os}"))
                .unwrap_or_default()
        );
        out.push_str(
            "\n**Read the chain, not the rows.** A new stub against a NEW commit means the \
             preceding patch did not fix it — that is how outcome is evidenced here, so there is \
             no outcome field to trust or maintain.\n\n",
        );
        for (index, record) in hits.iter().enumerate() {
            let patch = field(record, "patch");
            out.push_str(&format!(
                "## {}. run {} @ {}\n- when: {}\n- os: {}\n- error: {}\n- **patch tried**: {}\n\n",
                index + 1,
                field(record, "run_id"),
                &field(record, "run_commit")
                    .chars()
                    .take(12)
                    .collect::<String>(),
                field(record, "ts_utc"),
                record
                    .get("os_family")
                    .and_then(|v| v.as_array())
                    .map(|a| a
                        .iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(", "))
                    .unwrap_or_default(),
                field(record, "error")
                    .replace('\n', " ")
                    .chars()
                    .take(400)
                    .collect::<String>(),
                if patch.is_empty() {
                    "(NOT YET RECORDED — fill this before the verification run)".to_owned()
                } else {
                    patch
                },
            ));
        }
        if unfilled > 0 {
            out.push_str(&format!(
                "---\n\n**{unfilled} stub(s) have no patch recorded.** Fill each with the patch you \
                 are about to test, BEFORE the verification run, so the ledger row's own commit is \
                 the patch commit. A deliberate decision not to patch is a filled value \
                 (`\"none: <reason>\"`), never blank — blank reads as forgotten.\n",
            ));
        }
        out.push_str(
            "\n**Do not repeat a patch listed above.** If the same error recurs after one of these, \
             that approach is refuted — say so in the next stub rather than trying it again.\n",
        );
        tool_success(&out)
    }

    fn get_loop_journal(&self, args: Option<&Value>) -> ToolCallResult {
        let limit = args
            .and_then(|a| a.get("limit"))
            .and_then(|v| v.as_u64())
            .unwrap_or(30)
            .clamp(1, 500) as usize;
        let path = self.abs_path(LOOP_JOURNAL);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => {
                return tool_success(
                    "# Loop journal\n\nEmpty — no notes yet. Use write_loop_note to record each iteration's hypothesis/patch/result; it survives context compaction over a long run.\n",
                );
            }
        };
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        let total = lines.len();
        let start = total.saturating_sub(limit);
        let now = now_unix();
        let mut out = format!(
            "# Loop journal ({total} notes, showing last {})\n\n",
            total - start
        );
        for (i, line) in lines[start..].iter().enumerate() {
            let n = start + i + 1;
            if let Ok(v) = serde_json::from_str::<Value>(line) {
                let ts = v.get("ts_unix").and_then(|x| x.as_u64()).unwrap_or(0);
                let ago = now.saturating_sub(ts);
                let ago_s = if ago < 90 {
                    format!("{ago}s ago")
                } else if ago < 5400 {
                    format!("{}m ago", ago / 60)
                } else {
                    format!("{}h ago", ago / 3600)
                };
                let it = v
                    .get("iteration")
                    .and_then(|x| x.as_u64())
                    .map(|i| format!("it{i} "))
                    .unwrap_or_default();
                let st = v
                    .get("status")
                    .and_then(|x| x.as_str())
                    .map(|s| format!("[{s}] "))
                    .unwrap_or_default();
                let note = v.get("note").and_then(|x| x.as_str()).unwrap_or("");
                out.push_str(&format!("{n}. ({ago_s}) {it}{st}{note}\n"));
            } else {
                out.push_str(&format!("{n}. {line}\n"));
            }
        }
        tool_success(&out)
    }

    /// Run `git` in the repo and capture trimmed stdout on success.
    fn git_capture(&self, args: &[&str]) -> Option<String> {
        run_with_timeout("git", args, &self.repo_root, &[], Duration::from_secs(30))
            .ok()
            .filter(|o| o.success)
            .map(|o| o.stdout.trim().to_string())
    }

    /// Preview exactly what the next run ships to the VMs for a given source mode
    /// — so the agent never tests stale code (working-tree captures TRACKED
    /// changes only; new files need `git add`).
    fn what_will_deploy(&self, args: Option<&Value>) -> ToolCallResult {
        let mode = arg_str(args, "source_mode").unwrap_or("working-tree");
        let head = self
            .git_capture(&["rev-parse", "--short", "HEAD"])
            .unwrap_or_else(|| "?".into());
        let subj = self
            .git_capture(&["log", "-1", "--pretty=%s"])
            .unwrap_or_default();
        let mut out =
            format!("# Deploy preview (source_mode={mode})\n\n- **HEAD:** {head} — {subj}\n");
        match mode {
            "working-tree" => {
                let tracked = self
                    .git_capture(&["diff", "--name-only", "HEAD"])
                    .unwrap_or_default();
                let tracked: Vec<&str> = tracked.lines().filter(|l| !l.trim().is_empty()).collect();
                out.push_str(&format!(
                    "\n## Will deploy — tracked changes vs HEAD ({})\n",
                    tracked.len()
                ));
                for f in tracked.iter().take(60) {
                    out.push_str(&format!("- {f}\n"));
                }
                if tracked.len() > 60 {
                    out.push_str(&format!("- … {} more\n", tracked.len() - 60));
                }
                let status = self
                    .git_capture(&["status", "--porcelain", "--untracked-files=all"])
                    .unwrap_or_default();
                let untracked: Vec<&str> = status
                    .lines()
                    .filter_map(|l| l.strip_prefix("?? "))
                    .collect();
                out.push_str(&format!(
                    "\n## Will NOT deploy — untracked (`git add` to include) ({})\n",
                    untracked.len()
                ));
                for f in untracked.iter().take(60) {
                    let crit = if f.starts_with("crates/") {
                        " ⚠️ (code — tests would be STALE)"
                    } else {
                        ""
                    };
                    out.push_str(&format!("- {f}{crit}\n"));
                }
                if untracked.len() > 60 {
                    out.push_str(&format!("- … {} more\n", untracked.len() - 60));
                }
                let crit = untracked
                    .iter()
                    .filter(|f| f.starts_with("crates/"))
                    .count();
                let verdict = if crit > 0 {
                    format!(
                        "⚠️ {crit} untracked file(s) under crates/ will be MISSING from the deploy — `git add` them or the run builds stale code."
                    )
                } else if tracked.is_empty() && untracked.is_empty() {
                    "✅ Clean tree — deploys exactly HEAD.".to_string()
                } else {
                    "✅ All code changes are tracked and will deploy.".to_string()
                };
                out.push_str(&format!("\n## Verdict\n{verdict}\n"));
            }
            "local-head" | "origin-main" => {
                out.push_str(
                    "\nDeploys the committed ref only; uncommitted edits (tracked or untracked) are NOT included — commit first.\n",
                );
                let dirty = self
                    .git_capture(&["status", "--porcelain"])
                    .unwrap_or_default();
                let n = dirty.lines().filter(|l| !l.trim().is_empty()).count();
                if n > 0 {
                    out.push_str(&format!(
                        "- ⚠️ {n} uncommitted change(s) will be ignored under {mode}.\n"
                    ));
                }
            }
            other => {
                out.push_str(&format!(
                    "\nsource_mode={other}: deploys per that mode's ref (commit-ref / repo-url); working-tree edits are not involved.\n"
                ));
            }
        }
        tool_success(&out)
    }

    /// Live mid-run progress for a running job: elapsed, last-activity age (hang
    /// detection), the latest log lines, and artifacts produced so far. Fills the
    /// gap between start_live_lab_run and the end — stages.tsv isn't written until
    /// finalize, so this reads the streaming combined log + report-dir mtimes.
    fn get_run_progress(&self, args: Option<&Value>) -> ToolCallResult {
        let job_id = arg_str(args, "job_id");
        let rec = job_id.and_then(|j| self.read_job_record(j));
        let report_dir = self.resolve_report_dir(args).ok();
        if rec.is_none() && report_dir.is_none() {
            return tool_error("Provide job_id or report_dir");
        }
        let mut out = String::from("# Run progress\n\n");

        if let (Some(rec), Some(jid)) = (&rec, job_id) {
            let pid = rec.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
            let created = rec
                .get("created_unix")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let rd = match report_dir.clone().or_else(|| {
                rec.get("report_dir")
                    .and_then(|v| v.as_str())
                    .and_then(|dir| self.report_dir_from_record(dir))
            }) {
                Some(rd) => rd,
                None => return tool_error("job record has invalid report_dir"),
            };
            let state = self.job_state(jid, pid, &rd);
            let elapsed = now_unix().saturating_sub(created);
            out.push_str(&format!(
                "- **job:** `{jid}`\n- **state:** {state}\n- **elapsed:** {}\n",
                fmt_dur(elapsed)
            ));

            // The combined log goes silent for long stretches during healthy
            // stages (utmctl source pushes, on-node builds write nothing), so
            // log mtime alone false-positives. Report-dir artifact mtimes are
            // the second liveness signal: only flag a hang when BOTH are stale.
            let newest_artifact_age = {
                let mut files: Vec<(String, u64)> = Vec::new();
                collect_files(&rd, &rd, &mut files, 0);
                files
                    .iter()
                    .filter_map(|(rel, _)| mtime_age_secs(&rd.join(rel)))
                    .min()
            };
            if let Some(log) = rec.get("log_path").and_then(|v| v.as_str()) {
                let lp = Path::new(log);
                if let Ok(meta) = std::fs::metadata(lp) {
                    let age = mtime_age_secs(lp).unwrap_or(0);
                    out.push_str(&format!(
                        "- **log size:** {} bytes\n- **last activity:** {} ago\n",
                        meta.len(),
                        fmt_dur(age)
                    ));
                    if state == "running" && age > 600 {
                        let artifacts_stale = newest_artifact_age.is_none_or(|a| a > 600);
                        if artifacts_stale {
                            out.push_str(&format!(
                                "- ⚠️ **possible hang:** no log output for {} and no report artifact written for {} (both >10m). Inspect the tail below; if truly stuck, cancel_job then recover.\n",
                                fmt_dur(age),
                                newest_artifact_age.map_or_else(|| "ever".to_owned(), fmt_dur)
                            ));
                        } else {
                            out.push_str(&format!(
                                "- **log silent {} but artifacts still flowing** (newest {} ago) — a long quiet stage (source push / on-node build), not a hang.\n",
                                fmt_dur(age),
                                newest_artifact_age.map_or_else(String::new, fmt_dur)
                            ));
                        }
                    }
                }
                if let Ok(body) = tail_file(lp, 200) {
                    // Best-effort current stage: the last known stage token seen
                    // in the tail (the verbatim lines below are authoritative).
                    let mut current: Option<&str> = None;
                    for line in body.lines() {
                        let toks: Vec<String> = line
                            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                            .map(|t| t.to_ascii_lowercase())
                            .collect();
                        for s in STAGE_INFO {
                            // Match the stage name + only SPECIFIC aliases (>=8
                            // chars). Short generic aliases like "ssh"/"install"/
                            // "enforce" match unrelated log noise (e.g. "SSH allow
                            // CIDRs") and would mislabel the stage.
                            let hit = toks.iter().any(|t| t == s.name)
                                || s.aliases
                                    .iter()
                                    .filter(|a| a.len() >= 8)
                                    .any(|a| toks.iter().any(|t| t == a));
                            if hit {
                                current = Some(s.name);
                            }
                        }
                    }
                    if let Some(cs) = current {
                        out.push_str(&format!("- **latest stage seen (heuristic):** {cs}\n"));
                    }
                    // Authoritative current stage: read the `running` row from
                    // stages.tsv (upserted in real time by RustNativeStageRecorder).
                    // This is the canonical realtime contract — the heuristic
                    // log-line approach above is best-effort.
                    let stages_path = rd.join("state/stages.tsv");
                    if let Some(active) =
                        read_rust_native_running_stage_from_tsv(stages_path.as_path())
                    {
                        out.push_str(&format!("- **active stage (stages.tsv):** {active}\n"));
                    }
                    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
                    let start = lines.len().saturating_sub(12);
                    out.push_str("\n## Latest log lines\n```\n");
                    for l in &lines[start..] {
                        out.push_str(l);
                        out.push('\n');
                    }
                    out.push_str("```\n");
                } else {
                    out.push_str("\n_Log not readable yet (run may be starting up)._\n");
                }
            }
        }

        if let Some(rd) = &report_dir {
            let mut files: Vec<(String, u64)> = Vec::new();
            collect_files(rd, rd, &mut files, 0);
            out.push_str(&format!(
                "\n## Report dir\n- artifacts so far: {}\n",
                files.len()
            ));
            let mut newest: Option<(String, u64)> = None;
            for (rel, _) in &files {
                if let Some(age) = mtime_age_secs(&rd.join(rel))
                    && newest.as_ref().is_none_or(|(_, a)| age < *a)
                {
                    newest = Some((rel.clone(), age));
                }
            }
            if let Some((rel, age)) = newest {
                out.push_str(&format!(
                    "- newest artifact: `{rel}` ({} ago)\n",
                    fmt_dur(age)
                ));
            }
        }

        out.push_str(
            "\nFull log: tail_job_log. Finished run: get_run_result. Stuck (no activity): cancel_job → recover.\n",
        );
        tool_success(&out)
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Path to the utmctl binary (env override, else the standard UTM.app location).
fn utmctl_path() -> String {
    std::env::var("RUSTYNET_UTMCTL_PATH")
        .unwrap_or_else(|_| "/Applications/UTM.app/Contents/MacOS/utmctl".to_string())
}

/// Human-friendly duration: `45s`, `12m3s`, `4h7m`.
fn fmt_dur(secs: u64) -> String {
    if secs < 90 {
        format!("{secs}s")
    } else if secs < 5400 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Seconds since a file was last modified (None if unreadable / clock skew).
fn mtime_age_secs(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .elapsed()
        .ok()
        .map(|d| d.as_secs())
}

/// Read the first `running` row from a stages.tsv file and return the stage
/// name (column 0). Returns None when the file is absent, unparseable, or has
/// no `running` row.
///
/// stages.tsv columns: stage \t tier \t status \t rc \t log_path \t summary \t started_at \t finished_at
/// The Rust engine upserts a `status=running` row at stage start and replaces
/// it at stage finish — this is the canonical realtime active-stage signal.
fn read_rust_native_running_stage_from_tsv(path: &Path) -> Option<String> {
    let body = std::fs::read_to_string(path).ok()?;
    for line in body.lines() {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() >= 3 && cols[2].trim() == "running" && !cols[0].trim().is_empty() {
            return Some(cols[0].trim().to_owned());
        }
    }
    None
}

/// Parse `ps -o state=,lstart=` output into the process start-time token, or
/// `None` when the process is a zombie/defunct (state begins with `Z`) or the
/// output is empty.
///
/// A defunct process still has a `ps` entry and an `lstart`, but it is NOT
/// running — its parent has exited or not yet reaped it. Treating it as alive
/// pegged a crashed live-lab job "running" forever (and `cancel_job`'s SIGKILL
/// is a no-op on an already-dead pid), which wedged the single job slot until a
/// human cleared the record by hand. Failing closed to "not alive" for zombies
/// lets the job-state machinery report the crashed job as ended and frees the
/// slot automatically. The returned token is the `lstart` string only, so it
/// stays byte-compatible with records written before this change (which stored
/// the bare `lstart`).
fn parse_ps_state_lstart(output: &str) -> Option<String> {
    let s = output.trim();
    if s.is_empty() {
        return None;
    }
    let mut parts = s.splitn(2, char::is_whitespace);
    let state = parts.next().unwrap_or("");
    if state.starts_with('Z') {
        return None;
    }
    let lstart = parts.next().map(str::trim).unwrap_or("");
    (!lstart.is_empty()).then(|| lstart.to_string())
}

/// True if a TCP connection to `ip:port` succeeds within `timeout`.
fn tcp_reachable(ip: &str, port: u16, timeout: Duration) -> bool {
    if ip.is_empty() {
        return false;
    }
    let parsed_ip: IpAddr = match ip.trim().parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let socket_addr = SocketAddr::new(parsed_ip, port);
    if TcpStream::connect_timeout(&socket_addr, timeout).is_ok() {
        return true;
    }
    // On macOS some process contexts (e.g. MCP server spawned under Claude.app) cannot
    // reach bridged-network VMs with an unbound socket. Retry bound to the source IP the
    // kernel would select (discovered via zero-cost UDP connect — sends no bytes).
    let IpAddr::V4(v4) = parsed_ip else {
        return false;
    };
    let octets = v4.octets();
    let source_ip: Option<IpAddr> = if octets[0] == 192 && octets[1] == 168 && octets[2] == 64 {
        "192.168.64.1".parse().ok()
    } else {
        std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|u| {
                u.connect(SocketAddr::new(IpAddr::V4(v4), port))?;
                u.local_addr()
            })
            .ok()
            .map(|a| a.ip())
            .filter(|src| *src != IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
    };
    if let (Some(src), Ok(sock)) = (source_ip, Socket::new(Domain::IPV4, Type::STREAM, None)) {
        let bind: SocketAddr = SocketAddr::new(src, 0);
        if sock.bind(&SockAddr::from(bind)).is_ok()
            && sock
                .connect_timeout(&SockAddr::from(socket_addr), timeout)
                .is_ok()
        {
            return true;
        }
    }
    // Third fallback: UDP connect also fails from sandboxed process contexts on macOS.
    // Enumerate local interface addresses and find one in the same /24 as the target.
    let target_prefix = {
        let o = v4.octets();
        [o[0], o[1], o[2]]
    };
    let ifaddr_src: Option<IpAddr> = nix::ifaddrs::getifaddrs().ok().and_then(|addrs| {
        addrs
            .filter_map(|ia| ia.address)
            .filter_map(|sa| {
                let v4_local = sa.as_sockaddr_in()?.ip();
                let o = v4_local.octets();
                if [o[0], o[1], o[2]] == target_prefix && v4_local != v4 {
                    Some(IpAddr::V4(v4_local))
                } else {
                    None
                }
            })
            .next()
    });
    if let (Some(src), Ok(sock)) = (ifaddr_src, Socket::new(Domain::IPV4, Type::STREAM, None)) {
        let bind: SocketAddr = SocketAddr::new(src, 0);
        if sock.bind(&SockAddr::from(bind)).is_ok()
            && sock
                .connect_timeout(&SockAddr::from(socket_addr), timeout)
                .is_ok()
        {
            return true;
        }
    }
    false
}

/// The fields of macOS `route get <ip>` output that matter for diagnosing
/// lab connectivity: which interface the kernel would actually send packets
/// out on, and whether that's a specific route or a fallback to the default
/// route (`destination: default` — no more-specific route exists at all).
struct RouteGetResult {
    destination: String,
    interface: Option<String>,
}

fn parse_route_get_output(output: &str) -> Option<RouteGetResult> {
    let mut destination = None;
    let mut interface = None;
    for line in output.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("destination:") {
            destination = Some(v.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("interface:") {
            interface = Some(v.trim().to_owned());
        }
    }
    destination.map(|destination| RouteGetResult {
        destination,
        interface,
    })
}

/// Host network interfaces currently carrying an IPv4 address in the same
/// /24 as `target`. Used to find which local interface (e.g. a UTM NAT
/// bridge) actually owns a lab-VM subnet right now, independent of what the
/// kernel's route table currently resolves — the two can disagree when a
/// stale route lingers after a network change.
fn host_interfaces_in_same_slash24(target: Ipv4Addr) -> Vec<String> {
    let target_prefix = {
        let o = target.octets();
        [o[0], o[1], o[2]]
    };
    nix::ifaddrs::getifaddrs()
        .map(|addrs| {
            addrs
                .filter_map(|ia| {
                    let v4 = ia.address?.as_sockaddr_in()?.ip();
                    let o = v4.octets();
                    ([o[0], o[1], o[2]] == target_prefix && v4 != target)
                        .then_some(ia.interface_name)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Extract the first `<key>MacAddress</key><string>…</string>` value from a
/// UTM bundle's `config.plist` (UTM always writes this as XML, not binary
/// plist). Text-scan rather than a plist dependency: the schema is simple
/// and stable. Mirrors `rustynet-cli`'s function of the same purpose
/// (separate crate, no code sharing — kept in sync by hand).
fn mac_address_from_utm_config_plist(bundle_path: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(bundle_path.join("config.plist")).ok()?;
    let key_pos = contents.find("<key>MacAddress</key>")?;
    let after_key = &contents[key_pos + "<key>MacAddress</key>".len()..];
    let string_start = after_key.find("<string>")? + "<string>".len();
    let string_end = after_key[string_start..].find("</string>")?;
    normalize_mac_address(after_key[string_start..string_start + string_end].trim())
}

/// Extract the first `<key>Mode</key><string>…</string>` value from a UTM
/// bundle's `config.plist` Network entry — `"Shared"` (UTM's internal
/// vmnet NAT, may or may not land the guest on the physical LAN depending
/// on Apple's own allocation) or `"Bridged"` (ties the virtual NIC directly
/// to a real host interface, e.g. `en0`, guaranteeing a real DHCP lease
/// from the physical router).
fn utm_config_network_mode(bundle_path: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(bundle_path.join("config.plist")).ok()?;
    let key_pos = contents.find("<key>Mode</key>")?;
    let after_key = &contents[key_pos + "<key>Mode</key>".len()..];
    let string_start = after_key.find("<string>")? + "<string>".len();
    let string_end = after_key[string_start..].find("</string>")?;
    Some(
        after_key[string_start..string_start + string_end]
            .trim()
            .to_owned(),
    )
}

/// Normalize a MAC address to lowercase, zero-padded colon-hex. macOS's
/// `arp -a` omits leading zeros per octet (e.g. `6:2b:b:28:e3:ff`), while
/// UTM's config.plist writes them zero-padded — normalize both sides.
fn normalize_mac_address(mac: &str) -> Option<String> {
    let octets: Vec<&str> = mac.split(':').collect();
    if octets.len() != 6 {
        return None;
    }
    let mut normalized = String::with_capacity(17);
    for (index, octet) in octets.iter().enumerate() {
        if octet.is_empty() || octet.len() > 2 || !octet.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        if index > 0 {
            normalized.push(':');
        }
        if octet.len() == 1 {
            normalized.push('0');
        }
        normalized.push_str(&octet.to_ascii_lowercase());
    }
    Some(normalized)
}

/// Parse macOS `arp -a` output (`? (10.0.0.5) at aa:bb:cc:dd:ee:ff on en0 …`)
/// for the first row whose MAC matches `target_mac` (already normalized).
/// Skips `(incomplete)` rows, which carry no resolvable MAC.
fn extract_ip_for_mac_from_arp_output(arp_output: &str, target_mac: &str) -> Option<String> {
    for line in arp_output.lines() {
        let ip_start = line.find('(')? + 1;
        let Some(ip_end) = line[ip_start..].find(')') else {
            continue;
        };
        let ip = &line[ip_start..ip_start + ip_end];
        let Some(at_pos) = line.find(" at ") else {
            continue;
        };
        let after_at = line[at_pos + " at ".len()..].trim_start();
        let mac_token = after_at.split_whitespace().next().unwrap_or("");
        if mac_token == "(incomplete)" {
            continue;
        }
        if normalize_mac_address(mac_token).as_deref() == Some(target_mac) {
            return Some(ip.to_owned());
        }
    }
    None
}

/// Resolve a lab VM's CURRENT live IP by reading its MAC from the UTM
/// bundle's config.plist, then scanning the host `arp -a` table for a
/// match. This is the freshness check that must run BEFORE any host-route
/// diagnosis: a VM's UTM "Shared" network subnet can be silently
/// reallocated to a different range on every restart (found live — some
/// guests land on an isolated UTM bridge, others get MACNAT'd onto
/// whichever physical LAN the host is currently on), so inventory's
/// `last_known_ip` can be stale in a way that looks identical to "host
/// physically off this LAN" if you only look at routing.
fn resolve_live_ip_via_arp_by_mac(bundle_path: &Path) -> Option<String> {
    let mac = mac_address_from_utm_config_plist(bundle_path)?;
    let output =
        run_with_timeout("arp", &["-a"], Path::new("/"), &[], Duration::from_secs(5)).ok()?;
    if !output.success {
        return None;
    }
    extract_ip_for_mac_from_arp_output(&output.stdout, mac.as_str())
}

/// Diagnosis of whether the host's current route to a lab VM's subnet is
/// trustworthy, distinguishing the two failure modes found live: a stale
/// route pointing at the wrong interface (fixable with one `route add`) vs
/// the host simply not being on that LAN at all right now (not fixable
/// remotely — a physical network change).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostLabRouteVerdict {
    Correct,
    StaleOrMissing,
    OffLabLan,
}

fn classify_host_route(
    route: &RouteGetResult,
    owning_interfaces: &[String],
) -> HostLabRouteVerdict {
    if owning_interfaces.is_empty() {
        return HostLabRouteVerdict::OffLabLan;
    }
    match route.interface.as_deref() {
        Some(iface) if owning_interfaces.iter().any(|i| i == iface) => HostLabRouteVerdict::Correct,
        _ => HostLabRouteVerdict::StaleOrMissing,
    }
}

/// True only for OS-reported interface names (`en0`, `bridge101`, `utun7`,
/// ...), which are always plain ASCII alphanumerics. Defense-in-depth before
/// this string is interpolated into a shell command that runs with
/// administrator privileges — even though it's always sourced from
/// `nix::ifaddrs`, never from caller input, a string that fails this check
/// is refused rather than shelled out.
fn is_safe_interface_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Build the idempotent fix. Three steps, each best-effort (failure
/// swallowed via `>/dev/null 2>&1` — only the final add's outcome matters):
/// (1) delete any kernel-cloned HOST-specific route for `target_ip` — the
/// kernel auto-creates one of these on ARP resolution and can leave it
/// REJECT-flagged (a blackhole) after repeated ARP failures, e.g. right
/// after a VM boots and briefly doesn't answer ARP; this is a MORE SPECIFIC
/// route than the network one below, so fixing the network route alone
/// does not clear it — found live, the guest stayed unreachable with a
/// structurally-correct network route until this was added; (2) delete any
/// existing (possibly wrong) route for `subnet`; (3) add the correct one
/// pinned to `interface`.
fn build_route_fix_shell_command(target_ip: &str, subnet: &str, interface: &str) -> String {
    format!(
        "/sbin/route delete -host {target_ip} >/dev/null 2>&1; /sbin/route delete -net {subnet} >/dev/null 2>&1; /sbin/route add -net {subnet} -interface {interface}"
    )
}

/// The guest-side port an internet-access reverse SOCKS tunnel listens on.
/// Fixed rather than per-alias: the forwarded port lives in the GUEST's own
/// network namespace, not the host's, so there is no host-side collision
/// between multiple simultaneous tunnels to different guests.
const VM_INTERNET_PROXY_PORT: u16 = 1080;

/// Where a VM's internet-access tunnel state (host-side pid) is tracked, so
/// enable/disable/status calls are idempotent across MCP-server reloads
/// instead of spawning duplicate tunnels or losing track of one — mirrors
/// the `state/mcp-jobs/*.json` pattern already used for live-lab jobs.
fn vm_internet_tunnel_state_path(repo_root: &Path, alias: &str) -> PathBuf {
    repo_root
        .join("state/vm-internet-tunnels")
        .join(format!("{alias}.json"))
}

fn read_vm_internet_tunnel_pid(repo_root: &Path, alias: &str) -> Option<u32> {
    let contents = std::fs::read_to_string(vm_internet_tunnel_state_path(repo_root, alias)).ok()?;
    let value: Value = serde_json::from_str(&contents).ok()?;
    value.get("pid").and_then(Value::as_u64).map(|p| p as u32)
}

fn write_vm_internet_tunnel_pid(repo_root: &Path, alias: &str, pid: u32) -> Result<(), String> {
    let path = vm_internet_tunnel_state_path(repo_root, alias);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, serde_json::json!({ "pid": pid }).to_string())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn remove_vm_internet_tunnel_state(repo_root: &Path, alias: &str) {
    let _ = std::fs::remove_file(vm_internet_tunnel_state_path(repo_root, alias));
}

/// Aliases with a LIVE reverse-SOCKS bootstrap tunnel (recorded pid still
/// running). SOCKS bootstrap contaminates network evidence: it must be
/// disabled and recorded absent before any evidence run launches
/// (LiveLabVmConnectivityRulebook §9).
fn active_vm_internet_tunnels(repo_root: &Path) -> Vec<String> {
    let dir = repo_root.join("state/vm-internet-tunnels");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut live = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(alias) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if read_vm_internet_tunnel_pid(repo_root, alias).is_some_and(host_pid_alive) {
            live.push(alias.to_owned());
        }
    }
    live.sort();
    live
}

/// True if a HOST-local process with this pid still exists. `kill -0` sends
/// no signal, only checks existence + permission — safe to call on a pid we
/// don't own without side effects.
fn host_pid_alive(pid: u32) -> bool {
    run_with_timeout(
        "kill",
        &["-0", &pid.to_string()],
        Path::new("/"),
        &[],
        Duration::from_secs(5),
    )
    .map(|o| o.success)
    .unwrap_or(false)
}

fn is_valid_vm_internet_access_action(action: &str) -> bool {
    matches!(action, "enable" | "disable" | "status")
}

/// Assemble the `ssh` argv for the reverse-SOCKS internet tunnel: the crate's
/// hardened transport options (strict host-key checking, BatchMode,
/// IdentitiesOnly, known_hosts, identity — inherited verbatim so the tunnel and
/// the reachability probe stay on ONE host-key policy) plus the persistent
/// reverse-dynamic-forwarding flags. Pure builder so the policy is unit-testable
/// without spawning ssh.
fn build_vm_internet_tunnel_argv(
    mut transport_opts: Vec<String>,
    port: u16,
    dest: String,
) -> Vec<String> {
    transport_opts.push("-o".to_owned());
    transport_opts.push("ExitOnForwardFailure=yes".to_owned());
    transport_opts.push("-N".to_owned());
    transport_opts.push("-R".to_owned());
    transport_opts.push(port.to_string());
    transport_opts.push(dest);
    transport_opts
}

/// Distinguish the two ways a guest's owning-subnet interface set can look
/// when it reaches its gateway but not the internet: a real physical-LAN
/// interface (`en0`, MACNAT'd — subject to the physical network's own
/// per-device admission control) vs an isolated UTM virtual bridge
/// (`bridgeNN` — subject to whatever limits UTM's own Shared-Network NAT
/// has, independent of the physical network).
fn classify_guest_network_path(owning_interfaces: &[String]) -> &'static str {
    if owning_interfaces.iter().any(|i| i == "en0") {
        "physical-lan"
    } else if owning_interfaces.iter().any(|i| i.starts_with("bridge")) {
        "isolated-utm-bridge"
    } else {
        "unknown"
    }
}

/// Quote `s` as an AppleScript string literal (backslash + double-quote
/// escaped). Used to embed a shell command inside a `do shell script`
/// AppleScript statement without going through an intermediate shell parse —
/// `Command::new("osascript").arg(...)` passes the AppleScript source as a
/// single argv element, so this only needs to satisfy AppleScript's own
/// string-literal syntax, not shell quoting.
fn apple_script_string_literal(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// RFC4180-aware single-line CSV split (handles quoted fields with commas).
fn split_csv_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                cur.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => out.push(std::mem::take(&mut cur)),
                _ => cur.push(c),
            }
        }
    }
    out.push(cur);
    out
}

fn coverage_columns_from_header(header: &[String]) -> Vec<(Option<usize>, String)> {
    let mut seen = BTreeSet::new();
    let mut cols = Vec::new();
    for (index, name) in header.iter().enumerate() {
        if name.contains("_stage_") || name.starts_with("cross_os_") {
            seen.insert(name.clone());
            cols.push((Some(index), name.clone()));
        }
    }
    for name in CANONICAL_COVERAGE_COLUMNS {
        if seen.insert((*name).to_owned()) {
            cols.push((None, (*name).to_owned()));
        }
    }
    cols
}

/// Classify a run history (oldest-first `(overall_result, first_failed_stage)`
/// pairs) into a one-line trend verdict. Pure so it's unit-testable without the
/// matrix file. Used by get_run_trend.
fn trend_verdict(rows: &[(String, String)]) -> String {
    let is_pass = |r: &str| r.eq_ignore_ascii_case("pass") || r.eq_ignore_ascii_case("passed");
    // Drop rows with no recorded result (in-flight / malformed).
    let runs: Vec<(&str, &str)> = rows
        .iter()
        .filter(|(r, _)| !r.trim().is_empty())
        .map(|(r, s)| (r.as_str(), s.as_str()))
        .collect();
    if runs.is_empty() {
        return "NO DATA".to_string();
    }
    let (last_res, _) = runs[runs.len() - 1];
    if is_pass(last_res) {
        let prev_pass = runs.len() >= 2 && is_pass(runs[runs.len() - 2].0);
        return if prev_pass {
            "GREEN — stable (last 2+ runs pass)".to_string()
        } else {
            "JUST GREEN (latest run passed; confirm with one more run)".to_string()
        };
    }
    // Latest run failed — measure the trailing run of consecutive failures.
    let mut streak: Vec<&str> = Vec::new();
    for pair in runs.iter().rev() {
        if is_pass(pair.0) {
            break;
        }
        streak.push(pair.1);
    }
    let latest_stage = streak.first().copied().unwrap_or("");
    let stage_label = if latest_stage.is_empty() {
        "(unknown stage)"
    } else {
        latest_stage
    };
    if streak.len() >= 2 && streak.iter().all(|s| *s == latest_stage) {
        format!(
            "STUCK at {stage_label} ({} consecutive fails at the same stage)",
            streak.len()
        )
    } else if streak.len() >= 2 {
        format!("MOVING (failing, but the stage is changing — latest: {stage_label})")
    } else {
        format!("FAILING at {stage_label} (only 1 run; need history to judge a trend)")
    }
}

fn find_digest_recursive(dir: &Path, depth: usize) -> Option<Value> {
    if depth == 0 {
        return None;
    }
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let p = entry.path();
        if p.is_dir() {
            if let Some(v) = find_digest_recursive(&p, depth - 1) {
                return Some(v);
            }
        } else if p
            .file_name()
            .map(|n| n == "failure_digest.json")
            .unwrap_or(false)
            && let Ok(s) = std::fs::read_to_string(&p)
            && let Ok(v) = serde_json::from_str(&s)
        {
            return Some(v);
        }
    }
    None
}

fn format_lab_outcome(title: &str, o: &CommandOutcome) -> ToolCallResult {
    let mut result = format!("# {title}\n\n");
    if o.timed_out {
        result.push_str("## ⏱️ TIMED OUT (process killed)\n\n");
    } else if o.success {
        result.push_str("## ✅ PASSED\n\n");
    } else {
        result.push_str("## ❌ FAILED\n\n");
    }
    result.push_str(&format!(
        "**Exit code:** {}\n\n",
        o.code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "killed".into())
    ));
    // Tail-bias: when a lab op's output overflows, the error/verdict is at the end.
    let stdout = o.stdout.trim();
    if !stdout.is_empty() {
        result.push_str(&format!(
            "```\n{}\n```\n",
            truncate_tail(stdout, 400, 100_000)
        ));
    }
    let stderr = o.stderr.trim();
    if !stderr.is_empty() {
        result.push_str(&format!(
            "### stderr\n```\n{}\n```\n",
            truncate_tail(stderr, 80, 40_000)
        ));
    }
    ToolCallResult {
        content: text_content(result),
        is_error: if o.success { None } else { Some(true) },
    }
}

fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return format!("{home}/{rest}");
    }
    path.to_string()
}

fn default_ssh_identity() -> String {
    expand_tilde("~/.ssh/rustynet_lab_ed25519")
}

fn default_known_hosts() -> String {
    expand_tilde("~/.ssh/known_hosts")
}

fn arg_str<'a>(args: Option<&'a Value>, key: &str) -> Option<&'a str> {
    args.and_then(|a| a.get(key)).and_then(|v| v.as_str())
}

fn arg_bool(args: Option<&Value>, key: &str) -> bool {
    args.and_then(|a| a.get(key))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Auto-synthesize a full `nodes` (`alias:role`) topology from role-platform
/// selectors + inventory, so `start_live_lab_run` routes through the Rust
/// `--node` engine instead of the legacy bash arm whenever a selector is used
/// without explicit `nodes`. Bash is slated for removal once Rust parity
/// evidence is complete, so a selector-driven run should exercise Rust by
/// default. Role priority mirrors ai_lab_run's `synthesize_rust_node_args`:
/// `admin`/`blind_exit` are first-class `--node` role tokens (Bucket 1.5;
/// `NodeRole::parse` accepts both, and `is_lab_assignable_for_platform` allows
/// any OS for lab-evidence purposes) so each selector maps to its own real
/// role instead of aliasing onto anchor/exit.
///
/// `linux_lab_roles` is `(alias, lab_role)` for every Linux inventory entry
/// (see `inventory_linux_lab_roles`) — this is the same data bash's own
/// auto-topology derives its Linux backbone from, kept 1:1 so a
/// selector-driven Rust run covers the same nodes a bash run would.
#[allow(clippy::too_many_arguments)]
fn synthesize_nodes_from_platform_selectors(
    linux_lab_roles: &[(String, String)],
    macos_alias: Option<&str>,
    windows_alias: Option<&str>,
    exit_platform: Option<&str>,
    relay_platform: Option<&str>,
    anchor_platform: Option<&str>,
    admin_platform: Option<&str>,
    blind_exit_platform: Option<&str>,
    macos_promote_exit: bool,
) -> Vec<String> {
    let role_for_os = |os: &str| -> &'static str {
        let is = |sel: Option<&str>| sel.is_some_and(|s| s.eq_ignore_ascii_case(os));
        if is(admin_platform) {
            "admin"
        } else if is(blind_exit_platform) {
            "blind_exit"
        } else if (os == "macos" && macos_promote_exit) || is(exit_platform) {
            "exit"
        } else if is(relay_platform) {
            "relay"
        } else if is(anchor_platform) {
            "anchor"
        } else {
            "client"
        }
    };
    // A mac/win node taking the exit role replaces the Linux exit, not adds
    // to it — Exit is the membership-issuing singleton.
    let non_linux_exit_selected =
        macos_promote_exit || exit_platform.is_some_and(|p| matches!(p, "macos" | "windows"));

    let mut out = Vec::new();
    for (alias, role) in linux_lab_roles {
        if role == "exit" && non_linux_exit_selected {
            continue;
        }
        out.push(format!("{alias}:{role}"));
    }
    if let Some(m) = macos_alias {
        out.push(format!("{m}:{}", role_for_os("macos")));
    }
    if let Some(w) = windows_alias {
        out.push(format!("{w}:{}", role_for_os("windows")));
    }
    out
}

/// True when at least one role-platform selector (or the Option-B macOS
/// secondary-exit selector) is present in the tool args — the signal that a
/// selector-driven run should synthesize `--node` instead of falling to bash.
fn has_role_platform_selector(args: Option<&Value>) -> bool {
    arg_bool(args, "macos_promote_exit")
        || [
            "exit_platform",
            "relay_platform",
            "anchor_platform",
            "admin_platform",
            "blind_exit_platform",
        ]
        .into_iter()
        .any(|k| arg_str(args, k).is_some())
}

const OVERNIGHT_PLAYBOOK: &str = r#"# Overnight live-lab autonomous loop

Drive: run live lab (Windows + macOS + Linux) → catch bugs → patch → re-verify,
unattended, until your time budget is spent or you get 2 consecutive all-green runs.

PACING — never block on one call. Lab runs are async: start_live_lab_run returns a
job_id instantly; poll get_job_status every ~5–10 min. Use your /loop or scheduled
wakeups between polls.

LOOP:
1. READY THE LAB (no human needed)
   - preflight_check FIRST — one go/no-go over host tools, ssh material, inventory,
     disk, the deploy set, and every node's power+TCP. 🛑 NO-GO → fix the ❌ host
     items; ⚠️/✅ → proceed, recovering flagged nodes below.
   - check_vm_reachable(alias) per node. DOWN → power_on_vm. UP-but-UNREACHABLE →
     reset_vm_network (out-of-band via utmctl exec: flushes the killswitch +
     restarts networking, no SSH), then update_inventory (refresh live IPs — NEVER
     hand-edit). Still unreachable after reset → the VM is on the wrong UTM network
     (host-side fix) or try power_off_vm force=true → power_on_vm (hard reset).
     ensure_lab_ready does discover→restart→confirm in one call; recover_stuck_vms
     clears killswitch lockouts fleet-wide.
2. START A RUN (non-blocking)
   - start_live_lab_run mode=orchestrate. Leave windows_vm/macos_vm unset —
     auto_topology (default on) fills them from the inventory for full 3-OS
     coverage. Note the returned job_id + report_dir.
3. WAIT until done (don't busy-poll)
   - wait_for_job(job_id) — blocks up to ~4 min and returns the instant the job
     ends; call it in a loop. State resolves to passed / failed / ended.
   - get_run_progress(job_id) between waits for live mid-run visibility: elapsed,
     last-activity age (flags a possible hang if no log output >10m), latest log
     lines, artifacts so far. Use it to tell 'progressing' from 'stuck' over a
     multi-hour run; tail_job_log(job_id) for the full log.
4. CATCH BUGS (on failure)
   - get_run_result(job_id) → overall_result, first_failed_stage, per-OS/per-stage
     map, failure digest (stage / reason / message).
   - explain_stage(first_failed_stage) → what that stage checks, the owning
     file/crate, and common causes (turns the failure into a patch target).
   - get_stage_log(job_id, stage=first_failed_stage) → that stage's row + the tail
     of its log in one call (faster than browsing artifacts). grep_report(job_id,
     pattern) to hunt a specific error string / panic / peer id across all logs.
     list_report_artifacts + read_report_artifact for anything else;
     get_vm_diagnostics(alias) on the failing node — or, if it's unreachable,
     get_vm_network_info(alias) (out-of-band: ip/route/nft killswitch/daemon log,
     no SSH); diagnose_live_lab_failure for deep triage.
5. PATCH
   - repo-context which_crate (on explain_stage's owning file) + get_read_order to
     find the owning crate + rules; get_architecture_constraints (default-deny,
     fail-closed, no unwrap in prod). Edit the ROOT cause, minimally.
6. VERIFY THE PATCH (fast, before re-running the lab)
   - gate-runner run_gates with changed_only=true (auto-scopes to the crates you
     touched) for a fast inner loop, then a full run_gates. Fix until green.
7. RE-VERIFY ON THE LAB (don't waste hours)
   - what_will_deploy FIRST — confirm your patch (incl. any NEW files) is in the
     deploy set; untracked crates/ files won't ship until `git add`ed.
   - If the patch touched ONE node's code: start_live_lab_run mode=orchestrate with
     your full `nodes` topology + rebuild_nodes=[that node] + skip_soak — redeploys
     only that node (others keep their daemon/state), skips the slow soak. This is
     the big time saver. There is NO mid-stage resume (redeploying a node resets its
     state, so its setup stages must replay); explain_stage(first_failed_stage) spells
     out the exact re-verify command.
   - If the patch is in shared code / affects all nodes: omit rebuild_nodes (all
     rebuild). Dirty tree is fine (working-tree deploys it; git add new files).
   - Fresh report_dir each run. Back to step 3. When it ends, diff_runs(old=prev,
     new=this) tells you whether the patch HELPED or REGRESSED (which stages flipped).
8. TRACK
   - get_run_trend → one-line verdict across recent runs: STUCK at <stage> (keep
     patching that stage), MOVING (each fix advanced the run), or two greens =
     done. get_run_matrix for the full per-stage CSV when you need detail.

PICKING WORK (when there's no active failure to chase)
   - find_untested_work → a prioritized queue from the whole matrix history:
     REGRESSED (passed before, now failing) → NEVER-PASSED → STALE-GREEN →
     NEVER-RUN (check get_platform_support — some are unsupported-by-design).
     Take the suggested target, explain_stage it, drive a focused run. This is
     how you make forward progress without a human handing you a task.

RULES
- One root-cause fix per iteration; re-verify before moving on.
- JOURNAL every iteration: write_loop_note (iteration #, hypothesis, patch, result)
  as you go. Your context WILL compact over a long run — at the start of each
  iteration (and right after any compaction) get_loop_journal to recover what you
  already tried, so you don't repeat a dead end.
- If a VM wedges repeatedly: recover_stuck_vms + update_inventory before retrying.
- Never claim green without get_run_result overall_result=pass (or run_passed=true).
- Commit/push ONLY if the user authorized it; otherwise leave patches in the tree
  and summarize what changed and why.

LONG-RUN (24h+) NOTES
- Source: start_live_lab_run defaults to source_mode=working-tree, so your
  UNCOMMITTED edits are deployed. BUT working-tree capture (git stash create) only
  includes TRACKED changes — if a patch ADDS a new file, `git add` it or it won't
  reach the VMs.
- A single run is capped at 24h (CLI default). For a longer soak, pass
  timeout_secs to start_live_lab_run.
- Disk: each run writes a report dir + log. Check host_disk_status periodically;
  every ~10 iterations call prune_jobs (keeps the most recent; never touches a
  running job) to reclaim space.
- Job status is read from the run's completion record first (pid-reuse-safe), so
  get_job_status stays correct across MCP-server reloads over many hours.
"#;

impl McpServer for LabStateServer {
    fn server_info(&self) -> ServerInfo {
        ServerInfo {
            name: "rustynet-lab-state".into(),
            version: rustynet_mcp::server_version(),
        }
    }

    fn prompts(&self) -> Vec<Prompt> {
        vec![Prompt {
            name: "overnight-live-lab-loop".into(),
            description: Some(
                "Turnkey recipe for an agent to run the live lab autonomously overnight: run → catch bugs → patch → re-verify across Windows/macOS/Linux.".into(),
            ),
            arguments: vec![
                PromptArgument {
                    name: "windows_vm".into(),
                    description: Some("Windows VM alias to include".into()),
                    required: Some(false),
                },
                PromptArgument {
                    name: "macos_vm".into(),
                    description: Some("macOS VM alias to include".into()),
                    required: Some(false),
                },
                PromptArgument {
                    name: "hours".into(),
                    description: Some("Time budget in hours".into()),
                    required: Some(false),
                },
            ],
        }]
    }

    fn get_prompt(&self, name: &str, arguments: Option<Value>) -> Option<GetPromptResult> {
        if name != "overnight-live-lab-loop" {
            return None;
        }
        let args = arguments.as_ref();
        let mut body = OVERNIGHT_PLAYBOOK.to_string();
        let mut params = String::new();
        if let Some(w) = arg_str(args, "windows_vm") {
            params.push_str(&format!("\n- windows_vm: {w}"));
        }
        if let Some(m) = arg_str(args, "macos_vm") {
            params.push_str(&format!("\n- macos_vm: {m}"));
        }
        if let Some(h) = arg_str(args, "hours") {
            params.push_str(&format!("\n- time budget: {h} hours"));
        }
        if !params.is_empty() {
            body.push_str(&format!("\n## This run's parameters{params}\n"));
        }
        Some(prompt_text("Overnight live-lab loop", body))
    }

    fn tools(&self) -> Vec<Tool> {
        vec![
            Tool {
                name: "get_lab_status".into(),
                description: "Discover all UTM VMs and return platform, live IP, SSH reachability, execution readiness. `ops vm-lab-discover-local-utm-summary`.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "get_lab_status_json".into(),
                description: "Full JSON discovery report. `ops vm-lab-discover-local-utm --json`.".into(),
                input_schema: json_schema_object(
                    json!({"report_dir": json_schema_string("Optional dir to write the discovery report into")}),
                    vec![],
                ),
            },
            Tool {
                name: "get_inventory".into(),
                description: "Return the machine-readable VM inventory JSON with credential-like fields redacted. For a compact topology digest prefer get_lab_topology.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "get_lab_topology".into(),
                description: "Compact, secret-free per-node digest (alias, platform, lab_role, exit/relay-capable, include_in_all, mesh_ip) PLUS the resolved auto-topology — what start_live_lab_run will actually use for Windows/macOS/Linux if you pass no VM flags. Use this to plan a run.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "validate_inventory".into(),
                description: "Compare the stored inventory against live discovery; flag stale IPs / unreachable hosts.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },

            // ---- multi-host lab (LinuxVmHostPlan §6.7) --------------------
            // The lab spans more than one MACHINE (macOS/UTM + x86-64 KVM). These
            // three answer "are the machines comparable, and what can they run?"
            // so a driving agent never has to remember the order or the checks.
            Tool {
                name: "host_preflight".into(),
                description: "START HERE for any multi-machine run. Ordered, fail-closed gates over every declared host: inventory -> commit_pinned -> local_clean -> commit_pushed -> hosts_on_commit -> hosts_agree -> guests_ready. Stops at the first failure and NAMES THE COMMAND that fixes it; skipped gates report not_run (never assumed green). Verdict GO/NO-GO. `ops vm-lab-host-preflight`. This is the MACHINE-level gate; vm-lab-preflight (preflight_check) gates individual GUESTS — run this first, that second.".into(),
                input_schema: json_schema_object(
                    json!({
                        "inventory": {"type": "string", "description": "Inventory path (repo-relative). Default: the lab inventory. Use to target a different fleet or a scratch inventory."},
                        "commit": {"type": "string", "description": "Ref/SHA every host must be on. Default HEAD. Pin an explicit SHA for a multi-host comparison: this repo has concurrent sessions committing, so 'main' can resolve differently per host."},
                        "hosts": {"type": "string", "description": "Comma-separated host_ids to check. Default: every declared host."},
                        "allow_dirty": {"type": "boolean", "description": "Permit a dirty worktree. Off by default: a dirty tree is not reproducible from a SHA, so its evidence does not match the commit it claims."},
                        "ssh_identity_file": {"type": "string", "description": "SSH identity for reaching remote hosts. Defaults to the lab identity."}
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "sync_host".into(),
                description: "Put a lab host's orchestrator source on a named commit and PROVE it by reading back that host's own `git rev-parse HEAD`. Required before a host's run evidence means anything: run provenance (git_commit/git_dirty_state) is computed by shelling out to git in each host's OWN checkout, so a host that is not really on the commit produces evidence that lies. Fetches from the public origin (no credentials) — so the commit MUST be pushed first. Refuses a dirty tree; never moves your local working tree. `ops vm-lab-sync-host`.".into(),
                input_schema: json_schema_object(
                    json!({
                        "inventory": {"type": "string", "description": "Inventory path (repo-relative). Default: the lab inventory. Use to target a different fleet or a scratch inventory."},
                        "host": {"type": "string", "description": "host_id from the inventory's hosts[] (e.g. ubuntu-kvm-1). Omit and set all:true to sync every host."},
                        "all": {"type": "boolean", "description": "Sync EVERY declared host to the same commit in one call. Mutually exclusive with host."},
                        "commit": {"type": "string", "description": "Ref/SHA to pin. Default HEAD. Must exist on origin."},
                        "verify_only": {"type": "boolean", "description": "Assert the host's state without changing it."},
                        "allow_dirty": {"type": "boolean"},
                        "ssh_identity_file": {"type": "string"}
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "host_net_status".into(),
                description: "Answer 'why can't I reach this host, and has its address drifted?'. Probes the DECLARED connect_uri endpoint first, then any declared alt_ssh_endpoints, and — over whichever path answers — asks the machine what addresses it ACTUALLY has. Distinguishes the three cases you would otherwise guess between: DOWN (nothing answered), PATH-DRIFT (declared endpoint dead but the machine is alive on an alternate — the inventory is stale), and UP-BUT-UNUSABLE (the machine ANSWERED but SSH could not complete). Probe states are classified, never flattened: up:host-key-not-pinned / up:auth-failed / up:ssh-refused mean the box is UP and it is a trust/auth problem, NOT a network fault — chasing it as one wastes real time. Never rewrites connect_uri: silent failover would hide the drift worth reporting. `ops vm-lab-host-net-status`.".into(),
                input_schema: json_schema_object(
                    json!({
                        "inventory": {"type": "string", "description": "Inventory path (repo-relative). Default: the lab inventory. Use to target a different fleet or a scratch inventory."},
                        "host": {"type": "string", "description": "Restrict to one host_id. Default: every declared host."},
                        "format": {"type": "string", "enum": ["table", "json"]},
                        "ssh_identity_file": {"type": "string"}
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "host_run_status".into(),
                description: "Ask a REMOTE lab host what it is doing and what its last run found — without going there. Reports whether an orchestrator process is IN FLIGHT, then reads that host's OWN evidence ledger over SSH and returns which stages passed, which failed (with alias + error_detail), the no-verdict count, the commit + dirty state the run recorded, and its report_dir. IMPORTANT: each machine keeps its own ledger — a run writes to the host that ran it — so the local ledger CANNOT see the box's runs and this is the only way to read them. Read-only. `ops vm-lab-host-run-status`.".into(),
                input_schema: json_schema_object(
                    json!({
                        "inventory": {"type": "string", "description": "Inventory path (repo-relative). Default: the lab inventory. Use to target a different fleet or a scratch inventory."},
                        "host": {"type": "string", "description": "host_id of a remote host from hosts[]."},
                        "run_id": {"type": "string", "description": "Which run to report. Default: the newest recorded on that host."},
                        "stage": {"type": "string", "description": "Report only stages whose name CONTAINS this (case-insensitive), e.g. 'two_hop' or 'dns'. One filter rather than a function per stage — the stage set changes, a filter cannot drift from it. Errors (listing the run's real stages) if nothing matches, so a typo never reads as 'nothing wrong'."},
                        "format": {"type": "string", "enum": ["table", "json"], "description": "json gives full error_detail per failed stage."},
                        "ssh_identity_file": {"type": "string"}
                    }),
                    vec!["host"],
                ),
            },
            Tool {
                name: "launch_live_lab_on_host".into(),
                description: "Start a live-lab run ON a remote host, DETACHED, and return immediately with a pid — the one action that was still a manual SSH. The orchestrator runs 30-45 min; this does NOT wait for it. It launches under setsid+nohup with all fds off the SSH channel, so the run survives the connection dropping, records its own pid for a later stop, and refuses to start if one is already in flight on that host. Poll it with host_run_status and stop it with stop_host_run. report_dir is RELATIVE to the host's repo_dir (the orchestrator refuses a non-empty one, so use a fresh name). Pass orchestrator_args as the exact flags you would give `ops vm-lab-orchestrate-live-lab` (node selectors, platform/skip flags) — each is single-quoted into the remote script, so none may contain a single quote or shell metacharacter. dry_run renders the launcher without running it. `ops vm-lab-launch-on-host`.".into(),
                input_schema: json_schema_object(
                    json!({
                        "inventory": {"type": "string", "description": "Inventory path (repo-relative). Default: the lab inventory."},
                        "host": {"type": "string", "description": "host_id of a remote host from hosts[]."},
                        "report_dir": {"type": "string", "description": "Report directory ON the host, relative to its repo_dir (e.g. artifacts/live_lab/run-2026-07-17). Must be fresh: the orchestrator refuses a non-empty one."},
                        "orchestrator_args": {"type": "array", "items": {"type": "string"}, "description": "Flags forwarded verbatim to vm-lab-orchestrate-live-lab, e.g. [\"--client-vm\",\"linux-x86-client-1\",\"--exit-vm\",\"linux-x86-exit-1\",\"--skip-cross-network\"]. No single quotes or shell metacharacters."},
                        "host_ssh_identity": {"type": "string", "description": "Path ON THE HOST to the key the orchestrator uses to reach its guests. Default $HOME/.ssh/id_ed25519 (verified on ubuntu-kvm-1)."},
                        "dry_run": {"type": "boolean", "description": "Render the launcher + runner and return them without launching."},
                        "format": {"type": "string", "enum": ["table", "json"]},
                        "ssh_identity_file": {"type": "string"}
                    }),
                    vec!["host", "report_dir"],
                ),
            },
            Tool {
                name: "fetch_host_artifact".into(),
                description: "Read one file out of a remote host's checkout — the missing half of host_run_status, which hands back a report_dir that nothing could then read. Give it a path RELATIVE to the host's repo_dir (a report file, a launch log under state/host-lab-runs/, a stage ledger). Read-only and size-capped (default 5MB) so a stray huge path can't be streamed back; relative + no-traversal, so it can't reach outside the checkout. Text-oriented (a trailing newline may be dropped) — for reading evidence, not byte-exact binary copy. `ops vm-lab-fetch-host-artifact`.".into(),
                input_schema: json_schema_object(
                    json!({
                        "inventory": {"type": "string", "description": "Inventory path (repo-relative). Default: the lab inventory."},
                        "host": {"type": "string", "description": "host_id of a remote host from hosts[]."},
                        "path": {"type": "string", "description": "File to read, relative to the host's repo_dir (e.g. artifacts/live_lab/run-x/orchestration/summary.json)."},
                        "max_bytes": {"type": "integer", "description": "Refuse a file larger than this. Default 5242880 (5MB)."},
                        "ssh_identity_file": {"type": "string"}
                    }),
                    vec!["host", "path"],
                ),
            },
            Tool {
                name: "stop_host_run".into(),
                description: "Stop an in-flight live-lab run on a remote host. Signals the run's whole PROCESS GROUP (cargo -> rustynet-cli -> the guest-SSH children), not just the leader, so nothing is orphaned to keep hammering the guests; TERM first, then KILL after a grace period. Uses the pid the launch recorded (reload-proof) and falls back to pgrep. Idempotent: if nothing is running it says so rather than erroring, and it retires the handle files so a later host_run_status does not report a dead pid as live. `ops vm-lab-stop-host-run`.".into(),
                input_schema: json_schema_object(
                    json!({
                        "inventory": {"type": "string", "description": "Inventory path (repo-relative). Default: the lab inventory."},
                        "host": {"type": "string", "description": "host_id of a remote host from hosts[]."},
                        "format": {"type": "string", "enum": ["table", "json"]},
                        "ssh_identity_file": {"type": "string"}
                    }),
                    vec!["host"],
                ),
            },
            Tool {
                name: "compare_runs_at_commit".into(),
                description: "STEP 6 of the multi-machine loop: collapse every run recorded at ONE commit into a single verdict, so you read a conclusion instead of two report trees. Per-platform pass/fail/no-verdict rollup + the failing stages + which machine each run came from (alias -> host_id join). SURFACES CONFLICTS: the same node+stage answering differently across runs at one commit invalidates the comparison and is reported loudly, never silently resolved. An absent result (skip/not_run/reused/unknown) is NEVER counted as pass — that is how a two-machine split would otherwise manufacture parity that was never tested. Refuses runs recorded from a dirty worktree, and refuses to call one run a comparison (--expect-runs, default 2). `ops vm-lab-run-matrix-compare`.".into(),
                input_schema: json_schema_object(
                    json!({
                        "inventory": {"type": "string", "description": "Inventory path (repo-relative). Default: the lab inventory. Use to target a different fleet or a scratch inventory."},
                        "commit": {"type": "string", "description": "Ref/SHA to compare at. Default HEAD."},
                        "expect_runs": {"type": "integer", "description": "Minimum runs required. Default 2 — one machine reporting is not agreement."},
                        "allow_dirty": {"type": "boolean", "description": "Compare runs whose worktree was dirty (their evidence does not match the commit it names)."},
                        "stage": {"type": "string", "description": "Restrict to stages whose name CONTAINS this — 'how did THIS stage do across both machines?'."},
                        "include_hosts": {"type": "string", "description": "Comma-separated remote host_ids whose ledgers should be FETCHED and merged. REQUIRED for a genuine cross-machine comparison: each machine writes results to its OWN ledger, so without this you are comparing only the local one. If a named host cannot be read it errors rather than quietly comparing half the evidence."},
                        "format": {"type": "string", "enum": ["table", "json"]}
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "provision_guest".into(),
                description: "Create a headless cloud-image guest on a libvirt lab host (e.g. ubuntu-kvm-1) from a base image already in its pool. Bakes in the lessons that are NOT obvious: --video vga (virt-install --graphics none attaches no video device, and Debian cloud images boot-loop forever in GRUB's gfxterm without one — no kernel output at all), --cpu host-passthrough (so nested virt reaches inside the guest), and a backing-file overlay so guests share one read-only base. Verifies the pool's disk BY MODEL before writing anything if the host declares pool_disk_model. ALWAYS run with dry_run first to see the plan. It seeds cloud-init with the provisioning HOST's own public key (default $HOME/.ssh/id_ed25519.pub, override with authorized_key) so the host can SSH into the new guest immediately — no follow-up authorize step. Cleans up a half-made guest if virt-install fails. libvirt hosts only — UTM guests are created in the UTM app. `ops vm-lab-provision-guest`.".into(),
                input_schema: json_schema_object(
                    json!({
                        "inventory": {"type": "string", "description": "Inventory path (repo-relative). Default: the lab inventory. Use to target a different fleet or a scratch inventory."},
                        "host": {"type": "string", "description": "host_id of a libvirt host from hosts[]."},
                        "name": {"type": "string", "description": "Guest/domain name. ASCII alphanumeric, '-' or '_' only — it becomes a libvirt domain name AND a filename."},
                        "image": {"type": "string", "description": "Base image filename inside the host's pool (bare name, no path). Use discover_hosts / host_disk_status to see what is there."},
                        "ram_mb": {"type": "integer", "description": "Default 4096."},
                        "vcpus": {"type": "integer", "description": "Default 2."},
                        "disk_gb": {"type": "integer", "description": "Overlay size. Default 40."},
                        "pool": {"type": "string", "description": "libvirt image pool path on the host. Default /var/lib/libvirt/images. The host's declared pool_disk_model guard still applies to whatever you pass."},
                        "authorized_key": {"type": "string", "description": "Path ON THE HOST to the public key seeded into the guest. Default $HOME/.ssh/id_ed25519.pub (the key the host reaches its guests with)."},
                        "dry_run": {"type": "boolean", "description": "Print the plan and change nothing. Do this first."},
                        "ssh_identity_file": {"type": "string"}
                    }),
                    vec!["host", "name", "image"],
                ),
            },
            Tool {
                name: "discover_hosts".into(),
                description: "Point at the lab's MACHINES and get the VMs each actually has, and which are ready to join a run. Covers both host kinds uniformly: libvirt/KVM (probes `virsh version`, enumerates `virsh list --all`) and macOS/UTM (delegates to the UTM bundle scan). ready = domain running AND an IP resolved — running-without-IP is deliberately NOT ready, because the SSH plane would have nowhere to connect. Unregistered VMs are reported, not hidden. An unreachable host reports probe=FAILED and contributes no guests, so 'no VMs' never looks like 'could not ask'. `ops vm-lab-discover-hosts`.".into(),
                input_schema: json_schema_object(
                    json!({
                        "inventory": {"type": "string", "description": "Inventory path (repo-relative). Default: the lab inventory. Use to target a different fleet or a scratch inventory."},
                        "host": {"type": "string", "description": "Restrict to one host_id. Default: every declared host."},
                        "format": {"type": "string", "enum": ["table", "json"], "description": "json for machine consumption."}
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "update_inventory".into(),
                description: "Safely refresh the inventory's live IPs via `ops vm-lab-discover-local-utm-summary --update-inventory-live-ips`. The ONLY supported way to update IPs — never hand-edit the inventory.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "restart_vm".into(),
                description: "Restart one or more VMs (power cycle). ['--all'] for all; wait_ready waits for SSH. Minutes-scale (blocking).".into(),
                input_schema: json_schema_object(
                    json!({
                        "aliases": json_schema_array_string("VM aliases, or ['--all']"),
                        "wait_ready": json_schema_boolean("Wait for SSH readiness (default: true)"),
                    }),
                    vec!["aliases"],
                ),
            },
            Tool {
                name: "power_on_vm".into(),
                description: "Power ON one or more stopped VMs via utmctl (`ops vm-lab-start`). ['--all'] for all. Does NOT wait for SSH — follow with get_lab_status, or use restart_vm with wait_ready to start+wait. Use this to bring up a VM that get_vm_power_state shows as 'stopped'.".into(),
                input_schema: json_schema_object(
                    json!({"aliases": json_schema_array_string("VM aliases to power on, or ['--all']")}),
                    vec!["aliases"],
                ),
            },
            Tool {
                name: "power_off_vm".into(),
                description: "Power OFF one or more VMs via utmctl (`ops vm-lab-stop`). Graceful by default; force=true hard-stops a wedged VM. ['--all'] for all. Pair with power_on_vm for a hard reset when recover_stuck_vms isn't enough.".into(),
                input_schema: json_schema_object(
                    json!({
                        "aliases": json_schema_array_string("VM aliases to power off, or ['--all']"),
                        "force": json_schema_boolean("Hard stop (utmctl --force) instead of graceful (default: false)"),
                    }),
                    vec!["aliases"],
                ),
            },
            Tool {
                name: "get_vm_power_state".into(),
                description: "VM power state across EVERY declared host (started/stopped), annotated with inventory aliases and the owning host_id — distinct from SSH reachability. 'started but unreachable' = network/killswitch issue (recover_stuck_vms/update_inventory); 'stopped' = power_on_vm. Pass alias to filter (matches alias or domain). Delegates to the controller-aware CLI (`ops vm-lab-discover-hosts`), so libvirt/KVM guests and macOS/UTM guests are both covered — it used to drive `utmctl list` directly and therefore could not see a second host at all. A host that could not be probed is listed under an explicit warning rather than contributing nothing, so \"no VMs\" never reads as \"could not ask\".".into(),
                input_schema: json_schema_object(
                    json!({"alias": json_schema_string("Optional: only show this VM (alias or utm_name)")}),
                    vec![],
                ),
            },
            Tool {
                name: "check_vm_reachable".into(),
                description: "Answer 'is this VM up but unreachable?' in one call: combines utmctl power state with a direct TCP/22 probe → DOWN (power off) / UP+reachable / UP-but-UNREACHABLE, plus the right next action (power_on_vm / reset_vm_network / update_inventory).".into(),
                input_schema: json_schema_object(
                    json!({"alias": json_schema_string("VM alias")}),
                    vec!["alias"],
                ),
            },
            Tool {
                name: "reset_vm_network".into(),
                description: "Reset a Linux VM's networking OUT-OF-BAND via utmctl exec (no SSH needed) when it's up but unreachable: flush the nft killswitch, stop rustynetd, restart systemd-networkd/networking, then re-probe TCP/22. Use when check_vm_reachable says UP-but-UNREACHABLE. (macOS Apple-Virt has no utmctl exec; Windows: use restart_vm.) SCOPE: UTM guests only.".into(),
                input_schema: json_schema_object(
                    json!({"alias": json_schema_string("VM alias (Linux guest)")}),
                    vec!["alias"],
                ),
            },
            Tool {
                name: "get_vm_network_info".into(),
                description: "Out-of-band Linux guest network diagnostics via utmctl exec (no SSH): ip addr, ip route, the nft killswitch ruleset, rustynetd active-state, and the daemon's recent journal. The triage companion to reset_vm_network — run it when check_vm_reachable says UP-but-UNREACHABLE to see WHY (stale killswitch? wrong NAT subnet? daemon crashed?) before resetting. (macOS Apple-Virt / Windows: use get_vm_diagnostics over SSH.) SCOPE: UTM guests only.".into(),
                input_schema: json_schema_object(
                    json!({"alias": json_schema_string("VM alias (Linux guest)")}),
                    vec!["alias"],
                ),
            },
            Tool {
                name: "diagnose_host_lab_network".into(),
                description: "Diagnose HOST-side routing to lab VM subnets — a failure class none of the guest-facing tools can see, because it isn't a guest problem: the host's own kernel route table doesn't know how to reach the VM's subnet. Distinguishes two causes: a stale/missing host route (e.g. the macOS VM's Apple-Virtualization NAT subnet after a VPN or mesh-session route clobbered it — fixable, prints the exact `sudo route add` command) vs the host simply being off that VM's LAN right now (a physical Wi-Fi/Ethernet roam — not fixable remotely, just diagnosed clearly instead of every node timing out mysteriously). Read-only; does not execute the fix. Omit alias to check every inventory node at once.".into(),
                input_schema: json_schema_object(
                    json!({"alias": json_schema_string("Optional: only check this VM (alias)")}),
                    vec![],
                ),
            },
            Tool {
                name: "apply_host_route_fix".into(),
                description: "Apply the fix diagnose_host_lab_network can only prescribe, for ONE node's stale/missing host route. Re-derives the exact fix command internally from a fresh diagnosis (never accepts a raw command — no injection surface), then runs it via macOS's native `osascript ... with administrator privileges` prompt: the password/Touch ID goes straight to the OS's Security Server on the user's own screen, never through this tool, the agent, or any log. No-ops if the route is already correct; refuses (with an explanation) if the verdict is 'host off this LAN' — that's a physical network fact, not fixable by any tool. Verifies REAL TCP reachability after applying (not just that the route table looks right) — if multiple interfaces claim the same subnet (a UTM bridge-collision edge case), tries each in turn, which can mean approving more than one prompt. Requires the user to be at the keyboard to approve the OS prompt(s).".into(),
                input_schema: json_schema_object(
                    json!({"alias": json_schema_string("VM alias whose host route to fix")}),
                    vec!["alias"],
                ),
            },
            Tool {
                name: "set_vm_internet_access".into(),
                description: "Give a lab VM internet access without ever hand-typing SSH: enable (default)/disable/status a reverse dynamic SOCKS tunnel (`ssh -R 1080 user@guest`) so the guest routes outbound traffic through the HOST's own internet connection. `status` always reports DIRECT (no-tunnel) reachability first and, if that's failing, WHY — distinguishing (via gateway-ping + interface-ownership classification) an isolated UTM Shared-Network bridge whose own NAT isn't completing the forward (not fixable, host-independent) from a guest that's genuinely on the physical LAN but blocked by the network's own per-device admission control (captive portal / 802.1X — also not fixable by this tool, but a different kind of not-fixable). `enable` verifies REAL reachability through the tunnel before reporting success (not just that the process started) and is idempotent (safe to call repeatedly). Requires the node's SSH key already authorized (same requirement as every other lab-state remote-exec tool). Does NOT persist a system-wide proxy config on the guest — pass `http_proxy`/`https_proxy=socks5h://127.0.0.1:1080` (or dnf's `--setopt=proxy=`) to whatever command needs it.".into(),
                input_schema: json_schema_object(
                    json!({
                        "alias": json_schema_string("VM alias"),
                        "action": json_schema_string("enable (default) | disable | status"),
                    }),
                    vec!["alias"],
                ),
            },
            Tool {
                name: "diagnose_vm_lan_presence".into(),
                description: "Read-only: is this VM (all of them, if alias is omitted) directly on the physical LAN — a real DHCP lease from the same router the host uses, like debian-headless-4 achieved — or stuck on UTM's isolated internal Shared-Network bridge? Uses a FRESH ARP-by-MAC resolution (not stale inventory) plus the declared UTM config.plist Mode (Shared/Bridged) for context, since a 'Shared'-mode VM's actual network path is non-deterministic per restart — it can silently land on either side. Flags anything not on the physical LAN with the exact fix: apply_vm_bridged_network.".into(),
                input_schema: json_schema_object(
                    json!({"alias": json_schema_string("Optional: only check this VM (alias)")}),
                    vec![],
                ),
            },
            Tool {
                name: "apply_vm_bridged_network".into(),
                description: "DEPRECATED — always refuses (LiveLabVmConnectivityRulebook §11.3). This tool used to bridge a VM onto the host's everyday LAN (en0) via AppleScript with no profile, transaction, rollback, or evidence contract; that mutation path has been removed. Use audit_lab_network to see current attachments and prepare_lab_network (explicit approve_reconfigure + an allowlisted physical network profile) for any attachment change; en0 is denied by policy.".into(),
                input_schema: json_schema_object(
                    json!({"alias": json_schema_string("VM alias (recorded in the refusal message only)")}),
                    vec![],
                ),
            },
            Tool {
                name: "audit_lab_network".into(),
                description: "READ-ONLY network audit of the whole UTM fleet against the reviewed network profiles (profiles/vm_lab/network/*.toml). Runs `rustynet ops vm-lab-network-audit`: observes every VM's backend + per-NIC attachment (Shared/Host Only/Bridged + pinned interface), host routes/VPN/proxy, inventory staleness (duplicate IPs, drifted network_group labels), duplicate MACs, and the netns-simulator transit vs mesh 100.64.0.0/10 collision; writes redacted owner-only evidence to state/vm_network_evidence.json. NEVER mutates anything. Pass profile to evaluate drift against one profile id.".into(),
                input_schema: json_schema_object(
                    json!({
                        "profile": json_schema_string("Optional network profile id to evaluate drift against (e.g. mgmt_shared_smoke_v1, isolated_multivm_v1)"),
                        "include_guests": json_schema_boolean("Also SSH into guests for address/route/DNS/MTU observations (slower; default false)"),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "prepare_lab_network".into(),
                description: "The ONLY VM network mutation path (LiveLabVmConnectivityRulebook §11.2/§13). Runs `rustynet ops vm-lab-network-prepare --profile <id>`: WITHOUT approve_reconfigure=true it only prints the redacted dry-run plan (current vs target attachment per VM) and changes NOTHING. With approve_reconfigure=true it executes the atomic transaction: overlap-refusing network lease, full-config rollback snapshots (owner-only, outside committed evidence), stop every affected VM, apply, restart, verify, and roll everything back (verified by digest) on any failure. Autonomous loops MUST NOT set approve_reconfigure — it is an explicit operator authorization. en0 can never be a bridge target.".into(),
                input_schema: json_schema_object(
                    json!({
                        "profile": json_schema_string("Network profile id from profiles/vm_lab/network/ (required)"),
                        "aliases": json_schema_array_string("Optional subset of inventory VM aliases; empty = every local-UTM VM"),
                        "approve_reconfigure": json_schema_boolean("EXPLICIT mutation authorization. false/absent = dry-run plan only. Never set from an autonomous loop without operator approval."),
                    }),
                    vec!["profile"],
                ),
            },
            Tool {
                name: "restore_lab_network".into(),
                description: "Verified, idempotent rollback of a recorded network transaction: runs `rustynet ops vm-lab-network-restore --transaction <id>` (restores every VM's snapshotted configuration + power state, digest-verified) or lists recorded transactions when list=true. Safe after an interrupted prepare — the journal under state/vm_lab_network_txn/ survives MCP reloads and crashes, so lease and transaction truth are preserved.".into(),
                input_schema: json_schema_object(
                    json!({
                        "transaction_id": json_schema_string("Transaction id to restore (from prepare_lab_network output or list=true)"),
                        "list": json_schema_boolean("List recorded transactions and their outcomes instead of restoring"),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "recover_stuck_vms".into(),
                description: "Recover stuck VMs. WITHOUT host: local UTM guests stuck behind a stale nftables killswitch (SSH closed but VM alive) via probe-and-recover. WITH host: a REMOTE libvirt host's stuck guests — a running-but-unleased, paused, or shut-off guest is hard-reset (destroy+start) to force a clean boot and fresh DHCP lease, while a HEALTHY running-with-IP guest is left alone (so it is a safe no-op unless something is actually stuck). Pass force to reset even healthy guests.".into(),
                input_schema: json_schema_object(
                    json!({
                        "aliases": json_schema_array_string("Specific VMs; omit for all. Local: UTM aliases. Remote: libvirt domain names."),
                        "host": {"type": "string", "description": "host_id of a REMOTE libvirt host from hosts[]. Omit for the local UTM path."},
                        "force": {"type": "boolean", "description": "Remote only: reset even a healthy running guest."},
                        "inventory": {"type": "string", "description": "Inventory path (repo-relative). Default: the lab inventory."},
                        "ssh_identity_file": {"type": "string"}
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "ensure_lab_ready".into(),
                description: "Pre-flight: discover → restart unready + wait SSH → re-confirm. Minutes-scale (blocking). Pass profile to PRESERVE and re-verify a network profile: the fleet's attachments are audited against it after the restart (verify-only, fail-closed on drift) — this tool never 'repairs' Shared into Bridged or mutates any attachment (use prepare_lab_network for that).".into(),
                input_schema: json_schema_object(
                    json!({
                        "profile": json_schema_string("Optional network profile id to re-verify after readiness (verify-only; drift is reported, never repaired)"),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "preflight_check".into(),
                description: "Fast, read-only loop-start go/no-go in ONE call: host tools (cargo/utmctl/ssh/git), ssh identity + known_hosts, inventory parseability, disk headroom, the working-tree deploy set (untracked crates/ that won't ship), and every node's power+TCP. Returns a 🛑 NO-GO / ⚠️ CAUTION / ✅ GO verdict. Pass profile to ALSO run the read-only network audit against that profile — the report then includes the network evidence path (state/vm_network_evidence.json) and the profile's canonical digest. Use it before start_live_lab_run instead of calling host_disk_status + get_lab_topology + check_vm_reachable separately. (Does not mutate or restart anything — for active recovery use ensure_lab_ready.)".into(),
                input_schema: json_schema_object(
                    json!({
                        "profile": json_schema_string("Optional network profile id; adds the network audit + evidence path/digest to the report"),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "sync_repo_to_vm".into(),
                description: "rsync the working tree to a VM. `ops vm-lab-sync-repo`.".into(),
                input_schema: json_schema_object(
                    json!({"alias": json_schema_string("VM alias")}),
                    vec!["alias"],
                ),
            },
            Tool {
                name: "provision_guest_toolchain".into(),
                description: "Install everything a fresh Linux lab guest needs BEFORE Rustynet can be built on it — run this before bootstrap_vm on any new guest. rn_bootstrap.sh VERIFIES prerequisites and fails if absent; it does not install them, so a fresh cloud image needs this first. Installs the apt set (clang/llvm, build-essential, nftables, wireguard-tools, openssl+sqlite3 dev, tcpdump...) plus rustup PINNED to the repo's rust-toolchain.toml channel, and links the rustup shims into /usr/local/bin — without that `ssh guest cargo build` dies with 127 because a NON-LOGIN ssh shell never sources ~/.profile, which is exactly the shell the orchestrator uses. Idempotent; verify_only reports the prerequisite state and changes nothing. Takes a LIST of aliases. Debian-family Linux only. `ops vm-lab-provision-toolchain`.".into(),
                input_schema: json_schema_object(
                    json!({
                        "inventory": {"type": "string", "description": "Inventory path (repo-relative). Default: the lab inventory. Use to target a different fleet or a scratch inventory."},
                        "aliases": {"type": "array", "items": {"type": "string"}, "description": "Guest aliases to provision, e.g. [\"linux-x86-exit-1\",\"linux-x86-client-1\"]."},
                        "select_all": {"type": "boolean", "description": "Every include_in_all VM instead of a list."},
                        "verify_only": {"type": "boolean", "description": "Report prerequisite state, install nothing."},
                        "timeout_secs": {"type": "integer", "description": "Default 1800; apt+rustup on a slow link can take a while."},
                        "ssh_identity_file": {"type": "string"},
                        "format": {"type": "string", "enum": ["table", "json"]}
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "bootstrap_vm".into(),
                description: "Install/build Rustynet on one or MORE lab VMs. Phases: sync-source (ship the source), build-release (cargo build ON the guest), install-release, restart-runtime, verify-runtime, tunnel-smoke, killswitch-smoke, dns-smoke, ipv6-smoke, or `all` for the full chain. Pass `aliases` for several VMs in one call (they are handled by the same run, so a pair stays on identical source) or `select_all` for every include_in_all VM. Works for any inventory VM regardless of host — libvirt guests on a remote KVM box and local UTM guests alike, because the whole path is SSH. The guest must already have the toolchain rn_bootstrap verifies (rustup+cargo, clang/llvm, nft, wg, pkg-config openssl+sqlite3, passwordless sudo). SLOW: build-release compiles the workspace on the guest. `ops vm-lab-bootstrap-phase`.".into(),
                input_schema: json_schema_object(
                    json!({
                        "inventory": {"type": "string", "description": "Inventory path (repo-relative). Default: the lab inventory. Use to target a different fleet or a scratch inventory."},
                        "aliases": {"type": "array", "items": {"type": "string"}, "description": "VM aliases to bootstrap, e.g. [\"linux-x86-exit-1\",\"linux-x86-client-1\"]. One call keeps them on identical source."},
                        "alias": json_schema_string("Single VM alias (legacy; prefer `aliases`)"),
                        "select_all": {"type": "boolean", "description": "Every include_in_all VM instead of a list."},
                        "phase": json_schema_string("sync-source | build-release | install-release | restart-runtime | verify-runtime | all"),
                        "local_source_dir": {"type": "string", "description": "Ship source from this local path instead of cloning a repo. Default: the repo working tree."},
                        "repo_url": {"type": "string", "description": "Clone from this URL on the guest instead of shipping local source."},
                        "branch": {"type": "string"},
                        "dest_dir": {"type": "string", "description": "Absolute path on the guest. Default: the entry's rustynet_src_dir."},
                        "timeout_secs": {"type": "integer", "description": "build-release on a cold guest can take many minutes; raise this."}
                    }),
                    vec!["phase"],
                ),
            },
            Tool {
                name: "get_vm_diagnostics".into(),
                description: "Collect diagnostics from a VM (daemon status, tunnels, handshake, service state). `ops vm-lab-status` + `vm-lab-collect-artifacts`.".into(),
                input_schema: json_schema_object(
                    json!({"alias": json_schema_string("VM alias")}),
                    vec!["alias"],
                ),
            },
            Tool {
                name: "seed_cargo_cache".into(),
                description: "Keep the UTM guests' OFFLINE cargo registry in sync with the workspace Cargo.lock. When the lock changes (a dep added/bumped), a guest's `cargo build --offline` fails with `error: no matching package` / `failed to download from https://index.crates.io/...` because its registry is stale. This parses the lock for crates.io packages, ensures the HOST has each one (runs `cargo fetch --locked` if not), then per node detects which crates' `.crate` blob + sparse-index entry are missing on the guest, tar+scp's ONLY the missing files into the guest's registry root (Unix `$HOME/.cargo/registry`, Windows `C:\\CargoHome\\registry` via PowerShell bsdtar), and re-probes to verify 0 remain missing. Returns PASS/FAIL per node (missing_before/seeded/missing_after) + any host-missing crates. dry_run probes without shipping. Run this after a Cargo.lock change before a live-lab run.".into(),
                input_schema: json_schema_object(
                    json!({
                        "nodes": json_schema_array_string("Inventory aliases to seed (default: all execution guests in the inventory)"),
                        "cargo_lock_path": json_schema_string("Path to the Cargo.lock to read (default: <repo_root>/Cargo.lock)"),
                        "dry_run": json_schema_boolean("Probe + report missing counts only; ship nothing (default: false)"),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "diagnose_live_lab_failure".into(),
                description: "Deep SSH-into-nodes triage of a failed run. `ops vm-lab-diagnose-live-lab-failure`. Only report_dir is required — profile is auto-resolved from the run's matrix row (bash setup runs generate one internally); pass profile only to override. For a profile-less Rust --node run, diagnoses directly from the report-dir evidence artifacts (orchestrate_result.json + stages.tsv + failure_digest.json) and returns a useful failure summary with log pointers — no SSH needed. Fail-closed: errors on a report dir with no diagnosable evidence.".into(),
                input_schema: json_schema_object(
                    json!({
                        "report_dir": json_schema_string("Report directory of the failed run (from start_live_lab_run / get_job_status)"),
                        "profile": json_schema_string("Optional: profile env file; auto-resolved from the report dir if omitted"),
                        "stage": json_schema_string("Optional stage to focus on"),
                        "collect_artifacts": json_schema_boolean("Collect per-VM artifacts (default: false)"),
                    }),
                    vec!["report_dir"],
                ),
            },
            // ── Async live-lab jobs ──
            Tool {
                name: "start_live_lab_run".into(),
                description: "Launch a live-lab run as a DETACHED background job and return immediately with a job_id (does NOT block). mode=orchestrate (one-shot discover→setup→run→diagnose, all 3 OS), run (against an existing profile), or setup. Poll with get_job_status; results via get_run_result. Survives an MCP-server reload. Use dry_run to validate quickly. FAST RE-VERIFY after a per-node code patch: pass nodes=[topology] + rebuild_nodes=[patched node] + skip_soak — redeploys only that node (others keep state) instead of a full multi-node rebuild. (No mid-stage resume; see explain_stage.) ENGINE ROUTING: `nodes=[\"alias:role\", ...]` is the ONLY thing that drives the Rust `--node` engine — dry_run's own log line confirms it with \"rust --node: N node(s), M planned stage(s)\". The `*_platform` role-election selectors below (exit_platform/relay_platform/anchor_platform/admin_platform/blind_exit_platform/macos_promote_exit) are mutually exclusive with `nodes` and currently route through the LEGACY BASH orchestrator instead — real stage names in the resulting logs look like `bootstrap_macos_host.log` / `validate_windows_key_custody.log`, not Rust `StageId`s. If you're verifying the Rust engine specifically (not just the underlying daemon subcommand), use `nodes` with an explicit role per alias, not a `*_platform` selector.".into(),
                input_schema: json_schema_object(
                    json!({
                        "mode": json_schema_string("orchestrate | run | setup (default: orchestrate)"),
                        "report_dir": json_schema_string("Optional report dir (default: a fresh state/live-lab-<job_id>)"),
                        "auto_topology": json_schema_boolean("orchestrate: if true (default) and windows_vm/macos_vm are not given, auto-fill them from the inventory so the run covers all 3 OSes. Set false for Linux-only."),
                        "windows_vm": json_schema_string("orchestrate: Windows VM alias (overrides auto_topology)"),
                        "macos_vm": json_schema_string("orchestrate: macOS VM alias (overrides auto_topology)"),
                        "nodes": json_schema_array_string("orchestrate: role assignments 'alias:role'"),
                        "rebuild_nodes": json_schema_array_string("orchestrate: redeploy code to ONLY these node aliases (others keep their daemon+state); the fast re-verify after a per-node code patch. Requires nodes to be set. Pair with skip_soak."),
                        "profile": json_schema_string("run: profile env file (required for mode=run)"),
                        "profile_output": json_schema_string("setup: where to write the generated profile"),
                        "resume_from": json_schema_string("setup: resume a FAILED setup from this setup-stage (preflight..validate_baseline_runtime) reusing the same report_dir. For a code patch use 'prepare_source_archive' (later = stale code)."),
                        "rerun_stage": json_schema_string("setup: run exactly one setup stage (same names as resume_from)."),
                        "source_mode": json_schema_string("working-tree (default — deploys your uncommitted patch) | local-head | commit-ref | repo-url"),
                        "timeout_secs": json!({"type": "integer", "description": "Per-run hard cap in seconds (CLI default 86400 = 24h). Raise for a >24h soak."}),
                        "dry_run": json_schema_boolean("Plan only (default: false)"),
                        "stop_after_ready": json_schema_boolean("orchestrate: stop once VMs are ready"),
                        "trust_inventory_ready": json_schema_boolean("orchestrate: SKIP the pre-run restart-unready gate and go straight to bootstrap. The readiness gate uses a raw TCP :22 probe that can be BLIND in this sandboxed context (probes 0 ports open) even though the bootstrap `ssh` binary reaches the nodes fine — without this flag a blind probe reboots every healthy VM and aborts. Set this when you have separately confirmed the VMs are up + SSH-reachable (e.g. preflight_check / check_vm_reachable). Bootstrap SSH then fails loudly if a node is truly unreachable. Off by default."),
                        "skip_setup": json_schema_boolean("run: skip setup stages"),
                        "skip_gates": json_schema_boolean("Skip gate stages"),
                        "skip_soak": json_schema_boolean("Skip soak stages"),
                        "skip_cross_network": json_schema_boolean("Skip cross-network stages"),
                        "network_profile": json_schema_string("Network profile id (profiles/vm_lab/network/). Verify-only: recorded immutably at launch; an EXPLICIT id stops the run before deployment when the fleet does not satisfy it. Omitted = derived management-plane default (recorded, not blocking). This tool never mutates attachments — use prepare_lab_network."),
                        "exit_platform": json_schema_string("orchestrate: ELECT this OS (linux|macos|windows) into the EXIT role so the focused mac/win exit cell runs live instead of skipping. Routes through the LEGACY BASH orchestrator, NOT the Rust --node engine (mutually exclusive with `nodes`) — use `nodes=[\"alias:exit\", ...]` instead to test the Rust engine."),
                        "relay_platform": json_schema_string("orchestrate: ELECT this OS (linux|macos|windows) into the RELAY role. Routes through the LEGACY BASH orchestrator, NOT the Rust --node engine (mutually exclusive with `nodes`) — use `nodes=[\"alias:relay\", ...]` instead to test the Rust engine."),
                        "anchor_platform": json_schema_string("orchestrate: ELECT this OS (linux|macos|windows) into the ANCHOR role. Routes through the LEGACY BASH orchestrator, NOT the Rust --node engine (mutually exclusive with `nodes`) — use `nodes=[\"alias:anchor\", ...]` instead to test the Rust engine."),
                        "admin_platform": json_schema_string("orchestrate: ELECT this OS (linux|macos|windows) into the ADMIN role. Routes through the LEGACY BASH orchestrator, NOT the Rust --node engine (mutually exclusive with `nodes`) — use `nodes=[\"alias:admin\", ...]` instead to test the Rust engine."),
                        "blind_exit_platform": json_schema_string("orchestrate: ELECT this OS (linux|macos) into the BLIND_EXIT role (irreversible; Windows unsupported by design). Routes through the LEGACY BASH orchestrator, NOT the Rust --node engine (mutually exclusive with `nodes`) — use `nodes=[\"alias:blind_exit\", ...]` instead to test the Rust engine."),
                        "macos_promote_exit": json_schema_boolean("orchestrate: Option-B macOS secondary-exit selector — promote the macOS node to an active exit. Routes through the LEGACY BASH orchestrator, NOT the Rust --node engine."),
                        "skip_linux_live_suite": json_schema_boolean("orchestrate: skip the ~30-45 min Linux live-validation suite and jump to the mac/win role stages after setup. Pair with a role-platform selector to drive ONE mac/win cell fast."),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "what_will_deploy".into(),
                description: "Preview exactly what the next run ships to the VMs for a source_mode (default working-tree): tracked changes vs HEAD that WILL deploy, and untracked files that will NOT (crates/ ones flagged as stale-code hazards). Run before start_live_lab_run so a patch that adds a new file isn't silently left behind. Read-only.".into(),
                input_schema: json_schema_object(
                    json!({"source_mode": json_schema_string("working-tree (default) | local-head | origin-main | commit-ref | repo-url")}),
                    vec![],
                ),
            },
            Tool {
                name: "get_job_status".into(),
                description: "Poll a background live-lab job: state (running/passed/failed/ended), overall_result, first_failed_stage, report_dir, log path. Fast, non-blocking.".into(),
                input_schema: json_schema_object(
                    json!({"job_id": json_schema_string("Job id from start_live_lab_run")}),
                    vec!["job_id"],
                ),
            },
            Tool {
                name: "get_run_progress".into(),
                description: "Live mid-run progress for a RUNNING job (the gap between start and finish): elapsed, last-activity age with a possible-hang flag (no log output >10m), best-effort current stage, the latest log lines, and how many report artifacts exist so far. Use it between wait_for_job calls to tell 'progressing' from 'hung' without scrolling the whole log. (stages.tsv isn't written until the run ends, so this reads the streaming log + report-dir mtimes.) Pass a job_id (or report_dir for artifacts only).".into(),
                input_schema: json_schema_object(
                    json!({
                        "job_id": json_schema_string("Job id from start_live_lab_run"),
                        "report_dir": json_schema_string("Report dir (alternative; artifacts only, no log/elapsed)"),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "wait_for_job".into(),
                description: "Block until a live-lab job finishes OR up to timeout_secs (default 240, max 270 — kept under client/cache limits), then return its status. Returns the instant the job ends, so you can call this in a loop instead of busy-polling get_job_status. If it returns state=running, the job is still going — call again.".into(),
                input_schema: json_schema_object(
                    json!({
                        "job_id": json_schema_string("Job id from start_live_lab_run"),
                        "timeout_secs": json!({"type": "integer", "description": "Max seconds to block (default 240, clamped to 10..270)"}),
                    }),
                    vec!["job_id"],
                ),
            },
            Tool {
                name: "list_jobs".into(),
                description: "List all live-lab background jobs this server knows about, with their current state and report dir.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "tail_job_log".into(),
                description: "Return the tail of a background job's combined stdout/stderr log, for live progress.".into(),
                input_schema: json_schema_object(
                    json!({
                        "job_id": json_schema_string("Job id"),
                        "lines": json!({"type": "integer", "description": "Lines to return (default: 100)"}),
                    }),
                    vec!["job_id"],
                ),
            },
            Tool {
                name: "cancel_job".into(),
                description: "Kill a running background live-lab job.".into(),
                input_schema: json_schema_object(
                    json!({"job_id": json_schema_string("Job id")}),
                    vec!["job_id"],
                ),
            },
            Tool {
                name: "get_run_result".into(),
                description: "Structured result of a finished run: run_complete/run_passed, overall_result, first_failed_stage, per-OS/per-stage pass/fail summary, cross-OS failures, failure digest (stage/reason/message), git commit + dirty state. Pass a job_id OR a report_dir.".into(),
                input_schema: json_schema_object(
                    json!({
                        "job_id": json_schema_string("Job id (resolves its report dir)"),
                        "report_dir": json_schema_string("Report dir (alternative to job_id)"),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "explain_stage".into(),
                description: "Explain a live-lab stage (the value in first_failed_stage) — what it checks, the owning file/crate, and the most common failure causes. Use right after get_run_result to turn a failed stage into a concrete patch target.".into(),
                input_schema: json_schema_object(
                    json!({"stage": json_schema_string("Stage name, e.g. 'validate_baseline_runtime', 'bootstrap_hosts', 'anchor', 'role_switch_matrix' (linux_/macos_/windows_stage_ prefixes are stripped)")}),
                    vec!["stage"],
                ),
            },
            Tool {
                name: "list_report_artifacts".into(),
                description: "List the files in a run's report directory (relative paths + sizes), so you can pick logs to read. Pass a job_id OR a report_dir.".into(),
                input_schema: json_schema_object(
                    json!({
                        "job_id": json_schema_string("Job id"),
                        "report_dir": json_schema_string("Report dir (alternative to job_id)"),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "read_report_artifact".into(),
                description: "Read one file from a run's report directory (path-confined to a repo-local report dir). Pass a job_id OR report_dir, plus the relative path.".into(),
                input_schema: json_schema_object(
                    json!({
                        "job_id": json_schema_string("Job id"),
                        "report_dir": json_schema_string("Report dir (alternative to job_id)"),
                        "path": json_schema_string("Path relative to the report dir, e.g. 'state/report_state.json'"),
                    }),
                    vec!["path"],
                ),
            },
            Tool {
                name: "grep_report".into(),
                description: "Case-insensitive substring search across every text file in a run's report directory → `path:line — matching text`. Fast way to find an error string, panic, peer id, or stage marker without reading whole logs. Pass a job_id OR a report_dir, plus a pattern. Binary/archive files are skipped; results capped (max_matches, default 100).".into(),
                input_schema: json_schema_object(
                    json!({
                        "job_id": json_schema_string("Job id"),
                        "report_dir": json_schema_string("Report dir (alternative to job_id)"),
                        "pattern": json_schema_string("Substring to search for (case-insensitive)"),
                        "max_matches": json!({"type": "integer", "description": "Cap on matches returned (default 100, max 1000)"}),
                    }),
                    vec!["pattern"],
                ),
            },
            Tool {
                name: "get_stage_log".into(),
                description: "Jump straight to one stage's evidence: its row(s) in state/stages.tsv (status, rc, description) plus the tail of that stage's log file. The fast path after explain_stage(first_failed_stage) — go from a failed stage name to its actual log without browsing artifacts. Pass a job_id OR report_dir, plus the stage (linux_/macos_/windows_stage_ prefixes are stripped).".into(),
                input_schema: json_schema_object(
                    json!({
                        "job_id": json_schema_string("Job id"),
                        "report_dir": json_schema_string("Report dir (alternative to job_id)"),
                        "stage": json_schema_string("Stage name, e.g. 'anchor', 'role_switch_matrix', 'validate_baseline_runtime'"),
                    }),
                    vec!["stage"],
                ),
            },
            Tool {
                name: "get_run_matrix".into(),
                description: "Read the live-lab run matrix (CSV evidence ledger) — recent runs with OS/role/stage coverage and pass/fail.".into(),
                input_schema: json_schema_object(
                    json!({"limit": json!({"type": "integer", "description": "Recent rows (default: 20)"})}),
                    vec![],
                ),
            },
            Tool {
                name: "get_run_trend".into(),
                description: "Trend across the last N matrix rows: a one-line verdict (GREEN — stable / JUST GREEN / STUCK at <stage> / MOVING) plus a compact run_id/commit/result/first_failed_stage table. Use it to decide whether the loop is converging — 'STUCK at X' means keep patching that stage; 'MOVING' means each fix advanced the run; two greens means done. Cheaper than get_run_matrix for loop control.".into(),
                input_schema: json_schema_object(
                    json!({"limit": json!({"type": "integer", "description": "Recent rows to analyze (default: 10, max 200)"})}),
                    vec![],
                ),
            },
            Tool {
                name: "find_untested_work".into(),
                description: "Coverage-driven WORK FINDER: aggregates every per-OS-stage and cross-OS cell DOWN the whole run-matrix history → a prioritized queue of what still needs proving green: 🔴 REGRESSED (passed before, latest fail), 🟠 NEVER-PASSED (only ever failed), ⚪ NEVER-RUN (untested; some unsupported-by-design), 🟡 STALE-GREEN (passed only in old runs). Hands the agent a target instead of making it hunt. Filter by os (linux|macos|windows|cross); include_green lists currently-green cells. Pair with explain_stage + get_platform_support.".into(),
                input_schema: json_schema_object(
                    json!({
                        "os": json_schema_string("Filter to one OS: linux | macos | windows | cross (cross-OS scenarios)"),
                        "include_green": json_schema_boolean("Also list currently-green cells (default: false)"),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "diff_runs".into(),
                description: "Diff two runs' per-stage outcomes — which stages flipped pass↔fail/rc and the first divergent stage — so you can tell whether a patch HELPED or REGRESSED. Pass old + new as report dirs or job_ids (old_report_dir|old_job_id, new_report_dir|new_job_id). Both runs need state/stages.tsv. The direct answer after a re-verify run.".into(),
                input_schema: json_schema_object(
                    json!({
                        "old_job_id": json_schema_string("Baseline run's job_id"),
                        "old_report_dir": json_schema_string("Baseline run's report dir (alternative)"),
                        "new_job_id": json_schema_string("New run's job_id"),
                        "new_report_dir": json_schema_string("New run's report dir (alternative)"),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "host_disk_status".into(),
                description: "Disk free space + biggest consumers. WITHOUT host: THIS machine's disk + the local lab consumers (state/, target-livelab/, target/) — reclaim with prune_jobs. WITH host: a REMOTE lab host's image pool over SSH — filesystem headroom plus the base images and per-guest qcow2 overlays that accrue there (e.g. \"how much room is left on the 870, and what is eating it?\"). Check periodically over a long run — a full disk fails builds/runs.".into(),
                input_schema: json_schema_object(
                    json!({
                        "host": {"type": "string", "description": "host_id of a REMOTE host from hosts[]. Omit to report THIS machine."},
                        "pool": {"type": "string", "description": "Image pool path on the remote host. Default /var/lib/libvirt/images. Only meaningful with host."},
                        "inventory": {"type": "string", "description": "Inventory path (repo-relative). Default: the lab inventory."},
                        "ssh_identity_file": {"type": "string"}
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "prune_jobs".into(),
                description: "Reclaim disk from old FINISHED jobs over a long loop: keep the most recent N job records+logs, delete the rest. Running jobs are never touched. Set delete_report_dirs to also remove their report directories (lab evidence) — off by default.".into(),
                input_schema: json_schema_object(
                    json!({
                        "keep": json!({"type": "integer", "description": "How many most-recent jobs to keep (default: 10)"}),
                        "delete_report_dirs": json_schema_boolean("Also delete each pruned job's report dir (default: false)"),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "write_loop_note".into(),
                description: "Append one note to the durable loop journal (state/mcp-loop-journal.jsonl) — the agent's own memory across context compaction over a 24h+ run. Record each iteration's hypothesis, the patch you made, and the result, so after a compaction you don't repeat a fix you already tried. Pair with get_loop_journal.".into(),
                input_schema: json_schema_object(
                    json!({
                        "note": json_schema_string("What you're recording (hypothesis / patch / result / blocker)"),
                        "iteration": json!({"type": "integer", "description": "Loop iteration number (optional)"}),
                        "status": json_schema_string("Optional tag, e.g. trying | failed | fixed | blocked | green"),
                    }),
                    vec!["note"],
                ),
            },
            Tool {
                name: "stage_triage_history".into(),
                description: "Every fix already ATTEMPTED against a failing live-lab stage, oldest first — read this BEFORE debugging a stage failure so you do not re-derive or repeat a patch someone already tried. Pass stage (e.g. live_two_hop_validation) and optionally os (debian/rocky/ubuntu/fedora/macos/windows). Each entry pairs the run's verbatim error with the patch that was tried against it. There is deliberately no outcome field: a patch that worked turns the stage green in the next run, and one that did not opens a NEW stub against a NEW commit — so read the chain. Because the patch is recorded before the verification run, the ledger row's own commit IS the patch commit (git log the ledger). `--node` engine only: the legacy bash archive uses a different stage vocabulary, so its results are not evidence here.".into(),
                input_schema: json_schema_object(
                    json!({
                        "stage": json_schema_string("Stage name, e.g. live_two_hop_validation"),
                        "os": json_schema_string("Optional OS family filter: debian|rocky|ubuntu|fedora|macos|windows"),
                    }),
                    vec!["stage"],
                ),
            },
            Tool {
                name: "get_loop_journal".into(),
                description: "Read back the loop journal (last N notes, default 30) — what past iterations tried and concluded. Call this after a context compaction, or at the start of an iteration, to recover continuity instead of repeating work.".into(),
                input_schema: json_schema_object(
                    json!({"limit": json!({"type": "integer", "description": "Most-recent notes to show (default 30, max 500)"})}),
                    vec![],
                ),
            },
        ]
    }

    fn call_tool(&self, name: &str, arguments: Option<Value>) -> ToolCallResult {
        let args = arguments.as_ref();
        match name {
            "get_lab_status" => self.run_ops(
                "vm-lab-discover-local-utm-summary",
                &[],
                DISCOVERY_TIMEOUT_SECS,
            ),

            "get_lab_status_json" => {
                let mut extra: Vec<&str> = vec!["--json"];
                let report_dir_owned;
                if let Some(dir) = arg_str(args, "report_dir") {
                    report_dir_owned = match self.ensure_report_dir(dir) {
                        Ok(dir) => dir,
                        Err(e) => return tool_error(&e),
                    };
                    extra.push("--report-dir");
                    extra.push(&report_dir_owned);
                }
                self.run_ops("vm-lab-discover-local-utm", &extra, DISCOVERY_TIMEOUT_SECS)
            }

            // ---- multi-host lab (LinuxVmHostPlan §6.7) --------------------
            "host_preflight" => {
                let mut extra: Vec<&str> = Vec::new();
                let commit_owned;
                if let Some(commit) = arg_str(args, "commit") {
                    commit_owned = commit.to_owned();
                    extra.push("--commit");
                    extra.push(&commit_owned);
                }
                let hosts_owned;
                if let Some(hosts) = arg_str(args, "hosts") {
                    hosts_owned = hosts.to_owned();
                    extra.push("--hosts");
                    extra.push(&hosts_owned);
                }
                if arg_bool(args, "allow_dirty") {
                    extra.push("--allow-dirty");
                }
                let identity_owned;
                if let Some(identity) = arg_str(args, "ssh_identity_file") {
                    identity_owned = identity.to_owned();
                    extra.push("--ssh-identity-file");
                    extra.push(&identity_owned);
                }
                match self.arg_inventory(args) {
                    Ok(inventory) => self.run_ops_with_inventory(
                        "vm-lab-host-preflight",
                        inventory.as_deref(),
                        &extra,
                        DISCOVERY_TIMEOUT_SECS,
                    ),
                    Err(err) => tool_error(&err),
                }
            }

            "sync_host" => {
                let all = arg_bool(args, "all");
                let mut extra: Vec<&str> = Vec::new();
                match (arg_str(args, "host"), all) {
                    (Some(_), true) => {
                        return tool_error("sync_host: `all` and `host` are mutually exclusive");
                    }
                    (Some(host), false) => {
                        extra.push("--host");
                        extra.push(host);
                    }
                    (None, true) => extra.push("--all"),
                    (None, false) => {
                        return tool_error(
                            "sync_host requires `host` (a host_id from hosts[]) or `all: true`",
                        );
                    }
                }
                let commit_owned;
                if let Some(commit) = arg_str(args, "commit") {
                    commit_owned = commit.to_owned();
                    extra.push("--commit");
                    extra.push(&commit_owned);
                }
                if arg_bool(args, "verify_only") {
                    extra.push("--verify-only");
                }
                if arg_bool(args, "allow_dirty") {
                    extra.push("--allow-dirty");
                }
                let identity_owned;
                if let Some(identity) = arg_str(args, "ssh_identity_file") {
                    identity_owned = identity.to_owned();
                    extra.push("--ssh-identity-file");
                    extra.push(&identity_owned);
                }
                match self.arg_inventory(args) {
                    Ok(inventory) => self.run_ops_with_inventory(
                        "vm-lab-sync-host",
                        inventory.as_deref(),
                        &extra,
                        DISCOVERY_TIMEOUT_SECS,
                    ),
                    Err(err) => tool_error(&err),
                }
            }

            "host_net_status" => {
                let mut extra: Vec<&str> = Vec::new();
                let host_owned;
                if let Some(host) = arg_str(args, "host") {
                    host_owned = host.to_owned();
                    extra.push("--host");
                    extra.push(&host_owned);
                }
                let format_owned;
                if let Some(format) = arg_str(args, "format") {
                    if !matches!(format, "table" | "json") {
                        return tool_error("format must be `table` or `json`");
                    }
                    format_owned = format.to_owned();
                    extra.push("--format");
                    extra.push(&format_owned);
                }
                let identity_owned;
                if let Some(identity) = arg_str(args, "ssh_identity_file") {
                    identity_owned = identity.to_owned();
                    extra.push("--ssh-identity-file");
                    extra.push(&identity_owned);
                }
                match self.arg_inventory(args) {
                    Ok(inventory) => self.run_ops_with_inventory(
                        "vm-lab-host-net-status",
                        inventory.as_deref(),
                        &extra,
                        DISCOVERY_TIMEOUT_SECS,
                    ),
                    Err(err) => tool_error(&err),
                }
            }

            "host_run_status" => {
                let Some(host) = arg_str(args, "host") else {
                    return tool_error("host_run_status requires `host` (a remote host_id)");
                };
                let mut extra: Vec<&str> = vec!["--host", host];
                let run_owned;
                if let Some(run) = arg_str(args, "run_id") {
                    run_owned = run.to_owned();
                    extra.push("--run-id");
                    extra.push(&run_owned);
                }
                let stage_owned;
                if let Some(stage) = arg_str(args, "stage") {
                    stage_owned = stage.to_owned();
                    extra.push("--stage");
                    extra.push(&stage_owned);
                }
                let format_owned;
                if let Some(format) = arg_str(args, "format") {
                    if !matches!(format, "table" | "json") {
                        return tool_error("format must be `table` or `json`");
                    }
                    format_owned = format.to_owned();
                    extra.push("--format");
                    extra.push(&format_owned);
                }
                let identity_owned;
                if let Some(identity) = arg_str(args, "ssh_identity_file") {
                    identity_owned = identity.to_owned();
                    extra.push("--ssh-identity-file");
                    extra.push(&identity_owned);
                }
                match self.arg_inventory(args) {
                    Ok(inventory) => self.run_ops_with_inventory(
                        "vm-lab-host-run-status",
                        inventory.as_deref(),
                        &extra,
                        DISCOVERY_TIMEOUT_SECS,
                    ),
                    Err(err) => tool_error(&err),
                }
            }

            "launch_live_lab_on_host" => {
                let Some(host) = arg_str(args, "host") else {
                    return tool_error("launch_live_lab_on_host requires `host`");
                };
                let Some(report_dir) = arg_str(args, "report_dir") else {
                    return tool_error("launch_live_lab_on_host requires `report_dir`");
                };
                let mut extra: Vec<&str> = vec!["--host", host, "--report-dir", report_dir];
                let identity_owned;
                if let Some(identity) = arg_str(args, "host_ssh_identity") {
                    identity_owned = identity.to_owned();
                    extra.push("--host-ssh-identity");
                    extra.push(&identity_owned);
                }
                let ssh_owned;
                if let Some(ssh) = arg_str(args, "ssh_identity_file") {
                    ssh_owned = ssh.to_owned();
                    extra.push("--ssh-identity-file");
                    extra.push(&ssh_owned);
                }
                if args
                    .and_then(|v| v.get("dry_run"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    extra.push("--dry-run");
                }
                let format_owned;
                if let Some(format) = arg_str(args, "format") {
                    format_owned = format.to_owned();
                    extra.push("--format");
                    extra.push(&format_owned);
                }
                // The `--` separator and the forwarded orchestrator args go LAST,
                // so everything after `--` reaches the orchestrator, not the launch
                // parser. Own the strings first, then borrow.
                let orch_owned: Vec<String> = args
                    .and_then(|v| v.get("orchestrator_args"))
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|v| v.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default();
                extra.push("--");
                extra.extend(orch_owned.iter().map(String::as_str));

                // Launch returns in ~2s; give SSH generous headroom but nowhere near
                // the run's own length — this call does not wait for the run.
                match self.arg_inventory(args) {
                    Ok(inventory) => self.run_ops_with_inventory(
                        "vm-lab-launch-on-host",
                        inventory.as_deref(),
                        &extra,
                        120,
                    ),
                    Err(err) => tool_error(&err),
                }
            }

            "fetch_host_artifact" => {
                let Some(host) = arg_str(args, "host") else {
                    return tool_error("fetch_host_artifact requires `host`");
                };
                let Some(path) = arg_str(args, "path") else {
                    return tool_error(
                        "fetch_host_artifact requires `path` (relative to repo_dir)",
                    );
                };
                let mut extra: Vec<&str> = vec!["--host", host, "--path", path];
                let max_owned;
                if let Some(max) = args
                    .and_then(|v| v.get("max_bytes"))
                    .and_then(Value::as_u64)
                {
                    max_owned = max.to_string();
                    extra.push("--max-bytes");
                    extra.push(&max_owned);
                }
                let ssh_owned;
                if let Some(ssh) = arg_str(args, "ssh_identity_file") {
                    ssh_owned = ssh.to_owned();
                    extra.push("--ssh-identity-file");
                    extra.push(&ssh_owned);
                }
                match self.arg_inventory(args) {
                    Ok(inventory) => self.run_ops_with_inventory(
                        "vm-lab-fetch-host-artifact",
                        inventory.as_deref(),
                        &extra,
                        DISCOVERY_TIMEOUT_SECS,
                    ),
                    Err(err) => tool_error(&err),
                }
            }

            "stop_host_run" => {
                let Some(host) = arg_str(args, "host") else {
                    return tool_error("stop_host_run requires `host`");
                };
                let mut extra: Vec<&str> = vec!["--host", host];
                let ssh_owned;
                if let Some(ssh) = arg_str(args, "ssh_identity_file") {
                    ssh_owned = ssh.to_owned();
                    extra.push("--ssh-identity-file");
                    extra.push(&ssh_owned);
                }
                let format_owned;
                if let Some(format) = arg_str(args, "format") {
                    format_owned = format.to_owned();
                    extra.push("--format");
                    extra.push(&format_owned);
                }
                match self.arg_inventory(args) {
                    Ok(inventory) => self.run_ops_with_inventory(
                        "vm-lab-stop-host-run",
                        inventory.as_deref(),
                        &extra,
                        90,
                    ),
                    Err(err) => tool_error(&err),
                }
            }

            "compare_runs_at_commit" => {
                let mut extra: Vec<&str> = Vec::new();
                let commit_owned;
                if let Some(commit) = arg_str(args, "commit") {
                    commit_owned = commit.to_owned();
                    extra.push("--commit");
                    extra.push(&commit_owned);
                }
                let expect_owned;
                if let Some(n) = args
                    .and_then(|a| a.get("expect_runs"))
                    .and_then(|v| v.as_u64())
                {
                    expect_owned = n.to_string();
                    extra.push("--expect-runs");
                    extra.push(&expect_owned);
                }
                if arg_bool(args, "allow_dirty") {
                    extra.push("--allow-dirty");
                }
                let stage_owned;
                if let Some(stage) = arg_str(args, "stage") {
                    stage_owned = stage.to_owned();
                    extra.push("--stage");
                    extra.push(&stage_owned);
                }
                let include_owned;
                if let Some(hosts) = arg_str(args, "include_hosts") {
                    include_owned = hosts.to_owned();
                    extra.push("--include-hosts");
                    extra.push(&include_owned);
                }
                let format_owned;
                if let Some(format) = arg_str(args, "format") {
                    if !matches!(format, "table" | "json") {
                        return tool_error("format must be `table` or `json`");
                    }
                    format_owned = format.to_owned();
                    extra.push("--format");
                    extra.push(&format_owned);
                }
                match self.arg_inventory(args) {
                    Ok(inventory) => self.run_ops_with_inventory(
                        "vm-lab-run-matrix-compare",
                        inventory.as_deref(),
                        &extra,
                        DISCOVERY_TIMEOUT_SECS,
                    ),
                    Err(err) => tool_error(&err),
                }
            }

            "provision_guest" => {
                let Some(host) = arg_str(args, "host") else {
                    return tool_error("provision_guest requires `host` (a libvirt host_id)");
                };
                let Some(name) = arg_str(args, "name") else {
                    return tool_error("provision_guest requires `name`");
                };
                let Some(image) = arg_str(args, "image") else {
                    return tool_error(
                        "provision_guest requires `image` (a base image filename in the host's pool)",
                    );
                };
                let mut extra: Vec<&str> = vec!["--host", host, "--name", name, "--image", image];
                let ram_owned;
                if let Some(ram) = args.and_then(|a| a.get("ram_mb")).and_then(|v| v.as_u64()) {
                    ram_owned = ram.to_string();
                    extra.push("--ram-mb");
                    extra.push(&ram_owned);
                }
                let vcpus_owned;
                if let Some(vcpus) = args.and_then(|a| a.get("vcpus")).and_then(|v| v.as_u64()) {
                    vcpus_owned = vcpus.to_string();
                    extra.push("--vcpus");
                    extra.push(&vcpus_owned);
                }
                let disk_owned;
                if let Some(disk) = args.and_then(|a| a.get("disk_gb")).and_then(|v| v.as_u64()) {
                    disk_owned = disk.to_string();
                    extra.push("--disk-gb");
                    extra.push(&disk_owned);
                }
                let pool_owned;
                if let Some(pool) = arg_str(args, "pool") {
                    pool_owned = pool.to_owned();
                    extra.push("--pool");
                    extra.push(&pool_owned);
                }
                let key_owned;
                if let Some(key) = arg_str(args, "authorized_key") {
                    key_owned = key.to_owned();
                    extra.push("--authorized-key");
                    extra.push(&key_owned);
                }
                if arg_bool(args, "dry_run") {
                    extra.push("--dry-run");
                }
                let identity_owned;
                if let Some(identity) = arg_str(args, "ssh_identity_file") {
                    identity_owned = identity.to_owned();
                    extra.push("--ssh-identity-file");
                    extra.push(&identity_owned);
                }
                match self.arg_inventory(args) {
                    Ok(inventory) => self.run_ops_with_inventory(
                        "vm-lab-provision-guest",
                        inventory.as_deref(),
                        &extra,
                        DISCOVERY_TIMEOUT_SECS,
                    ),
                    Err(err) => tool_error(&err),
                }
            }

            "discover_hosts" => {
                let mut extra: Vec<&str> = Vec::new();
                let host_owned;
                if let Some(host) = arg_str(args, "host") {
                    host_owned = host.to_owned();
                    extra.push("--host");
                    extra.push(&host_owned);
                }
                let format_owned;
                if let Some(format) = arg_str(args, "format") {
                    if !matches!(format, "table" | "json") {
                        return tool_error("format must be `table` or `json`");
                    }
                    format_owned = format.to_owned();
                    extra.push("--format");
                    extra.push(&format_owned);
                }
                match self.arg_inventory(args) {
                    Ok(inventory) => self.run_ops_with_inventory(
                        "vm-lab-discover-hosts",
                        inventory.as_deref(),
                        &extra,
                        DISCOVERY_TIMEOUT_SECS,
                    ),
                    Err(err) => tool_error(&err),
                }
            }

            "get_lab_topology" => self.get_lab_topology(),

            "get_inventory" => {
                let inv_path = self.repo_root.join(DEFAULT_INVENTORY);
                match std::fs::read_to_string(&inv_path) {
                    Ok(content) => {
                        if let Ok(mut parsed) = serde_json::from_str::<Value>(&content) {
                            redact_secret_fields(&mut parsed);
                            let pretty = serde_json::to_string_pretty(&parsed).unwrap_or(content);
                            tool_success(&format!("# VM Lab Inventory\n\n```json\n{pretty}\n```\n"))
                        } else {
                            tool_error(
                                "Invalid inventory JSON; refusing to echo unredacted content",
                            )
                        }
                    }
                    Err(e) => tool_error(&format!("Cannot read inventory: {e}")),
                }
            }

            "validate_inventory" => {
                let inv_path = self.repo_root.join(DEFAULT_INVENTORY);
                if !inv_path.exists() {
                    return tool_error(&format!("Inventory file not found: {DEFAULT_INVENTORY}"));
                }
                let inv_content = match std::fs::read_to_string(&inv_path) {
                    Ok(c) => c,
                    Err(e) => return tool_error(&format!("Cannot read inventory: {e}")),
                };
                let inv: Value = match serde_json::from_str(&inv_content) {
                    Ok(v) => v,
                    Err(e) => return tool_error(&format!("Invalid inventory JSON: {e}")),
                };
                let entries = inv.get("entries").and_then(|e| e.as_array());
                let mut result = format!(
                    "# Inventory Validation\n\n**Inventory entries:** {}\n\n## Live Discovery\n\n",
                    entries.map_or(0, |e| e.len())
                );
                let discovery = self.run_ops(
                    "vm-lab-discover-local-utm",
                    &["--json"],
                    DISCOVERY_TIMEOUT_SECS,
                );
                result.push_str(
                    &discovery
                        .content
                        .first()
                        .map(|c| c.text.clone())
                        .unwrap_or_default(),
                );
                tool_success(&result)
            }

            "update_inventory" => self.run_ops(
                "vm-lab-discover-local-utm-summary",
                &["--update-inventory-live-ips"],
                DISCOVERY_TIMEOUT_SECS,
            ),

            "restart_vm" => {
                let aliases = string_array(args, "aliases");
                let wait_ready = args
                    .and_then(|a| a.get("wait_ready"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                if aliases.is_empty() {
                    return tool_error("At least one alias is required");
                }
                let ssh_key = default_ssh_identity();
                let kh = default_known_hosts();
                let mut extra: Vec<&str> = Vec::new();
                if aliases.len() == 1 && aliases[0] == "--all" {
                    extra.push("--all");
                } else {
                    for alias in &aliases {
                        extra.push("--vm");
                        extra.push(alias.as_str());
                    }
                }
                if wait_ready {
                    extra.extend([
                        "--wait-ready",
                        "--ssh-identity-file",
                        &ssh_key,
                        "--known-hosts-file",
                        &kh,
                    ]);
                }
                self.run_ops("vm-lab-restart", &extra, 900)
            }

            "power_on_vm" => {
                let aliases = string_array(args, "aliases");
                if aliases.is_empty() {
                    return tool_error("At least one alias (or ['--all']) is required");
                }
                let mut extra: Vec<&str> = Vec::new();
                if aliases.len() == 1 && aliases[0] == "--all" {
                    extra.push("--all");
                } else {
                    for a in &aliases {
                        extra.push("--vm");
                        extra.push(a.as_str());
                    }
                }
                self.run_ops("vm-lab-start", &extra, 300)
            }

            "power_off_vm" => {
                let aliases = string_array(args, "aliases");
                if aliases.is_empty() {
                    return tool_error("At least one alias (or ['--all']) is required");
                }
                let mut extra: Vec<&str> = Vec::new();
                if aliases.len() == 1 && aliases[0] == "--all" {
                    extra.push("--all");
                } else {
                    for a in &aliases {
                        extra.push("--vm");
                        extra.push(a.as_str());
                    }
                }
                if arg_bool(args, "force") {
                    extra.push("--force");
                }
                self.run_ops("vm-lab-stop", &extra, 300)
            }

            "get_vm_power_state" => self.get_vm_power_state(arg_str(args, "alias")),
            "check_vm_reachable" => self.check_vm_reachable(arg_str(args, "alias").unwrap_or("")),
            "reset_vm_network" => self.reset_vm_network(arg_str(args, "alias").unwrap_or("")),
            "get_vm_network_info" => self.get_vm_network_info(arg_str(args, "alias").unwrap_or("")),
            "diagnose_host_lab_network" => self.diagnose_host_lab_network(arg_str(args, "alias")),
            "apply_host_route_fix" => {
                self.apply_host_route_fix(arg_str(args, "alias").unwrap_or(""))
            }
            "set_vm_internet_access" => self.set_vm_internet_access(args),
            "diagnose_vm_lan_presence" => self.diagnose_vm_lan_presence(arg_str(args, "alias")),
            "apply_vm_bridged_network" => {
                self.apply_vm_bridged_network(arg_str(args, "alias").unwrap_or(""))
            }
            "audit_lab_network" => {
                let mut cli: Vec<String> = vec![
                    "ops".into(),
                    "vm-lab-network-audit".into(),
                    "--inventory".into(),
                    DEFAULT_INVENTORY.into(),
                ];
                if let Some(profile) = arg_str(args, "profile").filter(|p| !p.is_empty()) {
                    cli.extend(["--profile".into(), profile.to_string()]);
                }
                let include_guests = arg_bool(args, "include_guests");
                if !include_guests {
                    cli.push("--skip-guests".into());
                }
                let refs: Vec<&str> = cli.iter().map(String::as_str).collect();
                self.run_cli(&refs, "vm-lab-network-audit (read-only)", 300)
            }
            "prepare_lab_network" => {
                let Some(profile) = arg_str(args, "profile").filter(|p| !p.is_empty()) else {
                    return tool_error("Missing required parameter: profile");
                };
                let approve = arg_bool(args, "approve_reconfigure");
                let mut cli: Vec<String> = vec![
                    "ops".into(),
                    "vm-lab-network-prepare".into(),
                    "--inventory".into(),
                    DEFAULT_INVENTORY.into(),
                    "--profile".into(),
                    profile.to_string(),
                ];
                for alias in string_array(args, "aliases") {
                    cli.extend(["--vm".into(), alias]);
                }
                if approve {
                    // The explicit operator authorization boundary — flows 1:1
                    // into the Rust transaction's own --approve-reconfigure.
                    cli.push("--approve-reconfigure".into());
                } else {
                    cli.push("--dry-run".into());
                }
                let refs: Vec<&str> = cli.iter().map(String::as_str).collect();
                self.run_cli(
                    &refs,
                    if approve {
                        "vm-lab-network-prepare (AUTHORIZED transaction)"
                    } else {
                        "vm-lab-network-prepare (dry-run plan; nothing changed)"
                    },
                    1800,
                )
            }
            "restore_lab_network" => {
                let list = arg_bool(args, "list");
                let mut cli: Vec<String> = vec![
                    "ops".into(),
                    "vm-lab-network-restore".into(),
                    "--inventory".into(),
                    DEFAULT_INVENTORY.into(),
                ];
                if list {
                    cli.push("--list".into());
                } else if let Some(txn) = arg_str(args, "transaction_id").filter(|t| !t.is_empty())
                {
                    cli.extend(["--transaction".into(), txn.to_string()]);
                } else {
                    return tool_error(
                        "restore_lab_network requires transaction_id, or list=true to enumerate",
                    );
                }
                let refs: Vec<&str> = cli.iter().map(String::as_str).collect();
                self.run_cli(&refs, "vm-lab-network-restore", 1800)
            }

            "recover_stuck_vms" => {
                // With a host, recover that REMOTE libvirt host's stuck guests via the
                // CLI (destroy+start a running-but-unleased/paused/shut-off guest,
                // skip a healthy one). Without, keep the local UTM probe+recover.
                if let Some(host) = arg_str(args, "host") {
                    let mut extra: Vec<&str> = vec!["--host", host];
                    let domains = string_array(args, "aliases");
                    for d in &domains {
                        extra.push("--vm");
                        extra.push(d.as_str());
                    }
                    if arg_bool(args, "force") {
                        extra.push("--force");
                    }
                    let ssh_owned;
                    if let Some(ssh) = arg_str(args, "ssh_identity_file") {
                        ssh_owned = ssh.to_owned();
                        extra.push("--ssh-identity-file");
                        extra.push(&ssh_owned);
                    }
                    match self.arg_inventory(args) {
                        Ok(inventory) => self.run_ops_with_inventory(
                            "vm-lab-recover-host-vms",
                            inventory.as_deref(),
                            &extra,
                            300,
                        ),
                        Err(err) => tool_error(&err),
                    }
                } else {
                    let aliases = string_array(args, "aliases");
                    let refs: Vec<&str> = aliases.iter().map(|s| s.as_str()).collect();
                    self.run_shell_script(
                        "scripts/vm_lab/probe_and_recover_local_utm.sh",
                        &refs,
                        600,
                    )
                }
            }

            "ensure_lab_ready" => {
                let mut result = String::from("# Ensure Lab Ready\n\n## Step 1: Discover\n\n");
                let discover = self.run_ops(
                    "vm-lab-discover-local-utm-summary",
                    &[],
                    DISCOVERY_TIMEOUT_SECS,
                );
                if let Some(c) = discover.content.first() {
                    result.push_str(&c.text);
                    result.push_str("\n\n");
                }
                result.push_str("## Step 2: Restart + Wait Ready\n\n");
                let ssh_key = default_ssh_identity();
                let kh = default_known_hosts();
                let restart = self.run_ops(
                    "vm-lab-restart",
                    &[
                        "--all",
                        "--wait-ready",
                        "--ssh-identity-file",
                        &ssh_key,
                        "--known-hosts-file",
                        &kh,
                    ],
                    900,
                );
                if let Some(c) = restart.content.first() {
                    result.push_str(&c.text);
                    result.push_str("\n\n");
                }
                result.push_str("## Step 3: Confirm\n\n");
                let confirm = self.run_ops(
                    "vm-lab-discover-local-utm-summary",
                    &[],
                    DISCOVERY_TIMEOUT_SECS,
                );
                if let Some(c) = confirm.content.first() {
                    result.push_str(&c.text);
                }
                // Rulebook §11.2: ensure_lab_ready(profile) preserves and
                // re-verifies the profile after the restart. Verify-only —
                // drift is reported fail-closed, never repaired here.
                if let Some(profile) = arg_str(args, "profile").filter(|p| !p.is_empty()) {
                    result.push_str("\n\n## Step 4: Network profile re-verify (read-only)\n\n");
                    // vm-lab-network-preflight exits nonzero unless the
                    // observed fleet satisfies the profile — the fail-closed
                    // verify the rulebook requires.
                    let verify = self.run_cli(
                        &[
                            "ops",
                            "vm-lab-network-preflight",
                            "--inventory",
                            DEFAULT_INVENTORY,
                            "--profile",
                            profile,
                            "--skip-guests",
                        ],
                        "vm-lab-network-preflight (post-readiness re-verify)",
                        300,
                    );
                    if let Some(c) = verify.content.first() {
                        result.push_str(&c.text);
                    }
                    if verify.is_error.unwrap_or(false) {
                        result.push_str(
                            "\n\n🛑 network profile re-verify FAILED — the lab is ready but does not satisfy the requested profile; do not run evidence stages against it (use prepare_lab_network with explicit operator approval to migrate).",
                        );
                        return tool_error(&result);
                    }
                }
                tool_success(&result)
            }

            "sync_repo_to_vm" => {
                let alias = arg_str(args, "alias").unwrap_or("");
                if alias.is_empty() {
                    return tool_error("Missing required parameter: alias");
                }
                self.run_ops("vm-lab-sync-repo", &["--vm", alias], 900)
            }

            "provision_guest_toolchain" => {
                let aliases = string_array(args, "aliases");
                let select_all = arg_bool(args, "select_all");
                if aliases.is_empty() && !select_all {
                    return tool_error(
                        "Provide `aliases` (e.g. [\"linux-x86-exit-1\"]) or select_all:true",
                    );
                }
                if !aliases.is_empty() && select_all {
                    return tool_error("Pass either `aliases` or select_all, not both");
                }
                let mut extra: Vec<&str> = Vec::new();
                for alias in &aliases {
                    extra.push("--vm");
                    extra.push(alias.as_str());
                }
                if select_all {
                    extra.push("--all");
                }
                if arg_bool(args, "verify_only") {
                    extra.push("--verify-only");
                }
                let identity_owned;
                if let Some(identity) = arg_str(args, "ssh_identity_file") {
                    identity_owned = identity.to_owned();
                    extra.push("--ssh-identity-file");
                    extra.push(&identity_owned);
                }
                let format_owned;
                if let Some(format) = arg_str(args, "format") {
                    if !matches!(format, "table" | "json") {
                        return tool_error("format must be `table` or `json`");
                    }
                    format_owned = format.to_owned();
                    extra.push("--format");
                    extra.push(&format_owned);
                }
                let timeout = args
                    .and_then(|a| a.get("timeout_secs"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1800);
                let timeout_owned = timeout.to_string();
                extra.push("--timeout-secs");
                extra.push(&timeout_owned);
                match self.arg_inventory(args) {
                    Ok(inventory) => self.run_ops_with_inventory(
                        "vm-lab-provision-toolchain",
                        inventory.as_deref(),
                        &extra,
                        timeout + 120,
                    ),
                    Err(err) => tool_error(&err),
                }
            }

            "bootstrap_vm" => {
                let phase = arg_str(args, "phase").unwrap_or("");
                if phase.is_empty() {
                    return tool_error("Missing required parameter: phase");
                }

                // Accept a list, a single legacy alias, or select_all — but exactly
                // one selector. Guessing between an empty `aliases` and a stray
                // `alias` is how a "bootstrap both" call silently does one.
                let mut aliases = string_array(args, "aliases");
                if let Some(single) = arg_str(args, "alias") {
                    if !single.is_empty() {
                        aliases.push(single.to_owned());
                    }
                }
                let select_all = arg_bool(args, "select_all");
                if aliases.is_empty() && !select_all {
                    return tool_error(
                        "Provide `aliases` (e.g. [\"linux-x86-exit-1\",\"linux-x86-client-1\"]), \
                         or `alias` for one, or select_all:true",
                    );
                }
                if !aliases.is_empty() && select_all {
                    return tool_error("Pass either `aliases`/`alias` or select_all, not both");
                }

                let mut extra: Vec<&str> = Vec::new();
                // one --vm per alias: the CLI collects repeats, and passing them in a
                // single invocation keeps the set on identical source
                for alias in &aliases {
                    extra.push("--vm");
                    extra.push(alias.as_str());
                }
                if select_all {
                    extra.push("--all");
                }
                extra.push("--phase");
                extra.push(phase);

                let source_owned;
                if let Some(dir) = arg_str(args, "local_source_dir") {
                    source_owned = dir.to_owned();
                    extra.push("--local-source-dir");
                    extra.push(&source_owned);
                }
                let repo_owned;
                if let Some(url) = arg_str(args, "repo_url") {
                    repo_owned = url.to_owned();
                    extra.push("--repo-url");
                    extra.push(&repo_owned);
                }
                let branch_owned;
                if let Some(branch) = arg_str(args, "branch") {
                    branch_owned = branch.to_owned();
                    extra.push("--branch");
                    extra.push(&branch_owned);
                }
                let dest_owned;
                if let Some(dest) = arg_str(args, "dest_dir") {
                    dest_owned = dest.to_owned();
                    extra.push("--dest-dir");
                    extra.push(&dest_owned);
                }

                // build-release compiles the workspace ON the guest; the default is
                // generous but a cold guest over a slow link can still exceed it.
                let timeout = args
                    .and_then(|a| a.get("timeout_secs"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(2400);
                let timeout_owned = timeout.to_string();
                extra.push("--timeout-secs");
                extra.push(&timeout_owned);

                match self.arg_inventory(args) {
                    Ok(inventory) => self.run_ops_with_inventory(
                        "vm-lab-bootstrap-phase",
                        inventory.as_deref(),
                        &extra,
                        timeout + 120,
                    ),
                    Err(err) => tool_error(&err),
                }
            }

            "get_vm_diagnostics" => {
                let alias = arg_str(args, "alias").unwrap_or("");
                if alias.is_empty() {
                    return tool_error("Missing required parameter: alias");
                }
                let mut result = format!("# VM Diagnostics: {alias}\n\n## Daemon Status\n\n");
                let status = self.run_ops("vm-lab-status", &["--vm", alias], 300);
                if let Some(c) = status.content.first() {
                    result.push_str(&c.text);
                    result.push_str("\n\n");
                }
                result.push_str("## Diagnostic Artifacts\n\n");
                let report_dir =
                    match self.ensure_report_dir(&format!("state/live-lab-mcp/diag-{alias}")) {
                        Ok(dir) => dir,
                        Err(e) => return tool_error(&e),
                    };
                let artifacts = self.run_ops(
                    "vm-lab-collect-artifacts",
                    &["--vm", alias, "--report-dir", &report_dir],
                    600,
                );
                if let Some(c) = artifacts.content.first() {
                    result.push_str(&c.text);
                }
                tool_success(&result)
            }

            "diagnose_live_lab_failure" => {
                let report_dir_arg = arg_str(args, "report_dir").unwrap_or("");
                if report_dir_arg.is_empty() {
                    return tool_error("Missing required parameter: report_dir");
                }
                // `profile` is optional: orchestrate runs generate it internally.
                // Resolve it from the run's matrix row (profile_path) when omitted,
                // so the result→deep-triage handoff isn't broken for orchestrate.
                let profile_owned: String = match arg_str(args, "profile") {
                    Some(p) if !p.is_empty() => p.to_string(),
                    _ => {
                        let report_path =
                            match self.confined_repo_path(report_dir_arg, "report_dir") {
                                Ok(path) => path,
                                Err(e) => return tool_error(&e),
                            };
                        self.read_matrix_row(&report_path)
                            .and_then(|row| row.get("profile_path").cloned())
                            .filter(|p| !p.is_empty())
                            .unwrap_or_default()
                    }
                };
                let report_dir = match self.ensure_report_dir(report_dir_arg) {
                    Ok(dir) => dir,
                    Err(e) => return tool_error(&e),
                };
                if profile_owned.is_empty() {
                    // A Rust --node run records no profile (bash setup generates
                    // one; the Rust path does not). Diagnose directly from the
                    // report-dir evidence artifacts (orchestrate_result.json +
                    // stages.tsv + failure_digest.json) — no SSH-into-nodes.
                    return self.diagnose_profileless_run(
                        &PathBuf::from(&report_dir),
                        arg_str(args, "stage"),
                        arg_bool(args, "collect_artifacts"),
                    );
                }
                let mut extra: Vec<&str> =
                    vec!["--profile", &profile_owned, "--report-dir", &report_dir];
                if let Some(stage) = arg_str(args, "stage") {
                    extra.push("--stage");
                    extra.push(stage);
                }
                if arg_bool(args, "collect_artifacts") {
                    extra.push("--collect-artifacts");
                }
                self.run_ops("vm-lab-diagnose-live-lab-failure", &extra, 600)
            }

            "seed_cargo_cache" => self.seed_cargo_cache(args),
            "start_live_lab_run" => self.start_live_lab_run(args),
            "get_job_status" => self.get_job_status(args),
            "get_run_progress" => self.get_run_progress(args),
            "wait_for_job" => self.wait_for_job(args),
            "explain_stage" => explain_stage(arg_str(args, "stage").unwrap_or("")),
            "list_jobs" => self.list_jobs(),
            "tail_job_log" => self.tail_job_log(args),
            "cancel_job" => self.cancel_job(args),
            "get_run_result" => self.get_run_result(args),
            "list_report_artifacts" => self.list_report_artifacts(args),
            "read_report_artifact" => self.read_report_artifact(args),
            "grep_report" => self.grep_report(args),
            "get_stage_log" => self.get_stage_log(args),
            "get_run_trend" => self.get_run_trend(args),
            "find_untested_work" => self.find_untested_work(args),
            "diff_runs" => self.diff_runs(args),
            "what_will_deploy" => self.what_will_deploy(args),
            "preflight_check" => {
                let base = self.preflight_check();
                let Some(profile) = arg_str(args, "profile").filter(|p| !p.is_empty()) else {
                    return base;
                };
                // Profile-aware preflight (rulebook §11.2): append the
                // read-only network audit; its summary carries the profile's
                // canonical digest and the evidence path.
                let mut result = base
                    .content
                    .first()
                    .map(|c| c.text.clone())
                    .unwrap_or_default();
                result.push_str("\n\n## Network audit (read-only)\n\n");
                let audit = self.run_cli(
                    &[
                        "ops",
                        "vm-lab-network-audit",
                        "--inventory",
                        DEFAULT_INVENTORY,
                        "--profile",
                        profile,
                        "--skip-guests",
                    ],
                    "vm-lab-network-audit",
                    300,
                );
                if let Some(c) = audit.content.first() {
                    result.push_str(&c.text);
                }
                if base.is_error.unwrap_or(false) || audit.is_error.unwrap_or(false) {
                    tool_error(&result)
                } else {
                    tool_success(&result)
                }
            }
            "write_loop_note" => self.write_loop_note(args),
            "stage_triage_history" => self.stage_triage_history(args),
            "get_loop_journal" => self.get_loop_journal(args),
            "prune_jobs" => self.prune_jobs(args),

            "get_run_matrix" => {
                let limit = args
                    .and_then(|a| a.get("limit"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(20) as usize;
                let matrix_path = self
                    .repo_root
                    .join("documents/operations/live_lab_run_matrix.csv");
                match std::fs::read_to_string(&matrix_path) {
                    Ok(content) => {
                        let lines: Vec<&str> = content.lines().collect();
                        let total = lines.len().saturating_sub(1);
                        let mut result = format!("# Live Lab Run Matrix ({total} total runs)\n\n");
                        if lines.is_empty() {
                            result.push_str("Matrix is empty.\n");
                        } else {
                            result.push_str(&format!("```\n{}\n```\n\n", lines[0]));
                            let start = if lines.len() > limit + 1 {
                                lines.len() - limit
                            } else {
                                1
                            };
                            result.push_str(&format!("## Last {limit} runs\n\n```\n"));
                            for line in &lines[start..] {
                                result.push_str(line);
                                result.push('\n');
                            }
                            result.push_str("```\n");
                        }
                        tool_success(&result)
                    }
                    Err(e) => tool_error(&format!("Cannot read run matrix: {e}")),
                }
            }

            "host_disk_status" => {
                // With a host, report that REMOTE machine's pool via the CLI; without,
                // keep the existing local report.
                if let Some(host) = arg_str(args, "host") {
                    let mut extra: Vec<&str> = vec!["--host", host];
                    let pool_owned;
                    if let Some(pool) = arg_str(args, "pool") {
                        pool_owned = pool.to_owned();
                        extra.push("--pool");
                        extra.push(&pool_owned);
                    }
                    let ssh_owned;
                    if let Some(ssh) = arg_str(args, "ssh_identity_file") {
                        ssh_owned = ssh.to_owned();
                        extra.push("--ssh-identity-file");
                        extra.push(&ssh_owned);
                    }
                    match self.arg_inventory(args) {
                        Ok(inventory) => self.run_ops_with_inventory(
                            "vm-lab-host-disk-status",
                            inventory.as_deref(),
                            &extra,
                            DISCOVERY_TIMEOUT_SECS,
                        ),
                        Err(err) => tool_error(&err),
                    }
                } else {
                    self.host_disk_status()
                }
            }

            _ => tool_error(&format!("Unknown tool: {name}")),
        }
    }
}

// ── Async job tool implementations ────────────────────────────────────

impl LabStateServer {
    fn start_live_lab_run(&self, args: Option<&Value>) -> ToolCallResult {
        let mode = arg_str(args, "mode").unwrap_or("orchestrate");
        if !matches!(mode, "orchestrate" | "run" | "setup") {
            return tool_error("mode must be one of: orchestrate, run, setup");
        }
        let profile = arg_str(args, "profile").unwrap_or("");
        if mode == "run" && profile.is_empty() {
            return tool_error("mode=run requires a 'profile'");
        }
        // SOCKS bootstrap blocks evidence stages (rulebook §9): a live
        // reverse-SOCKS tunnel would contaminate egress/DNS/leak evidence.
        // Dry-run wiring checks are exempt.
        if !arg_bool(args, "dry_run") {
            let live_tunnels = active_vm_internet_tunnels(&self.repo_root);
            if !live_tunnels.is_empty() {
                return tool_error(&format!(
                    "refusing to launch: reverse-SOCKS bootstrap tunnel(s) are still active for [{}]. \
                     They contaminate network evidence — run set_vm_internet_access with action=disable \
                     for each alias first, then retry.",
                    live_tunnels.join(", ")
                ));
            }
        }

        // Fail closed on the nodes + role-platform-selector conflict: passing
        // `nodes` routes to the Rust --node engine, which takes each node's role
        // from its `alias:role` and IGNORES the bash-arm --{role}-platform
        // election flags. Emitting both would silently drop the election — so
        // reject rather than run a topology the operator did not intend.
        if mode == "orchestrate" && !string_array(args, "nodes").is_empty() {
            for sel in [
                "exit_platform",
                "relay_platform",
                "anchor_platform",
                "admin_platform",
                "blind_exit_platform",
            ] {
                if arg_str(args, sel).is_some() {
                    return tool_error(&format!(
                        "'{sel}' (a role-platform election) is ignored when 'nodes' is set: \
                         nodes routes to the Rust --node engine, which takes each node's role \
                         from its alias:role. Pass the role directly in nodes (e.g. \
                         \"macos-utm-1:exit\"), or omit nodes to use the bash auto-topology \
                         path with platform election."
                    ));
                }
            }
            if arg_bool(args, "macos_promote_exit") {
                return tool_error(
                    "'macos_promote_exit' is ignored when 'nodes' is set (Rust --node engine). \
                     Pass the macOS node's role directly in nodes (e.g. \"macos-utm-1:exit\").",
                );
            }
        }

        let job_id = self.new_job_id();
        let report_dir = arg_str(args, "report_dir")
            .map(String::from)
            .unwrap_or_else(|| format!("state/live-lab-{job_id}"));
        let report_dir = match self.ensure_report_dir(&report_dir) {
            Ok(dir) => dir,
            Err(e) => return tool_error(&e),
        };
        let active_jobs = self.active_live_job_count();
        if active_jobs >= MAX_CONCURRENT_LIVE_LAB_JOBS {
            return tool_error(&format!(
                "live-lab job already running ({active_jobs}/{MAX_CONCURRENT_LIVE_LAB_JOBS}); cancel or wait before starting another"
            ));
        }
        if let Err(e) = std::fs::create_dir_all(self.jobs_dir()) {
            return tool_error(&format!("cannot create jobs dir: {e}"));
        }
        let log_path = self.jobs_dir().join(format!("{job_id}.log"));
        let ssh = default_ssh_identity();
        let kh = default_known_hosts();

        let mut cli: Vec<String> = [
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--features",
            "vm-lab",
            "--",
            "ops",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        match mode {
            "orchestrate" => {
                cli.push("vm-lab-orchestrate-live-lab".into());
                cli.extend(["--inventory".into(), DEFAULT_INVENTORY.into()]);
                cli.extend([
                    "--ssh-identity-file".into(),
                    ssh,
                    "--known-hosts-file".into(),
                    kh,
                ]);
                cli.extend(["--report-dir".into(), report_dir.clone()]);
                if arg_bool(args, "dry_run") {
                    cli.push("--dry-run".into());
                }
                if arg_bool(args, "stop_after_ready") {
                    cli.push("--stop-after-ready".into());
                }
                if arg_bool(args, "trust_inventory_ready") {
                    cli.push("--trust-inventory-ready".into());
                }
                for (flag, key) in [
                    ("--skip-gates", "skip_gates"),
                    ("--skip-soak", "skip_soak"),
                    ("--skip-cross-network", "skip_cross_network"),
                ] {
                    if arg_bool(args, key) {
                        cli.push(flag.into());
                    }
                }
                // Verify-only network-profile propagation (rulebook §11.2):
                // the orchestrator records the profile immutably at launch and
                // an explicit id is enforced fail-closed. This tool never
                // mutates attachments to satisfy a profile.
                if let Some(network_profile) =
                    arg_str(args, "network_profile").filter(|p| !p.is_empty())
                {
                    cli.extend(["--network-profile".into(), network_profile.to_string()]);
                }
                // Windows/macOS: explicit arg wins; otherwise auto-topology
                // (default on) fills them from the inventory.
                let auto = args
                    .and_then(|a| a.get("auto_topology"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let win = arg_str(args, "windows_vm").map(String::from).or_else(|| {
                    auto.then(|| self.inventory_alias_for_platform("windows"))
                        .flatten()
                });
                let mac = arg_str(args, "macos_vm").map(String::from).or_else(|| {
                    auto.then(|| self.inventory_alias_for_platform("macos"))
                        .flatten()
                });

                let explicit_nodes = string_array(args, "nodes");
                // Role-platform selectors (Bucket 5) ELECT an OS into a role so the
                // focused mac/win cell runs live instead of skipping. Bash is slated
                // for removal once Rust parity evidence is complete, so — unlike the
                // raw `--exit-platform` etc. CLI flags, which only the legacy bash
                // arm honors — a selector-driven run here AUTO-SYNTHESIZES a full
                // `--node alias:role` topology (mirrors ai_lab_run's default
                // `rust_engine: true` behavior) instead of falling to bash. The
                // earlier mutual-exclusivity check guarantees `explicit_nodes` is
                // empty whenever a selector is present, so this and the
                // `!explicit_nodes.is_empty()` branch below never both fire.
                if explicit_nodes.is_empty() && has_role_platform_selector(args) {
                    let linux_lab_roles = self.inventory_linux_lab_roles();
                    let synthesized = synthesize_nodes_from_platform_selectors(
                        &linux_lab_roles,
                        mac.as_deref(),
                        win.as_deref(),
                        arg_str(args, "exit_platform"),
                        arg_str(args, "relay_platform"),
                        arg_str(args, "anchor_platform"),
                        arg_str(args, "admin_platform"),
                        arg_str(args, "blind_exit_platform"),
                        arg_bool(args, "macos_promote_exit"),
                    );
                    if synthesized.is_empty() {
                        return tool_error(
                            "a role-platform selector was set but no --node topology could be \
                             synthesized: the inventory has no Linux lab_role entries and the \
                             selected OS did not resolve to an alias (check windows_vm/macos_vm \
                             or the inventory's platform field). Without this, the run would \
                             silently emit zero --node flags and fall back to bash.",
                        );
                    }
                    for n in synthesized {
                        cli.extend(["--node".into(), n]);
                    }
                } else {
                    if let Some(w) = &win {
                        cli.extend(["--windows-vm".into(), w.clone()]);
                    }
                    if let Some(m) = &mac {
                        cli.extend(["--macos-vm".into(), m.clone()]);
                    }
                    for n in explicit_nodes {
                        cli.extend(["--node".into(), n]);
                    }
                    // Raw platform-selector flags only reach the CLI here if
                    // `nodes` was also set — the earlier mutual-exclusivity check
                    // already rejected that combination, so this is unreachable
                    // in practice; kept as a fail-safe rather than a silent drop.
                    for (flag, key) in [
                        ("--exit-platform", "exit_platform"),
                        ("--relay-platform", "relay_platform"),
                        ("--anchor-platform", "anchor_platform"),
                        ("--admin-platform", "admin_platform"),
                        ("--blind-exit-platform", "blind_exit_platform"),
                    ] {
                        if let Some(v) = arg_str(args, key) {
                            cli.extend([flag.into(), v.into()]);
                        }
                    }
                    if arg_bool(args, "macos_promote_exit") {
                        cli.push("--macos-promote-exit".into());
                    }
                }
                // Fast re-verify of a code patch: redeploy ONLY the affected
                // node(s); others keep their daemon + distributed state. The full
                // stage sequence still replays (cheap SSH steps; pair with
                // skip_soak) but the expensive multi-node rebuild is avoided.
                // Requires the Rust-native path → `nodes` must also be set.
                let rebuild = string_array(args, "rebuild_nodes");
                if !rebuild.is_empty() {
                    cli.push("--rebuild-nodes".into());
                    cli.push(rebuild.join(","));
                }
                if arg_bool(args, "skip_linux_live_suite") {
                    cli.push("--skip-linux-live-suite".into());
                }
            }
            "run" => {
                cli.push("vm-lab-run-live-lab".into());
                cli.extend(["--profile".into(), profile.into()]);
                cli.extend(["--report-dir".into(), report_dir.clone()]);
                if arg_bool(args, "dry_run") {
                    cli.push("--dry-run".into());
                }
                for (flag, key) in [
                    ("--skip-setup", "skip_setup"),
                    ("--skip-gates", "skip_gates"),
                    ("--skip-soak", "skip_soak"),
                    ("--skip-cross-network", "skip_cross_network"),
                ] {
                    if arg_bool(args, key) {
                        cli.push(flag.into());
                    }
                }
            }
            "setup" => {
                cli.push("vm-lab-setup-live-lab".into());
                cli.extend(["--inventory".into(), DEFAULT_INVENTORY.into()]);
                cli.extend([
                    "--ssh-identity-file".into(),
                    ssh,
                    "--known-hosts-file".into(),
                    kh,
                ]);
                cli.extend(["--report-dir".into(), report_dir.clone()]);
                if let Some(po) = arg_str(args, "profile_output") {
                    cli.extend(["--profile-output".into(), po.into()]);
                }
                // Resume a FAILED SETUP (preflight..validate_baseline_runtime)
                // against the SAME report_dir without redoing earlier setup
                // stages. For a CODE patch, only resume from prepare_source_archive
                // (or earlier) — resuming later reuses the prior build = STALE
                // code. rerun_stage runs exactly one setup stage.
                if let Some(rf) = arg_str(args, "resume_from") {
                    cli.extend(["--resume-from".into(), rf.into()]);
                }
                if let Some(rs) = arg_str(args, "rerun_stage") {
                    cli.extend(["--rerun-stage".into(), rs.into()]);
                }
                if arg_bool(args, "dry_run") {
                    cli.push("--dry-run".into());
                }
            }
            _ => unreachable!(),
        }

        // Source mode applies to all modes. Default to working-tree so an
        // agent's UNCOMMITTED patch is what gets built/tested on the VMs
        // (git stash create captures tracked edits; new files must be `git add`ed).
        let source_mode = arg_str(args, "source_mode").unwrap_or("working-tree");
        cli.push("--source-mode".into());
        cli.push(source_mode.into());
        // Optional per-run timeout cap (CLI default is 24h). Allows a single
        // soak run to exceed 24h, or a tighter cap for fast iterations.
        if let Some(t) = args
            .and_then(|a| a.get("timeout_secs"))
            .and_then(|v| v.as_u64())
        {
            cli.push("--timeout-secs".into());
            cli.push(t.to_string());
        }

        let cli_refs: Vec<&str> = cli.iter().map(|s| s.as_str()).collect();
        // Isolated build dir so the lab job's local cargo build never contends on
        // the workspace target lock with the gate-runner's builds. Persistent +
        // gitignored, so it's a warm cache reused across runs (not a rebuild tax).
        let lab_target = self.repo_root.join("target-livelab");
        let lab_target_s = lab_target.to_string_lossy().to_string();
        match spawn_logged(
            "cargo",
            &cli_refs,
            &self.repo_root,
            &[
                ("CARGO_TERM_COLOR", "never"),
                ("CARGO_TARGET_DIR", &lab_target_s),
            ],
            &log_path,
        ) {
            Ok(child) => {
                let pid = child.id();
                // Capture the pid's start-time NOW (while we hold the live child,
                // so the pid is unambiguously this process) as a reuse-detection
                // token. job_state/cancel_job compare against it after a server
                // reload to avoid acting on a recycled pid.
                let pid_start = self.pid_start_time(pid as u64);
                self.jobs
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(job_id.clone(), child);
                let rec = json!({
                    "job_id": job_id,
                    "mode": mode,
                    "report_dir": report_dir,
                    "log_path": log_path.to_string_lossy(),
                    "pid": pid,
                    "pid_start": pid_start,
                    "command": format!("cargo {}", cli.join(" ")),
                    "created_unix": now_unix(),
                });
                let _ = self.write_job_record(&job_id, &rec);
                // Warn if untracked crates/ files won't deploy (working-tree
                // source captures TRACKED changes only) — else the run tests
                // stale code and the agent gets a misleading "still failing".
                let mut warn = String::new();
                if source_mode == "working-tree" {
                    let untracked = self.untracked_crate_files();
                    if !untracked.is_empty() {
                        warn = format!(
                            "\n\n⚠️ **{} untracked file(s) under crates/ will NOT be deployed** (working-tree captures tracked changes only). `git add` them or this run builds stale code:\n{}",
                            untracked.len(),
                            untracked
                                .iter()
                                .map(|p| format!("- `{p}`"))
                                .collect::<Vec<_>>()
                                .join("\n")
                        );
                    }
                }
                tool_success(&format!(
                    "# Started live-lab job\n\n- **job_id:** `{job_id}`\n- **mode:** {mode}\n- **report_dir:** `{report_dir}`\n- **pid:** {pid}\n- **log:** `{}`{warn}\n\nThis is async — poll `get_job_status(job_id=\"{job_id}\")` or `wait_for_job`, `tail_job_log` for progress, `get_run_result` when done.",
                    log_path.display()
                ))
            }
            Err(e) => tool_error(&format!("Failed to start job: {e}")),
        }
    }

    /// Shared status renderer → (state, markdown). Used by get_job_status +
    /// wait_for_job so they never drift.
    fn render_job_status(&self, job_id: &str, rec: &Value) -> (String, String) {
        let report_dir_rel = rec.get("report_dir").and_then(|v| v.as_str()).unwrap_or("");
        let report_dir = self
            .report_dir_from_record(report_dir_rel)
            .unwrap_or_else(|| self.repo_root.join("__invalid_out_of_repo_path__"));
        let pid = rec.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
        let created = rec
            .get("created_unix")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let state = self.job_state(job_id, pid, &report_dir);
        let elapsed = now_unix().saturating_sub(created);
        let mut out = format!(
            "# Job {job_id}\n\n- **state:** {state}\n- **mode:** {}\n- **report_dir:** `{report_dir_rel}`\n- **pid:** {pid}\n- **elapsed:** {elapsed}s\n- **log:** `{}`\n",
            rec.get("mode").and_then(|v| v.as_str()).unwrap_or("?"),
            rec.get("log_path").and_then(|v| v.as_str()).unwrap_or("?"),
        );
        if let Some(row) = self.read_matrix_row(&report_dir) {
            out.push_str(&format!(
                "- **overall_result:** {}\n- **first_failed_stage:** {}\n",
                row.get("overall_result").map(|s| s.as_str()).unwrap_or(""),
                row.get("first_failed_stage")
                    .map(|s| s.as_str())
                    .unwrap_or(""),
            ));
        }
        (state, out)
    }

    fn get_job_status(&self, args: Option<&Value>) -> ToolCallResult {
        let job_id = arg_str(args, "job_id").unwrap_or("");
        let Some(rec) = self.read_job_record(job_id) else {
            return tool_error(&format!("Unknown job_id: {job_id}"));
        };
        let (state, mut out) = self.render_job_status(job_id, &rec);
        if state == "running" {
            out.push_str(
                "\nStill running. wait_for_job to block until done, or tail_job_log for progress.\n",
            );
        } else {
            out.push_str("\nFinished. Use get_run_result for the structured breakdown.\n");
        }
        tool_success(&out)
    }

    fn wait_for_job(&self, args: Option<&Value>) -> ToolCallResult {
        let job_id = arg_str(args, "job_id").unwrap_or("");
        let Some(rec) = self.read_job_record(job_id) else {
            return tool_error(&format!("Unknown job_id: {job_id}"));
        };
        let timeout = args
            .and_then(|a| a.get("timeout_secs"))
            .and_then(|v| v.as_u64())
            .unwrap_or(240)
            .clamp(10, 270);
        let report_dir_rel = rec.get("report_dir").and_then(|v| v.as_str()).unwrap_or("");
        let report_dir = match self.report_dir_from_record(report_dir_rel) {
            Some(dir) => dir,
            None => return tool_error("job record has invalid report_dir"),
        };
        let pid = rec.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
        let start = Instant::now();
        loop {
            if self.job_state(job_id, pid, &report_dir) != "running" {
                let (_, mut out) = self.render_job_status(job_id, &rec);
                out.push_str(&format!(
                    "\nJob finished after {}s. Use get_run_result for the breakdown.\n",
                    start.elapsed().as_secs()
                ));
                return tool_success(&out);
            }
            if start.elapsed() >= Duration::from_secs(timeout) {
                let (_, mut out) = self.render_job_status(job_id, &rec);
                out.push_str(&format!(
                    "\nStill running after {timeout}s — call wait_for_job again, or tail_job_log.\n"
                ));
                return tool_success(&out);
            }
            std::thread::sleep(Duration::from_secs(3));
        }
    }

    fn list_jobs(&self) -> ToolCallResult {
        let dir = self.jobs_dir();
        let mut out = String::from("# Live-lab jobs\n\n");
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => return tool_success("# Live-lab jobs\n\nNo jobs yet.\n"),
        };
        let mut rows: Vec<(u64, String)> = Vec::new();
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().map(|e| e == "json").unwrap_or(false)
                && let Ok(s) = std::fs::read_to_string(&p)
                && let Ok(rec) = serde_json::from_str::<Value>(&s)
            {
                let job_id = rec.get("job_id").and_then(|v| v.as_str()).unwrap_or("?");
                let report_dir_rel = rec.get("report_dir").and_then(|v| v.as_str()).unwrap_or("");
                let pid = rec.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
                let created = rec
                    .get("created_unix")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let state = self
                    .report_dir_from_record(report_dir_rel)
                    .map(|dir| self.job_state(job_id, pid, &dir))
                    .unwrap_or_else(|| "invalid report_dir".into());
                rows.push((
                    created,
                    format!(
                        "- `{job_id}` — **{state}** — mode={} — `{report_dir_rel}`",
                        rec.get("mode").and_then(|v| v.as_str()).unwrap_or("?")
                    ),
                ));
            }
        }
        rows.sort_by_key(|row| std::cmp::Reverse(row.0));
        if rows.is_empty() {
            out.push_str("No jobs yet.\n");
        } else {
            for (_, line) in rows {
                out.push_str(&line);
                out.push('\n');
            }
        }
        tool_success(&out)
    }

    fn tail_job_log(&self, args: Option<&Value>) -> ToolCallResult {
        let job_id = arg_str(args, "job_id").unwrap_or("");
        let Some(rec) = self.read_job_record(job_id) else {
            return tool_error(&format!("Unknown job_id: {job_id}"));
        };
        let lines = args
            .and_then(|a| a.get("lines"))
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize;
        let log_path = rec.get("log_path").and_then(|v| v.as_str()).unwrap_or("");
        match tail_file(Path::new(log_path), lines) {
            Ok(body) => tool_success(&format!(
                "# Tail of {job_id} (last {lines} lines)\n\n```\n{}\n```\n",
                truncate_output(&body, lines, 80_000)
            )),
            Err(e) => tool_error(&e),
        }
    }

    fn cancel_job(&self, args: Option<&Value>) -> ToolCallResult {
        let job_id = arg_str(args, "job_id").unwrap_or("");
        let Some(rec) = self.read_job_record(job_id) else {
            return tool_error(&format!("Unknown job_id: {job_id}"));
        };
        let pid = rec.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
        let report_dir_rel = rec.get("report_dir").and_then(|v| v.as_str()).unwrap_or("");
        let report_dir = match self.report_dir_from_record(report_dir_rel) {
            Some(dir) => dir,
            None => return tool_error("job record has invalid report_dir"),
        };

        // If we still hold the child handle, kill via it (no pid race at all).
        // The job was spawned as a process-group leader, so signal the whole
        // group FIRST (orchestrator → bash workers → utmctl pushes), then reap
        // the leader through the handle. Killing only the leader leaves
        // workers orphaned, still pushing archives and retrying bootstraps.
        if let Some(mut child) = self
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(job_id)
        {
            if pid != 0 {
                self.kill_process_group(pid);
            }
            let _ = child.kill();
            let _ = child.wait();
            return tool_success(&format!(
                "# Cancelled job {job_id}\n\nKilled the job's process group and reaped the leader (pid {pid}).\n"
            ));
        }

        // No handle (e.g. after a server reload). Only kill-by-pid if the job is
        // STILL running — a finished job's pid may have been recycled by the OS,
        // and signalling it would hit an unrelated process.
        let state = self.job_state(job_id, pid, &report_dir);
        if state != "running" {
            return tool_success(&format!(
                "# Job {job_id} not cancelled\n\nIt is already **{state}** — refusing to kill pid {pid} (it may have been recycled to another process).\n"
            ));
        }
        if pid != 0 {
            self.kill_process_group(pid);
        }
        tool_success(&format!(
            "# Cancelled job {job_id}\n\nSent kill to running pid {pid} and its process group.\n"
        ))
    }

    /// Signal a job's whole process group (TERM, then KILL): `kill -- -<pid>`
    /// targets the group of which the job is the leader (set at spawn via
    /// `process_group(0)`). Falls back to the bare pid for any straggler that
    /// detached into its own group.
    fn kill_process_group(&self, pid: u64) {
        let group = format!("-{pid}");
        let pid_s = pid.to_string();
        let _ = run_with_timeout(
            "kill",
            &["--", &group],
            &self.repo_root,
            &[],
            Duration::from_secs(5),
        );
        let _ = run_with_timeout(
            "kill",
            &["-9", "--", &group],
            &self.repo_root,
            &[],
            Duration::from_secs(5),
        );
        let _ = run_with_timeout(
            "kill",
            &["-9", &pid_s],
            &self.repo_root,
            &[],
            Duration::from_secs(5),
        );
    }

    /// Resolve report dir from an explicit report_dir arg or a job_id's record.
    fn resolve_report_dir(&self, args: Option<&Value>) -> Result<PathBuf, String> {
        if let Some(dir) = arg_str(args, "report_dir") {
            return self.confined_repo_path(dir, "report_dir");
        }
        if let Some(job_id) = arg_str(args, "job_id") {
            let rec = self
                .read_job_record(job_id)
                .ok_or_else(|| format!("Unknown job_id: {job_id}"))?;
            let dir = rec
                .get("report_dir")
                .and_then(|v| v.as_str())
                .ok_or("job record missing report_dir")?;
            return self.confined_repo_path(dir, "job report_dir");
        }
        Err("Provide either job_id or report_dir".into())
    }

    fn get_run_result(&self, args: Option<&Value>) -> ToolCallResult {
        let report_dir = match self.resolve_report_dir(args) {
            Ok(d) => d,
            Err(e) => return tool_error(&e),
        };
        let mut out = format!(
            "# Live Lab Run Result\n\n- **report_dir:** `{}`\n",
            report_dir.display()
        );

        match self.read_report_state(&report_dir) {
            Some(rs) => {
                out.push_str(&format!(
                    "- **run_complete:** {}\n- **run_passed:** {}\n",
                    rs.get("run_complete")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    rs.get("run_passed")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                ));
            }
            None => out.push_str("- report_state.json: not found (run may not have completed)\n"),
        }

        if let Some(row) = self.read_matrix_row(&report_dir) {
            let get = |k: &str| row.get(k).map(|s| s.as_str()).unwrap_or("");
            out.push_str(&format!(
                "- **overall_result:** {}\n- **first_failed_stage:** {}\n- **git_commit:** {}\n- **git_dirty_state:** {}\n\n## Per-OS stages\n",
                get("overall_result"),
                get("first_failed_stage"),
                get("git_commit"),
                get("git_dirty_state"),
            ));
            for os in ["linux", "macos", "windows"] {
                let prefix = format!("{os}_stage_");
                let (mut pass, mut fail, mut not_run) = (0u32, 0u32, 0u32);
                let mut failed_stages = Vec::new();
                for (k, v) in &row {
                    if let Some(stage) = k.strip_prefix(prefix.as_str()) {
                        match v.as_str() {
                            "pass" => pass += 1,
                            "fail" => {
                                fail += 1;
                                failed_stages.push(stage.to_string());
                            }
                            _ => not_run += 1,
                        }
                    }
                }
                let present = get(&format!("{os}_present"));
                out.push_str(&format!(
                    "- **{os}** (present={present}): pass={pass} fail={fail} not_run={not_run}"
                ));
                if !failed_stages.is_empty() {
                    out.push_str(&format!(" — FAILED: {}", failed_stages.join(", ")));
                }
                out.push('\n');
            }
            let cross_failed: Vec<String> = row
                .iter()
                .filter(|(k, v)| k.starts_with("cross_os_") && v.as_str() == "fail")
                .filter_map(|(k, _)| k.strip_prefix("cross_os_").map(String::from))
                .collect();
            if !cross_failed.is_empty() {
                out.push_str(&format!(
                    "- **cross-OS FAILED:** {}\n",
                    cross_failed.join(", ")
                ));
            }
        } else {
            out.push_str("- matrix row: not found\n");
        }

        if let Some(dig) = self.find_failure_digest(&report_dir) {
            let ff = dig.get("first_failure").unwrap_or(&dig);
            let stage = ff.get("stage").and_then(|v| v.as_str()).unwrap_or("?");
            let reason = ff
                .get("primary_failure_reason")
                .or_else(|| ff.get("reason"))
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let msg = ff.get("message").and_then(|v| v.as_str()).unwrap_or("");
            out.push_str(&format!(
                "\n## Failure digest\n- **stage:** {stage}\n- **reason:** {reason}\n- **message:** {}\n",
                truncate_output(msg, 40, 4_000)
            ));
        }

        out.push_str(
            "\nUse list_report_artifacts / read_report_artifact for raw logs, or diagnose_live_lab_failure for deep triage.\n",
        );
        tool_success(&out)
    }

    fn list_report_artifacts(&self, args: Option<&Value>) -> ToolCallResult {
        let report_dir = match self.resolve_report_dir(args) {
            Ok(d) => d,
            Err(e) => return tool_error(&e),
        };
        let mut files: Vec<(String, u64)> = Vec::new();
        collect_files(&report_dir, &report_dir, &mut files, 0);
        files.sort();
        let mut out = format!(
            "# Report artifacts ({} files)\n\n`{}`\n\n",
            files.len(),
            report_dir.display()
        );
        for (rel, size) in files.iter().take(400) {
            out.push_str(&format!("- `{rel}` ({size} bytes)\n"));
        }
        if files.len() > 400 {
            out.push_str(&format!("\n... ({} more)\n", files.len() - 400));
        }
        tool_success(&out)
    }

    fn read_report_artifact(&self, args: Option<&Value>) -> ToolCallResult {
        let report_dir = match self.resolve_report_dir(args) {
            Ok(d) => d,
            Err(e) => return tool_error(&e),
        };
        let rel = arg_str(args, "path").unwrap_or("");
        if rel.is_empty() {
            return tool_error("Missing required parameter: path");
        }
        if rel.contains("..") {
            return tool_error("Invalid path: '..' not allowed");
        }
        let base = match report_dir.canonicalize() {
            Ok(b) => b,
            Err(e) => return tool_error(&format!("Cannot resolve report dir: {e}")),
        };
        let target = match base.join(rel).canonicalize() {
            Ok(t) => t,
            Err(e) => return tool_error(&format!("Cannot read '{rel}': {e}")),
        };
        if !target.starts_with(&base) {
            return tool_error("Invalid path: escapes the report directory");
        }
        match read_file_capped(&target, 1_000_000) {
            Ok(content) => tool_success(&format!(
                "# `{rel}`\n\n```\n{}\n```\n",
                truncate_output(&content, 800, 80_000)
            )),
            Err(e) => tool_error(&format!("Cannot read '{rel}': {e}")),
        }
    }

    fn prune_jobs(&self, args: Option<&Value>) -> ToolCallResult {
        let keep = args
            .and_then(|a| a.get("keep"))
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as usize;
        let delete_reports = arg_bool(args, "delete_report_dirs");
        let mut jobs: Vec<(u64, String, Value)> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(self.jobs_dir()) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().map(|e| e == "json").unwrap_or(false)
                    && let Ok(s) = std::fs::read_to_string(&p)
                    && let Ok(rec) = serde_json::from_str::<Value>(&s)
                {
                    let created = rec
                        .get("created_unix")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let job_id = rec
                        .get("job_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    if !job_id.is_empty() {
                        jobs.push((created, job_id, rec));
                    }
                }
            }
        }
        jobs.sort_by_key(|job| std::cmp::Reverse(job.0)); // newest first
        let mut pruned = 0;
        let mut skipped_running = 0;
        for (_, job_id, rec) in jobs.into_iter().skip(keep) {
            let report_dir_rel = rec.get("report_dir").and_then(|v| v.as_str()).unwrap_or("");
            let pid = rec.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
            if self
                .report_dir_from_record(report_dir_rel)
                .map(|dir| self.job_state(&job_id, pid, &dir) == "running")
                .unwrap_or_else(|| pid != 0 && self.pid_alive_verified(&job_id, pid))
            {
                skipped_running += 1;
                continue;
            }
            self.jobs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&job_id);
            let _ = std::fs::remove_file(self.job_record_path(&job_id));
            if let Some(log) = rec.get("log_path").and_then(|v| v.as_str()) {
                let _ = std::fs::remove_file(log);
            }
            if delete_reports
                && !report_dir_rel.is_empty()
                && let Some(report_dir) = self.report_dir_from_record(report_dir_rel)
            {
                let _ = std::fs::remove_dir_all(report_dir);
            }
            pruned += 1;
        }
        tool_success(&format!(
            "# Pruned {pruned} finished job(s)\n\n- kept the {keep} most recent\n- skipped {skipped_running} still-running\n- report dirs {}deleted\n",
            if delete_reports { "" } else { "NOT " }
        ))
    }
}

fn string_array(args: Option<&Value>, key: &str) -> Vec<String> {
    args.and_then(|a| a.get(key))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn canonicalize_existing_prefix(path: &Path) -> PathBuf {
    let normalized = lexical_normalize(path);
    let mut current = normalized.clone();
    let mut suffix: Vec<OsString> = Vec::new();
    while !current.exists() {
        if let Some(name) = current.file_name() {
            suffix.push(name.to_os_string());
        }
        if !current.pop() {
            return normalized;
        }
    }
    let mut out = current.canonicalize().unwrap_or(current);
    for name in suffix.into_iter().rev() {
        out.push(name);
    }
    lexical_normalize(&out)
}

fn deepest_existing_ancestor(path: &Path) -> Option<PathBuf> {
    let mut current = path.to_path_buf();
    loop {
        if current.exists() {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

fn redact_secret_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let lower = key.to_ascii_lowercase();
                if lower.contains("password")
                    || lower.contains("private_key")
                    || lower.contains("secret")
                    || lower.ends_with("token")
                    || lower == "token"
                {
                    *child = Value::String("<redacted>".into());
                } else {
                    redact_secret_fields(child);
                }
            }
        }
        Value::Array(items) => {
            for child in items {
                redact_secret_fields(child);
            }
        }
        _ => {}
    }
}

fn collect_files(dir: &Path, base: &Path, out: &mut Vec<(String, u64)>, depth: usize) {
    if depth > 8 || out.len() > 2000 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_files(&p, base, out, depth + 1);
        } else if let Ok(rel) = p.strip_prefix(base) {
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            out.push((rel.to_string_lossy().to_string(), size));
        }
    }
}

// ── Stage knowledge (for explain_stage) ──────────────────────────────
// Sourced from the orchestrator stage impls + the run-matrix evidence.

struct StageInfo {
    name: &'static str,
    aliases: &'static [&'static str],
    checks: &'static str,
    owning: &'static str,
    causes: &'static [&'static str],
}

static STAGE_INFO: &[StageInfo] = &[
    StageInfo {
        name: "bootstrap",
        aliases: &["cleanup_hosts", "bootstrap_hosts", "install"],
        checks: "Builds rustynetd on each node from the source archive, installs the service, starts the daemon, and waits for the control socket.",
        owning: "crates/rustynet-cli/src/vm_lab/orchestrator/stage/install.rs",
        causes: &[
            "cargo registry unreachable during the remote build (network/DNS)",
            "daemon control socket never appears in the wait window (build failed or daemon crashed)",
            "macOS: no default egress route after DHCP → node isolated",
        ],
    },
    StageInfo {
        name: "membership",
        aliases: &["membership_init", "distribute_membership"],
        checks: "Exit node (membership owner) signs the initial membership snapshot with the operator key and seeds all peer pubkeys + role capabilities.",
        owning: "crates/rustynet-cli/src/vm_lab/orchestrator/stage/membership_init.rs",
        causes: &[
            "missing WireGuard pubkey for a node (collect_pubkeys failed earlier)",
            "missing/empty node_id for a node",
            "no Exit node present in the assignments",
        ],
    },
    StageInfo {
        name: "assignments",
        aliases: &["distribute_assignments"],
        checks: "Signs and distributes per-node role-capability bundles (e.g. exit_server for Exit) plus the full-mesh allow list.",
        owning: "crates/rustynet-cli/src/vm_lab/orchestrator/stage/distribute_assignments.rs",
        causes: &[
            "missing node_id from a prior stage",
            "platform capability unavailable for a role",
            "endpoint resolution failure",
        ],
    },
    StageInfo {
        name: "baseline_runtime",
        aliases: &[
            "validate_baseline_runtime",
            "enforce_baseline_runtime",
            "validate_runtime",
        ],
        checks: "Each node runs 6 daemon posture probes: RuntimeAcls, ServiceHardening, KeyCustody, Authenticode, MeshStatus, DnsFailclosed.",
        owning: "crates/rustynet-cli/src/vm_lab/orchestrator/stage/validate_runtime.rs",
        causes: &[
            "daemon control socket unavailable (node never started after bootstrap, or crashed)",
            "an individual validator reports not-passed (runtime ACLs not enforced, key not in custody, DNS not fail-closed, …)",
            "no adapter for the node",
        ],
    },
    StageInfo {
        name: "anchor",
        aliases: &["anchor_validation"],
        checks: "Each Anchor node proves it advertises the required anchor capabilities; the primary must advertise anchor.gossip_seed; Linux anchors run bundle-pull substages (loopback, invalid-token, log-redaction).",
        owning: "crates/rustynet-cli/src/vm_lab/orchestrator/stage/anchor_validation.rs",
        causes: &[
            "an anchor sub-capability missing in membership (e.g. anchor.gossip_seed)",
            "bundle-pull token path empty or loopback listener disabled",
            "no adapter / shell host unavailable for the anchor node",
        ],
    },
    StageInfo {
        name: "relay",
        aliases: &[
            "deploy_relay",
            "deploy_relay_service",
            "relay_validation",
            "relay_service_lifecycle",
        ],
        checks: "Deploys the rustynet-relay service + verifier key on Relay nodes, then proves lifecycle: running (datapath UDP + health TCP bound, /healthz ok) → stop → restart. Linux/macOS live; Windows skipped.",
        owning: "crates/rustynet-cli/src/vm_lab/orchestrator/stage/{deploy_relay,relay_validation}.rs",
        causes: &[
            "relay service fails to start or bind its datapath/health ports",
            "/healthz endpoint not responding",
            "service install/enable (systemctl) failure on Linux",
        ],
    },
    StageInfo {
        name: "traffic",
        aliases: &["traffic_test_matrix", "two_hop"],
        checks: "Re-collects mesh IPs (60s retry, detects collisions), then pings every peer from every node (90s retry) to prove baseline reachability.",
        owning: "crates/rustynet-cli/src/vm_lab/orchestrator/stage/traffic_test_matrix.rs",
        causes: &[
            "no mesh IPs collected (WireGuard interface never settled)",
            "duplicate IPs across nodes = assignment bundle not applied",
            "ping still failing after the retry window (WireGuard/daemon issue)",
        ],
    },
    StageInfo {
        name: "role_switch",
        aliases: &["role_switch_matrix"],
        checks: "Each node enumerates active WireGuard tunnels and verifies the list is non-empty and not the wg-not-installed sentinel — tunnels survived role distribution.",
        owning: "crates/rustynet-cli/src/vm_lab/orchestrator/stage/role_switch_matrix.rs",
        causes: &[
            "daemon reports no active tunnels (daemon down or interface dropped)",
            "WireGuard enumeration tool not installed on the node",
            "no adapter for the node",
        ],
    },
    StageInfo {
        name: "exit_handoff",
        aliases: &[],
        checks: "Exit node proves it holds the membership owner key AND has active tunnels (serving the mesh). Fails closed if either is false.",
        owning: "crates/rustynet-cli/src/vm_lab/orchestrator/stage/exit_handoff.rs",
        causes: &[
            "membership owner key unavailable/corrupted on the exit node",
            "no active tunnels on the exit after role distribution",
            "no Exit node in assignments",
        ],
    },
    StageInfo {
        name: "dns",
        aliases: &["distribute_dns_zone", "managed_dns"],
        checks: "Signs and distributes the Magic DNS zone bundle to all nodes.",
        owning: "crates/rustynet-cli/src/vm_lab/orchestrator/stage/distribute_dns_zone.rs",
        causes: &[
            "Exit node not found in assignments",
            "no node_id for a node",
            "bundle issuance failure",
        ],
    },
    StageInfo {
        name: "traversal",
        aliases: &["distribute_traversal"],
        checks: "Signs and distributes traversal hints before runtime enforcement so peers can prefer direct paths and fail closed on stale/invalid traversal state.",
        owning: "crates/rustynet-cli/src/vm_lab/orchestrator/stage/distribute_traversal.rs",
        causes: &[
            "Exit node not found in assignments",
            "no node_id for a node",
            "traversal bundle issuance or distribution failure",
        ],
    },
    // ── Early stages (common first failure points) ──
    StageInfo {
        name: "preflight",
        aliases: &[],
        checks: "Local prerequisites on the host: cargo, ssh, git, utmctl present and the inventory readable.",
        owning: "crates/rustynet-cli/src/vm_lab/orchestrator/stage/preflight.rs",
        causes: &[
            "a required local tool is missing (cargo/ssh/git/utmctl)",
            "inventory file missing or unparseable",
        ],
    },
    StageInfo {
        name: "source_archive",
        aliases: &["prepare_source_archive"],
        checks: "Tars the working tree (or HEAD, per source-mode) into the state archive that gets scp'd to each node.",
        owning: "crates/rustynet-cli/src/vm_lab/orchestrator/stage/source_archive.rs",
        causes: &[
            "`git stash create` / `git archive` failed (not a git repo, or a huge untracked tree)",
            "NOTE: source-mode=working-tree captures only TRACKED changes — `git add` new files or they won't deploy",
        ],
    },
    StageInfo {
        name: "verify_ssh",
        aliases: &["verify_ssh_reachability", "ssh"],
        checks: "Confirms SSH reachability to each selected node before doing any work.",
        owning: "crates/rustynet-cli/src/vm_lab/orchestrator/stage/verify_ssh.rs",
        causes: &[
            "a VM is powered off or on the wrong (non-bridged) network → unreachable",
            "VM alive but SSH closed behind a stale nft killswitch → run recover_stuck_vms",
            "stale inventory IP → run update_inventory; then ensure_lab_ready",
        ],
    },
    StageInfo {
        name: "collect_pubkeys",
        aliases: &[],
        checks: "SSHes each peer and reads its WireGuard public key (needed before membership_init).",
        owning: "crates/rustynet-cli/src/vm_lab/orchestrator/stage/collect_pubkeys.rs",
        causes: &[
            "WireGuard not installed / interface not up on a node",
            "the daemon hasn't generated a key yet (bootstrap incomplete)",
            "SSH dropped mid-run (see verify_ssh causes)",
        ],
    },
    StageInfo {
        name: "enforce_runtime",
        aliases: &["enforce"],
        checks: "Starts the daemon on each peer so it ingests the distributed signed state.",
        owning: "crates/rustynet-cli/src/vm_lab/orchestrator/stage/enforce_runtime.rs",
        causes: &[
            "daemon fails to start / crashes on boot (check the node's daemon log)",
            "service unit not installed (bootstrap/install didn't complete)",
            "fail-closed: missing/invalid signed state so the daemon refuses to serve",
        ],
    },
    StageInfo {
        name: "active_exit",
        aliases: &["exit_route_advertise"],
        checks: "Windows active-exit promotion: advertises the default route and verifies egress through the exit.",
        owning: "crates/rustynet-cli/src/vm_lab/orchestrator/stage/active_exit.rs",
        causes: &[
            "Windows exit is fail-closed pending WinNAT/HNS live evidence (expected until promoted)",
            "route advertisement / NAT setup failed on the exit",
        ],
    },
    StageInfo {
        name: "cleanup",
        aliases: &["final_cleanup"],
        checks: "Final teardown and artifact collection after exit/role validation has completed.",
        owning: "crates/rustynet-cli/src/vm_lab/orchestrator/stage/final_cleanup.rs",
        causes: &[
            "cleanup command failed on a node",
            "artifact collection failed or report directory is not writable",
        ],
    },
    StageInfo {
        name: "validate_linux_membership_revoke_applies",
        aliases: &["membership_revoke_applies", "revoke_applies"],
        checks: "Drives rustynetd membership-revoke-audit on the Linux node: signs Revoke/RotateKey/Restore/SetCapabilities updates and applies them strictly later than signing, proving RSA-0009's fix (the reducer used to stamp apply-time instead of the signed record's own timestamp, so these four ops were rejected with NewStateRootMismatch and revocation/key-rotation were non-functional).",
        owning: "crates/rustynetd/src/membership_revoke_audit.rs (daemon audit); crates/rustynet-cli/src/vm_lab/mod.rs::evaluate_membership_revoke_audit_report (orchestrator validator)",
        causes: &[
            "RSA-0009 regressed: a delayed-apply case is rejected with NewStateRootMismatch again",
            "the 2 negative cases (tampered new_state_root, stale prev_state_root) stopped rejecting — state-root integrity weakened",
            "gated on validate_linux_runtime_acls passing first",
        ],
    },
    StageInfo {
        name: "validate_linux_revoked_peer_denied_e2e",
        aliases: &["revoked_peer_denied", "dd-03", "rsa-0007"],
        checks: "Drives rustynetd revoked-peer-denied-audit on the Linux node: builds a real Phase10Controller with a broad/wildcard ACL allow rule, then proves a REVOKED peer is denied at set_exit_node/ensure_lan_route_allowed (DD-03/RSA-0007's fix — these call sites used to evaluate ACLs membership-blind) while an ACTIVE peer in the identical scenario is still allowed (anti-vacuous baseline).",
        owning: "crates/rustynetd/src/revoked_peer_denied_audit.rs (daemon audit); crates/rustynet-cli/src/vm_lab/mod.rs::evaluate_revoked_peer_denied_report (orchestrator validator)",
        causes: &[
            "DD-03/RSA-0007 regressed: a revoked peer is granted exit-node or LAN-route access again",
            "the active-peer baseline case stopped being allowed — the ACL gate became over-broad/vacuous-deny",
            "gated on validate_linux_runtime_acls passing first",
        ],
    },
    StageInfo {
        name: "validate_linux_runtime_acls",
        aliases: &["runtime_acls"],
        checks: "Drives rustynetd linux-runtime-acls-check on the Linux node: walks the canonical Linux runtime roots (/etc/rustynet, /var/lib/rustynet, per scripts/systemd/rustynetd.service + scripts/e2e/live_lab_common.sh) and fails if any reviewed root is missing or its owner/group/mode has drifted from the reviewed posture.",
        owning: "crates/rustynetd/src/linux_runtime_acls.rs (daemon probe); crates/rustynet-cli/src/vm_lab/mod.rs::evaluate_linux_runtime_acls_report (orchestrator validator)",
        causes: &[
            "a reviewed root is missing, or its owner/group/mode drifted from the reviewed posture",
            "unsupported schema_version returned (daemon/orchestrator skew) or an empty roots list",
            "this stage gates most of the rest of the daemon-security-validator family — its failure cascades to make_skipped downstream",
        ],
    },
    StageInfo {
        name: "validate_linux_key_custody",
        aliases: &["key_custody"],
        checks: "Drives rustynetd linux-key-custody-check on the Linux node: confirms the encrypted WireGuard private key (/var/lib/rustynet/keys/wireguard.key.enc, 0600), the public key, and the keys directory (0700) all match the reviewed custody contract, and that the legacy plaintext private-key path is absent.",
        owning: "crates/rustynetd/src/linux_key_custody.rs (daemon probe); crates/rustynet-cli/src/vm_lab/mod.rs::evaluate_linux_key_custody_report (orchestrator validator)",
        causes: &[
            "a key artifact drifted from its reviewed owner/mode, or the plaintext legacy private-key path is present at rest",
            "unsupported schema_version returned",
            "gated on validate_linux_runtime_acls passing first",
        ],
    },
    StageInfo {
        name: "validate_linux_service_hardening",
        aliases: &["service_hardening"],
        checks: "Drives rustynetd linux-service-hardening-check on the Linux node: probes the installed systemd unit's hardening directives and fails if the probe couldn't run (systemctl show failed / unit not installed) or overall_ok is false.",
        owning: "crates/rustynetd/src/linux_service_hardening.rs (daemon probe); crates/rustynet-cli/src/vm_lab/mod.rs::evaluate_linux_service_hardening_report (orchestrator validator)",
        causes: &[
            "probe could not run (systemctl show failed, unit not installed)",
            "a hardening directive drifted from the shipped unit file",
            "gated on validate_linux_runtime_acls passing first",
        ],
    },
    StageInfo {
        name: "validate_linux_authenticode",
        aliases: &["authenticode"],
        checks: "Drives rustynetd linux-authenticode-check on the Linux node. Linux has no runtime binary-signature enforcement (that's Windows-specific), so the daemon always reports applicable=false; the validator passes the not-applicable verdict through honestly rather than silently passing, and only fails if a future dpkg/rpm-signature slice flips applicable=true with overall_ok=false.",
        owning: "crates/rustynetd/src/linux_authenticode.rs (daemon probe); crates/rustynet-cli/src/vm_lab/mod.rs::evaluate_linux_authenticode_report (orchestrator validator)",
        causes: &[
            "unsupported schema_version returned",
            "a future dpkg/rpm signature-verification slice reports applicable=true, overall_ok=false",
            "gated on validate_linux_runtime_acls passing first",
        ],
    },
    StageInfo {
        name: "validate_linux_privileged_helper_allowlist",
        aliases: &["privileged_helper_allowlist"],
        checks: "Drives rustynetd privileged-helper-allowlist-audit on the Linux node: runs an adversarial request corpus through the REAL argv allowlist (SecurityMinimumBar.md §7) and fails if any adversarial request was accepted (privilege-escalation regression) or any reviewed request was rejected (control-plane breakage).",
        owning: "crates/rustynetd/src/privileged_helper_allowlist_audit.rs (daemon audit); crates/rustynet-cli/src/vm_lab/mod.rs::evaluate_privileged_helper_allowlist_report (orchestrator validator)",
        causes: &[
            "an adversarial request was accepted by the allowlist (privilege-escalation regression)",
            "a reviewed/benign request was rejected (control-plane breakage)",
            "gated on validate_linux_runtime_acls passing first",
        ],
    },
    StageInfo {
        name: "validate_linux_membership_signature_forgery",
        aliases: &["membership_signature_forgery"],
        checks: "Drives rustynetd membership-signature-audit on the Linux node: runs an adversarial forgery corpus through the REAL signed-membership verify funnel (apply_signed_update/decode_signed_update, verify_strict; SecurityMinimumBar.md §3.2/§6.B) and fails on an accepted forgery, a rejected valid baseline, or too small/vacuous a corpus.",
        owning: "crates/rustynetd/src/membership_signature_audit.rs (daemon audit); crates/rustynet-cli/src/vm_lab/mod.rs::evaluate_membership_signature_audit_report (orchestrator validator)",
        causes: &[
            "a forged/tampered membership update was accepted",
            "the valid baseline update was rejected, or the corpus was too small/vacuous to be meaningful",
            "gated on validate_linux_runtime_acls passing first",
        ],
    },
    StageInfo {
        name: "validate_linux_policy_default_deny",
        aliases: &["policy_default_deny"],
        checks: "Drives rustynetd policy-default-deny-audit on the Linux node: runs a default-deny truth table through the REAL rustynet_policy evaluator (SecurityMinimumBar.md §3.6) and fails on an empty/vacuous corpus (no ALLOW case exercised) or any case whose decision didn't match expectation.",
        owning: "crates/rustynetd/src/policy_default_deny_audit.rs (daemon audit); crates/rustynet-cli/src/vm_lab/mod.rs::evaluate_policy_default_deny_report (orchestrator validator)",
        causes: &[
            "a case's decision didn't match its expected ALLOW/DENY outcome",
            "empty corpus, or no ALLOW case exercised (the vacuous deny-all pass)",
            "gated on validate_linux_runtime_acls passing first",
        ],
    },
    StageInfo {
        name: "validate_linux_membership_genesis",
        aliases: &["membership_genesis"],
        checks: "SSHes the Linux node directly (no rustynetd subcommand) and asserts the canonical membership files (membership.snapshot/.log/.watermark under /var/lib/rustynet) exist with mode 600 owned by rustynetd:rustynetd, then runs `rustynet membership status` against them and confirms it reports a readable signed snapshot (network_id/epoch/active_nodes present).",
        owning: "crates/rustynet-cli/src/vm_lab/mod.rs::exercise_linux_membership_genesis_validation + validate_linux_membership_genesis_output",
        causes: &[
            "a membership file has drifted from mode 600 / rustynetd:rustynetd ownership",
            "`rustynet membership status` output doesn't prove a readable signed snapshot",
            "gated on validate_linux_runtime_acls and validate_linux_key_custody passing first",
        ],
    },
    StageInfo {
        name: "validate_linux_mesh_status",
        aliases: &["mesh_status"],
        checks: "Drives rustynetd linux-mesh-status-check on the Linux node (optionally with --state-path/--expected-peer-id/--max-age-seconds overrides) and fails if overall_ok=false, surfacing the reported drift_reasons.",
        owning: "crates/rustynetd/src/linux_mesh_status.rs (daemon probe); crates/rustynet-cli/src/vm_lab/mod.rs::evaluate_linux_mesh_status_report (orchestrator validator)",
        causes: &[
            "mesh status reports drift (e.g. missing expected peer, stale state)",
            "unsupported schema_version returned",
            "gated on validate_linux_runtime_acls passing first",
        ],
    },
    StageInfo {
        name: "validate_linux_blind_exit_reversal_denied",
        aliases: &["blind_exit_reversal_denied", "rt-2"],
        checks: "Drives rustynetd blind-exit-reversal-audit on the Linux node: runs an adversarial corpus of SetNodeCapabilities updates through the REAL preview_next_state/reduce_membership_state funnel, proving RT-2's fix (blind_exit is immutable at the signed-state layer — reversing it away requires factory reset + fresh enrollment, not just a signed capability update) against client/admin/exit/relay/anchor/nas/llm reversal targets, plus a baseline case proving a non-blind_exit node's capabilities can still be changed.",
        owning: "crates/rustynet-control/src/membership.rs::reduce_membership_state (fix); crates/rustynetd/src/blind_exit_reversal_audit.rs (daemon audit); crates/rustynet-cli/src/vm_lab/mod.rs::evaluate_blind_exit_reversal_report (orchestrator validator)",
        causes: &[
            "RT-2 regressed: a SetNodeCapabilities update reversing blind_exit away from a node was accepted",
            "the non-blind_exit baseline case stopped being accepted — the guard became over-broad",
            "gated on validate_linux_runtime_acls passing first",
        ],
    },
    StageInfo {
        name: "validate_linux_gossip_revoked_readmit",
        aliases: &["gossip_revoked_readmit", "gm-1", "rsa-0034"],
        checks: "Drives rustynetd gossip-revoked-readmit-audit on the Linux node: builds a real GossipNode with synthetic Ed25519 keys and a loopback transport, proving GM-1's fix (ingest_inbound_bundle now checks signed membership status, not just routing/verification state, before admitting a bundle) — a bundle from a peer marked Revoked in membership is denied, while the identical scenario with an Active peer is still accepted (anti-vacuous baseline).",
        owning: "crates/rustynetd/src/gossip_runtime.rs::ingest_inbound_bundle (fix); crates/rustynetd/src/gossip_revoked_readmit_audit.rs (daemon audit); crates/rustynet-cli/src/vm_lab/mod.rs::evaluate_gossip_revoked_readmit_report (orchestrator validator)",
        causes: &[
            "GM-1/RSA-0034 regressed: a bundle from a revoked peer was admitted again",
            "the active-peer baseline case stopped being accepted — the guard became over-broad/vacuous-deny",
            "gossip is a wired-but-not-yet-daemon-integrated subsystem (no production call sites for attach_gossip_runtime yet)",
        ],
    },
    StageInfo {
        name: "validate_linux_enrollment_replay",
        aliases: &["enrollment_replay", "enr-1", "toctou-1", "rsa-0023"],
        checks: "Drives rustynetd enrollment-replay-audit on the Linux node: drives the REAL enrollment-token consume path (acquire_ledger_lock -> load_ledger -> verify_and_consume_token_with_now -> write_ledger) against a throwaway on-disk ledger, proving ENR-1 (sequential replay of the same token is denied with AlreadyConsumed) and TOCTOU-1 (8 threads racing to redeem the same token yield exactly one winner), plus a baseline case proving two distinct tokens can both be redeemed.",
        owning: "crates/rustynetd/src/enrollment_token.rs::acquire_ledger_lock (RSA-0023 fix, pre-existing); crates/rustynetd/src/enrollment_replay_audit.rs (daemon audit); crates/rustynet-cli/src/vm_lab/mod.rs::evaluate_enrollment_replay_report (orchestrator validator)",
        causes: &[
            "ENR-1 regressed: sequential replay of the same token succeeded twice",
            "TOCTOU-1 regressed: concurrent racers double-spent the single-use token (lock no longer serializes the read-modify-write)",
            "the distinct-tokens baseline case stopped being accepted — the guard became over-broad",
        ],
    },
    StageInfo {
        name: "validate_linux_hello_limiter_flood",
        aliases: &["hello_limiter_flood", "dos-1", "rsa-0037"],
        checks: "Drives rustynet-relay hello-limiter-audit on the Linux node: floods the REAL HelloLimiter (relay's pre-auth Hello rate limiter) with MAX_HELLO_LIMITER_ENTRIES distinct node_id strings, proving DOS-1/RSA-0037's fix (the map is hard-capped and prunes-then-rejects a new node_id once at capacity) — one more node_id beyond the cap is denied, while a baseline case on a fresh limiter proves a single legitimate node_id's first hello is still allowed.",
        owning: "crates/rustynet-relay/src/transport.rs::HelloLimiter (fix, pre-existing); crates/rustynet-relay/src/hello_limiter_audit.rs (daemon audit); crates/rustynet-cli/src/vm_lab/mod.rs::evaluate_hello_limiter_flood_report (orchestrator validator)",
        causes: &[
            "DOS-1/RSA-0037 regressed: a node_id beyond MAX_HELLO_LIMITER_ENTRIES was admitted, growing the map without bound",
            "the single-node baseline case stopped being accepted — the guard became over-broad/vacuous-deny",
            "this stage targets the rustynet-relay binary, not rustynetd — no validate_linux_runtime_acls gating",
        ],
    },
    StageInfo {
        name: "validate_linux_relay_forwards_frame",
        aliases: &["relay_forwards_frame", "hp3", "rpt-01"],
        checks: "HP-3: forces two spare Linux peers onto a relay-only path (firewalls their direct UDP with a dedicated nft table, restarts both daemons to force fresh traversal negotiation, polls each peer's own `rustynet status` until both independently report a relay-routed session), sends a real marked ICMP payload between them, then asserts the relay's own forwarded-frame/byte counters (rustynet-relay's ForwardStats, exposed via /healthz+/metrics) increased AND a tcpdump capture on the relay's own wire never contained the plaintext marker (RPT-01, ciphertext-only). Always cleans up the firewall block and restarts both daemons back to normal, pass or fail.",
        owning: "crates/rustynet-relay/src/main.rs::ForwardStats/record_forward (forwarding counter); crates/rustynet-cli/src/vm_lab/mod.rs::exercise_linux_relay_forwards_frame (orchestrator validator)",
        causes: &[
            "the relay's forwarded-frame/byte counters did not increase after a real marked ping between the two firewalled peers",
            "the relay's own captured wire traffic contained the plaintext marker — ciphertext-only property violated",
            "neither peer's own `rustynet status` ever reported a relay-routed session within the traversal timeout",
            "gated on validate_linux_runtime_acls passing first",
        ],
    },
];

// `aliases` are &'static str but `norm` is borrowed from a local, so
// slice::contains() does not typecheck here — iter().any() is required.
#[allow(clippy::manual_contains)]
fn explain_stage(stage: &str) -> ToolCallResult {
    if stage.trim().is_empty() {
        return tool_error("Missing required parameter: stage");
    }
    let lower = stage.trim().to_lowercase();
    let norm = lower
        .strip_prefix("linux_stage_")
        .or_else(|| lower.strip_prefix("macos_stage_"))
        .or_else(|| lower.strip_prefix("windows_stage_"))
        .unwrap_or(lower.as_str());

    let found = STAGE_INFO
        .iter()
        .find(|s| s.name == norm || s.aliases.iter().any(|a| *a == norm));

    match found {
        Some(s) => {
            let mut out = format!(
                "# Stage: {}\n\n- **What it checks:** {}\n- **Owning file:** `{}`\n\n## Common failure causes\n",
                s.name, s.checks, s.owning
            );
            for c in s.causes {
                out.push_str(&format!("- {c}\n"));
            }
            out.push_str(&format!(
                "\n## Next\nRead the failing node's log (read_report_artifact / tail_job_log), then `which_crate` on `{}` (repo-context) for the boundary rules before patching the root cause.\n",
                s.owning
            ));
            out.push_str(
                "\n## Re-verify a code fix WITHOUT redoing the whole lab\nThere is no mid-stage resume. The efficient path: start_live_lab_run mode=orchestrate with your full `nodes` topology + `rebuild_nodes=[<the failing node>]` + `skip_soak=true` — redeploys ONLY the patched node (others keep their daemon/state), replays the stage sequence (cheap), skips the slow soak. (Redeploying a node resets its distributed state, so its setup stages must replay — that's why you can't skip them.) If this was a SETUP stage and no test stage ran yet, mode=setup `resume_from=prepare_source_archive` also redeploys + continues.\n",
            );
            tool_success(&out)
        }
        None => {
            let known: Vec<&str> = STAGE_INFO.iter().map(|s| s.name).collect();
            tool_success(&format!(
                "# Unknown stage: `{stage}`\n\nNo entry for `{norm}`. Known stages:\n{}\n\n(linux_/macos_/windows_stage_ prefixes are stripped automatically; check get_orchestrator_stages in repo-context for the full ordered list.)\n",
                known
                    .iter()
                    .map(|k| format!("- {k}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ))
        }
    }
}

// ── seed_cargo_cache: keep the UTM guests' offline cargo registry in sync ──
//
// When the workspace Cargo.lock changes (a dependency added/bumped), every
// guest's offline registry goes stale and `cargo build --offline` fails with
// `error: no matching package` / `failed to download from
// https://index.crates.io/...`. This seeds the crates.io packages the lock
// names — the `.crate` blob + the sparse-index `.cache` entry — from the HOST's
// warm `~/.cargo/registry` into each guest's registry root, so the offline
// build resolves again. All ssh/scp is argv-only via run_with_timeout; the only
// caller-influenced values are crate names/versions parsed from the LOCAL lock,
// and each is validated against `^[A-Za-z0-9_.+-]+$` before it touches a path
// or command.

/// One crates.io package from the workspace lock.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LockCrate {
    name: String,
    version: String,
}

/// A crate name/version token is safe to embed in a registry path or a guest-side
/// probe only if it matches this conservative charset. crates.io names are
/// `[A-Za-z0-9_-]` and semver versions add `.` and `+`; anything else (slashes,
/// spaces, shell metacharacters, control chars) is rejected — fail closed.
fn is_safe_crate_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'+' | b'-'))
}

/// Parse the `[[package]]` blocks of a Cargo.lock and return only the packages
/// whose `source` is the crates.io registry (either the git-index legacy form
/// `registry+https://github.com/rust-lang/crates.io-index` or the sparse form
/// `sparse+https://index.crates.io/`). Packages with NO `source` (workspace /
/// path crates) and packages with any other source (git deps, alternate
/// registries) are skipped — those are never in the crates.io offline cache.
///
/// Minimal hand parser (no new dependency): the lock is `@generated`, so each
/// block is `[[package]]` then `key = "value"` lines until a blank line or the
/// next block. Tokens that fail `is_safe_crate_token` are dropped (defensive;
/// a real `@generated` lock never produces them).
fn parse_lock_registry_crates(lock: &str) -> Vec<LockCrate> {
    const CRATES_IO_GIT: &str = "registry+https://github.com/rust-lang/crates.io-index";
    const CRATES_IO_SPARSE: &str = "sparse+https://index.crates.io/";

    let mut out = Vec::new();
    let mut in_pkg = false;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut source: Option<String> = None;

    // Flush the block we just finished reading.
    let flush = |name: &mut Option<String>,
                 version: &mut Option<String>,
                 source: &mut Option<String>,
                 out: &mut Vec<LockCrate>| {
        let is_crates_io = matches!(
            source.as_deref(),
            Some(CRATES_IO_GIT) | Some(CRATES_IO_SPARSE)
        );
        if is_crates_io
            && let (Some(n), Some(v)) = (name.as_ref(), version.as_ref())
            && is_safe_crate_token(n)
            && is_safe_crate_token(v)
        {
            out.push(LockCrate {
                name: n.clone(),
                version: v.clone(),
            });
        }
        *name = None;
        *version = None;
        *source = None;
    };

    for line in lock.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if in_pkg {
                flush(&mut name, &mut version, &mut source, &mut out);
            }
            in_pkg = true;
            continue;
        }
        if !in_pkg {
            continue;
        }
        // A new top-level table (e.g. `[[patch.unused]]` or `[metadata]`) ends
        // the package section; flush and stop treating lines as package fields.
        if trimmed.starts_with('[') && trimmed != "[[package]]" {
            flush(&mut name, &mut version, &mut source, &mut out);
            in_pkg = false;
            continue;
        }
        if let Some(v) = lock_str_field(trimmed, "name") {
            name = Some(v);
        } else if let Some(v) = lock_str_field(trimmed, "version") {
            version = Some(v);
        } else if let Some(v) = lock_str_field(trimmed, "source") {
            source = Some(v);
        }
    }
    if in_pkg {
        flush(&mut name, &mut version, &mut source, &mut out);
    }
    out
}

/// Extract the value of a `key = "value"` line (returns None for any other line,
/// including the `dependencies = [` array opener and `checksum`).
fn lock_str_field(line: &str, key: &str) -> Option<String> {
    let rest = line.strip_prefix(key)?.trim_start();
    let rest = rest.strip_prefix('=')?.trim();
    let inner = rest.strip_prefix('"')?.strip_suffix('"')?;
    Some(inner.to_string())
}

/// Sparse-index `.cache` shard path for a crate name, relative to the index
/// `<hash>/.cache/` dir. Cargo lowercases the name and shards by length:
/// len 1 → `1/<n>`, len 2 → `2/<n>`, len 3 → `3/<n[0]>/<n>`,
/// len ≥4 → `<n[0..2]>/<n[2..4]>/<n>`. (ureq → `ur/eq/ureq`,
/// rustls → `ru/st/rustls`, url → `3/u/url`, ab → `2/ab`, a → `1/a`.)
fn index_shard_path(name: &str) -> String {
    let n = name.to_ascii_lowercase();
    let bytes = n.as_bytes();
    match bytes.len() {
        0 => n,
        1 => format!("1/{n}"),
        2 => format!("2/{n}"),
        3 => format!("3/{}/{n}", &n[0..1]),
        _ => format!("{}/{}/{n}", &n[0..2], &n[2..4]),
    }
}

/// The two host-relative registry paths for one crate, relative to
/// `~/.cargo/registry`:
///   - `.crate` blob:  `cache/<hash>/<name>-<version>.crate`
///   - sparse index:   `index/<hash>/.cache/<shard>`
///
/// The shard path returned by [`index_shard_path`] already ends in the
/// lowercased crate name (e.g. `ur/eq/ureq`), and the index entry IS that file
/// — there is no extra `/<name>` component. (Verified against a real
/// `~/.cargo/registry/index/<hash>/.cache` tree: `serde` lives at
/// `.cache/se/rd/serde`, `url` at `.cache/3/u/url`.)
fn crate_registry_paths(hash: &str, c: &LockCrate) -> (String, String) {
    let crate_path = format!("cache/{hash}/{}-{}.crate", c.name, c.version);
    let index_path = format!("index/{hash}/.cache/{}", index_shard_path(&c.name));
    (crate_path, index_path)
}

/// Given the set of lock crates and a presence map (key = a registry-relative
/// path, value = present?), the crates whose `.crate` OR index entry is missing.
/// A crate counts as present only when BOTH its blob and its index entry exist.
fn missing_crates_from_presence(
    hash: &str,
    crates: &[LockCrate],
    present: &std::collections::HashMap<String, bool>,
) -> Vec<LockCrate> {
    crates
        .iter()
        .filter(|c| {
            let (cp, ip) = crate_registry_paths(hash, c);
            !(present.get(&cp).copied().unwrap_or(false)
                && present.get(&ip).copied().unwrap_or(false))
        })
        .cloned()
        .collect()
}

/// Detect the sparse-index `<hash>` dir name (e.g.
/// `index.crates.io-1949cf8c6b5b557f`) under a registry root by listing its
/// `cache/` subdir. The same hash names the `index/` subdir. The host and every
/// guest share the same hash for the same cargo, so a per-target detection
/// keeps the tool correct even if a future cargo changes the hash.
fn detect_registry_hash(cache_dir: &Path) -> Option<String> {
    let mut found: Option<String> = None;
    for entry in std::fs::read_dir(cache_dir).ok()?.flatten() {
        if entry.path().is_dir()
            && let Some(name) = entry.file_name().to_str()
            && name.starts_with("index.crates.io-")
        {
            // Prefer a unique hit; if several exist, the first deterministically
            // sorted is taken (read_dir order is not sorted, so sort).
            match &found {
                Some(prev) if prev.as_str() <= name => {}
                _ => found = Some(name.to_string()),
            }
        }
    }
    found
}

impl LabStateServer {
    /// Host registry root (`~/.cargo/registry`), honoring CARGO_HOME.
    fn host_registry_root(&self) -> PathBuf {
        if let Ok(home) = std::env::var("CARGO_HOME") {
            PathBuf::from(home).join("registry")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".cargo").join("registry")
        } else {
            PathBuf::from(".cargo").join("registry")
        }
    }

    /// `cargo fetch --locked` in the repo root to populate `~/.cargo/registry`
    /// from the lock — used when some lock crates are not yet on the host.
    fn cargo_fetch_locked(&self) -> Result<(), String> {
        let outcome = run_with_timeout(
            "cargo",
            &["fetch", "--locked"],
            &self.repo_root,
            &[("CARGO_TERM_COLOR", "never")],
            Duration::from_secs(600),
        )?;
        if outcome.success {
            Ok(())
        } else {
            Err(format!(
                "cargo fetch --locked failed (exit {}): {}",
                outcome
                    .code
                    .map(|c| c.to_string())
                    .unwrap_or("killed".into()),
                truncate_tail(outcome.stderr.trim(), 12, 2_000)
            ))
        }
    }

    /// Resolve an inventory alias → (ssh_target, ssh_user, platform). Only
    /// entries that have an ssh_target are returned (path/aux LAN entries do).
    fn alias_to_ssh(&self, alias: &str) -> Option<(String, String, String)> {
        let s = std::fs::read_to_string(self.repo_root.join(DEFAULT_INVENTORY)).ok()?;
        let inv: Value = serde_json::from_str(&s).ok()?;
        inv.get("entries")?.as_array()?.iter().find_map(|e| {
            if e.get("alias").and_then(|v| v.as_str()) != Some(alias) {
                return None;
            }
            let target = e.get("ssh_target").and_then(|v| v.as_str())?.to_string();
            let user = e
                .get("ssh_user")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let platform = e
                .get("platform")
                .and_then(|v| v.as_str())
                .unwrap_or("linux")
                .to_string();
            Some((target, user, platform))
        })
    }

    /// Every "execution" guest alias: an inventory entry that has both a
    /// `controller.utm_name` (a real lab VM, not a bare LAN device) and an
    /// `ssh_target`. This is the default node set for seed_cargo_cache.
    fn execution_guest_aliases(&self) -> Vec<String> {
        let Ok(s) = std::fs::read_to_string(self.repo_root.join(DEFAULT_INVENTORY)) else {
            return Vec::new();
        };
        let Ok(inv) = serde_json::from_str::<Value>(&s) else {
            return Vec::new();
        };
        inv.get("entries")
            .and_then(|v| v.as_array())
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| {
                        e.get("controller")
                            .and_then(|c| c.get("utm_name"))
                            .is_some()
                            && e.get("ssh_target").and_then(|v| v.as_str()).is_some()
                    })
                    .filter_map(|e| e.get("alias").and_then(|v| v.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Shared ssh -o option block (key auth, strict host keys, batch mode) —
    /// mirrors the orchestrator's transport options. Returned as owned strings so
    /// the identity/known-hosts paths can be borrowed into the argv.
    fn ssh_transport_opts(&self) -> Vec<String> {
        let mut opts: Vec<String> = vec![
            "-o".into(),
            "LogLevel=ERROR".into(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "StrictHostKeyChecking=yes".into(),
            "-o".into(),
            "ConnectTimeout=15".into(),
            "-o".into(),
            "IdentitiesOnly=yes".into(),
            "-i".into(),
            default_ssh_identity(),
        ];
        let kh = default_known_hosts();
        if Path::new(&kh).exists() {
            opts.push("-o".into());
            opts.push(format!("UserKnownHostsFile={kh}"));
        }
        opts
    }

    /// One ssh exec to a guest: runs `remote_script` (a complete shell/PowerShell
    /// program string passed as a single argv element — never built from
    /// untrusted values). `user@target` form.
    fn ssh_exec(
        &self,
        target: &str,
        user: &str,
        remote_script: &str,
        timeout: Duration,
    ) -> Result<CommandOutcome, String> {
        let opts = self.ssh_transport_opts();
        let dest = if user.is_empty() {
            target.to_string()
        } else {
            format!("{user}@{target}")
        };
        let mut argv: Vec<&str> = vec!["-n"];
        argv.extend(opts.iter().map(String::as_str));
        argv.push("--");
        argv.push(&dest);
        argv.push(remote_script);
        run_with_timeout("ssh", &argv, &self.repo_root, &[], timeout)
    }

    /// scp a local file to `user@target:dst`.
    fn scp_to(
        &self,
        target: &str,
        user: &str,
        local: &Path,
        dst: &str,
        timeout: Duration,
    ) -> Result<CommandOutcome, String> {
        let opts = self.ssh_transport_opts();
        let dest = if user.is_empty() {
            format!("{target}:{dst}")
        } else {
            format!("{user}@{target}:{dst}")
        };
        let local_str = local.to_string_lossy().to_string();
        let mut argv: Vec<&str> = vec!["-q"];
        argv.extend(opts.iter().map(String::as_str));
        argv.push("--");
        argv.push(&local_str);
        argv.push(&dest);
        run_with_timeout("scp", &argv, &self.repo_root, &[], timeout)
    }

    /// Main tool entry: seed every target guest's offline cargo registry with the
    /// crates.io packages named by the workspace lock so `cargo build --offline`
    /// resolves after a Cargo.lock change.
    fn seed_cargo_cache(&self, args: Option<&Value>) -> ToolCallResult {
        // 1) Parse the lock.
        let lock_path = match arg_str(args, "cargo_lock_path") {
            Some(p) if !p.trim().is_empty() => PathBuf::from(p),
            _ => self.repo_root.join("Cargo.lock"),
        };
        let lock_text = match std::fs::read_to_string(&lock_path) {
            Ok(t) => t,
            Err(e) => {
                return tool_error(&format!(
                    "cannot read Cargo.lock {}: {e}",
                    lock_path.display()
                ));
            }
        };
        let crates = parse_lock_registry_crates(&lock_text);
        if crates.is_empty() {
            return tool_error(&format!(
                "no crates.io registry packages found in {} (path/git-only lock?)",
                lock_path.display()
            ));
        }
        let dry_run = arg_bool(args, "dry_run");

        // 2) Detect the host registry hash + ensure the host has the blobs;
        //    `cargo fetch --locked` if any are missing, then recompute.
        let host_root = self.host_registry_root();
        let host_cache = host_root.join("cache");
        let mut host_hash = match detect_registry_hash(&host_cache) {
            Some(h) => h,
            None => {
                // No registry yet — fetch to create it.
                if let Err(e) = self.cargo_fetch_locked() {
                    return tool_error(&format!(
                        "host has no cargo registry and cargo fetch failed: {e}"
                    ));
                }
                match detect_registry_hash(&host_cache) {
                    Some(h) => h,
                    None => {
                        return tool_error(
                            "could not detect host cargo registry hash even after cargo fetch",
                        );
                    }
                }
            }
        };
        let mut host_missing = self.host_missing_crates(&host_root, &host_hash, &crates);
        if !host_missing.is_empty() {
            // Try one fetch to fill the gaps, then recompute (hash may have been
            // created/extended by the fetch).
            if let Err(e) = self.cargo_fetch_locked() {
                return tool_error(&format!(
                    "{} lock crate(s) missing on host and cargo fetch failed: {e}",
                    host_missing.len()
                ));
            }
            if let Some(h) = detect_registry_hash(&host_cache) {
                host_hash = h;
            }
            host_missing = self.host_missing_crates(&host_root, &host_hash, &crates);
        }
        let host_missing_names: Vec<String> = host_missing
            .iter()
            .map(|c| format!("{}-{}", c.name, c.version))
            .collect();

        // 3) Resolve target nodes.
        let requested = string_array(args, "nodes");
        let nodes: Vec<String> = if requested.is_empty() {
            self.execution_guest_aliases()
        } else {
            requested
        };
        if nodes.is_empty() {
            return tool_error(
                "no target nodes (empty `nodes` and no execution guests in the inventory)",
            );
        }

        let mut node_reports: Vec<Value> = Vec::new();
        let mut text = format!(
            "# seed_cargo_cache\n\n- lock: `{}`\n- crates.io registry crates in lock: **{}**\n- host registry hash: `{host_hash}`\n",
            lock_path.display(),
            crates.len()
        );
        if !host_missing_names.is_empty() {
            text.push_str(&format!(
                "- ⚠️ {} lock crate(s) MISSING ON HOST even after `cargo fetch` (cannot be seeded): {}\n",
                host_missing_names.len(),
                truncate_output(&host_missing_names.join(", "), 1, 800)
            ));
        }
        if dry_run {
            text.push_str("- mode: **DRY RUN** (probe only, nothing shipped)\n");
        }
        text.push('\n');

        // 4) Per node.
        for alias in &nodes {
            let report = self.seed_node(
                alias,
                &crates,
                &host_root,
                &host_hash,
                &host_missing,
                dry_run,
            );
            let ok = report.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
            let verdict = if dry_run {
                "DRY"
            } else if ok {
                "PASS"
            } else {
                "FAIL"
            };
            let os = report.get("os").and_then(|v| v.as_str()).unwrap_or("?");
            let before = report
                .get("missing_before")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let seeded = report.get("seeded").and_then(|v| v.as_u64()).unwrap_or(0);
            let after = report
                .get("missing_after")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let note = report.get("error").and_then(|v| v.as_str()).unwrap_or("");
            text.push_str(&format!(
                "## {verdict} — `{alias}` ({os})\n- missing_before: {before}\n- seeded: {seeded}\n- missing_after: {after}\n"
            ));
            if !note.is_empty() {
                text.push_str(&format!("- note: {note}\n"));
            }
            text.push('\n');
            node_reports.push(report);
        }

        let all_ok = dry_run
            || node_reports
                .iter()
                .all(|r| r.get("ok").and_then(|v| v.as_bool()).unwrap_or(false));
        text.push_str(if all_ok {
            "**Result: all target nodes resolved (0 missing after seeding).**\n"
        } else {
            "**Result: at least one node still has missing crates — see FAIL nodes above.**\n"
        });

        let summary = json!({
            "lock_path": lock_path.to_string_lossy(),
            "lock_registry_crate_count": crates.len(),
            "host_registry_hash": host_hash,
            "host_missing": host_missing_names,
            "dry_run": dry_run,
            "all_ok": all_ok,
            "nodes": node_reports,
        });
        text.push_str(&format!(
            "\n<details><summary>structured</summary>\n\n```json\n{}\n```\n</details>\n",
            serde_json::to_string_pretty(&summary).unwrap_or_default()
        ));

        ToolCallResult {
            content: text_content(text),
            is_error: if all_ok { None } else { Some(true) },
        }
    }

    /// Which lock crates are absent from the HOST registry (blob OR index entry).
    fn host_missing_crates(
        &self,
        host_root: &Path,
        hash: &str,
        crates: &[LockCrate],
    ) -> Vec<LockCrate> {
        crates
            .iter()
            .filter(|c| {
                let (cp, ip) = crate_registry_paths(hash, c);
                !(host_root.join(&cp).exists() && host_root.join(&ip).exists())
            })
            .cloned()
            .collect()
    }

    /// Seed one node. Returns a structured per-node report (always; failures are
    /// reported via `ok=false` + `error`, never a panic).
    fn seed_node(
        &self,
        alias: &str,
        crates: &[LockCrate],
        host_root: &Path,
        host_hash: &str,
        host_missing: &[LockCrate],
        dry_run: bool,
    ) -> Value {
        let mut base = json!({
            "alias": alias,
            "os": "?",
            "registry_hash": Value::Null,
            "lock_registry_crate_count": crates.len(),
            "missing_before": 0,
            "seeded": 0,
            "missing_after": 0,
            "ok": false,
        });
        let set_err = |mut v: Value, msg: String| -> Value {
            v["error"] = Value::String(msg);
            v
        };

        let Some((target, user, platform)) = self.alias_to_ssh(alias) else {
            return set_err(
                base,
                format!("alias '{alias}' not in inventory or has no ssh_target"),
            );
        };
        let os = if platform.eq_ignore_ascii_case("windows") {
            "windows"
        } else if platform.eq_ignore_ascii_case("macos") {
            "macos"
        } else {
            "linux"
        };
        base["os"] = Value::String(os.to_string());
        let is_windows = os == "windows";

        // Guest registry root + hash.
        let guest_root = if is_windows {
            r"C:\CargoHome\registry".to_string()
        } else {
            "$HOME/.cargo/registry".to_string()
        };
        let guest_hash = match self.detect_guest_hash(&target, &user, is_windows) {
            Ok(Some(h)) => h,
            Ok(None) => host_hash.to_string(), // empty guest registry → use host hash
            Err(e) => return set_err(base, format!("hash detection failed: {e}")),
        };
        base["registry_hash"] = Value::String(guest_hash.clone());

        // Probe which lock crates are missing on the guest.
        let probe = match self.probe_guest_missing(&target, &user, is_windows, &guest_hash, crates)
        {
            Ok(p) => p,
            Err(e) => return set_err(base, format!("missing-probe failed: {e}")),
        };
        let missing_before = missing_crates_from_presence(&guest_hash, crates, &probe);
        base["missing_before"] = json!(missing_before.len());

        if dry_run {
            base["ok"] = json!(true);
            if !missing_before.is_empty() {
                let sample: Vec<String> = missing_before
                    .iter()
                    .take(8)
                    .map(|c| format!("{}-{}", c.name, c.version))
                    .collect();
                base["sample_missing"] = json!(sample);
            }
            return base;
        }

        // Only ship files the host actually has (skip host-missing crates).
        let host_missing_set: std::collections::HashSet<(String, String)> = host_missing
            .iter()
            .map(|c| (c.name.clone(), c.version.clone()))
            .collect();
        let to_ship: Vec<LockCrate> = missing_before
            .iter()
            .filter(|c| !host_missing_set.contains(&(c.name.clone(), c.version.clone())))
            .cloned()
            .collect();

        if !to_ship.is_empty()
            && let Err(e) = self.ship_crates(
                &target,
                &user,
                is_windows,
                host_root,
                &guest_hash,
                &guest_root,
                &to_ship,
            )
        {
            return set_err(base, format!("ship failed: {e}"));
        }
        base["seeded"] = json!(to_ship.len());

        // Re-probe to verify.
        let probe2 = match self.probe_guest_missing(&target, &user, is_windows, &guest_hash, crates)
        {
            Ok(p) => p,
            Err(e) => return set_err(base, format!("verify-probe failed: {e}")),
        };
        let missing_after = missing_crates_from_presence(&guest_hash, crates, &probe2);
        base["missing_after"] = json!(missing_after.len());
        base["ok"] = json!(missing_after.is_empty());
        if !missing_after.is_empty() {
            let still: Vec<String> = missing_after
                .iter()
                .take(8)
                .map(|c| format!("{}-{}", c.name, c.version))
                .collect();
            // Distinguish host-missing (unseedable) from a real ship failure.
            let host_blocked = missing_after
                .iter()
                .filter(|c| host_missing_set.contains(&(c.name.clone(), c.version.clone())))
                .count();
            base["error"] = Value::String(format!(
                "{} still missing after seeding ({host_blocked} of them missing on host, unseedable); sample: {}",
                missing_after.len(),
                still.join(", ")
            ));
        }
        base
    }

    /// Detect the guest's registry `<hash>` by listing its `cache/` dir. Returns
    /// `Ok(None)` when the guest has no registry cache yet (fresh guest).
    fn detect_guest_hash(
        &self,
        target: &str,
        user: &str,
        is_windows: bool,
    ) -> Result<Option<String>, String> {
        // Static scripts — no interpolation of any caller value.
        let script = if is_windows {
            // PowerShell: list cache subdirs, print one name per line.
            "if (Test-Path 'C:\\CargoHome\\registry\\cache') { Get-ChildItem -Directory 'C:\\CargoHome\\registry\\cache' | ForEach-Object { $_.Name } }"
        } else {
            "ls -1 \"$HOME/.cargo/registry/cache\" 2>/dev/null || true"
        };
        let out = self.ssh_exec(target, user, script, Duration::from_secs(30))?;
        // Don't hard-fail on nonzero (a missing dir is normal); parse stdout.
        let hash = out
            .stdout
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("index.crates.io-"))
            .max()
            .map(String::from);
        Ok(hash)
    }

    /// Probe presence of every lock crate's blob + index entry on the guest in
    /// ONE ssh round-trip: stream the relative paths on stdin, the guest emits
    /// `1 <path>` / `0 <path>` per line. Returns a path→present map.
    fn probe_guest_missing(
        &self,
        target: &str,
        user: &str,
        is_windows: bool,
        hash: &str,
        crates: &[LockCrate],
    ) -> Result<std::collections::HashMap<String, bool>, String> {
        // Build the list of registry-relative paths to test (two per crate).
        let mut rel_paths: Vec<String> = Vec::with_capacity(crates.len() * 2);
        for c in crates {
            let (cp, ip) = crate_registry_paths(hash, c);
            rel_paths.push(cp);
            rel_paths.push(ip);
        }
        // Injection-free probe: scp a newline-delimited path manifest to the
        // guest, then run a STATIC script that reads it and tests each path. The
        // path list is the only caller-influenced data, and every element is
        // composed from validated crate tokens + the detected hash, so it is
        // path-safe even before it reaches the guest file — and the guest script
        // never interpolates it into a command, it only reads it as data.
        let manifest = rel_paths.join("\n");
        let tmp = self.write_temp(&manifest, "rn-seed-probe", "txt")?;

        let (remote_manifest, script) = if is_windows {
            let rm = r"C:\Windows\Temp\rn_seed_probe.txt".to_string();
            // PowerShell: read manifest, test each path under the registry root.
            let s = "$root='C:\\CargoHome\\registry'; \
                 Get-Content 'C:\\Windows\\Temp\\rn_seed_probe.txt' | ForEach-Object { \
                   $p = $_.Trim(); if ($p) { \
                     $full = Join-Path $root $p; \
                     if (Test-Path -LiteralPath $full) { Write-Output \"1 $p\" } else { Write-Output \"0 $p\" } \
                   } \
                 }"
            .to_string();
            (rm, s)
        } else {
            let rm = "/tmp/rn_seed_probe.txt".to_string();
            let s = "root=\"$HOME/.cargo/registry\"; \
                 while IFS= read -r p; do \
                   [ -z \"$p\" ] && continue; \
                   if [ -e \"$root/$p\" ]; then echo \"1 $p\"; else echo \"0 $p\"; fi; \
                 done < /tmp/rn_seed_probe.txt"
                .to_string();
            (rm, s)
        };

        // Ship the manifest, then run the static probe.
        let scp = self.scp_to(
            target,
            user,
            &tmp,
            &remote_manifest,
            Duration::from_secs(120),
        )?;
        let _ = std::fs::remove_file(&tmp);
        if !scp.success {
            return Err(format!(
                "scp manifest failed: {}",
                truncate_tail(scp.stderr.trim(), 6, 800)
            ));
        }
        let out = self.ssh_exec(target, user, &script, Duration::from_secs(120))?;
        if !out.success {
            return Err(format!(
                "probe script exit {}: {}",
                out.code.map(|c| c.to_string()).unwrap_or("killed".into()),
                truncate_tail(out.stderr.trim(), 6, 800)
            ));
        }
        let mut map = std::collections::HashMap::new();
        for line in out.stdout.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("1 ") {
                map.insert(rest.to_string(), true);
            } else if let Some(rest) = line.strip_prefix("0 ") {
                map.insert(rest.to_string(), false);
            }
        }
        Ok(map)
    }

    /// Tar the to-ship files (relative to the host registry root), scp the
    /// tarball to the guest, and extract it into the guest registry root.
    // Internal host-side cache-seeding helper (dev tooling, not a production or
    // security path): the guest-connection triple (target/user/is_windows) and
    // the registry-layout triple (host_root/guest_hash/guest_root) are passed
    // explicitly for clarity. Grouping them into a struct would add indirection
    // without removing any real coupling, so the lint is suppressed locally.
    #[allow(clippy::too_many_arguments)]
    fn ship_crates(
        &self,
        target: &str,
        user: &str,
        is_windows: bool,
        host_root: &Path,
        guest_hash: &str,
        guest_root: &str,
        to_ship: &[LockCrate],
    ) -> Result<(), String> {
        // Build the relative path list for tar. The host stores blobs under the
        // HOST hash; the guest expects the GUEST hash. They're normally equal,
        // but if they differ we must not ship paths the guest can't place. Fail
        // closed when they differ (cannot be sure of layout).
        let host_hash = detect_registry_hash(&host_root.join("cache"))
            .ok_or_else(|| "host registry hash vanished".to_string())?;
        if host_hash != guest_hash {
            return Err(format!(
                "host registry hash {host_hash} != guest hash {guest_hash}; refusing to ship mismatched layout"
            ));
        }

        // Collect host-relative paths that actually exist on the host.
        let mut rel: Vec<String> = Vec::with_capacity(to_ship.len() * 2);
        for c in to_ship {
            let (cp, ip) = crate_registry_paths(&host_hash, c);
            if host_root.join(&cp).exists() {
                rel.push(cp);
            }
            if host_root.join(&ip).exists() {
                rel.push(ip);
            }
        }
        if rel.is_empty() {
            return Ok(()); // nothing host has; caller already accounts for it
        }

        // Write the tar member manifest, build the tar via `tar -T <manifest>`
        // from the host registry root (argv-only; paths come from validated
        // tokens, never the shell).
        let manifest = rel.join("\n");
        let tar_list = self.write_temp(&manifest, "rn-seed-tarlist", "txt")?;
        let tarball = self.temp_path("rn-seed", "tgz");
        let tar_args: Vec<&str> = vec![
            "czf",
            tarball.to_str().ok_or("tarball path not utf-8")?,
            "-C",
            host_root.to_str().ok_or("host root not utf-8")?,
            "-T",
            tar_list.to_str().ok_or("tar list path not utf-8")?,
        ];
        let tar_out = run_with_timeout(
            "tar",
            &tar_args,
            &self.repo_root,
            &[],
            Duration::from_secs(300),
        );
        let _ = std::fs::remove_file(&tar_list);
        let tar_out = tar_out?;
        if !tar_out.success {
            let _ = std::fs::remove_file(&tarball);
            return Err(format!(
                "host tar failed: {}",
                truncate_tail(tar_out.stderr.trim(), 6, 800)
            ));
        }

        // scp the tarball to the guest + extract into the registry root.
        let (remote_tar, extract) = if is_windows {
            let rt = r"C:\Windows\Temp\rn_seed.tgz".to_string();
            // bsdtar on modern Windows; -C into the registry root.
            let ex = format!(
                "tar -xzf C:\\Windows\\Temp\\rn_seed.tgz -C {guest_root}; Remove-Item -Force C:\\Windows\\Temp\\rn_seed.tgz"
            );
            (rt, ex)
        } else {
            let rt = "/tmp/rn_seed.tgz".to_string();
            // cd into the registry root (here it IS $HOME/.cargo/registry).
            let ex =
                "mkdir -p \"$HOME/.cargo/registry\" && cd \"$HOME/.cargo/registry\" && tar xzf /tmp/rn_seed.tgz && rm -f /tmp/rn_seed.tgz"
                    .to_string();
            (rt, ex)
        };
        let scp = self.scp_to(
            target,
            user,
            &tarball,
            &remote_tar,
            Duration::from_secs(600),
        );
        let _ = std::fs::remove_file(&tarball);
        let scp = scp?;
        if !scp.success {
            return Err(format!(
                "scp tarball failed: {}",
                truncate_tail(scp.stderr.trim(), 6, 800)
            ));
        }
        let out = self.ssh_exec(target, user, &extract, Duration::from_secs(300))?;
        if !out.success {
            return Err(format!(
                "guest extract exit {}: {}",
                out.code.map(|c| c.to_string()).unwrap_or("killed".into()),
                truncate_tail(out.stderr.trim(), 6, 800)
            ));
        }
        Ok(())
    }

    /// A unique host temp file path under the scratch state dir (never a guest
    /// path). Created lazily by callers that write to it.
    fn temp_path(&self, prefix: &str, ext: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}.{ext}", std::process::id()))
    }

    /// Write `content` to a unique host temp file and return its path.
    fn write_temp(&self, content: &str, prefix: &str, ext: &str) -> Result<PathBuf, String> {
        let p = self.temp_path(prefix, ext);
        std::fs::write(&p, content)
            .map_err(|e| format!("cannot write temp {}: {e}", p.display()))?;
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_route_get_output_reads_specific_route() {
        // Real captured output: host route correctly pinned to the UTM bridge.
        let output = "   route to: 192.168.64.18\n\
             destination: 192.168.64.18\n  interface: bridge101\n\
             flags: <UP,HOST,DONE,LLINFO,WASCLONED,IFSCOPE,IFREF>\n";
        let route = parse_route_get_output(output).expect("should parse");
        assert_eq!(route.destination, "192.168.64.18");
        assert_eq!(route.interface.as_deref(), Some("bridge101"));
    }

    #[test]
    fn parse_route_get_output_reads_default_fallback() {
        // Real captured output: no specific route, falls through to a VPN
        // tunnel's default route — the "host route missing" signature.
        let output = "   route to: 192.168.64.18\n\
             destination: default\n       mask: default\n\
             interface: utun7\n";
        let route = parse_route_get_output(output).expect("should parse");
        assert_eq!(route.destination, "default");
        assert_eq!(route.interface.as_deref(), Some("utun7"));
    }

    #[test]
    fn parse_route_get_output_reads_stale_gateway_route() {
        // Real captured output: a specific route exists, but it points at a
        // dead lab-node gateway via en0 instead of the local NAT bridge.
        let output = "   route to: 192.168.64.18\n\
             destination: 192.168.64.0\n       mask: 255.255.255.0\n\
             gateway: 10.47.225.138\n  interface: en0\n";
        let route = parse_route_get_output(output).expect("should parse");
        assert_eq!(route.destination, "192.168.64.0");
        assert_eq!(route.interface.as_deref(), Some("en0"));
    }

    #[test]
    fn parse_route_get_output_returns_none_without_destination_line() {
        assert!(parse_route_get_output("garbage\nno destination here\n").is_none());
    }

    #[test]
    fn classify_host_route_correct_when_interface_owns_subnet() {
        let route = RouteGetResult {
            destination: "192.168.64.18".to_owned(),
            interface: Some("bridge101".to_owned()),
        };
        let owning = vec!["bridge101".to_owned()];
        assert_eq!(
            classify_host_route(&route, &owning),
            HostLabRouteVerdict::Correct
        );
    }

    #[test]
    fn classify_host_route_stale_when_default_fallback() {
        let route = RouteGetResult {
            destination: "default".to_owned(),
            interface: Some("utun7".to_owned()),
        };
        let owning = vec!["bridge101".to_owned()];
        assert_eq!(
            classify_host_route(&route, &owning),
            HostLabRouteVerdict::StaleOrMissing
        );
    }

    #[test]
    fn classify_host_route_stale_when_specific_route_points_elsewhere() {
        let route = RouteGetResult {
            destination: "192.168.64.0".to_owned(),
            interface: Some("en0".to_owned()),
        };
        let owning = vec!["bridge101".to_owned()];
        assert_eq!(
            classify_host_route(&route, &owning),
            HostLabRouteVerdict::StaleOrMissing
        );
    }

    #[test]
    fn classify_host_route_off_lan_when_nothing_owns_the_subnet() {
        let route = RouteGetResult {
            destination: "default".to_owned(),
            interface: Some("en0".to_owned()),
        };
        assert_eq!(
            classify_host_route(&route, &[]),
            HostLabRouteVerdict::OffLabLan
        );
    }

    #[test]
    fn classify_host_route_correct_when_multiple_interfaces_own_subnet() {
        // The duplicate-NAT-subnet case (two UTM VMs both on 192.168.64.0/24)
        // should still classify as correct as long as the route matches one
        // of them.
        let route = RouteGetResult {
            destination: "192.168.64.18".to_owned(),
            interface: Some("bridge101".to_owned()),
        };
        let owning = vec!["bridge100".to_owned(), "bridge101".to_owned()];
        assert_eq!(
            classify_host_route(&route, &owning),
            HostLabRouteVerdict::Correct
        );
    }

    #[test]
    fn normalize_mac_address_zero_pads_and_lowercases() {
        assert_eq!(
            normalize_mac_address("6:2b:b:28:e3:ff").as_deref(),
            Some("06:2b:0b:28:e3:ff")
        );
        assert_eq!(
            normalize_mac_address("32:6B:39:DF:D7:4E").as_deref(),
            Some("32:6b:39:df:d7:4e")
        );
    }

    #[test]
    fn normalize_mac_address_rejects_malformed_input() {
        assert_eq!(normalize_mac_address("not-a-mac"), None);
        assert_eq!(normalize_mac_address("32:6b:39:df:d7"), None);
        assert_eq!(normalize_mac_address("zz:6b:39:df:d7:4e"), None);
    }

    #[test]
    fn extract_ip_for_mac_from_arp_output_matches_unpadded_host_mac() {
        let arp_output = "? (10.47.225.138) at 6:2b:b:28:e3:ff on en0 ifscope [ethernet]\n\
             ? (192.168.65.2) at 32:6b:39:df:d7:4e on bridge102 ifscope [bridge]\n";
        let target = normalize_mac_address("32:6b:39:df:d7:4e").expect("valid mac");
        assert_eq!(
            extract_ip_for_mac_from_arp_output(arp_output, target.as_str()).as_deref(),
            Some("192.168.65.2")
        );
    }

    #[test]
    fn extract_ip_for_mac_from_arp_output_skips_incomplete_rows() {
        let arp_output = "? (10.47.225.50) at (incomplete) on en0 ifscope [ethernet]\n\
             ? (192.168.65.2) at 32:6b:39:df:d7:4e on bridge102 ifscope [bridge]\n";
        let target = normalize_mac_address("32:6b:39:df:d7:4e").expect("valid mac");
        assert_eq!(
            extract_ip_for_mac_from_arp_output(arp_output, target.as_str()).as_deref(),
            Some("192.168.65.2")
        );
    }

    #[test]
    fn extract_ip_for_mac_from_arp_output_returns_none_when_absent() {
        let arp_output =
            "? (10.47.225.56) at 5e:55:cf:16:b3:ed on en0 ifscope permanent [ethernet]\n";
        let target = normalize_mac_address("32:6b:39:df:d7:4e").expect("valid mac");
        assert_eq!(
            extract_ip_for_mac_from_arp_output(arp_output, target.as_str()),
            None
        );
    }

    #[test]
    fn mac_address_from_utm_config_plist_reads_shared_network_mac() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let bundle = std::env::temp_dir().join(format!("mcp-mac-plist-{unique}.utm"));
        std::fs::create_dir_all(&bundle).expect("bundle dir should be created");
        std::fs::write(
            bundle.join("config.plist"),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <plist version=\"1.0\"><dict>\n\
             <key>Network</key><array><dict>\n\
             <key>MacAddress</key><string>32:6b:39:df:d7:4e</string>\n\
             <key>Mode</key><string>Shared</string>\n\
             </dict></array>\n\
             </dict></plist>\n",
        )
        .expect("config.plist should be written");

        let mac = mac_address_from_utm_config_plist(bundle.as_path());
        assert_eq!(mac.as_deref(), Some("32:6b:39:df:d7:4e"));

        let _ = std::fs::remove_dir_all(&bundle);
    }

    #[test]
    fn mac_address_from_utm_config_plist_returns_none_when_missing() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let bundle = std::env::temp_dir().join(format!("mcp-mac-plist-missing-{unique}.utm"));
        assert_eq!(mac_address_from_utm_config_plist(bundle.as_path()), None);
    }

    #[test]
    fn diagnose_host_lab_network_reports_no_entries_for_unknown_alias() {
        let tmp = std::env::temp_dir().join(format!(
            "mcp-diagnose-host-net-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let inv_dir = tmp.join("documents/operations/active");
        std::fs::create_dir_all(&inv_dir).unwrap();
        std::fs::write(
            inv_dir.join("vm_lab_inventory.json"),
            r#"{"entries":[{"alias":"deb-1","last_known_ip":"10.47.225.58","platform":"linux","controller":{"utm_name":"debian-headless-1"}}],"version":1}"#,
        )
        .unwrap();
        let srv = test_server(&tmp);
        let result = srv.diagnose_host_lab_network(Some("does-not-exist"));
        assert!(result.is_error.unwrap_or(false));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn is_safe_interface_name_accepts_real_os_names() {
        assert!(is_safe_interface_name("en0"));
        assert!(is_safe_interface_name("bridge101"));
        assert!(is_safe_interface_name("utun7"));
    }

    #[test]
    fn is_safe_interface_name_rejects_anything_with_shell_metacharacters() {
        assert!(!is_safe_interface_name(""));
        assert!(!is_safe_interface_name("en0; rm -rf /"));
        assert!(!is_safe_interface_name("en0 && echo hi"));
        assert!(!is_safe_interface_name("en0\nrm -rf /"));
        assert!(!is_safe_interface_name("$(whoami)"));
    }

    #[test]
    fn build_route_fix_shell_command_is_idempotent_delete_then_add() {
        let cmd = build_route_fix_shell_command("192.168.64.18", "192.168.64.0/24", "bridge101");
        assert_eq!(
            cmd,
            "/sbin/route delete -host 192.168.64.18 >/dev/null 2>&1; /sbin/route delete -net 192.168.64.0/24 >/dev/null 2>&1; /sbin/route add -net 192.168.64.0/24 -interface bridge101"
        );
    }

    #[test]
    fn apple_script_string_literal_escapes_quotes_and_backslashes() {
        assert_eq!(
            apple_script_string_literal(r#"say "hi" \ bye"#),
            r#""say \"hi\" \\ bye""#
        );
    }

    #[test]
    fn apply_host_route_fix_rejects_unknown_alias() {
        let tmp = std::env::temp_dir().join(format!(
            "mcp-fix-host-net-unknown-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let inv_dir = tmp.join("documents/operations/active");
        std::fs::create_dir_all(&inv_dir).unwrap();
        std::fs::write(
            inv_dir.join("vm_lab_inventory.json"),
            r#"{"entries":[{"alias":"deb-1","last_known_ip":"10.47.225.58","platform":"linux","controller":{"utm_name":"debian-headless-1"}}],"version":1}"#,
        )
        .unwrap();
        let srv = test_server(&tmp);
        let result = srv.apply_host_route_fix("does-not-exist");
        assert!(result.is_error.unwrap_or(false));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn apply_host_route_fix_rejects_missing_alias_param() {
        let tmp = std::env::temp_dir().join(format!(
            "mcp-fix-host-net-empty-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(tmp.join("documents/operations/active")).unwrap();
        let srv = test_server(&tmp);
        let result = srv.apply_host_route_fix("");
        assert!(result.is_error.unwrap_or(false));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn is_valid_vm_internet_access_action_accepts_only_the_three_modes() {
        assert!(is_valid_vm_internet_access_action("enable"));
        assert!(is_valid_vm_internet_access_action("disable"));
        assert!(is_valid_vm_internet_access_action("status"));
        assert!(!is_valid_vm_internet_access_action("reset"));
        assert!(!is_valid_vm_internet_access_action(""));
    }

    #[test]
    fn vm_internet_tunnel_argv_inherits_strict_transport_and_appends_forwarding() {
        // Simulates `ssh_transport_opts()` output: the hardened policy the tunnel
        // must inherit (must NOT be downgraded to StrictHostKeyChecking=no, and
        // must match the reachability probe's policy).
        let transport = vec![
            "-o".to_owned(),
            "StrictHostKeyChecking=yes".to_owned(),
            "-o".to_owned(),
            "BatchMode=yes".to_owned(),
            "-i".to_owned(),
            "/home/lab/.ssh/id".to_owned(),
        ];
        let argv = build_vm_internet_tunnel_argv(transport, 1080, "fedora@10.0.0.5".to_owned());

        // Hardened host-key policy preserved verbatim; no downgrade.
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "-o" && w[1] == "StrictHostKeyChecking=yes"),
            "must inherit strict host-key checking: {argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a == "StrictHostKeyChecking=no"),
            "must never downgrade host-key checking: {argv:?}"
        );
        // Fail-closed forwarding + persistent reverse-dynamic SOCKS flags appended.
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "-o" && w[1] == "ExitOnForwardFailure=yes"),
            "tunnel must fail closed on forward-setup failure: {argv:?}"
        );
        assert!(
            argv.iter().any(|a| a == "-N"),
            "no remote command: {argv:?}"
        );
        let r = argv.iter().position(|a| a == "-R").expect("has -R forward");
        assert_eq!(argv[r + 1], "1080", "port immediately follows -R");
        assert_eq!(
            argv.last().map(String::as_str),
            Some("fedora@10.0.0.5"),
            "destination is the final argv element"
        );
    }

    #[test]
    fn ssh_transport_opts_enforce_strict_host_key_checking_at_the_source() {
        // The builder test above proves the tunnel doesn't downgrade what it's
        // GIVEN; this guards the real SOURCE both the tunnel and the reachability
        // probe derive from, so `ssh_transport_opts()` can never regress to
        // StrictHostKeyChecking=no (which would weaken the tunnel AND re-open the
        // tunnel-accepts / probe-rejects host-key divergence).
        let tmp = std::env::temp_dir().join(format!(
            "mcp-ssh-transport-opts-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let srv = test_server(&tmp);
        let opts = srv.ssh_transport_opts();
        assert!(
            opts.windows(2)
                .any(|w| w[0] == "-o" && w[1] == "StrictHostKeyChecking=yes"),
            "transport opts must enforce strict host-key checking: {opts:?}"
        );
        assert!(
            !opts.iter().any(|o| o == "StrictHostKeyChecking=no"),
            "transport opts must never disable host-key checking: {opts:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn classify_guest_network_path_detects_physical_lan() {
        assert_eq!(
            classify_guest_network_path(&["en0".to_owned()]),
            "physical-lan"
        );
    }

    #[test]
    fn classify_guest_network_path_detects_isolated_utm_bridge() {
        assert_eq!(
            classify_guest_network_path(&["bridge101".to_owned()]),
            "isolated-utm-bridge"
        );
    }

    #[test]
    fn classify_guest_network_path_prefers_physical_lan_when_both_present() {
        // A node could in principle be reachable via both an isolated
        // bridge AND en0 (e.g. duplicate-subnet edge case) — physical-LAN
        // wins because it's the more actionable diagnosis (captive portal
        // is something the operator can potentially do something about;
        // "vmnet's own NAT" is not).
        assert_eq!(
            classify_guest_network_path(&["bridge100".to_owned(), "en0".to_owned()]),
            "physical-lan"
        );
    }

    #[test]
    fn classify_guest_network_path_unknown_when_neither_matches() {
        assert_eq!(
            classify_guest_network_path(&["utun7".to_owned()]),
            "unknown"
        );
        assert_eq!(classify_guest_network_path(&[]), "unknown");
    }

    fn write_fixture_config_plist(bundle: &Path, mode: &str) {
        std::fs::create_dir_all(bundle).unwrap();
        std::fs::write(
            bundle.join("config.plist"),
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <plist version=\"1.0\"><dict>\n\
                 <key>Network</key><array><dict>\n\
                 <key>MacAddress</key><string>32:6b:39:df:d7:4e</string>\n\
                 <key>Mode</key>\n\t\t\t<string>{mode}</string>\n\
                 <key>PortForward</key><array/>\n\
                 </dict></array>\n\
                 </dict></plist>\n"
            ),
        )
        .unwrap();
    }

    fn temp_bundle_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "mcp-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn utm_config_network_mode_reads_shared_and_bridged() {
        let shared = temp_bundle_dir("mode-shared");
        write_fixture_config_plist(&shared, "Shared");
        assert_eq!(utm_config_network_mode(&shared).as_deref(), Some("Shared"));
        let _ = std::fs::remove_dir_all(&shared);

        let bridged = temp_bundle_dir("mode-bridged");
        write_fixture_config_plist(&bridged, "Bridged");
        assert_eq!(
            utm_config_network_mode(&bridged).as_deref(),
            Some("Bridged")
        );
        let _ = std::fs::remove_dir_all(&bridged);
    }

    #[test]
    fn utm_config_network_mode_none_when_bundle_missing() {
        let missing = temp_bundle_dir("mode-missing");
        assert_eq!(utm_config_network_mode(&missing), None);
    }

    #[test]
    fn diagnose_vm_lan_presence_rejects_unknown_alias() {
        let tmp = temp_bundle_dir("lan-presence-unknown");
        let inv_dir = tmp.join("documents/operations/active");
        std::fs::create_dir_all(&inv_dir).unwrap();
        std::fs::write(
            inv_dir.join("vm_lab_inventory.json"),
            r#"{"entries":[{"alias":"deb-1"}],"version":1}"#,
        )
        .unwrap();
        let srv = test_server(&tmp);
        let result = srv.diagnose_vm_lan_presence(Some("does-not-exist"));
        assert!(result.is_error.unwrap_or(false));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn apply_vm_bridged_network_always_refuses_as_deprecated() {
        // Rulebook §11.3: the AppleScript/en0 mutation path is removed; the
        // tool refuses unconditionally and points at the sanctioned
        // prepare_lab_network transaction.
        let tmp = temp_bundle_dir("apply-bridge-deprecated");
        std::fs::create_dir_all(tmp.join("documents/operations/active")).unwrap();
        let srv = test_server(&tmp);
        for alias in ["", "fedora-utm-1"] {
            let result = srv.apply_vm_bridged_network(alias);
            assert!(result.is_error.unwrap_or(false));
            let text = result
                .content
                .first()
                .map(|c| c.text.clone())
                .unwrap_or_default();
            assert!(text.contains("DEPRECATED"), "{text}");
            assert!(text.contains("prepare_lab_network"), "{text}");
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn vm_internet_tunnel_pid_round_trips_through_state_file() {
        let tmp = std::env::temp_dir().join(format!(
            "mcp-vm-inet-roundtrip-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        assert_eq!(read_vm_internet_tunnel_pid(&tmp, "fedora-utm-1"), None);
        write_vm_internet_tunnel_pid(&tmp, "fedora-utm-1", 4242).unwrap();
        assert_eq!(
            read_vm_internet_tunnel_pid(&tmp, "fedora-utm-1"),
            Some(4242)
        );
        remove_vm_internet_tunnel_state(&tmp, "fedora-utm-1");
        assert_eq!(read_vm_internet_tunnel_pid(&tmp, "fedora-utm-1"), None);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn vm_internet_tunnel_state_is_scoped_per_alias() {
        let tmp = std::env::temp_dir().join(format!(
            "mcp-vm-inet-scoped-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        write_vm_internet_tunnel_pid(&tmp, "fedora-utm-1", 111).unwrap();
        write_vm_internet_tunnel_pid(&tmp, "ubuntu-utm-1", 222).unwrap();
        assert_eq!(read_vm_internet_tunnel_pid(&tmp, "fedora-utm-1"), Some(111));
        assert_eq!(read_vm_internet_tunnel_pid(&tmp, "ubuntu-utm-1"), Some(222));
        remove_vm_internet_tunnel_state(&tmp, "fedora-utm-1");
        assert_eq!(read_vm_internet_tunnel_pid(&tmp, "fedora-utm-1"), None);
        assert_eq!(read_vm_internet_tunnel_pid(&tmp, "ubuntu-utm-1"), Some(222));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn host_pid_alive_true_for_current_process_false_for_unlikely_pid() {
        assert!(host_pid_alive(std::process::id()));
        assert!(!host_pid_alive(999_999_999));
    }

    #[test]
    fn set_vm_internet_access_rejects_unknown_alias() {
        let tmp = std::env::temp_dir().join(format!(
            "mcp-vm-inet-unknown-alias-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let inv_dir = tmp.join("documents/operations/active");
        std::fs::create_dir_all(&inv_dir).unwrap();
        std::fs::write(
            inv_dir.join("vm_lab_inventory.json"),
            r#"{"entries":[{"alias":"deb-1","last_known_ip":"10.47.225.58","ssh_user":"debian"}],"version":1}"#,
        )
        .unwrap();
        let srv = test_server(&tmp);
        let result = srv.set_vm_internet_access(Some(&json!({"alias": "does-not-exist"})));
        assert!(result.is_error.unwrap_or(false));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn set_vm_internet_access_rejects_unknown_action() {
        let tmp = std::env::temp_dir().join(format!(
            "mcp-vm-inet-bad-action-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let inv_dir = tmp.join("documents/operations/active");
        std::fs::create_dir_all(&inv_dir).unwrap();
        std::fs::write(
            inv_dir.join("vm_lab_inventory.json"),
            r#"{"entries":[{"alias":"deb-1","last_known_ip":"10.47.225.58","ssh_user":"debian"}],"version":1}"#,
        )
        .unwrap();
        let srv = test_server(&tmp);
        let result =
            srv.set_vm_internet_access(Some(&json!({"alias": "deb-1", "action": "reset"})));
        assert!(result.is_error.unwrap_or(false));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn set_vm_internet_access_rejects_alias_missing_ssh_fields() {
        let tmp = std::env::temp_dir().join(format!(
            "mcp-vm-inet-missing-fields-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let inv_dir = tmp.join("documents/operations/active");
        std::fs::create_dir_all(&inv_dir).unwrap();
        std::fs::write(
            inv_dir.join("vm_lab_inventory.json"),
            r#"{"entries":[{"alias":"no-ssh-info"}],"version":1}"#,
        )
        .unwrap();
        let srv = test_server(&tmp);
        let result = srv.set_vm_internet_access(Some(&json!({"alias": "no-ssh-info"})));
        assert!(result.is_error.unwrap_or(false));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn set_vm_internet_access_status_reports_no_tunnel_when_none_tracked() {
        let tmp = std::env::temp_dir().join(format!(
            "mcp-vm-inet-status-none-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let inv_dir = tmp.join("documents/operations/active");
        std::fs::create_dir_all(&inv_dir).unwrap();
        // 192.0.2.1 is TEST-NET-1 (RFC 5737): guaranteed unroutable, so the
        // direct-reachability SSH attempt fails fast and deterministically
        // instead of depending on the test host's actual network/routing
        // state (or a real ConnectTimeout wait).
        std::fs::write(
            inv_dir.join("vm_lab_inventory.json"),
            r#"{"entries":[{"alias":"deb-1","last_known_ip":"192.0.2.1","ssh_user":"debian"}],"version":1}"#,
        )
        .unwrap();
        let srv = test_server(&tmp);
        let result =
            srv.set_vm_internet_access(Some(&json!({"alias": "deb-1", "action": "status"})));
        assert!(!result.is_error.unwrap_or(false));
        let text = result
            .content
            .first()
            .map(|c| c.text.as_str())
            .unwrap_or("");
        assert!(text.contains("tunnel: not active"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn set_vm_internet_access_disable_is_idempotent_when_nothing_tracked() {
        let tmp = std::env::temp_dir().join(format!(
            "mcp-vm-inet-disable-noop-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let inv_dir = tmp.join("documents/operations/active");
        std::fs::create_dir_all(&inv_dir).unwrap();
        std::fs::write(
            inv_dir.join("vm_lab_inventory.json"),
            r#"{"entries":[{"alias":"deb-1","last_known_ip":"10.47.225.58","ssh_user":"debian"}],"version":1}"#,
        )
        .unwrap();
        let srv = test_server(&tmp);
        let result =
            srv.set_vm_internet_access(Some(&json!({"alias": "deb-1", "action": "disable"})));
        assert!(!result.is_error.unwrap_or(false));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn split_csv_handles_quoted_commas() {
        let row = split_csv_line(r#"a,b,"c,d",e,"f""g""#);
        assert_eq!(row, vec!["a", "b", "c,d", "e", r#"f"g"#]);
    }

    #[test]
    fn split_csv_simple() {
        assert_eq!(
            split_csv_line("pass,fail,not_run"),
            vec!["pass", "fail", "not_run"]
        );
    }

    #[test]
    fn string_array_parses() {
        let v = json!({"aliases": ["a", "b"]});
        assert_eq!(string_array(Some(&v), "aliases"), vec!["a", "b"]);
        assert!(string_array(Some(&v), "missing").is_empty());
    }

    // ── seed_cargo_cache pure logic ──────────────────────────────────────

    #[test]
    fn lock_parse_keeps_registry_skips_path_and_git() {
        // Mirrors the real @generated Cargo.lock shape: registry crates (both the
        // git-index and sparse forms), a workspace/path crate with NO source, and
        // a git-sourced crate. Only the two crates.io entries survive.
        let lock = r#"# This file is automatically @generated by Cargo.
version = 4

[[package]]
name = "adler2"
version = "2.0.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "deadbeef"

[[package]]
name = "ureq"
version = "2.10.1"
source = "sparse+https://index.crates.io/"
checksum = "cafef00d"
dependencies = [
 "base64",
]

[[package]]
name = "boringtun"
version = "0.7.0"
dependencies = [
 "aead",
]

[[package]]
name = "rustynet-mcp"
version = "0.1.0"

[[package]]
name = "some-git-dep"
version = "0.1.0"
source = "git+https://example.com/repo.git#abc123"
checksum = "00"

[metadata]
"#;
        let got = parse_lock_registry_crates(lock);
        assert_eq!(
            got,
            vec![
                LockCrate {
                    name: "adler2".into(),
                    version: "2.0.1".into()
                },
                LockCrate {
                    name: "ureq".into(),
                    version: "2.10.1".into()
                },
            ],
            "only crates.io (git-index + sparse) registry packages, skipping path/workspace + git"
        );
    }

    #[test]
    fn lock_parse_drops_unsafe_tokens() {
        // A defensive case: a name with a path-traversal char must never be
        // emitted even if some malformed lock contained it.
        let lock = r#"[[package]]
name = "../evil"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        assert!(parse_lock_registry_crates(lock).is_empty());
    }

    #[test]
    fn index_shard_path_matches_cargo_layout() {
        // Verified against a real ~/.cargo/registry/index/<hash>/.cache tree.
        assert_eq!(index_shard_path("ureq"), "ur/eq/ureq"); // len >= 4
        assert_eq!(index_shard_path("rustls"), "ru/st/rustls"); // len >= 4
        assert_eq!(index_shard_path("url"), "3/u/url"); // len 3
        assert_eq!(index_shard_path("ab"), "2/ab"); // len 2
        assert_eq!(index_shard_path("a"), "1/a"); // len 1
        // Uppercase names are lowercased into the shard.
        assert_eq!(index_shard_path("Inflector"), "in/fl/inflector");
    }

    #[test]
    fn crate_registry_paths_compose_blob_and_index() {
        let hash = "index.crates.io-1949cf8c6b5b557f";
        let c = LockCrate {
            name: "Serde".into(), // exercise the case mismatch
            version: "1.0.0".into(),
        };
        let (blob, index) = crate_registry_paths(hash, &c);
        // .crate keeps the lock's exact name+version casing.
        assert_eq!(blob, format!("cache/{hash}/Serde-1.0.0.crate"));
        // index entry is the lowercased, sharded path — and the shard already
        // ends in the name, so there is NO trailing duplicate `/serde`.
        assert_eq!(index, format!("index/{hash}/.cache/se/rd/serde"));
    }

    #[test]
    fn missing_detection_requires_both_blob_and_index() {
        let hash = "index.crates.io-1949cf8c6b5b557f";
        let present_full = LockCrate {
            name: "full".into(),
            version: "1.0.0".into(),
        };
        let blob_only = LockCrate {
            name: "blobonly".into(),
            version: "1.0.0".into(),
        };
        let index_only = LockCrate {
            name: "indexonly".into(),
            version: "1.0.0".into(),
        };
        let totally_missing = LockCrate {
            name: "gone".into(),
            version: "1.0.0".into(),
        };
        let crates = vec![
            present_full.clone(),
            blob_only.clone(),
            index_only.clone(),
            totally_missing.clone(),
        ];

        let mut present = std::collections::HashMap::new();
        let mark = |present: &mut std::collections::HashMap<String, bool>,
                    c: &LockCrate,
                    blob: bool,
                    index: bool| {
            let (cp, ip) = crate_registry_paths(hash, c);
            present.insert(cp, blob);
            present.insert(ip, index);
        };
        mark(&mut present, &present_full, true, true);
        mark(&mut present, &blob_only, true, false);
        mark(&mut present, &index_only, false, true);
        // totally_missing: not in the map at all → treated as absent.

        let missing = missing_crates_from_presence(hash, &crates, &present);
        // Everything except the fully-present crate is missing.
        assert_eq!(missing, vec![blob_only, index_only, totally_missing]);
    }

    #[test]
    fn safe_crate_token_rejects_dangerous_input() {
        assert!(is_safe_crate_token("serde"));
        assert!(is_safe_crate_token("x25519-dalek"));
        assert!(is_safe_crate_token("1.0.0+build.5"));
        assert!(!is_safe_crate_token(""));
        assert!(!is_safe_crate_token("../etc"));
        assert!(!is_safe_crate_token("a b"));
        assert!(!is_safe_crate_token("a;rm -rf"));
        assert!(!is_safe_crate_token("a/b"));
        assert!(!is_safe_crate_token("a\nb"));
    }

    #[test]
    fn parse_ps_state_lstart_treats_zombie_as_not_alive() {
        // Running/sleeping process: return the lstart token (state stripped),
        // byte-compatible with the legacy bare-lstart record.
        assert_eq!(
            parse_ps_state_lstart("S Thu Jun 12 07:03:26 2026"),
            Some("Thu Jun 12 07:03:26 2026".to_string())
        );
        assert_eq!(
            parse_ps_state_lstart("  R+   Fri Jan  3 11:22:33 2025  "),
            Some("Fri Jan  3 11:22:33 2025".to_string())
        );
        // Zombie/defunct (a crashed job's unreaped leader): NOT alive, so the
        // job-state machinery reports the job ended instead of pegging the slot.
        assert_eq!(parse_ps_state_lstart("Z Thu Jun 12 07:03:26 2026"), None);
        assert_eq!(parse_ps_state_lstart("Z+ Thu Jun 12 07:03:26 2026"), None);
        // Empty (no such pid) and state-only (no lstart) → not alive.
        assert_eq!(parse_ps_state_lstart(""), None);
        assert_eq!(parse_ps_state_lstart("   "), None);
        assert_eq!(parse_ps_state_lstart("S"), None);
    }

    fn test_server(root: &Path) -> LabStateServer {
        LabStateServer {
            repo_root: root.to_path_buf(),
            jobs: Mutex::new(HashMap::new()),
            job_seq: AtomicU64::new(0),
        }
    }

    #[test]
    fn job_state_completion_record_beats_pid() {
        // PID 1 (init) — completion record must win regardless, proving the
        // pid-reuse hazard cannot mask a finished run over a long loop.
        let tmp = std::env::temp_dir().join(format!("mcp-jobstate-{}", std::process::id()));
        let report = tmp.join("report");
        std::fs::create_dir_all(report.join("state")).unwrap();
        let srv = test_server(&tmp);

        std::fs::write(
            report.join("state/report_state.json"),
            r#"{"run_complete":true,"run_passed":false}"#,
        )
        .unwrap();
        assert_eq!(srv.job_state("j", 1, &report), "failed");

        std::fs::write(
            report.join("state/report_state.json"),
            r#"{"run_complete":true,"run_passed":true}"#,
        )
        .unwrap();
        assert_eq!(srv.job_state("j", 1, &report), "passed");

        std::fs::remove_file(report.join("state/report_state.json")).unwrap();
        assert!(
            srv.job_state("j", 999_999_999, &report)
                .starts_with("ended")
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn job_state_pid_identity_detects_reuse() {
        // No completion record + a LIVE pid: the verdict must hinge on the
        // recorded pid_start token. Matching identity → running; a mismatch (the
        // recycled-pid case) → ended, NOT a false "running" forever.
        let tmp = std::env::temp_dir().join(format!("mcp-pididentity-{}", std::process::id()));
        let srv = test_server(&tmp);
        std::fs::create_dir_all(srv.jobs_dir()).unwrap();
        let report = tmp.join("rep");
        // Deliberately NO state/report_state.json → forces the liveness path.
        std::fs::create_dir_all(report.join("state")).unwrap();

        // This test process's own pid is guaranteed alive — use it as the
        // stand-in for a job's pid, and its real start-time as the token.
        let mypid = std::process::id() as u64;
        let real_start = srv
            .pid_start_time(mypid)
            .expect("our own pid must report a start time");

        // (a) matching identity → running
        let rec_ok = json!({
            "job_id": "live", "report_dir": report.to_string_lossy(),
            "pid": mypid, "pid_start": real_start,
            "log_path": tmp.join("live.log").to_string_lossy(), "created_unix": 1,
        });
        std::fs::write(
            srv.job_record_path("live"),
            serde_json::to_string(&rec_ok).unwrap(),
        )
        .unwrap();
        assert_eq!(srv.job_state("live", mypid, &report), "running");

        // (b) same live pid, MISMATCHED recorded start → recycled → ended
        let rec_recycled = json!({
            "job_id": "recycled", "report_dir": report.to_string_lossy(),
            "pid": mypid, "pid_start": "Thu Jan  1 00:00:00 1970",
            "log_path": tmp.join("recycled.log").to_string_lossy(), "created_unix": 1,
        });
        std::fs::write(
            srv.job_record_path("recycled"),
            serde_json::to_string(&rec_recycled).unwrap(),
        )
        .unwrap();
        assert!(
            srv.job_state("recycled", mypid, &report)
                .starts_with("ended")
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn prune_jobs_keeps_recent_skips_running() {
        let tmp = std::env::temp_dir().join(format!("mcp-prune-{}", std::process::id()));
        let srv = test_server(&tmp);
        std::fs::create_dir_all(srv.jobs_dir()).unwrap();
        // 3 finished jobs (completed report_state + dead pid), created 0,1,2.
        for i in 0..3u64 {
            let job_id = format!("j{i}");
            let rd = tmp.join(format!("rep{i}"));
            std::fs::create_dir_all(rd.join("state")).unwrap();
            std::fs::write(
                rd.join("state/report_state.json"),
                r#"{"run_complete":true,"run_passed":true}"#,
            )
            .unwrap();
            let rec = json!({
                "job_id": job_id,
                "report_dir": rd.to_string_lossy(),
                "pid": 999_999_990u64 + i,
                "log_path": tmp.join(format!("{job_id}.log")).to_string_lossy(),
                "created_unix": i,
            });
            std::fs::write(
                srv.job_record_path(&job_id),
                serde_json::to_string(&rec).unwrap(),
            )
            .unwrap();
        }
        let _ = srv.prune_jobs(Some(&json!({"keep": 1})));
        // Newest (j2) kept; j0, j1 pruned.
        assert!(srv.job_record_path("j2").exists());
        assert!(!srv.job_record_path("j1").exists());
        assert!(!srv.job_record_path("j0").exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn explain_stage_known_alias_and_unknown() {
        let r = explain_stage("validate_baseline_runtime");
        assert!(r.content[0].text.contains("baseline_runtime"));
        assert!(r.content[0].text.contains("validate_runtime.rs"));
        // os prefix stripped + alias resolved
        let r2 = explain_stage("linux_stage_anchor");
        assert!(r2.content[0].text.contains("anchor_validation.rs"));
        // unknown
        assert!(
            explain_stage("nonsense").content[0]
                .text
                .contains("Unknown stage")
        );
    }

    #[test]
    fn explain_stage_covers_tier0_revocation_audits() {
        let revoke = explain_stage("validate_linux_membership_revoke_applies");
        assert!(
            revoke.content[0]
                .text
                .contains("membership_revoke_audit.rs")
        );
        assert!(revoke.content[0].text.contains("RSA-0009"));

        let denied = explain_stage("validate_linux_revoked_peer_denied_e2e");
        assert!(
            denied.content[0]
                .text
                .contains("revoked_peer_denied_audit.rs")
        );
        assert!(denied.content[0].text.contains("RSA-0007"));
    }

    #[test]
    fn explain_stage_covers_daemon_security_validator_family() {
        for (stage, expected_fragment) in [
            ("validate_linux_runtime_acls", "linux_runtime_acls.rs"),
            ("validate_linux_key_custody", "linux_key_custody.rs"),
            (
                "validate_linux_service_hardening",
                "linux_service_hardening.rs",
            ),
            ("validate_linux_authenticode", "linux_authenticode.rs"),
            (
                "validate_linux_privileged_helper_allowlist",
                "privileged_helper_allowlist_audit.rs",
            ),
            (
                "validate_linux_membership_signature_forgery",
                "membership_signature_audit.rs",
            ),
            (
                "validate_linux_policy_default_deny",
                "policy_default_deny_audit.rs",
            ),
            (
                "validate_linux_membership_genesis",
                "exercise_linux_membership_genesis_validation",
            ),
            ("validate_linux_mesh_status", "linux_mesh_status.rs"),
        ] {
            let txt = explain_stage(stage).content[0].text.clone();
            assert!(
                txt.starts_with("# Stage:"),
                "{stage} should resolve, got: {txt}"
            );
            assert!(
                txt.contains(expected_fragment),
                "{stage} should mention {expected_fragment}, got: {txt}"
            );
        }
        // never falls into "Unknown stage" for this family.
        for s in [
            "runtime_acls",
            "key_custody",
            "service_hardening",
            "authenticode",
            "privileged_helper_allowlist",
            "membership_signature_forgery",
            "policy_default_deny",
            "membership_genesis",
            "mesh_status",
        ] {
            assert!(
                !explain_stage(s).content[0].text.contains("Unknown stage"),
                "alias {s} should resolve"
            );
        }
    }

    #[test]
    fn explain_stage_covers_tier1_security_stages() {
        for (stage, expected_fragment) in [
            (
                "validate_linux_blind_exit_reversal_denied",
                "blind_exit_reversal_audit.rs",
            ),
            (
                "validate_linux_gossip_revoked_readmit",
                "gossip_revoked_readmit_audit.rs",
            ),
            (
                "validate_linux_enrollment_replay",
                "enrollment_replay_audit.rs",
            ),
            (
                "validate_linux_hello_limiter_flood",
                "hello_limiter_audit.rs",
            ),
            ("validate_linux_relay_forwards_frame", "ForwardStats"),
        ] {
            let txt = explain_stage(stage).content[0].text.clone();
            assert!(
                txt.starts_with("# Stage:"),
                "{stage} should resolve, got: {txt}"
            );
            assert!(
                txt.contains(expected_fragment),
                "{stage} should mention {expected_fragment}, got: {txt}"
            );
        }
        // never falls into "Unknown stage" for this family.
        for s in [
            "blind_exit_reversal_denied",
            "gossip_revoked_readmit",
            "enrollment_replay",
            "hello_limiter_flood",
            "rt-2",
            "gm-1",
            "enr-1",
            "toctou-1",
            "dos-1",
            "relay_forwards_frame",
            "hp3",
            "rpt-01",
        ] {
            assert!(
                !explain_stage(s).content[0].text.contains("Unknown stage"),
                "alias {s} should resolve"
            );
        }
    }

    #[test]
    fn explain_stage_covers_early_failure_stages() {
        for s in [
            "verify_ssh",
            "verify_ssh_reachability",
            "preflight",
            "source_archive",
            "prepare_source_archive",
            "collect_pubkeys",
            "distribute_traversal",
            "enforce_runtime",
            "active_exit",
            "cleanup",
        ] {
            let txt = explain_stage(s).content[0].text.clone();
            assert!(
                txt.starts_with("# Stage:"),
                "{s} should resolve, got: {txt}"
            );
        }
        // verify_ssh must point the agent at recovery.
        assert!(
            explain_stage("verify_ssh").content[0]
                .text
                .contains("recover_stuck_vms")
        );
    }

    #[test]
    fn get_lab_topology_digest_and_resolution() {
        let tmp = std::env::temp_dir().join(format!("mcp-topo-{}", std::process::id()));
        let inv_dir = tmp.join("documents/operations/active");
        std::fs::create_dir_all(&inv_dir).unwrap();
        std::fs::write(
            inv_dir.join("vm_lab_inventory.json"),
            r#"{"entries":[{"alias":"deb-1","lab_role":"exit","exit_capable":true,"ssh_password":"tempo"},{"alias":"win-1","platform":"windows"},{"alias":"mac-1","platform":"macos"}],"version":1}"#,
        )
        .unwrap();
        let srv = test_server(&tmp);
        let txt = srv.get_lab_topology().content[0].text.clone();
        assert!(txt.contains("deb-1") && txt.contains("win-1") && txt.contains("mac-1"));
        assert!(txt.contains("windows_vm → win-1"));
        assert!(txt.contains("macos_vm → mac-1"));
        assert!(txt.contains("deb-1=exit"));
        // secret-free: the raw ssh_password must NOT appear.
        assert!(
            !txt.contains("tempo"),
            "topology digest must not leak credentials"
        );
        let inv = srv.call_tool("get_inventory", None).content[0].text.clone();
        assert!(
            !inv.contains("tempo"),
            "inventory MCP output must redact credentials"
        );
        assert!(
            inv.contains("<redacted>"),
            "redacted inventory should mark secret fields"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn report_dir_inputs_are_confined_to_repo() {
        let tmp = std::env::temp_dir().join(format!("mcp-confine-{}", std::process::id()));
        let outside = std::env::temp_dir().join(format!("mcp-outside-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let srv = test_server(&tmp);

        let abs =
            srv.list_report_artifacts(Some(&json!({"report_dir": outside.to_string_lossy()})));
        assert_eq!(abs.is_error, Some(true));
        assert!(abs.content[0].text.contains("repo root"));

        let rel = srv.list_report_artifacts(Some(&json!({"report_dir": "../outside"})));
        assert_eq!(rel.is_error, Some(true));
        assert!(rel.content[0].text.contains("repo root"));

        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn start_live_lab_run_rejects_second_running_job() {
        let tmp = std::env::temp_dir().join(format!("mcp-jobcap-{}", std::process::id()));
        let srv = test_server(&tmp);
        std::fs::create_dir_all(srv.jobs_dir()).unwrap();
        let report = tmp.join("rep");
        std::fs::create_dir_all(report.join("state")).unwrap();
        let pid = std::process::id() as u64;
        let pid_start = srv
            .pid_start_time(pid)
            .expect("test process must have a start token");
        let rec = json!({
            "job_id":"active",
            "report_dir": report.to_string_lossy(),
            "pid": pid,
            "pid_start": pid_start,
            "log_path": tmp.join("active.log").to_string_lossy(),
            "created_unix": now_unix()
        });
        std::fs::write(
            srv.job_record_path("active"),
            serde_json::to_string(&rec).unwrap(),
        )
        .unwrap();

        let res = srv.start_live_lab_run(Some(
            &json!({"mode":"run","profile":"dummy","report_dir":"state/next"}),
        ));
        assert_eq!(res.is_error, Some(true));
        assert!(
            res.content[0].text.contains("already running"),
            "got: {}",
            res.content[0].text
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn alias_to_utm_resolves_fields() {
        let tmp = std::env::temp_dir().join(format!("mcp-a2u-{}", std::process::id()));
        let inv_dir = tmp.join("documents/operations/active");
        std::fs::create_dir_all(&inv_dir).unwrap();
        std::fs::write(
            inv_dir.join("vm_lab_inventory.json"),
            r#"{"entries":[{"alias":"deb-1","last_known_ip":"192.168.0.200","controller":{"utm_name":"debian-headless-1"}}],"version":1}"#,
        )
        .unwrap();
        let srv = test_server(&tmp);
        let (utm, plat, ip, port) = srv.alias_to_utm("deb-1").unwrap();
        assert_eq!(utm, "debian-headless-1");
        assert_eq!(plat, "linux"); // no platform field → linux default
        assert_eq!(ip, "192.168.0.200");
        assert_eq!(port, 22);
        assert!(srv.alias_to_utm("nope").is_none());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A UTM-only listing must never read as "the whole lab" once a second host
    /// is declared: a partial answer that looks total is worse than an error.
    /// A libvirt guest IS in the inventory; saying "not in inventory" would send
    /// an operator hunting a phantom inventory bug. The two cases must differ.
    #[test]
    fn utm_resolution_error_distinguishes_absent_from_non_utm_backed() {
        let tmp = std::env::temp_dir().join(format!("mcp-ure-{}", std::process::id()));
        let inv_dir = tmp.join("documents/operations/active");
        std::fs::create_dir_all(&inv_dir).unwrap();
        std::fs::write(
            inv_dir.join("vm_lab_inventory.json"),
            r#"{"entries":[
                 {"alias":"deb-1","controller":{"type":"local_utm","utm_name":"debian-headless-1"}},
                 {"alias":"kvm-1","controller":{"type":"libvirt","domain":"linux-x86-client-1","host_id":"ubuntu-kvm-1"}}
               ],"version":1}"#,
        )
        .unwrap();
        let srv = test_server(&tmp);

        // genuinely absent
        let absent = srv.utm_resolution_error("nope");
        assert!(absent.contains("not in inventory"), "{absent}");

        // present, but libvirt-backed: must NOT claim it is missing, must name the
        // controller kind + host, and must point at the controller-aware path.
        let libvirt = srv.utm_resolution_error("kvm-1");
        assert!(
            !libvirt.contains("not in inventory"),
            "must not lie about a present alias: {libvirt}"
        );
        assert!(libvirt.contains("IS in the inventory"), "{libvirt}");
        assert!(libvirt.contains("libvirt"), "{libvirt}");
        assert!(libvirt.contains("ubuntu-kvm-1"), "{libvirt}");
        assert!(libvirt.contains("vm-lab-start"), "{libvirt}");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn tcp_reachable_false_for_closed_and_empty() {
        assert!(!tcp_reachable("", 22, Duration::from_millis(200)));
        // 127.0.0.1:1 is reserved/closed → connection refused, fast.
        assert!(!tcp_reachable("127.0.0.1", 1, Duration::from_millis(500)));
    }

    #[test]
    fn inventory_alias_for_platform_finds_desktop_vms() {
        let tmp = std::env::temp_dir().join(format!("mcp-inv-{}", std::process::id()));
        let inv_dir = tmp.join("documents/operations/active");
        std::fs::create_dir_all(&inv_dir).unwrap();
        std::fs::write(
            inv_dir.join("vm_lab_inventory.json"),
            r#"{"entries":[{"alias":"deb-1","os":"Debian/Linux"},{"alias":"win-1","platform":"windows"},{"alias":"mac-1","platform":"macos"}],"version":1}"#,
        )
        .unwrap();
        let srv = test_server(&tmp);
        assert_eq!(
            srv.inventory_alias_for_platform("windows").as_deref(),
            Some("win-1")
        );
        assert_eq!(
            srv.inventory_alias_for_platform("macos").as_deref(),
            Some("mac-1")
        );
        assert_eq!(srv.inventory_alias_for_platform("linux"), None);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn wait_for_job_returns_immediately_when_completed() {
        let tmp = std::env::temp_dir().join(format!("mcp-wait-{}", std::process::id()));
        let report = tmp.join("rep");
        std::fs::create_dir_all(report.join("state")).unwrap();
        std::fs::write(
            report.join("state/report_state.json"),
            r#"{"run_complete":true,"run_passed":true}"#,
        )
        .unwrap();
        let srv = test_server(&tmp);
        std::fs::create_dir_all(srv.jobs_dir()).unwrap();
        let rec = json!({
            "job_id":"w1","report_dir":report.to_string_lossy(),
            "pid":999_999_999u64,"log_path":tmp.join("w1.log").to_string_lossy(),"created_unix":1
        });
        std::fs::write(
            srv.job_record_path("w1"),
            serde_json::to_string(&rec).unwrap(),
        )
        .unwrap();
        let res = srv.wait_for_job(Some(&json!({"job_id":"w1","timeout_secs":10})));
        assert!(res.content[0].text.contains("passed"));
        assert!(res.content[0].text.contains("finished"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn trend_verdict_classifies() {
        let mk = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(r, s)| (r.to_string(), s.to_string()))
                .collect()
        };
        // ≥2 trailing passes → stable green.
        assert!(trend_verdict(&mk(&[("pass", ""), ("pass", "")])).starts_with("GREEN"));
        // single latest pass after a fail → just green.
        assert!(trend_verdict(&mk(&[("fail", "anchor"), ("pass", "")])).starts_with("JUST GREEN"));
        // same failing stage repeatedly → stuck (names the stage).
        let v = trend_verdict(&mk(&[
            ("fail", "relay_service_lifecycle"),
            ("fail", "relay_service_lifecycle"),
            ("fail", "relay_service_lifecycle"),
        ]));
        assert!(
            v.starts_with("STUCK at relay_service_lifecycle"),
            "got: {v}"
        );
        // failing but the stage advances → moving.
        let v = trend_verdict(&mk(&[("fail", "bootstrap"), ("fail", "anchor")]));
        assert!(v.starts_with("MOVING"), "got: {v}");
        // no usable rows.
        assert_eq!(trend_verdict(&mk(&[("", "")])), "NO DATA");
    }

    #[test]
    fn grep_report_finds_matches_case_insensitive() {
        let tmp = std::env::temp_dir().join(format!("mcp-grep-{}", std::process::id()));
        let rd = tmp.join("rep");
        std::fs::create_dir_all(rd.join("logs")).unwrap();
        std::fs::write(rd.join("logs/a.log"), "all good\nFATAL: boom\nmore\n").unwrap();
        std::fs::write(rd.join("logs/b.log"), "nothing here\n").unwrap();
        let srv = test_server(&tmp);
        let res = srv.grep_report(Some(
            &json!({"report_dir": rd.to_string_lossy(), "pattern": "fatal"}),
        ));
        let txt = res.content[0].text.clone();
        assert!(txt.contains("logs/a.log"), "got: {txt}");
        assert!(
            txt.contains(":2"),
            "should report the line number; got: {txt}"
        );
        assert!(
            !txt.contains("b.log"),
            "non-matching file excluded; got: {txt}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn get_stage_log_reads_matching_row_and_log() {
        let tmp = std::env::temp_dir().join(format!("mcp-stagelog-{}", std::process::id()));
        let rd = tmp.join("rep");
        std::fs::create_dir_all(rd.join("state")).unwrap();
        std::fs::create_dir_all(rd.join("logs")).unwrap();
        let anchor_log = rd.join("logs/anchor.log");
        std::fs::write(&anchor_log, "anchor stage output\nVALIDATION OK\n").unwrap();
        let tsv = format!(
            "bootstrap\thard\tpass\t0\t{}\tbootstrap stage\nanchor_validation\thard\tfail\t1\t{}\tanchor stage\n",
            rd.join("logs/bootstrap.log").display(),
            anchor_log.display(),
        );
        std::fs::write(rd.join("state/stages.tsv"), tsv).unwrap();
        let srv = test_server(&tmp);
        // 'linux_stage_anchor' must normalize and match the 'anchor_validation' row.
        let res = srv.get_stage_log(Some(
            &json!({"report_dir": rd.to_string_lossy(), "stage": "linux_stage_anchor"}),
        ));
        let txt = res.content[0].text.clone();
        assert!(
            txt.contains("anchor_validation"),
            "row should match; got: {txt}"
        );
        assert!(
            txt.contains("VALIDATION OK"),
            "log body should be included; got: {txt}"
        );
        assert!(
            !txt.contains("bootstrap stage"),
            "non-matching row excluded; got: {txt}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn loop_journal_appends_and_reads_back() {
        let tmp = std::env::temp_dir().join(format!("mcp-journal-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let srv = test_server(&tmp);
        // empty first
        assert!(srv.get_loop_journal(None).content[0].text.contains("Empty"));
        // append two notes (one with iteration+status)
        let r = srv.write_loop_note(Some(
            &json!({"note":"relay bind failed; trying port fix","iteration":3,"status":"trying"}),
        ));
        assert!(
            r.content[0].text.contains("#1"),
            "got: {}",
            r.content[0].text
        );
        srv.write_loop_note(Some(&json!({"note":"port fix worked","status":"fixed"})));
        let j = srv.get_loop_journal(Some(&json!({"limit":10}))).content[0]
            .text
            .clone();
        assert!(j.contains("2 notes"), "count; got: {j}");
        assert!(j.contains("it3"), "iteration rendered; got: {j}");
        assert!(
            j.contains("[trying]") && j.contains("[fixed]"),
            "status; got: {j}"
        );
        assert!(j.contains("port fix worked"), "note body; got: {j}");
        // empty note rejected
        assert_eq!(
            srv.write_loop_note(Some(&json!({"note":"  "}))).is_error,
            Some(true)
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn fmt_dur_formats() {
        assert_eq!(fmt_dur(45), "45s");
        assert_eq!(fmt_dur(125), "2m5s");
        assert_eq!(fmt_dur(7380), "2h3m");
    }

    #[test]
    fn get_run_progress_reports_tail_and_artifacts() {
        let tmp = std::env::temp_dir().join(format!("mcp-prog-{}", std::process::id()));
        let report = tmp.join("rep");
        std::fs::create_dir_all(report.join("logs")).unwrap();
        std::fs::write(report.join("logs/x.log"), "stage out\n").unwrap();
        let srv = test_server(&tmp);
        std::fs::create_dir_all(srv.jobs_dir()).unwrap();
        let log = tmp.join("p1.log");
        std::fs::write(&log, "bootstrap ok\n=== anchor ===\nssh peer ping\n").unwrap();
        let rec = json!({
            "job_id":"p1","report_dir":report.to_string_lossy(),
            "pid":999_999_999u64,"log_path":log.to_string_lossy(),
            "created_unix": now_unix().saturating_sub(7)
        });
        std::fs::write(
            srv.job_record_path("p1"),
            serde_json::to_string(&rec).unwrap(),
        )
        .unwrap();
        let t = srv.get_run_progress(Some(&json!({"job_id":"p1"}))).content[0]
            .text
            .clone();
        assert!(t.contains("elapsed"), "got: {t}");
        assert!(t.contains("Latest log lines"), "got: {t}");
        assert!(t.contains("ssh peer ping"), "verbatim tail; got: {t}");
        assert!(t.contains("anchor"), "heuristic stage token; got: {t}");
        assert!(
            t.contains("artifacts so far: 1"),
            "report artifacts; got: {t}"
        );
        // neither job_id nor report_dir → error
        assert_eq!(srv.get_run_progress(None).is_error, Some(true));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn find_untested_work_classifies_coverage() {
        let tmp = std::env::temp_dir().join(format!("mcp-untested-{}", std::process::id()));
        let dir = tmp.join("documents/operations");
        std::fs::create_dir_all(&dir).unwrap();
        // a=pass→fail (regressed), b=fail,fail (never passed), c=not_run (never run),
        // cross_os_x=pass,pass (green).
        let csv = "run_id,linux_stage_a,linux_stage_b,linux_stage_c,cross_os_x\n\
                   r1,pass,fail,not_run,pass\n\
                   r2,fail,fail,not_run,pass\n";
        std::fs::write(dir.join("live_lab_run_matrix.csv"), csv).unwrap();
        let srv = test_server(&tmp);
        let t = srv.find_untested_work(None).content[0].text.clone();
        // regressed section names a; never-passed names b; never-run names c.
        let regressed = t.split("NEVER PASSED").next().unwrap_or("");
        assert!(
            regressed.contains("linux_stage_a"),
            "a should be REGRESSED; got: {t}"
        );
        assert!(
            t.contains("linux_stage_b"),
            "b should appear (never passed); got: {t}"
        );
        let after_never_passed = t.split("NEVER PASSED").nth(1).unwrap_or("");
        assert!(
            after_never_passed.contains("linux_stage_b"),
            "b under NEVER PASSED; got: {t}"
        );
        assert!(
            t.contains("linux_stage_c"),
            "c should appear (never run); got: {t}"
        );
        assert!(
            t.contains("linux_stage_traversal") && t.contains("linux_stage_cleanup"),
            "canonical new rust-native cells must be visible even before schema upgrade; got: {t}"
        );
        // cross_os_x is green → not listed unless include_green.
        assert!(
            !t.contains("cross_os_x"),
            "green cell hidden by default; got: {t}"
        );
        // os filter
        let macos = srv
            .find_untested_work(Some(&json!({"os": "macos"})))
            .content[0]
            .text
            .clone();
        assert!(
            !macos.contains("linux_stage_a"),
            "os=macos excludes linux cells; got: {macos}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── Diagnose profile-less (Rust --node) runs ────────────────────────

    #[test]
    fn diagnose_profileless_empty_dir_errors_closed() {
        let tmp = std::env::temp_dir().join(format!("mcp-diag-empty-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let srv = test_server(&tmp);
        let result = srv.diagnose_profileless_run(&tmp, None, false);
        assert!(
            result.is_error.is_some(),
            "empty dir must error closed; got: {:?}",
            result.content
        );
        let text = result.content[0].text.to_lowercase();
        assert!(
            text.contains("no diagnosable evidence"),
            "error must mention no evidence; got: {text}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn diagnose_profileless_with_stages_tsv_and_orchestrate_result() {
        let tmp = std::env::temp_dir().join(format!("mcp-diag-tsv-{}", std::process::id()));
        let orch_dir = tmp.join("orchestration");
        let state_dir = tmp.join("state");
        std::fs::create_dir_all(&orch_dir).unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();

        let orch = json!({
            "command": "vm-lab-orchestrate-live-lab",
            "overall_status": "fail",
            "report_dir": tmp.to_string_lossy(),
            "outcomes": [
                {"stage": "bootstrap", "status": "pass", "summary": "ok"},
                {"stage": "membership", "status": "fail", "summary": "timeout"},
                {"stage": "anchor", "status": "skipped", "summary": ""}
            ],
            "warnings": [],
            "next_actions": []
        });
        std::fs::write(
            orch_dir.join("orchestrate_result.json"),
            serde_json::to_string_pretty(&orch).unwrap(),
        )
        .unwrap();

        let tsv = "bootstrap\tinfo\tpass\t0\tlogs/bootstrap.log\tok\t2026-01-01T00:00:00Z\t2026-01-01T00:01:00Z\n\
                   membership\tinfo\tfail\t1\tlogs/membership.log\ttimeout\t2026-01-01T00:01:00Z\t2026-01-01T00:02:00Z\n\
                   anchor\tinfo\tskipped\t\t\t\t2026-01-01T00:02:00Z\t\n";
        std::fs::write(state_dir.join("stages.tsv"), tsv).unwrap();

        let srv = test_server(&tmp);
        let result = srv.diagnose_profileless_run(&tmp, None, false);
        assert!(
            result.is_error.is_none(),
            "should succeed: {:?}",
            result.content
        );
        let text = &result.content[0].text;
        assert!(
            text.contains("Overall: **fail**"),
            "must show overall fail; got: {text}"
        );
        assert!(
            text.contains("1/3") || text.contains("(1"),
            "must show 1 failure from orchestrate; got: {text}"
        );
        assert!(
            text.to_lowercase().contains("membership"),
            "must mention failed stage membership; got: {text}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn diagnose_profileless_with_failure_digest() {
        let tmp = std::env::temp_dir().join(format!("mcp-diag-digest-{}", std::process::id()));
        let state_dir = tmp.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();

        let digest = json!({
            "first_failure": {
                "stage": "anchor",
                "primary_failure_reason": "anchor handshake timeout",
                "message": "tunnel did not establish",
                "log_path": "logs/anchor.log"
            }
        });
        std::fs::write(
            tmp.join("failure_digest.json"),
            serde_json::to_string_pretty(&digest).unwrap(),
        )
        .unwrap();

        let tsv = "anchor\tcritical\tfail\t1\tlogs/anchor.log\thandshake timeout\t2026-01-01T00:00:00Z\t2026-01-01T00:01:00Z\n";
        std::fs::write(state_dir.join("stages.tsv"), tsv).unwrap();

        let srv = test_server(&tmp);
        let result = srv.diagnose_profileless_run(&tmp, Some("anchor"), false);
        assert!(
            result.is_error.is_none(),
            "should succeed: {:?}",
            result.content
        );
        let text = &result.content[0].text;
        assert!(
            text.contains("anchor handshake timeout"),
            "must show failure reason; got: {text}"
        );
        assert!(
            text.contains("First failure"),
            "must have first-failure section; got: {text}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn diagnose_profileless_stage_filter_log() {
        let tmp = std::env::temp_dir().join(format!("mcp-diag-filter-{}", std::process::id()));
        let state_dir = tmp.join("state");
        let logs_dir = tmp.join("logs");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::create_dir_all(&logs_dir).unwrap();

        let tsv = "bootstrap\tinfo\tpass\t0\tlogs/bootstrap.log\tok\t2026-01-01T00:00:00Z\t2026-01-01T00:01:00Z\n";
        std::fs::write(state_dir.join("stages.tsv"), tsv).unwrap();
        std::fs::write(
            logs_dir.join("bootstrap.log"),
            "bootstrap completed\nall peers joined\n",
        )
        .unwrap();

        let srv = test_server(&tmp);
        let result = srv.diagnose_profileless_run(&tmp, Some("bootstrap"), false);
        assert!(
            result.is_error.is_none(),
            "should succeed: {:?}",
            result.content
        );
        let text = &result.content[0].text;
        assert!(
            text.contains("bootstrap completed"),
            "must include stage log tail; got: {text}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn diagnose_profileless_collect_artifacts_notes_unsupported() {
        let tmp = std::env::temp_dir().join(format!("mcp-diag-collect-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();

        let orch = json!({
            "command": "vm-lab-orchestrate-live-lab",
            "overall_status": "pass",
            "report_dir": tmp.to_string_lossy(),
            "outcomes": [],
            "warnings": [],
            "next_actions": []
        });
        std::fs::create_dir_all(tmp.join("orchestration")).unwrap();
        std::fs::write(
            tmp.join("orchestration/orchestrate_result.json"),
            serde_json::to_string_pretty(&orch).unwrap(),
        )
        .unwrap();
        std::fs::create_dir_all(tmp.join("state")).unwrap();
        std::fs::write(tmp.join("state/stages.tsv"), "b\tinfo\tpass\t0\t\tok\t\t\n").unwrap();

        let srv = test_server(&tmp);
        let result = srv.diagnose_profileless_run(&tmp, None, true);
        assert!(
            result.is_error.is_none(),
            "should succeed: {:?}",
            result.content
        );
        let text = &result.content[0].text;
        assert!(
            text.to_lowercase().contains("collect_artifacts"),
            "must note collect_artifacts not supported without profile; got: {text}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── start_live_lab_run mutually-exclusive validation ────────────────

    #[test]
    fn start_live_lab_run_rejects_nodes_with_role_platform_selector() {
        let tmp = std::env::temp_dir().join(format!("mcp-reject-selector-{}", std::process::id()));
        let inv_dir = tmp.join("documents/operations/active");
        std::fs::create_dir_all(&inv_dir).unwrap();
        std::fs::write(inv_dir.join("vm_lab_inventory.json"), r#"{"entries":[]}"#).unwrap();
        let srv = test_server(&tmp);

        let args = json!({
            "mode": "orchestrate",
            "nodes": ["vm1:exit"],
            "exit_platform": "linux"
        });
        let result = srv.start_live_lab_run(Some(&args));
        assert!(
            result.is_error.is_some(),
            "nodes + exit_platform must error; got: {:?}",
            result.content
        );
        let text = result.content[0].text.to_lowercase();
        assert!(
            text.contains("exit_platform") && text.contains("ignored"),
            "error must mention exit_platform ignored; got: {text}"
        );

        let args2 = json!({
            "mode": "orchestrate",
            "nodes": ["vm1:client"],
            "macos_promote_exit": true
        });
        let result2 = srv.start_live_lab_run(Some(&args2));
        assert!(
            result2.is_error.is_some(),
            "nodes + macos_promote_exit must error; got: {:?}",
            result2.content
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── Rust-engine synthesis from role-platform selectors ──────────────

    #[test]
    fn synthesize_nodes_maps_each_selector_to_its_own_role() {
        let linux: Vec<(String, String)> = vec![];
        let node = |ep, rp, ap, adp, bxp| {
            synthesize_nodes_from_platform_selectors(
                &linux,
                Some("mac-1"),
                None,
                ep,
                rp,
                ap,
                adp,
                bxp,
                false,
            )
        };
        assert_eq!(
            node(Some("macos"), None, None, None, None),
            vec!["mac-1:exit"]
        );
        assert_eq!(
            node(None, Some("macos"), None, None, None),
            vec!["mac-1:relay"]
        );
        assert_eq!(
            node(None, None, Some("macos"), None, None),
            vec!["mac-1:anchor"]
        );
        assert_eq!(
            node(None, None, None, Some("macos"), None),
            vec!["mac-1:admin"],
            "admin is a first-class --node role (Bucket 1.5), not aliased to anchor"
        );
        assert_eq!(
            node(None, None, None, None, Some("macos")),
            vec!["mac-1:blind_exit"],
            "blind_exit is a first-class --node role (Bucket 1.5), not aliased to exit"
        );
        assert_eq!(
            node(None, None, None, None, None),
            vec!["mac-1:client"],
            "no matching selector → client"
        );
    }

    #[test]
    fn synthesize_nodes_keeps_linux_backbone_and_appends_the_selected_guest() {
        let linux = vec![
            ("deb-1".to_string(), "exit".to_string()),
            ("deb-2".to_string(), "client".to_string()),
        ];
        let out = synthesize_nodes_from_platform_selectors(
            &linux,
            None,
            Some("win-1"),
            None,
            Some("windows"),
            None,
            None,
            None,
            false,
        );
        assert_eq!(out, vec!["deb-1:exit", "deb-2:client", "win-1:relay"]);
    }

    #[test]
    fn synthesize_nodes_drops_linux_exit_when_a_non_linux_exit_is_selected() {
        let linux = vec![
            ("deb-1".to_string(), "exit".to_string()),
            ("deb-2".to_string(), "client".to_string()),
        ];
        // exit_platform=windows: the Linux exit is superseded, not duplicated.
        let out = synthesize_nodes_from_platform_selectors(
            &linux,
            None,
            Some("win-1"),
            Some("windows"),
            None,
            None,
            None,
            None,
            false,
        );
        assert_eq!(out, vec!["deb-2:client", "win-1:exit"]);

        // macos_promote_exit: same supersession rule.
        let out2 = synthesize_nodes_from_platform_selectors(
            &linux,
            Some("mac-1"),
            None,
            None,
            None,
            None,
            None,
            None,
            true,
        );
        assert_eq!(out2, vec!["deb-2:client", "mac-1:exit"]);
    }

    #[test]
    fn synthesize_nodes_empty_when_no_backbone_and_no_resolved_guest() {
        let linux: Vec<(String, String)> = vec![];
        let out = synthesize_nodes_from_platform_selectors(
            &linux,
            None,
            None,
            Some("windows"),
            None,
            None,
            None,
            None,
            false,
        );
        assert!(
            out.is_empty(),
            "no inventory + unresolved windows alias → nothing to synthesize: {out:?}"
        );
    }

    #[test]
    fn has_role_platform_selector_detects_each_field() {
        assert!(has_role_platform_selector(Some(
            &json!({"exit_platform": "windows"})
        )));
        assert!(has_role_platform_selector(Some(
            &json!({"blind_exit_platform": "macos"})
        )));
        assert!(has_role_platform_selector(Some(
            &json!({"macos_promote_exit": true})
        )));
        assert!(!has_role_platform_selector(Some(
            &json!({"macos_promote_exit": false})
        )));
        assert!(!has_role_platform_selector(Some(
            &json!({"nodes": ["a:exit"]})
        )));
        assert!(!has_role_platform_selector(None));
    }

    #[test]
    fn inventory_linux_lab_roles_reads_only_linux_entries_with_both_fields() {
        let tmp = std::env::temp_dir().join(format!("mcp-linux-lab-roles-{}", std::process::id()));
        let inv_dir = tmp.join("documents/operations/active");
        std::fs::create_dir_all(&inv_dir).unwrap();
        std::fs::write(
            inv_dir.join("vm_lab_inventory.json"),
            r#"{"entries":[
                {"alias":"deb-1","lab_role":"exit"},
                {"alias":"deb-2","lab_role":"client"},
                {"alias":"deb-3"},
                {"alias":"mac-1","platform":"macos","lab_role":"macos_client"},
                {"alias":"win-1","platform":"windows","lab_role":"windows_client"}
            ]}"#,
        )
        .unwrap();
        let srv = test_server(&tmp);
        let roles = srv.inventory_linux_lab_roles();
        assert_eq!(
            roles,
            vec![
                ("deb-1".to_string(), "exit".to_string()),
                ("deb-2".to_string(), "client".to_string()),
            ],
            "must skip the no-lab_role Linux entry and every platform-tagged (mac/win) entry"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn start_live_lab_run_fails_closed_instead_of_silently_falling_back_to_bash() {
        // Regression test: a role-platform selector with no synthesizable --node
        // topology (empty inventory, no explicit guest) used to silently emit the
        // raw --relay-platform flag and spawn the legacy bash arm. It must now
        // fail closed with a clear message instead.
        let tmp =
            std::env::temp_dir().join(format!("mcp-selector-failclosed-{}", std::process::id()));
        let inv_dir = tmp.join("documents/operations/active");
        std::fs::create_dir_all(&inv_dir).unwrap();
        std::fs::write(inv_dir.join("vm_lab_inventory.json"), r#"{"entries":[]}"#).unwrap();
        let srv = test_server(&tmp);

        let args = json!({
            "mode": "orchestrate",
            "relay_platform": "windows",
            "auto_topology": false
        });
        let result = srv.start_live_lab_run(Some(&args));
        assert!(
            result.is_error.is_some(),
            "must fail closed rather than silently routing to bash; got: {:?}",
            result.content
        );
        let text = result.content[0].text.to_lowercase();
        assert!(
            text.contains("no --node topology could be synthesized"),
            "error must explain the synthesis failure; got: {text}"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
