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
use std::net::{IpAddr, SocketAddr, TcpStream};
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
        let mut full: Vec<&str> = vec!["run", "--quiet", "-p", "rustynet-cli", "--"];
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
        let mut args: Vec<&str> = vec!["ops", subcommand, "--inventory", DEFAULT_INVENTORY];
        args.extend_from_slice(extra_args);
        self.run_cli(&args, &format!("ops {subcommand}"), timeout_secs)
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

    /// Map UTM `utm_name` → inventory `alias` (Windows/macOS utm_names differ
    /// from their aliases, e.g. "Windows" vs "windows-utm-1").
    fn utm_name_alias_map(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        if let Ok(s) = std::fs::read_to_string(self.repo_root.join(DEFAULT_INVENTORY))
            && let Ok(inv) = serde_json::from_str::<Value>(&s)
            && let Some(entries) = inv.get("entries").and_then(|v| v.as_array())
        {
            for e in entries {
                if let (Some(name), Some(alias)) = (
                    e.get("controller")
                        .and_then(|c| c.get("utm_name"))
                        .and_then(|v| v.as_str()),
                    e.get("alias").and_then(|v| v.as_str()),
                ) {
                    m.insert(name.to_string(), alias.to_string());
                }
            }
        }
        m
    }

    fn get_vm_power_state(&self, filter: Option<&str>) -> ToolCallResult {
        let utmctl = utmctl_path();
        let outcome = match run_with_timeout(
            &utmctl,
            &["list"],
            &self.repo_root,
            &[],
            Duration::from_secs(30),
        ) {
            Ok(o) => o,
            Err(e) => {
                return tool_error(&format!(
                    "Cannot run utmctl ({utmctl}): {e}. Set RUSTYNET_UTMCTL_PATH if UTM is elsewhere."
                ));
            }
        };
        if !outcome.success {
            return tool_error(&format!("utmctl list failed: {}", outcome.stderr.trim()));
        }
        let map = self.utm_name_alias_map();
        let mut out = String::from(
            "# VM power state (utmctl list)\n\n| alias | utm_name | status |\n|---|---|---|\n",
        );
        let mut rows = 0;
        for line in outcome.stdout.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with("UUID") {
                continue;
            }
            // Columns: UUID  Status  Name (mirror of the CLI's own parser).
            let status = match t.split_whitespace().nth(1) {
                Some(s) => s,
                None => continue,
            };
            let name = match t.find(status) {
                Some(i) => t[i + status.len()..].trim(),
                None => continue,
            };
            let alias = map.get(name).cloned().unwrap_or_else(|| "-".into());
            if let Some(f) = filter
                && f != name
                && f != alias
            {
                continue;
            }
            out.push_str(&format!("| {alias} | {name} | {status} |\n"));
            rows += 1;
        }
        if rows == 0 {
            out.push_str("| (none matched) | | |\n");
        }
        out.push_str(
            "\n_started + SSH-reachable = ready. started + unreachable = network/killswitch (recover_stuck_vms / update_inventory), NOT a power issue. stopped = power_on_vm._\n",
        );
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

    /// Resolve an inventory alias → (utm_name, platform, ip, ssh_port).
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
            return tool_error(&format!("Unknown alias '{alias}' (not in inventory)"));
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

    fn reset_vm_network(&self, alias: &str) -> ToolCallResult {
        if alias.is_empty() {
            return tool_error("Missing required parameter: alias");
        }
        let Some((utm_name, platform, ip, port)) = self.alias_to_utm(alias) else {
            return tool_error(&format!("Unknown alias '{alias}' (not in inventory)"));
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
            return tool_error(&format!("Unknown alias '{alias}' (not in inventory)"));
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

    /// Parse `utmctl list` once → utm_name → power status. Mirrors the parse in
    /// utm_power_status but returns the whole fleet in one call.
    fn utm_status_map(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        if let Ok(o) = run_with_timeout(
            &utmctl_path(),
            &["list"],
            &self.repo_root,
            &[],
            Duration::from_secs(30),
        ) && o.success
        {
            for line in o.stdout.lines() {
                let t = line.trim();
                if t.is_empty() || t.starts_with("UUID") {
                    continue;
                }
                if let Some(status) = t.split_whitespace().nth(1)
                    && let Some(idx) = t.find(status)
                {
                    let name = t[idx + status.len()..].trim().to_string();
                    if !name.is_empty() {
                        m.insert(name, status.to_string());
                    }
                }
            }
        }
        m
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
        let status_map = self.utm_status_map();
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
            let power = status_map
                .get(utm_name)
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
                description: "Raw VM power state from `utmctl list` (started/stopped/paused), annotated with inventory aliases — distinct from SSH reachability. 'started but unreachable' = network/killswitch issue (recover_stuck_vms/update_inventory); 'stopped' = power_on_vm. Pass alias to filter.".into(),
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
                description: "Reset a Linux VM's networking OUT-OF-BAND via utmctl exec (no SSH needed) when it's up but unreachable: flush the nft killswitch, stop rustynetd, restart systemd-networkd/networking, then re-probe TCP/22. Use when check_vm_reachable says UP-but-UNREACHABLE. (macOS Apple-Virt has no utmctl exec; Windows: use restart_vm.)".into(),
                input_schema: json_schema_object(
                    json!({"alias": json_schema_string("VM alias (Linux guest)")}),
                    vec!["alias"],
                ),
            },
            Tool {
                name: "get_vm_network_info".into(),
                description: "Out-of-band Linux guest network diagnostics via utmctl exec (no SSH): ip addr, ip route, the nft killswitch ruleset, rustynetd active-state, and the daemon's recent journal. The triage companion to reset_vm_network — run it when check_vm_reachable says UP-but-UNREACHABLE to see WHY (stale killswitch? wrong NAT subnet? daemon crashed?) before resetting. (macOS Apple-Virt / Windows: use get_vm_diagnostics over SSH.)".into(),
                input_schema: json_schema_object(
                    json!({"alias": json_schema_string("VM alias (Linux guest)")}),
                    vec!["alias"],
                ),
            },
            Tool {
                name: "recover_stuck_vms".into(),
                description: "Recover Linux QEMU VMs stuck behind a stale nftables killswitch (SSH closed but VM alive). Runs probe-and-recover.".into(),
                input_schema: json_schema_object(
                    json!({"aliases": json_schema_array_string("Optional specific aliases; omit for all stuck Linux VMs")}),
                    vec![],
                ),
            },
            Tool {
                name: "ensure_lab_ready".into(),
                description: "Pre-flight: discover → restart unready + wait SSH → re-confirm. Minutes-scale (blocking).".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "preflight_check".into(),
                description: "Fast, read-only loop-start go/no-go in ONE call: host tools (cargo/utmctl/ssh/git), ssh identity + known_hosts, inventory parseability, disk headroom, the working-tree deploy set (untracked crates/ that won't ship), and every node's power+TCP. Returns a 🛑 NO-GO / ⚠️ CAUTION / ✅ GO verdict. Use it before start_live_lab_run instead of calling host_disk_status + get_lab_topology + check_vm_reachable separately. (Does not mutate or restart anything — for active recovery use ensure_lab_ready.)".into(),
                input_schema: json_schema_object(json!({}), vec![]),
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
                name: "bootstrap_vm".into(),
                description: "Run a bootstrap phase on a VM (sync-source, build-release, install-release, restart-runtime, verify-runtime, tunnel-smoke, killswitch-smoke, dns-smoke, ipv6-smoke, all). `ops vm-lab-bootstrap-phase`. Can be slow.".into(),
                input_schema: json_schema_object(
                    json!({
                        "alias": json_schema_string("VM alias"),
                        "phase": json_schema_string("Bootstrap phase"),
                    }),
                    vec!["alias", "phase"],
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
                name: "diagnose_live_lab_failure".into(),
                description: "Deep triage of a failed run. `ops vm-lab-diagnose-live-lab-failure`. Only report_dir is required — profile is auto-resolved from the run's matrix row (orchestrate runs generate it internally); pass profile only to override.".into(),
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
                description: "Launch a live-lab run as a DETACHED background job and return immediately with a job_id (does NOT block). mode=orchestrate (one-shot discover→setup→run→diagnose, all 3 OS), run (against an existing profile), or setup. Poll with get_job_status; results via get_run_result. Survives an MCP-server reload. Use dry_run to validate quickly. FAST RE-VERIFY after a per-node code patch: pass nodes=[topology] + rebuild_nodes=[patched node] + skip_soak — redeploys only that node (others keep state) instead of a full multi-node rebuild. (No mid-stage resume; see explain_stage.)".into(),
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
                description: "Host disk free space + the lab's biggest consumers (state/, target-livelab/, target/). Check periodically over a long run — a full disk fails builds/runs. Reclaim with prune_jobs.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
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

            "recover_stuck_vms" => {
                let aliases = string_array(args, "aliases");
                let refs: Vec<&str> = aliases.iter().map(|s| s.as_str()).collect();
                self.run_shell_script("scripts/vm_lab/probe_and_recover_local_utm.sh", &refs, 600)
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
                tool_success(&result)
            }

            "sync_repo_to_vm" => {
                let alias = arg_str(args, "alias").unwrap_or("");
                if alias.is_empty() {
                    return tool_error("Missing required parameter: alias");
                }
                self.run_ops("vm-lab-sync-repo", &["--vm", alias], 900)
            }

            "bootstrap_vm" => {
                let alias = arg_str(args, "alias").unwrap_or("");
                let phase = arg_str(args, "phase").unwrap_or("");
                if alias.is_empty() || phase.is_empty() {
                    return tool_error("Missing required parameters: alias and phase");
                }
                self.run_ops(
                    "vm-lab-bootstrap-phase",
                    &["--vm", alias, "--phase", phase],
                    2400,
                )
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
                if profile_owned.is_empty() {
                    return tool_error(
                        "No 'profile' given and none recorded in the report dir's matrix row (profile_path); pass profile explicitly.",
                    );
                }
                let report_dir = match self.ensure_report_dir(report_dir_arg) {
                    Ok(dir) => dir,
                    Err(e) => return tool_error(&e),
                };
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
            "preflight_check" => self.preflight_check(),
            "write_loop_note" => self.write_loop_note(args),
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

            "host_disk_status" => self.host_disk_status(),

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

        let mut cli: Vec<String> = ["run", "--quiet", "-p", "rustynet-cli", "--", "ops"]
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
                // Windows/macOS: explicit arg wins; otherwise auto-topology
                // (default on) fills them from the inventory so a run covers all
                // three OSes by default. Linux nodes auto-resolve from inventory
                // lab_role metadata in the CLI, so no Linux handling needed here.
                let auto = args
                    .and_then(|a| a.get("auto_topology"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let win = arg_str(args, "windows_vm").map(String::from).or_else(|| {
                    auto.then(|| self.inventory_alias_for_platform("windows"))
                        .flatten()
                });
                if let Some(w) = win {
                    cli.extend(["--windows-vm".into(), w]);
                }
                let mac = arg_str(args, "macos_vm").map(String::from).or_else(|| {
                    auto.then(|| self.inventory_alias_for_platform("macos"))
                        .flatten()
                });
                if let Some(m) = mac {
                    cli.extend(["--macos-vm".into(), m]);
                }
                for n in string_array(args, "nodes") {
                    cli.extend(["--node".into(), n]);
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
        rows.sort_by(|a, b| b.0.cmp(&a.0));
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
        jobs.sort_by(|a, b| b.0.cmp(&a.0)); // newest first
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn utm_name_alias_map_maps_controller_names() {
        let tmp = std::env::temp_dir().join(format!("mcp-utmmap-{}", std::process::id()));
        let inv_dir = tmp.join("documents/operations/active");
        std::fs::create_dir_all(&inv_dir).unwrap();
        std::fs::write(
            inv_dir.join("vm_lab_inventory.json"),
            r#"{"entries":[{"alias":"deb-1","controller":{"utm_name":"debian-headless-1"}},{"alias":"win-1","platform":"windows","controller":{"utm_name":"Windows"}}],"version":1}"#,
        )
        .unwrap();
        let srv = test_server(&tmp);
        let m = srv.utm_name_alias_map();
        // utm_name differs from alias for Windows — the annotation must bridge it.
        assert_eq!(m.get("Windows").map(|s| s.as_str()), Some("win-1"));
        assert_eq!(
            m.get("debian-headless-1").map(|s| s.as_str()),
            Some("deb-1")
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
}
