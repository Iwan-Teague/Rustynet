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
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Default machine-readable inventory path (repo-relative).
const DEFAULT_INVENTORY: &str = "documents/operations/active/vm_lab_inventory.json";
/// Where job records + logs live (repo-relative; under gitignored state/).
const JOBS_SUBDIR: &str = "state/mcp-jobs";
/// Timeout for discovery/inventory ops. Generous because the FIRST lab call on a
/// cold checkout must also build rustynet-cli (the largest crate), which can take
/// several minutes; warm calls return in seconds. The kill-on-timeout watchdog
/// still bounds a genuinely hung probe.
const DISCOVERY_TIMEOUT_SECS: u64 = 600;

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

    fn ensure_report_dir(&self, dir: &str) -> String {
        let path = self.abs_path(dir);
        let _ = std::fs::create_dir_all(&path);
        dir.to_string()
    }

    fn abs_path(&self, dir: &str) -> PathBuf {
        let p = Path::new(dir);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.repo_root.join(dir)
        }
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

    /// `kill -0 <pid>` exits 0 iff the (same-user) process is alive.
    fn pid_alive(&self, pid: u64) -> bool {
        matches!(
            run_with_timeout(
                "kill",
                &["-0", &pid.to_string()],
                &self.repo_root,
                &[],
                Duration::from_secs(5),
            ),
            Ok(o) if o.success
        )
    }

    /// running / passed / failed / ended for a job.
    ///
    /// The completion record (report_state.json) is checked FIRST and is
    /// authoritative — this is immune to PID reuse, which is a real hazard over
    /// 24h+ runs where a finished job's pid could be recycled by the OS and a
    /// naive `kill -0` would falsely report "running" forever. Liveness is only
    /// consulted when there is no completion record yet.
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
            Live::Unknown => self.pid_alive(pid),
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
            "\nOverride any with start_live_lab_run's `nodes` ('alias:role') / windows_vm / macos_vm. Credentials are intentionally omitted here — use get_inventory for the raw record.\n",
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
        let utmctl = std::env::var("RUSTYNET_UTMCTL_PATH")
            .unwrap_or_else(|_| "/Applications/UTM.app/Contents/MacOS/utmctl".to_string());
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
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
   - get_vm_power_state: any VM 'stopped' → power_on_vm. get_lab_status for SSH
     reachability. If a VM is 'started' but unreachable: recover_stuck_vms (Linux
     QEMU killswitch lockouts) → update_inventory (refresh live IPs — NEVER
     hand-edit). If a VM is wedged and recover_stuck_vms doesn't fix it:
     power_off_vm force=true → power_on_vm (hard reset). ensure_lab_ready does
     discover→restart→confirm in one call.
2. START A RUN (non-blocking)
   - start_live_lab_run mode=orchestrate. Leave windows_vm/macos_vm unset —
     auto_topology (default on) fills them from the inventory for full 3-OS
     coverage. Note the returned job_id + report_dir.
3. WAIT until done (don't busy-poll)
   - wait_for_job(job_id) — blocks up to ~4 min and returns the instant the job
     ends; call it in a loop. tail_job_log(job_id) any time for progress.
     State resolves to passed / failed / ended.
4. CATCH BUGS (on failure)
   - get_run_result(job_id) → overall_result, first_failed_stage, per-OS/per-stage
     map, failure digest (stage / reason / message).
   - explain_stage(first_failed_stage) → what that stage checks, the owning
     file/crate, and common causes (turns the failure into a patch target).
   - list_report_artifacts(job_id) then read_report_artifact for the failing stage's
     log; get_vm_diagnostics(alias) on the failing node; diagnose_live_lab_failure
     for deep triage.
5. PATCH
   - repo-context which_crate (on explain_stage's owning file) + get_read_order to
     find the owning crate + rules; get_architecture_constraints (default-deny,
     fail-closed, no unwrap in prod). Edit the ROOT cause, minimally.
6. VERIFY THE PATCH (fast, before re-running the lab)
   - gate-runner run_gates with changed_only=true (auto-scopes to the crates you
     touched) for a fast inner loop, then a full run_gates. Fix until green.
7. RE-VERIFY ON THE LAB
   - start_live_lab_run again with a fresh report_dir (a dirty tree is fine; the run
     records it and builds from the working tree). Back to step 3.
8. TRACK
   - get_run_matrix to see the first_failed_stage trend across iterations.

RULES
- One root-cause fix per iteration; re-verify before moving on.
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
            version: env!("CARGO_PKG_VERSION").into(),
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
                description: "Return the raw machine-readable VM inventory JSON (aliases, IPs, roles, OS, capabilities — includes credentials). For a clean, secret-free topology digest prefer get_lab_topology.".into(),
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
                description: "Launch a live-lab run as a DETACHED background job and return immediately with a job_id (does NOT block). mode=orchestrate (one-shot discover→setup→run→diagnose, all 3 OS), run (against an existing profile), or setup. Poll with get_job_status; results via get_run_result. Survives an MCP-server reload. Use dry_run to validate quickly.".into(),
                input_schema: json_schema_object(
                    json!({
                        "mode": json_schema_string("orchestrate | run | setup (default: orchestrate)"),
                        "report_dir": json_schema_string("Optional report dir (default: a fresh state/live-lab-<job_id>)"),
                        "auto_topology": json_schema_boolean("orchestrate: if true (default) and windows_vm/macos_vm are not given, auto-fill them from the inventory so the run covers all 3 OSes. Set false for Linux-only."),
                        "windows_vm": json_schema_string("orchestrate: Windows VM alias (overrides auto_topology)"),
                        "macos_vm": json_schema_string("orchestrate: macOS VM alias (overrides auto_topology)"),
                        "nodes": json_schema_array_string("orchestrate: role assignments 'alias:role'"),
                        "profile": json_schema_string("run: profile env file (required for mode=run)"),
                        "profile_output": json_schema_string("setup: where to write the generated profile"),
                        "source_mode": json_schema_string("working-tree (default — deploys your uncommitted patch) | local-head | commit-ref | repo-url"),
                        "timeout_secs": json!({"type": "integer", "description": "Per-run hard cap in seconds (CLI default 86400 = 24h). Raise for a >24h soak."}),
                        "dry_run": json_schema_boolean("Plan only (default: false)"),
                        "stop_after_ready": json_schema_boolean("orchestrate: stop once VMs are ready"),
                        "skip_setup": json_schema_boolean("run: skip setup stages"),
                        "skip_gates": json_schema_boolean("Skip gate stages"),
                        "skip_soak": json_schema_boolean("Skip soak stages"),
                        "skip_cross_network": json_schema_boolean("Skip cross-network stages"),
                    }),
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
                description: "Read one file from a run's report directory (path-confined to that directory; report dirs can live outside the repo). Pass a job_id OR report_dir, plus the relative path.".into(),
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
                name: "get_run_matrix".into(),
                description: "Read the live-lab run matrix (CSV evidence ledger) — recent runs with OS/role/stage coverage and pass/fail.".into(),
                input_schema: json_schema_object(
                    json!({"limit": json!({"type": "integer", "description": "Recent rows (default: 20)"})}),
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
                if let Some(dir) = arg_str(args, "report_dir") {
                    extra.push("--report-dir");
                    extra.push(dir);
                }
                self.run_ops("vm-lab-discover-local-utm", &extra, DISCOVERY_TIMEOUT_SECS)
            }

            "get_lab_topology" => self.get_lab_topology(),

            "get_inventory" => {
                let inv_path = self.repo_root.join(DEFAULT_INVENTORY);
                match std::fs::read_to_string(&inv_path) {
                    Ok(content) => {
                        if let Ok(parsed) = serde_json::from_str::<Value>(&content) {
                            let pretty = serde_json::to_string_pretty(&parsed).unwrap_or(content);
                            tool_success(&format!("# VM Lab Inventory\n\n```json\n{pretty}\n```\n"))
                        } else {
                            tool_success(&format!(
                                "# VM Lab Inventory\n\n```json\n{content}\n```\n"
                            ))
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
                    self.ensure_report_dir(&format!("state/live-lab-mcp/diag-{alias}"));
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
                    _ => self
                        .read_matrix_row(&self.abs_path(report_dir_arg))
                        .and_then(|row| row.get("profile_path").cloned())
                        .filter(|p| !p.is_empty())
                        .unwrap_or_default(),
                };
                if profile_owned.is_empty() {
                    return tool_error(
                        "No 'profile' given and none recorded in the report dir's matrix row (profile_path); pass profile explicitly.",
                    );
                }
                let report_dir = self.ensure_report_dir(report_dir_arg);
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
            "wait_for_job" => self.wait_for_job(args),
            "explain_stage" => explain_stage(arg_str(args, "stage").unwrap_or("")),
            "list_jobs" => self.list_jobs(),
            "tail_job_log" => self.tail_job_log(args),
            "cancel_job" => self.cancel_job(args),
            "get_run_result" => self.get_run_result(args),
            "list_report_artifacts" => self.list_report_artifacts(args),
            "read_report_artifact" => self.read_report_artifact(args),
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
        self.ensure_report_dir(&report_dir);
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
        let report_dir = self.abs_path(report_dir_rel);
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
        let report_dir = self.abs_path(report_dir_rel);
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
                let state = self.job_state(job_id, pid, &self.abs_path(report_dir_rel));
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
        let report_dir =
            self.abs_path(rec.get("report_dir").and_then(|v| v.as_str()).unwrap_or(""));

        // If we still hold the child handle, kill via it (no pid race at all).
        if let Some(mut child) = self
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(job_id)
        {
            let _ = child.kill();
            let _ = child.wait();
            return tool_success(&format!(
                "# Cancelled job {job_id}\n\nKilled via the live child handle (pid {pid}).\n"
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
            let pid_s = pid.to_string();
            let _ = run_with_timeout(
                "kill",
                &[&pid_s],
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
        tool_success(&format!(
            "# Cancelled job {job_id}\n\nSent kill to running pid {pid}.\n"
        ))
    }

    /// Resolve report dir from an explicit report_dir arg or a job_id's record.
    fn resolve_report_dir(&self, args: Option<&Value>) -> Result<PathBuf, String> {
        if let Some(dir) = arg_str(args, "report_dir") {
            return Ok(self.abs_path(dir));
        }
        if let Some(job_id) = arg_str(args, "job_id") {
            let rec = self
                .read_job_record(job_id)
                .ok_or_else(|| format!("Unknown job_id: {job_id}"))?;
            let dir = rec
                .get("report_dir")
                .and_then(|v| v.as_str())
                .ok_or("job record missing report_dir")?;
            return Ok(self.abs_path(dir));
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
            if self.job_state(&job_id, pid, &self.abs_path(report_dir_rel)) == "running" {
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
            if delete_reports && !report_dir_rel.is_empty() {
                let _ = std::fs::remove_dir_all(self.abs_path(report_dir_rel));
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
        aliases: &["bootstrap_hosts", "install"],
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
        aliases: &[],
        checks: "Tars the working tree (or HEAD, per source-mode) into the state archive that gets scp'd to each node.",
        owning: "crates/rustynet-cli/src/vm_lab/orchestrator/stage/source_archive.rs",
        causes: &[
            "`git stash create` / `git archive` failed (not a git repo, or a huge untracked tree)",
            "NOTE: source-mode=working-tree captures only TRACKED changes — `git add` new files or they won't deploy",
        ],
    },
    StageInfo {
        name: "verify_ssh",
        aliases: &["ssh"],
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
            "preflight",
            "source_archive",
            "collect_pubkeys",
            "enforce_runtime",
            "active_exit",
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
}
