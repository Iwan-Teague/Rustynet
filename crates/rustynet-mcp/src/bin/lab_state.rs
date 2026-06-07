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
    json_schema_string, prompt_text, run_server, run_with_timeout, spawn_logged, tail_file,
    text_content, tool_error, tool_success, truncate_output,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default machine-readable inventory path (repo-relative).
const DEFAULT_INVENTORY: &str = "documents/operations/active/vm_lab_inventory.json";
/// Where job records + logs live (repo-relative; under gitignored state/).
const JOBS_SUBDIR: &str = "state/mcp-jobs";

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
        format!("ll-{millis}-{seq}")
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

    /// running / passed / failed / ended for a job, using the in-memory child
    /// if present, else process liveness + the report dir.
    fn job_state(&self, job_id: &str, pid: u64, report_dir: &Path) -> String {
        let running = match self.jobs.lock() {
            Ok(mut jobs) => match jobs.get_mut(job_id) {
                Some(child) => match child.try_wait() {
                    Ok(Some(_)) => false,
                    Ok(None) => true,
                    Err(_) => self.pid_alive(pid),
                },
                None => self.pid_alive(pid),
            },
            Err(_) => self.pid_alive(pid),
        };
        if running {
            return "running".into();
        }
        match self.read_report_state(report_dir) {
            Some(rs) => {
                let complete = rs
                    .get("run_complete")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let passed = rs
                    .get("run_passed")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if passed {
                    "passed".into()
                } else if complete {
                    "failed".into()
                } else {
                    "ended (setup-only or no run record)".into()
                }
            }
            None => "ended (no completion record — likely crashed; check tail_job_log)".into(),
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
    let stdout = o.stdout.trim();
    if !stdout.is_empty() {
        result.push_str(&format!(
            "```\n{}\n```\n",
            truncate_output(stdout, 400, 100_000)
        ));
    }
    let stderr = o.stderr.trim();
    if !stderr.is_empty() {
        result.push_str(&format!(
            "### stderr\n```\n{}\n```\n",
            truncate_output(stderr, 80, 40_000)
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
1. READY THE LAB
   - get_lab_status. If a VM is unready / SSH times out: recover_stuck_vms (Linux
     QEMU killswitch lockouts) → restart_vm or ensure_lab_ready → update_inventory
     (refresh live IPs — NEVER hand-edit the inventory).
2. START A RUN (non-blocking)
   - start_live_lab_run mode=orchestrate with windows_vm + macos_vm + Linux nodes
     for full 3-OS coverage. Note the returned job_id + report_dir.
3. POLL until done
   - get_job_status(job_id) every ~5–10 min; tail_job_log(job_id) for progress.
     State resolves to passed / failed / ended.
4. CATCH BUGS (on failure)
   - get_run_result(job_id) → overall_result, first_failed_stage, per-OS/per-stage
     map, failure digest (stage / reason / message).
   - list_report_artifacts(job_id) then read_report_artifact for the failing stage's
     log; get_vm_diagnostics(alias) on the failing node; diagnose_live_lab_failure
     for deep triage.
5. PATCH
   - repo-context which_crate + get_read_order to find the owning crate + rules;
     get_architecture_constraints (default-deny, fail-closed, no unwrap in prod).
     Edit the ROOT cause, minimally — not the symptom.
6. VERIFY THE PATCH (fast, before re-running the lab)
   - gate-runner run_gates (skip_test=true for a fast inner loop, then full). Fix
     until green.
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
                description: "Return the machine-readable VM inventory (aliases, IPs, roles, OS, capabilities).".into(),
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
                description: "Restart one or more VMs. ['--all'] for all; wait_ready waits for SSH. Minutes-scale (blocking).".into(),
                input_schema: json_schema_object(
                    json!({
                        "aliases": json_schema_array_string("VM aliases, or ['--all']"),
                        "wait_ready": json_schema_boolean("Wait for SSH readiness (default: true)"),
                    }),
                    vec!["aliases"],
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
                description: "Deep triage of a failed run. `ops vm-lab-diagnose-live-lab-failure` (needs profile + report_dir from the failed run).".into(),
                input_schema: json_schema_object(
                    json!({
                        "profile": json_schema_string("Profile env file used by the failed run"),
                        "report_dir": json_schema_string("Report directory of the failed run"),
                        "stage": json_schema_string("Optional stage to focus on"),
                        "collect_artifacts": json_schema_boolean("Collect per-VM artifacts (default: false)"),
                    }),
                    vec!["profile", "report_dir"],
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
                        "windows_vm": json_schema_string("orchestrate: Windows VM alias"),
                        "macos_vm": json_schema_string("orchestrate: macOS VM alias"),
                        "nodes": json_schema_array_string("orchestrate: role assignments 'alias:role'"),
                        "profile": json_schema_string("run: profile env file (required for mode=run)"),
                        "profile_output": json_schema_string("setup: where to write the generated profile"),
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
        ]
    }

    fn call_tool(&self, name: &str, arguments: Option<Value>) -> ToolCallResult {
        let args = arguments.as_ref();
        match name {
            "get_lab_status" => self.run_ops("vm-lab-discover-local-utm-summary", &[], 180),

            "get_lab_status_json" => {
                let mut extra: Vec<&str> = vec!["--json"];
                if let Some(dir) = arg_str(args, "report_dir") {
                    extra.push("--report-dir");
                    extra.push(dir);
                }
                self.run_ops("vm-lab-discover-local-utm", &extra, 180)
            }

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
                let discovery = self.run_ops("vm-lab-discover-local-utm", &["--json"], 180);
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
                180,
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
                        extra.push("--alias");
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

            "recover_stuck_vms" => {
                let aliases = string_array(args, "aliases");
                let refs: Vec<&str> = aliases.iter().map(|s| s.as_str()).collect();
                self.run_shell_script("scripts/vm_lab/probe_and_recover_local_utm.sh", &refs, 600)
            }

            "ensure_lab_ready" => {
                let mut result = String::from("# Ensure Lab Ready\n\n## Step 1: Discover\n\n");
                let discover = self.run_ops("vm-lab-discover-local-utm-summary", &[], 180);
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
                let confirm = self.run_ops("vm-lab-discover-local-utm-summary", &[], 180);
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
                self.run_ops("vm-lab-sync-repo", &["--alias", alias], 900)
            }

            "bootstrap_vm" => {
                let alias = arg_str(args, "alias").unwrap_or("");
                let phase = arg_str(args, "phase").unwrap_or("");
                if alias.is_empty() || phase.is_empty() {
                    return tool_error("Missing required parameters: alias and phase");
                }
                self.run_ops(
                    "vm-lab-bootstrap-phase",
                    &["--alias", alias, "--phase", phase],
                    2400,
                )
            }

            "get_vm_diagnostics" => {
                let alias = arg_str(args, "alias").unwrap_or("");
                if alias.is_empty() {
                    return tool_error("Missing required parameter: alias");
                }
                let mut result = format!("# VM Diagnostics: {alias}\n\n## Daemon Status\n\n");
                let status = self.run_ops("vm-lab-status", &["--alias", alias], 300);
                if let Some(c) = status.content.first() {
                    result.push_str(&c.text);
                    result.push_str("\n\n");
                }
                result.push_str("## Diagnostic Artifacts\n\n");
                let report_dir =
                    self.ensure_report_dir(&format!("state/live-lab-mcp/diag-{alias}"));
                let artifacts = self.run_ops(
                    "vm-lab-collect-artifacts",
                    &["--alias", alias, "--report-dir", &report_dir],
                    600,
                );
                if let Some(c) = artifacts.content.first() {
                    result.push_str(&c.text);
                }
                tool_success(&result)
            }

            "diagnose_live_lab_failure" => {
                let profile = arg_str(args, "profile").unwrap_or("");
                let report_dir_arg = arg_str(args, "report_dir").unwrap_or("");
                if profile.is_empty() || report_dir_arg.is_empty() {
                    return tool_error("Missing required parameters: profile and report_dir");
                }
                let report_dir = self.ensure_report_dir(report_dir_arg);
                let mut extra: Vec<&str> = vec!["--profile", profile, "--report-dir", &report_dir];
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
            "list_jobs" => self.list_jobs(),
            "tail_job_log" => self.tail_job_log(args),
            "cancel_job" => self.cancel_job(args),
            "get_run_result" => self.get_run_result(args),
            "list_report_artifacts" => self.list_report_artifacts(args),
            "read_report_artifact" => self.read_report_artifact(args),

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
                if let Some(w) = arg_str(args, "windows_vm") {
                    cli.extend(["--windows-vm".into(), w.into()]);
                }
                if let Some(m) = arg_str(args, "macos_vm") {
                    cli.extend(["--macos-vm".into(), m.into()]);
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

        let cli_refs: Vec<&str> = cli.iter().map(|s| s.as_str()).collect();
        match spawn_logged(
            "cargo",
            &cli_refs,
            &self.repo_root,
            &[("CARGO_TERM_COLOR", "never")],
            &log_path,
        ) {
            Ok(child) => {
                let pid = child.id();
                if let Ok(mut jobs) = self.jobs.lock() {
                    jobs.insert(job_id.clone(), child);
                }
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
                tool_success(&format!(
                    "# Started live-lab job\n\n- **job_id:** `{job_id}`\n- **mode:** {mode}\n- **report_dir:** `{report_dir}`\n- **pid:** {pid}\n- **log:** `{}`\n\nThis is async — poll `get_job_status(job_id=\"{job_id}\")` every ~5–10 min, `tail_job_log` for progress, `get_run_result` when done.",
                    log_path.display()
                ))
            }
            Err(e) => tool_error(&format!("Failed to start job: {e}")),
        }
    }

    fn get_job_status(&self, args: Option<&Value>) -> ToolCallResult {
        let job_id = arg_str(args, "job_id").unwrap_or("");
        let Some(rec) = self.read_job_record(job_id) else {
            return tool_error(&format!("Unknown job_id: {job_id}"));
        };
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
        if state == "running" {
            out.push_str("\nStill running. Poll again later, or tail_job_log for progress.\n");
        } else {
            out.push_str("\nFinished. Use get_run_result for the structured breakdown.\n");
        }
        tool_success(&out)
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
        let mut killed_handle = false;
        if let Ok(mut jobs) = self.jobs.lock()
            && let Some(mut child) = jobs.remove(job_id)
        {
            let _ = child.kill();
            let _ = child.wait();
            killed_handle = true;
        }
        if !killed_handle && pid != 0 {
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
            "# Cancelled job {job_id}\n\nSent kill to pid {pid}.\n"
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
        match std::fs::read_to_string(&target) {
            Ok(content) => tool_success(&format!(
                "# `{rel}`\n\n```\n{}\n```\n",
                truncate_output(&content, 800, 80_000)
            )),
            Err(e) => tool_error(&format!("Cannot read '{rel}': {e}")),
        }
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
}
